// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {AntelopeLib} from "@hiero-ledger/clpr/verifiers/evm/antelope/AntelopeLib.sol";
import {AntelopeClprBase} from "@hiero-ledger/clpr/verifiers/evm/antelope/AntelopeClprBase.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title AntelopeDposVerifier
/// @notice Legacy Antelope DPoS (Leap 3.x-5.x, pre-Savanna) → Hiero `IClprVerifier`: a producer-
///         schedule light client that replays K1 block signatures and the DPoS last-irreversible-block
///         rule, then proves CLPR action receipts against the header's action_mroot.
///         Serves XPR Network, which has not activated Savanna (its public API nodes report Leap
///         v5.0.0 on mainnet and testnet, 2026-10-01).
///
/// @dev Rules (AntelopeIO/leap v5.0.3 block_header_state.cpp, unchanged from v3.1.2):
///      - Block id = sha256(header) with the first 4 bytes set to the block number (big-endian);
///        number = num_from_id(previous) + 1. Headers are linked by `previous`.
///      - Signature digest = sha256( sha256(sha256(header) || blockroot_merkle_root) || pending_schedule_hash ).
///        The block-root accumulator and the pending schedule hash are carried per signed header
///        as opaque values: the producer's signature commits to them.
///      - LIB (`next` + `calc_dpos_last_irreversible`). With n producers in the active schedule:
///        (1) a block B becomes "proposed irreversible" once R1 = n*2/3+1 distinct producers have
///            produced blocks whose confirmation range [num - confirmed, num] covers B (each block
///            decrements confirm_count for itself and `confirmed` predecessors; a producer cannot
///            confirm a range twice: producer_double_confirm);
///        (2) B is irreversible once R2 = n - (n-1)/3 distinct producers have produced blocks after
///            the block P where (1) completed: each such producer's implied irreversible block is
///            then >= B, and the LIB is the ((n-1)/3)-th lowest of those values.
///        The verifier replays exactly this on a contiguous header chain starting at B. Counting is
///        conservative: a confirmation is only counted while B is within the 1024 blocks nodeos
///        tracks (maximum_tracked_dpos_confirmations).
///      - Schedule rotation: a header with a producer_schedule_change_extension (id 1, WTMSIG
///        format) proposing version v+1, proven irreversible under schedule v. The proposed schedule
///        then always activates (a pending schedule cannot be replaced until it is confirmed), and
///        headers signed under it carry schedule_version v+1.
///      - Producer keys: a producer counts if one K1 key of its block-signing authority has weight
///        >= threshold. The relayer supplies that key uncompressed; the verifier checks it against
///        the compressed key in the schedule and stores its EVM address for ecrecover. Producers
///        whose authority needs several signatures, or R1/WebAuthn keys, never count.
///
///      Trust anchor: abi.encode(uint32 version, bytes32 scheduleHash),
///      scheduleHash = keccak256(abi.encode(version, uint64[] producers, address[] signers)).
///
///      Bundle proof: RLP([
///        0 schedule       [[producer, signer], ...] matching the anchor,
///        1 rotations      [[HeaderChain, keys], ...]  keys = per producer [] or [keyIndex, xy64],
///        2 finality       HeaderChain starting at the block holding the action,
///        3 action         ActionProof of `queuestate`,
///        4 bundleContent  ClprBundleContent protobuf,
///        5 manifest       ClprEndpointManifest protobuf preimage, or ""
///      ])
///      HeaderChain = [[header] | [header, sig65, blockrootMerkleRoot, pendingScheduleHash], ...]
///      ActionProof = [actionBase, data, returnValue, receiver, receiptTail, index, count, siblings]
///      sig65 = recovery byte (27 + 4 + recid) || r || s, the SIG_K1_ payload.
contract AntelopeDposVerifier is AntelopeClprBase {
    uint256 public constant MAX_PRODUCERS = 125; // leap config::max_producers
    uint256 internal constant MAX_TRACKED_CONFIRMATIONS = 1024; // config::maximum_tracked_dpos_confirmations
    uint256 internal constant TRUST_ANCHOR_LENGTH = 64;
    uint16 internal constant SCHEDULE_CHANGE_EXTENSION = 1;
    uint256 internal constant SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    struct Schedule {
        uint32 version;
        uint64[] producers;
        address[] signers;
    }

    struct Header {
        uint32 num;
        uint32 timestamp;
        uint64 producer;
        uint16 confirmed;
        uint32 scheduleVersion;
        bytes32 id;
        bytes32 actionMroot;
        address signer; // zero when the header carries no signature
        uint256 scheduleExtOffset; // offset of the schedule-change extension data, 0 if none
        bytes raw;
    }

    error InvalidTrustAnchor();
    error ScheduleMismatch();
    error ScheduleMalformed();
    error HeaderMalformed();
    error HeaderChainBroken(uint256 index);
    error EmptyHeaderChain();
    error BadSignature(uint256 index);
    error UnknownProducer(uint64 producer);
    error SignerMismatch(uint64 producer, address signer);
    error WrongScheduleVersion(uint32 version, uint32 expected);
    error NotIrreversible(uint256 stage, uint256 count);
    error NoScheduleChange();
    error RotationKeysMalformed();
    error ActionRootMismatch();

    constructor(string memory chainId) AntelopeClprBase(chainId) {}

    // ── IClprVerifier ─────────────────────────────────────────────────────────

    /// @notice IClprVerifier.verifyBundle.
    function verifyBundle(bytes calldata proofBytes, bytes calldata trustAnchor, bytes calldata channelContext)
        external
        view
        override
        returns (
            ClprTypes.QueueMetadata memory metadata,
            bytes[] memory messagePayloads,
            bytes memory newTrustAnchor,
            bytes memory newTrustAnchorId,
            ClprTypes.ClprEndpointManifest memory newEndpointManifest
        )
    {
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        if (trustAnchor.length != TRUST_ANCHOR_LENGTH) revert InvalidTrustAnchor();
        (uint32 version, bytes32 scheduleHash) = abi.decode(trustAnchor, (uint32, bytes32));

        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory p = RLP.decodeList(proofMem);
        if (p.length != 6) revert InvalidPayloadShape();

        Schedule memory sched = _decodeSchedule(p[0], version);
        if (_hashSchedule(sched) != scheduleHash) revert ScheduleMismatch();

        Memory.Slice[] memory rotations = RLP.readList(p[1]);
        for (uint256 i = 0; i < rotations.length; ++i) {
            sched = _rotate(rotations[i], sched);
        }

        ProvenAction memory a = _proveAction(p[2], p[3], sched);
        bytes32 manifestCommitment;
        (metadata, manifestCommitment) = _queueState(a, ctx);
        messagePayloads = _decodeBundleContent(RLP.readBytes(p[4]));

        bytes memory manifestPreimage = RLP.readBytes(p[5]);
        newEndpointManifest = manifestPreimage.length == 0
            ? _absentEndpointManifest()
            : _bindManifest(manifestPreimage, manifestCommitment, ctx.remoteServiceAddress);

        if (rotations.length != 0) {
            newTrustAnchor = abi.encode(sched.version, _hashSchedule(sched));
            newTrustAnchorId = abi.encodePacked(sched.version);
        }
    }

    /// @notice IClprVerifier.verifyConfig.
    /// @dev configProof = RLP([version, schedule, HeaderChain, ActionProof of `ledgerconfig`]).
    ///      The schedule is the channel's weak-subjectivity input; the action's block must be
    ///      irreversible under it. endpointManifestProof = RLP([HeaderChain, ActionProof of `manifest`]).
    function verifyConfig(bytes calldata configProofBytes, bytes32 channelId, bytes calldata endpointManifestProofBytes)
        external
        view
        override
        returns (
            bytes memory channelContext,
            string memory chainId,
            bytes memory serviceAddress,
            uint96 peerConfigNanos,
            ClprTypes.Throttles memory throttles,
            bytes memory initialTrustAnchor,
            bytes memory initialTrustAnchorId,
            ClprTypes.ClprEndpointManifest memory endpointManifest
        )
    {
        if (configProofBytes.length == 0) revert InvalidPayloadShape();
        bytes memory cfgMem = configProofBytes;
        Memory.Slice[] memory c = RLP.decodeList(cfgMem);
        if (c.length != 4) revert InvalidPayloadShape();

        Schedule memory sched = _decodeSchedule(c[1], _u32(c[0]));
        ClprTypes.LedgerConfiguration memory lc = _ledgerConfig(_proveAction(c[2], c[3], sched));
        serviceAddress = lc.serviceAddress;

        if (endpointManifestProofBytes.length == 0) {
            endpointManifest = _uninitializedEndpointManifest(serviceAddress);
        } else {
            bytes memory mMem = endpointManifestProofBytes;
            Memory.Slice[] memory m = RLP.decodeList(mMem);
            if (m.length != 2) revert InvalidPayloadShape();
            endpointManifest = _manifestAction(_proveAction(m[0], m[1], sched), serviceAddress);
        }

        initialTrustAnchor = abi.encode(sched.version, _hashSchedule(sched));
        initialTrustAnchorId = abi.encodePacked(sched.version);
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        return (
            channelContext,
            lc.chainId,
            serviceAddress,
            lc.nanosSinceEpoch,
            lc.throttles,
            initialTrustAnchor,
            initialTrustAnchorId,
            endpointManifest
        );
    }

    // ── Actions ───────────────────────────────────────────────────────────────

    /// @dev Prove an action receipt in the first header of an irreversible header chain.
    function _proveAction(Memory.Slice chainItem, Memory.Slice actionItem, Schedule memory sched)
        internal
        pure
        returns (ProvenAction memory a)
    {
        Header[] memory hs = _parseChain(chainItem);
        _requireIrreversible(hs, sched);

        Memory.Slice[] memory ap = RLP.readList(actionItem);
        if (ap.length != 8) revert InvalidPayloadShape();
        bytes32 actDigest;
        (a, actDigest) = _action(_u64(ap[3]), RLP.readBytes(ap[0]), RLP.readBytes(ap[1]), RLP.readBytes(ap[2]));
        bytes32 receipt = AntelopeLib.legacyReceiptDigest(a.receiver, actDigest, RLP.readBytes(ap[4]));
        bytes32 root =
            AntelopeLib.legacyMerkleRoot(receipt, RLP.readUint256(ap[5]), RLP.readUint256(ap[6]), _b32s(ap[7]));
        if (root != hs[0].actionMroot) revert ActionRootMismatch();
    }

    // ── Headers ───────────────────────────────────────────────────────────────

    function _parseChain(Memory.Slice item) internal pure returns (Header[] memory hs) {
        Memory.Slice[] memory list = RLP.readList(item);
        if (list.length == 0) revert EmptyHeaderChain();
        hs = new Header[](list.length);
        for (uint256 i = 0; i < list.length; ++i) {
            Memory.Slice[] memory e = RLP.readList(list[i]);
            if (e.length != 1 && e.length != 4) revert InvalidPayloadShape();
            Header memory h = _parseHeader(RLP.readBytes(e[0]));
            if (i > 0) {
                Header memory prev = hs[i - 1];
                if (
                    AntelopeLib.readBytes32(h.raw, AntelopeLib.HDR_PREVIOUS) != prev.id || h.timestamp <= prev.timestamp
                ) {
                    revert HeaderChainBroken(i);
                }
            }
            if (e.length == 4) h.signer = _recover(h, RLP.readBytes(e[1]), _b32(e[2]), _b32(e[3]), i);
            hs[i] = h;
        }
    }

    /// @dev Parse a packed block_header. Requires the WTMSIG layout (no legacy new_producers) and
    ///      extensions that consume the input exactly.
    function _parseHeader(bytes memory raw) internal pure returns (Header memory h) {
        h.raw = raw;
        h.timestamp = AntelopeLib.readU32(raw, 0);
        h.producer = AntelopeLib.readU64(raw, AntelopeLib.HDR_PRODUCER);
        h.confirmed = AntelopeLib.readU16(raw, AntelopeLib.HDR_CONFIRMED);
        bytes32 previous = AntelopeLib.readBytes32(raw, AntelopeLib.HDR_PREVIOUS);
        h.actionMroot = AntelopeLib.readBytes32(raw, AntelopeLib.HDR_ACTION_MROOT);
        h.scheduleVersion = AntelopeLib.readU32(raw, AntelopeLib.HDR_SCHEDULE_VERSION);
        if (AntelopeLib.readU8(raw, AntelopeLib.HDR_NEW_PRODUCERS) != 0) revert HeaderMalformed();
        (uint256 n, uint256 off) = AntelopeLib.readVarUint(raw, AntelopeLib.HDR_EXTENSIONS);
        for (uint256 i = 0; i < n; ++i) {
            uint16 extId = AntelopeLib.readU16(raw, off);
            uint256 len;
            (len, off) = AntelopeLib.readVarUint(raw, off + 2);
            if (extId == SCHEDULE_CHANGE_EXTENSION) h.scheduleExtOffset = off;
            off += len;
        }
        if (off != raw.length) revert HeaderMalformed();
        h.num = AntelopeLib.blockNumFromId(previous) + 1;
        h.id = AntelopeLib.blockId(sha256(raw), h.num);
    }

    function _recover(Header memory h, bytes memory sig, bytes32 bmroot, bytes32 scheduleHash, uint256 index)
        internal
        pure
        returns (address signer)
    {
        if (sig.length != 65) revert BadSignature(index);
        uint8 i = uint8(sig[0]);
        if (i < 31 || i > 32) revert BadSignature(index); // compressed-key flag, recid 0 or 1
        bytes32 headerBmroot = sha256(abi.encodePacked(sha256(h.raw), bmroot));
        bytes32 digest = sha256(abi.encodePacked(headerBmroot, scheduleHash));
        bytes32 r = AntelopeLib.readBytes32(sig, 1);
        bytes32 s = AntelopeLib.readBytes32(sig, 33);
        signer = ecrecover(digest, i - 4, r, s);
        if (signer == address(0)) revert BadSignature(index);
    }

    /// @dev Replay the DPoS LIB rule for hs[0] under `sched` (see contract docs).
    function _requireIrreversible(Header[] memory hs, Schedule memory sched) internal pure {
        uint256 n = sched.producers.length;
        uint256 r1 = n * 2 / 3 + 1;
        uint256 r2 = n - (n - 1) / 3;
        uint32 target = hs[0].num;
        uint256 confirmed; // bitmap of producers whose blocks confirmed the target (stage 1)
        uint256 implied; // bitmap of producers that produced after stage 1 completed (stage 2)
        uint256 c1;
        uint256 c2;
        for (uint256 i = 0; i < hs.length; ++i) {
            Header memory h = hs[i];
            if (h.scheduleVersion != sched.version) revert WrongScheduleVersion(h.scheduleVersion, sched.version);
            if (h.signer == address(0)) continue;
            uint256 bit = uint256(1) << _producerIndex(sched, h.producer, h.signer);
            if (c1 < r1) {
                if (
                    uint256(h.num) <= uint256(target) + h.confirmed
                        && uint256(h.num) - target < MAX_TRACKED_CONFIRMATIONS && confirmed & bit == 0
                ) {
                    confirmed |= bit;
                    ++c1;
                }
            } else if (implied & bit == 0) {
                implied |= bit;
                if (++c2 == r2) return;
            }
        }
        if (c1 < r1) revert NotIrreversible(1, c1);
        revert NotIrreversible(2, c2);
    }

    function _producerIndex(Schedule memory sched, uint64 producer, address signer) internal pure returns (uint256) {
        for (uint256 j = 0; j < sched.producers.length; ++j) {
            if (sched.producers[j] == producer) {
                if (sched.signers[j] != signer) revert SignerMismatch(producer, signer);
                return j;
            }
        }
        revert UnknownProducer(producer);
    }

    // ── Schedules ─────────────────────────────────────────────────────────────

    function _decodeSchedule(Memory.Slice item, uint32 version) internal pure returns (Schedule memory s) {
        Memory.Slice[] memory l = RLP.readList(item);
        if (l.length == 0 || l.length > MAX_PRODUCERS) revert ScheduleMalformed();
        s.version = version;
        s.producers = new uint64[](l.length);
        s.signers = new address[](l.length);
        for (uint256 i = 0; i < l.length; ++i) {
            Memory.Slice[] memory e = RLP.readList(l[i]);
            if (e.length != 2) revert ScheduleMalformed();
            s.producers[i] = _u64(e[0]);
            s.signers[i] = RLP.readAddress(e[1]);
            for (uint256 j = 0; j < i; ++j) {
                if (s.producers[j] == s.producers[i]) revert ScheduleMalformed();
            }
        }
    }

    function _hashSchedule(Schedule memory s) internal pure returns (bytes32) {
        // forge-lint: disable-next-line(asm-keccak256)
        return keccak256(abi.encode(s.version, s.producers, s.signers));
    }

    /// @dev Apply one schedule rotation: [HeaderChain, keys].
    function _rotate(Memory.Slice item, Schedule memory old) internal pure returns (Schedule memory next) {
        Memory.Slice[] memory r = RLP.readList(item);
        if (r.length != 2) revert InvalidPayloadShape();
        Header[] memory hs = _parseChain(r[0]);
        _requireIrreversible(hs, old);
        uint256 off = hs[0].scheduleExtOffset;
        if (off == 0) revert NoScheduleChange();
        next = _parseScheduleChange(hs[0].raw, off, RLP.readList(r[1]));
        if (next.version != old.version + 1) revert ScheduleMismatch();
    }

    /// @dev Parse producer_authority_schedule {version, [producer, variant<block_signing_authority_v0>]}
    ///      and bind each producer to the relayer-supplied uncompressed K1 key.
    function _parseScheduleChange(bytes memory raw, uint256 off, Memory.Slice[] memory keys)
        internal
        pure
        returns (Schedule memory s)
    {
        s.version = AntelopeLib.readU32(raw, off);
        uint256 n;
        (n, off) = AntelopeLib.readVarUint(raw, off + 4);
        if (n == 0 || n > MAX_PRODUCERS || keys.length != n) revert ScheduleMalformed();
        s.producers = new uint64[](n);
        s.signers = new address[](n);
        for (uint256 i = 0; i < n; ++i) {
            s.producers[i] = AntelopeLib.readU64(raw, off);
            uint256 variant;
            (variant, off) = AntelopeLib.readVarUint(raw, off + 8);
            if (variant != 0) revert ScheduleMalformed();
            uint32 threshold = AntelopeLib.readU32(raw, off);
            uint256 nk;
            (nk, off) = AntelopeLib.readVarUint(raw, off + 4);
            Memory.Slice[] memory pick = RLP.readList(keys[i]);
            if (pick.length != 0 && pick.length != 2) revert RotationKeysMalformed();
            uint256 want = pick.length == 2 ? RLP.readUint256(pick[0]) : type(uint256).max;
            for (uint256 k = 0; k < nk; ++k) {
                uint256 keyType;
                (keyType, off) = AntelopeLib.readVarUint(raw, off);
                uint256 keyOff = off;
                if (keyType == 0 || keyType == 1) {
                    off += 33;
                } else if (keyType == 2) {
                    uint256 rpidLen;
                    (rpidLen, off) = AntelopeLib.readVarUint(raw, off + 34);
                    off += rpidLen;
                } else {
                    revert ScheduleMalformed();
                }
                uint16 weight = AntelopeLib.readU16(raw, off);
                off += 2;
                if (k == want) {
                    if (keyType != 0 || weight < threshold) revert RotationKeysMalformed();
                    s.signers[i] = _k1Address(raw, keyOff, RLP.readBytes(pick[1]));
                }
            }
            if (pick.length == 2 && want >= nk) revert RotationKeysMalformed();
            for (uint256 j = 0; j < i; ++j) {
                if (s.producers[j] == s.producers[i]) revert ScheduleMalformed();
            }
        }
    }

    /// @dev EVM address of the compressed secp256k1 key at raw[off..off+33), given its uncompressed
    ///      form `xy` (64 bytes), after checking that `xy` is on the curve and compresses to it.
    function _k1Address(bytes memory raw, uint256 off, bytes memory xy) internal pure returns (address) {
        if (xy.length != 64) revert RotationKeysMalformed();
        uint256 x = uint256(AntelopeLib.readBytes32(xy, 0));
        uint256 y = uint256(AntelopeLib.readBytes32(xy, 32));
        uint8 prefix = AntelopeLib.readU8(raw, off);
        if (x >= SECP_P || y >= SECP_P) revert RotationKeysMalformed();
        // forge-lint: disable-next-line(unsafe-typecast)
        if (prefix != 2 + uint8(y & 1) || uint256(AntelopeLib.readBytes32(raw, off + 1)) != x) {
            revert RotationKeysMalformed();
        }
        if (mulmod(y, y, SECP_P) != addmod(mulmod(mulmod(x, x, SECP_P), x, SECP_P), 7, SECP_P)) {
            revert RotationKeysMalformed();
        }
        return address(uint160(uint256(keccak256(xy))));
    }
}
