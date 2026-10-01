// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {ClprBeaconBls} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconBls.sol";
import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";
import {CometBftProofCodec as Codec} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftProofCodec.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title PlasmaBftVerifier
/// @notice "Plasma → Hiero" verifier. Plasma (chain 9745) runs PlasmaBFT, a closed-source Fast
///         HotStuff variant, over reth. Its consensus formats are undocumented; everything here was
///         reverse-engineered from the `plasma-consensus` 1.1.0 binary and checked against live
///         mainnet gossip (README, "How it works").
///
/// ## Finality (Fast HotStuff 2-chain)
///   Block B is final once B has a QC and its child B+1 (view(B)+1, parent = B) has a QC. The QC on B
///   is carried in B+1; the QC on B+1 is carried in B+2. The verifier checks both QCs.
///
/// ## Verification chain
///   0. Anchor = committeeRoot(32) ‖ height(8, BE): the committee whose SSZ root is `committeeRoot`
///      signs heights ≥ `height`.
///   1. Committee in calldata (EIP-2537 uncompressed G1 keys, strictly ascending by compressed bytes:
///      PlasmaBFT indexes voters into the pubkey-sorted committee). Compressed and hashed as
///      SSZ `List[Bytes48, 1024]`; must equal the anchor root.
///   2. Header B (11 SSZ leaves, ConsensusBlock V1): hash = sha256(htr(leaves) ‖ le32(1)).
///      Its body_root opens (6-node SSZ branch) to the execution payload's `state_root` (the EVM
///      stateRoot of block B).
///   3. Header B+1: parent_root = hash(B), view = view(B)+1, its `qc` leaf = root of QC1, the QC on
///      B (view(B), hash(B), height H).
///   4. QC1 and QC2 (the QC on B+1: view(B)+1, hash(B+1), H+1): strictly ascending voter indices,
///      count ≥ n − ⌊(n−1)/3⌋, aggregate BLS (min-pk, `..._POP_` DST) over per-voter messages
///      `pubkey(48) ‖ blockHash ‖ le64(height) ‖ le64(voterIndex) ‖ le64(view)`, i.e. one pairing
///      check with k+1 pairs.
///   5. Fail-safe committee pinning: B and B+1 must declare `committed_validators_hash` and B+1
///      `qc_validators_hash` equal to the anchor root. A committee change therefore halts the
///      channel instead of trusting an unproven handoff (README, "Validator-set rotation").
contract PlasmaBftVerifier is ClprEvmBundleVerifier {
    struct Profile {
        string chainId;
        bytes32 bootstrapCommitteeRoot;
        uint64 bootstrapHeight;
    }

    struct Qc {
        uint64 proposer;
        uint64 height;
        uint64[] votes;
        bytes sig96;
        bytes sig256;
    }

    uint256 internal constant ANCHOR_LENGTH = 40;
    uint256 internal constant HEADER_LEAVES = 11;
    uint256 internal constant L_VIEW = 0;
    uint256 internal constant L_PARENT = 2;
    uint256 internal constant L_QC = 6;
    uint256 internal constant L_BODY = 8;
    uint256 internal constant L_QC_VALIDATORS = 9;
    uint256 internal constant L_COMMITTED_VALIDATORS = 10;
    uint256 internal constant BLOCK_SELECTOR_V1 = 1;
    uint256 internal constant QC_SELECTOR_V1 = 1;
    uint256 internal constant MAX_COMMITTEE = 1024;
    uint256 internal constant COMMITTEE_LIST_DEPTH = 10; // log2(1024)
    uint256 internal constant STATE_BRANCH_LENGTH = 6;
    uint256 internal constant SERVICE_ADDRESS_SLOT = 25;

    bytes internal constant G1_GENERATOR_NEG =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";
    address internal constant BLS12_PAIRING_CHECK = address(0x0f);

    bytes32 public immutable CHAIN_ID_HASH;
    bytes32 public immutable BOOTSTRAP_COMMITTEE_ROOT;
    uint64 public immutable BOOTSTRAP_HEIGHT;

    error InvalidProfile();
    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error InvalidCommittee();
    error CommitteeNotSorted();
    error CommitteeRootMismatch();
    error CommitteeChanged();
    error InvalidHeader();
    error StateRootBranchMismatch();
    error NotChildOfCertifiedBlock();
    error ViewNotConsecutive();
    error QcRootMismatch();
    error VotesNotIncreasing();
    error VoterOutOfRange();
    error QuorumNotMet();
    error SignatureEncodingMismatch();
    error BlsSignatureInvalid();
    error HeightTooOld();
    error ChainIdMismatch();
    error ServiceAddressSlotMismatch();

    constructor(Profile memory p) {
        if (bytes(p.chainId).length == 0 || p.bootstrapCommitteeRoot == bytes32(0)) revert InvalidProfile();
        CHAIN_ID_HASH = keccak256(bytes(p.chainId));
        BOOTSTRAP_COMMITTEE_ROOT = p.bootstrapCommitteeRoot;
        BOOTSTRAP_HEIGHT = p.bootstrapHeight;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   IClprVerifier
    // ─────────────────────────────────────────────────────────────────────────

    /// @inheritdoc IClprVerifier
    /// @dev proofBytes = RLP([finality, serviceAccountProof, storageProof, bundleContent
    ///      (, manifestStorageProof, manifestPreimage)]); finality = see {_verifyFinality}.
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
        if (trustAnchor.length != ANCHOR_LENGTH) revert InvalidTrustAnchor();
        bytes32 root = bytes32(trustAnchor[0:32]);
        uint64 minHeight = uint64(bytes8(trustAnchor[32:40]));
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        Memory.Slice[] memory p = RLP.decodeList(proofBytes);
        if (p.length != 4 && p.length != 6) revert InvalidPayloadShape();

        (bytes32 stateRoot,) = _verifyFinality(p[0], root, minHeight);

        bytes32 storageRoot = _verifyServiceStorageRoot(p[1], stateRoot, _toAddress(ctx.remoteServiceAddress), 0);
        metadata = _verifyChannelStorage(p[2], storageRoot, ctx.channelId);
        messagePayloads = _decodeBundleContent(RLP.readBytes(p[3]));
        newEndpointManifest = p.length == 6
            ? _verifyEndpointManifest(p[4], storageRoot, RLP.readBytes(p[5]), ctx.remoteServiceAddress)
            : _absentEndpointManifest();
        // No rotation: the committee is pinned (contract docs §5), so the anchor never changes.
        newTrustAnchor = "";
        newTrustAnchorId = "";
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes = RLP([finality, serviceAccountProof, slot25Proof, ledgerConfiguration]),
    ///      verified from the deploy-time checkpoint. endpointManifestProofBytes = empty or
    ///      RLP([manifestStorageProof, manifestPreimage]).
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
        Memory.Slice[] memory p = RLP.decodeList(configProofBytes);
        if (p.length != 4) revert InvalidPayloadShape();

        (bytes32 stateRoot, uint64 height) = _verifyFinality(p[0], BOOTSTRAP_COMMITTEE_ROOT, BOOTSTRAP_HEIGHT);

        bytes20 service;
        (chainId, service, peerConfigNanos, throttles,) = Codec.parseLedgerConfiguration(RLP.readBytes(p[3]));
        if (keccak256(bytes(chainId)) != CHAIN_ID_HASH) revert ChainIdMismatch();

        bytes32 storageRoot = _verifyServiceStorageRoot(p[1], stateRoot, address(service), 0);
        bytes32[] memory slot = new bytes32[](1);
        slot[0] = bytes32(SERVICE_ADDRESS_SLOT);
        bytes32[] memory proven = ClprEvmStateProof.verifyProvenSlots(RLP.readList(p[2]), storageRoot, slot);
        if (proven[0] != bytes32(uint256(bytes32(service)) | 0x28)) revert ServiceAddressSlotMismatch();

        serviceAddress = abi.encodePacked(service);
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        initialTrustAnchor = abi.encodePacked(BOOTSTRAP_COMMITTEE_ROOT, height);
        initialTrustAnchorId = initialTrustAnchor;
        if (endpointManifestProofBytes.length == 0) {
            endpointManifest = _uninitializedEndpointManifest(serviceAddress);
        } else {
            Memory.Slice[] memory m = RLP.decodeList(endpointManifestProofBytes);
            if (m.length != 2) revert InvalidPayloadShape();
            endpointManifest = _verifyEndpointManifest(m[0], storageRoot, RLP.readBytes(m[1]), serviceAddress);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Finality
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev finality = RLP([committee (n × 128 B uncompressed G1), headerB (11 × 32 B leaves),
    ///      stateBranch (6 × 32 B), headerB1 (11 × 32 B), qc1, qc2]);
    ///      qc = RLP([proposerIndex, height, [voterIndex…], sig96 (as in the QC), sig256 (EIP-2537 G2)]).
    ///      Returns the EVM stateRoot of B and its height.
    function _verifyFinality(Memory.Slice item, bytes32 committeeRoot, uint64 minHeight)
        internal
        view
        returns (bytes32 evmStateRoot, uint64 height)
    {
        Memory.Slice[] memory f = RLP.readList(item);
        if (f.length != 6) revert InvalidPayloadShape();

        bytes memory keys = _committee(RLP.readBytes(f[0]), committeeRoot);

        bytes32[] memory hb = _leaves(RLP.readBytes(f[1]));
        bytes32[] memory hb1 = _leaves(RLP.readBytes(f[3]));
        if (
            hb[L_COMMITTED_VALIDATORS] != committeeRoot || hb1[L_COMMITTED_VALIDATORS] != committeeRoot
                || hb1[L_QC_VALIDATORS] != committeeRoot
        ) revert CommitteeChanged();
        evmStateRoot = _openStateRoot(RLP.readBytes(f[2]), hb[L_BODY]);

        bytes32 hashB = _blockHash(hb);
        uint64 viewB = _leU64(hb[L_VIEW]);
        if (hb1[L_PARENT] != hashB) revert NotChildOfCertifiedBlock();
        if (_leU64(hb1[L_VIEW]) != viewB + 1) revert ViewNotConsecutive();

        Qc memory qc1 = _qc(f[4]);
        Qc memory qc2 = _qc(f[5]);
        height = qc1.height;
        if (height < minHeight) revert HeightTooOld();
        if (qc2.height != height + 1) revert QcRootMismatch();
        // QC1 is the one block B+1 carries: its SSZ root must be B+1's `qc` leaf.
        if (_qcRoot(qc1, viewB, hashB) != hb1[L_QC]) revert QcRootMismatch();

        _verifyQc(qc1, keys, hashB, viewB);
        _verifyQc(qc2, keys, _blockHash(hb1), viewB + 1);
    }

    // ── Committee ─────────────────────────────────────────────────────────────

    /// @dev Uncompressed keys → (strictly ascending compressed keys) → SSZ List[Bytes48, 1024] root.
    function _committee(bytes memory keys, bytes32 expectedRoot) internal pure returns (bytes memory) {
        if (keys.length == 0 || keys.length % 128 != 0) revert InvalidCommittee();
        uint256 n = keys.length / 128;
        if (n > MAX_COMMITTEE) revert InvalidCommittee();
        bytes32[] memory layer = new bytes32[](n);
        bytes32 prevHi;
        bytes16 prevLo;
        for (uint256 i; i < n; ++i) {
            bytes memory u = new bytes(128);
            assembly ("memory-safe") {
                mcopy(add(u, 32), add(add(keys, 32), mul(i, 128)), 128)
            }
            bytes memory c = ClprBls12381.compressG1(u);
            bytes32 hi;
            bytes16 lo;
            assembly ("memory-safe") {
                hi := mload(add(c, 32))
                lo := mload(add(c, 64))
            }
            if (i > 0 && (hi < prevHi || (hi == prevHi && lo <= prevLo))) revert CommitteeNotSorted();
            (prevHi, prevLo) = (hi, lo);
            layer[i] = sha256(abi.encodePacked(hi, lo, bytes16(0)));
        }
        if (_mixLength(_merkleizeLimit(layer, COMMITTEE_LIST_DEPTH), n) != expectedRoot) {
            revert CommitteeRootMismatch();
        }
        return keys;
    }

    // ── Headers ───────────────────────────────────────────────────────────────

    function _leaves(bytes memory b) internal pure returns (bytes32[] memory l) {
        if (b.length != HEADER_LEAVES * 32) revert InvalidHeader();
        l = new bytes32[](HEADER_LEAVES);
        for (uint256 i; i < HEADER_LEAVES; ++i) {
            bytes32 w;
            assembly ("memory-safe") {
                w := mload(add(add(b, 32), mul(i, 32)))
            }
            l[i] = w;
        }
    }

    /// @notice ConsensusBlock V1 hash: sha256(merkleize(11 leaves → 16) ‖ le256(1)).
    function _blockHash(bytes32[] memory leaves) internal pure returns (bytes32) {
        return _mixSelector(_merkleize(leaves), BLOCK_SELECTOR_V1);
    }

    /// @dev body_root = H(graffiti, payload_root); payload has 18 fields (32-leaf tree) and
    ///      `state_root` is field 2. branch = [field3, H(field0, field1), node(4..7), node(8..15),
    ///      node(16..31), graffiti].
    function _openStateRoot(bytes memory branch, bytes32 bodyRoot) internal pure returns (bytes32 stateRoot) {
        if (branch.length != (STATE_BRANCH_LENGTH + 1) * 32) revert InvalidHeader();
        bytes32[7] memory w;
        for (uint256 i; i < 7; ++i) {
            bytes32 x;
            assembly ("memory-safe") {
                x := mload(add(add(branch, 32), mul(i, 32)))
            }
            w[i] = x;
        }
        stateRoot = w[0];
        bytes32 node = sha256(abi.encodePacked(stateRoot, w[1])); // index 2 = left of (2,3)
        node = sha256(abi.encodePacked(w[2], node)); // right of (0..1, 2..3)
        node = sha256(abi.encodePacked(node, w[3])); // left of (0..3, 4..7)
        node = sha256(abi.encodePacked(node, w[4])); // left of (0..7, 8..15)
        node = sha256(abi.encodePacked(node, w[5])); // left of (0..15, 16..31) = payload_root
        if (sha256(abi.encodePacked(w[6], node)) != bodyRoot) revert StateRootBranchMismatch();
    }

    // ── QCs ───────────────────────────────────────────────────────────────────

    function _qc(Memory.Slice item) internal pure returns (Qc memory q) {
        Memory.Slice[] memory f = RLP.readList(item);
        if (f.length != 5) revert InvalidPayloadShape();
        uint256 prop = RLP.readUint256(f[0]);
        uint256 h = RLP.readUint256(f[1]);
        if (prop > type(uint64).max || h >= type(uint64).max) revert InvalidPayloadShape();
        // forge-lint: disable-next-line(unsafe-typecast)
        (q.proposer, q.height) = (uint64(prop), uint64(h));
        Memory.Slice[] memory v = RLP.readList(f[2]);
        q.votes = new uint64[](v.length);
        for (uint256 i; i < v.length; ++i) {
            uint256 x = RLP.readUint256(v[i]);
            if (x > type(uint64).max) revert VoterOutOfRange();
            // forge-lint: disable-next-line(unsafe-typecast)
            q.votes[i] = uint64(x);
        }
        q.sig96 = RLP.readBytes(f[3]);
        q.sig256 = RLP.readBytes(f[4]);
        if (q.sig96.length != 96 || q.sig256.length != 256) revert SignatureEncodingMismatch();
        _checkSigEncoding(q.sig96, q.sig256);
    }

    /// @notice QC V1 root: mix_in_selector(merkleize([view, proposer, block_hash, height,
    ///         htr(votes), htr(agg_sign)]), 1). Lists hash as Plasma's unbounded lists: chunks padded
    ///         to a power of two, then the length mixed in.
    function _qcRoot(Qc memory q, uint64 view_, bytes32 blockHash) internal pure returns (bytes32) {
        bytes32[] memory l = new bytes32[](6);
        l[0] = _u64Chunk(view_);
        l[1] = _u64Chunk(q.proposer);
        l[2] = blockHash;
        l[3] = _u64Chunk(q.height);
        l[4] = _votesRoot(q.votes);
        l[5] = _mixLength(_merkleize(_pack(q.sig96)), 96);
        return _mixSelector(_merkleize(l), QC_SELECTOR_V1);
    }

    function _votesRoot(uint64[] memory votes) internal pure returns (bytes32) {
        bytes memory packed;
        for (uint256 i; i < votes.length; ++i) {
            packed = abi.encodePacked(packed, _le64(votes[i]));
        }
        return _mixLength(_merkleize(_pack(packed)), votes.length);
    }

    /// @dev Strictly ascending voters, quorum n − ⌊(n−1)/3⌋, one pairing check over k+1 pairs:
    ///      Π e(pk_i, H(m_i)) · e(−G1, sig) == 1, m_i = pk_i(48) ‖ blockHash ‖ le64(height) ‖
    ///      le64(i) ‖ le64(view).
    function _verifyQc(Qc memory q, bytes memory keys, bytes32 blockHash, uint64 view_) internal view {
        uint256 n = keys.length / 128;
        uint256 k = q.votes.length;
        if (k < n - (n - 1) / 3) revert QuorumNotMet();
        bytes memory input = new bytes((k + 1) * 384);
        for (uint256 i; i < k; ++i) {
            uint64 v = q.votes[i];
            if (v >= n) revert VoterOutOfRange();
            if (i > 0 && v <= q.votes[i - 1]) revert VotesNotIncreasing();
            bytes memory pk = new bytes(128);
            assembly ("memory-safe") {
                mcopy(add(pk, 32), add(add(keys, 32), mul(v, 128)), 128)
            }
            bytes memory hm = ClprBeaconBls.hashToG2Message(
                abi.encodePacked(ClprBls12381.compressG1(pk), blockHash, _le64(q.height), _le64(v), _le64(view_))
            );
            assembly ("memory-safe") {
                let dst := add(add(input, 32), mul(i, 384))
                mcopy(dst, add(pk, 32), 128)
                mcopy(add(dst, 128), add(hm, 32), 256)
            }
        }
        bytes memory g1neg = G1_GENERATOR_NEG;
        bytes memory sig = q.sig256;
        assembly ("memory-safe") {
            let dst := add(add(input, 32), mul(k, 384))
            mcopy(dst, add(g1neg, 32), 128)
            mcopy(add(dst, 128), add(sig, 32), 256)
        }
        (bool ok, bytes memory res) = BLS12_PAIRING_CHECK.staticcall(input);
        // forge-lint: disable-next-line(unsafe-typecast)
        if (!ok || res.length != 32 || uint256(bytes32(res)) != 1) revert BlsSignatureInvalid();
    }

    /// @dev Binds the QC's 96-byte compressed signature (hashed into the QC root) to the EIP-2537
    ///      point the pairing check uses: the compression flag is set, the infinity flag is clear and
    ///      the x coordinate (x.c1 ‖ x.c0, flag bits masked) equals the point's. The y choice is not
    ///      compared: the pairing check accepts only the one point that is the aggregate signature.
    function _checkSigEncoding(bytes memory sig96, bytes memory u) internal pure {
        uint256 x0h;
        uint256 x0l;
        uint256 x1h;
        uint256 x1l;
        uint256 c0;
        uint256 c1;
        uint256 c2;
        assembly ("memory-safe") {
            let p := add(u, 32)
            x0h := mload(p)
            x0l := mload(add(p, 32))
            x1h := mload(add(p, 64))
            x1l := mload(add(p, 96))
            let q := add(sig96, 32)
            c0 := mload(q)
            c1 := mload(add(q, 32))
            c2 := mload(add(q, 64))
        }
        // Each EIP-2537 coordinate is 16 zero bytes + 48 bytes.
        if ((x0h | x1h) >> 128 != 0) revert SignatureEncodingMismatch();
        // forge-lint: disable-next-line(unsafe-typecast)
        uint8 flags = uint8(c0 >> 253); // top 3 bits only
        if (flags & 0x4 == 0 || flags & 0x2 != 0) revert SignatureEncodingMismatch(); // compressed, not infinity
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes memory x = abi.encodePacked(bytes16(uint128(x1h)), bytes32(x1l), bytes16(uint128(x0h)), bytes32(x0l));
        bytes memory c = abi.encodePacked((c0 << 3) >> 3, c1, c2);
        if (keccak256(x) != keccak256(c)) revert SignatureEncodingMismatch();
    }

    // ── SSZ (sha256) ──────────────────────────────────────────────────────────

    function _merkleize(bytes32[] memory chunks) internal pure returns (bytes32) {
        uint256 width = 1;
        while (width < chunks.length) width <<= 1;
        bytes32[] memory layer = new bytes32[](width);
        for (uint256 i; i < chunks.length; ++i) {
            layer[i] = chunks[i];
        }
        while (width > 1) {
            width >>= 1;
            for (uint256 i; i < width; ++i) {
                layer[i] = sha256(abi.encodePacked(layer[2 * i], layer[2 * i + 1]));
            }
        }
        return layer[0];
    }

    /// @dev Merkleize to a fixed depth (zero subtrees hashed on the fly, one per level).
    function _merkleizeLimit(bytes32[] memory chunks, uint256 depth) internal pure returns (bytes32) {
        bytes32[] memory layer = chunks;
        uint256 len = chunks.length; // ≥ 1
        bytes32 zero;
        for (uint256 d; d < depth; ++d) {
            uint256 next = (len + 1) / 2;
            bytes32[] memory up = new bytes32[](next);
            for (uint256 i; i < next; ++i) {
                up[i] = sha256(abi.encodePacked(layer[2 * i], 2 * i + 1 < len ? layer[2 * i + 1] : zero));
            }
            zero = sha256(abi.encodePacked(zero, zero));
            (layer, len) = (up, next);
        }
        return layer[0];
    }

    function _pack(bytes memory b) internal pure returns (bytes32[] memory c) {
        uint256 n = (b.length + 31) / 32;
        c = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            bytes32 w;
            assembly ("memory-safe") {
                w := mload(add(add(b, 32), mul(i, 32)))
            }
            uint256 rem = b.length - i * 32;
            if (rem < 32) w &= bytes32(~(type(uint256).max >> (rem * 8)));
            c[i] = w;
        }
    }

    function _mixLength(bytes32 root, uint256 len) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(root, _le256(len)));
    }

    function _mixSelector(bytes32 root, uint256 sel) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(root, _le256(sel)));
    }

    function _u64Chunk(uint64 v) internal pure returns (bytes32) {
        return bytes32(_le64(v));
    }

    function _leU64(bytes32 chunk) internal pure returns (uint64 v) {
        for (uint256 i; i < 8; ++i) {
            // forge-lint: disable-next-line(unsafe-typecast)
            v |= uint64(uint8(chunk[i])) << uint64(8 * i);
        }
    }

    function _le64(uint64 v) internal pure returns (bytes8 r) {
        uint64 x = v;
        x = ((x & 0x00ff00ff00ff00ff) << 8) | ((x >> 8) & 0x00ff00ff00ff00ff);
        x = ((x & 0x0000ffff0000ffff) << 16) | ((x >> 16) & 0x0000ffff0000ffff);
        r = bytes8((x << 32) | (x >> 32));
    }

    function _le256(uint256 v) internal pure returns (bytes32 r) {
        for (uint256 i; i < 32; ++i) {
            // forge-lint: disable-next-line(unsafe-typecast)
            r |= bytes32(uint256(uint8(v >> (8 * i))) << (8 * (31 - i)));
        }
    }
}
