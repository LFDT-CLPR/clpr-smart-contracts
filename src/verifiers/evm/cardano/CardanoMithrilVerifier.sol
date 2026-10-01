// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprCbor} from "@hiero-ledger/clpr/libraries/proof/cardano/ClprCbor.sol";
import {ClprBlake2} from "@hiero-ledger/clpr/libraries/proof/cardano/ClprBlake2.sol";
import {ClprMithrilStm} from "@hiero-ledger/clpr/libraries/proof/cardano/ClprMithrilStm.sol";
import {ClprMithrilMessage} from "@hiero-ledger/clpr/libraries/proof/cardano/ClprMithrilMessage.sol";
import {ClprMithrilMmr} from "@hiero-ledger/clpr/libraries/proof/cardano/ClprMithrilMmr.sol";
import {ClprCardanoLedger} from "@hiero-ledger/clpr/libraries/proof/cardano/ClprCardanoLedger.sol";
import {MithrilStmVerifier} from "@hiero-ledger/clpr/verifiers/evm/cardano/MithrilStmVerifier.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title CardanoMithrilVerifier
/// @notice Cardano (#36) → Hiero CLPR verifier. A light client of Mithril, Cardano's stake-based
///         threshold multi-signature over certified chain data:
///
///   Mithril certificate      STM concatenation proof (BLS12-381 min_sig, lottery over stake) of the
///                            protocol-message hash, under the epoch's aggregate verification key (AVK)
///   epoch rotation           a certificate of epoch e signs `next_aggregate_verification_key` and
///                            `next_protocol_parameters` for e + 1 (mithril `verify_*_chaining`)
///   CardanoBlocksTransactions the certified MKMap root over `Tx/<tx id>/<block hash>/<number>/<slot>`
///                            leaves — the transaction is in that block
///   block header             Blake2b-256(header) = block hash; header → block_body_hash
///   validity                 the block body hash binds `invalid_transactions`; the transaction is
///                            not phase-2 invalid (an invalid transaction's outputs never exist)
///   transaction body         Blake2b-256(body) = transaction id; output → the CLPR state UTxO
///   queue record             inline datum (Plutus data `ChannelQueue`) of the UTxO at the CLPR
///                            script that holds the channel's thread token
///
/// ## CLPR Service on Cardano (Plutus) — the state this verifier reads
/// The CLPR Service is one Plutus script with hash `S` (28 bytes = the channel's remote service
/// address) used both as spending validator and as minting policy. Each channel has a state UTxO at
/// an address whose payment credential is `S`, holding exactly one thread token `S.<channelId>` (the
/// 32-byte channel id as asset name), with an inline datum
/// ```
/// ChannelQueue = Constr 0 [ status            : Int        -- ClprTypes.ChannelStatus
///                         , next_message_id   : Int
///                         , received_message_id : Int
///                         , sent_running_hash : ByteString -- 32 bytes
///                         , received_running_hash : ByteString -- 32 bytes
///                         , peer_endpoint_manifest_version : Int
///                         , endpoint_manifest_commitment : ByteString ] -- 0 or 32 bytes
/// ```
/// Every transaction that advances the queue spends the state UTxO and recreates it; the bundle proves
/// the output that carries the queue state the relayer delivers.
///
/// ## Trust anchor (flat, 86 bytes)
/// `epoch u64 ‖ avkRoot 32 ‖ nrLeaves u64 ‖ totalStake u64 ‖ k u64 ‖ m u64 ‖ phiU8F24 u32 ‖
///  lnMant u64 ‖ lnExpNeg u16`  — `|ln(1 − φ_f)| = lnMant · 2^-lnExpNeg` exactly as the f64 Mithril uses.
///
/// ## Bundle proof (RLP list, 8 items, or 9 with an endpoint manifest)
/// ```
/// [ 0 rotations   [cert, …] certificates of the anchor epoch, then the next, … (may be empty)
///   1 stateCert   cert carrying cardano_blocks_transactions_merkle_root, of the (rotated) anchor epoch
///   2 inclusion   [blockNumber, slot, innerPos, innerMmrSize, innerItems[], rangeStart, rangeEnd,
///                  outerPos, outerMmrSize, outerItems[]]
///   3 header      block header CBOR
///   4 body        [bodies (32-byte hash, or full CBOR), witsHash, auxHash, invalidTxs CBOR, txIndex]
///   5 txBody      transaction body CBOR
///   6 outputIndex
///   7 bundleContent  protobuf ClprBundleContent
///   8 manifest    (optional) ClprProtobuf endpoint manifest; keccak = the record's commitment ]
/// cert = [keyIds[], values[], signers[], batchValues]   (see ClprMithrilMessage / ClprMithrilStm)
/// ```
contract CardanoMithrilVerifier is ClprEvmBundleVerifier {
    using ClprCbor for bytes;

    uint256 internal constant ANCHOR_LENGTH = 86;
    uint256 internal constant SCRIPT_HASH_LENGTH = 28;
    uint256 internal constant BUNDLE_FIELDS = 8;
    uint256 internal constant CONFIG_FIELDS = 11;
    uint256 internal constant MAX_ROTATIONS = 8;
    uint8 internal constant CHANNEL_STATUS_MAX = uint8(type(ClprTypes.ChannelStatus).max);

    /// @notice The shared STM engine.
    MithrilStmVerifier public immutable STM;
    /// @notice The BLAKE2s-256 engine ({ClprBlake2sHasher}) for Mithril's MMR trees.
    address public immutable BLAKE2S;

    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error CertificateEpochMismatch(uint64 expected, uint64 got);
    error MissingMessagePart(uint8 keyId);
    error PhiFChanged();
    error TooManyRotations();
    error InclusionProofInvalid();
    error BlockRangeMismatch();
    error InvalidQueueRecord();
    error ManifestCommitmentAbsent();
    error InvalidServiceAddress();
    error WrongChainNamespace();

    struct Anchor {
        uint64 epoch;
        ClprMithrilStm.Avk avk;
        ClprMithrilStm.Params params;
    }

    struct Proven {
        bytes32 txId;
        bytes32 blockHash;
        uint64 blockNumber;
    }

    constructor(MithrilStmVerifier stm, address blake2s) {
        STM = stm;
        BLAKE2S = blake2s;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   IClprVerifier
    // ─────────────────────────────────────────────────────────────────────────

    /// @inheritdoc IClprVerifier
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
        Anchor memory a = decodeAnchor(trustAnchor);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        bytes28 script = _scriptHash(ctx.remoteServiceAddress);

        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory p = RLP.decodeList(proofMem);
        if (p.length != BUNDLE_FIELDS && p.length != BUNDLE_FIELDS + 1) revert InvalidPayloadShape();

        uint64 startEpoch = a.epoch;
        a = _applyRotations(a, RLP.readList(p[0]));
        bytes32 commitment;
        (metadata, commitment) = _provenQueue(a, p, script, ctx.channelId);
        messagePayloads = _decodeBundleContent(RLP.readBytes(p[7]));
        newEndpointManifest = p.length == BUNDLE_FIELDS + 1
            ? _verifyManifest(RLP.readBytes(p[8]), commitment, ctx.remoteServiceAddress)
            : _absentEndpointManifest();
        if (a.epoch != startEpoch) {
            newTrustAnchor = encodeAnchor(a);
            newTrustAnchorId = abi.encodePacked(a.epoch);
        }
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes = RLP `[epoch, avkRoot, nrLeaves, totalStake, k, m, phiU8F24, lnMant,
    ///      lnExpNeg, cert, ledgerConfiguration]`. The aggregate key seeds the anchor (a waypoint
    ///      bootstrap vouched for by the governance that completes the channel, as for the other
    ///      committee verifiers); `cert` must be a valid certificate of that epoch under it, which
    ///      pins the key to a live Mithril network. `endpointManifestProofBytes`, when non-empty, is a
    ///      bundle proof (no rotations, empty bundle content, with manifest) against the new anchor.
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
        bytes memory cfgMem = configProofBytes;
        Memory.Slice[] memory c = RLP.decodeList(cfgMem);
        if (c.length != CONFIG_FIELDS) revert InvalidPayloadShape();
        Anchor memory a;
        a.epoch = uint64(RLP.readUint256(c[0]));
        a.avk = ClprMithrilStm.Avk({
            root: RLP.readBytes32(c[1]),
            nrLeaves: uint64(RLP.readUint256(c[2])),
            totalStake: uint64(RLP.readUint256(c[3]))
        });
        a.params = ClprMithrilStm.Params({
            k: uint64(RLP.readUint256(c[4])),
            m: uint64(RLP.readUint256(c[5])),
            phiFixed: uint32(RLP.readUint256(c[6])),
            lnMant: uint64(RLP.readUint256(c[7])),
            lnExpNeg: uint16(RLP.readUint256(c[8]))
        });
        // round-trip through the anchor encoding (rejects out-of-range values)
        a = decodeAnchor(encodeAnchor(a));
        _verifyCertificate(a, RLP.readList(c[9]));

        ClprTypes.LedgerConfiguration memory lc = ClprProtobuf.decodeControlMessage(RLP.readBytes(c[10])).config;
        serviceAddress = lc.serviceAddress;
        _scriptHash(serviceAddress);
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        chainId = lc.chainId;
        _requireNamespace(chainId, "cip34:");
        peerConfigNanos = lc.nanosSinceEpoch;
        throttles = lc.throttles;
        initialTrustAnchor = encodeAnchor(a);
        initialTrustAnchorId = abi.encodePacked(a.epoch);

        if (endpointManifestProofBytes.length == 0) {
            endpointManifest = _uninitializedEndpointManifest(serviceAddress);
        } else {
            bytes memory mMem = endpointManifestProofBytes;
            Memory.Slice[] memory mp = RLP.decodeList(mMem);
            if (mp.length != BUNDLE_FIELDS + 1 || RLP.readList(mp[0]).length != 0) revert InvalidPayloadShape();
            (, bytes32 commitment) = _provenQueue(a, mp, _scriptHash(serviceAddress), channelId);
            endpointManifest = _verifyManifest(RLP.readBytes(mp[8]), commitment, serviceAddress);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Generic entry points (live-data checks, other consumers)
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Verify `[rotations, cert]` against `trustAnchor`; returns the signed message and the
    ///         rotated anchor (empty if unchanged). Works for any signed entity type.
    function verifyCertificate(bytes calldata proofBytes, bytes calldata trustAnchor)
        external
        view
        returns (bytes memory signedMessage, bytes memory newTrustAnchor)
    {
        Anchor memory a = decodeAnchor(trustAnchor);
        uint64 startEpoch = a.epoch;
        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory p = RLP.decodeList(proofMem);
        if (p.length != 2) revert InvalidPayloadShape();
        a = _applyRotations(a, RLP.readList(p[0]));
        signedMessage = _verifyCertificate(a, RLP.readList(p[1])).message;
        if (a.epoch != startEpoch) newTrustAnchor = encodeAnchor(a);
    }

    /// @notice Verify bundle items 0–6 for an arbitrary transaction output (no CLPR checks); returns
    ///         the transaction id, block, the raw output CBOR and the rotated anchor (empty if unchanged).
    function verifyTransactionOutput(bytes calldata proofBytes, bytes calldata trustAnchor)
        external
        view
        returns (Proven memory proven, bytes memory output, bytes memory newTrustAnchor)
    {
        Anchor memory a = decodeAnchor(trustAnchor);
        uint64 startEpoch = a.epoch;
        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory p = RLP.decodeList(proofMem);
        if (p.length != 7) revert InvalidPayloadShape();
        a = _applyRotations(a, RLP.readList(p[0]));
        bytes memory txBody;
        (proven, txBody) = _provenTransaction(a, p);
        (uint256 s, uint256 e) = ClprCardanoLedger.outputAt(txBody, RLP.readUint256(p[6]));
        output = txBody.slice(s, e - s);
        if (a.epoch != startEpoch) newTrustAnchor = encodeAnchor(a);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Proof pipeline
    // ─────────────────────────────────────────────────────────────────────────

    function _applyRotations(Anchor memory a, Memory.Slice[] memory certs) internal view returns (Anchor memory) {
        if (certs.length > MAX_ROTATIONS) revert TooManyRotations();
        for (uint256 i = 0; i < certs.length; i++) {
            ClprMithrilMessage.Parsed memory m = _verifyCertificate(a, RLP.readList(certs[i]));
            if (!m.hasNextAvk) revert MissingMessagePart(ClprMithrilMessage.NEXT_AVK);
            if (!m.hasNextParams) revert MissingMessagePart(ClprMithrilMessage.NEXT_PARAMS);
            if (m.nextPhi != a.params.phiFixed) revert PhiFChanged();
            a.epoch += 1;
            a.avk = ClprMithrilStm.Avk({root: m.nextAvkRoot, nrLeaves: m.nextAvkLeaves, totalStake: m.nextAvkTotal});
            a.params.k = m.nextK;
            a.params.m = m.nextM;
        }
        return a;
    }

    /// @dev Rebuild the protocol message, check its epoch and verify the STM signature over it.
    function _verifyCertificate(Anchor memory a, Memory.Slice[] memory cert)
        internal
        view
        returns (ClprMithrilMessage.Parsed memory m)
    {
        if (cert.length != 4) revert InvalidPayloadShape();
        Memory.Slice[] memory ids = RLP.readList(cert[0]);
        Memory.Slice[] memory vals = RLP.readList(cert[1]);
        uint256[] memory keyIds = new uint256[](ids.length);
        bytes[] memory values = new bytes[](vals.length);
        for (uint256 i = 0; i < ids.length; i++) {
            keyIds[i] = RLP.readUint256(ids[i]);
        }
        for (uint256 i = 0; i < vals.length; i++) {
            values[i] = RLP.readBytes(vals[i]);
        }
        // epoch first: cheap, and a stale certificate fails with a precise error
        bool epochFound;
        for (uint256 i = 0; i < keyIds.length && i < values.length; i++) {
            if (keyIds[i] == ClprMithrilMessage.CURRENT_EPOCH && values[i].length == 8) {
                // forge-lint: disable-next-line(unsafe-typecast)
                uint64 e = uint64(bytes8(values[i])); // length checked: 8 bytes
                if (e != a.epoch) revert CertificateEpochMismatch(a.epoch, e);
                epochFound = true;
            }
        }
        if (!epochFound) revert MissingMessagePart(ClprMithrilMessage.CURRENT_EPOCH);
        m = STM.verifyCertificate(keyIds, values, a.avk, a.params, _readBytesList(cert[2]), RLP.readBytes(cert[3]));
        if (!m.hasEpoch) revert MissingMessagePart(ClprMithrilMessage.CURRENT_EPOCH);
        if (m.epoch != a.epoch) revert CertificateEpochMismatch(a.epoch, m.epoch);
    }

    /// @dev Items 1–5: certified (tx, block) leaf → header → validity → transaction body.
    function _provenTransaction(Anchor memory a, Memory.Slice[] memory p)
        internal
        view
        returns (Proven memory r, bytes memory txBody)
    {
        ClprMithrilMessage.Parsed memory m = _verifyCertificate(a, RLP.readList(p[1]));
        if (!m.hasBlocksTxRoot) revert MissingMessagePart(ClprMithrilMessage.BLOCKS_TX_ROOT);

        bytes memory header = RLP.readBytes(p[3]);
        txBody = RLP.readBytes(p[5]);
        r.txId = ClprBlake2.b2b256(txBody);
        r.blockHash = ClprBlake2.b2b256(header);
        ClprCardanoLedger.Header memory h = ClprCardanoLedger.parseHeader(header);
        r.blockNumber = h.blockNumber;

        _checkInclusion(m.blocksTxRoot, r, h.slot, RLP.readList(p[2]));

        Memory.Slice[] memory body = RLP.readList(p[4]);
        if (body.length != 5) revert InvalidPayloadShape();
        ClprCardanoLedger.checkValidInBlock(
            h.bodyHash,
            RLP.readBytes(body[0]),
            RLP.readBytes32(body[1]),
            RLP.readBytes32(body[2]),
            RLP.readBytes(body[3]),
            txBody,
            RLP.readUint256(body[4])
        );
    }

    /// @dev `Tx/<id>/<block>/<number>/<slot>` is in the block-range tree whose `"start-end" ‖ root`
    ///      leaf is in the certified MKMap tree.
    function _checkInclusion(bytes32 certifiedRoot, Proven memory r, uint64 slot, Memory.Slice[] memory q)
        internal
        view
    {
        if (q.length != 10) revert InvalidPayloadShape();
        if (RLP.readUint256(q[0]) != r.blockNumber || RLP.readUint256(q[1]) != slot) revert InclusionProofInvalid();
        bytes memory leaf = abi.encodePacked(
            "Tx/",
            ClprMithrilMessage.toHex(abi.encodePacked(r.txId)),
            "/",
            ClprMithrilMessage.toHex(abi.encodePacked(r.blockHash)),
            "/",
            _dec(r.blockNumber),
            "/",
            _dec(slot)
        );
        bytes[] memory inner = _readBytesList(q[4]);
        for (uint256 i = 0; i < inner.length; i++) {
            if (inner[i].length != 32 && !_isLeafString(inner[i])) revert InclusionProofInvalid();
        }
        bytes memory innerRoot =
            ClprMithrilMmr.root(BLAKE2S, leaf, uint64(RLP.readUint256(q[2])), uint64(RLP.readUint256(q[3])), inner);
        uint256 start = RLP.readUint256(q[5]);
        uint256 end = RLP.readUint256(q[6]);
        if (r.blockNumber < start || r.blockNumber >= end) revert BlockRangeMismatch();
        bytes memory outerLeaf =
            abi.encodePacked(ClprMithrilMmr.b2s256(BLAKE2S, abi.encodePacked(_dec(start), "-", _dec(end), innerRoot)));
        bytes[] memory outer = _readBytesList(q[9]);
        for (uint256 i = 0; i < outer.length; i++) {
            if (outer[i].length != 32) revert InclusionProofInvalid();
        }
        bytes memory root = ClprMithrilMmr.root(
            BLAKE2S, outerLeaf, uint64(RLP.readUint256(q[7])), uint64(RLP.readUint256(q[8])), outer
        );
        if (root.length != 32 || bytes32(root) != certifiedRoot) revert InclusionProofInvalid();
    }

    /// @dev Proven state UTxO of the channel → its ChannelQueue record.
    function _provenQueue(Anchor memory a, Memory.Slice[] memory p, bytes28 script, bytes32 channelId)
        internal
        view
        returns (ClprTypes.QueueMetadata memory metadata, bytes32 commitment)
    {
        (, bytes memory txBody) = _provenTransaction(a, p);
        (uint256 s,) = ClprCardanoLedger.outputAt(txBody, RLP.readUint256(p[6]));
        bytes memory datum = ClprCardanoLedger.scriptOutputDatum(txBody, s, script, abi.encodePacked(channelId));
        (metadata, commitment) = decodeChannelQueue(datum);
    }

    /// @notice Decode the `ChannelQueue` Plutus datum (Constr 0, definite or indefinite field list).
    function decodeChannelQueue(bytes memory d)
        public
        pure
        returns (ClprTypes.QueueMetadata memory metadata, bytes32 commitment)
    {
        (uint8 major, uint256 tag, uint256 p) = d.head(0);
        if (major != ClprCbor.MAJOR_TAG || tag != 121) revert InvalidQueueRecord();
        uint256 n;
        (n, p) = d.readArray(p);
        bool indefinite = n == ClprCbor.INDEFINITE;
        if (!indefinite && n != 7) revert InvalidQueueRecord();
        uint256 v;
        (v, p) = d.readUint(p);
        if (v > CHANNEL_STATUS_MAX) revert InvalidQueueRecord();
        metadata.state = ClprTypes.ChannelStatus(v);
        (v, p) = d.readUint(p);
        if (v > type(uint64).max) revert InvalidQueueRecord();
        metadata.nextMessageId = uint64(v);
        (v, p) = d.readUint(p);
        if (v > type(uint64).max) revert InvalidQueueRecord();
        metadata.receivedMessageId = uint64(v);
        (metadata.sentRunningHash, p) = _hash32(d, p);
        (metadata.receivedRunningHash, p) = _hash32(d, p);
        (v, p) = d.readUint(p);
        if (v > type(uint64).max) revert InvalidQueueRecord();
        metadata.endpointManifestVersion = uint64(v);
        (uint256 cs, uint256 clen, uint256 np) = d.readBytesRef(p);
        if (clen == 32) {
            commitment = d.word(cs);
            if (commitment == bytes32(0)) revert InvalidQueueRecord();
        } else if (clen != 0) {
            revert InvalidQueueRecord();
        }
        p = np;
        if (indefinite) {
            if (!d.isBreak(p)) revert InvalidQueueRecord();
            p++;
        }
        if (p != d.length) revert InvalidQueueRecord();
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Anchor
    // ─────────────────────────────────────────────────────────────────────────

    function encodeAnchor(Anchor memory a) public pure returns (bytes memory) {
        return abi.encodePacked(
            a.epoch,
            a.avk.root,
            a.avk.nrLeaves,
            a.avk.totalStake,
            a.params.k,
            a.params.m,
            a.params.phiFixed,
            a.params.lnMant,
            a.params.lnExpNeg
        );
    }

    function decodeAnchor(bytes memory t) public pure returns (Anchor memory a) {
        if (t.length != ANCHOR_LENGTH) revert InvalidTrustAnchor();
        a.epoch = uint64(_be(t, 0, 8));
        a.avk.root = t.word(8);
        a.avk.nrLeaves = uint64(_be(t, 40, 8));
        a.avk.totalStake = uint64(_be(t, 48, 8));
        a.params.k = uint64(_be(t, 56, 8));
        a.params.m = uint64(_be(t, 64, 8));
        a.params.phiFixed = uint32(_be(t, 72, 4));
        a.params.lnMant = uint64(_be(t, 76, 8));
        a.params.lnExpNeg = uint16(_be(t, 84, 2));
        if (
            a.avk.nrLeaves == 0 || a.avk.totalStake == 0 || a.params.k == 0 || a.params.k > a.params.m
                || a.params.phiFixed == 0 || a.params.phiFixed > (1 << 24)
                || (a.params.phiFixed < (1 << 24) && (a.params.lnMant == 0 || a.params.lnExpNeg > 128))
        ) revert InvalidTrustAnchor();
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Helpers
    // ─────────────────────────────────────────────────────────────────────────

    function _verifyManifest(bytes memory preimage, bytes32 commitment, bytes memory expectedServiceAddress)
        internal
        pure
        returns (ClprTypes.ClprEndpointManifest memory manifest)
    {
        if (commitment == bytes32(0)) revert ManifestCommitmentAbsent();
        if (keccak256(preimage) != commitment) revert ManifestCommitmentMismatch();
        manifest = ClprProtobuf.decodeEndpointManifest(preimage);
        if (manifest.version == 0) revert ManifestVersionZero();
        if (keccak256(manifest.serviceAddress) != keccak256(expectedServiceAddress)) {
            revert ManifestServiceAddressMismatch();
        }
    }

    function _hash32(bytes memory d, uint256 p) private pure returns (bytes32 h, uint256 next) {
        (uint256 s, uint256 len, uint256 n) = d.readBytesRef(p);
        if (len != 32) revert InvalidQueueRecord();
        return (d.word(s), n);
    }

    function _scriptHash(bytes memory a) internal pure returns (bytes28 h) {
        if (a.length != SCRIPT_HASH_LENGTH) revert InvalidServiceAddress();
        assembly ("memory-safe") {
            h := mload(add(a, 0x20))
        }
    }

    function _requireNamespace(string memory chainId, bytes memory prefix) internal pure {
        bytes memory c = bytes(chainId);
        if (c.length <= prefix.length) revert WrongChainNamespace();
        for (uint256 i = 0; i < prefix.length; i++) {
            if (c[i] != prefix[i]) revert WrongChainNamespace();
        }
    }

    /// @dev A raw MKTree leaf: `Tx/<64 hex>/<64 hex>/<digits>/<digits>` or
    ///      `Block/<64 hex>/<digits>/<digits>`. Used to constrain variable-length proof items.
    function _isLeafString(bytes memory s) internal pure returns (bool) {
        uint256 p;
        uint256 hexFields;
        if (s.length > 3 && s[0] == "T" && s[1] == "x" && s[2] == "/") {
            p = 3;
            hexFields = 2;
        } else if (
            s.length > 6 && s[0] == "B" && s[1] == "l" && s[2] == "o" && s[3] == "c" && s[4] == "k" && s[5] == "/"
        ) {
            p = 6;
            hexFields = 1;
        } else {
            return false;
        }
        for (uint256 f = 0; f < hexFields; f++) {
            if (p + 65 > s.length) return false;
            for (uint256 i = 0; i < 64; i++) {
                uint8 c = uint8(s[p + i]);
                if (!((c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66))) return false;
            }
            if (s[p + 64] != "/") return false;
            p += 65;
        }
        for (uint256 f = 0; f < 2; f++) {
            uint256 d;
            while (p < s.length && uint8(s[p]) >= 0x30 && uint8(s[p]) <= 0x39) {
                p++;
                d++;
            }
            if (d == 0) return false;
            if (f == 0) {
                if (p >= s.length || s[p] != "/") return false;
                p++;
            }
        }
        return p == s.length;
    }

    /// @notice Decimal rendering used in MKTree leaves and block-range keys.
    function dec(uint256 x) external pure returns (bytes memory) {
        return _dec(x);
    }

    function _readBytesList(Memory.Slice item) internal pure returns (bytes[] memory out) {
        Memory.Slice[] memory l = RLP.readList(item);
        out = new bytes[](l.length);
        for (uint256 i = 0; i < l.length; i++) {
            out[i] = RLP.readBytes(l[i]);
        }
    }

    function _dec(uint256 x) internal pure returns (bytes memory s) {
        if (x == 0) return "0";
        uint256 len;
        for (uint256 t = x; t != 0; t /= 10) {
            len++;
        }
        s = new bytes(len);
        while (x != 0) {
            // forge-lint: disable-next-line(unsafe-typecast)
            s[--len] = bytes1(uint8(48 + (x % 10)));
            x /= 10;
        }
    }

    function _be(bytes memory b, uint256 off, uint256 n) private pure returns (uint256 v) {
        for (uint256 i = 0; i < n; i++) {
            v = (v << 8) | uint8(b[off + i]);
        }
    }
}
