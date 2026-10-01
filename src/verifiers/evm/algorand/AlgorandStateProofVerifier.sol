// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprAlgorandStateProof as SP} from "@hiero-ledger/clpr/libraries/proof/algorand/ClprAlgorandStateProof.sol";
import {ClprMsgpack as MP} from "@hiero-ledger/clpr/libraries/proof/algorand/ClprMsgpack.sol";
import {
    AlgorandStateProofAccumulator
} from "@hiero-ledger/clpr/verifiers/evm/algorand/AlgorandStateProofAccumulator.sol";

/// @title AlgorandStateProofVerifier
/// @notice Algorand → Hiero CLPR verifier. Reads state-proof intervals from the
///         {AlgorandStateProofAccumulator} and proves one application-call transaction inside them:
///
///   interval        (root, lastAttestedRound) accumulated from the channel's bootstrap root: its
///                   message commits to the 256 light block headers of the interval
///   light header    SHA-256("B256" ‖ msgpack header) at vector index round − firstAttestedRound under
///                   BlockHeadersCommitment (depth 8); the header's genesis hash must be the anchor's
///   transaction     SHA-256("TL" ‖ txid ‖ SHA-256("STIB" ‖ stib)) under the header's
///                   Sha256TxnCommitment. Algorand blocks contain only transactions that succeeded.
///   queue record    the SignedTxnInBlock is a top-level `appl` call of the CLPR application
///                   (`txn.apid` = the 8-byte remote service address) and its own log `dt.lg[i]` is an
///                   ARC-28 event `ClprQueue(byte[32],uint8,uint64,uint64,byte[32],byte[32],uint64,byte[32])`
///
/// ## CLPR Service on Algorand — the state this verifier reads
/// Algorand block headers carry no state root, so application state cannot be proven by key. The CLPR
/// Service application instead emits, in every application call that changes a channel's queue, one
/// ARC-28 log (selector = first 4 bytes of SHA-512/256 of the signature, then ARC-4 static encoding):
/// ```
/// 27fe15da ‖ channelId byte[32] ‖ status uint8 ‖ nextMessageId uint64 ‖ receivedMessageId uint64 ‖
/// sentRunningHash byte[32] ‖ receivedRunningHash byte[32] ‖ endpointManifestVersion uint64 ‖
/// endpointManifestCommitment byte[32] (zero = none)          — 157 bytes
/// ```
/// Logs of inner transactions sit under `dt.itx` and are not accepted: only the application's own
/// top-level call counts.
///
/// ## Trust anchor (64 bytes)
/// `root ‖ genesisHash` — the accumulator lineage (SHA-256 hash of the bootstrap state-proof message)
/// and the network's genesis hash. Bundles never rotate the anchor: rotation happens in the
/// accumulator, interval by interval.
///
/// ## Bundle proof: `abi.encode(BundleProof)`. Config proof: `abi.encode(ConfigProof)`.
contract AlgorandStateProofVerifier is ClprEvmBundleVerifier {
    uint256 internal constant ANCHOR_LENGTH = 64;
    uint256 internal constant APP_ID_LENGTH = 8;
    uint256 internal constant HEADER_DEPTH = 8; // log2(StateProofInterval)
    uint256 internal constant MAX_TXN_DEPTH = 20;
    bytes4 internal constant QUEUE_EVENT = 0x27fe15da;
    uint256 internal constant QUEUE_EVENT_LENGTH = 157;
    uint8 internal constant CHANNEL_STATUS_MAX = uint8(type(ClprTypes.ChannelStatus).max);

    AlgorandStateProofAccumulator public immutable ACCUMULATOR;

    struct TxProof {
        uint64 intervalLastRound;
        bytes32 blockHash;
        uint64 round;
        bytes32 txnCommitment;
        bytes headerPath; // 8 × 32, bottom-up
        uint64 txIndex;
        bytes txPath; // depth × 32, bottom-up
        bytes32 txid; // SHA-256 transaction id
        bytes stib; // SignedTxnInBlock, canonical msgpack as in the block
    }

    struct BundleProof {
        TxProof txn;
        uint256 logIndex;
        bytes bundleContent; // protobuf ClprBundleContent
        bool hasManifest;
        bytes manifest; // protobuf ClprEndpointManifest; keccak256 = the record's commitment
    }

    struct ConfigProof {
        SP.Message bootstrap; // message whose hash is the lineage root (already bootstrapped)
        bytes32 genesisHash;
        bytes ledgerConfiguration; // protobuf ClprControlMessage carrying the LedgerConfiguration
    }

    struct Proven {
        uint64 round;
        uint64 appId;
        bytes stib;
        bytes[] logs;
    }

    error InvalidTrustAnchor();
    error InvalidServiceAddress();
    error IntervalNotAccumulated(uint64 lastRound);
    error RoundOutsideInterval();
    error HeaderProofInvalid();
    error TransactionProofInvalid();
    error NotAnApplicationCall();
    error WrongApplication(uint64 appId);
    error LogMissing(uint256 index);
    error InvalidQueueRecord();
    error ChannelMismatch();
    error ManifestCommitmentAbsent();
    error WrongChainNamespace();
    error BootstrapUnknown();

    constructor(AlgorandStateProofAccumulator accumulator) {
        ACCUMULATOR = accumulator;
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
        (bytes32 root, bytes32 genesisHash) = _anchor(trustAnchor);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        uint64 appId = _appId(ctx.remoteServiceAddress);
        BundleProof memory p = abi.decode(proofBytes, (BundleProof));
        bytes32 commitment;
        (metadata, commitment) = _provenQueue(root, genesisHash, appId, ctx.channelId, p);
        messagePayloads = _decodeBundleContent(p.bundleContent);
        newEndpointManifest =
            p.hasManifest ? _manifest(p.manifest, commitment, ctx.remoteServiceAddress) : _absentEndpointManifest();
        (newTrustAnchor, newTrustAnchorId) = ("", "");
    }

    /// @inheritdoc IClprVerifier
    /// @dev The bootstrap message must already be bootstrapped in the accumulator (its hash is the
    ///      lineage root). The governance that completes the channel vouches for that message, as for
    ///      the other committee verifiers' waypoints. `endpointManifestProofBytes`, when non-empty, is a
    ///      bundle proof with a manifest against the new anchor.
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
        ConfigProof memory c = abi.decode(configProofBytes, (ConfigProof));
        bytes32 root = SP.messageHash(c.bootstrap);
        if (ACCUMULATOR.interval(root, c.bootstrap.lastAttestedRound).lastAttestedRound == 0) {
            revert BootstrapUnknown();
        }
        if (c.genesisHash == bytes32(0)) revert InvalidTrustAnchor();
        ClprTypes.LedgerConfiguration memory lc = ClprProtobuf.decodeControlMessage(c.ledgerConfiguration).config;
        serviceAddress = lc.serviceAddress;
        uint64 appId = _appId(serviceAddress);
        chainId = lc.chainId;
        if (keccak256(bytes(chainId)) != keccak256(caip2(c.genesisHash))) revert WrongChainNamespace();
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        peerConfigNanos = lc.nanosSinceEpoch;
        throttles = lc.throttles;
        initialTrustAnchor = abi.encodePacked(root, c.genesisHash);
        initialTrustAnchorId = abi.encodePacked(root);

        if (endpointManifestProofBytes.length == 0) {
            endpointManifest = _uninitializedEndpointManifest(serviceAddress);
        } else {
            BundleProof memory p = abi.decode(endpointManifestProofBytes, (BundleProof));
            if (!p.hasManifest) revert ManifestCommitmentAbsent();
            (, bytes32 commitment) = _provenQueue(root, c.genesisHash, appId, channelId, p);
            endpointManifest = _manifest(p.manifest, commitment, serviceAddress);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Generic entry point (live-data checks, other consumers)
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Prove any transaction of an accumulated interval; returns its round, application id
    ///         (0 if not an application call), the SignedTxnInBlock and its top-level logs.
    function verifyTransaction(bytes calldata txProof, bytes calldata trustAnchor)
        external
        view
        returns (Proven memory r)
    {
        (bytes32 root, bytes32 genesisHash) = _anchor(trustAnchor);
        TxProof memory t = abi.decode(txProof, (TxProof));
        _provenTransaction(root, genesisHash, t);
        r.round = t.round;
        r.stib = t.stib;
        (bool isAppl, uint64 appId, uint256 logsPos) = _appCall(t.stib);
        if (isAppl) r.appId = appId;
        if (logsPos != 0) {
            (uint8 tp, uint256 n, uint256 q) = MP.header(t.stib, logsPos);
            if (tp != MP.T_ARR) revert MP.MsgpackMalformed(logsPos);
            r.logs = new bytes[](n);
            for (uint256 i = 0; i < n; i++) {
                (uint256 s, uint256 len) = MP.readBytesRef(t.stib, q, MP.T_STR);
                r.logs[i] = _copy(t.stib, s, len);
                q = s + len;
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Proof pipeline
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Interval → light header → transaction leaf.
    function _provenTransaction(bytes32 root, bytes32 genesisHash, TxProof memory t) internal view {
        AlgorandStateProofAccumulator.Interval memory iv = ACCUMULATOR.interval(root, t.intervalLastRound);
        if (iv.lastAttestedRound == 0) revert IntervalNotAccumulated(t.intervalLastRound);
        if (t.round < iv.firstAttestedRound || t.round > iv.lastAttestedRound) revert RoundOutsideInterval();
        if (t.headerPath.length != HEADER_DEPTH * 32) revert HeaderProofInvalid();
        bytes32 leaf = SP.lightHeaderLeaf(t.blockHash, genesisHash, t.round, t.txnCommitment);
        if (SP.sha256Root(leaf, t.round - iv.firstAttestedRound, t.headerPath) != iv.blockHeadersCommitment) {
            revert HeaderProofInvalid();
        }
        if (t.txPath.length > MAX_TXN_DEPTH * 32) revert TransactionProofInvalid();
        bytes32 txRoot = SP.sha256Root(SP.txnLeaf(t.txid, t.stib), t.txIndex, t.txPath);
        if (txRoot == bytes32(0) || txRoot != t.txnCommitment) revert TransactionProofInvalid();
    }

    /// @dev Proven transaction → the CLPR application's own queue log for `channelId`.
    function _provenQueue(bytes32 root, bytes32 genesisHash, uint64 appId, bytes32 channelId, BundleProof memory p)
        internal
        view
        returns (ClprTypes.QueueMetadata memory metadata, bytes32 commitment)
    {
        _provenTransaction(root, genesisHash, p.txn);
        bytes memory stib = p.txn.stib;
        (bool isAppl, uint64 called, uint256 logsPos) = _appCall(stib);
        if (!isAppl) revert NotAnApplicationCall();
        if (called != appId) revert WrongApplication(called);
        if (logsPos == 0) revert LogMissing(p.logIndex);
        (uint8 tp, uint256 n, uint256 q) = MP.header(stib, logsPos);
        if (tp != MP.T_ARR) revert MP.MsgpackMalformed(logsPos);
        if (p.logIndex >= n) revert LogMissing(p.logIndex);
        uint256 s;
        uint256 len;
        for (uint256 i = 0; i <= p.logIndex; i++) {
            (s, len) = MP.readBytesRef(stib, q, MP.T_STR);
            q = s + len;
        }
        bytes32 logChannel;
        (metadata, commitment, logChannel) = decodeQueueEvent(_copy(stib, s, len));
        if (logChannel != channelId) revert ChannelMismatch();
    }

    /// @dev `txn.type == "appl"`, `txn.apid`, and the offset of `dt.lg` (0 if absent).
    function _appCall(bytes memory stib) internal pure returns (bool isAppl, uint64 appId, uint256 logsPos) {
        uint256 txn = MP.lookup(stib, 0, "txn");
        if (txn == 0) revert MP.MsgpackMalformed(0);
        uint256 tp = MP.lookup(stib, txn, "type");
        if (tp != 0) {
            (uint256 s, uint256 len) = MP.readBytesRef(stib, tp, MP.T_STR);
            isAppl = len == 4 && keccak256(_copy(stib, s, len)) == keccak256("appl");
        }
        uint256 ap = MP.lookup(stib, txn, "apid");
        if (ap != 0) {
            uint256 v = MP.readUint(stib, ap);
            if (v > type(uint64).max) revert MP.MsgpackMalformed(ap);
            appId = uint64(v);
        }
        uint256 dt = MP.lookup(stib, 0, "dt");
        if (dt != 0) logsPos = MP.lookup(stib, dt, "lg");
    }

    /// @notice Decode an ARC-28 `ClprQueue` log.
    function decodeQueueEvent(bytes memory e)
        public
        pure
        returns (ClprTypes.QueueMetadata memory metadata, bytes32 commitment, bytes32 channelId)
    {
        if (e.length != QUEUE_EVENT_LENGTH || bytes4(e) != QUEUE_EVENT) revert InvalidQueueRecord();
        uint256 status = uint8(e[36]);
        if (status > CHANNEL_STATUS_MAX) revert InvalidQueueRecord();
        channelId = _word(e, 4);
        metadata.state = ClprTypes.ChannelStatus(status);
        metadata.nextMessageId = uint64(bytes8(_word(e, 37)));
        metadata.receivedMessageId = uint64(bytes8(_word(e, 45)));
        metadata.sentRunningHash = _word(e, 53);
        metadata.receivedRunningHash = _word(e, 85);
        metadata.endpointManifestVersion = uint64(bytes8(_word(e, 117)));
        commitment = _word(e, 125);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Helpers
    // ─────────────────────────────────────────────────────────────────────────

    function _anchor(bytes calldata a) internal pure returns (bytes32 root, bytes32 genesisHash) {
        if (a.length != ANCHOR_LENGTH) revert InvalidTrustAnchor();
        root = bytes32(a[0:32]);
        genesisHash = bytes32(a[32:64]);
        if (root == bytes32(0) || genesisHash == bytes32(0)) revert InvalidTrustAnchor();
    }

    function _appId(bytes memory a) internal pure returns (uint64 id) {
        if (a.length != APP_ID_LENGTH) revert InvalidServiceAddress();
        id = uint64(bytes8(_word(a, 0)));
        if (id == 0) revert InvalidServiceAddress();
    }

    function _manifest(bytes memory preimage, bytes32 commitment, bytes memory expectedServiceAddress)
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

    /// @notice CAIP-2 id of the Algorand network with this genesis hash (ChainAgnostic namespaces,
    ///         algorand/caip2.md): "algorand:" ‖ the first 32 characters of the URL-safe base64 genesis
    ///         hash, i.e. base64url of its first 24 bytes.
    function caip2(bytes32 genesisHash) public pure returns (bytes memory id) {
        bytes memory alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        id = new bytes(41);
        bytes memory prefix = "algorand:";
        for (uint256 i = 0; i < 9; i++) {
            id[i] = prefix[i];
        }
        uint256 bits = uint256(genesisHash) >> 64; // first 24 bytes = 192 bits = 32 sextets
        for (uint256 i = 0; i < 32; i++) {
            id[9 + i] = alphabet[(bits >> (186 - 6 * i)) & 63];
        }
    }

    function _word(bytes memory b, uint256 off) private pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 0x20), off))
        }
    }

    function _copy(bytes memory b, uint256 s, uint256 len) private pure returns (bytes memory out) {
        out = new bytes(len);
        assembly ("memory-safe") {
            mcopy(add(out, 0x20), add(add(b, 0x20), s), len)
        }
    }
}
