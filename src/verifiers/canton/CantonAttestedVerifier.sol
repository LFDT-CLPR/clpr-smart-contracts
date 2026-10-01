// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title CantonAttestedVerifier
/// @notice Canton -> Hiero verifier. TRUST MODEL: t-of-n CLPR operators.
///
///         Canton has no global state root that a Hiero contract can check today (see
///         src/verifiers/canton/README.md). Instead, the n operators that host the decentralized
///         `clpr` party on Canton sign the head of a channel's outbound queue with secp256k1 over an
///         EIP-712 typed message, and this contract accepts the head once t distinct operators of the
///         current epoch signed it. Nothing here proves Canton finality or Canton state: a quorum of t
///         colluding operators can attest any queue head. The CLPR Service still enforces message-id
///         contiguity and recomputes the running hash over the returned payloads.
///
///         Operator-set rotations are signed by the current quorum and advance the epoch by exactly
///         one; every signature commits to (cantonParty, epoch), and the EIP-712 domain commits to this
///         chain and this contract, so signatures replay neither across epochs, Canton deployments,
///         Hiero networks nor verifier deployments.
contract CantonAttestedVerifier is IClprVerifier, EIP712 {
    // ── Constants ────────────────────────────────────────────────────────────

    /// @notice Human-readable trust label surfaced to integrators and UIs.
    string public constant TRUST_MODEL = "t-of-n CLPR operators";

    /// @notice Proof format version carried as the first field of every proof.
    uint8 public constant PROOF_VERSION = 1;

    /// @notice Upper bound on n. Bounds worst-case gas (n * ~7k for signature checks).
    uint256 public constant MAX_OPERATORS = 64;

    /// @dev One signature entry: operator index (1 byte) || r (32) || s (32) || v (1).
    uint256 internal constant SIG_ENTRY_LENGTH = 66;

    /// @dev Smallest ABI encoding of a TrustAnchor (head + empty operator array).
    uint256 internal constant MIN_TRUST_ANCHOR_LENGTH = 192;

    uint8 internal constant MAX_CHANNEL_STATUS = uint8(type(ClprTypes.ChannelStatus).max);

    bytes32 public constant ROTATION_TYPEHASH = keccak256(
        "Rotation(bytes32 cantonParty,uint64 epoch,uint64 newEpoch,uint16 newThreshold,address[] newOperators)"
    );

    bytes32 public constant QUEUE_HEAD_TYPEHASH = keccak256(
        "QueueHead(bytes32 cantonParty,uint64 epoch,bytes32 channelId,uint64 messageId,bytes32 runningHash,"
        "uint64 receivedMessageId,bytes32 receivedRunningHash,uint8 status,uint64 endpointManifestVersion,"
        "bytes[] payloads,bytes manifest)"
    );

    bytes32 public constant THROTTLES_TYPEHASH = keccak256(
        "Throttles(uint32 maxMessagesPerBundle,uint64 maxMessagePayloadBytes,uint64 maxGasPerMessage,"
        "uint32 maxQueueDepth,uint64 maxSyncBytes,uint32 maxLocalEndpoints,uint32 maxPeerEndpoints)"
    );

    bytes32 public constant CONFIG_TYPEHASH = keccak256(
        "Config(bytes32 cantonParty,uint64 epoch,bytes32 channelId,string chainId,bytes serviceAddress,"
        "uint96 peerConfigNanos,Throttles throttles)"
        "Throttles(uint32 maxMessagesPerBundle,uint64 maxMessagePayloadBytes,uint64 maxGasPerMessage,"
        "uint32 maxQueueDepth,uint64 maxSyncBytes,uint32 maxLocalEndpoints,uint32 maxPeerEndpoints)"
    );

    bytes32 public constant ENDPOINT_MANIFEST_TYPEHASH =
        keccak256("EndpointManifest(bytes32 cantonParty,uint64 epoch,bytes32 channelId,bytes manifest)");

    // ── Types ────────────────────────────────────────────────────────────────

    /// @notice Channel trust anchor: the operator set of one Canton `clpr` party at one epoch.
    ///         Stored by the CLPR Service as `abi.encode(TrustAnchor)`.
    struct TrustAnchor {
        bytes32 cantonParty; // keccak256 of the clpr party id (UTF-8) = keccak256(serviceAddress)
        uint64 epoch;
        uint16 threshold;
        address[] operators; // strictly ascending
    }

    /// @notice Successor operator set, signed by a quorum of the set it replaces.
    struct Rotation {
        uint16 newThreshold;
        address[] newOperators;
        bytes signatures;
    }

    /// @notice The attested queue state. `messageId` is the bundle's anchor message (the newest
    ///         message whose `runningHash` is attested); `payloads` are the last
    ///         `payloads.length` messages ending at `messageId`.
    struct QueueHead {
        bytes32 channelId;
        uint64 messageId;
        bytes32 runningHash;
        uint64 receivedMessageId;
        bytes32 receivedRunningHash;
        uint8 status;
        uint64 endpointManifestVersion;
    }

    struct BundleProof {
        uint8 version;
        Rotation[] rotations;
        QueueHead head;
        bytes[] payloads;
        bytes manifest; // ClprEndpointManifest protobuf, or empty
        bytes signatures;
    }

    struct ConfigProof {
        uint8 version;
        TrustAnchor genesis;
        Rotation[] rotations;
        string chainId;
        bytes serviceAddress;
        uint96 peerConfigNanos;
        ClprTypes.Throttles throttles;
        bytes signatures;
    }

    struct ManifestProof {
        bytes manifest;
        bytes signatures;
    }

    // ── Errors ───────────────────────────────────────────────────────────────

    error InvalidTrustAnchor();
    error WrongCantonParty();
    error ServiceAddressMismatch();
    error MalformedProof();
    error NonCanonicalProof();
    error UnsupportedProofVersion(uint8 version);
    error InvalidOperatorSet();
    error ChannelMismatch();
    error InvalidQueueHead();
    error GenesisMismatch();
    error WrongChainId();
    error MalformedSignatures();
    error BelowThreshold(uint256 signatures, uint256 threshold);
    error SignersNotAscending();
    error UnknownOperator(uint256 index);
    error BadSignature(uint256 index);
    error ManifestVersionZero();
    error ManifestServiceAddressMismatch();

    // ── Immutables ───────────────────────────────────────────────────────────

    /// @notice keccak256 of the Canton `clpr` party id this verifier accepts.
    bytes32 public immutable CANTON_PARTY;
    /// @notice keccak256(abi.encode(genesis TrustAnchor)); verifyConfig starts from it.
    bytes32 public immutable GENESIS_ANCHOR_HASH;
    /// @notice keccak256 of the CAIP-2-style chain id this Canton deployment reports.
    bytes32 public immutable CHAIN_ID_HASH;

    constructor(TrustAnchor memory genesis, string memory chainId) EIP712("CLPR Canton Operators", "1") {
        _validateSet(genesis.threshold, genesis.operators);
        if (genesis.cantonParty == bytes32(0)) revert InvalidTrustAnchor();
        CANTON_PARTY = genesis.cantonParty;
        GENESIS_ANCHOR_HASH = keccak256(abi.encode(genesis));
        CHAIN_ID_HASH = keccak256(bytes(chainId));
    }

    // ── IClprVerifier ────────────────────────────────────────────────────────

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
        TrustAnchor memory anchor = _decodeTrustAnchor(trustAnchor);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        if (keccak256(ctx.remoteServiceAddress) != CANTON_PARTY) revert ServiceAddressMismatch();

        BundleProof memory p = _decodeBundleProof(proofBytes);

        // 1. Operator-set rotations, each signed by the set before it.
        uint256 rotationCount = p.rotations.length;
        for (uint256 i = 0; i < rotationCount; ++i) {
            anchor = _applyRotation(anchor, p.rotations[i]);
        }

        // 2. Queue head, signed by the (possibly rotated) current set.
        QueueHead memory h = p.head;
        if (h.channelId != ctx.channelId) revert ChannelMismatch();
        if (
            h.status > MAX_CHANNEL_STATUS || p.payloads.length > h.messageId || h.messageId == type(uint64).max
                || h.receivedMessageId == type(uint64).max
        ) revert InvalidQueueHead();
        _checkQuorum(_queueHeadDigest(anchor, h, p.payloads, p.manifest), p.signatures, anchor);

        // 3. Optional endpoint manifest, covered by the same signatures.
        if (p.manifest.length > 0) {
            newEndpointManifest = _decodeManifest(p.manifest, ctx.remoteServiceAddress);
        } else {
            newEndpointManifest.endpoints = new ClprTypes.Endpoint[](0);
        }

        metadata = ClprTypes.QueueMetadata({
            nextMessageId: h.messageId + 1,
            sentRunningHash: h.runningHash,
            receivedMessageId: h.receivedMessageId,
            receivedRunningHash: h.receivedRunningHash,
            state: ClprTypes.ChannelStatus(h.status),
            endpointManifestVersion: h.endpointManifestVersion
        });
        messagePayloads = p.payloads;

        if (rotationCount > 0) {
            newTrustAnchor = abi.encode(anchor);
            newTrustAnchorId = abi.encodePacked(anchor.epoch);
        }
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes = abi.encode(ConfigProof). The proof starts from the genesis operator set
    ///      pinned at deployment, applies its rotations, and must carry a quorum of the resulting set
    ///      over the Config typed message. endpointManifestProofBytes = abi.encode(ManifestProof),
    ///      signed by that same set, or empty for bring-up.
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
        if (configProofBytes.length < 32) revert MalformedProof();
        ConfigProof memory p = abi.decode(configProofBytes, (ConfigProof));
        if (keccak256(abi.encode(p)) != keccak256(configProofBytes)) revert NonCanonicalProof();
        if (p.version != PROOF_VERSION) revert UnsupportedProofVersion(p.version);
        if (keccak256(abi.encode(p.genesis)) != GENESIS_ANCHOR_HASH) revert GenesisMismatch();

        TrustAnchor memory anchor = p.genesis;
        for (uint256 i = 0; i < p.rotations.length; ++i) {
            anchor = _applyRotation(anchor, p.rotations[i]);
        }

        if (keccak256(p.serviceAddress) != CANTON_PARTY) revert ServiceAddressMismatch();
        if (keccak256(bytes(p.chainId)) != CHAIN_ID_HASH) revert WrongChainId();
        _checkQuorum(_configDigest(anchor, channelId, p), p.signatures, anchor);

        serviceAddress = p.serviceAddress;
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );

        if (endpointManifestProofBytes.length == 0) {
            endpointManifest.serviceAddress = serviceAddress;
            endpointManifest.endpoints = new ClprTypes.Endpoint[](0);
        } else {
            if (endpointManifestProofBytes.length < 32) revert MalformedProof();
            ManifestProof memory m = abi.decode(endpointManifestProofBytes, (ManifestProof));
            if (keccak256(abi.encode(m)) != keccak256(endpointManifestProofBytes)) revert NonCanonicalProof();
            _checkQuorum(_manifestDigest(anchor, channelId, m.manifest), m.signatures, anchor);
            endpointManifest = _decodeManifest(m.manifest, serviceAddress);
        }

        return (
            channelContext,
            p.chainId,
            serviceAddress,
            p.peerConfigNanos,
            p.throttles,
            abi.encode(anchor),
            abi.encodePacked(anchor.epoch),
            endpointManifest
        );
    }

    // ── Digests (public so relays and tests can cross-check) ─────────────────

    function queueHeadDigest(
        TrustAnchor calldata anchor,
        QueueHead calldata head,
        bytes[] calldata payloads,
        bytes calldata manifest
    ) external view returns (bytes32) {
        return _queueHeadDigest(anchor, head, payloads, manifest);
    }

    function rotationDigest(TrustAnchor calldata anchor, uint16 newThreshold, address[] calldata newOperators)
        external
        view
        returns (bytes32)
    {
        return _rotationDigest(anchor, newThreshold, newOperators);
    }

    // ── Internals ────────────────────────────────────────────────────────────

    function _decodeTrustAnchor(bytes calldata raw) internal view returns (TrustAnchor memory a) {
        if (raw.length < MIN_TRUST_ANCHOR_LENGTH) revert InvalidTrustAnchor();
        a = abi.decode(raw, (TrustAnchor));
        if (a.cantonParty != CANTON_PARTY) revert WrongCantonParty();
        _validateSet(a.threshold, a.operators);
    }

    function _decodeBundleProof(bytes calldata raw) internal pure returns (BundleProof memory p) {
        // A canonical BundleProof head alone is 7 words; anything shorter cannot decode.
        if (raw.length < 32 * 7) revert MalformedProof();
        p = abi.decode(raw, (BundleProof));
        // Reject non-canonical encodings (dirty padding, aliased offsets) so one attested head has
        // exactly one valid byte representation.
        if (keccak256(abi.encode(p)) != keccak256(raw)) revert NonCanonicalProof();
        if (p.version != PROOF_VERSION) revert UnsupportedProofVersion(p.version);
    }

    function _applyRotation(TrustAnchor memory current, Rotation memory r)
        internal
        view
        returns (TrustAnchor memory next)
    {
        _validateSet(r.newThreshold, r.newOperators);
        _checkQuorum(_rotationDigest(current, r.newThreshold, r.newOperators), r.signatures, current);
        next = TrustAnchor({
            cantonParty: current.cantonParty,
            epoch: current.epoch + 1,
            threshold: r.newThreshold,
            operators: r.newOperators
        });
    }

    /// @dev n in [1, MAX_OPERATORS], n/2 < t <= n, operators non-zero and strictly ascending.
    ///      A strict majority makes any two quorums of one epoch intersect.
    function _validateSet(uint16 threshold, address[] memory operators) internal pure {
        uint256 n = operators.length;
        if (n == 0 || n > MAX_OPERATORS || threshold > n || 2 * uint256(threshold) <= n) {
            revert InvalidOperatorSet();
        }
        address prev = address(0);
        for (uint256 i = 0; i < n; ++i) {
            if (operators[i] <= prev) revert InvalidOperatorSet();
            prev = operators[i];
        }
    }

    /// @dev `sigs` is a concatenation of 66-byte entries `index || r || s || v` with strictly
    ///      ascending operator indexes; at least `threshold` entries, each recovering (low-s only)
    ///      to `operators[index]`.
    function _checkQuorum(bytes32 digest, bytes memory sigs, TrustAnchor memory anchor) internal pure {
        if (sigs.length % SIG_ENTRY_LENGTH != 0) revert MalformedSignatures();
        uint256 count = sigs.length / SIG_ENTRY_LENGTH;
        if (count < anchor.threshold) revert BelowThreshold(count, anchor.threshold);
        uint256 n = anchor.operators.length;
        uint256 next = 0; // lowest index the next entry may use
        for (uint256 i = 0; i < count; ++i) {
            uint256 idx;
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly ("memory-safe") {
                let base := add(add(sigs, 32), mul(i, SIG_ENTRY_LENGTH))
                idx := byte(0, mload(base))
                r := mload(add(base, 1))
                s := mload(add(base, 33))
                v := byte(0, mload(add(base, 65)))
            }
            if (idx < next) revert SignersNotAscending();
            if (idx >= n) revert UnknownOperator(idx);
            (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, v, r, s);
            if (err != ECDSA.RecoverError.NoError || signer != anchor.operators[idx]) revert BadSignature(idx);
            next = idx + 1;
        }
    }

    function _rotationDigest(TrustAnchor memory a, uint16 newThreshold, address[] memory newOperators)
        internal
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    ROTATION_TYPEHASH,
                    a.cantonParty,
                    a.epoch,
                    a.epoch + 1,
                    newThreshold,
                    keccak256(abi.encodePacked(newOperators))
                )
            )
        );
    }

    function _queueHeadDigest(TrustAnchor memory a, QueueHead memory h, bytes[] memory payloads, bytes memory manifest)
        internal
        view
        returns (bytes32)
    {
        uint256 k = payloads.length;
        bytes32[] memory leafs = new bytes32[](k);
        for (uint256 i = 0; i < k; ++i) {
            leafs[i] = keccak256(payloads[i]);
        }
        // Two-step encode keeps the stack shallow; the field order matches QUEUE_HEAD_TYPEHASH.
        bytes memory head = abi.encode(
            QUEUE_HEAD_TYPEHASH,
            a.cantonParty,
            a.epoch,
            h.channelId,
            h.messageId,
            h.runningHash,
            h.receivedMessageId,
            h.receivedRunningHash
        );
        return _hashTypedDataV4(
            keccak256(
                bytes.concat(
                    head,
                    abi.encode(
                        h.status, h.endpointManifestVersion, keccak256(abi.encodePacked(leafs)), keccak256(manifest)
                    )
                )
            )
        );
    }

    function _configDigest(TrustAnchor memory a, bytes32 channelId, ConfigProof memory p)
        internal
        view
        returns (bytes32)
    {
        ClprTypes.Throttles memory t = p.throttles;
        bytes32 throttlesHash = keccak256(
            abi.encode(
                THROTTLES_TYPEHASH,
                t.maxMessagesPerBundle,
                t.maxMessagePayloadBytes,
                t.maxGasPerMessage,
                t.maxQueueDepth,
                t.maxSyncBytes,
                t.maxLocalEndpoints,
                t.maxPeerEndpoints
            )
        );
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    CONFIG_TYPEHASH,
                    a.cantonParty,
                    a.epoch,
                    channelId,
                    keccak256(bytes(p.chainId)),
                    keccak256(p.serviceAddress),
                    p.peerConfigNanos,
                    throttlesHash
                )
            )
        );
    }

    function _manifestDigest(TrustAnchor memory a, bytes32 channelId, bytes memory manifest)
        internal
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(abi.encode(ENDPOINT_MANIFEST_TYPEHASH, a.cantonParty, a.epoch, channelId, keccak256(manifest)))
        );
    }

    function _decodeManifest(bytes memory manifest, bytes memory expectedServiceAddress)
        internal
        pure
        returns (ClprTypes.ClprEndpointManifest memory m)
    {
        m = ClprProtobuf.decodeEndpointManifest(manifest);
        if (m.version == 0) revert ManifestVersionZero();
        if (keccak256(m.serviceAddress) != keccak256(expectedServiceAddress)) {
            revert ManifestServiceAddressMismatch();
        }
    }
}
