// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprStateProof} from "@hiero-ledger/clpr/libraries/proof/hiero/ClprStateProof.sol";
import {ClprMerkleProof} from "@hiero-ledger/clpr/libraries/proof/hiero/ClprMerkleProof.sol";
import {TSSVerifier} from "@hiero-ledger/clpr/verifiers/hiero/TSSVerifier.sol";
import {BN254Util} from "@hiero-ledger/clpr/verifiers/hiero/wraps/BN254Util.sol";

/// @title HieroVerifier
/// @notice `IClprVerifier` for bundles originating on a Hiero ledger.
/// @dev Implements a four-step bundle verification pipeline:
///      (1) decode the `StateProof` protobuf, (2) derive the Merkle block root,
///      (3) verify the TSS aggregate signature via `TSSVerifier`, (4) walk the
///      authenticated leaf paths to extract the proven `ClprChannel` and
///      message queue. Config verification decodes a `ClprLedgerConfiguration`
///      control message; if empty, returns default throttles and the pinned ledger id.
contract HieroVerifier is IClprVerifier {
    /// @notice The supplied ledger id is empty.
    error ClprHieroEmptyLedgerId();
    /// @notice The derived block root is not exactly `BLOCK_HASH_LEN` (48) bytes.
    error ClprHieroBlockHashLength(uint256 got);
    /// @notice The TSS aggregate signature check failed.
    error ClprHieroTssVerificationFailed();

    /// @notice `StateProof` carries no `signed_block_proof` (oneof field 2).
    /// @dev Without a TSS signature the verifier cannot anchor the block root;
    ///      bundle is rejected outright (same posture as `VerifyBundleCall.execute`).
    error ClprHieroBlockProofMissing();
    /// @notice `StateProof.paths` contains no `state_item_leaf`.
    /// @dev The bundle must prove at least the channel's `StateValue` leaf
    ///      against the signed block root.
    error ClprHieroNoStateItemLeaf();
    /// @notice The proven `ClprChannel` leaf's `channel_id` does not match the
    ///         local channel identity in `channelContext`.
    error ClprHieroChannelMismatch();

    /// @notice ConfigProof bytes were malformed (basic shape verification failed).
    error InvalidPayloadShape();

    /// @dev Length of a Hiero block hash (SHA-384 root).
    uint256 internal constant BLOCK_HASH_LEN = 48;

    /// @dev Length of a trust anchor `keccak256(hintsVk) ‖ wrapsStep` (32 + 32 bytes).
    uint256 internal constant VK_ANCHOR_LEN = 64;

    /// @dev Offset of the WRAPS abProof in a TSS block signature: hintVk (1096) ‖ hintSig (1632).
    uint256 internal constant ABPROOF_OFFSET = 2728;

    /// @notice keccak256 of the raw `ledgerId` bytes. Used as the fast-path equality check
    ///         against the `trustAnchor` argument supplied to `verifyBundle`.
    /// @dev    This is the verifier's only true trust anchor. The hintsVK is *not* a trust
    ///         anchor; see `_verifyHintsVkAgainstLedger`.
    bytes public ledgerId;

    /// @notice The peer's `ClprService` contract address on the Hiero ledger.
    address public immutable CLPR_SERVICE;

    /// @notice keccak256 of the initial pinned hintsVK supplied at construction.
    bytes32 public immutable INITIAL_PINNED_KEY_HASH;

    TSSVerifier public immutable TSS_VERIFIER;

    /// @param ledgerId_   The raw Hiero ledger ID bytes (network identifier).
    /// @param tssVerifier_ Pre-deployed `TSSVerifier` shared across this network.
    constructor(bytes memory ledgerId_, TSSVerifier tssVerifier_) {
        if (ledgerId_.length == 0) revert ClprHieroEmptyLedgerId();
        ledgerId = ledgerId_;
        TSS_VERIFIER = tssVerifier_;
    }

    /// @inheritdoc IClprVerifier
    /// @dev Reverts with `ClprTypes.ClprBundleStartsAtOrBeforeAcked` if the proven payloads start at or
    ///      before the proven channel's ackedMessageId. The state proof authenticates the `ClprChannel`
    ///      leaf's `service_address` directly; `channelContext` is decoded only to bind a carried
    ///      endpoint manifest to the remote service address.
    function verifyBundle(bytes calldata proofBytes, bytes calldata trustAnchor, bytes calldata channelContext)
        external
        view
        returns (
            ClprTypes.QueueMetadata memory metadata,
            bytes[] memory messagePayloads,
            bytes memory newTrustAnchor,
            bytes memory newTrustAnchorId,
            ClprTypes.ClprEndpointManifest memory newEndpointManifest
        )
    {
        // Step 1: protobuf-decode the StateProof envelope.
        ClprStateProof.StateProofDecoded memory sp = ClprStateProof.decode(proofBytes);
        if (sp.signature.length == 0) revert ClprHieroBlockProofMissing();

        // Step 2: derive the block root from the first state-item-leaf path.
        uint256 baseIdx = ClprMerkleProof.findFirstPath(sp.paths, ClprMerkleProof.LeafKind.StateItemLeaf);
        if (baseIdx == type(uint256).max) revert ClprHieroNoStateItemLeaf();
        bytes memory blockRootHash = ClprMerkleProof.computeChainedRoot(sp.paths, baseIdx);
        if (blockRootHash.length != BLOCK_HASH_LEN) revert ClprHieroBlockHashLength(blockRootHash.length);

        // Step 3: TSS aggregate-signature check. `trustAnchor` is used as a cache hint:
        // if it equals keccak256(hintsVk) for the current proof, TSSVerifier/WRAPS can
        // skip recomputing the Poseidon hash of hinTS VK. On success we return the
        // canonical keccak256(hintsVk) so callers can cache it for subsequent calls.
        bool tssValid;
        (tssValid, newTrustAnchor) = TSS_VERIFIER.verifyTss(ledgerId, sp.signature, blockRootHash, trustAnchor);
        if (!tssValid) revert ClprHieroTssVerificationFailed();
        newTrustAnchor = _advancedAnchor(trustAnchor, newTrustAnchor, sp.signature);

        // Step 4: walk every leaf path, authenticate it against `blockRootHash`, decode the
        // proven `ClprChannel` and `ClprMessageValue` leaves. Reverts inside the lib if
        // any path fails to converge or the channel leaf is absent.
        (
            ClprTypes.Channel memory channel,
            bytes[] memory payloads,
            bytes memory manifestWire,
            uint64 lastMessageId,
            bytes32 lastMessageRunningHash
        ) = ClprStateProof.extractDecodedQueueData(sp.paths, blockRootHash);
        // The payloads are contiguous and end at lastMessageId, so the first is
        // lastMessageId - payloads.length + 1, which must lie past the sender's proven
        // ackedMessageId: this ledger has already acknowledged every message at or below it.
        if (payloads.length > 0 && uint256(channel.ackedMessageId) + payloads.length > lastMessageId) {
            revert ClprTypes.ClprBundleStartsAtOrBeforeAcked();
        }

        // Step 4b: bind the proven Channel to the local channel identity.
        if (channelContext.length < 32) revert ClprHieroChannelMismatch();
        bytes32 ctxChannelId;
        assembly ("memory-safe") {
            ctxChannelId := calldataload(channelContext.offset)
        }
        if (channel.channelId != ctxChannelId) revert ClprHieroChannelMismatch();

        // Step 5: synthesize the queue metadata from the proven Channel. `next_message_id`
        // is derived (acked + 1 + bundle size) so the receiver can sanity-check the bundle's
        // monotone-id invariant against the proven Channel state.
        metadata = ClprTypes.QueueMetadata({
            nextMessageId: channel.nextMessageId,
            sentRunningHash: channel.sentRunningHash,
            receivedMessageId: channel.receivedMessageId,
            receivedRunningHash: channel.receivedRunningHash,
            state: channel.status,
            // Zero when the proven Channel carries no manifest version.
            endpointManifestVersion: channel.endpointManifestVersion,
            lastMessageId: lastMessageId,
            lastMessageRunningHash: lastMessageRunningHash
        });
        messagePayloads = payloads;
        newTrustAnchorId = "";

        // Endpoint-manifest update. Only here is the full context needed, to bind the manifest
        // to the peer's service_address.
        if (manifestWire.length > 0) {
            ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
            newEndpointManifest = _decodeAndBindManifest(manifestWire, ctx.remoteServiceAddress);
        } else {
            newEndpointManifest.endpoints = new ClprTypes.Endpoint[](0);
        }
    }

    /// @inheritdoc IClprVerifier
    function verifyConfig(bytes calldata configProofBytes, bytes32 channelId, bytes calldata endpointManifestProofBytes)
        external
        view
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

        ClprTypes.DecodedControl memory dc = ClprProtobuf.decodeControlMessage(bytes(configProofBytes));
        ClprTypes.LedgerConfiguration memory cfg = dc.config;

        chainId = cfg.chainId;
        serviceAddress = cfg.serviceAddress;
        peerConfigNanos = cfg.nanosSinceEpoch;
        throttles = cfg.throttles;
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: cfg.serviceAddress})
        );

        initialTrustAnchor = ledgerId;
        initialTrustAnchorId = "";

        // Verify + bind the endpoint manifest: decoded from its proto proof, service_address bound to
        // the peer's config service_address, keys normalized. Version MUST be >= 1; empty list is OK.
        endpointManifest = _verifyManifestStateProof(endpointManifestProofBytes, cfg.serviceAddress);
    }

    function _advancedAnchor(bytes calldata trustAnchor, bytes memory vkHash, bytes memory signature)
        internal
        pure
        returns (bytes memory)
    {
        bool hasVk = trustAnchor.length == VK_ANCHOR_LEN;
        if (hasVk && keccak256(trustAnchor[:32]) == keccak256(vkHash)) return "";
        uint256 step = _wrapsStep(signature);
        if (hasVk && step <= abi.decode(trustAnchor[32:], (uint256))) return "";
        return abi.encodePacked(vkHash, step);
    }

    /// @dev The WRAPS Nova IVC step `i`, the abProof's leading 32-byte little-endian field element.
    function _wrapsStep(bytes memory signature) internal pure returns (uint256) {
        bytes32 raw;
        assembly ("memory-safe") {
            raw := mload(add(add(signature, 0x20), ABPROOF_OFFSET))
        }
        return BN254Util._bswap32(uint256(raw));
    }

    /// @dev Verify a config-time endpoint-manifest proof: a full Hiero `StateProof` carrying a
    ///      `ClprEndpointManifest` state-item leaf.
    function _verifyManifestStateProof(bytes calldata proofBytes, bytes memory expectedServiceAddress)
        internal
        view
        returns (ClprTypes.ClprEndpointManifest memory manifest)
    {
        if (proofBytes.length == 0) {
            manifest.serviceAddress = expectedServiceAddress;
            manifest.endpoints = new ClprTypes.Endpoint[](0);
            return manifest;
        }

        ClprStateProof.StateProofDecoded memory sp = ClprStateProof.decode(proofBytes);
        if (sp.signature.length == 0) revert ClprHieroBlockProofMissing();

        uint256 baseIdx = ClprMerkleProof.findFirstPath(sp.paths, ClprMerkleProof.LeafKind.StateItemLeaf);
        if (baseIdx == type(uint256).max) revert ClprHieroNoStateItemLeaf();
        bytes memory blockRootHash = ClprMerkleProof.computeChainedRoot(sp.paths, baseIdx);
        if (blockRootHash.length != BLOCK_HASH_LEN) revert ClprHieroBlockHashLength(blockRootHash.length);

        (bool tssValid,) = TSS_VERIFIER.verifyTss(ledgerId, sp.signature, blockRootHash, "");
        if (!tssValid) revert ClprHieroTssVerificationFailed();

        bytes memory manifestWire = ClprStateProof.extractManifestWire(sp.paths, blockRootHash);
        if (manifestWire.length == 0) revert ClprTypes.VerifyFailed("manifest leaf missing");
        return _decodeAndBindManifest(manifestWire, expectedServiceAddress);
    }

    /// @dev Decode a proto `ClprEndpointManifest` from `proofBytes` and bind it: require
    ///      version >= 1 and (when `expectedServiceAddress` is non-empty) require the manifest's
    ///      serviceAddress to match it. An empty endpoint list is permitted. An empty `proofBytes`
    ///      yields the UNINITIALIZED manifest (version 0): the Channel then stores
    ///      endpointManifestVersion = 0 so the first proven manifest (version >= 1, including a
    ///      peer's genuine version-1 manifest) strictly exceeds it and applies via Step 1b.
    function _decodeAndBindManifest(bytes memory proofBytes, bytes memory expectedServiceAddress)
        internal
        pure
        returns (ClprTypes.ClprEndpointManifest memory manifest)
    {
        if (proofBytes.length == 0) {
            manifest.serviceAddress = expectedServiceAddress;
            manifest.endpoints = new ClprTypes.Endpoint[](0);
            return manifest;
        }
        manifest = ClprProtobuf.decodeEndpointManifest(proofBytes);
        if (manifest.version == 0) revert ClprTypes.VerifyFailed("manifest version 0");
        if (
            expectedServiceAddress.length > 0 && keccak256(manifest.serviceAddress) != keccak256(expectedServiceAddress)
        ) {
            revert ClprTypes.VerifyFailed("manifest service_address mismatch");
        }
    }
}
