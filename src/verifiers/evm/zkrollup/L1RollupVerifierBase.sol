// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {IEthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/lib/IEthL1StateVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {EthBeaconLightClient} from "@hiero-ledger/clpr/libraries/proof/beacon/EthBeaconLightClient.sol";
import {L1RollupStateRoot} from "@hiero-ledger/clpr/libraries/proof/zkrollup/L1RollupStateRoot.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title L1RollupVerifierBase
/// @notice CLPR verifier for rollups that keep their finalized L2 state roots in an Ethereum (L1)
///         contract mapping (Linea, Scroll, Morph — see README). A bundle is trusted through:
///
///         1. Ethereum sync committee → L1 execution `state_root`            ({IEthL1StateVerifier})
///         2. L1 `state_root` → rollup contract storage → finalized L2 state root
///                                                                           ({L1RollupStateRoot})
///         3. L2 state root → ClprService account (code hash pinned) → channel queue slots
///                                                                           (L2 trie, per subclass)
///
///         Step 3 depends on the rollup's L2 state trie: Ethereum's Merkle-Patricia trie for Scroll and
///         Morph ({L1RollupMptVerifier}), Linea's Poseidon2 sparse Merkle tree for Linea
///         ({LineaRollupVerifier}). Everything else (wire format, trust anchor, config) is shared.
///
/// ## Trust anchor
/// The 260-byte Ethereum anchor of {EthBeaconLightClient}; its `codeHash` field pins the L2
/// ClprService's keccak256 code hash. It rotates with the L1 sync committee as for {EthMainnetVerifier}.
///
/// ## Bundle proof (top-level RLP list, 5 items; 7 with an endpoint-manifest update)
/// ```
/// [ 0: lightClientProof    RLP string wrapping the {IEthL1StateVerifier.verifyL1State} proof
///   1: rollupProof         [key, l1AccountProof, l1StorageProof]  (see {L1RollupStateRoot})
///   2: l2AccountProof      the ClprService account proof against the L2 state root (trie-specific)
///   3: l2StorageProof      the channel-slot proof: 5 slots, or 6 with the last message's running hash
///   4: bundleContent       protobuf ClprBundleContent
///  (5: manifestStorageProof, 6: manifestPreimage) ]
/// ```
/// @dev The rollup facts (L1 contract, mapping slot, pinned implementation, first key of the current
///      trie format) are constructor data — a "profile" in the sense of the fork-aware verifier ADR — so
///      one audited bytecode per trie type serves every rollup with that layout.
abstract contract L1RollupVerifierBase is ClprEvmBundleVerifier {
    uint256 internal constant PAYLOAD_FIELDS = 5;
    uint256 internal constant PAYLOAD_FIELDS_WITH_MANIFEST = 7;
    uint256 internal constant IDX_LIGHT_CLIENT_PROOF = 0;
    uint256 internal constant IDX_ROLLUP_PROOF = 1;
    uint256 internal constant IDX_L2_ACCOUNT_PROOF = 2;
    uint256 internal constant IDX_L2_STORAGE_PROOF = 3;
    uint256 internal constant IDX_BUNDLE_CONTENT = 4;
    uint256 internal constant IDX_MANIFEST_STORAGE_PROOF = 5;
    uint256 internal constant IDX_MANIFEST_PREIMAGE = 6;

    // Config-time endpoint-manifest proof (verifyConfig's 3rd arg, when non-empty), verified under the
    // genesis anchor: [lightClientProof, rollupProof, l2AccountProof, manifestStorageProof, manifestPreimage].
    uint256 internal constant CONFIG_MANIFEST_PROOF_FIELDS = 5;
    uint256 internal constant CM_IDX_MANIFEST_STORAGE_PROOF = 3;
    uint256 internal constant CM_IDX_MANIFEST_PREIMAGE = 4;

    /// @notice Ethereum L1 light client (stateless helper).
    IEthL1StateVerifier public immutable L1_STATE_VERIFIER;
    /// @notice L1 rollup contract (proxy) holding the finalized-root mapping.
    address public immutable ROLLUP;
    /// @notice Storage slot of the finalized-root mapping.
    uint256 public immutable STATE_ROOTS_SLOT;
    /// @notice Pinned EIP-1967 implementation of {ROLLUP} (zero: not pinned).
    address public immutable ROLLUP_IMPLEMENTATION;
    /// @notice Smallest accepted mapping key.
    uint256 public immutable MIN_KEY;

    error InvalidPayloadShape();
    error InvalidConfigPayload();
    error InvalidTrustAnchor();
    error InvalidDeployment();

    constructor(IEthL1StateVerifier l1StateVerifier, L1RollupStateRoot.Profile memory profile_) {
        if (address(l1StateVerifier) == address(0) || profile_.rollup == address(0)) revert InvalidDeployment();
        L1_STATE_VERIFIER = l1StateVerifier;
        ROLLUP = profile_.rollup;
        STATE_ROOTS_SLOT = profile_.stateRootsSlot;
        ROLLUP_IMPLEMENTATION = profile_.implementation;
        MIN_KEY = profile_.minKey;
    }

    /// @notice The deployment's rollup profile.
    function profile() public view returns (L1RollupStateRoot.Profile memory) {
        return L1RollupStateRoot.Profile({
            rollup: ROLLUP, stateRootsSlot: STATE_ROOTS_SLOT, implementation: ROLLUP_IMPLEMENTATION, minKey: MIN_KEY
        });
    }

    // ── L2 trie hooks ──────────────────────────────────────────────────────

    /// @dev Prove the ClprService account against the L2 state root, enforce the pinned code hash
    ///      (skipped when zero), and return its storage root.
    function _l2ServiceStorageRoot(Memory.Slice accountProof, bytes32 l2StateRoot, address service, bytes32 codeHash)
        internal
        view
        virtual
        returns (bytes32 storageRoot);

    /// @dev Prove every slot the storage-proof item carries against the service's storage root and
    ///      return the (declared slot, proven value) pairs. The caller then picks the slots it derived
    ///      itself, so a declared slot only selects which proof to use.
    function _l2ProveSlots(Memory.Slice storageProof, bytes32 storageRoot)
        internal
        view
        virtual
        returns (bytes32[] memory slots, bytes32[] memory values);

    // ── IClprVerifier ──────────────────────────────────────────────────────

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
        if (trustAnchor.length != EthBeaconLightClient.TRUST_ANCHOR_LENGTH) {
            revert InvalidTrustAnchor();
        }
        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory payload = RLP.decodeList(proofMem);
        if (payload.length != PAYLOAD_FIELDS && payload.length != PAYLOAD_FIELDS_WITH_MANIFEST) {
            revert InvalidPayloadShape();
        }

        // Steps 1–2: L1 light client → finalized L2 state root.
        bytes32 l2StateRoot;
        (, l2StateRoot, newTrustAnchor, newTrustAnchorId) = _verifyL2StateRoot(payload, trustAnchor);

        // Step 3: ClprService account (code hash pinned by the anchor) → channel slots bound to channelId.
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        bytes32 storageRoot = _l2ServiceStorageRoot(
            payload[IDX_L2_ACCOUNT_PROOF],
            l2StateRoot,
            _toAddress(ctx.remoteServiceAddress),
            bytes32(
                trustAnchor[EthBeaconLightClient.ANCHOR_OFF_CODE_HASH:EthBeaconLightClient.ANCHOR_OFF_CODE_HASH + 32]
            )
        );
        metadata = _verifyChannelSlots(
            payload[IDX_L2_STORAGE_PROOF],
            storageRoot,
            bytes32(
                trustAnchor[EthBeaconLightClient.ANCHOR_OFF_CHANNEL_ID:EthBeaconLightClient.ANCHOR_OFF_CHANNEL_ID + 32]
            )
        );
        messagePayloads = _decodeBundleContent(RLP.readBytes(payload[IDX_BUNDLE_CONTENT]));

        if (payload.length == PAYLOAD_FIELDS_WITH_MANIFEST) {
            newEndpointManifest = _verifyManifest(
                payload[IDX_MANIFEST_STORAGE_PROOF],
                storageRoot,
                RLP.readBytes(payload[IDX_MANIFEST_PREIMAGE]),
                ctx.remoteServiceAddress
            );
        } else {
            newEndpointManifest = _absentEndpointManifest();
        }
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes is {EthMainnetVerifier}'s config RLP
    ///      `[slot, syncCommittee, gvr, forkVersion, ledgerConfiguration, codeHash]`, `codeHash` being the
    ///      L2 ClprService's.
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
        bytes memory ledgerConfiguration;
        (initialTrustAnchor, initialTrustAnchorId, ledgerConfiguration) =
            L1_STATE_VERIFIER.genesisTrustAnchor(configProofBytes, channelId);
        ClprTypes.LedgerConfiguration memory lc = ClprProtobuf.decodeControlMessage(ledgerConfiguration).config;
        serviceAddress = lc.serviceAddress;
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        chainId = lc.chainId;
        peerConfigNanos = lc.nanosSinceEpoch;
        throttles = lc.throttles;
        endpointManifest = _verifyConfigEndpointManifest(endpointManifestProofBytes, initialTrustAnchor, serviceAddress);
    }

    /// @notice Steps 1–2 only: the finalized L2 state root a proof commits to, under `trustAnchor`.
    ///         For relayers and monitoring.
    /// @param proof RLP list whose items 0–1 are `[lightClientProof, rollupProof]`.
    /// @return key the mapping key (L2 block number for Linea, batch index for Scroll and Morph)
    function verifyL2StateRoot(bytes calldata proof, bytes calldata trustAnchor)
        external
        view
        returns (uint256 key, bytes32 l2StateRoot, bytes memory newTrustAnchor, bytes memory newTrustAnchorId)
    {
        if (trustAnchor.length != EthBeaconLightClient.TRUST_ANCHOR_LENGTH) revert InvalidTrustAnchor();
        bytes memory proofMem = proof;
        Memory.Slice[] memory items = RLP.decodeList(proofMem);
        if (items.length <= IDX_ROLLUP_PROOF) revert InvalidPayloadShape();
        return _verifyL2StateRoot(items, trustAnchor);
    }

    // ── Internals ──────────────────────────────────────────────────────────

    function _verifyL2StateRoot(Memory.Slice[] memory items, bytes memory trustAnchor)
        internal
        view
        returns (uint256 key, bytes32 l2StateRoot, bytes memory newTrustAnchor, bytes memory newTrustAnchorId)
    {
        bytes32 l1StateRoot;
        (l1StateRoot,, newTrustAnchor, newTrustAnchorId) =
            L1_STATE_VERIFIER.verifyL1State(RLP.readBytes(items[IDX_LIGHT_CLIENT_PROOF]), trustAnchor);
        (key, l2StateRoot) = L1RollupStateRoot.verify(profile(), items[IDX_ROLLUP_PROOF], l1StateRoot);
    }

    /// @dev The five `Channel` slots, plus the last message's running-hash slot when the proof carries 6,
    ///      all derived from `channelId` (never taken from the proof).
    function _verifyChannelSlots(Memory.Slice storageProof, bytes32 storageRoot, bytes32 channelId)
        internal
        view
        returns (ClprTypes.QueueMetadata memory metadata)
    {
        (bytes32[] memory provenSlots, bytes32[] memory provenValues) = _l2ProveSlots(storageProof, storageRoot);
        if (provenSlots.length != 5 && provenSlots.length != 6) revert InvalidStorageProofShape();
        bytes32[] memory channelSlots = _channelMetadataSlots(channelId);
        bytes32[] memory values = new bytes32[](channelSlots.length);
        for (uint256 i = 0; i < channelSlots.length; ++i) {
            values[i] = _pick(provenSlots, provenValues, channelSlots[i]);
        }
        metadata = _buildQueueMetadata(values);
        if (provenSlots.length == 6) {
            // The 6th proof is the last sent message's running hash, which exists only once
            // nextMessageId > 0; its value is not returned, proving the slot binds the bundle to the queue.
            if (metadata.nextMessageId == 0) revert InvalidNextMessageId();
            // slither-disable-next-line unused-return
            _pick(provenSlots, provenValues, _lastMessageRunningHashSlot(channelId, uint64(metadata.nextMessageId - 1)));
        }
    }

    /// @dev The proven value of `slot`, which must be among `provenSlots`.
    function _pick(bytes32[] memory provenSlots, bytes32[] memory provenValues, bytes32 slot)
        internal
        pure
        returns (bytes32)
    {
        for (uint256 i = 0; i < provenSlots.length; ++i) {
            if (provenSlots[i] == slot) return provenValues[i];
        }
        revert ClprEvmStateProof.SlotNotProven(slot);
    }

    /// @dev Endpoint-manifest commitment slot proof + preimage binding (see
    ///      {ClprEvmBundleVerifier._verifyEndpointManifest}), with the slot proven through the L2 trie hook.
    function _verifyManifest(
        Memory.Slice manifestStorageProof,
        bytes32 storageRoot,
        bytes memory manifestProtobuf,
        bytes memory expectedServiceAddress
    ) internal view returns (ClprTypes.ClprEndpointManifest memory manifest) {
        (bytes32[] memory provenSlots, bytes32[] memory provenValues) = _l2ProveSlots(manifestStorageProof, storageRoot);
        bytes32 commitment = _pick(provenSlots, provenValues, bytes32(ENDPOINT_MANIFEST_COMMITMENT_SLOT));
        if (keccak256(manifestProtobuf) != commitment) revert ManifestCommitmentMismatch();
        manifest = ClprProtobuf.decodeEndpointManifest(manifestProtobuf);
        if (manifest.version == 0) revert ManifestVersionZero();
        if (
            expectedServiceAddress.length > 0 && keccak256(manifest.serviceAddress) != keccak256(expectedServiceAddress)
        ) {
            revert ManifestServiceAddressMismatch();
        }
    }

    /// @dev Config-time endpoint-manifest proof, verified end to end under the genesis anchor; empty →
    ///      UNINITIALIZED manifest.
    function _verifyConfigEndpointManifest(
        bytes calldata proofBytes,
        bytes memory genesisAnchor,
        bytes memory serviceAddress
    ) private view returns (ClprTypes.ClprEndpointManifest memory) {
        if (proofBytes.length == 0) return _uninitializedEndpointManifest(serviceAddress);
        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory p = RLP.decodeList(proofMem);
        if (p.length != CONFIG_MANIFEST_PROOF_FIELDS) revert InvalidConfigPayload();

        (, bytes32 l2StateRoot,,) = _verifyL2StateRoot(p, genesisAnchor);
        bytes32 codeHash;
        uint256 codeHashOffset = 0x20 + EthBeaconLightClient.ANCHOR_OFF_CODE_HASH;
        assembly ("memory-safe") {
            codeHash := mload(add(genesisAnchor, codeHashOffset))
        }
        bytes32 storageRoot =
            _l2ServiceStorageRoot(p[IDX_L2_ACCOUNT_PROOF], l2StateRoot, _toAddress(serviceAddress), codeHash);
        return _verifyManifest(
            p[CM_IDX_MANIFEST_STORAGE_PROOF], storageRoot, RLP.readBytes(p[CM_IDX_MANIFEST_PREIMAGE]), serviceAddress
        );
    }
}
