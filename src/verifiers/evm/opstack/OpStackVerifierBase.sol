// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {IEthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/lib/IEthL1StateVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {EthBeaconLightClient} from "@hiero-ledger/clpr/libraries/proof/beacon/EthBeaconLightClient.sol";
import {OpStackOutputRootProof} from "@hiero-ledger/clpr/libraries/proof/opstack/OpStackOutputRootProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title OpStackVerifierBase
/// @notice CLPR verifier for OP Stack L2s that settle on Ethereum with permissionless fault proofs
///         (Base, OP Mainnet, Ink, Unichain, World Chain, … — see README). A bundle is trusted through:
///
///         1. Ethereum sync committee → L1 execution `state_root`       ({IEthL1StateVerifier})
///         2. L1 `state_root` → the chain's AnchorStateRegistry / DisputeGameFactory / dispute game
///            storage → an accepted L2 output root                       ({OpStackOutputRootProof})
///         3. output root preimage → L2 `state_root`
///         4. L2 `state_root` → ClprService account (code hash pinned) → channel queue slots
///                                                                        ({ClprEvmBundleVerifier})
///
///         Which output roots step 2 accepts is the verifier's tier, fixed at deployment:
///         FINALIZED ({OpStackVerifier}) or PROPOSED ({OpStackProposedVerifier}).
///
/// ## Trust anchor
/// The 260-byte Ethereum anchor of {EthBeaconLightClient}; its `codeHash` field pins the L2
/// ClprService's code hash. The anchor rotates with the L1 sync committee exactly as for
/// {EthMainnetVerifier}.
///
/// ## Bundle proof (top-level RLP list, 6 items; 8 with an endpoint-manifest update)
/// ```
/// [ 0: lightClientProof    RLP string wrapping the {IEthL1StateVerifier.verifyL1State} proof
///   1: disputeProof        see {OpStackOutputRootProof.verify}
///   2: outputRootPreimage  128 bytes: version(0) ‖ stateRoot ‖ messagePasserStorageRoot ‖ blockHash
///   3: l2AccountProof      MPT account proof of the ClprService against the L2 stateRoot
///   4: l2StorageProof      5 or 6 × [slot, proofNodes] for the channelId-derived slots
///   5: bundleContent       protobuf ClprBundleContent
///  (6: manifestStorageProof, 7: manifestPreimage) ]
/// ```
/// @dev The per-chain facts (L1 contract addresses, pinned implementation code, finality delay, L1
///      clock, storage layout) are constructor data — a "profile" in the sense of the fork-aware
///      verifier ADR — so one audited bytecode serves every OP Stack chain with the same layout.
abstract contract OpStackVerifierBase is ClprEvmBundleVerifier {
    enum Finality {
        /// Output roots of games the L1 fault-proof system has finalized (ASR.isGameClaimValid), or
        /// the ASR anchor root. Trusts: the Ethereum sync committee, and the chain's fault proofs.
        FINALIZED,
        /// Additionally the claimed output root of any registered, not-yet-lost game of the respected
        /// type. Trusts THE PROPOSER: a wrong proposal is accepted until someone wins a challenge.
        PROPOSED
    }

    // ── Bundle payload layout ────────────────────────────────────────────────
    uint256 internal constant PAYLOAD_FIELDS = 6;
    uint256 internal constant PAYLOAD_FIELDS_WITH_MANIFEST = 8;
    uint256 internal constant IDX_LIGHT_CLIENT_PROOF = 0;
    uint256 internal constant IDX_DISPUTE_PROOF = 1;
    uint256 internal constant IDX_OUTPUT_ROOT_PREIMAGE = 2;
    uint256 internal constant IDX_L2_ACCOUNT_PROOF = 3;
    uint256 internal constant IDX_L2_STORAGE_PROOF = 4;
    uint256 internal constant IDX_BUNDLE_CONTENT = 5;
    uint256 internal constant IDX_MANIFEST_STORAGE_PROOF = 6;
    uint256 internal constant IDX_MANIFEST_PREIMAGE = 7;

    // Config-time endpoint-manifest proof (verifyConfig's 3rd arg, when non-empty), verified under the
    // genesis anchor: [lightClientProof, disputeProof, outputRootPreimage, l2AccountProof,
    //                  manifestStorageProof, manifestPreimage].
    uint256 internal constant CONFIG_MANIFEST_PROOF_FIELDS = 6;
    uint256 internal constant CM_IDX_MANIFEST_STORAGE_PROOF = 4;
    uint256 internal constant CM_IDX_MANIFEST_PREIMAGE = 5;

    /// @notice The tier this deployment verifies at.
    Finality public immutable FINALITY;
    /// @notice Ethereum L1 light client (stateless helper).
    IEthL1StateVerifier public immutable L1_STATE_VERIFIER;
    /// @notice L1 clock: the attested beacon slot `s` has wall-clock time `L1_GENESIS_TIME + s × L1_SECONDS_PER_SLOT`.
    uint64 public immutable L1_GENESIS_TIME;
    uint64 public immutable L1_SECONDS_PER_SLOT;

    // Profile (see {OpStackOutputRootProof.Profile}); immutables, rebuilt in memory per call.
    OpStackOutputRootProof.RootFormat public immutable ROOT_FORMAT;
    uint256 public immutable L2_CHAIN_ID;
    address public immutable ANCHOR_STATE_REGISTRY;
    bytes32 public immutable ANCHOR_STATE_REGISTRY_IMPL_CODE_HASH;
    uint256 public immutable DISPUTE_GAME_FINALITY_DELAY_SECONDS;
    address public immutable GAME_IMPLEMENTATION;
    uint256 internal immutable ASR_DISPUTE_GAME_FACTORY_SLOT;
    uint256 internal immutable ASR_ANCHOR_GAME_SLOT;
    uint256 internal immutable ASR_STARTING_ANCHOR_ROOT_SLOT;
    uint256 internal immutable ASR_BLACKLIST_SLOT;
    uint256 internal immutable ASR_RESPECTED_GAME_TYPE_SLOT;
    uint256 internal immutable ASR_RESPECTED_GAME_TYPE_OFFSET;
    uint256 internal immutable ASR_RETIREMENT_TIMESTAMP_OFFSET;
    uint256 internal immutable DGF_GAMES_SLOT;
    uint256 internal immutable GAME_STATE_SLOT;
    uint256 internal immutable GAME_CREATED_AT_OFFSET;
    uint256 internal immutable GAME_RESOLVED_AT_OFFSET;
    uint256 internal immutable GAME_STATUS_OFFSET;
    uint256 internal immutable GAME_WAS_RESPECTED_SLOT;
    uint256 internal immutable GAME_WAS_RESPECTED_OFFSET;

    error InvalidPayloadShape();
    error InvalidConfigPayload();
    error InvalidTrustAnchor();
    error InvalidDeployment();

    constructor(
        Finality finality,
        IEthL1StateVerifier l1StateVerifier,
        uint64 l1GenesisTime,
        uint64 l1SecondsPerSlot,
        OpStackOutputRootProof.Profile memory profile_
    ) {
        if (
            address(l1StateVerifier) == address(0) || l1SecondsPerSlot == 0
                || profile_.anchorStateRegistry == address(0) || profile_.anchorStateRegistryImplCodeHash == bytes32(0)
                || profile_.gameImplementation == address(0)
                || (profile_.rootFormat == OpStackOutputRootProof.RootFormat.SUPER_ROOT_V1 && profile_.l2ChainId == 0)
        ) revert InvalidDeployment();
        FINALITY = finality;
        L1_STATE_VERIFIER = l1StateVerifier;
        L1_GENESIS_TIME = l1GenesisTime;
        L1_SECONDS_PER_SLOT = l1SecondsPerSlot;
        ROOT_FORMAT = profile_.rootFormat;
        L2_CHAIN_ID = profile_.l2ChainId;
        ANCHOR_STATE_REGISTRY = profile_.anchorStateRegistry;
        ANCHOR_STATE_REGISTRY_IMPL_CODE_HASH = profile_.anchorStateRegistryImplCodeHash;
        DISPUTE_GAME_FINALITY_DELAY_SECONDS = profile_.disputeGameFinalityDelaySeconds;
        GAME_IMPLEMENTATION = profile_.gameImplementation;
        OpStackOutputRootProof.Layout memory l = profile_.layout;
        ASR_DISPUTE_GAME_FACTORY_SLOT = l.asrDisputeGameFactorySlot;
        ASR_ANCHOR_GAME_SLOT = l.asrAnchorGameSlot;
        ASR_STARTING_ANCHOR_ROOT_SLOT = l.asrStartingAnchorRootSlot;
        ASR_BLACKLIST_SLOT = l.asrBlacklistSlot;
        ASR_RESPECTED_GAME_TYPE_SLOT = l.asrRespectedGameTypeSlot;
        ASR_RESPECTED_GAME_TYPE_OFFSET = l.asrRespectedGameTypeOffset;
        ASR_RETIREMENT_TIMESTAMP_OFFSET = l.asrRetirementTimestampOffset;
        DGF_GAMES_SLOT = l.dgfGamesSlot;
        GAME_STATE_SLOT = l.gameStateSlot;
        GAME_CREATED_AT_OFFSET = l.gameCreatedAtOffset;
        GAME_RESOLVED_AT_OFFSET = l.gameResolvedAtOffset;
        GAME_STATUS_OFFSET = l.gameStatusOffset;
        GAME_WAS_RESPECTED_SLOT = l.gameWasRespectedSlot;
        GAME_WAS_RESPECTED_OFFSET = l.gameWasRespectedOffset;
    }

    /// @notice The deployment's profile (addresses, pinned code, finality delay, storage layout).
    function profile() public view returns (OpStackOutputRootProof.Profile memory p) {
        p.rootFormat = ROOT_FORMAT;
        p.l2ChainId = L2_CHAIN_ID;
        p.anchorStateRegistry = ANCHOR_STATE_REGISTRY;
        p.anchorStateRegistryImplCodeHash = ANCHOR_STATE_REGISTRY_IMPL_CODE_HASH;
        p.disputeGameFinalityDelaySeconds = DISPUTE_GAME_FINALITY_DELAY_SECONDS;
        p.gameImplementation = GAME_IMPLEMENTATION;
        p.layout = OpStackOutputRootProof.Layout({
            asrDisputeGameFactorySlot: ASR_DISPUTE_GAME_FACTORY_SLOT,
            asrAnchorGameSlot: ASR_ANCHOR_GAME_SLOT,
            asrStartingAnchorRootSlot: ASR_STARTING_ANCHOR_ROOT_SLOT,
            asrBlacklistSlot: ASR_BLACKLIST_SLOT,
            asrRespectedGameTypeSlot: ASR_RESPECTED_GAME_TYPE_SLOT,
            asrRespectedGameTypeOffset: ASR_RESPECTED_GAME_TYPE_OFFSET,
            asrRetirementTimestampOffset: ASR_RETIREMENT_TIMESTAMP_OFFSET,
            dgfGamesSlot: DGF_GAMES_SLOT,
            gameStateSlot: GAME_STATE_SLOT,
            gameCreatedAtOffset: GAME_CREATED_AT_OFFSET,
            gameResolvedAtOffset: GAME_RESOLVED_AT_OFFSET,
            gameStatusOffset: GAME_STATUS_OFFSET,
            gameWasRespectedSlot: GAME_WAS_RESPECTED_SLOT,
            gameWasRespectedOffset: GAME_WAS_RESPECTED_OFFSET
        });
    }

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

        // Steps 1–3: L1 light client → accepted output root → L2 state root.
        bytes32 l2StateRoot;
        (l2StateRoot, newTrustAnchor, newTrustAnchorId) = _verifyL2StateRoot(payload, trustAnchor);

        // Step 4: ClprService account (code hash pinned by the anchor) → channel slots bound to channelId.
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        bytes32 storageRoot = _verifyServiceStorageRoot(
            payload[IDX_L2_ACCOUNT_PROOF],
            l2StateRoot,
            _toAddress(ctx.remoteServiceAddress),
            bytes32(
                trustAnchor[EthBeaconLightClient.ANCHOR_OFF_CODE_HASH:EthBeaconLightClient.ANCHOR_OFF_CODE_HASH + 32]
            )
        );
        metadata = _verifyChannelStorage(
            payload[IDX_L2_STORAGE_PROOF],
            storageRoot,
            bytes32(
                trustAnchor[EthBeaconLightClient.ANCHOR_OFF_CHANNEL_ID:EthBeaconLightClient.ANCHOR_OFF_CHANNEL_ID + 32]
            )
        );
        messagePayloads = _decodeBundleContent(RLP.readBytes(payload[IDX_BUNDLE_CONTENT]));

        if (payload.length == PAYLOAD_FIELDS_WITH_MANIFEST) {
            newEndpointManifest = _verifyEndpointManifest(
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

    /// @dev Config-time endpoint-manifest proof, verified end to end under the genesis anchor (the
    ///      config committee), exactly like a bundle's manifest; empty → UNINITIALIZED manifest.
    function _verifyConfigEndpointManifest(
        bytes calldata proofBytes,
        bytes memory genesisAnchor,
        bytes memory serviceAddress
    ) private view returns (ClprTypes.ClprEndpointManifest memory) {
        if (proofBytes.length == 0) return _uninitializedEndpointManifest(serviceAddress);
        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory p = RLP.decodeList(proofMem);
        if (p.length != CONFIG_MANIFEST_PROOF_FIELDS) revert InvalidConfigPayload();

        (bytes32 l2StateRoot,,) = _verifyL2StateRoot(p, genesisAnchor);
        bytes32 codeHash;
        uint256 codeHashOffset = 0x20 + EthBeaconLightClient.ANCHOR_OFF_CODE_HASH;
        assembly ("memory-safe") {
            codeHash := mload(add(genesisAnchor, codeHashOffset))
        }
        bytes32 storageRoot =
            _verifyServiceStorageRoot(p[IDX_L2_ACCOUNT_PROOF], l2StateRoot, _toAddress(serviceAddress), codeHash);
        return _verifyEndpointManifest(
            p[CM_IDX_MANIFEST_STORAGE_PROOF], storageRoot, RLP.readBytes(p[CM_IDX_MANIFEST_PREIMAGE]), serviceAddress
        );
    }

    /// @notice Steps 1–3 only: the L2 state root a proof commits to, under `trustAnchor`. Exposed for
    ///         relayers/monitoring and for the config path (which holds its anchor in memory).
    /// @param proof RLP list whose items 0–2 are `[lightClientProof, disputeProof, outputRootPreimage]`.
    function verifyL2StateRoot(bytes calldata proof, bytes calldata trustAnchor)
        external
        view
        returns (bytes32 l2StateRoot, bytes memory newTrustAnchor, bytes memory newTrustAnchorId)
    {
        if (trustAnchor.length != EthBeaconLightClient.TRUST_ANCHOR_LENGTH) revert InvalidTrustAnchor();
        bytes memory proofMem = proof;
        Memory.Slice[] memory items = RLP.decodeList(proofMem);
        if (items.length <= IDX_OUTPUT_ROOT_PREIMAGE) revert InvalidPayloadShape();
        return _verifyL2StateRoot(items, trustAnchor);
    }

    function _verifyL2StateRoot(Memory.Slice[] memory items, bytes memory trustAnchor)
        internal
        view
        returns (bytes32 l2StateRoot, bytes memory newTrustAnchor, bytes memory newTrustAnchorId)
    {
        (bytes32 l1StateRoot, uint64 slot, bytes memory na, bytes memory naId) =
            L1_STATE_VERIFIER.verifyL1State(RLP.readBytes(items[IDX_LIGHT_CLIENT_PROOF]), trustAnchor);
        bytes32 root;
        (root, l2StateRoot) = OpStackOutputRootProof.outputRoot(RLP.readBytes(items[IDX_OUTPUT_ROOT_PREIMAGE]));
        OpStackOutputRootProof.verify(
            profile(),
            items[IDX_DISPUTE_PROOF],
            l1StateRoot,
            L1_GENESIS_TIME + slot * L1_SECONDS_PER_SLOT,
            root,
            FINALITY == Finality.PROPOSED
        );
        return (l2StateRoot, na, naId);
    }
}
