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

/// @title OpStackBundleVerifierBase
/// @notice The part every verifier of an OP-Stack-derived L2 settling on Ethereum shares:
///
///         1. Ethereum sync committee → L1 execution `state_root`       ({IEthL1StateVerifier})
///         2. L1 `state_root` → an output root the chain's L1 settlement contract accepts
///                                                                        ({_verifyOutputRoot}, per family)
///         3. output root preimage → L2 `state_root`                      ({OpStackOutputRootProof.outputRoot})
///         4. L2 `state_root` → ClprService account (code hash pinned) → channel queue slots
///                                                                        ({ClprEvmBundleVerifier})
///
///         Step 2 is the only thing that differs between settlement families: dispute games
///         ({OpStackVerifierBase}: AnchorStateRegistry + DisputeGameFactory) or an output-oracle array
///         ({OpOutputOracleVerifierBase}: L2OutputOracle, OPSuccinctL2OutputOracle, AggchainFEP).
///
/// ## Trust anchor
/// The 260-byte Ethereum anchor of {EthBeaconLightClient}; its `codeHash` field pins the L2
/// ClprService's code hash. The anchor rotates with the L1 sync committee exactly as for
/// {EthMainnetVerifier}.
///
/// ## Bundle proof (top-level RLP list, 6 items; 8 with an endpoint-manifest update)
/// ```
/// [ 0: lightClientProof    RLP string wrapping the {IEthL1StateVerifier.verifyL1State} proof
///   1: settlementProof     family-specific (dispute proof / output-oracle proof)
///   2: outputRootPreimage  128 bytes: version(0) ‖ stateRoot ‖ messagePasserStorageRoot ‖ blockHash
///   3: l2AccountProof      MPT account proof of the ClprService against the L2 stateRoot
///   4: l2StorageProof      5 or 6 × [slot, proofNodes] for the channelId-derived slots
///   5: bundleContent       protobuf ClprBundleContent
///  (6: manifestStorageProof, 7: manifestPreimage) ]
/// ```
abstract contract OpStackBundleVerifierBase is ClprEvmBundleVerifier {
    enum Finality {
        /// Output roots the chain's own L1 contracts treat as final (withdrawals against them can be
        /// finalized). Trusts: the Ethereum sync committee and the chain's settlement system.
        FINALIZED,
        /// Additionally output roots that are posted but not yet final. Trusts THE PROPOSER (or, where
        /// posting requires a validity proof, whoever can still veto the output): see each family.
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
    // genesis anchor: [lightClientProof, settlementProof, outputRootPreimage, l2AccountProof,
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

    error InvalidPayloadShape();
    error InvalidConfigPayload();
    error InvalidTrustAnchor();
    error InvalidDeployment();

    constructor(Finality finality, IEthL1StateVerifier l1StateVerifier, uint64 l1GenesisTime, uint64 l1SecondsPerSlot) {
        if (address(l1StateVerifier) == address(0) || l1SecondsPerSlot == 0) revert InvalidDeployment();
        FINALITY = finality;
        L1_STATE_VERIFIER = l1StateVerifier;
        L1_GENESIS_TIME = l1GenesisTime;
        L1_SECONDS_PER_SLOT = l1SecondsPerSlot;
    }

    /// @notice Step 2: revert unless `outputRoot` is accepted at this deployment's tier by the chain's L1
    ///         settlement contract in the L1 state `l1StateRoot`, whose wall-clock time is `l1Time`.
    function _verifyOutputRoot(Memory.Slice settlementProof, bytes32 l1StateRoot, uint64 l1Time, bytes32 outputRoot)
        internal
        view
        virtual;

    /// @notice Step 4's account half: the ClprService's storage root, its code hash checked against the
    ///         anchor. Chains whose L2 account leaf is not the Ethereum 4-field list override this.
    function _verifyL2ServiceStorageRoot(
        Memory.Slice accountProofItem,
        bytes32 l2StateRoot,
        address service,
        bytes32 expectedCodeHash
    ) internal view virtual returns (bytes32) {
        return _verifyServiceStorageRoot(accountProofItem, l2StateRoot, service, expectedCodeHash);
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
        bytes32 storageRoot = _verifyL2ServiceStorageRoot(
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
            _verifyL2ServiceStorageRoot(p[IDX_L2_ACCOUNT_PROOF], l2StateRoot, _toAddress(serviceAddress), codeHash);
        return _verifyEndpointManifest(
            p[CM_IDX_MANIFEST_STORAGE_PROOF], storageRoot, RLP.readBytes(p[CM_IDX_MANIFEST_PREIMAGE]), serviceAddress
        );
    }

    /// @notice Steps 1–3 only: the L2 state root a proof commits to, under `trustAnchor`. Exposed for
    ///         relayers/monitoring and for the config path (which holds its anchor in memory).
    /// @param proof RLP list whose items 0–2 are `[lightClientProof, settlementProof, outputRootPreimage]`.
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
        _verifyOutputRoot(items[IDX_DISPUTE_PROOF], l1StateRoot, L1_GENESIS_TIME + slot * L1_SECONDS_PER_SLOT, root);
        return (l2StateRoot, na, naId);
    }
}
