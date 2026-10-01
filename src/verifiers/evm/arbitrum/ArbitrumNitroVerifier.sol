// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {IEthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/lib/IEthL1StateVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {EthBeaconLightClient} from "@hiero-ledger/clpr/libraries/proof/beacon/EthBeaconLightClient.sol";
import {ArbitrumAssertionProof} from "@hiero-ledger/clpr/libraries/proof/arbitrum/ArbitrumAssertionProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title ArbitrumNitroVerifier
/// @notice CLPR verifier for Arbitrum Nitro chains that settle on Ethereum with BoLD rollup contracts
///         (Arbitrum One, Arbitrum Nova, and Orbit L2s such as Robinhood Chain and Reya — see README).
///         A bundle is trusted through:
///
///         1. Ethereum sync committee → L1 execution `state_root`            ({IEthL1StateVerifier})
///         2. L1 `state_root` → rollup proxy storage (pinned logic) → a CONFIRMED assertion
///            → its L2 block hash → L2 header → L2 `state_root`            ({ArbitrumAssertionProof})
///         3. L2 `state_root` → ClprService account (code hash pinned) → channel queue slots
///                                                                          ({ClprEvmBundleVerifier})
///
///         Only confirmed assertions are accepted: trust is Ethereum's sync committee plus the chain's
///         BoLD fault proofs (and its rollup owner, who can upgrade the rollup or force-confirm). No
///         sequencer, validator or relayer is trusted.
///
/// ## Trust anchor
/// The 260-byte Ethereum anchor of {EthBeaconLightClient}; its `codeHash` field pins the L2
/// ClprService's code hash. The anchor rotates with the L1 sync committee exactly as for
/// {EthMainnetVerifier}.
///
/// ## Bundle proof (top-level RLP list, 7 items; 9 with an endpoint-manifest update)
/// ```
/// [ 0: lightClientProof    RLP string wrapping the {IEthL1StateVerifier.verifyL1State} proof
///   1: assertionProof      [rollupAccountProof, rollupStorageProof] — see {ArbitrumAssertionProof.verify}
///   2: assertionPreimage   256 bytes: parentAssertionHash ‖ abi.encode(AssertionState) ‖ inboxAcc
///   3: l2Header            RLP block header whose keccak is the assertion's L2 block hash
///   4: l2AccountProof      MPT account proof of the ClprService against the L2 stateRoot
///   5: l2StorageProof      5 or 6 × [slot, proofNodes] for the channelId-derived slots
///   6: bundleContent       protobuf ClprBundleContent
///  (7: manifestStorageProof, 8: manifestPreimage) ]
/// ```
/// @dev The per-chain facts (rollup address, pinned logic contracts, storage layout) are constructor
///      data — a profile — so one audited bytecode serves every BoLD chain with the same layout.
contract ArbitrumNitroVerifier is ClprEvmBundleVerifier {
    // ── Bundle payload layout ────────────────────────────────────────────────
    uint256 internal constant PAYLOAD_FIELDS = 7;
    uint256 internal constant PAYLOAD_FIELDS_WITH_MANIFEST = 9;
    uint256 internal constant IDX_LIGHT_CLIENT_PROOF = 0;
    uint256 internal constant IDX_ASSERTION_PROOF = 1;
    uint256 internal constant IDX_ASSERTION_PREIMAGE = 2;
    uint256 internal constant IDX_L2_HEADER = 3;
    uint256 internal constant IDX_L2_ACCOUNT_PROOF = 4;
    uint256 internal constant IDX_L2_STORAGE_PROOF = 5;
    uint256 internal constant IDX_BUNDLE_CONTENT = 6;
    uint256 internal constant IDX_MANIFEST_STORAGE_PROOF = 7;
    uint256 internal constant IDX_MANIFEST_PREIMAGE = 8;

    // Config-time endpoint-manifest proof (verifyConfig's 3rd arg, when non-empty), verified under the
    // genesis anchor: [lightClientProof, assertionProof, assertionPreimage, l2Header, l2AccountProof,
    //                  manifestStorageProof, manifestPreimage].
    uint256 internal constant CONFIG_MANIFEST_PROOF_FIELDS = 7;
    uint256 internal constant CM_IDX_MANIFEST_STORAGE_PROOF = 5;
    uint256 internal constant CM_IDX_MANIFEST_PREIMAGE = 6;

    /// @notice Ethereum L1 light client (stateless helper).
    IEthL1StateVerifier public immutable L1_STATE_VERIFIER;
    /// @notice The rollup proxy on Ethereum.
    address public immutable ROLLUP;
    /// @notice Pinned RollupAdminLogic (EIP-1967 primary implementation slot of the proxy).
    address public immutable ROLLUP_ADMIN_LOGIC;
    /// @notice Pinned RollupUserLogic (secondary implementation slot of the proxy).
    address public immutable ROLLUP_USER_LOGIC;
    uint256 internal immutable ASSERTIONS_SLOT;
    uint256 internal immutable ASSERTION_STATUS_OFFSET;

    error InvalidPayloadShape();
    error InvalidConfigPayload();
    error InvalidTrustAnchor();
    error InvalidDeployment();

    constructor(IEthL1StateVerifier l1StateVerifier, ArbitrumAssertionProof.Profile memory profile_) {
        if (
            address(l1StateVerifier) == address(0) || profile_.rollup == address(0)
                || profile_.rollupAdminLogic == address(0) || profile_.rollupUserLogic == address(0)
                || profile_.layout.assertionStatusOffset > 31
        ) revert InvalidDeployment();
        L1_STATE_VERIFIER = l1StateVerifier;
        ROLLUP = profile_.rollup;
        ROLLUP_ADMIN_LOGIC = profile_.rollupAdminLogic;
        ROLLUP_USER_LOGIC = profile_.rollupUserLogic;
        ASSERTIONS_SLOT = profile_.layout.assertionsSlot;
        ASSERTION_STATUS_OFFSET = profile_.layout.assertionStatusOffset;
    }

    /// @notice The deployment's profile (rollup, pinned logic contracts, storage layout).
    function profile() public view returns (ArbitrumAssertionProof.Profile memory p) {
        p.rollup = ROLLUP;
        p.rollupAdminLogic = ROLLUP_ADMIN_LOGIC;
        p.rollupUserLogic = ROLLUP_USER_LOGIC;
        p.layout = ArbitrumAssertionProof.Layout({
            assertionsSlot: ASSERTIONS_SLOT, assertionStatusOffset: ASSERTION_STATUS_OFFSET
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

        // Steps 1–2: L1 light client → confirmed assertion → L2 state root.
        ArbitrumAssertionProof.ConfirmedState memory s;
        (s, newTrustAnchor, newTrustAnchorId) = _verifyL2State(payload, trustAnchor);

        // Step 3: ClprService account (code hash pinned by the anchor) → channel slots bound to channelId.
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        bytes32 storageRoot = _verifyServiceStorageRoot(
            payload[IDX_L2_ACCOUNT_PROOF],
            s.l2StateRoot,
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

        (ArbitrumAssertionProof.ConfirmedState memory s,,) = _verifyL2State(p, genesisAnchor);
        bytes32 codeHash;
        uint256 codeHashOffset = 0x20 + EthBeaconLightClient.ANCHOR_OFF_CODE_HASH;
        assembly ("memory-safe") {
            codeHash := mload(add(genesisAnchor, codeHashOffset))
        }
        bytes32 storageRoot =
            _verifyServiceStorageRoot(p[IDX_L2_ACCOUNT_PROOF], s.l2StateRoot, _toAddress(serviceAddress), codeHash);
        return _verifyEndpointManifest(
            p[CM_IDX_MANIFEST_STORAGE_PROOF], storageRoot, RLP.readBytes(p[CM_IDX_MANIFEST_PREIMAGE]), serviceAddress
        );
    }

    /// @notice Steps 1–2 only: the confirmed L2 state a proof commits to, under `trustAnchor`. Exposed
    ///         for relayers/monitoring (it runs exactly the code verifyBundle runs).
    /// @param proof RLP list whose items 0–3 are `[lightClientProof, assertionProof, assertionPreimage,
    ///        l2Header]`.
    function verifyL2State(bytes calldata proof, bytes calldata trustAnchor)
        external
        view
        returns (
            ArbitrumAssertionProof.ConfirmedState memory state,
            bytes memory newTrustAnchor,
            bytes memory newTrustAnchorId
        )
    {
        if (trustAnchor.length != EthBeaconLightClient.TRUST_ANCHOR_LENGTH) {
            revert InvalidTrustAnchor();
        }
        bytes memory proofMem = proof;
        Memory.Slice[] memory items = RLP.decodeList(proofMem);
        if (items.length <= IDX_L2_HEADER) revert InvalidPayloadShape();
        return _verifyL2State(items, trustAnchor);
    }

    function _verifyL2State(Memory.Slice[] memory items, bytes memory trustAnchor)
        internal
        view
        returns (
            ArbitrumAssertionProof.ConfirmedState memory s,
            bytes memory newTrustAnchor,
            bytes memory newTrustAnchorId
        )
    {
        bytes32 l1StateRoot;
        (l1StateRoot,, newTrustAnchor, newTrustAnchorId) =
            L1_STATE_VERIFIER.verifyL1State(RLP.readBytes(items[IDX_LIGHT_CLIENT_PROOF]), trustAnchor);
        s = ArbitrumAssertionProof.verify(
            profile(),
            items[IDX_ASSERTION_PROOF],
            l1StateRoot,
            RLP.readBytes(items[IDX_ASSERTION_PREIMAGE]),
            RLP.readBytes(items[IDX_L2_HEADER])
        );
    }
}
