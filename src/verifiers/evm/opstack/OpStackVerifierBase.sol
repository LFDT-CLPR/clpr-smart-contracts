// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {OpStackBundleVerifierBase} from "@hiero-ledger/clpr/verifiers/evm/opstack/OpStackBundleVerifierBase.sol";
import {IEthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/lib/IEthL1StateVerifier.sol";
import {OpStackOutputRootProof} from "@hiero-ledger/clpr/libraries/proof/opstack/OpStackOutputRootProof.sol";
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
/// Trust anchor and bundle layout: see {OpStackBundleVerifierBase}; item 1 of the bundle is the
/// dispute proof of {OpStackOutputRootProof.verify}.
/// @dev The per-chain facts (L1 contract addresses, pinned implementation code, finality delay, L1
///      clock, storage layout) are constructor data — a "profile" in the sense of the fork-aware
///      verifier ADR — so one audited bytecode serves every OP Stack chain with the same layout.
abstract contract OpStackVerifierBase is OpStackBundleVerifierBase {
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

    constructor(
        Finality finality,
        IEthL1StateVerifier l1StateVerifier,
        uint64 l1GenesisTime,
        uint64 l1SecondsPerSlot,
        OpStackOutputRootProof.Profile memory profile_
    ) OpStackBundleVerifierBase(finality, l1StateVerifier, l1GenesisTime, l1SecondsPerSlot) {
        if (
            profile_.anchorStateRegistry == address(0) || profile_.anchorStateRegistryImplCodeHash == bytes32(0)
                || profile_.gameImplementation == address(0)
                || (profile_.rootFormat == OpStackOutputRootProof.RootFormat.SUPER_ROOT_V1 && profile_.l2ChainId == 0)
        ) revert InvalidDeployment();
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

    /// @inheritdoc OpStackBundleVerifierBase
    /// @dev The settlement proof is the dispute proof of {OpStackOutputRootProof.verify}.
    function _verifyOutputRoot(Memory.Slice disputeProof, bytes32 l1StateRoot, uint64 l1Time, bytes32 outputRoot)
        internal
        view
        override
    {
        OpStackOutputRootProof.verify(
            profile(), disputeProof, l1StateRoot, l1Time, outputRoot, FINALITY == Finality.PROPOSED
        );
    }
}
