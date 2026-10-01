// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {OpStackOutputRootProof as OP} from "@hiero-ledger/clpr/libraries/proof/opstack/OpStackOutputRootProof.sol";

/// @title MegaEthProfile
/// @notice Deployment profile of {OpStackVerifier} / {OpStackProposedVerifier} for MegaETH (chain 4326), which
///         settles on Ethereum mainnet through Kailua games (game type 1337) respected by an OptimismPortal2
///         3.x that has no AnchorStateRegistry.
/// @dev L1 contracts (read on 2026-10-01 from Sourcify and live mainnet storage):
///        OptimismPortal 0x7f82f57F0Dd546519324392e408b01fcC7D709e8 (proxy; implementation
///          0x55400445e384393f9c1be23e7e734e8d44ed9fd9, OptimismPortal2 3.15.2) acts as the registry: it holds
///          disputeGameFactory (slot 56), disputeGameBlacklist (58), respectedGameType | respectedGameTypeUpdatedAt
///          (59) and the finality-delay immutable (302,400 s)
///        → DisputeGameFactory 0x8546840adF796875cD9AAcc5B3B048f6B2c9D563 (1.0.1, no game args)
///        → gameImpls[1337] = KailuaGame 0x8c0Ed8Dd0CcF6d596e321d81eD895ad51fE30B84 (version 0.1.0; slot 10 packs
///          createdAt | resolvedAt | status | wasRespectedGameTypeWhenCreated). Each game's rootClaim is the v0
///          output root of the L2 block in its extraData (l2BlockNumber ‖ parentIndex ‖ duplicationCounter).
///      The portal has no anchor root. Both anchor slots point at slot 2 (ResourceMetering `__gap`, always zero),
///      so ANCHOR mode always reverts with OutputRootNotAnchor; only GAME mode verifies. The verifier reads
///      `respectedGameTypeUpdatedAt` as the retirement timestamp: games created at or before it are rejected
///      (the portal accepts a game created in that same second; the verifier is one second stricter).
///
///      Trust (README §7): the Ethereum sync committee; Kailua (RISC Zero fault proofs, 7-day challenge clock);
///      one proposer in practice (the treasury's vanguard 0x6644…8EC5, whose advantage is 2^60 − 1 s); the
///      guardian, a 1-of-1 Safe 0xB2A9…E67F (pause, blacklist, respected type); and the 6-of-10 Safe
///      0x92e0…b7d6 that owns the ProxyAdmin and the DGF, with no timelock.
library MegaEthProfile {
    uint256 internal constant L2_CHAIN_ID = 4326;
    /// @dev The OptimismPortal: it is the registry on this chain.
    address internal constant ANCHOR_STATE_REGISTRY = 0x7f82f57F0Dd546519324392e408b01fcC7D709e8;
    /// @dev keccak256 of the OptimismPortal2 3.15.2 implementation's runtime code; binds the 3.5-day delay.
    bytes32 internal constant ANCHOR_STATE_REGISTRY_IMPL_CODE_HASH =
        0xb6f8eea7ffbe1cf300214a7aec117095296e02ce4dbe88d7f25866205f511b7e;
    uint256 internal constant DISPUTE_GAME_FINALITY_DELAY_SECONDS = 302_400;
    address internal constant GAME_IMPLEMENTATION = 0x8c0Ed8Dd0CcF6d596e321d81eD895ad51fE30B84;
    /// @dev DGF 1.0.1 has no game args.
    bytes32 internal constant GAME_ARGS_HASH = bytes32(0);
    uint32 internal constant GAME_TYPE = 1337;

    function profile() internal pure returns (OP.Profile memory) {
        return OP.Profile({
            rootFormat: OP.RootFormat.OUTPUT_ROOT,
            l2ChainId: L2_CHAIN_ID,
            anchorStateRegistry: ANCHOR_STATE_REGISTRY,
            anchorStateRegistryImplCodeHash: ANCHOR_STATE_REGISTRY_IMPL_CODE_HASH,
            disputeGameFinalityDelaySeconds: DISPUTE_GAME_FINALITY_DELAY_SECONDS,
            gameImplementation: GAME_IMPLEMENTATION,
            gameArgsHash: GAME_ARGS_HASH,
            layout: layout()
        });
    }

    /// @notice OptimismPortal2 3.15.2 as the registry / DGF 1.0.1 / KailuaGame 0.1.0 (Sourcify storage layouts).
    function layout() internal pure returns (OP.Layout memory) {
        return OP.Layout({
            asrDisputeGameFactorySlot: 56,
            asrAnchorGameSlot: 2, // no anchor root: ResourceMetering __gap[0], always zero
            asrStartingAnchorRootSlot: 2,
            asrBlacklistSlot: 58,
            asrRespectedGameTypeSlot: 59, // respectedGameType (0) | respectedGameTypeUpdatedAt (4)
            asrRespectedGameTypeOffset: 0,
            asrRetirementTimestampOffset: 4,
            dgfGamesSlot: 103,
            gameStateSlot: 10, // createdAt (0) | resolvedAt (8) | status (16) | wasRespected… (17)
            gameCreatedAtOffset: 0,
            gameResolvedAtOffset: 8,
            gameStatusOffset: 16,
            gameWasRespectedSlot: 10,
            gameWasRespectedOffset: 17
        });
    }
}
