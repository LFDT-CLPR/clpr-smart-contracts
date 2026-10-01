// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {OpStackOutputRootProof as OP} from "@hiero-ledger/clpr/libraries/proof/opstack/OpStackOutputRootProof.sol";

/// @title UnichainProfile
/// @notice Deployment profile of {OpStackVerifier} / {OpStackProposedVerifier} for Unichain (chain 130), which
///         settles on Ethereum mainnet through permissionless SuperFaultDisputeGames (game type 9) claiming
///         interop super roots.
/// @dev L1 contracts (read on 2026-10-01 from Sourcify and live mainnet storage; Superchain registry):
///        OptimismPortal 0x0bd48f6B86a26D3a217d0Fa6FfE2B491B956A7a2 (5.8.0)
///        → AnchorStateRegistry 0x27Cf508E4E3Aa8d30b3226aC3b5Ea0e8bcaCAFF9 (proxy; implementation
///          0x8f40cc98d694ab986f026c5383a181fcc9b6b281, version 3.9.0, Ronin's bytecode)
///        → DisputeGameFactory 0x2F12d621a16e2d3285929C9996f478508951dFe4 (1.6.1)
///        → gameImpls[9] = SuperFaultDisputeGame 0.8.0 0x19AF533Cc2A2A55786DCB8672aA5717e64213208 (V2:
///          configured by gameArgs[9] = absolute prestate 0x031ac6f1…e1df, VM 0xacc0…5cfa, ASR, WETH
///          0x74ad…2fcf, L2 chain id 0 for super games).
///      Each game's extraData is the whole super-root preimage `0x01 ‖ timestamp ‖ (130 ‖ outputRoot)` (the
///      dependency set is Unichain alone) and its rootClaim is its keccak256. The ASR has no anchor game
///      since its re-initialisation: the anchor root is the starting anchor root (a super root).
///
///      Trust (README §7): the Ethereum sync committee; the permissionless fault proof (Cannon, 3.5-day
///      clocks); the Superchain guardian 0x09f7…dAf2 (pause, blacklist, retire); and the 2-of-2 Safe
///      0x5a0A…3d2A (Optimism Foundation and Security Council) that owns the ProxyAdmin and the DGF.
library UnichainProfile {
    uint256 internal constant L2_CHAIN_ID = 130;
    address internal constant ANCHOR_STATE_REGISTRY = 0x27Cf508E4E3Aa8d30b3226aC3b5Ea0e8bcaCAFF9;
    /// @dev keccak256 of the ASR 3.9.0 implementation's runtime code; binds the 3.5-day delay.
    bytes32 internal constant ANCHOR_STATE_REGISTRY_IMPL_CODE_HASH =
        0x3f54fcc2d17726f6c927da08dec4dbfbecc43a013fd309344ecd2cace85ae36d;
    uint256 internal constant DISPUTE_GAME_FINALITY_DELAY_SECONDS = 302_400;
    address internal constant GAME_IMPLEMENTATION = 0x19AF533Cc2A2A55786DCB8672aA5717e64213208;
    /// @dev keccak256(DisputeGameFactory.gameArgs(9)), 124 bytes.
    bytes32 internal constant GAME_ARGS_HASH = 0xa8b484d71cba05e23a78f585f0b52d044f4d77d9011e16a8fd69cec591b67e32;
    uint32 internal constant GAME_TYPE = 9;

    function profile() internal pure returns (OP.Profile memory) {
        return OP.Profile({
            rootFormat: OP.RootFormat.SUPER_ROOT_V1,
            l2ChainId: L2_CHAIN_ID,
            anchorStateRegistry: ANCHOR_STATE_REGISTRY,
            anchorStateRegistryImplCodeHash: ANCHOR_STATE_REGISTRY_IMPL_CODE_HASH,
            disputeGameFinalityDelaySeconds: DISPUTE_GAME_FINALITY_DELAY_SECONDS,
            gameImplementation: GAME_IMPLEMENTATION,
            gameArgsHash: GAME_ARGS_HASH,
            layout: layout()
        });
    }

    /// @notice ASR 3.9.0 / DGF 1.6.1 / SuperFaultDisputeGame 0.8.0 (Sourcify storage layouts).
    function layout() internal pure returns (OP.Layout memory) {
        return OP.Layout({
            asrDisputeGameFactorySlot: 1,
            asrAnchorGameSlot: 2,
            asrStartingAnchorRootSlot: 3,
            asrBlacklistSlot: 5,
            asrRespectedGameTypeSlot: 6,
            asrRespectedGameTypeOffset: 0,
            asrRetirementTimestampOffset: 4,
            dgfGamesSlot: 103,
            gameStateSlot: 0, // createdAt (0) | resolvedAt (8) | status (16)
            gameCreatedAtOffset: 0,
            gameResolvedAtOffset: 8,
            gameStatusOffset: 16,
            gameWasRespectedSlot: 9, // wasRespectedGameTypeWhenCreated
            gameWasRespectedOffset: 0
        });
    }
}
