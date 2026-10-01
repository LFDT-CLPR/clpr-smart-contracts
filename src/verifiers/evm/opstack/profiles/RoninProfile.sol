// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {OpStackOutputRootProof as OP} from "@hiero-ledger/clpr/libraries/proof/opstack/OpStackOutputRootProof.sol";

/// @title RoninProfile
/// @notice Deployment profile of {OpStackVerifier} / {OpStackProposedVerifier} for Ronin (chain 2020), an
///         OP Stack L2 that settles on Ethereum mainnet through permissioned dispute games (game type 1).
/// @dev L1 contracts (read on 2026-10-01 from Sourcify and live mainnet storage):
///        L1CrossDomainMessenger 0xF9aD628d9F907ad5d46Ab80100dacDf09EAc9A8e → OptimismPortal
///        0x652CD53eCf9466E5Fb00D0E11d6CBf6469a56D77 (5.6.1)
///        → AnchorStateRegistry 0x0B95fF1d1B113bac3E29Ac0BBF2089126C9aE81A (proxy; implementation
///          0x8f40cc98d694ab986f026c5383a181fcc9b6b281, version 3.9.0)
///        → DisputeGameFactory 0x45dA2CD511DA5FEAa535eBF166E628314a65843a (1.6.1, implementation
///          0x72B971717E088B59F26d4236BE222ADB6ACD393b)
///        → gameImpls[1] = PermissionedDisputeGame 2.4.0 0xe1dFFCBE4e22B813F26d2106D943C102e7cAb87e (V2:
///          configured by gameArgs[1] = absolute prestate 0x038512e0…d54c, VM 0xacc0…5cfa, ASR, WETH
///          0x2562…ec6d, L2 chain id 2020, proposer 0xd379…d620, challenger 0x4a49…a746).
///
///      Trust (README §7): the Ethereum sync committee; one proposer (an EOA) and one challenger (a 4-of-11
///      Safe), so a wrong root that the challenger does not dispute within the game clock is finalized; and
///      a 5-of-6 Safe 0xE9Ad…5607 that owns the ProxyAdmin and the DGF and is the guardian, with no timelock.
library RoninProfile {
    uint256 internal constant L2_CHAIN_ID = 2020;
    address internal constant ANCHOR_STATE_REGISTRY = 0x0B95fF1d1B113bac3E29Ac0BBF2089126C9aE81A;
    /// @dev keccak256 of the ASR 3.9.0 implementation's runtime code (Unichain's too); binds the 3.5-day delay.
    bytes32 internal constant ANCHOR_STATE_REGISTRY_IMPL_CODE_HASH =
        0x3f54fcc2d17726f6c927da08dec4dbfbecc43a013fd309344ecd2cace85ae36d;
    uint256 internal constant DISPUTE_GAME_FINALITY_DELAY_SECONDS = 302_400;
    address internal constant GAME_IMPLEMENTATION = 0xe1dFFCBE4e22B813F26d2106D943C102e7cAb87e;
    /// @dev keccak256(DisputeGameFactory.gameArgs(1)), 164 bytes.
    bytes32 internal constant GAME_ARGS_HASH = 0x935142cfa45769773f43a67571713dc18b13d04ab29892197b8225c879f17796;
    uint32 internal constant GAME_TYPE = 1;

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

    /// @notice ASR 3.9.0 / DGF 1.6.1 / PermissionedDisputeGame 2.4.0 (Sourcify storage layouts).
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
            gameWasRespectedSlot: 10, // wasRespectedGameTypeWhenCreated
            gameWasRespectedOffset: 0
        });
    }
}
