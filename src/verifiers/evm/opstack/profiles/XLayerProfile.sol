// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {OpStackOutputRootProof as OP} from "@hiero-ledger/clpr/libraries/proof/opstack/OpStackOutputRootProof.sol";

/// @title XLayerProfile
/// @notice Deployment profile of {OpStackVerifier} / {OpStackProposedVerifier} for X Layer (chain 196),
///         which settles on Ethereum mainnet through OP Succinct Lite dispute games (game type 42).
/// @dev X Layer's provable state on L1 is its OP Stack fault-proof system:
///        OptimismPortal 0x64057ad1DdAc804d0D26A7275b193D9DACa19993 (5.2.0)
///        → AnchorStateRegistry 0x000590BB65ab1864a7AD46d6B957cC9a4F2C149d (proxy; implementation
///          0xeb69cc681e8d4a557b30dffbad85affd47a2cf2e, version 3.5.0)
///        → DisputeGameFactory 0x9D4c8FAEadDdDeeE1Ed0c92dAbAD815c2484f675 (1.3.0)
///        → gameImpls[42] = OPSuccinctFaultDisputeGame 2.0.0 0x8841FA06099FEdfE7DB6962926C6A281e9E1e607.
///      Its AggLayer side (AggchainECDSAMultisig 0x2B0ee28D4D51bC9aDde5E58E295873F61F4a0507, rollup 3)
///      stores exit and pessimistic roots only, never an L2 state or output root.
///
///      Every value was read on 2026-10-01 from Sourcify storage layouts and live mainnet storage, and the
///      live builder re-checks them (`buildOpStackLiveProof.ts --chain xlayer`). Re-read before deploying:
///      an upgrade of the ASR implementation or a new gameImpls[42] makes the verifiers fail closed until
///      they are redeployed with a new profile (README §3).
///
///      Trust (README §7.1): the Ethereum sync committee, X Layer's single permissioned proposer and single
///      permissioned challenger, SP1, and upgrade keys with no or a 1-hour delay.
library XLayerProfile {
    uint256 internal constant L2_CHAIN_ID = 196;
    address internal constant ANCHOR_STATE_REGISTRY = 0x000590BB65ab1864a7AD46d6B957cC9a4F2C149d;
    /// @dev keccak256 of the ASR 3.5.0 implementation's runtime code; binds DISPUTE_GAME_FINALITY_DELAY_SECONDS.
    bytes32 internal constant ANCHOR_STATE_REGISTRY_IMPL_CODE_HASH =
        0x1194081c631cd5141ef68135c5aaaa59b92a7c2df303a713c3cf81c6bab69348;
    /// @dev 3.5 days, the ASR implementation's immutable.
    uint256 internal constant DISPUTE_GAME_FINALITY_DELAY_SECONDS = 302_400;
    address internal constant GAME_IMPLEMENTATION = 0x8841FA06099FEdfE7DB6962926C6A281e9E1e607;
    uint32 internal constant GAME_TYPE = 42;

    function profile() internal pure returns (OP.Profile memory) {
        return OP.Profile({
            rootFormat: OP.RootFormat.OUTPUT_ROOT,
            l2ChainId: L2_CHAIN_ID,
            anchorStateRegistry: ANCHOR_STATE_REGISTRY,
            anchorStateRegistryImplCodeHash: ANCHOR_STATE_REGISTRY_IMPL_CODE_HASH,
            disputeGameFinalityDelaySeconds: DISPUTE_GAME_FINALITY_DELAY_SECONDS,
            gameImplementation: GAME_IMPLEMENTATION,
            gameArgsHash: bytes32(0), // DGF 1.3.0: clones carry no game args
            layout: layout()
        });
    }

    /// @notice ASR 3.5.0 / DGF 1.3.0 / OPSuccinctFaultDisputeGame 2.0.0 (Sourcify storage layouts).
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
