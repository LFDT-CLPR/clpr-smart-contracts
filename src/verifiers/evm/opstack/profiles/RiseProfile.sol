// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {OpStackOutputRootProof as OP} from "@hiero-ledger/clpr/libraries/proof/opstack/OpStackOutputRootProof.sol";
import {XLayerProfile} from "@hiero-ledger/clpr/verifiers/evm/opstack/profiles/XLayerProfile.sol";

/// @title RiseProfile
/// @notice Deployment profile of {OpStackVerifier} / {OpStackProposedVerifier} for RISE (chain 4153), which
///         settles on Ethereum mainnet through OP Succinct Lite dispute games (game type 42).
/// @dev L1 contracts (read on 2026-10-01 from Sourcify and live mainnet storage):
///        L1CrossDomainMessenger 0xC0de1d9B1cD2Caf782355C66a6A8e5948e63c9c6 → OptimismPortal
///        0xad92Fa18EB74E46Db844240623124BF46589db4C (5.1.1)
///        → AnchorStateRegistry 0x551A672d703966D83C3EC3ea0e844f43c3373c91 (proxy; implementation
///          0xeb69cc681e8d4a557b30dffbad85affd47a2cf2e, version 3.5.0: the same bytecode as X Layer's)
///        → DisputeGameFactory 0x6A4139810986CF13408330e14C4ac9Daf0511aA3 (1.3.0, no game args)
///        → gameImpls[42] = OPSuccinctFaultDisputeGame 0xBf60dBc272833cD25f0426983c3175C32C8E5A7a
///          (`version()` 1.0.0; Sourcify exact match; same storage layout as X Layer's 2.0.0).
///
///      Trust (README §7): the Ethereum sync committee; one permissioned challenger set (AccessManager
///      0xF90a…2d17: `challengers[address(0)] == false`, a 1-day challenge window after which an
///      unchallenged game resolves without a proof); SP1 (verifier gateway 0x3B60…185e) for challenged
///      games; and a 3-of-5 Safe 0x9196…002c that owns the ProxyAdmin, the DGF and the AccessManager with
///      no timelock. Proposals fall back to permissionless after 14 days without one.
library RiseProfile {
    uint256 internal constant L2_CHAIN_ID = 4153;
    address internal constant ANCHOR_STATE_REGISTRY = 0x551A672d703966D83C3EC3ea0e844f43c3373c91;
    /// @dev keccak256 of the ASR 3.5.0 implementation's runtime code (X Layer's too); binds the 3.5-day delay.
    bytes32 internal constant ANCHOR_STATE_REGISTRY_IMPL_CODE_HASH =
        0x1194081c631cd5141ef68135c5aaaa59b92a7c2df303a713c3cf81c6bab69348;
    uint256 internal constant DISPUTE_GAME_FINALITY_DELAY_SECONDS = 302_400;
    address internal constant GAME_IMPLEMENTATION = 0xBf60dBc272833cD25f0426983c3175C32C8E5A7a;
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
            layout: XLayerProfile.layout() // ASR 3.5.0 / DGF 1.3.0 / OPSuccinctFaultDisputeGame (slot 9)
        });
    }
}
