// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {OpOutputOracleProof as OO} from "@hiero-ledger/clpr/libraries/proof/opstack/OpOutputOracleProof.sol";
import {
    OpOutputOracleVerifierBase
} from "@hiero-ledger/clpr/verifiers/evm/opstack/oracle/OpOutputOracleVerifierBase.sol";

/// @title FraxtalProfile
/// @notice Deployment profile of {OpOutputOracleVerifier} / {OpOutputOracleProposedVerifier} for Fraxtal
///         (chain 252), which settles on Ethereum mainnet through an `L2OutputOracle` with NO state validation:
///         one proposer posts output roots and nothing on L1 proves them.
/// @dev L1 contracts (read on 2026-10-01 from live mainnet storage; Superchain registry `fraxtal.toml`):
///        OptimismPortal 0x36cb65c1967A0Fb0EEE11569C51C2f2aA1Ca6f6D (2.8.1-beta.4) `l2Oracle()`
///        → L2OutputOracle 0x66CC916Ed5C6C2FA97014f7D1cD141528Ae171e4 (proxy; implementation
///          0x6f3ccc8c9daf8b9b39ade481213ff7a626a42b65, version 1.8.0). Storage: l2Outputs at slot 3,
///          submissionInterval 4 (1,800 blocks), l2BlockTime 5 (2 s), challenger 6, proposer 7,
///          finalizationPeriodSeconds 8 (604,800 s). No optimistic-mode flag. The L2 account leaf is
///          Ethereum's 4 fields.
///
///      Trust (docs/chains/fraxtal.md): the Ethereum sync committee; the proposer EOA 0xFb90…bc50 for every
///      output; and the challenger, a 3-of-5 Safe 0xe0d7…0508, which can delete outputs within the 7-day
///      period and also owns the ProxyAdmin (no timelock). FINALIZED trusts the proposer unless that Safe
///      deletes a bad output within 7 days; PROPOSED trusts the proposer alone.
library FraxtalProfile {
    uint256 internal constant L2_CHAIN_ID = 252;
    address internal constant ORACLE = 0x66CC916Ed5C6C2FA97014f7D1cD141528Ae171e4;
    /// @dev keccak256 of the L2OutputOracle 1.8.0 implementation's runtime code; fixes the storage layout.
    bytes32 internal constant ORACLE_IMPL_CODE_HASH =
        0x530ddbfd353de0a3d5a4f4c8a69bf1e1208fe92783ef6b13d30d7aea6ff3ed2f;
    uint256 internal constant OUTPUTS_SLOT = 3;
    /// @dev Read from storage at the proven L1 state (604,800 s on 2026-10-01).
    uint256 internal constant FINALIZATION_PERIOD_SLOT = 8;

    function profile() internal pure returns (OO.Profile memory) {
        return OO.Profile({
            oracle: ORACLE,
            oracleImplCodeHash: ORACLE_IMPL_CODE_HASH,
            outputsSlot: OUTPUTS_SLOT,
            periodSource: OO.PeriodSource.STORAGE,
            finalizationPeriodSeconds: 0,
            finalizationPeriodSlot: FINALIZATION_PERIOD_SLOT,
            hasOptimisticMode: false,
            optimisticModeSlot: 0,
            optimisticModeOffset: 0
        });
    }

    /// @notice op-geth state accounts: `[nonce, balance, storageRoot, codeHash]`.
    function accountFormat() internal pure returns (OpOutputOracleVerifierBase.L2AccountFormat memory) {
        return OpOutputOracleVerifierBase.L2AccountFormat({fields: 4, storageRootIndex: 2, codeHashIndex: 3});
    }
}
