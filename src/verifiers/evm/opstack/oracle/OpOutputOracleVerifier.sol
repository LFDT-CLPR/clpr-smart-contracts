// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {
    OpOutputOracleVerifierBase
} from "@hiero-ledger/clpr/verifiers/evm/opstack/oracle/OpOutputOracleVerifierBase.sol";
import {IEthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/lib/IEthL1StateVerifier.sol";
import {OpOutputOracleProof} from "@hiero-ledger/clpr/libraries/proof/opstack/OpOutputOracleProof.sol";

/// @title OpOutputOracleVerifier — FINALIZED tier
/// @notice Accepts an L2 output root only if, in L1 state authenticated by the Ethereum sync committee,
///         it is posted in the chain's output oracle (not deleted), the oracle is not in optimistic mode
///         (where it has one), and its finalization period has passed — the rule the chain's own
///         OptimismPortal applies to withdrawals. Latency: Blast 7 days, Mantle 12 hours, Katana one
///         AggLayer certificate (outputs are validity-proven and cannot be deleted).
contract OpOutputOracleVerifier is OpOutputOracleVerifierBase {
    constructor(
        IEthL1StateVerifier l1StateVerifier,
        uint64 l1GenesisTime,
        uint64 l1SecondsPerSlot,
        OpOutputOracleProof.Profile memory profile_,
        L2AccountFormat memory accountFormat
    )
        OpOutputOracleVerifierBase(
            Finality.FINALIZED, l1StateVerifier, l1GenesisTime, l1SecondsPerSlot, profile_, accountFormat
        )
    {}
}
