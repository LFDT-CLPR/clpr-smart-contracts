// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {
    OpOutputOracleVerifierBase
} from "@hiero-ledger/clpr/verifiers/evm/opstack/oracle/OpOutputOracleVerifierBase.sol";
import {IEthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/lib/IEthL1StateVerifier.sol";
import {OpOutputOracleProof} from "@hiero-ledger/clpr/libraries/proof/opstack/OpOutputOracleProof.sol";

/// @title OpOutputOracleProposedVerifier — PROPOSED tier (fast; see the trust note)
/// @notice Everything {OpOutputOracleVerifier} accepts, plus any output that is posted and not deleted
///         at the proven L1 state, without waiting for the finalization period.
/// @dev !!! TRUST depends on the chain (README §2):
///      - Blast: THE PROPOSER. Outputs are unproven; the challenger can delete a wrong one within 7 days,
///        and CLPR cannot undo a message delivered against it.
///      - Mantle: the SP1 validity proof checked at posting, plus the challenger's power to delete the
///        output within the 12-hour window (a delivered message is not undone).
///      - Katana: identical to FINALIZED (outputs cannot be deleted; the period is 0).
contract OpOutputOracleProposedVerifier is OpOutputOracleVerifierBase {
    constructor(
        IEthL1StateVerifier l1StateVerifier,
        uint64 l1GenesisTime,
        uint64 l1SecondsPerSlot,
        OpOutputOracleProof.Profile memory profile_,
        L2AccountFormat memory accountFormat
    )
        OpOutputOracleVerifierBase(
            Finality.PROPOSED, l1StateVerifier, l1GenesisTime, l1SecondsPerSlot, profile_, accountFormat
        )
    {}
}
