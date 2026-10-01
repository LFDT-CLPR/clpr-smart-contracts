// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {OpStackVerifierBase} from "@hiero-ledger/clpr/verifiers/evm/opstack/OpStackVerifierBase.sol";
import {IEthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/lib/IEthL1StateVerifier.sol";
import {OpStackOutputRootProof} from "@hiero-ledger/clpr/libraries/proof/opstack/OpStackOutputRootProof.sol";

/// @title OpStackProposedVerifier — PROPOSED tier (fast, TRUSTS THE PROPOSER)
/// @notice Everything {OpStackVerifier} accepts, plus the claimed output root of any dispute game of
///         the respected type that exists on L1 and has not been lost by its proposer (IN_PROGRESS or
///         DEFENDER_WINS; not blacklisted, not retired, respected when created), with no resolution or
///         finality-delay requirement.
/// @dev !!! TRUST: a game's root claim is the proposer's word until the challenge window closes. A
///      dishonest or faulty proposer can get an invalid L2 state accepted here, and CLPR cannot undo a
///      delivered message when the game is later lost. Use only for channels whose applications accept
///      proposer trust (value-at-risk bounded by the application); otherwise use {OpStackVerifier}.
contract OpStackProposedVerifier is OpStackVerifierBase {
    constructor(
        IEthL1StateVerifier l1StateVerifier,
        uint64 l1GenesisTime,
        uint64 l1SecondsPerSlot,
        OpStackOutputRootProof.Profile memory profile_
    ) OpStackVerifierBase(Finality.PROPOSED, l1StateVerifier, l1GenesisTime, l1SecondsPerSlot, profile_) {}
}
