// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {OpStackVerifierBase} from "@hiero-ledger/clpr/verifiers/evm/opstack/OpStackVerifierBase.sol";
import {IEthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/lib/IEthL1StateVerifier.sol";
import {OpStackOutputRootProof} from "@hiero-ledger/clpr/libraries/proof/opstack/OpStackOutputRootProof.sol";

/// @title OpStackVerifier — FINALIZED tier (trust-minimized)
/// @notice Accepts an OP Stack L2 output root only if, in L1 state authenticated by the Ethereum sync
///         committee, it is (a) the AnchorStateRegistry anchor root, or (b) the root claim of a dispute
///         game of the respected type that resolved DEFENDER_WINS more than the registry's finality
///         delay ago and is neither blacklisted nor retired — `AnchorStateRegistry.isGameClaimValid`.
///         Trust: Ethereum's sync committee (2/3) and the L2's own fault-proof system; no proposer or
///         relayer is trusted. Latency: the chain's withdrawal-finality time (days).
contract OpStackVerifier is OpStackVerifierBase {
    constructor(
        IEthL1StateVerifier l1StateVerifier,
        uint64 l1GenesisTime,
        uint64 l1SecondsPerSlot,
        OpStackOutputRootProof.Profile memory profile_
    ) OpStackVerifierBase(Finality.FINALIZED, l1StateVerifier, l1GenesisTime, l1SecondsPerSlot, profile_) {}
}
