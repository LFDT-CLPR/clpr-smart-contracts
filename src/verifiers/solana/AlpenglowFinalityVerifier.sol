// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {AlpenglowCert} from "@hiero-ledger/clpr/verifiers/solana/AlpenglowCert.sol";

/// @title AlpenglowFinalityVerifier
/// @notice Stateless, standalone deployment of {AlpenglowCert}. `SolanaVerifier` calls it in ALPENGLOW
///         mode (kept separate to stay under EIP-170), and relayers or fork-profile arming can call it
///         directly — the Alpenglow genesis certificate is the fork evidence (README §4).
contract AlpenglowFinalityVerifier {
    /// @notice Reverts unless `p` finalizes `(p.slot, p.blockId)` under `set`; returns signed stake
    ///         (the smaller of the two aggregates for a slow finalization).
    function verifyFinality(AlpenglowCert.FinalityProof calldata p, AlpenglowCert.EpochSet calldata set)
        external
        view
        returns (uint256 signedStake)
    {
        return AlpenglowCert.verifyFinality(p, set);
    }

    /// @notice keccak256(abi.encode(set)) — the value a SolanaVerifier trust anchor stores.
    function setHash(AlpenglowCert.EpochSet calldata set) external pure returns (bytes32) {
        return AlpenglowCert.setHash(set);
    }

    /// @notice Signed bytes of a vote payload (exposed for relayers and tests).
    function payload(uint8 tag, uint64 slot, bytes32 blockId, bool withBlock, uint16 shredVersion)
        external
        pure
        returns (bytes memory)
    {
        return AlpenglowCert.payload(tag, slot, blockId, withBlock, shredVersion);
    }
}
