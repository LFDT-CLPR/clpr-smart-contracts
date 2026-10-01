// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title ICometBftHeaderSource
/// @notice The two read functions of `CometBftCommitAccumulator` (CometBFT family, LFDT-CLPR
///         clpr-smart-contracts PR #6) that a store-proof verifier needs, declared here so that
///         {InitiaMoveVerifier} builds on a branch that does not contain the CometBFT light client
///         yet. The ABI is identical: a deployed `CometBftCommitAccumulator` is a valid source.
/// @dev Both functions check CometBFT finality: more than 2/3 of the voting power of the validator
///      set with hash `validatorsHash` signed the header (Ed25519 for Initia).
interface ICometBftHeaderSource {
    /// @notice What a verifier needs from a verified header (same field order as the accumulator's).
    struct Header {
        bytes32 validatorsHash;
        bytes32 nextValidatorsHash;
        bytes32 appHash;
        uint64 height;
    }

    /// @notice The summary of a header whose commit reached more than 2/3 of its set's power over
    ///         earlier `accumulate` transactions. Reverts if it has not.
    function finalizedHeader(bytes32 headerHash) external view returns (Header memory h);

    /// @notice One-transaction path: `validatorSet` hashes to `setHash`, the signed header is this
    ///         chain's, at or above `minHeight`, and its commit carries more than 2/3 of the power.
    function checkHeader(bytes calldata validatorSet, bytes calldata signedHeader, bytes32 setHash, uint64 minHeight)
        external
        view
        returns (bytes32 headerHash, Header memory h);
}
