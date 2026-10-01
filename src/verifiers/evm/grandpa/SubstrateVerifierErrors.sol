// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title SubstrateVerifierErrors
/// @notice Errors shared by the Substrate verifiers' finality and state layers, declared once so
///         both layers can be combined in one contract.
abstract contract SubstrateVerifierErrors {
    /// @dev The justified (or committed) block is below the trust anchor's minimum height.
    error HeightTooOld();
}
