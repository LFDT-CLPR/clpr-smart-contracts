// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprMithrilStm} from "@hiero-ledger/clpr/libraries/proof/cardano/ClprMithrilStm.sol";
import {ClprMithrilMessage} from "@hiero-ledger/clpr/libraries/proof/cardano/ClprMithrilMessage.sol";

/// @title MithrilStmVerifier
/// @notice Stateless Mithril certificate engine, deployed once and called by
///         {CardanoMithrilVerifier} with `staticcall` (keeps the channel verifier under EIP-170):
///         rebuilds the protocol message from typed parts ({ClprMithrilMessage}) and verifies the
///         STM concatenation proof over it ({ClprMithrilStm}).
contract MithrilStmVerifier {
    /// @notice Reverts unless `signers`/`batchValues` are a valid STM proof of the message rebuilt
    ///         from `keyIds`/`values` under `avk`/`params`; returns the parsed message parts.
    function verifyCertificate(
        uint256[] calldata keyIds,
        bytes[] calldata values,
        ClprMithrilStm.Avk calldata avk,
        ClprMithrilStm.Params calldata params,
        bytes[] calldata signers,
        bytes calldata batchValues
    ) external view returns (ClprMithrilMessage.Parsed memory m) {
        m = ClprMithrilMessage.build(keyIds, values);
        ClprMithrilStm.verify(m.message, avk, params, signers, batchValues);
    }

    /// @notice STM proof over an arbitrary message (the 64-byte ASCII signed message).
    function verify(
        bytes calldata message,
        ClprMithrilStm.Avk calldata avk,
        ClprMithrilStm.Params calldata params,
        bytes[] calldata signers,
        bytes calldata batchValues
    ) external view returns (uint256 nrIndices) {
        return ClprMithrilStm.verify(message, avk, params, signers, batchValues);
    }
}
