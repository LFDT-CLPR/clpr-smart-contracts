// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {TezosContextProof} from "@hiero-ledger/clpr/libraries/proof/tezos/TezosContextProof.sol";

/// @title TezosContextVerifier
/// @notice Stateless contract wrapper around {TezosContextProof}, deployed once and called by the
///         Tezos verifiers. Keeping the context-proof code in its own contract keeps the verifiers
///         under the 24,576-byte contract size limit; a call costs a calldata copy of the proof.
contract TezosContextVerifier {
    /// @notice See {TezosContextProof.verify}. `absentName == 0` disables the absence check.
    function verify(bytes32 root, bytes[] calldata steps, bytes calldata proof, uint256 absentStep, bytes32 absentName)
        external
        view
        returns (bytes memory)
    {
        return TezosContextProof.verify(root, steps, proof, absentStep, absentName);
    }
}
