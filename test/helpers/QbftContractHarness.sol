// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {QbftContractValidatorSource} from "@hiero-ledger/clpr/libraries/proof/qbft/QbftContractValidatorSource.sol";
import {QbftContractModeVerifier} from "@hiero-ledger/clpr/verifiers/evm/qbft/QbftContractModeVerifier.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @dev Exposes {QbftContractValidatorSource.resolveSet} for direct unit tests.
contract ContractSourceHarness {
    using Memory for bytes;

    function resolve(bytes memory proof, bytes32 stateRoot, address expectedContract, bytes32 expectedSlot)
        external
        pure
        returns (address[] memory)
    {
        return QbftContractValidatorSource.resolveSet(proof.asSlice(), stateRoot, expectedContract, expectedSlot)
        .members;
    }
}

/// @dev Exposes {QbftContractModeVerifier._openCommitment} for direct unit tests of the trusted-set
///      list parse and the commitment check.
contract OpenCommitmentHarness is QbftContractModeVerifier {
    using Memory for bytes;

    function open(bytes memory listRlp, bytes32 expected) external pure returns (address[] memory) {
        return _openCommitment(listRlp.asSlice(), expected).members;
    }
}
