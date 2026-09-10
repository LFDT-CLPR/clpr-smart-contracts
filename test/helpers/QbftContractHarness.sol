// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {QbftContractValidatorSource} from "@hiero-ledger/clpr/libraries/proof/qbft/QbftContractValidatorSource.sol";

/// @dev Exposes {QbftContractValidatorSource.resolveSet} for direct unit tests.
contract ContractSourceHarness {
    function resolve(bytes memory proof, bytes32 stateRoot, address expectedContract, bytes32 expectedSlot)
        external
        pure
        returns (address[] memory)
    {
        return QbftContractValidatorSource.resolveSet(proof, stateRoot, expectedContract, expectedSlot).members;
    }
}
