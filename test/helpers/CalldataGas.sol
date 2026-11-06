// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title CalldataGas
/// @notice EIP-2028 intrinsic calldata pricing shared by the gas-report suites: 4 gas per zero
///         byte, 16 per non-zero. Charged before execution begins, so it is invisible to
///         `gasleft()` deltas and `vm.lastCallGas()`.
library CalldataGas {
    function eip2028(bytes memory data) internal pure returns (uint256 gasUsed) {
        for (uint256 i = 0; i < data.length; i++) {
            gasUsed += data[i] == 0 ? 4 : 16;
        }
    }
}
