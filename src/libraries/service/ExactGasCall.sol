// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @notice Calls a contract with the requested gas, less the CALL's own cost, or reverts.
library ExactGasCall {
    /// @notice Fires when `available` gas is below `required` (`gasLimit + gasLimit / 63`), the least that
    ///         forwards `gasLimit`, less the CALL's own cost, under EIP-150.
    error InsufficientGasForCall(uint256 required, uint256 available);

    /// @dev Calls `target` with `gasLimit` gas. With `decodeBytesReturn`, the return or revert data is
    ///      copied; the copy is sized by the callee and paid from the caller's gas, outside `gasLimit`. If
    ///      the call succeeded and the copy is a valid ABI encoding of one `bytes` (exactly what
    ///      `abi.decode` accepts for `(bytes)`), `wellFormed` is true and `returnData` is that `bytes`,
    ///      pointing into the copy; otherwise `wellFormed` is false and `returnData` is the raw return or
    ///      revert data. Without the flag nothing is copied, `returnData` is empty and `wellFormed` is
    ///      false. A CALL forwards at most 63/64 of the gas left, so without the check a transaction sender
    ///      could pick a gas limit that hands the callee less than `gasLimit` and still lets the transaction
    ///      finish. The check reserves no gas for the CALL itself, so the callee is guaranteed `gasLimit`
    ///      less the CALL's own cost (account access for the target and, for an EIP-7702 target, its
    ///      delegate) and the few instructions between the check and the CALL, whatever those cost on the
    ///      chain. A `target` without code returns `success = false`, but the gas check runs first and can
    ///      still revert, so a caller that skips such a target checks its code before calling.
    function callWithExactGas(address target, uint256 gasLimit, bytes memory data, bool decodeBytesReturn)
        internal
        returns (bool success, bool wellFormed, bytes memory returnData)
    {
        uint256 required = gasLimit + gasLimit / 63;
        uint256 available = gasleft();
        if (available < required) revert InsufficientGasForCall(required, available);
        assembly ("memory-safe") {
            success := call(gasLimit, target, 0, add(data, 0x20), mload(data), 0, 0)
            // A call to an address without code succeeds with no return data.
            if and(success, iszero(returndatasize())) { success := gt(extcodesize(target), 0) }
            if decodeBytesReturn {
                let size := returndatasize()
                returnData := mload(0x40)
                mstore(returnData, size)
                returndatacopy(add(returnData, 0x20), 0, size)
                mstore(0x40, add(add(returnData, 0x20), and(add(size, 31), not(31))))

                // Each bound is checked before the next subtraction, so none can underflow.
                if and(success, iszero(lt(size, 32))) {
                    let offset := mload(add(returnData, 0x20))
                    if iszero(gt(offset, sub(size, 32))) {
                        let length := mload(add(add(returnData, 0x20), offset))
                        if iszero(gt(length, sub(sub(size, 32), offset))) {
                            // The ABI length word at `offset` is already a valid `bytes` header.
                            returnData := add(add(returnData, 0x20), offset)
                            wellFormed := true
                        }
                    }
                }
            }
        }
    }
}
