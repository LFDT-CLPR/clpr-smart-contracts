// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title IClprApplication
/// @notice Interface for application contracts that send/receive cross-ledger messages.
interface IClprApplication {
    /// @notice Called when a cross-ledger data message arrives.
    /// @dev Called with the lower of `throttles.maxGasPerMessage` and the gas the connector can pay for,
    ///      less the CALL's own cost (account access under EIP-2929 and, for an EIP-7702 account, its
    ///      delegate), or the bundle reverts with `ExactGasCall.InsufficientGasForCall`. A revert, or a
    ///      return that is not an ABI-encoded `bytes`, is recorded as an `APPLICATION_ERROR` reply that
    ///      carries the raw revert or return data.
    /// @param sender The sender address on the peer chain (opaque bytes)
    /// @return responseData Response data to send back to the peer
    function onClprMessage(bytes32 channelId, bytes calldata sender, bytes calldata messageData)
        external
        returns (bytes memory responseData);

    /// @notice Called (best-effort) when a response to a previously sent message arrives.
    /// @dev Called with `throttles.maxGasPerMessage` gas, less the CALL's own cost, or the bundle reverts with
    ///      `ExactGasCall.InsufficientGasForCall`. Reverts are caught and ignored.
    /// @param messageId The original outbound message ID this responds to
    /// @param status The reply status code (cast from ClprTypes.ReplyStatus)
    function onClprResponse(bytes32 channelId, uint64 messageId, uint8 status, bytes calldata responseData) external;
}
