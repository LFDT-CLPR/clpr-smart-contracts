// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title IClprConnector
/// @notice Interface for connector contracts. The CLPR Service calls into the
///         connector on the source ledger to authorize outbound messages, and
///         on the destination ledger to notify it of inbound messages.
interface IClprConnector {
    /// @notice Authorize an outbound message. Called by ClprService during sendMessage.
    /// @dev The implementing contract IS the source connector — the connector knows
    ///      its own identity, so no connector address parameter is passed.
    /// @param channelId The channel the message will be sent on
    /// @param targetApplication The destination application address bytes
    /// @param sender The sender address bytes
    /// @param messageData The message payload bytes
    /// @return authorized True if the connector approves the message
    function authorizeOutboundMessage(
        bytes32 channelId,
        bytes calldata targetApplication,
        bytes calldata sender,
        bytes calldata messageData
    ) external returns (bool authorized);

    /// @notice Pay the protocol for inbound message execution.
    /// @dev Called by ClprService during bundle processing, for an inbound DATA message and for an inbound
    ///      reply to an outbound message this connector authorized, with
    ///      `economicConfig.connectorPaymentGasLimit` gas (at least `ClprTypes.MIN_CONNECTOR_PAYMENT_GAS_LIMIT`),
    ///      less the CALL's own cost (account access under EIP-2929 and, for an EIP-7702 account, its
    ///      delegate), or the bundle reverts with `ExactGasCall.InsufficientGasForCall`. The connector MUST
    ///      transfer exactly `amount` of the service's fee asset to `msg.sender` (the manager forwards it to
    ///      the bundle submitter): native value when `IClprService.getFeeToken()` is `address(0)`, otherwise
    ///      that ERC-20.
    ///      Reverting, running out of gas, transferring any other amount, or holding a balance below `amount`
    ///      (checked first; the call is then skipped) fails the charge. A failed charge for a DATA message
    ///      slashes the connector and leaves the message's reply status unchanged; a failed charge for a
    ///      reply does not slash it. A fee token that pauses transfers, or blocks this contract or the
    ///      service, fails the charge the same way.
    ///
    ///      Implementations SHOULD restrict callers to the manager (the address
    ///      they were registered with), otherwise any caller can drain the
    ///      contract's operating balance.
    /// @param amount Fee-asset units to transfer back to `msg.sender`.
    function payForExecution(uint256 amount) external;

    /// @notice Notify the connector that an inbound message has been processed.
    ///         Best-effort: reverts are caught by the protocol.
    /// @dev Called after the charge, if any, even if the charge failed and slashed the connector,
    ///      with `economicConfig.connectorInboundGasStipend` gas, less the CALL's own cost, or the bundle
    ///      reverts with `ExactGasCall.InsufficientGasForCall`. Not called when that stipend is 0 or the
    ///      message's reply status is `CONNECTOR_UNDERFUNDED`.
    ///      The implementing contract IS the destination connector.
    /// @param messageId The destination-side message ID
    function onInboundMessage(
        bytes32 channelId,
        uint64 messageId,
        bytes calldata sender,
        bytes calldata targetApplication,
        bytes calldata messageData
    ) external;
}
