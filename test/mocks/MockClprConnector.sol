// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprConnector} from "@hiero-ledger/clpr/interfaces/IClprConnector.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @notice Mock connector contract used in tests. Configurable approve/reject for
///         outbound authorization, and a recorder for inbound notifications.
contract MockClprConnector is IClprConnector {
    struct AuthorizeCall {
        bytes32 channelId;
        bytes targetApplication;
        bytes sender;
        bytes messageData;
    }

    struct InboundCall {
        bytes32 channelId;
        uint64 messageId;
        bytes sender;
        bytes targetApplication;
        bytes messageData;
    }

    AuthorizeCall[] public authorizeCalls;
    InboundCall[] public inboundCalls;

    bool private _authorize = true;
    bool private _authorizeReverts;
    bool private _inboundReverts;
    bool private _payReverts;
    bool private _payShortfall; // if true, pays only amount-1 (forces the manager's check to fail)
    bool private _reentrantOnAuthorize;
    address private _reentrantTarget;
    bytes private _reentrantCalldata;
    address private _payToken;

    function setAuthorize(bool ok) external {
        _authorize = ok;
    }

    function setAuthorizeReverts(bool reverts) external {
        _authorizeReverts = reverts;
    }

    function setInboundReverts(bool reverts) external {
        _inboundReverts = reverts;
    }

    function setPayReverts(bool reverts) external {
        _payReverts = reverts;
    }

    function setPayShortfall(bool shortfall) external {
        _payShortfall = shortfall;
    }

    function setReentrancy(address target, bytes calldata data) external {
        _reentrantOnAuthorize = true;
        _reentrantTarget = target;
        _reentrantCalldata = data;
    }

    function authorizeCallCount() external view returns (uint256) {
        return authorizeCalls.length;
    }

    function inboundCallCount() external view returns (uint256) {
        return inboundCalls.length;
    }

    function authorizeOutboundMessage(
        bytes32 channelId,
        bytes calldata targetApplication,
        bytes calldata sender,
        bytes calldata messageData
    ) external override returns (bool) {
        if (_authorizeReverts) revert("authorize revert");
        authorizeCalls.push(
            AuthorizeCall({
                channelId: channelId, targetApplication: targetApplication, sender: sender, messageData: messageData
            })
        );
        if (_reentrantOnAuthorize) {
            _reentrantOnAuthorize = false;
            (bool ok,) = _reentrantTarget.call(_reentrantCalldata);
            // Surface the inner failure so the test can observe ReentrancyGuardReentrantCall.
            require(ok, "reentrant call failed");
        }
        return _authorize;
    }

    /// @dev Pay `payForExecution` in this ERC-20 instead of native value (token-mode services).
    function setPayToken(address token) external {
        _payToken = token;
    }

    function payForExecution(uint256 amount) external override {
        if (_payReverts) revert("pay revert");
        uint256 toPay = _payShortfall && amount > 0 ? amount - 1 : amount;
        if (_payToken != address(0)) {
            require(IERC20(_payToken).transfer(msg.sender, toPay), "pay transfer failed");
            return;
        }
        (bool ok,) = msg.sender.call{value: toPay}("");
        require(ok, "pay transfer failed");
    }

    function onInboundMessage(
        bytes32 channelId,
        uint64 messageId,
        bytes calldata sender,
        bytes calldata targetApplication,
        bytes calldata messageData
    ) external override {
        if (_inboundReverts) revert("inbound revert");
        inboundCalls.push(
            InboundCall({
                channelId: channelId,
                messageId: messageId,
                sender: sender,
                targetApplication: targetApplication,
                messageData: messageData
            })
        );
    }

    receive() external payable {}
}
