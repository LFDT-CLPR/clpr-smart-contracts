// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprConnector} from "@hiero-ledger/clpr/interfaces/IClprConnector.sol";
import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @notice Connector whose `payForExecution` does not pay, but re-enters the service to top up its
///         own stake with `amount`, so a missing reentrancy guard would count one deposit as both
///         the execution payment and new stake.
contract ReentrantPayConnector is IClprConnector {
    IClprService public immutable service;
    /// @dev `address(0)` re-enters `topUpConnectorStake{value: amount}`; otherwise
    ///      `topUpConnectorStake(amount)` paid in this token.
    address public immutable payToken;
    bytes32 public channelId;
    bytes32 public connectorId;

    constructor(IClprService service_, address payToken_) {
        service = service_;
        payToken = payToken_;
        if (payToken_ != address(0)) IERC20(payToken_).approve(address(service_), type(uint256).max);
    }

    function arm(bytes32 channelId_, bytes32 connectorId_) external {
        channelId = channelId_;
        connectorId = connectorId_;
    }

    function payForExecution(uint256 amount) external override {
        if (payToken == address(0)) {
            service.topUpConnectorStake{value: amount}(channelId, connectorId, amount);
        } else {
            service.topUpConnectorStake(channelId, connectorId, amount);
        }
    }

    function authorizeOutboundMessage(bytes32, bytes calldata, bytes calldata, bytes calldata)
        external
        pure
        override
        returns (bool)
    {
        return true;
    }

    function onInboundMessage(bytes32, uint64, bytes calldata, bytes calldata, bytes calldata) external override {}

    receive() external payable {}
}
