// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";
import {ConnectorRegistrar} from "@test/helpers/ConnectorRegistrar.sol";
import {BundleLibTestBase} from "@test/libraries/service/bundle-lib/BundleLibTestBase.sol";

/// @notice `messageExecutionCost == 0` is free execution: inbound DATA is delivered without
///         consulting the connector's balance, charging it, or slashing it. This is what a chain
///         without a native asset (BALANCE always 0) needs.
contract BundleLib_FreeExecutionTest is BundleLibTestBase {
    function _freeExecution() internal {
        ClprTypes.EconomicConfig memory econ = _defaultEconomicConfig();
        econ.messageExecutionCost = 0;
        service.updateEconomicConfiguration(econ);
    }

    function _registerUnfundedConnector() internal {
        // Stake is locked, but the connector contract itself holds no balance to pay for execution.
        connectorId = ConnectorRegistrar.register(
            IClprService(address(service)),
            channelId,
            keccak256(abi.encodePacked("free-connector")),
            address(connector),
            owner,
            0.5 ether
        );
        assertEq(address(connector).balance, 0);
    }

    function _inboundData() internal {
        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"01020304");
        _submitSingleInboundMessage(dataPayload);
    }

    function _replyStatus() internal returns (ClprTypes.ReplyStatus) {
        return ClprProtobuf.decodeReplyMessage(service.getMessage(channelId, 1).payload).status;
    }

    function test_freeExecution_unfundedConnector_messageIsDelivered() public {
        _freeExecution();
        vm.txGasPrice(1 gwei);
        _registerUnfundedConnector();
        uint256 submitterBefore = address(this).balance;

        _inboundData();

        assertEq(uint8(_replyStatus()), uint8(ClprTypes.ReplyStatus.SUCCESS), "delivered, not underfunded");
        assertEq(app.getMessageCallCount(), 1, "application received the message");
        assertEq(service.getConnector(channelId, connectorId).slashCount, 0, "not slashed");
        assertEq(address(this).balance, submitterBefore, "submitter is not paid");
    }

    function test_freeExecution_fundedConnector_isNotCharged() public {
        _freeExecution();
        vm.txGasPrice(1 gwei);
        _registerUnfundedConnector();
        vm.deal(address(connector), 1 ether);
        // A payForExecution call would revert and lead to a slash; proves the call is never made.
        connector.setPayReverts(true);
        uint256 submitterBefore = address(this).balance;

        _inboundData();

        assertEq(uint8(_replyStatus()), uint8(ClprTypes.ReplyStatus.SUCCESS));
        assertEq(address(connector).balance, 1 ether, "connector keeps its balance");
        assertEq(address(this).balance, submitterBefore, "submitter is not paid");
        assertEq(service.getConnector(channelId, connectorId).slashCount, 0, "payForExecution was never called");
    }

    function test_chargedExecution_unfundedConnector_isUnderfunded() public {
        // Control: the default non-zero cost keeps the balance check and the slash.
        vm.txGasPrice(1 gwei);
        _registerUnfundedConnector();

        _inboundData();

        assertEq(uint8(_replyStatus()), uint8(ClprTypes.ReplyStatus.CONNECTOR_UNDERFUNDED));
        assertEq(app.getMessageCallCount(), 0, "application is not called");
        assertEq(service.getConnector(channelId, connectorId).slashCount, 1, "slashed once");
    }
}
