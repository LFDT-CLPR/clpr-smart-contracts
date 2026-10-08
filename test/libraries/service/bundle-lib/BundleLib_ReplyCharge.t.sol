// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {BundleLibTestBase} from "@test/libraries/service/bundle-lib/BundleLibTestBase.sol";

/// @dev Source-side charging for REPLY delivery: the connector pays for the gas the sender's
///      onClprResponse callback uses, plus margin, and the submitter (this contract) is paid.
contract BundleLib_ReplyChargeTest is BundleLibTestBase {
    function _submitReply(ClprTypes.ReplyStatus status) internal {
        bytes memory replyPayload = ClprProtobuf.encodeReplyMessage(1, status, hex"0102");
        bytes[] memory msgs = new bytes[](1);
        msgs[0] = replyPayload;
        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(replyPayload)));
        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 2,
            sentRunningHash: hash,
            receivedMessageId: 1,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 1,
            lastMessageRunningHash: hash
        });
        verifier.setVerifyBundleResult(meta, msgs);
        _submitBundle(hex"00FF");
    }

    function _sendFromApp() internal {
        vm.prank(address(app));
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"01020304");
    }

    function test_reply_chargesSourceConnector_paidToSubmitter() public {
        _registerTestConnector();
        _sendFromApp();
        vm.txGasPrice(1 gwei);

        uint256 connectorBefore = address(connector).balance;
        uint256 submitterBefore = address(this).balance;

        _submitReply(ClprTypes.ReplyStatus.SUCCESS);

        uint256 charged = connectorBefore - address(connector).balance;
        assertGt(charged, 0, "connector should be charged for the callback");
        assertEq(address(this).balance - submitterBefore, charged, "whole charge goes to the submitter");
        assertEq(app.getResponseCallCount(), 1);
    }

    /// The reply-path payment has the same budget as the DATA-path one, `connectorPaymentGasLimit`:
    /// a stipend of 0, which only turns the inbound notification off, does not stop it.
    function test_reply_zeroStipend_stillCharged() public {
        _registerTestConnector();
        _sendFromApp();
        ClprTypes.EconomicConfig memory econ = service.getEconomicConfig();
        econ.connectorInboundGasStipend = 0;
        service.updateEconomicConfiguration(econ);
        vm.txGasPrice(1 gwei);
        uint256 connectorBefore = address(connector).balance;

        _submitReply(ClprTypes.ReplyStatus.SUCCESS);

        assertGt(connectorBefore - address(connector).balance, 0, "the connector must still pay for its callback");
    }

    function test_reply_chargeIncludesMargin() public {
        _registerTestConnector();
        _sendFromApp();
        vm.txGasPrice(1 gwei);
        uint256 connectorBefore = address(connector).balance;

        _submitReply(ClprTypes.ReplyStatus.SUCCESS);

        uint256 charged = connectorBefore - address(connector).balance;
        assertGt(charged, 0);
        uint256 margin = service.getEconomicConfig().endpointMarginPercent;
        // charge = g · price · (100 + margin) / 100 for some integer gas g ≤ maxGasPerMessage
        uint256 gasCharged = charged * 100 / ((100 + margin) * 1 gwei);
        assertLe(gasCharged, defaultThrottles.maxGasPerMessage);
        uint256 base = gasCharged * 1 gwei;
        assertEq(charged, base + base * margin / 100, "charge must be gasUsed x price plus margin");
    }

    function test_reply_zeroGasPrice_noCharge() public {
        _registerTestConnector();
        _sendFromApp();
        vm.txGasPrice(0);
        uint256 connectorBefore = address(connector).balance;

        _submitReply(ClprTypes.ReplyStatus.SUCCESS);

        assertEq(address(connector).balance, connectorBefore);
        assertEq(app.getResponseCallCount(), 1);
    }

    function test_reply_revertingCallback_stillCharged() public {
        _registerTestConnector();
        _sendFromApp();
        app.setResponseShouldRevert(true, "nope");
        vm.txGasPrice(1 gwei);
        uint256 connectorBefore = address(connector).balance;

        _submitReply(ClprTypes.ReplyStatus.SUCCESS);

        assertGt(connectorBefore - address(connector).balance, 0, "gas burnt by a reverting callback is charged");
    }

    function test_reply_noCallbackTarget_noCharge() public {
        _registerTestConnector();
        // A redacted slot has no recoverable sender, so no callback runs and nothing is charged.
        _sendFromApp();
        service.redactMessage(channelId, 1);
        vm.txGasPrice(1 gwei);
        uint256 connectorBefore = address(connector).balance;

        _submitReply(ClprTypes.ReplyStatus.CONNECTOR_NOT_FOUND);

        assertEq(address(connector).balance, connectorBefore);
        assertEq(app.getResponseCallCount(), 0);
    }

    function test_reply_chargeFails_noSlash_bundleSucceeds() public {
        _registerTestConnector();
        _sendFromApp();
        connector.setPayReverts(true);
        vm.txGasPrice(1 gwei);
        ClprTypes.Connector memory connBefore = service.getConnector(channelId, connectorId);
        uint256 submitterBefore = address(this).balance;

        _submitReply(ClprTypes.ReplyStatus.SUCCESS);

        ClprTypes.Connector memory connAfter = service.getConnector(channelId, connectorId);
        assertEq(connAfter.slashCount, connBefore.slashCount, "failed reply charge must not slash");
        assertEq(connAfter.lockedStake, connBefore.lockedStake);
        assertEq(address(this).balance, submitterBefore, "submitter absorbs the unpaid cost");
        assertEq(app.getResponseCallCount(), 1);
        assertEq(service.getMessage(channelId, 1).payload.length, 0, "original still deleted");
    }

    function test_reply_underfundedStatus_slashesAndCharges() public {
        _registerTestConnector();
        _sendFromApp();
        vm.txGasPrice(1 gwei);
        ClprTypes.Connector memory connBefore = service.getConnector(channelId, connectorId);
        uint256 connectorBefore = address(connector).balance;

        _submitReply(ClprTypes.ReplyStatus.CONNECTOR_UNDERFUNDED);

        ClprTypes.Connector memory connAfter = service.getConnector(channelId, connectorId);
        assertGt(connAfter.slashCount, connBefore.slashCount, "source slash still applies");
        assertGt(connectorBefore - address(connector).balance, 0, "callback still charged");
    }

    receive() external payable {}
}
