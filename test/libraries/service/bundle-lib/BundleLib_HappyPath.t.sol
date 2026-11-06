// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {BundleLib} from "@hiero-ledger/clpr/libraries/service/BundleLib.sol";
import {MockClprApplication} from "@test/mocks/MockClprApplication.sol";
import {MockClprConnector} from "@test/mocks/MockClprConnector.sol";
import {ClprTestBase} from "@test/helpers/ClprTestBase.sol";
import {BundleLibTestBase} from "@test/libraries/service/bundle-lib/BundleLibTestBase.sol";

contract BundleLib_HappyPathTest is BundleLibTestBase {
    // ── Test 1: Happy path -- single DATA message dispatched, reply queued

    function test_happyPath_singleDataMessage() public {
        _registerTestConnector();

        // Build inbound DATA message targeting our app
        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");

        _submitSingleInboundMessage(dataPayload);

        // Verify channel state updated
        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(channel.receivedMessageId, 1);
        assertEq(channel.nextMessageId, 2); // reply was queued as message ID 1

        // Verify reply was stored
        ClprTypes.MessageValue memory reply = service.getMessage(channelId, 1);
        assertTrue(reply.payload.length > 0);
        ClprTypes.DecodedReply memory decoded = ClprProtobuf.decodeReplyMessage(reply.payload);
        assertEq(decoded.messageId, 1); // reply to inbound message 1
        assertEq(uint8(decoded.status), uint8(ClprTypes.ReplyStatus.SUCCESS));

        // Verify app was called
        assertEq(app.getMessageCallCount(), 1);

        // Verify connector inbound notification was delivered
        assertEq(connector.inboundCallCount(), 1);
    }

    function test_inboundMessage_connectorRevert_doesNotBlock() public {
        _registerTestConnector();
        connector.setInboundReverts(true);

        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");

        // Bundle still processes successfully despite reverting onInboundMessage
        _submitSingleInboundMessage(dataPayload);

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(channel.receivedMessageId, 1);
        assertEq(channel.nextMessageId, 2); // reply still queued
        assertEq(app.getMessageCallCount(), 1); // app still dispatched
        assertEq(connector.inboundCallCount(), 0); // mock didn't record (it reverted)
    }

    /// A zero `connectorInboundGasStipend` turns the inbound notification off: the connector is not
    /// called and no failure is reported. The payment has its own budget, `connectorPaymentGasLimit`,
    /// so the connector still pays and is not slashed.
    function test_zeroStipend_skipsTheNotification_butNotThePayment() public {
        _registerTestConnector();
        ClprTypes.EconomicConfig memory econ = service.getEconomicConfig();
        econ.connectorInboundGasStipend = 0;
        service.updateEconomicConfiguration(econ);
        vm.txGasPrice(1 gwei);
        uint256 submitterBefore = address(this).balance;

        vm.recordLogs();
        _submitSingleInboundMessage(
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F")
        );

        assertEq(connector.inboundCallCount(), 0, "the connector is not notified");
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; i++) {
            assertTrue(
                logs[i].topics[0] != BundleLib.ConnectorInboundCallbackFailed.selector, "and no failure is reported"
            );
        }
        assertGt(address(this).balance, submitterBefore, "the payment still goes through");
        assertEq(service.getConnector(channelId, connectorId).slashCount, 0, "and the connector is not slashed");
    }

    // ── Additional: Multi-message bundle (DATA + CONTROL)

    function test_multiMessage_dataAndControl() public {
        _registerTestConnector();

        bytes memory controlPayload = ClprProtobuf.encodeControlMessage(_makeConfig(3000));
        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"01020304");

        bytes[] memory msgs = new bytes[](2);
        msgs[0] = controlPayload;
        msgs[1] = dataPayload;

        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(controlPayload)));
        hash = sha256(abi.encodePacked(hash, sha256(dataPayload)));

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 3,
            sentRunningHash: hash,
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 2,
            lastMessageRunningHash: hash
        });
        verifier.setVerifyBundleResult(meta, msgs);
        _submitBundle(hex"00FF");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(channel.receivedMessageId, 2);
        // peerConfigTimestamp stores nanos: 3000 * 1e9 = 3000000000000
        assertEq(channel.peerConfigTimestamp, uint96(3000) * 1_000_000_000);
        assertEq(channel.nextMessageId, 2); // 1 reply queued for the DATA message
    }

    /// @dev §4.2 CLOSING: inbound bundles are still accepted and processed normally — Data
    ///      Messages are dispatched to the application and generate Response Messages. A CLOSING
    ///      channel does NOT bounce inbound DATA; it delivers it and replies SUCCESS.
    function test_dataMessage_closingState_dispatchesNormally() public {
        _registerTestConnector();

        // Keep an outbound DATA message unacked so admin-close stays at CLOSING
        // instead of advancing immediately to DRAINED.
        vm.prank(address(app));
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"4441544130");

        // Close channel
        service.closeChannel(channelId);
        assertEq(uint8(service.getChannel(channelId).status), uint8(ClprTypes.ChannelStatus.CLOSING));

        // Submit DATA message while CLOSING
        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"01020304");

        bytes[] memory msgs = new bytes[](1);
        msgs[0] = dataPayload;
        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(dataPayload)));

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 2,
            sentRunningHash: hash,
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 1,
            lastMessageRunningHash: hash
        });
        verifier.setVerifyBundleResult(meta, msgs);
        _submitBundle(hex"00FF");

        // The DATA message is dispatched to the application despite CLOSING ...
        assertEq(app.getMessageCallCount(), 1);

        // ... and generates a SUCCESS Response Message (id 2: id 1 is our own outbound DATA).
        ClprTypes.MessageValue memory reply = service.getMessage(channelId, 2);
        assertTrue(reply.payload.length > 0);
        ClprTypes.DecodedReply memory decoded = ClprProtobuf.decodeReplyMessage(reply.payload);
        assertEq(uint8(decoded.status), uint8(ClprTypes.ReplyStatus.SUCCESS));
    }

    /// @dev — `if (connectorContract.code.length == 0) return`
    ///      _notifyConnectorInbound skips the IClprConnector.onInboundMessage call when
    ///      the registered connectorContract is an EOA (code.length == 0).
    function test_notifyConnectorInbound_noCodeAddress_skipsCallback() public {
        // Register the real connector (has code) so registration succeeds.
        _registerTestConnector();
        // Wipe the code after registration so code.length == 0 at dispatch time.
        vm.etch(address(connector), new bytes(0));

        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");
        _submitSingleInboundMessage(dataPayload);

        // Bundle completes without revert; channel remains ACTIVE.
        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE));
    }

    receive() external payable {}
}
