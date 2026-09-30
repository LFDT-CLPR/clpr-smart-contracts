// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {ClprService} from "@hiero-ledger/clpr/ClprService.sol";
import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";
import {ClprTypes, ChannelStatusChanged} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {MockClprVerifier} from "@test/mocks/MockClprVerifier.sol";
import {MockClprApplication} from "@test/mocks/MockClprApplication.sol";
import {MockClprConnector} from "@test/mocks/MockClprConnector.sol";
import {BundleLib} from "@hiero-ledger/clpr/libraries/service/BundleLib.sol";
import {BundleLogicTestBase} from "@test/logic/bundle-logic/BundleLogicTestBase.sol";

contract BundleLogic_HappyPath is BundleLogicTestBase {
    MockClprApplication public app;

    function setUp() public override {
        super.setUp();
        app = new MockClprApplication();
        app.setResponse(hex"504F4E47"); // "PONG"
    }

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

    function test_replyMessage_deletesOriginal() public {
        _registerTestConnector();

        // First send an outbound DATA message
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"01020304");

        // Verify outbound message exists
        ClprTypes.MessageValue memory original = service.getMessage(channelId, 1);
        assertTrue(original.payload.length > 0);

        // Submit inbound REPLY for message 1, with ack of message 1
        bytes memory replyPayload = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"0102");
        bytes[] memory msgs = new bytes[](1);
        msgs[0] = replyPayload;
        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(replyPayload)));

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 2,
            sentRunningHash: hash,
            receivedMessageId: 1, // must ack message 1 to match the reply
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 1,
            lastMessageRunningHash: hash
        });
        verifier.setVerifyBundleResult(meta, msgs);
        _submitBundle(hex"00FF");

        // Original should be deleted
        ClprTypes.MessageValue memory deleted = service.getMessage(channelId, 1);
        assertEq(deleted.payload.length, 0);
        assertEq(deleted.runningHashAfterProcessing, bytes32(0));
    }

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

    function test_emptyBundle_withZeroAck() public {
        bytes[] memory msgs = new bytes[](0);

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 0,
            lastMessageRunningHash: bytes32(0)
        });
        verifier.setVerifyBundleResult(meta, msgs);
        // _newTrustAnchor defaults to "" in mock, receivedMessageId == ackedMessageId == 0
        // → nothing accomplished → NoProgress revert

        vm.expectRevert(BundleLib.NoProgress.selector);
        _submitBundle(hex"00FF");
    }

    receive() external payable override {}
}
