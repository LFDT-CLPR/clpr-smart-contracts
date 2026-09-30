// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {MockClprApplication} from "@test/mocks/MockClprApplication.sol";
import {MockClprConnector} from "@test/mocks/MockClprConnector.sol";
import {BundleLibTestBase} from "@test/libraries/service/bundle-lib/BundleLibTestBase.sol";

contract BundleLib_ReplyDeliveryTest is BundleLibTestBase {
    // ── Test 11: REPLY message -> deletes original

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

    // ── Additional: onClprResponse callback on reply delivery

    function test_replyMessage_callsOnClprResponse() public {
        _registerTestConnector();

        // Send outbound DATA as `app` so the service stamps sender = app.
        // The REPLY will then be delivered via onClprResponse on app.
        vm.prank(address(app));
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"01020304");

        // Submit inbound REPLY for message 1 (must ack message 1)
        bytes memory replyPayload = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"AABB0102");
        bytes[] memory msgs = new bytes[](1);
        msgs[0] = replyPayload;
        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(replyPayload)));

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 2,
            sentRunningHash: hash,
            receivedMessageId: 1, // ack message 1
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 1,
            lastMessageRunningHash: hash
        });
        verifier.setVerifyBundleResult(meta, msgs);
        _submitBundle(hex"00FF");

        // Verify onClprResponse was called
        assertEq(app.getResponseCallCount(), 1);
    }

    // ── Additional: onClprResponse revert is caught (best-effort)

    function test_replyMessage_responseRevert_isCaught() public {
        _registerTestConnector();

        // Configure response callback to revert
        app.setResponseShouldRevert(true, "Response revert");

        // Send outbound DATA
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"01020304");

        // Submit inbound REPLY (must ack message 1)
        bytes memory replyPayload = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"0102");
        bytes[] memory msgs = new bytes[](1);
        msgs[0] = replyPayload;
        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(replyPayload)));

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 2,
            sentRunningHash: hash,
            receivedMessageId: 1, // ack message 1
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 1,
            lastMessageRunningHash: hash
        });
        verifier.setVerifyBundleResult(meta, msgs);

        // Should not revert even though onClprResponse reverts
        _submitBundle(hex"00FF");

        // Original message should still be deleted
        ClprTypes.MessageValue memory deleted = service.getMessage(channelId, 1);
        assertEq(deleted.payload.length, 0);
    }

    // ── Additional: Source-side slashing on CONNECTOR_NOT_FOUND reply

    function test_replyMessage_sourceSlash_connectorNotFound() public {
        _registerTestConnector();

        // Send outbound DATA
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"01020304");

        // Get connector state before
        ClprTypes.Connector memory connBefore = service.getConnector(channelId, connectorId);
        uint256 stakeBefore = connBefore.lockedStake;

        // Submit reply with CONNECTOR_NOT_FOUND status (must ack message 1)
        bytes memory replyPayload = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.CONNECTOR_NOT_FOUND, hex"");
        bytes[] memory msgs = new bytes[](1);
        msgs[0] = replyPayload;
        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(replyPayload)));

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 2,
            sentRunningHash: hash,
            receivedMessageId: 1, // ack message 1
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 1,
            lastMessageRunningHash: hash
        });
        verifier.setVerifyBundleResult(meta, msgs);
        _submitBundle(hex"00FF");

        // Connector should have been slashed
        ClprTypes.Connector memory connAfter = service.getConnector(channelId, connectorId);
        assertTrue(connAfter.lockedStake < stakeBefore);
    }

    /// @dev `if (msgType == CONTROL)` FALSE branch.
    ///      — `else if (msgType == DATA)` FALSE branch.
    ///      Covered by an inbound REPLY message: neither CONTROL nor DATA, so both
    ///      checks evaluate to false before the REPLY arm is reached.
    function test_dispatchLoop_replyMessage_coversNonControlNonDataBranches() public {
        _registerTestConnector();
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"AABB");
        // channel.nextMessageId=2, channel.nextExpectedReplyId=1

        bytes memory replyPayload = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"");
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
        _submitBundle(hex"DD");

        // Outbound DATA at slot 1 was deleted when the REPLY was processed.
        ClprTypes.MessageValue memory slot1 = service.getMessage(channelId, 1);
        assertEq(slot1.payload.length, 0);
    }

    // ── redactMessage decrements inflight so removeConnector can succeed; REPLY still slashes the connector

    function test_redactMessage_decrementsInflight() public {
        _registerTestConnector();

        // Send a DATA message
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"01020304");

        // Redact it
        service.redactMessage(channelId, 1);

        // Now removeConnector should succeed (inflight = 0 after redaction fix)
        // First we need to ack the message so removeConnector's inflight check passes.
        // The ack is what processBundle does, but we can also test removeConnector directly.
        // After redaction, inflight should be 0, so removeConnector should not revert
        // with ClprConnectorHasInflightMessages.

        // Submit a bundle that acks the redacted message (receivedMessageId=1) with no reply.
        // Since payload is redacted (empty), ordering check doesn't flag it as a live DATA.
        bytes[] memory emptyMsgs = new bytes[](0);
        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 1,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 0,
            lastMessageRunningHash: bytes32(0)
        });
        verifier.setVerifyBundleResult(meta, emptyMsgs);
        _submitBundle(hex"00FF");

        // After redaction + ack (no reply needed since payload was empty), try removeConnector
        service.removeConnector(channelId, connectorId, owner);
        // Should not revert — inflight was decremented by redactMessage
    }

    function test_redactMessage_replyStillSlashesSourceConnector() public {
        _registerTestConnector();

        // Send a DATA message
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"01020304");

        // Redact it
        service.redactMessage(channelId, 1);

        // Get connector state before
        ClprTypes.Connector memory connBefore = service.getConnector(channelId, connectorId);
        uint256 stakeBefore = connBefore.lockedStake;

        // Submit inbound CONNECTOR_NOT_FOUND reply for the redacted message
        bytes memory replyPayload = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.CONNECTOR_NOT_FOUND, hex"");
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

        // Connector is slashed by the REPLY even though the original DATA was redacted
        ClprTypes.Connector memory connAfter = service.getConnector(channelId, connectorId);
        assertTrue(connAfter.lockedStake < stakeBefore, "connector should be slashed");
    }

    receive() external payable {}
}
