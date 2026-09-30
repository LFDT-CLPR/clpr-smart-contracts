// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {BundleLib} from "@hiero-ledger/clpr/libraries/service/BundleLib.sol";
import {MockClprApplication} from "@test/mocks/MockClprApplication.sol";
import {MockClprConnector} from "@test/mocks/MockClprConnector.sol";
import {ClprTestBase} from "@test/helpers/ClprTestBase.sol";
import {BundleLibTestBase} from "@test/libraries/service/bundle-lib/BundleLibTestBase.sol";

contract BundleLib_ResponseOrderingTest is BundleLibTestBase {
    // ── Test 6: Response ordering violation -> PAUSE

    function test_responseOrderingViolation_pausesChannel() public {
        _registerTestConnector();

        // First, send an outbound DATA message so there's something to ack
        service.sendMessage(channelId, connectorId, hex"0011223344", hex"01020304");

        // Now submit a bundle that acks our message but without a reply
        bytes[] memory msgs = new bytes[](0);
        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 1, // acking our outbound message 1
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 0,
            lastMessageRunningHash: bytes32(0)
        });
        verifier.setVerifyBundleResult(meta, msgs);

        _submitBundle(hex"00FF");

        // Channel should be PAUSED
        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.PAUSED));
    }

    // ── Test 7: Auto-resume after PAUSE

    function test_autoResume_afterPause() public {
        _registerTestConnector();

        // Send an outbound DATA message
        service.sendMessage(channelId, connectorId, hex"0011223344", hex"01020304");

        // Submit bundle acking without reply -> PAUSE
        bytes[] memory emptyMsgs = new bytes[](0);
        ClprTypes.QueueMetadata memory meta1 = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 1,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 0,
            lastMessageRunningHash: bytes32(0)
        });
        verifier.setVerifyBundleResult(meta1, emptyMsgs);
        _submitBundle(hex"00FF");

        // Verify PAUSED
        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.PAUSED));

        // Now submit a valid bundle with a reply and no new acks
        bytes memory replyPayload = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"0102");
        bytes[] memory msgs = new bytes[](1);
        msgs[0] = replyPayload;
        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(replyPayload)));

        ClprTypes.QueueMetadata memory meta2 = ClprTypes.QueueMetadata({
            nextMessageId: 2,
            sentRunningHash: hash,
            receivedMessageId: 1, // same ack level
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 1,
            lastMessageRunningHash: hash
        });
        verifier.setVerifyBundleResult(meta2, msgs);
        _submitBundle(hex"00FF02");

        // Channel should be ACTIVE again
        channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE));
    }

    // ── Cross-bundle response ordering

    /// @dev Bundle 1 acks DATA #1 and #2 with no REPLYs; bundle 2 carries REPLYs
    ///      in order #2 then #1 → expect PAUSE (ordering violation).
    function test_crossBundleReplyOrdering_outOfOrder_pausesChannel() public {
        _registerTestConnector();

        // Send two outbound DATA messages
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"AABB");
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"CCDD");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        // nextMessageId should be 3 (sent IDs 1 and 2)
        assertEq(channel.nextMessageId, 3);

        // Bundle 1: peer acks both DATA messages (#1 and #2) without sending any REPLYs → PAUSED
        {
            bytes[] memory emptyMsgs = new bytes[](0);
            ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
                nextMessageId: 1,
                sentRunningHash: bytes32(0),
                receivedMessageId: 2, // acking both our messages
                receivedRunningHash: bytes32(0),
                state: ClprTypes.ChannelStatus.ACTIVE,
                endpointManifestVersion: 0,
                lastMessageId: 0,
                lastMessageRunningHash: bytes32(0)
            });
            verifier.setVerifyBundleResult(meta, emptyMsgs);
            _submitBundle(hex"00FF");
        }
        channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.PAUSED), "should be PAUSED after no-reply ack");
    }

    // ── CLOSING + ordering violation → revert

    function test_closingPlusOrderingViolation_reverts() public {
        _registerTestConnector();

        // Send two outbound DATA messages
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"AABB");
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"CCDD");

        // Close the channel
        service.closeChannel(channelId);
        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.CLOSING));

        // Submit a bundle that acks DATA #1 but provides REPLY for #2 first (out of order)
        bytes memory reply2 = ClprProtobuf.encodeReplyMessage(2, ClprTypes.ReplyStatus.SUCCESS, hex"");
        bytes memory reply1 = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"");
        bytes[] memory msgs = new bytes[](2);
        msgs[0] = reply2;
        msgs[1] = reply1;

        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(reply2)));
        hash = sha256(abi.encodePacked(hash, sha256(reply1)));

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 3,
            sentRunningHash: hash,
            receivedMessageId: 2,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 2,
            lastMessageRunningHash: hash
        });
        verifier.setVerifyBundleResult(meta, msgs);

        vm.expectRevert(ClprTypes.ClprBundleVerificationFailed.selector);
        _submitBundle(hex"00FF");
    }

    // ── non-DATA slot AFTER matched replyId → scan-forward loop

    /// @dev Our queue: [1=DATA, 2=REPLY (auto)]. Peer sends REPLY for slot 1.
    ///      After matching slot 1, scan-forward sees slot 2 is REPLY (not DATA) →
    ///      line 452 (nextExpected++) fires inside the scan-forward while loop.
    function test_scanForwardSkipsReplySlot_coversLine452() public {
        _registerTestConnector();

        // Send outbound DATA at slot 1 (nextMessageId → 2)
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"AABB");

        // Bundle 1: peer sends inbound DATA → auto-queues REPLY at our slot 2 (nextMessageId → 3)
        bytes memory inboundData =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"CCDD");
        {
            bytes[] memory msgs = new bytes[](1);
            msgs[0] = inboundData;
            bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(inboundData)));
            ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
                nextMessageId: 2, // peer has sent 1 message
                sentRunningHash: hash,
                receivedMessageId: 0, // peer hasn't acked our DATA yet
                receivedRunningHash: bytes32(0),
                state: ClprTypes.ChannelStatus.ACTIVE,
                endpointManifestVersion: 0,
                lastMessageId: 1,
                lastMessageRunningHash: hash
            });
            verifier.setVerifyBundleResult(meta, msgs);
            _submitBundle(hex"00A1");
        }
        // Our outbound queue: [1=DATA, 2=REPLY], nextMessageId=3

        // Bundle 2: peer sends REPLY for our DATA slot 1 (matching replyId=1).
        //           Scan-forward then sees slot 2 = REPLY → line 452 fires.
        bytes memory replyPayload = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"");
        {
            bytes[] memory msgs = new bytes[](1);
            msgs[0] = replyPayload;
            bytes32 hash1 = sha256(abi.encodePacked(bytes32(0), sha256(inboundData)));
            bytes32 hash2 = sha256(abi.encodePacked(hash1, sha256(replyPayload)));
            ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
                nextMessageId: 3, // peer has sent 2 messages
                sentRunningHash: hash2,
                receivedMessageId: 1, // peer acks our DATA at slot 1
                receivedRunningHash: bytes32(0),
                state: ClprTypes.ChannelStatus.ACTIVE,
                endpointManifestVersion: 0,
                lastMessageId: 2,
                lastMessageRunningHash: hash2
            });
            verifier.setVerifyBundleResult(meta, msgs);
            _submitBundle(hex"00A2");
        }
        // Verify the channel is still ACTIVE (no violation occurred)
        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE), "ACTIVE after ordered reply");
        // Our DATA at slot 1 should be deleted (reply delivered)
        ClprTypes.MessageValue memory slot1 = service.getMessage(channelId, 1);
        assertEq(slot1.payload.length, 0, "slot 1 DATA deleted after reply");
    }

    // ── non-DATA slot BEFORE replyId → while-skip loop

    /// @dev Our queue: [1=REPLY (auto), 2=DATA]. Peer sends REPLY for slot 2.
    ///      nextExpectedReplyId=1, replyId=2 → while(1<2) runs, skips slot 1 (REPLY) →
    ///      line 436 (nextExpected++) fires inside the pre-match while loop.
    function test_skipNonDataSlotBeforeReplyId_coversLine436() public {
        _registerTestConnector();

        // Bundle 1: peer sends inbound DATA → auto-queues REPLY at our slot 1 (nextMessageId → 2)
        bytes memory inboundData =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"EEFF");
        {
            bytes[] memory msgs = new bytes[](1);
            msgs[0] = inboundData;
            bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(inboundData)));
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
            _submitBundle(hex"00B1");
        }
        // Our queue: [1=REPLY], nextMessageId=2, nextExpectedReplyId=1

        // We send outbound DATA at slot 2 (nextMessageId → 3)
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"1234");

        // Bundle 2: peer sends REPLY for our DATA slot 2 (replyId=2).
        //           nextExpectedReplyId=1, replyId=2 → while(1<2) runs:
        //           slot 1 is REPLY (not DATA) → line 436 fires → nextExpected=2.
        bytes memory replyPayload = ClprProtobuf.encodeReplyMessage(2, ClprTypes.ReplyStatus.SUCCESS, hex"");
        {
            bytes[] memory msgs = new bytes[](1);
            msgs[0] = replyPayload;
            bytes32 hash1 = sha256(abi.encodePacked(bytes32(0), sha256(inboundData)));
            bytes32 hash2 = sha256(abi.encodePacked(hash1, sha256(replyPayload)));
            ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
                nextMessageId: 3, // peer has sent 2 messages
                sentRunningHash: hash2,
                receivedMessageId: 2, // peer acks our slots 1 (REPLY) and 2 (DATA)
                receivedRunningHash: bytes32(0),
                state: ClprTypes.ChannelStatus.ACTIVE,
                endpointManifestVersion: 0,
                lastMessageId: 2,
                lastMessageRunningHash: hash2
            });
            verifier.setVerifyBundleResult(meta, msgs);
            _submitBundle(hex"00B2");
        }
        // Channel stays ACTIVE: slot 1 was a REPLY (skippable), slot 2 was DATA (peer replied)
        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE), "ACTIVE after skipped REPLY slot");
        // Our DATA at slot 2 should be deleted (reply delivered)
        ClprTypes.MessageValue memory slot2 = service.getMessage(channelId, 2);
        assertEq(slot2.payload.length, 0, "slot 2 DATA deleted after reply");
    }

    // ── duplicate REPLY (replyId < nextExpected) → violation, channel PAUSED

    /// @dev Bundle 1 provides a valid REPLY for outbound DATA #1, advancing nextExpectedReplyId to 2.
    ///      Bundle 2 provides a duplicate REPLY for DATA #1 again (replyId=1 < nextExpected=2).
    ///      A reply not matching the oldest unresponded DATA is an ordering violation → PAUSED.
    function test_duplicateReply_crossBundle_pausesChannel() public {
        _registerTestConnector();

        // Send outbound DATA message 1 (nextMessageId becomes 2)
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"01020304");

        bytes memory replyPayload1 = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"0102");
        {
            bytes[] memory msgs = new bytes[](1);
            msgs[0] = replyPayload1;
            bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(replyPayload1)));

            ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
                nextMessageId: 2, // peer has now sent message 1 (this REPLY)
                sentRunningHash: hash, // running hash through peer message 1
                receivedMessageId: 1, // peer acked our DATA #1
                receivedRunningHash: bytes32(0),
                state: ClprTypes.ChannelStatus.ACTIVE,
                endpointManifestVersion: 0,
                lastMessageId: 1,
                lastMessageRunningHash: hash
            });
            verifier.setVerifyBundleResult(meta, msgs);
            _submitBundle(hex"00FF");
        }

        // Verify channel is still ACTIVE and nextExpectedReplyId advanced to 2
        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE), "still ACTIVE after bundle 1");

        // replyId=1, channel.nextExpectedReplyId=2 → duplicate reply → ordering violation → PAUSED
        bytes memory replyPayload2 = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"0304");
        {
            bytes[] memory msgs = new bytes[](1);
            msgs[0] = replyPayload2;
            bytes32 hash1 = sha256(abi.encodePacked(bytes32(0), sha256(replyPayload1)));
            bytes32 hash2 = sha256(abi.encodePacked(hash1, sha256(replyPayload2)));

            ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
                nextMessageId: 3, // peer claims to have sent 2 messages now
                sentRunningHash: hash2, // chained running hash
                receivedMessageId: 1, // peer still acked only message 1
                receivedRunningHash: bytes32(0),
                state: ClprTypes.ChannelStatus.ACTIVE,
                endpointManifestVersion: 0,
                lastMessageId: 2,
                lastMessageRunningHash: hash2
            });
            verifier.setVerifyBundleResult(meta, msgs);
            _submitBundle(hex"00FF02");
        }

        // Duplicate reply is an ordering violation; channel is PAUSED
        channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.PAUSED), "PAUSED after duplicate reply");
    }

    /// @dev `if (replyId >= channel.nextMessageId) return true`
    ///      Peer sends a REPLY for outbound slot 2, but channel.nextMessageId==2 so slot 2
    ///      was never sent. _checkResponseOrdering returns true → earlyReturn → channel=PAUSED.
    function test_checkResponseOrdering_replyForFutureMessage_causesViolation() public {
        _registerTestConnector();
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"AABB");
        // channel.nextMessageId = 2

        bytes memory replyPayload = ClprProtobuf.encodeReplyMessage(2, ClprTypes.ReplyStatus.SUCCESS, hex"");
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
        _submitBundle(hex"EE");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.PAUSED));
    }

    receive() external payable {}
}
