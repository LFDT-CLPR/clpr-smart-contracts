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

    // ── Prefix bundles: ack ahead of the last REPLY while the peer still has queued messages

    /// @dev Peer received DATA 1..3 and queued REPLY 1..3 (its nextMessageId = 4), but the
    ///      bundle is a capped prefix carrying only REPLY 1, under ack = 3. REPLY 2..3 are still
    ///      in the peer's queue, so this is not AwaitingReply: the channel must stay ACTIVE and
    ///      dispatch REPLY 1.
    function test_prefixBundle_ackAheadOfLastReply_staysActive() public {
        _registerTestConnector();
        for (uint256 i = 0; i < 3; i++) {
            service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"AABB");
        }

        bytes[] memory replies = _replies(1, 3);
        bytes32[] memory hashes = _runningHashes(replies);

        // Bundle 1: prefix [REPLY 1] of the peer's 3-message queue, ack = 3.
        bytes[] memory prefix = new bytes[](1);
        prefix[0] = replies[0];
        verifier.setVerifyBundleResult(_peerMeta(4, hashes[2], 3, 1, hashes[0]), prefix);
        _submitBundle(hex"00F1");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE), "prefix must not pause");
        assertEq(channel.receivedMessageId, 1, "REPLY 1 dispatched");
        assertEq(channel.ackedMessageId, 3, "ack committed");
        assertEq(channel.nextExpectedReplyId, 2, "next expected reply advanced");

        // Bundle 2: the rest of the queue [REPLY 2, REPLY 3] drains the peer; all DATA answered.
        bytes[] memory rest = new bytes[](2);
        rest[0] = replies[1];
        rest[1] = replies[2];
        verifier.setVerifyBundleResult(_peerMeta(4, hashes[2], 3, 3, hashes[2]), rest);
        _submitBundle(hex"00F2");

        channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE), "drained bundle stays ACTIVE");
        assertEq(channel.receivedMessageId, 3, "all replies dispatched");
        assertEq(channel.nextExpectedReplyId, 4, "every DATA answered");
    }

    /// @dev A message-less bundle whose ack covers DATA 1..2 while the peer still has REPLY 1..2
    ///      undelivered (peer nextMessageId = 3, nothing received yet) must not pause either.
    function test_ackOnlyBundle_peerHasUndeliveredMessages_staysActive() public {
        _registerTestConnector();
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"AABB");
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"CCDD");

        bytes32[] memory hashes = _runningHashes(_replies(1, 2));
        verifier.setVerifyBundleResult(_peerMeta(3, hashes[1], 2, 0, bytes32(0)), new bytes[](0));
        _submitBundle(hex"00F3");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE), "ack-only with backlog must not pause");
        assertEq(channel.ackedMessageId, 2, "ack committed");
        assertEq(channel.nextExpectedReplyId, 1, "no reply consumed");
    }

    /// @dev The bundle reaches the end of the peer's queue (peer nextMessageId = 2, last = 1) yet
    ///      the ack covers DATA 2..3 with no REPLY anywhere: a genuine AwaitingReply, still PAUSED.
    function test_drainedBundle_ackedDataWithoutReply_stillPauses() public {
        _registerTestConnector();
        for (uint256 i = 0; i < 3; i++) {
            service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"AABB");
        }

        bytes[] memory replies = _replies(1, 1);
        bytes32[] memory hashes = _runningHashes(replies);
        verifier.setVerifyBundleResult(_peerMeta(2, hashes[0], 3, 1, hashes[0]), replies);
        _submitBundle(hex"00F4");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.PAUSED), "drained + unanswered must pause");
        assertEq(channel.receivedMessageId, 0, "dispatch skipped");
        assertEq(channel.ackedMessageId, 3, "ack still committed");
    }

    /// @dev A bundle built from a stale request: it re-sends only the already-received REPLY 1
    ///      (lastMessageId == receivedMessageId) under a fresher ack = 3, while REPLY 2..3 are still
    ///      queued on the peer. The ack advance is progress and must commit without pausing.
    function test_duplicateOnlyBundle_peerStillQueued_staysActive() public {
        bytes32[] memory hashes = _sendThreeAndReceiveReplyOne();

        bytes[] memory dup = _replies(1, 1);
        verifier.setVerifyBundleResult(_peerMeta(4, hashes[2], 3, 1, hashes[0]), dup);
        _submitBundle(hex"00F6");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE), "stale duplicate must not pause");
        assertEq(channel.receivedMessageId, 1, "nothing new dispatched");
        assertEq(channel.ackedMessageId, 3, "ack committed");
        assertEq(channel.nextExpectedReplyId, 2, "reply cursor unchanged");
    }

    /// @dev Same duplicate-only shape, but the peer's queue ends at REPLY 1 (nextMessageId = 2) while
    ///      its ack covers DATA 2..3: the tail is reached, so the unanswered DATA still pauses.
    function test_duplicateOnlyBundle_peerDrained_ackedDataWithoutReply_pauses() public {
        bytes32[] memory hashes = _sendThreeAndReceiveReplyOne();

        bytes[] memory dup = _replies(1, 1);
        verifier.setVerifyBundleResult(_peerMeta(2, hashes[0], 3, 1, hashes[0]), dup);
        _submitBundle(hex"00F7");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.PAUSED), "drained + unanswered must pause");
        assertEq(channel.ackedMessageId, 3, "ack still committed");
    }

    /// @dev A CLOSING channel with DATA 1..3 unanswered drains through prefix bundles. Each bundle's
    ///      ack (3) is ahead of its last REPLY; the replies must still dispatch, or nextExpectedReplyId
    ///      never passes lastDataMessageId and CLOSING -> DRAINED can never fire.
    function test_closing_prefixBundles_drainToDrained() public {
        _registerTestConnector();
        for (uint256 i = 0; i < 3; i++) {
            service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"AABB");
        }
        service.closeChannel(channelId);
        assertEq(uint8(service.getChannel(channelId).status), uint8(ClprTypes.ChannelStatus.CLOSING));

        bytes[] memory replies = _replies(1, 3);
        bytes32[] memory hashes = _runningHashes(replies);

        bytes[] memory prefix = new bytes[](1);
        prefix[0] = replies[0];
        ClprTypes.QueueMetadata memory meta = _peerMeta(4, hashes[2], 3, 1, hashes[0]);
        meta.state = ClprTypes.ChannelStatus.CLOSING;
        verifier.setVerifyBundleResult(meta, prefix);
        _submitBundle(hex"00F8");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.CLOSING), "still awaiting REPLY 2..3");
        assertEq(channel.receivedMessageId, 1, "REPLY 1 dispatched while CLOSING");
        assertEq(channel.nextExpectedReplyId, 2, "reply cursor advanced");

        bytes[] memory rest = new bytes[](2);
        rest[0] = replies[1];
        rest[1] = replies[2];
        meta = _peerMeta(4, hashes[2], 3, 3, hashes[2]);
        meta.state = ClprTypes.ChannelStatus.CLOSING;
        verifier.setVerifyBundleResult(meta, rest);
        _submitBundle(hex"00F9");

        channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.DRAINED), "all DATA answered -> DRAINED");
        assertEq(channel.receivedMessageId, 3, "all replies dispatched");
    }

    /// @dev Sends DATA 1..3, then delivers REPLY 1 as a complete queue (peer nextMessageId = 2,
    ///      ack = 1). Returns the running hashes of the peer's REPLY 1..3.
    function _sendThreeAndReceiveReplyOne() private returns (bytes32[] memory hashes) {
        _registerTestConnector();
        for (uint256 i = 0; i < 3; i++) {
            service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"AABB");
        }
        hashes = _runningHashes(_replies(1, 3));
        verifier.setVerifyBundleResult(_peerMeta(2, hashes[0], 1, 1, hashes[0]), _replies(1, 1));
        _submitBundle(hex"00F5");
        assertEq(service.getChannel(channelId).receivedMessageId, 1);
    }

    function _replies(uint64 firstId, uint64 lastId) private pure returns (bytes[] memory replies) {
        replies = new bytes[](lastId - firstId + 1);
        for (uint64 id = firstId; id <= lastId; id++) {
            replies[id - firstId] = ClprProtobuf.encodeReplyMessage(id, ClprTypes.ReplyStatus.SUCCESS, hex"01");
        }
    }

    function _runningHashes(bytes[] memory payloads) private pure returns (bytes32[] memory hashes) {
        hashes = new bytes32[](payloads.length);
        bytes32 h;
        for (uint256 i = 0; i < payloads.length; i++) {
            h = sha256(abi.encodePacked(h, sha256(payloads[i])));
            hashes[i] = h;
        }
    }

    function _peerMeta(
        uint64 nextMessageId,
        bytes32 sentRunningHash,
        uint64 receivedMessageId,
        uint64 lastMessageId,
        bytes32 lastMessageRunningHash
    ) private pure returns (ClprTypes.QueueMetadata memory) {
        return ClprTypes.QueueMetadata({
            nextMessageId: nextMessageId,
            sentRunningHash: sentRunningHash,
            receivedMessageId: receivedMessageId,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: lastMessageId,
            lastMessageRunningHash: lastMessageRunningHash
        });
    }

    receive() external payable {}
}
