// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes, ChannelStatusChanged} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {BundleLib} from "@hiero-ledger/clpr/libraries/service/BundleLib.sol";
import {MockClprApplication} from "@test/mocks/MockClprApplication.sol";
import {BundleLogicTestBase} from "@test/logic/bundle-logic/BundleLogicTestBase.sol";

/// @notice Tests for channel-closing semantics introduced by the
///         `fixing-channel-closing-logic` spec branch.
///
/// Key behavioral changes covered:
///  1. DATA messages on CLOSING/DRAINED channels are dispatched normally
///     (no CHANNEL_CLOSED; Connector charged; real Response generated).
///  2. Peer status CLOSED triggers local ACTIVE/PAUSED → CLOSING.
///  3. CLOSING → DRAINED fires when all outbound DATA messages are acked
///     (Response Messages for the peer's DATA may still be in-flight).
///  4. closeChannel from DRAINED transitions directly to CLOSED.
contract BundleLogic_ClosingLogic is BundleLogicTestBase {
    MockClprApplication internal app;

    function setUp() public override {
        super.setUp();
        app = new MockClprApplication();
        app.setResponse(hex"504F4E47"); // "PONG"
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    /// @dev Drive the channel to CLOSING via admin.
    function _adminClose() internal {
        service.closeChannel(channelId);
        assertEq(
            uint8(service.getChannel(channelId).status),
            uint8(ClprTypes.ChannelStatus.CLOSING),
            "should be CLOSING after admin close"
        );
    }

    /// @dev Submit a bundle that carries a single inbound DATA message while
    ///      the peer reports the given status. Returns the reply message ID
    ///      (= channel.nextMessageId before submission).
    function _submitDataOnStatus(ClprTypes.ChannelStatus peerStatus, uint64 peerNextMsgId, bytes32 peerHash)
        internal
        returns (uint64 replyMsgId)
    {
        _registerTestConnector();
        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");

        bytes[] memory msgs = new bytes[](1);
        msgs[0] = dataPayload;
        bytes32 hash = sha256(abi.encodePacked(peerHash, sha256(dataPayload)));

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: peerNextMsgId,
            sentRunningHash: hash,
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: peerStatus,
            endpointManifestVersion: 0,
            lastMessageId: peerNextMsgId - 1,
            lastMessageRunningHash: hash
        });
        verifier.setVerifyBundleResult(meta, msgs);

        ClprTypes.Channel memory before = service.getChannel(channelId);
        replyMsgId = before.nextMessageId;
        _submitBundle(hex"00FF");
    }

    // ── Test 1: DATA on CLOSING → dispatched normally ────────────────────────

    /// @notice A DATA message arriving on a CLOSING channel must be dispatched
    ///         to the application, generate a real Response Message, and charge the
    ///         Connector — not generate a CHANNEL_CLOSED reply (spec §4.2).
    function test_dataMessage_onClosingChannel_dispatchedNormally() public {
        _adminClose();

        // Submit a DATA message while channel is CLOSING and peer is ACTIVE.
        // We need peerNextMsgId = 2 because the channel moved to CLOSING (no outbound
        // DATA messages were sent, so lastDataMessageId = 0 and ackedMessageId = 0 ≥ 0
        // → CLOSING→DRAINED will fire immediately after this bundle; that's fine for the
        // test, what matters is the reply content).
        uint64 replyMsgId = _submitDataOnStatus(ClprTypes.ChannelStatus.ACTIVE, 2, bytes32(0));

        // The app must have been called.
        assertEq(app.getMessageCallCount(), 1, "application must be dispatched");

        // A real Response Message (not CHANNEL_CLOSED) must be queued.
        ClprTypes.MessageValue memory reply = service.getMessage(channelId, replyMsgId);
        assertTrue(reply.payload.length > 0, "reply must be queued");
        ClprTypes.DecodedReply memory decoded = ClprProtobuf.decodeReplyMessage(reply.payload);
        assertEq(decoded.messageId, 1, "reply is for inbound message 1");
        assertTrue(
            uint8(decoded.status) != uint8(ClprTypes.ReplyStatus.CHANNEL_CLOSED), "reply must NOT be CHANNEL_CLOSED"
        );
        assertEq(uint8(decoded.status), uint8(ClprTypes.ReplyStatus.SUCCESS), "reply must be SUCCESS");
    }

    /// @notice A DATA message arriving on a DRAINED channel must also be dispatched
    ///         normally — the channel still accepts the peer's remaining messages.
    function test_dataMessage_onDrainedChannel_dispatchedNormally() public {
        // Drive to CLOSING then immediately to DRAINED (no outbound DATA, so
        // lastDataMessageId = 0 and the ack check is satisfied trivially).
        _adminClose();

        bytes[] memory noMsgs = new bytes[](0);
        ClprTypes.QueueMetadata memory drainMeta = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 0,
            lastMessageRunningHash: bytes32(0)
        });
        verifier.setVerifyBundleResult(drainMeta, noMsgs);
        verifier.setNewTrustAnchor(hex"01");
        _submitBundle(hex"00FF");
        assertEq(
            uint8(service.getChannel(channelId).status), uint8(ClprTypes.ChannelStatus.DRAINED), "should be DRAINED"
        );

        // Now submit a DATA message while DRAINED.
        _registerTestConnector();
        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");
        bytes[] memory msgs = new bytes[](1);
        msgs[0] = dataPayload;
        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(dataPayload)));

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 2,
            sentRunningHash: hash,
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.DRAINED,
            endpointManifestVersion: 0,
            lastMessageId: 1,
            lastMessageRunningHash: hash
        });
        verifier.setVerifyBundleResult(meta, msgs);
        uint64 replyMsgId = service.getChannel(channelId).nextMessageId;
        _submitBundle(hex"00FF02");

        assertEq(app.getMessageCallCount(), 1, "application must be dispatched on DRAINED");
        ClprTypes.MessageValue memory reply = service.getMessage(channelId, replyMsgId);
        assertTrue(reply.payload.length > 0, "reply must be queued");
        ClprTypes.DecodedReply memory decoded = ClprProtobuf.decodeReplyMessage(reply.payload);
        assertTrue(
            uint8(decoded.status) != uint8(ClprTypes.ReplyStatus.CHANNEL_CLOSED), "reply must NOT be CHANNEL_CLOSED"
        );
    }

    // ── Test 2: Peer status CLOSED triggers local ACTIVE → CLOSING ───────────

    /// @notice A bundle arriving from a peer with status=CLOSED must trigger the
    ///         local ACTIVE channel to advance to CLOSING (spec §4.2 Step 5a).
    function test_peerClosed_triggersLocalClosing() public {
        assertEq(uint8(service.getChannel(channelId).status), uint8(ClprTypes.ChannelStatus.ACTIVE), "initially ACTIVE");

        bytes[] memory noMsgs = new bytes[](0);
        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.CLOSED, // peer is CLOSED
            endpointManifestVersion: 0,
            lastMessageId: 0,
            lastMessageRunningHash: bytes32(0)
        });
        verifier.setVerifyBundleResult(meta, noMsgs);
        verifier.setNewTrustAnchor(hex"AA");

        vm.expectEmit(true, false, false, true);
        emit ChannelStatusChanged(channelId, ClprTypes.ChannelStatus.CLOSING);
        _submitBundle(hex"00FF");

        // Since no outbound DATA messages exist (lastDataMessageId = 0), CLOSING → DRAINED
        // fires in the same bundle. The close-notification also sets DRAINED → CLOSED.
        ClprTypes.Channel memory channel = service.getChannel(channelId);
        // Channel transitions: ACTIVE → CLOSING → DRAINED → CLOSED (all in one bundle
        // because lastDataMessageId == 0 and peer status == CLOSED).
        assertEq(
            uint8(channel.status),
            uint8(ClprTypes.ChannelStatus.CLOSED),
            "channel should be CLOSED after peer close-notification with no local DATA"
        );
    }

    /// @notice Peer status CLOSED on a PAUSED channel also triggers CLOSING.
    function test_peerClosed_triggersLocalClosing_fromPaused() public {
        // Force a PAUSED state by sending a bundle with out-of-order REPLYs.
        // Simpler: submit a bundle that signals PAUSED directly via a known pattern.
        // Use peer state CLOSING which is already supported to put it in CLOSING,
        // then separately test via the ordering path. Instead, let's directly verify
        // the condition in _applyStateMachine by checking it on PAUSED.
        // We'll use a bundle that contains an out-of-sequence REPLY to trigger PAUSED.
        _registerTestConnector();

        // Send an outbound DATA message first so there's a pending REPLY to expect.
        vm.prank(address(app));
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"01020304");

        // Submit a bundle with a REPLY that refers to message 2 (skipping message 1) —
        // this should trigger PAUSED per the ordering check.
        bytes memory badReply = ClprProtobuf.encodeReplyMessage(2, ClprTypes.ReplyStatus.SUCCESS, hex"");
        bytes[] memory msgs = new bytes[](1);
        msgs[0] = badReply;
        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(badReply)));

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

        assertEq(
            uint8(service.getChannel(channelId).status),
            uint8(ClprTypes.ChannelStatus.PAUSED),
            "should be PAUSED after out-of-order reply"
        );

        // Now submit a bundle with peer status = CLOSED.
        // After the PAUSED early-return, channel.receivedMessageId was NOT updated (stays 0),
        // so expectedFirstId = 1 and with 0 messages nextMessageId must be 1.
        // channel.receivedRunningHash also not updated (stays bytes32(0) from initial state),
        // so computedHash = bytes32(0) (the receivedMessageId==0 branch kicks in).
        bytes[] memory noMsgs = new bytes[](0);
        ClprTypes.QueueMetadata memory closedMeta = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.CLOSED,
            endpointManifestVersion: 0,
            lastMessageId: 0,
            lastMessageRunningHash: bytes32(0)
        });
        verifier.setVerifyBundleResult(closedMeta, noMsgs);
        verifier.setNewTrustAnchor(hex"BB");
        _submitBundle(hex"00FF02");

        uint8 status = uint8(service.getChannel(channelId).status);
        assertTrue(
            status == uint8(ClprTypes.ChannelStatus.CLOSING) || status == uint8(ClprTypes.ChannelStatus.DRAINED)
                || status == uint8(ClprTypes.ChannelStatus.CLOSED),
            "PAUSED + peer CLOSED must advance toward CLOSING/DRAINED/CLOSED"
        );
    }

    // ── Test 3: CLOSING → DRAINED only waits for DATA messages ──────────────

    /// @notice CLOSING → DRAINED fires as soon as all outbound DATA messages are acked,
    ///         not when all queue messages (DATA + REPLY) are acked.
    ///         Scenario: two DATA messages sent; peer acks only the first one → still
    ///         CLOSING. Then peer acks both → DRAINED.
    function test_closingToDrained_firesOnDataAck_notFullQueueDrain() public {
        _registerTestConnector();

        // Send two outbound DATA messages.
        vm.prank(address(app));
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"4441544131");
        vm.prank(address(app));
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"4441544132");
        // lastDataMessageId = 2, nextMessageId = 3.

        // Admin-close: ACTIVE → CLOSING.
        _adminClose();

        // Pre-compute the SHA-256 hash chain for inbound messages from peer.
        // Bundle A has reply1; bundle B has reply2. Hash must chain across bundles because
        // channel.receivedRunningHash is updated at the end of each bundle.
        bytes memory reply1 = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"");
        bytes memory reply2 = ClprProtobuf.encodeReplyMessage(2, ClprTypes.ReplyStatus.SUCCESS, hex"");
        bytes32 hashA = sha256(abi.encodePacked(bytes32(0), sha256(reply1)));
        bytes32 hashB = sha256(abi.encodePacked(hashA, sha256(reply2)));

        // Bundle A: peer sends REPLY for our DATA#1 only (not DATA#2).
        // Peer acks only DATA#1 (receivedMessageId=1).
        {
            bytes[] memory msgs = new bytes[](1);
            msgs[0] = reply1;
            ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
                nextMessageId: 2, // peer sends message 1 in this bundle
                sentRunningHash: hashA,
                receivedMessageId: 1, // peer acked our DATA#1
                receivedRunningHash: bytes32(0),
                state: ClprTypes.ChannelStatus.ACTIVE,
                endpointManifestVersion: 0,
                lastMessageId: 1,
                lastMessageRunningHash: hashA
            });
            verifier.setVerifyBundleResult(meta, msgs);
            _submitBundle(hex"00FF");
        }
        // ackedMessageId=1 < lastDataMessageId=2 → still CLOSING.
        assertEq(
            uint8(service.getChannel(channelId).status),
            uint8(ClprTypes.ChannelStatus.CLOSING),
            "should still be CLOSING - DATA#2 not yet acked"
        );

        // Bundle B: peer sends REPLY for our DATA#2 and acks DATA#2.
        // sentRunningHash must continue from hashA (hash of bundle A's messages).
        {
            bytes[] memory msgs = new bytes[](1);
            msgs[0] = reply2;
            ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
                nextMessageId: 3, // peer sends message 2 in this bundle (message 1 was in bundle A)
                sentRunningHash: hashB,
                receivedMessageId: 2, // peer acked our DATA#2 (and implicitly #1)
                receivedRunningHash: bytes32(0),
                state: ClprTypes.ChannelStatus.ACTIVE,
                endpointManifestVersion: 0,
                lastMessageId: 2,
                lastMessageRunningHash: hashB
            });
            verifier.setVerifyBundleResult(meta, msgs);
            _submitBundle(hex"00FF02");
        }
        // ackedMessageId=2 >= lastDataMessageId=2 → DRAINED.
        assertEq(
            uint8(service.getChannel(channelId).status),
            uint8(ClprTypes.ChannelStatus.DRAINED),
            "must be DRAINED once all DATA messages acked"
        );
    }

    /// @notice When there are NO outbound DATA messages (only CONTROL/REPLY messages),
    ///         CLOSING → DRAINED should fire immediately (lastDataMessageId == 0).
    function test_closingToDrained_noDataMessages_firesImmediately() public {
        // No sendMessage calls → lastDataMessageId = 0.
        _adminClose();

        bytes[] memory noMsgs = new bytes[](0);
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
        verifier.setVerifyBundleResult(meta, noMsgs);
        verifier.setNewTrustAnchor(hex"CC");
        _submitBundle(hex"00FF");

        assertEq(
            uint8(service.getChannel(channelId).status),
            uint8(ClprTypes.ChannelStatus.DRAINED),
            "CLOSING->DRAINED must fire immediately when no DATA messages were ever sent"
        );
    }

    // ── Test 4: DRAINED → CLOSED waits for the peer's whole queue ───────────

    /// @dev Peer queue metadata proven for a DRAINED peer.
    function _drainedPeerMeta(uint64 nextId, bytes32 sentHash, uint64 acked, uint64 lastId, bytes32 lastHash)
        internal
        pure
        returns (ClprTypes.QueueMetadata memory)
    {
        return ClprTypes.QueueMetadata({
            nextMessageId: nextId,
            sentRunningHash: sentHash,
            receivedMessageId: acked,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.DRAINED,
            endpointManifestVersion: 0,
            lastMessageId: lastId,
            lastMessageRunningHash: lastHash
        });
    }

    /// @notice A partial bundle from a DRAINED peer must not close the channel while the
    ///         peer's proven queue still holds messages beyond the bundle's last one.
    ///         Scenario: our DATA#1 is acked and replied to, but the peer's queue also holds
    ///         its DATA#2, which bundle A does not carry.
    function test_drainedToClosed_waitsForPeerQueue_acrossPartialBundles() public {
        _registerTestConnector();
        vm.prank(address(app));
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"4441544131");
        _adminClose();

        bytes memory reply1 = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"");
        bytes memory data2 =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");
        bytes32 hash1 = sha256(abi.encodePacked(bytes32(0), sha256(reply1)));
        bytes32 hash2 = sha256(abi.encodePacked(hash1, sha256(data2)));

        // Bundle A: prefix of the peer's queue (message 1 of 2); our only message is acked.
        bytes[] memory msgs = new bytes[](1);
        msgs[0] = reply1;
        verifier.setVerifyBundleResult(_drainedPeerMeta(3, hash2, 1, 1, hash1), msgs);
        _submitBundle(hex"00FF");
        assertEq(
            uint8(service.getChannel(channelId).status),
            uint8(ClprTypes.ChannelStatus.DRAINED),
            "must stay DRAINED while peer message 2 is undelivered"
        );

        // A message-less bundle cannot close the channel either, so it makes no progress.
        verifier.setVerifyBundleResult(_drainedPeerMeta(3, hash2, 1, 0, bytes32(0)), new bytes[](0));
        vm.expectRevert(BundleLib.NoProgress.selector);
        _submitBundle(hex"00FF01");

        // Bundle B: the rest of the peer's queue. Our reply to DATA#2 is still unacked.
        msgs[0] = data2;
        verifier.setVerifyBundleResult(_drainedPeerMeta(3, hash2, 1, 2, hash2), msgs);
        _submitBundle(hex"00FF02");
        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(channel.receivedMessageId, 2, "peer queue fully received");
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.DRAINED), "our reply to DATA#2 is unacked");

        // Bundle C: peer acks our reply → CLOSED.
        verifier.setVerifyBundleResult(_drainedPeerMeta(3, hash2, 2, 0, bytes32(0)), new bytes[](0));
        _submitBundle(hex"00FF03");
        assertEq(
            uint8(service.getChannel(channelId).status),
            uint8(ClprTypes.ChannelStatus.CLOSED),
            "must CLOSE once both queues are drained"
        );
    }

    receive() external payable override {}
}
