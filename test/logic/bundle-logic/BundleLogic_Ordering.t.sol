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
import {ClprServiceStorageSlots, ClprStorageLayoutLib} from "@test/helpers/ClprServiceStorageSlots.sol";

/// @dev A contract with no receive()/fallback, used as both the bundle submitter and the
///      temporary service owner in test_sourceSlash_banRemovesConnector_withNonZeroInflight, so
///      that _transferWithFallback's direct-transfer and owner-fallback attempts both fail and
///      the forfeited stake lands in pendingWithdrawals.
contract NonReceivingSubmitterOwner {
    function submitBundle(IClprService svc, bytes32 connId, bytes memory proof) external {
        svc.submitBundle(connId, proof);
    }
}

contract BundleLogic_Ordering is BundleLogicTestBase {
    MockClprApplication public app;

    function setUp() public override {
        super.setUp();
        app = new MockClprApplication();
        app.setResponse(hex"504F4E47"); // "PONG"
    }

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

    // ── Ack commit on the PAUSE path

    /// @dev the ack that triggers the response-ordering PAUSE must
    ///      still be committed to chan.ackedMessageId, even though dispatch is skipped. Otherwise
    ///      chan.ackedMessageId never advances, so an identical resubmission of the same ack-only
    ///      bundle keeps looking like fresh "ack progress" to _checkBundleProgress and re-pauses
    ///      indefinitely instead of being rejected as a no-op.
    function test_pause_commitsAck_soRepeatedNoOpBundleIsRejectedAsNoProgress() public {
        _registerTestConnector();

        // Send an outbound DATA message so there's something to ack.
        service.sendMessage(channelId, connectorId, hex"0011223344", hex"01020304");

        // Bundle acks our message without providing its REPLY -> PAUSE.
        bytes[] memory emptyMsgs = new bytes[](0);
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
        verifier.setVerifyBundleResult(meta, emptyMsgs);
        _submitBundle(hex"00FF");

        ClprTypes.Channel memory chan = service.getChannel(channelId);
        assertEq(uint8(chan.status), uint8(ClprTypes.ChannelStatus.PAUSED));
        assertEq(chan.ackedMessageId, 1, "ack that triggered the pause must still be committed");

        // Resubmitting the exact same ack-only bundle no longer looks like fresh ack progress,
        // so it must be rejected as a no-op instead of re-triggering the same pause again.
        verifier.setVerifyBundleResult(meta, emptyMsgs);
        vm.expectRevert(BundleLib.NoProgress.selector);
        _submitBundle(hex"00FF");
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

    function test_peerCloseDuringPause_transitionsToClosing() public {
        _registerTestConnector();

        // Send TWO outbound DATA messages (so all outbound are NOT acked in bundle 2,
        // preventing CLOSING → DRAINED transition which would hide the CLOSING state).
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"01020304");
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"05060708");

        // Bundle 1: peer acks message 1 without providing a REPLY → PAUSED (ordering violation)
        {
            bytes[] memory emptyMsgs = new bytes[](0);
            ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
                nextMessageId: 1,
                sentRunningHash: bytes32(0),
                receivedMessageId: 1, // acking our DATA #1
                receivedRunningHash: bytes32(0),
                state: ClprTypes.ChannelStatus.ACTIVE,
                endpointManifestVersion: 0,
                lastMessageId: 0,
                lastMessageRunningHash: bytes32(0)
            });
            verifier.setVerifyBundleResult(meta, emptyMsgs);
            _submitBundle(hex"00FF");
        }
        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.PAUSED), "should be PAUSED");

        // Bundle 2: peer provides REPLY for message 1 (ordering satisfied) + peer state = CLOSING.
        //           Bundle 1's ack of message 1 is already committed (see #416 fix), so ack
        //           progress can't go backward; keep it at 1 so message 2 stays unacked and
        //           CLOSING won't immediately drain.
        {
            bytes memory replyPayload = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"");
            bytes[] memory msgs = new bytes[](1);
            msgs[0] = replyPayload;
            bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(replyPayload)));

            ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
                nextMessageId: 2,
                sentRunningHash: hash,
                receivedMessageId: 1, // no further ack progress; message 2 still unacked
                receivedRunningHash: bytes32(0),
                state: ClprTypes.ChannelStatus.CLOSING, // peer is closing
                endpointManifestVersion: 0,
                lastMessageId: 1,
                lastMessageRunningHash: hash
            });
            verifier.setVerifyBundleResult(meta, msgs);
            _submitBundle(hex"00FF02");
        }

        channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.CLOSING), "should be CLOSING");
    }

    // ── Cross-bundle response ordering

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

    // ── Repeated violation on PAUSED must not advance nextExpectedReplyId

    /// @dev Scenario
    ///      PAUSED channel receives a bundle that still violates ordering
    ///      (skips DATA#3). nextExpectedReplyId must NOT be advanced so that the
    ///      next correct bundle ([1,2,3,4]) can still recover the channel to ACTIVE.
    function test_paused_repeatedViolationAllowsRecovery() public {
        _registerTestConnector();

        // Send 4 outbound DATA messages (ids 1..4). nextMessageId=5, nextExpectedReplyId=1.
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"01");
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"02");
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"03");
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"04");

        // ── Bundle 1: peer acks DATA#1 with no reply → PAUSED ──────────────────
        {
            bytes[] memory empty = new bytes[](0);
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
            verifier.setVerifyBundleResult(meta, empty);
            _submitBundle(hex"B101");
        }
        assertEq(
            uint8(service.getChannel(channelId).status),
            uint8(ClprTypes.ChannelStatus.PAUSED),
            "should be PAUSED after bundle 1"
        );

        // Pre-compute reply payloads for the violation bundles.
        bytes memory reply1 = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"");
        bytes memory reply2 = ClprProtobuf.encodeReplyMessage(2, ClprTypes.ReplyStatus.SUCCESS, hex"");
        bytes memory reply4 = ClprProtobuf.encodeReplyMessage(4, ClprTypes.ReplyStatus.SUCCESS, hex"");

        // Running hash of [reply1, reply2, reply4] starting from bytes32(0)
        // (channel.receivedMessageId is 0, i.e. no committed peer messages yet).
        bytes32 hash124 = sha256(abi.encodePacked(bytes32(0), sha256(reply1)));
        hash124 = sha256(abi.encodePacked(hash124, sha256(reply2)));
        hash124 = sha256(abi.encodePacked(hash124, sha256(reply4)));

        // ── Bundle 2: REPLYs [1, 2, 4] – skips DATA#3 → still a violation ──────
        {
            bytes[] memory msgs = new bytes[](3);
            msgs[0] = reply1;
            msgs[1] = reply2;
            msgs[2] = reply4;
            ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
                nextMessageId: 4,
                sentRunningHash: hash124,
                receivedMessageId: 1,
                receivedRunningHash: bytes32(0),
                state: ClprTypes.ChannelStatus.ACTIVE,
                endpointManifestVersion: 0,
                lastMessageId: 3,
                lastMessageRunningHash: hash124
            });
            verifier.setVerifyBundleResult(meta, msgs);
            _submitBundle(hex"B102");
        }
        assertEq(
            uint8(service.getChannel(channelId).status),
            uint8(ClprTypes.ChannelStatus.PAUSED),
            "should still be PAUSED after bundle 2 (skip 3 violation)"
        );

        // ── Bundle 3: same incorrect bundle again → still PAUSED ─────────────
        // If nextExpectedReplyId were incorrectly advanced to 3 by bundle 2,
        // bundle 4 below (correct ordering from id=1) would be rejected as a
        // backward-reply violation and the channel would be stuck forever.
        {
            bytes[] memory msgs = new bytes[](3);
            msgs[0] = reply1;
            msgs[1] = reply2;
            msgs[2] = reply4;
            ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
                nextMessageId: 4,
                sentRunningHash: hash124,
                receivedMessageId: 1,
                receivedRunningHash: bytes32(0),
                state: ClprTypes.ChannelStatus.ACTIVE,
                endpointManifestVersion: 0,
                lastMessageId: 3,
                lastMessageRunningHash: hash124
            });
            verifier.setVerifyBundleResult(meta, msgs);
            _submitBundle(hex"B103");
        }
        assertEq(
            uint8(service.getChannel(channelId).status),
            uint8(ClprTypes.ChannelStatus.PAUSED),
            "should still be PAUSED after bundle 3 (same skip 3 violation)"
        );

        // ── Bundle 4: correct REPLYs [1, 2, 3, 4] → ACTIVE (recovery) ─────────
        bytes memory reply3 = ClprProtobuf.encodeReplyMessage(3, ClprTypes.ReplyStatus.SUCCESS, hex"");
        bytes32 hash1234 = sha256(abi.encodePacked(bytes32(0), sha256(reply1)));
        hash1234 = sha256(abi.encodePacked(hash1234, sha256(reply2)));
        hash1234 = sha256(abi.encodePacked(hash1234, sha256(reply3)));
        hash1234 = sha256(abi.encodePacked(hash1234, sha256(reply4)));
        {
            bytes[] memory msgs = new bytes[](4);
            msgs[0] = reply1;
            msgs[1] = reply2;
            msgs[2] = reply3;
            msgs[3] = reply4;
            ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
                nextMessageId: 5,
                sentRunningHash: hash1234,
                receivedMessageId: 1,
                receivedRunningHash: bytes32(0),
                state: ClprTypes.ChannelStatus.ACTIVE,
                endpointManifestVersion: 0,
                lastMessageId: 4,
                lastMessageRunningHash: hash1234
            });
            verifier.setVerifyBundleResult(meta, msgs);
            _submitBundle(hex"B104");
        }
        assertEq(
            uint8(service.getChannel(channelId).status),
            uint8(ClprTypes.ChannelStatus.ACTIVE),
            "should be ACTIVE after correct bundle 4 recovers from PAUSED"
        );
    }

    /// @dev When the channel is already PAUSED, a subsequent ordering violation
    ///      must NOT re-emit the ChannelStatusChanged(PAUSED) event — there is
    ///      no state change, so no event should fire.
    function test_paused_noSpuriousEventOnRepeatedViolation() public {
        _registerTestConnector();

        // Send 2 outbound DATA messages so we have something to violate ordering on.
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"01");
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"02");

        // Bundle 1: ack DATA#1 with no reply → transitions ACTIVE → PAUSED (1 event).
        {
            bytes[] memory empty = new bytes[](0);
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
            verifier.setVerifyBundleResult(meta, empty);
            _submitBundle(hex"C101");
        }
        assertEq(
            uint8(service.getChannel(channelId).status),
            uint8(ClprTypes.ChannelStatus.PAUSED),
            "should be PAUSED after bundle 1"
        );

        // Bundle 2: another ordering violation while already PAUSED.
        // No new state change occurs, so ChannelStatusChanged must NOT be emitted.
        bytes memory reply2 = ClprProtobuf.encodeReplyMessage(2, ClprTypes.ReplyStatus.SUCCESS, hex"");
        {
            bytes[] memory msgs = new bytes[](1);
            msgs[0] = reply2;
            bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(reply2)));
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

            vm.recordLogs();
            _submitBundle(hex"C102");
        }

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 0, "no ChannelStatusChanged event when already PAUSED");
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

    // ── CLOSING + AwaitingReply → state machine must still transition

    /// @dev A CLOSING channel receives an ack-only bundle: the ack satisfies dataAcked (so
    ///      CLOSING -> DRAINED should fire), but the acked DATA has no REPLY yet, so
    ///      _checkResponseOrdering reports AwaitingReply rather than Ok. The early-return path
    ///      must still apply the state machine transition, not just commit the ack — otherwise
    ///      the channel is stuck CLOSING forever and the identical bundle can be resubmitted
    ///      indefinitely with no progress and no revert.
    /// @dev A DATA Message that is acked but not yet answered (AwaitingReply) must NOT drain
    ///      CLOSING -> DRAINED. Draining anyway would let the channel reach DRAINED with a
    ///      REPLY still outstanding that, since no DATA Message ever exists past
    ///      lastDataMessageId, could never subsequently arrive — leaving the channel stuck.
    function test_closingPlusAwaitingReply_staysClosingUntilAnswered() public {
        _registerTestConnector();

        // Send one outbound DATA message so there is something to ack.
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"AABB");

        // Close the channel locally.
        service.closeChannel(channelId);
        ClprTypes.Channel memory chan = service.getChannel(channelId);
        assertEq(uint8(chan.status), uint8(ClprTypes.ChannelStatus.CLOSING));

        // Peer acks our DATA #1 but hasn't sent its REPLY yet -> AwaitingReply.
        bytes[] memory emptyMsgs = new bytes[](0);
        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 1, // acking our DATA #1
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.CLOSING, // peer is also closing
            endpointManifestVersion: 0,
            lastMessageId: 0,
            lastMessageRunningHash: bytes32(0)
        });
        verifier.setVerifyBundleResult(meta, emptyMsgs);
        _submitBundle(hex"00FF");

        // dataAcked is false (acked but not answered), so CLOSING -> DRAINED must not fire,
        // even though dispatch was skipped and the ack itself is still committed.
        chan = service.getChannel(channelId);
        assertEq(uint8(chan.status), uint8(ClprTypes.ChannelStatus.CLOSING), "must stay CLOSING until answered");
        assertEq(chan.ackedMessageId, 1, "ack must still be committed");

        // Resubmitting the identical no-op bundle must now be rejected as no progress,
        // instead of silently re-evaluating the same non-transition forever.
        verifier.setVerifyBundleResult(meta, emptyMsgs);
        vm.expectRevert(BundleLib.NoProgress.selector);
        _submitBundle(hex"00FF");
    }

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

        // duplicate reply → ordering violation → channel PAUSED
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

    // ── Source-side slash + in-flight decrement: no-clobber regression ────
    // The reply handler must BOTH decrement in-flight AND slash the source connector on a failure
    // reply, without one write reverting the other. In-flight lives in a dedicated mapping
    // (slot CONNECTOR_INFLIGHT), separate from the Connector struct slash() mutates, so we read
    // it directly via vm.load to assert the decrement survived.
    // (Relocated from test/logic/ConnectorManager.t.sol; adapted to use this contract's shared
    //  `connectorId` field instead of a local `cid`, and its inherited `owner` instead of a local
    //  `admin`.)

    function test_sourceSlash_connectorNotFound_decrementsInflight_noClobber() public {
        connectorId = _registerConnectorWithStake(keccak256(abi.encodePacked("cm-test")), owner, 1 ether);

        service.sendMessage(channelId, connectorId, abi.encodePacked(address(0xDEAD)), hex"01");
        assertEq(_inflight(connectorId), 1, "inflight is 1 after send");

        _submitFailureReplyBundle(1, ClprTypes.ReplyStatus.CONNECTOR_NOT_FOUND);

        ClprTypes.Connector memory c = service.getConnector(channelId, connectorId);
        assertEq(c.lockedStake, 1 ether - 0.01 ether, "stake reduced by basePenalty");
        assertEq(c.slashCount, 1, "slashed once");
        assertEq(_inflight(connectorId), 0, "decrement survives the slash");
    }

    function test_sourceSlash_connectorUnderfunded_escalatedPenalty_inflightSurvives() public {
        connectorId = _registerConnectorWithStake(keccak256(abi.encodePacked("cm-test")), owner, 1 ether);

        // Four outbound messages → inflight = 4.
        for (uint256 i = 0; i < 4; i++) {
            service.sendMessage(channelId, connectorId, abi.encodePacked(address(0xDEAD)), hex"01");
        }
        assertEq(_inflight(connectorId), 4, "inflight is 4 after four sends");

        // One bundle replies CONNECTOR_UNDERFUNDED to ids 1,2,3 (leaving id 4 in-flight).
        // Penalty escalates geometrically per slash: basePenalty * penaltyMultiplier^slashCount
        // → 0.01, 0.02, 0.04 ether (sum 0.07). The third slash exercises the escalated path.
        uint64[] memory ids = new uint64[](3);
        ids[0] = 1;
        ids[1] = 2;
        ids[2] = 3;
        ClprTypes.ReplyStatus[] memory statuses = new ClprTypes.ReplyStatus[](3);
        statuses[0] = ClprTypes.ReplyStatus.CONNECTOR_UNDERFUNDED;
        statuses[1] = ClprTypes.ReplyStatus.CONNECTOR_UNDERFUNDED;
        statuses[2] = ClprTypes.ReplyStatus.CONNECTOR_UNDERFUNDED;
        _submitFailureReplyBundleMulti(ids, statuses);

        ClprTypes.Connector memory c = service.getConnector(channelId, connectorId);
        assertEq(c.lockedStake, 1 ether - 0.07 ether, "escalated penalties 0.01+0.02+0.04 deducted");
        assertEq(c.slashCount, 3, "slashed three times");
        assertEq(_inflight(connectorId), 1, "three decrements survive the three slashes (4 -> 1)");
    }

    /// @dev The forfeited-stake transfer in ConnectorLib.slash routes through
    ///      _transferWithFallback(recipient=bundleSubmitter, fallbackTo=serviceOwner): it tries
    ///      `recipient` first, then `fallbackTo`, and only falls back to pendingWithdrawals if
    ///      BOTH fail. This test contract (and its `owner`, which is the same address here) can
    ///      receive ETH directly, unlike the original standalone ConnectorManagerTest — so
    ///      reaching the pendingWithdrawals branch requires routing the submission through a
    ///      dedicated non-receiving contract AND temporarily making that same contract the
    ///      service's owner, forcing both `_transferWithFallback` attempts to fail.
    function test_sourceSlash_banRemovesConnector_withNonZeroInflight() public {
        connectorId = _registerConnectorWithStake(keccak256(abi.encodePacked("cm-test")), owner, 1 ether);
        _setSlashBanThreshold(1); // a single slash now bans

        // Two outbound messages → inflight = 2.
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(0xDEAD)), hex"01");
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(0xDEAD)), hex"01");
        assertEq(_inflight(connectorId), 2, "inflight is 2 after two sends");

        NonReceivingSubmitterOwner nonReceiver = new NonReceivingSubmitterOwner();
        // Submission is permissionless — nonReceiver submits directly without registering.
        service.transferOwnership(address(nonReceiver));

        // Reply to id 1 only → decrement in-flight (2 -> 1), then the slash bans (threshold 1).
        _submitFailureReplyBundleAs(nonReceiver, 1, ClprTypes.ReplyStatus.CONNECTOR_NOT_FOUND);

        // Banned: the connector row is removed outright, even though id 2 was still in-flight —
        // so the leftover in-flight count is moot (the row no longer exists to be deregistered).
        assertFalse(service.hasConnector(channelId, connectorId), "banned connector removed");

        // Fund accounting: a ban FORFEITS the entire stake (it is NOT returned to the admin).
        // The full 1 ether penalty is routed to the bundle submitter. Since neither the submitter
        // nor the service owner (both `nonReceiver`) can receive ETH, _transferWithFallback
        // credits it to pendingWithdrawals, claimable via withdraw(). Every wei is accounted
        // for — nothing is stranded on-ledger.
        assertEq(
            service.pendingWithdrawals(address(nonReceiver)), 1 ether, "full stake forfeited to submitter, claimable"
        );
        assertEq(address(service).balance, 1 ether, "stake still custodied by the service, earmarked for withdrawal");

        vm.expectRevert(ClprTypes.ClprConnectorNotFound.selector);
        service.getConnector(channelId, connectorId);
    }

    function _setSlashBanThreshold(uint32 threshold) internal {
        ClprTypes.EconomicConfig memory econ = service.getEconomicConfig();
        econ.slashBanThreshold = threshold;
        service.updateEconomicConfiguration(econ);
    }

    /// @dev Read `_connectorInflightCount[keccak256(channelId || connectorId)]` directly,
    ///      since the count is not exposed via a public getter.
    function _inflight(bytes32 cId) internal view returns (uint256) {
        bytes32 key = keccak256(abi.encodePacked(channelId, cId));
        return uint256(
            vm.load(
                address(service), ClprStorageLayoutLib.mapBytes32Slot(key, ClprServiceStorageSlots.CONNECTOR_INFLIGHT)
            )
        );
    }

    /// @dev Same scenario as _submitFailureReplyBundle, but submits through `submitter` instead
    ///      of this contract, so msg.sender for submitBundle (and thus the recipient side of any
    ///      forfeited-stake transfer) is `submitter`, not this test contract.
    function _submitFailureReplyBundleAs(
        NonReceivingSubmitterOwner submitter,
        uint64 outboundMsgId,
        ClprTypes.ReplyStatus status
    ) internal {
        bytes memory replyPayload = ClprProtobuf.encodeReplyMessage(outboundMsgId, status, hex"");
        bytes32 runningHash = sha256(abi.encodePacked(bytes32(0), sha256(replyPayload)));

        bytes[] memory msgs = new bytes[](1);
        msgs[0] = replyPayload;

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 2,
            sentRunningHash: runningHash,
            receivedMessageId: outboundMsgId,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 1,
            lastMessageRunningHash: runningHash
        });
        verifier.setVerifyBundleResult(meta, msgs);
        submitter.submitBundle(IClprService(address(service)), channelId, hex"00");
    }

    /// @dev Submit a single inbound bundle carrying replies for several outbound DATA ids,
    ///      processed in order. `outboundIds` must be ascending; the highest is acked.
    function _submitFailureReplyBundleMulti(uint64[] memory outboundIds, ClprTypes.ReplyStatus[] memory statuses)
        internal
    {
        uint256 n = outboundIds.length;
        bytes[] memory msgs = new bytes[](n);
        bytes32 runningHash = bytes32(0);
        for (uint256 i = 0; i < n; i++) {
            bytes memory replyPayload = ClprProtobuf.encodeReplyMessage(outboundIds[i], statuses[i], hex"");
            runningHash = sha256(abi.encodePacked(runningHash, sha256(replyPayload)));
            msgs[i] = replyPayload;
        }

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            // forge-lint: disable-next-line(unsafe-typecast)
            nextMessageId: uint64(n + 1),
            sentRunningHash: runningHash,
            receivedMessageId: outboundIds[n - 1],
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            // forge-lint: disable-next-line(unsafe-typecast)
            lastMessageId: uint64(n),
            lastMessageRunningHash: runningHash
        });
        verifier.setVerifyBundleResult(meta, msgs);
        service.submitBundle(channelId, hex"00");
    }

    receive() external payable override {}

    // ── Regression: an overlapping bundle must not pause the channel
    //
    // Reproduces the testnet settlement wedge. A peer builds each bundle from
    // `ackedMessageId + 1`, so a REPLY that was already delivered — but whose ack has not yet
    // round-tripped — reappears at the front of the next bundle, ahead of a genuinely new
    // inbound DATA. A read-only proof format (the Hiero block-stream StateProof) cannot be
    // trimmed endpoint-side, so the duplicate prefix reaches the response-ordering pre-scan by
    // design and must be skipped there, exactly as the running-hash and dispatch loops skip it.
    // Re-scanning it compares an already-consumed REPLY against an already-advanced
    // `nextExpectedReplyId`, reports a spurious backward-reply violation, pauses the channel and
    // drops the new DATA in the same bundle.
    function test_overlappingBundle_replayedReply_doesNotPauseOrDropNewData() public {
        _registerTestConnector();

        // Outbound DATA #1, sent as `app` so the peer's REPLY routes back to `app`.
        vm.prank(address(app));
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"01020304");

        // Bundle 1: the peer's REPLY for our DATA #1, acking it.
        bytes memory replyPayload = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"0102");
        bytes[] memory msgs1 = new bytes[](1);
        msgs1[0] = replyPayload;
        bytes32 hash1 = sha256(abi.encodePacked(bytes32(0), sha256(replyPayload)));
        verifier.setVerifyBundleResult(
            ClprTypes.QueueMetadata({
                nextMessageId: 2,
                sentRunningHash: hash1,
                receivedMessageId: 1,
                receivedRunningHash: bytes32(0),
                state: ClprTypes.ChannelStatus.ACTIVE,
                endpointManifestVersion: 0,
                lastMessageId: 1,
                lastMessageRunningHash: hash1
            }),
            msgs1
        );
        _submitBundle(hex"00FF01");

        ClprTypes.Channel memory chan = service.getChannel(channelId);
        assertEq(uint8(chan.status), uint8(ClprTypes.ChannelStatus.ACTIVE));
        assertEq(chan.receivedMessageId, 1);
        assertEq(app.getResponseCallCount(), 1);

        // Bundle 2: the same REPLY again (our ack has not reached the peer yet) followed by a new
        // inbound DATA #2 — the Prepare that still has to be delivered.
        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");
        bytes[] memory msgs2 = new bytes[](2);
        msgs2[0] = replyPayload; // already-received duplicate prefix
        msgs2[1] = dataPayload;
        // The running hash continues from the channel's receivedRunningHash over the new suffix only.
        bytes32 hash2 = sha256(abi.encodePacked(hash1, sha256(dataPayload)));
        verifier.setVerifyBundleResult(
            ClprTypes.QueueMetadata({
                nextMessageId: 3,
                sentRunningHash: hash2,
                receivedMessageId: 1, // ack level unchanged
                receivedRunningHash: bytes32(0),
                state: ClprTypes.ChannelStatus.ACTIVE,
                endpointManifestVersion: 0,
                lastMessageId: 2,
                lastMessageRunningHash: hash2
            }),
            msgs2
        );
        _submitBundle(hex"00FF02");

        // The channel stays ACTIVE and the new DATA is delivered.
        chan = service.getChannel(channelId);
        assertEq(uint8(chan.status), uint8(ClprTypes.ChannelStatus.ACTIVE));
        assertEq(chan.receivedMessageId, 2);
        assertEq(app.getMessageCallCount(), 1);
        // The duplicate REPLY is not re-delivered to the application.
        assertEq(app.getResponseCallCount(), 1);
    }

    function test_overlappingBundle_outOfOrderReplyAfterDuplicatePrefix_stillPauses() public {
        _registerTestConnector();

        // Outbound DATA #1, #2, #3, sent as `app` so REPLYs route back to `app`. nextMessageId = 4.
        vm.startPrank(address(app));
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"01");
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"02");
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"03");
        vm.stopPrank();

        // Bundle 1: the peer's REPLY for DATA #1, acking it. nextExpectedReplyId advances to 2.
        bytes memory reply1 = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"01");
        bytes[] memory msgs1 = new bytes[](1);
        msgs1[0] = reply1;
        bytes32 hash1 = sha256(abi.encodePacked(bytes32(0), sha256(reply1)));
        verifier.setVerifyBundleResult(
            ClprTypes.QueueMetadata({
                nextMessageId: 2,
                sentRunningHash: hash1,
                receivedMessageId: 1,
                receivedRunningHash: bytes32(0),
                state: ClprTypes.ChannelStatus.ACTIVE,
                endpointManifestVersion: 0,
                lastMessageId: 1,
                lastMessageRunningHash: hash1
            }),
            msgs1
        );
        _submitBundle(hex"00FF01");

        ClprTypes.Channel memory chan = service.getChannel(channelId);
        assertEq(uint8(chan.status), uint8(ClprTypes.ChannelStatus.ACTIVE));
        assertEq(chan.receivedMessageId, 1);
        assertEq(app.getResponseCallCount(), 1);

        // Bundle 2: the stale REPLY #1 again (duplicate prefix)
        bytes memory reply3 = ClprProtobuf.encodeReplyMessage(3, ClprTypes.ReplyStatus.SUCCESS, hex"03");
        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");
        bytes[] memory msgs2 = new bytes[](3);
        msgs2[0] = reply1; // already-received duplicate prefix
        msgs2[1] = reply3; // out of order: DATA #2 still awaits its REPLY
        msgs2[2] = dataPayload;

        bytes32 hash2 = sha256(abi.encodePacked(hash1, sha256(reply3)));
        hash2 = sha256(abi.encodePacked(hash2, sha256(dataPayload)));
        verifier.setVerifyBundleResult(
            ClprTypes.QueueMetadata({
                nextMessageId: 4,
                sentRunningHash: hash2,
                receivedMessageId: 1,
                receivedRunningHash: bytes32(0),
                state: ClprTypes.ChannelStatus.ACTIVE,
                endpointManifestVersion: 0,
                lastMessageId: 3,
                lastMessageRunningHash: hash2
            }),
            msgs2
        );
        _submitBundle(hex"00FF02");

        chan = service.getChannel(channelId);
        assertEq(
            uint8(chan.status), uint8(ClprTypes.ChannelStatus.PAUSED), "out-of-order reply after prefix must pause"
        );
        assertEq(chan.receivedMessageId, 1, "aborted bundle must not advance the received id");
        assertEq(app.getMessageCallCount(), 0, "the new DATA must not be dispatched");
        assertEq(app.getResponseCallCount(), 1, "neither the stale nor the bad REPLY is delivered");
    }
}
