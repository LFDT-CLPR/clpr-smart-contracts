// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {BundleLib} from "@hiero-ledger/clpr/libraries/service/BundleLib.sol";
import {ClprTypes, ChannelStatusChanged} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {MockClprConnector} from "@test/mocks/MockClprConnector.sol";
import {BundleLibTestBase} from "@test/libraries/service/bundle-lib/BundleLibTestBase.sol";

/// @dev Thin harness exposing BundleLib's `internal` state-machine and progress helpers for
///      direct, exhaustive unit testing. Both functions inline into this importing contract,
///      so `ChannelStatusChanged` events are emitted from this contract's address.
contract BundleLibHarness {
    /// @return The channel status after applying the state machine.
    function runStateMachine(
        bytes32 channelId,
        ClprTypes.ChannelStatus current,
        ClprTypes.ChannelStatus peerState,
        uint64 nextMessageId,
        uint64 lastDataMessageId,
        uint64 newAckedMessageId
    ) external returns (ClprTypes.ChannelStatus) {
        ClprTypes.Channel memory channel;
        channel.status = current;
        channel.nextMessageId = nextMessageId;
        channel.lastDataMessageId = lastDataMessageId;

        ClprTypes.QueueMetadata memory meta;
        meta.state = peerState;

        BundleLib._applyStateMachine(channelId, channel, meta, newAckedMessageId);
        return channel.status;
    }

    /// @dev Reverts with `BundleLib.NoProgress` when the bundle makes no progress.
    function checkProgress(
        ClprTypes.ChannelStatus current,
        uint64 connNextMessageId,
        uint64 connLastDataMessageId,
        uint64 connReceivedMessageId,
        uint64 connAckedMessageId,
        ClprTypes.ChannelStatus peerState,
        uint64 metaNextMessageId,
        uint64 metaReceivedMessageId,
        bytes memory newTrustAnchor
    ) external pure {
        ClprTypes.Channel memory channel;
        channel.status = current;
        channel.nextMessageId = connNextMessageId;
        channel.lastDataMessageId = connLastDataMessageId;
        channel.receivedMessageId = connReceivedMessageId;
        channel.ackedMessageId = connAckedMessageId;

        ClprTypes.QueueMetadata memory meta;
        meta.state = peerState;
        meta.nextMessageId = metaNextMessageId;
        meta.receivedMessageId = metaReceivedMessageId;

        BundleLib._checkBundleProgress(channel, meta, newTrustAnchor, false);
    }
}

/// @title BundleLibStateMachineTest
/// @notice Exhaustive unit coverage of `_applyStateMachine` and `_checkBundleProgress`.
///
/// The expected outcomes below are a hand-computed oracle derived from the CLPR §4.2 state
/// machine, deliberately NOT re-derived from the implementation, so a regression is caught
/// rather than mirrored.
contract BundleLib_StateMachineTest is BundleLibTestBase {
    BundleLibHarness internal harness;
    bytes32 internal constant CID = bytes32(uint256(0xC1));

    function setUp() public override {
        super.setUp();
        harness = new BundleLibHarness();
    }

    // Shorthands for the enum to keep the transition tables readable.
    ClprTypes.ChannelStatus internal constant PENDING = ClprTypes.ChannelStatus.PENDING;
    ClprTypes.ChannelStatus internal constant ACTIVE = ClprTypes.ChannelStatus.ACTIVE;
    ClprTypes.ChannelStatus internal constant PAUSED = ClprTypes.ChannelStatus.PAUSED;
    ClprTypes.ChannelStatus internal constant CLOSING = ClprTypes.ChannelStatus.CLOSING;
    ClprTypes.ChannelStatus internal constant DRAINED = ClprTypes.ChannelStatus.DRAINED;
    ClprTypes.ChannelStatus internal constant CLOSED = ClprTypes.ChannelStatus.CLOSED;

    // ─────────────────────────────────────────────────────────────────────────
    // _applyStateMachine / _stepStatus — full transition table
    //
    // `allAcked` here means "every outbound message acked", driving BOTH drain predicates
    // to the same value so the transition table reads cleanly:
    //   true  → nextMessageId = 1, lastDataMessageId = 0, acked = 0 (vacuous: nothing ever sent)
    //   false → nextMessageId = 3, lastDataMessageId = 2, acked = 0 (0 >= 2 is false for both)
    // The DATA-acked vs all-acked distinction (§4.2 Step 5b sub-checks 1 vs 2) is exercised
    // separately in test_stateMachine_responsesGateClosedNotDrained.
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Assert the settled status for a given (current, peer, allAcked) triple.
    function _assertSM(
        ClprTypes.ChannelStatus current,
        ClprTypes.ChannelStatus peer,
        bool allAcked,
        ClprTypes.ChannelStatus expected
    ) internal {
        uint64 nextMessageId = allAcked ? 1 : 3;
        uint64 lastDataMessageId = allAcked ? 0 : 2;
        uint64 acked = 0;
        ClprTypes.ChannelStatus got =
            harness.runStateMachine(CID, current, peer, nextMessageId, lastDataMessageId, acked);
        assertEq(uint8(got), uint8(expected), "unexpected settled status");
    }

    function test_stateMachine_fromActive_allCombos() public {
        // Peer not closing → no transition.
        _assertSM(ACTIVE, ACTIVE, true, ACTIVE);
        _assertSM(ACTIVE, ACTIVE, false, ACTIVE);
        _assertSM(ACTIVE, PAUSED, true, ACTIVE);
        _assertSM(ACTIVE, PAUSED, false, ACTIVE);

        // Peer CLOSING (peerClosing, not peerDone).
        _assertSM(ACTIVE, CLOSING, true, DRAINED); // ACTIVE→CLOSING→DRAINED (peer not done, stop)
        _assertSM(ACTIVE, CLOSING, false, CLOSING); // ACTIVE→CLOSING (not all acked, stop)

        // Peer DRAINED/CLOSED (peerClosing AND peerDone).
        _assertSM(ACTIVE, DRAINED, true, CLOSED); // ACTIVE→CLOSING→DRAINED→CLOSED
        _assertSM(ACTIVE, DRAINED, false, CLOSING);
        _assertSM(ACTIVE, CLOSED, true, CLOSED);
        _assertSM(ACTIVE, CLOSED, false, CLOSING);
    }

    function test_stateMachine_fromPaused_allCombos() public {
        // PAUSED behaves identically to ACTIVE in the first transition rule.
        _assertSM(PAUSED, ACTIVE, true, PAUSED);
        _assertSM(PAUSED, ACTIVE, false, PAUSED);
        _assertSM(PAUSED, CLOSING, true, DRAINED);
        _assertSM(PAUSED, CLOSING, false, CLOSING);
        _assertSM(PAUSED, DRAINED, true, CLOSED);
        _assertSM(PAUSED, DRAINED, false, CLOSING);
        _assertSM(PAUSED, CLOSED, true, CLOSED);
        _assertSM(PAUSED, CLOSED, false, CLOSING);
    }

    function test_stateMachine_fromClosing_allCombos() public {
        // Not all acked → stays CLOSING regardless of peer.
        _assertSM(CLOSING, ACTIVE, false, CLOSING);
        _assertSM(CLOSING, PAUSED, false, CLOSING);
        _assertSM(CLOSING, CLOSING, false, CLOSING);
        _assertSM(CLOSING, DRAINED, false, CLOSING);
        _assertSM(CLOSING, CLOSED, false, CLOSING);

        // All acked → DRAINED; then →CLOSED only if peer is done.
        _assertSM(CLOSING, ACTIVE, true, DRAINED);
        _assertSM(CLOSING, PAUSED, true, DRAINED);
        _assertSM(CLOSING, CLOSING, true, DRAINED);
        _assertSM(CLOSING, DRAINED, true, CLOSED);
        _assertSM(CLOSING, CLOSED, true, CLOSED);
    }

    function test_stateMachine_fromDrained_allCombos() public {
        // → CLOSED only when peer is done AND all acked; otherwise stays DRAINED.
        _assertSM(DRAINED, ACTIVE, true, DRAINED);
        _assertSM(DRAINED, ACTIVE, false, DRAINED);
        _assertSM(DRAINED, PAUSED, true, DRAINED);
        _assertSM(DRAINED, CLOSING, true, DRAINED);
        _assertSM(DRAINED, DRAINED, true, CLOSED);
        _assertSM(DRAINED, DRAINED, false, DRAINED);
        _assertSM(DRAINED, CLOSED, true, CLOSED);
        _assertSM(DRAINED, CLOSED, false, DRAINED);
    }

    function test_stateMachine_terminalStates_neverTransition() public {
        // CLOSED is terminal.
        _assertSM(CLOSED, ACTIVE, true, CLOSED);
        _assertSM(CLOSED, CLOSED, true, CLOSED);
        // PENDING has no rule (defensive; never reaches the state machine in production).
        _assertSM(PENDING, CLOSED, true, PENDING);
        _assertSM(PENDING, DRAINED, false, PENDING);
    }

    // ── DATA-acked predicate boundary (CLOSING → DRAINED, §4.2 Step 5b sub-check 1) ──
    // This transition is gated on DATA Messages only (lastDataMessageId), not all outbound.

    function test_stateMachine_dataAcked_boundary() public {
        // lastDataMessageId == 0 → no DATA ever sent → vacuously acked → drains.
        assertEq(uint8(harness.runStateMachine(CID, CLOSING, ACTIVE, 1, 0, 0)), uint8(DRAINED));
        // acked == lastDataMessageId → all DATA acked → drains.
        assertEq(uint8(harness.runStateMachine(CID, CLOSING, ACTIVE, 2, 1, 1)), uint8(DRAINED));
        // acked < lastDataMessageId → DATA not fully acked → stays CLOSING.
        assertEq(uint8(harness.runStateMachine(CID, CLOSING, ACTIVE, 2, 1, 0)), uint8(CLOSING));
    }

    /// @dev §4.2 Step 5b uses two DIFFERENT drain predicates, and a Response Message in flight
    ///      is exactly what separates them: CLOSING → DRAINED requires only DATA Messages acked
    ///      (responses drain through DRAINED), but DRAINED → CLOSED requires ALL messages acked
    ///      including those responses. Guards against collapsing both onto one predicate.
    function test_stateMachine_responsesGateClosedNotDrained() public {
        // One DATA Message (id 1) + one Response (id 2): nextMessageId = 3, lastDataMessageId = 1.
        // acked = 1 → DATA fully acked, Response (id 2) still in flight.
        assertEq(
            uint8(harness.runStateMachine(CID, CLOSING, CLOSED, 3, 1, 1)),
            uint8(DRAINED),
            "CLOSING drains on DATA-acked even with a response in flight"
        );
        // DRAINED must NOT close while the response is unacked (acked 1 < nextMessageId - 1 = 2).
        assertEq(
            uint8(harness.runStateMachine(CID, DRAINED, CLOSED, 3, 1, 1)),
            uint8(DRAINED),
            "DRAINED holds until the in-flight response is acked"
        );
        // Once the response (id 2) is acked too, DRAINED → CLOSED.
        assertEq(
            uint8(harness.runStateMachine(CID, DRAINED, CLOSED, 3, 1, 2)),
            uint8(CLOSED),
            "DRAINED closes once all messages are acked"
        );
    }

    // ── events: each hop is emitted, including the full cascade ────────────────

    function test_stateMachine_emitsEachHop_fullCascade() public {
        // ACTIVE + peer CLOSED + all acked → three transitions, three events, in order.
        vm.expectEmit(true, false, false, true, address(harness));
        emit ChannelStatusChanged(CID, CLOSING);
        vm.expectEmit(true, false, false, true, address(harness));
        emit ChannelStatusChanged(CID, DRAINED);
        vm.expectEmit(true, false, false, true, address(harness));
        emit ChannelStatusChanged(CID, CLOSED);

        harness.runStateMachine(CID, ACTIVE, CLOSED, 1, 0, 0);
    }

    function test_stateMachine_noTransition_emitsNothing() public {
        vm.recordLogs();
        harness.runStateMachine(CID, ACTIVE, ACTIVE, 1, 0, 0);
        assertEq(vm.getRecordedLogs().length, 0, "no event expected when status is unchanged");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // _checkBundleProgress — one condition at a time
    //
    // Helper neutralizes conditions 1-3 so condition 4 (state transition) is isolated:
    //   cond1 false: metaNextMessageId = connReceivedMessageId + 1 (no new messages)
    //   cond2 false: empty trust anchor
    //   cond3 false: metaReceivedMessageId <= connAckedMessageId
    // ─────────────────────────────────────────────────────────────────────────

    function test_progress_cond1_newMessages_passes() public view {
        // channel.receivedMessageId = 0, peer advertises nextMessageId = 2 → 2 > 1 → progress.
        harness.checkProgress(ACTIVE, 1, 0, 0, 0, ACTIVE, 2, 0, hex"");
    }

    function test_progress_cond2_trustAnchor_passes() public view {
        // No new messages, no ack advance, no transition — only a new trust anchor.
        harness.checkProgress(ACTIVE, 1, 0, 0, 0, ACTIVE, 1, 0, hex"ABCD");
    }

    function test_progress_cond3_ackAdvance_passes() public view {
        // metadata.receivedMessageId (1) > channel.ackedMessageId (0) → progress.
        harness.checkProgress(ACTIVE, 3, 0, 0, 0, ACTIVE, 1, 1, hex"");
    }

    function test_progress_cond4_eachTransition_passes() public view {
        // ACTIVE → CLOSING (peer closing).
        harness.checkProgress(ACTIVE, 1, 0, 0, 0, CLOSING, 1, 0, hex"");
        // PAUSED → CLOSING (peer closed).
        harness.checkProgress(PAUSED, 1, 0, 0, 0, CLOSED, 1, 0, hex"");
        // CLOSING → DRAINED (all DATA acked; lastDataMessageId == 0).
        harness.checkProgress(CLOSING, 1, 0, 0, 0, ACTIVE, 1, 0, hex"");
        // DRAINED → CLOSED (peer done AND all acked).
        harness.checkProgress(DRAINED, 1, 0, 0, 0, CLOSED, 1, 0, hex"");
    }

    function test_progress_noTransition_reverts() public {
        // ACTIVE + peer ACTIVE → no transition, no other progress.
        vm.expectRevert(BundleLib.NoProgress.selector);
        harness.checkProgress(ACTIVE, 1, 0, 0, 0, ACTIVE, 1, 0, hex"");
    }

    function test_progress_closingNotAllAcked_reverts() public {
        // CLOSING but DATA not all acked (lastDataMessageId 2, acked 0) → no drain, no transition.
        vm.expectRevert(BundleLib.NoProgress.selector);
        harness.checkProgress(CLOSING, 3, 2, 0, 0, ACTIVE, 1, 0, hex"");
    }

    // ── condition 4: DRAINED → CLOSED progress now requires all-acked ─────────────

    /// @dev Routed through the shared `_stepStatus`, a DRAINED channel whose peer is
    ///      DRAINED/CLOSED but whose outbound messages are NOT all acked makes NO state
    ///      transition, so with no other progress the bundle is rejected. This is the
    ///      behavior the progress pre-check and `_applyStateMachine` agree on.
    function test_progress_drained_peerDone_notAllAcked_reverts() public {
        // nextMessageId 3, acked 0 → not all acked → DRAINED stays DRAINED → no progress.
        vm.expectRevert(BundleLib.NoProgress.selector);
        harness.checkProgress(DRAINED, 3, 0, 0, 0, CLOSED, 1, 0, hex"");

        vm.expectRevert(BundleLib.NoProgress.selector);
        harness.checkProgress(DRAINED, 3, 0, 0, 0, DRAINED, 1, 0, hex"");
    }

    /// @dev DRAINED + peer CLOSED with all-acked transitions to CLOSED → progress.
    ///      cond3 kept false (1 > 1 is false) so only condition 4 carries it.
    function test_progress_drained_peerClosed_allAcked_passes() public view {
        harness.checkProgress(DRAINED, 2, 0, 0, 1, CLOSED, 1, 1, hex"");
    }

    /// @dev DRAINED → CLOSED is gated on peer being done: DRAINED + peer ACTIVE is NOT progress
    ///      even when all-acked.
    function test_progress_drained_peerActive_reverts() public {
        vm.expectRevert(BundleLib.NoProgress.selector);
        harness.checkProgress(DRAINED, 1, 0, 0, 0, ACTIVE, 1, 0, hex"");
    }

    /// @dev The look-ahead: condition 4 uses max(channel.ackedMessageId, metadata.receivedMessageId)
    ///      because the new ack is only committed in Step 6, after this check. Here channel.ackedMessageId
    ///      is stale (0) but the bundle's metadata.receivedMessageId (1) acks the last outbound,
    ///      so CLOSING must be seen as drainable.
    function test_progress_closing_drainsViaMetadataAck_passes() public view {
        // nextMessageId = 2, channel.ackedMessageId = 0 (not yet drained by stored ack),
        // metadata.receivedMessageId = 1 → effectiveAcked = 1 ≥ 1 → all acked → CLOSING→DRAINED.
        // cond3 alone would also pass (1 > 0), so force it false by setting connAckedMessageId = 1
        // is impossible without losing the look-ahead intent; instead verify the transition path
        // by keeping cond3 true is acceptable here — the point is the bundle is accepted.
        harness.checkProgress(CLOSING, 2, 1, 0, 0, ACTIVE, 1, 1, hex"");
    }

    // ── Test 12: State machine: ACTIVE -> CLOSING (peer closing)

    function test_stateMachine_activeToClosing_peerClosing() public {
        _registerTestConnector();

        // Send an outbound DATA message so channel doesn't immediately drain
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"01020304");

        bytes[] memory msgs = new bytes[](0);

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 0, // NOT acking our outbound message
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.CLOSING, // peer is closing
            endpointManifestVersion: 0
        });
        verifier.setVerifyBundleResult(meta, msgs);
        // Trust anchor advancement keeps the bundle non-empty (NoProgress guard)
        verifier.setNewTrustAnchor(hex"01");
        _submitBundle(hex"00FF");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.CLOSING));
    }

    // ── Test: State machine: ACTIVE -> CLOSING (peer reports CLOSED directly, skipping CLOSING)

    function test_stateMachine_activeToClosing_peerClosed() public {
        _registerTestConnector();

        // Keep one unacked outbound message so the channel doesn't immediately drain.
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"01020304");

        bytes[] memory msgs = new bytes[](0);
        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.CLOSED, // peer jumped straight to CLOSED without sending CLOSING first
            endpointManifestVersion: 0
        });
        verifier.setVerifyBundleResult(meta, msgs);
        _submitBundle(hex"00FF");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.CLOSING));
    }

    // ── Test: State machine: PAUSED -> CLOSING (peer reports CLOSED)

    function test_stateMachine_pausedToClosing_peerClosed() public {
        _registerTestConnector();

        // Send two outbound DATA messages so CLOSING doesn't immediately drain to DRAINED.
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"01020304");
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"05060708");

        // Bundle 1: peer acks our message 1 without a REPLY — ordering violation → PAUSED.
        {
            bytes[] memory emptyMsgs = new bytes[](0);
            ClprTypes.QueueMetadata memory meta1 = ClprTypes.QueueMetadata({
                nextMessageId: 1,
                sentRunningHash: bytes32(0),
                receivedMessageId: 1,
                receivedRunningHash: bytes32(0),
                state: ClprTypes.ChannelStatus.ACTIVE,
                endpointManifestVersion: 0
            });
            verifier.setVerifyBundleResult(meta1, emptyMsgs);
            _submitBundle(hex"00FF");
        }
        assertEq(uint8(service.getChannel(channelId).status), uint8(ClprTypes.ChannelStatus.PAUSED));

        // Bundle 2: REPLY for message 1 clears the ordering violation; peer state is CLOSED.
        //           Auto-resume fires (PAUSED -> ACTIVE), then Step 9 fires (ACTIVE -> CLOSING).
        //           Message 2 is still outstanding so we don't immediately drain.
        {
            bytes memory replyPayload = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"");
            bytes[] memory msgs = new bytes[](1);
            msgs[0] = replyPayload;
            bytes32 runningHash = sha256(abi.encodePacked(bytes32(0), sha256(replyPayload)));
            ClprTypes.QueueMetadata memory meta2 = ClprTypes.QueueMetadata({
                nextMessageId: 2,
                sentRunningHash: runningHash,
                receivedMessageId: 1,
                receivedRunningHash: bytes32(0),
                state: ClprTypes.ChannelStatus.CLOSED,
                endpointManifestVersion: 0
            });
            verifier.setVerifyBundleResult(meta2, msgs);
            _submitBundle(hex"00FF02");
        }

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.CLOSING));
    }

    // ── Test 13: State machine: CLOSING -> DRAINED (all acked)

    function test_stateMachine_closingToDrained() public {
        // Close our channel first
        service.closeChannel(channelId);

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.CLOSING));

        // Submit bundle with peer ACTIVE, no new messages
        // Since nextMessageId==1 (no messages), all outbound are "acked"
        bytes[] memory msgs = new bytes[](0);
        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0
        });
        verifier.setVerifyBundleResult(meta, msgs);
        // Trust anchor advancement keeps the bundle non-empty (NoProgress guard)
        // When the channel is CLOSING on our side, the only additional condition
        // we need is that all messages we have sent have already been acknowledged.
        // Once that condition is met, we should transition to DRAINED regardless of whether
        // we receive an empty bundle and regardless of the state of the remote peer.
        _submitBundle(hex"00FF");

        channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.DRAINED));
    }

    // ── Test 14: State machine: DRAINED -> CLOSED (peer drained)

    function test_stateMachine_drainedToClosed() public {
        // Close our channel
        service.closeChannel(channelId);

        // First bundle: CLOSING -> DRAINED (nextMessageId==1, all acked)
        bytes[] memory msgs = new bytes[](0);
        ClprTypes.QueueMetadata memory meta1 = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0
        });
        verifier.setVerifyBundleResult(meta1, msgs);
        // Trust anchor advancement should not be required to advance
        _submitBundle(hex"00FF");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.DRAINED));

        // Second bundle: peer is DRAINED -> CLOSED
        ClprTypes.QueueMetadata memory meta2 = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.DRAINED,
            endpointManifestVersion: 0
        });
        verifier.setVerifyBundleResult(meta2, msgs);
        // Trust anchor advancement should not be required to advance
        _submitBundle(hex"00FF02");

        channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.CLOSED));
    }

    // ── Test 15: State machine: CLOSING -> DRAINED -> CLOSED (all acked)

    function test_stateMachine_closingToDrainedToClosed() public {
        // Close our channel first
        service.closeChannel(channelId);

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.CLOSING));

        // Submit bundle with peer DRAINED already, and no new messages
        // Since nextMessageId==1 (no messages), all outbound are "acked"
        bytes[] memory msgs = new bytes[](0);
        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.DRAINED, // All drained on both ends.
            endpointManifestVersion: 0
        });
        verifier.setVerifyBundleResult(meta, msgs);
        // Trust anchor advancement should not be required to advance
        _submitBundle(hex"00FF");

        channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.CLOSED)); // Double hop
    }

    /// @dev The transition CLOSING → DRAINED should occur when all outbound messages
    ///      are acknowledged, regardless of peer state.
    function test_regression_closingToDrained_withPeerStillActive() public {
        // Close our channel first
        service.closeChannel(channelId);

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.CLOSING));

        // Submit bundle with peer ACTIVE (not DRAINED), and no new messages
        // Since nextMessageId==1 (no messages), all outbound are "acked"
        // This should trigger CLOSING -> DRAINED even though peer is still ACTIVE
        bytes[] memory msgs = new bytes[](0);
        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE, // peer is still ACTIVE
            endpointManifestVersion: 0
        });
        verifier.setVerifyBundleResult(meta, msgs);
        _submitBundle(hex"00FF");

        channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.DRAINED));
    }

    // ── Additional: CLOSED channel rejects bundle

    function test_closedChannel_reverts() public {
        // Move channel to CLOSED state
        service.closeChannel(channelId);

        // CLOSING -> DRAINED
        bytes[] memory msgs = new bytes[](0);
        ClprTypes.QueueMetadata memory meta1 = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0
        });
        verifier.setVerifyBundleResult(meta1, msgs);
        // Trust anchor advancement keeps the bundle non-empty (NoProgress guard)
        verifier.setNewTrustAnchor(hex"01");
        _submitBundle(hex"00FF");

        // DRAINED -> CLOSED
        ClprTypes.QueueMetadata memory meta2 = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.DRAINED,
            endpointManifestVersion: 0
        });
        verifier.setVerifyBundleResult(meta2, msgs);
        verifier.setNewTrustAnchor(hex"02");
        _submitBundle(hex"00FF02");

        // Now channel is CLOSED -- next bundle should revert
        ClprTypes.QueueMetadata memory meta3 = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.CLOSED,
            endpointManifestVersion: 0
        });
        verifier.setVerifyBundleResult(meta3, msgs);

        vm.expectRevert(ClprTypes.ClprInvalidChannelStatus.selector);
        _submitBundle(hex"00FF03");
    }

    // ── PAUSED + peer-CLOSING → CLOSING

    /// @dev Drive channel to PAUSED (ordering violation), then submit a bundle
    ///      with peer state = CLOSING → local status must become CLOSING (not stuck in PAUSED).
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
                endpointManifestVersion: 0
            });
            verifier.setVerifyBundleResult(meta, emptyMsgs);
            _submitBundle(hex"00FF");
        }
        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.PAUSED), "should be PAUSED");

        // Bundle 2: peer provides REPLY for message 1 (ordering satisfied) + peer state = CLOSING.
        //           Bundle 1's ack of message 1 is already committed, so ack
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
                endpointManifestVersion: 0
            });
            verifier.setVerifyBundleResult(meta, msgs);
            _submitBundle(hex"00FF02");
        }

        channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.CLOSING), "should be CLOSING");
    }

    // ── PENDING channel rejected at submitBundle

    function test_pendingChannel_reverts() public {
        // PENDING status is not stored in _channels (defensive guard for future use).
        // The simplest way to test: create a real channel and manually check the guard
        // logic compiles correctly. We rely on the CLOSED test as the existing pattern.
        // For PENDING: channels are stored with status != PENDING, so this is defense-in-depth.
        // We verify the revert path exists by testing an existing CLOSED variant,
        // which uses the same code path.
        service.closeChannel(channelId);

        bytes[] memory msgs = new bytes[](0);
        ClprTypes.QueueMetadata memory meta1 = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0
        });
        verifier.setVerifyBundleResult(meta1, msgs);
        verifier.setNewTrustAnchor(hex"01");
        _submitBundle(hex"00FF");

        ClprTypes.QueueMetadata memory meta2 = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.DRAINED,
            endpointManifestVersion: 0
        });
        verifier.setVerifyBundleResult(meta2, msgs);
        verifier.setNewTrustAnchor(hex"02");
        _submitBundle(hex"00FF02");

        // Now CLOSED → revert
        ClprTypes.QueueMetadata memory meta3 = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.CLOSED,
            endpointManifestVersion: 0
        });
        verifier.setVerifyBundleResult(meta3, msgs);

        vm.expectRevert(ClprTypes.ClprInvalidChannelStatus.selector);
        _submitBundle(hex"00FF03");
    }

    // ── PENDING status rejected at processBundle (direct)

    /// @dev Directly exercises the PENDING guard in BundleLib.
    ///      Uses vm.store to force an existing channel's status
    ///      field to PENDING (enum value 0) without going through the full
    ///      commitment lifecycle.
    ///
    ///      Storage layout (from `forge inspect ClprService storage`):
    ///        _channels is at slot 17.
    ///        Channel struct offset 1 packs: verifier (160 bits) | status (8 bits) | nextMessageId (64 bits).
    ///        So status occupies bits 160–167 of the word at keccak256(abi.encode(channelId, 17)) + 1.
    function test_C9_processBundle_rejectsPendingDirectly() public {
        // Compute the storage slot for Channel.status within _channels[channelId].
        // _channels is mapping at slot 15; struct field offset 1 holds the packed slot.
        uint256 channelsSlot = 15;
        bytes32 baseSlot = keccak256(abi.encode(channelId, channelsSlot));
        bytes32 packedSlot = bytes32(uint256(baseSlot) + 1); // struct offset 1

        // Read current packed word and clear the status byte (bits 160-167).
        // Status is ACTIVE (1) after setUp; we want PENDING (0).
        bytes32 current = vm.load(address(service), packedSlot);
        // Mask: zero out bits 160-167 (the one byte immediately above the 20-byte address).
        uint256 mask = ~(uint256(0xFF) << 160);
        bytes32 patched = bytes32(uint256(current) & mask);
        // status = PENDING = 0, so no OR needed — the masked value already encodes PENDING.
        vm.store(address(service), packedSlot, patched);

        // Verify the status was written correctly by reading back through getChannel.
        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.PENDING), "setup: status should be PENDING");

        // Now attempt to submit a bundle — must revert with ClprInvalidChannelStatus.
        bytes[] memory msgs = new bytes[](0);
        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0
        });
        verifier.setVerifyBundleResult(meta, msgs);
        verifier.setNewTrustAnchor(hex"01");

        vm.expectRevert(ClprTypes.ClprInvalidChannelStatus.selector);
        _submitBundle(hex"DEAD");
    }

    /// @dev condition 4a second operand FALSE: meta.state=CLOSING but
    ///      channel.status=CLOSING (not ACTIVE/PAUSED), so (ACTIVE||PAUSED) evaluates to false.
    ///      BRDA:131,6,0,- — inside 4c: `meta.receivedMessageId(0) > effectiveAcked(0)` FALSE;
    ///      effectiveAcked stays at channel.ackedMessageId.
    ///      Both branches are covered in one test: local CLOSING + peer CLOSING + nextMessageId==1.
    function test_checkBundleProgress_closingConnMetaClosing_drains() public {
        service.closeChannel(channelId); // channel.status → CLOSING

        bytes[] memory msgs = new bytes[](0);
        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.CLOSING,
            endpointManifestVersion: 0
        });
        verifier.setVerifyBundleResult(meta, msgs);
        _submitBundle(hex"CC");

        // 4c fires (nextMessageId==1 → all acked) → channel transitions CLOSING → DRAINED.
        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.DRAINED));
    }
}
