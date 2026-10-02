// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {BundleLogicTestBase} from "@test/logic/bundle-logic/BundleLogicTestBase.sol";
import {SecurityAssertions} from "@test/security/SecurityAssertions.sol";

/// @notice Multi-step attacks on inbound bundle processing.
/// @dev Each scenario chains several of BundleLib's guards and then asserts the channel's
///      integrity *after* the attack fails — that no partial state was written, no accounting was
///      freed, and no message was skipped. The individual guards are asserted on their own by the
///      `BundleLib_*` and `BundleLogic_*` suites; what those cannot show is the state a failed
///      attempt leaves behind, because each stops at its own revert.
///
///      `submitBundle` is permissionless by design, so the attacker needs no privilege. The mock
///      verifier stands in for a proof, which is what lets these tests choose the `QueueMetadata`
///      and payload list a proof would attest while BundleLib's own checks stay live.
contract BundleAttacksTest is BundleLogicTestBase, SecurityAssertions {
    function setUp() public override {
        super.setUp();
        _registerTestConnector();
    }

    /// A rewound bundle cannot re-deliver messages the channel already accepted.
    ///
    /// A relay replaying an older proof claims a `nextMessageId` behind what the channel has
    /// received; accepting it would dispatch those messages a second time. The attacker pairs the
    /// rewind with an ack advance so the bundle clears the progress gate and reaches the
    /// message-position check, which rejects it. The channel is left where it was and still
    /// accepts the honest continuation.
    /// @custom:matrix-row B4
    function test_rewoundBundle_cannotRedeliverAcceptedMessages() public {
        bytes[] memory all = _payloads(3);

        // Legitimately receive messages 1..2. Each inbound DATA queues a reply, so there is an ack to advance.
        _submitBundleWithAnchor(channelId, _slice(all, 0, 2), 2, _runningHashThrough(all, 2));
        assertEq(_localSyncData(channelId).receivedMessageId, 2, "precondition: 1..2 received");
        bytes32 receivedHashBefore = service.getChannel(channelId).receivedRunningHash;

        // Replay the bundle that delivered message 1, acking our first reply so it clears the progress gate.
        _armBundleAnchor(_slice(all, 0, 1), 1, _runningHashThrough(all, 1), 1);
        vm.prank(attacker);
        vm.expectRevert(ClprTypes.ClprReplayDetected.selector);
        service.submitBundle(channelId, hex"00FF");

        assertEq(_localSyncData(channelId).receivedMessageId, 2, "a rewind must not move progress");
        assertEq(
            service.getChannel(channelId).receivedRunningHash,
            receivedHashBefore,
            "a rewind must not touch the hash chain"
        );
        assertEq(service.getChannel(channelId).ackedMessageId, 0, "the rewound bundle's ack must not apply");

        // The honest continuation still applies.
        _submitBundleWithAnchor(channelId, _slice(all, 2, 3), 3, _runningHashThrough(all, 3));
        assertEq(_localSyncData(channelId).receivedMessageId, 3, "the honest continuation must still apply");
    }

    /// A message cannot be skipped, by any route, and failed attempts leave no trace.
    ///
    /// Chains the message-position and hash-chain guards across two attempts. An attacker that
    /// wants message 3 never delivered must either claim a `lastMessageId` beyond the payloads it
    /// carries, or carry a forged payload in message 3's slot. Both fail; the interesting part
    /// is that after both failures the channel is byte-for-byte where it started, so the
    /// legitimate bundle still applies and message 3 is delivered exactly once.
    /// @custom:matrix-row B10
    function test_messageCannotBeSkipped_andFailedAttemptsLeaveNoState() public {
        bytes[] memory all = _payloads(4);

        // Legitimately receive messages 1..2.
        _submitBundleWithAnchor(channelId, _slice(all, 0, 2), 2, _runningHashThrough(all, 2));
        assertEq(_localSyncData(channelId).receivedMessageId, 2, "precondition: 1..2 received");
        bytes32 receivedHashBefore = service.getChannel(channelId).receivedRunningHash;

        // Attempt 1: claim the run ends at message 4 (`lastMessageId` 4) while carrying only
        // message 4 — skipping 3 outright.
        bytes[] memory onlyFourth = _slice(all, 3, 4);
        _armBundleAnchor(onlyFourth, 4, _runningHashThrough(all, 4), 2);
        vm.prank(attacker);
        vm.expectRevert(ClprTypes.ClprReplayDetected.selector);
        service.submitBundle(channelId, hex"00FF");

        // Attempt 2: carry two payloads so the count checks out, but substitute message 3.
        bytes[] memory forged = _slice(all, 2, 4);
        forged[0] = ClprProtobuf.encodeDataMessage(
            connectorId, abi.encodePacked(address(connector)), abi.encodePacked(uint32(3)), "FORGED"
        );
        _armBundleAnchor(forged, 4, _runningHashThrough(all, 4), 2);
        vm.prank(attacker);
        vm.expectRevert(ClprTypes.ClprRunningHashMismatch.selector);
        service.submitBundle(channelId, hex"00FF");

        // Neither failure moved the channel.
        assertEq(_localSyncData(channelId).receivedMessageId, 2, "failed attempts must not advance progress");
        assertEq(
            service.getChannel(channelId).receivedRunningHash,
            receivedHashBefore,
            "failed attempts must not touch the hash chain"
        );

        // And the honest continuation still applies, delivering 3 and 4 exactly once.
        _submitBundleWithAnchor(channelId, _slice(all, 2, 4), 4, _runningHashThrough(all, 4));
        assertEq(_localSyncData(channelId).receivedMessageId, 4, "honest bundle must still apply after the attack");
        assertEq(
            service.getChannel(channelId).receivedRunningHash,
            _runningHashThrough(all, 4),
            "hash chain must cover all four messages"
        );
    }

    /// A forged ack cannot launder per-connector queue quota.
    ///
    /// A connector's quota is held until the peer's reply to each of its messages is processed.
    /// If an unbacked ack released it, the connector could exceed its share of the shared queue
    /// indefinitely. This drives the queue to its quota, has the attacker try to free it with an
    /// unbacked ack, and asserts the quota is still exhausted afterwards; only a legitimate reply
    /// releases exactly one slot.
    /// @custom:matrix-row B11
    function test_forgedAck_cannotLaunderConnectorQuota() public {
        // maxQueueDepth 4 with the default 50% connector quota gives this connector 2 slots.
        ClprTypes.Throttles memory throttles = defaultThrottles;
        throttles.maxQueueDepth = 4;
        service.updateLedgerConfiguration(hex"1234", throttles, "", "");

        bytes memory target = abi.encodePacked(address(connector));
        service.sendMessage(channelId, connectorId, target, "one");
        service.sendMessage(channelId, connectorId, target, "two");

        // Quota is now exhausted.
        vm.expectRevert(ClprTypes.ClprQueueQuotaExceeded.selector);
        service.sendMessage(channelId, connectorId, target, "three");

        uint64 nextMessageId = service.getChannel(channelId).nextMessageId;

        // Attack: claim an ack beyond anything we ever sent, to free both slots at once.
        bytes[] memory none = new bytes[](0);
        _armBundleAnchor(none, 0, bytes32(0), nextMessageId + 10);
        vm.prank(attacker);
        vm.expectRevert(ClprTypes.ClprAckVerificationFailed.selector);
        service.submitBundle(channelId, hex"00FF");

        // The quota is still exhausted: nothing was laundered.
        assertEq(service.getChannel(channelId).ackedMessageId, 0, "forged ack must not apply");
        vm.expectRevert(ClprTypes.ClprQueueQuotaExceeded.selector);
        service.sendMessage(channelId, connectorId, target, "three");

        // A legitimate reply releases exactly one slot, and no more. The quota is released by the
        // reply, not the ack: an ack covering a live DATA message without its reply is committed,
        // but pauses the channel and leaves the quota held.
        bytes[] memory reply = new bytes[](1);
        reply[0] = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"");
        _armBundleAnchor(reply, 1, _runningHashThrough(reply, 1), 1);
        vm.prank(attacker);
        service.submitBundle(channelId, hex"00FF");
        assertEq(service.getChannel(channelId).ackedMessageId, 1, "honest ack should apply");
        assertEq(
            uint8(_localSyncData(channelId).status),
            uint8(ClprTypes.ChannelStatus.ACTIVE),
            "an in-order reply must leave the channel ACTIVE"
        );

        service.sendMessage(channelId, connectorId, target, "three");
        vm.expectRevert(ClprTypes.ClprQueueQuotaExceeded.selector);
        service.sendMessage(channelId, connectorId, target, "four");
    }

    /// A closing channel drains forward and can never be revived.
    ///
    /// Once the operator closes a channel, a peer that keeps claiming ACTIVE must not be able to
    /// hold it open or walk it back — that would defeat the close and keep accepting traffic the
    /// operator decided to stop. Status transitions are monotonic, so each of the peer's claims
    /// either advances the drain or does nothing. `BundleLib_StateMachine` asserts the same rule
    /// against `BundleLibHarness`; this is the end-to-end path through `submitBundle`, and it
    /// also checks the channel cannot be sent to after the close. The local side has one DATA
    /// message the peer never acks: with an empty queue `closeChannel` goes straight to DRAINED.
    /// @custom:matrix-row B9
    function test_closingChannel_cannotBeRevivedByPeerClaims() public {
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(connector)), "unacked");
        service.closeChannel(channelId);
        assertEq(
            uint8(_localSyncData(channelId).status), uint8(ClprTypes.ChannelStatus.CLOSING), "precondition: CLOSING"
        );

        bytes[] memory all = _payloads(2);

        // The peer insists the channel is ACTIVE while delivering traffic, twice.
        _armBundleAnchor(_slice(all, 0, 1), 1, _runningHashThrough(all, 1), 0);
        vm.prank(attacker);
        service.submitBundle(channelId, hex"00FF");
        uint8 afterFirst = uint8(_localSyncData(channelId).status);
        assertGe(afterFirst, uint8(ClprTypes.ChannelStatus.CLOSING), "status must not move backwards");

        _armBundleAnchor(_slice(all, 1, 2), 2, _runningHashThrough(all, 2), 0);
        vm.prank(attacker);
        service.submitBundle(channelId, hex"00FF");
        uint8 afterSecond = uint8(_localSyncData(channelId).status);
        assertGe(afterSecond, afterFirst, "status must only ever step forward");
        assertTrue(
            afterSecond != uint8(ClprTypes.ChannelStatus.ACTIVE)
                && afterSecond != uint8(ClprTypes.ChannelStatus.PAUSED),
            "a peer's ACTIVE claim must not revive a closing channel"
        );

        // And the local side cannot be talked into sending on it again.
        vm.expectRevert(ClprTypes.ClprInvalidChannelStatus.selector);
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(connector)), "after close");
    }
}
