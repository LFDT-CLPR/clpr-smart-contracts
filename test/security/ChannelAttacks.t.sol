// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {BundleLogicTestBase} from "@test/logic/bundle-logic/BundleLogicTestBase.sol";
import {SecurityAssertions} from "@test/security/SecurityAssertions.sol";

/// @notice Channel lifecycle attack rows from `docs/security-test-matrix.md` (C domain).
/// @dev This file holds multi-step attacks. The single channel guards —
///      the commitment check, the reveal signature and its router binding, the duplicate and cap
///      checks, the channel-id re-derivation, the verifier code check, the legal close
///      transitions — are each asserted at this level by `ChannelLogic.t.sol`, so those rows are
///      `E*` and the matrix points at them.
contract ChannelAttacksTest is BundleLogicTestBase, SecurityAssertions {
    function setUp() public override {
        super.setUp();
        _registerTestConnector();
    }

    /// @dev Arms the mock verifier with the peer's `QueueMetadata`, including its `state`, which
    ///      drives the close state machine. `_armBundleAnchor` always claims ACTIVE.
    function _armBundleWithPeerStatus(
        bytes[] memory payloads,
        uint64 nextMessageId,
        bytes32 sentRunningHash,
        uint64 receivedMessageId,
        ClprTypes.ChannelStatus remoteStatus
    ) internal {
        verifier.setVerifyBundleResult(
            ClprTypes.QueueMetadata({
                nextMessageId: nextMessageId,
                sentRunningHash: sentRunningHash,
                receivedMessageId: receivedMessageId,
                receivedRunningHash: bytes32(0),
                state: remoteStatus,
                endpointManifestVersion: 0,
                lastMessageId: payloads.length > 0 ? nextMessageId - 1 : 0,
                lastMessageRunningHash: payloads.length > 0 ? sentRunningHash : bytes32(0)
            }),
            payloads
        );
    }

    /// C15 — closing a channel with messages in flight loses nothing and cannot be short-circuited.
    ///
    /// The close sequence is where message loss would hide: the operator stops new traffic while
    /// replies for already-sent messages are still arriving. This drives the full
    /// ACTIVE→CLOSING→DRAINED→CLOSED walk with two messages in flight and asserts the drain gates
    /// hold — the channel cannot reach CLOSED before every message is acked — and that a closed
    /// channel is inert in both directions afterwards.
    function test_C15_closeWithInflightMessages_drainsWithoutLoss() public {
        bytes memory target = abi.encodePacked(address(connector));
        service.sendMessage(channelId, connectorId, target, "one");
        service.sendMessage(channelId, connectorId, target, "two");
        assertEq(service.getChannel(channelId).nextMessageId, 3, "precondition: two messages in flight");

        service.closeChannel(channelId);
        assertEq(
            uint8(_localSyncData(channelId).status), uint8(ClprTypes.ChannelStatus.CLOSING), "close moves to CLOSING"
        );

        // The peer claims it is done while only acking the first message. The DRAINED gate is
        // `all DATA acked`, so this must not reach CLOSED with message 2 unacknowledged.
        bytes[] memory firstReply = new bytes[](1);
        firstReply[0] = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"");
        _armBundleWithPeerStatus(firstReply, 2, _runningHashThrough(firstReply, 1), 1, ClprTypes.ChannelStatus.CLOSED);
        vm.prank(attacker);
        service.submitBundle(channelId, hex"00FF");

        assertEq(service.getChannel(channelId).ackedMessageId, 1, "only message 1 is acked");
        // Still CLOSING: the DRAINED gate is `all DATA acked`, and message 2 is not. Asserting
        // the exact status rather than "not CLOSED" is what pins that gate — a version of this
        // test that only checked "not CLOSED" survived a mutation that forced the gate open.
        assertEq(
            uint8(_localSyncData(channelId).status),
            uint8(ClprTypes.ChannelStatus.CLOSING),
            "must stay CLOSING while message 2 is unacked"
        );

        // The peer acks the rest. Only now may the channel close.
        bytes[] memory secondReply = new bytes[](1);
        secondReply[0] = ClprProtobuf.encodeReplyMessage(2, ClprTypes.ReplyStatus.SUCCESS, hex"");
        bytes32 chainThroughTwo = sha256(abi.encodePacked(_runningHashThrough(firstReply, 1), sha256(secondReply[0])));
        _armBundleWithPeerStatus(secondReply, 3, chainThroughTwo, 2, ClprTypes.ChannelStatus.CLOSED);
        vm.prank(attacker);
        service.submitBundle(channelId, hex"00FF");

        assertEq(service.getChannel(channelId).ackedMessageId, 2, "both messages acked");
        assertEq(
            uint8(_localSyncData(channelId).status), uint8(ClprTypes.ChannelStatus.CLOSED), "channel should be CLOSED"
        );

        // Both messages were replied to exactly once: their queue slots are released.
        assertEq(service.getMessage(channelId, 1).payload.length, 0, "message 1 slot must be released");
        assertEq(service.getMessage(channelId, 2).payload.length, 0, "message 2 slot must be released");

        // A closed channel is inert in both directions.
        vm.expectRevert(ClprTypes.ClprInvalidChannelStatus.selector);
        service.sendMessage(channelId, connectorId, target, "after close");

        _armBundleWithPeerStatus(secondReply, 4, chainThroughTwo, 2, ClprTypes.ChannelStatus.CLOSED);
        vm.prank(attacker);
        vm.expectRevert(ClprTypes.ClprInvalidChannelStatus.selector);
        service.submitBundle(channelId, hex"00FF");
    }

    /// C15 — the second drain gate: an unacked *reply* also blocks CLOSED.
    ///
    /// `all DATA acked` releases CLOSING→DRAINED, but DRAINED→CLOSED additionally requires every
    /// outbound message to be acked, replies included. Otherwise a channel could close while our
    /// reply to the peer's last message was still unacknowledged, and the peer would never learn
    /// the outcome of the message it sent. `BundleLib_StateMachine` covers this against the
    /// harness; this is the end-to-end path.
    function test_C15_responseGateBlocksCloseUntilRepliesAreAcked() public {
        // An inbound DATA message makes us enqueue an outbound REPLY (message 1).
        bytes[] memory inbound = _payloads(1);
        _submitBundleWithAnchor(channelId, inbound, 1, _runningHashThrough(inbound, 1));
        assertEq(service.getChannel(channelId).nextMessageId, 2, "precondition: a reply is queued");

        // We never sent DATA, so the DATA gate is already met and the close goes straight to
        // DRAINED. Our reply is unacked, so it must stay there even though the peer reports CLOSED.
        service.closeChannel(channelId);
        assertEq(
            uint8(_localSyncData(channelId).status), uint8(ClprTypes.ChannelStatus.DRAINED), "precondition: DRAINED"
        );

        bytes[] memory none = new bytes[](0);
        // A payload-free bundle must restate our head — `nextMessageId` one past our
        // receivedMessageId, `sentRunningHash` our receivedRunningHash — or it fails the replay or
        // running-hash check.
        bytes32 inboundHash = _runningHashThrough(inbound, 1);
        _armBundleWithPeerStatus(none, 2, inboundHash, 0, ClprTypes.ChannelStatus.CLOSED);
        // With no message, no ack and no status change the bundle would revert `NoProgress`; a new
        // trust anchor lets it apply, so the state machine runs on the peer's CLOSED claim.
        verifier.setNewTrustAnchor(hex"AA");
        vm.prank(attacker);
        service.submitBundle(channelId, hex"00FF");
        assertEq(
            uint8(_localSyncData(channelId).status),
            uint8(ClprTypes.ChannelStatus.DRAINED),
            "must stop at DRAINED while our reply is unacked"
        );

        // Once the peer acks the reply, the channel may close.
        _armBundleWithPeerStatus(none, 2, inboundHash, 1, ClprTypes.ChannelStatus.CLOSED);
        vm.prank(attacker);
        service.submitBundle(channelId, hex"00FF");
        assertEq(
            uint8(_localSyncData(channelId).status),
            uint8(ClprTypes.ChannelStatus.CLOSED),
            "an acked reply releases the final gate"
        );
    }
}
