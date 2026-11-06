// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {BundleLib} from "@hiero-ledger/clpr/libraries/service/BundleLib.sol";
import {MockClprConnector} from "@test/mocks/MockClprConnector.sol";
import {BundleLibTestBase} from "@test/libraries/service/bundle-lib/BundleLibTestBase.sol";

contract BundleLib_ReplayTest is BundleLibTestBase {
    // ── Test 3: Replay defense -- submitting same bundle twice

    function test_replayDefense_sameBundleTwice() public {
        _registerTestConnector();

        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");

        _submitSingleInboundMessage(dataPayload);

        // Second submission with same metadata makes no progress (all messages already received,
        // ack unchanged) — NoProgress now takes precedence over ClprReplayDetected.
        vm.expectRevert(BundleLib.NoProgress.selector);
        _submitBundle(hex"00FF");
    }

    // ── Allow duplicate messages as long as the bundle makes progress

    /// @dev A bundle covering messages [1, 2] is submitted when receivedMessageId=1.
    ///      Message 1 is a duplicate; message 2 is genuinely new.
    ///      The duplicate leading message is skipped, message 2 is
    ///      processed, and receivedMessageId advances to 2.
    function test_bundleWithLeadingDuplicate_isAcceptedWhenBundleMakesProgress() public {
        _registerTestConnector();

        bytes memory payload1 =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");

        // Deliver message 1. receivedMessageId → 1.
        _submitSingleInboundMessage(payload1);
        assertEq(service.getChannel(channelId).receivedMessageId, 1);

        // Second bundle: re-includes message 1 (duplicate) and adds new message 2.
        bytes memory payload2 =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"DEADBEEF");

        bytes[] memory msgs = new bytes[](2);
        msgs[0] = payload1; // duplicate — already received
        msgs[1] = payload2; // new

        // sentRunningHash covers both messages chained from the zero seed;
        // the receiver can verify by starting from its stored receivedRunningHash.
        bytes32 h1 = sha256(abi.encodePacked(bytes32(0), sha256(payload1)));
        bytes32 h2 = sha256(abi.encodePacked(h1, sha256(payload2)));

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 3,
            sentRunningHash: h2,
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 2,
            lastMessageRunningHash: h2
        });
        verifier.setVerifyBundleResult(meta, msgs);

        // Currently reverts; must succeed after the fix.
        service.submitBundle(channelId, hex"00FF");

        assertEq(service.getChannel(channelId).receivedMessageId, 2);
    }

    /// @dev Both sides simultaneously reach received=1, acked=0.  Each relay rebuilds
    ///      its outbound bundle from ackedMessageId+1=1, so the peer receives a bundle
    ///      that re-includes message 1 (already received) plus a new ack.
    ///
    ///      The ack must target a non-DATA outbound slot so that response-ordering does
    ///      not demand a missing REPLY.  Processing an inbound DATA message automatically
    ///      queues a REPLY in our outbound slot 1 (nextMessageId -> 2); the peer's ack of
    ///      that REPLY slot is valid without an accompanying REPLY-back.
    ///
    ///      The duplicate is stripped, only the ack lands, and
    ///      ackedMessageId advances to 1, breaking the deadlock.
    function test_bundleWithAllDuplicates_andNewAck_isAccepted() public {
        _registerTestConnector();

        bytes memory peerPayload1 =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");

        // Deliver peer's DATA message 1. receivedMessageId -> 1.
        // Processing the inbound DATA queues a REPLY in our outbound slot 1
        // (nextMessageId -> 2). A REPLY slot does not require a REPLY-back, so
        // the peer can ack it without including one in the bundle.
        _submitSingleInboundMessage(peerPayload1);

        assertEq(service.getChannel(channelId).receivedMessageId, 1);
        assertEq(service.getChannel(channelId).ackedMessageId, 0);
        assertEq(service.getChannel(channelId).nextMessageId, 2); // REPLY at slot 1

        // Second bundle: peer re-sends DATA message 1 (duplicate) and acks our
        // outbound REPLY at slot 1.
        bytes[] memory msgs = new bytes[](1);
        msgs[0] = peerPayload1; // duplicate - already received

        bytes32 h1 = sha256(abi.encodePacked(bytes32(0), sha256(peerPayload1)));

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 2, // no new messages beyond peer's message 1
            sentRunningHash: h1,
            receivedMessageId: 1, // acks our outbound REPLY at slot 1
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 1,
            lastMessageRunningHash: h1
        });
        verifier.setVerifyBundleResult(meta, msgs);

        // Currently reverts; must succeed after the fix.
        service.submitBundle(channelId, hex"00FF");

        ClprTypes.Channel memory connAfter = service.getChannel(channelId);
        assertEq(connAfter.ackedMessageId, 1); // ack landed
        assertEq(connAfter.receivedMessageId, 1); // no new messages
    }

    /// @dev Exchange between two peers (A/B)
    ///      So after the first exchange A's real outbound is:
    ///        slot 1: DATA(A1)       — queued by sendMessage()
    ///        slot 2: REPLY(for=B1)  — auto-queued when A received B1
    ///
    ///      B's second bundle therefore covers [ackedMessageId+1=1 .. nextMessageId-1=3]:
    ///        slot 1: DATA(B1)        — duplicate (A already has receivedMessageId=1)
    ///        slot 2: REPLY(for=A1)   — B's auto-reply to A's DATA at slot 1
    ///        slot 3: DATA(B2)        — new
    ///
    ///      _checkResponseOrdering requires REPLY(for=A1) to be present when B acks A's
    ///      slot 1 (a live DATA). That REPLY arrives at B's slot 2, so the guard passes.
    ///
    ///      Without the fix: expectedCount=2, payloads.length=3 → ClprReplayDetected.
    ///      With the fix: B1 skipped, REPLY(for=A1) and B2 processed,
    ///      receivedMessageId → 3, ackedMessageId → 1.
    function test_deadlock_bothSidesSendData_secondBundleHasLeadingDuplicateReplyAndNewData() public {
        _registerTestConnector();

        // Step 1: A queues an outbound DATA message (A1).
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"AABBCCDD");
        // slot 1 = DATA(A1), nextMessageId = 2
        assertEq(service.getChannel(channelId).nextMessageId, 2);

        // Step 2: First exchange — simultaneous. B sent B1 before knowing A sent A1,
        // so B's bundle has receivedMessageId=0 (no ack for A yet).
        // A receives B1; the contract auto-queues REPLY(for=B1) at slot 2 (nextMessageId → 3).
        bytes memory peerMsg1 =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");
        _submitSingleInboundMessage(peerMsg1); // peer nextMessageId=2, receivedMessageId=0
        // slot 2 = REPLY(for=B1), nextMessageId = 3
        assertEq(service.getChannel(channelId).nextMessageId, 3);
        assertEq(service.getChannel(channelId).receivedMessageId, 1);
        assertEq(service.getChannel(channelId).ackedMessageId, 0); // peer hadn't acked A1 yet

        // Step 3: A queues a second DATA message (A2).
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"EEFF0011");
        // slot 3 = DATA(A2), nextMessageId = 4
        assertEq(service.getChannel(channelId).nextMessageId, 4);

        // Step 4: B's second bundle. B covers [ackedMessageId+1=1 .. nextMessageId-1=3]:
        //   B1(dup) | REPLY(for=A1) | B2
        // B reports receivedMessageId=1: it received our slot 1 (DATA A1).
        //
        // _checkResponseOrdering demands REPLY(for=A1) for A's live DATA slot 1.
        // REPLY(for=A1) is present at B's slot 2 — guard passes.
        //
        // Without the fix: payloads.length(3) != expectedCount(2) → ClprReplayDetected.
        bytes memory peerReplyForA1 = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"");
        bytes memory peerMsg2 =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"DEADBEEF");

        bytes[] memory msgs = new bytes[](3);
        msgs[0] = peerMsg1; // B1 — duplicate
        msgs[1] = peerReplyForA1; // REPLY(for=A1) — required by _checkResponseOrdering
        msgs[2] = peerMsg2; // B2 — new DATA

        bytes32 h1 = sha256(abi.encodePacked(bytes32(0), sha256(peerMsg1)));
        bytes32 h2 = sha256(abi.encodePacked(h1, sha256(peerReplyForA1)));
        bytes32 h3 = sha256(abi.encodePacked(h2, sha256(peerMsg2)));

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 4, // B's slots 1, 2, 3 used
            sentRunningHash: h3,
            receivedMessageId: 1, // B received A's slot 1 (DATA A1) — advances ackedMessageId
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 3,
            lastMessageRunningHash: h3
        });
        verifier.setVerifyBundleResult(meta, msgs);

        service.submitBundle(channelId, hex"00FF");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(channel.receivedMessageId, 3); // B's messages 2 (REPLY) and 3 (B2) processed
        assertEq(channel.ackedMessageId, 1); // DATA(A1) acked — deadlock broken
    }

    receive() external payable {}
}
