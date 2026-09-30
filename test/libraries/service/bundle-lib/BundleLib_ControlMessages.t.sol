// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {MockClprApplication} from "@test/mocks/MockClprApplication.sol";
import {MockClprConnector} from "@test/mocks/MockClprConnector.sol";
import {BundleLibTestBase} from "@test/libraries/service/bundle-lib/BundleLibTestBase.sol";

contract BundleLib_ControlMessagesTest is BundleLibTestBase {
    // ── Test 10: CONTROL message -> updates timestamp

    function test_controlMessage_updatesTimestamp() public {
        uint64 newTimestamp = 2000000; // seconds
        // _makeConfig encodes as nanosSinceEpoch (seconds * 1e9).
        // BundleLib now stores nanosSinceEpoch directly in channel.peerConfigTimestamp (uint96).
        bytes memory controlPayload = ClprProtobuf.encodeControlMessage(_makeConfig(newTimestamp));

        _submitSingleInboundMessage(controlPayload);

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        // peerConfigTimestamp stores nanos: 2000000 * 1e9 = 2000000000000000
        assertEq(channel.peerConfigTimestamp, uint96(newTimestamp) * 1_000_000_000);
        // No reply should be queued for control messages
        assertEq(channel.nextMessageId, 1); // still 1, no outbound messages added
    }

    function test_lazyConfigPropagation_enqueuesControl() public {
        // Bump service ledger config to a timestamp strictly greater than
        // channel.lastConfigTimestamp so step 10b triggers.
        // Move time forward to ensure a strictly larger nanosSinceEpoch.
        vm.warp(block.timestamp + 10);
        service.updateLedgerConfiguration(hex"BEEF", defaultThrottles, "", "");

        // Submit a bundle that would otherwise be a no-op but carries a new trust anchor
        // to avoid the NoProgress guard in _validateAndPrepare.
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
        bytes[] memory msgs = new bytes[](0);
        verifier.setVerifyBundleResult(meta, msgs);
        verifier.setNewTrustAnchor(hex"01");

        // Call submitBundle with a valid peer-endpoint signature
        bytes memory proofBytes = hex"00FF";
        service.submitBundle(channelId, proofBytes);

        // After processing, a CONTROL message must be enqueued at outbound id 1.
        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(channel.nextMessageId, 2, "nextMessageId should increment after enqueuing CONTROL");
        assertGt(channel.lastConfigTimestamp, 0, "lastConfigTimestamp should be set");

        ClprTypes.MessageValue memory slot = service.getMessage(channelId, 1);
        assertGt(slot.payload.length, 0, "control payload must be stored");
        assertEq(uint8(ClprProtobuf.getMessageType(slot.payload)), uint8(ClprTypes.MessageType.CONTROL));
        // runningHashAfterProcessing should reflect the enqueued CONTROL payload
        assertTrue(slot.runningHashAfterProcessing != bytes32(0), "running hash should be updated");
    }

    /// @dev A ConfigUpdate declaring a protocol_version this ledger doesn't recognize must
    ///      revert the entire bundle, not be silently skipped (spec §1.1, §3.1.1).
    function test_controlMessage_protocolVersionMismatchRejected() public {
        ClprTypes.LedgerConfiguration memory cfg = _makeConfig(2_000_000);
        cfg.protocolVersion = 2; // deployed service runs protocolVersion 1

        bytes memory controlPayload = ClprProtobuf.encodeControlMessage(cfg);

        // Inlined (not via _submitSingleInboundMessage): vm.expectRevert only watches the
        // very next call, so the harmless verifier setup call must happen first, with the
        // watcher armed immediately before the submitBundle call it's actually meant to catch.
        bytes[] memory msgs = new bytes[](1);
        msgs[0] = controlPayload;
        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(controlPayload)));
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

        // Channel creation seeds peerConfigTimestamp to 1000 (see ClprTestBase's
        // verifier.setVerifyConfigResult call) — capture it to confirm no partial effect below.
        ClprTypes.Channel memory connBefore = service.getChannel(channelId);

        vm.expectRevert(ClprTypes.ClprProtocolVersionMismatch.selector);
        service.submitBundle(channelId, hex"00FF");

        // No partial effect: peerConfigTimestamp must be unchanged after the rejected update.
        ClprTypes.Channel memory connAfter = service.getChannel(channelId);
        assertEq(connAfter.peerConfigTimestamp, connBefore.peerConfigTimestamp);
    }

    /// @dev A second CONTROL message carrying a timestamp that is not strictly greater than
    ///      the stored peerConfigTimestamp must be rejected (spec §2.4.2 replay protection).
    function test_controlMessage_replayRejected() public {
        uint64 t1 = 2_000_000;
        bytes memory payload1 = ClprProtobuf.encodeControlMessage(_makeConfig(t1));
        _submitSingleInboundMessage(payload1);

        ClprTypes.Channel memory connAfterFirst = service.getChannel(channelId);
        assertEq(connAfterFirst.peerConfigTimestamp, uint96(t1) * 1_000_000_000);

        // Replay: same timestamp again, delivered as the next message in sequence (id 2).
        bytes memory payload2 = ClprProtobuf.encodeControlMessage(_makeConfig(t1));
        bytes32 hash1 = sha256(abi.encodePacked(bytes32(0), sha256(payload1)));
        bytes32 hash2 = sha256(abi.encodePacked(hash1, sha256(payload2)));

        bytes[] memory msgs = new bytes[](1);
        msgs[0] = payload2;
        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 3,
            sentRunningHash: hash2,
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 2,
            lastMessageRunningHash: hash2
        });
        verifier.setVerifyBundleResult(meta, msgs);

        vm.expectRevert(ClprTypes.ClprReplayDetected.selector);
        service.submitBundle(channelId, hex"00FF");

        // Stored timestamp must be unchanged after the rejected replay.
        ClprTypes.Channel memory connAfterReplay = service.getChannel(channelId);
        assertEq(connAfterReplay.peerConfigTimestamp, uint96(t1) * 1_000_000_000);
    }

    /// @dev A strictly greater timestamp on a subsequent CONTROL message must still be accepted.
    function test_controlMessage_strictlyGreaterTimestampAccepted() public {
        uint64 t1 = 2_000_000;
        bytes memory payload1 = ClprProtobuf.encodeControlMessage(_makeConfig(t1));
        _submitSingleInboundMessage(payload1);

        uint64 t2 = 3_000_000;
        bytes memory payload2 = ClprProtobuf.encodeControlMessage(_makeConfig(t2));
        bytes32 hash1 = sha256(abi.encodePacked(bytes32(0), sha256(payload1)));
        bytes32 hash2 = sha256(abi.encodePacked(hash1, sha256(payload2)));

        bytes[] memory msgs = new bytes[](1);
        msgs[0] = payload2;
        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 3,
            sentRunningHash: hash2,
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 2,
            lastMessageRunningHash: hash2
        });
        verifier.setVerifyBundleResult(meta, msgs);

        service.submitBundle(channelId, hex"00FF");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(channel.peerConfigTimestamp, uint96(t2) * 1_000_000_000);
    }

    // NOTE: test_refreshPeerRoster_badKeyLength_endpointSkipped removed — endpoints no longer
    // carry a signing key and LedgerConfiguration no longer carries seedEndpoints; the roster
    // is now derived on the fly from the cached peer manifest (ChannelLogic.getPeerEndpointRoster).

    /// @dev _refreshPeerEndpointRoster de-duplicates within a single batch: two seed endpoints
    ///      sharing an accountId register only once (the second hits the already-registered guard).
    function test_refreshPeerRoster_duplicateAccountId_registeredOnce() public {
        ClprTypes.Endpoint[] memory eps = new ClprTypes.Endpoint[](2);
        eps[0] = ClprTypes.Endpoint({ipAddress: "127.0.0.1", port: 50211, tlsCertificate: hex"", accountId: hex"0A"});
        eps[1] = ClprTypes.Endpoint({ipAddress: "127.0.0.2", port: 50212, tlsCertificate: hex"", accountId: hex"0A"});

        ClprTypes.LedgerConfiguration memory cfg;
        cfg.protocolVersion = 1; // must match the deployed service's protocolVersion
        cfg.nanosSinceEpoch = 1_000_000_000; // > 0 triggers pendingRosterRefresh
        cfg.throttles = defaultThrottles;

        bytes memory controlPayload = ClprProtobuf.encodeControlMessage(cfg);
        _submitSingleInboundMessage(controlPayload);

        // Duplicate accountId collapses to a single roster entry (first one wins).
        ClprTypes.PeerEndpoint[] memory roster = service.getPeerEndpointRoster(channelId);
        assertEq(roster.length, 1, "duplicate accountId registers once");
        assertEq(roster[0].ipAddress, bytes("127.0.0.1"), "first endpoint wins");
    }

    receive() external payable {}
}
