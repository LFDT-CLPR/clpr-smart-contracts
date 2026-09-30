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
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";

contract BundleLogic_Configuration is BundleLogicTestBase {
    /// @dev A second "alternate" peer endpoint key used in CONTROL-message tests.
    uint256 internal altPeerEpPk = uint256(keccak256("clpr.test.altPeerEndpoint"));

    function setUp() public override {
        super.setUp();
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

    /// @dev A config update pending while CLOSING/DRAINED must not enqueue a new
    /// outbound CONTROL message, or DRAINED -> CLOSED would wait forever on a peer that has no
    /// reason to ack a message sent after it already reported itself DRAINED.
    function test_lazyConfigPropagation_skippedWhileClosing_allowsDrainedToClosed() public {
        vm.warp(block.timestamp + 10);
        service.updateLedgerConfiguration(hex"BEEF", defaultThrottles, "", "");

        service.closeChannel(channelId);
        assertEq(
            uint8(service.getChannel(channelId).status),
            uint8(ClprTypes.ChannelStatus.CLOSING),
            "channel should be CLOSING before the bundle"
        );

        // Peer already reports DRAINED with nothing outstanding; with nextMessageId still 1,
        // every prior outbound message is trivially acked.
        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.DRAINED,
            endpointManifestVersion: 0,
            lastMessageId: 0,
            lastMessageRunningHash: bytes32(0)
        });
        bytes[] memory msgs = new bytes[](0);
        verifier.setVerifyBundleResult(meta, msgs);
        service.submitBundle(channelId, hex"00FF");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(channel.nextMessageId, 1, "config propagation must not enqueue a CONTROL message");
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.CLOSED), "channel should reach CLOSED");
    }

    // NOTE: test_refreshPeerRoster_badKeyLength_endpointSkipped removed — roster refresh via
    // ConfigUpdate CONTROL messages is removed.

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

    // NOTE: test_controlMessage_refreshesRoster and test_controlMessage_skipsDuplicateEndpointsInRoster
    // removed — endpoint changes no longer propagate via ConfigUpdate CONTROL messages (ADR: endpoint
    // manifests). Peer endpoints now travel through manifest-update bundle payloads (BundleLib Step 1b);
    // covered by the manifest test suite.

    /// @notice Craft a CONTROL payload whose LedgerConfiguration and nested ServiceEndpoint
    ///         contain unknown fields, ensuring the decoder exercises PB.skipField at both levels:
    ///         - Inside ServiceEndpoint loop (svcPos branch)
    ///         - At top-level LedgerConfiguration loop (pos branch)
    function test_controlMessage_unknownFields_inConfig_revertEntireBundle() public {
        // LedgerConfiguration: normal fields plus an unknown top-level field 99. Endpoints are no
        // longer carried here (they moved into the versioned endpoint manifest), so field 99 is the
        // first and only unrecognized field the config decoder meets.
        bytes memory configMsg = abi.encodePacked(
            PB.encodeVarintField(1, uint64(1)), // protocolVersion
            PB.encodeBytesField(2, bytes("eip155:1")),
            PB.encodeBytesField(3, hex"AABB"),
            // unknown top-level field
            PB.encodeBytesField(99, hex"DEAD")
        );

        // Wrap into ClprControlMessage and ClprMessagePayload
        bytes memory configUpdate = abi.encodePacked(PB.encodeFieldKey(1, 2), PB.encodeLengthDelimited(configMsg));
        bytes memory controlMsg = abi.encodePacked(PB.encodeFieldKey(1, 2), PB.encodeLengthDelimited(configUpdate));
        bytes memory controlPayload = abi.encodePacked(PB.encodeFieldKey(3, 2), PB.encodeLengthDelimited(controlMsg));

        // Prepare verifier to return this CONTROL message
        bytes32 runningHash = sha256(abi.encodePacked(bytes32(0), sha256(controlPayload)));
        bytes[] memory msgs = new bytes[](1);
        msgs[0] = controlPayload;
        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 2,
            sentRunningHash: runningHash,
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 1,
            lastMessageRunningHash: runningHash
        });
        verifier.setVerifyBundleResult(meta, msgs);

        // The unknown field is hit first
        vm.expectRevert(abi.encodeWithSelector(ClprTypes.ClprUnknownWireField.selector, 99));
        service.submitBundle(channelId, hex"ABCD");

        // Atomic rejection: no inbound progress, no config change.
        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(channel.receivedMessageId, 0, "no inbound progress on a rejected bundle");
        assertEq(channel.peerConfigTimestamp, 1000, "peer config unchanged");
    }

    // ── Throttle validation inside ConfigUpdate ───────────────────────────────

    function test_configUpdate_revert_invalidPeerThrottles() public {
        uint64 newTimestamp = 3_000_000;
        ClprTypes.LedgerConfiguration memory cfg = _makeConfig(newTimestamp);
        cfg.throttles.maxGasPerMessage = 0;
        bytes memory controlPayload = ClprProtobuf.encodeControlMessage(cfg);

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
        vm.expectRevert(ClprTypes.ClprInvalidConfiguration.selector);
        service.submitBundle(channelId, hex"00FF");
    }

    receive() external payable override {}
}
