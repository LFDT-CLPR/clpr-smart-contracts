// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprProtobufHelpers} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";

/// @dev Harness that exposes ClprProtobuf internal functions via external calls
///      so that forge coverage properly instruments their lines.
contract ClprProtobufHarness {
    function decodeChannelFromMemory(bytes memory data) external pure returns (ClprTypes.Channel memory) {
        return ClprProtobuf.decodeChannelFromMemory(data);
    }

    function decodeControlMessage(bytes memory data) external pure returns (ClprTypes.DecodedControl memory) {
        return ClprProtobuf.decodeControlMessage(data);
    }

    function decodeEndpointManifest(bytes memory data) external pure returns (ClprTypes.ClprEndpointManifest memory) {
        return ClprProtobuf.decodeEndpointManifest(data);
    }

    function decodeBundleContent(bytes calldata data)
        external
        pure
        returns (ClprTypes.QueueMetadata memory meta, bytes[] memory payloads)
    {
        return ClprProtobuf.decodeBundleContent(data);
    }
}

contract ClprProtobufTest is Test {
    ClprProtobufHarness internal harness;

    function setUp() public {
        harness = new ClprProtobufHarness();
    }

    function test_getMessageType_dataMessage() public pure {
        bytes memory payload = ClprProtobuf.encodeDataMessage(hex"AA", hex"BB", hex"CC", hex"DD");
        assertEq(uint8(ClprProtobuf.getMessageType(payload)), uint8(ClprTypes.MessageType.DATA));
    }

    function test_getMessageType_replyMessage() public pure {
        bytes memory payload = ClprProtobuf.encodeReplyMessage(42, ClprTypes.ReplyStatus.SUCCESS, hex"EE");
        assertEq(uint8(ClprProtobuf.getMessageType(payload)), uint8(ClprTypes.MessageType.REPLY));
    }

    function test_getMessageType_controlMessage() public pure {
        bytes memory payload = ClprProtobuf.encodeControlMessage(_makeConfig(12345));
        assertEq(uint8(ClprProtobuf.getMessageType(payload)), uint8(ClprTypes.MessageType.CONTROL));
    }

    function test_dataMessage_roundtrip() public pure {
        bytes32 connectorId = hex"AABBCCDD";
        bytes memory targetApp = hex"1122334455";
        bytes memory sender = hex"DEADBEEF";
        bytes memory msgData = hex"CAFEBABE";

        bytes memory encoded = ClprProtobuf.encodeDataMessage(connectorId, targetApp, sender, msgData);
        ClprTypes.DecodedDataMessage memory decoded = ClprProtobuf.decodeDataMessage(encoded);

        assertEq(decoded.connectorId, connectorId);
        assertEq(decoded.targetApplication, targetApp);
        assertEq(decoded.sender, sender);
        assertEq(decoded.messageData, msgData);
    }

    function test_dataMessage_emptyFields() public pure {
        bytes memory encoded = ClprProtobuf.encodeDataMessage(hex"AA", hex"BB", "", "");
        ClprTypes.DecodedDataMessage memory decoded = ClprProtobuf.decodeDataMessage(encoded);
        assertEq(decoded.connectorId, hex"AA");
        assertEq(decoded.targetApplication, hex"BB");
        assertEq(decoded.sender.length, 0);
        assertEq(decoded.messageData.length, 0);
    }

    function test_replyMessage_roundtrip() public pure {
        bytes memory encoded = ClprProtobuf.encodeReplyMessage(42, ClprTypes.ReplyStatus.SUCCESS, hex"AABBCCDD");
        ClprTypes.DecodedReply memory decoded = ClprProtobuf.decodeReplyMessage(encoded);
        assertEq(decoded.messageId, 42);
        assertEq(uint8(decoded.status), uint8(ClprTypes.ReplyStatus.SUCCESS));
        assertEq(decoded.messageReplyData, hex"AABBCCDD");
    }

    function test_replyMessage_applicationError() public pure {
        bytes memory encoded = ClprProtobuf.encodeReplyMessage(7, ClprTypes.ReplyStatus.APPLICATION_ERROR, "");
        ClprTypes.DecodedReply memory decoded = ClprProtobuf.decodeReplyMessage(encoded);
        assertEq(decoded.messageId, 7);
        assertEq(uint8(decoded.status), uint8(ClprTypes.ReplyStatus.APPLICATION_ERROR));
        assertEq(decoded.messageReplyData.length, 0);
    }

    function test_replyMessage_connectorNotFound() public pure {
        bytes memory encoded = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.CONNECTOR_NOT_FOUND, "");
        ClprTypes.DecodedReply memory decoded = ClprProtobuf.decodeReplyMessage(encoded);
        assertEq(uint8(decoded.status), uint8(ClprTypes.ReplyStatus.CONNECTOR_NOT_FOUND));
    }

    function test_controlMessage_roundtrip() public pure {
        ClprTypes.LedgerConfiguration memory config;
        config.protocolVersion = 2;
        config.chainId = "eip155:1";
        config.serviceAddress = hex"AABB";
        config.nanosSinceEpoch = 1700000000 * 1_000_000_000; // seconds only, nanos=0
        config.throttles = ClprTypes.Throttles({
            maxMessagesPerBundle: 50,
            maxMessagePayloadBytes: 512,
            maxGasPerMessage: 500_000,
            maxQueueDepth: 200,
            maxSyncBytes: 524_288,
            maxLocalEndpoints: 0,
            maxPeerEndpoints: 0
        });
        // Endpoints are no longer part of LedgerConfiguration — the config
        // round-trip covers protocol version, chain id, service address, timestamp, and throttles only.

        bytes memory encoded = ClprProtobuf.encodeControlMessage(config);
        ClprTypes.DecodedControl memory decoded = ClprProtobuf.decodeControlMessage(encoded);

        assertEq(decoded.config.protocolVersion, config.protocolVersion);
        assertEq(decoded.config.chainId, config.chainId);
        assertEq(decoded.config.serviceAddress, config.serviceAddress);
        assertEq(decoded.config.nanosSinceEpoch, config.nanosSinceEpoch);
        assertEq(decoded.config.throttles.maxMessagesPerBundle, config.throttles.maxMessagesPerBundle);
        assertEq(decoded.config.throttles.maxMessagePayloadBytes, config.throttles.maxMessagePayloadBytes);
        assertEq(decoded.config.throttles.maxGasPerMessage, config.throttles.maxGasPerMessage);
        assertEq(decoded.config.throttles.maxQueueDepth, config.throttles.maxQueueDepth);
        assertEq(decoded.config.throttles.maxSyncBytes, config.throttles.maxSyncBytes);
        assertEq(decoded.config.throttles.maxLocalEndpoints, config.throttles.maxLocalEndpoints);
        assertEq(decoded.config.throttles.maxPeerEndpoints, config.throttles.maxPeerEndpoints);
    }

    function _makeConfig(uint64 timestamp) internal pure returns (ClprTypes.LedgerConfiguration memory config) {
        config.nanosSinceEpoch = uint96(timestamp) * 1_000_000_000;
    }

    // ── Unknown ClprControlMessage oneof variant reverts ─────────────────────

    /// @dev External wrapper so vm.expectRevert can intercept the revert from a pure library call.
    function _decodeControlMessageExternal(bytes memory payload) external pure {
        ClprProtobuf.decodeControlMessage(payload);
    }

    // ── Layer wrappers (ClprMessage → ControlMessage → ConfigUpdate → LedgerConfiguration) ──

    function _controlPayloadWithThrottles(bytes memory throttlesMsg) internal pure returns (bytes memory) {
        bytes memory configMsg = abi.encodePacked(
            ClprProtobufHelpers.encodeVarintField(1, 1), // protocolVersion
            ClprProtobufHelpers.encodeFieldKey(5, 2),
            ClprProtobufHelpers.encodeLengthDelimited(throttlesMsg)
        );
        bytes memory configUpdate = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(1, 2), ClprProtobufHelpers.encodeLengthDelimited(configMsg)
        );
        bytes memory controlMsg = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(1, 2), ClprProtobufHelpers.encodeLengthDelimited(configUpdate)
        );
        return abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(3, 2), ClprProtobufHelpers.encodeLengthDelimited(controlMsg)
        );
    }

    // ── _decodeThrottles: uint32 bound checks (fields 1, 4, 6, 7) ───────────────

    function _assertThrottleFieldOverflowReverts(uint64 fieldNum) internal {
        bytes memory throttles = ClprProtobufHelpers.encodeVarintField(fieldNum, uint64(type(uint32).max) + 1);
        bytes memory payload = _controlPayloadWithThrottles(throttles);
        vm.expectRevert(ClprTypes.ClprBundleVerificationFailed.selector);
        harness.decodeControlMessage(payload);
    }

    function test_decodeControlMessage_unknownOneofReverts() public {
        // Build a ClprControlMessage with field 99 instead of field 1 (config_update).
        // Wire format: ClprMessagePayload.field3 (CONTROL) -> ClprControlMessage.field99
        bytes memory innerControlMsg = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(99, 2), // field 99, LEN
            ClprProtobufHelpers.encodeLengthDelimited(hex"01") // 1-byte dummy body
        );
        bytes memory controlPayload = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(3, 2), ClprProtobufHelpers.encodeLengthDelimited(innerControlMsg)
        );
        // Call via external wrapper so vm.expectRevert can catch the revert.
        vm.expectRevert(ClprTypes.ClprBundleVerificationFailedOneOfVariant.selector);
        this._decodeControlMessageExternal(controlPayload);
    }

    // ── Timestamp nanos survive round-trip ───────────────────────────────────

    function test_timestamp_nanos_roundtrip() public pure {
        // 1700000000 seconds + 123456789 nanos
        uint64 seconds_ = 1_700_000_000;
        uint32 nanos_ = 123_456_789;
        uint96 expectedNs = uint96(seconds_) * 1_000_000_000 + uint96(nanos_);

        ClprTypes.LedgerConfiguration memory config;
        config.nanosSinceEpoch = expectedNs;
        bytes memory encoded = ClprProtobuf.encodeControlMessage(config);
        ClprTypes.DecodedControl memory decoded = ClprProtobuf.decodeControlMessage(encoded);
        assertEq(decoded.config.nanosSinceEpoch, expectedNs);
    }

    function test_timestamp_zeronanos_roundtrip() public pure {
        uint96 ns = uint96(1_700_000_000) * 1_000_000_000; // exact seconds, zero nanos
        ClprTypes.LedgerConfiguration memory config;
        config.nanosSinceEpoch = ns;
        bytes memory encoded = ClprProtobuf.encodeControlMessage(config);
        ClprTypes.DecodedControl memory decoded = ClprProtobuf.decodeControlMessage(encoded);
        assertEq(decoded.config.nanosSinceEpoch, ns);
    }

    // NOTE: test_endpoint_nested_serviceEndpoint_roundtrip removed — endpoints are no longer carried in
    // LedgerConfiguration. ClprEndpointManifest encode/decode round-trip is
    // covered by the manifest test suite.

    // ── Throttle fields wider than uint32 survive round-trip ─────────────────

    function test_throttles_wideValues_roundtrip() public pure {
        // The uint64 throttle fields carry values that exceed uint32 max
        // (4,294,967,295). maxMessagesPerBundle/maxQueueDepth are uint32
        // (endpoint-manifest spec) and carry their type maximum.
        uint64 bigVal = uint64(type(uint32).max) + 1; // 4,294,967,296
        uint32 u32Max = type(uint32).max;
        ClprTypes.LedgerConfiguration memory config;
        config.throttles = ClprTypes.Throttles({
            maxMessagesPerBundle: u32Max,
            maxMessagePayloadBytes: bigVal,
            maxGasPerMessage: bigVal,
            maxQueueDepth: u32Max,
            maxSyncBytes: bigVal,
            maxLocalEndpoints: 0,
            maxPeerEndpoints: 0
        });
        bytes memory encoded = ClprProtobuf.encodeControlMessage(config);
        ClprTypes.DecodedControl memory decoded = ClprProtobuf.decodeControlMessage(encoded);
        assertEq(decoded.config.throttles.maxMessagesPerBundle, u32Max);
        assertEq(decoded.config.throttles.maxMessagePayloadBytes, bigVal);
        assertEq(decoded.config.throttles.maxGasPerMessage, bigVal);
        assertEq(decoded.config.throttles.maxQueueDepth, u32Max);
        assertEq(decoded.config.throttles.maxSyncBytes, bigVal);
    }

    function test_decodeControlMessage_protocolVersionOverflow_reverts() public {
        bytes memory configMsg = ClprProtobufHelpers.encodeVarintField(1, uint64(type(uint32).max) + 1);
        bytes memory configUpdate = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(1, 2), ClprProtobufHelpers.encodeLengthDelimited(configMsg)
        );
        bytes memory controlMsg = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(1, 2), ClprProtobufHelpers.encodeLengthDelimited(configUpdate)
        );
        bytes memory payload = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(3, 2), ClprProtobufHelpers.encodeLengthDelimited(controlMsg)
        );

        vm.expectRevert(ClprTypes.ClprBundleVerificationFailed.selector);
        harness.decodeControlMessage(payload);
    }

    function test_runningHash_deterministic() public pure {
        bytes memory payload = ClprProtobuf.encodeDataMessage(hex"AA", hex"BB", hex"CC", hex"DD");
        bytes32 hash1 = sha256(abi.encodePacked(bytes32(0), payload));
        bytes32 hash2 = sha256(abi.encodePacked(bytes32(0), payload));
        assertEq(hash1, hash2);
    }

    function test_runningHash_chain() public pure {
        bytes memory payload1 = ClprProtobuf.encodeDataMessage(hex"AA", hex"BB", hex"CC", hex"DD");
        bytes memory payload2 = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"EE");
        bytes32 hash0 = bytes32(0);
        bytes32 hash1 = sha256(abi.encodePacked(hash0, payload1));
        bytes32 hash2 = sha256(abi.encodePacked(hash1, payload2));
        assertTrue(hash1 != hash0);
        assertTrue(hash2 != hash1);
        assertTrue(hash2 != hash0);
    }

    function test_fuzz_dataMessage_roundtrip(
        bytes32 connectorId,
        bytes calldata targetApp,
        bytes calldata sender,
        bytes calldata msgData
    ) public pure {
        vm.assume(targetApp.length < 1024);
        vm.assume(sender.length < 1024);
        vm.assume(msgData.length < 1024);

        bytes memory encoded = ClprProtobuf.encodeDataMessage(connectorId, targetApp, sender, msgData);
        assertEq(uint8(ClprProtobuf.getMessageType(encoded)), uint8(ClprTypes.MessageType.DATA));
        ClprTypes.DecodedDataMessage memory decoded = ClprProtobuf.decodeDataMessage(encoded);
        assertEq(decoded.connectorId, connectorId);
        assertEq(decoded.targetApplication, targetApp);
        assertEq(decoded.sender, sender);
        assertEq(decoded.messageData, msgData);
    }

    function test_fuzz_replyMessage_roundtrip(uint64 messageId, uint8 statusRaw, bytes calldata replyData) public pure {
        vm.assume(statusRaw <= uint8(type(ClprTypes.ReplyStatus).max));
        vm.assume(replyData.length < 1024);
        ClprTypes.ReplyStatus status = ClprTypes.ReplyStatus(statusRaw);
        bytes memory encoded = ClprProtobuf.encodeReplyMessage(messageId, status, replyData);
        assertEq(uint8(ClprProtobuf.getMessageType(encoded)), uint8(ClprTypes.MessageType.REPLY));
        ClprTypes.DecodedReply memory decoded = ClprProtobuf.decodeReplyMessage(encoded);
        assertEq(decoded.messageId, messageId);
        assertEq(uint8(decoded.status), uint8(status));
        assertEq(decoded.messageReplyData, replyData);
    }

    function test_decodeDataMessage_unknownField_reverts() public {
        bytes32 connId = hex"AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD";
        bytes memory inner = abi.encodePacked(
            ClprProtobufHelpers.encodeBytesField(1, abi.encodePacked(connId)),
            ClprProtobufHelpers.encodeBytesField(2, hex"BB"),
            ClprProtobufHelpers.encodeBytesField(3, hex"CC"),
            ClprProtobufHelpers.encodeBytesField(4, hex"DD"),
            ClprProtobufHelpers.encodeBytesField(99, hex"EE")
        );
        bytes memory payload = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(1, 2), ClprProtobufHelpers.encodeLengthDelimited(inner)
        );

        vm.expectRevert(abi.encodeWithSelector(ClprTypes.ClprUnknownWireField.selector, 99));
        this._decodeDataExternal(payload);
    }

    function test_decodeDataMessage_connectorIdWrongLength_reverts() public {
        bytes memory inner = abi.encodePacked(
            ClprProtobufHelpers.encodeBytesField(1, hex"AABBCC"), // 3-byte connectorId (must be 32)
            ClprProtobufHelpers.encodeBytesField(2, hex"BB"),
            ClprProtobufHelpers.encodeBytesField(3, hex"CC"),
            ClprProtobufHelpers.encodeBytesField(4, hex"DD")
        );
        bytes memory payload = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(1, 2), ClprProtobufHelpers.encodeLengthDelimited(inner)
        );

        vm.expectRevert(ClprTypes.ClprBundleVerificationFailed.selector);
        this._decodeDataExternal(payload);
    }

    function _decodeDataExternal(bytes memory payload) external pure {
        ClprProtobuf.decodeDataMessage(payload);
    }

    function test_decodeReplyMessage_unknownField_reverts() public {
        bytes memory inner = abi.encodePacked(
            ClprProtobufHelpers.encodeVarintField(1, 7),
            ClprProtobufHelpers.encodeVarintField(2, uint64(uint8(ClprTypes.ReplyStatus.SUCCESS))),
            ClprProtobufHelpers.encodeBytesField(3, hex"A1B2"),
            // Unknown field 77 — length-delimited one byte
            ClprProtobufHelpers.encodeBytesField(77, hex"FF")
        );
        bytes memory payload = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(2, 2), ClprProtobufHelpers.encodeLengthDelimited(inner)
        );

        vm.expectRevert(abi.encodeWithSelector(ClprTypes.ClprUnknownWireField.selector, 77));
        this._decodeReplyExternal(payload);
    }

    function test_decodeControlMessage_unknownConfigField_reverts() public {
        bytes memory configMsg = ClprProtobufHelpers.encodeBytesField(99, hex"DEAD");
        bytes memory configUpdate = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(1, 2), ClprProtobufHelpers.encodeLengthDelimited(configMsg)
        );
        bytes memory controlMsg = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(1, 2), ClprProtobufHelpers.encodeLengthDelimited(configUpdate)
        );
        bytes memory payload = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(3, 2), ClprProtobufHelpers.encodeLengthDelimited(controlMsg)
        );

        vm.expectRevert(abi.encodeWithSelector(ClprTypes.ClprUnknownWireField.selector, 99));
        this._decodeControlExternal(payload);
    }

    function test_decodeControlMessage_timestamp_unknownField_reverts() public {
        bytes memory tsMsg = abi.encodePacked(
            ClprProtobufHelpers.encodeVarintField(1, 1),
            ClprProtobufHelpers.encodeVarintField(2, 2),
            ClprProtobufHelpers.encodeBytesField(99, hex"01")
        );
        bytes memory throttles = hex"";
        bytes memory configMsg = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(4, 2),
            ClprProtobufHelpers.encodeLengthDelimited(tsMsg),
            ClprProtobufHelpers.encodeFieldKey(5, 2),
            ClprProtobufHelpers.encodeLengthDelimited(throttles)
        );
        bytes memory configUpdate = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(1, 2), ClprProtobufHelpers.encodeLengthDelimited(configMsg)
        );
        bytes memory controlMsg = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(1, 2), ClprProtobufHelpers.encodeLengthDelimited(configUpdate)
        );
        bytes memory payload = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(3, 2), ClprProtobufHelpers.encodeLengthDelimited(controlMsg)
        );

        vm.expectRevert(abi.encodeWithSelector(ClprTypes.ClprUnknownWireField.selector, 99));
        this._decodeControlExternal(payload);
    }

    function _getMessageTypeExternal(bytes memory payload) external pure returns (uint8) {
        return uint8(ClprProtobuf.getMessageType(payload));
    }

    function _decodeReplyExternal(bytes memory payload) external pure {
        ClprProtobuf.decodeReplyMessage(payload);
    }

    function _decodeControlExternal(bytes memory payload) external pure {
        ClprProtobuf.decodeControlMessage(payload);
    }

    function test_getMessageType_revert_emptyPayload() public {
        vm.expectRevert(ClprTypes.ClprBundleVerificationFailedEmptyPayload.selector);
        this._getMessageTypeExternal("");
    }

    function test_getMessageType_revert_unknownOuterField() public {
        // Outer field 99 (LEN) is not one of 1/2/3/4.
        bytes memory payload = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(99, 2), ClprProtobufHelpers.encodeLengthDelimited(hex"00")
        );
        vm.expectRevert(abi.encodeWithSelector(ClprTypes.ClprUnknownWireField.selector, 99));
        this._getMessageTypeExternal(payload);
    }

    function test_decodeReplyMessage_revert_statusOutOfRange() public {
        bytes memory inner = abi.encodePacked(
            ClprProtobufHelpers.encodeVarintField(1, 1), // messageId
            ClprProtobufHelpers.encodeVarintField(2, 300), // invalid status
            ClprProtobufHelpers.encodeBytesField(3, hex"")
        );
        bytes memory payload = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(2, 2), ClprProtobufHelpers.encodeLengthDelimited(inner)
        );
        vm.expectRevert(ClprTypes.ClprBundleVerificationFailed.selector);
        this._decodeReplyExternal(payload);
    }

    function test_decodeControl_throttles_unknownField_reverts() public {
        bytes memory tMsg = abi.encodePacked(
            ClprProtobufHelpers.encodeVarintField(1, 123), ClprProtobufHelpers.encodeBytesField(99, hex"AB")
        );
        bytes memory configMsg =
            abi.encodePacked(ClprProtobufHelpers.encodeFieldKey(5, 2), ClprProtobufHelpers.encodeLengthDelimited(tMsg));
        bytes memory configUpdate = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(1, 2), ClprProtobufHelpers.encodeLengthDelimited(configMsg)
        );
        bytes memory controlMsg = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(1, 2), ClprProtobufHelpers.encodeLengthDelimited(configUpdate)
        );
        bytes memory payload = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(3, 2), ClprProtobufHelpers.encodeLengthDelimited(controlMsg)
        );

        vm.expectRevert(abi.encodeWithSelector(ClprTypes.ClprUnknownWireField.selector, 99));
        this._decodeControlExternal(payload);
    }

    // NOTE: test_decodeControl_endpoint_revert_portOverflow removed — endpoints (field 6) are no longer
    // part of LedgerConfiguration, so the config decoder rejects them and never reaches the nested
    // ServiceEndpoint port. Port-overflow rejection is covered where ClprEndpointManifest is decoded.

    function _decodeBundleContentExternal(bytes calldata payload)
        external
        pure
        returns (ClprTypes.QueueMetadata memory meta, bytes[] memory messagePayloads)
    {
        return ClprProtobuf.decodeBundleContent(payload);
    }

    function test_decodeBundleContent_unknownTopLevelField_reverts() public {
        bytes memory metadata =
            abi.encodePacked(ClprProtobufHelpers.encodeVarintField(5, uint64(uint8(ClprTypes.ChannelStatus.ACTIVE))));

        bytes memory payload = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(1, 2),
            ClprProtobufHelpers.encodeLengthDelimited(metadata),
            ClprProtobufHelpers.encodeFieldKey(99, 2),
            ClprProtobufHelpers.encodeLengthDelimited(hex"DEADBEEF")
        );

        vm.expectRevert(abi.encodeWithSelector(ClprTypes.ClprUnknownWireField.selector, 99));
        this._decodeBundleContentExternal(payload);
    }

    // ── decodeChannelFromMemory ────────────────────────────────────────────

    /// @dev Field 7 (status=1 ACTIVE) + field 8 (nextMessageId=5) + field 9 (ackedMessageId=3).
    function test_decodeChannelFromMemory_varintFields() public view {
        // field 7 = status (varint): 1 (assuming 1=ACTIVE or similar valid value)
        // field 8 = nextMessageId: 5
        // field 9 = ackedMessageId: 3
        // field 11 = receivedMessageId: 2
        bytes memory encoded = abi.encodePacked(
            ClprProtobufHelpers.encodeVarintField(7, 0), // status=0 (first valid enum value)
            ClprProtobufHelpers.encodeVarintField(8, 5), // nextMessageId=5
            ClprProtobufHelpers.encodeVarintField(9, 3), // ackedMessageId=3 (covers line 526)
            ClprProtobufHelpers.encodeVarintField(11, 2) // receivedMessageId=2
        );
        ClprTypes.Channel memory channel = harness.decodeChannelFromMemory(encoded);
        assertEq(channel.nextMessageId, 5);
        assertEq(channel.ackedMessageId, 3, "ackedMessageId field 9 must be decoded");
        assertEq(channel.receivedMessageId, 2);
    }

    /// @dev Field 10 (sentRunningHash, 32 bytes) and field 12 (receivedRunningHash, 32 bytes).
    function test_decodeChannelFromMemory_hashFields() public view {
        bytes32 sent = keccak256("sent");
        bytes32 recv = keccak256("recv");
        bytes memory encoded = abi.encodePacked(
            ClprProtobufHelpers.encodeBytesField(10, abi.encodePacked(sent)),
            ClprProtobufHelpers.encodeBytesField(12, abi.encodePacked(recv))
        );
        ClprTypes.Channel memory channel = harness.decodeChannelFromMemory(encoded);
        assertEq(channel.sentRunningHash, sent);
        assertEq(channel.receivedRunningHash, recv);
    }

    /// @dev Field 3 (service_address, bytes) → channel.peerServiceAddress. This is the proven
    ///      peer ClprService address.
    function test_decodeChannelFromMemory_serviceAddress() public view {
        bytes memory serviceAddress = hex"00112233445566778899aabbccddeeff00112233";
        bytes memory encoded = abi.encodePacked(
            ClprProtobufHelpers.encodeBytesField(3, serviceAddress), // field 3 = service_address
            ClprProtobufHelpers.encodeVarintField(8, 9) // nextMessageId=9 (decode must continue past field 3)
        );
        ClprTypes.Channel memory channel = harness.decodeChannelFromMemory(encoded);
        assertEq(channel.peerServiceAddress, serviceAddress, "field 3 must populate peerServiceAddress");
        assertEq(channel.nextMessageId, 9, "decode must continue past service_address");
    }

    function test_decodeChannelFromMemory_channelId() public view {
        bytes32 cid = 0x1122334455667788990011223344556677889900112233445566778899001122;
        bytes memory encoded = abi.encodePacked(
            ClprProtobufHelpers.encodeBytesField(1, abi.encodePacked(cid)), // field 1 = channel_id
            ClprProtobufHelpers.encodeVarintField(8, 4) // decode must continue past field 1
        );
        ClprTypes.Channel memory channel = harness.decodeChannelFromMemory(encoded);
        assertEq(channel.channelId, cid, "field 1 must populate channelId");
        assertEq(channel.nextMessageId, 4, "decode must continue past channel_id");
    }

    function test_decodeChannelFromMemory_channelId_wrongLength_staysZero() public view {
        bytes memory encoded = abi.encodePacked(
            ClprProtobufHelpers.encodeBytesField(1, hex"aabbcc"), // 3-byte channel_id
            ClprProtobufHelpers.encodeVarintField(8, 4)
        );
        ClprTypes.Channel memory channel = harness.decodeChannelFromMemory(encoded);
        assertEq(channel.channelId, bytes32(0), "non-32-byte channel_id must leave channelId zero");
        assertEq(channel.nextMessageId, 4, "decode must continue past channel_id");
    }

    /// @dev service_address absent → channel.peerServiceAddress defaults to empty.
    function test_decodeChannelFromMemory_serviceAddress_absent_isEmpty() public view {
        bytes memory encoded = ClprProtobufHelpers.encodeVarintField(8, 1); // only nextMessageId
        ClprTypes.Channel memory channel = harness.decodeChannelFromMemory(encoded);
        assertEq(channel.peerServiceAddress.length, 0, "absent service_address must stay empty");
    }

    /// @dev Field 7 with value > ChannelStatus.max → reverts ClprBundleVerificationFailed.
    function test_decodeChannelFromMemory_invalidStatus_reverts() public {
        // Encode status=255 which exceeds any valid ChannelStatus enum value
        bytes memory encoded = ClprProtobufHelpers.encodeVarintField(7, 255);
        vm.expectRevert(ClprTypes.ClprBundleVerificationFailed.selector);
        harness.decodeChannelFromMemory(encoded);
    }

    /// @dev wireType=1 (fixed64) in channel → hits line 547 else-branch → skipField reverts.
    function test_decodeChannelFromMemory_skipUnsupportedWireType_reverts() public {
        // wireType=1 (fixed64) for KNOWN field 6 (verifier_fingerprint) → skipField fires
        // "Unsupported wire type" (field numbers outside 1-15 revert ClprUnknownWireField first).
        bytes memory encoded = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(6, 1), // known field, wireType=1 (fixed64)
            bytes8(0) // 8 bytes of fixed64 data
        );
        vm.expectRevert(bytes("Unsupported wire type"));
        harness.decodeChannelFromMemory(encoded);
    }

    /// @dev Field 20 (`endpoint_manifest_version`) is the highest number ClprChannel defines, so
    ///      field 21 is the first that must reject.
    function test_decodeChannelFromMemory_unknownField_reverts() public {
        bytes memory encoded = abi.encodePacked(
            ClprProtobufHelpers.encodeBytesField(21, hex"aabb"), ClprProtobufHelpers.encodeVarintField(8, 7)
        );
        vm.expectRevert(abi.encodeWithSelector(ClprTypes.ClprUnknownWireField.selector, 21));
        harness.decodeChannelFromMemory(encoded);
    }

    /// @dev Field 19 (`endpoint_manifest`, a sub-message) is length-delimited and skipped; field 20
    ///      carries `endpoint_manifest_version` — the newest ClprChannel varint field, and the one
    ///      the manifest-staleness check in BundleLib compares against.
    function test_decodeChannelFromMemory_endpointManifestVersion_decoded() public view {
        bytes memory encoded = abi.encodePacked(
            ClprProtobufHelpers.encodeVarintField(8, 7), // nextMessageId
            ClprProtobufHelpers.encodeBytesField(19, hex"0a01"), // endpoint_manifest sub-msg — skipped
            ClprProtobufHelpers.encodeVarintField(20, 12) // endpointManifestVersion
        );
        ClprTypes.Channel memory channel = harness.decodeChannelFromMemory(encoded);
        assertEq(channel.nextMessageId, 7);
        assertEq(channel.endpointManifestVersion, 12, "ClprChannel proto field 20");
    }

    /// @dev Length-delimited field (wireType=2) that the decoder does not surface (not 1/3/10/12)
    ///      → skipped. Field 2 (`chain_id`) is such a field.
    function test_decodeChannelFromMemory_skipUnknownLenField() public view {
        bytes memory encoded = abi.encodePacked(
            ClprProtobufHelpers.encodeBytesField(2, hex"aabbcc"), // field 2 = chain_id → skipped
            ClprProtobufHelpers.encodeVarintField(8, 7)
        );
        ClprTypes.Channel memory channel = harness.decodeChannelFromMemory(encoded);
        assertEq(channel.nextMessageId, 7);
    }

    // ── decodeControlMessage — trust anchor fields ────────────────────────────

    /// @dev Encode a control message with trustAnchor (field 7) and trustAnchorId (field 8).
    ///      These are decoded by decodeControlMessage but not reached in existing tests.
    function test_decodeControlMessage_trustAnchorFields() public view {
        // Build a minimal LedgerConfiguration with trustAnchor and trustAnchorId set
        ClprTypes.LedgerConfiguration memory cfg;
        cfg.protocolVersion = 1;
        cfg.chainId = "test-chain";
        cfg.serviceAddress = hex"";
        cfg.nanosSinceEpoch = 0;
        cfg.throttles = ClprTypes.Throttles({
            maxMessagesPerBundle: 10,
            maxMessagePayloadBytes: 1000,
            maxGasPerMessage: 100000,
            maxQueueDepth: 100,
            maxSyncBytes: 1000,
            maxLocalEndpoints: 0,
            maxPeerEndpoints: 0
        });
        cfg.trustAnchor = hex"aabbccddeeff"; // non-empty trust anchor (covers field 7)
        cfg.trustAnchorId = hex"11223344"; // non-empty trust anchor ID (covers field 8)

        bytes memory encoded = ClprProtobuf.encodeControlMessage(cfg);
        ClprTypes.DecodedControl memory decoded = harness.decodeControlMessage(encoded);

        assertEq(decoded.config.trustAnchor.length, cfg.trustAnchor.length, "trustAnchor must be decoded");
        assertEq(decoded.config.trustAnchorId.length, cfg.trustAnchorId.length, "trustAnchorId must be decoded");
        assertEq(keccak256(decoded.config.trustAnchor), keccak256(cfg.trustAnchor));
        assertEq(keccak256(decoded.config.trustAnchorId), keccak256(cfg.trustAnchorId));
    }

    /// @dev Field 6 (the removed `seed_endpoints`) is rejected like any other unknown field.
    function test_decodeControlMessage_removedSeedEndpointsField_reverts() public {
        bytes memory throttlesMsg = abi.encodePacked(
            ClprProtobufHelpers.encodeVarintField(1, 10), // maxMessagesPerBundle
            ClprProtobufHelpers.encodeVarintField(2, 1000), // maxMessagePayloadBytes
            ClprProtobufHelpers.encodeVarintField(3, 100000), // maxGasPerMessage
            ClprProtobufHelpers.encodeVarintField(4, 100), // maxQueueDepth
            ClprProtobufHelpers.encodeVarintField(5, 1000) // maxSyncBytes
        );
        bytes memory configMsg = abi.encodePacked(
            ClprProtobufHelpers.encodeVarintField(1, 1), // protocolVersion = 1
            ClprProtobufHelpers.encodeBytesField(2, bytes("chain")), // chainId
            ClprProtobufHelpers.encodeFieldKey(5, 2),
            ClprProtobufHelpers.encodeLengthDelimited(throttlesMsg), // throttles
            ClprProtobufHelpers.encodeBytesField(6, hex"AABB") // removed seed_endpoints → must reject
        );

        vm.expectRevert(abi.encodeWithSelector(ClprTypes.ClprUnknownWireField.selector, 6));
        harness.decodeControlMessage(_wrapConfigAsControlPayload(configMsg));
    }

    /// @dev Endpoints now reach `_decodeEndpoint` through the endpoint manifest. An unknown field in
    ///      the endpoint body rejects the whole bundle rather than being skipped.
    function test_manifest_endpointBody_unknownField_reverts() public {
        bytes memory serviceEp = ClprProtobufHelpers.encodeVarintField(2, 8080);
        bytes memory epBody = abi.encodePacked(
            ClprProtobufHelpers.encodeBytesField(1, serviceEp), // field 1 = ServiceEndpoint
            ClprProtobufHelpers.encodeVarintField(99, 42), // UNKNOWN field → must reject
            ClprProtobufHelpers.encodeBytesField(3, new bytes(64)) // field 3 = account_id
        );

        vm.expectRevert(abi.encodeWithSelector(ClprTypes.ClprUnknownWireField.selector, 99));
        harness.decodeEndpointManifest(_wrapEndpointBodyAsManifest(epBody));
    }

    /// @dev Same strictness one level deeper: an unknown field inside the nested ServiceEndpoint.
    function test_manifest_serviceEndpoint_unknownSubField_reverts() public {
        bytes memory serviceEp = abi.encodePacked(
            ClprProtobufHelpers.encodeBytesField(1, bytes("10.0.0.1")),
            ClprProtobufHelpers.encodeVarintField(2, 8080),
            ClprProtobufHelpers.encodeVarintField(77, 1) // UNKNOWN sub-field → must reject
        );
        bytes memory epBody = abi.encodePacked(
            ClprProtobufHelpers.encodeBytesField(1, serviceEp),
            ClprProtobufHelpers.encodeBytesField(3, new bytes(64)) // field 3 = account_id
        );

        vm.expectRevert(abi.encodeWithSelector(ClprTypes.ClprUnknownWireField.selector, 77));
        harness.decodeEndpointManifest(_wrapEndpointBodyAsManifest(epBody));
    }

    /// @dev Wrap a `LedgerConfiguration` body in the ClprConfigUpdate → ClprControlMessage →
    ///      ClprMessagePayload envelope `decodeControlMessage` expects.
    function _wrapConfigAsControlPayload(bytes memory configMsg) private pure returns (bytes memory) {
        bytes memory configUpdate = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(1, 2), ClprProtobufHelpers.encodeLengthDelimited(configMsg)
        );
        bytes memory controlMsgBytes = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(1, 2), ClprProtobufHelpers.encodeLengthDelimited(configUpdate)
        );
        return abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(3, 2), ClprProtobufHelpers.encodeLengthDelimited(controlMsgBytes)
        );
    }

    /// @dev Wrap a single ClprEndpoint body as manifest field 3 (repeated endpoints).
    function _wrapEndpointBodyAsManifest(bytes memory epBody) private pure returns (bytes memory) {
        return
            abi.encodePacked(
                ClprProtobufHelpers.encodeFieldKey(3, 2), ClprProtobufHelpers.encodeLengthDelimited(epBody)
            );
    }

    function test_decodeReplyMessage_revert_wrongWireType() public {
        // wire type 0 (varint) instead of 2 (length-delimited)
        bytes memory payload = abi.encodePacked(ClprProtobufHelpers.encodeFieldKey(2, 0), hex"00");
        vm.expectRevert(ClprTypes.ClprBundleVerificationFailed.selector);
        this._decodeReplyExternal(payload);
    }

    function test_throttles_maxMessagesPerBundle_overflow_reverts() public {
        _assertThrottleFieldOverflowReverts(1);
    }

    function test_throttles_maxQueueDepth_overflow_reverts() public {
        _assertThrottleFieldOverflowReverts(4);
    }

    function test_throttles_maxLocalEndpoints_overflow_reverts() public {
        _assertThrottleFieldOverflowReverts(6);
    }

    function test_throttles_maxPeerEndpoints_overflow_reverts() public {
        _assertThrottleFieldOverflowReverts(7);
    }

    /// @dev A throttles message carrying only an unknown field walks the entire else-if chain
    ///      (the false side of every known-field comparison) into skipField.
    /// @dev Throttles carry no forward-compatible padding: `ClprThrottles` is fields 1–7 on every
    ///      peer proto, so an unrecognized throttle field is a dialect mismatch and rejects.
    function test_throttles_unknownField_reverts() public {
        bytes memory throttles = ClprProtobufHelpers.encodeVarintField(9, 123);
        vm.expectRevert(abi.encodeWithSelector(ClprTypes.ClprUnknownWireField.selector, 9));
        harness.decodeControlMessage(_controlPayloadWithThrottles(throttles));
    }

    // ── decodeEndpointManifest: unknown fields and wire-type mismatches ─────────

    /// @dev Field 3 with a non-LEN wire type must be skipped (both in the counting pass and the
    ///      decode pass), and unknown field numbers fall through to skipField.
    function test_manifest_field3WrongWireType_andUnknownField_skipped() public view {
        bytes memory wire = abi.encodePacked(
            ClprProtobufHelpers.encodeVarintField(9, 7), // unknown field → skip
            ClprProtobufHelpers.encodeVarintField(3, 1) // field 3 but wire type 0 → not an endpoint
        );
        ClprTypes.ClprEndpointManifest memory m = harness.decodeEndpointManifest(wire);
        assertEq(m.endpoints.length, 0, "varint field 3 must not count as an endpoint");
        assertEq(m.version, 0, "version untouched");
    }

    /// @dev A fully-populated endpoint body decodes; omitting the optional ip inside ServiceEndpoint
    ///      leaves it empty rather than reverting (every field of ClprEndpoint is proto3-optional).
    function test_manifest_endpointBody_allKnownFields_decoded() public view {
        bytes memory svcEp = ClprProtobufHelpers.encodeVarintField(2, 50211); // port only — no ip
        bytes memory epBody = abi.encodePacked(
            ClprProtobufHelpers.encodeBytesField(1, svcEp),
            ClprProtobufHelpers.encodeBytesField(2, hex"AA"), // tlsCertificate
            ClprProtobufHelpers.encodeBytesField(3, hex"BB") // accountId
        );
        bytes memory wire = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(3, 2), ClprProtobufHelpers.encodeLengthDelimited(epBody)
        );

        ClprTypes.ClprEndpointManifest memory m = harness.decodeEndpointManifest(wire);
        assertEq(m.endpoints.length, 1);
        assertEq(m.endpoints[0].port, 50211);
        assertEq(m.endpoints[0].tlsCertificate, hex"AA");
        assertEq(m.endpoints[0].accountId, hex"BB");
        assertEq(bytes(m.endpoints[0].ipAddress).length, 0, "ip never supplied");
    }

    /// @dev Ports are 16-bit; a peer-supplied larger varint must revert, not truncate.
    function test_manifest_endpointPortOverflow_reverts() public {
        bytes memory svcEp = ClprProtobufHelpers.encodeVarintField(2, 70000);
        bytes memory epBody = ClprProtobufHelpers.encodeBytesField(1, svcEp);
        bytes memory wire = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(3, 2), ClprProtobufHelpers.encodeLengthDelimited(epBody)
        );
        vm.expectRevert(ClprTypes.ClprBundleVerificationFailed.selector);
        harness.decodeEndpointManifest(wire);
    }

    // ── decodeBundleContent: metadata field 7 + unknown-field skip ──────────────

    function test_bundleContent_manifestVersion_decoded() public view {
        bytes memory metaBytes = abi.encodePacked(
            ClprProtobufHelpers.encodeVarintField(1, 5), // nextMessageId
            ClprProtobufHelpers.encodeVarintField(7, 42) // endpointManifestVersion
        );
        bytes memory wire = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(1, 2),
            ClprProtobufHelpers.encodeLengthDelimited(metaBytes),
            ClprProtobufHelpers.encodeFieldKey(2, 2),
            ClprProtobufHelpers.encodeLengthDelimited(hex"AABB")
        );
        (ClprTypes.QueueMetadata memory meta, bytes[] memory payloads) = harness.decodeBundleContent(wire);
        assertEq(meta.nextMessageId, 5);
        assertEq(meta.endpointManifestVersion, 42, "QueueMetadata proto field 7");
        assertEq(payloads.length, 1);
        assertEq(payloads[0], hex"AABB");
    }

    // ── tryGetMessageType: empty payload ────────────────────────────────────────

    function test_tryGetMessageType_emptyPayload_unknown() public pure {
        (bool known, ClprTypes.MessageType t) = ClprProtobuf.tryGetMessageType("");
        assertFalse(known, "empty payload is not a recognized message");
        assertEq(uint8(t), uint8(ClprTypes.MessageType.DATA));
    }
}
