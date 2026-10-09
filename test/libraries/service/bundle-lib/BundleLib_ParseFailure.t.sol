// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprService} from "@hiero-ledger/clpr/ClprService.sol";
import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprProtobufHelpers} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {BundleLib} from "@hiero-ledger/clpr/libraries/service/BundleLib.sol";
import {MockClprVerifier} from "@test/mocks/MockClprVerifier.sol";
import {MockClprApplication} from "@test/mocks/MockClprApplication.sol";
import {MockClprConnector} from "@test/mocks/MockClprConnector.sol";
import {MockBundleDecodeHelper} from "@test/mocks/MockBundleDecodeHelper.sol";
import {ConnectorRegistrar} from "@test/helpers/ConnectorRegistrar.sol";
import {ClprDeployHelper} from "@test/helpers/ClprDeployHelper.sol";
import {BundleLibTestBase} from "@test/libraries/service/bundle-lib/BundleLibTestBase.sol";
import {ClprTestBase} from "@test/helpers/ClprTestBase.sol";

contract BundleLib_ParseFailureTest is BundleLibTestBase {
    function _decodeStringError(bytes memory encodedError) internal pure returns (string memory) {
        // Skip the 4-byte selector and decode the remaining ABI-encoded string
        bytes memory errorDataWithoutSelector = new bytes(encodedError.length - 4);
        for (uint256 i = 0; i < errorDataWithoutSelector.length; i++) {
            errorDataWithoutSelector[i] = encodedError[i + 4];
        }
        (string memory result) = abi.decode(errorDataWithoutSelector, (string));
        return result;
    }

    function test_parseFailure_control_revertsEntireBundle() public {
        // 0x1A is a CONTROL tag (field 3, wire type 2). The body byte 0xFF sets the continuation
        // bit with no next byte, so the inner varint is truncated. decodeControlMessage reverts
        // TruncatedInput. A CONTROL message that does not parse must reject the whole bundle.
        bytes memory malformedControl = hex"1A01FF";

        bytes[] memory msgs = new bytes[](1);
        msgs[0] = malformedControl;
        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(malformedControl)));
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

        vm.expectRevert(ClprProtobufHelpers.TruncatedInput.selector);
        service.submitBundle(channelId, hex"00FF");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE));
        assertEq(channel.receivedMessageId, 0, "inbound cursor must not advance on a rejected bundle");
        assertEq(channel.nextMessageId, 1, "no reply queued on a rejected bundle");
    }

    function test_parseFailure_control_unknownWireField_revertsEntireBundle() public {
        // ClprMessage(3) -> ControlMessage(1) -> ConfigUpdate(1) -> LedgerConfiguration{ field 99 }.
        bytes memory configMsg = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(99, 2), ClprProtobufHelpers.encodeLengthDelimited(hex"00")
        );
        bytes memory configUpdate = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(1, 2), ClprProtobufHelpers.encodeLengthDelimited(configMsg)
        );
        bytes memory controlMsg = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(1, 2), ClprProtobufHelpers.encodeLengthDelimited(configUpdate)
        );
        bytes memory badControl = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(3, 2), ClprProtobufHelpers.encodeLengthDelimited(controlMsg)
        );

        bytes[] memory msgs = new bytes[](1);
        msgs[0] = badControl;
        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(badControl)));
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

        vm.expectRevert(abi.encodeWithSelector(ClprTypes.ClprUnknownWireField.selector, 99));
        service.submitBundle(channelId, hex"00FF");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE));
        assertEq(channel.receivedMessageId, 0, "no inbound progress on a rejected bundle");
        assertEq(channel.nextMessageId, 1, "no reply queued on a rejected bundle");
    }

    /// @dev A DATA message carrying a field number the protocol version does not define is a
    ///      protocol violation
    function test_parseFailure_data_unknownField_revertsEntireBundle() public {
        _registerTestConnector();

        // Well-formed DataMessage body (fields 1-4) plus an unknown field 99.
        bytes memory inner = abi.encodePacked(
            ClprProtobufHelpers.encodeBytesField(1, abi.encodePacked(connectorId)),
            ClprProtobufHelpers.encodeBytesField(2, abi.encodePacked(address(app))),
            ClprProtobufHelpers.encodeBytesField(3, hex"AA01BB02"),
            ClprProtobufHelpers.encodeBytesField(4, hex"FFEEDD"),
            ClprProtobufHelpers.encodeBytesField(99, hex"EE")
        );
        bytes memory badData = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(1, 2), ClprProtobufHelpers.encodeLengthDelimited(inner)
        );

        bytes[] memory msgs = new bytes[](1);
        msgs[0] = badData;
        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(badData)));
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

        vm.expectRevert(abi.encodeWithSelector(ClprTypes.ClprUnknownWireField.selector, 99));
        _submitBundle(hex"00FF");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE));
        assertEq(channel.receivedMessageId, 0, "no inbound progress on a rejected bundle");
        assertEq(channel.nextMessageId, 1, "no APPLICATION_ERROR reply for a protocol violation");
        assertEq(app.getMessageCallCount(), 0, "app must not observe the rejected DATA message");
    }

    function test_parseFailure_data_emitsEvent_enqueuesToApplicationError_channelStaysActive() public {
        // 0x08 = (field_number=1 << 3) | wire_type=0 → passes getMessageType as DATA,
        // but decodeData() requires wire_type=2 (length-delimited), so it fails.
        bytes memory malformedData = hex"0800";

        bytes[] memory msgs = new bytes[](1);
        msgs[0] = malformedData;
        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(malformedData)));
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

        vm.expectEmit(true, true, false, true, address(service));
        emit BundleLib.BundleParseFailed(channelId, 1);

        service.submitBundle(channelId, hex"00FF");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE), "ACTIVE after DATA decode failure");

        // APPLICATION_ERROR reply must be queued so the peer gets a response.
        assertEq(channel.nextMessageId, 2, "APPLICATION_ERROR reply queued");
        ClprTypes.MessageValue memory reply = service.getMessage(channelId, 1);
        ClprTypes.DecodedReply memory dr = ClprProtobuf.decodeReplyMessage(reply.payload);
        assertEq(dr.messageId, 1);
        assertEq(uint8(dr.status), uint8(ClprTypes.ReplyStatus.APPLICATION_ERROR));
    }

    // dispatch continues past decode failures
    // DATA: [good][fail][fail][good] — both failures get APPLICATION_ERROR replies,
    // the surrounding successes are unaffected, channel stays ACTIVE.
    function test_parseFailure_data_middle2of4_continuesDispatch() public {
        _registerTestConnector();

        bytes memory good =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");
        // 0x08 = DATA tag with varint wire type — passes getMessageType, fails decodeData.
        bytes memory bad = hex"0800";

        bytes[] memory msgs = new bytes[](4);
        msgs[0] = good; // inbound msg 1 — succeeds
        msgs[1] = bad; // inbound msg 2 — decode failure
        msgs[2] = bad; // inbound msg 3 — decode failure
        msgs[3] = good; // inbound msg 4 — succeeds

        bytes32 h = bytes32(0);
        for (uint256 i = 0; i < 4; i++) {
            h = sha256(abi.encodePacked(h, sha256(msgs[i])));
        }

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 5,
            sentRunningHash: h,
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 4,
            lastMessageRunningHash: h
        });
        verifier.setVerifyBundleResult(meta, msgs);

        vm.expectEmit(true, true, false, true, address(service));
        emit BundleLib.BundleParseFailed(channelId, 2);
        vm.expectEmit(true, true, false, true, address(service));
        emit BundleLib.BundleParseFailed(channelId, 3);

        _submitBundle(hex"00FF");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE), "channel must stay ACTIVE");
        assertEq(channel.receivedMessageId, 4, "all 4 inbound messages marked received");
        assertEq(channel.nextMessageId, 5, "4 outbound replies queued (2 SUCCESS + 2 APPLICATION_ERROR)");

        // Msg 1 → SUCCESS
        ClprTypes.DecodedReply memory r1 = ClprProtobuf.decodeReplyMessage(service.getMessage(channelId, 1).payload);
        assertEq(r1.messageId, 1);
        assertEq(uint8(r1.status), uint8(ClprTypes.ReplyStatus.SUCCESS));

        // Msg 2 → APPLICATION_ERROR (decode failure, no penalty)
        ClprTypes.DecodedReply memory r2 = ClprProtobuf.decodeReplyMessage(service.getMessage(channelId, 2).payload);
        assertEq(r2.messageId, 2);
        assertEq(uint8(r2.status), uint8(ClprTypes.ReplyStatus.APPLICATION_ERROR));

        // Msg 3 → APPLICATION_ERROR
        ClprTypes.DecodedReply memory r3 = ClprProtobuf.decodeReplyMessage(service.getMessage(channelId, 3).payload);
        assertEq(r3.messageId, 3);
        assertEq(uint8(r3.status), uint8(ClprTypes.ReplyStatus.APPLICATION_ERROR));

        // Msg 4 → SUCCESS
        ClprTypes.DecodedReply memory r4 = ClprProtobuf.decodeReplyMessage(service.getMessage(channelId, 4).payload);
        assertEq(r4.messageId, 4);
        assertEq(uint8(r4.status), uint8(ClprTypes.ReplyStatus.SUCCESS));

        // Application was invoked only for msgs 1 and 4.
        assertEq(app.getMessageCallCount(), 2);
    }

    // CONTROL: [DATA-good][CTRL-fail][CTRL-fail][DATA-good] — an unknown CONTROL oneof
    // variant anywhere in the bundle must reject the whole thing atomically, even though
    // DATA msg 1 dispatched (and would have queued a SUCCESS reply) before the bad CONTROL
    // was reached.
    function test_parseFailure_control_middle2of4_revertsEntireBundle() public {
        _registerTestConnector();

        bytes memory goodData =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"CCDDEE");
        // 0x1A = CONTROL tag (field 3, wire_type 2), length=1, one garbage byte — see
        // test_parseFailure_control_revertsEntireBundle for why this trips the oneof guard.
        bytes memory badCtrl = hex"1A01FF";

        bytes[] memory msgs = new bytes[](4);
        msgs[0] = goodData; // inbound msg 1 — DATA, would succeed
        msgs[1] = badCtrl; // inbound msg 2 — CONTROL, truncated (malformed)
        msgs[2] = badCtrl; // inbound msg 3 — CONTROL, truncated (malformed)
        msgs[3] = goodData; // inbound msg 4 — DATA, would succeed

        bytes32 h = bytes32(0);
        for (uint256 i = 0; i < 4; i++) {
            h = sha256(abi.encodePacked(h, sha256(msgs[i])));
        }

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 5,
            sentRunningHash: h,
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 4,
            lastMessageRunningHash: h
        });
        verifier.setVerifyBundleResult(meta, msgs);

        uint96 timestampBefore = service.getChannel(channelId).peerConfigTimestamp;

        vm.expectRevert(ClprProtobufHelpers.TruncatedInput.selector);
        _submitBundle(hex"00FF");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE));
        // Atomic rejection: DATA msg 1, which ran before the bad CONTROL was reached, must
        // not have taken effect either.
        assertEq(channel.receivedMessageId, 0, "no inbound progress on a rejected bundle");
        assertEq(channel.nextMessageId, 1, "no replies queued on a rejected bundle");
        assertEq(
            channel.peerConfigTimestamp, timestampBefore, "peerConfigTimestamp must not change on a rejected bundle"
        );
        assertEq(app.getMessageCallCount(), 0, "app must not observe a rejected bundle's DATA messages");
    }

    // Mixed: [CTRL-good][DATA-fail][CTRL-fail][DATA-good] — an unknown CONTROL oneof variant
    // (msg 3) must reject the whole bundle atomically, even though the earlier good CONTROL
    // (msg 1) and the recoverable DATA decode failure (msg 2) would otherwise have taken
    // effect on their own.
    function test_parseFailure_mixed_types_middle2of4_revertsEntireBundle() public {
        _registerTestConnector();

        uint64 newTimestamp = 5_000_000;
        bytes memory goodCtrl = ClprProtobuf.encodeControlMessage(_makeConfig(newTimestamp));
        bytes memory badData = hex"0800";
        bytes memory badCtrl = hex"1A01FF";
        bytes memory goodData =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"FFEEDD");

        bytes[] memory msgs = new bytes[](4);
        msgs[0] = goodCtrl; // inbound msg 1 — CONTROL, would succeed
        msgs[1] = badData; // inbound msg 2 — DATA, would recover as APPLICATION_ERROR
        msgs[2] = badCtrl; // inbound msg 3 — CONTROL, truncated (malformed)
        msgs[3] = goodData; // inbound msg 4 — DATA, would succeed

        bytes32 h = bytes32(0);
        for (uint256 i = 0; i < 4; i++) {
            h = sha256(abi.encodePacked(h, sha256(msgs[i])));
        }

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 5,
            sentRunningHash: h,
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 4,
            lastMessageRunningHash: h
        });
        verifier.setVerifyBundleResult(meta, msgs);

        uint96 timestampBefore = service.getChannel(channelId).peerConfigTimestamp;

        vm.expectRevert(ClprProtobufHelpers.TruncatedInput.selector);
        _submitBundle(hex"00FF");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE));
        assertEq(channel.receivedMessageId, 0, "no inbound progress on a rejected bundle");
        assertEq(channel.nextMessageId, 1, "no replies queued on a rejected bundle");
        // The earlier successful CONTROL (msg 1) must not have applied either.
        assertEq(channel.peerConfigTimestamp, timestampBefore, "CONTROL config must not apply on a rejected bundle");
        assertEq(app.getMessageCallCount(), 0, "app must not observe a rejected bundle's DATA messages");
    }

    /// @dev A CONTROL message that fails to decode for a reason that is NEITHER an unknown-oneof
    ///      variant NOR an unknown wire field (here: a protocolVersion that overflows uint32, which
    ///      surfaces as ClprBundleVerificationFailed) is not a whole-bundle protocol violation: it
    ///      degrades to a per-message BundleParseFailed and the bundle keeps processing. CONTROL
    ///      messages never generate a reply, so no reply is queued.
    function test_parseFailure_control_nonProtocolError_emitsEventNoRevert() public {
        // ClprControlMessage carrying a LedgerConfiguration whose protocolVersion (field 1) exceeds
        // uint32 → decodeControl reverts ClprBundleVerificationFailed on the bound check. Every field
        // number used here is known, so this is a value error, not a wire-format violation.
        bytes memory configMsg = ClprProtobufHelpers.encodeVarintField(1, uint64(type(uint32).max) + 1);
        bytes memory configUpdate = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(1, 2), ClprProtobufHelpers.encodeLengthDelimited(configMsg)
        );
        bytes memory controlMsg = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(1, 2), ClprProtobufHelpers.encodeLengthDelimited(configUpdate)
        );
        bytes memory badControl = abi.encodePacked(
            ClprProtobufHelpers.encodeFieldKey(3, 2), ClprProtobufHelpers.encodeLengthDelimited(controlMsg)
        );

        bytes[] memory msgs = new bytes[](1);
        msgs[0] = badControl;
        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(badControl)));
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

        vm.expectEmit(true, true, false, true, address(service));
        emit BundleLib.BundleParseFailed(channelId, 1);

        service.submitBundle(channelId, hex"00FF");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE), "ACTIVE after CONTROL decode failure");
        assertEq(channel.nextMessageId, 1, "CONTROL never generates a reply");
    }

    // ── Unknown message type: protocol violation, whole-bundle rejection ──

    /// @dev 0x2a = (field_number=5 << 3) | wire_type=2 → not a ClprMessage oneof member (1-4).
    ///      An unrecognized discriminator from a same-version peer is a protocol violation, the
    ///      sender runs the wrong version or produces malformed output so the entire bundle is
    ///      rejected.
    function test_unknownMessageType_singleMessage_revertsEntireBundle() public {
        bytes memory unknownType = hex"2a00";

        bytes[] memory msgs = new bytes[](1);
        msgs[0] = unknownType;
        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(unknownType)));
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

        vm.expectRevert(abi.encodeWithSelector(ClprTypes.ClprUnknownWireField.selector, 5));
        _submitBundle(hex"00FF");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE), "channel state untouched");
        assertEq(channel.receivedMessageId, 0, "no inbound progress on a rejected bundle");
        assertEq(channel.nextMessageId, 1, "no replies queued on a rejected bundle");
    }

    /// @dev A payload carrying ClprMessagePayload field 4 (the former `redacted_message` variant) is an
    ///      unknown wire field: the whole bundle is rejected.
    function test_redactedMessage_rejectsBundle() public {
        // 0x22 = (field_number=4 << 3) | wire_type=2, empty body.
        bytes memory redacted = hex"2200";

        bytes[] memory msgs = new bytes[](1);
        msgs[0] = redacted;
        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(redacted)));
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

        vm.expectRevert(abi.encodeWithSelector(ClprTypes.ClprUnknownWireField.selector, uint64(4)));
        service.submitBundle(channelId, hex"00FF");
    }

    function test_replyWithRemovedStatus_rejectsBundle() public {
        _registerTestConnector();
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"0001");

        for (uint64 status = 4; status <= 5; status++) {
            bytes memory reply = abi.encodePacked(
                ClprProtobufHelpers.encodeFieldKey(2, 2),
                ClprProtobufHelpers.encodeLengthDelimited(
                    abi.encodePacked(
                        ClprProtobufHelpers.encodeVarintField(1, 1), ClprProtobufHelpers.encodeVarintField(2, status)
                    )
                )
            );
            bytes[] memory msgs = new bytes[](1);
            msgs[0] = reply;
            bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(reply)));
            verifier.setVerifyBundleResult(
                ClprTypes.QueueMetadata({
                    nextMessageId: 2,
                    sentRunningHash: hash,
                    receivedMessageId: 1,
                    receivedRunningHash: bytes32(0),
                    state: ClprTypes.ChannelStatus.ACTIVE,
                    endpointManifestVersion: 0,
                    lastMessageId: 1,
                    lastMessageRunningHash: hash
                }),
                msgs
            );

            vm.expectRevert(ClprTypes.ClprBundleVerificationFailed.selector);
            service.submitBundle(channelId, hex"00FF");
        }

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(channel.ackedMessageId, 0, "the outbound DATA stays unacked");
        assertEq(channel.receivedMessageId, 0, "no inbound progress on a rejected bundle");
        assertGt(service.getMessage(channelId, 1).payload.length, 0, "the outbound DATA stays queued");
    }

    /// @dev An empty-payload message is unclassifiable (getMessageType has nothing to read). It is
    ///      a protocol violation distinct from an unknown discriminator, so the whole bundle is
    ///      rejected with the dedicated empty-payload error rather than ClprUnknownWireField.
    function test_emptyPayload_singleMessage_revertsEntireBundle() public {
        bytes memory emptyPayload = hex"";

        bytes[] memory msgs = new bytes[](1);
        msgs[0] = emptyPayload;
        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(emptyPayload)));
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

        vm.expectRevert(ClprTypes.ClprBundleVerificationFailedEmptyPayload.selector);
        _submitBundle(hex"00FF");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE), "channel state untouched");
        assertEq(channel.receivedMessageId, 0, "no inbound progress on a rejected bundle");
        assertEq(channel.nextMessageId, 1, "no replies queued on a rejected bundle");
    }

    /// @dev An unknown-type message between two good DATA messages rejects the ENTIRE bundle,
    ///      including the good messages dispatched before it (atomic rejection).
    function test_unknownMessageType_middleOf3_revertsEntireBundle() public {
        _registerTestConnector();

        bytes memory goodData1 =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"FFEEDD");
        bytes memory unknownType = hex"2a00"; // field 5 → unclassifiable
        bytes memory goodData2 =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"CC03DD04", hex"112233");

        bytes[] memory msgs = new bytes[](3);
        msgs[0] = goodData1; // inbound msg 1 — DATA, succeeds
        msgs[1] = unknownType; // inbound msg 2 — unknown type, rejects the bundle
        msgs[2] = goodData2; // inbound msg 3 — DATA, succeeds

        bytes32 h = bytes32(0);
        for (uint256 i = 0; i < 3; i++) {
            h = sha256(abi.encodePacked(h, sha256(msgs[i])));
        }

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 4,
            sentRunningHash: h,
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 3,
            lastMessageRunningHash: h
        });
        verifier.setVerifyBundleResult(meta, msgs);

        vm.expectRevert(abi.encodeWithSelector(ClprTypes.ClprUnknownWireField.selector, 5));
        _submitBundle(hex"00FF");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE));
        // Atomic rejection: the good DATA messages dispatched before the unknown type must not
        // have taken effect either.
        assertEq(channel.receivedMessageId, 0, "no inbound progress on a rejected bundle");
        assertEq(channel.nextMessageId, 1, "no replies queued on a rejected bundle");
        assertEq(app.getMessageCallCount(), 0, "app must not observe a rejected bundle's DATA messages");
    }

    // ── Fix: unknown CONTROL oneof variant rejects the entire bundle ──

    /// @dev Per CLPR spec, an unrecognized `ClprControlMessage` oneof variant is a
    ///      protocol-level violation: the whole bundle MUST be rejected before any of its
    ///      messages take effect. `ClprProtobuf.decodeControlMessage` throws a dedicated
    ///      error for it — `ClprBundleVerificationFailedOneOfVariant`.
    ///
    ///      `_dispatchMessages` re-throws that specific error out of its CONTROL try/catch
    ///      instead of swallowing it into a generic per-message `BundleParseFailed`, so it
    ///      propagates out of `submitBundle` and reverts the whole call.
    ///
    ///      Bundle: [DATA-good][DATA-good][CONTROL-unknown-variant][DATA-good]. DATA1/DATA2
    ///      dispatch (and would-be app calls / queued replies) before message 3 is reached,
    ///      but the revert must unwind them along with everything else in the bundle.
    function test_unknownControlOneOfVariant_revertsEntireBundle() public {
        _registerTestConnector();

        bytes memory data1 =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"D1D1D1");
        bytes memory data2 =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"D2D2D2");
        // ClprMessage field 3 (CONTROL), length 2, inner ClprControlMessage field 2 (not the
        // field-1 config_update oneof member) → decodeControlMessage reverts with
        // ClprBundleVerificationFailedOneOfVariant.
        bytes memory unknownControlVariant = hex"1A021000";
        bytes memory data4 =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"D4D4D4");

        bytes[] memory msgs = new bytes[](4);
        msgs[0] = data1;
        msgs[1] = data2;
        msgs[2] = unknownControlVariant;
        msgs[3] = data4;

        bytes32 h = bytes32(0);
        for (uint256 i = 0; i < 4; i++) {
            h = sha256(abi.encodePacked(h, sha256(msgs[i])));
        }

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 5,
            sentRunningHash: h,
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 4,
            lastMessageRunningHash: h
        });
        verifier.setVerifyBundleResult(meta, msgs);

        vm.expectRevert(ClprTypes.ClprBundleVerificationFailedOneOfVariant.selector);
        _submitBundle(hex"00FF");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE));
        // Atomic rejection: DATA1/DATA2, which ran before the bad CONTROL was reached, must
        // not have taken effect either.
        assertEq(channel.receivedMessageId, 0, "no inbound progress on a rejected bundle");
        assertEq(channel.nextMessageId, 1, "no replies queued on a rejected bundle");
        assertEq(app.getMessageCallCount(), 0, "app must not observe a rejected bundle's DATA messages");
    }

    receive() external payable {}
}

// ── REPLY decode failure requires MockBundleDecodeHelper ──────────────────────

contract BundleProcessor_ReplyDecodeFailTest is ClprTestBase {
    MockBundleDecodeHelper internal mockHelper;
    MockClprApplication internal app2;

    function setUp() public override {
        // Perform the standard base setup but replace the BundleDecodeHelper.
        mockHelper = new MockBundleDecodeHelper();

        signer = vm.addr(signerPk);

        // Deploy service with mock helper.
        ClprDeployHelper.Modules memory m = ClprDeployHelper.deployModules();
        m.bundleDecodeHelper = address(mockHelper);
        service = new ClprService(
            owner,
            1,
            "eip155:1337",
            m.channelLogic,
            m.messagingLogic,
            m.bundleLogic,
            m.connectorLogic,
            m.adminLogic,
            m.bundleDecodeHelper
        );

        verifier = new MockClprVerifier();
        verifier.setVerifyConfigResult("eip155:1", hex"AABB", 1000);
        verifier.setPeerThrottles(defaultThrottles);
        connector = new MockClprConnector();

        _initializeAndEnable();

        ClprTypes.Endpoint[] memory seeds = new ClprTypes.Endpoint[](1);
        seeds[0] = _peerEndpointSeedEntry();
        verifier.setSeedEndpoints(seeds);

        _createActiveChannel();

        app2 = new MockClprApplication();
        app2.setResponse(hex"504F4E47");
    }

    // REPLY: [good][fail][fail][good] — a REPLY that fails to decode has no in-protocol
    // recovery (it can never be matched, so response ordering can never advance past it):
    // the ENTIRE bundle is rejected, including the good REPLYs around it.
    function test_parseFailure_reply_middle2of4_revertsEntireBundle() public {
        connectorId = ConnectorRegistrar.register(
            IClprService(address(service)),
            channelId,
            keccak256(abi.encodePacked("svc-test-connector")),
            address(connector),
            owner,
            0.5 ether
        );
        (bool ok,) = address(connector).call{value: 0.5 ether}("");
        require(ok, "fund connector");

        // Send 4 outbound DATA messages (IDs 1-4).
        vm.startPrank(address(app2));
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app2)), hex"0001");
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app2)), hex"0002");
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app2)), hex"0003");
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app2)), hex"0004");
        vm.stopPrank();
        // channel.nextMessageId == 5, channel.nextExpectedReplyId == 1

        // Build 4 valid REPLY payloads (all pass _checkResponseOrdering's direct decode).
        bytes memory rp1 = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"");
        bytes memory rp2 = ClprProtobuf.encodeReplyMessage(2, ClprTypes.ReplyStatus.SUCCESS, hex"");
        bytes memory rp3 = ClprProtobuf.encodeReplyMessage(3, ClprTypes.ReplyStatus.SUCCESS, hex"");
        bytes memory rp4 = ClprProtobuf.encodeReplyMessage(4, ClprTypes.ReplyStatus.SUCCESS, hex"");

        // Tell the mock to fail dispatch-level decode for REPLY messages 2 and 3.
        mockHelper.setReplyDecodeFails(rp2);
        mockHelper.setReplyDecodeFails(rp3);

        bytes[] memory msgs = new bytes[](4);
        msgs[0] = rp1;
        msgs[1] = rp2;
        msgs[2] = rp3;
        msgs[3] = rp4;

        bytes32 h = bytes32(0);
        for (uint256 i = 0; i < 4; i++) {
            h = sha256(abi.encodePacked(h, sha256(msgs[i])));
        }

        // Peer acks all 4 of our DATA messages.
        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 5,
            sentRunningHash: h,
            receivedMessageId: 4,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 4,
            lastMessageRunningHash: h
        });
        verifier.setVerifyBundleResult(meta, msgs);

        vm.expectRevert(bytes("mock: REPLY decode failed"));
        service.submitBundle(channelId, hex"00FF");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE), "channel stays ACTIVE");
        // Atomic rejection: nothing in the bundle takes effect, not even the good REPLYs.
        assertEq(channel.receivedMessageId, 0, "no inbound progress on a rejected bundle");
        assertEq(channel.ackedMessageId, 0, "no ack progress on a rejected bundle");
        assertGt(service.getMessage(channelId, 1).payload.length, 0, "DATA slot 1 retained");
        assertGt(service.getMessage(channelId, 2).payload.length, 0, "DATA slot 2 retained");
        assertGt(service.getMessage(channelId, 3).payload.length, 0, "DATA slot 3 retained");
        assertGt(service.getMessage(channelId, 4).payload.length, 0, "DATA slot 4 retained");
        assertEq(app2.getResponseCallCount(), 0, "no responses delivered from a rejected bundle");
    }

    receive() external payable {}
}
