// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {MockClprApplication} from "@test/mocks/MockClprApplication.sol";
import {MockClprConnector} from "@test/mocks/MockClprConnector.sol";
import {BundleLibTestBase} from "@test/libraries/service/bundle-lib/BundleLibTestBase.sol";

contract BundleLib_ApplicationErrorsTest is BundleLibTestBase {
    function _decodeStringError(bytes memory encodedError) internal pure returns (string memory) {
        // Skip the 4-byte selector and decode the remaining ABI-encoded string
        bytes memory errorDataWithoutSelector = new bytes(encodedError.length - 4);
        for (uint256 i = 0; i < errorDataWithoutSelector.length; i++) {
            errorDataWithoutSelector[i] = encodedError[i + 4];
        }
        (string memory result) = abi.decode(errorDataWithoutSelector, (string));
        return result;
    }

    // ── Test 8: DATA message -> connector not found

    function test_dataMessage_connectorNotFound() public {
        // Don't register connector -- use unknown connector address
        bytes memory dataPayload = ClprProtobuf.encodeDataMessage(
            hex"FF00FF00", abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F"
        );

        _submitSingleInboundMessage(dataPayload);

        // Verify CONNECTOR_NOT_FOUND reply
        ClprTypes.MessageValue memory reply = service.getMessage(channelId, 1);
        ClprTypes.DecodedReply memory decoded = ClprProtobuf.decodeReplyMessage(reply.payload);
        assertEq(uint8(decoded.status), uint8(ClprTypes.ReplyStatus.CONNECTOR_NOT_FOUND));
    }

    // ── Test 9: DATA message -> application reverts -> APPLICATION_ERROR

    function test_dataMessage_applicationReverts() public {
        _registerTestConnector();

        // Configure app to revert
        app.setShouldRevert(true, "App error");

        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");

        _submitSingleInboundMessage(dataPayload);

        // Verify APPLICATION_ERROR reply
        ClprTypes.MessageValue memory reply = service.getMessage(channelId, 1);
        ClprTypes.DecodedReply memory decoded = ClprProtobuf.decodeReplyMessage(reply.payload);
        assertEq(uint8(decoded.status), uint8(ClprTypes.ReplyStatus.APPLICATION_ERROR));
    }

    // ── Test 9.1: String revert captures error message

    function test_dataMessage_applicationReverts_capturesErrorMessage() public {
        _registerTestConnector();

        string memory errorMsg = "Application validation failed";
        app.setShouldRevert(true, errorMsg);

        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");

        _submitSingleInboundMessage(dataPayload);

        // Verify APPLICATION_ERROR reply with captured error message
        ClprTypes.MessageValue memory reply = service.getMessage(channelId, 1);
        ClprTypes.DecodedReply memory decoded = ClprProtobuf.decodeReplyMessage(reply.payload);
        assertEq(uint8(decoded.status), uint8(ClprTypes.ReplyStatus.APPLICATION_ERROR));

        // Verify messageReplyData contains the error message
        // The encoded error includes the Error(string) selector (0x08c379a0) + ABI-encoded string
        assertTrue(decoded.messageReplyData.length > 4, "messageReplyData should contain error reason");

        string memory capturedError = _decodeStringError(decoded.messageReplyData);
        assertEq(capturedError, errorMsg);
    }

    // ── Test 9.2: Empty revert message

    function test_dataMessage_applicationReverts_emptyMessage() public {
        _registerTestConnector();

        app.setShouldRevert(true, "");

        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");

        _submitSingleInboundMessage(dataPayload);

        // Verify APPLICATION_ERROR reply
        ClprTypes.MessageValue memory reply = service.getMessage(channelId, 1);
        ClprTypes.DecodedReply memory decoded = ClprProtobuf.decodeReplyMessage(reply.payload);
        assertEq(uint8(decoded.status), uint8(ClprTypes.ReplyStatus.APPLICATION_ERROR));

        // messageReplyData should be the encoded empty string
        // Empty revert message encodes to a very short reason (still valid)
        string memory capturedError = _decodeStringError(decoded.messageReplyData);
        assertEq(capturedError, "");
    }

    // ── Test 9.3: Custom error revert captures error data

    function test_dataMessage_applicationReverts_customError() public {
        _registerTestConnector();

        // Configure app to throw custom error InvalidAmount(100, 50)
        app.setShouldThrowCustomError(true, 100, 50);

        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");

        _submitSingleInboundMessage(dataPayload);

        // Verify APPLICATION_ERROR reply
        ClprTypes.MessageValue memory reply = service.getMessage(channelId, 1);
        ClprTypes.DecodedReply memory decoded = ClprProtobuf.decodeReplyMessage(reply.payload);
        assertEq(uint8(decoded.status), uint8(ClprTypes.ReplyStatus.APPLICATION_ERROR));

        // Verify messageReplyData contains custom error data
        assertTrue(decoded.messageReplyData.length >= 4, "messageReplyData should contain custom error with selector");
        // First 4 bytes should be the error selector for InvalidAmount
        bytes memory replyData = decoded.messageReplyData;
        bytes4 errorSelector;
        assembly {
            errorSelector := mload(add(replyData, 32))
        }
        // InvalidAmount error selector
        bytes4 expectedSelector = bytes4(keccak256("InvalidAmount(uint256,uint256)"));
        assertEq(errorSelector, expectedSelector);
    }

    // ── Test 9.4: Long error message is fully captured

    function test_dataMessage_applicationReverts_longMessage() public {
        _registerTestConnector();

        string memory longError =
            "This is a very long error message that contains detailed information about what went wrong in the application. It includes stack traces and context that can help with debugging. The system should capture the entire message without truncation.";
        app.setShouldRevert(true, longError);

        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");

        _submitSingleInboundMessage(dataPayload);

        // Verify APPLICATION_ERROR reply with full message
        ClprTypes.MessageValue memory reply = service.getMessage(channelId, 1);
        ClprTypes.DecodedReply memory decoded = ClprProtobuf.decodeReplyMessage(reply.payload);
        assertEq(uint8(decoded.status), uint8(ClprTypes.ReplyStatus.APPLICATION_ERROR));

        // Verify full error message is captured
        string memory capturedError = _decodeStringError(decoded.messageReplyData);
        assertEq(capturedError, longError);
    }

    // ── Test 9.5: Require statement reverts

    function test_dataMessage_applicationReverts_requireStatement() public {
        _registerTestConnector();

        app.setShouldRevert(true, "require check failed");

        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");

        _submitSingleInboundMessage(dataPayload);

        // Verify APPLICATION_ERROR reply
        ClprTypes.MessageValue memory reply = service.getMessage(channelId, 1);
        ClprTypes.DecodedReply memory decoded = ClprProtobuf.decodeReplyMessage(reply.payload);
        assertEq(uint8(decoded.status), uint8(ClprTypes.ReplyStatus.APPLICATION_ERROR));

        // Verify the require error message is captured
        string memory capturedError = _decodeStringError(decoded.messageReplyData);
        assertEq(capturedError, "require check failed");
    }

    // ── Test 9.6: Application error independent of connector callback error

    function test_dataMessage_applicationReverts_thenConnectorCallbackAlsoReverts() public {
        _registerTestConnector();

        string memory appError = "Application processing error";
        app.setShouldRevert(true, appError);
        connector.setInboundReverts(true);

        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");

        _submitSingleInboundMessage(dataPayload);

        // Verify APPLICATION_ERROR reply was queued despite connector callback failure
        ClprTypes.MessageValue memory reply = service.getMessage(channelId, 1);
        ClprTypes.DecodedReply memory decoded = ClprProtobuf.decodeReplyMessage(reply.payload);

        // Main assertion: reply contains APPLICATION_ERROR (from app, not connector)
        assertEq(uint8(decoded.status), uint8(ClprTypes.ReplyStatus.APPLICATION_ERROR));

        // Verify the app error reason is captured, not the connector error
        string memory capturedError = _decodeStringError(decoded.messageReplyData);
        assertEq(capturedError, appError, "Should capture app error, not connector error");
    }

    // ── Decode failure → PAUSED, not whole-bundle revert

    function test_malformedDataPayload_invalidAddressYieldsApplicationError() public {
        // Craft a DATA message where targetApplication is 3 bytes (not 20).
        // "Inability to PARSE" → PAUSED. Decode succeeds here (proto is fine);
        // the bad address is caught at dispatch time and treated as APPLICATION_ERROR
        // (_bytesToAddress returns address(0), which has no code → APPLICATION_ERROR reply).
        // The channel stays ACTIVE; no whole-bundle revert.
        _registerTestConnector();

        bytes memory malformed = ClprProtobuf.encodeDataMessage(
            connectorId,
            hex"AABBCC", // 3 bytes — not a valid EVM address
            hex"AA01BB02",
            hex"48454C4C4F"
        );

        bytes[] memory msgs = new bytes[](1);
        msgs[0] = malformed;
        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(malformed)));

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

        // Should NOT revert; channel stays ACTIVE; reply is APPLICATION_ERROR
        _submitBundle(hex"00FF");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE), "channel stays ACTIVE");

        // A reply should have been queued: APPLICATION_ERROR because address(0) has no code
        ClprTypes.MessageValue memory reply = service.getMessage(channelId, 1);
        assertTrue(reply.payload.length > 0, "reply queued");
        ClprTypes.DecodedReply memory decoded = ClprProtobuf.decodeReplyMessage(reply.payload);
        assertEq(uint8(decoded.status), uint8(ClprTypes.ReplyStatus.APPLICATION_ERROR));
    }

    receive() external payable {}
}
