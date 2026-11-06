// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";

/// @title ClprProtobuf
/// @notice Encodes/decodes CLPR message payloads in protobuf wire format.
/// @dev Handles only the specific CLPR message schemas, not general protobuf.
///      Wire format matches Hiero's clpr_message.proto definitions exactly.
library ClprProtobuf {
    /// @notice Infer the CLPR message type from the first protobuf field tag in `payload`.
    /// @param payload Encoded CLPR message bytes (must be non-empty).
    /// @return The `MessageType` discriminator.
    function getMessageType(bytes memory payload) internal pure returns (ClprTypes.MessageType) {
        if (payload.length == 0) revert ClprTypes.ClprBundleVerificationFailedEmptyPayload();
        (bool known, ClprTypes.MessageType msgType) = tryGetMessageType(payload);
        if (!known) {
            (uint64 tag,,) = PB.decodeFieldKey(payload, 0);
            revert ClprTypes.ClprUnknownWireField(tag);
        }
        return msgType;
    }

    /// @notice Non-reverting variant of {getMessageType} for untrusted bundle payloads.
    /// @dev Returns `known = false` for an empty payload or an unrecognized field tag instead of
    ///      reverting, so a single malformed message inside a validly-signed bundle degrades to a
    ///      per-message skip rather than reverting the entire bundle. The underlying varint decode
    ///      cannot revert, so these two are the only failure modes.
    /// @param payload Encoded CLPR message bytes.
    /// @return known True if `payload` carries a recognized CLPR message tag (field 1/2/3).
    /// @return msgType The decoded discriminator; only meaningful when `known` is true.
    function tryGetMessageType(bytes memory payload) internal pure returns (bool known, ClprTypes.MessageType msgType) {
        if (payload.length == 0) return (false, ClprTypes.MessageType.DATA);
        (uint64 fieldNumber,,) = PB.decodeFieldKey(payload, 0);
        if (fieldNumber == 1) return (true, ClprTypes.MessageType.DATA);
        if (fieldNumber == 2) return (true, ClprTypes.MessageType.REPLY);
        if (fieldNumber == 3) return (true, ClprTypes.MessageType.CONTROL);
        return (false, ClprTypes.MessageType.DATA);
    }

    /// @notice Encode a DATA message as `ClprMessage { data: DataMessage { ... } }`.
    /// @param connectorId Connector identifier (32-byte keccak); serialized as a 32-byte protobuf
    ///        bytes field, so the wire format is unchanged from the previous dynamic-`bytes` form.
    /// @param targetApplication ABI-encoded target application address on the peer.
    /// @param sender ABI-encoded msg.sender set by the router (cannot be spoofed).
    /// @param messageData Opaque payload for the peer application.
    /// @return Encoded protobuf bytes.
    function encodeDataMessage(
        bytes32 connectorId,
        bytes memory targetApplication,
        bytes memory sender,
        bytes memory messageData
    ) internal pure returns (bytes memory) {
        bytes memory innerMsg = abi.encodePacked(
            PB.encodeBytesField(1, abi.encodePacked(connectorId)),
            PB.encodeBytesField(2, targetApplication),
            PB.encodeBytesField(3, sender),
            PB.encodeBytesField(4, messageData)
        );
        return abi.encodePacked(PB.encodeFieldKey(1, 2), PB.encodeLengthDelimited(innerMsg));
    }

    /// @notice Encode a REPLY message as `ClprMessage { reply: ReplyMessage { ... } }`.
    /// @param messageId The original DATA message id this is a reply to.
    /// @param status Outcome of the original message dispatch.
    /// @param replyData Optional application-level response bytes.
    /// @return Encoded protobuf bytes.
    function encodeReplyMessage(uint64 messageId, ClprTypes.ReplyStatus status, bytes memory replyData)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory innerReply = abi.encodePacked(
            PB.encodeVarintField(1, messageId),
            PB.encodeVarintField(2, uint64(uint8(status))),
            PB.encodeBytesField(3, replyData)
        );
        return abi.encodePacked(PB.encodeFieldKey(2, 2), PB.encodeLengthDelimited(innerReply));
    }

    /// @notice Encode a CONTROL message wrapping a `ClprLedgerConfiguration` update.
    /// @dev Wire format: `ClprMessage { control: ControlMessage { config_update: ClprLedgerConfiguration } }`.
    /// @param config The current ledger configuration to broadcast to the peer.
    /// @return Encoded protobuf bytes.
    function encodeControlMessage(ClprTypes.LedgerConfiguration memory config) internal pure returns (bytes memory) {
        // Encode Timestamp submessage: split nanosSinceEpoch into seconds (field 1) and nanos (field 2).
        uint96 ns = config.nanosSinceEpoch;
        // Bound the seconds component before truncating: uint96 / 1e9 can exceed uint64 max
        // (uint96 max ≈ 7.9e28 → seconds max ≈ 7.9e19; uint64 max ≈ 1.84e19).
        uint256 secondsValue = uint256(ns) / 1_000_000_000;
        if (secondsValue > type(uint64).max) revert ClprTypes.ClprInvalidConfiguration();
        // casting to 'uint64' is safe because of the bound check above.
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 tsSeconds = uint64(secondsValue);
        // casting to 'uint32' is safe because `ns % 1_000_000_000` is in [0, 1e9), which fits in uint32 (max ~4.29e9).
        // forge-lint: disable-next-line(unsafe-typecast)
        uint32 tsNanos = uint32(ns % 1_000_000_000);
        bytes memory tsMsg = abi.encodePacked(
            PB.encodeVarintField(1, tsSeconds), tsNanos > 0 ? PB.encodeVarintField(2, uint64(tsNanos)) : bytes("")
        );
        bytes memory throttlesMsg = _encodeThrottles(config.throttles);
        bytes memory configMsg = abi.encodePacked(
            PB.encodeVarintField(1, uint64(config.protocolVersion)),
            PB.encodeBytesField(2, bytes(config.chainId)),
            PB.encodeBytesField(3, config.serviceAddress),
            abi.encodePacked(PB.encodeFieldKey(4, 2), PB.encodeLengthDelimited(tsMsg)),
            abi.encodePacked(PB.encodeFieldKey(5, 2), PB.encodeLengthDelimited(throttlesMsg)),
            // Spec fields 7 and 8. proto3 default-elision: skip when empty.
            config.trustAnchor.length > 0 ? PB.encodeBytesField(7, config.trustAnchor) : bytes(""),
            config.trustAnchorId.length > 0 ? PB.encodeBytesField(8, config.trustAnchorId) : bytes("")
        );
        bytes memory configUpdate = abi.encodePacked(PB.encodeFieldKey(1, 2), PB.encodeLengthDelimited(configMsg));
        bytes memory controlMsg = abi.encodePacked(PB.encodeFieldKey(1, 2), PB.encodeLengthDelimited(configUpdate));
        return abi.encodePacked(PB.encodeFieldKey(3, 2), PB.encodeLengthDelimited(controlMsg));
    }

    function _encodeThrottles(ClprTypes.Throttles memory t) internal pure returns (bytes memory) {
        return abi.encodePacked(
            PB.encodeVarintField(1, t.maxMessagesPerBundle),
            PB.encodeVarintField(2, t.maxMessagePayloadBytes),
            PB.encodeVarintField(3, t.maxGasPerMessage),
            PB.encodeVarintField(4, t.maxQueueDepth),
            PB.encodeVarintField(5, t.maxSyncBytes),
            PB.encodeVarintField(6, uint64(t.maxLocalEndpoints)),
            PB.encodeVarintField(7, uint64(t.maxPeerEndpoints))
        );
    }

    /// @dev Encode one `ClprEndpoint` submessage body (no outer field key). Fields:
    ///      service_endpoint=1 (nested ServiceEndpoint{ip=1, port=2}), tls_certificate=2,
    ///      account_id=3.
    function _encodeEndpointBody(ClprTypes.Endpoint memory ep) internal pure returns (bytes memory) {
        bytes memory svcEpMsg =
            abi.encodePacked(PB.encodeBytesField(1, bytes(ep.ipAddress)), PB.encodeVarintField(2, uint64(ep.port)));
        return abi.encodePacked(
            abi.encodePacked(PB.encodeFieldKey(1, 2), PB.encodeLengthDelimited(svcEpMsg)),
            PB.encodeBytesField(2, ep.tlsCertificate),
            PB.encodeBytesField(3, ep.accountId)
        );
    }

    /// @notice Encode a `ClprEndpointManifest`: version=1 (varint), service_address=2 (bytes),
    ///         endpoints=3 (repeated ClprEndpoint).
    function encodeEndpointManifest(ClprTypes.ClprEndpointManifest memory m) internal pure returns (bytes memory out) {
        out = abi.encodePacked(
            PB.encodeVarintField(1, m.version),
            m.serviceAddress.length > 0 ? PB.encodeBytesField(2, m.serviceAddress) : bytes("")
        );
        for (uint256 i = 0; i < m.endpoints.length; i++) {
            out = abi.encodePacked(
                out, PB.encodeFieldKey(3, 2), PB.encodeLengthDelimited(_encodeEndpointBody(m.endpoints[i]))
            );
        }
    }

    /// @notice Decode a `ClprEndpointManifest` (as produced by {encodeEndpointManifest}).
    function decodeEndpointManifest(bytes memory data) internal pure returns (ClprTypes.ClprEndpointManifest memory m) {
        // First pass: count repeated endpoints (field 3).
        uint256 epCount = 0;
        {
            uint256 scanPos = 0;
            while (scanPos < data.length) {
                uint64 fn;
                uint8 wt;
                (fn, wt, scanPos) = PB.decodeFieldKey(data, scanPos);
                if (fn == 3 && wt == 2) {
                    (, scanPos) = PB.decodeLengthDelimited(data, scanPos);
                    epCount++;
                } else {
                    scanPos = PB.skipField(data, scanPos, wt);
                }
            }
        }
        m.endpoints = new ClprTypes.Endpoint[](epCount);

        uint256 pos = 0;
        uint256 epIdx = 0;
        while (pos < data.length) {
            uint64 fieldNum;
            uint8 wireType;
            (fieldNum, wireType, pos) = PB.decodeFieldKey(data, pos);
            if (fieldNum == 1) {
                (m.version, pos) = PB.decodeVarint(data, pos);
            } else if (fieldNum == 2) {
                (m.serviceAddress, pos) = PB.decodeLengthDelimited(data, pos);
            } else if (fieldNum == 3 && wireType == 2) {
                // Wire type must match the counting pass above, or epIdx would run past epCount.
                bytes memory epMsg;
                (epMsg, pos) = PB.decodeLengthDelimited(data, pos);
                m.endpoints[epIdx++] = _decodeEndpoint(epMsg);
            } else {
                pos = PB.skipField(data, pos, wireType);
            }
        }
    }

    /// @notice Decode a DATA message encoded by `encodeDataMessage`.
    /// @param payload Full `ClprMessage` bytes (outer field 1 wraps the `DataMessage`).
    /// @return result Decoded fields: connectorId, targetApplication, sender, messageData.
    function decodeDataMessage(bytes memory payload)
        internal
        pure
        returns (ClprTypes.DecodedDataMessage memory result)
    {
        (, uint8 outerWireType, uint256 offset) = PB.decodeFieldKey(payload, 0);
        if (outerWireType != 2) revert ClprTypes.ClprBundleVerificationFailed();
        bytes memory innerMsg;
        (innerMsg,) = PB.decodeLengthDelimited(payload, offset);

        uint256 pos = 0;
        while (pos < innerMsg.length) {
            uint64 fieldNum;
            uint8 wireType;
            (fieldNum, wireType, pos) = PB.decodeFieldKey(innerMsg, pos);
            if (fieldNum == 1) {
                // connectorId is a fixed 32-byte keccak id; a peer-supplied field of any other
                // length is malformed. Reject rather than truncate/pad silently — inbound dispatch
                // wraps this decode in try/catch, so a bad message degrades to a per-message skip.
                bytes memory raw;
                (raw, pos) = PB.decodeLengthDelimited(innerMsg, pos);
                if (raw.length != 32) revert ClprTypes.ClprBundleVerificationFailed();
                result.connectorId = _bytes32From(raw);
            } else if (fieldNum == 2) {
                (result.targetApplication, pos) = PB.decodeLengthDelimited(innerMsg, pos);
            } else if (fieldNum == 3) {
                (result.sender, pos) = PB.decodeLengthDelimited(innerMsg, pos);
            } else if (fieldNum == 4) {
                (result.messageData, pos) = PB.decodeLengthDelimited(innerMsg, pos);
            } else {
                revert ClprTypes.ClprUnknownWireField(fieldNum);
            }
        }
    }

    /// @notice Decode a REPLY message encoded by `encodeReplyMessage`.
    /// @param payload Full `ClprMessage` bytes (outer field 2 wraps the `ReplyMessage`).
    /// @return result Decoded fields: messageId, status, replyData.
    function decodeReplyMessage(bytes memory payload) internal pure returns (ClprTypes.DecodedReply memory result) {
        (, uint8 outerWireType, uint256 offset) = PB.decodeFieldKey(payload, 0);
        if (outerWireType != 2) revert ClprTypes.ClprBundleVerificationFailed();
        bytes memory innerReply;
        (innerReply,) = PB.decodeLengthDelimited(payload, offset);

        uint256 pos = 0;
        while (pos < innerReply.length) {
            uint64 fieldNum;
            uint8 wireType;
            (fieldNum, wireType, pos) = PB.decodeFieldKey(innerReply, pos);
            if (fieldNum == 1) {
                uint64 msgId;
                (msgId, pos) = PB.decodeVarint(innerReply, pos);
                result.messageId = msgId;
            } else if (fieldNum == 2) {
                uint64 statusVal;
                (statusVal, pos) = PB.decodeVarint(innerReply, pos);
                // Bound-check before truncating: a peer-supplied `statusVal > 255` would
                // truncate to a valid-looking uint8 and silently land on the wrong enum variant.
                if (statusVal > uint64(uint8(type(ClprTypes.ReplyStatus).max))) {
                    revert ClprTypes.ClprBundleVerificationFailed();
                }
                // casting to 'uint8' is safe because of the bound check above.
                // forge-lint: disable-next-line(unsafe-typecast)
                result.status = ClprTypes.ReplyStatus(uint8(statusVal));
            } else if (fieldNum == 3) {
                (result.messageReplyData, pos) = PB.decodeLengthDelimited(innerReply, pos);
            } else {
                revert ClprTypes.ClprUnknownWireField(fieldNum);
            }
        }
    }

    /// @notice Decode a CONTROL message encoded by `encodeControlMessage`.
    /// @param payload Full `ClprMessage` bytes (outer field 3 wraps the `ControlMessage`).
    function decodeControlMessage(bytes memory payload) internal pure returns (ClprTypes.DecodedControl memory result) {
        uint256 offset;
        // Layer 1: ClprMessagePayload field 3 (control)
        (,, offset) = PB.decodeFieldKey(payload, 0);
        bytes memory controlMsg;
        (controlMsg,) = PB.decodeLengthDelimited(payload, offset);
        // Layer 2: ClprControlMessage — must be exactly field 1 (config_update oneof).
        {
            uint64 ctrlField;
            (ctrlField,, offset) = PB.decodeFieldKey(controlMsg, 0);
            if (ctrlField != 1) revert ClprTypes.ClprBundleVerificationFailedOneOfVariant();
        }
        bytes memory configUpdate;
        (configUpdate,) = PB.decodeLengthDelimited(controlMsg, offset);
        // Layer 3: ClprConfigUpdate field 1 (configuration)
        (,, offset) = PB.decodeFieldKey(configUpdate, 0);
        bytes memory configMsg;
        (configMsg,) = PB.decodeLengthDelimited(configUpdate, offset);

        uint256 pos = 0;
        while (pos < configMsg.length) {
            uint64 fieldNum;
            (fieldNum,, pos) = PB.decodeFieldKey(configMsg, pos);
            if (fieldNum == 1) {
                uint64 v;
                (v, pos) = PB.decodeVarint(configMsg, pos);
                if (v > type(uint32).max) revert ClprTypes.ClprBundleVerificationFailed();
                // casting to 'uint32' is safe because of the bound check above.
                // forge-lint: disable-next-line(unsafe-typecast)
                result.config.protocolVersion = uint32(v);
            } else if (fieldNum == 2) {
                bytes memory b;
                (b, pos) = PB.decodeLengthDelimited(configMsg, pos);
                result.config.chainId = string(b);
            } else if (fieldNum == 3) {
                (result.config.serviceAddress, pos) = PB.decodeLengthDelimited(configMsg, pos);
            } else if (fieldNum == 4) {
                bytes memory tsMsg;
                (tsMsg, pos) = PB.decodeLengthDelimited(configMsg, pos);
                if (tsMsg.length > 0) {
                    // Decode Timestamp { int64 seconds = 1; int32 nanos = 2 } and combine.
                    uint64 tsSeconds = 0;
                    uint64 tsNanos = 0;
                    uint256 tsPos = 0;
                    while (tsPos < tsMsg.length) {
                        uint64 tsFn;
                        uint8 tsWt;
                        (tsFn, tsWt, tsPos) = PB.decodeFieldKey(tsMsg, tsPos);
                        if (tsFn == 1) (tsSeconds, tsPos) = PB.decodeVarint(tsMsg, tsPos);
                        else if (tsFn == 2) (tsNanos, tsPos) = PB.decodeVarint(tsMsg, tsPos);
                        else revert ClprTypes.ClprUnknownWireField(tsFn);
                    }
                    result.config.nanosSinceEpoch = uint96(tsSeconds) * 1_000_000_000 + uint96(tsNanos);
                }
            } else if (fieldNum == 5) {
                bytes memory tMsg;
                (tMsg, pos) = PB.decodeLengthDelimited(configMsg, pos);
                result.config.throttles = _decodeThrottles(tMsg);
            } else if (fieldNum == 7) {
                (result.config.trustAnchor, pos) = PB.decodeLengthDelimited(configMsg, pos);
            } else if (fieldNum == 8) {
                (result.config.trustAnchorId, pos) = PB.decodeLengthDelimited(configMsg, pos);
            } else {
                // Strict wire format: every unrecognized field number rejects the whole bundle.
                revert ClprTypes.ClprUnknownWireField(fieldNum);
            }
        }
    }

    function _decodeThrottles(bytes memory data) internal pure returns (ClprTypes.Throttles memory t) {
        uint256 pos = 0;
        while (pos < data.length) {
            uint64 fn;
            uint8 wt;
            uint64 v;
            (fn, wt, pos) = PB.decodeFieldKey(data, pos);
            (v, pos) = PB.decodeVarint(data, pos);
            if (fn == 1) {
                if (v > type(uint32).max) revert ClprTypes.ClprBundleVerificationFailed();
                // Condition above already ensured cast safety.
                // forge-lint: disable-next-line(unsafe-typecast)
                t.maxMessagesPerBundle = uint32(v);
            } else if (fn == 2) {
                t.maxMessagePayloadBytes = v;
            } else if (fn == 3) {
                t.maxGasPerMessage = v;
            } else if (fn == 4) {
                if (v > type(uint32).max) revert ClprTypes.ClprBundleVerificationFailed();
                // Condition above already ensured cast safety.
                // forge-lint: disable-next-line(unsafe-typecast)
                t.maxQueueDepth = uint32(v);
            } else if (fn == 5) {
                t.maxSyncBytes = v;
            } else if (fn == 6) {
                if (v > type(uint32).max) revert ClprTypes.ClprBundleVerificationFailed();
                // Condition above already ensured cast safety.
                // forge-lint: disable-next-line(unsafe-typecast)
                t.maxLocalEndpoints = uint32(v);
            } else if (fn == 7) {
                if (v > type(uint32).max) revert ClprTypes.ClprBundleVerificationFailed();
                // Condition above already ensured cast safety.
                // forge-lint: disable-next-line(unsafe-typecast)
                t.maxPeerEndpoints = uint32(v);
            } else {
                revert ClprTypes.ClprUnknownWireField(fn);
            }
        }
    }

    function _decodeEndpoint(bytes memory data) internal pure returns (ClprTypes.Endpoint memory ep) {
        // ClprEndpoint: service_endpoint=1 (nested ServiceEndpoint LEN), tls_certificate=2,
        //               account_id=3. ecdsa_signing_key was removed and account_id renumbered down.
        // ServiceEndpoint: ip=1, port=2
        uint256 pos = 0;
        while (pos < data.length) {
            uint64 fn;
            uint8 wt;
            (fn, wt, pos) = PB.decodeFieldKey(data, pos);
            if (fn == 1) {
                // Nested ServiceEndpoint submessage
                bytes memory svcEpBytes;
                (svcEpBytes, pos) = PB.decodeLengthDelimited(data, pos);
                uint256 svcPos = 0;
                while (svcPos < svcEpBytes.length) {
                    uint64 sfn;
                    uint8 swt;
                    (sfn, swt, svcPos) = PB.decodeFieldKey(svcEpBytes, svcPos);
                    if (sfn == 1) {
                        bytes memory b;
                        (b, svcPos) = PB.decodeLengthDelimited(svcEpBytes, svcPos);
                        ep.ipAddress = string(b);
                    } else if (sfn == 2) {
                        uint64 v;
                        (v, svcPos) = PB.decodeVarint(svcEpBytes, svcPos);
                        // Ports are 16-bit by definition. Reject anything larger before truncating to uint32.
                        if (v > 65535) revert ClprTypes.ClprBundleVerificationFailed();
                        // casting to 'uint32' is safe because of the bound check above (65535 fits in uint32).
                        // forge-lint: disable-next-line(unsafe-typecast)
                        ep.port = uint32(v);
                    } else {
                        revert ClprTypes.ClprUnknownWireField(sfn);
                    }
                }
            } else if (fn == 2) {
                (ep.tlsCertificate, pos) = PB.decodeLengthDelimited(data, pos);
            } else if (fn == 3) {
                (ep.accountId, pos) = PB.decodeLengthDelimited(data, pos);
            } else {
                revert ClprTypes.ClprUnknownWireField(fn);
            }
        }
    }

    // ── BundleContent encode/decode (for stub/testing verifiers) ──────

    /// @notice Encode a BundleContent proto: field 1 = QueueMetadata, field 2 = each message payload (repeated).
    function encodeBundleContent(ClprTypes.QueueMetadata memory meta, bytes[] memory messagePayloads)
        internal
        pure
        returns (bytes memory out)
    {
        bytes memory metaBytes = abi.encodePacked(
            PB.encodeVarintField(1, meta.nextMessageId),
            PB.encodeBytesField(2, abi.encodePacked(meta.sentRunningHash)),
            PB.encodeVarintField(3, meta.receivedMessageId),
            PB.encodeBytesField(4, abi.encodePacked(meta.receivedRunningHash)),
            PB.encodeVarintField(5, uint64(uint8(meta.state))),
            PB.encodeVarintField(7, meta.endpointManifestVersion)
        );
        bytes memory metaField = abi.encodePacked(PB.encodeFieldKey(1, 2), PB.encodeLengthDelimited(metaBytes));

        // Pre-encode each message field; accumulate total length for a single allocation.
        bytes[] memory msgFields = new bytes[](messagePayloads.length);
        uint256 total = metaField.length;
        for (uint256 i = 0; i < messagePayloads.length; i++) {
            msgFields[i] = abi.encodePacked(PB.encodeFieldKey(2, 2), PB.encodeLengthDelimited(messagePayloads[i]));
            total += msgFields[i].length;
        }

        // Single allocation + sequential copy; avoids O(N²) buffer growth.
        out = new bytes(total);
        uint256 pos = 0;
        _appendBytes(out, metaField, pos);
        pos += metaField.length;
        for (uint256 i = 0; i < msgFields.length; i++) {
            _appendBytes(out, msgFields[i], pos);
            pos += msgFields[i].length;
        }
    }

    /// @dev Copy `src` into `dst` starting at byte offset `at`, using 32-byte word stores.
    function _appendBytes(bytes memory dst, bytes memory src, uint256 at) private pure {
        assembly ("memory-safe") {
            let len := mload(src)
            let srcPtr := add(src, 32)
            let dstPtr := add(add(dst, 32), at)
            let end := add(dstPtr, len)
            for {} lt(dstPtr, end) {
                dstPtr := add(dstPtr, 32)
                srcPtr := add(srcPtr, 32)
            } { mstore(dstPtr, mload(srcPtr)) }
        }
    }

    /// @notice Decode a BundleContent proto encoded by {encodeBundleContent}. BundleContent has no
    ///         last-message fields, so a message-bearing bundle is taken to end at the sender's latest
    ///         message: `lastMessageId = nextMessageId - 1`, `lastMessageRunningHash = sentRunningHash`.
    function decodeBundleContent(bytes calldata data)
        internal
        pure
        returns (ClprTypes.QueueMetadata memory meta, bytes[] memory messagePayloads)
    {
        if (data.length == 0) return (meta, new bytes[](0));

        // First pass: count message payload fields for array sizing
        uint256 count = 0;
        uint256 pos = 0;
        while (pos < data.length) {
            uint64 fieldNum;
            uint8 wireType;
            (fieldNum, wireType, pos) = PB.decodeFieldKey(data, pos);
            if (fieldNum == 2) {
                count++;
                (, pos) = PB.decodeLengthDelimited(data, pos);
            } else if (fieldNum == 1) {
                (, pos) = PB.decodeLengthDelimited(data, pos);
            } else {
                revert ClprTypes.ClprUnknownWireField(fieldNum);
            }
        }

        // Second pass: decode
        messagePayloads = new bytes[](count);
        uint256 idx = 0;
        pos = 0;
        while (pos < data.length) {
            uint64 fieldNum;
            uint8 wireType;
            (fieldNum, wireType, pos) = PB.decodeFieldKey(data, pos);
            if (fieldNum == 1) {
                bytes memory metaBytes;
                (metaBytes, pos) = PB.decodeLengthDelimited(data, pos);
                uint256 mp = 0;
                while (mp < metaBytes.length) {
                    uint64 fn;
                    uint8 wt;
                    (fn, wt, mp) = PB.decodeFieldKey(metaBytes, mp);
                    if (fn == 1) {
                        (meta.nextMessageId, mp) = PB.decodeVarint(metaBytes, mp);
                    } else if (fn == 2) {
                        bytes memory h;
                        (h, mp) = PB.decodeLengthDelimited(metaBytes, mp);
                        // casting `h` to 'bytes32' is safe because the `h.length == 32` guard ensures exactly 32 bytes.
                        // forge-lint: disable-next-line(unsafe-typecast)
                        if (h.length == 32) meta.sentRunningHash = bytes32(h);
                    } else if (fn == 3) {
                        (meta.receivedMessageId, mp) = PB.decodeVarint(metaBytes, mp);
                    } else if (fn == 4) {
                        bytes memory h;
                        (h, mp) = PB.decodeLengthDelimited(metaBytes, mp);
                        // casting `h` to 'bytes32' is safe because the `h.length == 32` guard ensures exactly 32 bytes.
                        // forge-lint: disable-next-line(unsafe-typecast)
                        if (h.length == 32) meta.receivedRunningHash = bytes32(h);
                    } else if (fn == 5) {
                        uint64 s;
                        (s, mp) = PB.decodeVarint(metaBytes, mp);
                        // Bound-check before truncating to uint8: peer-supplied `s > 255` would
                        // truncate to a valid-looking uint8 and silently land on the wrong enum variant.
                        if (s > uint64(uint8(type(ClprTypes.ChannelStatus).max))) {
                            revert ClprTypes.ClprBundleVerificationFailed();
                        }
                        // casting to 'uint8' is safe because of the bound check above.
                        // forge-lint: disable-next-line(unsafe-typecast)
                        meta.state = ClprTypes.ChannelStatus(uint8(s));
                    } else if (fn == 7) {
                        (meta.endpointManifestVersion, mp) = PB.decodeVarint(metaBytes, mp);
                    } else {
                        revert ClprTypes.ClprUnknownWireField(fn);
                    }
                }
            } else {
                (messagePayloads[idx++], pos) = PB.decodeLengthDelimited(data, pos);
            }
        }
        if (messagePayloads.length > 0 && meta.nextMessageId > 0) {
            meta.lastMessageId = meta.nextMessageId - 1;
            meta.lastMessageRunningHash = meta.sentRunningHash;
        }
    }

    /// @notice Decode a `ClprChannel` (proven state-item value) from memory bytes.
    /// @dev    Wire layout mirrors `services/state/clpr/clpr_channel.proto`
    ///         (`clpr-evm-endpoint/clpr-relay-proto`):
    ///           field  1 = channel_id            (bytes, 32)            — skipped
    ///           field  2 = chain_id                 (string)               — skipped
    ///           field  3 = service_address          (bytes)                — decoded → peerServiceAddress
    ///           field  4 = peer_config_timestamp    (Timestamp sub-msg)    — skipped
    ///           field  5 = verifier_contract        (ContractID sub-msg)   — skipped
    ///           field  6 = verifier_fingerprint     (bytes)                — skipped
    ///           field  7 = status                   (varint, ChannelStatus enum)
    ///           field  8 = next_message_id          (varint, uint64)
    ///           field  9 = acked_message_id         (varint, uint64)
    ///           field 10 = sent_running_hash        (bytes, 32)
    ///           field 11 = received_message_id      (varint, uint64)
    ///           field 12 = received_running_hash    (bytes, 32)
    ///           field 13 = last_config_timestamp    (Timestamp sub-msg)    — skipped
    ///           field 14 = ownership_commitment     (bytes)                — skipped
    ///           field 15 = peer_throttles           (ClprThrottles sub-msg)— skipped
    ///           field 16 = trust_anchor             (bytes)                — skipped
    ///           field 17 = trust_anchor_id          (bytes)                — skipped
    ///           field 18 = remote_trust_anchor_id   (bytes)                — skipped
    ///           field 19 = endpoint_manifest        (ClprEndpointManifest sub-msg) — skipped
    ///           field 20 = endpoint_manifest_version (varint, uint64)
    ///         The fields the bundle verifier needs (3, 7, 8, 9, 10, 11, 12, 20)
    ///         are decoded; everything else is skipped at the wire-type
    ///         level to avoid copying their length-delimited bodies.
    function decodeChannelFromMemory(bytes memory data) internal pure returns (ClprTypes.Channel memory channel) {
        uint256 pos = 0;

        while (pos < data.length) {
            uint64 fieldNum;
            uint8 wireType;
            (fieldNum, wireType, pos) = PB.decodeFieldKey(data, pos);

            // Strict wire format: field 20 (`endpoint_manifest_version`) is the highest number this
            // ledger understands. Anything above it — or the invalid field 0 — rejects the bundle.
            if (fieldNum == 0 || fieldNum > 20) revert ClprTypes.ClprUnknownWireField(fieldNum);

            if (wireType == 0) {
                uint64 v;
                (v, pos) = PB.decodeVarint(data, pos);

                if (fieldNum == 7) {
                    if (v > uint64(uint8(type(ClprTypes.ChannelStatus).max))) {
                        revert ClprTypes.ClprBundleVerificationFailed();
                    }
                    // forge-lint: disable-next-line(unsafe-typecast)
                    channel.status = ClprTypes.ChannelStatus(uint8(v));
                } else if (fieldNum == 8) {
                    channel.nextMessageId = v;
                } else if (fieldNum == 9) {
                    channel.ackedMessageId = v;
                } else if (fieldNum == 11) {
                    channel.receivedMessageId = v;
                } else if (fieldNum == 20) {
                    channel.endpointManifestVersion = v;
                }
            } else if (wireType == 2) {
                if (fieldNum == 1) {
                    bytes memory val;
                    (val, pos) = PB.decodeLengthDelimited(data, pos);
                    if (val.length == 32) channel.channelId = _bytes32From(val);
                } else if (fieldNum == 3) {
                    (channel.peerServiceAddress, pos) = PB.decodeLengthDelimited(data, pos);
                } else if (fieldNum == 10) {
                    bytes memory val;
                    (val, pos) = PB.decodeLengthDelimited(data, pos);
                    if (val.length == 32) channel.sentRunningHash = _bytes32From(val);
                } else if (fieldNum == 12) {
                    bytes memory val;
                    (val, pos) = PB.decodeLengthDelimited(data, pos);
                    if (val.length == 32) channel.receivedRunningHash = _bytes32From(val);
                } else {
                    // Skip every other length-delimited field without copying
                    // its body — chain_id, verifier_contract,
                    // verifier_fingerprint, the two Timestamps,
                    // ownership_commitment, trust_anchor.
                    pos = PB.skipField(data, pos, wireType);
                }
            } else {
                pos = PB.skipField(data, pos, wireType);
            }
        }
    }

    function _bytes32From(bytes memory b) private pure returns (bytes32 out) {
        if (b.length != 32) return bytes32(0);
        assembly ("memory-safe") {
            out := mload(add(b, 32))
        }
    }
}
