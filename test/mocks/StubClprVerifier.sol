// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";

/// @title StubClprVerifier
/// @notice Verifier for integration tests that decodes real CLPRSTUB-prefixed protobuf
///         bundle proofs emitted by StubProofConstructor. No cryptographic verification
///         is performed — the proof bytes ARE the bundle content.
///
/// @dev Wire format: "CLPRSTUB" (8 bytes) || protobuf(ClprBundleContent)
///
///      ClprBundleContent proto fields:
///        field 1 (LEN): ClprQueueMetadata
///        field 2 (LEN): repeated ClprMessagePayload (raw payload bytes)
///
///      ClprQueueMetadata proto fields:
///        field 1 (VARINT): next_message_id  → QueueMetadata.nextMessageId
///        field 2 (LEN):    sent_running_hash (32 bytes) → QueueMetadata.sentRunningHash
///        field 3 (VARINT): received_message_id → QueueMetadata.receivedMessageId
///        field 4 (LEN):    received_running_hash (32 bytes) → QueueMetadata.receivedRunningHash
///        field 5 (VARINT): state (enum) → QueueMetadata.state
///
///      ClprQueueMetadata has no last-message fields, so a message-bearing bundle is taken to end at
///      the sender's latest message: lastMessageId = nextMessageId - 1, lastMessageRunningHash =
///      sentRunningHash (the same fallback as ClprProtobuf.decodeBundleContent).
contract StubClprVerifier is IClprVerifier {
    bytes8 private constant STUB_PREFIX = "CLPRSTUB";

    // Pre-configured values returned by verifyConfig().
    // TODO: replace with real ClprLedgerConfiguration protobuf parsing.
    string private _chainId;
    bytes private _serviceAddress;
    uint96 private _peerConfigNanos;
    ClprTypes.Throttles private _peerThrottles;
    bytes private _initialTrustAnchor;
    bytes private _initialTrustAnchorId;
    ClprTypes.Endpoint[] private _seedEndpoints;

    /// @notice Configure the values returned by verifyConfig(). Call once during test setup.
    function setVerifyConfigResult(string memory chainId, bytes memory serviceAddress, uint96 peerConfigNanos)
        external
    {
        _chainId = chainId;
        _serviceAddress = serviceAddress;
        _peerConfigNanos = peerConfigNanos;
    }

    /// @notice Configure peer throttles returned by verifyConfig().
    function setPeerThrottles(ClprTypes.Throttles memory throttles) external {
        _peerThrottles = throttles;
    }

    /// @notice Configure initial trust anchor returned by verifyConfig().
    function setInitialTrustAnchor(bytes memory initialTrustAnchor) external {
        _initialTrustAnchor = initialTrustAnchor;
    }

    /// @notice Configure initial trust anchor id returned by verifyConfig().
    function setInitialTrustAnchorId(bytes memory initialTrustAnchorId) external {
        _initialTrustAnchorId = initialTrustAnchorId;
    }

    /// @notice Configure seed endpoints returned by verifyConfig().
    /// @dev Deliberately does NOT run validation - purpose of this stub is to allow
    //       injecting arbitrary data, no matter if correct or not.
    function setSeedEndpoints(ClprTypes.Endpoint[] memory endpoints) external {
        delete _seedEndpoints;
        for (uint256 i = 0; i < endpoints.length; i++) {
            _seedEndpoints.push(endpoints[i]);
        }
    }

    /// @inheritdoc IClprVerifier
    function verifyBundle(bytes calldata proofBytes, bytes calldata, bytes calldata)
        external
        pure
        override
        returns (
            ClprTypes.QueueMetadata memory metadata,
            bytes[] memory messagePayloads,
            bytes memory newTrustAnchor,
            bytes memory newTrustAnchorId,
            ClprTypes.ClprEndpointManifest memory newEndpointManifest
        )
    {
        newEndpointManifest.endpoints = new ClprTypes.Endpoint[](0); // absent (version 0)
        require(proofBytes.length >= 8, "StubVerifier: missing CLPRSTUB prefix");
        bytes memory data = proofBytes; // calldata -> memory copy

        // Verify the 8-byte magic prefix.
        bytes8 prefix;
        assembly {
            prefix := mload(add(data, 32))
        }
        require(prefix == STUB_PREFIX, "StubVerifier: missing CLPRSTUB prefix");

        (metadata, messagePayloads) = _decodeClprBundleContent(data, 8);
        if (messagePayloads.length > 0 && metadata.nextMessageId > 0) {
            metadata.lastMessageId = metadata.nextMessageId - 1;
            metadata.lastMessageRunningHash = metadata.sentRunningHash;
        }
        newTrustAnchorId = new bytes(0);
        newTrustAnchor = new bytes(0);
    }

    /// @inheritdoc IClprVerifier
    function verifyConfig(bytes calldata, bytes32 channelId, bytes calldata)
        external
        view
        override
        returns (
            bytes memory channelContext,
            string memory,
            bytes memory,
            uint96,
            ClprTypes.Throttles memory,
            bytes memory,
            bytes memory,
            ClprTypes.ClprEndpointManifest memory
        )
    {
        // TODO: parse real ClprLedgerConfiguration protobuf instead of returning pre-configured values.
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: _serviceAddress})
        );
        ClprTypes.ClprEndpointManifest memory manifest =
            ClprTypes.ClprEndpointManifest({version: 1, serviceAddress: _serviceAddress, endpoints: _seedEndpoints});
        return (
            channelContext,
            _chainId,
            _serviceAddress,
            _peerConfigNanos,
            _peerThrottles,
            _initialTrustAnchor,
            _initialTrustAnchorId,
            manifest
        );
    }

    /// @dev Decode a ClprBundleContent starting at `startOffset` in `data`.
    ///      Two-pass: first count repeated message fields, then fill arrays.
    function _decodeClprBundleContent(bytes memory data, uint256 startOffset)
        private
        pure
        returns (ClprTypes.QueueMetadata memory metadata, bytes[] memory messages)
    {
        // Pass 1: count message payloads and confirm metadata field present.
        uint256 msgCount = 0;
        bool hasMetadata = false;
        uint256 off = startOffset;

        while (off < data.length) {
            uint64 fieldNumber;
            uint8 wireType;
            (fieldNumber, wireType, off) = PB.decodeFieldKey(data, off);
            if (fieldNumber == 1 && wireType == 2) hasMetadata = true;
            if (fieldNumber == 2 && wireType == 2) msgCount++;
            off = PB.skipField(data, off, wireType);
        }
        require(hasMetadata, "StubVerifier: metadata field missing");

        // Pass 2: decode metadata struct and collect message payload bytes.
        messages = new bytes[](msgCount);
        uint256 msgIdx = 0;
        off = startOffset;

        while (off < data.length) {
            uint64 fieldNumber;
            uint8 wireType;
            (fieldNumber, wireType, off) = PB.decodeFieldKey(data, off);

            if (fieldNumber == 1 && wireType == 2) {
                bytes memory metaBytes;
                (metaBytes, off) = PB.decodeLengthDelimited(data, off);
                metadata = _decodeQueueMetadata(metaBytes);
            } else if (fieldNumber == 2 && wireType == 2) {
                (messages[msgIdx], off) = PB.decodeLengthDelimited(data, off);
                msgIdx++;
            } else {
                off = PB.skipField(data, off, wireType);
            }
        }
    }

    /// @dev Decode a ClprQueueMetadata protobuf blob.
    function _decodeQueueMetadata(bytes memory data) private pure returns (ClprTypes.QueueMetadata memory meta) {
        uint256 off = 0;

        while (off < data.length) {
            uint64 fieldNumber;
            uint8 wireType;
            (fieldNumber, wireType, off) = PB.decodeFieldKey(data, off);

            if (fieldNumber == 1 && wireType == 0) {
                (meta.nextMessageId, off) = PB.decodeVarint(data, off);
            } else if (fieldNumber == 2 && wireType == 2) {
                bytes memory hashBytes;
                (hashBytes, off) = PB.decodeLengthDelimited(data, off);
                require(hashBytes.length == 32, "StubVerifier: running hash must be 32 bytes");
                bytes32 h;
                assembly {
                    h := mload(add(hashBytes, 32))
                }
                meta.sentRunningHash = h;
            } else if (fieldNumber == 3 && wireType == 0) {
                (meta.receivedMessageId, off) = PB.decodeVarint(data, off);
            } else if (fieldNumber == 4 && wireType == 2) {
                bytes memory hashBytes;
                (hashBytes, off) = PB.decodeLengthDelimited(data, off);
                require(hashBytes.length == 32, "StubVerifier: running hash must be 32 bytes");
                bytes32 h;
                assembly {
                    h := mload(add(hashBytes, 32))
                }
                meta.receivedRunningHash = h;
            } else if (fieldNumber == 5 && wireType == 0) {
                uint64 val;
                (val, off) = PB.decodeVarint(data, off);
                meta.state = ClprTypes.ChannelStatus(val);
            } else {
                off = PB.skipField(data, off, wireType);
            }
        }
    }
}
