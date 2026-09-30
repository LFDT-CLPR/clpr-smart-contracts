// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {StubClprVerifier} from "@test/mocks/StubClprVerifier.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";

/// @title StubClprVerifierTest
/// @notice First-party round-trip tests for StubClprVerifier.
///         Encodes bundle content via ClprProtobuf, prefixes with "CLPRSTUB",
///         and asserts that StubClprVerifier.verifyBundle decodes the result
///         identically to what was encoded.
contract StubClprVerifierTest is Test {
    StubClprVerifier internal verifier;

    bytes8 private constant STUB_PREFIX = "CLPRSTUB";

    function setUp() public {
        verifier = new StubClprVerifier();
    }

    // ── helpers

    /// @dev Prepend the 8-byte CLPRSTUB magic string to encoded bundle content.
    function _buildProofBytes(bytes memory bundleContent) internal pure returns (bytes memory) {
        return abi.encodePacked(STUB_PREFIX, bundleContent);
    }

    // ── round-trip tests

    /// @notice Encode a QueueMetadata + two payloads, pass through StubClprVerifier,
    ///         assert every field decodes back identically.
    function test_roundTrip_metadataAndPayloads() public view {
        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 7,
            sentRunningHash: bytes32(uint256(0xDEADBEEF)),
            receivedMessageId: 3,
            receivedRunningHash: bytes32(uint256(0xCAFEBABE)),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 6,
            lastMessageRunningHash: bytes32(uint256(0xDEADBEEF))
        });

        bytes[] memory payloads = new bytes[](2);
        payloads[0] = ClprProtobuf.encodeDataMessage(
            hex"AABB", // connectorId
            hex"CCDD", // targetApplication
            hex"EEFF", // sender
            hex"11223344" // messageData
        );
        payloads[1] = ClprProtobuf.encodeReplyMessage(2, ClprTypes.ReplyStatus.SUCCESS, hex"DEADBEEF");

        bytes memory bundleContent = ClprProtobuf.encodeBundleContent(meta, payloads);
        bytes memory proofBytes = _buildProofBytes(bundleContent);

        (ClprTypes.QueueMetadata memory outMeta, bytes[] memory outPayloads, bytes memory anchor,,) =
            verifier.verifyBundle(proofBytes, "", "");

        assertEq(outMeta.nextMessageId, meta.nextMessageId);
        assertEq(outMeta.sentRunningHash, meta.sentRunningHash);
        assertEq(outMeta.receivedMessageId, meta.receivedMessageId);
        assertEq(outMeta.receivedRunningHash, meta.receivedRunningHash);
        assertEq(uint8(outMeta.state), uint8(meta.state));

        assertEq(outPayloads.length, payloads.length);
        assertEq(outPayloads[0], payloads[0]);
        assertEq(outPayloads[1], payloads[1]);

        assertEq(anchor.length, 0);
    }

    /// @notice Encode with zero payloads (metadata-only bundle).
    function test_roundTrip_noPayloads() public view {
        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(uint256(1)),
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.CLOSING,
            endpointManifestVersion: 0,
            lastMessageId: 0,
            lastMessageRunningHash: bytes32(uint256(1))
        });

        bytes[] memory payloads = new bytes[](0);
        bytes memory proofBytes = _buildProofBytes(ClprProtobuf.encodeBundleContent(meta, payloads));

        (ClprTypes.QueueMetadata memory outMeta, bytes[] memory outPayloads, bytes memory anchor,,) =
            verifier.verifyBundle(proofBytes, "", "");

        assertEq(outMeta.nextMessageId, meta.nextMessageId);
        assertEq(outMeta.sentRunningHash, meta.sentRunningHash);
        assertEq(outMeta.receivedMessageId, meta.receivedMessageId);
        assertEq(uint8(outMeta.state), uint8(meta.state));
        assertEq(outPayloads.length, 0);
        assertEq(anchor.length, 0);
    }

    /// @notice Encode with multiple payloads including a CONTROL message.
    function test_roundTrip_multiplePayloadTypes() public view {
        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 20,
            sentRunningHash: bytes32(keccak256("sentHash")),
            receivedMessageId: 15,
            receivedRunningHash: bytes32(keccak256("rcvdHash")),
            state: ClprTypes.ChannelStatus.PAUSED,
            endpointManifestVersion: 0,
            lastMessageId: 19,
            lastMessageRunningHash: bytes32(keccak256("sentHash"))
        });

        bytes[] memory payloads = new bytes[](3);
        payloads[0] = ClprProtobuf.encodeDataMessage(hex"01", hex"02", hex"03", hex"04");
        payloads[1] = ClprProtobuf.encodeReplyMessage(5, ClprTypes.ReplyStatus.APPLICATION_ERROR, hex"");
        payloads[2] = ClprProtobuf.encodeDataMessage(hex"0A0B", hex"0C0D", hex"0E0F", hex"10111213");

        bytes memory proofBytes = _buildProofBytes(ClprProtobuf.encodeBundleContent(meta, payloads));

        (ClprTypes.QueueMetadata memory outMeta, bytes[] memory outPayloads,,,) =
            verifier.verifyBundle(proofBytes, "", "");

        assertEq(outMeta.nextMessageId, meta.nextMessageId);
        assertEq(outMeta.receivedMessageId, meta.receivedMessageId);
        assertEq(uint8(outMeta.state), uint8(meta.state));

        assertEq(outPayloads.length, 3);
        assertEq(outPayloads[0], payloads[0]);
        assertEq(outPayloads[1], payloads[1]);
        assertEq(outPayloads[2], payloads[2]);
    }

    /// @notice Missing CLPRSTUB prefix reverts.
    function test_missingPrefix_reverts() public {
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
        bytes[] memory payloads = new bytes[](0);
        bytes memory bundleContent = ClprProtobuf.encodeBundleContent(meta, payloads);

        // No prefix — should revert
        vm.expectRevert(bytes("StubVerifier: missing CLPRSTUB prefix"));
        verifier.verifyBundle(bundleContent, "", "");
    }

    /// @notice Wrong prefix reverts.
    function test_wrongPrefix_reverts() public {
        // casting to 'bytes8' is safe because BADPREFIX is 8 bytes long and is used only to demonstrate the wrong prefix.
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes memory proofBytes = abi.encodePacked(bytes8("BADPREFI"), hex"00");
        vm.expectRevert(bytes("StubVerifier: missing CLPRSTUB prefix"));
        verifier.verifyBundle(proofBytes, "", "");
    }

    /// @notice verifyConfig returns the pre-configured values set via setters.
    function test_verifyConfig_returnsPreconfiguredValues() public {
        verifier.setVerifyConfigResult("eip155:1337", hex"AABBCC", 9999);

        (, string memory chainId, bytes memory svc, uint96 ts,,,,) = verifier.verifyConfig("", bytes32(0), "");
        assertEq(chainId, "eip155:1337");
        assertEq(svc, hex"AABBCC");
        assertEq(ts, 9999);
    }

    function test_verifyConfig_havingPeerThrottles() public {
        ClprTypes.Throttles memory t = ClprTypes.Throttles({
            maxMessagesPerBundle: 11,
            maxMessagePayloadBytes: 3333,
            maxGasPerMessage: 4444,
            maxQueueDepth: 55,
            maxSyncBytes: 666666,
            maxLocalEndpoints: 0,
            maxPeerEndpoints: 0
        });
        verifier.setPeerThrottles(t);

        (,,,, ClprTypes.Throttles memory out,,,) = verifier.verifyConfig("", bytes32(0), "");
        assertEq(out.maxMessagesPerBundle, t.maxMessagesPerBundle);
        assertEq(out.maxMessagePayloadBytes, t.maxMessagePayloadBytes);
        assertEq(out.maxGasPerMessage, t.maxGasPerMessage);
        assertEq(out.maxQueueDepth, t.maxQueueDepth);
        assertEq(out.maxSyncBytes, t.maxSyncBytes);
    }

    function test_verifyConfig_havingInitialTrustAnchor() public {
        bytes memory anchor = hex"DEADBEEFCAFEBABE";
        verifier.setInitialTrustAnchor(anchor);

        (,,,,, bytes memory outAnchor,,) = verifier.verifyConfig("", bytes32(0), "");
        assertEq(outAnchor, anchor);
    }

    function test_verifyConfig_havingEndpoints() public {
        ClprTypes.Endpoint[] memory eps = new ClprTypes.Endpoint[](2);
        eps[0] = ClprTypes.Endpoint({
            ipAddress: string(abi.encodePacked("192.168.0.", "1")),
            port: 1234,
            tlsCertificate: hex"01",
            accountId: hex"AA"
        });
        eps[1] = ClprTypes.Endpoint({
            ipAddress: string(abi.encodePacked("10.0.0.", "2")), port: 4321, tlsCertificate: hex"02", accountId: hex"BB"
        });

        verifier.setSeedEndpoints(eps);

        (,,,,,,, ClprTypes.ClprEndpointManifest memory out) = verifier.verifyConfig("", bytes32(0), "");
        assertEq(out.endpoints.length, eps.length);
        // endpoint 0
        assertEq(keccak256(bytes(out.endpoints[0].ipAddress)), keccak256(bytes(eps[0].ipAddress)));
        assertEq(out.endpoints[0].port, eps[0].port);
        assertEq(out.endpoints[0].tlsCertificate, eps[0].tlsCertificate);
        assertEq(out.endpoints[0].accountId, eps[0].accountId);
        // endpoint 1
        assertEq(keccak256(bytes(out.endpoints[1].ipAddress)), keccak256(bytes(eps[1].ipAddress)));
        assertEq(out.endpoints[1].port, eps[1].port);
        assertEq(out.endpoints[1].tlsCertificate, eps[1].tlsCertificate);
        assertEq(out.endpoints[1].accountId, eps[1].accountId);
    }
}
