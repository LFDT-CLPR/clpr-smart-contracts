// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {MockClprVerifier} from "@test/mocks/MockClprVerifier.sol";
import {IntegrationTestBase} from "@test/integration/IntegrationTestBase.sol";

/// @dev Integration test exercising the full CLPR lifecycle with MockClprVerifier.
///      MockClprVerifier returns canned verifyBundle results — no crypto verification.
///      Use this to validate service-side message flow, reply queuing, and state transitions.
contract IntegrationMockTest is IntegrationTestBase {
    function setUp() public override {
        _setUp();
        _deployServiceAndConnect(address(verifier));
    }

    // ═══════════════════════════════════════════════════════════════════
    // Full lifecycle: register connector → send → receive bundle → close
    // ═══════════════════════════════════════════════════════════════════

    function test_fullLifecycle() public {
        uint64 outboundMsgId = _registerConnectorAndSend();
        assertEq(outboundMsgId, 1, "first outbound message");

        // Build inbound bundle: DATA + REPLY
        bytes32 hash1 = sha256(abi.encodePacked(bytes32(0), sha256(_getDataPayload())));
        bytes32 hash2 = sha256(abi.encodePacked(hash1, sha256(_getReplyPayload())));

        bytes[] memory inboundMsgs = _buildInboundBundles(1);

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 3,
            sentRunningHash: hash2,
            receivedMessageId: 1,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 2,
            lastMessageRunningHash: hash2
        });
        verifier.setVerifyBundleResult(meta, inboundMsgs);

        // Submit and verify
        service.submitBundle(channelId, hex"DEADBEEF");

        _verifyPostBundle(1, 3, hex"48454C4C4F", 2, 2, 1, ClprTypes.ChannelStatus.ACTIVE);
        _closeChannel();
    }

    function _getDataPayload() internal view returns (bytes memory) {
        return ClprProtobuf.encodeDataMessage(
            IntegrationTestBase.connectorAddr,
            abi.encodePacked(address(IntegrationTestBase.app)),
            hex"BEEF0102",
            hex"48454C4C4F"
        );
    }

    function _getReplyPayload() internal pure returns (bytes memory) {
        return ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"504F4E47524550");
    }
}
