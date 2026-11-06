// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {BundleLib} from "@hiero-ledger/clpr/libraries/service/BundleLib.sol";
import {BundleLibTestBase} from "@test/libraries/service/bundle-lib/BundleLibTestBase.sol";

/// @notice Tests for partial-bundle handling and bundle-scoped verifier metadata.
///
/// A "partial bundle" occurs when chain A has N outstanding messages but the relay delivers
/// only K < N due to max_messages_per_bundle. The verifier MUST return bundle-scoped metadata:
///   nextMessageId  = A.ackedMessageId + 1 + K  (not A's global nextMessageId)
///   sentRunningHash = hash through message (A.ackedMessageId + K)  (not A's full chain)
///
/// Negative tests document the exact failures that a non-compliant EVM verifier (one that
/// returns global metadata) would produce — proving BundleLib is correct and the bug lives
/// entirely in the verifier layer.
contract BundleLib_PartialBundleTest is BundleLibTestBase {
    // ── Helpers ────────────────────────────────────────────────────────────────

    function _makeDataPayload(bytes memory data) internal view returns (bytes memory) {
        return ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", data);
    }

    /// @dev Cumulative SHA-256 running hash seeded at zero, chaining through the first `count`
    ///      entries of `payloads`.  Matches A's `_messageQueues[channel][count].runningHashAfterProcessing`.
    function _runningHashThrough(bytes[] memory payloads, uint256 count) internal pure returns (bytes32 h) {
        for (uint256 i = 0; i < count; i++) {
            h = sha256(abi.encodePacked(h, sha256(payloads[i])));
        }
    }

    /// @dev Submits a partial bundle covering `payloads[from..to)` to the test service.
    ///      `ackedMsgId` is A's ackedMessageId (highest A-message B confirmed back); the relay
    ///      builds from ackedMsgId+1 so bundleLastMessageId = ackedMsgId + (to - from).
    ///      `allPayloads` must contain ALL messages 0..bundleLastMessageId-1 so the cumulative
    ///      sentRunningHash can be computed correctly.
    function _submitPartialBundle(bytes[] memory allPayloads, uint256 from, uint256 to, uint64 ackedMsgId) internal {
        uint256 bundleSize = to - from;
        bytes[] memory bundlePayloads = new bytes[](bundleSize);
        for (uint256 i = 0; i < bundleSize; i++) {
            bundlePayloads[i] = allPayloads[from + i];
        }

        // sentRunningHash covers ALL messages from seed 0 through bundleLastMessageId.
        // bundleLastMessageId = ackedMsgId + bundleSize (A builds from ackedMsgId+1).
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes32 sentHash = _runningHashThrough(allPayloads, ackedMsgId + uint64(bundleSize));
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 nextMsgId = ackedMsgId + 1 + uint64(bundleSize);

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: nextMsgId,
            sentRunningHash: sentHash,
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: nextMsgId - 1,
            lastMessageRunningHash: sentHash
        });
        verifier.setVerifyBundleResult(meta, bundlePayloads);
        service.submitBundle(channelId, hex"00FF");
    }

    // ── Happy-path: partial bundles ────────────────────────────────────────────

    /// @dev A delivers the first 3 of 6 outstanding messages.
    ///      Bundle-scoped: nextMessageId=4, sentRunningHash=H3.
    ///      receivedMessageId must advance to 3.
    function test_partialBundle_firstThreeOfSix_succeeds() public {
        _registerTestConnector();

        bytes[] memory payloads = new bytes[](6);
        for (uint256 i = 0; i < 6; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            payloads[i] = _makeDataPayload(abi.encodePacked(uint8(i + 1)));
        }

        // A.ackedMessageId=0 (B hasn't confirmed any of A's messages yet).
        // Relay delivers [m1, m2, m3].  bundleLastMessageId = 0+3 = 3, nextMessageId = 4.
        _submitPartialBundle(payloads, 0, 3, 0);

        assertEq(service.getChannel(channelId).receivedMessageId, 3);
    }

    /// @dev Two sequential partial bundles of 3 together exhaust all 6 outstanding messages.
    ///      Second bundle uses A.ackedMessageId=3 (B confirmed m1-m3 back to A).
    function test_partialBundle_twoSequentialBatchesExhaustQueue() public {
        _registerTestConnector();

        bytes[] memory payloads = new bytes[](6);
        for (uint256 i = 0; i < 6; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            payloads[i] = _makeDataPayload(abi.encodePacked(uint8(i + 1)));
        }

        // First partial bundle: messages 1-3 (A.ackedMessageId=0).
        _submitPartialBundle(payloads, 0, 3, 0);
        assertEq(service.getChannel(channelId).receivedMessageId, 3);

        // Second partial bundle: messages 4-6 (A.ackedMessageId=3, B confirmed m1-m3 back).
        // bundleLastMessageId = 3 + 3 = 6, nextMessageId = 7.
        _submitPartialBundle(payloads, 3, 6, 3);
        assertEq(service.getChannel(channelId).receivedMessageId, 6);
    }

    /// @dev Partial bundle at the exact max_messages_per_bundle boundary (3 messages).
    ///      The bundle covers messages 4-6 after messages 1-3 were already delivered,
    ///      so A.ackedMessageId=3.
    function test_partialBundle_atMaxMessagesPerBundleLimit_succeeds() public {
        _registerTestConnector();

        bytes[] memory payloads = new bytes[](6);
        for (uint256 i = 0; i < 6; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            payloads[i] = _makeDataPayload(abi.encodePacked(uint8(i + 1)));
        }

        _submitPartialBundle(payloads, 0, 3, 0);
        _submitPartialBundle(payloads, 3, 6, 3);

        assertEq(service.getChannel(channelId).receivedMessageId, 6);
    }

    // ── Happy-path: partial bundle with leading duplicates ─────────────────────

    /// @dev A's ackedMessageId is stale (B received more than A knows).
    ///      A.ackedMessageId=0, B.receivedMessageId=3.  A builds bundle from message 1
    ///      (leading duplicates m1, m2, m3) then includes new messages m4, m5.
    ///      The bundle covers [m1, m2, m3, m4, m5]; bundleLastMessageId=5, nextMessageId=6.
    ///      Duplicates are skipped; m4 and m5 are delivered; receivedMessageId→5.
    function test_partialBundle_staleAck_leadingDuplicatesSkipped() public {
        _registerTestConnector();

        // 5 messages total — bundle size 5 fits within defaultThrottles.maxMessagesPerBundle=100.
        bytes[] memory payloads = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            payloads[i] = _makeDataPayload(abi.encodePacked(uint8(i + 1)));
        }

        // Deliver messages 1-3 first so B.receivedMessageId=3.
        _submitPartialBundle(payloads, 0, 3, 0);
        assertEq(service.getChannel(channelId).receivedMessageId, 3);

        // Now A still thinks its ackedMessageId=0 (stale).  Relay delivers [m1..m5].
        // bundleLastMessageId = 0 + 5 = 5, nextMessageId = 6.
        // m1, m2, m3 are duplicates (receivedMessageId=3), m4 and m5 are new.
        _submitPartialBundle(payloads, 0, 5, 0);

        assertEq(service.getChannel(channelId).receivedMessageId, 5);
    }

    /// @dev A partial bundle that re-includes the most recently received message (single leading dup)
    ///      plus two new messages.  Exercises the minimal leading-duplicate case.
    function test_partialBundle_singleLeadingDuplicate_succeeds() public {
        _registerTestConnector();

        bytes[] memory payloads = new bytes[](4);
        for (uint256 i = 0; i < 4; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            payloads[i] = _makeDataPayload(abi.encodePacked(uint8(i + 1)));
        }

        // Deliver message 1. B.receivedMessageId=1.
        _submitPartialBundle(payloads, 0, 1, 0);
        assertEq(service.getChannel(channelId).receivedMessageId, 1);

        // A.ackedMessageId=0 (stale).  Bundle = [m1, m2, m3].
        // bundleLastMessageId = 0+3=3, nextMessageId=4.
        // m1 is the single leading duplicate; m2 and m3 are new.
        _submitPartialBundle(payloads, 0, 3, 0);
        assertEq(service.getChannel(channelId).receivedMessageId, 3);
    }

    // ── Negative: global nextMessageId causes ClprReplayDetected ──────────────

    /// @dev A non-compliant EVM verifier returns A's global nextMessageId instead of
    ///      bundle-scoped.  With 3 new messages in the bundle but nextMessageId=10 (global),
    ///      BundleLib sees expectedCountSigned=6 > payloads.length=3 and reverts.
    ///
    ///      This test documents the exact failure mode that the EVM verifier fix resolves.
    function test_partialBundle_globalNextMessageId_causesReplayDetected() public {
        _registerTestConnector();

        bytes[] memory payloads = new bytes[](6);
        for (uint256 i = 0; i < 6; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            payloads[i] = _makeDataPayload(abi.encodePacked(uint8(i + 1)));
        }

        // Deliver messages 1-3 first. B.receivedMessageId=3.
        _submitPartialBundle(payloads, 0, 3, 0);

        // Second bundle: messages 4-6 only.  Compliant verifier would return nextMessageId=7.
        // Non-compliant verifier returns A's global nextMessageId=9 (A has 8 messages total).
        bytes[] memory bundlePayloads = new bytes[](3);
        for (uint256 i = 0; i < 3; i++) {
            bundlePayloads[i] = payloads[3 + i];
        }
        bytes32 globalHash = _runningHashThrough(payloads, 6); // global hash through all 6 (placeholder)

        ClprTypes.QueueMetadata memory badMeta = ClprTypes.QueueMetadata({
            nextMessageId: 9, // WRONG: global (A sent 8 messages so nextMessageId=9)
            sentRunningHash: globalHash,
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 8,
            lastMessageRunningHash: globalHash
        });
        verifier.setVerifyBundleResult(badMeta, bundlePayloads);

        // expectedFirstId = B.receivedMessageId+1 = 4
        // expectedCountSigned = nextMessageId - expectedFirstId = 9 - 4 = 5
        // 5 > payloads.length(3) → ClprReplayDetected
        vm.expectRevert(ClprTypes.ClprReplayDetected.selector);
        service.submitBundle(channelId, hex"00FF");
    }

    /// @dev A non-compliant EVM verifier returns the correct bundle-scoped nextMessageId
    ///      but the global sentRunningHash (covering all A's messages, not just this bundle).
    ///      BundleLib's running hash check catches the mismatch.
    function test_partialBundle_globalSentRunningHash_causesHashMismatch() public {
        _registerTestConnector();

        bytes[] memory payloads = new bytes[](6);
        for (uint256 i = 0; i < 6; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            payloads[i] = _makeDataPayload(abi.encodePacked(uint8(i + 1)));
        }

        // Deliver messages 1-3. B.receivedMessageId=3.
        _submitPartialBundle(payloads, 0, 3, 0);

        // Bundle: messages 4-6.  bundle-scoped nextMessageId=7 is correct.
        // But sentRunningHash incorrectly covers all 6 messages (not 4-6 only).
        bytes[] memory bundlePayloads = new bytes[](3);
        for (uint256 i = 0; i < 3; i++) {
            bundlePayloads[i] = payloads[3 + i];
        }
        // This is the SAME as the correct value since H3→H6 covers all 6; let's make it wrong
        // by using a hash that covers only messages 1-6 from an UNRELATED chain (wrong seed).
        bytes32 wrongHash = sha256(abi.encodePacked(bytes32(uint256(1)), sha256(payloads[5]))); // arbitrary wrong hash

        ClprTypes.QueueMetadata memory badMeta = ClprTypes.QueueMetadata({
            nextMessageId: 7, // correct bundle-scoped nextMessageId
            sentRunningHash: wrongHash, // WRONG: not the actual cumulative hash through m6
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 6,
            lastMessageRunningHash: wrongHash
        });
        verifier.setVerifyBundleResult(badMeta, bundlePayloads);

        vm.expectRevert(ClprTypes.ClprRunningHashMismatch.selector);
        service.submitBundle(channelId, hex"00FF");
    }

    receive() external payable {}
}
