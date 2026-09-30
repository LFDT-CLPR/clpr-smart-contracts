// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {BundleLib} from "@hiero-ledger/clpr/libraries/service/BundleLib.sol";
import {MockClprApplication} from "@test/mocks/MockClprApplication.sol";
import {MockClprConnector} from "@test/mocks/MockClprConnector.sol";
import {ClprTestBase} from "@test/helpers/ClprTestBase.sol";
import {BundleLibTestBase} from "@test/libraries/service/bundle-lib/BundleLibTestBase.sol";

contract BundleLib_ValidationTest is BundleLibTestBase {
    // ── Test 2: Verifier failure

    function test_verifierFailure_reverts() public {
        verifier.setShouldRevert(true, "Bad proof");

        vm.expectRevert("Bad proof");
        _submitBundle(hex"BAAD");
    }

    // ── Test 4: Running hash mismatch

    function test_runningHashMismatch_reverts() public {
        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");

        bytes[] memory msgs = new bytes[](1);
        msgs[0] = dataPayload;

        // Set wrong running hash
        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 2,
            sentRunningHash: bytes32(uint256(0xDEAD)), // wrong hash
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 1,
            lastMessageRunningHash: bytes32(uint256(0xDEAD))
        });
        verifier.setVerifyBundleResult(meta, msgs);

        vm.expectRevert(ClprTypes.ClprRunningHashMismatch.selector);
        _submitBundle(hex"00FF");
    }

    // ── Test 5: Ack verification -- acking unsent messages

    function test_ackVerification_ackingUnsentMessages_reverts() public {
        bytes[] memory msgs = new bytes[](0);

        // Try to ack messageId 5 when nextMessageId is 1 (nothing sent)
        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 5, // acking unsent
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 0,
            lastMessageRunningHash: bytes32(0)
        });
        verifier.setVerifyBundleResult(meta, msgs);

        vm.expectRevert(ClprTypes.ClprAckVerificationFailed.selector);
        _submitBundle(hex"00FF");
    }

    // ── Additional: Bundle size check

    function test_bundleTooLarge_reverts() public {
        // maxSyncBytes is 1_048_576. Create proof larger than that.
        bytes memory bigProof = new bytes(1_048_577);

        // The verifier won't be called, so no need to configure it
        // But we need to ensure the revert happens before verifier call
        vm.expectRevert(BundleLib.BundleTooLarge.selector);
        _submitBundle(bigProof);
    }

    // ── Additional: Too many messages in bundle

    function test_tooManyMessages_reverts() public {
        // maxMessagesPerBundle is 100
        bytes[] memory tooMany = new bytes[](101);
        for (uint64 i = 0; i < 101; i++) {
            tooMany[i] = ClprProtobuf.encodeControlMessage(_makeConfig(uint64(1000 + i)));
        }

        // Compute hash chain
        bytes32 hash = bytes32(0);
        for (uint256 i = 0; i < 101; i++) {
            hash = sha256(abi.encodePacked(hash, sha256(tooMany[i])));
        }

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 102,
            sentRunningHash: hash,
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 101,
            lastMessageRunningHash: hash
        });
        verifier.setVerifyBundleResult(meta, tooMany);

        vm.expectRevert(BundleLib.TooManyMessages.selector);
        _submitBundle(hex"00FF");
    }

    // ── Per-message payload size enforcement

    function test_messagePayloadTooLarge_reverts() public {
        // maxMessagePayloadBytes is 1024; a 1025-byte payload must be rejected
        bytes memory oversized = new bytes(1025);
        bytes[] memory msgs = new bytes[](1);
        msgs[0] = oversized;

        // sentRunningHash is irrelevant — we revert before the hash check
        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 2,
            sentRunningHash: bytes32(0),
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 1,
            lastMessageRunningHash: bytes32(0)
        });
        verifier.setVerifyBundleResult(meta, msgs);

        vm.expectRevert(ClprTypes.ClprPayloadTooLarge.selector);
        _submitBundle(hex"00FF");
    }

    function test_messagePayloadAtLimit_accepted() public {
        _registerTestConnector();

        // maxMessagePayloadBytes is 1024; a payload of exactly 1024 bytes must pass the size
        // check (it will still fail the running-hash check, but that is a separate guard)
        bytes memory atLimit = new bytes(1024);
        bytes[] memory msgs = new bytes[](1);
        msgs[0] = atLimit;

        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(atLimit)));
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

        // Does NOT revert with ClprPayloadTooLarge; may revert for another reason (e.g. bad
        // message type), but the payload-size gate must be passed
        bytes memory _proof668 = hex"00FF";
        try service.submitBundle(channelId, _proof668) {}
        catch (bytes memory err) {
            assertFalse(
                // casting to 'bytes4' is safe because that retrieves the error selector
                // forge-lint: disable-next-line(unsafe-typecast)
                bytes4(err) == ClprTypes.ClprPayloadTooLarge.selector,
                "at-limit payload should not trigger ClprPayloadTooLarge"
            );
        }
    }

    // ── Additional: Empty bundle (zero messages) with ack

    function test_emptyBundle_withZeroAck() public {
        bytes[] memory msgs = new bytes[](0);

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
        verifier.setVerifyBundleResult(meta, msgs);
        // _newTrustAnchor defaults to "" in mock, receivedMessageId == ackedMessageId == 0
        // → nothing accomplished → NoProgress revert

        vm.expectRevert(BundleLib.NoProgress.selector);
        _submitBundle(hex"00FF");
    }

    function test_submitBundle_unknownChannelId_reverts() public {
        bytes32 unknownConn = keccak256("no-such-channel");
        vm.expectRevert(ClprTypes.ClprChannelNotFound.selector);
        service.submitBundle(unknownConn, hex"00FF");
    }

    /// @dev `if (newAcked < oldAcked) revert ClprAckVerificationFailed()`
    ///      Bundle 1 advances ackedMessageId to 1 by delivering a REPLY for our DATA #1.
    ///      Bundle 2 supplies receivedMessageId=0 (< 1) with a new trust anchor to pass
    ///      the NoProgress check.
    function test_submitBundle_ackGoesBackward_reverts() public {
        _registerTestConnector();
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"AABB");
        // channel.nextMessageId=2, channel.nextExpectedReplyId=1

        // Bundle 1: peer sends REPLY for DATA #1 (satisfies ordering) and acks it.
        bytes memory replyPayload = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"");
        bytes32 hash1 = sha256(abi.encodePacked(bytes32(0), sha256(replyPayload)));
        {
            bytes[] memory msgs = new bytes[](1);
            msgs[0] = replyPayload;
            ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
                nextMessageId: 2,
                sentRunningHash: hash1,
                receivedMessageId: 1,
                receivedRunningHash: bytes32(0),
                state: ClprTypes.ChannelStatus.ACTIVE,
                endpointManifestVersion: 0,
                lastMessageId: 1,
                lastMessageRunningHash: hash1
            });
            verifier.setVerifyBundleResult(meta, msgs);
            _submitBundle(hex"A1");
        }
        // channel.ackedMessageId=1, channel.receivedMessageId=1

        // Bundle 2: trust anchor passes NoProgress; receivedMessageId=0 < ackedMessageId=1.
        verifier.setNewTrustAnchor(hex"02");
        {
            bytes[] memory msgs = new bytes[](0);
            ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
                nextMessageId: 2, // peer still at 2 total messages
                sentRunningHash: hash1, // same hash, no new messages
                receivedMessageId: 0, // backward: < channel.ackedMessageId=1
                receivedRunningHash: bytes32(0),
                state: ClprTypes.ChannelStatus.ACTIVE,
                endpointManifestVersion: 0,
                lastMessageId: 1,
                lastMessageRunningHash: hash1
            });
            verifier.setVerifyBundleResult(meta, msgs);
            vm.expectRevert(ClprTypes.ClprAckVerificationFailed.selector);
            _submitBundle(hex"A2");
        }
    }

    receive() external payable {}
}
