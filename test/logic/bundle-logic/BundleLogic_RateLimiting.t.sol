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

contract BundleLogic_RateLimiting is BundleLogicTestBase {
    MockClprApplication public app;

    function setUp() public override {
        super.setUp();
        app = new MockClprApplication();
        app.setResponse(hex"504F4E47"); // "PONG"
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

    receive() external payable override {}
}
