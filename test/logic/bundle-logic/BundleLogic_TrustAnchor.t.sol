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

contract BundleLogic_TrustAnchor is BundleLogicTestBase {
    MockClprApplication public app;

    function setUp() public override {
        super.setUp();
        app = new MockClprApplication();
        app.setResponse(hex"504F4E47"); // "PONG"
    }

    // ── Edge case - Trust anchor only progress

    function test_bundleProgress_trustAnchorOnly() public {
        // Submit bundle with no messages, no acks, no state change - only trust anchor
        bytes[] memory msgs = new bytes[](0);
        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE, // same state
            endpointManifestVersion: 0,
            lastMessageId: 0,
            lastMessageRunningHash: bytes32(0)
        });
        verifier.setVerifyBundleResult(meta, msgs);
        verifier.setNewTrustAnchor(hex"ABCD1234"); // only progress is trust anchor
        _submitBundle(hex"00FF");

        // Should succeed (not revert with NoProgress)
        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE));
    }

    // ── Edge case - Invalid progress (no changes at all)

    function test_bundleProgress_noProgressAtAll_reverts() public {
        // Submit bundle with no messages, no acks, no state change, no trust anchor
        bytes[] memory msgs = new bytes[](0);
        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 1,
            sentRunningHash: bytes32(0),
            receivedMessageId: 0,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE, // same state
            endpointManifestVersion: 0,
            lastMessageId: 0,
            lastMessageRunningHash: bytes32(0)
        });
        verifier.setVerifyBundleResult(meta, msgs);
        // No trust anchor advancement (verifier returns empty bytes by default)

        vm.expectRevert(BundleLib.NoProgress.selector);
        _submitBundle(hex"00FF");
    }

    // ── Trust anchor: finality-only bundle advances anchor in channel

    function test_finalityOnlyBundle_advancesTrustAnchor() public {
        bytes memory newAnchor = hex"CAFEBABE";
        bytes[] memory emptyMsgs = new bytes[](0);

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
        verifier.setVerifyBundleResult(meta, emptyMsgs);
        verifier.setNewTrustAnchor(newAnchor);

        _submitBundle(hex"00");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(channel.trustAnchor, newAnchor);
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE));
    }

    function test_dataBundleWithTrustAnchorRotation_advancesAnchor() public {
        _registerTestConnector();

        bytes memory newAnchor = hex"DEADC0DE";
        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");
        bytes[] memory msgs = new bytes[](1);
        msgs[0] = dataPayload;
        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(dataPayload)));

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
        verifier.setNewTrustAnchor(newAnchor);

        _submitBundle(hex"00FF");

        ClprTypes.Channel memory channel = service.getChannel(channelId);
        assertEq(channel.trustAnchor, newAnchor);
        assertEq(channel.receivedMessageId, 1);
    }

    receive() external payable override {}
}
