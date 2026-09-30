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
import {ConnectorRegistrar} from "@test/helpers/ConnectorRegistrar.sol";
import {ClprTestBase} from "@test/helpers/ClprTestBase.sol";

/// @notice Base contract for BundleLogic test suites.
///         Extends ClprTestBase with connector registration and bundle submission helpers.
abstract contract BundleLogicTestBase is ClprTestBase {
    function setUp() public virtual override {
        super.setUp();
    }

    // ── Connector registration helper

    function _registerTestConnector() internal override {
        connectorId = ConnectorRegistrar.register(
            IClprService(address(service)),
            channelId,
            keccak256(abi.encodePacked("test-connector")),
            address(connector),
            owner,
            0.5 ether
        );
    }

    // ── Bundle submission helpers

    /// @dev Submit a single inbound message. Computes hash and configures verifier.
    function _submitSingleInboundMessage(bytes memory payload) internal {
        bytes[] memory msgs = new bytes[](1);
        msgs[0] = payload;
        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(payload)));

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
        bytes memory proofBytes = hex"00FF";
        service.submitBundle(channelId, proofBytes);
    }

    /// @dev Submit a bundle. Convenience wrapper.
    function _submitBundle(bytes memory proofBytes) internal {
        service.submitBundle(channelId, proofBytes);
    }

    function _makeConfig(uint64 timestamp) internal pure returns (ClprTypes.LedgerConfiguration memory config) {
        // Must match the protocolVersion the test harness deploys with (ClprTestBase:
        // _deployClprService(1, ...)), or ConfigUpdate processing rejects it as a
        // protocol version mismatch.
        config.protocolVersion = 1;
        config.nanosSinceEpoch = uint96(timestamp) * 1_000_000_000;
        config.throttles = ClprTypes.Throttles({
            maxMessagesPerBundle: 100,
            maxMessagePayloadBytes: 1024,
            maxGasPerMessage: 1_000_000,
            maxQueueDepth: 1000,
            maxSyncBytes: 1_048_576,
            maxLocalEndpoints: 0,
            maxPeerEndpoints: 0
        });
    }

    function _dummyEndpointKey() internal pure override returns (bytes memory) {
        return abi.encodePacked(
            uint256(0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20),
            uint256(0x2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40)
        );
    }

    receive() external payable virtual {}
}
