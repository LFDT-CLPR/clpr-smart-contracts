// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTestBase} from "@test/helpers/ClprTestBase.sol";
import {MockClprApplication} from "@test/mocks/MockClprApplication.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";

abstract contract BundleLibTestBase is ClprTestBase {
    MockClprApplication public app;

    function setUp() public virtual override {
        super.setUp();
        app = new MockClprApplication();
        app.setResponse(hex"504F4E47"); // "PONG"
    }

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
}
