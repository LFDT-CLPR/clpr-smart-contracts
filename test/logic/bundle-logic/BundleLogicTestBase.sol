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

    // ── Payload and mock-verifier helpers (test/security/)

    /// @dev `n` distinct DATA payloads (ids 1..n by construction order), suitable for chaining
    ///      into a running hash via `_runningHashThrough`.
    function _payloads(uint256 n) internal view returns (bytes[] memory payloads) {
        payloads = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            payloads[i] = ClprProtobuf.encodeDataMessage(
                connectorId,
                abi.encodePacked(address(connector)),
                // forge-lint: disable-next-line(unsafe-typecast)
                abi.encodePacked(uint32(i + 1)),
                // forge-lint: disable-next-line(unsafe-typecast)
                abi.encodePacked("MSG-", uint8(i + 1))
            );
        }
    }

    /// @dev Returns `arr[from..to)` as a freshly allocated array.
    function _slice(bytes[] memory arr, uint256 from, uint256 to) internal pure returns (bytes[] memory out) {
        out = new bytes[](to - from);
        for (uint256 i = 0; i < out.length; i++) {
            out[i] = arr[from + i];
        }
    }

    /// @dev The running hash after the first `count` payloads from a zero seed, chained the way
    ///      `BundleLib` recomputes it: `h = sha256(h ‖ sha256(payload))`.
    function _runningHashThrough(bytes[] memory payloads, uint256 count) internal pure returns (bytes32 h) {
        for (uint256 i = 0; i < count; i++) {
            h = sha256(abi.encodePacked(h, sha256(payloads[i])));
        }
    }

    /// @dev The local channel; `receivedMessageId` and `status` are the fields bundle processing advances.
    function _localSyncData(bytes32 channelId_) internal returns (ClprTypes.Channel memory) {
        return service.getChannel(channelId_);
    }

    /// @dev Arms the mock verifier to return `payloads` as a bundle whose last message is
    ///      `anchorMessageId`, proven at `anchorRunningHash` (`lastMessageId`, `lastMessageRunningHash`),
    ///      from a peer queue that ends there (`nextMessageId = anchorMessageId + 1`, `sentRunningHash =
    ///      anchorRunningHash`), acking our messages up to `remoteReceivedMessageId`, with the peer claiming
    ///      ACTIVE. A payload-free bundle carries `lastMessageId = 0`, and its `sentRunningHash` is checked
    ///      only when `nextMessageId` is our `receivedMessageId + 1`, so it names our own head. Split from
    ///      the submit call so `vm.expectRevert` can sit immediately before `submitBundle`.
    ///
    ///      `remoteReceivedMessageId` matters when the anchor does not advance our `receivedMessageId`:
    ///      `_checkBundleProgress` runs before the replay and hash checks and reverts `NoProgress`
    ///      unless the ack advances instead, so a bundle probing those checks must advance one of the two.
    function _armBundleAnchor(
        bytes[] memory payloads,
        uint64 anchorMessageId,
        bytes32 anchorRunningHash,
        uint64 remoteReceivedMessageId
    ) internal {
        verifier.setVerifyBundleResult(
            ClprTypes.QueueMetadata({
                nextMessageId: anchorMessageId + 1,
                sentRunningHash: anchorRunningHash,
                receivedMessageId: remoteReceivedMessageId,
                receivedRunningHash: bytes32(0),
                state: ClprTypes.ChannelStatus.ACTIVE,
                endpointManifestVersion: 0,
                lastMessageId: payloads.length > 0 ? anchorMessageId : 0,
                lastMessageRunningHash: payloads.length > 0 ? anchorRunningHash : bytes32(0)
            }),
            payloads
        );
    }

    /// @dev Convenience overload for callers where the anchor itself makes progress
    ///      (`anchorMessageId > receivedMessageId`), so the peer's ack value is immaterial.
    function _armBundleAnchor(bytes[] memory payloads, uint64 anchorMessageId, bytes32 anchorRunningHash) internal {
        _armBundleAnchor(payloads, anchorMessageId, anchorRunningHash, 0);
    }

    /// @dev Convenience for the non-reverting (happy-path) case: arm then submit in one call.
    function _submitBundleWithAnchor(
        bytes32 channelId_,
        bytes[] memory payloads,
        uint64 anchorMessageId,
        bytes32 anchorRunningHash
    ) internal {
        _armBundleAnchor(payloads, anchorMessageId, anchorRunningHash);
        service.submitBundle(channelId_, hex"00FF");
    }

    function _dummyEndpointKey() internal pure override returns (bytes memory) {
        return abi.encodePacked(
            uint256(0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20),
            uint256(0x2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40)
        );
    }

    receive() external payable virtual {}
}
