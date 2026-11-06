// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprTestBase} from "@test/helpers/ClprTestBase.sol";

/// @notice Base contract for BundleProcessor test suite.
/// @dev Provides helpers for bundle submission, message configuration, and rate limiting tests.
/// @dev Inherits from ClprTestBase and adds suite-specific helpers for bundle processing.
abstract contract BundleProcessorTestBase is ClprTestBase {
    /// @dev Submit a single inbound message. Computes running hash and configures verifier result.
    /// @param payload The encoded message payload (DATA, CONTROL, or REPLY).
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

    /// @dev Submit a bundle with a given proof. Convenience wrapper.
    /// @param proofBytes The verifier proof bytes.
    function _submitBundle(bytes memory proofBytes) internal {
        service.submitBundle(channelId, proofBytes);
    }

    /// @dev Construct a LedgerConfiguration with a given timestamp (in seconds).
    /// @param timestamp Seconds since epoch; converted to nanosSinceEpoch.
    /// @return config A LedgerConfiguration with nanosSinceEpoch populated.
    function _makeConfig(uint64 timestamp) internal pure returns (ClprTypes.LedgerConfiguration memory config) {
        config.nanosSinceEpoch = uint96(timestamp) * 1_000_000_000;
    }

    /// @dev Configure the verifier for an empty bundle with a new trust anchor.
    /// @param anchor The new trust anchor bytes to advance finality.
    function _emptyBundleWithTrustAnchor(bytes memory anchor) internal {
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
        verifier.setNewTrustAnchor(anchor);
    }
}
