// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {MockClprVerifier} from "@test/mocks/MockClprVerifier.sol";

/// @notice Shared bundle metadata builders for invariant handler actions.
library InvariantBundleHelper {
    function buildInboundDataPayload(
        bytes32 connectorId,
        address targetApplication,
        bytes memory sender,
        bytes memory messageData
    ) internal pure returns (bytes memory) {
        return ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(targetApplication), sender, messageData);
    }

    /// @dev Metadata for a single inbound DATA message (peer sent us message id 1).
    function inboundMetadata(ClprTypes.Channel memory channel, bytes memory payload)
        internal
        pure
        returns (ClprTypes.QueueMetadata memory meta)
    {
        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(payload)));
        meta = ClprTypes.QueueMetadata({
            nextMessageId: channel.receivedMessageId + 2,
            sentRunningHash: hash,
            receivedMessageId: channel.ackedMessageId,
            receivedRunningHash: channel.sentRunningHash,
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: channel.receivedMessageId + 1,
            lastMessageRunningHash: hash
        });
    }

    /// @dev Metadata when outbound queue is fully acked (no pending local sends).
    function emptyAckMetadata(ClprTypes.Channel memory channel)
        internal
        pure
        returns (ClprTypes.QueueMetadata memory meta)
    {
        meta = ClprTypes.QueueMetadata({
            nextMessageId: channel.receivedMessageId + 1,
            sentRunningHash: channel.receivedRunningHash,
            receivedMessageId: channel.ackedMessageId,
            receivedRunningHash: channel.sentRunningHash,
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: channel.receivedMessageId,
            lastMessageRunningHash: channel.receivedRunningHash
        });
    }

    /// @dev Metadata that acks all pending outbound messages (send then bundle ordering).
    function outboundAckMetadata(ClprTypes.Channel memory channel)
        internal
        pure
        returns (ClprTypes.QueueMetadata memory meta)
    {
        meta = ClprTypes.QueueMetadata({
            nextMessageId: channel.receivedMessageId + 1,
            sentRunningHash: channel.receivedRunningHash,
            receivedMessageId: channel.nextMessageId - 1,
            receivedRunningHash: channel.sentRunningHash,
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: channel.receivedMessageId,
            lastMessageRunningHash: channel.receivedRunningHash
        });
    }

    function configureVerifierInbound(
        MockClprVerifier verifier,
        ClprTypes.QueueMetadata memory meta,
        bytes[] memory msgs
    ) internal {
        verifier.setVerifyBundleResult(meta, msgs);
    }
}
