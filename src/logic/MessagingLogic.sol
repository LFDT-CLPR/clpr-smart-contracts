// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes, MessageQueued} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {IClprConnector} from "@hiero-ledger/clpr/interfaces/IClprConnector.sol";
import {ConnectorLib} from "@hiero-ledger/clpr/libraries/service/ConnectorLib.sol";
import {LogicModuleBase} from "@hiero-ledger/clpr/logic/base/LogicModuleBase.sol";

/// @title MessagingLogic
/// @notice Outbound message queueing, redaction, and connector quota enforcement.
/// @dev Executed via delegatecall from ClprService. Bundle submission lives in
///      BundleLogic to keep this contract below the EIP-170 24 KB bytecode limit.
contract MessagingLogic is LogicModuleBase {
    constructor() {}

    /// @notice Returns the stored message value for a given channel and message ID.
    /// @dev Returns an empty struct for IDs outside the live window. Redacted messages
    ///      return a struct whose payload is an encoded ClprRedactedMessage carrying
    ///      SHA-256(original_payload).
    /// @param _channelId The channel the message belongs to.
    /// @param messageId The message sequence number.
    function getMessage(bytes32 _channelId, uint64 messageId) external view returns (ClprTypes.MessageValue memory) {
        return _messageQueues[_channelId][messageId];
    }

    /// @notice Returns the outbound queue depth for `_channelId`: how many DATA
    ///         messages have been sent but not yet acknowledged by the peer, and the
    ///         configured maximum queue depth throttle.
    /// @dev depth = nextMessageId - ackedMessageId - 1, the same quantity enforced by
    ///      the queue-full check in {sendMessage}. Reverts with `ClprChannelNotFound`
    ///      if the channel does not exist.
    /// @param _channelId The channel identifier.
    function getQueueDepth(bytes32 _channelId) external view returns (ClprTypes.QueueDepth memory) {
        if (!_channelExists[_channelId]) revert ClprTypes.ClprChannelNotFound();
        ClprTypes.Channel storage channel = _channels[_channelId];
        return ClprTypes.QueueDepth({
            queueDepth: _outboundQueueDepth(channel), maxQueueDepth: uint32(_config.throttles.maxQueueDepth)
        });
    }

    /// @dev Number of outbound messages sent but not yet acknowledged by the peer.
    ///      Shared by {getQueueDepth} and the queue-full checks in {sendMessage} so
    ///      the formula is defined in exactly one place.
    function _outboundQueueDepth(ClprTypes.Channel storage channel) private view returns (uint64) {
        return channel.nextMessageId - channel.ackedMessageId - 1;
    }

    /// @notice Enqueue an outbound data message on an active channel.
    /// @dev The sender field in the encoded payload is set to msg.sender and cannot
    ///      be spoofed by the caller. Enforces connector
    ///      authorisation, the peer's payload size limit, queue depth, and the
    ///      per-connector quota. Prepends a CONTROL message if the local config
    ///      has been updated since the last one was sent on this channel.
    ///      Emits {MessageQueued}.
    /// @param _channelId The channel to send on (must be ACTIVE).
    /// @param connectorId Connector identifier scoping the message.
    /// @param targetApplication ABI-encoded address of the target application on the peer.
    /// @param messageData Opaque payload forwarded to the peer application.
    /// @return messageId Sequence number assigned to the enqueued message.
    function sendMessage(
        bytes32 _channelId,
        bytes32 connectorId,
        bytes calldata targetApplication,
        bytes calldata messageData
    ) external nonReentrant onlyService whenEnabled returns (uint64 messageId) {
        if (!_channelExists[_channelId]) revert ClprTypes.ClprChannelNotFound();
        ClprTypes.Channel storage channel = _channels[_channelId];
        if (channel.status != ClprTypes.ChannelStatus.ACTIVE) revert ClprTypes.ClprInvalidChannelStatus();
        // Enforce the peer's payload limit. peerThrottles is populated at completeChannel from verifyConfig;
        // A zero value indicates an unpopulated channel (defensive guard)
        if (
            channel.peerThrottles.maxMessagePayloadBytes == 0
                || messageData.length > channel.peerThrottles.maxMessagePayloadBytes
        ) {
            revert ClprTypes.ClprPayloadTooLarge();
        }

        // Reject if this message, sent alone in a bundle, would exceed the peer's maxSyncBytes:
        // its variable fields:
        // (data + connectorId + target) + 20-byte stamped sender + worst-case proof/framing overhead.
        if (
            messageData.length + connectorId.length + targetApplication.length + 20
                    + ClprTypes.WORST_CASE_BUNDLE_OVERHEAD > channel.peerThrottles.maxSyncBytes
        ) {
            revert ClprTypes.ClprPayloadTooLarge();
        }

        // Early queue check: avoids the external authorize call when the queue is already full.
        if (_outboundQueueDepth(channel) >= _config.throttles.maxQueueDepth) {
            revert ClprTypes.ClprQueueFull();
        }

        // Stamp the on-chain caller as sender; callers cannot spoof this field.
        bytes memory sender = abi.encodePacked(msg.sender);

        /// Enforces the per-connector queue depth quota (connectorQueueQuotaPct % of maxQueueDepth).
        /// Reverts with ClprQueueQuotaExceeded if the connector's pending message count is at or above the quota.
        uint32 quota = (uint32(_config.throttles.maxQueueDepth) * economicConfig.connectorQueueQuotaPct) / 100;
        if (_connectorQueueCounts[_channelId][connectorId] >= quota) revert ClprTypes.ClprQueueQuotaExceeded();

        _authorizeConnector(_channelId, connectorId, targetApplication, sender, messageData);

        _maybeEnqueueConfigUpdate(_channelId, channel);

        // Second queue check: catches the case where _maybeEnqueueConfigUpdate consumed the last slot.
        if (_outboundQueueDepth(channel) >= _config.throttles.maxQueueDepth) {
            revert ClprTypes.ClprQueueFull();
        }

        messageId =
            _enqueueDataMessage(_channelId, channel, connectorId, connectorId, targetApplication, sender, messageData);
    }

    // submitBundle moved to BundleLogic to reduce bytecode size.

    /// @notice Replace the payload of a queued DATA message with a ClprRedactedMessage marker (owner-only via onlyService).
    /// @dev The payload is replaced with `ClprRedactedMessage { message_hash: SHA-256(original_payload) }` so
    ///      the destination chain can verify the running hash chain without receiving the original content.
    ///      Decrements connector queue and in-flight counters so the connector can be removed after redaction.
    ///      The message slot is retained to preserve sequence numbering and running hash continuity.
    ///      Reverts if the message is not a DATA message, has already been redacted, or if `messageId` is
    ///      outside the live window (ackedMessageId, nextMessageId).
    ///      Emits {MessageRedacted}.
    /// @param _channelId The channel the message belongs to.
    /// @param messageId Sequence number of the message to redact.
    function redactMessage(bytes32 _channelId, uint64 messageId) external onlyService whenEnabled {
        if (!_channelExists[_channelId]) revert ClprTypes.ClprChannelNotFound();
        ClprTypes.Channel storage channel = _channels[_channelId];
        if (messageId <= channel.ackedMessageId || messageId >= channel.nextMessageId) {
            revert ClprTypes.ClprInvalidMessageId();
        }

        ClprTypes.MessageValue storage msg_ = _messageQueues[_channelId][messageId];
        (bool known, ClprTypes.MessageType mt) = ClprProtobuf.tryGetMessageType(msg_.payload);
        if (known && mt == ClprTypes.MessageType.REDACTED) revert ClprTypes.ClprMessageAlreadyRedacted();
        if (!known || mt != ClprTypes.MessageType.DATA) revert ClprTypes.ClprMessageNotRedactable();

        ClprTypes.DecodedDataMessage memory decoded = ClprProtobuf.decodeDataMessage(msg_.payload);
        bytes32 connKey = decoded.connectorId;
        bytes32 inflightKey = keccak256(abi.encodePacked(_channelId, connKey));

        if (_connectorQueueCounts[_channelId][connKey] > 0) {
            _connectorQueueCounts[_channelId][connKey]--;
        }
        // Decrement inflight so removeConnector cannot be blocked by a redacted-but-uncounted message.
        if (_connectorInflightCount[inflightKey] > 0) {
            _connectorInflightCount[inflightKey]--;
        }

        msg_.payload = ClprProtobuf.encodeRedactedMessage(sha256(msg_.payload));
        emit MessageRedacted(_channelId, messageId);
    }

    // ── Internal helpers ───────────────────────────────────────────────────

    /// @dev Calls IClprConnector.authorizeOutboundMessage on the registered connector
    ///      contract. Reverts with ClprConnectorUnauthorized if the connector rejects.
    function _authorizeConnector(
        bytes32 _channelId,
        bytes32 connectorId,
        bytes calldata targetApplication,
        bytes memory sender,
        bytes calldata messageData
    ) internal {
        address connectorContract = ConnectorLib.getContract(_connectors, _connectorExists, _channelId, connectorId);
        bool ok = IClprConnector(connectorContract)
            .authorizeOutboundMessage(_channelId, targetApplication, sender, messageData);
        if (!ok) revert ClprTypes.ClprConnectorUnauthorized();
    }

    /// @dev If the local config has advanced since the last CONTROL message was sent
    ///      on this channel, prepends a CONTROL message carrying the new config.
    ///      Updates the running SHA-256 hash chain and stamps the config timestamp.
    function _maybeEnqueueConfigUpdate(bytes32 _channelId, ClprTypes.Channel storage channel) internal {
        // Both nanosSinceEpoch and lastConfigTimestamp are stored as uint96 nanoseconds.
        if (_config.nanosSinceEpoch > channel.lastConfigTimestamp) {
            ClprTypes.LedgerConfiguration memory cfg = _config;
            bytes memory controlPayload = ClprProtobuf.encodeControlMessage(cfg);
            bytes32 payloadHash = sha256(controlPayload);
            bytes32 controlHash = sha256(abi.encodePacked(channel.sentRunningHash, payloadHash));
            _messageQueues[_channelId][channel.nextMessageId] = ClprTypes.MessageValue({
                payload: controlPayload, runningHashAfterProcessing: controlHash, connectorIdForReply: ""
            });
            emit MessageQueued(_channelId, channel.nextMessageId, ClprTypes.MessageType.CONTROL);
            channel.nextMessageId++;
            channel.sentRunningHash = controlHash;
            channel.lastConfigTimestamp = _config.nanosSinceEpoch;
        }
    }

    /// @dev Encodes a DATA message via ClprProtobuf, assigns the next messageId,
    ///      updates the running SHA-256 hash chain, increments in-flight and quota
    ///      counters, and emits MessageQueued.
    function _enqueueDataMessage(
        bytes32 _channelId,
        ClprTypes.Channel storage channel,
        bytes32 connectorKey,
        bytes32 connectorId,
        bytes calldata targetApplication,
        bytes memory sender,
        bytes calldata messageData
    ) internal returns (uint64 messageId) {
        messageId = channel.nextMessageId;

        bytes memory payload = ClprProtobuf.encodeDataMessage(connectorId, targetApplication, sender, messageData);
        bytes32 payloadHash = sha256(payload);
        bytes32 newHash = sha256(abi.encodePacked(channel.sentRunningHash, payloadHash));

        _messageQueues[_channelId][messageId] = ClprTypes.MessageValue({
            payload: payload, runningHashAfterProcessing: newHash, connectorIdForReply: connectorId
        });

        bytes32 inflightKey = keccak256(abi.encodePacked(_channelId, connectorId));
        _connectorInflightCount[inflightKey]++;
        _connectorQueueCounts[_channelId][connectorKey]++;

        channel.nextMessageId++;
        channel.sentRunningHash = newHash;
        channel.lastDataMessageId = messageId;

        emit MessageQueued(_channelId, messageId, ClprTypes.MessageType.DATA);
    }
}
