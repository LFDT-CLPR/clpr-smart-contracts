// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes, ChannelStatusChanged, MessageQueued} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprProtobufHelpers} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {ConnectorLib} from "@hiero-ledger/clpr/libraries/service/ConnectorLib.sol";
import {BundleDecodeHelper} from "@hiero-ledger/clpr/libraries/codec/BundleDecodeHelper.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {IClprApplication} from "@hiero-ledger/clpr/interfaces/IClprApplication.sol";
import {IClprConnector} from "@hiero-ledger/clpr/interfaces/IClprConnector.sol";

/// @title BundleLib
/// @notice Implements the 12-step bundle submission algorithm for the CLPR protocol.
/// @dev Internal library; inlined into ClprService for size efficiency.
///
///      STACK STRATEGY: the optimized production build (via-ir + optimizer) compiles
///      this whole algorithm as a single function without trouble. The constraint is
///      CI's `forge coverage --ir-minimum`: it adds a hit-counter local per branch and
///      disables the optimizer's stack scheduler, which overflows a monolithic
///      `processBundle` by ~2 slots. To stay under that limit we (a) pack value-type
///      inputs into `ProcessBundleParams`, (b) carry cross-step state in `BundleContext`,
///      and (c) split the 12 steps across `_validateAndPrepare` (1-7) and `_applyBundle`
///      (8-11) so no single frame holds all 11 storage-mapping params at once.
library BundleLib {
    /// @dev Value-type inputs to `processBundle`, packed into one struct (see STACK STRATEGY).
    struct ProcessBundleParams {
        bytes32 channelId;
        address bundleSubmitter;
        address decodeHelperAddr;
        address fallbackRecipient;
        ClprTypes.LedgerConfiguration config;
        ClprTypes.EconomicConfig econ;
    }

    // ── Bundle processing context: cross-step state (see STACK STRATEGY) ──
    struct BundleContext {
        bytes32 channelId;
        address bundleSubmitter;
        uint64 expectedFirstId;
        uint64 expectedCount;
        uint64 messageStartIndex;
        uint64 oldAckedMessageId;
        uint64 newAckedMessageId;
        bytes32 computedHash;
        ClprTypes.Throttles throttles;
        ClprTypes.EconomicConfig econ;
        /// @dev Full ledger configuration as observed at bundle entry.
        ClprTypes.LedgerConfiguration config;
        /// @dev Recipient for slash/charge proceeds; falls back on transfer failure.
        address fallbackRecipient;
        /// @dev Address of the BundleDecodeHelper contract for try/catch protobuf decode.
        address decodeHelperAddr;
        uint256 bannedCount;
    }

    // ── Events ────────────────────────────────────────────────────────
    // ChannelStatusChanged and MessageQueued are file-level events in ClprTypes.sol.
    event BundleProcessed(bytes32 indexed channelId, uint64 receivedUpTo, uint64 ackedUpTo, uint256 messageCount);
    event MessageDispatched(bytes32 indexed channelId, uint64 receivedMessageId, ClprTypes.ReplyStatus status);
    event ReplyDelivered(bytes32 indexed channelId, uint64 originalMessageId, ClprTypes.ReplyStatus status);
    event ConnectorInboundCallbackFailed(bytes32 indexed channelId, uint64 receivedMessageId);
    /// @dev Emitted when a message payload cannot be decoded during bundle dispatch.
    event BundleParseFailed(bytes32 indexed channelId, uint64 receivedMessageId);

    // ── Errors ────────────────────────────────────────────────────────
    /// @notice The bundle's encoded byte length exceeds the configured maximum.
    error BundleTooLarge();
    /// @notice The bundle contains more messages than the configured maximum per bundle.
    error TooManyMessages();
    /// @notice The bundle contains no messages and no metadata update.
    error EmptyBundle();
    /// @dev Thrown when a bundle doesn't make any progress.
    error NoProgress();

    /// @dev Checks if the bundle meets progress criteria to prevent no-op bundles (DoS protection).
    ///      Reference: CLPR Specification §2.1.2 Bundle Progress Criteria
    ///      A bundle makes progress if AT LEAST ONE of the following holds:
    ///      1. New messages (messages with ID > channel.receivedMessageId)
    ///      2. Trust anchor advancement
    ///      3. Acknowledgement progress
    ///      4. Channel state transition
    ///      5. Endpoint manifest advancement (proven manifest version > stored version)
    /// @param channel Current channel state
    /// @param metadata Verified metadata from the bundle
    /// @param newTrustAnchor New trust anchor (if any) from the bundle
    /// @param manifestAdvances True when the verifier returned a manifest with a version strictly
    ///        greater than the Channel's stored endpointManifestVersion (Criterion 5)
    /// Reverts with NoProgress if none of the progress conditions hold
    function _checkBundleProgress(
        ClprTypes.Channel memory channel,
        ClprTypes.QueueMetadata memory metadata,
        bytes memory newTrustAnchor,
        bool manifestAdvances
    ) internal pure {
        // Condition 1: New messages (messages with ID > channel.receivedMessageId).
        // A bundle makes message progress iff nextMessageId > receivedMessageId + 1.
        // Leading duplicate messages don't count as progress.
        if (uint256(metadata.nextMessageId) > uint256(channel.receivedMessageId) + 1) return;

        // Condition 2: Trust anchor advancement
        if (newTrustAnchor.length > 0) return;

        // A manifest-only bundle is valid progress as well.
        if (manifestAdvances) return;

        // Condition 3: Acknowledgement progress
        if (metadata.receivedMessageId > channel.ackedMessageId) return;

        // Condition 4: the bundle drives a channel state transition.
        //     Routed through the shared `_stepStatus` so this pre-check can never drift from
        //     what `_applyStateMachine` actually does. The check runs before Step 6 commits
        //     the new ack, so it looks ahead using max(channel.ackedMessageId, metadata.receivedMessageId).
        uint64 effectiveAcked = channel.ackedMessageId;
        if (metadata.receivedMessageId > effectiveAcked) effectiveAcked = metadata.receivedMessageId;

        if (
            _stepStatus(
                    channel.status,
                    metadata.state,
                    _allDataAcked(channel, effectiveAcked),
                    _allOutboundAcked(channel, effectiveAcked)
                ) != channel.status
        ) {
            return;
        }

        // Reject if NONE of the four conditions hold
        revert NoProgress();
    }

    // ── Main entry point ──────────────────────────────────────────────

    /// @notice Process an inbound bundle for a given channel.
    /// @dev Called only from ClprService.submitBundle().
    function processBundle(
        mapping(bytes32 => ClprTypes.Channel) storage _channels,
        mapping(bytes32 => bool) storage _channelExists,
        mapping(
            bytes32 => mapping(uint64 => ClprTypes.MessageValue)
        ) storage _messageQueues,
        mapping(bytes32 => ClprTypes.Connector) storage _connectors,
        mapping(bytes32 => bool) storage _connectorExists,
        mapping(bytes32 => uint256) storage _connectorInflightCount,
        mapping(bytes32 => mapping(bytes32 => uint32)) storage _connectorQueueCounts,
        mapping(address => uint256) storage _pendingWithdrawals,
        mapping(bytes32 => ClprTypes.ClprEndpointManifest) storage _peerEndpointManifests,
        uint256 _connectorCountSlot,
        bytes calldata proofBytes,
        ProcessBundleParams memory params
    ) internal {
        // Steps 1-7 live in _validateAndPrepare, steps 8-11 in _applyBundle (see STACK STRATEGY).
        (
            BundleContext memory ctx,
            ClprTypes.Channel memory channel,
            ClprTypes.QueueMetadata memory metadata,
            bytes[] memory messagePayloads,
            bool earlyReturn
        ) = _validateAndPrepare(_channels, _channelExists, _messageQueues, _peerEndpointManifests, proofBytes, params);

        if (earlyReturn) return;

        // Steps 8-11. ctx.fallbackRecipient, ctx.decodeHelperAddr, and ctx.config
        // were populated in _validateAndPrepare.
        _applyBundle(
            ctx,
            channel,
            metadata,
            messagePayloads,
            _messageQueues,
            _connectors,
            _connectorExists,
            _connectorInflightCount,
            _connectorQueueCounts,
            _pendingWithdrawals
        );

        if (ctx.bannedCount > 0) {
            uint256 banned = ctx.bannedCount;
            // can't pass storage uint256 value directly so switching to slotPosition
            assembly ("memory-safe") {
                sstore(_connectorCountSlot, sub(sload(_connectorCountSlot), banned))
            }
        }

        // ── Step 12: Persist channel ──────────────────────────────
        _channels[ctx.channelId] = channel;
    }

    /// @dev Steps 1-7 of bundle processing (see STACK STRATEGY for why this is a separate function).
    ///      When the response-ordering pre-scan triggers a PAUSE/no-op exit, this function
    ///      persists `channel` itself and returns `earlyReturn = true`; the caller MUST stop.
    function _validateAndPrepare(
        mapping(bytes32 => ClprTypes.Channel) storage _channels,
        mapping(bytes32 => bool) storage _channelExists,
        mapping(
            bytes32 => mapping(uint64 => ClprTypes.MessageValue)
        ) storage _messageQueues,
        mapping(bytes32 => ClprTypes.ClprEndpointManifest) storage _peerEndpointManifests,
        bytes calldata proofBytes,
        ProcessBundleParams memory params
    )
        internal
        returns (
            BundleContext memory ctx,
            ClprTypes.Channel memory channel,
            ClprTypes.QueueMetadata memory metadata,
            bytes[] memory messagePayloads,
            bool earlyReturn
        )
    {
        // ── Step 1: Channel lookup ─────────────────────────────────
        if (!_channelExists[params.channelId]) revert ClprTypes.ClprChannelNotFound();
        channel = _channels[params.channelId];
        // Reject PENDING (defensive guard; PENDING records should not be in _channels,
        // but guard here in case a misconfigured or replayed commitment slips through).
        if (channel.status == ClprTypes.ChannelStatus.CLOSED || channel.status == ClprTypes.ChannelStatus.PENDING) {
            revert ClprTypes.ClprInvalidChannelStatus();
        }

        // ── Step 2: Bundle size check ─────────────────────────────────
        if (proofBytes.length > params.config.throttles.maxSyncBytes) {
            revert BundleTooLarge();
        }

        // ── Step 3: Verifier call ─────────────────────────────────────
        {
            bytes memory newTrustAnchor;
            bytes memory newTrustAnchorId;
            ClprTypes.ClprEndpointManifest memory newEndpointManifest;

            (metadata, messagePayloads, newTrustAnchor, newTrustAnchorId, newEndpointManifest) =
                IClprVerifier(channel.verifier).verifyBundle(proofBytes, channel.trustAnchor, channel.channelContext);

            _checkBundleProgress(
                channel, metadata, newTrustAnchor, newEndpointManifest.version > channel.endpointManifestVersion
            );

            if (messagePayloads.length > params.config.throttles.maxMessagesPerBundle) {
                revert TooManyMessages();
            }
            for (uint256 i = 0; i < messagePayloads.length; i++) {
                if (messagePayloads[i].length > params.config.throttles.maxMessagePayloadBytes) {
                    revert ClprTypes.ClprPayloadTooLarge();
                }
            }
            // ── Step 1b: endpoint-manifest update. The manifest is stored out-of-line (written
            // here directly — the only storage write BundleLib performs before Step 12; safe
            // because every later revert path aborts the whole transaction). The endpoint list is
            // truncated to the local maxPeerEndpoints throttle (0 = no limit) before storing.
            if (newEndpointManifest.version > channel.endpointManifestVersion) {
                ClprTypes.truncateEndpoints(newEndpointManifest, params.config.throttles.maxPeerEndpoints);
                _peerEndpointManifests[params.channelId] = newEndpointManifest;
                channel.endpointManifestVersion = newEndpointManifest.version;
            }
            // ── Step 1c: trust-anchor update.
            if (newTrustAnchor.length > 0) {
                channel.trustAnchor = newTrustAnchor;
                channel.trustAnchorId = newTrustAnchorId;
            }
        }

        // Build context
        ctx.channelId = params.channelId;
        ctx.bundleSubmitter = params.bundleSubmitter;
        ctx.throttles = params.config.throttles;
        ctx.econ = params.econ;
        ctx.fallbackRecipient = params.fallbackRecipient;
        ctx.decodeHelperAddr = params.decodeHelperAddr;
        ctx.config = params.config;

        // ── Step 4: Replay defense ───────────────────────────────────
        ctx.expectedFirstId = channel.receivedMessageId + 1;
        {
            int256 newMessageCount = int256(uint256(metadata.nextMessageId)) - int256(uint256(ctx.expectedFirstId));

            // < 0: nextMessageId is behind our receivedMessageId — the sender is replaying old state.
            // > length: metadata claims more new messages than the payload array can hold
            // forge-lint: disable-next-line(unsafe-typecast)
            if (newMessageCount < 0 || uint256(newMessageCount) > messagePayloads.length) {
                revert ClprTypes.ClprReplayDetected();
            }

            // newMessageCount is in [0, messagePayloads.length], which is bounded by maxMessagesPerBundle (uint16).
            // forge-lint: disable-next-line(unsafe-typecast)
            ctx.expectedCount = uint64(uint256(newMessageCount));
            // Payloads[0 .. messageStartIndex-1] are leading duplicates; payloads[messageStartIndex .. length-1] are new.
            // forge-lint: disable-next-line(unsafe-typecast)
            ctx.messageStartIndex = uint64(messagePayloads.length - uint256(newMessageCount));
        }

        // ── Step 5: Running hash verification ─────────────────────────
        ctx.computedHash = channel.receivedRunningHash;
        if (channel.receivedMessageId == 0) {
            ctx.computedHash = bytes32(0);
        }
        // Skip leading duplicate messages (indices 0..messageStartIndex-1); their
        // running-hash contribution is already captured in channel.receivedRunningHash.
        for (uint256 i = ctx.messageStartIndex; i < messagePayloads.length; i++) {
            bytes32 payloadHash = sha256(messagePayloads[i]);
            ctx.computedHash = sha256(abi.encodePacked(ctx.computedHash, payloadHash));
        }
        if (ctx.computedHash != metadata.sentRunningHash) {
            revert ClprTypes.ClprRunningHashMismatch();
        }

        // ── Step 6: Ack verification ─────────────────────────────────
        ctx.newAckedMessageId = metadata.receivedMessageId;
        ctx.oldAckedMessageId = channel.ackedMessageId;
        if (ctx.newAckedMessageId < ctx.oldAckedMessageId) {
            revert ClprTypes.ClprAckVerificationFailed();
        }
        if (ctx.newAckedMessageId != ctx.oldAckedMessageId && ctx.newAckedMessageId >= channel.nextMessageId) {
            revert ClprTypes.ClprAckVerificationFailed();
        }

        // ── Step 7: Response ordering pre-scan ───────────────────────
        (OrderingOutcome outcome, uint64 nextExpected) =
            _checkResponseOrdering(ctx, channel, messagePayloads, _messageQueues);
        if (outcome != OrderingOutcome.Ok) {
            if (channel.status == ClprTypes.ChannelStatus.CLOSING) {
                // A CLOSING channel receiving out-of-order responses is unrecoverable — revert.
                if (outcome == OrderingOutcome.StructuralViolation) revert ClprTypes.ClprBundleVerificationFailed();
                // AwaitingReply on a CLOSING channel: dispatch is skipped, but the CLOSING -> DRAINED
                // hop is gated only by dataAcked, not by the outstanding REPLY, so it can still fire.
                _applyStateMachine(ctx.channelId, channel, metadata, ctx.newAckedMessageId);
            } else if (channel.status == ClprTypes.ChannelStatus.ACTIVE) {
                // Out-of-order responses on ACTIVE → transition to PAUSED
                channel.status = ClprTypes.ChannelStatus.PAUSED;
                emit ChannelStatusChanged(ctx.channelId, ClprTypes.ChannelStatus.PAUSED);
            }
            // Commit the verified ack even though dispatch is skipped
            _deleteAckedNonDataMessages(ctx.channelId, ctx.oldAckedMessageId, ctx.newAckedMessageId, _messageQueues);
            channel.ackedMessageId = ctx.newAckedMessageId;
            _channels[ctx.channelId] = channel;
            return (ctx, channel, metadata, messagePayloads, true);
        }

        channel.nextExpectedReplyId = nextExpected;
    }

    /// @dev Steps 8-11 of bundle processing (see STACK STRATEGY for why this is a separate function).
    function _applyBundle(
        BundleContext memory ctx,
        ClprTypes.Channel memory channel,
        ClprTypes.QueueMetadata memory metadata,
        bytes[] memory messagePayloads,
        mapping(bytes32 => mapping(uint64 => ClprTypes.MessageValue)) storage _messageQueues,
        mapping(bytes32 => ClprTypes.Connector) storage _connectors,
        mapping(bytes32 => bool) storage _connectorExists,
        mapping(bytes32 => uint256) storage _connectorInflightCount,
        mapping(bytes32 => mapping(bytes32 => uint32)) storage _connectorQueueCounts,
        mapping(address => uint256) storage _pendingWithdrawals
    ) internal {
        // ── Step 8: Auto-resume ──────────────────────────────────────
        if (channel.status == ClprTypes.ChannelStatus.PAUSED) {
            channel.status = ClprTypes.ChannelStatus.ACTIVE;
            emit ChannelStatusChanged(ctx.channelId, ClprTypes.ChannelStatus.ACTIVE);
        }

        // ── Step 9a: Lazy config propagation ────────────────────────
        // Both nanosSinceEpoch and lastConfigTimestamp are stored as uint96 nanoseconds.
        if (ctx.config.nanosSinceEpoch > channel.lastConfigTimestamp) {
            channel.lastConfigTimestamp = ctx.config.nanosSinceEpoch;
            bytes memory controlPayload = ClprProtobuf.encodeControlMessage(ctx.config);
            _enqueueMessage(ctx.channelId, channel, controlPayload, _messageQueues, ClprTypes.MessageType.CONTROL);
        }

        // ── Step 9b: Delete acked non-data messages (CONTROL and REPLY) ──
        _deleteAckedNonDataMessages(ctx.channelId, ctx.oldAckedMessageId, ctx.newAckedMessageId, _messageQueues);

        // ── Step 10: Per-message dispatch loop ──────────────────────
        _dispatchMessages(
            ctx,
            channel,
            messagePayloads,
            _messageQueues,
            _connectors,
            _connectorExists,
            _connectorInflightCount,
            _connectorQueueCounts,
            _pendingWithdrawals
        );

        // Update receivedMessageId and receivedRunningHash
        if (ctx.expectedCount > 0) {
            channel.receivedMessageId = ctx.expectedFirstId + ctx.expectedCount - 1;
            channel.receivedRunningHash = ctx.computedHash;
        }

        // Update ackedMessageId
        channel.ackedMessageId = ctx.newAckedMessageId;

        // ── Step 11: Channel state machine ────────────────────────
        _applyStateMachine(ctx.channelId, channel, metadata, ctx.newAckedMessageId);

        emit BundleProcessed(ctx.channelId, channel.receivedMessageId, ctx.newAckedMessageId, messagePayloads.length);
    }

    // ── Internal: State machine ───────────────────────────────────────────

    /// @dev True when all outbound DATA Messages have been acked. `lastDataMessageId == 0`
    ///      means no DATA Message was ever sent (vacuously acked). Gates CLOSING -> DRAINED
    ///      (§4.2 Step 5b sub-check 1): Response Messages may still be in flight and drain
    ///      through DRAINED, so they are deliberately NOT considered here.
    function _allDataAcked(ClprTypes.Channel memory channel, uint64 acked) private pure returns (bool) {
        return channel.lastDataMessageId == 0 || acked >= channel.lastDataMessageId;
    }

    /// @dev True when every outbound message (DATA and Response) has been acked.
    ///      `nextMessageId == 1` means nothing was ever sent (vacuously acked). Gates
    ///      DRAINED -> CLOSED (§4.2 Step 5b sub-check 2), which requires the final in-flight
    ///      Response Messages to be acknowledged before the channel may close.
    function _allOutboundAcked(ClprTypes.Channel memory channel, uint64 acked) private pure returns (bool) {
        return channel.nextMessageId == 1 || acked >= channel.nextMessageId - 1;
    }

    /// @dev One §4.2 state-machine transition; returns `current` unchanged if no rule fires.
    ///      SINGLE source of truth for the transition rules: `_applyStateMachine` applies and
    ///      emits each hop, while `_checkBundleProgress` only asks whether a transition would
    ///      fire. Routing both through here keeps them from drifting apart. `dataAcked` gates
    ///      CLOSING -> DRAINED (DATA only); `allAcked` gates DRAINED -> CLOSED (DATA + Response).
    function _stepStatus(ClprTypes.ChannelStatus current, ClprTypes.ChannelStatus peer, bool dataAcked, bool allAcked)
        private
        pure
        returns (ClprTypes.ChannelStatus)
    {
        bool peerClosing = peer == ClprTypes.ChannelStatus.CLOSING || peer == ClprTypes.ChannelStatus.DRAINED
            || peer == ClprTypes.ChannelStatus.CLOSED;
        bool peerDone = peer == ClprTypes.ChannelStatus.DRAINED || peer == ClprTypes.ChannelStatus.CLOSED;

        // ACTIVE || PAUSED -> CLOSING (§4.2 Step 5a)
        if ((current == ClprTypes.ChannelStatus.ACTIVE || current == ClprTypes.ChannelStatus.PAUSED) && peerClosing) {
            return ClprTypes.ChannelStatus.CLOSING;
        }
        // CLOSING -> DRAINED (§4.2 Step 5b sub-check 1): all DATA acked; responses may drain later.
        if (current == ClprTypes.ChannelStatus.CLOSING && dataAcked) {
            return ClprTypes.ChannelStatus.DRAINED;
        }
        // DRAINED -> CLOSED (§4.2 Step 5b sub-check 2): peer done AND all messages (incl. responses) acked.
        if (current == ClprTypes.ChannelStatus.DRAINED && peerDone && allAcked) {
            return ClprTypes.ChannelStatus.CLOSED;
        }
        return current;
    }

    function _applyStateMachine(
        bytes32 channelId,
        ClprTypes.Channel memory channel,
        ClprTypes.QueueMetadata memory metadata,
        uint64 newAckedMessageId
    ) internal {
        bool dataAcked = _allDataAcked(channel, newAckedMessageId);
        bool allAcked = _allOutboundAcked(channel, newAckedMessageId);
        // Walk to the settled status, emitting each hop. Transitions are monotonic
        // (ACTIVE -> CLOSING -> DRAINED -> CLOSED), so this terminates in <= 3 steps.
        ClprTypes.ChannelStatus next = _stepStatus(channel.status, metadata.state, dataAcked, allAcked);
        while (next != channel.status) {
            channel.status = next;
            emit ChannelStatusChanged(channelId, next);
            next = _stepStatus(channel.status, metadata.state, dataAcked, allAcked);
        }
    }

    // ── Internal: Response ordering check ─────────────────────────────────

    /// @dev Outcome of the Step 7 response-ordering pre-scan.
    enum OrderingOutcome {
        Ok,
        /// A REPLY in this bundle is backward/duplicate, targets an unsent message, or skips
        /// an earlier live DATA - the proof itself is malformed.
        StructuralViolation,
        /// The ack covers a live DATA message with no REPLY for it: the peer's state
        /// is ahead of what's been relayed back.
        AwaitingReply
    }

    /// @dev Check if the payload is a message of type DATA
    function _isMessageValueOfTypeData(
        bytes32 channelId,
        uint64 id,
        mapping(bytes32 => mapping(uint64 => ClprTypes.MessageValue)) storage _messageQueues
    ) private view returns (bool) {
        ClprTypes.MessageValue storage slot = _messageQueues[channelId][id];
        return slot.payload.length > 0 && ClprProtobuf.getMessageType(slot.payload) == ClprTypes.MessageType.DATA;
    }

    /// @dev Validates cross-bundle reply ordering using channel.nextExpectedReplyId.
    ///      Every inbound REPLY must arrive for the oldest un-replied outbound DATA id.
    ///      This catches out-of-order replies that span bundle boundaries.
    ///
    ///      The check walks every inbound REPLY in order and verifies that its messageId
    ///      matches the current `nextExpectedReplyId`. After a match, `nextExpectedReplyId`
    ///      is advanced past any non-DATA or redacted (zero-payload) outbound ids to the
    ///      next live outbound DATA.
    ///
    ///      The walk starts at `ctx.messageStartIndex`, skipping the leading already-received
    ///      duplicate prefix exactly as the running-hash (Step 5) and dispatch (Step 10) loops
    ///      do. A peer legitimately re-sends messages until its ack round-trips, and a read-only
    ///      proof format (the Hiero block-stream StateProof) cannot be trimmed endpoint-side, so
    ///      those duplicates reach this pre-scan by design. Re-scanning them would compare an
    ///      already-consumed REPLY against an already-advanced `nextExpectedReplyId` and report
    ///      a spurious backward-reply violation, pausing the channel and dropping the genuinely
    ///      new messages that follow it in the same bundle.
    ///
    /// @return outcome see OrderingOutcome.
    /// @return nextExpectedReplyId
    function _checkResponseOrdering(
        BundleContext memory ctx,
        ClprTypes.Channel memory channel,
        bytes[] memory messagePayloads,
        mapping(bytes32 => mapping(uint64 => ClprTypes.MessageValue)) storage _messageQueues
    ) internal view returns (OrderingOutcome, uint64) {
        uint64 nextExpectedReplyId = channel.nextExpectedReplyId;
        uint64 nextMessageId = channel.nextMessageId;
        bytes32 channelId = ctx.channelId;

        // Start past the already-received duplicate prefix; see the note above.
        for (uint256 j = ctx.messageStartIndex; j < messagePayloads.length; j++) {
            // Unknown/empty types can't be REPLYs and are irrelevant to response ordering; skip
            // them here so a malformed message degrades to a per-message skip in _dispatchMessages
            // rather than reverting the entire bundle during this pre-scan.
            (bool known, ClprTypes.MessageType mt) = ClprProtobuf.tryGetMessageType(messagePayloads[j]);
            if (!known || mt != ClprTypes.MessageType.REPLY) continue;

            uint64 replyMessageId = ClprProtobuf.decodeReplyMessage(messagePayloads[j]).messageId;

            // A REPLY for an un-acked outbound message is a violation.
            if (replyMessageId >= nextMessageId) return (OrderingOutcome.StructuralViolation, 0);

            // Backward/duplicate reply - violation.
            if (nextExpectedReplyId > replyMessageId) return (OrderingOutcome.StructuralViolation, 0);

            // Advance past skipped live DATA messages.
            while (nextExpectedReplyId < replyMessageId) {
                // If nextExpected points to a slot that still has a live DATA (non-redacted),
                // that DATA is being skipped — ordering violation.
                if (
                    nextExpectedReplyId < nextMessageId
                        && _isMessageValueOfTypeData(channelId, nextExpectedReplyId, _messageQueues)
                ) {
                    return (OrderingOutcome.StructuralViolation, 0);
                    // CONTROL/REPLY/redacted-DATA slots are skipped silently.
                }
                nextExpectedReplyId++;
            }

            // nextExpectedReplyId == replyId guaranteed here
            // Advance past this id regardless of whether it was a live or redacted DATA.
            nextExpectedReplyId++;
            // Skip forward past non-DATA or redacted slots to preload next expected.
            while (nextExpectedReplyId < nextMessageId) {
                if (_isMessageValueOfTypeData(channelId, nextExpectedReplyId, _messageQueues)) break;
                // Redacted or non-DATA slot; skip.
                nextExpectedReplyId++;
            }
        }

        // After processing all inbound REPLYs, verify that every newly-acked outbound DATA
        // (ids in range [old nextExpectedReplyId ... newAckedMessageId]) has received its REPLY.
        // If nextExpectedReplyId <= newAckedMessageId, scan forward for any live DATA that should
        // have had a REPLY but didn't get one in this bundle.
        uint64 scanId = nextExpectedReplyId;
        while (scanId <= ctx.newAckedMessageId) {
            if (scanId < nextMessageId && _isMessageValueOfTypeData(channelId, scanId, _messageQueues)) {
                // A live DATA message was acked but no REPLY arrived — awaiting reply, not malformed.
                return (OrderingOutcome.AwaitingReply, 0);
            }
            // Non-DATA slots (CONTROL/REPLY) are always skipped.
            scanId++;
        }

        return (OrderingOutcome.Ok, nextExpectedReplyId);
    }

    // ── Internal: Delete acked non-data messages ──────────────────────────

    function _deleteAckedNonDataMessages(
        bytes32 channelId,
        uint64 oldAcked,
        uint64 newAcked,
        mapping(bytes32 => mapping(uint64 => ClprTypes.MessageValue)) storage _messageQueues
    ) internal {
        for (uint64 id = oldAcked + 1; id <= newAcked; id++) {
            ClprTypes.MessageValue storage msg_ = _messageQueues[channelId][id];
            if (msg_.payload.length > 0) {
                ClprTypes.MessageType msgType = ClprProtobuf.getMessageType(msg_.payload);
                if (msgType == ClprTypes.MessageType.CONTROL || msgType == ClprTypes.MessageType.REPLY) {
                    delete _messageQueues[channelId][id];
                }
            }
        }
    }

    // ── Internal: Message dispatch loop ────────────────────────────────────

    function _dispatchMessages(
        BundleContext memory ctx,
        ClprTypes.Channel memory channel,
        bytes[] memory messagePayloads,
        mapping(bytes32 => mapping(uint64 => ClprTypes.MessageValue)) storage _messageQueues,
        mapping(bytes32 => ClprTypes.Connector) storage _connectors,
        mapping(bytes32 => bool) storage _connectorExists,
        mapping(bytes32 => uint256) storage _connectorInflightCount,
        mapping(bytes32 => mapping(bytes32 => uint32)) storage _connectorQueueCounts,
        mapping(address => uint256) storage _pendingWithdrawals
    ) internal {
        BundleDecodeHelper helper = BundleDecodeHelper(ctx.decodeHelperAddr);
        // receivedMsgId advances in lockstep with i (which starts at messageStartIndex), so the
        // first dispatched message gets expectedFirstId. expectedCount is bounded by the uint16
        // maxMessagesPerBundle throttle (validated in _validateAndPrepare), so it cannot overflow.
        uint64 receivedMsgId = ctx.expectedFirstId;
        for (uint256 i = ctx.messageStartIndex; i < messagePayloads.length;) {
            bytes memory payload = messagePayloads[i];
            ClprTypes.MessageType msgType = ClprProtobuf.getMessageType(payload);

            if (msgType == ClprTypes.MessageType.DATA) {
                try helper.decodeData(payload) returns (ClprTypes.DecodedDataMessage memory decoded) {
                    _processDataMessageDecoded(
                        ctx,
                        channel,
                        decoded,
                        receivedMsgId,
                        _messageQueues,
                        _connectors,
                        _connectorExists,
                        _pendingWithdrawals
                    );
                } catch (bytes memory reason) {
                    // An unknown field inside the DATA message is a protocol violation (version
                    // resulting in rejection of the entire bundle.
                    // Every OTHER decode failure (missing/garbled fields) stays a
                    // per-message APPLICATION_ERROR reply, so the source application can react
                    // (e.g. redact the malformed message) and the rest of the bundle processes.
                    // Previous error is carried, its leading 4-byte selector is forwarded.
                    // forge-lint: disable-next-line(unsafe-typecast)
                    if (reason.length >= 4 && bytes4(reason) == ClprTypes.ClprUnknownWireField.selector) {
                        _revertWith(reason);
                    }
                    emit BundleParseFailed(ctx.channelId, receivedMsgId);
                    _enqueueReplyAndEmit(
                        ctx, channel, receivedMsgId, ClprTypes.ReplyStatus.APPLICATION_ERROR, "", _messageQueues
                    );
                }
            } else if (msgType == ClprTypes.MessageType.REPLY) {
                _processReplyMessageDecoded(
                    ctx,
                    helper.decodeReply(payload),
                    _messageQueues,
                    _connectors,
                    _connectorExists,
                    _connectorInflightCount,
                    _connectorQueueCounts,
                    _pendingWithdrawals
                );
            } else if (msgType == ClprTypes.MessageType.REDACTED) {
                // Destination receives a ClprRedactedMessage - generate a REDACTED reply
                _enqueueReplyAndEmit(ctx, channel, receivedMsgId, ClprTypes.ReplyStatus.REDACTED, "", _messageQueues);
            } else {
                // ClprTypes.MessageType.CONTROL
                try helper.decodeControl(payload) returns (ClprTypes.DecodedControl memory decoded) {
                    _processControlMessageDecoded(ctx, decoded, channel);
                } catch (bytes memory reason) {
                    // An unknown ClprControlMessage oneof variant is a protocol violation, not a
                    // malformed-payload hiccup: the spec requires rejecting the entire bundle
                    // rather than degrading to a per-message skip, so re-throw and let it
                    // propagate out of submitBundle instead of swallowing it below.
                    // A custom error's identity is fully carried by its leading 4-byte selector,
                    // so truncating `reason` to compare against `.selector` is the intended way
                    // to identify which error was thrown
                    if (reason.length >= 4) {
                        // forge-lint: disable-next-line(unsafe-typecast)
                        bytes4 selector = bytes4(reason);
                        if (selector == ClprTypes.ClprBundleVerificationFailedOneOfVariant.selector) {
                            revert ClprTypes.ClprBundleVerificationFailedOneOfVariant();
                        }
                        if (selector == ClprTypes.ClprUnknownWireField.selector) _revertWith(reason);
                        // A CONTROL message that does not parse is a protocol violation and rejects the whole bundle.
                        if (
                            selector == ClprProtobufHelpers.TruncatedInput.selector
                                || selector == ClprProtobufHelpers.VarintOverflow.selector
                        ) _revertWith(reason);
                    }
                    // CONTROL messages never generate responses per the protocol
                    emit BundleParseFailed(ctx.channelId, receivedMsgId);
                }
            }
            unchecked {
                ++i;
                ++receivedMsgId;
            }
        }
    }

    /// @dev Re-throw raw revert bytes unchanged, preserving the original error selector and
    ///      arguments.
    function _revertWith(bytes memory reason) private pure {
        assembly ("memory-safe") {
            revert(add(reason, 32), mload(reason))
        }
    }

    // ── Internal: Message type processors ──────────────────────────────────

    /// @dev Process a CONTROL message using a pre-decoded struct (decode isolated in BundleDecodeHelper).
    ///      If the control message carries a new ClprLedgerConfiguration (nanosSinceEpoch > 0),
    ///      updates the peer config timestamp and throttles.
    function _processControlMessageDecoded(
        BundleContext memory ctx,
        ClprTypes.DecodedControl memory control,
        ClprTypes.Channel memory channel
    ) internal pure {
        if (control.config.nanosSinceEpoch > 0) {
            // Reject unrecognized protocol versions by reverting the entire bundle rather
            // than silently skipping this message — forward-incompatible protocol changes
            // must not be silently ignored (spec §1.1, §3.1.1).
            if (control.config.protocolVersion != ctx.config.protocolVersion) {
                revert ClprTypes.ClprProtocolVersionMismatch();
            }
            // Reject replayed/stale ConfigUpdates: the incoming timestamp must be strictly
            // greater than the stored one (spec §1.3).
            if (control.config.nanosSinceEpoch <= channel.peerConfigTimestamp) {
                revert ClprTypes.ClprReplayDetected();
            }
            // Store nanosSinceEpoch directly as uint96; no seconds conversion.
            channel.peerConfigTimestamp = control.config.nanosSinceEpoch;
            ClprTypes.validateThrottles(control.config.throttles);
            channel.peerThrottles = control.config.throttles;
        }
    }

    /// @dev Process a DATA message using a pre-decoded struct.
    ///      Charges actual gas used (× gasPrice × margin factor) rather than a fixed cost; all paid to the submitter.
    function _processDataMessageDecoded(
        BundleContext memory ctx,
        ClprTypes.Channel memory channel,
        ClprTypes.DecodedDataMessage memory data,
        uint64 receivedMsgId,
        mapping(bytes32 => mapping(uint64 => ClprTypes.MessageValue)) storage _messageQueues,
        mapping(
            bytes32 => ClprTypes.Connector
        ) storage _connectors,
        mapping(bytes32 => bool) storage _connectorExists,
        mapping(address => uint256) storage _pendingWithdrawals
    ) internal {
        // Look up connector
        if (!ConnectorLib.has(_connectorExists, ctx.channelId, data.connectorId)) {
            _enqueueReplyAndEmit(
                ctx, channel, receivedMsgId, ClprTypes.ReplyStatus.CONNECTOR_NOT_FOUND, "", _messageQueues
            );
            return;
        }

        // Bound the gas forwarded to the application by what the connector can actually pay for,
        // so the endpoint never performs work it cannot recover the cost of.
        //

        address connectorContract =
            ConnectorLib.getContract(_connectors, _connectorExists, ctx.channelId, data.connectorId);
        uint256 gasLimit = ctx.throttles.maxGasPerMessage;
        // tx.gasprice == 0 (some test/L2 environments) means execution is free — nothing to
        // charge, so no affordability bound applies and the division is skipped.
        if (tx.gasprice > 0) {
            uint256 affordableGas =
                connectorContract.balance * 100 / ((100 + uint256(ctx.econ.endpointMarginPercent)) * tx.gasprice);
            if (affordableGas == 0) {
                _slashConnector(ctx, data.connectorId, _connectors, _connectorExists, _pendingWithdrawals);
                _enqueueReplyAndEmit(
                    ctx, channel, receivedMsgId, ClprTypes.ReplyStatus.CONNECTOR_UNDERFUNDED, "", _messageQueues
                );
                return;
            }
            if (affordableGas < gasLimit) gasLimit = affordableGas;
        }

        // Dispatch to application
        address targetApp = _bytesToAddress(data.targetApplication);
        ClprTypes.ReplyStatus replyStatus = ClprTypes.ReplyStatus.APPLICATION_ERROR;
        bytes memory responseData;
        uint256 gasUsed;

        if (targetApp.code.length != 0) {
            uint256 gasBefore = gasleft();
            try IClprApplication(targetApp).onClprMessage{gas: gasLimit}(
                ctx.channelId, data.sender, data.messageData
            ) returns (
                bytes memory response
            ) {
                replyStatus = ClprTypes.ReplyStatus.SUCCESS;
                responseData = response;
            } catch (bytes memory reason) {
                // Forward the raw revert reason to the peer so it can decode the error.
                responseData = reason;
            }
            gasUsed = gasBefore - gasleft();
        }

        // Charge actual gas used + margin; all goes to submitter.
        uint256 actualCharge = gasUsed * tx.gasprice;
        uint256 totalCharge = actualCharge + actualCharge * ctx.econ.endpointMarginPercent / 100;

        if (totalCharge > 0) {
            bool charged = ConnectorLib.charge(
                _connectors,
                _connectorExists,
                _pendingWithdrawals,
                ctx.fallbackRecipient,
                ctx.channelId,
                data.connectorId,
                totalCharge,
                ctx.bundleSubmitter
            );
            if (!charged) {
                _slashConnector(ctx, data.connectorId, _connectors, _connectorExists, _pendingWithdrawals);
            }
        }

        // Best-effort inbound notification to the connector contract. A revert here
        // does not block message processing — the connector has already been charged.
        _notifyConnectorInbound(ctx, connectorContract, receivedMsgId, data);

        // Enqueue reply
        _enqueueReplyAndEmit(ctx, channel, receivedMsgId, replyStatus, responseData, _messageQueues);
    }

    function _notifyConnectorInbound(
        BundleContext memory ctx,
        address connectorContract,
        uint64 receivedMsgId,
        ClprTypes.DecodedDataMessage memory data
    ) internal {
        if (connectorContract.code.length == 0) return;
        try IClprConnector(connectorContract).onInboundMessage{gas: ctx.econ.connectorInboundGasStipend}(
            ctx.channelId, receivedMsgId, data.sender, data.targetApplication, data.messageData
        ) {}
        catch {
            emit ConnectorInboundCallbackFailed(ctx.channelId, receivedMsgId);
        }
    }

    /// @dev Process a REPLY message using a pre-decoded struct.
    ///      Uses connectorIdForReply to decrement inflight and slash even when the
    ///      original DATA payload has been redacted (zeroed).
    function _processReplyMessageDecoded(
        BundleContext memory ctx,
        ClprTypes.DecodedReply memory reply,
        mapping(bytes32 => mapping(uint64 => ClprTypes.MessageValue)) storage _messageQueues,
        mapping(bytes32 => ClprTypes.Connector) storage _connectors,
        mapping(bytes32 => bool) storage _connectorExists,
        mapping(bytes32 => uint256) storage _connectorInflightCount,
        mapping(bytes32 => mapping(bytes32 => uint32)) storage _connectorQueueCounts,
        mapping(address => uint256) storage _pendingWithdrawals
    ) internal {
        // Fetch original outbound message
        ClprTypes.MessageValue memory message = _messageQueues[ctx.channelId][reply.messageId];

        // Delete original immediately (before callback). Note: channel state updates are batched
        // in memory and persisted after all dispatches complete via _channels assignment.
        delete _messageQueues[ctx.channelId][reply.messageId];

        // connectorIdForReply holds the connectorId for every DATA original (redacted or not)
        // and is bytes32(0) for CONTROL/REPLY messages
        bytes32 connectorIdBytes = message.connectorIdForReply;
        if (connectorIdBytes == bytes32(0)) {
            emit ReplyDelivered(ctx.channelId, reply.messageId, reply.status);
            return;
        }

        // senderBytes stays empty for redacted DATA (payload is a ClprRedactedMessage marker); only recoverable from a live payload.
        bytes memory senderBytes;
        (, ClprTypes.MessageType msgType) = ClprProtobuf.tryGetMessageType(message.payload);
        if (msgType == ClprTypes.MessageType.DATA) {
            // Live (non-redacted) DATA: recover sender for the callback and decrement counters.
            // Counters were already decremented at redactMessage time for redacted slots.
            senderBytes = ClprProtobuf.decodeDataMessage(message.payload).sender;
            bytes32 inflightKey = keccak256(abi.encodePacked(ctx.channelId, connectorIdBytes));
            bytes32 quotaKey = keccak256(abi.encodePacked(connectorIdBytes));
            if (_connectorInflightCount[inflightKey] > 0) _connectorInflightCount[inflightKey]--;
            if (_connectorQueueCounts[ctx.channelId][quotaKey] > 0) {
                _connectorQueueCounts[ctx.channelId][quotaKey]--;
            }
        }

        // Source-side slashing (fires even for redacted DATA)
        if (
            reply.status == ClprTypes.ReplyStatus.CONNECTOR_NOT_FOUND
                || reply.status == ClprTypes.ReplyStatus.CONNECTOR_UNDERFUNDED
        ) {
            _slashConnector(ctx, connectorIdBytes, _connectors, _connectorExists, _pendingWithdrawals);
        }

        // Best-effort callback to sender application (only if sender is a 20-byte address).
        //
        // REENTRANCY INVARIANT: this hands control to untrusted application code while
        // channel state is mid-update. The storage maps touched above (message slot,
        // inflight/quota counters) are already written, but `channel` is an in-memory copy —
        // `_channels[channelId]` is NOT persisted until the dispatch loop finishes, so
        // storage still holds the pre-bundle cursors. Two things keep this safe:
        //   1. Write paths: submitBundle (and the other mutating entry points) are
        //      nonReentrant.
        //   2. Read paths: view functions are NOT guarded, so a read during this window can
        //      observe inconsistent state (read-only reentrancy). This is only safe because no
        //      CLPR view is consumed by another contract as an authoritative oracle. If that
        //      ever changes, such a view must revert under the reentrancy guard.
        if (senderBytes.length == 20 && _bytesToAddress(senderBytes).code.length > 0) {
            try IClprApplication(_bytesToAddress(senderBytes)).onClprResponse{gas: ctx.throttles.maxGasPerMessage}(
                ctx.channelId, reply.messageId, uint8(reply.status), reply.messageReplyData
            ) {}
                catch {}
        }

        emit ReplyDelivered(ctx.channelId, reply.messageId, reply.status);
    }

    // ── Internal: Helpers ──────────────────────────────────────────────────

    function _enqueueMessage(
        bytes32 channelId,
        ClprTypes.Channel memory channel,
        bytes memory payload,
        mapping(bytes32 => mapping(uint64 => ClprTypes.MessageValue)) storage _messageQueues,
        ClprTypes.MessageType msgType
    ) internal {
        bytes32 newHash = sha256(abi.encodePacked(channel.sentRunningHash, sha256(payload)));

        _messageQueues[channelId][channel.nextMessageId] =
            ClprTypes.MessageValue({payload: payload, runningHashAfterProcessing: newHash, connectorIdForReply: ""});

        emit MessageQueued(channelId, channel.nextMessageId, msgType);

        channel.nextMessageId++;
        channel.sentRunningHash = newHash;
    }

    /// @dev Encode a REPLY for inbound `receivedMsgId`, queue it, and emit MessageDispatched.
    ///      Consolidates the reply-then-emit pattern shared by every DATA dispatch outcome.
    function _enqueueReplyAndEmit(
        BundleContext memory ctx,
        ClprTypes.Channel memory channel,
        uint64 receivedMsgId,
        ClprTypes.ReplyStatus status,
        bytes memory responseData,
        mapping(bytes32 => mapping(uint64 => ClprTypes.MessageValue)) storage _messageQueues
    ) internal {
        bytes memory replyPayload = ClprProtobuf.encodeReplyMessage(receivedMsgId, status, responseData);
        _enqueueMessage(ctx.channelId, channel, replyPayload, _messageQueues, ClprTypes.MessageType.REPLY);
        emit MessageDispatched(ctx.channelId, receivedMsgId, status);
    }

    /// @dev Slash `connectorId` using the bundle's economic parameters. Shared by the DATA
    ///      underfunded / charge-failure paths and the REPLY source-side slash.
    function _slashConnector(
        BundleContext memory ctx,
        bytes32 connectorId,
        mapping(bytes32 => ClprTypes.Connector) storage _connectors,
        mapping(bytes32 => bool) storage _connectorExists,
        mapping(address => uint256) storage _pendingWithdrawals
    ) internal {
        (, bool banned) = ConnectorLib.slash(
            _connectors,
            _connectorExists,
            _pendingWithdrawals,
            ctx.fallbackRecipient,
            ctx.channelId,
            connectorId,
            ctx.bundleSubmitter,
            ctx.econ.basePenalty,
            ctx.econ.penaltyMultiplier,
            ctx.econ.slashBanThreshold
        );
        if (banned) ctx.bannedCount++;
    }

    /// @dev Convert bytes to an address. Returns address(0) for empty or non-20-byte input
    ///      rather than reverting, so a malformed address in a DATA payload results in
    ///      APPLICATION_ERROR (no-contract dispatch) instead of a whole-bundle revert.
    function _bytesToAddress(bytes memory b) internal pure returns (address addr) {
        if (b.length != 20) return address(0);
        assembly ("memory-safe") {
            addr := mload(add(b, 20))
        }
    }
}
