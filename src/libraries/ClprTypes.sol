// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title ClprTypes
/// @notice Shared enums, structs, and custom errors for the CLPR protocol
library ClprTypes {
    // ── Enums ──────────────────────────────────────────────────────────

    /// @dev Values match the proto `ClprChannelStatus` enum exactly so that
    ///      QueueMetadata round-trips through protobuf without an offset map.
    ///      PENDING is the proto3 default; on-chain we don't store Channels
    ///      in PENDING state (registration uses a separate commitment map),
    ///      but the value is reserved so wire-level encodings line up.
    enum ChannelStatus {
        PENDING,
        ACTIVE,
        PAUSED,
        CLOSING,
        DRAINED,
        CLOSED
    }

    /// @notice Outcome reported in a REPLY message. Matches the proto
    ///         `ClprReplyStatus` enum so wire values are the same.
    enum ReplyStatus {
        SUCCESS,
        APPLICATION_ERROR,
        CONNECTOR_NOT_FOUND,
        CONNECTOR_UNDERFUNDED
    }

    /// @notice CLPR wire message discriminator. Maps to the `oneof` field number in
    ///         `clpr_message.proto` (field 1 = DATA, 2 = REPLY, 3 = CONTROL).
    enum MessageType {
        DATA,
        REPLY,
        CONTROL
    }

    /// @notice Allowance, in bytes, for everything a single-message bundle adds on
    ///         top of the message's own variable-length fields.
    /// @dev Used by the sendMessage guard: a message may only be enqueued if it could be
    ///       delivered ALONE in a bundle within the peer's `maxSyncBytes`.
    ///       This constant is a last-resort guard.
    ///
    ///       Covers: protobuf framing, QueueMetadata (~200 B) and the consensus proof
    ///       envelope:
    ///         - Hiero: ~2 KB  (TSS aggregate signature + merkle path)
    ///         - QBFT: ~7 KB  (RLP header + 65 B seal per validator + MPT receipt proof)
    ///         - Sei: ~11 KB (CometBFT header + ~150 B per validator sigs/valset + ICS-23 proofs)
    ///         - Eth mainnet: ~15-30 KB with normal (>95%) sync-committee participation
    ///                   (beacon header, sync aggregate, SSZ branches, MPT account +
    ///                   storage proofs ~5k, 416 B per non-signer proof)
    uint256 internal constant WORST_CASE_BUNDLE_OVERHEAD = 32768;

    /// @dev Admission state of a local endpoint-manifest entry (`EndpointManifestEntry.status`).
    ///      `NONE` is the zero default (no entry). `PENDING` — self-registered via `registerEndpoint`,
    ///      bond escrowed, not yet advertised. `LIVE` — admitted by the admin; appears in
    ///      `getEndpointManifest` and is advertised to peers.
    enum EndpointStatus {
        NONE,
        PENDING,
        LIVE
    }

    // ── Structs ────────────────────────────────────────────────────────

    struct ChannelContext {
        bytes32 channelId;
        bytes remoteServiceAddress;
    }

    /// @dev Encode ChannelContext to opaque bytes: channelId (32) || remoteServiceAddress (rest).
    function encodeChannelContext(ChannelContext memory ctx) internal pure returns (bytes memory encoded) {
        return abi.encodePacked(ctx.channelId, ctx.remoteServiceAddress);
    }

    /// @dev Validate throttle parameters for protocol correctness.
    function validateThrottles(Throttles memory t) internal pure {
        if (t.maxGasPerMessage == 0) revert ClprInvalidConfiguration();
        if (t.maxMessagesPerBundle == 0) revert ClprInvalidConfiguration();
        if (t.maxMessagePayloadBytes == 0) revert ClprInvalidConfiguration();
        if (t.maxSyncBytes == 0) revert ClprInvalidConfiguration();
        if (t.maxQueueDepth == 0) revert ClprInvalidConfiguration();
    }

    /// @dev Decode opaque channel context bytes back to ChannelContext.
    function decodeChannelContext(bytes memory encoded) internal pure returns (ChannelContext memory ctx) {
        if (encoded.length < 32) revert ClprInvalidConfiguration();
        bytes32 channelId;
        assembly ("memory-safe") {
            channelId := mload(add(encoded, 32))
        }
        ctx.channelId = channelId;
        uint256 remoteLen = encoded.length - 32;
        bytes memory remote = new bytes(remoteLen);
        assembly ("memory-safe") {
            let dst := add(remote, 32) // start of remote's data region (skip length word)
            let src := add(encoded, 64) // skip encoded's length word (32) + channelId (32)
            for { let i := 0 } lt(i, remoteLen) { i := add(i, 32) } {
                mstore(add(dst, i), mload(add(src, i)))
            }
        }
        ctx.remoteServiceAddress = remote;
    }

    struct Channel {
        // slot 0
        bytes32 channelId;
        // slot 1: verifier (20) + status (1) + nextMessageId (8) = 29 bytes
        address verifier;
        ChannelStatus status;
        uint64 nextMessageId;
        // slot 2
        uint64 ackedMessageId;
        uint64 receivedMessageId;
        /// @dev The messageId of the next outbound DATA message for which we expect a REPLY.
        ///      Initialized to 1 at channel creation. Incremented past each matched DATA id as
        ///      REPLYs arrive. Ensures cross-bundle ordering is enforced.
        uint64 nextExpectedReplyId;
        // Timestamps derived from proto Timestamp{seconds,nanos} stored as nanosSinceEpoch (uint96).
        // slot 3: peerConfigTimestamp (12) + lastConfigTimestamp (12) = 24 bytes
        uint96 peerConfigTimestamp;
        uint96 lastConfigTimestamp;
        // slots 4–6: three bytes32 values
        bytes32 sentRunningHash;
        bytes32 receivedRunningHash;
        bytes32 ownershipCommitment;
        // slot 7: salt for channel derivation validation
        bytes32 salt;
        // dynamic-length fields (each slot holds a pointer)
        string chainId;
        bytes peerServiceAddress;
        Throttles peerThrottles;
        /// @dev Opaque trust anchor bytes managed by the verifier. EVM verifiers store the current
        ///      signing-key state here (e.g. sync committee, IBFT validator set hash, BLS aggregate key).
        bytes trustAnchor;
        /// @dev Highest message ID ever assigned to an outbound DATA message (sendMessage).
        ///      Zero when no DATA messages have been sent. Used by the CLOSING->DRAINED
        ///      transition: drains to DRAINED once all DATA messages with ID <=
        ///      lastDataMessageId are acknowledged. Response Messages generated during
        ///      CLOSING may still be in-flight and drain through the DRAINED state.
        uint64 lastDataMessageId;
        /// @dev Opaque identifier for `trustAnchor`, populated from
        ///      LedgerConfiguration.trustAnchorId (spec field 8) at completeChannel.
        ///      Non-empty iff `trustAnchor` is non-empty.
        bytes trustAnchorId;
        /// @dev Channel context: opaque bytes encoding ChannelContext{channelId, peerServiceAddress}
        ///     created at channel setup time by the verifier. Static data that does not evolve with the trust anchor.
        bytes channelContext;
        /// @dev Version of the cached peer manifest. The manifest itself is stored out-of-line in
        ///      `ClprServiceStorage._peerEndpointManifests` (keyed by channelId) so bundle
        ///      processing does not round-trip the full endpoint set through memory on every
        ///      submitBundle. `0` = uninitialized: PENDING, or completed without a manifest proof
        ///      (bring-up) — the first proven manifest (version >= 1) then applies via BundleLib
        ///      Step 1b. A manifest update is applied only when the proven version is strictly
        ///      greater than this value.
        uint64 endpointManifestVersion;
    }

    /// @dev Operating funds (used to pay for inbound message execution) live as native
    ///      balance on the {connectorContract} itself — the protocol pulls payment via
    ///      {IClprConnector.payForExecution}. {lockedStake} is the slashable bond and
    ///      is held by ClprService.
    struct Connector {
        bytes32 connectorId;
        address connectorContract;
        address admin;
        uint256 lockedStake;
        uint32 slashCount;
    }

    struct MessageValue {
        bytes payload; // protobuf-encoded ClprMessagePayload
        bytes32 runningHashAfterProcessing;
        /// @dev For outbound DATA messages: the connectorId, so REPLY processing can decrement the
        ///      in-flight and quota counters and perform source-side slashing. `bytes32(0)` for CONTROL/REPLY messages
        ///      (a real connectorId is a keccak256 hash, so it can never collide with the zero sentinel).
        bytes32 connectorIdForReply;
    }

    struct QueueDepth {
        uint64 queueDepth;
        uint32 maxQueueDepth;
    }

    /// @dev The sender's proven channel state at the proof's block. A bundle may carry only a prefix
    ///      of the sender's queue, so `nextMessageId`/`sentRunningHash` can run ahead of the bundle's
    ///      messages; `lastMessageId`/`lastMessageRunningHash` pin the bundle's own last message.
    struct QueueMetadata {
        uint64 nextMessageId;
        bytes32 sentRunningHash;
        uint64 receivedMessageId;
        bytes32 receivedRunningHash;
        ChannelStatus state;
        /// @dev The sender's current `Channel.endpointManifestVersion` (proto field 7). Lets the
        ///      receiver detect whether the remote endpoint manifest has advanced since the last sync
        ///      without a full state query. Zero indicates the (source) Channel is PENDING.
        uint64 endpointManifestVersion;
        /// @dev Id of the bundle's last message; 0 when the bundle carries no messages.
        uint64 lastMessageId;
        /// @dev The sender's running hash after `lastMessageId`; zero when the bundle carries no messages.
        bytes32 lastMessageRunningHash;
    }

    /// @param maxLocalEndpoints Max endpoints registrable locally on this ledger (via
    ///        `registerEndpoint`). `0` means no limit.
    /// @param maxPeerEndpoints  Max peer endpoints this ledger stores per Channel; a
    ///        peer's endpoint list is truncated to the first N on roster refresh. `0` means
    ///        no limit.
    struct Throttles {
        uint32 maxMessagesPerBundle;
        uint64 maxMessagePayloadBytes;
        uint64 maxGasPerMessage;
        uint32 maxQueueDepth;
        uint64 maxSyncBytes;
        uint32 maxLocalEndpoints;
        uint32 maxPeerEndpoints;
    }

    /// @dev `ecdsa_signing_key` was removed (endpoint signatures dropped from
    ///      ClprSyncPayload). The surviving wire fields are renumbered compactly:
    ///      service_endpoint=1, tls_certificate=2, account_id=3. Discovery fields only.
    struct Endpoint {
        string ipAddress;
        uint32 port;
        bytes tlsCertificate;
        bytes accountId;
    }

    /// @dev The authoritative, on-ledger endpoint set for a CLPR Service — distinct state, separate
    ///      from `LedgerConfiguration`. Service-scoped: all admitted endpoints serve every Channel.
    /// @param version Monotonically increasing counter; MUST be strictly positive (>= 1). Starts at 1
    ///        when first created, incremented by 1 on each change to the endpoint set. No correlation
    ///        to any other version numbers. `0` is the uninitialized sentinel (never a valid manifest).
    /// @param serviceAddress On-ledger address of the CLPR Service this manifest belongs to. State-proven
    ///        content; a verifier MUST reject a manifest proof whose serviceAddress does not match the
    ///        Channel's peer service address (ctx.remoteServiceAddress).
    /// @param endpoints Current endpoint set. May be empty: version >= 1 with no endpoints is valid.
    struct ClprEndpointManifest {
        uint64 version;
        bytes serviceAddress;
        Endpoint[] endpoints;
    }

    /// @dev Truncate `m.endpoints` in place to at most `maxPeerEndpoints` entries (`0` = no limit),
    ///      per the `max_peer_endpoints` throttle: a ledger caches at most N peer endpoints per
    ///      Channel. Applied at completeChannel and on manifest-carrying bundles before the
    ///      manifest is stored.
    function truncateEndpoints(ClprEndpointManifest memory m, uint32 maxPeerEndpoints) internal pure {
        Endpoint[] memory eps = m.endpoints;
        if (maxPeerEndpoints == 0 || eps.length <= maxPeerEndpoints) return;
        assembly ("memory-safe") {
            mstore(eps, maxPeerEndpoints)
        }
    }

    /// @dev Local endpoint-manifest entry, keyed by the registrant's on-ledger account (the caller of
    ///      `registerEndpoint`). Two-step admission (endpoint-manifest spec §6.5): `registerEndpoint`
    ///      creates a PENDING entry holding a bond; the admin promotes it to LIVE. The bond is returned
    ///      in full on any exit and is NEVER slashed (slashing applies only to Connectors).
    /// @param endpoint The advertised {Endpoint} discovery data (ip / port / tls / accountId).
    /// @param bond held in escrow for this entry; refunded in full on removal/cancellation.
    /// @param status {EndpointStatus} — PENDING or LIVE (NONE means no entry).
    struct EndpointManifestEntry {
        Endpoint endpoint;
        uint256 bond;
        EndpointStatus status;
    }

    /// @dev One addition in an `updateEndpointManifest` batch. If a PENDING registration exists for
    ///      `registrantAccount`, it is promoted using its self-registered data and `endpoint` is
    ///      ignored; otherwise `endpoint` is added directly with no bond.
    struct ManifestUpdateEntry {
        address registrantAccount;
        Endpoint endpoint;
    }

    /// @dev All local endpoint-manifest state for this CLPR Service, consolidated into a single storage
    ///      struct so {ManifestLib} can operate on one storage pointer.
    /// @param version Current manifest version. Seeded to 1 (empty) at construction; incremented by 1 on
    ///        each change to the LIVE set. Always >= 1; see {ClprEndpointManifest.version}.
    /// @param commitment `keccak256` over the canonical protobuf encoding of the current LIVE manifest;
    ///        updated on every change so a remote verifier can bind a single-slot storage proof to it.
    /// @param entries Registration records keyed by registrant account (PENDING or LIVE).
    /// @param liveAccounts Ordered registrant accounts currently LIVE — the manifest's endpoint order.
    /// @param liveCounter 1-based index into `liveAccounts` (0 = not live); enables O(1) swap-removal.
    struct EndpointManifestState {
        uint64 version;
        bytes32 commitment;
        mapping(address => EndpointManifestEntry) entries;
        address[] liveAccounts;
        mapping(address => uint256) liveCounter;
    }

    /// @dev Legacy view shape for a remote peer endpoint (spec §2.4.2 — the concept is
    ///      superseded by the cached peer `ClprEndpointManifest`). `getPeerEndpointRoster`
    ///      derives these on the fly from the Channel's cached manifest; nothing is
    ///      stored in this shape any more.
    /// @param ipAddress  Raw IP address bytes of the endpoint.
    /// @param port       TCP port the endpoint listens on.
    /// @param tlsCertificate DER-encoded TLS certificate for mutual-TLS.
    /// @param accountId  Opaque account identifier bytes (platform-specific).
    /// @param registered Always true in derived roster entries.
    struct PeerEndpoint {
        bytes ipAddress;
        uint32 port;
        bytes tlsCertificate;
        bytes accountId;
        bool registered;
    }

    struct LedgerConfiguration {
        uint32 protocolVersion;
        string chainId;
        bytes serviceAddress;
        /// @dev Combined timestamp: seconds*1e9 + nanos, as decoded from Timestamp{seconds=1, nanos=2}.
        uint96 nanosSinceEpoch;
        Throttles throttles;
        /// @dev Spec field 7 (`initial_trust_anchor`). Opaque starting trust anchor for a
        ///      Channel bootstrapped from this configuration. For Hiero TSS this is the
        ///      source ledger's ledger_id. Stored as Channel.trustAnchor at
        ///      completeChannel. Empty on stateless verifiers and between genesis and
        ///      the first admin update that establishes the ledger_id.
        bytes trustAnchor;
        /// @dev Spec field 8 (`initial_trust_anchor_id`). Opaque identifier for
        ///      `trustAnchor`. Non-empty iff `trustAnchor` is non-empty. Stored as
        ///      Channel.trustAnchorId at completeChannel.
        bytes trustAnchorId;
    }

    struct EconomicConfig {
        uint256 messageExecutionCost;
        uint256 endpointMarginPercent;
        uint256 minLockedStake;
        uint256 minEndpointBond;
        uint256 basePenalty;
        uint256 penaltyMultiplier;
        uint32 slashBanThreshold;
        uint32 connectorQueueQuotaPct;
        /// @dev Gas forwarded to each IClprConnector.onInboundMessage notification, less the CALL's own
        ///      cost; 0 means onInboundMessage is not called. If `stipend + stipend / 63` exceeds what the
        ///      chain's per-transaction gas cap leaves after proof verification, every bundle that notifies a
        ///      connector reverts.
        uint64 connectorInboundGasStipend;
        /// @dev Maximum number of channels allowed. 0 means no limit.
        uint32 maxChannels;
        /// @dev Maximum number of connectors allowed across all channels. 0 means no limit.
        uint32 maxConnectors;
        /// @dev Gas forwarded to each IClprConnector.payForExecution call, less the CALL's own cost; a payment
        ///      that runs out of it fails the charge, which for an inbound DATA message slashes the connector.
        ///      At least `MIN_CONNECTOR_PAYMENT_GAS_LIMIT`. If `limit + limit / 63` exceeds what the chain's
        ///      per-transaction gas cap leaves after proof verification, every bundle that charges a connector
        ///      reverts.
        uint64 connectorPaymentGasLimit;
    }

    /// @notice Smallest `EconomicConfig.connectorPaymentGasLimit` the configuration accepts.
    /// @dev Keeps the limit well above a plain transfer back to the service (about 9,500 gas): a limit too
    ///      small for any payment would fail every charge, slashing even a funded connector for each inbound
    ///      DATA message.
    uint256 internal constant MIN_CONNECTOR_PAYMENT_GAS_LIMIT = 50_000;

    /// @dev Decoded fields from a protobuf ClprMessage (DATA type)
    struct DecodedDataMessage {
        bytes32 connectorId;
        bytes targetApplication;
        bytes sender;
        bytes messageData;
    }

    /// @dev Decoded fields from a protobuf ClprMessageReply (REPLY type)
    struct DecodedReply {
        uint64 messageId;
        ReplyStatus status;
        bytes messageReplyData;
    }

    /// @dev Decoded fields from a protobuf ClprControlMessage (CONTROL type)
    struct DecodedControl {
        LedgerConfiguration config;
    }

    // ── Custom Errors ──────────────────────────────────────────────────

    /// @notice The referenced channel does not exist.
    error ClprChannelNotFound();
    /// @notice A channel with the same id has already been completed.
    error ClprChannelAlreadyExists();
    /// @notice Operation is not permitted in the current channel status.
    error ClprInvalidChannelStatus();
    /// @notice The commitment supplied at reveal does not match the registered commitment.
    error ClprCommitmentMismatch();
    /// @notice The channel id derived from the proof inputs does not match the expected id.
    error ClprInvalidChannelId();
    /// @notice The provided ECDSA signature or public key is invalid.
    error ClprInvalidSignature();
    /// @notice The verifier address has no deployed code.
    error ClprInvalidVerifierContract();
    /// @notice A logic module address passed to the constructor has no deployed code.
    error ClprModuleNotDeployed();
    /// @notice The referenced connector does not exist on the given channel.
    error ClprConnectorNotFound();
    /// @notice A connector with the same id already exists on this channel.
    error ClprConnectorAlreadyExists();
    /// @notice The connector contract address has no deployed code.
    error ClprInvalidConnectorContract();
    /// @notice The connector's stake is below the required minimum.
    error ClprInsufficientStake();
    /// @notice The connector contract rejected the outbound message.
    error ClprConnectorUnauthorized();
    /// @notice Cannot remove the connector while it has in-flight messages.
    error ClprConnectorHasInflightMessages();
    /// @notice The message payload exceeds the peer's configured size limit.
    error ClprPayloadTooLarge();
    /// @notice The outbound message queue has reached its maximum depth.
    error ClprQueueFull();
    /// @notice The connector's share of the queue has reached its per-connector quota.
    error ClprQueueQuotaExceeded();
    /// @notice The verifier rejected the bundle proof.
    error ClprBundleVerificationFailed();
    /// @notice The verifier rejected the bundle proof with oneOf variant.
    error ClprBundleVerificationFailedOneOfVariant();
    /// @notice The verifier rejected the bundle proof with empty payload.
    error ClprBundleVerificationFailedEmptyPayload();
    /// @notice A peer-originated protocol message carried a field number the negotiated protocol
    ///         version does not define. Both services committed to the same wire vocabulary at
    ///         channel establishment, so an extra field is evidence of version misalignment or a
    ///         malformed-output bug on the remote.
    error ClprUnknownWireField(uint64 fieldNumber);
    /// @notice The running SHA-256 hash chain is inconsistent with stored state.
    error ClprRunningHashMismatch();
    /// @notice The bundle's acknowledged range has already been processed (replay).
    error ClprReplayDetected();
    /// @notice The bundle's first message is at or before the sender's proven ackedMessageId.
    error ClprBundleStartsAtOrBeforeAcked();
    /// @notice A ConfigUpdate control message declared a protocol_version this ledger
    ///         does not recognize.
    error ClprProtocolVersionMismatch();
    /// @notice The bundle's acknowledged message cursor is inconsistent.
    error ClprAckVerificationFailed();
    /// @notice An invariant violation was detected; indicates a contract bug.
    error ClprInternalStateCorruption();
    /// @notice A configuration parameter fails a protocol validity check.
    error ClprInvalidConfiguration();
    /// @notice msg.sender is already registered as an endpoint.
    error ClprEndpointAlreadyRegistered();
    /// @notice msg.sender (or the given account) is not a registered endpoint.
    error ClprEndpointNotRegistered();
    /// @notice The supplied ETH bond is below the configured minimum.
    error ClprInsufficientBond();
    /// @notice `addEndpoint`/`updateEndpointManifest` would push the live manifest past
    ///         `maxLocalEndpoints`.
    error ClprEndpointManifestFull();
    /// @notice `removeEndpoint` caller is neither the registrant nor the CLPR Service owner.
    error ClprEndpointUnauthorized();
    /// @notice The service has reached the maximum allowed number of active channels.
    error ClprTooManyChannels();
    /// @notice The channel has reached the maximum allowed number of connectors.
    error ClprTooManyConnectors();
    /// @dev Reverted when a mutating operation is called while the service is disabled.
    error ClprDisabled();
    /// @dev Reverted by initialize() if called more than once.
    error ClprAlreadyInitialized();
    /// @dev Reverted by setClprEnabled(true) if initialize() has not been called yet.
    error ClprNotInitialized();
    /// @dev Reverted by submitBundle when the channel's maxBundlesPerSec limit is exceeded
    ///      within the current one-second window. Zero means unlimited (not enforced).
    error ClprBundleRateLimitExceeded();
    /// @notice An ETH transfer to the intended recipient failed.
    error ClprTransferFailed();
    /// @notice The pull-payment balance is zero; nothing to withdraw.
    error ClprNothingToCollect();
    /// @notice A chain identifier passed to _sortChains / deriveChannelId was empty.
    error ClprInvalidChainId();
    /// @notice An endpoint's IP address is not a valid numeric IPv4 or IPv6 address.
    error ClprInvalidEndpointAddress();
    /// @notice An endpoint's TLS certificate is not a valid DER-encoded RSA cert with ≥2048-bit key.
    error ClprInvalidEndpointCertificate();

    /// @dev Generic verifier failure carrying a human-readable reason, for covering the
    ///      error occurring during config verification (by the verifier)
    error VerifyFailed(string reason);
}

// ── Shared protocol events ─────────────────────────────────────────────────
// Declared at file level so both ClprService and BundleLib (inlined library)
// reference the same ABI entry, avoiding duplicate selectors in the metadata.
event ChannelStatusChanged(bytes32 indexed channelId, ClprTypes.ChannelStatus newStatus);

event MessageQueued(bytes32 indexed channelId, uint64 messageId, ClprTypes.MessageType messageType);
