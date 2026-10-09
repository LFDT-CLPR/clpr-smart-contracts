// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";

/// @title IClprService
/// @notice The main entry point for the CLPR cross-ledger messaging protocol.
/// @dev This interface intentionally excludes the owner-only configuration updates and channel close.
///      It is the stable contract that external callers — applications,
///      connector contracts, bundle submitters, and integrators — should code
///      against. Implementations are expected to enforce reentrancy protection on
///      the state-modifying entry points (sendMessage, submitBundle).
///
///      Note on state-reading functions: functions that read contract storage
///      (getChannel, getLedgerConfiguration, etc.) are NOT annotated `view`
///      because the DELEGATECALL-based router cannot use `view`-annotated
///      delegatecall dispatch in Solidity 0.8. Off-chain callers should invoke
///      these via `eth_call` (staticcall) for gas-free reads. Only truly pure
///      helper functions (deriveChannelId, deriveConnectorId) retain `view`.
interface IClprService {
    // ── Channel lifecycle ───────────────────────────────────────────

    /// @notice Register a channel commitment (commit phase of commit-reveal).
    /// @dev Permissionless. Idempotent: re-registering the same commitment is a no-op.
    ///      A subsequent call to {completeChannel} with matching parameters
    ///      finalizes the channel.
    ///
    ///      The `channelId` parameter is used to build a reverse index so that
    ///      {closeChannel} can locate and purge pending (not-yet-revealed) commitments.
    ///      The service does not verify `channelId == keccak(channelId||pubKey)` at
    ///      registration time — that check happens at reveal. Callers MUST supply the
    ///      correct `channelId` (i.e., the value from {deriveChannelId}) or
    ///      {closeChannel} will not be able to clean up the pending entry.
    /// @param channelId The expected channel identifier, from {deriveChannelId}.
    /// @param commitment keccak256(channelId || pubKey). `pubKey` is the signer's
    ///        public-key bytes — encoding is platform-specific (e.g. 64-byte uncompressed
    ///        secp256k1 X||Y on this platform; Ed25519 / Falcon on others). The hash
    ///        function is fixed cross-platform so the commitment matches on both ledgers
    ///        when the same keypair is used.
    function registerChannel(bytes32 channelId, bytes32 commitment) external;

    /// @notice Complete a channel (reveal phase). Validates the prior commitment,
    ///         the ECDSA signature over `channelId`, the verifier contract, and
    ///         the peer configuration via {IClprVerifier.verifyConfig}.
    /// @dev Permissionless. On success the channel enters ACTIVE status and
    ///      can be used for {sendMessage} and {submitBundle}.
    /// @param channelId Unique identifier for the channel. Must equal the value
    ///        returned by {deriveChannelId}(peerChainId, pubKey, salt).
    /// @param pubKey Signer's public-key bytes used in the commitment. On this platform:
    ///        the 64-byte uncompressed secp256k1 public key (X || Y, no 0x04 prefix).
    ///        The Ethereum address used for signature verification is derived as the low
    ///        20 bytes of keccak256(pubKey).
    /// @param sig 65-byte ECDSA signature over keccak256(channelId) with the
    ///        Ethereum signed-message prefix
    /// @param salt Operator-chosen bytes32 label included in channelId derivation
    /// @param verifier Address of the {IClprVerifier} contract for this channel
    /// @param configProof Opaque config proof bytes passed to verifier.verifyConfig().
    ///        The verifier returns the initial trust anchor as part of the config proof result;
    ///        callers no longer supply it directly (the verifier is the source of truth).
    /// @param endpointManifestProof Proof of the peer's `ClprEndpointManifest`, forwarded to
    ///        verifier.verifyConfig() as its third argument. Must be verifiable against the same
    ///        initial trust anchor the config proof establishes; the returned manifest becomes
    ///        the Channel's initial peer manifest. May be empty for bring-up — the Channel
    ///        then starts with an uninitialized (version 0) peer manifest and the first
    ///        manifest-carrying bundle populates it.
    function completeChannel(
        bytes32 channelId,
        bytes calldata pubKey,
        bytes calldata sig,
        bytes32 salt,
        address verifier,
        bytes calldata configProof,
        bytes calldata endpointManifestProof
    ) external;

    /// @notice Derive a channelId deterministically from (peerChainId, pubKey, salt).
    ///         Applications can call this to compute the expected channelId before
    ///         calling {registerChannel} and {completeChannel}.
    /// @param peerChainId CAIP-2 chain ID of the peer ledger
    /// @param pubKey Full operator public key (64 bytes on EVM)
    /// @param salt Operator-chosen bytes32 label
    /// @return The derived channelId
    // Reads _config.chainId from router storage; cannot be view on the router.
    function deriveChannelId(string calldata peerChainId, bytes calldata pubKey, bytes32 salt)
        external
        returns (bytes32);

    // ── Message operations ─────────────────────────────────────────────

    /// @notice Queue an outbound DATA message on the given channel.
    /// @dev Permissionless at the Solidity level: anyone may call. Authorization
    ///      is delegated to the source connector contract via
    ///      {IClprConnector.authorizeOutboundMessage}, which is invoked by the service
    ///      and must return true for the call to succeed. The channel must
    ///      exist and be ACTIVE; payload size, queue depth, and per-connector
    ///      quota throttles are enforced.
    ///
    ///      The `sender` field in the queued payload is stamped as
    ///      `abi.encodePacked(msg.sender)` — the on-chain caller address. Callers
    ///      cannot supply their own sender value. Applications on the destination
    ///      side may rely on this field for attribution but MUST NOT trust any
    ///      in-band "from" claim in `messageData` without independent verification.
    /// @param channelId The channel to send on
    /// @param connectorId Opaque source-connector identifier; must be
    ///        registered with the {IClprService}
    /// @param targetApplication Destination application address bytes (peer chain)
    /// @param messageData Application-defined payload
    /// @return messageId The assigned outbound message ID
    function sendMessage(
        bytes32 channelId,
        bytes32 connectorId,
        bytes calldata targetApplication,
        bytes calldata messageData
    ) external returns (uint64 messageId);

    /// @notice Submit an inbound bundle for processing on the given channel.
    /// @dev Permissionless: any caller may submit. Bundle correctness is secured
    ///      entirely by the channel's verifier; there is no endpoint-registration
    ///      gate and no endpoint signature. `msg.sender` is recorded as the bundle submitter and
    ///      is the sole recipient of connector charges and slash proceeds for messages
    ///      in this bundle. Reverts with `ExactGasCall.InsufficientGasForCall` when the gas left
    ///      cannot give a callback its budget, less the CALL's own cost, under the EIP-150 63/64 rule.
    ///
    /// @param proofBytes Opaque proof bytes passed to the channel's verifier
    function submitBundle(bytes32 channelId, bytes calldata proofBytes) external;

    // ── State reads ────────────────────────────────────────────────────
    // NOTE: these functions are not annotated `view` because the router uses
    // DELEGATECALL dispatch and Solidity 0.8 forbids delegatecall in view
    // functions. Off-chain callers should use eth_call for gas-free reads.

    /// @notice Retrieve a channel by ID.
    /// @dev Reverts with `ClprChannelNotFound` if the channel does not exist.
    /// @param channelId The channel identifier
    /// @return The full channel record
    function getChannel(bytes32 channelId) external returns (ClprTypes.Channel memory);

    /// @notice Retrieve the per-Channel peer endpoint roster (legacy §2.4.2 view shape),
    ///         derived on the fly from the Channel's cached peer `ClprEndpointManifest`.
    /// @dev An unknown channel or an empty manifest yields an empty array rather than
    ///      reverting. Prefer {getPeerEndpointManifest} for the authoritative shape.
    /// @param channelId The channel identifier
    /// @return The peer endpoint roster for the channel
    function getPeerEndpointRoster(bytes32 channelId) external returns (ClprTypes.PeerEndpoint[] memory);

    /// @notice Retrieve the Channel's cached peer `ClprEndpointManifest`.
    /// @dev Returns a zero manifest (version 0) for an unknown channel or one completed
    ///      without a manifest proof (bring-up).
    /// @param channelId The channel identifier
    /// @return The cached peer endpoint manifest for the channel
    function getPeerEndpointManifest(bytes32 channelId) external returns (ClprTypes.ClprEndpointManifest memory);

    /// @notice Retrieve the current ledger configuration (protocol version,
    ///         chain ID, service address, throttles, timestamp).
    /// @return The current ledger configuration
    function getLedgerConfiguration() external returns (ClprTypes.LedgerConfiguration memory);

    /// @notice One-word digest of every field of the local `LedgerConfiguration`,
    ///         including spec fields 7 (`trustAnchor`) and 8 (`trustAnchorId`).
    ///         Lets peers and observers verify configuration equality without
    ///         ABI-decoding the full struct.
    /// @dev Off-chain recomputation, in field order, MUST encode the fields as
    ///      a flat ABIv2 tuple (NOT the whole struct — that prepends an outer
    ///      offset pointer and produces a different digest):
    ///
    ///        keccak256(abi.encode(
    ///            uint32  protocolVersion,
    ///            string  chainId,
    ///            bytes   serviceAddress,
    ///            uint96  nanosSinceEpoch,
    ///            Throttles throttles,
    ///            bytes   trustAnchor,
    ///            bytes   trustAnchorId
    ///        ))
    /// @return The keccak256 digest of the current ledger configuration
    function getLedgerConfigurationHash() external returns (bytes32);

    /// @notice One-word digest of the peer-derived configuration snapshot stored
    ///         on a `Channel`: chainId, peerServiceAddress, peerConfigTimestamp,
    ///         peerThrottles, trustAnchor, trustAnchorId. The per-channel
    ///         peer-endpoint roster is intentionally excluded.
    /// @dev Reverts with `ClprChannelNotFound` for unknown channelIds.
    /// @param channelId The channel identifier
    /// @return The keccak256 digest of the peer-config snapshot for the channel
    function getChannelPeerConfigHash(bytes32 channelId) external returns (bytes32);

    /// @notice Retrieve the current economic configuration (execution cost,
    ///         margins, stake/penalty parameters, connector inbound gas stipend).
    /// @return The current economic configuration
    function getEconomicConfig() external returns (ClprTypes.EconomicConfig memory);

    /// @notice Retrieve a message from a channel's queue.
    /// @dev Zero-valued (empty `payload`) for an unsent ID and once the slot is pruned: a DATA
    ///      message when its REPLY is processed, a CONTROL/REPLY message when the peer acknowledges it.
    /// @return The stored message value (payload + running hash after processing)
    function getMessage(bytes32 channelId, uint64 messageId) external returns (ClprTypes.MessageValue memory);

    /// @notice Retrieve the outbound queue depth for a channel: the number of DATA
    ///         messages sent but not yet acknowledged by the peer, and the configured
    ///         maximum queue depth throttle. Used by connectors and monitoring tooling
    ///         to observe backpressure.
    /// @dev Reverts with `ClprChannelNotFound` if the channel does not exist.
    /// @param channelId The channel identifier
    /// @return QueueDepth current depth and configured max queue depth
    function getQueueDepth(bytes32 channelId) external returns (ClprTypes.QueueDepth memory);

    // ── Connector management ───────────────────────────────────────────

    /// @notice Register a connector commitment (commit phase).
    function registerConnector(bytes32 commitment) external;

    /// @notice Complete connector registration (reveal phase).
    /// @param connectorId Must equal keccak256(channelId || pubKey || salt) packed as bytes.
    /// @param pubKey Full operator public key. On EVM: 64-byte uncompressed secp256k1 (X || Y).
    /// @param sig ECDSA signature over keccak256(connectorId || address(this)) with Ethereum prefix.
    /// @param salt Operator-chosen label differentiating connectors on the same channel.
    /// @param channelId The channel this connector is bound to.
    /// @param connectorContract Local contract implementing IClprConnector.
    /// @param admin Address authorized to deregister and top up stake.
    function completeConnector(
        bytes32 connectorId,
        bytes calldata pubKey,
        bytes calldata sig,
        bytes32 salt,
        bytes32 channelId,
        address connectorContract,
        address admin
    ) external payable;

    /// @notice Deterministically compute a connectorId.
    function deriveConnectorId(bytes32 channelId, bytes calldata pubKey, bytes32 salt) external view returns (bytes32);

    /// @notice Remove a connector and return the locked stake to `recipient`.
    function removeConnector(bytes32 channelId, bytes32 connectorId, address recipient) external;

    /// @notice Add ETH to a connector's locked stake.
    function topUpConnectorStake(bytes32 channelId, bytes32 connectorId) external payable;

    function getConnector(bytes32 channelId, bytes32 connectorId) external returns (ClprTypes.Connector memory);

    function hasConnector(bytes32 channelId, bytes32 connectorId) external returns (bool);

    // ── Endpoint manifest management (two-step admission, spec §6.5) ─────────

    /// @notice Self-register as a PENDING endpoint, locking `msg.value` as a refundable bond
    ///         (a quality/Sybil-resistance deposit; never slashed). Permissionless — any caller.
    /// @dev The caller is not advertised until the owner admits it via {addEndpoint}. Registration
    ///      does not gate {submitBundle}. Reverts if `msg.value < minEndpointBond`.
    /// @param endpoint The endpoint discovery data to advertise once admitted.
    function registerEndpoint(ClprTypes.Endpoint calldata endpoint) external payable;

    /// @notice Owner-only. Admit `registrant` to the live manifest (promote a pending registration or
    ///         directly add `endpoint`). Increments the manifest version.
    function addEndpoint(address registrant, ClprTypes.Endpoint calldata endpoint) external;

    /// @notice Remove `registrant` from the live manifest or cancel its pending registration.
    /// @dev Callable by the registrant itself or the owner. Bond refunded in full (pull-payment).
    function removeEndpoint(address registrant) external;

    /// @notice Owner-only. Atomically apply a batch of manifest additions and removals (version bumped once).
    function updateEndpointManifest(ClprTypes.ManifestUpdateEntry[] calldata add, address[] calldata remove) external;

    /// @notice Returns the current live `ClprEndpointManifest` (public read; always version >= 1).
    function getEndpointManifest() external returns (ClprTypes.ClprEndpointManifest memory);

    /// @notice Returns the manifest entry (endpoint, bond, status) for `account`.
    function getEndpointEntry(address account) external returns (ClprTypes.EndpointManifestEntry memory);

    // ── Kill switch ────────────────────────────────────────────────────────

    /// @notice Enable or disable all mutating operations on the service.
    /// @dev Owner-only. When `enabled` is false, every mutating operation
    ///      (registerChannel, completeChannel, closeChannel,
    ///      registerConnector, completeConnector, removeConnector,
    ///      topUpConnectorStake, registerEndpoint, addEndpoint, removeEndpoint,
    ///      updateEndpointManifest, sendMessage, submitBundle,
    ///      updateLedgerConfiguration, updateEconomicConfiguration) reverts
    ///      with {ClprDisabled}. Read-only views and {setClprEnabled} itself are
    ///      not gated by the enabled check, so the owner can always re-enable the
    ///      service. {setClprEnabled} reverts with {ClprNotInitialized} unless
    ///      {initialize} has already been called — once it has, this never blocks
    ///      again (there is no un-initializing).
    function setClprEnabled(bool enabled) external;

    /// @notice One-time bootstrap: apply the first ledger + economic configuration
    ///         while the service is still disabled.
    /// @dev Owner-only. Not gated by the enabled check — must be called before
    ///      {setClprEnabled} will succeed. Reverts with {ClprAlreadyInitialized}
    ///      if called more than once. Does not itself enable the service.
    ///      Reverts with {ClprInvalidConfiguration} when a throttle other than `maxLocalEndpoints` and
    ///      `maxPeerEndpoints` is zero, `econConfig.connectorQueueQuotaPct` is 100 or more, or
    ///      `econConfig.connectorPaymentGasLimit` is below `ClprTypes.MIN_CONNECTOR_PAYMENT_GAS_LIMIT`.
    /// @param serviceAddress ABI-encoded on-chain address of this CLPR service.
    /// @param trustAnchor Raw trust anchor bytes. Empty to clear.
    /// @param trustAnchorId Identifier for the trust anchor. Must pair with trustAnchor.
    function initialize(
        bytes calldata serviceAddress,
        ClprTypes.Throttles calldata throttles,
        bytes calldata trustAnchor,
        bytes calldata trustAnchorId,
        ClprTypes.EconomicConfig calldata econConfig
    ) external;
}
