// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";

/// @title ClprServiceStorage
/// @dev Shared base class for ClprService router and all logic modules.
/// Uses OpenZeppelin's ReentrancyGuardTransient (EIP-1153 transient storage).
///
/// This is safe for the following reasons:
/// 1. ReentrancyGuardTransient is purpose-built for reentrancy protection — the documented
///    safe use case for EIP-1153 transient storage per the EIP specification.
/// 2. The transient storage flag is cleared at the end of each call, preventing cross-call
///    interference within the same transaction.
/// 3. OpenZeppelin's implementation correctly manages the transient state lifecycle.
/// See: https://eips.ethereum.org/EIPS/eip-1153#security-and-composability
///
/// @notice ALL contracts in the router/logic system MUST inherit this in the same
///         order so every contract sees identical storage slot assignments.
///         ReentrancyGuardTransient stores its flag in EIP-1153 transient storage
///         at a hash-derived slot, so it claims no sequential storage slot.
///         Protocol fields start at slot 0.
///
///         Layout is grouped by change-risk so future maintainers can edit safely:
///         hot-path first, then packable scalars, then primitive-valued mappings,
///         then mapping-of-struct values, then direct struct state variables last
///         (appending fields to a trailing struct does not displace other state).
///
///         Note: Owner is stored in ClprService (via Ownable) using EIP-7201 namespaced
///         storage. Logic modules access it via direct owner() calls when executed via
///         DELEGATECALL from ClprService, which shares the same storage context.
/// slither-disable=transient-storage
abstract contract ClprServiceStorage is ReentrancyGuardTransient {
    // ── Service Authorization ────────────────────────────────────────────
    /// @dev The authorized ClprService address. Shared across all logic modules via DELEGATECALL.
    /// Set once during ClprService initialization and never changed.
    /// slither-disable-next-line uninitialized-state
    address internal _authorizedService;

    // ── Hot path ──────────────────────────────────────────────────────────
    /// @dev channelId => messageId => MessageValue
    mapping(bytes32 => mapping(uint64 => ClprTypes.MessageValue)) internal _messageQueues;

    // ── Non-struct: packable scalars ──────────────────────────────────────
    /// @dev Address of the BundleDecodeHelper contract used for try/catch around
    ///      protobuf decode in BundleLib. Set once in ClprService constructor;
    ///      never changed thereafter. Packs with `_clprEnabled` in the same slot.
    // slither-disable-next-line uninitialized-state
    address internal _bundleDecodeHelper;
    /// @dev Global enable flag. Initialized to false (default Solidity bool; spec §7
    ///      default clpr_enabled = false) — the service is inert until the owner
    ///      explicitly calls setClprEnabled(true) post-deployment.
    ///      When false, all mutating operations revert with ClprDisabled().
    ///      Set via AdminLogic.setClprEnabled(bool). Packs with `_bundleDecodeHelper`.
    // slither-disable-next-line uninitialized-state
    bool internal _clprEnabled;
    /// @dev One-time bootstrap latch set by AdminLogic.initialize(). setClprEnabled(true) reverts
    ///      until this is set, so the service can never go live with default (zero-value) config.
    ///      Packs with `_bundleDecodeHelper` and `_clprEnabled` in the same slot.
    // slither-disable-next-line uninitialized-state
    bool internal _isInitialized;
    uint256 internal _channelCount;
    // slither-disable-next-line uninitialized-state
    uint256 internal _connectorCount;

    // ── Non-struct: primitive-valued mappings ─────────────────────────────
    // slither-disable-next-line uninitialized-state
    mapping(bytes32 => bool) internal _channelExists;
    /// @dev commitmentHash => pending
    mapping(bytes32 => bool) internal _pendingCommitments;
    mapping(bytes32 => bool) internal _connectorExists;
    /// @dev commitment => registered (commit phase for connector registration)
    mapping(bytes32 => bool) internal _pendingConnectorCommitments;
    mapping(bytes32 => uint256) internal _connectorInflightCount;
    /// @dev channelId => connectorKey => unacked DATA message count
    mapping(bytes32 => mapping(bytes32 => uint32)) internal _connectorQueueCounts;
    mapping(address => uint256) internal _pendingWithdrawals;
    /// @dev Maps channelId => ownershipCommitment so closeChannel can find
    ///      and delete the pending commitment for not-yet-completed channels.
    ///      Populated at registerChannel time; deleted at completeChannel or
    ///      closeChannel.
    mapping(bytes32 => bytes32) internal _channelIdToCommitment;
    /// @dev DEPRECATED, slot reserved (13). The per-channel peer endpoint roster was superseded
    ///      by `_peerEndpointManifests`; the variable is retained so `_channels` stays at slot 15
    ///      (pinned by the EVM verifiers' storage-slot derivation and the relay tooling).
    mapping(bytes32 => uint32) internal _deprecatedPeerEndpointCount;
    /// @dev DEPRECATED, slot reserved (14). See `_deprecatedPeerEndpointCount`.
    mapping(bytes32 => bytes32[]) internal _deprecatedPeerEndpointAccounts;

    // ── Risky: mapping-of-struct values ───────────────────────────────────
    /// @dev channelId => Channel
    // slither-disable-next-line uninitialized-state
    mapping(bytes32 => ClprTypes.Channel) internal _channels;
    mapping(bytes32 => ClprTypes.Connector) internal _connectors;
    /// @dev Local endpoint manifest state (versioned two-step admission; ManifestLib operates on it).
    ///      Replaces the former flat `_endpoints` registry — the manifest is now the endpoint registry.
    ClprTypes.EndpointManifestState internal _endpointManifest;
    /// @dev channelId => cached peer `ClprEndpointManifest` (the remote CLPR Service's on-ledger
    ///      manifest). Populated at `completeChannel` from the manifest `verifyConfig` returns;
    ///      refreshed through manifest-carrying bundle payloads (BundleLib Step 1b). Stored
    ///      out-of-line from the Channel struct so submitBundle does not round-trip the full
    ///      endpoint set through memory on every bundle. Truncated to
    ///      `throttles.maxPeerEndpoints` entries when that throttle is non-zero.
    mapping(bytes32 => ClprTypes.ClprEndpointManifest) internal _peerEndpointManifests;

    // ── Risky: direct struct state vars (append-only-safe by virtue of being last) ──
    // slither-disable-next-line uninitialized-state
    ClprTypes.LedgerConfiguration internal _config;
    // slither-disable-next-line uninitialized-state
    ClprTypes.EconomicConfig internal economicConfig;

    function _checkEnabled() internal view {
        if (!_clprEnabled) revert ClprTypes.ClprDisabled();
    }

    function _checkInitialized() internal view {
        if (!_isInitialized) revert ClprTypes.ClprNotInitialized();
    }

    /// @dev Read owner from ClprService's Ownable storage (sequential slot 38).
    /// When called via DELEGATECALL from ClprService, reads ClprService's owner.
    /// @dev This slot is the sequential position of OpenZeppelin `Ownable._owner`,
    ///      immediately after this contract's storage (last var `economicConfig`).
    ///      It shifts whenever a storage layout above it changes; `ClprStorageLayoutGuard`
    ///      pins it against `storage-layout.json`'s `_owner` slot to catch silent drift.
    function _getOwner() internal view returns (address owner_) {
        bytes32 slot = bytes32(uint256(38));
        assembly ("memory-safe") {
            owner_ := sload(slot)
        }
    }

    // ── Events ─────────────────────────────────────────────────────────────
    event ChannelRegistered(bytes32 indexed commitment);
    event ChannelCompleted(
        bytes32 indexed channelId,
        string chainId,
        bytes peerServiceAddress,
        address verifier,
        bytes32 verifierFingerprint
    );
    event LedgerConfigurationUpdated(uint96 nanosSinceEpoch);
    event EconomicConfigurationUpdated();
    /// @dev Emitted when a message payload cannot be decoded during bundle dispatch.
    ///      The channel transitions to PAUSED; remaining messages in the bundle are skipped.
    event BundleParseFailed(bytes32 indexed channelId, uint64 receivedMessageId);
    /// @dev Emitted when the global kill switch is toggled.
    event ClprEnabledChanged(bool enabled);
}
