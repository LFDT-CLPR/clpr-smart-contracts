// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "../libraries/ClprTypes.sol";
import {ClprConfigHash} from "../libraries/codec/ClprConfigHash.sol";
import {ManifestLib} from "../libraries/service/ManifestLib.sol";
import {FeeAssetLib} from "../libraries/service/FeeAssetLib.sol";
import {LogicModuleBase} from "./base/LogicModuleBase.sol";

/// @title AdminLogic
/// @notice Administrator operations: endpoint registration, ledger and economic
///         configuration, the kill switch, and pending-withdrawal collection.
/// @dev Executed via delegatecall from ClprService. All state reads and writes
///      operate on ClprServiceStorage slots in the router's storage.
contract AdminLogic is LogicModuleBase {
    constructor() {}

    // ── Public views ───────────────────────────────────────────────────────

    /// @notice Number of endpoints in the live manifest.
    function endpointCount() external view returns (uint256) {
        return ManifestLib.liveCount(_endpointManifest);
    }

    /// @notice Returns the full local ledger configuration.
    function getLedgerConfiguration() external view returns (ClprTypes.LedgerConfiguration memory) {
        return _config;
    }

    /// @notice One-word digest of the entire local `LedgerConfiguration`.
    /// @dev Equivalent to `keccak256(abi.encode(getLedgerConfiguration()))`.
    ///      Lets peers compare what they received in CONTROL messages against
    ///      this ledger's current config without ABI-decoding the full struct.
    function getLedgerConfigurationHash() external view returns (bytes32) {
        return ClprConfigHash.hashLedgerConfiguration(_config);
    }

    /// @notice Returns the current economic configuration.
    function getEconomicConfig() external view returns (ClprTypes.EconomicConfig memory) {
        return economicConfig;
    }

    /// @notice One-word digest of the peer-derived configuration snapshot for a
    ///         channel: chainId, peerServiceAddress, peerConfigTimestamp,
    ///         peerThrottles, trustAnchor, trustAnchorId. The per-channel peer
    ///         endpoint roster is intentionally excluded.
    /// @dev Reverts with `ClprChannelNotFound` for unknown channelIds.
    /// @param channelId The channel to hash.
    /// @return Digest of the peer-derived configuration fields.
    function getChannelPeerConfigHash(bytes32 channelId) external view returns (bytes32) {
        if (!_channelExists[channelId]) revert ClprTypes.ClprChannelNotFound();
        ClprTypes.Channel storage c = _channels[channelId];
        return ClprConfigHash.hashChannelPeerConfig(
            c.chainId, c.peerServiceAddress, c.peerConfigTimestamp, c.peerThrottles, c.trustAnchor, c.trustAnchorId
        );
    }

    /// @notice Returns the current live `ClprEndpointManifest` for this CLPR Service (public read).
    /// @dev Always version >= 1 (an empty manifest at version 1 is valid). This is the authoritative
    ///      endpoint discovery mechanism — peers query it and construct state proofs over it.
    function getEndpointManifest() external view returns (ClprTypes.ClprEndpointManifest memory) {
        return ManifestLib.getManifest(_endpointManifest, _config.serviceAddress);
    }

    /// @notice Returns the manifest entry (endpoint data, bond, status) for `account`, if any.
    /// @param account The registrant account to look up.
    function getEndpointEntry(address account) external view returns (ClprTypes.EndpointManifestEntry memory) {
        return _endpointManifest.entries[account];
    }

    /// @notice Pending fee-asset withdrawal balance for `account` (pull-payment pattern).
    function pendingWithdrawals(address account) external view returns (uint256) {
        return _pendingWithdrawals[account];
    }

    /// @notice The ERC-20 stakes, bonds and charges are paid in; `address(0)` means native value.
    function getFeeToken() external view returns (address) {
        return _feeAsset.token;
    }

    // ── Kill switch ────────────────────────────────────────────────────────

    /// @notice Enable or disable all mutating operations on the service.
    /// @dev Owner-only (via onlyService). Emits {ClprEnabledChanged}. When disabled, every mutating
    ///      op (registerChannel, completeChannel, closeChannel,
    ///      registerConnector, completeConnector, removeConnector, topUpConnectorStake,
    ///      registerEndpoint, addEndpoint, removeEndpoint, updateEndpointManifest,
    ///      sendMessage, submitBundle,
    ///      updateLedgerConfiguration, updateEconomicConfiguration)
    ///      reverts with ClprDisabled(). Read-only views are not affected.
    ///      Reverts with ClprNotInitialized() unless initialize() has already been called.
    function setClprEnabled(bool enabled) external onlyService whenInitialized {
        _clprEnabled = enabled;
        emit ClprEnabledChanged(enabled);
    }

    // ── Bootstrap ──────────────────────────────────────────────────────────

    /// @notice One-time bootstrap: apply the first ledger + economic configuration
    ///         while the service is still disabled.
    /// @dev Owner-only. Not gated by whenEnabled — must be called before
    ///      setClprEnabled(true) will succeed. Reverts with ClprAlreadyInitialized()
    ///      if called more than once. Does not itself enable the service; call
    ///      setClprEnabled(true) separately once the applied config has been verified.
    ///      Validates `throttles` as {updateLedgerConfiguration} and `econConfig` as
    ///      {updateEconomicConfiguration} do.
    /// @param serviceAddress ABI-encoded on-chain address of this CLPR service.
    /// @param trustAnchor Raw trust anchor bytes (e.g. a BLS public key). Empty to clear.
    /// @param trustAnchorId Identifier for the trust anchor. Must pair with trustAnchor.
    function initialize(
        bytes calldata serviceAddress,
        ClprTypes.Throttles calldata throttles,
        bytes calldata trustAnchor,
        bytes calldata trustAnchorId,
        ClprTypes.EconomicConfig calldata econConfig
    ) external onlyService {
        if (_isInitialized) revert ClprTypes.ClprAlreadyInitialized();
        _setLedgerConfiguration(serviceAddress, throttles, trustAnchor, trustAnchorId);
        _setEconomicConfiguration(econConfig);
        _isInitialized = true;
    }

    // ── Configuration ──────────────────────────────────────────────────────

    /// @notice Update the local ledger configuration.
    /// @dev Owner-only. Replaces serviceAddress, throttles, trustAnchor, and trustAnchorId
    ///      atomically. `nanosSinceEpoch` is set to block.timestamp converted to nanoseconds;
    ///      peers use it to detect config staleness. Reverts with {ClprInvalidConfiguration} unless
    ///      `trustAnchor` and `trustAnchorId` are both empty or both non-empty, and every throttle
    ///      except `maxLocalEndpoints` and `maxPeerEndpoints` is non-zero. Emits {LedgerConfigurationUpdated}.
    ///      Each application callback gets at most `throttles.maxGasPerMessage` gas. If
    ///      `maxGasPerMessage + maxGasPerMessage / 63` exceeds what the chain's per-transaction gas cap
    ///      leaves after proof verification, a callback that gets the full amount reverts its bundle.
    /// @param serviceAddress ABI-encoded on-chain address of this CLPR service.
    /// @param trustAnchor Raw trust anchor bytes (e.g. a BLS public key). Empty to clear.
    function updateLedgerConfiguration(
        bytes calldata serviceAddress,
        ClprTypes.Throttles calldata throttles,
        bytes calldata trustAnchor,
        bytes calldata trustAnchorId
    ) external onlyService whenEnabled {
        _setLedgerConfiguration(serviceAddress, throttles, trustAnchor, trustAnchorId);
    }

    /// @notice Replace the economic configuration.
    /// @dev Owner-only (via onlyService). Reverts with {ClprInvalidConfiguration} unless
    ///      `connectorQueueQuotaPct` is below 100 and `connectorPaymentGasLimit` is at least
    ///      `ClprTypes.MIN_CONNECTOR_PAYMENT_GAS_LIMIT`. Emits {EconomicConfigurationUpdated}.
    function updateEconomicConfiguration(ClprTypes.EconomicConfig calldata config) external onlyService whenEnabled {
        _setEconomicConfiguration(config);
    }

    function _setLedgerConfiguration(
        bytes calldata serviceAddress,
        ClprTypes.Throttles calldata throttles,
        bytes calldata trustAnchor,
        bytes calldata trustAnchorId
    ) private {
        // Spec invariant: trustAnchorId is non-empty iff trustAnchor is non-empty.
        if ((trustAnchor.length == 0) != (trustAnchorId.length == 0)) {
            revert ClprTypes.ClprInvalidConfiguration();
        }
        ClprTypes.validateThrottles(throttles);
        bool serviceAddressChanged = keccak256(_config.serviceAddress) != keccak256(serviceAddress);
        _config.serviceAddress = serviceAddress;
        _config.throttles = throttles;
        // Store as nanoseconds (seconds * 1e9) per the nanosSinceEpoch field convention.
        _config.nanosSinceEpoch = uint96(block.timestamp) * 1_000_000_000;
        _config.trustAnchor = trustAnchor;
        _config.trustAnchorId = trustAnchorId;

        // serviceAddress is embedded in the committed manifest encoding; keep the on-chain
        // commitment coherent with what getEndpointManifest() now returns.
        if (serviceAddressChanged) {
            ManifestLib.syncCommitment(_endpointManifest, serviceAddress);
        }

        emit LedgerConfigurationUpdated(_config.nanosSinceEpoch);
    }

    function _setEconomicConfiguration(ClprTypes.EconomicConfig calldata config) private {
        if (config.connectorQueueQuotaPct >= 100) revert ClprTypes.ClprInvalidConfiguration();
        if (config.connectorPaymentGasLimit < ClprTypes.MIN_CONNECTOR_PAYMENT_GAS_LIMIT) {
            revert ClprTypes.ClprInvalidConfiguration();
        }
        economicConfig = config;
        emit EconomicConfigurationUpdated();
    }

    // ── Endpoint management ────────────────────────────────────────────────

    /// @notice Self-register the caller as a PENDING endpoint, posting a bond.
    /// @dev Two-step admission: the caller does not appear in the live manifest until the
    ///      owner admits it via {addEndpoint}/{updateEndpointManifest}. The bond is held in escrow,
    ///      refunded in full on removal/cancellation, and never slashed. Permissionless — any caller;
    ///      registration does not gate submitBundle. The bond is `msg.value` in native mode (at least
    ///      `minEndpointBond`); in token mode exactly `minEndpointBond` is pulled with `transferFrom`
    ///      and `msg.value` must be 0.
    /// @param endpoint The endpoint discovery data to advertise once admitted.
    function registerEndpoint(ClprTypes.Endpoint calldata endpoint)
        external
        payable
        nonReentrant
        onlyService
        whenEnabled
    {
        uint256 minBond = economicConfig.minEndpointBond;
        uint256 bond = FeeAssetLib.pullAtLeast(_feeAsset, minBond);
        ManifestLib.registerEndpoint(_endpointManifest, endpoint, bond, minBond, msg.sender);
    }

    /// @notice Admit a registrant to the live endpoint manifest. Owner-only (enforced at ClprService).
    /// @dev Promotes a PENDING registration using its self-registered data (`endpoint` ignored), or adds
    ///      `endpoint` directly with no bond when no pending entry exists. Increments the manifest
    ///      version. Reverts with `ClprEndpointManifestFull` if already at `maxLocalEndpoints`.
    /// @param registrant The account to admit.
    /// @param endpoint Endpoint data for a direct add (ignored when a pending registration exists).
    function addEndpoint(address registrant, ClprTypes.Endpoint calldata endpoint) external onlyService whenEnabled {
        ManifestLib.addEndpoint(
            _endpointManifest, registrant, endpoint, _config.throttles.maxLocalEndpoints, _config.serviceAddress
        );
    }

    /// @notice Remove `registrant` from the live manifest or cancel its pending registration.
    /// @dev Authorized by the registrant itself or the CLPR Service owner. The bond is credited in full
    ///      to the registrant's pull-payment balance ({collectPending}) — never slashed, and a contract
    ///      registrant that rejects ETH cannot block removal. The manifest version is incremented only
    ///      if the entry was live (cancelling a pending registration does not change the manifest).
    /// @param registrant The account to remove.
    function removeEndpoint(address registrant) external onlyService whenEnabled {
        if (msg.sender != registrant && msg.sender != _getOwner()) revert ClprTypes.ClprEndpointUnauthorized();
        ManifestLib.removeEndpoint(_endpointManifest, _pendingWithdrawals, registrant, _config.serviceAddress);
    }

    /// @notice Atomically apply a batch of manifest additions and removals. Owner-only.
    /// @dev Removals refund bonds in full; already-live adds and non-existent removals are silently
    ///      skipped. The version is incremented exactly once if the batch changed the live
    ///      set. Reverts with `ClprEndpointManifestFull` if the post-add live count would exceed the limit.
    /// @param add Entries to admit (promote pending or direct-add).
    /// @param remove Registrant accounts to evict.
    function updateEndpointManifest(ClprTypes.ManifestUpdateEntry[] calldata add, address[] calldata remove)
        external
        onlyService
        whenEnabled
    {
        ManifestLib.updateEndpointManifest(
            _endpointManifest,
            _pendingWithdrawals,
            add,
            remove,
            _config.throttles.maxLocalEndpoints,
            _config.serviceAddress
        );
    }

    // ── Pull-payment ───────────────────────────────────────────────────────

    /// @notice Withdraw the caller's pending fee-asset balance (pull-payment).
    /// @dev Reverts with ClprNothingToCollect on a zero balance and ClprTransferFailed when the
    ///      transfer fails.
    function collectPending() external nonReentrant {
        _collectPending(msg.sender);
    }

    /// @notice Withdraw the caller's pending fee-asset balance to `recipient`.
    /// @dev Lets an account the fee asset will not pay, such as one a fee token blocks, redirect its credit.
    ///      Reverts with ClprZeroRecipient for `address(0)`, otherwise like {collectPending}.
    function collectPendingTo(address recipient) external nonReentrant {
        if (recipient == address(0)) revert ClprTypes.ClprZeroRecipient();
        _collectPending(recipient);
    }

    function _collectPending(address recipient) private {
        uint256 amount = _pendingWithdrawals[msg.sender];
        if (amount == 0) revert ClprTypes.ClprNothingToCollect();
        _pendingWithdrawals[msg.sender] = 0;
        FeeAssetLib.send(_feeAsset, recipient, amount);
    }
}
