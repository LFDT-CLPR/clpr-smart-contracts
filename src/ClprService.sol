// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";
import {ClprServiceStorage} from "@hiero-ledger/clpr/ClprServiceStorage.sol";
import {ManifestLib} from "@hiero-ledger/clpr/libraries/service/ManifestLib.sol";
import {FeeAssetLib} from "@hiero-ledger/clpr/libraries/service/FeeAssetLib.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title ClprService
/// @notice Immutable DELEGATECALL router for the CLPR protocol. All state lives
///         here (via ClprServiceStorage). Logic is distributed across four immutable
///         logic contracts deployed in the constructor. Not upgradeable.
///
/// @dev State-reading "view" functions (getChannel, getLedgerConfiguration, etc.)
///      are intentionally NOT annotated `view` on the router because Solidity's
///      compiler forbids `delegatecall` inside a `view`-annotated function. At the
///      EVM level these calls are safe to invoke via `eth_call` (staticcall) — callers
///      using ethers.js / viem / cast will use `eth_call` automatically for read-only
///      operations. Only `deriveConnectorId` retains `view` (truly pure — no
///      storage reads) and is dispatched via `staticcall`.
contract ClprService is ClprServiceStorage, Ownable, IClprService {
    /// @notice Reverts when a logic module address supplied to the constructor is zero.
    error ZeroLogicAddress();

    address private immutable _CHANNEL_LOGIC;
    address private immutable _MESSAGING_LOGIC;
    address private immutable _BUNDLE_LOGIC;
    address private immutable _CONNECTOR_LOGIC;
    address private immutable _ADMIN_LOGIC;
    /// @dev Mirrors `_feeAsset.token` so receive() can reject native value without an SLOAD.
    address private immutable _FEE_TOKEN;

    /// @notice Deploy the CLPR service router with the given logic module addresses.
    /// @dev Each logic address is validated non-zero and deployed (code.length > 0).
    ///      Reverts with ClprInvalidFeeToken unless a non-zero feeToken's `decimals()` is readable
    ///      and at most `FeeAssetLib.MAX_DECIMALS`.
    ///      The kill switch is initialized to disabled.
    ///      The service is inert until the owner explicitly calls setClprEnabled(true) after
    ///      configuring bonds, throttles, and ledger config. protocolVersion and chainId
    ///      are stored in the shared LedgerConfiguration and never change.
    /// @param initialOwner Address granted Ownable ownership.
    /// @param protocolVersion CLPR protocol version encoded in the ledger configuration.
    /// @param chainId CAIP-2 chain identifier for this deployment.
    /// @param channelLogic Deployed ChannelLogic contract address.
    /// @param messagingLogic Deployed MessagingLogic contract address.
    /// @param bundleLogic Deployed BundleLogic contract address.
    /// @param connectorLogic Deployed ConnectorLogic contract address.
    /// @param adminLogic Deployed AdminLogic contract address.
    /// @param bundleDecodeHelper Deployed BundleDecodeHelper contract address.
    /// @param feeToken ERC-20 that stakes, bonds, execution charges and slash proceeds are paid in, or
    ///        `address(0)` for native value; fixed for the life of the service. The execution charge
    ///        scales gasUsed × `tx.gasprice` to token units by 10^(decimals - 18), so
    ///        `tx.gasprice` must be quoted in the token's currency at 18 decimals. Fee-on-transfer and
    ///        rebasing tokens are unsupported: deposits revert unless the exact amount arrives, and
    ///        held balances must not change on their own.
    constructor(
        address initialOwner,
        uint32 protocolVersion,
        string memory chainId,
        address channelLogic,
        address messagingLogic,
        address bundleLogic,
        address connectorLogic,
        address adminLogic,
        address bundleDecodeHelper,
        address feeToken
    ) Ownable(initialOwner) {
        if (channelLogic == address(0)) revert ZeroLogicAddress();
        if (messagingLogic == address(0)) revert ZeroLogicAddress();
        if (bundleLogic == address(0)) revert ZeroLogicAddress();
        if (connectorLogic == address(0)) revert ZeroLogicAddress();
        if (adminLogic == address(0)) revert ZeroLogicAddress();
        if (bundleDecodeHelper == address(0)) revert ZeroLogicAddress();

        if (channelLogic.code.length == 0) revert ClprTypes.ClprModuleNotDeployed();
        if (messagingLogic.code.length == 0) revert ClprTypes.ClprModuleNotDeployed();
        if (bundleLogic.code.length == 0) revert ClprTypes.ClprModuleNotDeployed();
        if (connectorLogic.code.length == 0) revert ClprTypes.ClprModuleNotDeployed();
        if (adminLogic.code.length == 0) revert ClprTypes.ClprModuleNotDeployed();
        if (bundleDecodeHelper.code.length == 0) revert ClprTypes.ClprModuleNotDeployed();

        _config.protocolVersion = protocolVersion;
        _config.chainId = chainId;
        _CHANNEL_LOGIC = channelLogic;
        _MESSAGING_LOGIC = messagingLogic;
        _BUNDLE_LOGIC = bundleLogic;
        _CONNECTOR_LOGIC = connectorLogic;
        _ADMIN_LOGIC = adminLogic;
        _bundleDecodeHelper = bundleDecodeHelper;
        // Zero is native mode.
        // slither-disable-next-line missing-zero-check
        _FEE_TOKEN = feeToken;
        if (feeToken != address(0)) {
            (bool ok, uint8 decimals) = SafeERC20.tryGetDecimals(IERC20(feeToken));
            if (!ok || decimals > FeeAssetLib.MAX_DECIMALS) revert ClprTypes.ClprInvalidFeeToken();
            _feeAsset = ClprTypes.FeeAsset({token: feeToken, decimals: decimals});
        }
        // _clprEnabled stays false (Solidity default; the spec's default clpr_enabled = false): the
        // service is inert until the owner runs initialize() and then setClprEnabled(true).
        // The local endpoint manifest is created empty at version 1 (see ClprEndpointManifest.version);
        // getEndpointManifest() therefore always returns a valid manifest (version >= 1). The
        // commitment is seeded too so the genesis empty manifest is provable via the commitment
        // slot from day one (serviceAddress is empty until initialize()/updateLedgerConfiguration
        // sets it — those calls re-sync the commitment).
        _endpointManifest.version = 1;
        ManifestLib.syncCommitment(_endpointManifest, _config.serviceAddress);

        // Initialize the shared _authorizedService for all logic modules.
        // All logic modules inherit ClprServiceStorage, so they all share the same
        // _authorizedService storage slot. Setting it once here ensures all modules
        // can authenticate DELEGATECALL execution from ClprService.
        _authorizedService = address(this);
    }

    /// @notice Accept native value sent directly to the router (e.g. `payForExecution` in native mode).
    /// @dev ConnectorLib.charge forwards a `payForExecution` payment to the bundle submitter or the owner,
    ///      or credits it for {collectPending}. Reverts with ClprNativeValueMismatch in token mode, where
    ///      every payout is in the fee token and native value would be locked.
    /// slither-disable-next-line locked-ether
    receive() external payable {
        if (_FEE_TOKEN != address(0)) revert ClprTypes.ClprNativeValueMismatch();
    }

    // ── Channel ─────────────────────────────────────────────────────────

    /// @inheritdoc IClprService
    function registerChannel(bytes32, bytes32) external {
        _delegate(_CHANNEL_LOGIC);
    }

    /// @inheritdoc IClprService
    function completeChannel(bytes32, bytes calldata, bytes calldata, bytes32, address, bytes calldata, bytes calldata)
        external
    {
        _delegate(_CHANNEL_LOGIC);
    }

    /// @notice Close a channel or abandon a pending commitment. Owner-only.
    /// @dev See ChannelLogic.closeChannel for full semantics.
    function closeChannel(bytes32) external onlyOwner {
        _delegate(_CHANNEL_LOGIC);
    }

    /// @inheritdoc IClprService
    // deriveChannelId reads _config.chainId from router storage — must use
    // delegatecall (not staticcall), so cannot be annotated view.
    function deriveChannelId(string calldata, bytes calldata, bytes32) external returns (bytes32) {
        _delegate(_CHANNEL_LOGIC);
    }

    /// @inheritdoc IClprService
    function getChannel(bytes32) external returns (ClprTypes.Channel memory) {
        _delegate(_CHANNEL_LOGIC);
    }

    /// @inheritdoc IClprService
    function getPeerEndpointRoster(bytes32) external returns (ClprTypes.PeerEndpoint[] memory) {
        _delegate(_CHANNEL_LOGIC);
    }

    /// @inheritdoc IClprService
    function getPeerEndpointManifest(bytes32) external returns (ClprTypes.ClprEndpointManifest memory) {
        _delegate(_CHANNEL_LOGIC);
    }

    /// @notice Returns true if a channel commitment has been registered but not yet revealed.
    function pendingCommitments(bytes32) external returns (bool) {
        _delegate(_CHANNEL_LOGIC);
    }

    /// @notice Number of channels that have been completed (any status).
    function channelCount() external returns (uint256) {
        _delegate(_CHANNEL_LOGIC);
    }

    // ── Messaging ──────────────────────────────────────────────────────────

    /// @inheritdoc IClprService
    function sendMessage(bytes32, bytes32, bytes calldata, bytes calldata) external returns (uint64) {
        _delegate(_MESSAGING_LOGIC);
    }

    /// @inheritdoc IClprService
    function submitBundle(bytes32, bytes calldata) external {
        _delegate(_BUNDLE_LOGIC);
    }

    /// @inheritdoc IClprService
    function getMessage(bytes32, uint64) external returns (ClprTypes.MessageValue memory) {
        _delegate(_MESSAGING_LOGIC);
    }

    /// @inheritdoc IClprService
    function getQueueDepth(bytes32) external returns (ClprTypes.QueueDepth memory) {
        _delegate(_MESSAGING_LOGIC);
    }

    // ── Connectors ─────────────────────────────────────────────────────────

    /// @inheritdoc IClprService
    function registerConnector(bytes32) external {
        _delegate(_CONNECTOR_LOGIC);
    }

    /// @inheritdoc IClprService
    function completeConnector(bytes32, bytes calldata, bytes calldata, bytes32, bytes32, address, address)
        external
        payable
    {
        _delegate(_CONNECTOR_LOGIC);
    }

    /// @inheritdoc IClprService
    function removeConnector(bytes32, bytes32, address) external {
        _delegate(_CONNECTOR_LOGIC);
    }

    /// @inheritdoc IClprService
    function topUpConnectorStake(bytes32, bytes32, uint256) external payable {
        _delegate(_CONNECTOR_LOGIC);
    }

    /// @inheritdoc IClprService
    function getConnector(bytes32, bytes32) external returns (ClprTypes.Connector memory) {
        _delegate(_CONNECTOR_LOGIC);
    }

    /// @inheritdoc IClprService
    function hasConnector(bytes32, bytes32) external returns (bool) {
        _delegate(_CONNECTOR_LOGIC);
    }

    /// @inheritdoc IClprService
    /// @notice Dispatched via staticcall — truly pure, reads no router storage.
    function deriveConnectorId(bytes32, bytes calldata, bytes32) external view returns (bytes32) {
        _staticDelegate(_CONNECTOR_LOGIC);
    }

    /// @notice Returns true if a connector commitment has been registered but not yet revealed.
    function pendingConnectorCommitments(bytes32) external returns (bool) {
        _delegate(_CONNECTOR_LOGIC);
    }

    /// @notice Total number of registered connectors across all channels.
    function connectorCount() external returns (uint256) {
        _delegate(_CONNECTOR_LOGIC);
    }

    // ── Admin ──────────────────────────────────────────────────────────────

    /// @inheritdoc IClprService
    function getFeeToken() external returns (address) {
        _delegate(_ADMIN_LOGIC);
    }

    /// @inheritdoc IClprService
    function setClprEnabled(bool) external onlyOwner {
        _delegate(_ADMIN_LOGIC);
    }

    /// @notice One-time bootstrap: apply the first ledger + economic configuration
    ///         while the service is still disabled. Owner-only.
    /// @dev See AdminLogic.initialize for full semantics.
    function initialize(
        bytes calldata,
        ClprTypes.Throttles calldata,
        bytes calldata,
        bytes calldata,
        ClprTypes.EconomicConfig calldata
    ) external onlyOwner {
        _delegate(_ADMIN_LOGIC);
    }

    /// @notice Update the local ledger configuration. Owner-only.
    /// @dev See AdminLogic.updateLedgerConfiguration for full semantics.
    function updateLedgerConfiguration(bytes calldata, ClprTypes.Throttles calldata, bytes calldata, bytes calldata)
        external
        onlyOwner
    {
        _delegate(_ADMIN_LOGIC);
    }

    /// @notice Replace the economic configuration. Owner-only.
    /// @dev See AdminLogic.updateEconomicConfiguration for full semantics.
    function updateEconomicConfiguration(ClprTypes.EconomicConfig calldata) external onlyOwner {
        _delegate(_ADMIN_LOGIC);
    }

    /// @inheritdoc IClprService
    function registerEndpoint(ClprTypes.Endpoint calldata) external payable {
        _delegate(_ADMIN_LOGIC);
    }

    /// @inheritdoc IClprService
    function addEndpoint(address, ClprTypes.Endpoint calldata) external onlyOwner {
        _delegate(_ADMIN_LOGIC);
    }

    /// @inheritdoc IClprService
    function removeEndpoint(address) external {
        _delegate(_ADMIN_LOGIC);
    }

    /// @inheritdoc IClprService
    function updateEndpointManifest(ClprTypes.ManifestUpdateEntry[] calldata, address[] calldata) external onlyOwner {
        _delegate(_ADMIN_LOGIC);
    }

    /// @inheritdoc IClprService
    function getEndpointManifest() external returns (ClprTypes.ClprEndpointManifest memory) {
        _delegate(_ADMIN_LOGIC);
    }

    /// @inheritdoc IClprService
    function getEndpointEntry(address) external returns (ClprTypes.EndpointManifestEntry memory) {
        _delegate(_ADMIN_LOGIC);
    }

    /// @inheritdoc IClprService
    function getLedgerConfiguration() external returns (ClprTypes.LedgerConfiguration memory) {
        _delegate(_ADMIN_LOGIC);
    }

    /// @inheritdoc IClprService
    function getLedgerConfigurationHash() external returns (bytes32) {
        _delegate(_ADMIN_LOGIC);
    }

    /// @inheritdoc IClprService
    function getChannelPeerConfigHash(bytes32) external returns (bytes32) {
        _delegate(_ADMIN_LOGIC);
    }

    /// @inheritdoc IClprService
    function getEconomicConfig() external returns (ClprTypes.EconomicConfig memory) {
        _delegate(_ADMIN_LOGIC);
    }

    /// @notice Pending fee-asset withdrawal balance for an account (pull-payment pattern).
    function pendingWithdrawals(address) external returns (uint256) {
        _delegate(_ADMIN_LOGIC);
    }

    /// @notice Withdraw the caller's pending fee-asset balance.
    /// @dev See AdminLogic.collectPending for full semantics.
    function collectPending() external {
        _delegate(_ADMIN_LOGIC);
    }

    /// @notice Withdraw the caller's pending fee-asset balance to `recipient`.
    /// @dev See AdminLogic.collectPendingTo for full semantics.
    function collectPendingTo(address) external {
        _delegate(_ADMIN_LOGIC);
    }

    /// @notice Number of currently registered endpoints.
    function endpointCount() external returns (uint256) {
        _delegate(_ADMIN_LOGIC);
    }

    // ── Dispatch ───────────────────────────────────────────────────────────

    /// @dev Forward the full calldata to `logic` via DELEGATECALL. State changes
    ///      are applied to this (router) contract's storage.
    function _delegate(address logic) private {
        assembly ("memory-safe") {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), logic, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    /// @dev Forward the full calldata to `logic` via STATICCALL. Used only for
    ///      functions that are truly pure (no router storage reads).
    function _staticDelegate(address logic) private view {
        assembly ("memory-safe") {
            calldatacopy(0, 0, calldatasize())
            let result := staticcall(gas(), logic, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
