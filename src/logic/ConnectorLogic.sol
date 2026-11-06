// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ConnectorLib} from "@hiero-ledger/clpr/libraries/service/ConnectorLib.sol";
import {FeeAssetLib} from "@hiero-ledger/clpr/libraries/service/FeeAssetLib.sol";
import {LogicModuleBase} from "@hiero-ledger/clpr/logic/base/LogicModuleBase.sol";

/// @title ConnectorLogic
/// @notice Connector lifecycle: register, complete, remove, and inspect connectors.
/// @dev Executed via delegatecall from ClprService. All state reads and writes
///      operate on ClprServiceStorage slots in the router's storage.
contract ConnectorLogic is LogicModuleBase {
    constructor() {}

    // ── Public views ───────────────────────────────────────────────────────

    /// @notice Returns true if `commitment` has been registered but not yet revealed.
    /// @param commitment The commitment hash to check.
    function pendingConnectorCommitments(bytes32 commitment) external view returns (bool) {
        return _pendingConnectorCommitments[commitment];
    }

    /// @notice Total number of registered connectors across all channels.
    function connectorCount() external view returns (uint256) {
        return _connectorCount;
    }

    /// @notice Returns the connector record for the given channel and connector ID.
    /// @dev Reverts with `ClprConnectorNotFound` if the connector does not exist.
    /// @param channelId The parent channel.
    /// @param connectorId The connector identifier derived via deriveConnectorId.
    function getConnector(bytes32 channelId, bytes32 connectorId) external view returns (ClprTypes.Connector memory) {
        return ConnectorLib.get(_connectors, _connectorExists, channelId, connectorId);
    }

    /// @notice Returns true if the connector exists on the given channel.
    /// @param channelId The parent channel.
    /// @param connectorId The connector identifier to check.
    function hasConnector(bytes32 channelId, bytes32 connectorId) external view returns (bool) {
        return ConnectorLib.has(_connectorExists, channelId, connectorId);
    }

    /// @notice Compute the deterministic connector identifier.
    /// @dev Formula: abi.encodePacked(keccak256(channelId || pubKey || salt)).
    ///      The result is 32 bytes packed as a `bytes` value, distinct per
    ///      (channel, key, salt) triple.
    /// @param channelId The channel to scope the connector to.
    /// @param pubKey Raw 64-byte uncompressed ECDSA public key of the connector operator.
    /// @param salt Caller-chosen entropy to allow multiple connectors per key.
    /// @return Deterministic connector identifier (32 bytes encoded as bytes).
    function deriveConnectorId(bytes32 channelId, bytes calldata pubKey, bytes32 salt) external pure returns (bytes32) {
        return ConnectorLib.deriveConnectorId(channelId, pubKey, salt);
    }

    // ── Connector lifecycle ────────────────────────────────────────────────

    /// @notice Register a connector commitment (commit phase of commit-reveal).
    /// @dev Anyone may commit; ECDSA ownership is enforced during completeConnector.
    /// @param commitment keccak256(connectorId || pubKey) binding the reveal.
    function registerConnector(bytes32 commitment) external onlyService whenEnabled {
        _pendingConnectorCommitments[commitment] = true;
    }

    /// @notice Reveal and complete a previously registered connector commitment.
    /// @dev Validates the commitment, verifies the ECDSA signature over
    ///      keccak256(connectorId || address(this)) — binding the reveal to this
    ///      ClprService deployment — checks connectorId derivation from
    ///      (channelId, pubKey, salt), and records the connector.
    ///      The stake is `msg.value` in native mode (at least `economicConfig.minLockedStake`); in
    ///      token mode exactly `minLockedStake` is pulled with `transferFrom` and `msg.value` must be 0.
    ///      Emits {ConnectorRegistered}.
    /// @param connectorId Connector identifier derived via deriveConnectorId.
    /// @param pubKey Raw 64-byte uncompressed ECDSA public key.
    /// @param sig ECDSA signature over keccak256(connectorId || address(this)).
    /// @param salt Entropy used when the connectorId was derived.
    /// @param connectorContract Address of the IClprConnector application contract.
    /// @param admin Address authorised to deregister this connector.
    function completeConnector(
        bytes32 connectorId,
        bytes calldata pubKey,
        bytes calldata sig,
        bytes32 salt,
        bytes32 channelId,
        address connectorContract,
        address admin
    ) external payable nonReentrant onlyService whenEnabled {
        if (!_channelExists[channelId]) revert ClprTypes.ClprChannelNotFound();
        if (economicConfig.maxConnectors > 0 && _connectorCount >= economicConfig.maxConnectors) {
            revert ClprTypes.ClprTooManyConnectors();
        }
        ConnectorLib.completeRegistration(
            _connectors,
            _connectorExists,
            _pendingConnectorCommitments,
            economicConfig,
            connectorId,
            pubKey,
            sig,
            salt,
            channelId,
            connectorContract,
            admin,
            FeeAssetLib.pullAtLeast(_feeAsset, economicConfig.minLockedStake)
        );
        unchecked {
            _connectorCount++;
        }
    }

    /// @notice Remove a connector and return its bond to `recipient`.
    /// @dev Caller must be the connector's admin (enforced in ConnectorLib.deregister).
    ///      Reverts if any messages for this connector are still in-flight. The bond is sent to
    ///      `recipient` directly; a failed transfer reverts with ClprTransferFailed.
    function removeConnector(bytes32 channelId, bytes32 connectorId, address recipient)
        external
        nonReentrant
        whenEnabled
    {
        uint256 stake = ConnectorLib.deregister(
            _connectors, _connectorExists, _connectorInflightCount, channelId, connectorId, recipient
        );
        unchecked {
            _connectorCount--;
        }
        if (stake > 0) FeeAssetLib.send(_feeAsset, recipient, stake);
    }

    /// @notice Add `amount` of the fee asset to an existing connector's stake.
    /// @dev Native mode requires `msg.value == amount`; token mode pulls `amount` with
    ///      `transferFrom` and requires `msg.value == 0`.
    /// @param amount Stake to add, in fee-asset units. Must be non-zero.
    function topUpConnectorStake(bytes32 channelId, bytes32 connectorId, uint256 amount)
        external
        payable
        nonReentrant
        whenEnabled
        onlyService
    {
        if (amount == 0) revert ClprTypes.ClprInsufficientStake();
        FeeAssetLib.pullExact(_feeAsset, amount);
        ConnectorLib.topUpStake(_connectors, _connectorExists, channelId, connectorId, amount);
    }
}
