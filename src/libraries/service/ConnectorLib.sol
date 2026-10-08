// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {IClprConnector} from "@hiero-ledger/clpr/interfaces/IClprConnector.sol";
import {ECDSA} from "@hiero-ledger/clpr/libraries/crypto/ECDSA.sol";
import {ExactGasCall} from "@hiero-ledger/clpr/libraries/service/ExactGasCall.sol";

/// @title ConnectorLib
/// @notice Stateless library for connector registration, stake management, charging, and slashing.
/// @dev All functions take explicit storage pointers so they operate on ClprService's storage.
///      ETH custody is ClprService's responsibility; this library only tracks accounting.
///      Connectors are scoped per-channel: storage key = keccak256(channelId || connectorId).
library ConnectorLib {
    // ── Events ────────────────────────────────────────────────────────
    event ConnectorRegistered(bytes32 indexed connectorKey, address connectorContract, address admin, uint256 stake);
    event ConnectorDeregistered(bytes32 indexed connectorKey, address recipient, uint256 stakeReturned);
    event ConnectorStakeToppedUp(bytes32 indexed connectorKey, uint256 amount, uint256 newStake);
    event ConnectorCharged(bytes32 indexed connectorKey, uint256 amount, address recipient);
    event ConnectorSlashed(bytes32 indexed connectorKey, uint256 penalty, uint32 newSlashCount, bool banned);

    // ── ID Derivation ─────────────────────────────────────────────────

    /// @notice Derive a connectorId from its inputs.
    /// @dev connectorId = keccak256(channelId || pubKey || salt)
    function deriveConnectorId(bytes32 channelId, bytes calldata pubKey, bytes32 salt) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(channelId, pubKey, salt));
    }

    // ── Storage Key ───────────────────────────────────────────────────

    /// @dev Compute the per-channel storage key for a connector. `abi.encodePacked` serializes a
    ///      `bytes32` connectorId to the same 32 raw bytes the previous `bytes` form produced, so the
    ///      derived key is unchanged from the pre-bytes32 layout.
    function _connectorKey(bytes32 channelId, bytes32 connectorId) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(channelId, connectorId));
    }

    // ── Registration ──────────────────────────────────────────────────

    /// @notice Complete connector registration (reveal phase of commit-reveal).
    /// @dev Validates the commitment, verifies connectorId derivation, checks the ECDSA
    ///      signature, and stores the connector scoped to the given channel.
    function completeRegistration(
        mapping(bytes32 => ClprTypes.Connector) storage connectors,
        mapping(bytes32 => bool) storage connectorExists,
        mapping(bytes32 => bool) storage pendingConnectorCommitments,
        ClprTypes.EconomicConfig memory econ,
        bytes32 connectorId,
        bytes calldata pubKey,
        bytes calldata sig,
        bytes32 salt,
        bytes32 channelId,
        address connectorContract,
        address admin,
        uint256 stake
    ) internal {
        if (stake < econ.minLockedStake) revert ClprTypes.ClprInsufficientStake();

        // 1. Verify commitment was registered: keccak256(connectorId || pubKey)
        bytes32 commitment = keccak256(abi.encodePacked(connectorId, pubKey));
        if (!pendingConnectorCommitments[commitment]) revert ClprTypes.ClprCommitmentMismatch();

        // 2. Validate connectorId derivation
        if (connectorId != deriveConnectorId(channelId, pubKey, salt)) revert ClprTypes.ClprInvalidChannelId();

        bytes32 key = _connectorKey(channelId, connectorId);
        if (connectorExists[key]) revert ClprTypes.ClprConnectorAlreadyExists();

        if (connectorContract.code.length == 0) revert ClprTypes.ClprInvalidConnectorContract();

        // 3. Verify signature scoped to this deployment
        _verifyConnectorSig(connectorId, pubKey, sig);

        connectors[key] = ClprTypes.Connector({
            connectorId: connectorId,
            connectorContract: connectorContract,
            admin: admin,
            lockedStake: stake,
            slashCount: 0
        });
        connectorExists[key] = true;
        delete pendingConnectorCommitments[commitment];

        emit ConnectorRegistered(key, connectorContract, admin, stake);
    }

    function _verifyConnectorSig(bytes32 connectorId, bytes calldata pubKey, bytes calldata sig) internal view {
        bytes32 msgHash = keccak256(abi.encodePacked(connectorId, address(this)));
        ECDSA._ecrecoverCheck(msgHash, pubKey, sig);
    }

    /// @notice Deregister a connector. Returns the stake amount for ClprService to send to `recipient`.
    function deregister(
        mapping(bytes32 => ClprTypes.Connector) storage connectors,
        mapping(bytes32 => bool) storage connectorExists,
        mapping(bytes32 => uint256) storage connectorInflightCount,
        bytes32 channelId,
        bytes32 connectorId,
        address recipient
    ) internal returns (uint256 stake) {
        bytes32 key = _connectorKey(channelId, connectorId);
        if (!connectorExists[key]) revert ClprTypes.ClprConnectorNotFound();
        if (msg.sender != connectors[key].admin) revert ClprTypes.ClprConnectorUnauthorized();
        if (connectorInflightCount[key] > 0) revert ClprTypes.ClprConnectorHasInflightMessages();

        stake = connectors[key].lockedStake;
        delete connectors[key];
        connectorExists[key] = false;

        emit ConnectorDeregistered(key, recipient, stake);
    }

    /// @notice Top up stake. `amount` is ETH already received by ClprService (msg.value).
    function topUpStake(
        mapping(bytes32 => ClprTypes.Connector) storage connectors,
        mapping(bytes32 => bool) storage connectorExists,
        bytes32 channelId,
        bytes32 connectorId,
        uint256 amount
    ) internal {
        bytes32 key = _connectorKey(channelId, connectorId);
        if (!connectorExists[key]) revert ClprTypes.ClprConnectorNotFound();
        connectors[key].lockedStake += amount;
        emit ConnectorStakeToppedUp(key, amount, connectors[key].lockedStake);
    }

    // ── Charge ────────────────────────────────────────────────────────

    /// @notice Pull payment from connector contract for inbound message execution.
    /// @dev Calls IClprConnector.payForExecution with `gasLimit` gas, less the CALL's own cost, reverting with
    ///      `ExactGasCall.InsufficientGasForCall` if that cannot be forwarded; every other failure
    ///      returns false. The connector sends ETH to address(this) (ClprService, since this is an
    ///      internal library). Forwards to `recipient`; falls back to `fallbackRecipient` (owner) if
    ///      the transfer fails. If both reject, credits `pendingWithdrawals[recipient]` so the
    ///      recipient can pull later.
    function charge(
        mapping(bytes32 => ClprTypes.Connector) storage connectors,
        mapping(bytes32 => bool) storage connectorExists,
        mapping(address => uint256) storage pendingWithdrawals,
        address fallbackRecipient,
        bytes32 channelId,
        bytes32 connectorId,
        uint256 amount,
        address recipient,
        uint256 gasLimit
    ) internal returns (bool success) {
        bytes32 key = _connectorKey(channelId, connectorId);
        if (!connectorExists[key]) return false;
        address connectorContract = connectors[key].connectorContract;

        if (connectorContract.balance < amount) return false;

        uint256 before = address(this).balance;
        // The balance delta, not the return data, decides whether the connector paid.
        // slither-disable-next-line unused-return
        (bool paid,,) = ExactGasCall.callWithExactGas(
            connectorContract, gasLimit, abi.encodeCall(IClprConnector.payForExecution, (amount)), false
        );
        if (!paid || address(this).balance != before + amount) return false;

        _transferWithFallback(pendingWithdrawals, recipient, fallbackRecipient, amount);
        emit ConnectorCharged(key, amount, recipient);
        return true;
    }

    // ── Slash ─────────────────────────────────────────────────────────

    /// @notice Slash connector stake using geometric penalty escalation.
    function slash(
        mapping(bytes32 => ClprTypes.Connector) storage connectors,
        mapping(bytes32 => bool) storage connectorExists,
        mapping(address => uint256) storage pendingWithdrawals,
        address fallbackRecipient,
        bytes32 channelId,
        bytes32 connectorId,
        address recipient,
        uint256 basePenalty,
        uint256 penaltyMultiplier,
        uint32 slashBanThreshold
    ) internal returns (uint256 penaltyAmount, bool banned) {
        bytes32 key = _connectorKey(channelId, connectorId);
        if (!connectorExists[key]) return (0, false);
        ClprTypes.Connector storage connector = connectors[key];

        uint256 stake = connector.lockedStake;
        uint32 slashCount = connector.slashCount;
        uint32 finalSlashCount = slashCount + 1;

        if (finalSlashCount >= slashBanThreshold) {
            // Ban: take the full stake. Skip penalty math and skip writing slashCount
            penaltyAmount = stake;
            banned = true;
            delete connectors[key];
            connectorExists[key] = false;
        } else {
            penaltyAmount = _geometricPenalty(basePenalty, penaltyMultiplier, slashCount);
            if (penaltyAmount > stake) penaltyAmount = stake;
            uint256 remaining = stake - penaltyAmount;
            if (remaining == 0) {
                banned = true;
                delete connectors[key];
                connectorExists[key] = false;
            } else {
                connector.slashCount = finalSlashCount;
                connector.lockedStake = remaining;
            }
        }

        emit ConnectorSlashed(key, penaltyAmount, finalSlashCount, banned);

        if (penaltyAmount > 0) {
            _transferWithFallback(pendingWithdrawals, recipient, fallbackRecipient, penaltyAmount);
        }
    }

    // ── Views ─────────────────────────────────────────────────────────

    /// @notice Returns true if the connector identified by `connectorId` exists on `channelId`.
    /// @param connectorExists Storage pointer to the connector existence map.
    /// @param channelId The parent channel.
    /// @param connectorId The connector identifier to check.
    /// @return True if the connector is registered.
    function has(mapping(bytes32 => bool) storage connectorExists, bytes32 channelId, bytes32 connectorId)
        internal
        view
        returns (bool)
    {
        return connectorExists[_connectorKey(channelId, connectorId)];
    }

    /// @notice Returns the full connector record. Reverts with `ClprConnectorNotFound` if absent.
    /// @param connectors Storage pointer to the connector map.
    /// @param connectorExists Storage pointer to the connector existence map.
    /// @param channelId The parent channel.
    /// @param connectorId The connector identifier.
    /// @return The stored `Connector` struct.
    function get(
        mapping(bytes32 => ClprTypes.Connector) storage connectors,
        mapping(bytes32 => bool) storage connectorExists,
        bytes32 channelId,
        bytes32 connectorId
    ) internal view returns (ClprTypes.Connector memory) {
        bytes32 key = _connectorKey(channelId, connectorId);
        if (!connectorExists[key]) revert ClprTypes.ClprConnectorNotFound();
        return connectors[key];
    }

    /// @notice Return only the connector contract address, avoiding a full struct copy.
    /// @dev Saves ~3 SLOADs vs get() when only the contract address is needed.
    function getContract(
        mapping(bytes32 => ClprTypes.Connector) storage connectors,
        mapping(bytes32 => bool) storage connectorExists,
        bytes32 channelId,
        bytes32 connectorId
    ) internal view returns (address) {
        bytes32 key = _connectorKey(channelId, connectorId);
        if (!connectorExists[key]) revert ClprTypes.ClprConnectorNotFound();
        return connectors[key].connectorContract;
    }

    // ── Internal: math helpers ────────────────────────────────────────

    /// @dev Compute base * multiplier^exp using binary exponentiation, saturating at type(uint256).max.
    function _geometricPenalty(uint256 base, uint256 multiplier, uint32 exp) internal pure returns (uint256) {
        if (multiplier <= 1 || exp == 0) return base;
        uint256 result = base;
        uint256 m = multiplier;
        uint32 e = exp;
        while (e > 0) {
            if (e & 1 != 0) {
                if (result > type(uint256).max / m) return type(uint256).max;
                result *= m;
            }
            e >>= 1;
            if (e > 0) {
                if (m > type(uint256).max / m) return type(uint256).max;
                m *= m;
            }
        }
        return result;
    }

    // ── Internal: ETH transfer ────────────────────────────────────────

    /// @dev Attempt ETH transfer to `recipient`; if it fails try `fallbackTo`; if both
    ///      fail, credit `pendingWithdrawals[recipient]` for pull-payment withdrawal.
    function _transferWithFallback(
        mapping(address => uint256) storage pendingWithdrawals,
        address recipient,
        address fallbackTo,
        uint256 amount
    ) private {
        (bool ok,) = recipient.call{value: amount}("");
        if (ok) return;
        (ok,) = fallbackTo.call{value: amount}("");
        if (ok) return;
        pendingWithdrawals[recipient] += amount;
    }
}
