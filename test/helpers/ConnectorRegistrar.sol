// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";

/// @notice Test helper: full commit-reveal connector registration in one call.
/// @dev connectorId = keccak256(channelId || pubKey || salt), per-channel scoped.
library ConnectorRegistrar {
    Vm internal constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    /// @notice Register with zero salt.
    function register(
        IClprService service,
        bytes32 channelId,
        bytes32 seed,
        address connectorContract,
        address admin,
        uint256 stake
    ) internal returns (bytes32 connectorId) {
        return registerWithSalt(service, channelId, seed, bytes32(0), connectorContract, admin, stake);
    }

    /// @notice Register with a specific salt.
    function registerWithSalt(
        IClprService service,
        bytes32 channelId,
        bytes32 seed,
        bytes32 salt,
        address connectorContract,
        address admin,
        uint256 stake
    ) internal returns (bytes32 connectorId) {
        uint256 pk = uint256(keccak256(abi.encodePacked("clpr.test.connectorSigner", seed)));
        Vm.Wallet memory w = VM.createWallet(pk);
        bytes memory pubKey = abi.encodePacked(w.publicKeyX, w.publicKeyY);

        connectorId = service.deriveConnectorId(channelId, pubKey, salt);

        // Commit: keccak256(connectorId || pubKey)
        bytes32 commitment = keccak256(abi.encodePacked(connectorId, pubKey));
        service.registerConnector(commitment);

        // Sign: keccak256(connectorId || address(service)) with Ethereum prefix
        bytes32 msgHash = keccak256(abi.encodePacked(connectorId, address(service)));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = VM.sign(pk, ethHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        service.completeConnector{value: stake}(connectorId, pubKey, sig, salt, channelId, connectorContract, admin);
    }

    /// @notice Register on a token-mode service: no `msg.value`; the service pulls `minLockedStake`
    ///         from the caller, which must have approved it.
    function registerTokenMode(
        IClprService service,
        bytes32 channelId,
        bytes32 seed,
        address connectorContract,
        address admin
    ) internal returns (bytes32 connectorId) {
        return registerWithSalt(service, channelId, seed, bytes32(0), connectorContract, admin, 0);
    }
}
