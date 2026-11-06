// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprApplication} from "@hiero-ledger/clpr/interfaces/IClprApplication.sol";
import {IClprConnector} from "@hiero-ledger/clpr/interfaces/IClprConnector.sol";
import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";

/// @notice An application that records the gas each callback receives, and fails cheaply below a
///         floor.
/// @dev Failing cheaply is what makes a starved call dangerous: the revert hands the unused gas
///      back, so the bundle can still finish while this callee's work never ran.
contract GasProbeApplication is IClprApplication {
    error Starved(uint256 gasReceived);

    uint256 public floor;
    uint256 public messageGas;
    uint256 public responseGas;
    bool public rawReturnSet;
    bytes public rawReturn;
    bool public burn;

    function setFloor(uint256 floor_) external {
        floor = floor_;
    }

    /// @dev Makes `onClprMessage` spend all the gas it receives.
    function setBurn(bool on) external {
        burn = on;
    }

    /// @dev Makes `onClprMessage` return `raw` byte for byte, instead of ABI-encoding a `bytes`.
    function setRawReturn(bytes calldata raw) external {
        rawReturnSet = true;
        rawReturn = raw;
    }

    /// @dev Sends a DATA message as this contract, so the peer's reply comes back to
    ///      `onClprResponse` here.
    function send(
        IClprService service,
        bytes32 channelId,
        bytes32 connectorId,
        bytes calldata target,
        bytes calldata data
    ) external returns (uint64) {
        return service.sendMessage(channelId, connectorId, target, data);
    }

    function onClprMessage(bytes32, bytes calldata, bytes calldata) external override returns (bytes memory) {
        uint256 g = gasleft();
        if (g < floor) revert Starved(g);
        messageGas = g;
        uint256 spins;
        while (burn) ++spins;
        if (rawReturnSet) {
            bytes memory raw = rawReturn;
            assembly ("memory-safe") {
                return(add(raw, 0x20), mload(raw))
            }
        }
        return hex"01";
    }

    function onClprResponse(bytes32, uint64, uint8, bytes calldata) external override {
        uint256 g = gasleft();
        if (g < floor) revert Starved(g);
        responseGas = g;
    }
}

/// @notice A connector that authorizes everything, pays on request, and records the gas its
///         `payForExecution` and `onInboundMessage` callbacks receive, failing cheaply below a floor.
contract GasProbeConnector is IClprConnector {
    error Starved(uint256 gasReceived);

    uint256 public floor;
    uint256 public payGas;
    uint256 public inboundGas;
    bool public burnOnPay;
    uint256 public burnBeforePay;

    function setFloor(uint256 floor_) external {
        floor = floor_;
    }

    /// @dev Makes `payForExecution` spend all the gas it receives instead of paying.
    function setBurnOnPay(bool on) external {
        burnOnPay = on;
    }

    /// @dev Makes `payForExecution` spend `gas_` gas before it pays.
    function setBurnBeforePay(uint256 gas_) external {
        burnBeforePay = gas_;
    }

    function authorizeOutboundMessage(bytes32, bytes calldata, bytes calldata, bytes calldata)
        external
        pure
        override
        returns (bool)
    {
        return true;
    }

    function payForExecution(uint256 amount) external override {
        uint256 g = gasleft();
        if (g < floor) revert Starved(g);
        payGas = g;
        uint256 spins;
        while (burnOnPay) ++spins;
        while (g - gasleft() < burnBeforePay) ++spins;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "pay failed");
    }

    function onInboundMessage(bytes32, uint64, bytes calldata, bytes calldata, bytes calldata) external override {
        uint256 g = gasleft();
        if (g < floor) revert Starved(g);
        inboundGas = g;
    }

    receive() external payable {}
}
