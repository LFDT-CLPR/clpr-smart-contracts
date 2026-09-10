// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {QbftContractModeVerifier} from "@hiero-ledger/clpr/verifiers/evm/qbft/QbftContractModeVerifier.sol";
import {QbftContractModeProofBuilders} from "@test/verifiers/evm/qbft/QbftContractModeProofBuilders.sol";

/// @notice Gas baselines for the QBFT Contract-mode verifier. The scenarios are built by the
///         shared helpers in {QbftContractModeProofBuilders}, which {QbftGasReportTest} also
///         consumes — a bundle-shape change lands in both suites at once.
contract QbftContractModeGasBenchmarkTest is QbftContractModeProofBuilders {
    QbftContractModeVerifier internal verifier;

    function setUp() public {
        verifier = new QbftContractModeVerifier();
    }

    function test_gas_verifyBundle_steadyState() public view {
        (bytes memory proof, bytes memory anchor) = _steadyScenario("gas-s", 3);
        verifier.verifyBundle(proof, anchor, _syntheticChannelContext());
    }

    function test_gas_rotation_10_to_11() public view {
        _runRotation(10);
    }

    function test_gas_rotation_51_to_52() public view {
        _runRotation(51);
    }

    function test_gas_verifyConfig_success() public view {
        verifier.verifyConfig(_configScenario("gas-c"), SYNTHETIC_CHANNEL_ID, "");
    }

    function _runRotation(uint256 n) private view {
        (bytes memory proof, bytes memory anchor) = _rotationScenario("gas-rot", n);
        verifier.verifyBundle(proof, anchor, _syntheticChannelContext());
    }
}
