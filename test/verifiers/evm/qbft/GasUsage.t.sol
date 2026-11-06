// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {QbftHeaderModeVerifier} from "@hiero-ledger/clpr/verifiers/evm/qbft/QbftHeaderModeVerifier.sol";
import {QbftHeaderModeProofBuilders} from "@test/verifiers/evm/qbft/QbftHeaderModeProofBuilders.sol";

/// @notice Gas baselines for the QBFT header-mode verifier (`script/gas/baselines.yml`). The
///         scenarios come from {QbftHeaderModeProofBuilders}, shared with {QbftGasReportTest}.
///         Exactly one `verifyBundle` call per test, so the gas report's `min` / `median` / `max`
///         columns map onto the steady-state, 10 -> 11 and 51 -> 52 scenarios respectively.
contract QbftHeaderModeGasBenchmarkTest is QbftHeaderModeProofBuilders {
    QbftHeaderModeVerifier internal verifier;

    function setUp() public {
        verifier = new QbftHeaderModeVerifier();
    }

    /// @dev One validator, one seal: the shape a single-node Besu network produces.
    function test_gas_verifyBundle_success() public view {
        (bytes memory proof, bytes memory anchor) = _steadyScenario("gas-h", 1);
        verifier.verifyBundle(proof, anchor, _syntheticChannelContext());
    }

    function test_gas_rotation_10_to_11() public view {
        _runRotation(10);
    }

    function test_gas_rotation_51_to_52() public view {
        _runRotation(51);
    }

    function test_gas_verifyConfig_success() public view {
        verifier.verifyConfig(_configScenario("gas-hc"), SYNTHETIC_CHANNEL_ID, "");
    }

    function _runRotation(uint256 n) private view {
        (bytes memory proof, bytes memory anchor) = _rotationScenario("gas-rot", n);
        verifier.verifyBundle(proof, anchor, _syntheticChannelContext());
    }
}
