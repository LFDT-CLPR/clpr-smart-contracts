// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {QbftContractModeVerifier} from "@hiero-ledger/clpr/verifiers/evm/qbft/QbftContractModeVerifier.sol";
import {QbftValidators} from "@hiero-ledger/clpr/libraries/proof/qbft/QbftValidators.sol";
import {QbftContractModeProofBuilders} from "@test/verifiers/evm/qbft/QbftContractModeProofBuilders.sol";

/// @notice Gas baselines for the QBFT Contract-mode verifier.
contract QbftContractModeGasBenchmarkTest is QbftContractModeProofBuilders {
    QbftContractModeVerifier internal verifier;

    function setUp() public {
        verifier = new QbftContractModeVerifier();
    }

    function test_gas_verifyBundle_steadyState() public view {
        address[] memory set = _set3("gas-s1", "gas-s2", "gas-s3");
        CurrentBlock memory cb = _buildCurrentBlock(set, _pks2("gas-s1", "gas-s2"), 100);

        verifier.verifyBundle(
            _topProof(cb, set, new bytes[](0)),
            _contractAnchor(set, VALIDATOR_CONTRACT, cb.arraySlot, 0),
            _syntheticChannelContext()
        );
    }

    function test_gas_rotation_10_to_11() public view {
        _runRotation(10);
    }

    function test_gas_rotation_51_to_52() public view {
        _runRotation(51);
    }

    function test_gas_verifyConfig_success() public view {
        uint256 pk1 = uint256(keccak256("gas-c1"));
        uint256 pk2 = uint256(keccak256("gas-c2"));
        address[] memory vals = _set3("gas-c1", "gas-c2", "gas-c3");

        (bytes32 stateRoot, bytes32 arraySlot, bytes memory vcProof) = _validatorContractProof(VALIDATOR_CONTRACT, vals);
        bytes memory header = _buildMultiSealedHeaderAtBlock(500, stateRoot, 0, pk1, pk2);

        verifier.verifyConfig(_buildContractConfigProof(arraySlot, vcProof, header), SYNTHETIC_CHANNEL_ID, "");
    }

    function _runRotation(uint256 n) private view {
        address[] memory oldSet = _setN("gas-rot", n);
        address[] memory newSet = _setN("gas-rot", n + 1);

        bytes[] memory hops = new bytes[](1);
        hops[0] = _buildHop(newSet, _pksN("gas-rot", QbftValidators.quorum(n)), 300);
        CurrentBlock memory cb = _buildCurrentBlock(newSet, _pksN("gas-rot", QbftValidators.quorum(n + 1)), 301);

        verifier.verifyBundle(
            _topProof(cb, oldSet, hops),
            _contractAnchor(oldSet, VALIDATOR_CONTRACT, cb.arraySlot, 0),
            _syntheticChannelContext()
        );
    }
}
