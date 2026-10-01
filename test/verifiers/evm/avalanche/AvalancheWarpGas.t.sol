// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {AvalancheWarpFixtures} from "@test/verifiers/evm/avalanche/AvalancheWarpFixtures.sol";
import {AvalancheWarpVerifier} from "@hiero-ledger/clpr/verifiers/evm/avalanche/AvalancheWarpVerifier.sol";

/// @dev Gas and calldata at Avalanche MAINNET scale (measured 2026-10-01: 588 unique Primary Network
///      BLS keys; the public ACP-118 aggregator returned 170 signers for a C-Chain block hash).
///      Hedera limits: 15M gas per transaction, 128 KB calldata.
contract AvalancheWarpGasTest is AvalancheWarpFixtures {
    uint256 internal constant N = 588;
    uint256 internal constant SIGNERS = 170;
    uint256 internal constant HEDERA_GAS = 15_000_000;
    uint256 internal constant HEDERA_CALLDATA = 128 * 1024;

    AvalancheWarpVerifier internal verifier;

    function setUp() public {
        verifier = new AvalancheWarpVerifier();
        _setupAttestors();
    }

    /// Skewed weights like mainnet: the first `heavy` validators (after canonical sorting they are
    /// spread across the set) carry enough stake that `heavy` signers reach 67%.
    function _mainnetLikeSet(string memory seed) internal view returns (Set memory s, uint256[] memory signers) {
        uint64[] memory w = new uint64[](N);
        for (uint256 i = 0; i < N; i++) {
            w[i] = i < SIGNERS ? 10e9 : 2e9; // 1700 / (1700 + 836) = 67.03%
        }
        s = _makeSet(N, seed, w);
        signers = new uint256[](SIGNERS);
        uint256 k;
        for (uint256 i = 0; i < N && k < SIGNERS; i++) {
            if (s.vals[i].weight == 10e9) signers[k++] = i;
        }
    }

    /// Execution gas of the verifier call alone: calldata is built first, so the caller's own memory
    /// expansion is not counted. Hedera total = 21k + calldata (16/byte upper bound) + execution.
    function _measure(string memory label, bytes memory proof, bytes memory anchor)
        internal
        view
        returns (uint256 gas)
    {
        bytes memory data = abi.encodeCall(AvalancheWarpVerifier.verifyBundle, (proof, anchor, _channelContext()));
        address target = address(verifier);
        uint256 g = gasleft();
        (bool ok,) = target.staticcall(data);
        gas = g - gasleft();
        require(ok, "verifyBundle reverted");
        uint256 nonZero;
        for (uint256 i = 0; i < data.length; i++) {
            if (data[i] != 0) nonZero++;
        }
        uint256 intrinsic = 21_000 + nonZero * 16 + (data.length - nonZero) * 4;
        console.log(label);
        console.log("  execution gas", gas);
        console.log("  calldata bytes", data.length);
        console.log("  total incl. 21k + calldata gas", gas + intrinsic);
        assertLt(gas + intrinsic, HEDERA_GAS, "exceeds Hedera gas");
        assertLt(data.length, HEDERA_CALLDATA, "exceeds Hedera calldata");
    }

    function test_gas_mainnetScale_typicalBundle() public {
        (Set memory s, uint256[] memory idx) = _mainnetLikeSet("mainnet");
        _measure(
            "mainnet-scale bundle: 588 keys, 170 signers",
            _signedBundle(s, idx, _noRotation()),
            _anchor(s, P_HEIGHT, P_TIME)
        );
    }

    /// Worst case for aggregation: equal weights, so 67% needs 394 of 588 signers.
    function test_gas_mainnetScale_equalWeights() public {
        Set memory s = _equalSet(N, "equal");
        _measure(
            "mainnet-scale bundle: 588 equal keys, 394 signers",
            _signedBundle(s, _range(0, 394), _noRotation()),
            _anchor(s, P_HEIGHT, P_TIME)
        );
    }

    /// Rotation to a fresh 588-key set (full canonical/curve/weight validation of the new set).
    function test_gas_mainnetScale_rotation() public {
        (Set memory s,) = _mainnetLikeSet("mainnet");
        (Set memory next, uint256[] memory idx) = _mainnetLikeSet("mainnet-next");
        uint256[] memory who = new uint256[](2);
        (who[0], who[1]) = (0, 1);
        bytes memory rot = _rotation(next, P_HEIGHT + 100, P_TIME + 60, 2, who);
        _measure(
            "mainnet-scale rotation bundle: 588 -> 588 keys, 2-of-3 attestors",
            _signedBundle(next, idx, rot),
            _anchor(s, P_HEIGHT, P_TIME)
        );
    }

    /// Fuji scale (71 keys, 12 signers as captured live).
    function test_gas_fujiScale() public {
        uint64[] memory w = new uint64[](71);
        for (uint256 i = 0; i < 71; i++) {
            w[i] = i < 12 ? 2e15 : 2e14;
        }
        Set memory s = _makeSet(71, "fuji", w);
        uint256[] memory idx = new uint256[](12);
        uint256 k;
        for (uint256 i = 0; i < 71 && k < 12; i++) {
            if (s.vals[i].weight == 2e15) idx[k++] = i;
        }
        _measure(
            "fuji-scale bundle: 71 keys, 12 signers", _signedBundle(s, idx, _noRotation()), _anchor(s, P_HEIGHT, P_TIME)
        );
    }
}
