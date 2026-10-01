// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {MonadVerifier} from "@hiero-ledger/clpr/verifiers/evm/monad/MonadVerifier.sol";
import {MonadValsetRotation} from "@hiero-ledger/clpr/verifiers/evm/monad/MonadValsetRotation.sol";

/// @dev Execution gas of MonadVerifier.verifyBundle on the 196-validator synthetic fixture, against the
///      Hedera per-transaction limits (15M gas, 128 KiB calldata). Calldata gas (16/4 per byte) is reported
///      separately; on Hedera the relay's transaction gas = intrinsic + calldata + execution.
contract MonadGasUsageTest is Test {
    string internal constant DIR = "test/verifiers/evm/monad/fixtures/synthetic/";
    uint256 internal constant HEDERA_GAS = 15_000_000;
    uint256 internal constant HEDERA_CALLDATA = 131_072;

    MonadVerifier verifier;
    bytes ctx;

    function setUp() public {
        verifier = new MonadVerifier(new MonadValsetRotation());
        ctx = vm.parseJsonBytes(vm.readFile(string.concat(DIR, "meta.json")), ".channelContext");
    }

    function _calldataGas(bytes memory b) internal pure returns (uint256 g) {
        for (uint256 i = 0; i < b.length; ++i) {
            g += b[i] == 0 ? 4 : 16;
        }
    }

    function _measure(string memory label, bytes memory proof, bytes memory anchor) internal returns (bytes memory na) {
        bytes memory cd = abi.encodeCall(MonadVerifier.verifyBundle, (proof, anchor, ctx));
        uint256 g = gasleft();
        (,, na,,) = verifier.verifyBundle(proof, anchor, ctx);
        uint256 used = g - gasleft();
        uint256 total = 21_000 + _calldataGas(cd) + used;
        console.log(label);
        console.log("  execution gas", used);
        console.log("  calldata bytes", cd.length);
        console.log("  tx gas (21000 + calldata + execution)", total);
        assertLt(total, HEDERA_GAS, "over Hedera gas limit");
        assertLt(cd.length, HEDERA_CALLDATA, "over Hedera calldata limit");
    }

    function _case(string memory name) internal view returns (bytes memory p, bytes memory a) {
        string memory c = vm.readFile(string.concat(DIR, name, ".json"));
        p = vm.parseJsonBytes(c, ".proof");
        a = vm.parseJsonBytes(c, ".anchor");
    }

    function test_gas_typicalBundle() public {
        (bytes memory p, bytes memory a) = _case("bundle_ok");
        _measure("typical bundle (196 validators, 2 messages)", p, a);
    }

    function test_gas_rotation() public {
        (bytes memory p, bytes memory a) = _case("rotation_start");
        bytes memory na = _measure("rotation start (finalized bundle + staking epoch/delay flag + id array)", p, a);
        _steps("rotation_step_", ".rotationSteps", "warm chunk ", na);
    }

    function test_gas_rotationCold() public {
        bytes memory na = vm.parseJsonBytes(vm.readFile(string.concat(DIR, "meta.json")), ".coldStart");
        _steps("rotation_cold_step_", ".rotationColdSteps", "cold chunk ", na);
    }

    function _steps(string memory prefix, string memory key, string memory label, bytes memory na) internal {
        uint256 steps = vm.parseJsonUint(vm.readFile(string.concat(DIR, "meta.json")), key);
        for (uint256 i = 0; i < steps; ++i) {
            string memory st = vm.readFile(string.concat(DIR, prefix, vm.toString(i), ".json"));
            na = _measure(
                string.concat(label, vm.toString(i), i + 1 == steps ? " (+ finalize)" : ""),
                vm.parseJsonBytes(st, ".proof"),
                na
            );
        }
    }
}
