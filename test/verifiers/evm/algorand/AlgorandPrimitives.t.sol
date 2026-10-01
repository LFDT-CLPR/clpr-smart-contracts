// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {AlgorandEngines} from "@test/verifiers/evm/algorand/AlgorandEngines.sol";
import {ClprFalconDet1024Engine} from "@hiero-ledger/clpr/libraries/proof/algorand/ClprFalconDet1024Engine.sol";

/// @notice Known-answer tests for the Algorand hash engines: SHAKE256 (vectors from @noble/hashes) and
///         SumHash512 vector-commitment folding on a REAL mainnet state-proof reveal
///         (test/e2e/fixtures/algorand-live/vectors.json).
contract AlgorandPrimitivesTest is Test {
    address internal shake;
    address internal sumhash;
    string internal json;

    function setUp() public {
        (shake, sumhash) = AlgorandEngines.deploy();
        json = vm.readFile("test/e2e/fixtures/algorand-live/vectors.json");
    }

    function _shake(bytes memory d, uint256 n) internal view returns (bytes memory out) {
        bool ok;
        (ok, out) = shake.staticcall(abi.encodePacked(uint8(1), uint32(n), d));
        require(ok, "shake");
    }

    function test_shake256_vectors() public view {
        assertEq(
            _shake("", 64),
            hex"46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
        );
        bytes memory abc = _shake("abc", 300);
        assertEq(abc.length, 300);
        assertEq(bytes32(abc), hex"483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739");
        bytes memory x = new bytes(300);
        for (uint256 i = 0; i < 300; i++) {
            x[i] = bytes1(uint8(i));
        }
        assertEq(_shake(x, 40), hex"bced6f4208dce0e6bc155ae057d0589bbfa798b46c7866d107e8d14aee3a46e9a292d82d60f77802");
        bytes memory y = new bytes(136);
        for (uint256 i = 0; i < 136; i++) {
            y[i] = bytes1(uint8(i * 7));
        }
        assertEq(_shake(y, 40), hex"df8d71c9fb19d0677171b3745b3c0cdaa5e15393d2d5fdd75bdedbc979af1d840b97ed6b0d2b9534");
        uint256 g = gasleft();
        _shake("", 136 * 10);
        console.log("SHAKE256 1360 bytes gas", g - gasleft());
    }

    function test_falcon_liveReveals() public {
        ClprFalconDet1024Engine f = new ClprFalconDet1024Engine(shake);
        bytes memory m = vm.parseJsonBytes(json, ".msgHash");
        for (uint256 i = 0; i < 3; i++) {
            string memory r = string.concat(".reveals[", vm.toString(i), "].");
            bytes memory vkey = vm.parseJsonBytes(json, string.concat(r, "vkey"));
            bytes memory sig = vm.parseJsonBytes(json, string.concat(r, "sigCT"));
            uint256 g = gasleft();
            assertTrue(f.verify(vkey, sig, m));
            if (i == 0) console.log("falcon-1024 verify gas", g - gasleft());
            bytes memory bad = bytes.concat(m);
            bad[5] ^= 0x01;
            assertFalse(f.verify(vkey, sig, bad));
            sig[700] ^= 0x10;
            assertFalse(f.verify(vkey, sig, m));
        }
    }

    /// @dev Engine costs used in the README: SumHash512 per 64-byte block (incl. the 256 KiB table load per
    ///      call) and Falcon hash-to-point.
    function test_engineGas() public view {
        bytes memory l0 = abi.encodePacked(uint32(0), uint64(0), uint8(0));
        bytes memory l10 = abi.encodePacked(uint32(640), new bytes(640), uint64(0), uint8(0));
        uint256 g = gasleft();
        (bool ok,) = sumhash.staticcall(l0);
        uint256 one = g - gasleft();
        g = gasleft();
        (ok,) = sumhash.staticcall(l10);
        uint256 eleven = g - gasleft();
        assertTrue(ok);
        console.log("sumhash call with 1 block", one);
        console.log("sumhash per extra block", (eleven - one) / 10);
        g = gasleft();
        (ok,) = shake.staticcall(abi.encodePacked(uint8(2), new bytes(72)));
        console.log("falcon hash-to-point gas", g - gasleft());
        assertTrue(ok);
    }

    function _le(uint256 v, uint256 n) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i = 0; i < n; i++) {
            b[i] = bytes1(uint8(v >> (8 * i)));
        }
    }

    function _r(string memory k) internal view returns (string memory) {
        return string.concat(".reveals[0].", k);
    }

    function test_sumhash_liveReveal() public view {
        uint256 pos = vm.parseJsonUint(json, _r("pos"));
        bytes memory part = abi.encodePacked(
            "spp",
            _le(vm.parseJsonUint(json, _r("weight")), 8),
            _le(vm.parseJsonUint(json, _r("keyLifetime")), 8),
            vm.parseJsonBytes(json, _r("commitment"))
        );
        bytes memory partPath = vm.parseJsonBytes(json, _r("partPath"));
        bytes memory job =
            abi.encodePacked(uint32(part.length), part, uint64(pos), uint8(partPath.length / 64), partPath);
        uint256 g = gasleft();
        (bool ok, bytes memory root) = sumhash.staticcall(job);
        console.log("sumhash part leaf + 10-level path gas", g - gasleft());
        assertTrue(ok);
        assertEq(root, vm.parseJsonBytes(json, ".prev.votersCommitment"));
    }
}

