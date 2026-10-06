// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";

/// @dev Validates the hand-rolled BLS12-381 compression against the published curve generators —
///      the authoritative correctness check for the field arithmetic and sign conventions.
contract ClprBls12381Test is Test {
    // BLS12-381 G1 generator, ZCash/Ethereum serialization.
    bytes internal constant G1_GEN_COMPRESSED =
        hex"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    bytes internal constant G1_GEN_X =
        hex"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    bytes internal constant G1_GEN_Y =
        hex"08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    /// @dev Compressing the uncompressed generator must reproduce the canonical compressed generator
    ///      (validates x-copy, the sign bit, and flags). On-chain decompression is not implemented —
    ///      the relayer supplies uncompressed points — so only the compress direction is exercised.
    function test_compressG1_generator() public pure {
        bytes memory uncompressed = abi.encodePacked(bytes16(0), G1_GEN_X, bytes16(0), G1_GEN_Y);
        bytes memory got = ClprBls12381.compressG1(uncompressed);
        assertEq(got.length, 48, "compressed G1 is 48 bytes");
        assertEq(keccak256(got), keccak256(G1_GEN_COMPRESSED), "compressed G1 generator mismatch");
    }

    function test_compressG1_infinity() public pure {
        bytes memory got = ClprBls12381.compressG1(new bytes(128));
        bytes memory expected = new bytes(48);
        expected[0] = bytes1(uint8(0xc0)); // compressed + infinity
        assertEq(keccak256(got), keccak256(expected), "infinity -> 0xc0 prefix");
    }

    function test_halfModulus_isHalfOfFieldModulus() public pure {
        (uint256 pHi, uint256 pLo) = _fieldModulus();
        uint256 carry = ClprBls12381.P_HALF_LO >> 255;
        assertEq(ClprBls12381.P_HALF_HI * 2 + carry, pHi, "2 * P_HALF + 1 == p, high word");
        assertEq((ClprBls12381.P_HALF_LO << 1) + 1, pLo, "2 * P_HALF + 1 == p, low word");
    }

    /// @dev (p - 1) / 2 comes from the modulus here, not from P_HALF, so a wrong constant fails.
    function test_compressG1_signFlagFlipsAboveHalfModulus() public pure {
        (uint256 pHi, uint256 pLo) = _fieldModulus();
        uint256 halfHi = pHi >> 1;
        uint256 halfLo = (pLo >> 1) | (pHi << 255);
        assertEq(uint8(ClprBls12381.compressG1(_withY(halfHi, halfLo))[0]) & 0x20, 0, "y = (p - 1) / 2");
        assertEq(uint8(ClprBls12381.compressG1(_withY(halfHi, halfLo + 1))[0]) & 0x20, 0x20, "y = (p + 1) / 2");
    }

    function _fieldModulus() internal pure returns (uint256 hi, uint256 lo) {
        bytes memory m = ClprBls12381.FIELD_MODULUS;
        assembly ("memory-safe") {
            hi := shr(128, mload(add(m, 0x20)))
            lo := mload(add(m, 0x30))
        }
    }

    function _withY(uint256 yHi, uint256 yLo) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes16(0), G1_GEN_X, yHi, yLo); // 32-byte yHi = 16 zero bytes + top of y
    }
}
