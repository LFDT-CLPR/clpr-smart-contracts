// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {MonadBlake3} from "@hiero-ledger/clpr/libraries/proof/monad/MonadBlake3.sol";

contract MonadBlake3Harness {
    function hash(bytes memory d) external pure returns (bytes32) {
        return MonadBlake3.hash(d);
    }

    function pageCommit(uint128 bm, bytes32[] memory v) external pure returns (bytes32) {
        return MonadBlake3.pageCommit(bm, v);
    }
}

/// @dev Hash vectors from @noble/hashes blake3; page-commit vectors are the C++ reference values in
///      category-labs/monad `category/execution/monad/db/test_storage_page.cpp`
///      (`page_commit_cross_check_with_reference`).
contract MonadBlake3Test is Test {
    MonadBlake3Harness h;

    function setUp() public {
        h = new MonadBlake3Harness();
    }

    function _input(uint256 n) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i = 0; i < n; ++i) {
            b[i] = bytes1(uint8((i * 7 + 3) & 0xff));
        }
    }

    function test_hash_vectors() public view {
        assertEq(h.hash(_input(0)), 0xaf1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262);
        assertEq(h.hash(_input(1)), 0xe1e0e81d6ea39b0cf8b86ffd440921011f57400cbc3f76a8a171906a9b8d7505);
        assertEq(h.hash(_input(64)), 0x5be24e499b8524251b3c29a2bf64c6311f06d1ed45b6dbd0fc7969ca1d40a8a1);
        assertEq(h.hash(_input(65)), 0xcbcd89c7de15737fb8c79ac39071fdf430dfa7cb771d140c0e5368200eb45a61);
        assertEq(h.hash(_input(1024)), 0xe3f027f2c0380f4ee59b4213e5bbfc65e5158b27196bb5ea63453a2cbc47a888);
        assertEq(h.hash(_input(1025)), 0xafd7cf3dec77579ce5aaab21256350d354ca4caaef56e897405771d6bb4c0c93);
        assertEq(h.hash(_input(2049)), 0xd736dbbf1f550c4cd458ff02c3af3a8e427fc8caaf907a883266e0922443864a);
        assertEq(h.hash(_input(3000)), 0x2285e439b7e4f97ba8ffddd68f8aff06a8ba2edbe908e0ef3aee03c002971afe);
        assertEq(h.hash(_input(5000)), 0x99dac71e48bb629da58fe862e286769ac5a0debf976c22bdba71cd34e4c25aa6);
    }

    function test_pageCommit_cppReferenceVectors() public view {
        bytes32[] memory none = new bytes32[](0);
        assertEq(h.pageCommit(0, none), 0xe572dff82304700b856a555ac3a4558d0df3646a3727816500270a93c66aac1e);

        bytes32[] memory one = new bytes32[](1);
        one[0] = bytes32(uint256(1));
        assertEq(h.pageCommit(1, one), 0x80218c63919cd8c68aa9a5c0117bb8b46eb02099a7ce0b47a36e7b21658cc9f9);
        assertEq(
            h.pageCommit(uint128(1) << 127, one), 0x39a2175f8fac8fbf447383b46ff40e03673b388c05c87e50ed7b3f1a810c98d8
        );

        bytes32[] memory full = new bytes32[](128);
        for (uint256 i = 0; i < 128; ++i) {
            full[i] = bytes32(i + 1);
        }
        assertEq(
            h.pageCommit(type(uint128).max, full), 0xe5a642261a2c2dedebd68ebd42237f2210d1eee94553d677d425dc3a46c7a687
        );
    }

    function test_pageCommit_rejectsNonCanonical() public {
        bytes32[] memory one = new bytes32[](1);
        // zero value behind a set bit
        vm.expectRevert(MonadBlake3.PageNotCanonical.selector);
        h.pageCommit(1, one);
        // too many values
        one[0] = bytes32(uint256(5));
        bytes32[] memory two = new bytes32[](2);
        two[0] = one[0];
        two[1] = one[0];
        vm.expectRevert(MonadBlake3.PageNotCanonical.selector);
        h.pageCommit(1, two);
        // too few values
        vm.expectRevert(MonadBlake3.PageNotCanonical.selector);
        h.pageCommit(3, one);
        // values with empty bitmap
        vm.expectRevert(MonadBlake3.PageNotCanonical.selector);
        h.pageCommit(0, one);
    }

    function test_gas_compress() public {
        bytes memory b = _input(64);
        uint256 g = gasleft();
        h.hash(b);
        emit log_named_uint("blake3(64B) gas", g - gasleft());
        b = _input(1500);
        g = gasleft();
        h.hash(b);
        emit log_named_uint("blake3(1500B) gas", g - gasleft());
    }
}
