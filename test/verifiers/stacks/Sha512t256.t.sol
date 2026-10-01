// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Sha512t256} from "../../../src/libraries/crypto/Sha512t256.sol";
import {Sha256Midstate} from "../../../src/libraries/crypto/Sha256Midstate.sol";
import {ClprSha512t256Hasher, Sha512t256Call} from "../../../src/libraries/crypto/ClprSha512t256Hasher.sol";

contract Sha512t256Test is Test {
    function _rep(uint256 n) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i = 0; i < n; ++i) {
            b[i] = "a";
        }
    }

    function test_sha512t256_vectors() public pure {
        assertEq(Sha512t256.hash(""), hex"c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
        assertEq(Sha512t256.hash("abc"), hex"53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23");
        assertEq(Sha512t256.hash(_rep(300)), hex"19f6f40dff1362d4798293b101b08b0e7d6ca4748780c164701ecce2412e3d17");
    }

    /// Every length 0..259 (one- and two-block tails, the 111/112 boundary where the length word
    /// shares the last block with message bytes): sha256 over all 260 digests vs. Python hashlib.
    function test_sha512t256_allTailLengths() public pure {
        bytes memory all;
        for (uint256 n = 0; n < 260; ++n) {
            all = abi.encodePacked(all, Sha512t256.hash(_rep(n)));
        }
        assertEq(sha256(all), hex"5abdc16c4f1855c4e73dd611ee56737d9fd57102b111e3ef7df36153345d7591");
    }

    /// The bytecode hasher: the same 260-length vector, plus a 17 KB input (a Node256-sized MARF node).
    function test_bytecodeHasher_allTailLengths() public {
        address hasher = address(new ClprSha512t256Hasher());
        bytes memory all;
        for (uint256 n = 0; n < 260; ++n) {
            all = abi.encodePacked(all, Sha512t256Call.hash(hasher, _rep(n)));
        }
        assertEq(sha256(all), hex"5abdc16c4f1855c4e73dd611ee56737d9fd57102b111e3ef7df36153345d7591");
        bytes memory big = new bytes(16_900);
        for (uint256 i = 0; i < big.length; ++i) {
            big[i] = bytes1(uint8(i * 7 + 3));
        }
        assertEq(Sha512t256Call.hash(hasher, big), Sha512t256.hash(big));
    }

    function test_gas_bytecodeHasher() public {
        address hasher = address(new ClprSha512t256Hasher());
        bytes memory d1 = new bytes(1270);
        uint256 g = gasleft();
        Sha512t256Call.hash(hasher, "");
        uint256 one = g - gasleft();
        g = gasleft();
        Sha512t256Call.hash(hasher, d1);
        console.log("bytecode sha512/256: 1 block", one, "11 blocks", g - gasleft());
        console.log("hasher runtime bytes", hasher.code.length);
    }

    /// Every SHA-256 tail length 0..129 (incl. the 55/56 boundary) against the precompile.
    function test_sha256_allTailLengths() public pure {
        for (uint256 n = 0; n < 130; ++n) {
            bytes memory d = _rep(n);
            assertEq(Sha256Midstate.resume(Sha256Midstate.IV, 0, d), sha256(d));
        }
    }

    /// Every tail length class (0..129 and around the 111/112 two-block boundary) against a fresh
    /// SHA-256 via the precompile, using the midstate API from the IV.
    function test_sha256_resumeFromIv_matchesPrecompile() public pure {
        for (uint256 n = 0; n < 140; n += 7) {
            bytes memory d = _rep(n);
            assertEq(Sha256Midstate.resume(Sha256Midstate.IV, 0, d), sha256(d));
        }
        assertEq(Sha256Midstate.resume(Sha256Midstate.IV, 0, _rep(55)), sha256(_rep(55)));
        assertEq(Sha256Midstate.resume(Sha256Midstate.IV, 0, _rep(56)), sha256(_rep(56)));
        assertEq(Sha256Midstate.resume(Sha256Midstate.IV, 0, _rep(64)), sha256(_rep(64)));
    }

    function test_sha256_rejectsUnalignedByteCount() public {
        Probe p = new Probe();
        vm.expectRevert(Sha256Midstate.Sha256BadByteCount.selector);
        p.resume(Sha256Midstate.IV, 63, "");
    }

    function test_gas_sha() public view {
        bytes memory d0 = new bytes(0);
        bytes memory d1 = new bytes(1270);
        uint256 g = gasleft();
        Sha512t256.hash(d0);
        uint256 one = g - gasleft();
        g = gasleft();
        Sha512t256.hash(d1);
        uint256 eleven = g - gasleft();
        console.log("sha512/256: 1 block", one, "11 blocks", eleven);
        g = gasleft();
        Sha256Midstate.resume(Sha256Midstate.IV, 0, new bytes(100));
        console.log("sha256 resume, 2 blocks", g - gasleft());
    }
}

contract Probe {
    function resume(bytes32 s, uint256 n, bytes memory d) external pure returns (bytes32) {
        return Sha256Midstate.resume(s, n, d);
    }
}
