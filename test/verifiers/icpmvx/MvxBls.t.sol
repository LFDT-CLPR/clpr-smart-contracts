// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {MvxBls} from "@hiero-ledger/clpr/libraries/proof/mvx/MvxBls.sol";
import {MvxMetachainVerifier} from "@hiero-ledger/clpr/verifiers/icpmvx/MvxMetachainVerifier.sol";
import {MvxHarness} from "@test/verifiers/icpmvx/MvxLive.t.sol";

/// @notice Synthetic MultiversX validator sets: keys sk·Q and signatures sk·H(m) made with the EIP-2537
///         MSM precompiles over the same Q and H as {MvxBls}; MvxLive.t.sol covers mainnet data.
contract MvxBlsTest is Test {
    uint256 internal constant R_MINUS_1 = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000;
    MvxHarness internal h;
    bytes internal q;

    function setUp() public {
        h = new MvxHarness();
        q = _g2Mul(MvxBls.NEG_Q, R_MINUS_1); // Q = −(−Q)
    }

    function _g2Mul(bytes memory p, uint256 k) internal view returns (bytes memory out) {
        bool ok;
        (ok, out) = address(0x0e).staticcall(abi.encodePacked(p, k));
        require(ok && out.length == 256, "G2MSM");
    }

    function _sign(uint256 sk, bytes memory m) internal view returns (bytes memory out) {
        bool ok;
        (ok, out) = address(0x0c).staticcall(abi.encodePacked(h.hashToG1(m), sk));
        require(ok && out.length == 128, "G1MSM");
    }

    function _g1Add(bytes memory a, bytes memory b) internal view returns (bytes memory out) {
        bool ok;
        (ok, out) = address(0x0b).staticcall(abi.encodePacked(a, b));
        require(ok, "G1ADD");
    }

    function test_signVerify_roundTrip() public view {
        bytes[3] memory msgs = [bytes(""), bytes("abc"), abi.encodePacked(keccak256("header"))];
        for (uint256 i = 0; i < 3; i++) {
            uint256 sk = 1000 + i;
            h.verify(_g2Mul(q, sk), _sign(sk, msgs[i]), msgs[i]);
        }
    }

    function test_rejects_wrongKey() public {
        bytes memory pk = _g2Mul(q, 7);
        bytes memory sig = _sign(8, "m");
        vm.expectRevert(MvxBls.BadSignature.selector);
        h.verify(pk, sig, "m");
    }

    function test_rejects_badLengths() public {
        vm.expectRevert(MvxBls.BadPointLength.selector);
        h.verify(new bytes(255), new bytes(128), "m");
    }

    function test_rejects_signatureNotInSubgroupOrCurve() public {
        bytes memory pk = _g2Mul(q, 7);
        bytes memory bad = _sign(7, "m");
        bad[127] ^= 0x01; // off the curve
        vm.expectRevert(MvxBls.BlsPrecompileFailed.selector);
        h.verify(pk, bad, "m");
    }

    function test_hashToG1_isInSubgroup() public view {
        // G1MSM rejects points outside the subgroup, so a successful r·H shows the cofactor was cleared
        bytes memory p = h.hashToG1("subgroup");
        (bool ok, bytes memory out) = address(0x0c).staticcall(abi.encodePacked(p, uint256(1)));
        assertTrue(ok);
        assertEq(out, p);
    }

    // ── aggregated proofs over a synthetic list of 10 validators (threshold 7) ──

    function _set(uint256 n) internal view returns (bytes memory keys) {
        for (uint256 i = 0; i < n; i++) {
            keys = bytes.concat(keys, _g2Mul(q, 100 + i));
        }
    }

    function _aggSig(bytes32 hh, uint256 mask) internal view returns (bytes memory sig) {
        for (uint256 i = 0; i < 16; i++) {
            if (mask & (1 << i) == 0) continue;
            bytes memory s = _sign(100 + i, abi.encodePacked(hh));
            sig = sig.length == 0 ? s : _g1Add(sig, s);
        }
    }

    function test_aggregate_thresholdAndPadding() public {
        bytes memory keys = _set(10);
        MvxMetachainVerifier v = new MvxMetachainVerifier(5, 10, keccak256(keys));
        bytes32 hh = keccak256("hdr");
        uint256 mask = 0x37f; // validators 0..6, 8, 9 → 9 signers
        bytes memory sig = _aggSig(hh, mask);
        assertEq(v.verifyHeaderHash(hh, abi.encodePacked(uint16(0x7f03)), sig, keys), 9); // bytes 0x7f, 0x03

        uint256 seven = 0x7f; // exactly the threshold 10·2/3 + 1 = 7
        assertEq(v.verifyHeaderHash(hh, abi.encodePacked(uint16(0x7f00)), _aggSig(hh, seven), keys), 7);

        bytes memory six = _aggSig(hh, 0x3f);
        vm.expectRevert(abi.encodeWithSelector(MvxMetachainVerifier.BelowThreshold.selector, 6, 7));
        v.verifyHeaderHash(hh, abi.encodePacked(uint16(0x3f00)), six, keys);

        // padding bits (10..15) must be clear
        vm.expectRevert(MvxMetachainVerifier.BadBitmap.selector);
        v.verifyHeaderHash(hh, abi.encodePacked(uint16(0x7f04)), sig, keys);
    }

    function test_aggregate_rejectsReorderedList() public {
        bytes memory keys = _set(10);
        MvxMetachainVerifier v = new MvxMetachainVerifier(5, 10, keccak256(keys));
        bytes32 hh = keccak256("hdr");
        bytes memory sig = _aggSig(hh, 0x3ff);
        bytes memory swapped = bytes.concat(_g2Mul(q, 101), _g2Mul(q, 100));
        for (uint256 i = 2; i < 10; i++) {
            swapped = bytes.concat(swapped, _g2Mul(q, 100 + i));
        }
        vm.expectRevert(MvxMetachainVerifier.KeysMismatch.selector);
        v.verifyHeaderHash(hh, abi.encodePacked(uint16(0xff03)), sig, swapped);
    }

    function test_aggregate_rejectsSignerNotInBitmap() public {
        bytes memory keys = _set(10);
        MvxMetachainVerifier v = new MvxMetachainVerifier(5, 10, keccak256(keys));
        bytes32 hh = keccak256("hdr");
        bytes memory sig = _aggSig(hh, 0x0ff); // 0..7 signed
        vm.expectRevert(MvxBls.BadSignature.selector);
        v.verifyHeaderHash(hh, abi.encodePacked(uint16(0x7f01)), sig, keys); // claims 0..6 and 8
    }
}
