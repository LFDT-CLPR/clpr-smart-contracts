// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {MvxBls} from "@hiero-ledger/clpr/libraries/proof/mvx/MvxBls.sol";
import {MvxBlake2b} from "@hiero-ledger/clpr/libraries/proof/mvx/MvxBlake2b.sol";
import {MvxSha512} from "@hiero-ledger/clpr/libraries/proof/mvx/MvxSha512.sol";
import {MvxMetachainVerifier} from "@hiero-ledger/clpr/verifiers/icpmvx/MvxMetachainVerifier.sol";

contract MvxHarness {
    function verify(bytes memory pk, bytes memory sig, bytes memory m) external view {
        MvxBls.verify(pk, sig, m);
    }

    function sha512(bytes memory m) external pure returns (bytes memory) {
        return MvxSha512.hash(m);
    }

    function blake2b(bytes memory m) external view returns (bytes32) {
        return MvxBlake2b.hash256(m);
    }

    function hashToG1(bytes memory m) external view returns (bytes memory) {
        return MvxBls.hashToG1(m);
    }
}

/// @notice MultiversX BLS and metachain header proofs against real mainnet blocks
///         (test/e2e/fixtures/mvx-live/mainnet.json, re-record with `npm run mvx-live:refresh`).
contract MvxLiveTest is Test {
    string internal j;
    MvxHarness internal h;

    function setUp() public {
        j = vm.readFile(string.concat(vm.projectRoot(), "/test/e2e/fixtures/mvx-live/mainnet.json"));
        h = new MvxHarness();
    }

    function _b(string memory path) internal view returns (bytes memory) {
        return vm.parseJsonBytes(j, path);
    }

    function _keys(string memory c) internal view returns (bytes memory out) {
        bytes[] memory ks = vm.parseJsonBytesArray(j, string.concat(".", c, ".keys"));
        for (uint256 i = 0; i < ks.length; i++) {
            out = bytes.concat(out, ks[i]);
        }
    }

    function _verifier(string memory c) internal returns (MvxMetachainVerifier) {
        return new MvxMetachainVerifier(
            uint32(vm.parseJsonUint(j, string.concat(".", c, ".epoch"))),
            vm.parseJsonUint(j, string.concat(".", c, ".eligible")),
            vm.parseJsonBytes32(j, string.concat(".", c, ".keysHash"))
        );
    }

    // ── hash primitives ─────────────────────────────────────────────────────

    function test_sha512_vectors() public view {
        assertEq(
            h.sha512(""),
            hex"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        assertEq(
            h.sha512("abc"),
            hex"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        bytes memory m = new bytes(200);
        for (uint256 i = 0; i < 200; i++) {
            m[i] = bytes1(uint8(i));
        }
        assertEq(
            h.sha512(m),
            hex"986058e9895e2c2ab8f9e8cbdf801db12a44842a56a91d5a4e87b1fc98b293722c4664142e42c3c551ff898646268cd92b84ed230b8c94bed7798d4f27cd7465"
        );
    }

    function test_blake2b_vectors() public view {
        assertEq(h.blake2b(""), 0x0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8);
        assertEq(h.blake2b("abc"), 0xbddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319);
        bytes memory m = new bytes(200);
        for (uint256 i = 0; i < 200; i++) {
            m[i] = bytes1(uint8(i));
        }
        assertEq(h.blake2b(m), 0x63c3d97a9f8894d5e043a707b0fee7f7ec4c049a23bbf1079df20b4165f9e22d);
    }

    function test_live_headerHashIsBlake2bOfRawHeader() public view {
        assertEq(h.blake2b(_b(".meta.rawHeader")), vm.parseJsonBytes32(j, ".meta.headerHash"));
        assertEq(h.blake2b(_b(".shard0.rawHeader")), vm.parseJsonBytes32(j, ".shard0.headerHash"));
    }

    // ── single signatures (leader rand seed) ────────────────────────────────

    function test_live_leaderRandSeedSignature_meta() public view {
        h.verify(_b(".meta.leader.key"), _b(".meta.leader.signature"), _b(".meta.leader.message"));
    }

    function test_live_leaderRandSeedSignature_shard0() public view {
        h.verify(_b(".shard0.leader.key"), _b(".shard0.leader.signature"), _b(".shard0.leader.message"));
    }

    function test_live_rejectsSignatureOnOtherMessage() public {
        bytes memory k = _b(".meta.leader.key");
        bytes memory s = _b(".meta.leader.signature");
        vm.expectRevert(MvxBls.BadSignature.selector);
        h.verify(k, s, "other");
    }

    function test_live_rejectsOtherLeaderKey() public {
        bytes memory k = _b(".shard0.leader.key");
        bytes memory s = _b(".meta.leader.signature");
        bytes memory m = _b(".meta.leader.message");
        vm.expectRevert(MvxBls.BadSignature.selector);
        h.verify(k, s, m);
    }

    // ── aggregated header proofs ────────────────────────────────────────────

    function test_live_metachainHeaderProof() public {
        MvxMetachainVerifier v = _verifier("meta");
        bytes memory raw = _b(".meta.rawHeader");
        bytes memory bitmap = _b(".meta.bitmap");
        bytes memory sig = _b(".meta.signature");
        bytes memory keys = _keys("meta");
        // gas and calldata are measured as real transactions in mvx-live.spec.ts
        (bytes32 hh, uint64 nonce, uint256 signers) = v.verifyHeader(raw, bitmap, sig, keys);
        assertEq(hh, vm.parseJsonBytes32(j, ".meta.headerHash"));
        assertEq(nonce, vm.parseJsonUint(j, ".meta.nonce"));
        assertEq(signers, vm.parseJsonUint(j, ".meta.signers"));
    }

    function test_live_shard0HeaderProof() public {
        MvxMetachainVerifier v = _verifier("shard0");
        bytes32 hh = vm.parseJsonBytes32(j, ".shard0.headerHash");
        uint256 signers = v.verifyHeaderHash(hh, _b(".shard0.bitmap"), _b(".shard0.signature"), _keys("shard0"));
        assertEq(signers, vm.parseJsonUint(j, ".shard0.signers"));
    }

    function test_live_rejectsTamperedHeader() public {
        MvxMetachainVerifier v = _verifier("meta");
        bytes memory raw = _b(".meta.rawHeader");
        raw[raw.length - 1] ^= 0x01;
        bytes memory bitmap = _b(".meta.bitmap");
        bytes memory sig = _b(".meta.signature");
        bytes memory keys = _keys("meta");
        vm.expectRevert(MvxBls.BadSignature.selector);
        v.verifyHeader(raw, bitmap, sig, keys);
    }

    function test_live_rejectsWrongValidatorSet() public {
        MvxMetachainVerifier v = _verifier("meta");
        bytes32 hh = vm.parseJsonBytes32(j, ".meta.headerHash");
        bytes memory bitmap = _b(".meta.bitmap");
        bytes memory sig = _b(".meta.signature");
        bytes memory keys = _keys("shard0"); // another eligible list
        vm.expectRevert(MvxMetachainVerifier.KeysMismatch.selector);
        v.verifyHeaderHash(hh, bitmap, sig, keys);
        // the shard-0 list pinned instead: the signature does not match
        MvxMetachainVerifier w = new MvxMetachainVerifier(0, 400, keccak256(keys));
        vm.expectRevert(MvxBls.BadSignature.selector);
        w.verifyHeaderHash(hh, bitmap, sig, keys);
    }

    function test_live_rejectsBelowThreshold() public {
        MvxMetachainVerifier v = _verifier("meta");
        bytes32 hh = vm.parseJsonBytes32(j, ".meta.headerHash");
        bytes memory bitmap = _b(".meta.bitmap");
        bytes memory sig = _b(".meta.signature");
        bytes memory keys = _keys("meta");
        // clear signer bits until 266 remain (threshold for 400 is 267)
        uint256 count = vm.parseJsonUint(j, ".meta.signers");
        for (uint256 i = 0; i < 400 && count > 266; i++) {
            if (uint8(bitmap[i >> 3]) & (1 << (i & 7)) != 0) {
                bitmap[i >> 3] = bytes1(uint8(bitmap[i >> 3]) & ~uint8(1 << (i & 7)));
                count--;
            }
        }
        vm.expectRevert(abi.encodeWithSelector(MvxMetachainVerifier.BelowThreshold.selector, 266, 267));
        v.verifyHeaderHash(hh, bitmap, sig, keys);
    }

    function test_live_rejectsBitmapWithMissingSigner() public {
        // one signer removed: still above threshold, but the aggregate no longer matches
        MvxMetachainVerifier v = _verifier("meta");
        bytes32 hh = vm.parseJsonBytes32(j, ".meta.headerHash");
        bytes memory bitmap = _b(".meta.bitmap");
        bytes memory sig = _b(".meta.signature");
        bytes memory keys = _keys("meta");
        for (uint256 i = 0; i < 400; i++) {
            if (uint8(bitmap[i >> 3]) & (1 << (i & 7)) != 0) {
                bitmap[i >> 3] = bytes1(uint8(bitmap[i >> 3]) & ~uint8(1 << (i & 7)));
                break;
            }
        }
        vm.expectRevert(MvxBls.BadSignature.selector);
        v.verifyHeaderHash(hh, bitmap, sig, keys);
    }

    function test_live_rejectsWrongEpochAndBadBitmap() public {
        MvxMetachainVerifier v = new MvxMetachainVerifier(
            uint32(vm.parseJsonUint(j, ".meta.epoch") + 1), 400, vm.parseJsonBytes32(j, ".meta.keysHash")
        );
        bytes memory raw = _b(".meta.rawHeader");
        bytes memory bitmap = _b(".meta.bitmap");
        bytes memory sig = _b(".meta.signature");
        bytes memory keys = _keys("meta");
        vm.expectRevert(
            abi.encodeWithSelector(MvxMetachainVerifier.WrongEpoch.selector, uint32(vm.parseJsonUint(j, ".meta.epoch")))
        );
        v.verifyHeader(raw, bitmap, sig, keys);
        MvxMetachainVerifier w = _verifier("meta");
        bytes32 hh = vm.parseJsonBytes32(j, ".meta.headerHash");
        vm.expectRevert(MvxMetachainVerifier.BadBitmap.selector);
        w.verifyHeaderHash(hh, bytes.concat(bitmap, hex"00"), sig, keys);
    }
}
