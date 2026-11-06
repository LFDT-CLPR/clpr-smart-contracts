// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {TSSVerifier} from "@hiero-ledger/clpr/verifiers/hiero/TSSVerifier.sol";
import {WRAPSVerifierContract} from "@hiero-ledger/clpr/verifiers/hiero/wraps/WRAPSVerifierContract.sol";
import {PoseidonBN254Contract} from "@hiero-ledger/clpr/verifiers/hiero/wraps/PoseidonBN254Contract.sol";
import {PoseidonPermuteA} from "@hiero-ledger/clpr/verifiers/hiero/wraps/PoseidonPermuteA.sol";
import {PoseidonPermuteB} from "@hiero-ledger/clpr/verifiers/hiero/wraps/PoseidonPermuteB.sol";

/// @dev Tests for TSSVerifier input-validation paths that are unreachable
///      from the happy path (test_correct_signature) but exercisable via crafted inputs.
contract TSSVerifierTest is Test {
    TSSVerifier internal tssVerifier;

    /// @dev TOTAL_SETTLED_WRAPS = 1096 + 1632 + 704 = 3432 bytes
    uint256 internal constant TOTAL_SETTLED_WRAPS = 3432;
    /// @dev TOTAL_GENESIS_SCHNORR = 1096 + 1632 + 192 = 2920 bytes
    uint256 internal constant TOTAL_GENESIS_SCHNORR = 2920;

    /// @dev Standard 48-byte block root (SHA-384 length)
    bytes internal constant GOOD_BLOCK_ROOT = new bytes(48);

    function setUp() public {
        address permuteA = deployCode("PoseidonPermuteA.sol:PoseidonPermuteA");
        address permuteB = deployCode("PoseidonPermuteB.sol:PoseidonPermuteB");
        address poseidon = deployCode("PoseidonBN254Contract.sol:PoseidonBN254Contract", abi.encode(permuteA, permuteB));
        address wraps = deployCode("WRAPSVerifierContract.sol:WRAPSVerifierContract", abi.encode(poseidon));
        tssVerifier = TSSVerifier(deployCode("TSSVerifier.sol:TSSVerifier", abi.encode(wraps)));
    }

    // ── splitTssBlockSignature

    /// @dev Signature of wrong length → ClprHieroSignatureLength.
    function test_verifyTss_wrongSigLength_reverts() public {
        bytes memory badSig = new bytes(100); // neither 2920 nor 3432
        vm.expectRevert(abi.encodeWithSelector(TSSVerifier.ClprHieroSignatureLength.selector, uint256(100)));
        tssVerifier.verifyTss(new bytes(32), badSig, GOOD_BLOCK_ROOT, hex"");
    }

    function test_verifyTss_zeroLengthSig_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(TSSVerifier.ClprHieroSignatureLength.selector, uint256(0)));
        tssVerifier.verifyTss(new bytes(32), new bytes(0), GOOD_BLOCK_ROOT, hex"");
    }

    function test_verifyTss_3431bytes_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(TSSVerifier.ClprHieroSignatureLength.selector, uint256(3431)));
        tssVerifier.verifyTss(new bytes(32), new bytes(3431), GOOD_BLOCK_ROOT, hex"");
    }

    /// @dev A 2920-byte signature (TOTAL_GENESIS_SCHNORR) takes the non-WRAPS split path
    ///      (isWrapsSettled=false) and exercises the _compressG1Ark/_compressG2Ark infinity
    ///      branches for G1/G2 points. With all-zero (infinity) fields the hinTS aggregate
    ///      reverts inside a BLS precompile before reaching the WRAPS-only gate, so any
    ///      revert is accepted. (The gate itself — `ClprHieroWrapsProofRequired` — needs a
    ///      valid hinTS aggregate over a Schnorr-length signature, which cannot be
    ///      synthesized from zero data; the WRAPS path is exercised by the real fixtures.)
    function test_verifyTss_2920byteSchnorrLength_reverts() public {
        bytes memory schnorrSig = new bytes(TOTAL_GENESIS_SCHNORR); // 2920 bytes, all zeros

        // n=4 (valid power of 2 ≥ 2) and aggWeight=1 (passes threshold).
        schnorrSig[0] = 0x04; // n = 4 (LE u64 at bytes[0..8])
        schnorrSig[1192] = 0x01; // aggWeight = 1 at hintSig offset 96+1096=1192

        vm.expectRevert(); // reverts in the hinTS aggregate (BLS precompile) before the WRAPS-only gate
        tssVerifier.verifyTss(new bytes(32), schnorrSig, GOOD_BLOCK_ROOT, hex"");
    }

    function test_verifyTss_badN_zero_withSchnorr_sig() public {
        bytes memory sig = new bytes(TOTAL_GENESIS_SCHNORR); // 2920 bytes
        // n = 0 at VK[0..8] (stays zero / default)
        // totalWeight = 0 (default)
        // aggWeight = 1 → threshold: 3*1 > 1*0 = true ✓
        sig[1192] = 0x01; // aggWeight = 1

        vm.expectRevert(abi.encodeWithSelector(TSSVerifier.HieroHintsBadN.selector, uint64(0)));
        tssVerifier.verifyTss(new bytes(32), sig, GOOD_BLOCK_ROOT, hex"");
    }

    // ── _verifyHintsAggregate — blockHash length check

    /// @dev Correct signature length (3432) but blockRoot not 48 bytes →
    ///      HieroHintsBadBlockRootLen. This fires before any BLS precompile calls.
    function test_verifyTss_badBlockRootLength_10bytes() public {
        bytes memory sig = new bytes(TOTAL_SETTLED_WRAPS); // zeros, right length
        // hintVk[8..40] = totalWeight = 0, hintSig[96..128] = aggWeight = 0
        // threshold: 3*0 > 1*0 = false → would normally fail, but blockRoot check fires first
        // Actually: length check fires BEFORE threshold check, so:
        vm.expectRevert(abi.encodeWithSelector(TSSVerifier.HieroHintsBadBlockRootLen.selector, uint256(10)));
        tssVerifier.verifyTss(new bytes(32), sig, new bytes(10), hex"");
    }

    function test_verifyTss_badBlockRootLength_0bytes() public {
        bytes memory sig = new bytes(TOTAL_SETTLED_WRAPS);
        vm.expectRevert(abi.encodeWithSelector(TSSVerifier.HieroHintsBadBlockRootLen.selector, uint256(0)));
        tssVerifier.verifyTss(new bytes(32), sig, new bytes(0), hex"");
    }

    function test_verifyTss_badBlockRootLength_100bytes() public {
        bytes memory sig = new bytes(TOTAL_SETTLED_WRAPS);
        vm.expectRevert(abi.encodeWithSelector(TSSVerifier.HieroHintsBadBlockRootLen.selector, uint256(100)));
        tssVerifier.verifyTss(new bytes(32), sig, new bytes(100), hex"");
    }

    // ── _checkThreshold → HieroHintsBelowThreshold

    /// @dev 3432-byte all-zero sig + 48-byte blockRoot:
    ///      totalWeight = 0, aggWeight = 0 → THRESHOLD_DEN*0 > THRESHOLD_NUM*0 = 0 > 0 = false
    ///      → HieroHintsBelowThreshold.
    function test_verifyTss_belowThreshold_allZeroSig() public {
        bytes memory sig = new bytes(TOTAL_SETTLED_WRAPS); // all zeros
        vm.expectRevert(TSSVerifier.HieroHintsBelowThreshold.selector);
        tssVerifier.verifyTss(new bytes(32), sig, GOOD_BLOCK_ROOT, hex"");
    }

    /// @dev Sig with totalWeight=1 (large) and aggWeight=0 → below 1/3 threshold.
    function test_verifyTss_belowThreshold_aggWeightZero() public {
        bytes memory sig = new bytes(TOTAL_SETTLED_WRAPS);
        // VK offset 8..40 = totalWeight (LE Fr): set to 1
        sig[8] = 0x01; // totalWeight = 1 (LE)
        // hintSig offset 96+1096=1192..1224 = aggWeight: stays 0

        vm.expectRevert(TSSVerifier.HieroHintsBelowThreshold.selector);
        tssVerifier.verifyTss(new bytes(32), sig, GOOD_BLOCK_ROOT, hex"");
    }

    // ── _verifyHintsAggregate — n validity check

    /// @dev Sig where n=0 (VK[0..8]=all zeros, LE) → n < 2 → HieroHintsBadN(0).
    ///      Need totalWeight=0 and aggWeight>0 so threshold passes first.
    function test_verifyTss_badN_zero() public {
        bytes memory sig = new bytes(TOTAL_SETTLED_WRAPS);
        // VK[0..8] = 0 (n=0, LE) — stays 0 (default)
        // VK[8..40] = totalWeight = 0 (default)
        // sig[OFFSET_SIG + 96 .. +128] = aggWeight; OFFSET_SIG=1096, so sig[1192] = aggWeight
        sig[1192] = 0x01; // aggWeight = 1 LE → threshold: 3*1 > 1*0 = true ✓

        vm.expectRevert(abi.encodeWithSelector(TSSVerifier.HieroHintsBadN.selector, uint64(0)));
        tssVerifier.verifyTss(new bytes(32), sig, GOOD_BLOCK_ROOT, hex"");
    }

    /// @dev Sig where n=3 (not a power of 2) → HieroHintsBadN(3).
    function test_verifyTss_badN_three() public {
        bytes memory sig = new bytes(TOTAL_SETTLED_WRAPS);
        // VK[0..8] = 3 LE
        sig[0] = 0x03; // n = 3 (LE uint64)
        // VK[8..40] = totalWeight = 0 (stays zero)
        // aggWeight at sig[1192] = 1 → threshold passes
        sig[1192] = 0x01;

        vm.expectRevert(abi.encodeWithSelector(TSSVerifier.HieroHintsBadN.selector, uint64(3)));
        tssVerifier.verifyTss(new bytes(32), sig, GOOD_BLOCK_ROOT, hex"");
    }

    /// @dev n=1 (1 < 2) → HieroHintsBadN(1).
    function test_verifyTss_badN_one() public {
        bytes memory sig = new bytes(TOTAL_SETTLED_WRAPS);
        sig[0] = 0x01; // n = 1 (LE)
        sig[1192] = 0x01; // aggWeight = 1

        vm.expectRevert(abi.encodeWithSelector(TSSVerifier.HieroHintsBadN.selector, uint64(1)));
        tssVerifier.verifyTss(new bytes(32), sig, GOOD_BLOCK_ROOT, hex"");
    }

    // ── _computeFiatShamirChallenge — G1/G2 infinity branches

    /// @dev A 3432-byte signature with n=4 (valid power-of-2) and aggWeight=1
    ///      (passes threshold) but all G1/G2 fields zero (infinity points) causes
    ///      _compressG1Ark and _compressG2Ark to take the infinity branches.
    ///      The call ultimately fails at Poseidon mismatch since hintVk contains
    ///      n=4 making poseidon(hintVk) ≠ zi_1=0.
    function test_verifyTss_n4_allZeroPoints_coversInfinityBranches() public {
        bytes memory sig = new bytes(TOTAL_SETTLED_WRAPS); // 3432 bytes, all zero
        // n = 4 at bytes[0..8] LE: valid power of 2 ≥ 2
        sig[0] = 0x04;
        // aggWeight = 1 at hintSig offset 96; hintSig starts at byte 1096
        // absolute index = 1096 + 96 = 1192
        sig[1192] = 0x01;

        // With all G1/G2 point fields zero, _compressG1Ark and _compressG2Ark
        // will hit their infinity branches (lines 573-575, 606-607).
        // All BLS pairings pass with infinity points.
        // Eventually fails at WRAPSVerifier: Poseidon mismatch.
        vm.expectRevert(); // accepts any revert (Poseidon mismatch expected)
        tssVerifier.verifyTss(new bytes(32), sig, new bytes(48), hex"");
    }

    // ── _checkThreshold overflow branch (line 280)

    /// @dev aggWeight = 0x6000..0000 (LE) > type(uint256).max / 3 → line 280.
    ///      After that, n=4 is valid, Fiat-Shamir runs → eventually reverts.
    function test_verifyTss_bigAggWeight_coversLine280() public {
        bytes memory sig = new bytes(TOTAL_SETTLED_WRAPS); // 3432 bytes
        sig[0] = 0x04; // n = 4 (LE u64: valid power-of-2)
        // aggWeight at hintSig[96..128] which is sig[1192..1224].
        // LE encoding of 0x6000...0000: byte[0]=0x00 (LSB) ... byte[31]=0x60 (MSB).
        // After _bswap256: 0x6000...0000 > 0x5555...5555 = type(uint256).max/3 → line 280.
        sig[1223] = 0x60;
        vm.expectRevert(); // HieroHintsBadN or deeper — any revert is fine
        tssVerifier.verifyTss(new bytes(32), sig, new bytes(48), hex"");
    }
}

// ── TSSVerifierHarness — exposes internal functions for line-coverage

contract TSSVerifierHarness is TSSVerifier {
    constructor(address wraps) TSSVerifier(wraps) {}

    function callIsFpAboveHalf(bytes calldata src, uint256 fpOffset) external pure returns (bool) {
        return _isFpAboveHalf(src, fpOffset);
    }

    function callCompressG2Ark(bytes calldata src, uint256 offset) external pure returns (bytes memory) {
        return _compressG2Ark(src, offset);
    }

    /// @dev Expose converter so tests can build valid EIP-2537 G2 points.
    function callArkG2ToEip2537(bytes calldata src, uint256 offset) external pure returns (bytes memory) {
        return _arkG2ToEip2537(src, offset);
    }

    function callVerifyDegreeBound(bytes calldata hintSig, bytes calldata h0, bytes calldata h1) external view {
        bytes memory h0m = h0;
        bytes memory h1m = h1;
        _verifyDegreeBound(hintSig, h0m, h1m);
    }

    function callVerifyBskIdentity(bytes calldata hintVk, bytes calldata hintSig, bytes calldata h0, bytes calldata h1)
        external
        view
    {
        bytes memory h0m = h0;
        bytes memory h1m = h1;
        _verifyBskIdentity(hintVk, hintSig, h0m, h1m);
    }

    function callVerifyShiftedKzgOpening(
        uint256 r,
        uint256 omega,
        bytes calldata hintSig,
        bytes calldata g0,
        bytes calldata h0,
        bytes calldata h1
    ) external view {
        bytes memory g0m = g0;
        bytes memory h0m = h0;
        bytes memory h1m = h1;
        _verifyShiftedKzgOpening(r, omega, hintSig, g0m, h0m, h1m);
    }

    function callVerifyHintsAggregate(bytes calldata hintVk, bytes calldata hintSig, bytes calldata blockHash)
        external
        view
        returns (bool)
    {
        return _verifyHintsAggregate(hintVk, hintSig, blockHash);
    }
}

/// @dev Separate harness for G1/G2 compression helpers.
contract TSSVerifierHarness2 is TSSVerifier {
    constructor(address wraps) TSSVerifier(wraps) {}

    function callCompressG1Ark(bytes calldata src, uint256 offset) external pure returns (bytes memory) {
        return _compressG1Ark(src, offset);
    }

    function callCompressG2ArkYImZero(bytes calldata src, uint256 offset) external pure returns (bytes memory) {
        return _compressG2Ark(src, offset);
    }
}

/// @dev Tests for TSSVerifier internal functions via TSSVerifierHarness.
contract TSSVerifierHarnessTest is Test {
    TSSVerifierHarness internal harness;
    TSSVerifierHarness2 internal harness2;

    // BLS12-381 G1 generator in ArkWorks format (96 bytes: x_BE(48) || y_BE(48))
    bytes internal constant G1_GEN_ARK = hex"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
        hex"08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    // BLS12-381 G2 generator in ArkWorks format (192 bytes: xIm(48)||xRe(48)||yIm(48)||yRe(48))
    bytes internal constant G2_GEN_ARK = hex"13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
        hex"024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
        hex"0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"
        hex"0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801";

    uint256 internal constant HINTS_VK_LEN = 1096;
    uint256 internal constant HINTS_SIG_LEN = 1632;

    function setUp() public {
        address wraps = deployCode(
            "WRAPSVerifierContract.sol:WRAPSVerifierContract",
            abi.encode(
                deployCode(
                    "PoseidonBN254Contract.sol:PoseidonBN254Contract",
                    abi.encode(
                        deployCode("PoseidonPermuteA.sol:PoseidonPermuteA"),
                        deployCode("PoseidonPermuteB.sol:PoseidonPermuteB")
                    )
                )
            )
        );
        harness = TSSVerifierHarness(deployCode("TSSVerifier.t.sol:TSSVerifierHarness", abi.encode(wraps)));
        harness2 = TSSVerifierHarness2(deployCode("TSSVerifier.t.sol:TSSVerifierHarness2", abi.encode(wraps)));
    }

    /// @dev Copy `src` bytes into `dest` starting at `offset`.
    function _copyAt(bytes memory dest, uint256 offset, bytes memory src) internal pure {
        for (uint256 i = 0; i < src.length; i++) {
            dest[offset + i] = src[i];
        }
    }

    // ── _isFpAboveHalf — hi == ClprBls12381.P_HALF_HI (line 552)

    /// @dev hi exactly equals ClprBls12381.P_HALF_HI → falls through to line 552 compare.
    ///      lo32 = 0xFF..FF > ClprBls12381.P_HALF_LO → returns true.
    function test_isFpAboveHalf_hiEquals_coversLine552() public view {
        // 48-byte Fp value: top 16 bytes = ClprBls12381.P_HALF_HI, bottom 32 = 0xFF..FF
        bytes memory src = abi.encodePacked(
            bytes16(0x0d0088f51cbff34d258dd3db21a5d66b), // hi == ClprBls12381.P_HALF_HI
            bytes32(type(uint256).max) // lo32 = 0xFFFF..FF > ClprBls12381.P_HALF_LO
        );
        bool result = harness.callIsFpAboveHalf(src, 0);
        assertTrue(result, "hi==ClprBls12381.P_HALF_HI and lo32>ClprBls12381.P_HALF_LO should be true");
    }

    // ── _compressG2Ark — ySign = true (line 621)

    /// @dev yIm = 0xFF..FF > (p-1)/2 → ySign = true → line 621 sets flag |= 0x20.
    function test_compressG2Ark_ySignTrue_coversLine621() public view {
        // 192-byte ArkWorks G2 point: xIm(48)||xRe(48)||yIm(48)||yRe(48)
        // Set yIm (offset 96..144) to 0xFF — not zero, and > half → ySign=true.
        // xIm=xRe=0, yRe=0. Not all-zero (yIm≠0) → not infinity branch.
        bytes memory src = new bytes(192);
        for (uint256 i = 96; i < 144; i++) {
            src[i] = 0xFF;
        }
        bytes memory out = harness.callCompressG2Ark(src, 0);
        assertEq(out.length, 96);
        // Expected: compressed bit (0x80) | y-sign bit (0x20) = 0xa0 in first byte
        assertEq(uint8(out[0]) & 0xa0, 0xa0, "compressed + y-sign flags must be set");
    }

    // ── _verifyDegreeBound — pairing failure

    /// @dev QX = QX_MUL_TAU = G1_gen; h0 = G2_inf; h1 = G2_gen.
    ///      e(G,H) * e(-G, G2_inf) = e(G,H) * 1 ≠ 1 → HieroHintsDegreeBoundFailed.
    function test_verifyDegreeBound_pairingFails() public {
        bytes memory hintSig = new bytes(HINTS_SIG_LEN);
        _copyAt(hintSig, 416, G1_GEN_ARK); // QX at SIG_OFFSET_QX=416
        _copyAt(hintSig, 512, G1_GEN_ARK); // QX_MUL_TAU at SIG_OFFSET_QX_MUL_TAU=512

        bytes memory h0 = new bytes(256); // G2 infinity (EIP-2537 all-zeros)
        bytes memory h1 = harness.callArkG2ToEip2537(G2_GEN_ARK, 0); // G2 generator (EIP-2537)

        vm.expectRevert(TSSVerifier.HieroHintsDegreeBoundFailed.selector);
        harness.callVerifyDegreeBound(hintSig, h0, h1);
    }

    // ── _verifyBskIdentity — pairing failure

    /// @dev B = G1_gen, SK = G2_gen; QZ=QX=AGG_PK = G1_gen, Z=h0=h1 = G2_inf.
    ///      e(G, G2gen) * 3×e(-G, G2_inf) = e(G, G2gen) ≠ 1 → HieroHintsBSkIdentityFailed.
    function test_verifyBskIdentity_pairingFails() public {
        bytes memory hintVk = new bytes(HINTS_VK_LEN);
        bytes memory hintSig = new bytes(HINTS_SIG_LEN);

        _copyAt(hintSig, 0, G1_GEN_ARK); // AGG_PK at SIG_OFFSET_AGG_PK=0
        _copyAt(hintSig, 320, G1_GEN_ARK); // B       at SIG_OFFSET_B=320
        _copyAt(hintSig, 416, G1_GEN_ARK); // QX      at SIG_OFFSET_QX=416
        _copyAt(hintSig, 608, G1_GEN_ARK); // QZ      at SIG_OFFSET_QZ=608

        _copyAt(hintVk, 712, G2_GEN_ARK); // SK at VK_OFFSET_SK=712 (G2_gen in ArkWorks)
        // Z at VK_OFFSET_Z=904 stays zeros → G2_inf in ArkWorks

        bytes memory h0 = new bytes(256); // G2_inf
        bytes memory h1 = new bytes(256); // G2_inf

        vm.expectRevert(TSSVerifier.HieroHintsBSkIdentityFailed.selector);
        harness.callVerifyBskIdentity(hintVk, hintSig, h0, h1);
    }

    // ── _verifyShiftedKzgOpening — pairing failure

    /// @dev OPENING_R_DIV_OMEGA = G1_gen; PARSUM = G1_inf; r=0, omega=0.
    ///      parsumArg = G1_inf; parsumRhsG2 = G2_gen.
    ///      e(G1_inf, G2_gen) * e(-G1_gen, G2_gen) = e(G,H)^{-1} ≠ 1
    ///      → HieroHintsKzgShiftedFailed.
    function test_verifyShiftedKzgOpening_pairingFails() public {
        bytes memory hintSig = new bytes(HINTS_SIG_LEN);
        // OPENING_R_DIV_OMEGA at SIG_OFFSET_OPENING_R_DIV_OMEGA=1280
        _copyAt(hintSig, 1280, G1_GEN_ARK);
        // PARSUM at 704 stays zeros → G1_inf

        bytes memory g0 = new bytes(128); // G1_inf (EIP-2537 all-zeros)
        bytes memory h1 = harness.callArkG2ToEip2537(G2_GEN_ARK, 0); // G2_gen EIP-2537
        bytes memory h0 = h1; // both G2_gen

        // r=0, omega=0 → _frInv(0)=0 → rDivOmega=0 → parsumRhsG2 = 0*h0 + 1*h1 = G2_gen
        vm.expectRevert(TSSVerifier.HieroHintsKzgShiftedFailed.selector);
        harness.callVerifyShiftedKzgOpening(0, 0, hintSig, g0, h0, h1);
    }

    /// @dev Both x and y are zero → infinity → output byte[0] = 0xc0.
    function test_compressG1Ark_infinity() public view {
        bytes memory src = new bytes(96); // all zeros = infinity G1 in ArkWorks uncompressed
        bytes memory out = harness2.callCompressG1Ark(src, 0);
        assertEq(out.length, 48);
        assertEq(uint8(out[0]), 0xc0, "infinity flag must be 0xc0");
    }

    /// @dev Non-infinity G1, y all zeros → y=0 <= (p-1)/2 → ySign=false → only 0x80.
    function test_compressG1Ark_nonInfinity_ySignFalse() public view {
        bytes memory src = new bytes(96);
        src[0] = 0x01; // x non-zero
        bytes memory out = harness2.callCompressG1Ark(src, 0);
        assertEq(out.length, 48);
        assertEq(uint8(out[0]) & 0xa0, 0x80, "only compressed flag must be set");
    }

    /// @dev Non-infinity G1, y[48]=0xFF (> (p-1)/2) → ySign=true → both 0x80 and 0x20.
    function test_compressG1Ark_nonInfinity_ySignTrue() public view {
        bytes memory src = new bytes(96);
        src[0] = 0x01; // x non-zero
        src[48] = 0xFF; // y above half
        bytes memory out = harness2.callCompressG1Ark(src, 0);
        assertEq(out.length, 48);
        assertEq(uint8(out[0]) & 0xa0, 0xa0, "compressed + ySign flags must be set");
    }

    /// @dev yIm=0, yRe[0]=0xFF → yImZero=true → inspect yRe → ySign=true.
    function test_compressG2Ark_yImZero_yReAboveHalf() public view {
        bytes memory src = new bytes(192);
        src[0] = 0x01; // xIm non-zero → not infinity
        src[144] = 0xFF; // yRe above half
        bytes memory out = harness2.callCompressG2ArkYImZero(src, 0);
        assertEq(out.length, 96);
        assertEq(uint8(out[0]) & 0xa0, 0xa0, "compressed + ySign flags must be set via yRe");
    }

    // ── _verifyHintsAggregate shape guards (BRDA:197, BRDA:198)

    /// @dev BRDA:197 — hintVk shorter than HINTS_VK_LEN (1096) → HieroHintsBadVkLen.
    function test_verifyHintsAggregate_badVkLen_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(TSSVerifier.HieroHintsBadVkLen.selector, uint256(1095)));
        harness.callVerifyHintsAggregate(new bytes(1095), new bytes(HINTS_SIG_LEN), new bytes(48));
    }

    /// @dev BRDA:198 — hintVk correct length but hintSig shorter than HINTS_SIG_LEN (1632) → HieroHintsBadSigLen.
    function test_verifyHintsAggregate_badSigLen_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(TSSVerifier.HieroHintsBadSigLen.selector, uint256(1631)));
        harness.callVerifyHintsAggregate(new bytes(HINTS_VK_LEN), new bytes(1631), new bytes(48));
    }
}
