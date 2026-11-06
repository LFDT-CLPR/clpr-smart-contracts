// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.10;

import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";

interface IWRAPSVerifier {
    function verify(bytes calldata abProof, bytes calldata hintsVk, bytes calldata ledgerId, bool skipPoseidon)
        external
        view
        returns (bool);
}

/// @title TSSVerifier
/// @notice Verifies Hiero hinTS aggregate BLS12-381 signatures over a SHA-384 block root.
/// @dev Implements the full hinTS verification protocol (steps 0-9) using EIP-2537
///      precompiles for BLS12-381 arithmetic. Called externally by HieroVerifier.
contract TSSVerifier {
    // Hiero TSS cryptographic parameters

    /// @dev Hash-to-curve domain-separation tag for the Hiero TSS BLS scheme.
    bytes internal constant HIERO_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    uint256 constant HINTS_VK_LEN = 1096;
    uint256 constant HINTS_SIG_LEN = 1632;
    uint256 constant TOTAL_GENESIS_SCHNORR = 2920; // 1096 + 1632 + 192
    uint256 constant TOTAL_SETTLED_WRAPS = 3432; // 1096 + 1632 + 704

    uint256 constant OFFSET_ABPROOF = HINTS_VK_LEN + HINTS_SIG_LEN; // 2728

    /// @dev HIP-1056 block root is SHA-384 ⇒ 48 bytes.
    uint256 internal constant BLOCK_ROOT_LEN = 48;

    // ArkWorks wire-format sizes for BLS12-381 elements.
    // (Hiero uses ArkWorks-uncompressed for VK/sig and ArkWorks-compressed
    // for the Fiat-Shamir transcript — NEITHER is EIP-2537 wire format.)

    uint256 internal constant ARK_FR_LEN = 32; // Fr little-endian
    uint256 internal constant ARK_G1_COMP_LEN = 48; // ZCash-style flagged x_BE
    uint256 internal constant ARK_G2_COMP_LEN = 96; // ZCash-style flagged (xIm_BE || xRe_BE)

    // hinTS VK byte offsets

    uint256 internal constant VK_OFFSET_N = 0; //   8 B   u64 LE
    uint256 internal constant VK_OFFSET_TOTAL_WEIGHT = 8; //  32 B   Fr LE
    uint256 internal constant VK_OFFSET_G0 = 40; //  96 B   G1 — SRS base [1]₁
    uint256 internal constant VK_OFFSET_H0 = 136; // 192 B   G2 — SRS [1]₂
    uint256 internal constant VK_OFFSET_H1 = 328; // 192 B   G2 — SRS [τ]₂
    uint256 internal constant VK_OFFSET_LN_MINUS_1 = 520; //  96 B   G1 — [L_{n-1}(τ)]₁
    uint256 internal constant VK_OFFSET_W = 616; //  96 B   G1 — [W(τ)]₁
    uint256 internal constant VK_OFFSET_SK = 712; // 192 B   G2 — [SK(τ)]₂
    uint256 internal constant VK_OFFSET_Z = 904; // 192 B   G2 — [Z(τ)]₂

    // hinTS signature byte offsets

    uint256 internal constant SIG_OFFSET_AGG_PK = 0; //  96 B   G1
    uint256 internal constant SIG_OFFSET_AGG_WEIGHT = 96; //  32 B   Fr LE
    uint256 internal constant SIG_OFFSET_AGG_SIG = 128; // 192 B   G2
    uint256 internal constant SIG_OFFSET_B = 320; //  96 B   G1
    uint256 internal constant SIG_OFFSET_QX = 416; //  96 B   G1
    uint256 internal constant SIG_OFFSET_QX_MUL_TAU = 512; //  96 B   G1
    uint256 internal constant SIG_OFFSET_QZ = 608; //  96 B   G1
    uint256 internal constant SIG_OFFSET_PARSUM = 704; //  96 B   G1
    uint256 internal constant SIG_OFFSET_Q1 = 800; //  96 B   G1
    uint256 internal constant SIG_OFFSET_Q3 = 896; //  96 B   G1  (note: q3 BEFORE q2 in layout)
    uint256 internal constant SIG_OFFSET_Q2 = 992; //  96 B   G1
    uint256 internal constant SIG_OFFSET_Q4 = 1088; //  96 B   G1
    uint256 internal constant SIG_OFFSET_OPENING_R = 1184; //  96 B   G1
    uint256 internal constant SIG_OFFSET_OPENING_R_DIV_OMEGA = 1280; //  96 B   G1
    uint256 internal constant SIG_OFFSET_PARSUM_OF_R = 1376; //  32 B   Fr
    uint256 internal constant SIG_OFFSET_PARSUM_OF_R_DIV_OMG = 1408; //  32 B   Fr
    uint256 internal constant SIG_OFFSET_W_OF_R = 1440; //  32 B   Fr
    uint256 internal constant SIG_OFFSET_B_OF_R = 1472; //  32 B   Fr
    uint256 internal constant SIG_OFFSET_Q1_OF_R = 1504; //  32 B   Fr
    uint256 internal constant SIG_OFFSET_Q3_OF_R = 1536; //  32 B   Fr
    uint256 internal constant SIG_OFFSET_Q2_OF_R = 1568; //  32 B   Fr
    uint256 internal constant SIG_OFFSET_Q4_OF_R = 1600; //  32 B   Fr

    // BLS12-381 Fr modulus (scalar field order).

    uint256 internal constant BLS_FR_ORDER = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    // hinTS verification protocol constants.

    /// @dev Threshold for "T" in TSS: agg_weight > total_weight × NUM / DEN.
    uint256 internal constant THRESHOLD_NUM = 1;
    uint256 internal constant THRESHOLD_DEN = 3;

    /// @dev Domain-separation tag for the hinTS Fiat-Shamir challenge.
    bytes internal constant FIAT_SHAMIR_DST = "HINTS_SIG_BLS12381:FIAT_SHAMIR";

    /// @dev ArkWorks expand_message_xmd output length used for hash-to-Fr.
    ///      Deviates from RFC 9380 by using Z_pad = L = 48 instead of s_in_bytes = 64.
    uint256 internal constant ARK_HASH_TO_FR_LEN = 48;

    /// @dev Two-adic root of unity in BLS12-381 Fr; ω of order 2^32.
    ///      The n-th root used in hinTS is ω^{2^{32−k}} where n = 2^k.
    uint256 internal constant BLS_FR_TWO_ADIC_ROOT = 0x16a2a19edfe81f20d09b681922c813b4b63683508c2280b93829971f439f0d2b;

    /// @dev BLS12-381 Fr 2-adicity. The largest power-of-2 subgroup has order 2^32.
    uint256 internal constant BLS_FR_TWO_ADICITY = 32;

    error ClprHieroSignatureLength(uint256 length);

    /// @notice Deployed WRAPSVerifierContract whose code contains PoseidonBN254 + BN254Util.
    ///         Called externally so those libraries are not inlined into this contract's initcode.
    IWRAPSVerifier public immutable WRAPS_VERIFIER;

    constructor(address wrapsVerifier_) {
        WRAPS_VERIFIER = IWRAPSVerifier(wrapsVerifier_);
    }

    error HieroHintsBadVkLen(uint256 got);
    error HieroHintsBadSigLen(uint256 got);
    error HieroHintsBadBlockRootLen(uint256 got);
    /// @dev `n` (address-book size, read from hintVk[0..8]) must be a power of
    ///      two in [2, 2^32]. Anything else either breaks the polynomial
    ///      domain assumption or exceeds Fr 2-adicity.
    error HieroHintsBadN(uint64 got);
    error HieroHintsBitmapNotBinary();
    error HieroHintsParsumBadRecurrence();
    error HieroHintsBelowThreshold();
    error HieroHintsKzgMergedFailed();
    error HieroHintsKzgShiftedFailed();
    error HieroHintsBSkIdentityFailed();
    error HieroHintsDegreeBoundFailed();
    error HieroHintsFinalPairingFailed();
    /// @notice The TSS signature is a non-WRAPS (Schnorr genesis) variant.
    /// @dev    Only WRAPS-settled signatures are accepted. The Schnorr genesis abProof
    ///         is unsupported by design — not a pending feature.
    error ClprHieroWrapsProofRequired();

    // tssSignature is of type = hintVk(1096) || hintSig(1632) || abProof(704)
    // abProof (address book proof) can change based on the genesis block and the number of WRAPS, but for now we can hardcode it to 704 bytes, which corresponds to 2 G2 elements (512 bytes) + 192 bytes of SHA-384 proof data.
    // The exact structure of the abProof will depend on the specific proof format used by Hiero.
    // abProof : 704 = 2 * 256 (G2 element) + 192 (SHA-384 proof bytes) - (genesis / WRAPS)
    // abPoof : 192 bytes of SHA-384 proof data, which includes the Merkle path and any additional proof information required to verify the block root hash against the trust anchor. (rotation / aggregate Schnorr)

    /// @notice Verify a Hiero TSS block signature.
    /// @dev    Two-stage verification:
    ///         (1) the 1096-byte hintVk + 1632-byte hintSig prefix is verified
    ///             end-to-end via `_verifyHintsAggregate`;
    ///         (2) the trailing 704-byte WRAPS abProof is verified via `WRAPS_VERIFIER`.
    ///         Only WRAPS-settled signatures are accepted: a non-WRAPS (192-byte
    ///         Schnorr genesis) abProof is rejected with `ClprHieroWrapsProofRequired`.
    ///
    ///         Trust model: pinned VK. The caller is expected to verify
    ///         `keccak256(hintVK)` against an immutable pinned hash before
    ///         invoking this function. `ledgerId` is enforced by WRAPS; `validHintVk`
    ///         is a cache hint equal to keccak256(hintsVK) that enables skipping
    ///         Poseidon hashing when matched.
    function verifyTss(
        bytes calldata ledgerId,
        bytes calldata tssSignature,
        bytes calldata message,
        bytes calldata validHintVk
    ) external view returns (bool, bytes memory) {
        (bytes calldata hintVk, bytes calldata hintSig, bytes calldata abProof, bool isWrapsSettled) =
            splitTssBlockSignature(tssSignature);

        if (!_verifyHintsAggregate(hintVk, hintSig, message)) return (false, validHintVk);

        if (isWrapsSettled) {
            bytes32 hintVkHash = keccak256(hintVk);
            // casting to 'bytes32' is safe because validHintVK correct length is ensured before storing it
            // forge-lint: disable-next-line(unsafe-typecast)
            bool skipPoseidon = validHintVk.length == 32 && bytes32(validHintVk) == hintVkHash;
            bool wrapsValid = WRAPS_VERIFIER.verify(abProof, hintVk, ledgerId, skipPoseidon);
            return (wrapsValid, abi.encodePacked(hintVkHash));
        }
        // Non-WRAPS (Schnorr genesis, 192-byte abProof) signature: unsupported by design.
        revert ClprHieroWrapsProofRequired();
    }

    /// @notice Verify a Hiero hinTS aggregate signature `hintSig` produced under
    ///         the aggregate verification key `hintVk` over the SHA-384 block
    ///         root `blockHash`.
    function _verifyHintsAggregate(bytes calldata hintVk, bytes calldata hintSig, bytes calldata blockHash)
        internal
        view
        returns (bool)
    {
        // Step 0a — shape pre-flight.
        if (hintVk.length != HINTS_VK_LEN) revert HieroHintsBadVkLen(hintVk.length);
        if (hintSig.length != HINTS_SIG_LEN) revert HieroHintsBadSigLen(hintSig.length);
        if (blockHash.length != BLOCK_ROOT_LEN) revert HieroHintsBadBlockRootLen(blockHash.length);

        // Step 0b — threshold (extracted to keep this function's stack shallow).
        _checkThreshold(hintVk, hintSig);

        // Read & validate `n` (address-book size, power of two ≤ 2^32).
        uint64 n = _readU64Le(hintVk, VK_OFFSET_N);
        if (n < 2 || (n & (n - 1)) != 0 || uint256(n) > (uint256(1) << BLS_FR_TWO_ADICITY)) revert HieroHintsBadN(n);

        // Step 3 — Fiat-Shamir challenge r
        uint256 r = _computeFiatShamirChallenge(hintVk, hintSig);
        uint256 omega = _nthRootOfUnity(uint256(n));

        // Cache shared EIP-2537-encoded SRS handles (used across several steps).
        bytes memory g0 = _arkG1ToEip2537(hintVk, VK_OFFSET_G0);
        bytes memory h0 = _arkG2ToEip2537(hintVk, VK_OFFSET_H0);
        bytes memory h1 = _arkG2ToEip2537(hintVk, VK_OFFSET_H1);

        _verifyBls12381SignaturePairing(blockHash, hintSig, g0);
        _verifyMergedKzgOpening(r, hintVk, hintSig, g0, h0, h1);
        _verifyShiftedKzgOpening(r, omega, hintSig, g0, h0, h1);
        _verifyBskIdentity(hintVk, hintSig, h0, h1);
        _verifyFieldIdentities(r, omega, n, hintSig);
        _verifyDegreeBound(hintSig, h0, h1);

        return true;
    }

    // Per-step helpers. Each one reverts on failure; otherwise returns silently.

    /// @dev Step 0b — Threshold: `DEN · aggWeight > NUM · totalWeight`
    ///      DEN × aggWeight can exceed uint256.max
    ///      since aggWeight ≤ r-1 ≈ 2^254, so short-circuit when the multiply
    ///      would overflow.
    function _checkThreshold(bytes calldata hintVk, bytes calldata hintSig) internal pure {
        uint256 totalWeight = _readFrLe(hintVk, VK_OFFSET_TOTAL_WEIGHT);
        uint256 aggWeight = _readFrLe(hintSig, SIG_OFFSET_AGG_WEIGHT);

        bool thresholdMet;
        if (aggWeight > type(uint256).max / THRESHOLD_DEN) {
            thresholdMet = true;
        } else {
            unchecked {
                thresholdMet = THRESHOLD_DEN * aggWeight > THRESHOLD_NUM * totalWeight;
            }
        }
        if (!thresholdMet) revert HieroHintsBelowThreshold();
    }

    /// @dev Step 4 — BLS sig pairing  e(aggPk, H_G2(m)) · e(-g0, aggSig) == 1
    function _verifyBls12381SignaturePairing(bytes calldata blockHash, bytes calldata hintSig, bytes memory g0)
        internal
        view
    {
        bytes memory hG2 = ClprBls12381.hashToG2(blockHash, HIERO_DST);
        bytes memory aggPk = _arkG1ToEip2537(hintSig, SIG_OFFSET_AGG_PK);
        bytes memory aggSig = _arkG2ToEip2537(hintSig, SIG_OFFSET_AGG_SIG);

        if (!ClprBls12381.pairing(bytes.concat(aggPk, hG2, _negG1Eip(g0), aggSig))) {
            revert HieroHintsFinalPairingFailed();
        }
    }

    /// @dev Merged batched KZG opening at r (hinTS step 5).
    ///      Packs the 7 [com − g0·eval] r-weighted args + the W' adjustment
    ///      into a single 9-term G1MSM, then pairs against (h1 − r·h0).
    function _verifyMergedKzgOpening(
        uint256 r,
        bytes calldata hintVk,
        bytes calldata hintSig,
        bytes memory g0,
        bytes memory h0,
        bytes memory h1
    ) internal view {
        // Powers of r live in a memory array so they cost one stack slot (the
        // array pointer), not five.
        uint256[5] memory rPow;
        rPow[0] = mulmod(r, r, BLS_FR_ORDER); // r²
        rPow[1] = mulmod(rPow[0], r, BLS_FR_ORDER); // r³
        rPow[2] = mulmod(rPow[1], r, BLS_FR_ORDER); // r⁴
        rPow[3] = mulmod(rPow[2], r, BLS_FR_ORDER); // r⁵
        rPow[4] = mulmod(rPow[3], r, BLS_FR_ORDER); // r⁶

        uint256 lnMinus1Scalar = mulmod(r, _frNeg(_readFrLe(hintSig, SIG_OFFSET_AGG_WEIGHT)), BLS_FR_ORDER);
        uint256 negCombinedEval = _frNeg(_combinedEvalAtR(r, rPow, hintSig));

        bytes memory mergedG1 = _buildMergedG1(r, rPow, lnMinus1Scalar, negCombinedEval, hintVk, hintSig, g0);

        bytes memory kzgRhsG2 = ClprBls12381.g2Msm(abi.encodePacked(h0, bytes32(_frNeg(r)), h1, bytes32(uint256(1))));

        if (!ClprBls12381.pairing(
                bytes.concat(mergedG1, h0, _negG1Eip(_arkG1ToEip2537(hintSig, SIG_OFFSET_OPENING_R)), kzgRhsG2)
            )) {
            revert HieroHintsKzgMergedFailed();
        }
    }

    /// @dev Σ_i r^i · eval_i over (parsum, w, b, q1, q3, q2, q4) at r.
    ///      Pulled out so its locals don't share a stack with _verifyMergedKzgOpening.
    function _combinedEvalAtR(uint256 r, uint256[5] memory rPow, bytes calldata hintSig)
        internal
        pure
        returns (uint256 ce)
    {
        ce = _readFrLe(hintSig, SIG_OFFSET_PARSUM_OF_R);
        ce = addmod(ce, mulmod(r, _readFrLe(hintSig, SIG_OFFSET_W_OF_R), BLS_FR_ORDER), BLS_FR_ORDER);
        ce = addmod(ce, mulmod(rPow[0], _readFrLe(hintSig, SIG_OFFSET_B_OF_R), BLS_FR_ORDER), BLS_FR_ORDER);
        ce = addmod(ce, mulmod(rPow[1], _readFrLe(hintSig, SIG_OFFSET_Q1_OF_R), BLS_FR_ORDER), BLS_FR_ORDER);
        ce = addmod(ce, mulmod(rPow[2], _readFrLe(hintSig, SIG_OFFSET_Q3_OF_R), BLS_FR_ORDER), BLS_FR_ORDER);
        ce = addmod(ce, mulmod(rPow[3], _readFrLe(hintSig, SIG_OFFSET_Q2_OF_R), BLS_FR_ORDER), BLS_FR_ORDER);
        ce = addmod(ce, mulmod(rPow[4], _readFrLe(hintSig, SIG_OFFSET_Q4_OF_R), BLS_FR_ORDER), BLS_FR_ORDER);
    }

    /// @dev The 9-term G1MSM that produces `mergedG1`.
    ///      Pre-allocates a single 1440-byte (9 × 160) buffer and fills each
    ///      (G1_128 || scalar_32) term directly via assembly, avoiding the
    ///      O(N²) memory copies that result from N sequential bytes.concat calls.
    function _buildMergedG1(
        uint256 r,
        uint256[5] memory rPow,
        uint256 lnMinus1Scalar,
        uint256 negCombinedEval,
        bytes calldata hintVk,
        bytes calldata hintSig,
        bytes memory g0
    ) internal view returns (bytes memory) {
        bytes memory input = new bytes(9 * 160);
        _writeMsmTerm(input, 0, _arkG1ToEip2537(hintSig, SIG_OFFSET_PARSUM), 1);
        _writeMsmTerm(input, 160, _arkG1ToEip2537(hintVk, VK_OFFSET_W), r);
        _writeMsmTerm(input, 320, _arkG1ToEip2537(hintVk, VK_OFFSET_LN_MINUS_1), lnMinus1Scalar);
        _writeMsmTerm(input, 480, _arkG1ToEip2537(hintSig, SIG_OFFSET_B), rPow[0]);
        _writeMsmTerm(input, 640, _arkG1ToEip2537(hintSig, SIG_OFFSET_Q1), rPow[1]);
        _writeMsmTerm(input, 800, _arkG1ToEip2537(hintSig, SIG_OFFSET_Q3), rPow[2]);
        _writeMsmTerm(input, 960, _arkG1ToEip2537(hintSig, SIG_OFFSET_Q2), rPow[3]);
        _writeMsmTerm(input, 1120, _arkG1ToEip2537(hintSig, SIG_OFFSET_Q4), rPow[4]);
        _writeMsmTerm(input, 1280, g0, negCombinedEval);
        return ClprBls12381.g1Msm(input);
    }

    /// @dev Write one EIP-2537 G1MSM term `(point_128 || scalar_32)` into `buf` at `offset`.
    ///      Direct assembly write avoids a temporary bytes.concat allocation.
    function _writeMsmTerm(bytes memory buf, uint256 offset, bytes memory point, uint256 scalar) internal pure {
        assembly ("memory-safe") {
            let dst := add(add(buf, 0x20), offset)
            mcopy(dst, add(point, 0x20), 128) // 128-byte G1 point
            mstore(add(dst, 128), scalar) // 32-byte scalar
        }
    }

    /// @dev Shifted KZG opening at r/ω (hinTS step 6).
    ///      Verifies the parsum commitment opens to parsumROmega at the shifted point.
    function _verifyShiftedKzgOpening(
        uint256 r,
        uint256 omega,
        bytes calldata hintSig,
        bytes memory g0,
        bytes memory h0,
        bytes memory h1
    ) internal view {
        uint256 rDivOmega = mulmod(r, _frInv(omega), BLS_FR_ORDER);
        uint256 parsumROmega = _readFrLe(hintSig, SIG_OFFSET_PARSUM_OF_R_DIV_OMG);

        bytes memory parsumArg = ClprBls12381.g1Msm(
            abi.encodePacked(
                _arkG1ToEip2537(hintSig, SIG_OFFSET_PARSUM), bytes32(uint256(1)), g0, bytes32(_frNeg(parsumROmega))
            )
        );

        bytes memory parsumRhsG2 =
            ClprBls12381.g2Msm(abi.encodePacked(h0, bytes32(_frNeg(rDivOmega)), h1, bytes32(uint256(1))));

        if (!ClprBls12381.pairing(
                bytes.concat(
                    parsumArg, h0, _negG1Eip(_arkG1ToEip2537(hintSig, SIG_OFFSET_OPENING_R_DIV_OMEGA)), parsumRhsG2
                )
            )) {
            revert HieroHintsKzgShiftedFailed();
        }
    }

    /// @dev B·SK identity check (hinTS step 7). 4-pair batched pairing.
    ///      Verifies that B·SK = QZ·Z + QX·h1 + aggPK·h0 holds on the curve.
    function _verifyBskIdentity(bytes calldata hintVk, bytes calldata hintSig, bytes memory h0, bytes memory h1)
        internal
        view
    {
        if (!ClprBls12381.pairing(
                bytes.concat(
                    _arkG1ToEip2537(hintSig, SIG_OFFSET_B),
                    _arkG2ToEip2537(hintVk, VK_OFFSET_SK),
                    _negG1Eip(_arkG1ToEip2537(hintSig, SIG_OFFSET_QZ)),
                    _arkG2ToEip2537(hintVk, VK_OFFSET_Z),
                    _negG1Eip(_arkG1ToEip2537(hintSig, SIG_OFFSET_QX)),
                    h1,
                    _negG1Eip(_arkG1ToEip2537(hintSig, SIG_OFFSET_AGG_PK)),
                    h0
                )
            )) {
            revert HieroHintsBSkIdentityFailed();
        }
    }

    /// @dev Four field-level polynomial identities (hinTS step 8).
    ///      Each identity is its own function so it compiles with a fresh shallow stack:
    ///      parsum recurrence, parsum endpoint, bitmap binary, bitmap endpoint.
    function _verifyFieldIdentities(uint256 r, uint256 omega, uint64 n, bytes calldata hintSig) internal view {
        uint256 vanishingOfR = addmod(_frPow(r, uint256(n)), BLS_FR_ORDER - 1, BLS_FR_ORDER);
        uint256 omegaPowNm1 = _frPow(omega, uint256(n) - 1);
        // L_{n-1}(r) = (ω^{n-1}·n⁻¹) · (Z_H(r) · (r − ω^{n-1})⁻¹)
        uint256 lnMinus1OfR = mulmod(
            mulmod(omegaPowNm1, _frInv(uint256(n)), BLS_FR_ORDER),
            mulmod(vanishingOfR, _frInv(addmod(r, _frNeg(omegaPowNm1), BLS_FR_ORDER)), BLS_FR_ORDER),
            BLS_FR_ORDER
        );

        _checkParsumRecurrence(hintSig, vanishingOfR);
        _checkParsumEndpoint(hintSig, vanishingOfR, lnMinus1OfR);
        _checkBitmapBinary(hintSig, vanishingOfR);
        _checkBitmapEndpoint(hintSig, vanishingOfR, lnMinus1OfR);
    }

    /// @dev Parsum recurrence identity (hinTS step 8a):
    ///      parsum(r) − parsum(r/ω) − w(r)·b(r)  ==  q1(r) · Z_H(r).
    function _checkParsumRecurrence(bytes calldata hintSig, uint256 vanishingOfR) internal pure {
        // parsumR − parsumRO − wR·bR  ==  q1R · vanishingOfR
        uint256 lhs = addmod(
            addmod(
                _readFrLe(hintSig, SIG_OFFSET_PARSUM_OF_R),
                _frNeg(_readFrLe(hintSig, SIG_OFFSET_PARSUM_OF_R_DIV_OMG)),
                BLS_FR_ORDER
            ),
            _frNeg(mulmod(_readFrLe(hintSig, SIG_OFFSET_W_OF_R), _readFrLe(hintSig, SIG_OFFSET_B_OF_R), BLS_FR_ORDER)),
            BLS_FR_ORDER
        );
        uint256 rhs = mulmod(_readFrLe(hintSig, SIG_OFFSET_Q1_OF_R), vanishingOfR, BLS_FR_ORDER);
        if (lhs != rhs) revert HieroHintsParsumBadRecurrence();
    }

    /// @dev Parsum endpoint identity (hinTS step 8b):
    ///      L_{n-1}(r) · parsum(r)  ==  Z_H(r) · q3(r).
    function _checkParsumEndpoint(bytes calldata hintSig, uint256 vanishingOfR, uint256 lnMinus1OfR) internal pure {
        // L_{n-1}(r) · parsumR  ==  vanishingOfR · q3R
        uint256 lhs = mulmod(lnMinus1OfR, _readFrLe(hintSig, SIG_OFFSET_PARSUM_OF_R), BLS_FR_ORDER);
        uint256 rhs = mulmod(vanishingOfR, _readFrLe(hintSig, SIG_OFFSET_Q3_OF_R), BLS_FR_ORDER);
        if (lhs != rhs) revert HieroHintsParsumBadRecurrence();
    }

    /// @dev Bitmap binary identity (hinTS step 8c):
    ///      b(r)² − b(r)  ==  q2(r) · Z_H(r).  Proves b is 0/1 at every point.
    function _checkBitmapBinary(bytes calldata hintSig, uint256 vanishingOfR) internal pure {
        // bR² − bR  ==  q2R · vanishingOfR
        uint256 bR = _readFrLe(hintSig, SIG_OFFSET_B_OF_R);
        uint256 lhs = addmod(mulmod(bR, bR, BLS_FR_ORDER), _frNeg(bR), BLS_FR_ORDER);
        uint256 rhs = mulmod(_readFrLe(hintSig, SIG_OFFSET_Q2_OF_R), vanishingOfR, BLS_FR_ORDER);
        if (lhs != rhs) revert HieroHintsBitmapNotBinary();
    }

    /// @dev Bitmap endpoint identity (hinTS step 8d):
    ///      L_{n-1}(r) · (b(r) − 1)  ==  Z_H(r) · q4(r).  Proves b[n-1] = 1.
    function _checkBitmapEndpoint(bytes calldata hintSig, uint256 vanishingOfR, uint256 lnMinus1OfR) internal pure {
        // L_{n-1}(r) · (bR − 1)  ==  vanishingOfR · q4R
        uint256 lhs = mulmod(
            lnMinus1OfR, addmod(_readFrLe(hintSig, SIG_OFFSET_B_OF_R), BLS_FR_ORDER - 1, BLS_FR_ORDER), BLS_FR_ORDER
        );
        uint256 rhs = mulmod(vanishingOfR, _readFrLe(hintSig, SIG_OFFSET_Q4_OF_R), BLS_FR_ORDER);
        if (lhs != rhs) revert HieroHintsBitmapNotBinary();
    }

    /// @dev Degree bound check (hinTS step 9).
    ///      Verifies e([Qx]₁, [τ]₂) · e(−[Qx·τ]₁, [1]₂) == 1.
    function _verifyDegreeBound(bytes calldata hintSig, bytes memory h0, bytes memory h1) internal view {
        if (!ClprBls12381.pairing(
                bytes.concat(
                    _arkG1ToEip2537(hintSig, SIG_OFFSET_QX),
                    h1,
                    _negG1Eip(_arkG1ToEip2537(hintSig, SIG_OFFSET_QX_MUL_TAU)),
                    h0
                )
            )) {
            revert HieroHintsDegreeBoundFailed();
        }
    }

    /// @dev Read a 32-byte little-endian Fr element from `src` at `offset`,
    ///      reduce mod BLS_FR_ORDER
    function _readFrLe(bytes calldata src, uint256 offset) internal pure returns (uint256) {
        bytes32 raw;
        assembly ("memory-safe") {
            raw := calldataload(add(src.offset, offset))
        }
        // Reverse byte order (LE → BE) so it can be interpreted as uint256.
        uint256 v = _reverseBytes32(uint256(raw));
        return v % BLS_FR_ORDER;
    }

    /// @dev Byte-reverse a uint256 (treats it as 32-byte big-endian or vice
    ///      versa). Standard bit-twiddling — same trick as in Solady etc.
    function _reverseBytes32(uint256 v) internal pure returns (uint256) {
        v = (v & 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00) >> 8
            | (v & 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff) << 8;
        v = (v & 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000) >> 16
            | (v & 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff) << 16;
        v = (v & 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000) >> 32
            | (v & 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff) << 32;
        v = (v & 0xffffffffffffffff0000000000000000ffffffffffffffff0000000000000000) >> 64
            | (v & 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff) << 64;
        v = v >> 128 | v << 128;
        return v;
    }

    /// @dev True iff the 48-byte big-endian Fp value at `src[fpOffset:fpOffset+48]`
    ///      is strictly greater than (p−1)/2. Used for compressed-point y-sign.
    function _isFpAboveHalf(bytes calldata src, uint256 fpOffset) internal pure returns (bool) {
        uint256 hi32; // top 32 bytes of the loaded word
        uint256 lo32; // next 32 bytes
        assembly ("memory-safe") {
            hi32 := calldataload(add(src.offset, fpOffset))
            lo32 := calldataload(add(src.offset, add(fpOffset, 16)))
        }
        uint256 hi = hi32 >> 128; // upper 16 bytes of the 48-byte BE value
        if (hi > ClprBls12381.P_HALF_HI) return true;
        if (hi < ClprBls12381.P_HALF_HI) return false;
        return lo32 > ClprBls12381.P_HALF_LO;
    }

    /// @dev True iff the 48-byte Fp value at `src[fpOffset:fpOffset+48]` is zero.
    function _isFpZero(bytes calldata src, uint256 fpOffset) internal pure returns (bool) {
        uint256 hi32;
        uint256 lo32;
        assembly ("memory-safe") {
            hi32 := calldataload(add(src.offset, fpOffset))
            lo32 := calldataload(add(src.offset, add(fpOffset, 16)))
        }
        return (hi32 >> 128) == 0 && lo32 == 0;
    }

    /// @dev Serialize an ArkWorks-uncompressed G1 point at `src[offset:offset+96]`
    ///      into a 48-byte ArkWorks-compressed (ZCash-style) encoding.
    ///      Flag layout: byte[0] bit7 = compressed (always), bit6 = infinity,
    ///      bit5 = y-sign (y > (p−1)/2).
    function _compressG1Ark(bytes calldata src, uint256 offset) internal pure returns (bytes memory out) {
        out = new bytes(ARK_G1_COMP_LEN);

        if (_isFpZero(src, offset) && _isFpZero(src, offset + 48)) {
            out[0] = 0xc0; // compressed + infinity
            return out;
        }

        // Copy x (48 bytes BE) from src into out.
        assembly ("memory-safe") {
            let srcPtr := add(src.offset, offset)
            let dstPtr := add(out, 0x20)
            calldatacopy(dstPtr, srcPtr, 48)
        }

        // Set compressed flag.
        uint8 flag = uint8(out[0]) | 0x80;
        if (_isFpAboveHalf(src, offset + 48)) {
            flag |= 0x20;
        }
        out[0] = bytes1(flag);
    }

    /// @dev Serialize an ArkWorks-uncompressed G2 point at `src[offset:offset+192]`
    ///      into a 96-byte ArkWorks-compressed encoding (xIm || xRe with flags).
    ///      y-sign rule: yIm > (p−1)/2, or (yIm == 0 AND yRe > (p−1)/2).
    function _compressG2Ark(bytes calldata src, uint256 offset) internal pure returns (bytes memory out) {
        out = new bytes(ARK_G2_COMP_LEN);

        bool xImZero = _isFpZero(src, offset);
        bool xReZero = _isFpZero(src, offset + 48);
        bool yImZero = _isFpZero(src, offset + 96);
        bool yReZero = _isFpZero(src, offset + 144);

        if (xImZero && xReZero && yImZero && yReZero) {
            out[0] = 0xc0;
            return out;
        }

        // Copy xIm || xRe (96 bytes) from src into out.
        assembly ("memory-safe") {
            let srcPtr := add(src.offset, offset)
            let dstPtr := add(out, 0x20)
            calldatacopy(dstPtr, srcPtr, 96)
        }

        uint8 flag = uint8(out[0]) | 0x80;
        bool ySign = yImZero
            ? _isFpAboveHalf(src, offset + 144)  // yIm == 0 ⇒ inspect yRe
            : _isFpAboveHalf(src, offset + 96); // otherwise yIm
        if (ySign) flag |= 0x20;
        out[0] = bytes1(flag);
    }

    /// @notice Compute the Fiat-Shamir challenge r ∈ F_r from the VK and signature.
    /// @dev    14 ArkWorks-compressed elements in a fixed order, hashed via
    ///         ArkWorks-flavored `expand_message_xmd` (Z_pad = 48, NOT 64)
    ///         with DST `HINTS_SIG_BLS12381:FIAT_SHAMIR`, output 48 BE bytes
    ///         reduced mod BLS_FR_ORDER.
    function _computeFiatShamirChallenge(bytes calldata hintVk, bytes calldata hintSig)
        internal
        view
        returns (uint256)
    {
        // Build the 800-byte transcript. Element order is load-bearing —
        // do not reorder.
        bytes memory transcript = abi.encodePacked(
            _compressG2Ark(hintVk, VK_OFFSET_SK), // [1]  sk_of_tau_com   (G2, 96)
            _compressG2Ark(hintVk, VK_OFFSET_H1), // [2]  h_1             (G2, 96)
            _compressG1Ark(hintSig, SIG_OFFSET_AGG_PK), // [3]  agg_pk          (G1, 48)
            hintSig[SIG_OFFSET_AGG_WEIGHT:SIG_OFFSET_AGG_WEIGHT + ARK_FR_LEN], // [4] agg_weight (Fr LE, 32)
            _compressG1Ark(hintVk, VK_OFFSET_W), // [5]  w_of_tau_com    (G1, 48)
            _compressG1Ark(hintSig, SIG_OFFSET_B), // [6]  b_of_tau_com    (G1, 48)
            _compressG1Ark(hintSig, SIG_OFFSET_PARSUM), // [7]  parsum_of_tau   (G1, 48)
            _compressG1Ark(hintSig, SIG_OFFSET_QX), // [8]  qx_of_tau       (G1, 48)
            _compressG1Ark(hintSig, SIG_OFFSET_QZ), // [9]  qz_of_tau       (G1, 48)
            _compressG1Ark(hintSig, SIG_OFFSET_QX_MUL_TAU), // [10] qx·τ_of_tau     (G1, 48)
            _compressG1Ark(hintSig, SIG_OFFSET_Q1), // [11] q1_of_tau       (G1, 48)
            _compressG1Ark(hintSig, SIG_OFFSET_Q2), // [12] q2_of_tau       (G1, 48)
            _compressG1Ark(hintSig, SIG_OFFSET_Q3), // [13] q3_of_tau       (G1, 48)
            _compressG1Ark(hintSig, SIG_OFFSET_Q4) // [14] q4_of_tau       (G1, 48)
        );

        return _hashToFr(transcript);
    }

    /// @dev ArkWorks DefaultFieldHasher<Sha256, 128> applied to `message` with
    ///      DST `FIAT_SHAMIR_DST`, producing one BLS12-381 Fr element.
    ///
    ///      Deviates from RFC 9380 `expand_message_xmd`: uses Z_pad of L = 48 bytes
    ///      instead of the SHA-256 block size 64. ArkWorks 0.4.2 quirk.
    ///
    ///      With len_in_bytes = 48 and SHA-256, ell = ceil(48/32) = 2, so we
    ///      need exactly b_0, b_1, b_2 and concatenate b_1 || top16(b_2).
    function _hashToFr(bytes memory message) internal view returns (uint256) {
        bytes memory dstPrime = abi.encodePacked(FIAT_SHAMIR_DST, uint8(FIAT_SHAMIR_DST.length));

        // msg_prime = Z_pad(L=48) || msg || I2OSP(48, 2) || I2OSP(0, 1) || DST_prime
        bytes memory msgPrime = abi.encodePacked(
            new bytes(ARK_HASH_TO_FR_LEN), message, SafeCast.toUint16(ARK_HASH_TO_FR_LEN), SafeCast.toUint8(0), dstPrime
        );

        bytes32 b0 = sha256(msgPrime);
        bytes32 b1 = sha256(abi.encodePacked(b0, uint8(1), dstPrime));
        bytes32 b2 = sha256(abi.encodePacked(b0 ^ b1, uint8(2), dstPrime));

        // casting to 'bytes16' is safe because we want only top16 bytes of b2
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes memory uniform = abi.encodePacked(b1, bytes16(b2));

        // Reduce 48-byte BE integer mod r via MODEXP(base^1 mod r).
        bytes memory modexpInput = abi.encodePacked(
            uint256(48), // length(base)
            uint256(32), // length(exp)
            uint256(32), // length(mod)
            uniform, // base (48 BE)
            uint256(1), // exp = 1
            BLS_FR_ORDER // mod = r (32 BE)
        );
        (bool ok, bytes memory out) = ClprBls12381.MODEXP.staticcall(modexpInput);
        if (!ok || out.length != 32) revert ClprBls12381.BlsPrecompileCallFailed();
        // casting to 'bytes32' is safe because there is a check above for out.length to equal 32
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint256(bytes32(out));
    }

    // hinTS helpers added for Steps 4–9: byte readers, ArkWorks↔EIP-2537
    // converters, and Fr arithmetic.

    /// @dev Read a u64 little-endian value from `src[offset..offset+8]`.
    ///      Uses a single calldataload + 64-bit byte-reversal instead of an 8-iteration loop.
    function _readU64Le(bytes calldata src, uint256 offset) internal pure returns (uint64 v) {
        uint256 word;
        assembly ("memory-safe") {
            // Load 32 bytes; the 8 bytes we need are the top 8 bytes (bits 255..192).
            word := calldataload(add(src.offset, offset))
        }
        // Shift right 192 bits to get our 8 bytes as a big-endian uint64,
        // then byte-reverse to convert little-endian → host order.
        uint64 raw = SafeCast.toUint64(word >> 192);
        // 64-bit byte-swap (bit-twiddling, branchless).
        raw = (raw & 0xFF00FF00FF00FF00) >> 8 | (raw & 0x00FF00FF00FF00FF) << 8;
        raw = (raw & 0xFFFF0000FFFF0000) >> 16 | (raw & 0x0000FFFF0000FFFF) << 16;
        v = raw >> 32 | raw << 32;
    }

    /// @dev Convert an ArkWorks-uncompressed G1 point (96 B: x_BE(48) || y_BE(48))
    ///      at `src[offset:offset+96]` to EIP-2537 G1 wire format (128 B:
    ///      16-byte zero pad || x_BE(48) || 16-byte zero pad || y_BE(48)).
    function _arkG1ToEip2537(bytes calldata src, uint256 offset) internal pure returns (bytes memory out) {
        out = new bytes(ClprBls12381.G1_POINT_LENGTH); // 128, zero-initialized — the 16-byte pads stay zero
        assembly ("memory-safe") {
            let srcPtr := add(src.offset, offset)
            let dstPtr := add(out, 0x20)
            // x at out[16..64]
            calldatacopy(add(dstPtr, 16), srcPtr, 48)
            // y at out[80..128]
            calldatacopy(add(dstPtr, 80), add(srcPtr, 48), 48)
        }
    }

    /// @dev Convert an ArkWorks-uncompressed G2 point (192 B:
    ///      xIm_BE || xRe_BE || yIm_BE || yRe_BE, each 48 BE) at
    ///      `src[offset:offset+192]` to EIP-2537 G2 wire format (256 B:
    ///      pad(16) || xRe || pad(16) || xIm || pad(16) || yRe || pad(16) || yIm).
    ///      Note the c0/c1 swap: ArkWorks stores imaginary first, EIP-2537 wants
    ///      real (c0) first.
    function _arkG2ToEip2537(bytes calldata src, uint256 offset) internal pure returns (bytes memory out) {
        out = new bytes(ClprBls12381.G2_POINT_LENGTH); // 256, zero-initialized
        assembly ("memory-safe") {
            let srcPtr := add(src.offset, offset)
            let dstPtr := add(out, 0x20)
            // xRe (Ark +48) → out[16..64]
            calldatacopy(add(dstPtr, 16), add(srcPtr, 48), 48)
            // xIm (Ark +0)  → out[80..128]
            calldatacopy(add(dstPtr, 80), srcPtr, 48)
            // yRe (Ark +144) → out[144..192]
            calldatacopy(add(dstPtr, 144), add(srcPtr, 144), 48)
            // yIm (Ark +96)  → out[208..256]
            calldatacopy(add(dstPtr, 208), add(srcPtr, 96), 48)
        }
    }

    /// @dev Negate an EIP-2537 G1 point by flipping the y-coordinate in Fp:  −y = p − y.
    ///      EIP-2537 G1 layout (128 bytes):
    ///        [0..16)  = 16 zero bytes (x padding)
    ///        [16..64) = x_BE (48-byte BLS Fp element)
    ///        [64..80) = 16 zero bytes (y padding)
    ///        [80..128)= y_BE (48-byte BLS Fp element)
    ///      BLS12-381 base-field prime p (48 bytes), split at the 16-byte boundary:
    ///        p_hi = 0x1a0111ea397fe69a4b1ba7b6434bacd7    (16 bytes, fits in uint128)
    ///        p_lo = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab (32 bytes)
    ///      For a non-infinity BLS12-381 G1 point, y ≠ 0, so p − y is always valid.
    ///      Pure arithmetic replaces the previous G1MSM call (12 000 gas → ~50 gas).
    function _negG1Eip(bytes memory g1Eip) internal pure returns (bytes memory neg) {
        neg = new bytes(ClprBls12381.G1_POINT_LENGTH); // 128 bytes, zero-initialised
        assembly ("memory-safe") {
            let src := add(g1Eip, 0x20)
            let dst := add(neg, 0x20)

            // Copy x-section unchanged: bytes[0..80) = [x-pad][x][y-pad].
            mcopy(dst, src, 80)

            // Load y as two chunks:
            //   mload(src+64) → bytes[64..96): top 16B are 0 (y-pad), bottom 16B are y_hi.
            //   mload(src+96) → bytes[96..128): y_lo (32 bytes).
            let y_hi := and(mload(add(src, 64)), 0xffffffffffffffffffffffffffffffff)
            let y_lo := mload(add(src, 96))

            // p_lo = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
            // p_hi = 0x1a0111ea397fe69a4b1ba7b6434bacd7
            let p_lo := 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
            let p_hi := 0x1a0111ea397fe69a4b1ba7b6434bacd7

            // 48-byte subtraction: r = p − y, tracking borrow across the 32/16-byte boundary.
            let r_lo := sub(p_lo, y_lo)
            let borrow := lt(p_lo, y_lo) // 1 if underflowed, else 0
            let r_hi := sub(sub(p_hi, y_hi), borrow)

            // Write negated y back.
            // mstore(dst+64, r_hi): r_hi < p_hi < 2^128, so bits[255:128] = 0 ← y-pad zeros;
            //                       bits[127:0]   = r_hi                      ← y_hi bytes[80..96).
            mstore(add(dst, 64), r_hi)
            mstore(add(dst, 96), r_lo)
        }
    }

    /// @dev Fr negation: −x mod r.
    function _frNeg(uint256 x) internal pure returns (uint256) {
        return x == 0 ? 0 : BLS_FR_ORDER - x;
    }

    /// @dev base^exp mod BLS_FR_ORDER via the MODEXP precompile.
    function _frPow(uint256 base, uint256 exp) internal view returns (uint256) {
        bytes memory input = abi.encodePacked(uint256(32), uint256(32), uint256(32), base, exp, BLS_FR_ORDER);
        (bool ok, bytes memory out) = ClprBls12381.MODEXP.staticcall(input);
        if (!ok || out.length != 32) revert ClprBls12381.BlsPrecompileCallFailed();
        // casting to 'bytes32' is safe because there is a check above for out.length to equal 32
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint256(bytes32(out));
    }

    /// @dev Fr multiplicative inverse via Fermat's little theorem: x^(r−2) mod r.
    ///      Reverts implicitly via MODEXP cost on x = 0 (returns 0; callers should
    ///      ensure x != 0 to avoid silently mapping to zero).
    function _frInv(uint256 x) internal view returns (uint256) {
        return _frPow(x, BLS_FR_ORDER - 2);
    }

    /// @dev Compute the primitive n-th root of unity in Fr where n = 2^k.
    ///      ω_n = TWO_ADIC_ROOT^{2^{32−k}}. Caller must have validated that
    ///      n is a power of two with 2 ≤ n ≤ 2^32.
    function _nthRootOfUnity(uint256 n) internal view returns (uint256) {
        // k = log2(n)
        uint256 k = 0;
        uint256 tmp = n;
        while (tmp > 1) {
            tmp >>= 1;
            k++;
        }
        uint256 exp = uint256(1) << (BLS_FR_TWO_ADICITY - k);
        return _frPow(BLS_FR_TWO_ADIC_ROOT, exp);
    }

    function splitTssBlockSignature(bytes calldata blockSig)
        internal
        pure
        returns (bytes calldata hintVk, bytes calldata hintSig, bytes calldata abProof, bool isWrapsSettled)
    {
        uint256 len = blockSig.length;

        if (len != TOTAL_GENESIS_SCHNORR && len != TOTAL_SETTLED_WRAPS) {
            revert ClprHieroSignatureLength(len);
        }

        hintVk = blockSig[:HINTS_VK_LEN]; // 0..1096
        hintSig = blockSig[HINTS_VK_LEN:OFFSET_ABPROOF]; // 1096..2728
        abProof = blockSig[OFFSET_ABPROOF:]; // 2728..len

        isWrapsSettled = (len == TOTAL_SETTLED_WRAPS);
    }
}
