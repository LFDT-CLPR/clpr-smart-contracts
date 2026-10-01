// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {MvxSha512} from "@hiero-ledger/clpr/libraries/proof/mvx/MvxSha512.sol";

/// @title MvxBls
/// @notice BLS signatures as MultiversX validators make them: herumi `bls-go-binary` v1.37.0 built
///         without `BLS_ETH` (mx-chain-crypto-go `signing/mcl`), on BLS12-381 with public keys in G2
///         and signatures in G1. This is not the IETF ciphersuite:
///
///           H(m)  = mcl "original" map (MCL_MAP_TO_MODE_ORIGINAL, `MapTo::calcBN`) of
///                   t = SHA-512(m)[0..48) read little-endian and masked to 381 bits (380 if ≥ p),
///                   followed by multiplication with the G1 cofactor 0x396c8c005555e1568c00aaab0000aaab
///           Q     = the G2 generator herumi uses in this mode, mapToG2(1) (not the IETF generator)
///           valid ⇔ e(sig, Q) = e(H(m), pk); an aggregate uses Σ pk_i of the bitmap's signers (KOSK)
///
///         Field arithmetic modulo p uses the MODEXP precompile; points use EIP-2537. The cofactor
///         multiplication runs on G1ADD (which checks curve membership but not the subgroup) because
///         the mapped point is not yet in the subgroup. Points are uncompressed EIP-2537 encodings.
library MvxBls {
    address internal constant BLS12_G1ADD = address(0x0b);
    address internal constant BLS12_G2ADD = address(0x0d);
    address internal constant BLS12_PAIRING_CHECK = address(0x0f);
    address internal constant MODEXP = address(0x05);

    bytes internal constant P =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
    uint256 internal constant P_HI = 0x1a0111ea397fe69a4b1ba7b6434bacd7;
    uint256 internal constant P_LO = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;
    /// @dev (p + 1) / 4: square roots for p ≡ 3 (mod 4), as mcl's SquareRoot computes them.
    bytes internal constant SQRT_EXP =
        hex"0680447a8e5ff9a692c6e9ed90d2eb35d91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab";
    /// @dev p − 2: inverses by Fermat.
    bytes internal constant INV_EXP =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaa9";
    /// @dev mcl `MapTo::initBLS12` constants for BLS12_381: c1 = √−3, c2 = (c1 − 1) / 2.
    uint256 internal constant C1_HI = 0xbe32ce5fbeed9ca3;
    uint256 internal constant C1_LO = 0x74d38c0ed41eefd5bb675277cdf12d11bc2fb026c41400045c03fffffffdfffd;
    uint256 internal constant C2_HI = 0x5f19672fdf76ce51;
    uint256 internal constant C2_LO = 0xba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe;
    /// @dev G1 cofactor (z − 1)² / 3.
    uint256 internal constant COFACTOR = 0x396c8c005555e1568c00aaab0000aaab;

    /// @dev −Q, herumi's G2 generator (mapToG2(1), original map) negated, EIP-2537 encoding.
    bytes internal constant NEG_Q = hex"000000000000000000000000000000000f3d011af81acf00140aab3c122c61bbdf0628db81c37664bdfc828163ce074ee33a1a5ce5488556603bc5d8d9f21ecc"
        hex"00000000000000000000000000000000171df7a5080f908a16c2658ea90164e28c924c3f0e6655f6d82adca6bfbdfb5f9efca82c1609676fa15cd30396f1a4b3"
        hex"0000000000000000000000000000000012c86d0f22e2b2e51c4db16f431aff011be8879bf710ab8aae20564de0fac0fda96460c86191ef19d596a8d87de9feda"
        hex"000000000000000000000000000000000017add25ac37931e030d5aced60e0cb4b7d3cbcdd5adfcdd8d299950845313056a01b44afc68094716fdbba21fba415";

    uint256 internal constant G1_LEN = 128;
    uint256 internal constant G2_LEN = 256;

    error BlsPrecompileFailed();
    error BadSignature();
    error BadPointLength();
    error MapFailed();

    /// @dev An element of Fp as value = hi · 2^256 + lo.
    struct Fp {
        uint256 hi;
        uint256 lo;
    }

    // ── signatures ──────────────────────────────────────────────────────────

    /// @notice Revert unless `signature` (G1) is valid for `message` under `publicKey` (G2).
    function verify(bytes memory publicKey, bytes memory signature, bytes memory message) internal view {
        if (publicKey.length != G2_LEN || signature.length != G1_LEN) revert BadPointLength();
        bytes memory input = abi.encodePacked(signature, NEG_Q, hashToG1(message), publicKey);
        (bool ok, bytes memory out) = BLS12_PAIRING_CHECK.staticcall(input);
        if (!ok || out.length != 32) revert BlsPrecompileFailed();
        // casting to 'bytes32' is safe because the length was checked to be 32 above.
        // forge-lint: disable-next-line(unsafe-typecast)
        if (uint256(bytes32(out)) != 1) revert BadSignature();
    }

    /// @notice Sum of G2 points (EIP-2537 G2ADD validates each input is on the curve).
    function addG2(bytes memory a, bytes memory b) internal view returns (bytes memory out) {
        bool ok;
        (ok, out) = BLS12_G2ADD.staticcall(abi.encodePacked(a, b));
        if (!ok || out.length != G2_LEN) revert BlsPrecompileFailed();
    }

    // ── hash to G1 (mcl original map) ───────────────────────────────────────

    /// @notice herumi `hashAndMapToG1` in MCL_MAP_TO_MODE_ORIGINAL (EIP-2537 G1 encoding).
    function hashToG1(bytes memory message) internal view returns (bytes memory) {
        return clearCofactor(mapToCurve(hashToField(message)));
    }

    /// @notice mcl `Fp::setHashOf`: SHA-512, first 48 bytes as a little-endian integer, masked to
    ///         381 bits, and to 380 bits if the result is not below p.
    function hashToField(bytes memory message) internal view returns (Fp memory t) {
        bytes memory h = MvxSha512.hash(message);
        for (uint256 i = 0; i < 48; i++) {
            uint256 b = uint8(h[i]);
            if (i < 32) t.lo |= b << (8 * i);
            else t.hi |= b << (8 * (i - 32));
        }
        t.hi &= (uint256(1) << 125) - 1; // 381 bits
        Fp memory r = _mod(abi.encodePacked(t.hi, t.lo));
        if (r.hi != t.hi || r.lo != t.lo) t.hi &= (uint256(1) << 124) - 1; // t ≥ p: 380 bits
    }

    /// @notice mcl `MapTo::calcBN` on G1 (y² = x³ + 4) for t ≠ 0; returns a curve point before
    ///         cofactor clearing, as 128-byte EIP-2537 encoding.
    function mapToCurve(Fp memory t) internal view returns (bytes memory) {
        if (_isZero(t)) revert MapFailed();
        // negative ⇔ t is not a square (Legendre symbol −1); tested by squaring the candidate root
        Fp memory s = _pow(t, SQRT_EXP);
        bool negative = !_eq(_mul(s, s), t);
        // w = c1 · t / (t² + b + 1), b = 4
        Fp memory w = _add(_mul(t, t), Fp({hi: 0, lo: 5}));
        if (_isZero(w)) revert MapFailed();
        w = _mul(_mul(_pow(w, INV_EXP), Fp({hi: C1_HI, lo: C1_LO})), t);
        Fp memory x;
        for (uint256 i = 0; i < 3; i++) {
            if (i == 0) {
                x = _sub(Fp({hi: C2_HI, lo: C2_LO}), _mul(t, w)); // c2 − t·w
            } else if (i == 1) {
                x = _neg(_add(x, Fp({hi: 0, lo: 1}))); // −x − 1
            } else {
                x = _add(_pow(_mul(w, w), INV_EXP), Fp({hi: 0, lo: 1})); // 1/w² + 1
            }
            Fp memory rhs = _add(_mul(_mul(x, x), x), Fp({hi: 0, lo: 4}));
            Fp memory y = _pow(rhs, SQRT_EXP);
            if (_eq(_mul(y, y), rhs)) {
                if (negative) y = _neg(y);
                return abi.encodePacked(bytes16(0), uint128(x.hi), x.lo, bytes16(0), uint128(y.hi), y.lo);
            }
        }
        revert MapFailed();
    }

    /// @notice COFACTOR · P by double-and-add on G1ADD (P is on the curve, not yet in the subgroup).
    function clearCofactor(bytes memory p) internal view returns (bytes memory r) {
        r = p;
        for (int256 bit = 124; bit >= 0; bit--) {
            r = _g1Add(r, r);
            // forge-lint: disable-next-line(unsafe-typecast)
            if ((COFACTOR >> uint256(bit)) & 1 == 1) r = _g1Add(r, p);
        }
    }

    function _g1Add(bytes memory a, bytes memory b) private view returns (bytes memory out) {
        bool ok;
        (ok, out) = BLS12_G1ADD.staticcall(abi.encodePacked(a, b));
        if (!ok || out.length != G1_LEN) revert BlsPrecompileFailed();
    }

    // ── Fp arithmetic (MODEXP reductions) ───────────────────────────────────

    function _isZero(Fp memory a) private pure returns (bool) {
        return a.hi == 0 && a.lo == 0;
    }

    function _eq(Fp memory a, Fp memory b) private pure returns (bool) {
        return a.hi == b.hi && a.lo == b.lo;
    }

    /// @dev Reduce a big-endian integer of any length modulo p.
    function _mod(bytes memory v) private view returns (Fp memory r) {
        (bool ok, bytes memory out) =
            MODEXP.staticcall(abi.encodePacked(v.length, uint256(1), uint256(48), v, uint8(1), P));
        if (!ok || out.length != 48) revert BlsPrecompileFailed();
        assembly ("memory-safe") {
            mstore(r, shr(128, mload(add(out, 0x20))))
            mstore(add(r, 0x20), mload(add(out, 0x30)))
        }
    }

    function _pow(Fp memory a, bytes memory e) private view returns (Fp memory r) {
        (bool ok, bytes memory out) =
            MODEXP.staticcall(abi.encodePacked(uint256(48), e.length, uint256(48), uint128(a.hi), a.lo, e, P));
        if (!ok || out.length != 48) revert BlsPrecompileFailed();
        assembly ("memory-safe") {
            mstore(r, shr(128, mload(add(out, 0x20))))
            mstore(add(r, 0x20), mload(add(out, 0x30)))
        }
    }

    function _add(Fp memory a, Fp memory b) private view returns (Fp memory) {
        unchecked {
            uint256 lo = a.lo + b.lo;
            uint256 carry = lo < a.lo ? 1 : 0;
            return _mod(abi.encodePacked(a.hi + b.hi + carry, lo));
        }
    }

    /// @dev p − a for a in [0, p); returns p for a = 0, which every consumer reduces or squares.
    function _neg(Fp memory a) private pure returns (Fp memory r) {
        unchecked {
            r.lo = P_LO - a.lo;
            uint256 borrow = P_LO < a.lo ? 1 : 0;
            r.hi = P_HI - a.hi - borrow;
        }
    }

    function _sub(Fp memory a, Fp memory b) private view returns (Fp memory) {
        return _add(a, _neg(b));
    }

    /// @dev a · b mod p: the 762-bit product in three words, reduced by MODEXP.
    function _mul(Fp memory a, Fp memory b) private view returns (Fp memory) {
        (uint256 l0, uint256 l1) = _fullMul(a.lo, b.lo); // al·bl
        (uint256 m0, uint256 m1) = _fullMul(a.hi, b.lo); // ah·bl
        (uint256 n0, uint256 n1) = _fullMul(a.lo, b.hi); // al·bh
        uint256 w0 = l0;
        uint256 w1;
        uint256 w2;
        unchecked {
            w1 = l1 + m0;
            uint256 c = w1 < l1 ? 1 : 0;
            uint256 w1b = w1 + n0;
            c += w1b < w1 ? 1 : 0;
            w1 = w1b;
            w2 = m1 + n1 + a.hi * b.hi + c; // < 2^250 + 2^126 + 2^126: no overflow
        }
        return _mod(abi.encodePacked(w2, w1, w0));
    }

    /// @dev Full 512-bit product of two 256-bit words.
    function _fullMul(uint256 x, uint256 y) private pure returns (uint256 lo, uint256 hi) {
        assembly ("memory-safe") {
            let mm := mulmod(x, y, not(0))
            lo := mul(x, y)
            hi := sub(sub(mm, lo), lt(mm, lo))
        }
    }
}
