// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {AntelopeLib} from "@hiero-ledger/clpr/verifiers/evm/antelope/AntelopeLib.sol";

/// @title AntelopeBls
/// @notice BLS12-381 for Savanna finalizer signatures, on the EIP-2537 precompiles.
/// @dev Scheme (AntelopeIO/bls12-381 signatures.cpp, used by spring libfc bls_private_key::sign and
///      qc_sig_t::verify_signatures): public keys in G1, signatures in G2, messages hashed with
///      hash_to_curve G2 XMD:SHA-256 SSWU and the DST "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
///      (CIPHERSUITE_ID, the NUL scheme, not the POP one Ethereum uses).
///
///      Encodings differ from EIP-2537: Spring serializes points affine, non-Montgomery, with each
///      48-byte field element little-endian (bls_public_key / bls_signature: x || y, and for G2
///      x.c0 || x.c1 || y.c0 || y.c1). EIP-2537 wants each element big-endian, left-padded to 64
///      bytes, in the same order. The converters below do that byte reversal.
library AntelopeBls {
    address internal constant G1ADD = address(0x0b);
    address internal constant G2ADD = address(0x0d);
    address internal constant PAIRING_CHECK = address(0x0f);
    address internal constant MAP_FP2_TO_G2 = address(0x11);
    address internal constant MODEXP = address(0x05);

    bytes internal constant DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

    bytes internal constant FIELD_MODULUS =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

    /// @dev -G1 generator in EIP-2537 form (checked against @noble/curves in the tests).
    bytes internal constant G1_GENERATOR_NEG =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";

    error BlsPrecompileFailed();
    error BlsSignatureInvalid();
    error BlsEncoding();

    // ── Encoding ──────────────────────────────────────────────────────────────

    /// @dev Write the 48-byte little-endian field element at `src[off..off+48)` to `dst[dOff..dOff+64)`
    ///      as a 64-byte big-endian value (16 zero bytes, then the 48 reversed bytes).
    function _feLeToBe(bytes memory src, uint256 off, bytes memory dst, uint256 dOff) private pure {
        if (off + 48 > src.length || dOff + 64 > dst.length) revert BlsEncoding();
        uint256 w0;
        uint256 w1;
        assembly ("memory-safe") {
            let p := add(add(src, 0x20), off)
            w0 := mload(p) // bytes [0, 32)
            w1 := mload(add(p, 32)) // bytes [32, 48) in the high half, then trailing bytes
        }
        uint256 hi = AntelopeLib.bswap256(w1) & ((uint256(1) << 128) - 1); // 16 zero bytes || rev(b[32..48))
        uint256 lo = AntelopeLib.bswap256(w0); // rev(b[0..32))
        assembly ("memory-safe") {
            let q := add(add(dst, 0x20), dOff)
            mstore(q, hi)
            mstore(add(q, 32), lo)
        }
    }

    /// @dev Spring G1 (96 bytes, LE) at `src[off..]` → EIP-2537 G1 (128 bytes).
    function g1FromSpring(bytes memory src, uint256 off) internal pure returns (bytes memory out) {
        out = new bytes(128);
        _feLeToBe(src, off, out, 0);
        _feLeToBe(src, off + 48, out, 64);
    }

    /// @dev Spring G2 (192 bytes, LE) → EIP-2537 G2 (256 bytes).
    function g2FromSpring(bytes memory sig) internal pure returns (bytes memory out) {
        if (sig.length != 192) revert BlsEncoding();
        out = new bytes(256);
        for (uint256 i = 0; i < 4; ++i) {
            _feLeToBe(sig, i * 48, out, i * 64);
        }
    }

    // ── Group operations ──────────────────────────────────────────────────────

    /// @dev a + b in G1 (EIP-2537 encoding). The precompile rejects points off the curve.
    function g1Add(bytes memory a, bytes memory b) internal view returns (bytes memory) {
        (bool ok, bytes memory res) = G1ADD.staticcall(abi.encodePacked(a, b));
        if (!ok || res.length != 128) revert BlsPrecompileFailed();
        return res;
    }

    function _g2Add(bytes memory a, bytes memory b) private view returns (bytes memory) {
        (bool ok, bytes memory res) = G2ADD.staticcall(abi.encodePacked(a, b));
        if (!ok || res.length != 256) revert BlsPrecompileFailed();
        return res;
    }

    // ── Hash to curve (RFC 9380, BLS12381G2_XMD:SHA-256_SSWU_RO_) ─────────────

    /// @dev hash_to_curve G2 of `message` with the Antelope DST.
    function hashToG2(bytes memory message) internal view returns (bytes memory) {
        bytes memory u = _expandMessageXmd(message, 256);
        bytes memory q0 = _map(_fp2(u, 0));
        bytes memory q1 = _map(_fp2(u, 128));
        return _g2Add(q0, q1);
    }

    function _expandMessageXmd(bytes memory message, uint256 len) private pure returns (bytes memory out) {
        bytes memory dstPrime = abi.encodePacked(DST, bytes1(uint8(DST.length)));
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes32 b0 = sha256(abi.encodePacked(new bytes(64), message, bytes2(uint16(len)), bytes1(0x00), dstPrime));
        bytes32 bi = sha256(abi.encodePacked(b0, bytes1(0x01), dstPrime));
        out = new bytes(len);
        uint256 ell = (len + 31) / 32;
        for (uint256 i = 1; i <= ell; ++i) {
            // forge-lint: disable-next-line(unsafe-typecast)
            if (i > 1) bi = sha256(abi.encodePacked(b0 ^ bi, bytes1(uint8(i)), dstPrime));
            assembly ("memory-safe") {
                mstore(add(add(out, 0x20), mul(sub(i, 1), 32)), bi)
            }
        }
    }

    function _fp2(bytes memory u, uint256 off) private view returns (bytes memory fp2) {
        fp2 = abi.encodePacked(bytes16(0), _modP(u, off), bytes16(0), _modP(u, off + 64));
    }

    /// @dev u[off..off+64) mod p via MODEXP (base^1 mod p), 48 bytes.
    function _modP(bytes memory u, uint256 off) private view returns (bytes memory) {
        bytes memory input = abi.encodePacked(
            uint256(64), uint256(1), uint256(48), AntelopeLib.slice(u, off, 64), bytes1(0x01), FIELD_MODULUS
        );
        (bool ok, bytes memory res) = MODEXP.staticcall(input);
        if (!ok || res.length != 48) revert BlsPrecompileFailed();
        return res;
    }

    function _map(bytes memory fp2) private view returns (bytes memory) {
        (bool ok, bytes memory res) = MAP_FP2_TO_G2.staticcall(fp2);
        if (!ok || res.length != 256) revert BlsPrecompileFailed();
        return res;
    }

    // ── Verification ──────────────────────────────────────────────────────────

    /// @dev Verify `sig` (EIP-2537 G2) by `pubkey` (EIP-2537 G1) over `message`:
    ///      e(pubkey, H(message)) · e(-G1, sig) == 1. The pairing precompile checks that both inputs
    ///      are on the curve and in the prime-order subgroup.
    function verify(bytes memory pubkey, bytes memory message, bytes memory sig) internal view {
        bytes memory input = abi.encodePacked(pubkey, hashToG2(message), G1_GENERATOR_NEG, sig);
        (bool ok, bytes memory res) = PAIRING_CHECK.staticcall(input);
        if (!ok || res.length != 32) revert BlsPrecompileFailed();
        // forge-lint: disable-next-line(unsafe-typecast)
        if (uint256(bytes32(res)) != 1) revert BlsSignatureInvalid();
    }
}
