// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";

/// @title MonadBls
/// @notice BLS12-381 (EIP-2537) helpers for verifying a MonadBFT quorum certificate.
/// @dev MonadBFT votes are BLS signatures in blst `min_pk` mode (G1 public keys, G2 signatures) with
///      the proof-of-possession ciphersuite DST `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`
///      (monad-bft `monad-bls/src/bls.rs`: `set_curve_constants!(minpk)`, `MIN_PK_DST`). The signed
///      message is the signing-domain prefix `"\x0Dmonad/vote/1\n"` followed by `rlp(Vote)`
///      (`monad-crypto/src/signing_domain.rs`, `monad-consensus/src/validation/signing.rs::verify_qc`).
///      A QC carries one aggregate signature; verification is `fast_aggregate_verify` over the
///      aggregate of the signers' public keys.
library MonadBls {
    address internal constant BLS12_G1ADD = address(0x0b);
    address internal constant BLS12_G2ADD = address(0x0d);
    address internal constant BLS12_PAIRING_CHECK = address(0x0f);
    address internal constant BLS12_MAP_FP2_TO_G2 = address(0x11);
    address internal constant MODEXP = address(0x05);

    bytes internal constant DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    bytes internal constant FIELD_MODULUS =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
    /// @dev -G1 generator, EIP-2537 encoding.
    bytes internal constant G1_GENERATOR_NEG =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";

    error BlsPrecompileFailed();
    error BlsSignatureInvalid();
    error BlsSignatureEncoding();

    // ── Hash to G2 (RFC 9380, BLS12381G2_XMD:SHA-256_SSWU_RO_) ─────────────────

    /// @notice hash_to_curve(msg) on G2 with the POP DST.
    function hashToG2(bytes memory message) internal view returns (bytes memory) {
        bytes memory u = _expandMessageXmd(message, 256);
        bytes memory q0 = _call(BLS12_MAP_FP2_TO_G2, _fp2(u, 0), 256);
        bytes memory q1 = _call(BLS12_MAP_FP2_TO_G2, _fp2(u, 128), 256);
        return _call(BLS12_G2ADD, abi.encodePacked(q0, q1), 256);
    }

    function _expandMessageXmd(bytes memory message, uint256 lenInBytes) private pure returns (bytes memory out) {
        bytes memory dstPrime = abi.encodePacked(DST, bytes1(uint8(DST.length)));
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes32 b0 = sha256(abi.encodePacked(new bytes(64), message, bytes2(uint16(lenInBytes)), bytes1(0), dstPrime));
        out = new bytes(lenInBytes);
        bytes32 bi = sha256(abi.encodePacked(b0, bytes1(0x01), dstPrime));
        uint256 ell = (lenInBytes + 31) / 32;
        for (uint256 i = 1; i <= ell; ++i) {
            // forge-lint: disable-next-line(unsafe-typecast)
            if (i > 1) bi = sha256(abi.encodePacked(b0 ^ bi, bytes1(uint8(i)), dstPrime));
            assembly ("memory-safe") {
                mstore(add(add(out, 0x20), mul(sub(i, 1), 32)), bi)
            }
        }
    }

    /// @dev Two 64-byte chunks of `u` reduced mod p → one EIP-2537 Fp2 element (c0 || c1, 64-byte padded).
    function _fp2(bytes memory u, uint256 off) private view returns (bytes memory fp2) {
        fp2 = new bytes(128);
        for (uint256 k = 0; k < 2; ++k) {
            bytes memory chunk = new bytes(64);
            assembly ("memory-safe") {
                mcopy(add(chunk, 0x20), add(add(u, 0x20), add(off, mul(k, 64))), 64)
            }
            bytes memory r = _call(
                MODEXP, abi.encodePacked(uint256(64), uint256(1), uint256(48), chunk, bytes1(0x01), FIELD_MODULUS), 48
            );
            assembly ("memory-safe") {
                mcopy(add(add(fp2, 0x20), add(mul(k, 64), 16)), add(r, 0x20), 48)
            }
        }
    }

    // ── Aggregation / verification ──────────────────────────────────────────────

    /// @dev G1 point addition (EIP-2537). Reverts if either input is malformed or off the curve.
    function g1Add(bytes memory a, bytes memory b) internal view returns (bytes memory) {
        return _call(BLS12_G1ADD, abi.encodePacked(a, b), 128);
    }

    /// @notice fast_aggregate_verify: e(apk, H(msg)) == e(G1, sig). `apk` is the 128-byte aggregate of
    ///         the signers' keys; `sig` the 256-byte uncompressed G2 aggregate signature. The pairing
    ///         precompile subgroup-checks both points.
    function verify(bytes memory apk, bytes memory sig, bytes memory message) internal view {
        if (_isZero(apk) || _isZero(sig)) revert BlsSignatureInvalid();
        bytes memory h = hashToG2(message);
        (bool ok, bytes memory res) = BLS12_PAIRING_CHECK.staticcall(abi.encodePacked(apk, h, G1_GENERATOR_NEG, sig));
        if (!ok || res.length != 32) revert BlsPrecompileFailed();
        // forge-lint: disable-next-line(unsafe-typecast)
        if (uint256(bytes32(res)) != 1) revert BlsSignatureInvalid();
    }

    /// @notice Bind a 256-byte uncompressed G2 signature to its 96-byte compressed (ZCash) encoding, as
    ///         carried in the QC: `x.c1 || x.c0` with the compression and sign flags in the top bits.
    /// @dev The sign flag is set iff y is lexicographically largest: y.c1 > (p-1)/2, or y.c1 == 0 and
    ///      y.c0 > (p-1)/2. Together with the on-curve check inside the pairing precompile this fixes
    ///      the point uniquely, so the verified signature is exactly the one the validators produced.
    function requireCompressedG2(bytes memory sig, bytes memory compressed) internal pure {
        if (sig.length != 256 || compressed.length != 96) revert BlsSignatureEncoding();
        uint256 x0Hi;
        uint256 x0Lo;
        uint256 x1Hi;
        uint256 x1Lo;
        uint256 y0Hi;
        uint256 y0Lo;
        uint256 y1Hi;
        uint256 y1Lo;
        uint256 c1Hi;
        uint256 c1Lo;
        uint256 c0Hi;
        uint256 c0Lo;
        assembly ("memory-safe") {
            let p := add(sig, 0x20)
            x0Hi := mload(p)
            x0Lo := mload(add(p, 32))
            x1Hi := mload(add(p, 64))
            x1Lo := mload(add(p, 96))
            y0Hi := mload(add(p, 128))
            y0Lo := mload(add(p, 160))
            y1Hi := mload(add(p, 192))
            y1Lo := mload(add(p, 224))
            let c := add(compressed, 0x20)
            c1Hi := shr(128, mload(c))
            c1Lo := mload(add(c, 16))
            c0Hi := shr(128, mload(add(c, 48)))
            c0Lo := mload(add(c, 64))
        }
        uint256 flags = c1Hi >> 125;
        c1Hi &= (uint256(1) << 125) - 1;
        if (flags & 4 == 0 || flags & 2 != 0) revert BlsSignatureEncoding(); // compressed, not infinity
        if (c1Hi != x1Hi || c1Lo != x1Lo || c0Hi != x0Hi || c0Lo != x0Lo) revert BlsSignatureEncoding();
        bool largest = (y1Hi != 0 || y1Lo != 0)
            ? ClprBls12381._gt(y1Hi, y1Lo, ClprBls12381.P_HALF_HI, ClprBls12381.P_HALF_LO)
            : ClprBls12381._gt(y0Hi, y0Lo, ClprBls12381.P_HALF_HI, ClprBls12381.P_HALF_LO);
        if (largest != (flags & 1 == 1)) revert BlsSignatureEncoding();
    }

    function _call(address pc, bytes memory input, uint256 outLen) private view returns (bytes memory res) {
        bool ok;
        (ok, res) = pc.staticcall(input);
        if (!ok || res.length != outLen) revert BlsPrecompileFailed();
    }

    function _isZero(bytes memory data) private pure returns (bool z) {
        z = true;
        for (uint256 i = 0; i < data.length; i += 32) {
            bytes32 w;
            assembly ("memory-safe") {
                w := mload(add(add(data, 0x20), i))
            }
            if (w != 0) return false;
        }
    }
}
