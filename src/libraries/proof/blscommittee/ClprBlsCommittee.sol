// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title ClprBlsCommittee
/// @notice BLS12-381 helpers for committee-certificate verifiers, built only on the EIP-2537
///         precompiles: RFC 9380 hash-to-curve (expand_message_xmd with SHA-256) into G1 or G2
///         with any domain-separation tag, point aggregation, subgroup checks and the two
///         pairing checks (min-pk: keys in G1 / signatures in G2; min-sig: keys in G2 /
///         signatures in G1).
///
/// @dev Points are carried in the EIP-2537 encoding: G1 = 128 bytes (`pad16‖x‖pad16‖y`), G2 = 256
///      bytes (`x.c0‖x.c1‖y.c0‖y.c1`, each `pad16‖48 bytes`). Keys and signatures always arrive
///      uncompressed from the relayer; nothing here decompresses a point.
///
/// @dev Precompile checks (EIP-2537): ADD checks that inputs are on the curve; MSM and
///      PAIRING_CHECK also check subgroup membership. `requireG1Subgroup`/`requireG2Subgroup` use a
///      one-term MSM with scalar 1 for that check.
library ClprBlsCommittee {
    address internal constant G1ADD = address(0x0b);
    address internal constant G1MSM = address(0x0c);
    address internal constant G2ADD = address(0x0d);
    address internal constant G2MSM = address(0x0e);
    address internal constant PAIRING_CHECK = address(0x0f);
    address internal constant MAP_FP_TO_G1 = address(0x10);
    address internal constant MAP_FP2_TO_G2 = address(0x11);
    address internal constant MODEXP = address(0x05);

    uint256 internal constant G1_LEN = 128;
    uint256 internal constant G2_LEN = 256;

    bytes internal constant FIELD_MODULUS =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

    /// @dev −G1 generator (EIP-2537 encoding).
    bytes internal constant G1_GEN_NEG =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";

    /// @dev −G2 generator (EIP-2537 encoding).
    bytes internal constant G2_GEN_NEG =
        hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed";

    error BlsPrecompileFailed();
    error BlsBadPointLength();
    error BlsSignatureInvalid();
    error BlsNoSigners();

    // ── hash-to-curve (RFC 9380, expand_message_xmd / SHA-256, SSWU via EIP-2537) ─────────────

    /// @notice `hash_to_curve` into G1 (suite `BLS12381G1_XMD:SHA-256_SSWU_RO_` with tag `dst`).
    function hashToG1(bytes memory message, bytes memory dst) internal view returns (bytes memory) {
        bytes memory u = expandMessageXmd(message, dst, 128);
        bytes memory q0 = _call(MAP_FP_TO_G1, abi.encodePacked(new bytes(16), _reduce64(u, 0)), G1_LEN);
        bytes memory q1 = _call(MAP_FP_TO_G1, abi.encodePacked(new bytes(16), _reduce64(u, 64)), G1_LEN);
        return _call(G1ADD, abi.encodePacked(q0, q1), G1_LEN);
    }

    /// @notice `hash_to_curve` into G2 (suite `BLS12381G2_XMD:SHA-256_SSWU_RO_` with tag `dst`).
    function hashToG2(bytes memory message, bytes memory dst) internal view returns (bytes memory) {
        bytes memory u = expandMessageXmd(message, dst, 256);
        bytes memory q0 = _call(MAP_FP2_TO_G2, _fp2(u, 0), G2_LEN);
        bytes memory q1 = _call(MAP_FP2_TO_G2, _fp2(u, 128), G2_LEN);
        return _call(G2ADD, abi.encodePacked(q0, q1), G2_LEN);
    }

    /// @notice expand_message_xmd(msg, DST, len) per RFC 9380 §5.3.1 with SHA-256 (b = 32, s = 64).
    function expandMessageXmd(bytes memory message, bytes memory dst, uint256 len)
        internal
        pure
        returns (bytes memory out)
    {
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes memory dstPrime = abi.encodePacked(dst, uint8(dst.length));
        uint256 ell = (len + 31) / 32;
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes32 b0 = sha256(abi.encodePacked(new bytes(64), message, uint16(len), uint8(0), dstPrime));
        bytes32 bi = sha256(abi.encodePacked(b0, uint8(1), dstPrime));
        out = new bytes(ell * 32);
        assembly ("memory-safe") {
            mstore(add(out, 0x20), bi)
        }
        for (uint256 i = 2; i <= ell; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            bi = sha256(abi.encodePacked(b0 ^ bi, uint8(i), dstPrime));
            assembly ("memory-safe") {
                mstore(add(out, mul(i, 0x20)), bi)
            }
        }
        assembly ("memory-safe") {
            mstore(out, len)
        }
    }

    // ── aggregation and checks ───────────────────────────────────────────────────────────────

    /// @notice Sum of the keys selected by `bitmap` (bit `i` of byte `i / 8`, LSB first) and the
    ///         sum of their weights. `keys` is the concatenation of `n` points of `pointLen` bytes.
    function aggregateByBitmap(bytes memory keys, uint256 pointLen, uint256[] memory weights, bytes memory bitmap)
        internal
        view
        returns (bytes memory agg, uint256 signedWeight)
    {
        uint256 n = weights.length;
        if (keys.length != n * pointLen) revert BlsBadPointLength();
        if (bitmap.length > (n + 7) / 8) revert BlsBadPointLength();
        address add = pointLen == G1_LEN ? G1ADD : G2ADD;
        for (uint256 i = 0; i < n; i++) {
            if (i / 8 >= bitmap.length || (uint8(bitmap[i / 8]) >> (i % 8)) & 1 == 0) continue;
            bytes memory k = slice(keys, i * pointLen, pointLen);
            agg = agg.length == 0 ? k : _call(add, abi.encodePacked(agg, k), pointLen);
            signedWeight += weights[i];
        }
        // Bits past `n` must be clear, so one bitmap has exactly one meaning.
        for (uint256 i = n; i < bitmap.length * 8; i++) {
            if ((uint8(bitmap[i / 8]) >> (i % 8)) & 1 != 0) revert BlsBadPointLength();
        }
        if (agg.length == 0) revert BlsNoSigners();
    }

    /// @notice min-pk check `e(pk, H) == e(G1, sig)` (keys in G1, signatures in G2).
    function verifyMinPk(bytes memory pkG1, bytes memory sigG2, bytes memory hG2) internal view {
        if (pkG1.length != G1_LEN || sigG2.length != G2_LEN || hG2.length != G2_LEN) revert BlsBadPointLength();
        _pairing(abi.encodePacked(pkG1, hG2, G1_GEN_NEG, sigG2));
    }

    /// @notice min-sig check `e(H, pk) == e(sig, G2)` (keys in G2, signatures in G1).
    function verifyMinSig(bytes memory pkG2, bytes memory sigG1, bytes memory hG1) internal view {
        if (pkG2.length != G2_LEN || sigG1.length != G1_LEN || hG1.length != G1_LEN) revert BlsBadPointLength();
        _pairing(abi.encodePacked(hG1, pkG2, sigG1, G2_GEN_NEG));
    }

    /// @notice Revert unless every `pointLen`-byte point in `points` is on the curve and in the
    ///         prime-order subgroup (one-term MSM with scalar 1 per point).
    function requireSubgroup(bytes memory points, uint256 pointLen) internal view {
        if (pointLen != G1_LEN && pointLen != G2_LEN) revert BlsBadPointLength();
        if (points.length % pointLen != 0) revert BlsBadPointLength();
        address msm = pointLen == G1_LEN ? G1MSM : G2MSM;
        for (uint256 off = 0; off < points.length; off += pointLen) {
            _call(msm, abi.encodePacked(slice(points, off, pointLen), uint256(1)), pointLen);
        }
    }

    /// @notice The 48-byte big-endian x coordinate of an EIP-2537 point (G1), or of the `c0`/`c1`
    ///         half of an Fp2 x coordinate (G2, `half` 0 or 1).
    function xCoordinate(bytes memory point, uint256 half) internal pure returns (bytes memory) {
        return slice(point, 16 + half * 64, 48);
    }

    function slice(bytes memory data, uint256 off, uint256 len) internal pure returns (bytes memory out) {
        if (off + len > data.length) revert BlsBadPointLength();
        out = new bytes(len);
        assembly ("memory-safe") {
            mcopy(add(out, 0x20), add(add(data, 0x20), off), len)
        }
    }

    // ── internals ────────────────────────────────────────────────────────────────────────────

    function _pairing(bytes memory input) private view {
        (bool ok, bytes memory res) = PAIRING_CHECK.staticcall(input);
        if (!ok || res.length != 32) revert BlsPrecompileFailed();
        // res is exactly 32 bytes (checked above); the last byte is 1 on success.
        // forge-lint: disable-next-line(unsafe-typecast)
        if (uint256(bytes32(res)) != 1) revert BlsSignatureInvalid();
    }

    function _call(address pre, bytes memory input, uint256 outLen) private view returns (bytes memory) {
        (bool ok, bytes memory res) = pre.staticcall(input);
        if (!ok || res.length != outLen) revert BlsPrecompileFailed();
        return res;
    }

    /// @dev Two 64-byte chunks of `u` from `off`, each reduced mod p → 128-byte EIP-2537 Fp2.
    function _fp2(bytes memory u, uint256 off) private view returns (bytes memory) {
        return abi.encodePacked(new bytes(16), _reduce64(u, off), new bytes(16), _reduce64(u, off + 64));
    }

    /// @dev `u[off..off+64] mod p` as 48 bytes (MODEXP with exponent 1).
    function _reduce64(bytes memory u, uint256 off) private view returns (bytes memory) {
        bytes memory input =
            abi.encodePacked(uint256(64), uint256(1), uint256(48), slice(u, off, 64), uint8(1), FIELD_MODULUS);
        return _call(MODEXP, input, 48);
    }
}
