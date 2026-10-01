// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title IcpBls
/// @notice BLS signatures with the ciphersuite `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_`
///         (signatures in G1, public keys in G2), as used by Internet Computer certificates. Built on
///         the EIP-2537 precompiles:
///
///           0x0b BLS12_G1ADD, 0x0d BLS12_G2ADD, 0x0f BLS12_PAIRING_CHECK, 0x10 BLS12_MAP_FP_TO_G1,
///           0x05 MODEXP (reduction of hash_to_field outputs mod p).
///
///         Points are passed uncompressed in the EIP-2537 encoding (G1: 128 bytes, G2: 256 bytes).
///         The pairing precompile rejects points that are not on the curve or not in the prime-order
///         subgroup, so every signature and key is subgroup-checked by the verification itself.
library IcpBls {
    address internal constant BLS12_G1ADD = address(0x0b);
    address internal constant BLS12_G2ADD = address(0x0d);
    address internal constant BLS12_PAIRING_CHECK = address(0x0f);
    address internal constant BLS12_MAP_FP_TO_G1 = address(0x10);
    address internal constant MODEXP = address(0x05);

    bytes internal constant DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

    bytes internal constant FIELD_MODULUS =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

    /// @dev −G2 generator, EIP-2537 encoding (x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1, 64 bytes each).
    bytes internal constant NEG_G2_GENERATOR =
        hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed";

    uint256 internal constant G1_LEN = 128;
    uint256 internal constant G2_LEN = 256;

    error BlsPrecompileFailed();
    error BadSignature();
    error BadPointLength();
    error KeyEncodingMismatch();

    /// @notice Revert unless `signature` (G1) is a valid signature of `message` under `publicKey` (G2).
    function verify(bytes memory publicKey, bytes memory signature, bytes memory message) internal view {
        if (publicKey.length != G2_LEN || signature.length != G1_LEN) revert BadPointLength();
        bytes memory input = abi.encodePacked(signature, NEG_G2_GENERATOR, hashToG1(message), publicKey);
        (bool ok, bytes memory out) = BLS12_PAIRING_CHECK.staticcall(input);
        if (!ok || out.length != 32) revert BlsPrecompileFailed();
        // casting to 'bytes32' is safe because the length was checked to be 32 above.
        // forge-lint: disable-next-line(unsafe-typecast)
        if (uint256(bytes32(out)) != 1) revert BadSignature();
    }

    /// @notice hash_to_curve for G1 (RFC 9380, `BLS12381G1_XMD:SHA-256_SSWU_RO_`) with {DST}.
    function hashToG1(bytes memory message) internal view returns (bytes memory) {
        bytes memory u = expandMessageXmd(message, DST, 128);
        bytes memory q0 = _mapToG1(_reduce(u, 0));
        bytes memory q1 = _mapToG1(_reduce(u, 64));
        (bool ok, bytes memory sum) = BLS12_G1ADD.staticcall(abi.encodePacked(q0, q1));
        if (!ok || sum.length != G1_LEN) revert BlsPrecompileFailed();
        return sum;
    }

    /// @notice expand_message_xmd (RFC 9380 §5.3.1) with SHA-256; `lenInBytes` ≤ 255 · 32.
    function expandMessageXmd(bytes memory message, bytes memory dst, uint256 lenInBytes)
        internal
        pure
        returns (bytes memory out)
    {
        bytes memory dstPrime = abi.encodePacked(dst, uint8(dst.length));
        uint256 ell = (lenInBytes + 31) / 32;
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes32 b0 = sha256(abi.encodePacked(new bytes(64), message, uint16(lenInBytes), uint8(0), dstPrime));
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
            mstore(out, lenInBytes)
        }
    }

    /// @notice Bind an uncompressed G2 key to its 96-byte compressed (ZCash-format) encoding: the
    ///         compression flag is set, the infinity flag is clear, and the x-coordinate matches.
    /// @dev The y-coordinate is not compared. A point with this x is one of two points ±P; a signature
    ///      valid under −P on a message is the negation of a signature valid under +P on the same
    ///      message, so accepting either point gives the same unforgeability as accepting +P alone.
    ///      Curve membership and the subgroup are enforced by the pairing precompile at use.
    function requireMatchesCompressedG2(bytes memory uncompressed, bytes memory compressed) internal pure {
        if (uncompressed.length != G2_LEN || compressed.length != 96) revert BadPointLength();
        uint8 flags = uint8(compressed[0]);
        if (flags & 0x80 == 0 || flags & 0x40 != 0) revert KeyEncodingMismatch();
        // compressed = x.c1 (48 bytes, top 3 bits are flags) ‖ x.c0 (48 bytes)
        // uncompressed = 16 zero ‖ x.c0 ‖ 16 zero ‖ x.c1 ‖ y...
        for (uint256 i = 0; i < 16; i++) {
            if (uncompressed[i] != 0 || uncompressed[64 + i] != 0) revert KeyEncodingMismatch();
        }
        if (uint8(uncompressed[80]) != flags & 0x1f) revert KeyEncodingMismatch();
        for (uint256 i = 1; i < 48; i++) {
            if (uncompressed[80 + i] != compressed[i]) revert KeyEncodingMismatch();
        }
        for (uint256 i = 0; i < 48; i++) {
            if (uncompressed[16 + i] != compressed[48 + i]) revert KeyEncodingMismatch();
        }
    }

    /// @notice Revert unless `p` is an on-curve G2 point (EIP-2537 G2ADD validates both inputs).
    function requireOnCurveG2(bytes memory p) internal view {
        if (p.length != G2_LEN) revert BadPointLength();
        (bool ok, bytes memory out) = BLS12_G2ADD.staticcall(abi.encodePacked(p, new bytes(G2_LEN)));
        if (!ok || out.length != G2_LEN) revert BlsPrecompileFailed();
    }

    function _mapToG1(bytes memory fp) private view returns (bytes memory out) {
        (bool ok, bytes memory res) = BLS12_MAP_FP_TO_G1.staticcall(fp);
        if (!ok || res.length != G1_LEN) revert BlsPrecompileFailed();
        return res;
    }

    /// @dev u[offset .. offset+64) mod p as a 64-byte EIP-2537 field element (16 zero bytes ‖ 48 bytes).
    function _reduce(bytes memory u, uint256 offset) private view returns (bytes memory) {
        bytes memory base = new bytes(64);
        assembly ("memory-safe") {
            mcopy(add(base, 0x20), add(add(u, 0x20), offset), 64)
        }
        (bool ok, bytes memory r) =
            MODEXP.staticcall(abi.encodePacked(uint256(64), uint256(1), uint256(48), base, uint8(1), FIELD_MODULUS));
        if (!ok || r.length != 48) revert BlsPrecompileFailed();
        return abi.encodePacked(bytes16(0), r);
    }
}
