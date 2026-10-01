// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title WavesBls
/// @notice BLS12-381 verification for Waves block endorsements (Deterministic Finality, feature 25),
///         on the EIP-2537 precompiles. Waves signs with the "basic" min-pk scheme of `blst`
///         (wavesplatform/Waves `crypto/bls/BlsUtils.scala`):
///           public key G1, signature G2, hash-to-G2 with DST `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`.
///         An aggregated endorsement over one message verifies as
///           e(Σ endorser keys, H(m)) · e(−G1, σ) = 1.
/// @dev Points are EIP-2537 uncompressed (G1 128 bytes, G2 256 bytes). The relayer decompresses them;
///      this library never decompresses or compresses a point. The pairing precompile checks that
///      every input is on the curve and in the prime-order subgroup.
library WavesBls {
    address internal constant BLS12_G1ADD = address(0x0b);
    address internal constant BLS12_G2ADD = address(0x0d);
    address internal constant BLS12_PAIRING_CHECK = address(0x0f);
    address internal constant BLS12_MAP_FP2_TO_G2 = address(0x11);
    address internal constant MODEXP = address(0x05);

    uint256 internal constant G1_LENGTH = 128;
    uint256 internal constant G2_LENGTH = 256;

    /// @dev BLS12-381 base-field modulus p (48 bytes), for hash_to_field reduction.
    bytes internal constant FIELD_MODULUS =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
    /// @dev −G1 (the negated generator), EIP-2537 encoding. Same value as `ClprBeaconBls.G1_GENERATOR_NEG`.
    bytes internal constant G1_GENERATOR_NEG =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";
    /// @dev Waves' ciphersuite (BlsUtils.BlsDomainSeparationTag).
    bytes internal constant DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

    error BlsPrecompileCallFailed();
    error BlsSignatureInvalid();
    error InvalidPointLength();

    /// @dev Sum of G1 points (each 128 bytes), via BLS12_G1ADD.
    function addG1(bytes memory a, bytes memory b) internal view returns (bytes memory out) {
        if (a.length != G1_LENGTH || b.length != G1_LENGTH) revert InvalidPointLength();
        (bool ok, bytes memory res) = BLS12_G1ADD.staticcall(abi.encodePacked(a, b));
        if (!ok || res.length != G1_LENGTH) revert BlsPrecompileCallFailed();
        return res;
    }

    /// @dev Reverts unless `signature` is a valid aggregate of `aggregateKey`'s owners over `message`.
    function verify(bytes memory aggregateKey, bytes memory message, bytes memory signature) internal view {
        if (aggregateKey.length != G1_LENGTH || signature.length != G2_LENGTH) revert InvalidPointLength();
        bytes memory input = abi.encodePacked(aggregateKey, hashToG2(message), G1_GENERATOR_NEG, signature);
        (bool ok, bytes memory res) = BLS12_PAIRING_CHECK.staticcall(input);
        if (!ok) revert BlsPrecompileCallFailed();
        // forge-lint: disable-next-line(unsafe-typecast)
        if (res.length != 32 || uint256(bytes32(res)) != 1) revert BlsSignatureInvalid();
    }

    /// @dev RFC 9380 hash_to_curve for G2 (expand_message_xmd SHA-256, two Fp2 elements, map, add).
    ///      Cofactor clearing is part of BLS12_MAP_FP2_TO_G2 (EIP-2537).
    function hashToG2(bytes memory message) internal view returns (bytes memory) {
        bytes memory u = expandMessageXmd(message, DST, 256);
        bytes memory q0 = _map(_fp2(u, 0));
        bytes memory q1 = _map(_fp2(u, 128));
        (bool ok, bytes memory res) = BLS12_G2ADD.staticcall(abi.encodePacked(q0, q1));
        if (!ok || res.length != G2_LENGTH) revert BlsPrecompileCallFailed();
        return res;
    }

    /// @dev expand_message_xmd(msg, DST, len) per RFC 9380 §5.3.1 (b_in_bytes 32, s_in_bytes 64).
    function expandMessageXmd(bytes memory message, bytes memory dst, uint256 len)
        internal
        pure
        returns (bytes memory out)
    {
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes memory dstPrime = abi.encodePacked(dst, uint8(dst.length));
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes32 b0 = sha256(abi.encodePacked(new bytes(64), message, uint16(len), uint8(0), dstPrime));
        bytes32 bi = sha256(abi.encodePacked(b0, uint8(1), dstPrime));
        out = new bytes(len);
        uint256 ell = (len + 31) / 32;
        for (uint256 i = 1; i <= ell; i++) {
            if (i > 1) {
                // forge-lint: disable-next-line(unsafe-typecast)
                bi = sha256(abi.encodePacked(b0 ^ bi, uint8(i), dstPrime));
            }
            assembly ("memory-safe") {
                mstore(add(add(out, 0x20), mul(sub(i, 1), 32)), bi)
            }
        }
    }

    function _map(bytes memory fp2) private view returns (bytes memory) {
        (bool ok, bytes memory res) = BLS12_MAP_FP2_TO_G2.staticcall(fp2);
        if (!ok || res.length != G2_LENGTH) revert BlsPrecompileCallFailed();
        return res;
    }

    /// @dev Fp2 element `c0 ‖ c1` (EIP-2537, 64-byte slots) from 128 expanded bytes at `off`.
    function _fp2(bytes memory u, uint256 off) private view returns (bytes memory fp2) {
        fp2 = abi.encodePacked(new bytes(16), _reduce(u, off), new bytes(16), _reduce(u, off + 64));
    }

    /// @dev 64 big-endian bytes mod p via MODEXP (base^1 mod p), 48-byte result.
    function _reduce(bytes memory u, uint256 off) private view returns (bytes memory) {
        bytes memory base = new bytes(64);
        assembly ("memory-safe") {
            mcopy(add(base, 0x20), add(add(u, 0x20), off), 64)
        }
        (bool ok, bytes memory res) =
            MODEXP.staticcall(abi.encodePacked(uint256(64), uint256(1), uint256(48), base, uint8(1), FIELD_MODULUS));
        if (!ok || res.length != 48) revert BlsPrecompileCallFailed();
        return res;
    }
}
