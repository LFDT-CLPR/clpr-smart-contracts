// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title TezosBls
/// @notice Verifies a Tezos tz4 aggregate attestation signature with the EIP-2537 precompiles.
///
/// Tezos BLS (octez src/lib_crypto/bls.ml) is BLS12-381 "MinPk" with the proof-of-possession
/// ciphersuite `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`: public keys in G1, signatures in G2,
/// and the signed message is `watermark ‖ bytes` (not pre-hashed). An `attestations_aggregate`
/// carries one signature from every committee member over the same BLS-mode attestation; members
/// that attest DAL shards add their companion key weighted by a BLAKE2b-derived scalar
/// (`Dal_dependent_signing`). The aggregate key is therefore one multi-scalar multiplication.
///
/// All points use the EIP-2537 uncompressed encoding (G1 128 bytes, G2 256 bytes) and are supplied
/// by the relayer; the caller binds every G1 key to the context key it stands for.
library TezosBls {
    address internal constant BLS12_G1MSM = address(0x0c);
    address internal constant BLS12_G2ADD = address(0x0d);
    address internal constant BLS12_PAIRING_CHECK = address(0x0f);
    address internal constant BLS12_MAP_FP2_TO_G2 = address(0x11);
    address internal constant MODEXP = address(0x05);

    bytes internal constant DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    bytes internal constant FIELD_MODULUS =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

    /// @dev −G1 generator, EIP-2537 encoding.
    bytes internal constant G1_GENERATOR_NEG =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";

    error BlsPrecompileFailed();
    error BlsSignatureInvalid();
    error BlsInputLength();

    /// @notice Check `e(Σ scalar_i · P_i, H(msg)) == e(G1, signature)`.
    /// @param msmInput  EIP-2537 G1MSM input: k × (128-byte point ‖ 32-byte scalar). The precompile
    ///                  checks every point is on the curve and in the subgroup.
    /// @param signature 256-byte uncompressed G2 signature (subgroup-checked by the pairing precompile).
    function verifyAggregate(bytes memory msmInput, bytes memory signature, bytes memory message) internal view {
        if (msmInput.length == 0 || msmInput.length % 160 != 0 || signature.length != 256) revert BlsInputLength();
        (bool ok, bytes memory aggregate) = BLS12_G1MSM.staticcall(msmInput);
        if (!ok || aggregate.length != 128) revert BlsPrecompileFailed();
        bytes memory h = hashToG2(message);
        (ok, h) = BLS12_PAIRING_CHECK.staticcall(abi.encodePacked(aggregate, h, G1_GENERATOR_NEG, signature));
        if (!ok || h.length != 32) revert BlsPrecompileFailed();
        // casting is safe: the 32-byte precompile result, length checked above.
        // forge-lint: disable-next-line(unsafe-typecast)
        if (uint256(bytes32(h)) != 1) revert BlsSignatureInvalid();
    }

    /// @notice hash_to_curve(msg) for G2 (RFC 9380, expand_message_xmd with SHA-256), 256-byte point.
    function hashToG2(bytes memory message) internal view returns (bytes memory) {
        bytes memory u = _expandMessageXmd(message, 256);
        bytes memory q0 = _map(_fp2(u, 0));
        bytes memory q1 = _map(_fp2(u, 128));
        (bool ok, bytes memory r) = BLS12_G2ADD.staticcall(abi.encodePacked(q0, q1));
        if (!ok || r.length != 256) revert BlsPrecompileFailed();
        return r;
    }

    function _map(bytes memory fp2) private view returns (bytes memory) {
        (bool ok, bytes memory r) = BLS12_MAP_FP2_TO_G2.staticcall(fp2);
        if (!ok || r.length != 256) revert BlsPrecompileFailed();
        return r;
    }

    /// @dev expand_message_xmd(msg, DST, len) — RFC 9380 §5.3.1 with SHA-256 (b = 32, s = 64).
    function _expandMessageXmd(bytes memory message, uint256 len) private pure returns (bytes memory out) {
        bytes memory dstPrime = abi.encodePacked(DST, uint8(DST.length));
        // casting is safe: len is 256 and DST is 43 bytes.
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes32 b0 = sha256(abi.encodePacked(new bytes(64), message, uint16(len), uint8(0), dstPrime));
        out = new bytes(len);
        bytes32 bi = sha256(abi.encodePacked(b0, uint8(1), dstPrime));
        uint256 ell = (len + 31) / 32;
        for (uint256 i = 1; i <= ell; i++) {
            // casting is safe: i <= ell = 8.
            // forge-lint: disable-next-line(unsafe-typecast)
            if (i > 1) bi = sha256(abi.encodePacked(b0 ^ bi, uint8(i), dstPrime));
            assembly ("memory-safe") {
                mstore(add(add(out, 0x20), mul(sub(i, 1), 32)), bi)
            }
        }
    }

    /// @dev Two 64-byte chunks of `u` at `off`, each reduced mod p into a 64-byte EIP-2537 Fp slot.
    function _fp2(bytes memory u, uint256 off) private view returns (bytes memory fp2) {
        fp2 = new bytes(128);
        for (uint256 k = 0; k < 2; k++) {
            bytes memory chunk = new bytes(64);
            assembly ("memory-safe") {
                mcopy(add(chunk, 0x20), add(add(u, 0x20), add(off, mul(k, 64))), 64)
            }
            (bool ok, bytes memory r) = MODEXP.staticcall(
                abi.encodePacked(uint256(64), uint256(1), uint256(48), chunk, uint8(1), FIELD_MODULUS)
            );
            if (!ok || r.length != 48) revert BlsPrecompileFailed();
            assembly ("memory-safe") {
                mcopy(add(add(fp2, 0x20), add(mul(k, 64), 16)), add(r, 0x20), 48)
            }
        }
    }
}
