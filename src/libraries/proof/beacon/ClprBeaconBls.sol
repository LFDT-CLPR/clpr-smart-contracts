// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title ClprBeaconBls
/// @notice Verifies an Ethereum sync-committee BLS aggregate signature using EIP-2537 precompiles.
///
/// Verification algorithm (Ethereum beacon light-client spec):
///   1. The participant aggregate is recovered by COMPLEMENT: `committeeAggregate − Σ(non-signers)`,
///      computed in a single BLS12_G1MSM (the committee aggregate is authenticated upstream). This is
///      ≤ 1/3 of the committee at the 2/3 supermajority, vs the ≥ 2/3 that signed.
///   2. The signing root (sha256(BeaconBlockHeader SSZ hash_tree_root || domain)) is hashed
///      to a G2 point via expand_message_xmd (RFC 9380) + BLS12_MAP_FP2_TO_G2.
///   3. Pairing check: e(aggPubkey, H(msg)) * e(-G1_GEN, sig) == 1
///
/// All inputs use EIP-2537 uncompressed encoding:
///   - G1 point: 128 bytes (two 64-byte big-endian Fp elements)
///   - G2 point: 256 bytes (two 128-byte big-endian Fp2 elements)
///
/// EIP-2537 precompile addresses (Prague/Electra, activated May 2025):
///   0x0c  BLS12_G1MSM         (complement participant aggregation)
///   0x0d  BLS12_G2ADD
///   0x0f  BLS12_PAIRING_CHECK
///   0x11  BLS12_MAP_FP2_TO_G2
library ClprBeaconBls {
    // ── EIP-2537 precompile addresses ────────────────────────────────────────
    address internal constant BLS12_G1ADD = address(0x0b);
    address internal constant BLS12_G1MSM = address(0x0c);
    address internal constant BLS12_G2ADD = address(0x0d);
    address internal constant BLS12_MAP_FP2_TO_G2 = address(0x11);
    address internal constant BLS12_PAIRING_CHECK = address(0x0f);
    address internal constant MODEXP = address(0x05);

    // BLS12-381 base-field modulus p (48 bytes), used to reduce hash_to_field elements mod p.
    bytes internal constant BLS_FIELD_MODULUS =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

    // Negated G1 generator — used in the pairing check as the second G1 input.
    // EIP-2537 format: x || y, each coordinate zero-padded to 64 bytes.
    // x = 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
    // y = p - y_gen = 0x0114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca
    bytes internal constant G1_GENERATOR_NEG =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";

    // Domain separation tag for Ethereum beacon chain BLS signatures (ETH2 spec §BLS).
    bytes internal constant BLS_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    // r - 1, where r is the BLS12-381 subgroup order. As a G1MSM scalar this negates a point
    // ((r-1)·P = -P), used to subtract the non-participants from the full-committee aggregate.
    uint256 internal constant R_MINUS_1 = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000;

    error BlsPrecompileCallFailed();
    error BlsSignatureInvalid();
    error InvalidSignatureLength();
    error InvalidPubkeyLength();
    error BlsPointNotOnCurveG1();

    /// @notice Aggregate and every pubkey needs to lie on the curve.
    ///         It is checked by calling `BLS12_G1ADD` (EIP-2537).
    ///         This precompile validates input. It checks encoding and if both
    ///         of the points provided in input are on the curve. So we can check 2
    ///         points at once. And all that in 375-gas call.
    ///         If any of the points is out of curve - reverts.
    function requireOnCurveG1(bytes[] memory pubkeys, bytes memory aggregatePubkey) internal view {
        bytes memory buf = new bytes(256);
        uint256 n = pubkeys.length;
        uint256 i = 0;
        for (; i + 1 < n; i += 2) {
            _requireOnCurvePairG1(buf, pubkeys[i], pubkeys[i + 1]);
        }
        if (i < n) {
            // Odd key count: the leftover key pairs with the aggregate.
            _requireOnCurvePairG1(buf, pubkeys[i], aggregatePubkey);
        } else {
            // Even key count: the aggregate pairs with the point at infinity (a valid G1ADD input).
            _requireOnCurvePairG1(buf, aggregatePubkey, new bytes(128));
        }
    }

    /// @dev One `BLS12_G1ADD` staticcall validating both 128-byte inputs.
    ///      We dont need the sum (result) for anything, so it's discarded.
    function _requireOnCurvePairG1(bytes memory buf, bytes memory p, bytes memory q) private view {
        if (p.length != 128 || q.length != 128) revert InvalidPubkeyLength();
        bool ok;
        uint256 returned;
        assembly ("memory-safe") {
            let dst := add(buf, 0x20)
            mcopy(dst, add(p, 0x20), 128)
            mcopy(add(dst, 128), add(q, 0x20), 128)
            ok := staticcall(gas(), 0x0b, dst, 256, dst, 128) // 0x0b = BLS12_G1ADD
            returned := returndatasize()
        }
        if (!ok || returned != 128) revert BlsPointNotOnCurveG1();
    }

    /// @notice Verify an aggregate signature via the COMPLEMENT of the participant set. The committee's
    ///         precomputed aggregate (Σ of ALL members, authenticated by the SSZ committee root / config)
    ///         lets the participant aggregate be recovered as `aggregate − Σ(nonParticipants)` in a
    ///         single `BLS12_G1MSM`. At the 2/3 supermajority the non-participants number ≤ 1/3 of the
    ///         committee, so the MSM has `1 + |nonParticipants|` terms instead of `|participants|` —
    ///         roughly halving the dominant MSM cost, and reducing to a single term at full participation.
    /// @param aggregatePubkey   128-byte uncompressed EIP-2537 G1 aggregate of the full committee.
    /// @param nonParticipants   committee members that did NOT sign (128-byte uncompressed G1 each).
    /// @param signature         256-byte uncompressed EIP-2537 G2 aggregate signature.
    function aggregateVerifyComplement(
        bytes memory aggregatePubkey,
        bytes[] memory nonParticipants,
        bytes memory signature,
        bytes32 signingRoot
    ) internal view {
        if (signature.length != 256) revert InvalidSignatureLength();
        if (aggregatePubkey.length != 128) revert InvalidPubkeyLength();
        // Full participation: the participant aggregate IS the committee aggregate, so skip the MSM
        // entirely. The PAIRING_CHECK below still subgroup-checks the aggregate (EIP-2537 §5).
        bytes memory participantsAggregate =
            nonParticipants.length == 0 ? aggregatePubkey : _aggregateG1Complement(aggregatePubkey, nonParticipants);
        if (_isZero(participantsAggregate) || _isZero(signature)) revert BlsSignatureInvalid();
        bytes memory hashMsg = _hashToG2(signingRoot);
        _verifyPairing(participantsAggregate, signature, hashMsg);
    }

    /// @dev Returns true if every byte of `data` is zero. Reads a word at a time:
    /// `data.length` is always a multiple of 32 (0x20) here (128 or 256), so the loop covers the array.
    function _isZero(bytes memory data) private pure returns (bool allZero) {
        assembly ("memory-safe") {
            let len := mload(data)
            let ptr := add(data, 0x20)
            allZero := 1
            for { let i := 0 } lt(i, len) { i := add(i, 0x20) } {
                if gt(mload(add(ptr, i)), 0) {
                    allZero := 0
                    break
                }
            }
        }
    }

    /// @dev `Σ(participants) = aggregate − Σ(nonParticipants)` via one `BLS12_G1MSM`:
    ///      term 0 is `aggregate · 1`, then each non-participant is `pk · (r−1)` (≡ `−pk`). The
    ///      precompile subgroup-checks every input point, including the aggregate. Caller guarantees
    ///      `aggregate.length == 128` and `nonParticipants.length > 0`.
    function _aggregateG1Complement(bytes memory aggregate, bytes[] memory nonParticipants)
        private
        view
        returns (bytes memory)
    {
        uint256 n = nonParticipants.length;
        bytes memory input = new bytes((n + 1) * 160); // (128-byte point || 32-byte scalar) per term
        assembly ("memory-safe") {
            let dst := add(input, 0x20)
            mcopy(dst, add(aggregate, 0x20), 128) // full-committee aggregate
            mstore(add(dst, 128), 1) // scalar = 1
        }
        for (uint256 i = 0; i < n; i++) {
            bytes memory pk = nonParticipants[i];
            if (pk.length != 128) revert InvalidPubkeyLength();
            uint256 offset = (i + 1) * 160;
            assembly ("memory-safe") {
                let dst := add(add(input, 0x20), offset)
                mcopy(dst, add(pk, 0x20), 128) // non-participant pubkey
                mstore(add(dst, 128), R_MINUS_1) // scalar = -1 mod r  (subtracts the point)
            }
        }
        (bool ok, bytes memory res) = BLS12_G1MSM.staticcall(input);
        if (!ok || res.length != 128) revert BlsPrecompileCallFailed();
        return res;
    }

    // ── Hash-to-G2 ───────────────────────────────────────────────────────────

    /// @dev Hash `signingRoot` to a G2 point per RFC 9380 §3 / ETH2 spec:
    ///      expand_message_xmd → two Fp2 elements → BLS12_MAP_FP2_TO_G2 × 2 → BLS12_G2ADD.
    ///      Cofactor clearing is performed inside BLS12_MAP_FP2_TO_G2 (EIP-2537 §5).
    ///      Exposed as `internal` so tests can construct a self-consistent signature `H(m)`.
    function hashToG2(bytes32 signingRoot) internal view returns (bytes memory) {
        return _hashToG2(signingRoot);
    }

    function _hashToG2(bytes32 signingRoot) private view returns (bytes memory) {
        return hashToG2Message(abi.encodePacked(signingRoot));
    }

    /// @dev Same as {hashToG2} for an arbitrary-length message (same DST, `..._POP_`). Used by
    ///      verifiers whose signers sign more than a 32-byte root (PlasmaBFT votes, 104 bytes).
    function hashToG2Message(bytes memory message) internal view returns (bytes memory) {
        // hash_to_field(msg, count=2) for G2: 2 Fp2 elements = 4 Fp elements, each from L=64 bytes
        // reduced mod p (RFC 9380 §5.3, L = ceil((ceil(log2 p) + k) / 8) = 64). So 256 expansion bytes.
        bytes memory expanded = _expandMessageXmd(message, BLS_DST, 256);
        bytes memory q0 = _mapFp2ToG2(_makeFp2(expanded, 0)); // u[0] = (e0, e1) from bytes [0..128)
        bytes memory q1 = _mapFp2ToG2(_makeFp2(expanded, 128)); // u[1] = (e2, e3) from bytes [128..256)
        return _g2Add(q0, q1);
    }

    /// @dev expand_message_xmd(msg, DST, len_in_bytes) per RFC 9380 §5.4.1.
    ///      b_in_bytes = 32 (SHA-256), s_in_bytes = 64.
    function _expandMessageXmd(bytes memory msgBytes, bytes memory dst, uint256 lenInBytes)
        private
        pure
        returns (bytes memory)
    {
        bytes memory dstPrime = abi.encodePacked(dst, bytes1(uint8(dst.length)));
        uint8 ell = uint8((lenInBytes + 31) / 32);
        bytes memory zPad = new bytes(64);
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes memory libStr = abi.encodePacked(bytes2(uint16(lenInBytes)), bytes1(0x00));
        bytes memory b0 = abi.encodePacked(sha256(abi.encodePacked(zPad, msgBytes, libStr, dstPrime)));
        bytes memory uniform = new bytes(lenInBytes);
        bytes memory bi = abi.encodePacked(sha256(abi.encodePacked(b0, bytes1(0x01), dstPrime)));
        _copyBytes(bi, 0, uniform, 0, 32);
        for (uint8 i = 2; i <= ell; i++) {
            bi = abi.encodePacked(sha256(abi.encodePacked(_xor32(b0, bi), bytes1(i), dstPrime)));
            uint256 off = uint256(i - 1) * 32;
            _copyBytes(bi, 0, uniform, off, lenInBytes - off < 32 ? lenInBytes - off : 32);
        }
        return uniform;
    }

    // ── EIP-2537 precompile wrappers ──────────────────────────────────────────

    /// @dev Map an Fp2 element (128 bytes) to a G2 point (256 bytes).
    function _mapFp2ToG2(bytes memory fp2) private view returns (bytes memory out) {
        (bool ok, bytes memory res) = BLS12_MAP_FP2_TO_G2.staticcall(fp2);
        if (!ok || res.length != 256) revert BlsPrecompileCallFailed();
        return res;
    }

    /// @dev Add two G2 points (512 bytes in → 256 bytes out).
    function _g2Add(bytes memory a, bytes memory b) private view returns (bytes memory out) {
        (bool ok, bytes memory res) = BLS12_G2ADD.staticcall(abi.encodePacked(a, b));
        if (!ok || res.length != 256) revert BlsPrecompileCallFailed();
        return res;
    }

    /// @dev Pairing check: e(aggPubkey, H(msg)) * e(-G1_GEN, sig) == GT_identity.
    ///      EIP-2537 PAIRING_CHECK input: [G1_0 || G2_0 || G1_1 || G2_1] (768 bytes total).
    function _verifyPairing(bytes memory aggPubkey, bytes memory sig, bytes memory hashMsg) private view {
        bytes memory input = abi.encodePacked(
            aggPubkey, // 128 bytes G1
            hashMsg, // 256 bytes G2
            G1_GENERATOR_NEG, // 128 bytes G1
            sig // 256 bytes G2
        );
        (bool ok, bytes memory res) = BLS12_PAIRING_CHECK.staticcall(input);
        if (!ok) revert BlsPrecompileCallFailed();
        // EIP-2537 PAIRING_CHECK returns a 32-byte big-endian word: 1 ⇒ product of pairings is the
        // Fp12 identity (success), 0 ⇒ otherwise. The success bit is the *last* byte.
        // forge-lint: disable-next-line(unsafe-typecast)
        if (res.length != 32 || uint256(bytes32(res)) != 1) revert BlsSignatureInvalid();
    }

    // ── Pure helpers ──────────────────────────────────────────────────────────

    /// @dev Build a 128-byte EIP-2537 Fp2 element from `expanded[offset..offset+128]`: two 64-byte
    ///      wide chunks (RFC 9380 L=64), each reduced mod p (OS2IP then `mod p`) into a 48-byte Fp
    ///      coordinate, right-aligned in its 64-byte slot. Order is `c0 || c1` (value = c0 + c1·u).
    function _makeFp2(bytes memory expanded, uint256 offset) private view returns (bytes memory fp2) {
        fp2 = new bytes(128);
        bytes memory c0 = _reduceFp64(expanded, offset); // 48-byte Fp element, < p
        bytes memory c1 = _reduceFp64(expanded, offset + 64);
        for (uint256 i = 0; i < 48; i++) {
            fp2[16 + i] = c0[i]; // c0: bytes [16..64)
            fp2[80 + i] = c1[i]; // c1: bytes [80..128)
        }
    }

    /// @dev Reduce the 64-byte big-endian value `data[offset..offset+64]` mod p via MODEXP (`base^1`),
    ///      returning the 48-byte result. This is RFC 9380's OS2IP-then-reduce for one field element.
    function _reduceFp64(bytes memory data, uint256 offset) private view returns (bytes memory) {
        bytes memory base = new bytes(64);
        assembly ("memory-safe") {
            mcopy(add(base, 0x20), add(add(data, 0x20), offset), 64)
        }
        bytes memory input =
            abi.encodePacked(uint256(64), uint256(1), uint256(48), base, bytes1(0x01), BLS_FIELD_MODULUS);
        (bool ok, bytes memory out) = MODEXP.staticcall(input);
        if (!ok || out.length != 48) revert BlsPrecompileCallFailed();
        return out;
    }

    /// @dev XOR two 32-byte buffers as a single word. Both inputs are exactly 32 bytes.
    function _xor32(bytes memory a, bytes memory b) private pure returns (bytes memory out) {
        out = new bytes(32);
        assembly ("memory-safe") {
            mstore(add(out, 0x20), xor(mload(add(a, 0x20)), mload(add(b, 0x20))))
        }
    }

    /// @dev Copy `len` bytes from `src[srcOff..]` to `dst[dstOff..]` via `mcopy`.
    function _copyBytes(bytes memory src, uint256 srcOff, bytes memory dst, uint256 dstOff, uint256 len) private pure {
        assembly ("memory-safe") {
            mcopy(add(add(dst, 0x20), dstOff), add(add(src, 0x20), srcOff), len)
        }
    }
}
