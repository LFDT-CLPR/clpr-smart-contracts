// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";

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
    // Domain separation tag for Ethereum beacon chain BLS signatures (ETH2 spec §BLS).
    bytes internal constant BLS_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    // r - 1, where r is the BLS12-381 subgroup order. As a G1MSM scalar this negates a point
    // ((r-1)·P = -P), used to subtract the non-participants from the full-committee aggregate.
    uint256 internal constant R_MINUS_1 = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000;

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
            ok := staticcall(gas(), 0x0b, dst, 256, dst, 128) // 0x0b = ClprBls12381.BLS12_G1ADD
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
        // entirely. The PAIRING_CHECK below still subgroup-checks the aggregate (EIP-2537).
        bytes memory participantsAggregate =
            nonParticipants.length == 0 ? aggregatePubkey : _aggregateG1Complement(aggregatePubkey, nonParticipants);
        if (_isZero(participantsAggregate) || _isZero(signature)) revert BlsSignatureInvalid();
        bytes memory hashMsg = hashToG2(signingRoot);
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
            mcopy(dst, add(aggregate, 0x20), 128)
            mstore(add(dst, 128), 1)
        }
        for (uint256 i = 0; i < n; i++) {
            bytes memory pk = nonParticipants[i];
            if (pk.length != 128) revert InvalidPubkeyLength();
            uint256 offset = (i + 1) * 160;
            assembly ("memory-safe") {
                let dst := add(add(input, 0x20), offset)
                mcopy(dst, add(pk, 0x20), 128)
                mstore(add(dst, 128), R_MINUS_1)
            }
        }
        return ClprBls12381.g1Msm(input);
    }

    // ── Hash-to-G2 ───────────────────────────────────────────────────────────

    /// @dev Hash `signingRoot` to a G2 point per RFC 9380 / ETH2 spec.
    ///      Exposed as `internal` so tests can construct a self-consistent signature `H(m)`.
    function hashToG2(bytes32 signingRoot) internal view returns (bytes memory) {
        return ClprBls12381.hashToG2(abi.encodePacked(signingRoot), BLS_DST);
    }

    // ── Pairing ──────────────────────────────────────────────────────────────

    /// @dev Pairing check: e(aggPubkey, H(msg)) * e(-G1_GEN, sig) == GT_identity.
    function _verifyPairing(bytes memory aggPubkey, bytes memory sig, bytes memory hashMsg) private view {
        bytes memory input = abi.encodePacked(
            aggPubkey, // 128 bytes G1
            hashMsg, // 256 bytes G2
            ClprBls12381.G1_GENERATOR_NEG, // 128 bytes G1
            sig // 256 bytes G2
        );
        if (!ClprBls12381.pairing(input)) revert BlsSignatureInvalid();
    }
}
