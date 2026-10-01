// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprBeaconBls} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconBls.sol";

/// @title AlpenglowCert
/// @notice Verifies Solana Alpenglow (SIMD-0326) consensus certificates on an EVM with EIP-2537.
///
/// Every format rule below was read from Agave `master` @ 6638e56 (1 Oct 2026):
///   - `votor-messages/src/wire.rs` `VotePayloadToSign`: the signed bytes are the wincode encoding
///     `tag:u8 ‖ slot:u64 LE ‖ [block_id:32] ‖ shred_version:u16 LE`, tags Notar=1, Finalize=2,
///     Skip=3, NotarFallback=4, SkipFallback=5, Genesis=6.
///   - `bls-cert-verify/src/cert_verify.rs` `verify_certificate`: Notarize, FinalizeFast, Finalize and
///     Genesis certificates sign a single payload (base2 bitmap); FinalizeFast reuses the *Notar*
///     payload. The signer stake must satisfy `signed / total >= threshold` (exact u128 fraction).
///   - `votor-messages/src/certificate.rs` thresholds: Notarize 60%, Finalize 60%, FinalizeFast 80%;
///     `migration.rs` GENESIS_VOTE_THRESHOLD 82%.
///   - `solana-signer-store` base2 bitmap: `0x00 ‖ nbits:u16 LE ‖ ceil(nbits/8) bytes`, bit i of the
///     payload is rank i (LSB first); unused high bits MUST be zero. Builders truncate the bitmap
///     after the last signer (`aggregate_accumulator.rs`), so ranks >= nbits did not sign.
///   - `solana-bls-signatures`: min-pubkey-size BLS (pubkeys in G1, signatures in G2), hash-to-curve
///     DST `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` — Ethereum's ciphersuite.
///   - `runtime/src/epoch_stakes.rs` `BLSPubkeyToRankMap::new`: rank = position after sorting the
///     epoch's staked vote accounts that carry a BLS key by stake descending, ties by compressed BLS
///     key ascending; duplicate BLS keys / node ids are dropped; `total_stake` sums only ranked entries.
///
/// Finality (`votor-messages/src/finalized_slot.rs`, SIMD-0326 "Finality"): a block is finalized by a
/// FinalizeFast certificate, or by a Notarize certificate for the block plus a Finalize certificate
/// for its slot. A Genesis certificate (82%) finalizes the Alpenglow genesis block at migration.
///
/// The epoch's rank map is committed as a keccak Merkle tree (see {leafHash}); the verifier never
/// learns it from Solana (vote-account state is not provable) — it is supplied under the caller's
/// trust anchor. Aggregation is by explicit signers or by complement (`aggregate − non-signers`),
/// whichever is shorter, each entry Merkle-proven.
library AlpenglowCert {
    // ── Vote payload tags (wire.rs VotePayloadToSign) ──────────────────────────
    uint8 internal constant TAG_NOTAR = 1;
    uint8 internal constant TAG_FINALIZE = 2;
    uint8 internal constant TAG_GENESIS = 6;

    // ── Finality proof kinds ──────────────────────────────────────────────────
    uint8 internal constant KIND_FAST_FINALIZE = 1; // one 80% Notar-payload aggregate
    uint8 internal constant KIND_SLOW_FINALIZE = 2; // 60% Notar aggregate + 60% Finalize aggregate
    uint8 internal constant KIND_GENESIS = 3; // one 82% Genesis-payload aggregate

    uint256 internal constant PCT_NOTAR = 60;
    uint256 internal constant PCT_FINALIZE = 60;
    uint256 internal constant PCT_FAST = 80;
    uint256 internal constant PCT_GENESIS = 82;

    /// @dev Alpenglow admits at most 2,000 validators (SIMD-0326 VAT); the tree depth is capped at 11.
    uint256 internal constant MAX_VALIDATORS = 2048;
    uint256 internal constant MAX_DEPTH = 11;

    // BLS12-381 base field modulus p, split as (hi 16 bytes, lo 32 bytes).
    uint256 private constant P_HI = 0x1a0111ea397fe69a4b1ba7b6434bacd7;
    uint256 private constant P_LO = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

    /// @notice One epoch's ranked validator set. `root` commits to the ranked entries ({leafHash}),
    ///         `aggregatePubkey` is Σ of all `size` keys (EIP-2537 G1, 128 bytes).
    struct EpochSet {
        uint64 epoch;
        uint64 firstSlot;
        uint64 lastSlot;
        uint16 shredVersion;
        uint16 size;
        uint8 depth;
        uint64 totalStake;
        bytes32 root;
        bytes aggregatePubkey;
    }

    /// @notice One ranked validator, proven against {EpochSet.root} at index `rank`.
    struct SetEntry {
        uint16 rank;
        bytes32 voteAccount;
        uint64 stake;
        bytes pubkey; // 128-byte EIP-2537 G1
        bytes32[] proof;
    }

    /// @notice One BLS aggregate over a single payload. `entries` are the signers (complement=false)
    ///         or the non-signers (complement=true), strictly increasing by rank.
    struct Aggregate {
        bytes signature; // 256-byte EIP-2537 G2
        bytes bitmap; // solana-signer-store base2
        bool complement;
        SetEntry[] entries;
    }

    /// @notice A finality proof for `(slot, blockId)`. FAST/GENESIS use `aggregates[0]`; SLOW uses
    ///         `aggregates[0]` (Notar) and `aggregates[1]` (Finalize).
    struct FinalityProof {
        uint8 kind;
        uint64 slot;
        bytes32 blockId;
        Aggregate[] aggregates;
    }

    error UnknownProofKind(uint8 kind);
    error WrongAggregateCount();
    error SlotOutsideEpoch(uint64 slot, uint64 firstSlot, uint64 lastSlot);
    error BadEpochSet();
    error BitmapUnsupportedEncoding();
    error BitmapMalformed();
    error BitmapTooLong(uint256 nbits, uint256 size);
    error EntriesNotSorted();
    error EntryRankOutOfRange(uint256 rank);
    error EntryBitMismatch(uint256 rank);
    error EntryCountMismatch(uint256 got, uint256 want);
    error EntryProofInvalid(uint256 rank);
    error InsufficientStake(uint256 signed, uint256 total, uint256 pct);
    error PointPrecompileFailed();

    // ── Public entry points ─────────────────────────────────────────────────

    /// @notice Revert unless `p` finalizes `(p.slot, p.blockId)` under `set`. Returns the lowest
    ///         signer-stake numerator observed (for logging/tests).
    function verifyFinality(FinalityProof memory p, EpochSet memory set) internal view returns (uint256 minSigned) {
        requireWellFormed(set);
        if (p.slot < set.firstSlot || p.slot > set.lastSlot) {
            revert SlotOutsideEpoch(p.slot, set.firstSlot, set.lastSlot);
        }
        if (p.kind == KIND_FAST_FINALIZE) {
            if (p.aggregates.length != 1) revert WrongAggregateCount();
            minSigned = verifyAggregate(
                p.aggregates[0], set, payload(TAG_NOTAR, p.slot, p.blockId, true, set.shredVersion), PCT_FAST
            );
        } else if (p.kind == KIND_SLOW_FINALIZE) {
            if (p.aggregates.length != 2) revert WrongAggregateCount();
            uint256 a = verifyAggregate(
                p.aggregates[0], set, payload(TAG_NOTAR, p.slot, p.blockId, true, set.shredVersion), PCT_NOTAR
            );
            uint256 b = verifyAggregate(
                p.aggregates[1], set, payload(TAG_FINALIZE, p.slot, bytes32(0), false, set.shredVersion), PCT_FINALIZE
            );
            minSigned = a < b ? a : b;
        } else if (p.kind == KIND_GENESIS) {
            if (p.aggregates.length != 1) revert WrongAggregateCount();
            minSigned = verifyAggregate(
                p.aggregates[0], set, payload(TAG_GENESIS, p.slot, p.blockId, true, set.shredVersion), PCT_GENESIS
            );
        } else {
            revert UnknownProofKind(p.kind);
        }
    }

    /// @notice `VotePayloadToSign` wincode bytes (43 bytes with a block id, 11 without).
    function payload(uint8 tag, uint64 slot, bytes32 blockId, bool withBlock, uint16 shredVersion)
        internal
        pure
        returns (bytes memory)
    {
        bytes8 slotLe = _le64(slot);
        bytes2 svLe = bytes2(uint16((shredVersion >> 8) | (shredVersion << 8)));
        return
            withBlock
                ? abi.encodePacked(bytes1(tag), slotLe, blockId, svLe)
                : abi.encodePacked(bytes1(tag), slotLe, svLe);
    }

    /// @notice Leaf of the ranked-set tree: keccak256(rank:u16 ‖ voteAccount:32 ‖ stake:u64 ‖ pubkey:128).
    function leafHash(uint16 rank, bytes32 voteAccount, uint64 stake, bytes memory pubkey)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(rank, voteAccount, stake, pubkey));
    }

    /// @notice keccak256 of the ABI encoding — the value a trust anchor stores for an epoch set.
    function setHash(EpochSet memory set) internal pure returns (bytes32) {
        return keccak256(abi.encode(set));
    }

    function requireWellFormed(EpochSet memory set) internal pure {
        if (
            set.size == 0 || set.size > MAX_VALIDATORS || set.depth > MAX_DEPTH || (uint256(1) << set.depth) < set.size
                || set.totalStake == 0 || set.aggregatePubkey.length != 128 || set.firstSlot > set.lastSlot
        ) revert BadEpochSet();
    }

    // ── Aggregate verification ───────────────────────────────────────────────

    /// @notice Verify one aggregate over `message` and the stake threshold `pct`. Returns signed stake.
    function verifyAggregate(Aggregate memory agg, EpochSet memory set, bytes memory message, uint256 pct)
        internal
        view
        returns (uint256 signedStake)
    {
        (uint256 nbits, uint256 popcount) = _decodeBitmap(agg.bitmap, set.size);
        uint256 n = agg.entries.length;
        uint256 want = agg.complement ? uint256(set.size) - popcount : popcount;
        if (n != want) revert EntryCountMismatch(n, want);

        bytes memory apk = agg.complement ? set.aggregatePubkey : new bytes(128); // infinity = all zero
        uint256 entryStake;
        uint256 prev;
        for (uint256 i = 0; i < n; i++) {
            SetEntry memory e = agg.entries[i];
            uint256 r = e.rank;
            if (i > 0 && r <= prev) revert EntriesNotSorted();
            prev = r;
            if (r >= set.size) revert EntryRankOutOfRange(r);
            bool bit = r < nbits && _bit(agg.bitmap, r);
            if (bit == agg.complement) revert EntryBitMismatch(r);
            if (!_verifyMerkle(leafHash(e.rank, e.voteAccount, e.stake, e.pubkey), e.proof, r, set.depth, set.root)) {
                revert EntryProofInvalid(r);
            }
            entryStake += e.stake;
            apk = _g1Add(apk, agg.complement ? _negG1(e.pubkey) : e.pubkey);
        }
        signedStake = agg.complement ? uint256(set.totalStake) - entryStake : entryStake;
        // Fraction(signed, total) >= Fraction(pct, 100)  ⇔  signed·100 >= pct·total (cert_verify.rs).
        if (signedStake * 100 < pct * uint256(set.totalStake)) {
            revert InsufficientStake(signedStake, set.totalStake, pct);
        }
        ClprBeaconBls.verifyAggregate(apk, agg.signature, message);
    }

    // ── Bitmap (solana-signer-store base2) ────────────────────────────────────

    function _decodeBitmap(bytes memory bm, uint256 size) private pure returns (uint256 nbits, uint256 popcount) {
        if (bm.length < 3) revert BitmapMalformed();
        if (uint8(bm[0]) != 0) revert BitmapUnsupportedEncoding(); // Base3 never carries a finality cert
        nbits = uint256(uint8(bm[1])) | (uint256(uint8(bm[2])) << 8);
        if (nbits > size) revert BitmapTooLong(nbits, size);
        if (bm.length - 3 != (nbits + 7) / 8) revert BitmapMalformed();
        uint256 rem = nbits % 8;
        if (rem != 0 && (uint8(bm[bm.length - 1]) >> rem) != 0) revert BitmapMalformed();
        for (uint256 i = 3; i < bm.length; i++) {
            uint8 b = uint8(bm[i]);
            while (b != 0) {
                b &= b - 1;
                popcount++;
            }
        }
    }

    function _bit(bytes memory bm, uint256 i) private pure returns (bool) {
        return (uint8(bm[3 + (i >> 3)]) >> (i & 7)) & 1 == 1;
    }

    // ── Merkle (keccak, power-of-two tree, zero-padded leaves) ────────────────

    function _verifyMerkle(bytes32 leaf, bytes32[] memory proof, uint256 index, uint8 depth, bytes32 root)
        private
        pure
        returns (bool)
    {
        if (proof.length != depth) return false;
        bytes32 h = leaf;
        for (uint256 i = 0; i < depth; i++) {
            h = (index >> i) & 1 == 0
                ? keccak256(abi.encodePacked(h, proof[i]))
                : keccak256(abi.encodePacked(proof[i], h));
        }
        return h == root;
    }

    // ── G1 helpers (EIP-2537 encoding: pad16‖x48‖pad16‖y48) ─────────────────

    /// @dev BLS12_G1ADD (0x0b, 375 gas). Inputs are on-curve checked by the precompile; the final
    ///      aggregate is subgroup-checked by the pairing precompile.
    function _g1Add(bytes memory a, bytes memory b) private view returns (bytes memory out) {
        out = new bytes(128);
        bool ok;
        assembly ("memory-safe") {
            let buf := mload(0x40)
            mcopy(buf, add(a, 0x20), 128)
            mcopy(add(buf, 128), add(b, 0x20), 128)
            ok := staticcall(gas(), 0x0b, buf, 256, add(out, 0x20), 128)
            if iszero(eq(returndatasize(), 128)) { ok := 0 }
        }
        if (!ok) revert PointPrecompileFailed();
    }

    /// @dev −(x, y) = (x, p − y); the point at infinity (all zero) is its own negation.
    function _negG1(bytes memory pt) private pure returns (bytes memory out) {
        if (pt.length != 128) revert PointPrecompileFailed();
        out = new bytes(128);
        uint256 yHi;
        uint256 yLo;
        assembly ("memory-safe") {
            mcopy(add(out, 0x20), add(pt, 0x20), 64) // x unchanged
            yHi := mload(add(pt, 0x60))
            yLo := mload(add(pt, 0x80))
        }
        if (yHi == 0 && yLo == 0) {
            // infinity (or y = 0, which is not on the curve) — leave y = 0
            return out;
        }
        uint256 lo;
        uint256 hi;
        unchecked {
            lo = P_LO - yLo;
            hi = P_HI - yHi - (yLo > P_LO ? 1 : 0);
        }
        assembly ("memory-safe") {
            mstore(add(out, 0x60), hi)
            mstore(add(out, 0x80), lo)
        }
    }

    function _le64(uint64 v) private pure returns (bytes8) {
        uint64 r = 0;
        for (uint256 i = 0; i < 8; i++) {
            r = (r << 8) | (v & 0xff);
            v >>= 8;
        }
        return bytes8(r);
    }
}
