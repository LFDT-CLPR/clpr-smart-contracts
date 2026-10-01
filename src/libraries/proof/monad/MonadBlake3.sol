// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title MonadBlake3
/// @notice BLAKE3 for the Monad verifier: the raw compression function, the standard 32-byte hash
///         (any input length, multi-chunk tree), and the MIP-8 storage-page commitment.
/// @dev Monad uses BLAKE3 in two places the verifier must reproduce:
///        1. the consensus block id: `BlockId = blake3(rlp(ConsensusBlockHeader))`
///           (monad-bft `monad-consensus-types/src/block.rs` `get_id`, `HasherType = Blake3Hash`);
///        2. the MIP-8 page commitment (ISMC) stored in every storage-trie leaf
///           (monad `category/execution/monad/db/storage_page.cpp` `page_commit`).
///
///      The 16-word BLAKE3 state is held as four 256-bit "rows", each carrying four 32-bit words in
///      64-bit lanes (word k of the row in lane k, lane 0 most significant). The column and diagonal
///      quarter-rounds then run on all four columns at once; 64-bit lanes leave room for the carry of
///      a 3-term 32-bit sum, and every result is masked back to 32 bits.
library MonadBlake3 {
    error PageNotCanonical();

    uint256 internal constant CHUNK_START = 1;
    uint256 internal constant CHUNK_END = 2;
    uint256 internal constant PARENT = 4;
    uint256 internal constant ROOT = 8;
    uint256 internal constant DERIVE_KEY_MATERIAL = 64;

    /// @dev Lane-packed BLAKE3 IV: row 0 = IV[0..4], row 1 = IV[4..8].
    uint256 internal constant IV_LO = 0x000000006a09e66700000000bb67ae85000000003c6ef37200000000a54ff53a;
    uint256 internal constant IV_HI = 0x00000000510e527f000000009b05688c000000001f83d9ab000000005be0cd19;

    /// @dev MIP-8 pair-leaf key: LEAF_IV = compress(IV, "ultra_merkle_pair_leaf_domain___" || 0^32,
    ///      counter 0, len 64, DERIVE_KEY_MATERIAL)[0..8], lane-packed. Recomputed in the test suite.
    uint256 internal constant LEAF_IV_LO = 0x00000000f457c1a400000000a61e3d2b0000000015d500b3000000006e129c09;
    uint256 internal constant LEAF_IV_HI = 0x000000000df9f0b200000000b644582d00000000eccbb536000000005ca12152;

    // ── Compression ───────────────────────────────────────────────────────────

    /// @dev Compress one 64-byte block at memory `blockPtr` (bytes past `blockLen` MUST be zero) under
    ///      chaining value (`cv0`, `cv1`) and return the new chaining value (first 8 output words).
    function compress(uint256 cv0, uint256 cv1, uint256 blockPtr, uint64 counter, uint256 blockLen, uint256 flags)
        internal
        pure
        returns (uint256 o0, uint256 o1)
    {
        assembly ("memory-safe") {
            let M := 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff

            function bswap32x8(x) -> y {
                y := or(
                    shl(8, and(x, 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)),
                    and(shr(8, x), 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)
                )
                y := or(
                    shl(16, and(y, 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff)),
                    and(shr(16, y), 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff)
                )
            }
            function rotr(x, n, mask) -> y {
                y := and(or(shr(n, x), shl(sub(32, n), x)), mask)
            }
            function rotl256(x, k) -> y {
                y := or(shl(k, x), shr(sub(256, k), x))
            }
            function sched(r) -> s {
                switch r
                case 0 { s := 0x000102030405060708090a0b0c0d0e0f }
                case 1 { s := 0x0206030a0700040d010b0c05090e0f08 }
                case 2 { s := 0x03040a0c0d02070e060509000b0f0801 }
                case 3 { s := 0x0a070c090e030d0f04000b0205080106 }
                case 4 { s := 0x0c0d090b0f0a0e080702050300010604 }
                case 5 { s := 0x090e0b05080c0f010d03000a02060407 }
                default { s := 0x0b0f0500010908060e0a020c0304070d }
            }
            // Pack message words s[k], s[k+2], s[k+4], s[k+6] into lanes 0..3.
            function vec(mp, s, k) -> v {
                v := or(
                    or(
                        shl(192, mload(add(mp, shl(5, byte(add(16, k), s))))),
                        shl(128, mload(add(mp, shl(5, byte(add(18, k), s)))))
                    ),
                    or(
                        shl(64, mload(add(mp, shl(5, byte(add(20, k), s))))),
                        mload(add(mp, shl(5, byte(add(22, k), s))))
                    )
                )
            }
            function g(a, b, c, d, mx, my, mask) -> a2, b2, c2, d2 {
                a := and(add(add(a, b), mx), mask)
                d := rotr(xor(d, a), 16, mask)
                c := and(add(c, d), mask)
                b := rotr(xor(b, c), 12, mask)
                a := and(add(add(a, b), my), mask)
                d := rotr(xor(d, a), 8, mask)
                c := and(add(c, d), mask)
                b := rotr(xor(b, c), 7, mask)
                a2 := a
                b2 := b
                c2 := c
                d2 := d
            }

            // Unpack the 16 little-endian message words into a 512-byte scratch area (past the free
            // memory pointer; nothing is allocated while it is in use).
            let mp := mload(0x40)
            {
                let w0 := bswap32x8(mload(blockPtr))
                let w1 := bswap32x8(mload(add(blockPtr, 32)))
                for { let j := 0 } lt(j, 8) { j := add(j, 1) } {
                    let sh := sub(224, shl(5, j))
                    mstore(add(mp, shl(5, j)), and(shr(sh, w0), 0xffffffff))
                    mstore(add(mp, shl(5, add(j, 8))), and(shr(sh, w1), 0xffffffff))
                }
            }

            let r0 := cv0
            let r1 := cv1
            let r2 := IV_LO
            let r3 :=
                or(or(shl(192, and(counter, 0xffffffff)), shl(128, shr(32, counter))), or(shl(64, blockLen), flags))
            for { let r := 0 } lt(r, 7) { r := add(r, 1) } {
                let s := sched(r)
                // Columns, then diagonals (rows 1..3 lane-rotated by 1..3), on all four lanes at once.
                r0, r1, r2, r3 := g(r0, r1, r2, r3, vec(mp, s, 0), vec(mp, s, 1), M)
                r1 := rotl256(r1, 64)
                r2 := rotl256(r2, 128)
                r3 := rotl256(r3, 192)
                r0, r1, r2, r3 := g(r0, r1, r2, r3, vec(mp, s, 8), vec(mp, s, 9), M)
                r1 := rotl256(r1, 192)
                r2 := rotl256(r2, 128)
                r3 := rotl256(r3, 64)
            }
            o0 := xor(r0, r2)
            o1 := xor(r1, r3)
        }
    }

    /// @dev Lane-packed chaining value → the 32 output bytes (words little-endian).
    function cvToBytes32(uint256 c0, uint256 c1) internal pure returns (bytes32 out) {
        assembly ("memory-safe") {
            function squeeze(x) -> y {
                y := or(
                    or(shl(96, and(shr(192, x), 0xffffffff)), shl(64, and(shr(128, x), 0xffffffff))),
                    or(shl(32, and(shr(64, x), 0xffffffff)), and(x, 0xffffffff))
                )
            }
            let y := or(shl(128, squeeze(c0)), squeeze(c1))
            y := or(
                shl(8, and(y, 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)),
                and(shr(8, y), 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)
            )
            out := or(
                shl(16, and(y, 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff)),
                and(shr(16, y), 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff)
            )
        }
    }

    // ── Standard hash ─────────────────────────────────────────────────────────

    /// @notice BLAKE3-256 of `data` (unkeyed). Supports multi-chunk inputs (the 1024-byte chunk tree).
    function hash(bytes memory data) internal pure returns (bytes32) {
        uint256 len = data.length;
        uint256 nChunks = len == 0 ? 1 : (len + 1023) / 1024;
        // Zeroed 64-byte buffer for partial final blocks / parent blocks.
        bytes memory buf = new bytes(64);
        uint256 bufPtr;
        uint256 dataPtr;
        assembly ("memory-safe") {
            bufPtr := add(buf, 0x20)
            dataPtr := add(data, 0x20)
        }
        if (nChunks == 1) {
            (uint256 a, uint256 b) = _chunk(dataPtr, len, 0, bufPtr, true);
            return cvToBytes32(a, b);
        }
        // CV stack (lane-packed pairs); depth ≤ log2(nChunks) + 1.
        uint256[] memory st = new uint256[](2 * 64);
        uint256 sp;
        for (uint256 ci = 0; ci + 1 < nChunks; ++ci) {
            // forge-lint: disable-next-line(unsafe-typecast)
            (uint256 c0, uint256 c1) = _chunk(dataPtr + ci * 1024, 1024, uint64(ci), bufPtr, false);
            uint256 total = ci + 1;
            while (total & 1 == 0) {
                sp -= 2;
                (c0, c1) = _parent(st[sp], st[sp + 1], c0, c1, bufPtr, 0);
                total >>= 1;
            }
            st[sp] = c0;
            st[sp + 1] = c1;
            sp += 2;
        }
        uint256 lastOff = (nChunks - 1) * 1024;
        // forge-lint: disable-next-line(unsafe-typecast)
        (uint256 l0, uint256 l1) = _chunk(dataPtr + lastOff, len - lastOff, uint64(nChunks - 1), bufPtr, false);
        while (sp > 2) {
            sp -= 2;
            (l0, l1) = _parent(st[sp], st[sp + 1], l0, l1, bufPtr, 0);
        }
        (l0, l1) = _parent(st[0], st[1], l0, l1, bufPtr, ROOT);
        return cvToBytes32(l0, l1);
    }

    /// @dev Chain the blocks of one chunk (≤ 1024 bytes at `ptr`); the final block gets CHUNK_END and,
    ///      for a single-chunk input, ROOT.
    function _chunk(uint256 ptr, uint256 len, uint64 counter, uint256 bufPtr, bool isRoot)
        private
        pure
        returns (uint256 c0, uint256 c1)
    {
        c0 = IV_LO;
        c1 = IV_HI;
        uint256 nBlocks = len == 0 ? 1 : (len + 63) / 64;
        for (uint256 bi = 0; bi + 1 < nBlocks; ++bi) {
            (c0, c1) = compress(c0, c1, ptr + bi * 64, counter, 64, bi == 0 ? CHUNK_START : 0);
        }
        uint256 off = (nBlocks - 1) * 64;
        uint256 lastLen = len - off;
        assembly ("memory-safe") {
            mstore(bufPtr, 0)
            mstore(add(bufPtr, 32), 0)
            mcopy(bufPtr, add(ptr, off), lastLen)
        }
        uint256 flags = (nBlocks == 1 ? CHUNK_START : 0) | CHUNK_END | (isRoot ? ROOT : 0);
        (c0, c1) = compress(c0, c1, bufPtr, counter, lastLen, flags);
    }

    function _parent(uint256 l0, uint256 l1, uint256 r0, uint256 r1, uint256 bufPtr, uint256 extraFlags)
        private
        pure
        returns (uint256, uint256)
    {
        bytes32 lb = cvToBytes32(l0, l1);
        bytes32 rb = cvToBytes32(r0, r1);
        assembly ("memory-safe") {
            mstore(bufPtr, lb)
            mstore(add(bufPtr, 32), rb)
        }
        return compress(IV_LO, IV_HI, bufPtr, 0, 64, PARENT | extraFlags);
    }

    // ── MIP-8 page commitment ──────────────────────────────────────────────────

    /// @notice MIP-8 Induced-Subtree Merkle Commitment of a 128-slot storage page.
    /// @param bitmap Bit i set iff slot offset i is non-zero.
    /// @param values The non-zero slot values in ascending offset order (one per set bit).
    /// @dev Reverts with {PageNotCanonical} unless `values.length == popcount(bitmap)` and every value
    ///      is non-zero (a zero slot is absent from a page, so a zero entry would let a prover hide a
    ///      slot behind a set bit).
    function pageCommit(uint128 bitmap, bytes32[] memory values) internal pure returns (bytes32) {
        bytes memory buf = new bytes(96);
        uint256 bufPtr;
        assembly ("memory-safe") {
            bufPtr := add(buf, 0x20)
        }
        // Seal block: slot bitmap as 16 little-endian bytes, then (if non-empty) the 32-byte root.
        bytes32 bmLe = _le128(bitmap);
        if (bitmap == 0) {
            if (values.length != 0) revert PageNotCanonical();
            assembly ("memory-safe") {
                mstore(bufPtr, bmLe)
                mstore(add(bufPtr, 32), 0)
            }
            (uint256 e0, uint256 e1) = compress(IV_LO, IV_HI, bufPtr, 0, 16, CHUNK_START | CHUNK_END | ROOT);
            return cvToBytes32(e0, e1);
        }

        // Phase 1 — leaves: one per pair (2i, 2i+1) with at least one non-zero slot.
        bytes32[64] memory scratch;
        uint256 pairBm;
        {
            uint256 vi;
            for (uint256 i = 0; i < 64; ++i) {
                uint256 two = (uint256(bitmap) >> (2 * i)) & 3;
                if (two == 0) continue;
                bytes32 left;
                bytes32 right;
                if (two & 1 != 0) {
                    if (vi >= values.length) revert PageNotCanonical();
                    left = values[vi++];
                    if (left == bytes32(0)) revert PageNotCanonical();
                }
                if (two & 2 != 0) {
                    if (vi >= values.length) revert PageNotCanonical();
                    right = values[vi++];
                    if (right == bytes32(0)) revert PageNotCanonical();
                }
                assembly ("memory-safe") {
                    mstore(bufPtr, left)
                    mstore(add(bufPtr, 32), right)
                }
                (uint256 h0, uint256 h1) = compress(LEAF_IV_LO, LEAF_IV_HI, bufPtr, 0, 64, DERIVE_KEY_MATERIAL);
                scratch[i] = cvToBytes32(h0, h1);
                pairBm |= uint256(1) << i;
            }
            if (vi != values.length) revert PageNotCanonical();
        }

        // Phase 2 — bitmap-driven sibling merges, six levels; singletons carry up.
        for (uint256 level = 0; level < 6 && _popcount(pairBm) > 1; ++level) {
            uint256 prev = 0xff;
            for (uint256 pos = 0; pos < 64; ++pos) {
                if ((pairBm >> pos) & 1 == 0) continue;
                if (prev != 0xff && (prev >> (level + 1)) == (pos >> (level + 1)) && (prev >> level) & 1 == 0) {
                    bytes32 l = scratch[prev];
                    bytes32 r = scratch[pos];
                    assembly ("memory-safe") {
                        mstore(bufPtr, l)
                        mstore(add(bufPtr, 32), r)
                    }
                    (uint256 m0, uint256 m1) = compress(IV_LO, IV_HI, bufPtr, 0, 64, CHUNK_START | CHUNK_END);
                    scratch[prev] = cvToBytes32(m0, m1);
                    pairBm &= ~(uint256(1) << pos);
                    prev = 0xff;
                } else {
                    prev = pos;
                }
            }
        }
        uint256 rootIdx;
        while ((pairBm >> rootIdx) & 1 == 0) {
            ++rootIdx;
        }

        // Phase 3 — seal.
        bytes32 root = scratch[rootIdx];
        assembly ("memory-safe") {
            mstore(bufPtr, bmLe)
            mstore(add(bufPtr, 16), root)
            mstore(add(bufPtr, 48), 0)
        }
        (uint256 s0, uint256 s1) = compress(IV_LO, IV_HI, bufPtr, 0, 48, CHUNK_START | CHUNK_END | ROOT);
        return cvToBytes32(s0, s1);
    }

    /// @dev `x` as 16 little-endian bytes, left-aligned in a word (bytes 16..32 zero).
    function _le128(uint128 x) private pure returns (bytes32 out) {
        uint256 y = x;
        uint256 r;
        for (uint256 i = 0; i < 16; ++i) {
            r |= ((y >> (8 * i)) & 0xff) << (248 - 8 * i);
        }
        out = bytes32(r);
    }

    function _popcount(uint256 x) private pure returns (uint256 c) {
        while (x != 0) {
            x &= x - 1;
            ++c;
        }
    }
}
