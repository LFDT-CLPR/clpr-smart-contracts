// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title ClprBlake3
/// @notice BLAKE3 (unkeyed, 32-byte output) per the BLAKE3 specification and its reference
///         implementation (github.com/BLAKE3-team/BLAKE3, reference_impl.rs). Mixin hashes snapshot
///         and transaction payloads with it (`crypto.Blake3Hash`), and the EVM has no precompile.
/// @dev Arbitrary-length input: 1024-byte chunks of 64-byte blocks, chunk chaining values merged
///      into the binary tree with the reference implementation's lazy CV stack. Words are
///      little-endian 32-bit. Checked against the official test vectors and noble-hashes in
///      ClprBlake3.t.sol.
library ClprBlake3 {
    uint256 private constant CHUNK_START = 1;
    uint256 private constant CHUNK_END = 2;
    uint256 private constant PARENT = 4;
    uint256 private constant ROOT = 8;
    /// @dev Message word order per round: round r reads m[SCHED[16r + i]] (the permutation applied r times).
    bytes private constant SCHED =
        hex"000102030405060708090a0b0c0d0e0f0206030a0700040d010b0c05090e0f0803040a0c0d02070e060509000b0f08010a070c090e030d0f04000b02050801060c0d090b0f0a0e080702050300010604090e0b05080c0f010d03000a020604070b0f0500010908060e0a020c0304070d";

    /// @notice BLAKE3-256 of `data`.
    function hash(bytes memory data) internal pure returns (bytes32 out) {
        uint256 len = data.length;
        uint256 nChunks = len == 0 ? 1 : (len + 1023) / 1024;
        // CV stack: at most log2(nChunks)+1 entries.
        uint256[8][] memory stack = new uint256[8][](64);
        uint256 sp;
        for (uint256 c = 0; c + 1 < nChunks; ++c) {
            uint256[8] memory cv = _chunkCv(data, c, 0);
            // Merge completed subtrees: while the number of chunks so far is even.
            uint256 total = c + 1;
            while (total & 1 == 0) {
                --sp;
                cv = _parentCv(stack[sp], cv, 0);
                total >>= 1;
            }
            stack[sp++] = cv;
        }
        if (sp == 0) {
            uint256[8] memory root = _chunkCv(data, nChunks - 1, ROOT);
            return _words(root);
        }
        uint256[8] memory right = _chunkCv(data, nChunks - 1, 0);
        while (sp > 0) {
            --sp;
            right = _parentCv(stack[sp], right, sp == 0 ? ROOT : 0);
        }
        return _words(right);
    }

    /// @dev Chaining value of chunk `c`; `rootFlag` is OR-ed into its last block (single-chunk input).
    function _chunkCv(bytes memory data, uint256 c, uint256 rootFlag) private pure returns (uint256[8] memory cv) {
        cv = _iv();
        uint256 start = c * 1024;
        uint256 end = start + 1024;
        if (end > data.length) end = data.length;
        uint256 n = end - start;
        uint256 nBlocks = n == 0 ? 1 : (n + 63) / 64;
        uint256[16] memory m;
        for (uint256 b = 0; b < nBlocks; ++b) {
            uint256 off = start + b * 64;
            uint256 blen = end - off;
            if (blen > 64) blen = 64;
            _loadBlock(data, off, blen, m);
            uint256 flags = (b == 0 ? CHUNK_START : 0) | (b + 1 == nBlocks ? CHUNK_END | rootFlag : 0);
            cv = _compress(cv, m, c, blen, flags);
        }
    }

    function _parentCv(uint256[8] memory l, uint256[8] memory r, uint256 rootFlag)
        private
        pure
        returns (uint256[8] memory)
    {
        uint256[16] memory m;
        for (uint256 i = 0; i < 8; ++i) {
            m[i] = l[i];
            m[i + 8] = r[i];
        }
        return _compress(_iv(), m, 0, 64, PARENT | rootFlag);
    }

    function _iv() private pure returns (uint256[8] memory iv) {
        iv = [uint256(0x6A09E667), 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];
    }

    /// @dev Read a (zero-padded) 64-byte block as 16 little-endian words.
    function _loadBlock(bytes memory data, uint256 off, uint256 blen, uint256[16] memory m) private pure {
        assembly ("memory-safe") {
            let p := add(add(data, 0x20), off)
            for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                let w := 0
                for { let j := 0 } lt(j, 4) { j := add(j, 1) } {
                    let idx := add(mul(i, 4), j)
                    if lt(idx, blen) { w := or(w, shl(mul(j, 8), byte(0, mload(add(p, idx))))) }
                }
                mstore(add(m, mul(i, 0x20)), w)
            }
        }
    }

    function _words(uint256[8] memory cv) private pure returns (bytes32 out) {
        uint256 acc;
        for (uint256 i = 0; i < 8; ++i) {
            uint256 w = cv[i];
            // little-endian word -> 4 output bytes
            uint256 le = ((w & 0xff) << 24) | ((w & 0xff00) << 8) | ((w >> 8) & 0xff00) | (w >> 24);
            acc |= le << (224 - 32 * i);
        }
        out = bytes32(acc);
    }

    /// @dev The BLAKE3 compression function, truncated to the 8-word chaining value. The 4x4 state
    ///      is held as four row words with one 32-bit value per 64-bit lane (lane i at bits 64i), so each
    ///      G step mixes all four columns (or, after rotating rows 1-3 by 1-3 lanes, all four diagonals)
    ///      at once. Lanes have 32 bits of headroom, so the adds never carry into a neighbour, and a
    ///      32-bit lane rotate is two shifts and a mask. The message permutation is applied by reading
    ///      words through a per-round schedule table (`SCHED`).
    function _compress(uint256[8] memory cv, uint256[16] memory m, uint256 counter, uint256 blen, uint256 flags)
        private
        pure
        returns (uint256[8] memory out)
    {
        bytes memory sched = SCHED;
        assembly ("memory-safe") {
            function rot(x, n) -> r {
                // 32-bit rotate right in every 64-bit lane
                r := and(
                    or(shr(n, x), shl(sub(32, n), x)),
                    0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff
                )
            }
            function g4(a, b, c, d, x, y) -> a2, b2, c2, d2 {
                let L := 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff
                a2 := and(add(add(a, b), x), L)
                d2 := rot(xor(d, a2), 16)
                c2 := and(add(c, d2), L)
                b2 := rot(xor(b, c2), 12)
                a2 := and(add(add(a2, b2), y), L)
                d2 := rot(xor(d2, a2), 8)
                c2 := and(add(c2, d2), L)
                b2 := rot(xor(b2, c2), 7)
            }
            // pack four message words, chosen by schedule bytes at s, s+2, s+4, s+6, into lanes 0..3
            function pk(mp, s) -> r {
                r := or(
                    or(
                        mload(add(mp, shl(5, byte(0, mload(s))))),
                        shl(64, mload(add(mp, shl(5, byte(0, mload(add(s, 2)))))))
                    ),
                    or(
                        shl(128, mload(add(mp, shl(5, byte(0, mload(add(s, 4))))))),
                        shl(192, mload(add(mp, shl(5, byte(0, mload(add(s, 6)))))))
                    )
                )
            }
            let r0 :=
                or(
                    or(mload(cv), shl(64, mload(add(cv, 0x20)))),
                    or(shl(128, mload(add(cv, 0x40))), shl(192, mload(add(cv, 0x60))))
                )
            let r1 :=
                or(
                    or(mload(add(cv, 0x80)), shl(64, mload(add(cv, 0xa0)))),
                    or(shl(128, mload(add(cv, 0xc0))), shl(192, mload(add(cv, 0xe0))))
                )
            let r2 := 0xa54ff53a000000003c6ef37200000000bb67ae85000000006a09e667
            let r3 :=
                or(
                    or(and(counter, 0xffffffff), shl(64, and(shr(32, counter), 0xffffffff))),
                    or(shl(128, blen), shl(192, flags))
                )
            let sp := add(sched, 0x20)
            for { let rr := 0 } lt(rr, 7) { rr := add(rr, 1) } {
                let s := add(sp, shl(4, rr))
                r0, r1, r2, r3 := g4(r0, r1, r2, r3, pk(m, s), pk(m, add(s, 1)))
                // diagonalise: row k rotated left by k lanes
                r1 := or(shr(64, r1), shl(192, r1))
                r2 := or(shr(128, r2), shl(128, r2))
                r3 := or(shr(192, r3), shl(64, r3))
                r0, r1, r2, r3 := g4(r0, r1, r2, r3, pk(m, add(s, 8)), pk(m, add(s, 9)))
                r1 := or(shl(64, r1), shr(192, r1))
                r2 := or(shl(128, r2), shr(128, r2))
                r3 := or(shl(192, r3), shr(64, r3))
            }
            let lo := xor(r0, r2)
            let hi := xor(r1, r3)
            let W := 0xffffffff
            mstore(out, and(lo, W))
            mstore(add(out, 0x20), and(shr(64, lo), W))
            mstore(add(out, 0x40), and(shr(128, lo), W))
            mstore(add(out, 0x60), and(shr(192, lo), W))
            mstore(add(out, 0x80), and(hi, W))
            mstore(add(out, 0xa0), and(shr(64, hi), W))
            mstore(add(out, 0xc0), and(shr(128, hi), W))
            mstore(add(out, 0xe0), and(shr(192, hi), W))
        }
    }
}
