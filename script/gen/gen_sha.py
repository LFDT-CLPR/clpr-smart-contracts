#!/usr/bin/env python3
"""Generates src/libraries/crypto/Sha512t256.sol and Sha256Midstate.sol.

Design (kept deliberately small for solc via-IR: a fully unrolled compression made solc use >10 GB):
- one round per loop iteration; the eight working variables live in a rolling memory buffer V, so
  round i reads V[i..i+7] (h..a) and writes only V[i+4] (new e) and V[i+8] (new a);
- a w-bit rotation is one shift of the doubled word x‖x;
- K, W and V live in unreserved scratch memory past the free-memory pointer.
"""
import os

K512 = """428a2f98d728ae22 7137449123ef65cd b5c0fbcfec4d3b2f e9b5dba58189dbbc 3956c25bf348b538 59f111f1b605d019 923f82a4af194f9b ab1c5ed5da6d8118
d807aa98a3030242 12835b0145706fbe 243185be4ee4b28c 550c7dc3d5ffb4e2 72be5d74f27b896f 80deb1fe3b1696b1 9bdc06a725c71235 c19bf174cf692694
e49b69c19ef14ad2 efbe4786384f25e3 0fc19dc68b8cd5b5 240ca1cc77ac9c65 2de92c6f592b0275 4a7484aa6ea6e483 5cb0a9dcbd41fbd4 76f988da831153b5
983e5152ee66dfab a831c66d2db43210 b00327c898fb213f bf597fc7beef0ee4 c6e00bf33da88fc2 d5a79147930aa725 06ca6351e003826f 142929670a0e6e70
27b70a8546d22ffc 2e1b21385c26c926 4d2c6dfc5ac42aed 53380d139d95b3df 650a73548baf63de 766a0abb3c77b2a8 81c2c92e47edaee6 92722c851482353b
a2bfe8a14cf10364 a81a664bbc423001 c24b8b70d0f89791 c76c51a30654be30 d192e819d6ef5218 d69906245565a910 f40e35855771202a 106aa07032bbd1b8
19a4c116b8d2d0c8 1e376c085141ab53 2748774cdf8eeb99 34b0bcb5e19b48a8 391c0cb3c5c95a63 4ed8aa4ae3418acb 5b9cca4f7763e373 682e6ff3d6b2b8a3
748f82ee5defb2fc 78a5636f43172f60 84c87814a1f0ab72 8cc702081a6439ec 90befffa23631e28 a4506cebde82bde9 bef9a3f7b2c67915 c67178f2e372532b
ca273eceea26619c d186b8c721c0c207 eada7dd6cde0eb1e f57d4f7fee6ed178 06f067aa72176fba 0a637dc5a2c898a6 113f9804bef90dae 1b710b35131c471b
28db77f523047d84 32caab7b40c72493 3c9ebe0a15c9bebc 431d67c49c100d4c 4cc5d4becb3e42b6 597f299cfc657e2a 5fcb6fab3ad6faec 6c44198c4a475817""".split()
K256 = """428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5 d807aa98 12835b01 243185be 550c7dc3
72be5d74 80deb1fe 9bdc06a7 c19bf174 e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da
983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967 27b70a85 2e1b2138 4d2c6dfc 53380d13
650a7354 766a0abb 81c2c92e 92722c85 a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070
19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3 748f82ee 78a5636f 84c87814 8cc70208
90befffa a4506ceb bef9a3f7 c67178f2""".split()
assert len(K512) == 80 and len(K256) == 64

def compress_fn(wb, rounds, ks, sig0, sig1, S0, S1):
    """Yul `compress(blk, w)`; w = scratch base. Layout: W[rounds] | K[rounds] | V[rounds+8] | state[8]."""
    R = rounds * 32
    bpw = wb // 8
    return f"""            function compress(blk, w) {{
                let M := {hex((1 << wb) - 1)}
                for {{ let i := 0 }} lt(i, 16) {{ i := add(i, 1) }} {{
                    mstore(add(w, shl(5, i)), shr({256 - wb}, mload(add(blk, mul(i, {bpw})))))
                }}
                for {{ let q := add(w, 0x200) }} lt(q, add(w, {hex(R)})) {{ q := add(q, 0x20) }} {{
                    let x := mload(sub(q, 0x1e0)) // W[i-15]
                    let y := mload(sub(q, 0x40)) // W[i-2]
                    let s0 := xor(xor(shr({sig0[0]}, or(x, shl({wb}, x))), shr({sig0[1]}, or(x, shl({wb}, x)))), shr({sig0[2]}, x))
                    let s1 := xor(xor(shr({sig1[0]}, or(y, shl({wb}, y))), shr({sig1[1]}, or(y, shl({wb}, y)))), shr({sig1[2]}, y))
                    mstore(q, and(add(add(s0, s1), add(mload(sub(q, 0xe0)), mload(sub(q, 0x200)))), M))
                }}
                // V[0..7] = h, g, f, e, d, c, b, a (the chaining state, reversed)
                let v := add(w, {hex(2 * R)})
                let st := add(v, {hex(R + 256)})
                for {{ let i := 0 }} lt(i, 8) {{ i := add(i, 1) }} {{
                    mstore(add(v, shl(5, i)), mload(add(st, shl(5, sub(7, i)))))
                }}
                for {{ let i := 0 }} lt(i, {rounds}) {{ i := add(i, 1) }} {{
                    let p := add(v, shl(5, i))
                    let t1 := 0
                    {{
                        let e := mload(add(p, 0x60))
                        let f := mload(add(p, 0x40))
                        let g := mload(add(p, 0x20))
                        let ee := or(e, shl({wb}, e))
                        t1 :=
                            add(
                                add(mload(p), xor(xor(shr({S1[0]}, ee), shr({S1[1]}, ee)), shr({S1[2]}, ee))),
                                add(xor(g, and(e, xor(f, g))), add(mload(add(w, shl(5, i))), mload(add(w, add({hex(R)}, shl(5, i))))))
                            )
                    }}
                    mstore(add(p, 0x80), and(add(mload(add(p, 0x80)), t1), M))
                    let a := mload(add(p, 0xe0))
                    let b := mload(add(p, 0xc0))
                    let c := mload(add(p, 0xa0))
                    let aa := or(a, shl({wb}, a))
                    mstore(
                        add(p, 0x100),
                        and(add(t1, add(xor(xor(shr({S0[0]}, aa), shr({S0[1]}, aa)), shr({S0[2]}, aa)), or(and(a, b), and(c, or(a, b))))), M)
                    )
                }}
                // After the last round V[rounds..rounds+7] = h, g, f, e, d, c, b, a.
                let last := add(v, {hex(R)})
                for {{ let i := 0 }} lt(i, 8) {{ i := add(i, 1) }} {{
                    let sp := add(st, shl(5, i))
                    mstore(sp, and(add(mload(sp), mload(add(last, shl(5, sub(7, i))))), M))
                }}
            }}"""

def kstores(ks, rounds):
    return "\n".join(f"            mstore(add(w, {hex(rounds * 32 + 32 * i)}), 0x{k})" for i, k in enumerate(ks))

HDR = "// SPDX-License-Identifier: Apache-2.0\npragma solidity ^0.8.28;\n\n"

sha512 = HDR + f'''/// @title Sha512t256
/// @notice SHA-512/256 (FIPS 180-4 §5.3.6.2): the SHA-512 compression function with its own initial
///         hash value, truncated to the first 256 bits. Stacks uses it for block hashes, the signer
///         signature hash, index block ids and every MARF node hash.
/// @dev Generated by script/gen/gen_sha.py (edit the generator). One round per loop iteration with the
///      working variables in a rolling memory buffer (round i reads V[i..i+7], writes V[i+4] and
///      V[i+8]); a 64-bit rotation is one shift of the doubled word `x ‖ x`. K, W and V live in
///      unreserved scratch memory past the free-memory pointer. A fully unrolled variant was tried
///      and abandoned: solc via-IR needed more than 10 GB to compile it.
library Sha512t256 {{
    function hash(bytes memory data) internal pure returns (bytes32 out) {{
        assembly ("memory-safe") {{
            // Scratch: W[80] | K[80] | V[88] | state[8] | tail[256 B]
{compress_fn(64, 80, K512, (1, 8, 7), (19, 61, 6), (28, 34, 39), (14, 18, 41))}

            let w := mload(0x40)
{kstores(K512, 80)}
            let s := add(w, {hex(80 * 32 * 3 + 256)})
            mstore(s, 0x22312194fc2bf72c)
            mstore(add(s, 0x20), 0x9f555fa3c84c64c2)
            mstore(add(s, 0x40), 0x2393b86b6f53b151)
            mstore(add(s, 0x60), 0x963877195940eabd)
            mstore(add(s, 0x80), 0x96283ee2a88effe3)
            mstore(add(s, 0xa0), 0xbe5e1e2553863992)
            mstore(add(s, 0xc0), 0x2b0199fc2c85b8aa)
            mstore(add(s, 0xe0), 0x0eb72ddc81c52ca2)

            let len := mload(data)
            let src := add(data, 0x20)
            let full := and(len, not(127))
            for {{ let off := 0 }} lt(off, full) {{ off := add(off, 128) }} {{
                compress(add(src, off), w)
            }}
            // Tail: the remaining (len mod 128) bytes, 0x80, zero padding and the 128-bit bit length.
            let t := add(s, 0x100)
            for {{ let i := 0 }} lt(i, 0x100) {{ i := add(i, 0x20) }} {{
                mstore(add(t, i), 0)
            }}
            let rem := sub(len, full)
            mcopy(t, add(src, full), rem)
            mstore8(add(t, rem), 0x80)
            let tl := 128
            if gt(rem, 111) {{ tl := 256 }}
            mstore(add(t, sub(tl, 0x20)), or(mload(add(t, sub(tl, 0x20))), shl(3, len)))
            compress(t, w)
            if eq(tl, 256) {{ compress(add(t, 128), w) }}
            out := or(or(shl(192, mload(s)), shl(128, mload(add(s, 0x20)))), or(shl(64, mload(add(s, 0x40))), mload(add(s, 0x60))))
        }}
    }}
}}
'''

sha256 = HDR + f'''/// @title Sha256Midstate
/// @notice SHA-256 that can resume from a chaining state ("midstate"). The SHA-256 precompile only
///         hashes complete messages, but Rootstock's merged-mining proof ships the Bitcoin coinbase
///         as `byteCount ‖ midstate ‖ tail`: the first `byteCount` bytes are already compressed into
///         the midstate and only the tail is public. Resuming from that state is the only way to
///         recompute the coinbase txid (RSKj `ProofOfWorkRule.isValid`).
/// @dev Generated by script/gen/gen_sha.py (edit the generator). Same structure as {{Sha512t256}}:
///      one round per iteration over a rolling memory buffer, rotations as shifts of `x ‖ x`.
library Sha256Midstate {{
    /// @dev SHA-256 initial hash value H(0), packed H0‖…‖H7 (big-endian words).
    bytes32 internal constant IV = 0x6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19;

    error Sha256BadByteCount();

    /// @notice Finish a SHA-256 computation: `state` is the chaining value after `byteCount` bytes
    ///         (a multiple of 64), `tail` the remaining message bytes. Returns the digest.
    function resume(bytes32 state, uint256 byteCount, bytes memory tail) internal pure returns (bytes32 out) {{
        if (byteCount % 64 != 0 || byteCount > type(uint64).max / 8 - tail.length) revert Sha256BadByteCount();
        assembly ("memory-safe") {{
            // Scratch: W[64] | K[64] | V[72] | state[8] | tail[128 B]
{compress_fn(32, 64, K256, (7, 18, 3), (17, 19, 10), (2, 13, 22), (6, 11, 25))}

            let w := mload(0x40)
{kstores(K256, 64)}
            let s := add(w, {hex(64 * 32 * 3 + 256)})
            for {{ let i := 0 }} lt(i, 8) {{ i := add(i, 1) }} {{
                mstore(add(s, shl(5, i)), and(shr(sub(224, shl(5, i)), state), 0xffffffff))
            }}
            let len := mload(tail)
            let src := add(tail, 0x20)
            let full := and(len, not(63))
            for {{ let off := 0 }} lt(off, full) {{ off := add(off, 64) }} {{
                compress(add(src, off), w)
            }}
            let t := add(s, 0x100)
            for {{ let i := 0 }} lt(i, 0x80) {{ i := add(i, 0x20) }} {{
                mstore(add(t, i), 0)
            }}
            let rem := sub(len, full)
            mcopy(t, add(src, full), rem)
            mstore8(add(t, rem), 0x80)
            let tl := 64
            if gt(rem, 55) {{ tl := 128 }}
            // 64-bit big-endian bit length of the WHOLE message (midstate bytes included).
            mstore(add(t, sub(tl, 0x20)), or(mload(add(t, sub(tl, 0x20))), shl(3, add(byteCount, len))))
            compress(t, w)
            if eq(tl, 128) {{ compress(add(t, 64), w) }}
            for {{ let i := 0 }} lt(i, 8) {{ i := add(i, 1) }} {{
                out := or(out, shl(sub(224, shl(5, i)), mload(add(s, shl(5, i)))))
            }}
        }}
    }}
}}
'''
root = os.path.join(os.path.dirname(__file__), "..", "..", "src", "libraries", "crypto")
open(os.path.join(root, "Sha512t256.sol"), "w").write(sha512)
open(os.path.join(root, "Sha256Midstate.sol"), "w").write(sha256)
