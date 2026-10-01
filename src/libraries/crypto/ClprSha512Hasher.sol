// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title ClprSha512Hasher
/// @notice SHA-512 (FIPS 180-4) as a stateless contract for chains without a SHA-512 precompile:
///         call it with the message as raw calldata; it returns the 64-byte digest. The XRPL light
///         client hashes dozens of objects per bundle (validations, SHAMap nodes, headers, leaves).
/// @dev One assembly block, compiled with the legacy pipeline and no optimizer (foundry.toml
///      `compilation_restrictions`): via-IR spills the working variables to memory, and the legacy
///      Yul optimizer runs out of stack slots on the unrolled rounds. The eight working variables stay
///      on the stack; rounds are unrolled by eight so the a..h roles rotate by renaming; the K[t] +
///      W[t] schedule is built once per block. About 47k gas per 128-byte block, half the via-IR
///      library's cost inside the size-optimized XRPL contracts. Fixed memory map: 0x80 K (80 words) | 0xa80 K[t]+W[t] (80 words) |
///      0x1480 block (128 bytes) | 0x1500 state (8 words). Checked against Node `crypto` vectors in
///      ClprHashes.t.sol.
contract ClprSha512Hasher {
    fallback() external {
        assembly {
            mstore(0x80, 0x428a2f98d728ae22)
            mstore(0xa0, 0x7137449123ef65cd)
            mstore(0xc0, 0xb5c0fbcfec4d3b2f)
            mstore(0xe0, 0xe9b5dba58189dbbc)
            mstore(0x100, 0x3956c25bf348b538)
            mstore(0x120, 0x59f111f1b605d019)
            mstore(0x140, 0x923f82a4af194f9b)
            mstore(0x160, 0xab1c5ed5da6d8118)
            mstore(0x180, 0xd807aa98a3030242)
            mstore(0x1a0, 0x12835b0145706fbe)
            mstore(0x1c0, 0x243185be4ee4b28c)
            mstore(0x1e0, 0x550c7dc3d5ffb4e2)
            mstore(0x200, 0x72be5d74f27b896f)
            mstore(0x220, 0x80deb1fe3b1696b1)
            mstore(0x240, 0x9bdc06a725c71235)
            mstore(0x260, 0xc19bf174cf692694)
            mstore(0x280, 0xe49b69c19ef14ad2)
            mstore(0x2a0, 0xefbe4786384f25e3)
            mstore(0x2c0, 0x0fc19dc68b8cd5b5)
            mstore(0x2e0, 0x240ca1cc77ac9c65)
            mstore(0x300, 0x2de92c6f592b0275)
            mstore(0x320, 0x4a7484aa6ea6e483)
            mstore(0x340, 0x5cb0a9dcbd41fbd4)
            mstore(0x360, 0x76f988da831153b5)
            mstore(0x380, 0x983e5152ee66dfab)
            mstore(0x3a0, 0xa831c66d2db43210)
            mstore(0x3c0, 0xb00327c898fb213f)
            mstore(0x3e0, 0xbf597fc7beef0ee4)
            mstore(0x400, 0xc6e00bf33da88fc2)
            mstore(0x420, 0xd5a79147930aa725)
            mstore(0x440, 0x06ca6351e003826f)
            mstore(0x460, 0x142929670a0e6e70)
            mstore(0x480, 0x27b70a8546d22ffc)
            mstore(0x4a0, 0x2e1b21385c26c926)
            mstore(0x4c0, 0x4d2c6dfc5ac42aed)
            mstore(0x4e0, 0x53380d139d95b3df)
            mstore(0x500, 0x650a73548baf63de)
            mstore(0x520, 0x766a0abb3c77b2a8)
            mstore(0x540, 0x81c2c92e47edaee6)
            mstore(0x560, 0x92722c851482353b)
            mstore(0x580, 0xa2bfe8a14cf10364)
            mstore(0x5a0, 0xa81a664bbc423001)
            mstore(0x5c0, 0xc24b8b70d0f89791)
            mstore(0x5e0, 0xc76c51a30654be30)
            mstore(0x600, 0xd192e819d6ef5218)
            mstore(0x620, 0xd69906245565a910)
            mstore(0x640, 0xf40e35855771202a)
            mstore(0x660, 0x106aa07032bbd1b8)
            mstore(0x680, 0x19a4c116b8d2d0c8)
            mstore(0x6a0, 0x1e376c085141ab53)
            mstore(0x6c0, 0x2748774cdf8eeb99)
            mstore(0x6e0, 0x34b0bcb5e19b48a8)
            mstore(0x700, 0x391c0cb3c5c95a63)
            mstore(0x720, 0x4ed8aa4ae3418acb)
            mstore(0x740, 0x5b9cca4f7763e373)
            mstore(0x760, 0x682e6ff3d6b2b8a3)
            mstore(0x780, 0x748f82ee5defb2fc)
            mstore(0x7a0, 0x78a5636f43172f60)
            mstore(0x7c0, 0x84c87814a1f0ab72)
            mstore(0x7e0, 0x8cc702081a6439ec)
            mstore(0x800, 0x90befffa23631e28)
            mstore(0x820, 0xa4506cebde82bde9)
            mstore(0x840, 0xbef9a3f7b2c67915)
            mstore(0x860, 0xc67178f2e372532b)
            mstore(0x880, 0xca273eceea26619c)
            mstore(0x8a0, 0xd186b8c721c0c207)
            mstore(0x8c0, 0xeada7dd6cde0eb1e)
            mstore(0x8e0, 0xf57d4f7fee6ed178)
            mstore(0x900, 0x06f067aa72176fba)
            mstore(0x920, 0x0a637dc5a2c898a6)
            mstore(0x940, 0x113f9804bef90dae)
            mstore(0x960, 0x1b710b35131c471b)
            mstore(0x980, 0x28db77f523047d84)
            mstore(0x9a0, 0x32caab7b40c72493)
            mstore(0x9c0, 0x3c9ebe0a15c9bebc)
            mstore(0x9e0, 0x431d67c49c100d4c)
            mstore(0xa00, 0x4cc5d4becb3e42b6)
            mstore(0xa20, 0x597f299cfc657e2a)
            mstore(0xa40, 0x5fcb6fab3ad6faec)
            mstore(0xa60, 0x6c44198c4a475817)
            mstore(0x1500, 0x6a09e667f3bcc908)
            mstore(0x1520, 0xbb67ae8584caa73b)
            mstore(0x1540, 0x3c6ef372fe94f82b)
            mstore(0x1560, 0xa54ff53a5f1d36f1)
            mstore(0x1580, 0x510e527fade682d1)
            mstore(0x15a0, 0x9b05688c2b3e6c1f)
            mstore(0x15c0, 0x1f83d9abfb41bd6b)
            mstore(0x15e0, 0x5be0cd19137e2179)
            // blocks after padding: ceil((len + 1 + 16) / 128), kept in scratch to save a stack slot
            mstore(0x00, div(add(calldatasize(), 144), 128))
            for { mstore(0x20, 0) } lt(mload(0x20), mload(0x00)) { mstore(0x20, add(mload(0x20), 1)) } {
                {
                    let len := calldatasize()
                    let off := mul(mload(0x20), 128)
                    mstore(0x1480, 0)
                    mstore(0x14a0, 0)
                    mstore(0x14c0, 0)
                    mstore(0x14e0, 0)
                    if lt(off, len) {
                        let n := sub(len, off)
                        if gt(n, 128) { n := 128 }
                        calldatacopy(0x1480, off, n)
                        if lt(n, 128) { mstore8(add(0x1480, n), 0x80) }
                    }
                    if eq(off, len) { mstore8(0x1480, 0x80) }
                    // last block: 128-bit bit length; OR it in (bytes 96..111 may hold data)
                    if eq(mload(0x20), sub(mload(0x00), 1)) { mstore(0x14e0, or(mload(0x14e0), mul(len, 8))) }
                }
                for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                    mstore(add(0xa80, shl(5, i)), shr(192, mload(add(0x1480, shl(3, i)))))
                }
                for { let p := 0xc80 } lt(p, 0x1480) { p := add(p, 0x20) } {
                    let w15 := mload(sub(p, 0x1e0))
                    let w2 := mload(sub(p, 0x40))
                    let y15 := or(w15, shl(64, w15))
                    let y2 := or(w2, shl(64, w2))
                    mstore(
                        p,
                        and(
                            add(
                                add(
                                    mload(sub(p, 0x200)),
                                    xor(and(xor(shr(1, y15), shr(8, y15)), 0xffffffffffffffff), shr(7, w15))
                                ),
                                add(
                                    mload(sub(p, 0xe0)),
                                    xor(and(xor(shr(19, y2), shr(61, y2)), 0xffffffffffffffff), shr(6, w2))
                                )
                            ),
                            0xffffffffffffffff
                        )
                    )
                }
                for { let i := 0 } lt(i, 0xa00) { i := add(i, 0x20) } {
                    mstore(add(0xa80, i), add(mload(add(0xa80, i)), mload(add(0x80, i))))
                }
                {
                    let t
                    let y
                    let a := mload(0x1500)
                    let b := mload(0x1520)
                    let c := mload(0x1540)
                    let d := mload(0x1560)
                    let e := mload(0x1580)
                    let f := mload(0x15a0)
                    let g := mload(0x15c0)
                    let h := mload(0x15e0)
                    for { mstore(0x40, 0xa80) } lt(mload(0x40), 0x1480) { mstore(0x40, add(mload(0x40), 0x100)) } {
                        y := or(e, shl(64, e))
                        t := add(h, and(xor(xor(shr(14, y), shr(18, y)), shr(41, y)), 0xffffffffffffffff))
                        t := add(t, mload(mload(0x40)))
                        t := add(t, xor(g, and(e, xor(f, g))))
                        d := and(add(d, t), 0xffffffffffffffff)
                        y := or(a, shl(64, a))
                        t := add(t, and(xor(xor(shr(28, y), shr(34, y)), shr(39, y)), 0xffffffffffffffff))
                        y := and(a, b)
                        y := or(y, and(c, or(a, b)))
                        h := and(add(t, y), 0xffffffffffffffff)
                        y := or(d, shl(64, d))
                        t := add(g, and(xor(xor(shr(14, y), shr(18, y)), shr(41, y)), 0xffffffffffffffff))
                        t := add(t, mload(add(mload(0x40), 0x20)))
                        t := add(t, xor(f, and(d, xor(e, f))))
                        c := and(add(c, t), 0xffffffffffffffff)
                        y := or(h, shl(64, h))
                        t := add(t, and(xor(xor(shr(28, y), shr(34, y)), shr(39, y)), 0xffffffffffffffff))
                        y := and(h, a)
                        y := or(y, and(b, or(h, a)))
                        g := and(add(t, y), 0xffffffffffffffff)
                        y := or(c, shl(64, c))
                        t := add(f, and(xor(xor(shr(14, y), shr(18, y)), shr(41, y)), 0xffffffffffffffff))
                        t := add(t, mload(add(mload(0x40), 0x40)))
                        t := add(t, xor(e, and(c, xor(d, e))))
                        b := and(add(b, t), 0xffffffffffffffff)
                        y := or(g, shl(64, g))
                        t := add(t, and(xor(xor(shr(28, y), shr(34, y)), shr(39, y)), 0xffffffffffffffff))
                        y := and(g, h)
                        y := or(y, and(a, or(g, h)))
                        f := and(add(t, y), 0xffffffffffffffff)
                        y := or(b, shl(64, b))
                        t := add(e, and(xor(xor(shr(14, y), shr(18, y)), shr(41, y)), 0xffffffffffffffff))
                        t := add(t, mload(add(mload(0x40), 0x60)))
                        t := add(t, xor(d, and(b, xor(c, d))))
                        a := and(add(a, t), 0xffffffffffffffff)
                        y := or(f, shl(64, f))
                        t := add(t, and(xor(xor(shr(28, y), shr(34, y)), shr(39, y)), 0xffffffffffffffff))
                        y := and(f, g)
                        y := or(y, and(h, or(f, g)))
                        e := and(add(t, y), 0xffffffffffffffff)
                        y := or(a, shl(64, a))
                        t := add(d, and(xor(xor(shr(14, y), shr(18, y)), shr(41, y)), 0xffffffffffffffff))
                        t := add(t, mload(add(mload(0x40), 0x80)))
                        t := add(t, xor(c, and(a, xor(b, c))))
                        h := and(add(h, t), 0xffffffffffffffff)
                        y := or(e, shl(64, e))
                        t := add(t, and(xor(xor(shr(28, y), shr(34, y)), shr(39, y)), 0xffffffffffffffff))
                        y := and(e, f)
                        y := or(y, and(g, or(e, f)))
                        d := and(add(t, y), 0xffffffffffffffff)
                        y := or(h, shl(64, h))
                        t := add(c, and(xor(xor(shr(14, y), shr(18, y)), shr(41, y)), 0xffffffffffffffff))
                        t := add(t, mload(add(mload(0x40), 0xa0)))
                        t := add(t, xor(b, and(h, xor(a, b))))
                        g := and(add(g, t), 0xffffffffffffffff)
                        y := or(d, shl(64, d))
                        t := add(t, and(xor(xor(shr(28, y), shr(34, y)), shr(39, y)), 0xffffffffffffffff))
                        y := and(d, e)
                        y := or(y, and(f, or(d, e)))
                        c := and(add(t, y), 0xffffffffffffffff)
                        y := or(g, shl(64, g))
                        t := add(b, and(xor(xor(shr(14, y), shr(18, y)), shr(41, y)), 0xffffffffffffffff))
                        t := add(t, mload(add(mload(0x40), 0xc0)))
                        t := add(t, xor(a, and(g, xor(h, a))))
                        f := and(add(f, t), 0xffffffffffffffff)
                        y := or(c, shl(64, c))
                        t := add(t, and(xor(xor(shr(28, y), shr(34, y)), shr(39, y)), 0xffffffffffffffff))
                        y := and(c, d)
                        y := or(y, and(e, or(c, d)))
                        b := and(add(t, y), 0xffffffffffffffff)
                        y := or(f, shl(64, f))
                        t := add(a, and(xor(xor(shr(14, y), shr(18, y)), shr(41, y)), 0xffffffffffffffff))
                        t := add(t, mload(add(mload(0x40), 0xe0)))
                        t := add(t, xor(h, and(f, xor(g, h))))
                        e := and(add(e, t), 0xffffffffffffffff)
                        y := or(b, shl(64, b))
                        t := add(t, and(xor(xor(shr(28, y), shr(34, y)), shr(39, y)), 0xffffffffffffffff))
                        y := and(b, c)
                        y := or(y, and(d, or(b, c)))
                        a := and(add(t, y), 0xffffffffffffffff)
                    }
                    mstore(0x1500, and(add(mload(0x1500), a), 0xffffffffffffffff))
                    mstore(0x1520, and(add(mload(0x1520), b), 0xffffffffffffffff))
                    mstore(0x1540, and(add(mload(0x1540), c), 0xffffffffffffffff))
                    mstore(0x1560, and(add(mload(0x1560), d), 0xffffffffffffffff))
                    mstore(0x1580, and(add(mload(0x1580), e), 0xffffffffffffffff))
                    mstore(0x15a0, and(add(mload(0x15a0), f), 0xffffffffffffffff))
                    mstore(0x15c0, and(add(mload(0x15c0), g), 0xffffffffffffffff))
                    mstore(0x15e0, and(add(mload(0x15e0), h), 0xffffffffffffffff))
                }
            }
            let r := 0
            for { let i := 0 } lt(i, 4) { i := add(i, 1) } { r := or(shl(64, r), mload(add(0x1500, shl(5, i)))) }
            let s := 0
            for { let i := 4 } lt(i, 8) { i := add(i, 1) } { s := or(shl(64, s), mload(add(0x1500, shl(5, i)))) }
            mstore(0, r)
            mstore(0x20, s)
            return(0, 0x40)
        }
    }
}
