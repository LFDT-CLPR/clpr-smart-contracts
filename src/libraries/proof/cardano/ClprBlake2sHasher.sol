// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title ClprBlake2sHasher
/// @notice Stand-alone BLAKE2s-256 engine (RFC 7693; digest 32, unkeyed). There is no BLAKE2s
///         precompile, and an inlined library version runs out of stack slots under via-IR, so this
///         contract owns its memory (working vector and message words at fixed addresses) and is
///         called with `staticcall`. Calldata is the message; returns the 32-byte digest.
/// @dev Memory map: 0x000 v[16] · 0x200 m[16] · 0x400 h[8] · 0x500 64-byte block · 0x580 input.
contract ClprBlake2sHasher {
    fallback() external {
        assembly {
            function sig(r) -> s {
                switch r
                case 0 { s := 0x0123456789abcdef }
                case 1 { s := 0xea489fd61c02b753 }
                case 2 { s := 0xb8c052fdae367194 }
                case 3 { s := 0x7931dcbe265a40f8 }
                case 4 { s := 0x905724afe1bc683d }
                case 5 { s := 0x2c6a0b834d75fe19 }
                case 6 { s := 0xc51fed4a0763928b }
                case 7 { s := 0xdb7ec13950f4862a }
                case 8 { s := 0x6fe9b308c2d714a5 }
                default { s := 0xa2847615fb9e3cd0 }
            }
            function mw(s, j) -> w {
                w := mload(add(0x200, shl(5, and(shr(sub(60, shl(2, j)), s), 0xf))))
            }
            function iv(i) -> w {
                switch i
                case 0 { w := 0x6a09e667 }
                case 1 { w := 0xbb67ae85 }
                case 2 { w := 0x3c6ef372 }
                case 3 { w := 0xa54ff53a }
                case 4 { w := 0x510e527f }
                case 5 { w := 0x9b05688c }
                case 6 { w := 0x1f83d9ab }
                default { w := 0x5be0cd19 }
            }
            function rounds() {
                for { let r := 0 } lt(r, 10) { r := add(r, 1) } {
                    let s := sig(r)
                    {
                        let a := mload(0x0)
                        let b := mload(0x80)
                        let c := mload(0x100)
                        let d := mload(0x180)
                        a := and(add(add(a, b), mw(s, 0)), 0xffffffff)
                        d := xor(d, a)
                        d := and(or(shr(16, d), shl(16, d)), 0xffffffff)
                        c := and(add(c, d), 0xffffffff)
                        b := xor(b, c)
                        b := and(or(shr(12, b), shl(20, b)), 0xffffffff)
                        a := and(add(add(a, b), mw(s, 1)), 0xffffffff)
                        d := xor(d, a)
                        d := and(or(shr(8, d), shl(24, d)), 0xffffffff)
                        c := and(add(c, d), 0xffffffff)
                        b := xor(b, c)
                        b := and(or(shr(7, b), shl(25, b)), 0xffffffff)
                        mstore(0x0, a)
                        mstore(0x80, b)
                        mstore(0x100, c)
                        mstore(0x180, d)
                    }
                    {
                        let a := mload(0x20)
                        let b := mload(0xa0)
                        let c := mload(0x120)
                        let d := mload(0x1a0)
                        a := and(add(add(a, b), mw(s, 2)), 0xffffffff)
                        d := xor(d, a)
                        d := and(or(shr(16, d), shl(16, d)), 0xffffffff)
                        c := and(add(c, d), 0xffffffff)
                        b := xor(b, c)
                        b := and(or(shr(12, b), shl(20, b)), 0xffffffff)
                        a := and(add(add(a, b), mw(s, 3)), 0xffffffff)
                        d := xor(d, a)
                        d := and(or(shr(8, d), shl(24, d)), 0xffffffff)
                        c := and(add(c, d), 0xffffffff)
                        b := xor(b, c)
                        b := and(or(shr(7, b), shl(25, b)), 0xffffffff)
                        mstore(0x20, a)
                        mstore(0xa0, b)
                        mstore(0x120, c)
                        mstore(0x1a0, d)
                    }
                    {
                        let a := mload(0x40)
                        let b := mload(0xc0)
                        let c := mload(0x140)
                        let d := mload(0x1c0)
                        a := and(add(add(a, b), mw(s, 4)), 0xffffffff)
                        d := xor(d, a)
                        d := and(or(shr(16, d), shl(16, d)), 0xffffffff)
                        c := and(add(c, d), 0xffffffff)
                        b := xor(b, c)
                        b := and(or(shr(12, b), shl(20, b)), 0xffffffff)
                        a := and(add(add(a, b), mw(s, 5)), 0xffffffff)
                        d := xor(d, a)
                        d := and(or(shr(8, d), shl(24, d)), 0xffffffff)
                        c := and(add(c, d), 0xffffffff)
                        b := xor(b, c)
                        b := and(or(shr(7, b), shl(25, b)), 0xffffffff)
                        mstore(0x40, a)
                        mstore(0xc0, b)
                        mstore(0x140, c)
                        mstore(0x1c0, d)
                    }
                    {
                        let a := mload(0x60)
                        let b := mload(0xe0)
                        let c := mload(0x160)
                        let d := mload(0x1e0)
                        a := and(add(add(a, b), mw(s, 6)), 0xffffffff)
                        d := xor(d, a)
                        d := and(or(shr(16, d), shl(16, d)), 0xffffffff)
                        c := and(add(c, d), 0xffffffff)
                        b := xor(b, c)
                        b := and(or(shr(12, b), shl(20, b)), 0xffffffff)
                        a := and(add(add(a, b), mw(s, 7)), 0xffffffff)
                        d := xor(d, a)
                        d := and(or(shr(8, d), shl(24, d)), 0xffffffff)
                        c := and(add(c, d), 0xffffffff)
                        b := xor(b, c)
                        b := and(or(shr(7, b), shl(25, b)), 0xffffffff)
                        mstore(0x60, a)
                        mstore(0xe0, b)
                        mstore(0x160, c)
                        mstore(0x1e0, d)
                    }
                    {
                        let a := mload(0x0)
                        let b := mload(0xa0)
                        let c := mload(0x140)
                        let d := mload(0x1e0)
                        a := and(add(add(a, b), mw(s, 8)), 0xffffffff)
                        d := xor(d, a)
                        d := and(or(shr(16, d), shl(16, d)), 0xffffffff)
                        c := and(add(c, d), 0xffffffff)
                        b := xor(b, c)
                        b := and(or(shr(12, b), shl(20, b)), 0xffffffff)
                        a := and(add(add(a, b), mw(s, 9)), 0xffffffff)
                        d := xor(d, a)
                        d := and(or(shr(8, d), shl(24, d)), 0xffffffff)
                        c := and(add(c, d), 0xffffffff)
                        b := xor(b, c)
                        b := and(or(shr(7, b), shl(25, b)), 0xffffffff)
                        mstore(0x0, a)
                        mstore(0xa0, b)
                        mstore(0x140, c)
                        mstore(0x1e0, d)
                    }
                    {
                        let a := mload(0x20)
                        let b := mload(0xc0)
                        let c := mload(0x160)
                        let d := mload(0x180)
                        a := and(add(add(a, b), mw(s, 10)), 0xffffffff)
                        d := xor(d, a)
                        d := and(or(shr(16, d), shl(16, d)), 0xffffffff)
                        c := and(add(c, d), 0xffffffff)
                        b := xor(b, c)
                        b := and(or(shr(12, b), shl(20, b)), 0xffffffff)
                        a := and(add(add(a, b), mw(s, 11)), 0xffffffff)
                        d := xor(d, a)
                        d := and(or(shr(8, d), shl(24, d)), 0xffffffff)
                        c := and(add(c, d), 0xffffffff)
                        b := xor(b, c)
                        b := and(or(shr(7, b), shl(25, b)), 0xffffffff)
                        mstore(0x20, a)
                        mstore(0xc0, b)
                        mstore(0x160, c)
                        mstore(0x180, d)
                    }
                    {
                        let a := mload(0x40)
                        let b := mload(0xe0)
                        let c := mload(0x100)
                        let d := mload(0x1a0)
                        a := and(add(add(a, b), mw(s, 12)), 0xffffffff)
                        d := xor(d, a)
                        d := and(or(shr(16, d), shl(16, d)), 0xffffffff)
                        c := and(add(c, d), 0xffffffff)
                        b := xor(b, c)
                        b := and(or(shr(12, b), shl(20, b)), 0xffffffff)
                        a := and(add(add(a, b), mw(s, 13)), 0xffffffff)
                        d := xor(d, a)
                        d := and(or(shr(8, d), shl(24, d)), 0xffffffff)
                        c := and(add(c, d), 0xffffffff)
                        b := xor(b, c)
                        b := and(or(shr(7, b), shl(25, b)), 0xffffffff)
                        mstore(0x40, a)
                        mstore(0xe0, b)
                        mstore(0x100, c)
                        mstore(0x1a0, d)
                    }
                    {
                        let a := mload(0x60)
                        let b := mload(0x80)
                        let c := mload(0x120)
                        let d := mload(0x1c0)
                        a := and(add(add(a, b), mw(s, 14)), 0xffffffff)
                        d := xor(d, a)
                        d := and(or(shr(16, d), shl(16, d)), 0xffffffff)
                        c := and(add(c, d), 0xffffffff)
                        b := xor(b, c)
                        b := and(or(shr(12, b), shl(20, b)), 0xffffffff)
                        a := and(add(add(a, b), mw(s, 15)), 0xffffffff)
                        d := xor(d, a)
                        d := and(or(shr(8, d), shl(24, d)), 0xffffffff)
                        c := and(add(c, d), 0xffffffff)
                        b := xor(b, c)
                        b := and(or(shr(7, b), shl(25, b)), 0xffffffff)
                        mstore(0x60, a)
                        mstore(0x80, b)
                        mstore(0x120, c)
                        mstore(0x1c0, d)
                    }
                }
            }

            let len := calldatasize()
            calldatacopy(0x580, 0, len)
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } { mstore(add(0x400, shl(5, i)), iv(i)) }
            mstore(0x400, xor(iv(0), 0x01010020))
            let blocks := div(add(len, 63), 64)
            if iszero(blocks) { blocks := 1 }
            for { let bi := 0 } lt(bi, blocks) { bi := add(bi, 1) } {
                let off := mul(bi, 64)
                let last := eq(bi, sub(blocks, 1))
                let n := 64
                if last { n := sub(len, off) }
                mstore(0x500, 0)
                mstore(0x520, 0)
                mcopy(0x500, add(0x580, off), n)
                for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                    let w := mload(add(0x500, shl(2, i)))
                    mstore(
                        add(0x200, shl(5, i)),
                        or(or(byte(0, w), shl(8, byte(1, w))), or(shl(16, byte(2, w)), shl(24, byte(3, w))))
                    )
                }
                for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                    mstore(shl(5, i), mload(add(0x400, shl(5, i))))
                    mstore(shl(5, add(i, 8)), iv(i))
                }
                let t := add(off, n)
                mstore(0x180, xor(iv(4), and(t, 0xffffffff)))
                mstore(0x1a0, xor(iv(5), shr(32, t)))
                if last { mstore(0x1c0, xor(iv(6), 0xffffffff)) }
                rounds()
                for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                    let q := add(0x400, shl(5, i))
                    mstore(q, xor(xor(mload(q), mload(shl(5, i))), mload(shl(5, add(i, 8)))))
                }
            }
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                let w := mload(add(0x400, shl(5, i)))
                let q := add(0x500, shl(2, i))
                mstore8(q, and(w, 0xff))
                mstore8(add(q, 1), and(shr(8, w), 0xff))
                mstore8(add(q, 2), and(shr(16, w), 0xff))
                mstore8(add(q, 3), and(shr(24, w), 0xff))
            }
            return(0x500, 32)
        }
    }
}
