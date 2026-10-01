// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @dev Exposes the lane-form Blake2s of {ZkSyncStateTreeVerifier} (the same generated Yul helpers,
///      spliced by script/zksync/generateBlake2s.ts) for known-answer tests and gas measurement.
contract Blake2sHarness {
    /// Blake2s-256 of `left ‖ right` (64 bytes).
    function hash64(bytes32 left, bytes32 right) external pure returns (bytes32 out) {
        assembly {
            spreadW(bswapWords(left), 0x2100)
            spreadW(bswapWords(right), 0x2200)
            let h0, h1 := compress(64)
            out := standardOf(h0, h1)

            // <generated:yul-helpers>
            /// Byte-reverse every 4-byte group: standard bytes <-> W-form.
            function bswapWords(x) -> y {
                y := or(
                    shr(8, and(x, 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00)),
                    shl(8, and(x, 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff))
                )
                y := or(
                    shr(16, and(y, 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000)),
                    shl(16, and(y, 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff))
                )
            }
            /// W-form word -> eight zero-padded message slots at `base`.
            function spreadW(w, base) {
                mstore(base, shr(224, w))
                mstore(add(base, 0x20), and(shr(192, w), 0xffffffff))
                mstore(add(base, 0x40), and(shr(160, w), 0xffffffff))
                mstore(add(base, 0x60), and(shr(128, w), 0xffffffff))
                mstore(add(base, 0x80), and(shr(96, w), 0xffffffff))
                mstore(add(base, 0xa0), and(shr(64, w), 0xffffffff))
                mstore(add(base, 0xc0), and(shr(32, w), 0xffffffff))
                mstore(add(base, 0xe0), and(w, 0xffffffff))
            }
            /// Lane-form hash -> eight zero-padded message slots at `base`.
            function spreadLanes(l0, l1, base) {
                mstore(base, and(l0, 0xffffffff))
                mstore(add(base, 0x20), and(shr(64, l0), 0xffffffff))
                mstore(add(base, 0x40), and(shr(128, l0), 0xffffffff))
                mstore(add(base, 0x60), shr(192, l0))
                mstore(add(base, 0x80), and(l1, 0xffffffff))
                mstore(add(base, 0xa0), and(shr(64, l1), 0xffffffff))
                mstore(add(base, 0xc0), and(shr(128, l1), 0xffffffff))
                mstore(add(base, 0xe0), shr(192, l1))
            }
            /// Standard 32-byte hash -> lane form.
            function lanesOf(x) -> l0, l1 {
                let w := bswapWords(x)
                l0 := or(
                    or(shr(224, w), shl(64, and(shr(192, w), 0xffffffff))),
                    or(shl(128, and(shr(160, w), 0xffffffff)), shl(192, and(shr(128, w), 0xffffffff)))
                )
                l1 := or(
                    or(and(shr(96, w), 0xffffffff), shl(64, and(shr(64, w), 0xffffffff))),
                    or(shl(128, and(shr(32, w), 0xffffffff)), shl(192, and(w, 0xffffffff)))
                )
            }
            /// Lane form -> standard 32-byte hash.
            function standardOf(l0, l1) -> x {
                let w :=
                    or(
                        or(shl(224, and(l0, 0xffffffff)), shl(192, and(shr(64, l0), 0xffffffff))),
                        or(shl(160, and(shr(128, l0), 0xffffffff)), shl(128, shr(192, l0)))
                    )
                w := or(
                    w,
                    or(
                        or(shl(96, and(l1, 0xffffffff)), shl(64, and(shr(64, l1), 0xffffffff))),
                        or(shl(32, and(shr(128, l1), 0xffffffff)), shr(192, l1))
                    )
                )
                x := bswapWords(w)
            }
            /// Blake2s final-block compression of the message in slots 0x2100.. (t = 64 or 40).
            function compress(t) -> o0, o1 {
                let M := 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff
                let a := 0x00000000a54ff53a000000003c6ef37200000000bb67ae85000000006b08e647
                let b := 0x000000005be0cd19000000001f83d9ab000000009b05688c00000000510e527f
                let c := 0x00000000a54ff53a000000003c6ef37200000000bb67ae85000000006a09e667
                let d := xor(0x000000005be0cd1900000000e07c2654000000009b05688c00000000510e527f, t)
                let y
                // round 0: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x2100), mload(0x2148)), or(mload(0x2190), mload(0x21d8)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2120), mload(0x2168)), or(mload(0x21b0), mload(0x21f8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 0: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x2200), mload(0x2248)), or(mload(0x2290), mload(0x22d8)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2220), mload(0x2268)), or(mload(0x22b0), mload(0x22f8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 1: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x22c0), mload(0x2188)), or(mload(0x2230), mload(0x22b8)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2240), mload(0x2208)), or(mload(0x22f0), mload(0x21d8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 1: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x2120), mload(0x2108)), or(mload(0x2270), mload(0x21b8)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2280), mload(0x2148)), or(mload(0x21f0), mload(0x2178)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 2: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x2260), mload(0x2288)), or(mload(0x21b0), mload(0x22f8)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2200), mload(0x2108)), or(mload(0x2150), mload(0x22b8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 2: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x2240), mload(0x2168)), or(mload(0x21f0), mload(0x2238)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x22c0), mload(0x21c8)), or(mload(0x2130), mload(0x2198)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 3: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x21e0), mload(0x2168)), or(mload(0x22b0), mload(0x2278)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2220), mload(0x2128)), or(mload(0x2290), mload(0x22d8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 3: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x2140), mload(0x21a8)), or(mload(0x2190), mload(0x22f8)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x21c0), mload(0x2248)), or(mload(0x2110), mload(0x2218)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 4: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x2220), mload(0x21a8)), or(mload(0x2150), mload(0x2258)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2100), mload(0x21e8)), or(mload(0x2190), mload(0x22f8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 4: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x22c0), mload(0x2268)), or(mload(0x21d0), mload(0x2178)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2120), mload(0x2288)), or(mload(0x2210), mload(0x22b8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 5: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x2140), mload(0x21c8)), or(mload(0x2110), mload(0x2218)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2280), mload(0x2248)), or(mload(0x2270), mload(0x2178)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 5: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x2180), mload(0x21e8)), or(mload(0x22f0), mload(0x2138)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x22a0), mload(0x21a8)), or(mload(0x22d0), mload(0x2238)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 6: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x2280), mload(0x2128)), or(mload(0x22d0), mload(0x2198)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x21a0), mload(0x22e8)), or(mload(0x22b0), mload(0x2258)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 6: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x2100), mload(0x21c8)), or(mload(0x2230), mload(0x2218)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x21e0), mload(0x2168)), or(mload(0x2150), mload(0x2278)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 7: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x22a0), mload(0x21e8)), or(mload(0x2290), mload(0x2178)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2260), mload(0x22c8)), or(mload(0x2130), mload(0x2238)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 7: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x21a0), mload(0x22e8)), or(mload(0x2210), mload(0x2158)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2100), mload(0x2188)), or(mload(0x21d0), mload(0x2258)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 8: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x21c0), mload(0x22c8)), or(mload(0x2270), mload(0x2118)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x22e0), mload(0x2228)), or(mload(0x2170), mload(0x2218)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 8: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x2280), mload(0x22a8)), or(mload(0x2130), mload(0x2258)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2140), mload(0x21e8)), or(mload(0x2190), mload(0x21b8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 9: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x2240), mload(0x2208)), or(mload(0x21f0), mload(0x2138)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2140), mload(0x2188)), or(mload(0x21d0), mload(0x21b8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 9: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x22e0), mload(0x2228)), or(mload(0x2170), mload(0x22b8)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2260), mload(0x22c8)), or(mload(0x2290), mload(0x2118)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                o0 := xor(xor(a, c), 0x00000000a54ff53a000000003c6ef37200000000bb67ae85000000006b08e647)
                o1 := xor(xor(b, d), 0x000000005be0cd19000000001f83d9ab000000009b05688c00000000510e527f)
            }
            // </generated:yul-helpers>
        }
    }

    /// Blake2s-256 of the first 40 bytes of `left ‖ right` (`right`'s low 24 bytes must be zero).
    function hash40(bytes32 left, bytes32 right) external pure returns (bytes32 out) {
        assembly {
            spreadW(bswapWords(left), 0x2100)
            spreadW(bswapWords(right), 0x2200)
            let h0, h1 := compress(40)
            out := standardOf(h0, h1)

            // <generated:yul-helpers>
            /// Byte-reverse every 4-byte group: standard bytes <-> W-form.
            function bswapWords(x) -> y {
                y := or(
                    shr(8, and(x, 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00)),
                    shl(8, and(x, 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff))
                )
                y := or(
                    shr(16, and(y, 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000)),
                    shl(16, and(y, 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff))
                )
            }
            /// W-form word -> eight zero-padded message slots at `base`.
            function spreadW(w, base) {
                mstore(base, shr(224, w))
                mstore(add(base, 0x20), and(shr(192, w), 0xffffffff))
                mstore(add(base, 0x40), and(shr(160, w), 0xffffffff))
                mstore(add(base, 0x60), and(shr(128, w), 0xffffffff))
                mstore(add(base, 0x80), and(shr(96, w), 0xffffffff))
                mstore(add(base, 0xa0), and(shr(64, w), 0xffffffff))
                mstore(add(base, 0xc0), and(shr(32, w), 0xffffffff))
                mstore(add(base, 0xe0), and(w, 0xffffffff))
            }
            /// Lane-form hash -> eight zero-padded message slots at `base`.
            function spreadLanes(l0, l1, base) {
                mstore(base, and(l0, 0xffffffff))
                mstore(add(base, 0x20), and(shr(64, l0), 0xffffffff))
                mstore(add(base, 0x40), and(shr(128, l0), 0xffffffff))
                mstore(add(base, 0x60), shr(192, l0))
                mstore(add(base, 0x80), and(l1, 0xffffffff))
                mstore(add(base, 0xa0), and(shr(64, l1), 0xffffffff))
                mstore(add(base, 0xc0), and(shr(128, l1), 0xffffffff))
                mstore(add(base, 0xe0), shr(192, l1))
            }
            /// Standard 32-byte hash -> lane form.
            function lanesOf(x) -> l0, l1 {
                let w := bswapWords(x)
                l0 := or(
                    or(shr(224, w), shl(64, and(shr(192, w), 0xffffffff))),
                    or(shl(128, and(shr(160, w), 0xffffffff)), shl(192, and(shr(128, w), 0xffffffff)))
                )
                l1 := or(
                    or(and(shr(96, w), 0xffffffff), shl(64, and(shr(64, w), 0xffffffff))),
                    or(shl(128, and(shr(32, w), 0xffffffff)), shl(192, and(w, 0xffffffff)))
                )
            }
            /// Lane form -> standard 32-byte hash.
            function standardOf(l0, l1) -> x {
                let w :=
                    or(
                        or(shl(224, and(l0, 0xffffffff)), shl(192, and(shr(64, l0), 0xffffffff))),
                        or(shl(160, and(shr(128, l0), 0xffffffff)), shl(128, shr(192, l0)))
                    )
                w := or(
                    w,
                    or(
                        or(shl(96, and(l1, 0xffffffff)), shl(64, and(shr(64, l1), 0xffffffff))),
                        or(shl(32, and(shr(128, l1), 0xffffffff)), shr(192, l1))
                    )
                )
                x := bswapWords(w)
            }
            /// Blake2s final-block compression of the message in slots 0x2100.. (t = 64 or 40).
            function compress(t) -> o0, o1 {
                let M := 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff
                let a := 0x00000000a54ff53a000000003c6ef37200000000bb67ae85000000006b08e647
                let b := 0x000000005be0cd19000000001f83d9ab000000009b05688c00000000510e527f
                let c := 0x00000000a54ff53a000000003c6ef37200000000bb67ae85000000006a09e667
                let d := xor(0x000000005be0cd1900000000e07c2654000000009b05688c00000000510e527f, t)
                let y
                // round 0: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x2100), mload(0x2148)), or(mload(0x2190), mload(0x21d8)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2120), mload(0x2168)), or(mload(0x21b0), mload(0x21f8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 0: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x2200), mload(0x2248)), or(mload(0x2290), mload(0x22d8)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2220), mload(0x2268)), or(mload(0x22b0), mload(0x22f8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 1: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x22c0), mload(0x2188)), or(mload(0x2230), mload(0x22b8)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2240), mload(0x2208)), or(mload(0x22f0), mload(0x21d8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 1: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x2120), mload(0x2108)), or(mload(0x2270), mload(0x21b8)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2280), mload(0x2148)), or(mload(0x21f0), mload(0x2178)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 2: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x2260), mload(0x2288)), or(mload(0x21b0), mload(0x22f8)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2200), mload(0x2108)), or(mload(0x2150), mload(0x22b8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 2: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x2240), mload(0x2168)), or(mload(0x21f0), mload(0x2238)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x22c0), mload(0x21c8)), or(mload(0x2130), mload(0x2198)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 3: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x21e0), mload(0x2168)), or(mload(0x22b0), mload(0x2278)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2220), mload(0x2128)), or(mload(0x2290), mload(0x22d8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 3: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x2140), mload(0x21a8)), or(mload(0x2190), mload(0x22f8)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x21c0), mload(0x2248)), or(mload(0x2110), mload(0x2218)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 4: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x2220), mload(0x21a8)), or(mload(0x2150), mload(0x2258)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2100), mload(0x21e8)), or(mload(0x2190), mload(0x22f8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 4: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x22c0), mload(0x2268)), or(mload(0x21d0), mload(0x2178)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2120), mload(0x2288)), or(mload(0x2210), mload(0x22b8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 5: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x2140), mload(0x21c8)), or(mload(0x2110), mload(0x2218)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2280), mload(0x2248)), or(mload(0x2270), mload(0x2178)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 5: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x2180), mload(0x21e8)), or(mload(0x22f0), mload(0x2138)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x22a0), mload(0x21a8)), or(mload(0x22d0), mload(0x2238)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 6: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x2280), mload(0x2128)), or(mload(0x22d0), mload(0x2198)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x21a0), mload(0x22e8)), or(mload(0x22b0), mload(0x2258)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 6: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x2100), mload(0x21c8)), or(mload(0x2230), mload(0x2218)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x21e0), mload(0x2168)), or(mload(0x2150), mload(0x2278)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 7: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x22a0), mload(0x21e8)), or(mload(0x2290), mload(0x2178)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2260), mload(0x22c8)), or(mload(0x2130), mload(0x2238)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 7: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x21a0), mload(0x22e8)), or(mload(0x2210), mload(0x2158)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2100), mload(0x2188)), or(mload(0x21d0), mload(0x2258)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 8: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x21c0), mload(0x22c8)), or(mload(0x2270), mload(0x2118)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x22e0), mload(0x2228)), or(mload(0x2170), mload(0x2218)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 8: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x2280), mload(0x22a8)), or(mload(0x2130), mload(0x2258)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2140), mload(0x21e8)), or(mload(0x2190), mload(0x21b8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 9: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x2240), mload(0x2208)), or(mload(0x21f0), mload(0x2138)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2140), mload(0x2188)), or(mload(0x21d0), mload(0x21b8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 9: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x22e0), mload(0x2228)), or(mload(0x2170), mload(0x22b8)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2260), mload(0x22c8)), or(mload(0x2290), mload(0x2118)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                o0 := xor(xor(a, c), 0x00000000a54ff53a000000003c6ef37200000000bb67ae85000000006b08e647)
                o1 := xor(xor(b, d), 0x000000005be0cd19000000001f83d9ab000000009b05688c00000000510e527f)
            }
            // </generated:yul-helpers>
        }
    }

    /// Gas of `n` chained 64-byte compressions in lane form (the per-level cost of a proof walk).
    function chain(bytes32 seed, uint256 n) external view returns (bytes32 out, uint256 gasUsed) {
        assembly {
            let g := gas()
            let h0, h1 := lanesOf(seed)
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                spreadLanes(h0, h1, 0x2100)
                spreadLanes(h0, h1, 0x2200)
                h0, h1 := compress(64)
            }
            gasUsed := sub(g, gas())
            out := standardOf(h0, h1)

            // <generated:yul-helpers>
            /// Byte-reverse every 4-byte group: standard bytes <-> W-form.
            function bswapWords(x) -> y {
                y := or(
                    shr(8, and(x, 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00)),
                    shl(8, and(x, 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff))
                )
                y := or(
                    shr(16, and(y, 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000)),
                    shl(16, and(y, 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff))
                )
            }
            /// W-form word -> eight zero-padded message slots at `base`.
            function spreadW(w, base) {
                mstore(base, shr(224, w))
                mstore(add(base, 0x20), and(shr(192, w), 0xffffffff))
                mstore(add(base, 0x40), and(shr(160, w), 0xffffffff))
                mstore(add(base, 0x60), and(shr(128, w), 0xffffffff))
                mstore(add(base, 0x80), and(shr(96, w), 0xffffffff))
                mstore(add(base, 0xa0), and(shr(64, w), 0xffffffff))
                mstore(add(base, 0xc0), and(shr(32, w), 0xffffffff))
                mstore(add(base, 0xe0), and(w, 0xffffffff))
            }
            /// Lane-form hash -> eight zero-padded message slots at `base`.
            function spreadLanes(l0, l1, base) {
                mstore(base, and(l0, 0xffffffff))
                mstore(add(base, 0x20), and(shr(64, l0), 0xffffffff))
                mstore(add(base, 0x40), and(shr(128, l0), 0xffffffff))
                mstore(add(base, 0x60), shr(192, l0))
                mstore(add(base, 0x80), and(l1, 0xffffffff))
                mstore(add(base, 0xa0), and(shr(64, l1), 0xffffffff))
                mstore(add(base, 0xc0), and(shr(128, l1), 0xffffffff))
                mstore(add(base, 0xe0), shr(192, l1))
            }
            /// Standard 32-byte hash -> lane form.
            function lanesOf(x) -> l0, l1 {
                let w := bswapWords(x)
                l0 := or(
                    or(shr(224, w), shl(64, and(shr(192, w), 0xffffffff))),
                    or(shl(128, and(shr(160, w), 0xffffffff)), shl(192, and(shr(128, w), 0xffffffff)))
                )
                l1 := or(
                    or(and(shr(96, w), 0xffffffff), shl(64, and(shr(64, w), 0xffffffff))),
                    or(shl(128, and(shr(32, w), 0xffffffff)), shl(192, and(w, 0xffffffff)))
                )
            }
            /// Lane form -> standard 32-byte hash.
            function standardOf(l0, l1) -> x {
                let w :=
                    or(
                        or(shl(224, and(l0, 0xffffffff)), shl(192, and(shr(64, l0), 0xffffffff))),
                        or(shl(160, and(shr(128, l0), 0xffffffff)), shl(128, shr(192, l0)))
                    )
                w := or(
                    w,
                    or(
                        or(shl(96, and(l1, 0xffffffff)), shl(64, and(shr(64, l1), 0xffffffff))),
                        or(shl(32, and(shr(128, l1), 0xffffffff)), shr(192, l1))
                    )
                )
                x := bswapWords(w)
            }
            /// Blake2s final-block compression of the message in slots 0x2100.. (t = 64 or 40).
            function compress(t) -> o0, o1 {
                let M := 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff
                let a := 0x00000000a54ff53a000000003c6ef37200000000bb67ae85000000006b08e647
                let b := 0x000000005be0cd19000000001f83d9ab000000009b05688c00000000510e527f
                let c := 0x00000000a54ff53a000000003c6ef37200000000bb67ae85000000006a09e667
                let d := xor(0x000000005be0cd1900000000e07c2654000000009b05688c00000000510e527f, t)
                let y
                // round 0: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x2100), mload(0x2148)), or(mload(0x2190), mload(0x21d8)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2120), mload(0x2168)), or(mload(0x21b0), mload(0x21f8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 0: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x2200), mload(0x2248)), or(mload(0x2290), mload(0x22d8)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2220), mload(0x2268)), or(mload(0x22b0), mload(0x22f8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 1: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x22c0), mload(0x2188)), or(mload(0x2230), mload(0x22b8)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2240), mload(0x2208)), or(mload(0x22f0), mload(0x21d8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 1: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x2120), mload(0x2108)), or(mload(0x2270), mload(0x21b8)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2280), mload(0x2148)), or(mload(0x21f0), mload(0x2178)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 2: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x2260), mload(0x2288)), or(mload(0x21b0), mload(0x22f8)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2200), mload(0x2108)), or(mload(0x2150), mload(0x22b8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 2: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x2240), mload(0x2168)), or(mload(0x21f0), mload(0x2238)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x22c0), mload(0x21c8)), or(mload(0x2130), mload(0x2198)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 3: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x21e0), mload(0x2168)), or(mload(0x22b0), mload(0x2278)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2220), mload(0x2128)), or(mload(0x2290), mload(0x22d8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 3: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x2140), mload(0x21a8)), or(mload(0x2190), mload(0x22f8)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x21c0), mload(0x2248)), or(mload(0x2110), mload(0x2218)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 4: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x2220), mload(0x21a8)), or(mload(0x2150), mload(0x2258)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2100), mload(0x21e8)), or(mload(0x2190), mload(0x22f8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 4: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x22c0), mload(0x2268)), or(mload(0x21d0), mload(0x2178)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2120), mload(0x2288)), or(mload(0x2210), mload(0x22b8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 5: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x2140), mload(0x21c8)), or(mload(0x2110), mload(0x2218)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2280), mload(0x2248)), or(mload(0x2270), mload(0x2178)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 5: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x2180), mload(0x21e8)), or(mload(0x22f0), mload(0x2138)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x22a0), mload(0x21a8)), or(mload(0x22d0), mload(0x2238)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 6: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x2280), mload(0x2128)), or(mload(0x22d0), mload(0x2198)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x21a0), mload(0x22e8)), or(mload(0x22b0), mload(0x2258)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 6: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x2100), mload(0x21c8)), or(mload(0x2230), mload(0x2218)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x21e0), mload(0x2168)), or(mload(0x2150), mload(0x2278)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 7: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x22a0), mload(0x21e8)), or(mload(0x2290), mload(0x2178)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2260), mload(0x22c8)), or(mload(0x2130), mload(0x2238)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 7: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x21a0), mload(0x22e8)), or(mload(0x2210), mload(0x2158)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2100), mload(0x2188)), or(mload(0x21d0), mload(0x2258)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 8: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x21c0), mload(0x22c8)), or(mload(0x2270), mload(0x2118)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x22e0), mload(0x2228)), or(mload(0x2170), mload(0x2218)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 8: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x2280), mload(0x22a8)), or(mload(0x2130), mload(0x2258)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2140), mload(0x21e8)), or(mload(0x2190), mload(0x21b8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                // round 9: columns; then rows 1-3 rotate left by 1, 2, 3 lanes for the diagonals
                a := and(add(add(a, b), or(or(mload(0x2240), mload(0x2208)), or(mload(0x21f0), mload(0x2138)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2140), mload(0x2188)), or(mload(0x21d0), mload(0x21b8)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shr(71, y), shl(185, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shl(64, d), shr(192, d))
                // round 9: diagonals; then rows 1-3 rotate back
                a := and(add(add(a, b), or(or(mload(0x22e0), mload(0x2228)), or(mload(0x2170), mload(0x22b8)))), M)
                d := and(shr(16, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                b := and(shr(12, mul(xor(b, c), 0x100000001)), M)
                a := and(add(add(a, b), or(or(mload(0x2260), mload(0x22c8)), or(mload(0x2290), mload(0x2118)))), M)
                d := and(shr(8, mul(xor(d, a), 0x100000001)), M)
                c := and(add(c, d), M)
                y := mul(xor(b, c), 0x100000001)
                b := and(or(shl(57, y), shr(199, y)), M)
                c := or(shr(128, c), shl(128, c))
                d := or(shr(64, d), shl(192, d))
                o0 := xor(xor(a, c), 0x00000000a54ff53a000000003c6ef37200000000bb67ae85000000006b08e647)
                o1 := xor(xor(b, d), 0x000000005be0cd19000000001f83d9ab000000009b05688c00000000510e527f)
            }
            // </generated:yul-helpers>
        }
    }
}
