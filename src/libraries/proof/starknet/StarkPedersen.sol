// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {StarkTables} from "@hiero-ledger/clpr/libraries/proof/starknet/StarkTables.sol";

/// @title StarkPedersen
/// @notice Starknet's Pedersen hash on the STARK curve (y² = x³ + x + β over p = 2²⁵¹ + 17·2¹⁹² + 1),
///         as defined by cairo-lang `fast_pedersen_hash.py`:
///
///             H(a, b) = [shift + a_low·P0 + a_high·P1 + b_low·P2 + b_high·P3].x
///
///         with `low` the 248 low bits and `high` the top 4 bits of each felt.
///
/// @dev There is no STARK-curve precompile, so this is EVM arithmetic. A fixed-base comb keeps it to
///      31 doublings and ≤ 64 mixed additions per hash: for the 248-bit parts, 8 teeth × 31 columns,
///      T[u] = Σ_{i∈bits(u)} 2^(31·i)·P (255 affine points per base); the 4-bit parts use a 15-entry
///      table. The accumulator starts at Q = 2^-31·shift (so it is never the identity and the
///      doublings land on the shift point), runs in Jacobian coordinates, and is normalized with one
///      modexp inversion. The comb digits come from a bit-spread transpose of each scalar (one byte
///      per column). The tables live in two data contracts ({StarkPedersenTableA}/{B}, code hashes
///      pinned by the caller) and are copied to memory once per call ({loadTables}).
///      A mixed addition that meets its own operand or negation is unreachable for honest inputs (it
///      needs a discrete-log relation between the independent generators) and reverts.
library StarkPedersen {
    uint256 internal constant P = 0x0800000000000011000000000000000000000000000000000000000000000001;
    /// @dev Bytes per data contract: 0x00 ‖ 255 comb points ‖ 15 nibble points, 64 bytes each.
    uint256 internal constant TABLE_BYTES = 17281;

    error FeltOutOfRange();
    error PedersenDegenerate();

    /// @notice Copy both tables into fresh memory; pass the returned pointer to {hash}.
    function loadTables(address tableA, address tableB) internal view returns (uint256 tables) {
        assembly ("memory-safe") {
            tables := mload(0x40)
            extcodecopy(tableA, tables, 0, 17281)
            extcodecopy(tableB, add(tables, 17281), 0, 17281)
            mstore(0x40, add(tables, 34592)) // 2 × 17281 rounded up to a word
        }
    }

    /// @notice H(a, b) with the tables at memory `tables` ({loadTables}). Reverts unless a, b < p.
    function hash(uint256 tables, uint256 a, uint256 b) internal view returns (uint256 r) {
        if (a >= P || b >= P) revert FeltOutOfRange();
        uint256 qx = StarkTables.COMB_START_X;
        uint256 qy = StarkTables.COMB_START_Y;
        assembly ("memory-safe") {
            // Bit (31·i + j) of k → bit (8·j + i) of w: byte j < 31 of w is the comb digit of column j;
            // byte 31 carries k's top nibble.
            function transpose(k) -> w {
                for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                    let c := and(shr(mul(31, i), k), 0x7fffffff)
                    c := or(and(c, not(0x7fff0000)), shl(112, and(c, 0x7fff0000)))
                    let m := 0x7f000000000000000000000000000000ff00
                    c := or(and(c, not(m)), shl(56, and(c, m)))
                    m := 0x7000000000000000f000000000000000f000000000000000f0
                    c := or(and(c, not(m)), shl(28, and(c, m)))
                    m := 0x40000000c0000000c0000000c0000000c0000000c0000000c0000000c
                    c := or(and(c, not(m)), shl(14, and(c, m)))
                    m := 0x200020002000200020002000200020002000200020002000200020002
                    c := or(and(c, not(m)), shl(7, and(c, m)))
                    w := or(w, shl(i, c))
                }
                w := or(w, shl(248, shr(248, k)))
            }

            // `or(p, gas() >> 255)` is p, but opaque: it keeps the optimizer from rebuilding the constant
            // (with SHL/ADD) at every use instead of DUPing it.
            let p := or(0x0800000000000011000000000000000000000000000000000000000000000001, shr(255, gas()))
            let wa := transpose(a)
            let wb := transpose(b)
            let x := qx
            let y := qy
            let z := 1
            // Byte offsets into the tables: comb A point u at tables + 64·u − 63, comb B point v at
            // tables + 17218 + 64·v, nibble A d at tables + 16257 + 64·d, nibble B at tables + 33538 + 64·d.
            // A degenerate addition (h = 0) zeroes z for good; that is checked once at the end.
            for { let j := 248 } j {} {
                j := sub(j, 8)
                // ── doubling (a = 1) ──
                {
                    let yy := mulmod(y, y, p)
                    let m := mulmod(z, z, p)
                    m := addmod(mulmod(mulmod(x, x, p), 3, p), mulmod(m, m, p), p)
                    let s := mulmod(mulmod(x, yy, p), 4, p)
                    z := mulmod(addmod(y, y, p), z, p)
                    x := addmod(mulmod(m, m, p), sub(p, addmod(s, s, p)), p)
                    y := addmod(mulmod(m, addmod(s, sub(p, x), p), p), sub(p, mulmod(mulmod(yy, yy, p), 8, p)), p)
                }
                // ── + T0[u] (table A) ──
                let pt := and(shr(j, wa), 0xff)
                if pt {
                    pt := add(sub(tables, 63), shl(6, pt))
                    let rr := mulmod(z, z, p)
                    let h := addmod(mulmod(mload(pt), rr, p), sub(p, x), p)
                    rr := addmod(mulmod(mload(add(pt, 0x20)), mulmod(z, rr, p), p), sub(p, y), p)
                    z := mulmod(z, h, p)
                    let hhh := mulmod(h, h, p)
                    let v := mulmod(x, hhh, p)
                    hhh := mulmod(h, hhh, p)
                    x := addmod(addmod(mulmod(rr, rr, p), sub(p, hhh), p), sub(p, addmod(v, v, p)), p)
                    y := addmod(mulmod(rr, addmod(v, sub(p, x), p), p), sub(p, mulmod(y, hhh, p)), p)
                }
                // ── + T2[v] (table B) ──
                pt := and(shr(j, wb), 0xff)
                if pt {
                    pt := add(add(tables, 17218), shl(6, pt))
                    let rr := mulmod(z, z, p)
                    let h := addmod(mulmod(mload(pt), rr, p), sub(p, x), p)
                    rr := addmod(mulmod(mload(add(pt, 0x20)), mulmod(z, rr, p), p), sub(p, y), p)
                    z := mulmod(z, h, p)
                    let hhh := mulmod(h, h, p)
                    let v := mulmod(x, hhh, p)
                    hhh := mulmod(h, hhh, p)
                    x := addmod(addmod(mulmod(rr, rr, p), sub(p, hhh), p), sub(p, addmod(v, v, p)), p)
                    y := addmod(mulmod(rr, addmod(v, sub(p, x), p), p), sub(p, mulmod(y, hhh, p)), p)
                }
            }
            // ── + a_high·P1, + b_high·P3 (nibble tables) ──
            for { let side := 0 } lt(side, 2) { side := add(side, 1) } {
                let pt := shr(248, wa)
                if side { pt := shr(248, wb) }
                if pt {
                    pt := add(add(tables, add(16257, mul(side, 17281))), shl(6, pt))
                    let rr := mulmod(z, z, p)
                    let h := addmod(mulmod(mload(pt), rr, p), sub(p, x), p)
                    rr := addmod(mulmod(mload(add(pt, 0x20)), mulmod(z, rr, p), p), sub(p, y), p)
                    z := mulmod(z, h, p)
                    let hhh := mulmod(h, h, p)
                    let v := mulmod(x, hhh, p)
                    hhh := mulmod(h, hhh, p)
                    x := addmod(addmod(mulmod(rr, rr, p), sub(p, hhh), p), sub(p, addmod(v, v, p)), p)
                    y := addmod(mulmod(rr, addmod(v, sub(p, x), p), p), sub(p, mulmod(y, hhh, p)), p)
                }
            }

            // x / z² via z^(p − 2) (modexp precompile), at the free-memory pointer (not reserved).
            let fm := mload(0x40)
            mstore(fm, 0x20)
            mstore(add(fm, 0x20), 0x20)
            mstore(add(fm, 0x40), 0x20)
            mstore(add(fm, 0x60), z)
            mstore(add(fm, 0x80), sub(p, 2))
            mstore(add(fm, 0xa0), p)
            // z = 0 marks a degenerate addition; a failed precompile call leaves r = 0 too.
            r := 0
            if and(iszero(iszero(z)), staticcall(gas(), 0x05, fm, 0xc0, 0x00, 0x20)) {
                let zi := mload(0x00)
                r := mulmod(x, mulmod(zi, zi, p), p)
                // r = 0 is impossible for a valid result here (it would need y² = β); use it as the flag.
            }
        }
        if (r == 0) revert PedersenDegenerate();
    }
}
