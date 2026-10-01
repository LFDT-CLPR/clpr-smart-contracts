// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {TonCells} from "@hiero-ledger/clpr/libraries/proof/ton/TonCells.sol";

/// @notice Builds TON cell trees and serializes them as bags of cells, for the synthetic TonVerifier
///         suite. Hashes are not computed here: a tree's root hash and depth come from parsing its
///         BoC with the production {TonCells} library.
library TonCellBuilder {
    struct Cell {
        bytes data; // 128-byte buffer, bit-packed big-endian
        uint256 bits;
        uint256[] refs;
        bool exotic;
        uint8 mask;
    }

    struct Tree {
        Cell[] cells;
        uint256 n;
    }

    /// @dev A bit writer for one cell.
    struct W {
        bytes buf;
        uint256 bits;
    }

    function tree() internal pure returns (Tree memory t) {
        t.cells = new Cell[](128);
    }

    function w() internal pure returns (W memory x) {
        x.buf = new bytes(128);
    }

    function u(W memory x, uint256 v, uint256 n) internal pure returns (W memory) {
        for (uint256 i = n; i > 0; i--) {
            if ((v >> (i - 1)) & 1 == 1) {
                x.buf[x.bits / 8] = bytes1(uint8(x.buf[x.bits / 8]) | uint8(1 << (7 - (x.bits % 8))));
            }
            x.bits++;
        }
        require(x.bits <= 1023, "cell overflow");
        return x;
    }

    function b32(W memory x, bytes32 v) internal pure returns (W memory) {
        return u(x, uint256(v), 256);
    }

    /// HmLabel as hml_long$10 n:(#<= m) s:(n * Bit)
    function label(W memory x, uint256 value, uint256 len, uint256 m) internal pure returns (W memory) {
        u(x, 2, 2);
        uint256 lb;
        for (uint256 t = m; t != 0; t >>= 1) {
            lb++;
        }
        u(x, len, lb);
        return u(x, value, len);
    }

    function add(Tree memory t, W memory x, uint256[] memory refs) internal pure returns (uint256 i) {
        i = t.n++;
        uint8 mask;
        for (uint256 k = 0; k < refs.length; k++) {
            mask |= t.cells[refs[k]].mask;
        }
        t.cells[i] = Cell(x.buf, x.bits, refs, false, mask);
    }

    function leaf(Tree memory t, W memory x) internal pure returns (uint256) {
        return add(t, x, new uint256[](0));
    }

    function add1(Tree memory t, W memory x, uint256 r0) internal pure returns (uint256) {
        uint256[] memory r = new uint256[](1);
        r[0] = r0;
        return add(t, x, r);
    }

    function add2(Tree memory t, W memory x, uint256 r0, uint256 r1) internal pure returns (uint256) {
        uint256[] memory r = new uint256[](2);
        (r[0], r[1]) = (r0, r1);
        return add(t, x, r);
    }

    /// A level-1 pruned branch standing for a cell with `hash` / `depth`.
    function pruned(Tree memory t, bytes32 hash, uint16 depth) internal pure returns (uint256 i) {
        W memory x = w();
        u(x, 1, 8);
        u(x, 1, 8);
        b32(x, hash);
        u(x, depth, 16);
        i = t.n++;
        t.cells[i] = Cell(x.buf, x.bits, new uint256[](0), true, 1);
    }

    function dummy(Tree memory t, string memory tag) internal pure returns (uint256) {
        return pruned(t, keccak256(bytes(tag)), 3);
    }

    /// `!merkle_update` whose two children are pruned branches (old, new).
    function merkleUpdate(Tree memory t, bytes32 oldHash, bytes32 newHash, uint16 newDepth)
        internal
        pure
        returns (uint256 i)
    {
        uint256 o = pruned(t, oldHash, 3);
        uint256 nw = pruned(t, newHash, newDepth);
        W memory x = w();
        u(x, 4, 8);
        b32(x, oldHash);
        b32(x, newHash);
        u(x, 3, 16);
        u(x, newDepth, 16);
        uint256[] memory r = new uint256[](2);
        (r[0], r[1]) = (o, nw);
        i = t.n++;
        t.cells[i] = Cell(x.buf, x.bits, r, true, 0); // (1 | 1) >> 1
    }

    // ── serialization ───────────────────────────────────────────────────────

    function boc(Tree memory t, uint256 root) internal pure returns (bytes memory out) {
        uint256[] memory order = new uint256[](t.n);
        uint256[] memory pos = new uint256[](t.n);
        for (uint256 i = 0; i < t.n; i++) {
            pos[i] = type(uint256).max;
        }
        uint256 cnt = _dfs(t, root, order, pos, 0);
        require(cnt < 256, "too many cells");
        bytes memory body;
        for (uint256 k = 0; k < cnt; k++) {
            Cell memory c = t.cells[order[k]];
            uint256 len = (c.bits + 7) / 8;
            bytes memory d = new bytes(len);
            for (uint256 j = 0; j < len; j++) {
                d[j] = c.data[j];
            }
            if (c.bits % 8 != 0) d[len - 1] = bytes1(uint8(d[len - 1]) | uint8(1 << (7 - (c.bits % 8))));
            uint8 d1 = uint8(c.refs.length) + (c.exotic ? 8 : 0) + (c.mask << 5);
            uint8 d2 = uint8((c.bits / 8) * 2 + (c.bits % 8 != 0 ? 1 : 0));
            body = abi.encodePacked(body, d1, d2, d);
            for (uint256 r = 0; r < c.refs.length; r++) {
                body = abi.encodePacked(body, uint8(pos[c.refs[r]]));
            }
        }
        require(body.length < 65536, "boc too large");
        out = abi.encodePacked(
            hex"b5ee9c72", uint8(1), uint8(2), uint8(cnt), uint8(1), uint8(0), uint16(body.length), uint8(0), body
        );
    }

    function _dfs(Tree memory t, uint256 i, uint256[] memory order, uint256[] memory pos, uint256 cnt)
        private
        pure
        returns (uint256)
    {
        require(pos[i] == type(uint256).max, "shared cell");
        pos[i] = cnt;
        order[cnt++] = i;
        uint256[] memory refs = t.cells[i].refs;
        for (uint256 k = 0; k < refs.length; k++) {
            cnt = _dfs(t, refs[k], order, pos, cnt);
        }
        return cnt;
    }

    /// Root hash and depth of a subtree (via the production parser).
    function hashOf(Tree memory t, uint256 root) internal view returns (bytes32 h, uint16 depth) {
        TonCells.Boc memory b = TonCells.parse(boc(t, root));
        h = b.cells[b.root].hashes[0];
        uint256 lvl = b.cells[b.root].mask;
        depth = uint16(b.cells[b.root].depths[lvl == 0 ? 0 : 0]);
    }
}
