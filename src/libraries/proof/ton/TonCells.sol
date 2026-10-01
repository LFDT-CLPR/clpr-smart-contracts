// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title TonCells
/// @notice TON bag-of-cells parsing, representation hashes (all four levels) and bit-slice reads.
///
/// Hashing is a port of ton-blockchain/ton `crypto/vm/cells/DataCell.cpp` (`CellChecker`, master
/// `3d478cb`, Aug 2026): each cell has a level mask and hashes/depths for levels 0..3. A pruned
/// branch returns its stored hashes below level 3; a Merkle proof or update hashes its children one
/// level up; at a level above the first computed one, the data is replaced by the previous hash.
/// A Merkle proof is therefore checked simply by computing the level-0 hash of the proof's root (or
/// of its child, when the root is a MERKLE_PROOF cell): pruned subtrees contribute their original
/// hash. Reading into a pruned cell reverts, so a verifier can only ever read data the proof shows.
library TonCells {
    uint8 internal constant ORDINARY = 0;
    uint8 internal constant PRUNED = 1;
    uint8 internal constant LIBRARY = 2;
    uint8 internal constant MERKLE_PROOF = 3;
    uint8 internal constant MERKLE_UPDATE = 4;
    uint256 internal constant MAX_CELLS = 4096;

    struct Cell {
        uint256 dataOff; // absolute offset of the (padded) data in Boc.data
        uint256 bits;
        uint256 dataLen; // ceil(bits / 8)
        uint256 refCount;
        uint8 cellType;
        uint8 mask;
        uint256[4] refs;
        bytes32[4] hashes;
        uint256[4] depths;
    }

    struct Boc {
        bytes data;
        Cell[] cells;
        uint256 root; // index of the (virtual) root: the child of a MERKLE_PROOF root
    }

    struct Slice {
        uint256 cell;
        uint256 pos;
        uint256 ref;
    }

    error BocMalformed(uint256 code);
    error CellMalformed(uint256 index);
    error PrunedRead(uint256 index);
    error SliceUnderflow();
    error RefUnderflow();
    error RootHashMismatch(bytes32 expected, bytes32 got);
    error KeyNotFound();

    // ── parsing ──────────────────────────────────────────────────────────────

    /// @notice Parse a single-root bag of cells (index, crc32c and cached hashes are accepted and
    ///         ignored) and compute every cell's hashes. A MERKLE_PROOF root is unwrapped.
    function parse(bytes memory boc) internal view returns (Boc memory b) {
        b.data = boc;
        uint256 p = 0;
        if (boc.length < 6 || _readBE(boc, 0, 4) != 0xb5ee9c72) revert BocMalformed(1);
        uint256 flags = uint8(boc[4]);
        uint256 sz = flags & 7;
        uint256 offBytes = uint8(boc[5]);
        if (sz == 0 || sz > 4 || offBytes == 0 || offBytes > 8) revert BocMalformed(2);
        p = 6;
        uint256 n = _readBE(boc, p, sz);
        uint256 rootsN = _readBE(boc, p + sz, sz);
        uint256 absent = _readBE(boc, p + 2 * sz, sz);
        p += 3 * sz;
        uint256 totSize = _readBE(boc, p, offBytes);
        p += offBytes;
        if (n == 0 || n > MAX_CELLS || rootsN != 1 || absent != 0) revert BocMalformed(3);
        uint256 rootIdx = _readBE(boc, p, sz);
        p += sz;
        if (flags & 0x80 != 0) p += n * offBytes; // index
        uint256 start = p;
        b.cells = new Cell[](n);
        for (uint256 i = 0; i < n; i++) {
            if (p + 2 > boc.length) revert BocMalformed(4);
            uint256 d1 = uint8(boc[p]);
            uint256 d2 = uint8(boc[p + 1]);
            p += 2;
            Cell memory c = b.cells[i];
            c.refCount = d1 & 7;
            if (c.refCount > 4) revert CellMalformed(i);
            if (d1 & 16 != 0) p += (_popcount(d1 >> 5) + 1) * 34; // stored hashes: ignored, recomputed
            uint256 len = (d2 >> 1) + (d2 & 1);
            if (p + len > boc.length) revert BocMalformed(5);
            c.dataOff = p;
            c.dataLen = len;
            c.bits = len * 8;
            if (d2 & 1 != 0) {
                uint256 lb = uint8(boc[p + len - 1]);
                if (lb == 0) revert CellMalformed(i);
                uint256 tz = 0;
                while ((lb >> tz) & 1 == 0) tz++;
                c.bits = len * 8 - tz - 1;
            }
            if (c.bits > 1023) revert CellMalformed(i);
            p += len;
            for (uint256 k = 0; k < c.refCount; k++) {
                uint256 r = _readBE(boc, p, sz);
                p += sz;
                if (r <= i || r >= n) revert CellMalformed(i);
                c.refs[k] = r;
            }
            c.cellType = d1 & 8 != 0 ? 255 : ORDINARY; // exotic type resolved below
            c.mask = uint8(d1 >> 5);
        }
        if (p - start != totSize) revert BocMalformed(6);
        if (flags & 0x40 != 0) p += 4; // crc32c
        if (p != boc.length) revert BocMalformed(7);
        for (uint256 i = n; i > 0; i--) {
            _computeCell(b, i - 1);
        }
        b.root = rootIdx;
        if (b.cells[rootIdx].cellType == MERKLE_PROOF) b.root = b.cells[rootIdx].refs[0];
    }

    /// @notice Parse and require the virtual root's level-0 hash to be `expected`.
    function parseExpect(bytes memory boc, bytes32 expected) internal view returns (Boc memory b) {
        b = parse(boc);
        bytes32 got = b.cells[b.root].hashes[0];
        if (got != expected) revert RootHashMismatch(expected, got);
    }

    function hash0(Boc memory b, uint256 i) internal pure returns (bytes32) {
        return b.cells[i].hashes[0];
    }

    function _computeCell(Boc memory b, uint256 i) private view {
        Cell memory c = b.cells[i];
        uint256 storedMask = c.mask;
        uint256 mask = 0;
        bytes memory data = b.data;
        if (c.cellType == ORDINARY) {
            for (uint256 k = 0; k < c.refCount; k++) {
                Cell memory r = b.cells[c.refs[k]];
                mask |= r.mask;
                for (uint256 j = 0; j < 4; j++) {
                    uint256 d = _depthAt(r, j);
                    if (d > c.depths[j]) c.depths[j] = d;
                }
            }
            if (c.refCount != 0) {
                for (uint256 j = 0; j < 4; j++) {
                    c.depths[j] += 1;
                }
            }
        } else {
            if (c.bits < 8) revert CellMalformed(i);
            uint8 t = uint8(data[c.dataOff]);
            c.cellType = t;
            if (t == PRUNED) {
                if (c.refCount != 0 || c.bits < 16) revert CellMalformed(i);
                mask = uint8(data[c.dataOff + 1]);
                uint256 lvl = _level(mask);
                if (lvl == 0 || lvl > 3) revert CellMalformed(i);
                uint256 hc = _popcount(mask);
                if (c.bits != (2 + hc * 34) * 8) revert CellMalformed(i);
                for (uint256 j = 3; j > 0; j--) {
                    uint256 lv = j - 1;
                    if ((mask >> lv) & 1 != 0) {
                        uint256 before = _popcount(mask & ((1 << lv) - 1));
                        c.depths[lv] = _readBE(data, c.dataOff + 2 + hc * 32 + before * 2, 2);
                    } else {
                        c.depths[lv] = c.depths[lv + 1];
                    }
                }
            } else if (t == LIBRARY) {
                if (c.refCount != 0 || c.bits != 8 * 33) revert CellMalformed(i);
            } else if (t == MERKLE_PROOF || t == MERKLE_UPDATE) {
                uint256 nRefs = t == MERKLE_PROOF ? 1 : 2;
                if (c.refCount != nRefs || c.bits != 8 * (1 + 34 * nRefs)) revert CellMalformed(i);
                for (uint256 k = 0; k < nRefs; k++) {
                    Cell memory r = b.cells[c.refs[k]];
                    bytes32 h = _word(data, c.dataOff + 1 + 32 * k);
                    uint256 d = _readBE(data, c.dataOff + 1 + 32 * nRefs + 2 * k, 2);
                    if (h != r.hashes[0] || d != _depthAt(r, 0)) revert CellMalformed(i);
                    for (uint256 j = 0; j < 4; j++) {
                        uint256 dd = _depthAt(r, j < 3 ? j + 1 : 3) + 1;
                        if (dd > c.depths[j]) c.depths[j] = dd;
                    }
                    mask |= r.mask;
                }
                mask >>= 1;
            } else {
                revert CellMalformed(i);
            }
        }
        if (mask != storedMask) revert CellMalformed(i);
        c.mask = uint8(mask);

        int256 last = -1;
        for (uint256 l = 0; l < 4; l++) {
            if (l != 3 && (mask >> l) & 1 == 0) continue;
            c.hashes[l] = _hashAt(b, c, l, last);
            for (uint256 j = uint256(last + 1); j < l; j++) {
                c.hashes[j] = c.hashes[l];
            }
            last = int256(l);
        }
    }

    function _hashAt(Boc memory b, Cell memory c, uint256 level, int256 last) private view returns (bytes32 h) {
        bytes memory data = b.data;
        if (c.cellType == PRUNED && level != 3) {
            uint256 before = _popcount(uint256(c.mask) & ((1 << level) - 1));
            return _word(data, c.dataOff + 2 + before * 32);
        }
        bool exotic = c.cellType != ORDINARY;
        uint256 d1 = c.refCount + (exotic ? 8 : 0) + ((uint256(c.mask) & ((1 << level) - 1)) << 5);
        uint256 d2 = ((c.bits >> 3) << 1) + (c.bits & 7 != 0 ? 1 : 0);
        bool merkle = c.cellType == MERKLE_PROOF || c.cellType == MERKLE_UPDATE;
        uint256 cl = merkle ? (level < 3 ? level + 1 : 3) : level;
        // Build the preimage in free memory without allocating (≤ 2 + 128 + 4·2 + 4·32 bytes).
        uint256 ptr;
        assembly ("memory-safe") {
            ptr := mload(0x40)
            mstore8(ptr, d1)
            mstore8(add(ptr, 1), d2)
        }
        uint256 len = 2;
        if (last != -1 && c.cellType != PRUNED) {
            bytes32 prev = c.hashes[uint256(last)];
            assembly ("memory-safe") {
                mstore(add(ptr, 2), prev)
            }
            len += 32;
        } else {
            uint256 src = c.dataOff;
            uint256 n = c.dataLen;
            assembly ("memory-safe") {
                let s := add(add(data, 0x20), src)
                for { let i := 0 } lt(i, n) { i := add(i, 32) } {
                    mstore(add(add(ptr, 2), i), mload(add(s, i)))
                }
            }
            len += n;
        }
        uint256 refCount = c.refCount;
        for (uint256 k = 0; k < refCount; k++) {
            uint256 d = _depthAt(b.cells[c.refs[k]], cl);
            assembly ("memory-safe") {
                mstore8(add(ptr, len), shr(8, d))
                mstore8(add(ptr, add(len, 1)), and(d, 0xff))
            }
            len += 2;
        }
        for (uint256 k = 0; k < refCount; k++) {
            bytes32 rh = b.cells[c.refs[k]].hashes[cl];
            assembly ("memory-safe") {
                mstore(add(ptr, len), rh)
            }
            len += 32;
        }
        assembly ("memory-safe") {
            if iszero(staticcall(gas(), 0x02, ptr, len, 0x00, 0x20)) { revert(0, 0) }
            h := mload(0x00)
        }
    }

    function _depthAt(Cell memory c, uint256 i) private pure returns (uint256) {
        uint256 lvl = _level(c.mask);
        return c.depths[i < lvl ? i : lvl];
    }

    // ── slices ───────────────────────────────────────────────────────────────

    /// @notice Open a slice on an ordinary cell. Pruned branches (data not in the proof) and other
    ///         exotic cells revert.
    function open(Boc memory b, uint256 cell) internal pure returns (Slice memory s) {
        if (b.cells[cell].cellType != ORDINARY) revert PrunedRead(cell);
        s.cell = cell;
    }

    function remaining(Boc memory b, Slice memory s) internal pure returns (uint256) {
        return b.cells[s.cell].bits - s.pos;
    }

    function refsLeft(Boc memory b, Slice memory s) internal pure returns (uint256) {
        return b.cells[s.cell].refCount - s.ref;
    }

    /// @notice Read `n` ≤ 256 bits as a big-endian unsigned integer.
    function loadUint(Boc memory b, Slice memory s, uint256 n) internal pure returns (uint256 v) {
        if (n == 0) return 0;
        Cell memory c = b.cells[s.cell];
        if (s.pos + n > c.bits) revert SliceUnderflow();
        if (n > 248) {
            uint256 hi = loadUint(b, s, n - 128);
            return (hi << 128) | loadUint(b, s, 128);
        }
        bytes memory data = b.data;
        uint256 byteOff = c.dataOff + (s.pos >> 3);
        uint256 shift = s.pos & 7;
        uint256 w;
        assembly ("memory-safe") {
            w := mload(add(add(data, 0x20), byteOff))
        }
        v = (w << shift) >> (256 - n);
        s.pos += n;
    }

    function loadBit(Boc memory b, Slice memory s) internal pure returns (bool) {
        return loadUint(b, s, 1) == 1;
    }

    function skip(Boc memory b, Slice memory s, uint256 n) internal pure {
        if (s.pos + n > b.cells[s.cell].bits) revert SliceUnderflow();
        s.pos += n;
    }

    /// @notice Next reference (cell index); does not open it.
    function loadRef(Boc memory b, Slice memory s) internal pure returns (uint256 r) {
        Cell memory c = b.cells[s.cell];
        if (s.ref >= c.refCount) revert RefUnderflow();
        r = c.refs[s.ref];
        s.ref += 1;
    }

    function ref(Boc memory b, uint256 cell, uint256 k) internal pure returns (uint256) {
        Cell memory c = b.cells[cell];
        if (k >= c.refCount) revert RefUnderflow();
        return c.refs[k];
    }

    /// @notice Raw bytes of an exotic cell's data (e.g. a MERKLE_UPDATE's hashes), by byte offset.
    function exoticWord(Boc memory b, uint256 cell, uint256 byteOff) internal pure returns (bytes32) {
        Cell memory c = b.cells[cell];
        if (byteOff + 32 > c.dataLen) revert SliceUnderflow();
        return _word(b.data, c.dataOff + byteOff);
    }

    /// @notice TL-B `VarUInteger n` with a `lenBits`-bit length prefix; returns the value.
    function loadVarUint(Boc memory b, Slice memory s, uint256 lenBits) internal pure returns (uint256) {
        uint256 len = loadUint(b, s, lenBits);
        return loadUint(b, s, len * 8);
    }

    /// @notice Skip a `CurrencyCollection` (Grams + ExtraCurrencyCollection dict).
    function skipCurrencyCollection(Boc memory b, Slice memory s) internal pure {
        loadVarUint(b, s, 4);
        if (loadBit(b, s)) loadRef(b, s);
    }

    // ── hashmaps ─────────────────────────────────────────────────────────────

    /// @notice Read an `HmLabel ~l m`; returns its length and value (≤ 256 bits).
    function loadLabel(Boc memory b, Slice memory s, uint256 m) internal pure returns (uint256 len, uint256 val) {
        if (!loadBit(b, s)) {
            // hml_short$0: unary length then bits
            while (loadBit(b, s)) {
                len++;
            }
            if (len > m) revert KeyNotFound();
            val = loadUint(b, s, len);
        } else if (!loadBit(b, s)) {
            // hml_long$10
            len = loadUint(b, s, _bitLength(m));
            if (len > m) revert KeyNotFound();
            val = loadUint(b, s, len);
        } else {
            // hml_same$11
            bool v = loadBit(b, s);
            len = loadUint(b, s, _bitLength(m));
            if (len > m) revert KeyNotFound();
            val = v ? (len == 256 ? type(uint256).max : (1 << len) - 1) : 0;
        }
    }

    /// @notice Look up `key` (n bits) in the Hashmap rooted at `root`; returns the leaf slice
    ///         positioned after the label (at the value, or at the extra for an augmented map).
    function lookup(Boc memory b, uint256 root, uint256 key, uint256 n) internal pure returns (Slice memory s) {
        uint256 cell = root;
        uint256 m = n;
        for (;;) {
            s = open(b, cell);
            (uint256 len, uint256 val) = loadLabel(b, s, m);
            uint256 part = len == 0 ? 0 : (key >> (m - len)) & (len == 256 ? type(uint256).max : (1 << len) - 1);
            if (part != val) revert KeyNotFound();
            m -= len;
            if (m == 0) return s;
            uint256 dir = (key >> (m - 1)) & 1;
            m -= 1;
            cell = ref(b, cell, dir);
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    function _bitLength(uint256 m) private pure returns (uint256 l) {
        while (m != 0) {
            l++;
            m >>= 1;
        }
    }

    function _level(uint256 mask) private pure returns (uint256) {
        return mask >= 4 ? 3 : mask >= 2 ? 2 : mask >= 1 ? 1 : 0;
    }

    function _popcount(uint256 x) private pure returns (uint256 c) {
        while (x != 0) {
            c += x & 1;
            x >>= 1;
        }
    }

    function _readBE(bytes memory d, uint256 off, uint256 n) private pure returns (uint256 v) {
        if (off + n > d.length) revert BocMalformed(8);
        for (uint256 i = 0; i < n; i++) {
            v = (v << 8) | uint8(d[off + i]);
        }
    }

    function _word(bytes memory d, uint256 off) private pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(d, 0x20), off))
        }
    }
}
