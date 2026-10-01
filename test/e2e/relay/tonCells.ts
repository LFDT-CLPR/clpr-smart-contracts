import {createHash} from "node:crypto";

/// Minimal TON cell / bag-of-cells toolkit for the TON live fixture builder and relay.
///
/// Hashing follows ton-blockchain/ton `crypto/vm/cells/DataCell.cpp` (`CellChecker`): every cell keeps
/// four representation hashes and depths (levels 0..3); pruned branches return their stored hash
/// below level 3; Merkle proof / update cells hash their children one level up. `TonCellLib.sol`
/// implements the same algorithm on-chain.

export const sha256 = (b: Uint8Array): Buffer => createHash("sha256").update(b).digest();

export const CELL_ORDINARY = -1;
export const CELL_PRUNED = 1;
export const CELL_LIBRARY = 2;
export const CELL_MERKLE_PROOF = 3;
export const CELL_MERKLE_UPDATE = 4;

export class Cell {
    readonly type: number;
    readonly levelMask: number;
    readonly hashes: Buffer[] = [];
    readonly depths: number[] = [];

    constructor(
        readonly data: Buffer, // ceil(bits/8) bytes, unused tail bits zero
        readonly bits: number,
        readonly refs: Cell[],
        readonly exotic: boolean,
    ) {
        if (bits > 1023 || refs.length > 4) throw new Error("cell: too large");
        this.type = exotic ? data[0] : CELL_ORDINARY;
        let mask = 0;
        const depth = [0, 0, 0, 0];
        if (!exotic) {
            for (const r of refs) {
                mask |= r.levelMask;
                for (let j = 0; j <= 3; j++) depth[j] = Math.max(depth[j], r.depthAt(j));
            }
            if (refs.length) for (let j = 0; j <= 3; j++) depth[j]++;
        } else if (this.type === CELL_PRUNED) {
            if (refs.length) throw new Error("pruned: refs");
            mask = data[1];
            const level = 32 - Math.clz32(mask);
            if (level === 0 || level > 3) throw new Error("pruned: level");
            const hc = popcount(mask);
            if (bits !== (2 + hc * 34) * 8) throw new Error("pruned: length");
            for (let i = 2; i >= 0; i--) {
                if ((mask >> i) & 1) {
                    const before = popcount(mask & ((1 << i) - 1));
                    const off = 2 + hc * 32 + before * 2;
                    depth[i] = data.readUInt16BE(off);
                } else depth[i] = depth[i + 1];
            }
        } else if (this.type === CELL_MERKLE_PROOF || this.type === CELL_MERKLE_UPDATE) {
            const n = this.type === CELL_MERKLE_PROOF ? 1 : 2;
            if (refs.length !== n || bits !== 8 * (1 + 34 * n)) throw new Error("merkle: shape");
            for (let k = 0; k < n; k++) {
                const h = data.subarray(1 + 32 * k, 33 + 32 * k);
                const d = data.readUInt16BE(1 + 32 * n + 2 * k);
                if (!h.equals(refs[k].hashAt(0)) || d !== refs[k].depthAt(0)) throw new Error("merkle: child hash");
                for (let i = 0; i <= 3; i++) depth[i] = Math.max(depth[i], refs[k].depthAt(Math.min(3, i + 1)) + 1);
                mask |= refs[k].levelMask;
            }
            mask >>= 1;
        } else if (this.type === CELL_LIBRARY) {
            if (refs.length || bits !== 8 * 33) throw new Error("library: shape");
        } else throw new Error(`exotic type ${this.type}`);
        this.levelMask = mask;
        this.depths = depth;
        let last = -1;
        for (let i = 0; i <= 3; i++) {
            if (!(i === 3 || (mask >> i) & 1)) continue;
            this.hashes[i] = this.computeHash(i, last);
            for (let j = last + 1; j < i; j++) this.hashes[j] = this.hashes[i];
            last = i;
        }
    }

    get level(): number {
        return 32 - Math.clz32(this.levelMask);
    }
    hashAt(i: number): Buffer {
        return this.hashes[Math.min(this.level, i)];
    }
    depthAt(i: number): number {
        return this.depths[Math.min(this.level, i)];
    }
    hash(): Buffer {
        return this.hashAt(0);
    }

    private computeHash(level: number, last: number): Buffer {
        if (level !== 3 && this.type === CELL_PRUNED) {
            const before = popcount(this.levelMask & ((1 << level) - 1));
            return this.data.subarray(2 + before * 32, 34 + before * 32);
        }
        const parts: Buffer[] = [];
        const d1 = this.refs.length + (this.exotic ? 8 : 0) + ((this.levelMask & ((1 << level) - 1)) << 5);
        const d2 = ((this.bits >> 3) << 1) + (this.bits & 7 ? 1 : 0);
        parts.push(Buffer.from([d1, d2]));
        if (last !== -1 && this.type !== CELL_PRUNED) parts.push(this.hashes[last]);
        else parts.push(paddedData(this.data, this.bits));
        const merkle = this.type === CELL_MERKLE_PROOF || this.type === CELL_MERKLE_UPDATE;
        const cl = merkle ? Math.min(3, level + 1) : level;
        for (const r of this.refs) {
            const b = Buffer.alloc(2);
            b.writeUInt16BE(r.depthAt(cl));
            parts.push(b);
        }
        for (const r of this.refs) parts.push(r.hashAt(cl));
        return sha256(Buffer.concat(parts));
    }

    /// d1 ‖ d2 ‖ padded data — the BoC cell header and payload
    serializedHeader(): Buffer {
        const d1 = this.refs.length + (this.exotic ? 8 : 0) + (this.levelMask << 5);
        const d2 = ((this.bits >> 3) << 1) + (this.bits & 7 ? 1 : 0);
        return Buffer.concat([Buffer.from([d1, d2]), paddedData(this.data, this.bits)]);
    }

    slice(): Slice {
        return new Slice(this);
    }
}

function popcount(x: number): number {
    let c = 0;
    while (x) {
        c += x & 1;
        x >>= 1;
    }
    return c;
}

function paddedData(data: Buffer, bits: number): Buffer {
    const n = Math.ceil(bits / 8);
    const out = Buffer.from(data.subarray(0, n));
    if (bits % 8) {
        let lb = out[n - 1];
        lb >>= 7 - (bits % 8);
        lb |= 1;
        lb <<= 7 - (bits % 8);
        out[n - 1] = lb & 0xff;
    }
    return out;
}

/// Parse a bag of cells; returns its roots.
export function parseBoc(boc: Buffer): Cell[] {
    let p = 0;
    const magic = boc.readUInt32BE(0);
    if (magic !== 0xb5ee9c72) throw new Error("boc: magic");
    p = 4;
    const flags = boc[p++];
    const hasIdx = (flags & 0x80) !== 0;
    const hasCrc = (flags & 0x40) !== 0;
    const sz = flags & 7;
    const offBytes = boc[p++];
    const readN = (n: number) => {
        let v = 0;
        for (let i = 0; i < n; i++) v = v * 256 + boc[p++];
        return v;
    };
    const cellsN = readN(sz);
    const rootsN = readN(sz);
    readN(sz); // absent
    const totSize = readN(offBytes);
    const roots: number[] = [];
    for (let i = 0; i < rootsN; i++) roots.push(readN(sz));
    if (hasIdx) p += cellsN * offBytes;
    const raw: {d1: number; data: Buffer; bits: number; refs: number[]}[] = [];
    const start = p;
    for (let i = 0; i < cellsN; i++) {
        const d1 = boc[p++];
        const d2 = boc[p++];
        const refsN = d1 & 7;
        if (refsN > 4) throw new Error("boc: absent cells unsupported");
        if (d1 & 16) p += (popcount(d1 >> 5) + 1) * 34; // with_hashes: stored hashes + depths
        const len = Math.ceil(d2 / 2);
        let data = Buffer.from(boc.subarray(p, p + len));
        p += len;
        let bits = len * 8;
        if (d2 & 1) {
            // strip completion tag
            const lb = data[len - 1];
            const tz = lb === 0 ? 8 : Math.log2(lb & -lb);
            bits = len * 8 - tz - 1;
            data[len - 1] = lb & ~(1 << tz) & 0xff;
        }
        const refs: number[] = [];
        for (let k = 0; k < refsN; k++) refs.push(readN(sz));
        raw.push({d1, data, bits, refs});
    }
    if (p - start !== totSize) throw new Error("boc: size");
    if (hasCrc) p += 4;
    if (p !== boc.length) throw new Error("boc: trailing");
    const cells: Cell[] = new Array(cellsN);
    for (let i = cellsN - 1; i >= 0; i--) {
        const r = raw[i];
        const refs = r.refs.map((j) => {
            if (j <= i) throw new Error("boc: order");
            return cells[j];
        });
        cells[i] = new Cell(r.data, r.bits, refs, (r.d1 & 8) !== 0);
        if (((r.d1 >> 5) & 7) !== cells[i].levelMask) throw new Error("boc: level mask");
    }
    return roots.map((i) => cells[i]);
}

/// Serialize a single-root bag of cells (no index, no crc), cells in DFS pre-order with dedup.
export function serializeBoc(root: Cell): Buffer {
    const order: Cell[] = [];
    const idx = new Map<string, number>();
    const visit = (c: Cell) => {
        const k = c.hashAt(3).toString("hex") + c.serializedHeader().toString("hex");
        if (idx.has(k)) return;
        idx.set(k, order.length);
        order.push(c);
        c.refs.forEach(visit);
    };
    visit(root);
    // topological order: a ref must point to a later index. DFS pre-order with dedup can violate
    // this for shared subtrees, so re-sort by reverse post-order.
    const post: Cell[] = [];
    const seen = new Set<string>();
    const key = (c: Cell) => c.hashAt(3).toString("hex") + c.serializedHeader().toString("hex");
    const dfs = (c: Cell) => {
        if (seen.has(key(c))) return;
        seen.add(key(c));
        c.refs.forEach(dfs);
        post.push(c);
    };
    dfs(root);
    const cells = post.reverse();
    const pos = new Map(cells.map((c, i) => [key(c), i]));
    const sz = cells.length < 256 ? 1 : 2;
    const body: Buffer[] = [];
    for (const c of cells) {
        body.push(c.serializedHeader());
        for (const r of c.refs) {
            const b = Buffer.alloc(sz);
            b.writeUIntBE(pos.get(key(r))!, 0, sz);
            body.push(b);
        }
    }
    const payload = Buffer.concat(body);
    const offBytes = payload.length < 256 ? 1 : payload.length < 65536 ? 2 : 3;
    const head = Buffer.alloc(4 + 1 + 1 + 3 * sz + offBytes + sz);
    let p = head.writeUInt32BE(0xb5ee9c72, 0);
    head[p++] = sz;
    head[p++] = offBytes;
    p = head.writeUIntBE(cells.length, p, sz);
    p = head.writeUIntBE(1, p, sz);
    p = head.writeUIntBE(0, p, sz);
    p = head.writeUIntBE(payload.length, p, offBytes);
    head.writeUIntBE(0, p, sz);
    return Buffer.concat([head, payload]);
}

/// Replace `cell` by a level-1 pruned branch (its level-0 hash and depth are preserved).
export function prune(cell: Cell): Cell {
    if (cell.type === CELL_PRUNED) return cell;
    // A level-1 pruned branch carries the level-0 hash and depth, which is all a level-0 hash of the
    // parent (what the verifier checks) needs, whatever the pruned cell's own level is.
    const data = Buffer.concat([Buffer.from([CELL_PRUNED, 1]), cell.hash(), Buffer.alloc(2)]);
    data.writeUInt16BE(cell.depthAt(0), 34);
    return new Cell(data, data.length * 8, [], true);
}

export class Slice {
    pos = 0;
    ref = 0;
    constructor(readonly cell: Cell) {
        if (cell.exotic) throw new Error(`slice: exotic cell type ${cell.type}`);
    }
    get remaining(): number {
        return this.cell.bits - this.pos;
    }
    bit(): number {
        if (this.pos >= this.cell.bits) throw new Error("slice: underflow");
        const b = (this.cell.data[this.pos >> 3] >> (7 - (this.pos & 7))) & 1;
        this.pos++;
        return b;
    }
    uint(n: number): bigint {
        let v = 0n;
        for (let i = 0; i < n; i++) v = (v << 1n) | BigInt(this.bit());
        return v;
    }
    int(n: number): bigint {
        const v = this.uint(n);
        return n && v >> BigInt(n - 1) ? v - (1n << BigInt(n)) : v;
    }
    num(n: number): number {
        return Number(this.uint(n));
    }
    bytes(n: number): Buffer {
        const out = Buffer.alloc(n);
        for (let i = 0; i < n; i++) out[i] = this.num(8);
        return out;
    }
    loadRef(): Cell {
        if (this.ref >= this.cell.refs.length) throw new Error("slice: no ref");
        return this.cell.refs[this.ref++];
    }
    skip(n: number): void {
        if (this.pos + n > this.cell.bits) throw new Error("slice: underflow");
        this.pos += n;
    }
}

/// Bits needed to store 0..n (TL-B `#<= n`).
export const bitsFor = (n: number): number => (n === 0 ? 0 : 32 - Math.clz32(n));

/// Read a hashmap label (TL-B HmLabel ~l m), returning the label as a bit array.
export function readLabel(s: Slice, m: number): number[] {
    if (s.bit() === 0) {
        // hml_short$0 len:(Unary ~n) s:(n * Bit)
        let n = 0;
        while (s.bit() === 1) n++;
        return Array.from({length: n}, () => s.bit());
    }
    if (s.bit() === 0) {
        // hml_long$10 n:(#<= m) s:(n * Bit)
        const n = s.num(bitsFor(m));
        return Array.from({length: n}, () => s.bit());
    }
    // hml_same$11 v:Bit n:(#<= m)
    const v = s.bit();
    const n = s.num(bitsFor(m));
    return Array.from({length: n}, () => v);
}

/// Look up `key` (n bits) in a Hashmap rooted at `root`. Returns the leaf slice positioned at the
/// value (after the label), plus the path of cells visited (root first). `aug` skips nothing: the
/// caller reads the extra itself.
export function hashmapLookup(root: Cell, keyBits: number[], n: number): {leaf: Slice; path: Cell[]} | null {
    let cell = root;
    let m = n;
    let k = 0;
    const path: Cell[] = [];
    for (;;) {
        path.push(cell);
        const s = cell.slice();
        const label = readLabel(s, m);
        for (const b of label) {
            if (keyBits[k++] !== b) return null;
        }
        m -= label.length;
        if (m === 0) return {leaf: s, path};
        const dir = keyBits[k++];
        m -= 1;
        cell = cell.refs[dir];
    }
}

export function bitsOf(v: bigint, n: number): number[] {
    const out: number[] = [];
    for (let i = n - 1; i >= 0; i--) out.push(Number((v >> BigInt(i)) & 1n));
    return out;
}

export function bufBits(b: Buffer): number[] {
    const out: number[] = [];
    for (const x of b) for (let i = 7; i >= 0; i--) out.push((x >> i) & 1);
    return out;
}

/// Union of two Merkle proofs of the same tree: wherever one side is a pruned branch and the other
/// is not, keep the unpruned side.
export function mergeProofs(a: Cell, b: Cell): Cell {
    if (!a.hash().equals(b.hash())) throw new Error("merge: different trees");
    if (a.type === CELL_PRUNED) return b;
    if (b.type === CELL_PRUNED) return a;
    if (a.refs.length !== b.refs.length) throw new Error("merge: shape");
    const refs = a.refs.map((r, i) => mergeProofs(r, b.refs[i]));
    return new Cell(a.data, a.bits, refs, a.exotic);
}

/// The proven tree of a MERKLE_PROOF root (or the cell itself).
export const unwrapProof = (c: Cell): Cell => (c.type === CELL_MERKLE_PROOF ? c.refs[0] : c);

/// Rebuild `root` keeping only the cells in `keep` (by identity); every other cell becomes a pruned branch.
export function pruneExcept(root: Cell, keep: Set<Cell>): Cell {
    const walk = (c: Cell): Cell => (keep.has(c) ? new Cell(c.data, c.bits, c.refs.map(walk), c.exotic) : prune(c));
    return walk(root);
}
