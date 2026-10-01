import {blake2s} from "@noble/hashes/blake2s";

/// Mithril `MKMapProof<BlockRange>` (bincode 2, standard config) and the ckb-merkle-mountain-range
/// 0.6.1 proof algorithm with Mithril's merge `Blake2s-256(lhs ‖ rhs)` (internal/mithril-merkle-tree).

export interface MKProof {
    root: Uint8Array;
    leaves: {pos: bigint; node: Uint8Array}[];
    mmrSize: bigint;
    items: Uint8Array[];
}
export interface MKMapProof {
    master: MKProof;
    subs: {start: bigint; end: bigint; proof: MKMapProof}[];
}

class Bin {
    off = 0;
    constructor(private b: Uint8Array) {}
    u8() {
        if (this.off >= this.b.length) throw new Error("bincode: eof");
        return this.b[this.off++];
    }
    varint(): bigint {
        const t = this.u8();
        if (t < 251) return BigInt(t);
        const n = t === 251 ? 2 : t === 252 ? 4 : t === 253 ? 8 : t === 254 ? 16 : -1;
        if (n < 0) throw new Error("bincode: bad varint tag");
        let v = 0n;
        for (let i = 0; i < n; i++) v |= BigInt(this.u8()) << BigInt(8 * i);
        return v;
    }
    bytes(): Uint8Array {
        const n = Number(this.varint());
        const v = this.b.subarray(this.off, this.off + n);
        if (v.length !== n) throw new Error("bincode: eof");
        this.off += n;
        return v;
    }
    done() {
        if (this.off !== this.b.length) throw new Error("bincode: trailing bytes");
    }
}

function readMK(r: Bin): MKProof {
    const root = r.bytes();
    const nl = Number(r.varint());
    const leaves = [];
    for (let i = 0; i < nl; i++) leaves.push({pos: r.varint(), node: r.bytes()});
    const mmrSize = r.varint();
    const ni = Number(r.varint());
    const items = [];
    for (let i = 0; i < ni; i++) items.push(r.bytes());
    return {root, leaves, mmrSize, items};
}

function readMap(r: Bin): MKMapProof {
    const master = readMK(r);
    const ns = Number(r.varint());
    const subs = [];
    for (let i = 0; i < ns; i++) {
        const start = r.varint();
        const end = r.varint();
        subs.push({start, end, proof: readMap(r)});
    }
    return {master, subs};
}

export function decodeMKMapProof(hexStr: string): MKMapProof {
    const r = new Bin(Buffer.from(hexStr, "hex"));
    const p = readMap(r);
    r.done();
    return p;
}

// ── MMR helpers (ckb-merkle-mountain-range 0.6.1 helper.rs, verbatim logic) ─────

const U64 = (1n << 64n) - 1n;
const leadingZeros = (x: bigint) => 64 - (x === 0n ? 0 : x.toString(2).length);
export function posHeight(pos: bigint): number {
    if (pos === 0n) return 0;
    let peakSize = U64 >> BigInt(leadingZeros(pos));
    while (peakSize > 0n) {
        if (pos >= peakSize) pos -= peakSize;
        peakSize >>= 1n;
    }
    return Number(pos);
}
export const parentOffset = (h: number) => 2n << BigInt(h);
export const siblingOffset = (h: number) => (2n << BigInt(h)) - 1n;
export function getPeaks(mmrSize: bigint): bigint[] {
    if (mmrSize === 0n) return [];
    let pos = mmrSize;
    let peakSize = U64 >> BigInt(leadingZeros(mmrSize));
    const peaks: bigint[] = [];
    let sum = 0n;
    while (peakSize > 0n) {
        if (pos >= peakSize) {
            pos -= peakSize;
            peaks.push(sum + peakSize - 1n);
            sum += peakSize;
        }
        peakSize >>= 1n;
    }
    return peaks;
}

const merge = (a: Uint8Array, b: Uint8Array) => blake2s(Buffer.concat([a, b]));

export function calculateRoot(leaves: {pos: bigint; node: Uint8Array}[], mmrSize: bigint, items: Uint8Array[]): Uint8Array {
    const it = items[Symbol.iterator]();
    const next = () => it.next().value as Uint8Array | undefined;
    if (leaves.some((l) => posHeight(l.pos) > 0)) throw new Error("node proofs not supported");
    let ls = leaves.slice().sort((a, b) => (a.pos < b.pos ? -1 : 1));
    const peaksHashes: Uint8Array[] = [];
    if (mmrSize === 1n && ls.length === 1 && ls[0].pos === 0n) return ls[0].node;
    for (const peak of getPeaks(mmrSize)) {
        const mine = ls.filter((l) => l.pos <= peak);
        ls = ls.filter((l) => l.pos > peak);
        let root: Uint8Array | undefined;
        if (mine.length === 1 && mine[0].pos === peak) root = mine[0].node;
        else if (mine.length === 0) {
            root = next();
            if (!root) break;
        } else {
            const q = mine.map((l) => ({pos: l.pos, item: l.node, h: 0}));
            for (;;) {
                const cur = q.shift();
                if (!cur) throw new Error("corrupted");
                if (cur.pos === peak) {
                    if (q.length) throw new Error("corrupted");
                    root = cur.item;
                    break;
                }
                const nextH = posHeight(cur.pos + 1n);
                let ppos: bigint;
                let pitem: Uint8Array;
                if (nextH > cur.h) {
                    const sib = cur.pos - siblingOffset(cur.h);
                    ppos = cur.pos + 1n;
                    const s = q[0]?.pos === sib ? q.shift()!.item : next();
                    if (!s) throw new Error("corrupted");
                    pitem = merge(s, cur.item);
                } else {
                    const sib = cur.pos + siblingOffset(cur.h);
                    ppos = cur.pos + parentOffset(cur.h);
                    const s = q[0]?.pos === sib ? q.shift()!.item : next();
                    if (!s) throw new Error("corrupted");
                    pitem = merge(cur.item, s);
                }
                if (ppos > peak) throw new Error("corrupted");
                q.push({pos: ppos, item: pitem, h: cur.h + 1});
            }
        }
        peaksHashes.push(root!);
    }
    if (ls.length) throw new Error("corrupted");
    const rhs = next();
    if (rhs) peaksHashes.push(rhs);
    if (next()) throw new Error("corrupted");
    while (peaksHashes.length > 1) {
        const r = peaksHashes.pop()!;
        const l = peaksHashes.pop()!;
        peaksHashes.push(merge(r, l));
    }
    return peaksHashes[0];
}

export const rangeKey = (start: bigint, end: bigint) => Buffer.from(`${start}-${end}`);

export function verifyMKMapProof(p: MKMapProof): Uint8Array {
    for (const s of p.subs) verifyMKMapProof(s.proof);
    const root = calculateRoot(p.master.leaves, p.master.mmrSize, p.master.items);
    if (!Buffer.from(root).equals(Buffer.from(p.master.root))) throw new Error("master root mismatch");
    for (const s of p.subs) {
        const leaf = merge(rangeKey(s.start, s.end), s.proof.master.root);
        if (!p.master.leaves.some((l) => Buffer.from(l.node).equals(Buffer.from(leaf)))) throw new Error("sub not in master");
    }
    return root;
}
