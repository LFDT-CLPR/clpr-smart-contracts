/// BLAKE3 reference used to build Monad fixtures: the raw compression function, the standard
/// (multi-chunk) hash, and the MIP-8 storage-page commitment (ISMC).
///
/// Page commitment mirrors category/execution/monad/db/storage_page.cpp (category-labs/monad):
/// pair-leaves hashed with LEAF_IV + DERIVE_KEY_MATERIAL, bitmap-driven sibling merges with
/// CHUNK_START|CHUNK_END, then a seal BLAKE3(slot_bitmap_le16 || root32) with ROOT.

export const IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
const PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
export const CHUNK_START = 1, CHUNK_END = 2, PARENT = 4, ROOT = 8, DERIVE_KEY_MATERIAL = 64;

const rotr = (x: number, n: number) => ((x >>> n) | (x << (32 - n))) >>> 0;

/// Full 16-word compression output.
export function compress(cv: number[], block: Uint8Array, counter: bigint, blockLen: number, flags: number): number[] {
    if (block.length > 64) throw new Error("block too long");
    const b = new Uint8Array(64);
    b.set(block);
    let m: number[] = [];
    for (let i = 0; i < 16; i++) m.push((b[4 * i] | (b[4 * i + 1] << 8) | (b[4 * i + 2] << 16) | (b[4 * i + 3] << 24)) >>> 0);
    const v = [...cv, IV[0], IV[1], IV[2], IV[3], Number(counter & 0xffffffffn), Number((counter >> 32n) & 0xffffffffn), blockLen, flags];
    const g = (a: number, bb: number, c: number, d: number, mx: number, my: number) => {
        v[a] = (v[a] + v[bb] + mx) >>> 0; v[d] = rotr(v[d] ^ v[a], 16);
        v[c] = (v[c] + v[d]) >>> 0; v[bb] = rotr(v[bb] ^ v[c], 12);
        v[a] = (v[a] + v[bb] + my) >>> 0; v[d] = rotr(v[d] ^ v[a], 8);
        v[c] = (v[c] + v[d]) >>> 0; v[bb] = rotr(v[bb] ^ v[c], 7);
    };
    for (let r = 0; r < 7; r++) {
        g(0, 4, 8, 12, m[0], m[1]); g(1, 5, 9, 13, m[2], m[3]); g(2, 6, 10, 14, m[4], m[5]); g(3, 7, 11, 15, m[6], m[7]);
        g(0, 5, 10, 15, m[8], m[9]); g(1, 6, 11, 12, m[10], m[11]); g(2, 7, 8, 13, m[12], m[13]); g(3, 4, 9, 14, m[14], m[15]);
        m = PERM.map((p) => m[p]);
    }
    for (let i = 0; i < 8; i++) { v[i] = (v[i] ^ v[i + 8]) >>> 0; v[i + 8] = (v[i + 8] ^ cv[i]) >>> 0; }
    return v;
}

export function wordsToBytes(w: number[]): Uint8Array {
    const out = new Uint8Array(w.length * 4);
    w.forEach((x, i) => { out[4 * i] = x & 0xff; out[4 * i + 1] = (x >>> 8) & 0xff; out[4 * i + 2] = (x >>> 16) & 0xff; out[4 * i + 3] = (x >>> 24) & 0xff; });
    return out;
}
export function bytesToWords(b: Uint8Array): number[] {
    const w: number[] = [];
    for (let i = 0; i < b.length; i += 4) w.push((b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0);
    return w;
}

/// Standard BLAKE3 hash (32-byte output), any input length.
export function blake3(input: Uint8Array): Uint8Array {
    const nChunks = Math.max(1, Math.ceil(input.length / 1024));
    const chunkOutput = (ci: number) => {
        const chunk = input.subarray(ci * 1024, Math.min(input.length, ci * 1024 + 1024));
        const nBlocks = Math.max(1, Math.ceil(chunk.length / 64));
        let cv = IV.slice();
        for (let bi = 0; bi < nBlocks - 1; bi++) {
            cv = compress(cv, chunk.subarray(bi * 64, bi * 64 + 64), BigInt(ci), 64, bi === 0 ? CHUNK_START : 0).slice(0, 8);
        }
        const last = chunk.subarray((nBlocks - 1) * 64);
        return {cv, block: last, counter: BigInt(ci), len: last.length, flags: (nBlocks === 1 ? CHUNK_START : 0) | CHUNK_END};
    };
    if (nChunks === 1) {
        const o = chunkOutput(0);
        return wordsToBytes(compress(o.cv, o.block, o.counter, o.len, o.flags | ROOT).slice(0, 8));
    }
    const stack: number[][] = [];
    const parentCv = (l: number[], r: number[], flags: number) =>
        compress(IV, wordsToBytes([...l, ...r]), 0n, 64, PARENT | flags).slice(0, 8);
    for (let ci = 0; ci < nChunks - 1; ci++) {
        const o = chunkOutput(ci);
        let cv = compress(o.cv, o.block, o.counter, o.len, o.flags).slice(0, 8);
        let total = ci + 1;
        while ((total & 1) === 0) { cv = parentCv(stack.pop()!, cv, 0); total >>= 1; }
        stack.push(cv);
    }
    const o = chunkOutput(nChunks - 1);
    let cv = compress(o.cv, o.block, o.counter, o.len, o.flags).slice(0, 8);
    while (stack.length > 1) cv = parentCv(stack.pop()!, cv, 0);
    return wordsToBytes(parentCv(stack.pop()!, cv, ROOT));
}

const DOMAIN_KEY = new TextEncoder().encode("ultra_merkle_pair_leaf_domain___");
export const LEAF_IV = compress(IV, DOMAIN_KEY, 0n, 64, DERIVE_KEY_MATERIAL).slice(0, 8);

/// A storage page: up to 128 32-byte slot values (big-endian words), indexed by slot offset.
export type Page = Map<number, Uint8Array>;

export function pageCommit(page: Page): Uint8Array {
    let bitmap = 0n;
    for (const [i, v] of page) if (v.some((x) => x !== 0)) bitmap |= 1n << BigInt(i);
    const bm16 = new Uint8Array(16);
    for (let i = 0; i < 16; i++) bm16[i] = Number((bitmap >> BigInt(8 * i)) & 0xffn);
    const seal = (root?: Uint8Array) => {
        const blk = new Uint8Array(root ? 48 : 16);
        blk.set(bm16);
        if (root) blk.set(root, 16);
        return wordsToBytes(compress(IV, blk, 0n, blk.length, CHUNK_START | CHUNK_END | ROOT).slice(0, 8));
    };
    if (bitmap === 0n) return seal();
    const slot = (i: number) => (bitmap >> BigInt(i)) & 1n ? page.get(i)! : new Uint8Array(32);
    let pairBm = 0n;
    const scratch: Uint8Array[] = [];
    for (let i = 0; i < 64; i++) {
        if (((bitmap >> BigInt(2 * i)) & 3n) === 0n) continue;
        pairBm |= 1n << BigInt(i);
        const blk = new Uint8Array(64);
        blk.set(slot(2 * i));
        blk.set(slot(2 * i + 1), 32);
        scratch[i] = wordsToBytes(compress(LEAF_IV, blk, 0n, 64, DERIVE_KEY_MATERIAL).slice(0, 8));
    }
    const pop = (x: bigint) => x.toString(2).split("").filter((c) => c === "1").length;
    for (let level = 0; level < 6 && pop(pairBm) > 1; level++) {
        let prev = -1;
        for (let pos = 0; pos < 64; pos++) {
            if (((pairBm >> BigInt(pos)) & 1n) === 0n) continue;
            const sib = prev !== -1 && prev >> (level + 1) === pos >> (level + 1) && ((prev >> level) & 1) === 0;
            if (sib) {
                const blk = new Uint8Array(64);
                blk.set(scratch[prev]);
                blk.set(scratch[pos], 32);
                scratch[prev] = wordsToBytes(compress(IV, blk, 0n, 64, CHUNK_START | CHUNK_END).slice(0, 8));
                pairBm &= ~(1n << BigInt(pos));
                prev = -1;
            } else prev = pos;
        }
    }
    let root = 0;
    while (((pairBm >> BigInt(root)) & 1n) === 0n) root++;
    return seal(scratch[root]);
}
