/// XRPL binary codec pieces the CLPR XRPL verifier relies on, mirrored off-chain for fixture building.
/// Sources (rippled @ ddbc5f1): STObject::add (fields sorted by type, then field code), Serializer
/// VL lengths, LedgerHeader.cpp (calculateLedgerHash), SHAMapInnerNode/SHAMapTxPlusMetaLeafNode
/// (inner = sha512Half("MIN\0" ‖ 16 hashes), tx+meta leaf = sha512Half("SND\0" ‖ VL(tx) ‖ VL(meta) ‖ txid)),
/// STTx::getTransactionID (sha512Half("TXN\0" ‖ tx)).
import {createHash} from "node:crypto";

export const sha512Half = (b: Buffer) => createHash("sha512").update(b).digest().subarray(0, 32);
export const prefix = (s: string) => Buffer.from(s + "\0", "latin1");

export type Field = {type: number; field: number; start: number; end: number; value: Buffer; depth: number};

function readVL(b: Buffer, i: number): [number, number] {
    const b1 = b[i];
    if (b1 <= 192) return [b1, i + 1];
    if (b1 <= 240) return [193 + (b1 - 193) * 256 + b[i + 1], i + 2];
    if (b1 <= 254) return [12481 + (b1 - 241) * 65536 + b[i + 1] * 256 + b[i + 2], i + 3];
    throw new Error("bad VL");
}

export function encodeVL(n: number): Buffer {
    if (n <= 192) return Buffer.from([n]);
    if (n <= 12480) {
        n -= 193;
        return Buffer.from([193 + (n >> 8), n & 0xff]);
    }
    n -= 12481;
    return Buffer.from([241 + (n >> 16), (n >> 8) & 0xff, n & 0xff]);
}

const FIXED: Record<number, number> = {1: 2, 2: 4, 3: 8, 4: 16, 5: 32, 9: 12, 10: 4, 11: 8, 16: 1, 17: 20, 20: 12, 21: 24, 22: 48, 23: 64, 26: 20};

/// Flat walk of a serialized STObject; nested objects/arrays are entered (depth+1) and their end
/// markers (0xE1 / 0xF1) reported as type 14/15 field 1.
export function walk(b: Buffer): Field[] {
    const out: Field[] = [];
    let i = 0;
    let depth = 0;
    while (i < b.length) {
        const start = i;
        const h = b[i++];
        let type = h >> 4;
        let field = h & 15;
        if (type === 0) type = b[i++];
        if (field === 0) field = b[i++];
        let vstart = i;
        if (type === 14 || type === 15) {
            if (field === 1) {
                depth--;
                out.push({type, field, start, end: i, value: Buffer.alloc(0), depth});
                continue;
            }
            out.push({type, field, start, end: i, value: Buffer.alloc(0), depth});
            depth++;
            continue;
        }
        if (FIXED[type] !== undefined) i += FIXED[type];
        else if (type === 7 || type === 8 || type === 19) {
            const [n, j] = readVL(b, i);
            vstart = j;
            i = j + n;
        } else if (type === 6) {
            const f = b[i];
            i += f & 0x80 ? 48 : f & 0x20 ? 33 : 8;
        } else throw new Error(`unsupported type ${type} at ${start}`);
        out.push({type, field, start, end: i, value: b.subarray(vstart, i), depth});
    }
    return out;
}

export const top = (fs: Field[], type: number, field: number) => fs.find((f) => f.depth === 0 && f.type === type && f.field === field);

export function ledgerHash(header: Buffer): Buffer {
    return sha512Half(Buffer.concat([prefix("LWR"), header]));
}

export function parseHeader(h: Buffer) {
    return {
        seq: h.readUInt32BE(0),
        parentHash: h.subarray(12, 44),
        txHash: h.subarray(44, 76),
        accountHash: h.subarray(76, 108),
        closeTime: h.readUInt32BE(112)
    };
}

export const txId = (tx: Buffer) => sha512Half(Buffer.concat([prefix("TXN"), tx]));
export const txLeafHash = (tx: Buffer, meta: Buffer, id: Buffer) =>
    sha512Half(Buffer.concat([prefix("SND"), encodeVL(tx.length), tx, encodeVL(meta.length), meta, id]));
export const innerHash = (kids: Buffer[]) => sha512Half(Buffer.concat([prefix("MIN"), ...kids]));
const ZERO = Buffer.alloc(32);
const nib = (k: Buffer, d: number) => (d % 2 ? k[d >> 1] & 15 : k[d >> 1] >> 4);

type Item = {key: Buffer; leafHash: Buffer};
/// Build a SHAMap over `items` and return its root plus, for `target`, the 16 child hashes of every
/// inner node from the root down to the leaf (root first). A leaf sits at the first depth where it
/// is alone in its branch; the root is always an inner node.
export function shamapProof(items: Item[], target: Buffer): {root: Buffer; path: Buffer[][]} {
    const path: Buffer[][] = [];
    const build = (its: Item[], depth: number, onPath: boolean): Buffer => {
        if (its.length === 1 && depth > 0) return its[0].leafHash;
        const kids = Array.from({length: 16}, () => ZERO);
        const groups: Item[][] = Array.from({length: 16}, () => []);
        for (const it of its) groups[nib(it.key, depth)].push(it);
        const myKids: Buffer[] = [];
        const idx = path.length;
        if (onPath) path.push(myKids);
        for (let n = 0; n < 16; n++) {
            if (groups[n].length) kids[n] = build(groups[n], depth + 1, onPath && nib(target, depth) === n);
        }
        if (onPath) path[idx].push(...kids);
        return innerHash(kids);
    };
    const root = build(items, 0, true);
    return {root, path};
}
