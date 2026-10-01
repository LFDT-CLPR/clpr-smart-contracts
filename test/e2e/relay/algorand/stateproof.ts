import {sha256} from "@noble/hashes/sha2";
import {shake256} from "@noble/hashes/sha3";
import {bin, encBin, encStr, encUint, get, int, mpDecode, type Node} from "./msgpack.js";
import {sumhash512} from "./sumhash.js";
import {toCT, verifyDet1024} from "./falcon.js";

/// Reference model of Algorand state-proof verification (go-algorand crypto/stateproof `Verifier.Verify`,
/// stateproof/verify `ValidateStateProof`, crypto/merklearray, crypto/merklesignature), used both to
/// validate live fixtures and to produce the per-reveal data the EVM verifier consumes.

export interface Message {
    blockHeadersCommitment: Uint8Array; // 32 (SHA-256 vector commitment over light block headers)
    votersCommitment: Uint8Array; // 64 (SumHash) — voters of the NEXT interval
    lnProvenWeight: bigint;
    firstAttestedRound: bigint;
    lastAttestedRound: bigint;
}

export function messageFromJson(m: any): Message {
    return {
        blockHeadersCommitment: Buffer.from(m.BlockHeadersCommitment, "base64"),
        votersCommitment: Buffer.from(m.VotersCommitment, "base64"),
        lnProvenWeight: BigInt(m.LnProvenWeight),
        firstAttestedRound: BigInt(m.FirstAttestedRound),
        lastAttestedRound: BigInt(m.LastAttestedRound),
    };
}

/// Canonical msgpack of stateproofmsg.Message (keys sorted: P b f l v; empty fields omitted).
export function encodeMessage(m: Message): Buffer {
    const fields: [string, Buffer][] = [];
    if (m.lnProvenWeight) fields.push(["P", encUint(m.lnProvenWeight)]);
    if (m.blockHeadersCommitment.length) fields.push(["b", encBin(m.blockHeadersCommitment)]);
    if (m.firstAttestedRound) fields.push(["f", encUint(m.firstAttestedRound)]);
    if (m.lastAttestedRound) fields.push(["l", encUint(m.lastAttestedRound)]);
    if (m.votersCommitment.length) fields.push(["v", encBin(m.votersCommitment)]);
    return Buffer.concat([Buffer.from([0x80 | fields.length]), ...fields.flatMap(([k, v]) => [encStr(k), v])]);
}

export const messageHash = (m: Message) => Buffer.from(sha256(Buffer.concat([Buffer.from("spm"), encodeMessage(m)])));

const le64 = (v: bigint) => {
    const b = Buffer.alloc(8);
    b.writeBigUInt64LE(v);
    return b;
};

// ── weights / coins ─────────────────────────────────────────────────────────

export const STRENGTH_TARGET = 256n;
const LN2 = 45427n;

function subExpr(signedWeight: bigint) {
    const d = BigInt(signedWeight.toString(2).length - 1);
    const sw2 = signedWeight * signedWeight;
    const y = (1n << (2n * d)) + (1n << (d + 2n)) * signedWeight + sw2;
    const x = (sw2 - (1n << (2n * d))) * 3n * (1n << 16n);
    const w = d * (LN2 - 1n);
    return {y, x, w};
}
export function verifyWeights(signedWeight: bigint, lnProvenWeight: bigint, numReveals: bigint, target = STRENGTH_TARGET): boolean {
    if (numReveals > 640n || signedWeight === 0n) return false;
    const {y, x, w} = subExpr(signedWeight);
    const lhs = numReveals * (x + w * y);
    const rhs = (target * LN2 + numReveals * lnProvenWeight) * y;
    return lhs >= rhs;
}

export function coins(partCommitment: Uint8Array, lnProvenWeight: bigint, sigCommit: Uint8Array, signedWeight: bigint, msgHash: Uint8Array, count: number): bigint[] {
    const seed = Buffer.concat([Buffer.from("spc"), Buffer.from([0]), partCommitment, le64(lnProvenWeight), sigCommit, le64(signedWeight), msgHash]);
    const threshold = ((1n << 64n) / signedWeight) * signedWeight;
    let len = 8 * count * 2 + 64;
    let stream = shake256(seed, {dkLen: len});
    let off = 0;
    const out: bigint[] = [];
    while (out.length < count) {
        if (off + 8 > stream.length) {
            len *= 2;
            stream = shake256(seed, {dkLen: len});
        }
        const r = Buffer.from(stream.subarray(off, off + 8)).readBigUInt64LE(0);
        off += 8;
        if (r < threshold) out.push(r % signedWeight);
    }
    return out;
}

// ── vector commitments (crypto/merklearray) ────────────────────────────────

export type HashFn = (d: Uint8Array) => Uint8Array;
export const reverseBits = (pos: bigint, depth: number) => {
    let r = 0n;
    for (let i = 0; i < depth; i++) if ((pos >> BigInt(i)) & 1n) r |= 1n << BigInt(depth - 1 - i);
    return r;
};

/// VerifyVectorCommitment: leaves given at vector positions; returns the root.
export function vcRoot(leaves: Map<bigint, Uint8Array>, path: Uint8Array[], depth: number, H: HashFn, digest: number): Uint8Array {
    let pl = [...leaves.entries()].map(([pos, h]) => ({pos: reverseBits(pos, depth), h})).sort((a, b) => (a.pos < b.pos ? -1 : 1));
    const hints = path.slice();
    const zero = new Uint8Array(digest);
    while (hints.length > 0 || pl.length > 1) {
        const next: {pos: bigint; h: Uint8Array}[] = [];
        for (let i = 0; i < pl.length; i++) {
            const {pos, h} = pl[i];
            const sib = pos ^ 1n;
            let sh: Uint8Array;
            if (i + 1 < pl.length && pl[i + 1].pos === sib) sh = pl[++i].h;
            else {
                if (!hints.length) throw new Error("vc: no more hints");
                sh = hints.shift()!;
                if (sh.length === 0) sh = zero;
            }
            const [l, r] = (pos & 1n) === 0n ? [h, sh] : [sh, h];
            next.push({pos: pos >> 1n, h: H(Buffer.concat([Buffer.from("MA"), l, r]))});
        }
        pl = next;
    }
    if (pl.length !== 1 || pl[0].pos !== 0n) throw new Error("vc: bad root position");
    return pl[0].h;
}

// ── state proof ─────────────────────────────────────────────────────────────

export interface Reveal {
    pos: bigint;
    weight: bigint;
    keyLifetime: bigint;
    commitment: Uint8Array; // participant's MSS root (64)
    l: bigint; // sigslot L
    sig: Uint8Array; // compressed falcon
    vkey: Uint8Array; // 1793
    vcIdx: bigint;
    keyPath: Uint8Array[];
    keyDepth: number;
}

export interface StateProof {
    sigCommit: Uint8Array;
    signedWeight: bigint;
    sigPath: Uint8Array[];
    sigDepth: number;
    partPath: Uint8Array[];
    partDepth: number;
    saltVersion: number;
    reveals: Reveal[];
    positions: bigint[];
    raw: Uint8Array;
}

export function decodeStateProof(raw: Uint8Array): StateProof {
    const n = mpDecode(raw);
    const S = get(n, "S")!;
    const P = get(n, "P")!;
    const r = get(n, "r")!;
    const reveals: Reveal[] = [];
    for (const [k, v] of (r as any).v as [Node, Node][]) {
        const p = get(v, "p")!;
        const pk = get(p, "p")!;
        const ss = get(v, "s")!;
        const s = get(ss, "s")!;
        const prf = get(s, "prf")!;
        reveals.push({
            pos: (k as any).v,
            weight: int(get(p, "w")),
            keyLifetime: int(get(pk, "lf")),
            commitment: bin(get(pk, "cmt")),
            l: int(get(ss, "l")),
            sig: bin(get(s, "sig")),
            vkey: bin(get(get(s, "vkey")!, "k")),
            vcIdx: int(get(s, "idx")),
            keyPath: ((get(prf, "pth") as any)?.v ?? []).map((x: Node) => bin(x)),
            keyDepth: Number(int(get(prf, "td"))),
        });
    }
    return {
        sigCommit: bin(get(n, "c")),
        signedWeight: int(get(n, "w")),
        sigPath: ((get(S, "pth") as any)?.v ?? []).map((x: Node) => bin(x)),
        sigDepth: Number(int(get(S, "td"))),
        partPath: ((get(P, "pth") as any)?.v ?? []).map((x: Node) => bin(x)),
        partDepth: Number(int(get(P, "td"))),
        saltVersion: Number(int(get(n, "v"))),
        reveals,
        positions: ((get(n, "pr") as any).v as Node[]).map((x) => int(x)),
        raw,
    };
}

export const SH: HashFn = (d) => sumhash512(d);
export const S256: HashFn = (d) => sha256(d);

export function keyLeaf(vkey: Uint8Array, round: bigint): Buffer {
    return Buffer.concat([Buffer.from("KP"), Buffer.from([0, 0]), le64(round), vkey]);
}
export function proofFixed(path: Uint8Array[], depth: number): Buffer {
    const parts: Buffer[] = [Buffer.from([depth])];
    for (let i = 0; i < 16 - depth; i++) parts.push(Buffer.alloc(64));
    for (let i = 0; i < depth; i++) parts.push(i < path.length && path[i].length ? Buffer.from(path[i]) : Buffer.alloc(64));
    return Buffer.concat(parts);
}
export function sigLeaf(r: Reveal): Buffer {
    return Buffer.concat([Buffer.from("sps"), le64(r.l), Buffer.from([0, 0]), toCT(r.sig), r.vkey, le64(r.vcIdx), proofFixed(r.keyPath, r.keyDepth)]);
}
export function partLeaf(r: Reveal): Buffer {
    return Buffer.concat([Buffer.from("spp"), le64(r.weight), le64(r.keyLifetime), r.commitment]);
}

export interface VerifyStats {
    reveals: number;
    positions: number;
    sumhashBlocks: number;
}

/// Full Verifier.Verify against (votersCommitment, lnProvenWeight) of the previous message.
export function verifyStateProof(prev: Message, msg: Message, sp: StateProof, checkFalcon = true): VerifyStats {
    const data = messageHash(msg);
    if (!verifyWeights(sp.signedWeight, prev.lnProvenWeight, BigInt(sp.positions.length))) throw new Error("weights");
    const round = msg.lastAttestedRound;
    const sigs = new Map<bigint, Uint8Array>();
    const parts = new Map<bigint, Uint8Array>();
    let blocks = 0;
    const blk = (n: number) => Math.ceil((n + 16 + 1) / 64);
    for (const r of sp.reveals) {
        if (r.sig[1] !== sp.saltVersion) throw new Error("salt version");
        const sl = sigLeaf(r);
        const pl = partLeaf(r);
        sigs.set(r.pos, SH(sl));
        parts.set(r.pos, SH(pl));
        blocks += blk(sl.length) + blk(pl.length);
        // merkle signature: key leaf at vcIdx under the participant's commitment
        const keyRound = round - (round % r.keyLifetime);
        const kl = keyLeaf(r.vkey, keyRound);
        const root = vcRoot(new Map([[r.vcIdx, SH(kl)]]), r.keyPath, r.keyDepth, SH, 64);
        blocks += blk(kl.length) + r.keyDepth * 3;
        if (!Buffer.from(root).equals(Buffer.from(r.commitment))) throw new Error(`key path of reveal ${r.pos}`);
        if (checkFalcon && !verifyDet1024(r.vkey, r.sig, data)) throw new Error(`falcon reveal ${r.pos}`);
    }
    if (!Buffer.from(vcRoot(sigs, sp.sigPath, sp.sigDepth, SH, 64)).equals(Buffer.from(sp.sigCommit))) throw new Error("sig commit");
    if (!Buffer.from(vcRoot(parts, sp.partPath, sp.partDepth, SH, 64)).equals(Buffer.from(prev.votersCommitment))) throw new Error("voters commit");
    const cs = coins(prev.votersCommitment, prev.lnProvenWeight, sp.sigCommit, sp.signedWeight, data, sp.positions.length);
    const byPos = new Map(sp.reveals.map((r) => [r.pos, r]));
    sp.positions.forEach((pos, j) => {
        const r = byPos.get(pos);
        if (!r) throw new Error("no reveal for position");
        if (!(r.l <= cs[j] && cs[j] < r.l + r.weight)) throw new Error(`coin ${j} out of range`);
    });
    return {reveals: sp.reveals.length, positions: sp.positions.length, sumhashBlocks: blocks};
}

// ── light block headers and transactions (bookkeeping.LightBlockHeader, txn_merkle.go) ─────

export interface LightHeader {
    blockHash: Uint8Array; // consensus ≥ v39: BlockHash replaces Seed
    genesisHash: Uint8Array;
    round: bigint;
    txnCommitment: Uint8Array; // Sha256TxnCommitment
}

/// Canonical msgpack: keys "1" gh r tc (Seed "0" is zero and omitted).
export function encodeLightHeader(h: LightHeader): Buffer {
    return Buffer.concat([
        Buffer.from([0x84]),
        encStr("1"),
        encBin(h.blockHash),
        encStr("gh"),
        encBin(h.genesisHash),
        encStr("r"),
        encUint(h.round),
        encStr("tc"),
        encBin(h.txnCommitment),
    ]);
}
export const lightHeaderLeaf = (h: LightHeader) => Buffer.from(sha256(Buffer.concat([Buffer.from("B256"), encodeLightHeader(h)])));

/// Re-encode a decoded msgpack map with extra entries, keys sorted (go-algorand canonical order).
export function withEntries(raw: Uint8Array, n: Node, extra: [string, Buffer][]): Buffer {
    const entries: [string, Buffer][] = (n as any).v.map(([k, v]: [Node, Node]) => [(k as any).v, Buffer.from(raw.subarray(v.start, v.end))]);
    for (const e of extra) if (!entries.some(([k]) => k === e[0])) entries.push(e);
    entries.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    const hdr = entries.length < 16 ? Buffer.from([0x80 | entries.length]) : Buffer.from([0xde, entries.length >> 8, entries.length & 0xff]);
    return Buffer.concat([hdr, ...entries.flatMap(([k, v]) => [encStr(k), v])]);
}

/// Transaction fields elided in a block, restored as bookkeeping `DecodeSignedTxn` does: the genesis id
/// when `hgi` is set, and the genesis hash always (consensus `RequireGenesisHash`, true on mainnet since v7)
/// or when `hgh` is set.
export function restoredGenesis(stib: Node, genesisId: string, genesisHash: Uint8Array, requireGenesisHash = true): [string, Buffer][] {
    const extra: [string, Buffer][] = [];
    if ((get(stib, "hgi") as any)?.v === true) extra.push(["gen", Buffer.concat([Buffer.from([0xa0 | genesisId.length]), Buffer.from(genesisId)])]);
    if (requireGenesisHash || (get(stib, "hgh") as any)?.v === true) extra.push(["gh", encBin(genesisHash)]);
    return extra;
}

/// SHA-256 transaction id of a SignedTxnInBlock (genesis id/hash restored).
export function txidSha256(blockRaw: Uint8Array, stib: Node, genesisId: string, genesisHash: Uint8Array): Buffer {
    const txn = get(stib, "txn")!;
    const extra = restoredGenesis(stib, genesisId, genesisHash);
    return Buffer.from(sha256(Buffer.concat([Buffer.from("TX"), withEntries(blockRaw, txn, extra)])));
}
export const stibSha256 = (stibRaw: Uint8Array) => Buffer.from(sha256(Buffer.concat([Buffer.from("STIB"), stibRaw])));
export const txLeaf = (txid: Uint8Array, stib: Uint8Array) => Buffer.from(sha256(Buffer.concat([Buffer.from("TL"), txid, stib])));

export function splitPath(proof: Uint8Array, digest: number): Uint8Array[] {
    const out: Uint8Array[] = [];
    for (let i = 0; i < proof.length; i += digest) out.push(proof.subarray(i, i + digest));
    return out;
}

/// RFC 4648 base32 (no padding) — Algorand block hashes print as "blk-" + base32.
export function base32Decode(s: string): Buffer {
    const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = 0;
    let val = 0;
    const out: number[] = [];
    for (const ch of s.replace(/=+$/, "")) {
        const i = A.indexOf(ch);
        if (i < 0) throw new Error("base32");
        val = (val << 5) | i;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out.push((val >>> bits) & 0xff);
        }
    }
    return Buffer.from(out);
}
