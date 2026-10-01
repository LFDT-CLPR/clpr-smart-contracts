/**
 * plasma.ts — PlasmaBFT (Plasma, chain 9745) consensus-block decoding and relay encoding for
 * PlasmaBftVerifier (src/verifiers/evm/plasma). Formats are reverse-engineered (see that README, "How it works")
 * and checked against live mainnet gossip: every captured block re-hashes to the hash its gossip
 * envelope carries, and every QC aggregate signature verifies.
 *
 * SSZ notes: little-endian ints; Plasma "vec" lists are wrapped in a container (4-byte offset 4),
 * hash with NO fixed limit (chunks padded to a power of two, then the length mixed in). Unions and
 * versioned types are `selector(1) ‖ body`, hashed as sha256(root ‖ le256(selector)).
 */

import {sha256} from "@noble/hashes/sha2";
import {bls12_381 as bls} from "@noble/curves/bls12-381";
import {toRlp, type Hex} from "viem";
import {rlpInt} from "./evmHeader.js";

type B = Uint8Array;
export const DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const Z = new Uint8Array(32);

export const hx = (s: string): B => Uint8Array.from(Buffer.from(s.replace(/^0x/, ""), "hex"));
export const toHex = (b: B): Hex => `0x${Buffer.from(b).toString("hex")}`;
const cat = (...a: B[]) => Uint8Array.from(Buffer.concat(a.map((x) => Buffer.from(x))));
const u32 = (b: B, o: number) => Buffer.from(b.subarray(o, o + 4)).readUInt32LE();
const u64 = (b: B, o: number) => Buffer.from(b.subarray(o, o + 8)).readBigUInt64LE();
export const le = (n: number | bigint, len = 32): B => {
    const o = new Uint8Array(len);
    let v = BigInt(n);
    for (let i = 0; i < len; i++) {
        o[i] = Number(v & 0xffn);
        v >>= 8n;
    }
    return o;
};
const H = (a: B, b: B) => sha256(cat(a, b));

export function merkleize(chunks: B[], minLeaves = 1): B {
    let w = 1;
    while (w < Math.max(chunks.length, minLeaves, 1)) w *= 2;
    let layer = [...chunks];
    while (layer.length < w) layer.push(Z);
    while (layer.length > 1) {
        const n: B[] = [];
        for (let i = 0; i < layer.length; i += 2) n.push(H(layer[i], layer[i + 1]));
        layer = n;
    }
    return layer[0];
}
const pack = (b: B): B[] => {
    const p = new Uint8Array(Math.ceil(b.length / 32) * 32);
    p.set(b);
    const o: B[] = [];
    for (let i = 0; i < p.length; i += 32) o.push(p.subarray(i, i + 32));
    return o;
};
const mixLen = (r: B, n: number) => H(r, le(n));
const byteVecRoot = (b: B) => mixLen(merkleize(pack(b)), b.length);
const votersRoot = (v: number[]) => mixLen(merkleize(pack(cat(...v.map((x) => le(x, 8))))), v.length);
const wrapped = (b: B) => {
    if (u32(b, 0) !== 4) throw new Error("bad list wrapper");
    return b.subarray(4);
};
const varList = (b: B): B[] => {
    if (!b.length) return [];
    const n = u32(b, 0) / 4;
    const offs = [...Array(n).keys()].map((i) => u32(b, 4 * i)).concat([b.length]);
    return [...Array(n).keys()].map((i) => b.subarray(offs[i], offs[i + 1]));
};

// ── QC ───────────────────────────────────────────────────────────────────────

export interface Qc {
    selector: number;
    view: bigint;
    proposer: bigint;
    blockHash: B;
    height: bigint;
    execHash?: B;
    votes: number[];
    sig: B;
}

export function decodeQc(b: B): Qc {
    const sel = b[0];
    const c = b.subarray(1);
    const q: any = {selector: sel, view: u64(c, 0), proposer: u64(c, 8), blockHash: c.subarray(16, 48), height: u64(c, 48)};
    let o1: number, o2: number;
    if (sel === 0) {
        q.execHash = c.subarray(56, 88);
        o1 = u32(c, 88);
        o2 = u32(c, 92);
    } else if (sel === 1) {
        o1 = u32(c, 56);
        o2 = u32(c, 60);
    } else throw new Error(`qc selector ${sel}`);
    const vb = wrapped(c.subarray(o1, o2));
    q.votes = [];
    for (let i = 0; i < vb.length; i += 8) q.votes.push(Number(u64(vb, i)));
    q.sig = wrapped(c.subarray(o2));
    return q;
}

export const qcRoot = (q: Qc) =>
    H(merkleize(q.selector === 1
        ? [le(q.view), le(q.proposer), q.blockHash, le(q.height), votersRoot(q.votes), byteVecRoot(q.sig)]
        : [le(q.view), le(q.proposer), q.blockHash, le(q.height), q.execHash!, votersRoot(q.votes), byteVecRoot(q.sig)]), le(q.selector));

function aggQcRoot(b: B): B {
    const o1 = u32(b, 0), o2 = u32(b, 4), o3 = u32(b, 8);
    const vb = wrapped(b.subarray(o1, o2));
    const votes: number[] = [];
    for (let i = 0; i < vb.length; i += 8) votes.push(Number(u64(vb, i)));
    const qcs = varList(wrapped(b.subarray(o2, o3))).map(decodeQc);
    const sig = wrapped(b.subarray(o3));
    return merkleize([votersRoot(votes), mixLen(merkleize(qcs.map(qcRoot)), qcs.length), byteVecRoot(sig)]);
}

// ── Execution payload (18 fields) ─────────────────────────────────────────────

function payloadLeaves(p: B): B[] {
    const oExtra = u32(p, 436), oTx = u32(p, 520), oWd = u32(p, 524), oRq = u32(p, 528);
    const bvv = (xs: B[]) => mixLen(merkleize(xs.map(byteVecRoot)), xs.length);
    const wd = wrapped(p.subarray(oWd, oRq));
    const wds: B[] = [];
    for (let i = 0; i < wd.length; i += 44) wds.push(wd.subarray(i, i + 44));
    const wdRoot = (w: B) => merkleize([le(u64(w, 0)), le(u64(w, 8)), cat(w.subarray(16, 36), new Uint8Array(12)), le(u64(w, 36))]);
    return [
        p.subarray(0, 32), cat(p.subarray(32, 52), new Uint8Array(12)), p.subarray(52, 84), p.subarray(84, 116),
        merkleize(pack(p.subarray(116, 372)), 8), p.subarray(372, 404), le(u64(p, 404)), le(u64(p, 412)), le(u64(p, 420)),
        le(u64(p, 428)), byteVecRoot(wrapped(p.subarray(oExtra, oTx))), p.subarray(440, 472), p.subarray(472, 504),
        le(u64(p, 504)), le(u64(p, 512)), bvv(varList(wrapped(p.subarray(oTx, oWd)))), merkleize(wds.map(wdRoot)),
        bvv(varList(wrapped(p.subarray(oRq))))
    ];
}

// ── ConsensusBlock V1 ─────────────────────────────────────────────────────────

export interface ConsensusBlock {
    view: bigint;
    leaves: B[]; // the 11 header leaves
    hash: B;
    qc: Qc;
    evm: {number: bigint; blockHash: B; stateRoot: B};
    stateBranch: B[]; // [stateRoot, field3, H(f0,f1), node(4..7), node(8..15), node(16..31), graffiti]
}

/** Gossip `consensus-block` message → (envelope block hash, block SSZ). */
export function decodeGossip(raw: B): {blockHash: B; height: bigint; view: bigint; block: B} {
    if (raw[0] !== 0) throw new Error("gossip selector");
    const o = wrapped(raw.subarray(1));
    return {blockHash: o.subarray(100, 132), height: u64(o, 132), view: u64(o, 148), block: o.subarray(u32(o, 0))};
}

export function decodeBlockV1(b: B): ConsensusBlock {
    if (b[0] !== 1) throw new Error("expected ConsensusBlock V1 (post-Aquila)");
    const c = b.subarray(1);
    const oR = u32(c, 88), oQ = u32(c, 92), oA = u32(c, 96), oB = u32(c, 100);
    const qc = decodeQc(c.subarray(oQ, oA));
    const body = c.subarray(oB);
    const graffiti = body.subarray(0, 32);
    const payload = body.subarray(u32(body, 32));
    const pl = payloadLeaves(payload);
    const layer = (xs: B[]) => merkleize(xs);
    const padded = [...pl, ...Array(32 - pl.length).fill(Z)];
    const bodyRoot = H(graffiti, layer(padded));
    const leaves = [
        le(u64(c, 0)), le(u64(c, 8)), c.subarray(16, 48), c.subarray(48, 80), le(u64(c, 80)),
        byteVecRoot(wrapped(c.subarray(oR, oQ))), qcRoot(qc), aggQcRoot(c.subarray(oA, oB)), bodyRoot,
        c.subarray(104, 136), c.subarray(136, 168)
    ];
    return {
        view: u64(c, 0),
        leaves,
        hash: H(merkleize(leaves), le(1)),
        qc,
        evm: {number: u64(payload, 404), blockHash: payload.subarray(472, 504), stateRoot: payload.subarray(52, 84)},
        stateBranch: [pl[2], pl[3], H(pl[0], pl[1]), layer(padded.slice(4, 8)), layer(padded.slice(8, 16)), layer(padded.slice(16, 32)), graffiti]
    };
}

// ── BLS ───────────────────────────────────────────────────────────────────────

/** EIP-2537 field element: 64-byte big-endian (16 zero bytes + 48). */
const fp = (n: bigint): B => Uint8Array.from(Buffer.from(n.toString(16).padStart(128, "0"), "hex"));

/** 48-byte compressed G1 → EIP-2537 128-byte uncompressed. */
export function g1Uncompressed(compressed: B): B {
    const p = bls.G1.ProjectivePoint.fromHex(compressed).toAffine();
    return cat(fp(p.x), fp(p.y));
}

/** 96-byte compressed G2 → EIP-2537 256-byte uncompressed (x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1). */
export function g2Uncompressed(compressed: B): B {
    const p = bls.G2.ProjectivePoint.fromHex(compressed).toAffine();
    return cat(fp(p.x.c0), fp(p.x.c1), fp(p.y.c0), fp(p.y.c1));
}

export const voteMessage = (pk: B, blockHash: B, height: bigint, voter: number, view: bigint) =>
    cat(pk, blockHash, le(height, 8), le(voter, 8), le(view, 8));

/** Off-chain QC check against the pubkey-sorted committee. */
export function verifyQc(q: Qc, sortedKeys: B[]): boolean {
    const n = sortedKeys.length;
    if (q.votes.length < n - Math.floor((n - 1) / 3)) return false;
    if (q.votes.some((v, i) => v >= n || (i > 0 && v <= q.votes[i - 1]))) return false;
    const msgs = q.votes.map((v) => voteMessage(sortedKeys[v], q.blockHash, q.height, v, q.view));
    return bls.verifyBatch(q.sig, msgs, q.votes.map((v) => sortedKeys[v]), {DST} as any);
}

/** SSZ List[Bytes48, 1024] root of the sorted committee (= header qc/committed_validators_hash). */
export function committeeRoot(sortedKeys: B[]): B {
    return mixLen(merkleize(sortedKeys.map((k) => merkleize(pack(k))), 1024), sortedKeys.length);
}

export const sortKeys = (keys: B[]) => [...keys].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));

// ── Payload encoding ──────────────────────────────────────────────────────────


export function qcItem(q: Qc): any[] {
    return [rlpInt(q.proposer), rlpInt(q.height), q.votes.map(rlpInt), toHex(q.sig), toHex(g2Uncompressed(q.sig))];
}

/** finality item for block B, given B, B+1 (carries QC on B) and B+2 (carries QC on B+1). */
export function finalityItem(sortedKeys: B[], b: ConsensusBlock, b1: ConsensusBlock, b2: ConsensusBlock): any[] {
    return [
        toHex(cat(...sortedKeys.map(g1Uncompressed))),
        toHex(cat(...b.leaves)),
        toHex(cat(...b.stateBranch)),
        toHex(cat(...b1.leaves)),
        qcItem(b1.qc),
        qcItem(b2.qc)
    ];
}

export function encodePlasmaBundle(p: {finality: any[]; serviceAccountProof: Hex[]; storageEntries: [Hex, Hex[]][]; bundleContent: Hex}): Hex {
    return toRlp([p.finality, p.serviceAccountProof, p.storageEntries, p.bundleContent] as any);
}

export function encodePlasmaConfig(p: {finality: any[]; serviceAccountProof: Hex[]; slotEntries: [Hex, Hex[]][]; ledgerConfig: Hex}): Hex {
    return toRlp([p.finality, p.serviceAccountProof, p.slotEntries, p.ledgerConfig] as any);
}

export const plasmaAnchor = (root: B | Hex, height: bigint): Hex =>
    `0x${(typeof root === "string" ? root.slice(2) : Buffer.from(root).toString("hex"))}${height.toString(16).padStart(16, "0")}`;
