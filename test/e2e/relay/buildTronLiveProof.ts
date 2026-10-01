import {mkdirSync, readFileSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {encodeAbiParameters, keccak256, recoverAddress, sha256, type Hex} from "viem";
import {type Input} from "@ethereumjs/rlp";
import {bigintToTrimmedBuf, hexToBuf, rlpEncode} from "../lib/rlp.js";

/// Live-data proof builder for `TronVerifier`, fed by a public TRON full node (TronGrid HTTP API).
///
/// TRON's HTTP API returns headers and transactions as JSON, not as the signed bytes, so this file
/// re-encodes them exactly as java-tron's generated protobuf code does (field order, proto3 default
/// elision) and proves the re-encoding right before using it:
///   - header: SHA-256(raw) must reproduce the node's `blockID` (number || hash[8..32]);
///   - transactions: the SHA-256 tree over SHA-256(Transaction bytes) must reproduce `txTrieRoot`.
///
/// Capture (`--refresh`) picks the latest maintenance boundary M (grid OFFSET + k * INTERVAL) that
/// has enough blocks after it and records:
///   config      the last blocks of the previous period, until all 27 SRs appear (initial SR set);
///   rotation    the maintenance block, a window naming all 27 SRs of the new period, then blocks
///               until 19 distinct old-set SRs have signed at or after the window's last block;
///   attestation the first later block holding a successful TriggerSmartContract, then blocks until
///               19 distinct new-set SRs have signed. No ClprService exists on TRON, so this real
///               contract call stands in for `attestQueue` (its contract becomes the anchor's attestor).
///
/// CLI:
///   npx tsx test/e2e/relay/buildTronLiveProof.ts [--network nile|mainnet]            build + summary
///   npx tsx test/e2e/relay/buildTronLiveProof.ts --refresh [--network nile|mainnet]  re-capture

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const TRON_LIVE_DIR = path.resolve(__dirname, "../fixtures/tron-live");

export interface TronNetwork {
    name: "nile" | "mainnet";
    rpc: string;
    intervalMs: number;
    offsetMs: number;
}

/// Maintenance grids, checked against `/wallet/getnextmaintenancetime` at capture time.
export const NETWORKS: Record<string, TronNetwork> = {
    nile: {name: "nile", rpc: "https://nile.trongrid.io", intervalMs: 1_800_000, offsetMs: 600_000},
    mainnet: {name: "mainnet", rpc: "https://api.trongrid.io", intervalMs: 21_600_000, offsetMs: 0}
};

export const SR_COUNT = 27;
export const THRESHOLD = 19;

export interface CapturedHeader {
    number: number;
    timestamp: number;
    witness: Hex; // 21-byte TRON address (0x41 || 20 bytes)
    raw: Hex; // re-encoded BlockHeader.raw (verified against blockID)
    sig: Hex; // 65-byte ECDSA signature, or "0x" for an FN-DSA-512 signed block
    blockId: Hex;
    pq?: boolean;
}

export interface TronCapture {
    network: string;
    rpc: string;
    capturedAt: string;
    caip2: string;
    genesisBlockId: Hex;
    intervalMs: number;
    offsetMs: number;
    maintenanceTimeMs: number;
    config: {headers: CapturedHeader[]};
    rotation: {headers: CapturedHeader[]; windowEnd: number};
    attestation: {
        headers: CapturedHeader[];
        txId: Hex;
        txHex: Hex;
        txIndex: number;
        leafHashes: Hex[];
        contractAddress: Hex; // 21-byte
        contractRet: string;
    };
}

// ── java-tron protobuf re-encoding ─────────────────────────────────────────────

function varint(n: bigint): number[] {
    const o: number[] = [];
    while (n >= 0x80n) {
        o.push(Number(n & 0x7fn) | 0x80);
        n >>= 7n;
    }
    o.push(Number(n));
    return o;
}
const key = (f: number, wt: number) => varint(BigInt((f << 3) | wt));
const fVarint = (f: number, v: bigint) => (v === 0n ? [] : [...key(f, 0), ...varint(v)]);
const fBytes = (f: number, b: Buffer) => (b.length === 0 ? [] : [...key(f, 2), ...varint(BigInt(b.length)), ...b]);
const hb = (h?: string) => Buffer.from((h ?? "").replace(/^0x/, ""), "hex");
const hx = (b: Uint8Array | Buffer) => ("0x" + Buffer.from(b).toString("hex")) as Hex;

/* eslint-disable @typescript-eslint/no-explicit-any */
export function encodeHeaderRaw(r: any): Buffer {
    return Buffer.from([
        ...fVarint(1, BigInt(r.timestamp ?? 0)),
        ...fBytes(2, hb(r.txTrieRoot)),
        ...fBytes(3, hb(r.parentHash)),
        ...fVarint(7, BigInt(r.number ?? 0)),
        ...fVarint(8, BigInt(r.witness_id ?? 0)),
        ...fBytes(9, hb(r.witness_address)),
        ...fVarint(10, BigInt(r.version ?? 0)),
        ...fBytes(11, hb(r.accountStateRoot))
    ]);
}

const CONTRACT_RESULT: Record<string, number> = {
    DEFAULT: 0, SUCCESS: 1, REVERT: 2, BAD_JUMP_DESTINATION: 3, OUT_OF_MEMORY: 4, PRECOMPILED_CONTRACT: 5,
    STACK_TOO_SMALL: 6, STACK_TOO_LARGE: 7, ILLEGAL_OPERATION: 8, STACK_OVERFLOW: 9, OUT_OF_ENERGY: 10,
    OUT_OF_TIME: 11, JVM_STACK_OVER_FLOW: 12, UNKNOWN: 13, TRANSFER_FAILED: 14, INVALID_CODE: 15
};

/// Transaction bytes as hashed into txTrieRoot: raw_data=1, signature=2 (repeated), ret=5 (repeated
/// Result{fee=1, contractRet=3}). Blocks only ever carry those Result fields in the JSON we read; any
/// other field would make the Merkle check below fail rather than pass silently.
export function encodeTransaction(t: any): Buffer {
    const out: number[] = [...fBytes(1, hb(t.raw_data_hex))];
    for (const s of t.signature ?? []) out.push(...fBytes(2, hb(s)));
    for (const r of t.ret ?? []) {
        const extra = Object.keys(r).filter((k) => k !== "contractRet" && k !== "fee");
        if (extra.length) throw new Error(`unhandled Result fields ${extra.join(",")} in ${t.txID}`);
        const inner = Buffer.from([...fVarint(1, BigInt(r.fee ?? 0)), ...fVarint(3, BigInt(CONTRACT_RESULT[r.contractRet] ?? 0))]);
        out.push(...key(5, 2), ...varint(BigInt(inner.length)), ...inner);
    }
    if (t.pq_auth_sig) throw new Error(`transaction ${t.txID} carries pq_auth_sig: re-encoding not implemented`);
    return Buffer.from(out);
}

const sha = (b: Uint8Array) => hb(sha256(b));

export function merkleRoot(leaves: Buffer[]): Buffer {
    if (leaves.length === 0) return Buffer.alloc(32);
    let level = leaves;
    while (level.length > 1) {
        const next: Buffer[] = [];
        for (let i = 0; i < level.length; i += 2) {
            next.push(i + 1 < level.length ? sha(Buffer.concat([level[i], level[i + 1]])) : level[i]);
        }
        level = next;
    }
    return level[0];
}

export function merkleProof(leaves: Buffer[], index: number): Buffer[] {
    const proof: Buffer[] = [];
    let level = leaves;
    let idx = index;
    while (level.length > 1) {
        if (!(idx === level.length - 1 && level.length % 2 === 1)) proof.push(level[idx ^ 1]);
        const next: Buffer[] = [];
        for (let i = 0; i < level.length; i += 2) {
            next.push(i + 1 < level.length ? sha(Buffer.concat([level[i], level[i + 1]])) : level[i]);
        }
        level = next;
        idx >>= 1;
    }
    return proof;
}

// ── Header checks ─────────────────────────────────────────────────────────────

export function blockIdOf(raw: Buffer, number: number): Hex {
    const h = sha(raw);
    return ("0x" + BigInt(number).toString(16).padStart(16, "0") + h.subarray(8).toString("hex")) as Hex;
}

export async function signerOf(h: CapturedHeader): Promise<Hex> {
    if (h.sig === "0x") return ("0x" + "00".repeat(20)) as Hex;
    const sig = hb(h.sig);
    const v = sig[64] < 27 ? sig[64] + 27 : sig[64];
    const fixed = Buffer.concat([sig.subarray(0, 64), Buffer.from([v])]);
    const a = await recoverAddress({hash: sha256(hb(h.raw)), signature: hx(fixed)});
    return a.toLowerCase() as Hex;
}

const evm = (tronAddr: Hex) => ("0x" + tronAddr.slice(4)).toLowerCase() as Hex; // drop 0x41

function checkChain(hs: CapturedHeader[], what: string) {
    for (let i = 0; i < hs.length; i++) {
        if (blockIdOf(hb(hs[i].raw), hs[i].number) !== hs[i].blockId) throw new Error(`${what}[${i}] blockId mismatch`);
        if (i > 0) {
            const parent = "0x" + parseRawParent(hb(hs[i].raw));
            if (parent !== hs[i - 1].blockId) throw new Error(`${what}[${i}] parentHash does not link`);
        }
    }
}

/// parentHash (field 3) of a re-encoded raw header.
function parseRawParent(raw: Buffer): string {
    let off = 0;
    while (off < raw.length) {
        const k = raw[off++];
        const field = k >> 3;
        const wt = k & 7;
        if (wt === 0) {
            while (raw[off++] & 0x80);
        } else {
            let len = 0;
            let shift = 0;
            for (;;) {
                const b = raw[off++];
                len |= (b & 0x7f) << shift;
                if (!(b & 0x80)) break;
                shift += 7;
            }
            if (field === 3) return raw.subarray(off, off + len).toString("hex");
            off += len;
        }
    }
    throw new Error("no parentHash");
}

// ── Capture ───────────────────────────────────────────────────────────────────

async function post(rpc: string, p: string, body: unknown): Promise<any> {
    for (let attempt = 0; ; attempt++) {
        const r = await fetch(rpc + p, {method: "POST", body: JSON.stringify(body)});
        if (r.ok) return r.json();
        if (attempt >= 4) throw new Error(`${p} → HTTP ${r.status}`);
        await new Promise((res) => setTimeout(res, 1000 * (attempt + 1)));
    }
}

const blockCache = new Map<number, any>();
async function getBlocks(rpc: string, from: number, to: number): Promise<any[]> {
    // getblockbylimitnext serves [startNum, endNum) in chunks.
    const out: any[] = [];
    for (let s = from; s < to; s += 20) {
        const missing = [...Array(Math.min(20, to - s)).keys()].map((i) => s + i).filter((n) => !blockCache.has(n));
        if (missing.length) {
            const res = await post(rpc, "/wallet/getblockbylimitnext", {startNum: s, endNum: Math.min(s + 20, to)});
            for (const b of res.block ?? []) blockCache.set(b.block_header.raw_data.number, b);
        }
        for (let n = s; n < Math.min(s + 20, to); n++) {
            const b = blockCache.get(n);
            if (!b) throw new Error(`block ${n} missing from node response`);
            out.push(b);
        }
    }
    return out;
}

function toCaptured(b: any): CapturedHeader {
    const r = b.block_header.raw_data;
    const raw = encodeHeaderRaw(r);
    const h: CapturedHeader = {
        number: r.number,
        timestamp: r.timestamp,
        witness: ("0x" + r.witness_address) as Hex,
        raw: hx(raw),
        sig: (b.block_header.witness_signature ? "0x" + b.block_header.witness_signature : "0x") as Hex,
        blockId: ("0x" + b.blockID) as Hex
    };
    if (b.block_header.pq_auth_sig) h.pq = true;
    if (blockIdOf(raw, h.number) !== h.blockId) throw new Error(`re-encoded header ${h.number} does not hash to its blockID`);
    return h;
}

async function blockByTime(rpc: string, ts: number, hi: number): Promise<number> {
    // First block with timestamp >= ts, by binary search on header timestamps.
    const tsOf = async (n: number) =>
        (await post(rpc, "/wallet/getblockbynum", {num: n, detail: false})).block_header.raw_data.timestamp as number;
    let lo = hi - Math.ceil((((await tsOf(hi)) - ts) / 3000) * 1.2) - 50;
    while ((await tsOf(lo)) >= ts) lo -= 200;
    while (lo + 1 < hi) {
        const mid = (lo + hi) >> 1;
        if ((await tsOf(mid)) >= ts) hi = mid;
        else lo = mid;
    }
    return hi;
}

export async function captureTronLive(net: TronNetwork): Promise<TronCapture> {
    const rpc = net.rpc;
    const nextMaint = (await post(rpc, "/wallet/getnextmaintenancetime", {})).num as number;
    if ((nextMaint - net.offsetMs) % net.intervalMs !== 0) throw new Error(`maintenance grid moved: next=${nextMaint}`);
    const params = (await post(rpc, "/wallet/getchainparameters", {})).chainParameter as {key: string; value?: number}[];
    const interval = params.find((p) => p.key === "getMaintenanceTimeInterval")?.value;
    if (interval !== net.intervalMs) throw new Error(`maintenance interval is ${interval}, expected ${net.intervalMs}`);

    const genesis = await post(rpc, "/wallet/getblockbynum", {num: 0});
    const genesisBlockId = ("0x" + genesis.blockID) as Hex;
    const now = await post(rpc, "/wallet/getnowblock", {});
    const head = now.block_header.raw_data.number as number;
    // Latest boundary with >= 8 minutes of blocks after it (window + endorsement + attestation).
    let M = nextMaint - net.intervalMs;
    if (now.block_header.raw_data.timestamp - M < 8 * 60_000) M -= net.intervalMs;
    const boundary = await blockByTime(rpc, M, head);

    // Config: walk back from the boundary until all 27 SRs of the previous period are seen.
    const before = await getBlocks(rpc, boundary - 60, boundary);
    const cfg: CapturedHeader[] = [];
    const seen = new Set<string>();
    for (let i = before.length - 1; i >= 0 && seen.size < SR_COUNT; i--) {
        const h = toCaptured(before[i]);
        cfg.unshift(h);
        seen.add(h.witness);
    }
    if (seen.size !== SR_COUNT) throw new Error(`only ${seen.size} SRs in the 60 blocks before the boundary`);
    const oldKeys = new Map<string, Hex>();
    for (const h of cfg) oldKeys.set(h.witness, await signerOf(h));

    // Rotation: maintenance block, window of 27 SRs, then 19 old-set signatures from the window end.
    const after = await getBlocks(rpc, boundary, boundary + 120);
    const rot: CapturedHeader[] = [toCaptured(after[0])];
    const win = new Set<string>();
    let i = 1;
    for (; win.size < SR_COUNT; i++) {
        const h = toCaptured(after[i]);
        rot.push(h);
        win.add(h.witness);
    }
    const windowEnd = rot.length - 1;
    const endorsed = new Set<string>();
    for (let j = windowEnd; ; j++) {
        if (j >= rot.length) rot.push(toCaptured(after[i++]));
        const h = rot[j];
        const k = await signerOf(h);
        if (k !== "0x" + "00".repeat(20) && oldKeys.get(h.witness) === k) endorsed.add(h.witness);
        if (endorsed.size >= THRESHOLD) break;
    }
    const newKeys = new Map<string, Hex>();
    for (const h of rot.slice(1, windowEnd + 1)) newKeys.set(h.witness, await signerOf(h));

    // Attestation stand-in: first later block with a successful TriggerSmartContract.
    let n = rot[rot.length - 1].number + 1;
    let att: TronCapture["attestation"] | undefined;
    for (; !att; n++) {
        const [b] = await getBlocks(rpc, n, n + 1);
        const txs: any[] = b.transactions ?? [];
        const idx = txs.findIndex(
            (t) => t.raw_data.contract[0].type === "TriggerSmartContract" && t.ret?.[0]?.contractRet === "SUCCESS" && !t.pq_auth_sig
        );
        if (idx < 0 || txs.some((t) => t.pq_auth_sig)) continue;
        const encoded = txs.map(encodeTransaction);
        const leaves = encoded.map(sha);
        if (merkleRoot(leaves).toString("hex") !== b.block_header.raw_data.txTrieRoot) {
            throw new Error(`block ${n}: re-encoded transactions do not reproduce txTrieRoot`);
        }
        const conf: CapturedHeader[] = [];
        const signed = new Set<string>();
        for (let m = n; signed.size < THRESHOLD; m++) {
            const [cb] = await getBlocks(rpc, m, m + 1);
            const h = toCaptured(cb);
            conf.push(h);
            const k = await signerOf(h);
            if (k !== "0x" + "00".repeat(20) && newKeys.get(h.witness) === k) signed.add(h.witness);
        }
        att = {
            headers: conf,
            txId: ("0x" + txs[idx].txID) as Hex,
            txHex: hx(encoded[idx]),
            txIndex: idx,
            leafHashes: leaves.map(hx),
            contractAddress: ("0x" + txs[idx].raw_data.contract[0].parameter.value.contract_address) as Hex,
            contractRet: txs[idx].ret[0].contractRet
        };
    }
    return {
        network: net.name,
        rpc,
        capturedAt: new Date().toISOString(),
        caip2: "tron:0x" + genesisBlockId.slice(-8),
        genesisBlockId,
        intervalMs: net.intervalMs,
        offsetMs: net.offsetMs,
        maintenanceTimeMs: M,
        config: {headers: cfg},
        rotation: {headers: rot, windowEnd},
        attestation: att
    };
}

// ── Build (offline) ───────────────────────────────────────────────────────────

export interface TronLiveProof {
    configProof: Hex;
    bundleProof: Hex;
    channelContext: Hex;
    serviceAddress: Hex;
    channelId: Hex;
    attestor: Hex;
    configAnchor: Hex;
    configPeriod: bigint;
    rotatedPeriod: bigint;
    rotatedSetHash: Hex;
    meta: {
        network: string;
        caip2: string;
        oldSet: {witness: Hex; key: Hex}[];
        newSet: {witness: Hex; key: Hex}[];
        joined: Hex[];
        left: Hex[];
        pqWitnesses: Hex[];
        permissionKeyWitnesses: Hex[];
        configHeaders: number;
        rotationHeaders: number;
        windowEnd: number;
        attestationHeaders: number;
        txBlock: number;
        txCount: number;
        merkleDepth: number;
    };
    parts: {set: Input; attestation: Input; rotation: Input};
    /// A typical bundle (no rotation) against the rotated anchor: the steady-state cost.
    steadyBundleProof: Hex;
    rotatedAnchor: Hex;
}

const ZERO20 = ("0x" + "00".repeat(20)) as Hex;
/// A placeholder 20-byte TRON-side ClprService address (no ClprService is deployed on TRON).
export const PLACEHOLDER_SERVICE = "0x00000000000000000000000000000000c1e0c1e0" as Hex;
export const LIVE_CHANNEL_ID = keccak256(new TextEncoder().encode("clpr-tron-live"));

export function periodOf(tsMs: number, c: {intervalMs: number; offsetMs: number}): bigint {
    return BigInt(Math.floor((tsMs - c.offsetMs) / c.intervalMs));
}

function sortSet(m: Map<string, Hex>): {witness: Hex; key: Hex}[] {
    return [...m.entries()]
        .map(([w, k]) => ({witness: evm(w as Hex), key: k}))
        .sort((a, b) => (a.witness < b.witness ? -1 : a.witness > b.witness ? 1 : 0));
}

export function setHash(set: {witness: Hex; key: Hex}[]): Hex {
    return keccak256(Buffer.concat(set.flatMap((e) => [hb(e.witness), hb(e.key)])));
}

const setRlp = (set: {witness: Hex; key: Hex}[]): Input => set.map((e) => [hb(e.witness), hb(e.key)]);
const headersRlp = (hs: CapturedHeader[]): Input => hs.map((h) => [hb(h.raw), hb(h.sig)]);

function ledgerConfig(caip2: string, service: Hex): Buffer {
    const throttles = Buffer.from([
        ...fVarint(1, 10n), ...fVarint(2, 4096n), ...fVarint(3, 500_000n), ...fVarint(4, 100n), ...fVarint(5, 65_536n),
        ...fVarint(6, 4n), ...fVarint(7, 4n)
    ]);
    const ts = Buffer.from([...fVarint(1, 1_790_822_400n)]);
    const cfg = Buffer.from([
        ...fVarint(1, 1n), ...fBytes(2, Buffer.from(caip2)), ...fBytes(3, hb(service)), ...fBytes(4, ts), ...fBytes(5, throttles)
    ]);
    const update = Buffer.from(fBytes(1, cfg));
    const control = Buffer.from(fBytes(1, update));
    return Buffer.from(fBytes(3, control));
}

export async function buildTronLiveProof(c: TronCapture): Promise<TronLiveProof> {
    checkChain(c.config.headers, "config");
    checkChain(c.rotation.headers, "rotation");
    checkChain(c.attestation.headers, "attestation");

    const oldKeys = new Map<string, Hex>();
    for (const h of c.config.headers) oldKeys.set(h.witness, await signerOf(h));
    if (oldKeys.size !== SR_COUNT) throw new Error(`config names ${oldKeys.size} SRs`);
    const oldSet = sortSet(oldKeys);

    const w = c.rotation.windowEnd;
    const newKeys = new Map<string, Hex>();
    for (const h of c.rotation.headers.slice(1, w + 1)) {
        const k = await signerOf(h);
        if (!newKeys.has(h.witness) || newKeys.get(h.witness) === ZERO20) newKeys.set(h.witness, k);
    }
    for (const [wit, k] of newKeys) if (k === ZERO20 && oldKeys.has(wit)) newKeys.set(wit, oldKeys.get(wit)!);
    const newSet = sortSet(newKeys);

    const attestor = evm(c.attestation.contractAddress);
    const configPeriod = periodOf(c.config.headers[0].timestamp, c);
    const watermark = BigInt(c.config.headers[c.config.headers.length - 1].number);
    const configAnchor = encodeAbiParameters(
        [{type: "uint64"}, {type: "bytes32"}, {type: "address"}, {type: "uint64"}],
        [configPeriod, setHash(oldSet), attestor, watermark]
    );
    const configProof = hx(
        rlpEncode([setRlp(oldSet), hb(attestor), headersRlp(c.config.headers), ledgerConfig(c.caip2, PLACEHOLDER_SERVICE)])
    );

    const leaves = c.attestation.leafHashes.map(hb);
    if (merkleRoot(leaves).toString("hex") !== headerTxRoot(hb(c.attestation.headers[0].raw))) {
        throw new Error("attestation leaves do not reproduce the block's txTrieRoot");
    }
    if (sha(hb(c.attestation.txHex)).toString("hex") !== leaves[c.attestation.txIndex].toString("hex")) {
        throw new Error("attestation tx is not the leaf at txIndex");
    }
    const siblings = merkleProof(leaves, c.attestation.txIndex);
    const attestation: Input = [
        headersRlp(c.attestation.headers),
        hb(c.attestation.txHex),
        bigintToTrimmedBuf(BigInt(c.attestation.txIndex)),
        bigintToTrimmedBuf(BigInt(leaves.length)),
        siblings
    ];
    const rotation: Input = [headersRlp(c.rotation.headers), bigintToTrimmedBuf(BigInt(w))];
    const bundleProof = hx(rlpEncode([setRlp(oldSet), [], rotation, attestation, Buffer.alloc(0), Buffer.alloc(0)]));
    const rotatedAnchor = encodeAbiParameters(
        [{type: "uint64"}, {type: "bytes32"}, {type: "address"}, {type: "uint64"}],
        [periodOf(c.rotation.headers[w].timestamp, c), setHash(newSet), attestor, watermark]
    );
    const steadyBundleProof = hx(rlpEncode([setRlp(newSet), [], [], attestation, Buffer.alloc(0), Buffer.alloc(0)]));
    const channelContext = (LIVE_CHANNEL_ID + PLACEHOLDER_SERVICE.slice(2)) as Hex;

    const oldW = new Set(oldSet.map((e) => e.witness));
    const newW = new Set(newSet.map((e) => e.witness));
    return {
        configProof,
        bundleProof,
        channelContext,
        serviceAddress: PLACEHOLDER_SERVICE,
        channelId: LIVE_CHANNEL_ID,
        attestor,
        configAnchor,
        configPeriod,
        rotatedPeriod: periodOf(c.rotation.headers[w].timestamp, c),
        rotatedSetHash: setHash(newSet),
        meta: {
            network: c.network,
            caip2: c.caip2,
            oldSet,
            newSet,
            joined: [...newW].filter((x) => !oldW.has(x)) as Hex[],
            left: [...oldW].filter((x) => !newW.has(x)) as Hex[],
            pqWitnesses: newSet.filter((e) => e.key === ZERO20).map((e) => e.witness),
            permissionKeyWitnesses: newSet.filter((e) => e.key !== ZERO20 && e.key !== e.witness).map((e) => e.witness),
            configHeaders: c.config.headers.length,
            rotationHeaders: c.rotation.headers.length,
            windowEnd: w,
            attestationHeaders: c.attestation.headers.length,
            txBlock: c.attestation.headers[0].number,
            txCount: leaves.length,
            merkleDepth: siblings.length
        },
        parts: {set: setRlp(oldSet), attestation, rotation},
        steadyBundleProof,
        rotatedAnchor
    };
}

/// Re-encode a bundle with some parts replaced (for negative tests).
export function reencodeBundle(p: TronLiveProof["parts"], o: Partial<TronLiveProof["parts"]>): Hex {
    const q = {...p, ...o};
    return hx(rlpEncode([q.set, [], q.rotation, q.attestation, Buffer.alloc(0), Buffer.alloc(0)]));
}

function headerTxRoot(raw: Buffer): string {
    let off = 0;
    while (off < raw.length) {
        const k = raw[off++];
        const field = k >> 3;
        if ((k & 7) === 0) {
            while (raw[off++] & 0x80);
        } else {
            const len = raw[off++]; // all length-delimited header fields are < 128 bytes
            if (field === 2) return raw.subarray(off, off + len).toString("hex");
            off += len;
        }
    }
    return "00".repeat(32);
}

export function fixturePath(network: string): string {
    return path.join(TRON_LIVE_DIR, `${network}.json`);
}

export function loadTronCapture(network = "nile"): TronCapture {
    return JSON.parse(readFileSync(fixturePath(network), "utf8")) as TronCapture;
}

async function main() {
    const args = process.argv.slice(2);
    const ni = args.indexOf("--network");
    const net = NETWORKS[ni >= 0 ? args[ni + 1] : "nile"];
    if (!net) throw new Error("--network must be nile or mainnet");
    if (args.includes("--refresh")) {
        const capture = await captureTronLive(net);
        mkdirSync(TRON_LIVE_DIR, {recursive: true});
        writeFileSync(fixturePath(net.name), JSON.stringify(capture, null, 1) + "\n");
        console.log(`captured ${net.name} → ${fixturePath(net.name)}`);
    }
    const live = await buildTronLiveProof(loadTronCapture(net.name));
    console.log(JSON.stringify({...live.meta, oldSet: undefined, newSet: undefined, configPeriod: String(live.configPeriod),
        rotatedPeriod: String(live.rotatedPeriod), bundleBytes: (live.bundleProof.length - 2) / 2,
        configBytes: (live.configProof.length - 2) / 2}, null, 1));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    main().catch((e) => {
        console.error(e);
        process.exit(1);
    });
}
