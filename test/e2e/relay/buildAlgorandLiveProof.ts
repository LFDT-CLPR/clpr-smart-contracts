import {readFileSync, writeFileSync} from "node:fs";
import {sha512_256} from "@noble/hashes/sha512";
import {sha256} from "@noble/hashes/sha2";
import {bin, get, int, mpDecode, type Node} from "./algorand/msgpack.js";
import {
    base32Decode,
    decodeStateProof,
    encodeLightHeader,
    encodeMessage,
    keyLeaf,
    lightHeaderLeaf,
    messageFromJson,
    messageHash,
    partLeaf,
    restoredGenesis,
    reverseBits,
    S256,
    SH,
    sigLeaf,
    splitPath,
    stibSha256,
    txidSha256,
    txLeaf,
    vcRoot,
    verifyStateProof,
    withEntries,
    type HashFn,
    type Message,
    type StateProof,
} from "./algorand/stateproof.js";
import {toCT} from "./algorand/falcon.js";

/// Builds AlgorandStateProofAccumulator / AlgorandStateProofVerifier inputs from REAL Algorand mainnet data.
///
///   capture (--refresh): from a public algod (non-archival nodes keep ~1,000 rounds, so the capture
///   targets the newest state proof), the state proof of interval i and of interval i − 1 (its message
///   carries the voters of interval i), one block of interval i with an application call that emitted
///   logs, the block's light-header proof and the transaction's SHA-256 proof; written to
///   test/e2e/fixtures/algorand-live/mainnet.json.
///   build: re-verifies everything with the TypeScript reference model (stateproof.ts, falcon.ts,
///   sumhash.ts) and writes test/e2e/fixtures/algorand-live/vectors.json for Foundry and vitest.
///
///   npx tsx test/e2e/relay/buildAlgorandLiveProof.ts [--refresh]
///   (ALGORAND_NETWORK=testnet and ALGORAND_FIXTURE_DIR=<dir>/ capture another network elsewhere;
///   ALGOD_URL overrides the public algod, default https://<network>-api.algonode.cloud)

const FIX = new URL(process.env.ALGORAND_FIXTURE_DIR ?? "../fixtures/algorand-live/", import.meta.url);
const NETWORK = process.env.ALGORAND_NETWORK ?? "mainnet";
const ALGOD = process.env.ALGOD_URL ?? `https://${NETWORK}-api.algonode.cloud`;

export const hx = (b: Uint8Array) => "0x" + Buffer.from(b).toString("hex");

async function getJson(path: string): Promise<any> {
    const r = await fetch(ALGOD + path, {signal: AbortSignal.timeout(60_000)});
    if (!r.ok) throw new Error(`${path}: HTTP ${r.status} ${await r.text()}`);
    return r.json();
}
async function getBin(path: string): Promise<Buffer> {
    const r = await fetch(ALGOD + path, {signal: AbortSignal.timeout(60_000)});
    if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
    return Buffer.from(await r.arrayBuffer());
}

export interface Capture {
    network: string;
    algod: string;
    capturedAt: string;
    prevStateProof: {Message: any; StateProof: string};
    stateProof: {Message: any; StateProof: string};
    round: number;
    block: string; // base64 msgpack {block, cert}
    lightHeaderProof: {index: number; proof: string; treedepth: number};
    txProof: {hashtype: string; idx: number; proof: string; stibhash: string; treedepth: number};
    txid: string;
    txIndex: number;
    blockHash: string;
}

/// Standard transaction id (SHA-512/256, base32) of a SignedTxnInBlock — the algod proof endpoint key.
function txidStd(blockRaw: Uint8Array, stib: Node, genesisId: string, genesisHash: Uint8Array): string {
    const txn = get(stib, "txn")!;
    const extra = restoredGenesis(stib, genesisId, genesisHash);
    const id = sha512_256(Buffer.concat([Buffer.from("TX"), withEntries(blockRaw, txn, extra)]));
    const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = 0;
    let val = 0;
    let s = "";
    for (const b of id) {
        val = (val << 8) | b;
        bits += 8;
        while (bits >= 5) {
            s += A[(val >>> (bits - 5)) & 31];
            bits -= 5;
        }
        val &= (1 << bits) - 1;
    }
    if (bits > 0) s += A[(val << (5 - bits)) & 31];
    return s;
}

/// First top-level application call with logs in `stibs` (index), or -1.
function findLoggingAppCall(stibs: Node[]): number {
    return stibs.findIndex((s) => {
        const t = get(s, "txn");
        const dt = get(s, "dt");
        return t && (get(t, "type") as any)?.v === "appl" && int(get(t, "apid")) > 0n && dt && (get(dt, "lg") as any)?.v?.length > 0;
    });
}

export async function capture(): Promise<Capture> {
    const status = await getJson("/v2/status");
    const last = BigInt(status["last-round"]);
    // newest interval whose state proof is already on chain
    let sp: any;
    for (let back = 300n; back < 1000n; back += 128n) {
        try {
            sp = await getJson(`/v2/stateproofs/${last - back}`);
            break;
        } catch {}
    }
    if (!sp) throw new Error("no recent state proof");
    const first = BigInt(sp.Message.FirstAttestedRound);
    const prev = await getJson(`/v2/stateproofs/${first - 1n}`);
    if (BigInt(prev.Message.LastAttestedRound) !== first - 1n) throw new Error("previous state proof is not adjacent");
    // a block of the interval with a logging app call
    for (let r = BigInt(sp.Message.LastAttestedRound); r >= first; r--) {
        const raw = await getBin(`/v2/blocks/${r}?format=msgpack`);
        const blk = get(mpDecode(raw), "block")!;
        const stibs = ((get(blk, "txns") as any)?.v ?? []) as Node[];
        const i = findLoggingAppCall(stibs);
        if (i < 0) continue;
        const txid = txidStd(raw, stibs[i], (get(blk, "gen") as any).v, bin(get(blk, "gh")));
        const lightHeaderProof = await getJson(`/v2/blocks/${r}/lightheader/proof`);
        const txProof = await getJson(`/v2/blocks/${r}/transactions/${txid}/proof?hashtype=sha256`);
        const {blockHash} = await getJson(`/v2/blocks/${r}/hash`);
        return {
            network: NETWORK,
            algod: ALGOD,
            capturedAt: new Date().toISOString(),
            prevStateProof: prev,
            stateProof: sp,
            round: Number(r),
            block: raw.toString("base64"),
            lightHeaderProof,
            txProof,
            txid,
            txIndex: i,
            blockHash,
        };
    }
    throw new Error("no logging application call in the interval");
}

// ── individual vector-commitment paths from a batched proof ─────────────────

/// Per-leaf authentication paths (bottom-up siblings) recovered from a merklearray batch proof.
export function individualPaths(leaves: Map<bigint, Uint8Array>, batch: Uint8Array[], depth: number, H: HashFn, digest: number): Map<bigint, Uint8Array[]> {
    const nodes: Map<bigint, Uint8Array>[] = Array.from({length: depth + 1}, () => new Map());
    let pl = [...leaves.entries()].map(([pos, h]) => ({pos: reverseBits(pos, depth), h})).sort((a, b) => (a.pos < b.pos ? -1 : 1));
    const hints = batch.slice();
    const zero = new Uint8Array(digest);
    for (let l = 0; l < depth; l++) {
        const next: {pos: bigint; h: Uint8Array}[] = [];
        for (let i = 0; i < pl.length; i++) {
            const {pos, h} = pl[i];
            nodes[l].set(pos, h);
            let sh: Uint8Array;
            if (i + 1 < pl.length && pl[i + 1].pos === (pos ^ 1n)) sh = pl[++i].h;
            else {
                sh = hints.shift()!;
                if (!sh.length) sh = zero;
            }
            nodes[l].set(pos ^ 1n, sh);
            const [a, b] = (pos & 1n) === 0n ? [h, sh] : [sh, h];
            next.push({pos: pos >> 1n, h: H(Buffer.concat([Buffer.from("MA"), a, b]))});
        }
        pl = next;
    }
    if (hints.length) throw new Error("unused hints");
    const out = new Map<bigint, Uint8Array[]>();
    for (const pos of leaves.keys()) {
        const tp = reverseBits(pos, depth);
        out.set(pos, Array.from({length: depth}, (_, l) => nodes[l].get((tp >> BigInt(l)) ^ 1n)!));
    }
    return out;
}

/// Fold one leaf hash up a single-leaf path (the engine's job semantics).
export function foldPath(leafHash: Uint8Array, pos: bigint, path: Uint8Array[], H: HashFn): Uint8Array {
    let tp = reverseBits(pos, path.length);
    let h = leafHash;
    for (const s of path) {
        h = H(Buffer.concat([Buffer.from("MA"), ...((tp & 1n) === 0n ? [h, s] : [s, h])]));
        tp >>= 1n;
    }
    return h;
}

// ── vectors ─────────────────────────────────────────────────────────────────

export interface RevealVector {
    pos: string;
    l: string;
    weight: string;
    keyLifetime: string;
    commitment: string;
    sigCT: string;
    vkey: string;
    vcIdx: string;
    keyDepth: number;
    keyPath: string;
    sigPath: string;
    partPath: string;
}

export interface MessageVector {
    blockHeadersCommitment: string;
    votersCommitment: string;
    lnProvenWeight: string;
    firstAttestedRound: string;
    lastAttestedRound: string;
}

const msgVec = (m: Message): MessageVector => ({
    blockHeadersCommitment: hx(m.blockHeadersCommitment),
    votersCommitment: hx(m.votersCommitment),
    lnProvenWeight: m.lnProvenWeight.toString(),
    firstAttestedRound: m.firstAttestedRound.toString(),
    lastAttestedRound: m.lastAttestedRound.toString(),
});

export function build(cap: Capture) {
    const prev = messageFromJson(cap.prevStateProof.Message);
    const msg = messageFromJson(cap.stateProof.Message);
    const sp: StateProof = decodeStateProof(Buffer.from(cap.stateProof.StateProof, "base64"));
    const stats = verifyStateProof(prev, msg, sp, true);

    const sigLeaves = new Map(sp.reveals.map((r) => [r.pos, SH(sigLeaf(r))]));
    const partLeaves = new Map(sp.reveals.map((r) => [r.pos, SH(partLeaf(r))]));
    const sigPaths = individualPaths(sigLeaves, sp.sigPath, sp.sigDepth, SH, 64);
    const partPaths = individualPaths(partLeaves, sp.partPath, sp.partDepth, SH, 64);
    const keyRound = msg.lastAttestedRound;
    const reveals: RevealVector[] = sp.reveals.map((r) => {
        const sPath = sigPaths.get(r.pos)!;
        const pPath = partPaths.get(r.pos)!;
        if (!Buffer.from(foldPath(sigLeaves.get(r.pos)!, r.pos, sPath, SH)).equals(Buffer.from(sp.sigCommit))) throw new Error("sig path");
        if (!Buffer.from(foldPath(partLeaves.get(r.pos)!, r.pos, pPath, SH)).equals(Buffer.from(prev.votersCommitment))) throw new Error("part path");
        const kPath = Array.from({length: r.keyDepth}, (_, i) => (r.keyPath[i]?.length ? r.keyPath[i] : new Uint8Array(64)));
        const kr = keyRound - (keyRound % r.keyLifetime);
        if (!Buffer.from(foldPath(SH(keyLeaf(r.vkey, kr)), r.vcIdx, kPath, SH)).equals(Buffer.from(r.commitment))) throw new Error("key path");
        return {
            pos: r.pos.toString(),
            l: r.l.toString(),
            weight: r.weight.toString(),
            keyLifetime: r.keyLifetime.toString(),
            commitment: hx(r.commitment),
            sigCT: hx(toCT(r.sig)),
            vkey: hx(r.vkey),
            vcIdx: r.vcIdx.toString(),
            keyDepth: r.keyDepth,
            keyPath: hx(Buffer.concat(kPath)),
            sigPath: hx(Buffer.concat(sPath)),
            partPath: hx(Buffer.concat(pPath)),
        };
    });

    // block → light header → BlockHeadersCommitment; transaction → Sha256TxnCommitment
    const raw = Buffer.from(cap.block, "base64");
    const blk = get(mpDecode(raw), "block")!;
    const genesisHash = bin(get(blk, "gh"));
    const round = int(get(blk, "rnd"));
    if (round !== BigInt(cap.round)) throw new Error("round");
    const txnCommitment = bin(get(blk, "txn256"));
    const blockHash = base32Decode(cap.blockHash);
    const lh = {blockHash, genesisHash, round, txnCommitment};
    const lhProof = splitPath(Buffer.from(cap.lightHeaderProof.proof, "base64"), 32);
    const lhIndex = BigInt(cap.lightHeaderProof.index);
    if (lhIndex !== round - msg.firstAttestedRound) throw new Error("light header index");
    const lhRoot = vcRoot(new Map([[lhIndex, lightHeaderLeaf(lh)]]), lhProof, cap.lightHeaderProof.treedepth, S256, 32);
    if (!Buffer.from(lhRoot).equals(Buffer.from(msg.blockHeadersCommitment))) throw new Error("light header proof");

    const stibs = (get(blk, "txns") as any).v as Node[];
    const stib = stibs[cap.txIndex];
    const stibRaw = raw.subarray(stib.start, stib.end);
    const stibHash = stibSha256(stibRaw);
    if (!stibHash.equals(Buffer.from(cap.txProof.stibhash, "base64"))) throw new Error("stib hash");
    const txid = txidSha256(raw, stib, (get(blk, "gen") as any).v, genesisHash);
    const txPath = splitPath(Buffer.from(cap.txProof.proof, "base64"), 32);
    const txRoot = vcRoot(new Map([[BigInt(cap.txProof.idx), txLeaf(txid, stibHash)]]), txPath, cap.txProof.treedepth, S256, 32);
    if (!Buffer.from(txRoot).equals(Buffer.from(txnCommitment))) throw new Error("tx proof");
    const txn = get(stib, "txn")!;
    const logs = (((get(get(stib, "dt")!, "lg") as any).v) as Node[]).map((x) => hx(Buffer.from((x as any).v, "latin1")));

    return {
        network: cap.network,
        capturedAt: cap.capturedAt,
        prev: msgVec(prev),
        msg: msgVec(msg),
        msgEncoding: hx(encodeMessage(msg)),
        msgHash: hx(messageHash(msg)),
        sigCommit: hx(sp.sigCommit),
        signedWeight: sp.signedWeight.toString(),
        saltVersion: sp.saltVersion,
        sigDepth: sp.sigDepth,
        partDepth: sp.partDepth,
        positions: sp.positions.map((p) => p.toString()),
        reveals,
        stats: {...stats, proofBytes: sp.raw.length},
        header: {
            round: round.toString(),
            blockHash: hx(blockHash),
            genesisHash: hx(genesisHash),
            txnCommitment: hx(txnCommitment),
            encoding: hx(encodeLightHeader(lh)),
            leaf: hx(lightHeaderLeaf(lh)),
            index: Number(lhIndex),
            depth: cap.lightHeaderProof.treedepth,
            path: hx(Buffer.concat(lhProof)),
        },
        tx: {
            index: cap.txProof.idx,
            depth: cap.txProof.treedepth,
            path: hx(Buffer.concat(txPath)),
            txid: hx(txid),
            stib: hx(stibRaw),
            stibHash: hx(stibHash),
            appId: int(get(txn, "apid")).toString(),
            logs,
        },
    };
}

export type Vectors = ReturnType<typeof build>;
const vectorsFile = (net: string) => (net === "mainnet" ? "vectors.json" : `${net}-vectors.json`);
const VECTORS = vectorsFile(NETWORK);
export const loadCapture = (): Capture => JSON.parse(readFileSync(new URL(`${NETWORK}.json`, FIX), "utf8"));
export const loadVectors = (net = NETWORK): Vectors => JSON.parse(readFileSync(new URL(vectorsFile(net), FIX), "utf8"));

if (import.meta.url === `file://${process.argv[1]}`) {
    if (process.argv.includes("--refresh")) {
        const cap = await capture();
        writeFileSync(new URL(`${NETWORK}.json`, FIX), JSON.stringify(cap, null, 1));
        console.log(`captured interval ${cap.stateProof.Message.FirstAttestedRound}–${cap.stateProof.Message.LastAttestedRound}, block ${cap.round} tx ${cap.txIndex}`);
    }
    const t = Date.now();
    const v = build(loadCapture());
    writeFileSync(new URL(VECTORS, FIX), JSON.stringify(v, null, 1));
    console.log(`verified state proof ${v.msg.firstAttestedRound}–${v.msg.lastAttestedRound}: ${v.reveals.length} reveals, ${v.positions.length} positions, signed weight ${v.signedWeight}; block ${v.header.round} tx ${v.tx.index} (app ${v.tx.appId}, ${v.tx.logs.length} logs) in ${Date.now() - t} ms`);
}
