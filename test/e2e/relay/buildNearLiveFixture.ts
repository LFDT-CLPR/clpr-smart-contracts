import {createHash} from "node:crypto";
import {readFileSync, writeFileSync, mkdirSync} from "node:fs";
import {dirname, resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {encodeAbiParameters, type Hex} from "viem";
import {ed25519} from "@noble/curves/ed25519";

/// NEAR live fixture: capture (`--refresh`) and proof building for NearVerifier.
///
/// Capture, per network, from the public RPC:
///  - the light-client block of the current final head (`next_light_client_block`), epoch E;
///  - the ordered block producers of epochs E−1 and E (`EXPERIMENTAL_validators_ordered`);
///  - the last block of E−1 (its `epoch_id` / `next_epoch_id` / `next_bp_hash`);
///  - the chunk `prev_state_root`s of the light-client block (`block`);
///  - a `view_state` proof (`include_proof`) of a small contract at the light-client block's parent,
///    whose post-state root is the chunk `prev_state_root` committed by the light-client block.
///
/// Built proofs: the same light-client block verifies from the epoch-E anchor (no rotation) and from
/// the epoch-(E−1) anchor (it is in the next epoch, so it rotates the anchor to E).
///
/// Run: npx tsx test/e2e/relay/buildNearLiveFixture.ts --refresh [mainnet|testnet]

const HERE = dirname(fileURLToPath(import.meta.url));
export const NEAR_FIXTURE_DIR = resolve(HERE, "../fixtures/near-live");

export const NEAR_TARGETS: Record<string, {rpc: string; account: string; key: string; chainId: string}> = {
    mainnet: {rpc: "https://rpc.mainnet.near.org", account: "lockup.near", key: "STATE", chainId: "near:mainnet"},
    testnet: {
        rpc: "https://rpc.testnet.near.org",
        account: "hello.near-examples.testnet",
        key: "STATE",
        chainId: "near:testnet",
    },
};

const sha256 = (b: Uint8Array): Buffer => createHash("sha256").update(b).digest();
export const hex = (b: Uint8Array): Hex => ("0x" + Buffer.from(b).toString("hex")) as Hex;

// ── base58 ──────────────────────────────────────────────────────────────────

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export function b58(s: string): Buffer {
    s = s.replace(/^ed25519:/, "");
    let n = 0n;
    for (const c of s) {
        const v = B58.indexOf(c);
        if (v < 0) throw new Error("base58");
        n = n * 58n + BigInt(v);
    }
    let h = n.toString(16);
    if (h.length % 2) h = "0" + h;
    const body = n === 0n ? Buffer.alloc(0) : Buffer.from(h, "hex");
    let zeros = 0;
    while (s[zeros] === "1") zeros++;
    return Buffer.concat([Buffer.alloc(zeros), body]);
}
const b32 = (s: string): Buffer => {
    const b = b58(s);
    if (b.length > 32) throw new Error("hash length");
    return Buffer.concat([Buffer.alloc(32 - b.length), b]);
};

// ── borsh ───────────────────────────────────────────────────────────────────

const le = (v: bigint, n: number): Buffer => {
    const b = Buffer.alloc(n);
    for (let i = 0; i < n; i++) b[i] = Number((v >> BigInt(8 * i)) & 0xffn);
    return b;
};

export interface NearProducer {
    account_id: string;
    public_key: string;
    stake: string;
}

export function borshProducers(ps: NearProducer[]): Buffer {
    const parts: Buffer[] = [le(BigInt(ps.length), 4)];
    for (const p of ps) {
        if (!p.public_key.startsWith("ed25519:")) throw new Error("only ed25519 producers handled by the builder");
        const id = Buffer.from(p.account_id, "utf8");
        parts.push(Buffer.from([0]), le(BigInt(id.length), 4), id, Buffer.from([0]), b32(p.public_key), le(BigInt(p.stake), 16));
    }
    return Buffer.concat(parts);
}

export interface LightClientBlockView {
    prev_block_hash: string;
    next_block_inner_hash: string;
    inner_lite: {
        height: number;
        epoch_id: string;
        next_epoch_id: string;
        prev_state_root: string;
        outcome_root: string;
        timestamp_nanosec: string;
        next_bp_hash: string;
        block_merkle_root: string;
    };
    inner_rest_hash: string;
    next_bps: NearProducer[] | null;
    approvals_after_next: (string | null)[];
}

export function borshInnerLite(l: LightClientBlockView["inner_lite"]): Buffer {
    return Buffer.concat([
        le(BigInt(l.height), 8),
        b32(l.epoch_id),
        b32(l.next_epoch_id),
        b32(l.prev_state_root),
        b32(l.outcome_root),
        le(BigInt(l.timestamp_nanosec), 8),
        b32(l.next_bp_hash),
        b32(l.block_merkle_root),
    ]);
}

export function lcBlockHash(lc: LightClientBlockView): Buffer {
    const inner = sha256(Buffer.concat([sha256(borshInnerLite(lc.inner_lite)), b32(lc.inner_rest_hash)]));
    return sha256(Buffer.concat([inner, b32(lc.prev_block_hash)]));
}

export function approvalMessage(lc: LightClientBlockView): Buffer {
    const next = sha256(Buffer.concat([b32(lc.next_block_inner_hash), lcBlockHash(lc)]));
    return Buffer.concat([Buffer.from([0]), next, le(BigInt(lc.inner_lite.height + 2), 8)]);
}

export function merklize(items: Buffer[]): Buffer {
    let h = items.map((x) => sha256(x));
    while (h.length > 1) {
        const n: Buffer[] = [];
        for (let i = 0; i < h.length; i += 2) n.push(i + 1 < h.length ? sha256(Buffer.concat([h[i], h[i + 1]])) : h[i]);
        h = n;
    }
    return h[0];
}

// ── trie path extraction ────────────────────────────────────────────────────

/// From the RPC's unordered proof set, return the nodes on the path to `key`, root first.
export function triePath(root: Buffer, key: Buffer, proof: Buffer[], known?: Buffer): {nodes: Buffer[]; value: Buffer} {
    const r = trieProve(root, key, proof, known ? [known] : []);
    if (!r.value) throw new Error("trie: absent");
    return {nodes: r.nodes, value: r.value};
}

/// The path to `key`, root first: ending at its value (`value` set) or where the key leaves the trie
/// (`value` null: an exclusion proof). `values` are value preimages served beside the proof.
export function trieProve(
    root: Buffer,
    key: Buffer,
    proof: Buffer[],
    values: Buffer[] = [],
): {nodes: Buffer[]; value: Buffer | null} {
    const byHash = new Map(proof.map((p) => [sha256(p).toString("hex"), p]));
    for (const v of values) byHash.set(sha256(v).toString("hex"), v);
    const nib = (i: number) => (i % 2 === 0 ? key[i >> 1] >> 4 : key[i >> 1] & 15);
    const total = key.length * 2;
    let pos = 0;
    let h = root;
    const nodes: Buffer[] = [];
    const valueOf = (ref: Buffer) => {
        const v = byHash.get(ref.toString("hex"));
        if (!v) throw new Error("trie: missing value");
        return v;
    };
    for (;;) {
        const n = byHash.get(h.toString("hex"));
        if (!n) throw new Error("trie: missing node");
        nodes.push(n);
        const tag = n[0];
        if (tag === 0 || tag === 3) {
            const len = n.readUInt32LE(1);
            const enc = n.subarray(5, 5 + len);
            const odd = (enc[0] & 0x10) !== 0;
            const path: number[] = odd ? [enc[0] & 15] : [];
            for (let j = 1; j < enc.length; j++) path.push(enc[j] >> 4, enc[j] & 15);
            if (pos + path.length > total) return {nodes, value: null};
            for (const x of path) if (nib(pos++) !== x) return {nodes, value: null};
            if (tag === 0) {
                if (pos !== total) return {nodes, value: null};
                return {nodes, value: valueOf(n.subarray(5 + len + 4, 5 + len + 36))};
            }
            h = n.subarray(5 + len, 5 + len + 32);
        } else {
            let off = 1;
            const vref = tag === 2 ? n.subarray(1, 37) : null;
            if (tag === 2) off += 36;
            const bitmap = n.readUInt16LE(off);
            off += 2;
            if (pos === total) return {nodes, value: vref ? valueOf(vref.subarray(4)) : null};
            const c = nib(pos++);
            if (!((bitmap >> c) & 1)) return {nodes, value: null};
            let k = 0;
            for (let j = 0; j < c; j++) if ((bitmap >> j) & 1) k++;
            h = n.subarray(off + 32 * k, off + 32 * k + 32);
        }
    }
}

// ── RPC capture ─────────────────────────────────────────────────────────────

export interface NearCapture {
    network: string;
    capturedAt: string;
    rpc: string;
    account: string;
    key: string;
    chainId: string;
    lc: LightClientBlockView;
    lcBlockHashRpc: string;
    producersPrev: NearProducer[]; // epoch E-1
    producersCur: NearProducer[]; // epoch E (the lc block's epoch)
    prevEpochLastBlock: {hash: string; height: number; epoch_id: string; next_epoch_id: string; next_bp_hash: string};
    chunkPrevStateRoots: string[];
    viewState: {block_hash: string; proof: string[]; values: {key: string; value: string}[]};
}

async function rpc(url: string, method: string, params: unknown): Promise<any> {
    for (let attempt = 0; ; attempt++) {
        const r = await fetch(url, {
            method: "POST",
            headers: {"content-type": "application/json"},
            body: JSON.stringify({jsonrpc: "2.0", id: 1, method, params}),
        });
        const text = await r.text();
        let d: any;
        try {
            d = JSON.parse(text);
        } catch {
            if (attempt > 5) throw new Error(`${method}: ${text.slice(0, 200)}`);
            await new Promise((res) => setTimeout(res, 2000 * (attempt + 1)));
            continue;
        }
        if (d.error) throw new Error(`${method}: ${JSON.stringify(d.error).slice(0, 300)}`);
        return d.result;
    }
}

/// The light-client half of a capture: everything except the contract `view_state`.
export type NearLightClientCapture = Pick<
    NearCapture,
    "lc" | "lcBlockHashRpc" | "producersPrev" | "producersCur" | "prevEpochLastBlock" | "chunkPrevStateRoots"
>;

export async function captureLightClient(url: string): Promise<NearLightClientCapture> {
    const head = await rpc(url, "block", {finality: "final"});
    const lc: LightClientBlockView = await rpc(url, "next_light_client_block", {last_block_hash: head.header.hash});
    const vinfo = await rpc(url, "validators", {epoch_id: lc.inner_lite.epoch_id});
    const prevLast = await rpc(url, "block", {block_id: vinfo.epoch_start_height - 1});
    if (prevLast.header.next_epoch_id !== lc.inner_lite.epoch_id) throw new Error("epoch boundary mismatch");
    const producersCur = await rpc(url, "EXPERIMENTAL_validators_ordered", {block_id: lc.inner_lite.height});
    const producersPrev = await rpc(url, "EXPERIMENTAL_validators_ordered", {block_id: prevLast.header.height});
    const lcBlock = await rpc(url, "block", {block_id: lc.inner_lite.height});
    return {
        lc,
        lcBlockHashRpc: lcBlock.header.hash,
        producersPrev,
        producersCur,
        prevEpochLastBlock: {
            hash: prevLast.header.hash,
            height: prevLast.header.height,
            epoch_id: prevLast.header.epoch_id,
            next_epoch_id: prevLast.header.next_epoch_id,
            next_bp_hash: prevLast.header.next_bp_hash,
        },
        chunkPrevStateRoots: lcBlock.chunks.map((c: {prev_state_root: string}) => c.prev_state_root),
    };
}

/// `view_state` with a proof, at the light-client block's parent: its post-state root is the chunk
/// `prev_state_root` the light-client block commits to.
export async function viewStateProof(url: string, lc: LightClientBlockView, account: string, prefix: Buffer) {
    const r = await rpc(url, "query", {
        request_type: "view_state",
        block_id: lc.prev_block_hash,
        account_id: account,
        prefix_base64: prefix.toString("base64"),
        include_proof: true,
    });
    return {block_hash: r.block_hash as string, proof: r.proof as string[], values: r.values as {key: string; value: string}[]};
}

export async function captureNear(network: string): Promise<NearCapture> {
    const t = NEAR_TARGETS[network];
    const lcc = await captureLightClient(t.rpc);
    const viewState = await viewStateProof(t.rpc, lcc.lc, t.account, Buffer.from(t.key));
    return {
        network,
        capturedAt: new Date().toISOString(),
        rpc: t.rpc,
        account: t.account,
        key: t.key,
        chainId: t.chainId,
        ...lcc,
        viewState,
    };
}

// ── proof building ──────────────────────────────────────────────────────────

const BLOCK_T = {
    type: "tuple",
    components: [
        {name: "prevBlockHash", type: "bytes32"},
        {name: "nextBlockInnerHash", type: "bytes32"},
        {name: "innerLite", type: "bytes"},
        {name: "innerRestHash", type: "bytes32"},
        {name: "producers", type: "bytes"},
        {name: "signers", type: "uint256[]"},
        {name: "signatures", type: "bytes[]"},
    ],
} as const;
const SHARDS_T = {
    type: "tuple",
    components: [
        {name: "roots", type: "bytes32[]"},
        {name: "index", type: "uint256"},
    ],
} as const;

export interface NearBlockArg {
    prevBlockHash: Hex;
    nextBlockInnerHash: Hex;
    innerLite: Hex;
    innerRestHash: Hex;
    producers: Hex;
    signers: bigint[];
    signatures: Hex[];
}

export const STATE_PROOF_ABI = [
    {
        type: "tuple",
        components: [
            {name: "blocks", ...BLOCK_T, type: "tuple[]"},
            {name: "shards", ...SHARDS_T},
            {name: "accountId", type: "bytes"},
            {name: "dataKey", type: "bytes"},
            {name: "nodes", type: "bytes[]"},
            {name: "value", type: "bytes"},
        ],
    },
] as const;

export const BUNDLE_PROOF_ABI = [
    {
        type: "tuple",
        components: [
            {name: "blocks", ...BLOCK_T, type: "tuple[]"},
            {name: "shards", ...SHARDS_T},
            {name: "queueNodes", type: "bytes[]"},
            {name: "queueRecord", type: "bytes"},
            {name: "bundleContent", type: "bytes"},
            {name: "manifestNodes", type: "bytes[]"},
            {name: "manifestPreimage", type: "bytes"},
        ],
    },
] as const;

export const CONFIG_PROOF_ABI = [
    {
        type: "tuple",
        components: [
            {name: "blocks", ...BLOCK_T, type: "tuple[]"},
            {name: "shards", ...SHARDS_T},
            {name: "configNodes", type: "bytes[]"},
            {name: "controlMessage", type: "bytes"},
        ],
    },
] as const;

export interface NearLiveProof {
    network: string;
    chainId: string;
    anchorPrev: Hex; // epoch E-1 window
    anchorCur: Hex; // epoch E window
    checkpointPrev: [Hex, Hex, Hex, Hex];
    message: Hex;
    signerKeys: Hex[]; // keys of the chosen signers, in signer order
    signerSignatures: Hex[];
    block: NearBlockArg; // all chosen signatures inline
    blockCached: NearBlockArg; // signatures empty: must be pre-recorded in the cache
    stateProof: Hex; // inline signatures
    stateProofCached: Hex;
    value: Hex;
    lcHash: Hex;
    height: number;
    meta: {producers: number; signedProducers: number; chosenSigners: number; shards: number; shardIndex: number; trieDepth: number};
}

export interface NearLightClientPart {
    anchorPrev: Buffer;
    anchorCur: Buffer;
    bpPrev: Buffer;
    bpCur: Buffer;
    msg: Buffer;
    chosen: number[];
    signedCount: number;
    sigOf: (i: number) => Buffer;
    block: NearBlockArg;
    blockCached: NearBlockArg;
    roots: Buffer[];
    bh: Buffer;
}

/// Light-client block, anchors, the > 2/3-stake signer choice and the shard roots of a capture.
export function buildLightClientPart(c: NearLightClientCapture): NearLightClientPart {
    const lc = c.lc;
    // Block hash recomputed from the light-client view must equal the RPC block hash.
    const bh = lcBlockHash(lc);
    if (!bh.equals(b32(c.lcBlockHashRpc))) throw new Error("light-client block hash mismatch");

    const prodPrev = borshProducers(c.producersPrev);
    const prodCur = borshProducers(c.producersCur);
    const bpPrev = sha256(prodPrev);
    const bpCur = sha256(prodCur);
    if (!bpCur.equals(b32(c.prevEpochLastBlock.next_bp_hash))) throw new Error("bp hash of epoch E mismatch");

    const anchorPrev = Buffer.concat([b32(c.prevEpochLastBlock.epoch_id), b32(c.prevEpochLastBlock.next_epoch_id), bpPrev, bpCur]);
    const anchorCur = Buffer.concat([b32(lc.inner_lite.epoch_id), b32(lc.inner_lite.next_epoch_id), bpCur, b32(lc.inner_lite.next_bp_hash)]);

    // Pick the heaviest signers until > 2/3 of total stake, then sort by index.
    const msg = approvalMessage(lc);
    const stakes = c.producersCur.map((p) => BigInt(p.stake));
    const total = stakes.reduce((a, b) => a + b, 0n);
    const signed = lc.approvals_after_next
        .map((s, i) => ({s, i}))
        .filter((x) => x.s !== null && x.i < c.producersCur.length);
    for (const x of signed) {
        if (!ed25519.verify(b58(x.s!), msg, b32(c.producersCur[x.i].public_key))) throw new Error(`bad approval ${x.i}`);
    }
    signed.sort((a, b) => (stakes[b.i] > stakes[a.i] ? 1 : stakes[b.i] < stakes[a.i] ? -1 : a.i - b.i));
    const chosen: number[] = [];
    let acc = 0n;
    for (const x of signed) {
        chosen.push(x.i);
        acc += stakes[x.i];
        if (acc * 3n > total * 2n) break;
    }
    if (acc * 3n <= total * 2n) throw new Error("approvals below 2/3");
    chosen.sort((a, b) => a - b);
    const sigOf = (i: number) => b58(lc.approvals_after_next[i]!);

    const blockBase = {
        prevBlockHash: hex(b32(lc.prev_block_hash)),
        nextBlockInnerHash: hex(b32(lc.next_block_inner_hash)),
        innerLite: hex(borshInnerLite(lc.inner_lite)),
        innerRestHash: hex(b32(lc.inner_rest_hash)),
        producers: hex(prodCur),
        signers: chosen.map(BigInt),
    };
    const block: NearBlockArg = {...blockBase, signatures: chosen.map((i) => hex(sigOf(i)))};
    const blockCached: NearBlockArg = {...blockBase, signatures: chosen.map(() => "0x" as Hex)};

    // State root: chunk prev_state_roots merklize to inner_lite.prev_state_root.
    const roots = c.chunkPrevStateRoots.map(b32);
    if (!merklize(roots).equals(b32(lc.inner_lite.prev_state_root))) throw new Error("state root merklize mismatch");
    return {anchorPrev, anchorCur, bpPrev, bpCur, msg, chosen, signedCount: signed.length, sigOf, block, blockCached, roots, bh};
}

export function buildNearLiveProof(c: NearCapture): NearLiveProof {
    const lc = c.lc;
    const {anchorPrev, anchorCur, bpPrev, bpCur, msg, chosen, signedCount, sigOf, block, blockCached, roots, bh} =
        buildLightClientPart(c);
    const proof = c.viewState.proof.map((p) => Buffer.from(p, "base64"));
    const rootSet = new Set(proof.map((p) => sha256(p).toString("hex")));
    const shardIndex = roots.findIndex((r) => rootSet.has(r.toString("hex")));
    if (shardIndex < 0) throw new Error("no shard root matches the view_state proof");
    const trieKey = Buffer.concat([Buffer.from([9]), Buffer.from(c.account), Buffer.from(","), Buffer.from(c.key)]);
    const rpcValue = c.viewState.values.find((v) => Buffer.from(v.key, "base64").toString() === c.key);
    if (!rpcValue) throw new Error("value missing from view_state");
    // view_state returns values beside the proof; the trie leaf's ValueRef hash binds them.
    const {nodes, value} = triePath(roots[shardIndex], trieKey, proof, Buffer.from(rpcValue.value, "base64"));

    const shards = {roots: roots.map(hex), index: BigInt(shardIndex)};
    const sp = (b: NearBlockArg) =>
        encodeAbiParameters(STATE_PROOF_ABI as never, [
            {
                blocks: [b],
                shards,
                accountId: hex(Buffer.from(c.account)),
                dataKey: hex(Buffer.from(c.key)),
                nodes: nodes.map(hex),
                value: hex(value),
            },
        ] as never);

    return {
        network: c.network,
        chainId: c.chainId,
        anchorPrev: hex(anchorPrev),
        anchorCur: hex(anchorCur),
        checkpointPrev: [hex(anchorPrev.subarray(0, 32)), hex(anchorPrev.subarray(32, 64)), hex(bpPrev), hex(bpCur)],
        message: hex(msg),
        signerKeys: chosen.map((i) => hex(b32(c.producersCur[i].public_key))),
        signerSignatures: chosen.map((i) => hex(sigOf(i))),
        block,
        blockCached,
        stateProof: sp(block),
        stateProofCached: sp(blockCached),
        value: hex(value),
        lcHash: hex(bh),
        height: lc.inner_lite.height,
        meta: {
            producers: c.producersCur.length,
            signedProducers: signedCount,
            chosenSigners: chosen.length,
            shards: roots.length,
            shardIndex,
            trieDepth: nodes.length,
        },
    };
}

export function loadNearCapture(network: string): NearCapture {
    return JSON.parse(readFileSync(resolve(NEAR_FIXTURE_DIR, `${network}.json`), "utf8")).capture;
}

/// Fixture file: the raw capture plus the derived hex the Foundry replay reads.
export function writeNearFixture(c: NearCapture): NearLiveProof {
    const p = buildNearLiveProof(c);
    mkdirSync(NEAR_FIXTURE_DIR, {recursive: true});
    const derived = {
        chainId: p.chainId,
        anchorPrev: p.anchorPrev,
        anchorCur: p.anchorCur,
        checkpointPrev: p.checkpointPrev,
        message: p.message,
        signerKeys: p.signerKeys,
        signerSignatures: p.signerSignatures,
        stateProof: p.stateProof,
        stateProofCached: p.stateProofCached,
        value: p.value,
        lcHash: p.lcHash,
        height: p.height,
        meta: p.meta,
    };
    writeFileSync(resolve(NEAR_FIXTURE_DIR, `${c.network}.json`), JSON.stringify({derived, capture: c}, null, 1) + "\n");
    return p;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    const nets = process.argv.slice(2).filter((a) => !a.startsWith("--"));
    const refresh = process.argv.includes("--refresh");
    for (const net of nets.length ? nets : ["mainnet", "testnet"]) {
        const c = refresh ? await captureNear(net) : loadNearCapture(net);
        const p = writeNearFixture(c);
        console.log(`[near-live] ${net}: height ${p.height}, ${JSON.stringify(p.meta)}`);
    }
}
