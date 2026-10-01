import {mkdirSync, readFileSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {secp256k1} from "@noble/curves/secp256k1";
import {sha256, sha512_256} from "@noble/hashes/sha2";
import {ripemd160} from "@noble/hashes/legacy";
import {encodeAbiParameters, type Hex, keccak256} from "viem";

/// Live-data proof builder for `StacksVerifier` (Stacks → Hiero).
///
/// Everything comes from a public Stacks node (default https://api.hiro.so, stacks-node 4.x):
///   - GET  /v3/blocks/{index_block_hash}       raw Nakamoto block (the header is its prefix)
///   - GET  /v3/stacker_set/{cycle}             the reward set: signing keys and weights, in signer order
///   - POST /v2/map_entry/{addr}/{contract}/{map}?proof=1&tip={index_block_hash}
///                                              a Clarity map entry and its MARF proof at that block
///
/// The fixture (test/e2e/fixtures/stacks-live/mainnet.json) holds:
///   - the signer sets of two reward cycles (N and N+1) with their uncompressed keys,
///   - rotation: the block of cycle N that wrote `.signers` `cycle-signer-set[N+1]`, its signer
///     signatures and the single-segment MARF proof of that entry,
///   - entry: a recent block of cycle N+1 that wrote a Clarity map entry (one segment, like a
///     CLPR channel-record write), its signatures and proof,
///   - hop1 / hop2: the same entry proven against later blocks (2 and 3 trie segments with
///     back-pointers and shunt proofs), with the headers that bind each older trie to its block.
///
/// Every header, signature and proof is checked here (block id, ≥70% signer weight, MARF walk)
/// before the fixture is written, with the same rules as the Solidity verifier.
///
/// CLI:
///   npx tsx test/e2e/relay/buildStacksProof.ts --refresh [--rpc URL]
///   npx tsx test/e2e/relay/buildStacksProof.ts --check            (re-verify the fixture offline)

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const FIXTURE_DIR = path.resolve(__dirname, "../fixtures/stacks-live");
export const MAINNET_FIXTURE = path.join(FIXTURE_DIR, "mainnet.json");
export const STACKS_RPC = "https://api.hiro.so";

/// `.signers` boot contract on mainnet; `cycle-signer-set` is a `uint → (list 4000 {signer, weight})` map.
export const SIGNERS_CONTRACT = "SP000000000000000000002Q6VF78.signers";
/// A live contract whose `responses` map gets one new `{response-id} → {hash}` entry per call.
export const ENTRY_CONTRACT = "SP21EK0KSQG7HEHBGCVRJGPGFMV8SCA2B85X01DK2.blocksurvey-proof-of-submission";

// ── bytes ──────────────────────────────────────────────────────────────────

export const hexOf = (b: Uint8Array): Hex => `0x${Buffer.from(b).toString("hex")}`;
export const bytesOf = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h.replace(/^0x/, ""), "hex"));
const cat = (...xs: Uint8Array[]) => Uint8Array.from(Buffer.concat(xs.map((x) => Buffer.from(x))));
const eq = (a: Uint8Array, b: Uint8Array) => Buffer.from(a).equals(Buffer.from(b));
const u32 = (b: Uint8Array, o: number) => Buffer.from(b).readUInt32BE(o);
const u16 = (b: Uint8Array, o: number) => Buffer.from(b).readUInt16BE(o);
const u64 = (b: Uint8Array, o: number) => Buffer.from(b).readBigUInt64BE(o);
export const H = (b: Uint8Array) => sha512_256(b);
const ascii = (s: string) => Uint8Array.from(Buffer.from(s, "latin1"));

// ── Nakamoto header ────────────────────────────────────────────────────────

/// The fixed prefix of a Nakamoto header: version(1) chain_length(8) burn_spent(8) consensus_hash(20)
/// parent_block_id(32) tx_merkle_root(32) state_index_root(32) timestamp(8) miner_signature(65).
export const HEADER_PREFIX = 206;

export interface ParsedHeader {
    version: number;
    chainLength: bigint;
    consensusHash: Uint8Array;
    parentBlockId: Uint8Array;
    stateIndexRoot: Uint8Array;
    timestamp: bigint;
    signatures: Uint8Array[]; // 65-byte VRS, as in the header
    preimage: Uint8Array; // signer_signature_hash preimage = the header without the signer signatures
    blockHash: Uint8Array; // = signer_signature_hash
    blockId: Uint8Array; // index block hash = H(block_hash ‖ consensus_hash)
}

/// Parse the header at the start of a raw Nakamoto block (stacks-core NakamotoBlockHeader codec).
export function parseHeader(raw: Uint8Array): ParsedHeader {
    const version = raw[0];
    let o = HEADER_PREFIX;
    const n = u32(raw, o);
    o += 4;
    const signatures: Uint8Array[] = [];
    for (let i = 0; i < n; i++, o += 65) signatures.push(raw.slice(o, o + 65));
    const sigEnd = o;
    o += 2; // pox_treatment: u16 bit length
    o += 4 + u32(raw, o); // Vec<u8> data
    if (version >= 1) o += 4 + 5 * u32(raw, o); // problematic_txs (epoch 4.0+): Vec<{u32, u8}>
    const preimage = cat(raw.slice(0, HEADER_PREFIX), raw.slice(sigEnd, o));
    const consensusHash = raw.slice(17, 37);
    const blockHash = H(preimage);
    return {
        version,
        chainLength: u64(raw, 1),
        consensusHash,
        parentBlockId: raw.slice(37, 69),
        stateIndexRoot: raw.slice(101, 133),
        timestamp: u64(raw, 133),
        signatures,
        preimage,
        blockHash,
        blockId: H(cat(blockHash, consensusHash)),
    };
}

// ── signers ────────────────────────────────────────────────────────────────

export interface Signer {
    signingKey: Hex; // 33-byte compressed secp256k1 key
    weight: number;
    x: Hex;
    y: Hex;
    address: Hex; // keccak256(x ‖ y)[12:], what ecrecover returns
}

export function signerOf(signingKey: string, weight: number): Signer {
    const p = secp256k1.ProjectivePoint.fromHex(signingKey.replace(/^0x/, ""));
    const u = p.toRawBytes(false);
    const address = `0x${keccak256(u.slice(1)).slice(26)}` as Hex;
    return {signingKey: `0x${signingKey.replace(/^0x/, "")}`, weight, x: hexOf(u.slice(1, 33)), y: hexOf(u.slice(33)), address};
}

/// hash160 = RIPEMD-160(SHA-256(compressed key)), the 20 bytes of a p2pkh principal.
export const hash160 = (key: Uint8Array) => ripemd160(sha256(key));

export interface SignedBlock {
    blockId: Hex;
    preimage: Hex;
    chainLength: string;
    stateIndexRoot: Hex;
    /// `index(2) ‖ v r s (65)` per signature, ascending signer index.
    signatures: Hex;
    signedWeight: number;
    totalWeight: number;
}

/// Map each header signature to its signer index (by public-key recovery) and check ≥70% weight.
export function signBlock(h: ParsedHeader, set: Signer[]): SignedBlock {
    const byKey = new Map(set.map((s, i) => [s.signingKey.slice(2).toLowerCase(), i]));
    const found: {index: number; sig: Uint8Array}[] = [];
    for (const sig of h.signatures) {
        const rec = sig[0];
        const pk = secp256k1.Signature.fromCompact(sig.slice(1)).addRecoveryBit(rec).recoverPublicKey(h.blockHash);
        const idx = byKey.get(Buffer.from(pk.toRawBytes(true)).toString("hex"));
        if (idx === undefined) throw new Error(`signature by a key outside the signer set`);
        found.push({index: idx, sig});
    }
    found.sort((a, b) => a.index - b.index);
    for (let i = 1; i < found.length; i++) if (found[i].index === found[i - 1].index) throw new Error("duplicate signer");
    const signedWeight = found.reduce((a, f) => a + set[f.index].weight, 0);
    const totalWeight = set.reduce((a, s) => a + s.weight, 0);
    if (signedWeight * 10 < totalWeight * 7) throw new Error(`below 70%: ${signedWeight}/${totalWeight}`);
    const packed = cat(...found.map((f) => cat(Uint8Array.of(f.index >> 8, f.index & 0xff), f.sig)));
    return {
        blockId: hexOf(h.blockId),
        preimage: hexOf(h.preimage),
        chainLength: h.chainLength.toString(),
        stateIndexRoot: hexOf(h.stateIndexRoot),
        signatures: hexOf(packed),
        signedWeight,
        totalWeight,
    };
}

// ── Clarity keys and values ────────────────────────────────────────────────

/// MARF key of a Clarity data-map entry: `vm::{contract}::0::{map}::{hex(serialize(key))}`
/// (clarity_db.rs make_key_for_quad; StoreType::DataMap = 0). The trie path is its SHA-512/256.
export const mapEntryKey = (contract: string, map: string, keyHex: string) =>
    `vm::${contract}::0::${map}::${keyHex.replace(/^0x/, "")}`;

/// MARF value of an entry: SHA-512/256 of the lowercase hex of `serialize(some(value))`.
export const valueHashOf = (serialized: string) => H(ascii(serialized.replace(/^0x/, "").toLowerCase()));

export const clarityUint = (v: bigint) => {
    const b = new Uint8Array(17);
    b[0] = 0x01;
    for (let i = 0; i < 16; i++) b[16 - i] = Number((v >> BigInt(8 * i)) & 0xffn);
    return b;
};

/// Parse `some(list {signer: principal, weight: uint})` from `.signers` `cycle-signer-set`.
export function parseSignerList(v: Uint8Array): {version: number; hash160: Uint8Array; weight: bigint}[] {
    let o = 0;
    const expect = (bytes: number[]) => {
        for (const x of bytes) if (v[o++] !== x) throw new Error(`unexpected byte at ${o - 1}`);
    };
    expect([0x0a, 0x0b]);
    const n = u32(v, o);
    o += 4;
    const out = [];
    for (let i = 0; i < n; i++) {
        expect([0x0c, 0, 0, 0, 2, 6, ...ascii("signer"), 0x05]);
        const version = v[o++];
        const h160 = v.slice(o, o + 20);
        o += 20;
        expect([6, ...ascii("weight"), 0x01]);
        let w = 0n;
        for (let j = 0; j < 16; j++) w = (w << 8n) | BigInt(v[o++]);
        out.push({version, hash160: h160, weight: w});
    }
    if (o !== v.length) throw new Error("trailing bytes");
    return out;
}

// ── MARF proofs ────────────────────────────────────────────────────────────

type Ptr = {id: number; chr: number; back: Uint8Array};
export type ProofItem =
    | {t: "node"; kind: number; chr: number; id: number; path: Uint8Array; ptrs: Ptr[]; ptrBytes: Uint8Array; hashes: Uint8Array[]}
    | {t: "leaf"; chr: number; path: Uint8Array; data: Uint8Array}
    | {t: "shunt"; idx: bigint; hashes: Uint8Array[]};

const CHILDREN = [4, 16, 48, 256];

/// Decode a `TrieMerkleProof` (stacks-core proofs.rs codec): u32 count, then typed items.
export function parseProof(p: Uint8Array): ProofItem[] {
    let o = 0;
    const n = u32(p, o);
    o += 4;
    const items: ProofItem[] = [];
    for (let i = 0; i < n; i++) {
        const t = p[o++];
        if (t <= 3) {
            const chr = p[o++];
            const id = p[o++];
            const pl = u32(p, o);
            o += 4;
            const nodePath = p.slice(o, o + pl);
            o += pl;
            const np = u32(p, o);
            o += 4;
            const ptrBytes = p.slice(o, o + 34 * np);
            const ptrs: Ptr[] = [];
            for (let j = 0; j < np; j++, o += 34) ptrs.push({id: p[o], chr: p[o + 1], back: p.slice(o + 2, o + 34)});
            const hashes: Uint8Array[] = [];
            for (let j = 0; j < CHILDREN[t] - 1; j++, o += 32) hashes.push(p.slice(o, o + 32));
            items.push({t: "node", kind: t, chr, id, path: nodePath, ptrs, ptrBytes, hashes});
        } else if (t === 4) {
            const chr = p[o++];
            const pl = u32(p, o);
            o += 4;
            const leafPath = p.slice(o, o + pl);
            o += pl;
            items.push({t: "leaf", chr, path: leafPath, data: p.slice(o, o + 40)});
            o += 40;
        } else if (t === 5) {
            const idx = Buffer.from(p).readBigInt64BE(o);
            o += 8;
            const k = u32(p, o);
            o += 4;
            const hashes: Uint8Array[] = [];
            for (let j = 0; j < k; j++, o += 32) hashes.push(p.slice(o, o + 32));
            items.push({t: "shunt", idx, hashes});
        } else throw new Error(`bad proof item type ${t}`);
    }
    if (o !== p.length) throw new Error("trailing proof bytes");
    return items;
}

const nodeHash = (n: Extract<ProofItem, {t: "node"}>, child: Uint8Array, nextBlock?: Uint8Array) => {
    const matches = n.ptrs.map((q, i) => [q, i] as const).filter(([q]) => q.id !== 0 && q.chr === n.chr);
    if (matches.length !== 1) throw new Error("node must have exactly one child at chr");
    const [q, at] = matches[0];
    const isBack = (q.id & 0x80) !== 0;
    if (nextBlock ? !isBack || !eq(q.back, nextBlock) : isBack) throw new Error("back-pointer mismatch");
    const kids = [...n.hashes.slice(0, at), child, ...n.hashes.slice(at)];
    return H(cat(Uint8Array.of(n.id), n.ptrBytes, Uint8Array.of(n.path.length), n.path, ...kids));
};

const insertAt = (hashes: Uint8Array[], idx: bigint, h: Uint8Array) => {
    const i = Number(idx) - 1;
    if (i < 0 || i > hashes.length) throw new Error("shunt index out of range");
    return [...hashes.slice(0, i), h, ...hashes.slice(i)];
};

/// Verify a MARF proof the way StacksMarf.sol does (stacks-core verify_proof plus explicit checks):
/// returns the block ids of the older tries the proof passes through (their headers bind each
/// intermediate trie root to its block).
export function verifyProof(items: ProofItem[], keyHash: Uint8Array, valueHash: Uint8Array, root: Uint8Array,
    bindings: (trieRoot: Uint8Array) => Uint8Array): Uint8Array[] {
    let i = 0;
    const leaf = items[i++];
    if (leaf?.t !== "leaf") throw new Error("first item must be a leaf");
    if (!eq(leaf.data, cat(valueHash, new Uint8Array(8)))) throw new Error("value mismatch");
    let hash: Uint8Array = H(cat(Uint8Array.of(1, leaf.path.length), leaf.path, leaf.data));
    let trieHash: Uint8Array = new Uint8Array(32);
    const bound: Uint8Array[] = [];
    for (let seg = 0; ; seg++) {
        const start = i;
        while (items[i]?.t === "node") i++;
        const nodes = items.slice(start, i) as Extract<ProofItem, {t: "node"}>[];
        if (nodes.length === 0) throw new Error("empty segment");
        // path: root first; segment 0 must spell the full key, later segments a prefix of it
        const parts: Uint8Array[] = [];
        for (const n of [...nodes].reverse()) parts.push(n.path, Uint8Array.of(n.chr));
        if (seg === 0) parts.push(leaf.path);
        const prefix = cat(...parts);
        if (seg === 0 ? !eq(prefix, keyHash) : !eq(prefix, keyHash.slice(0, prefix.length))) throw new Error("path mismatch");
        const blockOfOlderTrie = seg === 0 ? undefined : hash;
        nodes.forEach((n, k) => (hash = nodeHash(n, hash, k === 0 ? blockOfOlderTrie : undefined)));
        // shunts
        const sh: Extract<ProofItem, {t: "shunt"}>[] = [];
        while (items[i]?.t === "shunt") sh.push(items[i++] as never);
        if (sh.length === 0) throw new Error("missing shunt");
        if (seg === 0) {
            if (sh.length !== 1 || sh[0].idx !== 0n) throw new Error("bad shunt head");
            trieHash = sh[0].hashes.length === 0 ? hash : H(cat(hash, ...sh[0].hashes));
        } else {
            let t: Uint8Array = trieHash;
            for (const s of sh.slice(0, -1)) {
                if (s.idx === 0n) throw new Error("tail idx 0");
                t = H(cat(...insertAt(s.hashes, s.idx, t)));
            }
            const j = sh[sh.length - 1];
            if (j.idx === 0n) throw new Error("junction idx 0");
            trieHash = H(cat(hash, ...insertAt(j.hashes, j.idx, t)));
        }
        if (i === items.length) break;
        const blockId = bindings(trieHash);
        bound.push(blockId);
        hash = blockId;
    }
    if (!eq(trieHash, root)) throw new Error("root mismatch");
    return bound;
}

/// Block ids the proof's back-pointers name, oldest trie first (one per segment after the first).
export function backPointerBlocks(items: ProofItem[]): Uint8Array[] {
    const out: Uint8Array[] = [];
    for (let i = 1; i < items.length; i++) {
        const prev = items[i - 1];
        const it = items[i];
        if (prev.t === "shunt" && it.t === "node") out.push(it.ptrs.find((q) => q.id !== 0 && q.chr === it.chr)!.back);
    }
    return out;
}

// ── RPC ────────────────────────────────────────────────────────────────────

async function get(url: string): Promise<Response> {
    for (let attempt = 0; ; attempt++) {
        const r = await fetch(url);
        if (r.ok) return r;
        if (attempt >= 4) throw new Error(`${url}: HTTP ${r.status}`);
        await new Promise((res) => setTimeout(res, 1500 * (attempt + 1)));
    }
}

export async function fetchBlock(rpc: string, id: string): Promise<Uint8Array> {
    return new Uint8Array(await (await get(`${rpc}/v3/blocks/${id.replace(/^0x/, "")}`)).arrayBuffer());
}

export async function fetchStackerSet(rpc: string, cycle: number): Promise<Signer[]> {
    const j = (await (await get(`${rpc}/v3/stacker_set/${cycle}`)).json()) as {
        stacker_set: {signers: {signing_key: string; weight: number}[]};
    };
    return j.stacker_set.signers.map((s) => signerOf(s.signing_key, s.weight));
}

export async function fetchMapEntry(rpc: string, contract: string, map: string, keyHex: string, tip: string) {
    const [addr, name] = contract.split(".");
    const url = `${rpc}/v2/map_entry/${addr}/${name}/${map}?proof=1${tip ? `&tip=${tip.replace(/^0x/, "")}` : ""}`;
    for (let attempt = 0; ; attempt++) {
        const r = await fetch(url, {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify(keyHex)});
        if (r.ok) return (await r.json()) as {data: Hex; proof: Hex};
        if (attempt >= 4) throw new Error(`${url}: HTTP ${r.status}`);
        await new Promise((res) => setTimeout(res, 1500 * (attempt + 1)));
    }
}

async function json<T>(url: string): Promise<T> {
    return (await (await get(url)).json()) as T;
}

// ── fixture ────────────────────────────────────────────────────────────────

export interface SignerColumns {
    signingKeys: Hex[];
    weights: number[];
    x: Hex[];
    y: Hex[];
    addresses: Hex[];
}

export const toColumns = (set: Signer[]): SignerColumns => ({
    signingKeys: set.map((s) => s.signingKey),
    weights: set.map((s) => s.weight),
    x: set.map((s) => s.x),
    y: set.map((s) => s.y),
    addresses: set.map((s) => s.address),
});

export const fromColumns = (c: SignerColumns): Signer[] =>
    c.signingKeys.map((k, i) => ({signingKey: k, weight: c.weights[i], x: c.x[i], y: c.y[i], address: c.addresses[i]}));

export interface EntryCapture {
    blockId: Hex;
    block: SignedBlock;
    contract: string;
    map: string;
    key: Hex; // serialized Clarity key
    value: Hex; // serialized some(value), as stored
    proof: Hex;
    bindings: Hex[]; // header preimages of the older tries, in proof order
}

export interface StacksCapture {
    rpc: string;
    capturedAt: string;
    serverVersion: string;
    network: "mainnet";
    chainId: string; // CAIP-2
    principalVersion: number; // p2pkh address version byte (22 = mainnet "SP")
    cycles: {current: number; next: number};
    /// Per cycle, columns in reward-set order (Foundry's JSON reader takes flat arrays).
    signerSets: Record<string, SignerColumns>;
    rotation: EntryCapture & {cycle: number};
    entry: EntryCapture;
    hop1: EntryCapture;
    hop2: EntryCapture;
}

async function captureEntry(rpc: string, contract: string, map: string, key: Hex, tip: string, set: Signer[]): Promise<EntryCapture> {
    const raw = await fetchBlock(rpc, tip);
    const h = parseHeader(raw);
    if (hexOf(h.blockId) !== `0x${tip.replace(/^0x/, "")}`) throw new Error("block id mismatch");
    const block = signBlock(h, set);
    const {data, proof} = await fetchMapEntry(rpc, contract, map, key, tip);
    const items = parseProof(bytesOf(proof));
    const bindings: Hex[] = [];
    const byRoot = new Map<string, Uint8Array>();
    for (const id of backPointerBlocks(items)) {
        const bh = parseHeader(await fetchBlock(rpc, hexOf(id)));
        if (!eq(bh.blockId, id)) throw new Error("binding block id mismatch");
        byRoot.set(hexOf(bh.stateIndexRoot), bh.blockId);
        bindings.push(hexOf(bh.preimage));
    }
    verifyProof(items, H(ascii(mapEntryKey(contract, map, key))), valueHashOf(data), h.stateIndexRoot, (r) => {
        const id = byRoot.get(hexOf(r));
        if (!id) throw new Error("no binding header for trie root");
        return id;
    });
    return {blockId: hexOf(h.blockId), block, contract, map, key, value: data, proof, bindings};
}

/// Find the block that wrote `cycle-signer-set[cycle]`: the leaf's trie is named by the first
/// back-pointer of a proof taken at the tip.
async function findWriter(rpc: string, keyHex: Hex): Promise<string> {
    const {proof} = await fetchMapEntry(rpc, SIGNERS_CONTRACT, "cycle-signer-set", keyHex, "");
    const bp = backPointerBlocks(parseProof(bytesOf(proof)));
    if (bp.length === 0) throw new Error("the entry was written at the tip; retry in a few blocks");
    return hexOf(bp[0]).slice(2);
}

/// Serialized Clarity `{<name>: (string-utf8 …)}` tuple: 0x0c, u32 1, name, 0x0e, u32 length, bytes.
const clarityStringUtf8Tuple = (name: string, s: string): Hex => {
    const n = ascii(name);
    const v = Buffer.from(s, "utf8");
    const len = Buffer.alloc(4);
    len.writeUInt32BE(v.length);
    return hexOf(cat(Uint8Array.of(0x0c, 0, 0, 0, 1, n.length), n, Uint8Array.of(0x0e), len, v));
};

export async function captureMainnet(rpc = STACKS_RPC): Promise<StacksCapture> {
    const info = await json<{server_version: string; stacks_tip_height: number; network_id: number}>(`${rpc}/v2/info`);
    if (info.network_id !== 1) throw new Error("not mainnet");
    const pox = await json<{current_cycle: {id: number}}>(`${rpc}/v2/pox`);
    const next = pox.current_cycle.id;
    const current = next - 1;
    const sets: Record<string, Signer[]> = {
        [current]: await fetchStackerSet(rpc, current),
        [next]: await fetchStackerSet(rpc, next),
    };

    // Rotation: the cycle-`current` block that wrote cycle-signer-set[next].
    const cycleKey = hexOf(clarityUint(BigInt(next)));
    const writer = await findWriter(rpc, cycleKey);
    const rot = await captureEntry(rpc, SIGNERS_CONTRACT, "cycle-signer-set", cycleKey, writer, sets[current]);
    if (rot.bindings.length !== 0) throw new Error("rotation proof is not single-segment");
    const listed = parseSignerList(bytesOf(rot.value));
    const nextSigners = sets[next];
    if (listed.length !== nextSigners.length) throw new Error("signer list length differs from the stacker set");
    listed.forEach((l, k) => {
        if (!eq(l.hash160, hash160(bytesOf(nextSigners[k].signingKey)))) throw new Error(`signer ${k}: hash160 mismatch`);
        if (l.weight !== BigInt(nextSigners[k].weight)) throw new Error(`signer ${k}: weight mismatch`);
    });

    // Entry: a recent block that wrote a `responses` entry of the live contract (single segment).
    const tipHeight = info.stacks_tip_height;
    let entry: EntryCapture | undefined;
    let entryHeight = 0;
    for (let h = tipHeight - 3; h > tipHeight - 200 && !entry; h--) {
        const txs = await json<{results: {tx_type: string; tx_status: string; contract_call?: {contract_id: string; function_name: string; function_args: {repr: string}[]}}[]}>(
            `${rpc}/extended/v2/blocks/${h}/transactions?limit=50`);
        const tx = txs.results.find((t) => t.tx_type === "contract_call" && t.tx_status === "success" &&
            t.contract_call!.contract_id === ENTRY_CONTRACT && t.contract_call!.function_name === "proof-of-submission");
        if (!tx) continue;
        const responseId = JSON.parse(tx.contract_call!.function_args[1].repr.replace(/^u/, "")) as string;
        const blk = await json<{index_block_hash: string}>(`${rpc}/extended/v2/blocks/${h}`);
        entry = await captureEntry(rpc, ENTRY_CONTRACT, "responses", clarityStringUtf8Tuple("response-id", responseId),
            blk.index_block_hash, nextSigners);
        entryHeight = h;
    }
    if (!entry) throw new Error("no recent proof-of-submission call found");
    if (entry.bindings.length !== 0) throw new Error("entry proof is not single-segment");

    // The same entry proven at later blocks: one back-pointer hop, then two.
    const at = async (h: number) => (await json<{index_block_hash: string}>(`${rpc}/extended/v2/blocks/${h}`)).index_block_hash;
    let hop1: EntryCapture | undefined;
    let hop2: EntryCapture | undefined;
    for (let h = entryHeight + 1; h <= Math.min(entryHeight + 60, tipHeight) && !(hop1 && hop2); h++) {
        const c = await captureEntry(rpc, ENTRY_CONTRACT, "responses", entry.key, await at(h), nextSigners);
        if (c.bindings.length === 1 && !hop1) hop1 = c;
        if (c.bindings.length === 2 && !hop2) hop2 = c;
    }
    if (!hop1 || !hop2) throw new Error("could not find 2- and 3-segment proofs");

    return {
        rpc,
        capturedAt: new Date().toISOString(),
        serverVersion: info.server_version,
        network: "mainnet",
        chainId: "stacks:1",
        principalVersion: 22,
        cycles: {current, next},
        signerSets: {[current]: toColumns(sets[current]), [next]: toColumns(sets[next])},
        rotation: {...rot, cycle: next},
        entry,
        hop1,
        hop2,
    };
}

/// Re-run every off-chain check on a saved capture.
export function checkCapture(c: StacksCapture) {
    const sets = Object.fromEntries(Object.entries(c.signerSets).map(([k, v]) => [k, fromColumns(v)]));
    const check = (e: EntryCapture, set: Signer[]) => {
        const raw = bytesOf(e.block.preimage);
        // preimage has no signer-signature vector; rebuild a header with an empty one to reuse the parser
        const withEmpty = cat(raw.slice(0, HEADER_PREFIX), new Uint8Array(4), raw.slice(HEADER_PREFIX));
        const h = parseHeader(withEmpty);
        if (hexOf(h.blockId) !== e.blockId) throw new Error("block id");
        const byRoot = new Map<string, Uint8Array>();
        for (const b of e.bindings) {
            const r = bytesOf(b);
            const bh = parseHeader(cat(r.slice(0, HEADER_PREFIX), new Uint8Array(4), r.slice(HEADER_PREFIX)));
            byRoot.set(hexOf(bh.stateIndexRoot), bh.blockId);
        }
        verifyProof(parseProof(bytesOf(e.proof)), H(ascii(mapEntryKey(e.contract, e.map, e.key))), valueHashOf(e.value),
            h.stateIndexRoot, (r) => byRoot.get(hexOf(r))!);
        // signatures
        const sigs = bytesOf(e.block.signatures);
        let w = 0;
        for (let o = 0; o < sigs.length; o += 67) {
            const idx = u16(sigs, o);
            const sig = sigs.slice(o + 2, o + 67);
            const pk = secp256k1.Signature.fromCompact(sig.slice(1)).addRecoveryBit(sig[0]).recoverPublicKey(h.blockHash);
            if (hexOf(pk.toRawBytes(true)) !== set[idx].signingKey) throw new Error("signature");
            w += set[idx].weight;
        }
        if (w * 10 < set.reduce((a, s) => a + s.weight, 0) * 7) throw new Error("threshold");
    };
    check(c.rotation, sets[c.cycles.current]);
    for (const e of [c.entry, c.hop1, c.hop2]) check(e, sets[c.cycles.next]);
}

// ── ABI encoding (StacksVerifier) ───────────────────────────────────────────

export const SIGNER_SET_ABI = {type: "tuple", components: [
    {name: "cycle", type: "uint64"}, {name: "signers", type: "address[]"}, {name: "weights", type: "uint64[]"}]} as const;
export const ANCHOR_ABI = [{type: "tuple", components: [
    {name: "cycle", type: "uint64"}, {name: "signerSetHash", type: "bytes32"}, {name: "lastChainLength", type: "uint64"}]}] as const;
export const SIGNED_HEADER_ABI = {type: "tuple", components: [
    {name: "header", type: "bytes"}, {name: "signatures", type: "bytes"}]} as const;
export const NEXT_KEY_ABI = {type: "tuple[]", components: [{name: "x", type: "bytes32"}, {name: "y", type: "bytes32"}]} as const;

export const signerSetOf = (cycle: number, set: Signer[]) => ({
    cycle: BigInt(cycle),
    signers: set.map((s) => s.address),
    weights: set.map((s) => BigInt(s.weight)),
});
export const signerSetHash = (cycle: number, set: Signer[]) =>
    keccak256(encodeAbiParameters([SIGNER_SET_ABI], [signerSetOf(cycle, set)]));
export const encodeAnchor = (cycle: number, set: Signer[], lastChainLength = 0n) =>
    encodeAbiParameters(ANCHOR_ABI, [{cycle: BigInt(cycle), signerSetHash: signerSetHash(cycle, set), lastChainLength}]);
export const signedHeaderOf = (e: EntryCapture) => ({header: e.block.preimage, signatures: e.block.signatures});
export const nextKeysOf = (set: Signer[]) => set.map((s) => ({x: s.x, y: s.y}));

// ── CLI ────────────────────────────────────────────────────────────────────

function arg(name: string): string | undefined {
    const i = process.argv.indexOf(name);
    return i >= 0 ? process.argv[i + 1] : undefined;
}

async function main() {
    if (process.argv.includes("--refresh")) {
        const cap = await captureMainnet(arg("--rpc") ?? STACKS_RPC);
        checkCapture(cap);
        mkdirSync(FIXTURE_DIR, {recursive: true});
        writeFileSync(MAINNET_FIXTURE, JSON.stringify(cap, null, 2) + "\n");
        console.log(`wrote ${MAINNET_FIXTURE}: cycles ${cap.cycles.current}→${cap.cycles.next}, rotation block ${cap.rotation.blockId}, ` +
            `entry block ${cap.entry.blockId} (proof ${(cap.entry.proof.length - 2) / 2} B), hop1 ${(cap.hop1.proof.length - 2) / 2} B, hop2 ${(cap.hop2.proof.length - 2) / 2} B`);
    } else if (process.argv.includes("--check")) {
        checkCapture(JSON.parse(readFileSync(MAINNET_FIXTURE, "utf8")) as StacksCapture);
        console.log("fixture OK");
    } else {
        console.log("usage: buildStacksProof.ts --refresh [--rpc URL] | --check");
    }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
    main().catch((e) => {
        console.error(e);
        process.exit(1);
    });
}
