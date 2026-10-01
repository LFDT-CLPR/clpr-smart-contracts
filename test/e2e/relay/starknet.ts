import {encodeAbiParameters, keccak256, toHex, type Hex} from "viem";
import {createHash} from "node:crypto";
import {hexToBuf, rlpEncode} from "../lib/rlp.js";

/// Starknet primitives for the `StarknetVerifier` family, written against the current sources:
///   - Pedersen: cairo-lang `src/starkware/crypto/signature/fast_pedersen_hash.py` + `pedersen_params.json`
///     (H(a, b) = [shift + a_low·P0 + a_high·P1 + b_low·P2 + b_high·P3].x, low = 248 bits).
///   - Poseidon: cairo-lang `src/starkware/cairo/common/poseidon_utils.py` (Hades, width 3, 8 full +
///     83 partial rounds, x³, MDS [[3,1,1],[1,-1,1],[1,1,-2]], constants sha256("Hades" ‖ i) mod p) and
///     `poseidon_hash.py` (hash_many: pad with 1 then 0s to the rate 2).
///   - Patricia: binary H(left, right); edge H(child, path) + length (height 251, Pedersen).
///   - Contract leaf: H(H(H(class_hash, storage_root), nonce), 0) (sequencer
///     `apollo_starknet_os_program/.../os/state/commitment.cairo`, CONTRACT_STATE_HASH_VERSION = 0).
///   - Global root: 0 if both trees are empty, else Poseidon('STARKNET_STATE_V0', contracts, classes).
///   - Cairo storage: `selector!(name)` = sn_keccak (keccak250); `Map` entry = Pedersen chain over the
///     key's `Hash` serialization (u256 → low, high; tuples in order), reduced mod 2²⁵¹ − 256
///     (`storage_base_address_from_felt252`); a `Store`-derived struct's members sit at base + offset,
///     u256 as (low, high) in two consecutive felts.

export const P = 2n ** 251n + 17n * 2n ** 192n + 1n;
export const EC_ORDER = 0x800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2fn;
export const ADDR_BOUND = 2n ** 251n - 256n;
export const MASK_250 = (1n << 250n) - 1n;
const ALPHA = 1n;

export type Point = {x: bigint; y: bigint} | null;

const mod = (a: bigint, m = P) => ((a % m) + m) % m;

export function inv(a: bigint, m = P): bigint {
    let [t, newT, r, newR] = [0n, 1n, m, mod(a, m)];
    while (newR !== 0n) {
        const q = r / newR;
        [t, newT] = [newT, t - q * newT];
        [r, newR] = [newR, r - q * newR];
    }
    if (r !== 1n) throw new Error("not invertible");
    return mod(t, m);
}

export function ecAdd(a: Point, b: Point): Point {
    if (!a) return b;
    if (!b) return a;
    let l: bigint;
    if (a.x === b.x) {
        if (mod(a.y + b.y) === 0n) return null;
        l = mod((3n * a.x * a.x + ALPHA) * inv(2n * a.y));
    } else {
        l = mod((b.y - a.y) * inv(b.x - a.x));
    }
    const x = mod(l * l - a.x - b.x);
    return {x, y: mod(l * (a.x - x) - a.y)};
}

export function ecMul(k: bigint, p: Point): Point {
    let r: Point = null;
    let q = p;
    while (k > 0n) {
        if (k & 1n) r = ecAdd(r, q);
        q = ecAdd(q, q);
        k >>= 1n;
    }
    return r;
}

/// pedersen_params.json CONSTANT_POINTS[0, 2, 2+248, 2+252, 2+252+248].
export const PEDERSEN_POINTS = {
    shift: {x: 0x49ee3eba8c1600700ee1b87eb599f16716b0b1022947733551fde4050ca6804n,
        y: 0x3ca0cfe4b3bc6ddf346d49d06ea0ed34e621062c0e056c1d0405d266e10268an},
    p0: {x: 0x234287dcbaffe7f969c748655fca9e58fa8120b6d56eb0c1080d17957ebe47bn,
        y: 0x3b056f100f96fb21e889527d41f4e39940135dd7a6c94cc6ed0268ee89e5615n},
    p1: {x: 0x4fa56f376c83db33f9dab2656558f3399099ec1de5e3018b7a6932dba8aa378n,
        y: 0x3fa0984c931c9e38113e0c0e47e4401562761f92a7a23b45168f4e80ff5b54dn},
    p2: {x: 0x4ba4cc166be8dec764910f75b45f74b40c690c74709e90f3aa372f0bd2d6997n,
        y: 0x40301cf5c1751f4b971e46c4ede85fcac5c59a5ce5ae7c48151f27b24b219cn},
    p3: {x: 0x54302dcb0e6cc1c6e44cca8f61a63bb2ca65048d53fb325d36ff12c49a58202n,
        y: 0x1b77b3e37d13504b348046268d8ae25ce98ad783c25561a879dcc77e99c2426n}
} as const;

const LOW_MASK = (1n << 248n) - 1n;
const pedersenCache = new Map<string, bigint>();

export function pedersen(a: bigint, b: bigint): bigint {
    if (a < 0n || a >= P || b < 0n || b >= P) throw new Error("pedersen input out of range");
    const k = `${a}:${b}`;
    const c = pedersenCache.get(k);
    if (c !== undefined) return c;
    const pp = PEDERSEN_POINTS;
    let r: Point = pp.shift;
    r = ecAdd(r, ecMul(a & LOW_MASK, pp.p0));
    r = ecAdd(r, ecMul(a >> 248n, pp.p1));
    r = ecAdd(r, ecMul(b & LOW_MASK, pp.p2));
    r = ecAdd(r, ecMul(b >> 248n, pp.p3));
    pedersenCache.set(k, r!.x);
    return r!.x;
}

// ── Poseidon (Hades) ───────────────────────────────────────────────────────
export const POSEIDON_ROUNDS = 91;
export const POSEIDON_FULL_HALF = 4;
export const POSEIDON_RC: bigint[] = Array.from({length: POSEIDON_ROUNDS * 3}, (_, i) =>
    BigInt("0x" + createHash("sha256").update(`Hades${i}`).digest("hex")) % P);

export function hades(s: [bigint, bigint, bigint]): [bigint, bigint, bigint] {
    let [a, b, c] = s;
    for (let r = 0; r < POSEIDON_ROUNDS; r++) {
        a = mod(a + POSEIDON_RC[3 * r]);
        b = mod(b + POSEIDON_RC[3 * r + 1]);
        c = mod(c + POSEIDON_RC[3 * r + 2]);
        const full = r < POSEIDON_FULL_HALF || r >= POSEIDON_ROUNDS - POSEIDON_FULL_HALF;
        if (full) {
            a = mod(a * a * a);
            b = mod(b * b * b);
        }
        c = mod(c * c * c);
        [a, b, c] = [mod(3n * a + b + c), mod(a - b + c), mod(a + b - 2n * c)];
    }
    return [a, b, c];
}

export function poseidonHashMany(xs: bigint[]): bigint {
    const v = [...xs, 1n];
    if (v.length % 2) v.push(0n);
    let s: [bigint, bigint, bigint] = [0n, 0n, 0n];
    for (let i = 0; i < v.length; i += 2) s = hades([mod(s[0] + v[i]), mod(s[1] + v[i + 1]), s[2]]);
    return s[0];
}

export const shortString = (s: string): bigint => BigInt(toHex(s));
export const STARKNET_STATE_V0 = shortString("STARKNET_STATE_V0");

export function globalStateRoot(contractsRoot: bigint, classesRoot: bigint): bigint {
    if (contractsRoot === 0n && classesRoot === 0n) return 0n;
    return poseidonHashMany([STARKNET_STATE_V0, contractsRoot, classesRoot]);
}

export function contractStateHash(classHash: bigint, storageRoot: bigint, nonce: bigint): bigint {
    if (classHash === 0n && storageRoot === 0n && nonce === 0n) return 0n;
    return pedersen(pedersen(pedersen(classHash, storageRoot), nonce), 0n);
}

// ── Cairo storage addresses ────────────────────────────────────────────────
export const snKeccak = (name: string): bigint => BigInt(keccak256(toHex(name))) & MASK_250;
export function mapAddress(base: bigint, keyFelts: bigint[]): bigint {
    let h = base;
    for (const f of keyFelts) h = pedersen(h, f);
    return h % ADDR_BOUND;
}
export const u256Felts = (v: bigint): bigint[] => [v & ((1n << 128n) - 1n), v >> 128n];

/// `StarknetVerifier.Layout` — where a Cairo ClprService keeps the queue state (see the README).
export interface StarknetClprLayout {
    channelsBase: bigint;
    statusOffset: bigint;
    nextMessageIdOffset: bigint;
    receivedMessageIdOffset: bigint;
    sentRunningHashOffset: bigint;
    receivedRunningHashOffset: bigint;
    endpointManifestVersionOffset: bigint;
    messagesBase: bigint;
    messageRunningHashOffset: bigint;
    manifestCommitmentAddress: bigint;
}

/// Layout v0: `clpr_channels: Map<u256, ChannelQueue>` (ChannelQueue = status u8, next_message_id u64,
/// received_message_id u64, sent_running_hash u256, received_running_hash u256,
/// endpoint_manifest_version u64), `clpr_messages: Map<(u256, u64), MessageValue>` (running_hash_after_processing
/// u256 at offset 0), `clpr_endpoint_manifest_commitment: u256`.
export const CLPR_LAYOUT_V0: StarknetClprLayout = {
    channelsBase: snKeccak("clpr_channels"),
    statusOffset: 0n,
    nextMessageIdOffset: 1n,
    receivedMessageIdOffset: 2n,
    sentRunningHashOffset: 3n,
    receivedRunningHashOffset: 5n,
    endpointManifestVersionOffset: 7n,
    messagesBase: snKeccak("clpr_messages"),
    messageRunningHashOffset: 0n,
    manifestCommitmentAddress: snKeccak("clpr_endpoint_manifest_commitment")
};

/// The 8 channel keys in the order the verifier derives them: status, nextMessageId, receivedMessageId,
/// sentRunningHash low/high, receivedRunningHash low/high, endpointManifestVersion.
export function channelKeys(channelId: Hex, L: StarknetClprLayout = CLPR_LAYOUT_V0): bigint[] {
    const b = mapAddress(L.channelsBase, u256Felts(BigInt(channelId)));
    return [L.statusOffset, L.nextMessageIdOffset, L.receivedMessageIdOffset, L.sentRunningHashOffset,
        L.sentRunningHashOffset + 1n, L.receivedRunningHashOffset, L.receivedRunningHashOffset + 1n,
        L.endpointManifestVersionOffset].map((o) => b + o);
}
export function messageKeys(channelId: Hex, messageId: bigint, L: StarknetClprLayout = CLPR_LAYOUT_V0): bigint[] {
    const b = mapAddress(L.messagesBase, [...u256Felts(BigInt(channelId)), messageId]);
    return [b + L.messageRunningHashOffset, b + L.messageRunningHashOffset + 1n];
}
export function manifestKeys(L: StarknetClprLayout = CLPR_LAYOUT_V0): bigint[] {
    return [L.manifestCommitmentAddress, L.manifestCommitmentAddress + 1n];
}

// ── Patricia trie ──────────────────────────────────────────────────────────
export const HEIGHT = 251;
export type TrieNode = {kind: "binary"; left: bigint; right: bigint} | {kind: "edge"; child: bigint; path: bigint; length: number};

export function nodeHash(n: TrieNode): bigint {
    return n.kind === "binary" ? pedersen(n.left, n.right) : mod(pedersen(n.child, n.path) + BigInt(n.length));
}

/// Node from `starknet_getStorageProof` (`{node: {left,right} | {child,path,length}, node_hash}`).
export interface RpcNode {
    node: {left: string; right: string} | {child: string; path: string; length: number};
    node_hash: string;
}
export function fromRpcNode(n: RpcNode): TrieNode {
    const x = n.node as Record<string, string | number>;
    return "left" in x
        ? {kind: "binary", left: BigInt(x.left as string), right: BigInt(x.right as string)}
        : {kind: "edge", child: BigInt(x.child as string), path: BigInt(x.path as string), length: Number(x.length)};
}

/// Walk `key` from `root` through a node set (verifying every node hash); returns the leaf value, 0 for
/// a proven absence. Mirrors `StarknetPatricia.get`.
export function trieGet(nodes: TrieNode[], root: bigint, key: bigint): bigint {
    const byHash = new Map(nodes.map((n) => [nodeHash(n), n]));
    let cur = root;
    let depth = 0;
    while (depth < HEIGHT) {
        if (cur === 0n) return 0n;
        const n = byHash.get(cur);
        if (!n) throw new Error(`missing trie node ${toHex(cur)} at depth ${depth}`);
        if (n.kind === "binary") {
            cur = (key >> BigInt(HEIGHT - 1 - depth)) & 1n ? n.right : n.left;
            depth += 1;
        } else {
            const want = (key >> BigInt(HEIGHT - depth - n.length)) & ((1n << BigInt(n.length)) - 1n);
            if (want !== n.path) return 0n;
            cur = n.child;
            depth += n.length;
        }
    }
    return cur;
}

/// Sparse Patricia trie built from scratch (for synthetic fixtures). Returns the root and every node.
export function buildTrie(entries: Map<bigint, bigint>): {root: bigint; nodes: Map<bigint, TrieNode>} {
    const nodes = new Map<bigint, TrieNode>();
    const keys = [...entries.keys()].filter((k) => entries.get(k) !== 0n).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const bit = (k: bigint, d: number) => (k >> BigInt(HEIGHT - 1 - d)) & 1n;
    const put = (n: TrieNode) => {
        const h = nodeHash(n);
        nodes.set(h, n);
        return h;
    };
    // Hash of the subtree holding `ks` (non-empty) whose top is at depth `d`.
    const build = (ks: bigint[], d: number): bigint => {
        if (d === HEIGHT) return entries.get(ks[0])!;
        // Longest common prefix below depth d.
        let l = 0;
        while (d + l < HEIGHT && ks.every((k) => bit(k, d + l) === bit(ks[0], d + l))) l++;
        if (l > 0) {
            const child = build(ks, d + l);
            const path = (ks[0] >> BigInt(HEIGHT - d - l)) & ((1n << BigInt(l)) - 1n);
            return put({kind: "edge", child, path, length: l});
        }
        const left = ks.filter((k) => bit(k, d) === 0n);
        const right = ks.filter((k) => bit(k, d) === 1n);
        return put({kind: "binary", left: build(left, d + 1), right: build(right, d + 1)});
    };
    return {root: keys.length ? build(keys, 0) : 0n, nodes};
}

/// The nodes a walk for each key touches (deduplicated, in first-visit order).
export function proofNodes(all: Map<bigint, TrieNode>, root: bigint, keys: bigint[]): TrieNode[] {
    const out = new Map<bigint, TrieNode>();
    for (const key of keys) {
        let cur = root;
        let depth = 0;
        while (depth < HEIGHT && cur !== 0n) {
            const n = all.get(cur);
            if (!n) throw new Error("trie node missing");
            out.set(cur, n);
            if (n.kind === "binary") {
                cur = (key >> BigInt(HEIGHT - 1 - depth)) & 1n ? n.right : n.left;
                depth += 1;
            } else {
                const want = (key >> BigInt(HEIGHT - depth - n.length)) & ((1n << BigInt(n.length)) - 1n);
                if (want !== n.path) break;
                cur = n.child;
                depth += n.length;
            }
        }
    }
    return [...out.values()];
}

/// Flat `uint256[]` the contract reads: 3 words per node — binary `[left, right, 0]`, edge
/// `[child, path, length]` (length ≥ 1 tells them apart).
export function flattenNodes(nodes: TrieNode[]): bigint[] {
    return nodes.flatMap((n) => (n.kind === "binary" ? [n.left, n.right, 0n] : [n.child, n.path, BigInt(n.length)]));
}

/// `StarknetStateProver.verifyStorage` proof bytes.
export interface StarknetStorageProofParts {
    contractsTreeRoot: bigint;
    classesTreeRoot: bigint;
    classHash: bigint;
    storageRoot: bigint;
    nonce: bigint;
    contractNodes: TrieNode[];
    storageNodes: TrieNode[];
}
export function encodeStarknetStorageProof(p: StarknetStorageProofParts): Hex {
    return encodeAbiParameters(
        [{type: "uint256"}, {type: "uint256"}, {type: "uint256"}, {type: "uint256"}, {type: "uint256"},
            {type: "uint256[]"}, {type: "uint256[]"}],
        [p.contractsTreeRoot, p.classesTreeRoot, p.classHash, p.storageRoot, p.nonce,
            flattenNodes(p.contractNodes), flattenNodes(p.storageNodes)]
    );
}

/// Off-chain mirror of `StarknetStateProver.verifyStorage`.
export function verifyStarknetStorage(globalRoot: bigint, contract: bigint, keys: bigint[], p: StarknetStorageProofParts): bigint[] {
    if (globalStateRoot(p.contractsTreeRoot, p.classesTreeRoot) !== globalRoot) throw new Error("global root mismatch");
    const leaf = trieGet(p.contractNodes, p.contractsTreeRoot, contract);
    if (leaf === 0n || leaf !== contractStateHash(p.classHash, p.storageRoot, p.nonce)) throw new Error("contract leaf mismatch");
    return keys.map((k) => trieGet(p.storageNodes, p.storageRoot, k));
}

// ── L1 core contract (Starknet.sol + StarkWare Proxy) ──────────────────────
/// keccak256("STARKNET_1.0_INIT_STARKNET_STATE_STRUCT"): StarknetState.State {globalRoot, blockNumber, blockHash}.
export const CORE_STATE_SLOT = BigInt(keccak256(toHex("STARKNET_1.0_INIT_STARKNET_STATE_STRUCT")));
/// keccak256("StarkWare2019.implemntation-slot") (sic) — StarkWare Proxy implementation slot.
export const PROXY_IMPLEMENTATION_SLOT = BigInt(keccak256(toHex("StarkWare2019.implemntation-slot")));
export const PROGRAM_HASH_SLOT = BigInt(keccak256(toHex("STARKNET_1.0_INIT_PROGRAM_HASH_UINT")));
export const AGGREGATOR_PROGRAM_HASH_SLOT = BigInt(keccak256(toHex("STARKNET_1.0_INIT_AGGREGATOR_PROGRAM_HASH_UINT")));
export const VERIFIER_ADDRESS_SLOT = BigInt(keccak256(toHex("STARKNET_1.0_INIT_VERIFIER_ADDRESS")));
export const CONFIG_HASH_SLOT = BigInt(keccak256(toHex("STARKNET_1.0_STARKNET_CONFIG_HASH")));

export const slotHex = (n: bigint): Hex => ("0x" + n.toString(16).padStart(64, "0")) as Hex;

/// Slots the verifier proves on the core contract, in its order: globalRoot, blockNumber,
/// implementation, then the profile's pinned slots.
export function coreSlots(pinnedSlots: bigint[]): Hex[] {
    return [CORE_STATE_SLOT, CORE_STATE_SLOT + 1n, PROXY_IMPLEMENTATION_SLOT, ...pinnedSlots].map(slotHex);
}

export interface EthProof {
    accountProof: string[];
    storageProof: {key: string; value: string; proof: string[]}[];
    codeHash?: string;
    storageHash?: string;
}

/// `StarknetCoreProof` item: RLP [coreAccountProof, coreStorageProof, implAccountProof].
export function coreProofItem(core: EthProof, impl: EthProof, pinnedSlots: bigint[]): unknown[] {
    const byKey = new Map(core.storageProof.map((sp) => [BigInt(sp.key), sp]));
    const entries = coreSlots(pinnedSlots).map((k) => {
        const sp = byKey.get(BigInt(k));
        if (!sp) throw new Error(`missing core storage proof for ${k}`);
        return [hexToBuf(k), sp.proof.map(hexToBuf)];
    });
    return [core.accountProof.map(hexToBuf), entries, impl.accountProof.map(hexToBuf)];
}

/// Bundle: RLP [lightClientProof, coreProof, starknetProof, lastMessageId, bundleContent (, manifestPreimage)].
export function encodeStarknetBundle(p: {
    lightClientProof: Hex;
    coreProof: unknown[];
    starknetProof: Hex;
    lastMessageId?: bigint;
    bundleContent: Hex;
    manifestPreimage?: Hex;
}): Hex {
    const items: unknown[] = [hexToBuf(p.lightClientProof), p.coreProof, hexToBuf(p.starknetProof),
        p.lastMessageId === undefined ? Buffer.alloc(0) : p.lastMessageId, hexToBuf(p.bundleContent)];
    if (p.manifestPreimage !== undefined) items.push(hexToBuf(p.manifestPreimage));
    return toHex(rlpEncode(items as never));
}

/// `verifyStarknetState` input: RLP [lightClientProof, coreProof].
export function encodeStarknetStateProof(p: {lightClientProof: Hex; coreProof: unknown[]}): Hex {
    return toHex(rlpEncode([hexToBuf(p.lightClientProof), p.coreProof] as never));
}

// ── Pedersen comb tables (StarkPedersen) ───────────────────────────────────
export const COMB_TEETH = 8;
export const COMB_COLS = 31; // 8 × 31 = 248 low bits

/// T[u] = Σ_{i ∈ bits(u)} 2^(31·i) · B, u = 1..255 (affine).
export function combTable(base: Point): Point[] {
    const teeth: Point[] = [];
    for (let i = 0; i < COMB_TEETH; i++) teeth.push(ecMul(1n << BigInt(COMB_COLS * i), base));
    const t: Point[] = [null];
    for (let u = 1; u < 1 << COMB_TEETH; u++) {
        const low = u & -u;
        t.push(ecAdd(t[u - low], teeth[Math.log2(low)]));
    }
    return t;
}
/// d · B for d = 0..15.
export function nibbleTable(base: Point): Point[] {
    const t: Point[] = [null];
    for (let d = 1; d < 16; d++) t.push(ecAdd(t[d - 1], base));
    return t;
}
/// Q with 2^31 · Q = shift: the comb accumulator's start, so the 31 doublings land on the shift point.
export function combStart(): Point {
    return ecMul(inv(1n << BigInt(COMB_COLS), EC_ORDER), PEDERSEN_POINTS.shift);
}
