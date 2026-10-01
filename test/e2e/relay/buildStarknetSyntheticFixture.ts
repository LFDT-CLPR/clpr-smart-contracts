import {spawn, type ChildProcess} from "node:child_process";
import {mkdirSync, readFileSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {keccak256, toHex, type Hex} from "viem";
import {rlpEncode} from "../lib/rlp.js";
import {
    AGGREGATOR_PROGRAM_HASH_SLOT,
    buildTrie,
    channelKeys,
    CLPR_LAYOUT_V0,
    CORE_STATE_SLOT,
    contractStateHash,
    coreProofItem,
    coreSlots,
    encodeStarknetStorageProof,
    fromRpcNode,
    globalStateRoot,
    manifestKeys,
    messageKeys,
    P,
    pedersen,
    poseidonHashMany,
    PROGRAM_HASH_SLOT,
    PROXY_IMPLEMENTATION_SLOT,
    proofNodes,
    slotHex,
    u256Felts,
    verifyStarknetStorage,
    type EthProof,
    type RpcNode,
    type StarknetStorageProofParts,
    type TrieNode
} from "./starknet.js";

/// Fixture for the Foundry `StarknetVerifier` / `StarknetStateProver` tests.
///
/// - `vectors`: Pedersen / Poseidon test vectors computed by the reference code in starknet.ts.
/// - `live`: one REAL Starknet Sepolia `starknet_getStorageProof` (STRK token, total supply + absent keys,
///   fixtures/sepolia-storage-proof-15900215.json) — the prover must accept it as is.
/// - `starknet`: a synthetic Starknet state holding a Cairo ClprService in CLPR layout v0, built with
///   the reference trie code. To make the gas realistic the paths are dense: the contract trie path has
///   a binary node at each of the top 24 levels (Sepolia's is ~23) and every queue key one at each of the
///   top 22 levels (a service with ~4M storage slots).
/// - `l1`: a throw-away anvil holding a Starknet core contract (proxy + implementation) whose state
///   struct holds that global root; every MPT proof comes from anvil's eth_getProof.
///
/// Run: npx tsx test/e2e/relay/buildStarknetSyntheticFixture.ts

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const STARKNET_SYNTHETIC_FIXTURE = path.resolve(__dirname, "../../verifiers/evm/starknet/fixtures/synthetic.json");
/// A raw `starknet_getStorageProof` (+ header) from Starknet Sepolia block 15900215: STRK token, total
/// supply and two absent keys.
const LIVE_SAMPLE = path.resolve(__dirname, "../../verifiers/evm/starknet/fixtures/sepolia-storage-proof-15900215.json");

const CHANNEL_ID: Hex = keccak256(toHex("clpr/starknet/synthetic"));
const OTHER_CHANNEL_ID: Hex = keccak256(toHex("clpr/starknet/synthetic/other"));
const SERVICE = 0x05e7c1ce1acce5e7c1ce1acce5e7c1ce1acce5e7c1ce1acce5e7c1ce1acce5en;
const CLASS_HASH = 0x01a55c1a55c11a55c1a55c1a55c1a55c1a55c1a55c1a55c1a55c1a55c1a55c1an;
const CLASSES_ROOT = 0x01c1a55e5000000000000000000000000000000000000000000000000000c1a5n;
const STARKNET_BLOCK = 1_234_567n;

const CORE: Hex = "0xc0de000000000000000000000000000000000001";
const CORE_UNINIT: Hex = "0xc0de000000000000000000000000000000000002";
const CORE_IMPL: Hex = "0xc0de000000000000000000000000000000001111";
const CORE_IMPL_CODE: Hex = "0x6080604052348015600f57600080fd5b50"; // stand-in runtime
const PROGRAM_HASH = 0x01e9f4d0bc1e9b5a2f5c1b7f3a7c1d2e9f00aa11bb22cc33dd44ee55ff660011n;
const AGG_PROGRAM_HASH = 0x02aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff001122n;
export const PINNED_SLOTS = [PROGRAM_HASH_SLOT, AGGREGATOR_PROGRAM_HASH_SLOT];

const word = (v: bigint): Hex => slotHex(v);
const hexOf = (parts: unknown): Hex => ("0x" + rlpEncode(parts as never).toString("hex")) as Hex;

/// Deterministic felt stream.
function felts(seed: string): () => bigint {
    let i = 0;
    return () => BigInt(keccak256(toHex(`${seed}/${i++}`))) % P;
}

/// Siblings that force a binary node at each of the top `depth` levels of `key`'s path.
function denseNeighbours(key: bigint, depth: number): bigint[] {
    return Array.from({length: depth}, (_, i) => key ^ (1n << BigInt(250 - i)));
}

interface QueueState {
    status: bigint;
    nextMessageId: bigint;
    receivedMessageId: bigint;
    sentRunningHash: Hex;
    receivedRunningHash: Hex;
    endpointManifestVersion: bigint;
    lastMessageRunningHash: Hex;
}

function manifestProtobuf(version: bigint, service: bigint): Hex {
    // ClprEndpointManifest{version (1, varint), service_address (2, bytes32)}, no endpoints.
    return ("0x08" + version.toString(16).padStart(2, "0") + "1220" + service.toString(16).padStart(64, "0")) as Hex;
}

function serviceStorage(q: QueueState, manifest: Hex): Map<bigint, bigint> {
    const s = new Map<bigint, bigint>();
    const ch = channelKeys(CHANNEL_ID);
    const [sentLo, sentHi] = u256Felts(BigInt(q.sentRunningHash));
    const [recvLo, recvHi] = u256Felts(BigInt(q.receivedRunningHash));
    [q.status, q.nextMessageId, q.receivedMessageId, sentLo, sentHi, recvLo, recvHi, q.endpointManifestVersion]
        .forEach((v, i) => s.set(ch[i], v));
    const msg = messageKeys(CHANNEL_ID, q.nextMessageId - 1n);
    const [mLo, mHi] = u256Felts(BigInt(q.lastMessageRunningHash));
    s.set(msg[0], mLo);
    s.set(msg[1], mHi);
    const man = manifestKeys();
    const [cLo, cHi] = u256Felts(BigInt(keccak256(manifest)));
    s.set(man[0], cLo);
    s.set(man[1], cHi);
    // Another channel and dense neighbours around every queue key.
    const other = channelKeys(OTHER_CHANNEL_ID);
    other.forEach((k, i) => s.set(k, BigInt(i + 1)));
    const rnd = felts("storage-noise");
    for (const k of [...ch, ...msg, ...man]) for (const n of denseNeighbours(k, 22)) if (!s.has(n)) s.set(n, rnd() || 1n);
    return s;
}

function starknetState(q: QueueState, manifest: Hex) {
    const storage = buildTrie(serviceStorage(q, manifest));
    const leaf = contractStateHash(CLASS_HASH, storage.root, 0n);
    const contracts = new Map<bigint, bigint>([[SERVICE, leaf]]);
    const rnd = felts("contract-noise");
    for (const n of denseNeighbours(SERVICE, 24)) contracts.set(n, rnd() || 1n);
    const contractTrie = buildTrie(contracts);
    const globalRoot = globalStateRoot(contractTrie.root, CLASSES_ROOT);
    const proofFor = (keys: bigint[]): StarknetStorageProofParts => ({
        contractsTreeRoot: contractTrie.root,
        classesTreeRoot: CLASSES_ROOT,
        classHash: CLASS_HASH,
        storageRoot: storage.root,
        nonce: 0n,
        contractNodes: proofNodes(contractTrie.nodes, contractTrie.root, [SERVICE]),
        storageNodes: proofNodes(storage.nodes, storage.root, keys)
    });
    return {globalRoot, storageRoot: storage.root, contractsRoot: contractTrie.root, proofFor};
}

// ── anvil plumbing ─────────────────────────────────────────────────────────
async function startAnvil(port: number): Promise<{proc: ChildProcess; url: string}> {
    const proc = spawn("anvil", ["--port", String(port), "--silent"], {stdio: "ignore"});
    const url = `http://127.0.0.1:${port}`;
    const deadline = Date.now() + 15_000;
    for (;;) {
        try {
            await rpc(url, "eth_chainId", []);
            return {proc, url};
        } catch (err) {
            if (Date.now() > deadline) throw err;
            await new Promise((r) => setTimeout(r, 200));
        }
    }
}

let rpcId = 0;
async function rpc<T>(url: string, method: string, params: unknown[]): Promise<T> {
    const res = await fetch(url, {
        method: "POST",
        headers: {"content-type": "application/json"},
        body: JSON.stringify({jsonrpc: "2.0", id: ++rpcId, method, params})
    });
    const j = (await res.json()) as {result?: T; error?: {message: string}};
    if (j.error) throw new Error(`${method}: ${j.error.message}`);
    return j.result as T;
}

function liveSample() {
    const d = JSON.parse(readFileSync(LIVE_SAMPLE, "utf8"));
    const r = d.proof;
    const ld = r.contracts_proof.contract_leaves_data[0];
    const parts: StarknetStorageProofParts = {
        contractsTreeRoot: BigInt(r.global_roots.contracts_tree_root),
        classesTreeRoot: BigInt(r.global_roots.classes_tree_root),
        classHash: BigInt(ld.class_hash),
        storageRoot: BigInt(ld.storage_root),
        nonce: BigInt(ld.nonce),
        contractNodes: (r.contracts_proof.nodes as RpcNode[]).map(fromRpcNode),
        storageNodes: (r.contracts_storage_proofs[0] as RpcNode[]).map(fromRpcNode)
    };
    const keys = (d.keys as string[]).map(BigInt);
    const values = verifyStarknetStorage(BigInt(d.header.new_root), BigInt(d.contract), keys, parts);
    return {
        blockNumber: d.blockNumber,
        globalRoot: word(BigInt(d.header.new_root)),
        contract: word(BigInt(d.contract)),
        classHash: word(parts.classHash),
        keys: keys.map(word),
        values: values.map(word),
        proof: encodeStarknetStorageProof(parts),
        contractNodes: parts.contractNodes.length,
        storageNodes: parts.storageNodes.length
    };
}

export async function buildStarknetSyntheticFixture(port = 8613) {
    // ── vectors ──
    const pairs: [bigint, bigint][] = [
        [0n, 0n], [1n, 2n], [P - 1n, P - 1n], [1n << 248n, 1n << 250n], [(1n << 248n) - 1n, 8n << 248n],
        [0x3d937c035c878245caf64531a5756109c53068da139362728feb561405371cbn,
            0x208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31an]
    ];
    const rv = felts("pedersen-vectors");
    for (let i = 0; i < 6; i++) pairs.push([rv(), rv()]);
    const pedersenVectors = pairs.map(([a, b]) => ({a: word(a), b: word(b), h: word(pedersen(a, b))}));
    const poseidonInputs: bigint[][] = [[], [1n], [1n, 2n], [P - 1n, 0n, 7n], [rv(), rv(), rv(), rv(), rv()]];
    const poseidonVectors = poseidonInputs.map((xs) => ({xs: xs.map(word), h: word(poseidonHashMany(xs))}));

    // ── synthetic Starknet state (current) and a stale one (one message earlier) ──
    const manifest = manifestProtobuf(2n, SERVICE);
    const q: QueueState = {
        status: 1n,
        nextMessageId: 5n,
        receivedMessageId: 3n,
        sentRunningHash: keccak256(toHex("sent-running-hash")),
        receivedRunningHash: keccak256(toHex("received-running-hash")),
        endpointManifestVersion: 2n,
        lastMessageRunningHash: keccak256(toHex("message-4"))
    };
    const cur = starknetState(q, manifest);
    const stale = starknetState({...q, nextMessageId: 4n, lastMessageRunningHash: keccak256(toHex("message-3"))}, manifest);

    const ch = channelKeys(CHANNEL_ID);
    const msg = messageKeys(CHANNEL_ID, q.nextMessageId - 1n);
    const man = manifestKeys();
    const enc = (p: StarknetStorageProofParts) => encodeStarknetStorageProof(p);
    const proofs = {
        channel: cur.proofFor(ch),
        channelMessage: cur.proofFor([...ch, ...msg]),
        full: cur.proofFor([...ch, ...msg, ...man]),
        manifestOnly: cur.proofFor(man),
        staleChannel: stale.proofFor(ch)
    };
    // Sanity: the reference verifier reads back what was written.
    const got = verifyStarknetStorage(cur.globalRoot, SERVICE, [...ch, ...msg, ...man], proofs.full);
    if (got[1] !== q.nextMessageId || got[7] !== q.endpointManifestVersion) throw new Error("synthetic state mismatch");

    // ── L1: the core contract on anvil ──
    const l1 = await startAnvil(port);
    try {
        const set = (a: Hex, slot: bigint, v: bigint) => rpc(l1.url, "anvil_setStorageAt", [a, slotHex(slot), word(v)]);
        await rpc(l1.url, "anvil_setCode", [CORE, "0x6080"]);
        await rpc(l1.url, "anvil_setCode", [CORE_UNINIT, "0x6080"]);
        await rpc(l1.url, "anvil_setCode", [CORE_IMPL, CORE_IMPL_CODE]);
        for (const core of [CORE, CORE_UNINIT]) {
            await set(core, CORE_STATE_SLOT, cur.globalRoot);
            await set(core, CORE_STATE_SLOT + 1n, core === CORE ? STARKNET_BLOCK : (1n << 256n) - 1n); // -1: uninitialized
            await set(core, CORE_STATE_SLOT + 2n, 0xb10cn);
            await set(core, PROXY_IMPLEMENTATION_SLOT, BigInt(CORE_IMPL));
            await set(core, PROGRAM_HASH_SLOT, PROGRAM_HASH);
            await set(core, AGGREGATOR_PROGRAM_HASH_SLOT, AGG_PROGRAM_HASH);
        }
        await rpc(l1.url, "evm_mine", []);
        const block = await rpc<{stateRoot: Hex; number: Hex}>(l1.url, "eth_getBlockByNumber", ["latest", false]);
        const slots = coreSlots(PINNED_SLOTS);
        const coreProof = await rpc<EthProof>(l1.url, "eth_getProof", [CORE, slots, "latest"]);
        const uninitProof = await rpc<EthProof>(l1.url, "eth_getProof", [CORE_UNINIT, slots, "latest"]);
        const implProof = await rpc<EthProof>(l1.url, "eth_getProof", [CORE_IMPL, [], "latest"]);

        return {
            description: "Synthetic Starknet + L1 state for StarknetVerifier unit tests. Regenerate with "
                + "`npx tsx test/e2e/relay/buildStarknetSyntheticFixture.ts`.",
            vectors: {pedersen: pedersenVectors, poseidon: poseidonVectors},
            live: liveSample(),
            l1: {
                stateRoot: block.stateRoot,
                core: CORE,
                coreUninitialized: CORE_UNINIT,
                coreImplementation: CORE_IMPL,
                coreImplCodeHash: implProof.codeHash,
                pinnedSlots: PINNED_SLOTS.map(word),
                pinnedValues: [word(PROGRAM_HASH), word(AGG_PROGRAM_HASH)],
                coreProof: hexOf(coreProofItem(coreProof, implProof, PINNED_SLOTS)),
                coreProofUninitialized: hexOf(coreProofItem(uninitProof, implProof, PINNED_SLOTS)),
                coreProofNoPins: hexOf(coreProofItem(coreProof, implProof, []))
            },
            starknet: {
                blockNumber: STARKNET_BLOCK.toString(),
                globalRoot: word(cur.globalRoot),
                contractsRoot: word(cur.contractsRoot),
                classesRoot: word(CLASSES_ROOT),
                service: word(SERVICE),
                classHash: word(CLASS_HASH),
                channelId: CHANNEL_ID,
                otherChannelId: OTHER_CHANNEL_ID,
                manifest,
                layout: {
                    channelsBase: word(CLPR_LAYOUT_V0.channelsBase),
                    messagesBase: word(CLPR_LAYOUT_V0.messagesBase),
                    manifestCommitmentAddress: word(CLPR_LAYOUT_V0.manifestCommitmentAddress)
                },
                keys: {channel: ch.map(word), message: msg.map(word), manifest: man.map(word)},
                proofs: Object.fromEntries(Object.entries(proofs).map(([k, v]) => [k, enc(v)])),
                proofNodeCounts: Object.fromEntries(Object.entries(proofs).map(([k, v]: [string, StarknetStorageProofParts]) =>
                    [k, {contract: v.contractNodes.length, storage: v.storageNodes.length}])),
                expected: {
                    status: Number(q.status),
                    nextMessageId: q.nextMessageId.toString(),
                    receivedMessageId: q.receivedMessageId.toString(),
                    sentRunningHash: q.sentRunningHash,
                    receivedRunningHash: q.receivedRunningHash,
                    endpointManifestVersion: q.endpointManifestVersion.toString(),
                    lastMessageId: (q.nextMessageId - 1n).toString()
                }
            }
        };
    } finally {
        l1.proc.kill("SIGTERM");
    }
}

export type StarknetNodes = TrieNode[];

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    buildStarknetSyntheticFixture(Number(process.env.CLPR_ANVIL_PORT_A ?? 8613)).then((f) => {
        mkdirSync(path.dirname(STARKNET_SYNTHETIC_FIXTURE), {recursive: true});
        writeFileSync(STARKNET_SYNTHETIC_FIXTURE, JSON.stringify(f, null, 1) + "\n");
        console.log(`wrote ${path.relative(process.cwd(), STARKNET_SYNTHETIC_FIXTURE)}`, f.starknet.proofNodeCounts);
    }).catch((err) => {
        console.error(err);
        process.exit(1);
    });
}
