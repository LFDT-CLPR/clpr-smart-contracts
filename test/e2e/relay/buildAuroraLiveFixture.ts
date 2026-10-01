import {createHash} from "node:crypto";
import {readFileSync, writeFileSync, mkdirSync} from "node:fs";
import {dirname, resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {encodeAbiParameters, type Hex} from "viem";
import {
    buildLightClientPart,
    captureLightClient,
    hex,
    trieProve,
    viewStateProof,
    type NearLightClientCapture,
} from "./buildNearLiveFixture.js";

/// Aurora live fixture: capture (`--refresh`) and proof building for AuroraVerifier.
///
/// aurora-engine keeps every EVM account's storage in the NEAR contract data of the engine account.
/// The public NEAR RPCs refuse `view_state` on the main engine account `aurora` (its state exceeds
/// the RPC's `trie_viewer_state_size_limit`: TOO_LARGE_CONTRACT_STATE), so the live fixture reads an
/// Aurora Cloud silo: a separate NEAR mainnet account running the same aurora-engine (global contract
/// `global.c.aurora`), with the same storage layout and its own EIP-155 chain id.
///
/// Capture, from NEAR mainnet: the light-client block of the final head and its epoch data (as for
/// NearVerifier), then `view_state` proofs (`include_proof`) at the light-client block's parent of:
///  - the engine state `0x07 0x00 "STATE"` (shard binding + chain id);
///  - the generation `0x07 0x07 ‖ address` of the ERC-20 below (present: generation 1);
///  - six storage slots of that ERC-20 under generation 1: four set, two never written (absent);
///  - the generation and slot 0 of an EOA (both absent: generation 0, 54-byte storage key).
///
/// Run: npx tsx test/e2e/relay/buildAuroraLiveFixture.ts --refresh

const HERE = dirname(fileURLToPath(import.meta.url));
export const AURORA_FIXTURE_DIR = resolve(HERE, "../fixtures/aurora-live");

export const AURORA_TARGET = {
    rpc: "https://rpc.mainnet.near.org",
    engine: "0x4e45415c.c.aurora",
    evmChainId: 0x4e45415cn, // 1313161564
    // wNEAR on the silo (bridged NEP-141 `wrap.near`, mapping key 0x07 0x08 "wrap.near" in the engine)
    token: "0xc42c30ac6cc15fac9bd938618bcaa1a1fae8501d" as Hex,
    tokenSlots: [2n, 3n, 4n, 9n, 0n, 6n], // totalSupply, name, symbol, decimals, two unused slots
    eoa: "0x7a16a4b65e88553b74ca9ceaaff11d947296c797" as Hex,
};

const sha256 = (b: Uint8Array): Buffer => createHash("sha256").update(b).digest();
const word = (n: bigint): Buffer => Buffer.from(n.toString(16).padStart(64, "0"), "hex");
const addr = (a: Hex): Buffer => Buffer.from(a.slice(2), "hex");
const le32 = (v: number): Buffer => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(v);
    return b;
};

/// aurora-engine `storage_to_key` / `address_to_key` (engine-types/src/storage.rs).
export const engineStateKey = (): Buffer => Buffer.concat([Buffer.from([7, 0]), Buffer.from("STATE")]);
export const generationKey = (a: Hex): Buffer => Buffer.concat([Buffer.from([7, 7]), addr(a)]);
export const storageKey = (a: Hex, gen: number, slot: bigint): Buffer =>
    gen === 0
        ? Buffer.concat([Buffer.from([7, 4]), addr(a), word(slot)])
        : Buffer.concat([Buffer.from([7, 4]), addr(a), le32(gen), word(slot)]);
const trieKey = (engine: string, k: Buffer) => Buffer.concat([Buffer.from([9]), Buffer.from(engine), Buffer.from(","), k]);

interface ViewState {
    key: string; // hex engine key
    block_hash: string;
    proof: string[];
    values: {key: string; value: string}[];
}

export interface AuroraCapture extends NearLightClientCapture {
    network: string;
    capturedAt: string;
    rpc: string;
    engine: string;
    views: ViewState[];
}

export async function captureAurora(): Promise<AuroraCapture> {
    const t = AURORA_TARGET;
    const lcc = await captureLightClient(t.rpc);
    const keys = [
        engineStateKey(),
        generationKey(t.token),
        generationKey(t.eoa),
        storageKey(t.eoa, 0, 0n),
    ];
    // the token's generation is read from the chain, then its slots under that generation
    const views: ViewState[] = [];
    for (const k of keys) views.push({key: hex(k), ...(await viewStateProof(t.rpc, lcc.lc, t.engine, k))});
    const g = views[1].values[0];
    const gen = g ? Buffer.from(g.value, "base64").readUInt32BE(0) : 0;
    for (const s of t.tokenSlots) {
        const k = storageKey(t.token, gen, s);
        views.push({key: hex(k), ...(await viewStateProof(t.rpc, lcc.lc, t.engine, k))});
    }
    return {network: "mainnet", capturedAt: new Date().toISOString(), rpc: t.rpc, engine: t.engine, ...lcc, views};
}

// ── proof building ──────────────────────────────────────────────────────────

const BLOCK_T = {
    type: "tuple[]",
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

export const STORAGE_PROOF_ABI = [
    {
        type: "tuple",
        components: [
            {name: "blocks", ...BLOCK_T},
            {
                name: "shards",
                type: "tuple",
                components: [
                    {name: "roots", type: "bytes32[]"},
                    {name: "index", type: "uint256"},
                ],
            },
            {
                name: "engine",
                type: "tuple",
                components: [
                    {name: "stateNodes", type: "bytes[]"},
                    {name: "state", type: "bytes"},
                    {name: "generationNodes", type: "bytes[]"},
                    {name: "generation", type: "uint32"},
                ],
            },
            {name: "account", type: "address"},
            {name: "slots", type: "bytes32[]"},
            {
                name: "proofs",
                type: "tuple[]",
                components: [
                    {name: "nodes", type: "bytes[]"},
                    {name: "value", type: "bytes32"},
                ],
            },
        ],
    },
] as const;

export function buildAuroraLiveProof(c: AuroraCapture) {
    const t = AURORA_TARGET;
    const lcp = buildLightClientPart(c);
    const views = new Map(c.views.map((v) => [v.key, v]));

    // every view must share one shard root among the light-client block's chunk roots
    let shardIndex = -1;
    const prove = (k: Buffer) => {
        const v = views.get(hex(k));
        if (!v) throw new Error(`no view for ${hex(k)}`);
        const proof = v.proof.map((p) => Buffer.from(p, "base64"));
        const rootSet = new Set(proof.map((p) => sha256(p).toString("hex")));
        const idx = lcp.roots.findIndex((r) => rootSet.has(r.toString("hex")));
        if (idx < 0) throw new Error("no shard root matches the view_state proof");
        if (shardIndex >= 0 && idx !== shardIndex) throw new Error("views from different shards");
        shardIndex = idx;
        const r = trieProve(lcp.roots[idx], trieKey(c.engine, k), proof, v.values.map((x) => Buffer.from(x.value, "base64")));
        // the RPC's values must agree with the proof
        const served = v.values.find((x) => Buffer.from(x.key, "base64").equals(k));
        if (Boolean(served) !== Boolean(r.value)) throw new Error("view_state values disagree with the proof");
        return r;
    };

    const state = prove(engineStateKey());
    if (!state.value) throw new Error("engine state absent");
    const chainId = BigInt(hex(state.value.subarray(1, 33)));
    if (state.value[0] > 2 || chainId !== t.evmChainId) throw new Error(`engine chain id ${chainId}`);

    const engineFor = (a: Hex) => {
        const g = prove(generationKey(a));
        return {
            stateNodes: state.nodes.map(hex),
            state: hex(state.value!),
            generationNodes: g.nodes.map(hex),
            generation: g.value ? g.value.readUInt32BE(0) : 0,
        };
    };
    const tokenEngine = engineFor(t.token);
    const eoaEngine = engineFor(t.eoa);
    if (eoaEngine.generation !== 0) throw new Error("EOA has a generation");

    const slotProofs = (a: Hex, gen: number, slots: bigint[]) =>
        slots.map((s) => {
            const r = prove(storageKey(a, gen, s));
            if (r.value && r.value.length !== 32) throw new Error("storage value is not a word");
            return {nodes: r.nodes.map(hex), value: (r.value ? hex(r.value) : "0x" + "00".repeat(32)) as Hex};
        });
    const tokenProofs = slotProofs(t.token, tokenEngine.generation, t.tokenSlots);
    const eoaProofs = slotProofs(t.eoa, 0, [0n]);

    const shards = {roots: lcp.roots.map(hex), index: BigInt(shardIndex)};
    const encode = (block: unknown, engine: unknown, account: Hex, slots: bigint[], proofs: unknown[]) =>
        encodeAbiParameters(STORAGE_PROOF_ABI as never, [
            {blocks: [block], shards, engine, account, slots: slots.map((s) => hex(word(s))), proofs},
        ] as never);

    return {
        chainId: `eip155:${t.evmChainId}`,
        evmChainId: t.evmChainId.toString(),
        engineAccount: c.engine,
        anchorPrev: hex(lcp.anchorPrev),
        anchorCur: hex(lcp.anchorCur),
        checkpointPrev: [hex(lcp.anchorPrev.subarray(0, 32)), hex(lcp.anchorPrev.subarray(32, 64)), hex(lcp.bpPrev), hex(lcp.bpCur)],
        message: hex(lcp.msg),
        signerKeys: lcp.chosen.map((i) => keyOf(c, i)),
        signerSignatures: lcp.chosen.map((i) => hex(lcp.sigOf(i))),
        token: t.token,
        tokenSlots: t.tokenSlots.map((s) => hex(word(s))),
        tokenValues: tokenProofs.map((p) => p.value),
        tokenGeneration: tokenEngine.generation,
        storageProof: encode(lcp.block, tokenEngine, t.token, t.tokenSlots, tokenProofs),
        storageProofCached: encode(lcp.blockCached, tokenEngine, t.token, t.tokenSlots, tokenProofs),
        eoa: t.eoa,
        eoaProofCached: encode(lcp.blockCached, eoaEngine, t.eoa, [0n], eoaProofs),
        lcHash: hex(lcp.bh),
        height: c.lc.inner_lite.height,
        meta: {
            producers: c.producersCur.length,
            signedProducers: lcp.signedCount,
            chosenSigners: lcp.chosen.length,
            shards: lcp.roots.length,
            shardIndex,
            stateDepth: state.nodes.length,
            slotDepths: tokenProofs.map((p) => p.nodes.length),
            absentSlots: tokenProofs.filter((p) => /^0x0+$/.test(p.value)).length,
        },
    };
}

function keyOf(c: AuroraCapture, i: number): Hex {
    const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let n = 0n;
    for (const ch of c.producersCur[i].public_key.replace(/^ed25519:/, "")) n = n * 58n + BigInt(B58.indexOf(ch));
    return ("0x" + n.toString(16).padStart(64, "0")) as Hex;
}

export function loadAuroraCapture(): AuroraCapture {
    return JSON.parse(readFileSync(resolve(AURORA_FIXTURE_DIR, "mainnet.json"), "utf8")).capture;
}

export function writeAuroraFixture(c: AuroraCapture) {
    const derived = buildAuroraLiveProof(c);
    mkdirSync(AURORA_FIXTURE_DIR, {recursive: true});
    writeFileSync(resolve(AURORA_FIXTURE_DIR, "mainnet.json"), JSON.stringify({derived, capture: c}, null, 1) + "\n");
    return derived;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    const c = process.argv.includes("--refresh") ? await captureAurora() : loadAuroraCapture();
    const d = writeAuroraFixture(c);
    console.log(`[aurora-live] ${c.engine} @ NEAR height ${d.height}: ${JSON.stringify(d.meta)}`);
}
