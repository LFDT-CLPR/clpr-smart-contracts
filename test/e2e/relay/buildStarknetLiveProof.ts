import {existsSync, mkdirSync, readdirSync, readFileSync, unlinkSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {keccak256, toHex, type Hex} from "viem";
import {encodeEthTrustAnchor} from "./buildEthMainnetProof.js";
import {
    buildLiveLightClient,
    captureBeaconLive,
    DEFAULT_EXECUTION_RPC,
    rpc,
    type BeaconCapture,
    type LiveLightClient
} from "./buildEthLiveProof.js";
import {
    AGGREGATOR_PROGRAM_HASH_SLOT,
    channelKeys,
    CLPR_LAYOUT_V0,
    CORE_STATE_SLOT,
    coreProofItem,
    coreSlots,
    encodeStarknetBundle,
    encodeStarknetStateProof,
    encodeStarknetStorageProof,
    fromRpcNode,
    manifestKeys,
    PROGRAM_HASH_SLOT,
    PROXY_IMPLEMENTATION_SLOT,
    slotHex,
    snKeccak,
    verifyStarknetStorage,
    type EthProof,
    type RpcNode,
    type StarknetClprLayout,
    type StarknetStorageProofParts
} from "./starknet.js";

/// Live-data proof builder for `StarknetVerifier`: Starknet Sepolia settling on Ethereum Sepolia.
///
/// Chain of real data:
///   Sepolia sync committee (finality_update, bootstrap) → attested execution block B
///   → eth_getProof at B of the Starknet core contract (StarkWare proxy): StarknetState.globalRoot and
///     blockNumber, the implementation slot (+ the implementation's account, code hash pinned) and the
///     programHash / aggregatorProgramHash slots (pinned)
///   → starknet_getStorageProof at exactly that Starknet block: the STRK token's contract leaf and its
///     storage under the global root.
///
/// There is no ClprService on Starknet Sepolia, so the stand-in is the STRK ERC-20 with ITS real class
/// hash pinned: the CLPR channel keys (layout v0) are absent there (real Patricia non-membership proofs
/// → zeroed metadata), and the ERC-20 total supply is proven present through the same prover.
///
/// Timing. Public Starknet RPCs serve storage proofs for the last ~60 blocks only, while the core
/// contract on L1 lags the L2 head by hours. So the capture is two-phase:
///   --stage     poll the L2 head and save a storage proof for every block the core contract will post
///               (predicted from the stride of recent LogStateUpdate events: Sepolia posts every 1,000
///               blocks) into fixtures/starknet-sepolia-live/pending/
///   --refresh   wait until the core contract's blockNumber on L1 is a staged block, then capture the
///               beacon light client data and the L1 proofs at the attested block → capture.json
///
/// CLI:
///   npx tsx test/e2e/relay/buildStarknetLiveProof.ts                          build from the fixture
///   npx tsx test/e2e/relay/buildStarknetLiveProof.ts --stage [--hours H]
///   npx tsx test/e2e/relay/buildStarknetLiveProof.ts --refresh [--wait-nonsigners SECS] [--hours H]

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const STARKNET_FIXTURE_DIR = path.resolve(__dirname, "../fixtures/starknet-sepolia-live");
export const STARKNET_LIVE_FIXTURE = path.join(STARKNET_FIXTURE_DIR, "capture.json");
const PENDING_DIR = path.join(STARKNET_FIXTURE_DIR, "pending");

/// Starknet Sepolia (SN_SEPOLIA) on Ethereum Sepolia. Core contract from the Starknet docs
/// ("Important addresses"); STRK token = the fee token on SN_SEPOLIA.
export const STARKNET_SEPOLIA = {
    chainId: "SN_SEPOLIA",
    core: "0xE2Bb56ee936fd6433DC0F6e7e3b8365C906AA057" as Hex,
    l2Rpcs: ["https://api.cartridge.gg/x/starknet/sepolia", "https://starknet-sepolia-rpc.publicnode.com"],
    strk: 0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938dn
};
export const STARKNET_LIVE_CHANNEL_ID: Hex = keccak256(toHex("clpr/starknet-live/sepolia"));
/// OpenZeppelin Cairo ERC20 component storage: `ERC20_total_supply: u256` (low felt).
export const ERC20_TOTAL_SUPPLY_KEY = snKeccak("ERC20_total_supply");
export const LIVE_PINNED_SLOTS = [PROGRAM_HASH_SLOT, AGGREGATOR_PROGRAM_HASH_SLOT];
/// keccak256("LogStateUpdate(uint256,int256,uint256)").
const LOG_STATE_UPDATE = keccak256(toHex("LogStateUpdate(uint256,int256,uint256)"));

/// Keys staged per block: the live channel's 8 queue keys, the 2 manifest-commitment keys, total supply.
export function liveKeys(L: StarknetClprLayout = CLPR_LAYOUT_V0): bigint[] {
    return [...channelKeys(STARKNET_LIVE_CHANNEL_ID, L), ...manifestKeys(L), ERC20_TOTAL_SUPPLY_KEY];
}

async function l2rpc<T>(method: string, params: unknown): Promise<T> {
    let lastErr: unknown;
    for (const url of STARKNET_SEPOLIA.l2Rpcs) {
        try {
            const res = await fetch(url, {
                method: "POST",
                headers: {"content-type": "application/json"},
                body: JSON.stringify({jsonrpc: "2.0", id: 1, method, params})
            });
            const j = (await res.json()) as {result?: T; error?: {message: string}};
            if (j.error) throw new Error(`${method}: ${j.error.message}`);
            return j.result as T;
        } catch (err) {
            lastErr = err;
        }
    }
    throw lastErr;
}

// ── Capture shapes ─────────────────────────────────────────────────────────
export interface StagedStarknetProof {
    blockNumber: number;
    header: {block_hash: Hex; block_number: number; new_root: Hex; parent_hash: Hex; timestamp: number;
        starknet_version: string};
    contract: Hex;
    keys: Hex[];
    proof: {
        classes_proof: RpcNode[];
        contracts_proof: {nodes: RpcNode[]; contract_leaves_data: {class_hash: Hex; nonce: Hex; storage_root?: Hex}[]};
        contracts_storage_proofs: RpcNode[][];
        global_roots: {block_hash: Hex; classes_tree_root: Hex; contracts_tree_root: Hex};
    };
}

export interface StarknetLiveCapture {
    network: string;
    capturedAt: string;
    sources: {beaconApi: string; l1Rpc: string; l2Rpcs: string[]};
    beacon: BeaconCapture;
    l1: {
        block: {number: string; hash: Hex; stateRoot: Hex; timestamp: string};
        core: Hex;
        implementation: Hex;
        coreProof: EthProof;
        implProof: EthProof;
    };
    starknet: StagedStarknetProof;
}

// ── --stage ────────────────────────────────────────────────────────────────
async function coreBlockNumber(l1Rpc: string, tag: Hex | "latest"): Promise<bigint> {
    const v = await rpc<Hex>(l1Rpc, "eth_getStorageAt", [STARKNET_SEPOLIA.core, slotHex(CORE_STATE_SLOT + 1n), tag]);
    return BigInt(v);
}

/// Starknet blocks the core contract posted recently (from LogStateUpdate), oldest first.
async function recentPostedBlocks(l1Rpc: string): Promise<bigint[]> {
    const head = BigInt(await rpc<Hex>(l1Rpc, "eth_blockNumber", []));
    const logs = await rpc<{data: Hex}[]>(l1Rpc, "eth_getLogs", [{
        address: STARKNET_SEPOLIA.core, topics: [LOG_STATE_UPDATE],
        fromBlock: toHex(head - 5000n), toBlock: toHex(head)
    }]);
    return logs.map((l) => BigInt("0x" + l.data.slice(2 + 64, 2 + 128)));
}

export async function stageStarknetProof(blockNumber: number): Promise<StagedStarknetProof> {
    const keys = liveKeys().map((k) => toHex(k));
    const contract = toHex(STARKNET_SEPOLIA.strk);
    const header = await l2rpc<StagedStarknetProof["header"] & {transactions?: unknown}>(
        "starknet_getBlockWithTxHashes", {block_id: {block_number: blockNumber}});
    delete header.transactions;
    const proof = await l2rpc<StagedStarknetProof["proof"]>("starknet_getStorageProof", {
        block_id: {block_number: blockNumber},
        contract_addresses: [contract],
        contracts_storage_keys: [{contract_address: contract, storage_keys: keys}]
    });
    const staged: StagedStarknetProof = {blockNumber, header, contract, keys, proof};
    starknetParts(staged); // cross-check before saving
    return staged;
}

async function stage(opts: {hours: number; l1Rpc: string}): Promise<void> {
    mkdirSync(PENDING_DIR, {recursive: true});
    const deadline = Date.now() + opts.hours * 3600_000;
    let targets: bigint[] = [];
    while (Date.now() < deadline) {
        try {
            if (targets.length === 0) {
                const posted = await recentPostedBlocks(opts.l1Rpc);
                if (posted.length < 2) throw new Error("not enough recent LogStateUpdate events to learn the stride");
                const stride = posted[posted.length - 1] - posted[posted.length - 2];
                const head = BigInt(await l2rpc<number>("starknet_blockNumber", []));
                let t = posted[posted.length - 1];
                while (t < head - 40n) t += stride;
                targets = [t, t + stride, t + 2n * stride];
                console.error(`stride ${stride}; next targets ${targets.join(", ")}`);
            }
            const head = BigInt(await l2rpc<number>("starknet_blockNumber", []));
            const t = targets[0];
            if (head >= t) {
                targets.shift();
                const out = path.join(PENDING_DIR, `${t}.json`);
                if (!existsSync(out) && head - t < 50n) {
                    writeFileSync(out, JSON.stringify(await stageStarknetProof(Number(t)), null, 1) + "\n");
                    console.error(`staged Starknet block ${t}`);
                } else if (!existsSync(out)) {
                    console.error(`missed ${t} (head ${head})`);
                }
            }
        } catch (err) {
            console.error(`stage: ${String(err).slice(0, 200)}`);
        }
        await new Promise((r) => setTimeout(r, 10_000));
    }
}

function loadPending(): Map<bigint, StagedStarknetProof> {
    const m = new Map<bigint, StagedStarknetProof>();
    if (!existsSync(PENDING_DIR)) return m;
    for (const f of readdirSync(PENDING_DIR).filter((x) => x.endsWith(".json"))) {
        const s = JSON.parse(readFileSync(path.join(PENDING_DIR, f), "utf8")) as StagedStarknetProof;
        m.set(BigInt(s.blockNumber), s);
    }
    return m;
}

// ── --refresh ──────────────────────────────────────────────────────────────
export async function captureStarknetSepoliaLive(opts: {
    l1Rpc?: string;
    waitForNonSignersMs?: number;
    hours?: number;
} = {}): Promise<StarknetLiveCapture> {
    const l1Rpc = opts.l1Rpc ?? DEFAULT_EXECUTION_RPC;
    const deadline = Date.now() + (opts.hours ?? 6) * 3600_000;
    for (;;) {
        const pending = loadPending();
        const posted = await coreBlockNumber(l1Rpc, "latest");
        if (pending.has(posted)) {
            const {beacon, extra} = await captureBeaconLive(opts, async (_execution, B) => {
                const n = await coreBlockNumber(l1Rpc, B);
                const staged = pending.get(n);
                if (!staged) return null; // the core contract moved between head and the attested block
                const coreProof = await rpc<EthProof>(l1Rpc, "eth_getProof",
                    [STARKNET_SEPOLIA.core, coreSlots(LIVE_PINNED_SLOTS), B]);
                const implementation = ("0x" + BigInt(coreProof.storageProof[2].value).toString(16).padStart(40, "0")) as Hex;
                const implProof = await rpc<EthProof>(l1Rpc, "eth_getProof", [implementation, [], B]);
                const block = await rpc<StarknetLiveCapture["l1"]["block"]>(l1Rpc, "eth_getBlockByNumber", [B, false]);
                return {staged, l1: {block: {number: block.number, hash: block.hash, stateRoot: block.stateRoot,
                    timestamp: block.timestamp}, core: STARKNET_SEPOLIA.core, implementation, coreProof, implProof}};
            });
            if (extra) {
                return {
                    network: "starknet-sepolia on " + beacon.network,
                    capturedAt: new Date().toISOString(),
                    sources: {beaconApi: beacon.sources.beaconApi, l1Rpc, l2Rpcs: STARKNET_SEPOLIA.l2Rpcs},
                    beacon: {...beacon, sources: {beaconApi: beacon.sources.beaconApi, executionRpc: l1Rpc}},
                    l1: extra.l1,
                    starknet: extra.staged
                };
            }
            console.error("attested block is not at a staged Starknet block yet; retrying");
        } else {
            console.error(`core contract at Starknet block ${posted}; staged: ${[...pending.keys()].join(", ") || "none"}`);
        }
        if (Date.now() > deadline) throw new Error("timed out waiting for the core contract to reach a staged block");
        await new Promise((r) => setTimeout(r, 30_000));
    }
}

// ── Pure builder ───────────────────────────────────────────────────────────
export function starknetParts(s: StagedStarknetProof): {parts: StarknetStorageProofParts; values: bigint[]} {
    const r = s.proof;
    const ld = r.contracts_proof.contract_leaves_data[0];
    if (!ld.storage_root) throw new Error("RPC returned no storage_root in contract_leaves_data");
    const parts: StarknetStorageProofParts = {
        contractsTreeRoot: BigInt(r.global_roots.contracts_tree_root),
        classesTreeRoot: BigInt(r.global_roots.classes_tree_root),
        classHash: BigInt(ld.class_hash),
        storageRoot: BigInt(ld.storage_root),
        nonce: BigInt(ld.nonce),
        contractNodes: r.contracts_proof.nodes.map(fromRpcNode),
        storageNodes: r.contracts_storage_proofs[0].map(fromRpcNode)
    };
    if (BigInt(r.global_roots.block_hash) !== BigInt(s.header.block_hash)) throw new Error("proof is not for the header's block");
    const values = verifyStarknetStorage(BigInt(s.header.new_root), BigInt(s.contract), s.keys.map(BigInt), parts);
    return {parts, values};
}

export interface StarknetLiveProof {
    lightClient: LiveLightClient;
    trustAnchor: Hex;
    channelId: Hex;
    channelContext: Hex;
    profile: {core: Hex; coreImplCodeHash: Hex; pinnedSlots: Hex[]; pinnedValues: Hex[]};
    layout: StarknetClprLayout;
    globalRoot: bigint;
    starknetBlock: bigint;
    classHash: Hex;
    service: Hex;
    /// `verifyStarknetState` proof: RLP [lightClientProof, coreProof].
    stateProof: Hex;
    /// Full ACK-only `verifyBundle` proof (channel keys only).
    bundle: Hex;
    /// `StarknetStateProver.verifyStorage` inputs for every staged key (incl. the total supply).
    storage: {keys: bigint[]; values: bigint[]; proof: Hex};
    totalSupply: bigint;
}

export function buildStarknetLiveProof(c: StarknetLiveCapture): StarknetLiveProof {
    const lightClient = buildLiveLightClient(c.beacon);
    const attested = c.beacon.finalityUpdate.data.attested_header;
    if (BigInt(c.l1.block.number) !== BigInt(attested.execution.block_number)) throw new Error("L1 block != attested block");
    if (c.l1.block.stateRoot.toLowerCase() !== attested.execution.state_root.toLowerCase()) throw new Error("L1 stateRoot mismatch");

    // Core contract slots: globalRoot, blockNumber, implementation, pinned.
    const v = c.l1.coreProof.storageProof.map((sp) => BigInt(sp.value));
    const globalRoot = v[0];
    const starknetBlock = v[1];
    if (starknetBlock !== BigInt(c.starknet.blockNumber)) throw new Error("core blockNumber != staged block");
    if (globalRoot !== BigInt(c.starknet.header.new_root)) throw new Error("core globalRoot != staged block's new_root");
    if (BigInt(c.l1.coreProof.storageProof[2].key) !== PROXY_IMPLEMENTATION_SLOT) throw new Error("slot order");
    const {parts, values} = starknetParts(c.starknet);

    // The staged node set covers every staged key; the verifier walks only the channel keys.
    const channelOnly: StarknetStorageProofParts = parts;
    const classHash = toHex(parts.classHash, {size: 32});
    const service = toHex(STARKNET_SEPOLIA.strk, {size: 32});
    const trustAnchor = encodeEthTrustAnchor(STARKNET_LIVE_CHANNEL_ID, classHash, lightClient.committee, {
        gvr: c.beacon.genesisValidatorsRoot as Hex, forkVersion: lightClient.signed.forkVersion
    });
    const coreProof = coreProofItem(c.l1.coreProof, c.l1.implProof, LIVE_PINNED_SLOTS);
    const starknetProof = encodeStarknetStorageProof(channelOnly);
    return {
        lightClient,
        trustAnchor,
        channelId: STARKNET_LIVE_CHANNEL_ID,
        channelContext: (STARKNET_LIVE_CHANNEL_ID + service.slice(2)) as Hex,
        profile: {
            core: c.l1.core,
            coreImplCodeHash: c.l1.implProof.codeHash as Hex,
            pinnedSlots: LIVE_PINNED_SLOTS.map(slotHex),
            pinnedValues: c.l1.coreProof.storageProof.slice(3).map((sp) => slotHex(BigInt(sp.value)))
        },
        layout: CLPR_LAYOUT_V0,
        globalRoot,
        starknetBlock,
        classHash,
        service,
        stateProof: encodeStarknetStateProof({lightClientProof: lightClient.lightClientProof, coreProof}),
        bundle: encodeStarknetBundle({lightClientProof: lightClient.lightClientProof, coreProof, starknetProof,
            bundleContent: "0x"}),
        storage: {keys: c.starknet.keys.map(BigInt), values, proof: starknetProof},
        totalSupply: values[values.length - 1]
    };
}

export function loadStarknetLiveCapture(file = STARKNET_LIVE_FIXTURE): StarknetLiveCapture {
    return JSON.parse(readFileSync(file, "utf8")) as StarknetLiveCapture;
}

function summarize(p: StarknetLiveProof, c: StarknetLiveCapture): string {
    return [
        `L1 block ${BigInt(c.l1.block.number)} (slot ${c.beacon.finalityUpdate.data.attested_header.beacon.slot}), ` +
            `participation ${p.lightClient.signed.participants}/512`,
        `core ${p.profile.core} impl ${c.l1.implementation} codeHash ${p.profile.coreImplCodeHash}`,
        `Starknet block ${p.starknetBlock} (${c.starknet.header.starknet_version}), global root ${toHex(p.globalRoot)}`,
        `STRK class ${p.classHash}, total supply ${p.totalSupply}`,
        `bundle ${(p.bundle.length - 2) / 2} B, storage proof ${c.starknet.proof.contracts_proof.nodes.length} contract + ` +
            `${c.starknet.proof.contracts_storage_proofs[0].length} storage nodes`
    ].join("\n");
}

async function main(): Promise<void> {
    const args = process.argv.slice(2);
    const arg = (name: string) => {
        const i = args.indexOf(name);
        return i >= 0 ? args[i + 1] : undefined;
    };
    const hours = Number(arg("--hours") ?? 6);
    if (args.includes("--stage")) {
        await stage({hours, l1Rpc: DEFAULT_EXECUTION_RPC});
        return;
    }
    let capture: StarknetLiveCapture;
    if (args.includes("--refresh")) {
        capture = await captureStarknetSepoliaLive({
            hours,
            waitForNonSignersMs: Number(arg("--wait-nonsigners") ?? 0) * 1000
        });
        buildStarknetLiveProof(capture); // validate before writing
        writeFileSync(STARKNET_LIVE_FIXTURE, JSON.stringify(capture, null, 1) + "\n");
        // Prune stages at or below the captured block (the staged proof is now inside capture.json).
        for (const [n] of loadPending()) {
            if (n <= BigInt(capture.starknet.blockNumber)) unlinkSync(path.join(PENDING_DIR, `${n}.json`));
        }
        console.log(`captured → ${path.relative(process.cwd(), STARKNET_LIVE_FIXTURE)}`);
    } else {
        capture = loadStarknetLiveCapture();
    }
    console.log(summarize(buildStarknetLiveProof(capture), capture));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    main().catch((err) => {
        console.error(err);
        process.exit(1);
    });
}
