import {mkdirSync, readFileSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {encodeFunctionData, keccak256, toHex, type Hex} from "viem";
import {deriveChannelSlots, encodeEthTrustAnchor, type EthGetProofResult} from "./buildEthMainnetProof.js";
import {
    buildLiveLightClient,
    buildLiveRotationLightClient,
    captureBeaconLive,
    rpc,
    type BeaconCapture,
    type LiveLightClient,
    type LiveRotationLightClient
} from "./buildEthLiveProof.js";
import {
    encodeL1RollupBundle,
    encodeL2StateRootProof,
    EIP1967_IMPLEMENTATION_SLOT,
    PROFILES,
    rollupProofItem,
    stateRootSlot,
    storageEntries,
    type L1RollupProfile
} from "./zkrollup.js";
import {lineaAccountProof, lineaStorageProof, type LineaGetProofResult, type MultiProof, type SlotClaim} from "./linea.js";
import {hexToBuf} from "../lib/rlp.js";
import {RLP} from "@ethereumjs/rlp";

/// Live-data proof builder for the L1-settled rollup verifiers on Ethereum MAINNET:
///   --chain linea   LineaRollupVerifier  (Linea, chain 59144; Poseidon2 sparse Merkle tree)
///   --chain scroll  L1RollupMptVerifier  (Scroll, chain 534352; MPT)
///   --chain morph   L1RollupMptVerifier  (Morph, chain 2818; MPT)
///
/// Chain of real data:
///   mainnet sync committee (finality_update, bootstrap) → the signed header's execution block B
///   → at B: the rollup's newest finalized key (Linea currentL2BlockNumber; Scroll/Morph
///     lastFinalizedBatchIndex) and eth_getProof of the rollup proxy for the root slot of that key,
///     the EIP-1967 slot and the root slot of key+1 (not finalized: a negative case)
///   → the L2 block of that root (Linea: the key; Scroll: the batch's end block from Scroll's batch API,
///     checked by state-root equality; Morph: batchDataStore[key].blockNumber, checked the same way)
///   → the L2 proof at that block of the ClprService stand-in with the channelId-derived slots
///     (Linea: linea_getProof; Scroll/Morph: eth_getProof).
///
/// No ClprService runs on these chains, so the stand-in is a long-lived contract (code hash pinned);
/// the channel slots are absent there, so the slot proofs are genuine exclusion proofs (zero metadata).
///
/// CLI:
///   npx tsx test/e2e/relay/buildZkRollupLiveProof.ts --chain linea            build from the fixture, print a summary
///   npx tsx test/e2e/relay/buildZkRollupLiveProof.ts --chain linea --refresh [--wait-nonsigners SECS]

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const fixturePath = (chain: string) => path.resolve(__dirname, `../fixtures/${chain}-live/capture.json`);

export const MAINNET_BEACON_APIS = ["https://ethereum-beacon-api.publicnode.com", "https://lodestar-mainnet.chainsafe.io"];
export const MAINNET_L1_RPC = "https://ethereum-rpc.publicnode.com";
/// Ethereum mainnet beacon genesis time and slot length (for slot → wall clock in summaries).
export const L1_GENESIS_TIME = 1606824023n;
export const L1_SECONDS_PER_SLOT = 12n;

export interface ChainLiveConfig {
    profile: L1RollupProfile;
    l2Rpcs: string[];
    /// ClprService stand-in on L2.
    account: Hex;
    channelId: Hex;
}

export const LIVE: Record<string, ChainLiveConfig> = {
    linea: {
        profile: PROFILES.linea,
        l2Rpcs: ["https://rpc.linea.build", "https://linea.drpc.org"],
        // Linea L2 TimeLock (owner of the L2 message service's ProxyAdmin): small storage trie (~21 leaves).
        account: "0xc808BfCBeD34D90fa9579CAa664e67B9A03C56ca",
        channelId: keccak256(toHex("clpr/zkrollup-live/linea"))
    },
    scroll: {
        profile: PROFILES.scroll,
        l2Rpcs: ["https://rpc.scroll.io"],
        // L2MessageQueue predeploy.
        account: "0x5300000000000000000000000000000000000000",
        channelId: keccak256(toHex("clpr/zkrollup-live/scroll"))
    },
    morph: {
        profile: PROFILES.morph,
        l2Rpcs: ["https://rpc.morphl2.io"],
        // Morph predeploy 0x5300…01.
        account: "0x5300000000000000000000000000000000000001",
        channelId: keccak256(toHex("clpr/zkrollup-live/morph"))
    }
};

const LAST_FINALIZED_ABI = [{
    type: "function", name: "lastFinalizedBatchIndex", stateMutability: "view", inputs: [],
    outputs: [{type: "uint256"}]
}] as const;
const BATCH_DATA_STORE_ABI = [{
    type: "function", name: "batchDataStore", stateMutability: "view", inputs: [{type: "uint256"}],
    outputs: [{type: "uint256"}, {type: "uint256"}, {type: "uint256"}, {type: "address"}]
}] as const;
/// LineaRollup `currentL2BlockNumber` storage slot (ZkEvmV2, next to stateRootHashes at 282).
const LINEA_CURRENT_L2_BLOCK_SLOT = 281n;

async function l2rpc<T>(cfg: ChainLiveConfig, method: string, params: unknown[]): Promise<T> {
    let lastErr: unknown;
    for (const url of cfg.l2Rpcs) {
        try {
            return await rpc<T>(url, method, params);
        } catch (err) {
            lastErr = err;
        }
    }
    throw lastErr;
}

export interface ZkRollupLiveCapture {
    chain: string;
    network: string;
    capturedAt: string;
    sources: {beaconApi: string; l1Rpc: string; l2Rpcs: string[]; batchApi?: string};
    beacon: BeaconCapture;
    l1: {
        block: {number: string; hash: Hex; stateRoot: Hex; timestamp: string};
        rollup: Hex;
        key: string;
        rollupProof: EthGetProofResult;
    };
    l2: {
        block: {number: string; hash: Hex; stateRoot: Hex; timestamp: string};
        account: Hex;
        keys: Hex[];
        /// eth_getProof (MPT) or linea_getProof (Linea) result.
        proof: unknown;
    };
}

export async function captureZkRollupLive(chain: string, opts: {waitForNonSignersMs?: number} = {}): Promise<ZkRollupLiveCapture> {
    const cfg = LIVE[chain];
    if (!cfg) throw new Error(`unknown chain ${chain}`);
    const p = cfg.profile;
    const l1Rpc = MAINNET_L1_RPC;

    const {beacon, extra} = await captureBeaconLive(
        {beaconApis: MAINNET_BEACON_APIS, waitForNonSignersMs: opts.waitForNonSignersMs},
        async (_execution, B) => {
            let key: bigint;
            let l2BlockFromL1: bigint | undefined;
            if (p.trie === "linea") {
                key = BigInt(await rpc<Hex>(l1Rpc, "eth_getStorageAt",
                    [p.rollup, toHex(LINEA_CURRENT_L2_BLOCK_SLOT, {size: 32}), B]));
            } else {
                key = BigInt(await rpc<Hex>(l1Rpc, "eth_call",
                    [{to: p.rollup, data: encodeFunctionData({abi: LAST_FINALIZED_ABI, functionName: "lastFinalizedBatchIndex"})}, B]));
                if (chain === "morph") {
                    const ret = await rpc<Hex>(l1Rpc, "eth_call", [{to: p.rollup, data: encodeFunctionData({
                        abi: BATCH_DATA_STORE_ABI, functionName: "batchDataStore", args: [key]
                    })}, B]);
                    l2BlockFromL1 = BigInt("0x" + ret.slice(2 + 128, 2 + 192)); // 3rd word: last L2 block
                }
            }
            const slots = [stateRootSlot(p.stateRootsSlot, key), EIP1967_IMPLEMENTATION_SLOT, stateRootSlot(p.stateRootsSlot, key + 1n)];
            const rollupProof = await rpc<EthGetProofResult>(l1Rpc, "eth_getProof", [p.rollup, slots, B]);
            const block = await rpc<ZkRollupLiveCapture["l1"]["block"]>(l1Rpc, "eth_getBlockByNumber", [B, false]);
            return {key, l2BlockFromL1, rollupProof, block};
        }
    );

    const key = extra.key;
    let batchApi: string | undefined;
    let l2Block: bigint;
    if (p.trie === "linea") {
        l2Block = key;
    } else if (chain === "scroll") {
        batchApi = `https://mainnet-api-re.scroll.io/api/batch?index=${key}`;
        const res = await fetch(batchApi);
        const j = (await res.json()) as {batch: {end_block_number: number}};
        l2Block = BigInt(j.batch.end_block_number);
    } else {
        l2Block = extra.l2BlockFromL1!;
    }
    const l2Tag = toHex(l2Block);
    const l2BlockHeader = await l2rpc<ZkRollupLiveCapture["l2"]["block"]>(cfg, "eth_getBlockByNumber", [l2Tag, false]);
    const keys = [...deriveChannelSlots(cfg.channelId)];
    const proof = p.trie === "linea"
        ? await l2rpc<LineaGetProofResult>(cfg, "linea_getProof", [cfg.account, keys, l2Tag])
        : await l2rpc<EthGetProofResult>(cfg, "eth_getProof", [cfg.account, keys, l2Tag]);

    return {
        chain,
        network: `${chain} on ${beacon.network}`,
        capturedAt: new Date().toISOString(),
        sources: {beaconApi: beacon.sources.beaconApi, l1Rpc, l2Rpcs: cfg.l2Rpcs, ...(batchApi ? {batchApi} : {})},
        beacon: {...beacon, sources: {beaconApi: beacon.sources.beaconApi, executionRpc: l1Rpc}},
        l1: {block: extra.block, rollup: p.rollup, key: key.toString(), rollupProof: extra.rollupProof},
        l2: {
            block: {number: l2BlockHeader.number, hash: l2BlockHeader.hash, stateRoot: l2BlockHeader.stateRoot,
                timestamp: l2BlockHeader.timestamp},
            account: cfg.account,
            keys,
            proof
        }
    };
}

// ── Pure builder ───────────────────────────────────────────────────────────
export interface ZkRollupLiveProof {
    chain: string;
    profile: L1RollupProfile;
    lightClient: LiveLightClient;
    rotation?: LiveRotationLightClient;
    key: bigint;
    l2StateRoot: Hex;
    l1StateRoot: Hex;
    trustAnchor: Hex;
    channelId: Hex;
    channelContext: Hex;
    l2Account: Hex;
    l2CodeHash: Hex;
    rollupProof: unknown[];
    /// Rollup proof for key+1 (root slot is empty at B: not finalized).
    rollupProofNext: unknown[];
    l2AccountProof: unknown;
    l2StorageProof: unknown;
    /// `verifyL2StateRoot` input.
    l2StateRootProof: Hex;
    bundle: Hex;
    linea?: {accountMultiProof: MultiProof; storageMultiProof: MultiProof; claims: SlotClaim[]; storageRoot: Hex};
}

const lower = (h: string) => h.toLowerCase();

/// Pure/offline: turn a capture into verifier inputs, cross-checking every link off-chain.
export function buildZkRollupLiveProof(c: ZkRollupLiveCapture): ZkRollupLiveProof {
    const cfg = LIVE[c.chain];
    const p = cfg.profile;
    const lightClient = buildLiveLightClient(c.beacon);
    const attested = c.beacon.finalityUpdate.data.attested_header;
    if (BigInt(c.l1.block.number) !== BigInt(attested.execution.block_number)) throw new Error("L1 block != signed header's block");
    if (lower(c.l1.block.stateRoot) !== lower(attested.execution.state_root)) throw new Error("L1 stateRoot mismatch");
    if (lower(c.l1.rollup) !== lower(p.rollup)) throw new Error("capture is for another rollup contract");
    if (lower(keccak256(c.l1.rollupProof.accountProof[0] as Hex)) !== lower(c.l1.block.stateRoot)) {
        throw new Error("rollup account proof does not start at the L1 state root");
    }

    const key = BigInt(c.l1.key);
    const sp = new Map(c.l1.rollupProof.storageProof.map((s) => [BigInt(s.key), BigInt(s.value)]));
    const root = sp.get(BigInt(stateRootSlot(p.stateRootsSlot, key)));
    if (!root) throw new Error(`no finalized root for key ${key}`);
    const impl = sp.get(BigInt(EIP1967_IMPLEMENTATION_SLOT));
    if (impl !== BigInt(p.implementation)) {
        throw new Error(`rollup implementation is 0x${impl?.toString(16)}, profile pins ${p.implementation} (upgrade?)`);
    }
    if (sp.get(BigInt(stateRootSlot(p.stateRootsSlot, key + 1n))) !== 0n) throw new Error("key+1 is unexpectedly finalized");
    const l2StateRoot = toHex(root, {size: 32});

    let l2CodeHash: Hex;
    let l2AccountProof: unknown;
    let l2StorageProof: unknown;
    let linea: ZkRollupLiveProof["linea"];
    if (p.trie === "linea") {
        const r = c.l2.proof as LineaGetProofResult;
        const acct = lineaAccountProof(r, c.l2.account, root);
        const st = lineaStorageProof(r, c.l2.keys, acct.account.storageRoot);
        l2CodeHash = toHex(acct.account.keccakCodeHash, {size: 32});
        l2AccountProof = hexToBuf(acct.encoded);
        l2StorageProof = hexToBuf(st.encoded);
        linea = {accountMultiProof: acct.multiProof, storageMultiProof: st.multiProof, claims: st.claims,
            storageRoot: toHex(acct.account.storageRoot, {size: 32})};
    } else {
        if (lower(c.l2.block.stateRoot) !== lower(l2StateRoot)) {
            throw new Error(`L2 block ${BigInt(c.l2.block.number)} stateRoot ${c.l2.block.stateRoot} != finalized root ${l2StateRoot}`);
        }
        const r = c.l2.proof as EthGetProofResult;
        if (lower(keccak256(r.accountProof[0] as Hex)) !== lower(l2StateRoot)) throw new Error("L2 account proof does not start at the root");
        // Scroll's l2geth names the field keccakCodeHash; the MPT account leaf is the standard 4-item RLP.
        l2CodeHash = (r.codeHash ?? (r as unknown as {keccakCodeHash: Hex}).keccakCodeHash) as Hex;
        l2AccountProof = r.accountProof.map(hexToBuf);
        l2StorageProof = storageEntries(r, c.l2.keys);
    }

    const slots = [stateRootSlot(p.stateRootsSlot, key), EIP1967_IMPLEMENTATION_SLOT];
    const rollupProof = rollupProofItem(key, c.l1.rollupProof, slots);
    const rollupProofNext = rollupProofItem(key + 1n, c.l1.rollupProof,
        [stateRootSlot(p.stateRootsSlot, key + 1n), EIP1967_IMPLEMENTATION_SLOT]);

    const channelId = cfg.channelId;
    const trustAnchor = encodeEthTrustAnchor(channelId, l2CodeHash, lightClient.committee, {
        gvr: c.beacon.genesisValidatorsRoot as Hex, forkVersion: lightClient.signed.forkVersion
    });
    const channelContext = (channelId + lower(c.l2.account).slice(2)) as Hex;
    return {
        chain: c.chain,
        profile: p,
        lightClient,
        rotation: buildLiveRotationLightClient(c.beacon),
        key,
        l2StateRoot,
        l1StateRoot: c.l1.block.stateRoot,
        trustAnchor,
        channelId,
        channelContext,
        l2Account: c.l2.account,
        l2CodeHash,
        rollupProof,
        rollupProofNext,
        l2AccountProof,
        l2StorageProof,
        l2StateRootProof: encodeL2StateRootProof(lightClient.lightClientProof, rollupProof),
        bundle: encodeL1RollupBundle({
            lightClientProof: lightClient.lightClientProof, rollupProof, l2AccountProof, l2StorageProof, bundleContent: "0x"
        }),
        linea
    };
}

export const forgeFixturePath = (chain: string) =>
    path.resolve(__dirname, `../../verifiers/evm/zkrollup/fixtures/${chain}-live.json`);

/// The light-client proof with its sync-committee bits cut to 341 of 512 participants (below 2/3; the
/// threshold is checked before any key material, so this isolates that check).
export function belowThresholdLightClient(lightClientProof: Hex): Hex {
    const items = RLP.decode(hexToBuf(lightClientProof)) as unknown[];
    const agg = items[1] as Uint8Array[];
    const bits = Buffer.alloc(64);
    for (let i = 0; i < 341; i++) bits[i >> 3] |= 1 << (i & 7);
    items[1] = [bits, agg[1]];
    return ("0x" + Buffer.from(RLP.encode(items as never)).toString("hex")) as Hex;
}

/// Inputs for the Foundry replay (test/verifiers/evm/zkrollup/ZkRollupLive.t.sol).
export function forgeFixture(p: ZkRollupLiveProof, c: ZkRollupLiveCapture): Record<string, unknown> {
    const out: Record<string, unknown> = {
        chain: p.chain,
        capturedAt: c.capturedAt,
        l1Block: Number(BigInt(c.l1.block.number)),
        l2Block: Number(BigInt(c.l2.block.number)),
        l2ChainId: p.profile.l2ChainId,
        rollup: p.profile.rollup,
        stateRootsSlot: Number(p.profile.stateRootsSlot),
        implementation: p.profile.implementation,
        key: Number(p.key),
        l1StateRoot: p.l1StateRoot,
        l2StateRoot: p.l2StateRoot,
        l2Account: p.l2Account,
        l2CodeHash: p.l2CodeHash,
        channelId: p.channelId,
        trustAnchor: p.trustAnchor,
        channelContext: p.channelContext,
        bundle: p.bundle,
        l2StateRootProof: p.l2StateRootProof,
        notFinalizedProof: encodeL2StateRootProof(p.lightClient.lightClientProof, p.rollupProofNext),
        belowThresholdProof: encodeL2StateRootProof(belowThresholdLightClient(p.lightClient.lightClientProof), p.rollupProof),
        lightClientProof: p.lightClient.lightClientProof,
        participants: p.lightClient.signed.participants,
        rotationLightClientProof: p.rotation?.lightClientProof ?? "0x",
        rotationNextPeriod: p.rotation ? Number(p.rotation.nextPeriod) : 0,
        rotationNextCommitteeRoot: p.rotation?.nextCommitteeMerkleRoot ?? ("0x" + "00".repeat(32))
    };
    if (p.linea) {
        out.lineaStorageRoot = p.linea.storageRoot;
        out.lineaAccountProof = "0x" + (p.l2AccountProof as Buffer).toString("hex");
        out.lineaStorageProof = "0x" + (p.l2StorageProof as Buffer).toString("hex");
        out.lineaStorageLeaves = p.linea.storageMultiProof.leaves.length;
        out.lineaStorageSiblings = p.linea.storageMultiProof.siblings.length;
    } else {
        // One flipped byte in the deepest node of the first channel-slot proof.
        const entries = (p.l2StorageProof as [Buffer, Buffer[]][]).map(([k, nodes]) => [k, nodes.map((n) => Buffer.from(n))]);
        const nodes = entries[0][1] as Buffer[];
        nodes[nodes.length - 1][nodes[nodes.length - 1].length - 1] ^= 1;
        out.tamperedStorageBundle = encodeL1RollupBundle({
            lightClientProof: p.lightClient.lightClientProof, rollupProof: p.rollupProof,
            l2AccountProof: p.l2AccountProof, l2StorageProof: entries, bundleContent: "0x"
        });
    }
    return out;
}

export function loadZkRollupLiveCapture(chain: string): ZkRollupLiveCapture {
    return JSON.parse(readFileSync(fixturePath(chain), "utf8")) as ZkRollupLiveCapture;
}

function summarize(p: ZkRollupLiveProof, c: ZkRollupLiveCapture): string {
    const lines = [
        `${c.network}, captured ${c.capturedAt}`,
        `L1 block ${BigInt(c.l1.block.number)}, participation ${p.lightClient.signed.participants}/512`,
        `rollup ${p.profile.rollup} key ${p.key} (${p.profile.keyKind}) → L2 state root ${p.l2StateRoot}`,
        `L2 block ${BigInt(c.l2.block.number)}, stand-in ${p.l2Account}, code hash ${p.l2CodeHash}`,
        `bundle ${(p.bundle.length - 2) / 2} B` + (p.rotation ? `; rotation to period ${p.rotation.nextPeriod} available` : "")
    ];
    if (p.linea) {
        lines.push(`linea storage multiproof: ${p.linea.storageMultiProof.leaves.length} leaves, ` +
            `${p.linea.storageMultiProof.siblings.length} siblings; account siblings ${p.linea.accountMultiProof.siblings.length}`);
    }
    return lines.join("\n");
}

async function main(): Promise<void> {
    const args = process.argv.slice(2);
    const ci = args.indexOf("--chain");
    const chain = ci >= 0 ? args[ci + 1] : "linea";
    let capture: ZkRollupLiveCapture;
    if (args.includes("--refresh")) {
        const waitIdx = args.indexOf("--wait-nonsigners");
        capture = await captureZkRollupLive(chain, {waitForNonSignersMs: waitIdx >= 0 ? Number(args[waitIdx + 1]) * 1000 : 0});
        buildZkRollupLiveProof(capture); // validate before writing
        mkdirSync(path.dirname(fixturePath(chain)), {recursive: true});
        writeFileSync(fixturePath(chain), JSON.stringify(capture, null, 1) + "\n");
        console.log(`captured → ${path.relative(process.cwd(), fixturePath(chain))}`);
    } else {
        capture = loadZkRollupLiveCapture(chain);
    }
    const live = buildZkRollupLiveProof(capture);
    console.log(summarize(live, capture));
    if (args.includes("--refresh") || args.includes("--forge")) {
        mkdirSync(path.dirname(forgeFixturePath(chain)), {recursive: true});
        writeFileSync(forgeFixturePath(chain), JSON.stringify(forgeFixture(live, capture), null, 1) + "\n");
        console.log(`forge fixture → ${path.relative(process.cwd(), forgeFixturePath(chain))}`);
    }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    main().catch((err) => {
        console.error(err);
        process.exit(1);
    });
}
