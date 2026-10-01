import {existsSync, mkdirSync, readdirSync, readFileSync, unlinkSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {decodeAbiParameters, encodeFunctionData, keccak256, parseAbiItem, toHex, type Hex} from "viem";
import {deriveChannelSlots, encodeEthTrustAnchor, type EthGetProofResult} from "./buildEthMainnetProof.js";
import {buildLiveLightClient, captureBeaconLive, getJson, rpc, type BeaconCapture, type LiveLightClient} from "./buildEthLiveProof.js";
import {accountNodes, outputRootPreimage, storageEntries} from "./opstack.js";
import {rlpEncode} from "../lib/rlp.js";
import {
    BLAST_ACCOUNT,
    encodeOracleBundle,
    encodeOracleL2StateRootProof,
    encodeOracleProof,
    ETH_ACCOUNT,
    oracleSlots,
    outputElementSlot,
    PERIOD_SOURCE,
    provenSlot,
    type L2AccountFormat,
    type OracleProfile,
    type OracleProofParts
} from "./opOracle.js";

/// Live-data proof builder for the output-oracle verifiers (`OpOutputOracleVerifier` /
/// `OpOutputOracleProposedVerifier`) on three Ethereum-mainnet L2s, all captured at ONE attested L1 block:
///
///   blast   L2OutputOracle 1.6.0          0x826D…5c76  (portal 0x0Ec6…6Cb `l2Oracle()`)
///   mantle  OPSuccinctL2OutputOracle 2.0.1 0x31d5…f481  (portal 0xc54c…A8Fb `L2_ORACLE()`)
///   katana  AggchainFEP 3.0.0              0x100d…0666  (AgglayerManager 0x5132…7aB2, rollup id 20)
///
/// Chain of real data:
///   mainnet sync committee (finality_update, bootstrap) → attested execution block B
///   → eth_getProof at B of each oracle: `l2Outputs.length`, the EIP-1967 implementation (+ its code
///     hash), the chosen `l2Outputs[i]` elements, the finalization period (Mantle) and the
///     optimistic-mode flag (Mantle, Katana)
///   → `l2Outputs[i].outputRoot == keccak(0 ‖ L2 stateRoot ‖ messagePasserStorageRoot ‖ L2 blockHash)`
///     of the L2 block it names (Mantle and Katana: the header's withdrawalsRoot is the message-passer
///     root; Blast: taken from eth_getProof of the L2ToL1MessagePasser)
///   → eth_getProof on the L2 at that block (ClprService stand-in: the L2ToL1MessagePasser predeploy,
///     real code hash pinned; the channel slots are absent → exclusion proofs).
///
/// Outputs per chain:
///   `newest`     the last posted output (Blast/Mantle: still inside the finalization period → PROPOSED).
///   `finalized`  the last output past the finalization period at B (Katana: = newest, period 0).
///   `pending`    outputs staged by an EARLIER refresh (L2 proofs captured while fetchable) that have
///                since finalized — Blast's public RPC serves eth_getProof only 10,000 blocks (~5.5 h)
///                back, so its full FINALIZED bundle needs a refresh ≥ 7 days after a staging refresh.
///
/// CLI:
///   npx tsx test/e2e/relay/buildOpOracleLiveProof.ts                     build from the fixture, print a summary
///   npx tsx test/e2e/relay/buildOpOracleLiveProof.ts --refresh [--wait-nonsigners SECS]
///   npx tsx test/e2e/relay/buildOpOracleLiveProof.ts --set fraxtal [--refresh]
///
/// Fixture sets: `opadapters` (default: blast, mantle, katana → fixtures/opadapters-live, Forge export
/// with the oracle and L2 items only) and `fraxtal` (fraxtal → fixtures/fraxtal-live, Forge export with
/// the real light-client proof and trust anchor, replayed as is by OpOutputOracleFraxtalLive).

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const OPADAPTERS_FIXTURE_DIR = path.resolve(__dirname, "../fixtures/opadapters-live");
export const OPADAPTERS_LIVE_FIXTURE = path.join(OPADAPTERS_FIXTURE_DIR, "capture.json");
/// Forge-readable export of the built proofs (the Foundry tests sign the real L1 state root with a
/// generator committee and replay these real oracle and L2 proofs through the real verifiers).
export const OPADAPTERS_FORGE_FIXTURE = path.resolve(__dirname, "../../verifiers/evm/opstack/oracle/fixtures/live.json");

export const MAINNET_BEACON_APIS = ["https://ethereum-beacon-api.publicnode.com", "https://lodestar-mainnet.chainsafe.io"];
export const MAINNET_L1_RPC = "https://ethereum-rpc.publicnode.com";
export const L1_SECONDS_PER_SLOT = 12n;
/// L2ToL1MessagePasser predeploy: a real contract with real code and storage on every chain here.
export const L2_ACCOUNT: Hex = "0x4200000000000000000000000000000000000016";

export type ChainName = "blast" | "mantle" | "katana" | "fraxtal";

export interface OracleChain {
    name: ChainName;
    l2ChainId: number;
    oracle: Hex;
    /// Layout (from the verified implementation sources; checked against live storage by the builder).
    outputsSlot: bigint;
    periodSource: number;
    finalizationPeriodSlot: bigint;
    hasOptimisticMode: boolean;
    optimisticModeSlot: bigint;
    optimisticModeOffset: bigint;
    /// How the IMMUTABLE period is read for the profile: a view function, or a constant.
    periodGetter: string | null;
    accountFormat: L2AccountFormat;
    /// Isthmus+: the L2 header's withdrawalsRoot is the L2ToL1MessagePasser storage root.
    withdrawalsRootIsMessagePasser: boolean;
    l2Rpcs: string[];
    /// L1 binding: the chain's settlement entry point names this oracle (`eth_call` at B).
    binding: {to: Hex; fn: string; args: unknown[]};
}

export const ORACLE_CHAINS: Record<ChainName, OracleChain> = {
    blast: {
        name: "blast",
        l2ChainId: 81457,
        oracle: "0x826D1B0D4111Ad9146Eb8941D7Ca2B6a44215c76",
        outputsSlot: 3n, // L2OutputOracle 1.6.0: _initialized|_initializing, startingBlockNumber, startingTimestamp, l2Outputs
        periodSource: PERIOD_SOURCE.IMMUTABLE,
        finalizationPeriodSlot: 0n,
        hasOptimisticMode: false,
        optimisticModeSlot: 0n,
        optimisticModeOffset: 0n,
        periodGetter: "function FINALIZATION_PERIOD_SECONDS() view returns (uint256)",
        accountFormat: BLAST_ACCOUNT,
        withdrawalsRootIsMessagePasser: false,
        l2Rpcs: ["https://rpc.blast.io"],
        binding: {to: "0x0Ec68c5B10F21EFFb74f2A5C61DFe6b08C0Db6Cb", fn: "function l2Oracle() view returns (address)", args: []}
    },
    mantle: {
        name: "mantle",
        l2ChainId: 5000,
        oracle: "0x31d543e7BE1dA6eFDc2206Ef7822879045B9f481",
        outputsSlot: 3n, // OPSuccinctL2OutputOracle 2.0.1
        periodSource: PERIOD_SOURCE.STORAGE,
        finalizationPeriodSlot: 8n,
        hasOptimisticMode: true,
        optimisticModeSlot: 16n,
        optimisticModeOffset: 0n,
        periodGetter: null,
        accountFormat: ETH_ACCOUNT,
        withdrawalsRootIsMessagePasser: true,
        l2Rpcs: ["https://rpc.mantle.xyz"],
        binding: {to: "0xc54cb22944F2bE476E02dECfCD7e3E7d3e15A8Fb", fn: "function L2_ORACLE() view returns (address)", args: []}
    },
    katana: {
        name: "katana",
        l2ChainId: 747474,
        oracle: "0x100d3ca4f97776A40A7D93dB4AbF0FEA34230666",
        outputsSlot: 116n, // AggchainFEP 3.0.0 (after AggchainBase's 116 slots)
        periodSource: PERIOD_SOURCE.IMMUTABLE, // 0: no deleteL2Outputs; outputs are final when appended
        finalizationPeriodSlot: 0n,
        hasOptimisticMode: true,
        optimisticModeSlot: 124n, // optimisticMode (offset 0) | optimisticModeManager (offset 1)
        optimisticModeOffset: 0n,
        periodGetter: null,
        accountFormat: ETH_ACCOUNT,
        withdrawalsRootIsMessagePasser: true,
        l2Rpcs: ["https://katana.drpc.org", "https://rpc.katana.network"],
        // AgglayerManager.rollupIDToRollupDataV2(20).rollupContract
        binding: {
            to: "0x5132A183E9F3CB7C848b0AAC5Ae0c4f0491B7aB2",
            fn: "function rollupIDToRollupDataV2(uint32) view returns (address,uint64,address,uint64,bytes32,uint64,uint64,uint64,uint64,uint8,bytes32,bytes32)",
            args: [20]
        }
    },
    fraxtal: {
        name: "fraxtal",
        l2ChainId: 252,
        oracle: "0x66CC916Ed5C6C2FA97014f7D1cD141528Ae171e4",
        // L2OutputOracle 1.8.0: _initialized|_initializing, startingBlockNumber, startingTimestamp, l2Outputs (3),
        // submissionInterval, l2BlockTime, challenger, proposer, finalizationPeriodSeconds (8).
        outputsSlot: 3n,
        periodSource: PERIOD_SOURCE.STORAGE,
        finalizationPeriodSlot: 8n,
        hasOptimisticMode: false,
        optimisticModeSlot: 0n,
        optimisticModeOffset: 0n,
        periodGetter: null,
        accountFormat: ETH_ACCOUNT,
        withdrawalsRootIsMessagePasser: true, // Isthmus: checked against eth_getProof by every capture
        l2Rpcs: ["https://rpc.frax.com"],
        binding: {to: "0x36cb65c1967A0Fb0EEE11569C51C2f2aA1Ca6f6D", fn: "function l2Oracle() view returns (address)", args: []}
    }
};

/// The `opadapters` set (the default capture).
export const CHAIN_NAMES: ChainName[] = ["blast", "mantle", "katana"];

/// One capture file per set, all chains of a set at one signed L1 block.
export interface FixtureSet {
    name: string;
    chains: ChainName[];
    dir: string;
    /// Forge export: "items" (oracle and L2 items, light client built in Solidity) or "real" (the real
    /// light-client proof, trust anchor and full calldata).
    forgeKind: "items" | "real";
    forgeFile: string;
}

export const FIXTURE_SETS: Record<string, FixtureSet> = {
    opadapters: {name: "opadapters", chains: CHAIN_NAMES, dir: OPADAPTERS_FIXTURE_DIR, forgeKind: "items",
        forgeFile: OPADAPTERS_FORGE_FIXTURE},
    fraxtal: {name: "fraxtal", chains: ["fraxtal"], dir: path.resolve(__dirname, "../fixtures/fraxtal-live"), forgeKind: "real",
        forgeFile: path.resolve(__dirname, "../../verifiers/evm/opstack/oracle/fixtures/fraxtal-live.json")}
};
const captureFile = (set: FixtureSet) => path.join(set.dir, "capture.json");
const pendingDirOf = (set: FixtureSet) => path.join(set.dir, "pending");

export function channelIdFor(chain: ChainName): Hex {
    return keccak256(toHex(`clpr/opadapters-live/${chain}`));
}

// ── eth_call helper ────────────────────────────────────────────────────────
async function call<T>(url: string, to: Hex, signature: string, args: unknown[], blockTag: Hex | "latest"): Promise<T> {
    const item = parseAbiItem(signature) as {type: "function"; name: string; outputs: readonly {type: string}[]};
    const data = encodeFunctionData({abi: [item], functionName: item.name, args} as never);
    const out = await rpc<Hex>(url, "eth_call", [{to, data}, blockTag]);
    const decoded = decodeAbiParameters(item.outputs as never, out) as unknown[];
    return (decoded.length === 1 ? decoded[0] : decoded) as T;
}

async function l2rpc<T>(chain: OracleChain, method: string, params: unknown[]): Promise<T> {
    let lastErr: unknown;
    for (const url of chain.l2Rpcs) {
        try {
            return await rpc<T>(url, method, params);
        } catch (err) {
            lastErr = err;
        }
    }
    throw lastErr;
}

// ── Capture shapes ─────────────────────────────────────────────────────────
export interface L2Output {
    blockNumber: string;
    header: {hash: Hex; stateRoot: Hex; withdrawalsRoot: Hex};
    /// eth_getProof of L2_ACCOUNT with the channel slots at `blockNumber`; null when out of the RPC's window.
    proof: (EthGetProofResult & {storageHash: Hex}) | null;
}

export interface CapturedOutput {
    index: string;
    outputRoot: Hex;
    l1Timestamp: string;
    l2BlockNumber: string;
    l2: L2Output;
}

export interface ChainCapture {
    oracle: Hex;
    implementation: Hex;
    /// IMMUTABLE period as read through the getter (bound on-chain by the implementation code hash).
    finalizationPeriodSeconds: string;
    length: string;
    optimisticMode: boolean;
    oracleProof: EthGetProofResult;
    implProof: EthGetProofResult;
    outputs: {newest: CapturedOutput; finalized: CapturedOutput; pending: CapturedOutput[]};
}

export interface OpOracleLiveCapture {
    network: string;
    capturedAt: string;
    sources: {beaconApi: string; l1Rpc: string; l2Rpcs: Record<ChainName, string[]>};
    beacon: BeaconCapture;
    l1: {genesisTime: string; block: {number: string; hash: Hex; stateRoot: Hex; timestamp: string}};
    chains: Record<ChainName, ChainCapture>;
}

type PendingStage = Omit<CapturedOutput, "l1Timestamp"> & {chain: ChainName};

async function captureL2Output(chain: OracleChain, blockNumber: bigint, withProof: boolean): Promise<L2Output> {
    const tag = "0x" + blockNumber.toString(16);
    const h = await l2rpc<{hash: Hex; stateRoot: Hex; withdrawalsRoot: Hex}>(chain, "eth_getBlockByNumber", [tag, false]);
    let proof: L2Output["proof"] = null;
    if (withProof) {
        try {
            proof = await l2rpc<NonNullable<L2Output["proof"]>>(chain, "eth_getProof",
                [L2_ACCOUNT, deriveChannelSlots(channelIdFor(chain.name)), tag]);
        } catch (err) {
            console.error(`${chain.name}: L2 eth_getProof at ${blockNumber} unavailable: ${String(err).slice(0, 120)}`);
        }
    }
    return {blockNumber: blockNumber.toString(), header: {hash: h.hash, stateRoot: h.stateRoot, withdrawalsRoot: h.withdrawalsRoot}, proof};
}

function loadPending(set: FixtureSet): PendingStage[] {
    const dir = pendingDirOf(set);
    if (!existsSync(dir)) return [];
    return readdirSync(dir).filter((f) => f.endsWith(".json"))
        .map((f) => JSON.parse(readFileSync(path.join(dir, f), "utf8")) as PendingStage);
}

/// The chains a capture holds, in capture order.
const chainsOf = (c: {chains: Partial<Record<ChainName, unknown>>}) => Object.keys(c.chains) as ChainName[];

type OutputTuple = {outputRoot: Hex; timestamp: bigint; l2BlockNumber: bigint};
const GET_OUTPUT = "function getL2Output(uint256) view returns ((bytes32 outputRoot, uint128 timestamp, uint128 l2BlockNumber))";

/// L1 reads for one chain at block B (inside the beacon hook, while a full node still has the state).
async function captureChainL1(chain: OracleChain, l1Rpc: string, B: Hex, l1Time: bigint, pending: PendingStage[]) {
    const bound = await call<unknown>(l1Rpc, chain.binding.to, chain.binding.fn, chain.binding.args, B);
    const boundOracle = (Array.isArray(bound) ? bound[0] : bound) as Hex;
    if (boundOracle.toLowerCase() !== chain.oracle.toLowerCase()) {
        throw new Error(`${chain.name}: settlement entry point names ${boundOracle}, not ${chain.oracle}`);
    }
    const length = await call<bigint>(l1Rpc, chain.oracle, "function nextOutputIndex() view returns (uint256)", [], B);
    const getOutput = (i: bigint) => call<OutputTuple>(l1Rpc, chain.oracle, GET_OUTPUT, [i], B);
    const period = chain.periodGetter ? await call<bigint>(l1Rpc, chain.oracle, chain.periodGetter, [], B)
        : chain.periodSource === PERIOD_SOURCE.STORAGE
            ? await call<bigint>(l1Rpc, chain.oracle, "function finalizationPeriodSeconds() view returns (uint256)", [], B)
            : 0n;
    const optimisticMode = chain.hasOptimisticMode
        ? await call<boolean>(l1Rpc, chain.oracle, "function optimisticMode() view returns (bool)", [], B) : false;

    // Last index whose finalization period has elapsed at B (timestamps are non-decreasing).
    let lo = 0n;
    let hi = length - 1n;
    if ((await getOutput(lo)).timestamp + period >= l1Time) throw new Error(`${chain.name}: no finalized output`);
    while (lo < hi) {
        const mid = (lo + hi + 1n) / 2n;
        if ((await getOutput(mid)).timestamp + period < l1Time) lo = mid;
        else hi = mid - 1n;
    }
    const pick = async (i: bigint) => {
        const o = await getOutput(i);
        return {index: i.toString(), outputRoot: o.outputRoot, l1Timestamp: o.timestamp.toString(), l2BlockNumber: o.l2BlockNumber.toString()};
    };
    const newest = await pick(length - 1n);
    const finalized = await pick(lo);
    const pend = await Promise.all(pending.filter((p) => p.chain === chain.name).map((p) => pick(BigInt(p.index))));

    const p = profileOf(chain, "0x" as Hex, period);
    // Slots for every chosen index, plus index `length` (unposted: the negative case).
    const indices = [BigInt(newest.index), BigInt(finalized.index), ...pend.map((x) => BigInt(x.index)), length];
    const keys = [...new Set(indices.flatMap((i) => oracleSlots(p, i)))];
    const oracleProof = await rpc<EthGetProofResult>(l1Rpc, "eth_getProof", [chain.oracle, keys, B]);
    const implementation = ("0x" + provenSlot(oracleProof, oracleSlots(p, 0n)[1]).toString(16).padStart(40, "0")) as Hex;
    const implProof = await rpc<EthGetProofResult>(l1Rpc, "eth_getProof", [implementation, [], B]);
    return {
        oracle: chain.oracle, implementation, finalizationPeriodSeconds: period.toString(), length: length.toString(),
        optimisticMode, oracleProof, implProof, newest, finalized, pend
    };
}

/// Capture every chain of a set at one signed mainnet L1 block.
export async function captureOpOracleLive(opts: {beaconApis?: string[]; l1Rpc?: string; waitForNonSignersMs?: number;
    set?: FixtureSet} = {}): Promise<OpOracleLiveCapture> {
    const l1Rpc = opts.l1Rpc ?? MAINNET_L1_RPC;
    const beaconApis = opts.beaconApis ?? MAINNET_BEACON_APIS;
    const set = opts.set ?? FIXTURE_SETS.opadapters;
    const names = set.chains;
    const pending = loadPending(set);

    const {beacon, extra} = await captureBeaconLive({beaconApis, waitForNonSignersMs: opts.waitForNonSignersMs}, async (execution, B) => {
        const l1Time = BigInt(execution.timestamp);
        const chains = {} as Record<ChainName, Awaited<ReturnType<typeof captureChainL1>>>;
        for (const name of names) chains[name] = await captureChainL1(ORACLE_CHAINS[name], l1Rpc, B, l1Time, pending);
        const block = await rpc<{number: string; hash: Hex; stateRoot: Hex; timestamp: string}>(l1Rpc, "eth_getBlockByNumber", [B, false]);
        return {chains, block: {number: block.number, hash: block.hash, stateRoot: block.stateRoot, timestamp: block.timestamp}};
    });

    const {json: genesis} = await getJson<{data: {genesis_time: string}}>([beacon.sources.beaconApi, ...beaconApis], "/eth/v1/beacon/genesis");
    const chains = {} as Record<ChainName, ChainCapture>;
    for (const name of names) {
        const chain = ORACLE_CHAINS[name];
        const c = extra.chains[name];
        const l2Of = (o: {l2BlockNumber: string}) => captureL2Output(chain, BigInt(o.l2BlockNumber), true);
        const pend = c.pend.map((o) => ({...o, l2: pending.find((p) => p.chain === name && p.index === o.index)!.l2}));
        chains[name] = {
            oracle: c.oracle, implementation: c.implementation, finalizationPeriodSeconds: c.finalizationPeriodSeconds,
            length: c.length, optimisticMode: c.optimisticMode, oracleProof: c.oracleProof, implProof: c.implProof,
            outputs: {newest: {...c.newest, l2: await l2Of(c.newest)}, finalized: {...c.finalized, l2: await l2Of(c.finalized)}, pending: pend}
        };
    }
    return {
        network: names.join(", ") + " on " + beacon.network,
        capturedAt: new Date().toISOString(),
        sources: {beaconApi: beacon.sources.beaconApi, l1Rpc,
            l2Rpcs: Object.fromEntries(names.map((n) => [n, ORACLE_CHAINS[n].l2Rpcs])) as Record<ChainName, string[]>},
        beacon: {...beacon, sources: {beaconApi: beacon.sources.beaconApi, executionRpc: l1Rpc}},
        l1: {genesisTime: genesis.data.genesis_time, block: extra.block},
        chains
    };
}

// ── Pure builder ───────────────────────────────────────────────────────────
const rlpHex = (x: unknown) => ("0x" + rlpEncode(x as never).toString("hex")) as Hex;

export function profileOf(chain: OracleChain, implCodeHash: Hex, period: bigint): OracleProfile {
    return {
        oracle: chain.oracle,
        oracleImplCodeHash: implCodeHash,
        outputsSlot: chain.outputsSlot,
        periodSource: chain.periodSource,
        finalizationPeriodSeconds: chain.periodSource === PERIOD_SOURCE.IMMUTABLE ? period : 0n,
        finalizationPeriodSlot: chain.finalizationPeriodSlot,
        hasOptimisticMode: chain.hasOptimisticMode,
        optimisticModeSlot: chain.optimisticModeSlot,
        optimisticModeOffset: chain.optimisticModeOffset
    };
}

export interface OracleOutputCase {
    index: bigint;
    outputRoot: Hex;
    l1Timestamp: bigint;
    l2BlockNumber: bigint;
    /// Past the finalization period at the proven L1 time.
    finalizedAtL1: boolean;
    oracle: OracleProofParts;
    /// `verifyOutput` input.
    oracleProof: Hex;
    /// `verifyL2StateRoot` input; null when the message-passer root is unknown (Blast, out of window).
    l2StateRootProof: Hex | null;
    l2StateRoot: Hex;
    /// Full `verifyBundle` proof, when the L2 account proof is available.
    bundle: Hex | null;
    preimage: Hex | null;
    l2AccountProofRlp: Hex | null;
    l2StorageProofRlp: Hex | null;
}

export interface OracleChainProof {
    chain: OracleChain;
    profile: OracleProfile;
    finalizationPeriodSeconds: bigint;
    length: bigint;
    trustAnchor: Hex | null;
    channelId: Hex;
    channelContext: Hex;
    l2CodeHash: Hex | null;
    newest: OracleOutputCase;
    finalized: OracleOutputCase;
    pendingFinalized: OracleOutputCase[];
    /// Oracle proof for index `length` (never posted at B).
    unposted: OracleProofParts;
}

export interface OpOracleLiveProof {
    lightClient: LiveLightClient;
    l1Time: bigint;
    l1GenesisTime: bigint;
    l1StateRoot: Hex;
    l1Slot: bigint;
    chains: Record<ChainName, OracleChainProof>;
}

/// Pure/offline: turn a capture into verifier inputs, cross-checking every link off-chain.
export function buildOpOracleLiveProof(c: OpOracleLiveCapture): OpOracleLiveProof {
    const lightClient = buildLiveLightClient(c.beacon);
    const attested = c.beacon.finalityUpdate.data.attested_header;
    if (BigInt(c.l1.block.number) !== BigInt(attested.execution.block_number)) throw new Error("L1 block != attested block");
    if (c.l1.block.stateRoot.toLowerCase() !== attested.execution.state_root.toLowerCase()) throw new Error("L1 stateRoot mismatch");
    const l1GenesisTime = BigInt(c.l1.genesisTime);
    const l1Slot = BigInt(attested.beacon.slot);
    const l1Time = l1GenesisTime + l1Slot * L1_SECONDS_PER_SLOT;
    if (l1Time !== BigInt(attested.execution.timestamp) || l1Time !== BigInt(c.l1.block.timestamp)) {
        throw new Error("genesis_time + slot × 12 != execution timestamp");
    }

    const chains = {} as Record<ChainName, OracleChainProof>;
    for (const name of chainsOf(c)) {
        const chain = ORACLE_CHAINS[name];
        const cc = c.chains[name];
        const period = BigInt(cc.finalizationPeriodSeconds);
        const profile = profileOf(chain, cc.implProof.codeHash as Hex, period);

        // Layout cross-checks against the getters.
        const length = BigInt(cc.length);
        if (provenSlot(cc.oracleProof, chain.outputsSlot) !== length) throw new Error(`${name}: length slot != nextOutputIndex()`);
        if (chain.periodSource === PERIOD_SOURCE.STORAGE && provenSlot(cc.oracleProof, chain.finalizationPeriodSlot) !== period) {
            throw new Error(`${name}: period slot != finalizationPeriodSeconds()`);
        }
        if (chain.hasOptimisticMode) {
            const flag = ((provenSlot(cc.oracleProof, chain.optimisticModeSlot) >> (8n * chain.optimisticModeOffset)) & 0xffn) !== 0n;
            if (flag !== cc.optimisticMode) throw new Error(`${name}: optimistic slot != optimisticMode()`);
        }

        const withProof = [cc.outputs.newest, cc.outputs.finalized, ...cc.outputs.pending].find((o) => o.l2.proof)?.l2.proof;
        const l2CodeHash = (withProof?.codeHash as Hex | undefined) ?? null;
        const channelId = channelIdFor(name);
        const trustAnchor = l2CodeHash ? encodeEthTrustAnchor(channelId, l2CodeHash, lightClient.committee, {
            gvr: c.beacon.genesisValidatorsRoot as Hex, forkVersion: lightClient.signed.forkVersion
        }) : null;
        const channelContext = (channelId + L2_ACCOUNT.slice(2).toLowerCase()) as Hex;
        const chSlots = deriveChannelSlots(channelId);

        const oracleParts = (index: bigint): OracleProofParts => ({
            outputIndex: index,
            oracleAccountProof: accountNodes(cc.oracleProof),
            oracleStorageProof: storageEntries(cc.oracleProof, oracleSlots(profile, index)),
            oracleImplAccountProof: accountNodes(cc.implProof)
        });

        const outputCase = (o: CapturedOutput): OracleOutputCase => {
            const index = BigInt(o.index);
            const e = outputElementSlot(chain.outputsSlot, index);
            if (provenSlot(cc.oracleProof, e) !== BigInt(o.outputRoot)) throw new Error(`${name} #${index}: proven root != getL2Output`);
            const word = provenSlot(cc.oracleProof, e + 1n);
            if ((word & ((1n << 128n) - 1n)) !== BigInt(o.l1Timestamp) || word >> 128n !== BigInt(o.l2BlockNumber)) {
                throw new Error(`${name} #${index}: proven timestamp|l2BlockNumber != getL2Output`);
            }
            if (o.l2.proof && o.l2.proof.storageHash.toLowerCase() !== (chain.withdrawalsRootIsMessagePasser
                ? o.l2.header.withdrawalsRoot.toLowerCase() : o.l2.proof.storageHash.toLowerCase())) {
                throw new Error(`${name}: L2ToL1MessagePasser storage root != header withdrawalsRoot`);
            }
            const mpRoot = chain.withdrawalsRootIsMessagePasser ? o.l2.header.withdrawalsRoot : (o.l2.proof?.storageHash ?? null);
            let preimage: Hex | null = null;
            if (mpRoot) {
                const r = outputRootPreimage(o.l2.header.stateRoot, mpRoot, o.l2.header.hash);
                if (r.outputRoot.toLowerCase() !== o.outputRoot.toLowerCase()) {
                    throw new Error(`${name} #${index}: output root ${r.outputRoot} != posted ${o.outputRoot}`);
                }
                preimage = r.preimage;
            }
            const oracle = oracleParts(index);
            const lc = lightClient.lightClientProof;
            return {
                index,
                outputRoot: o.outputRoot,
                l1Timestamp: BigInt(o.l1Timestamp),
                l2BlockNumber: BigInt(o.l2BlockNumber),
                finalizedAtL1: l1Time > BigInt(o.l1Timestamp) + period,
                oracle,
                oracleProof: encodeOracleProof(oracle),
                l2StateRootProof: preimage ? encodeOracleL2StateRootProof({lightClientProof: lc, oracle, outputRootPreimage: preimage}) : null,
                l2StateRoot: o.l2.header.stateRoot,
                preimage,
                l2AccountProofRlp: o.l2.proof ? rlpHex(accountNodes(o.l2.proof)) : null,
                l2StorageProofRlp: o.l2.proof ? rlpHex(storageEntries(o.l2.proof, chSlots)) : null,
                bundle: preimage && o.l2.proof ? encodeOracleBundle({
                    lightClientProof: lc, oracle, outputRootPreimage: preimage,
                    l2AccountProof: accountNodes(o.l2.proof),
                    l2StorageProof: storageEntries(o.l2.proof, chSlots),
                    bundleContent: "0x"
                }) : null
            };
        };

        chains[name] = {
            chain, profile, finalizationPeriodSeconds: period, length, trustAnchor, channelId, channelContext, l2CodeHash,
            newest: outputCase(cc.outputs.newest),
            finalized: outputCase(cc.outputs.finalized),
            pendingFinalized: cc.outputs.pending.map(outputCase).filter((x) => x.finalizedAtL1),
            unposted: oracleParts(length)
        };
    }
    return {lightClient, l1Time, l1GenesisTime, l1StateRoot: c.l1.block.stateRoot, l1Slot, chains};
}

export function loadOpOracleLiveCapture(file = OPADAPTERS_LIVE_FIXTURE): OpOracleLiveCapture {
    return JSON.parse(readFileSync(file, "utf8")) as OpOracleLiveCapture;
}

/// Forge export: per chain, the profile, the L2 binding and each case's RLP items (no light-client
/// part — the Foundry tests build their own over the same L1 state root and slot).
export function forgeFixture(p: OpOracleLiveProof): unknown {
    const caseOf = (x: OracleOutputCase) => ({
        index: Number(x.index),
        outputRoot: x.outputRoot,
        l1Timestamp: Number(x.l1Timestamp),
        l2StateRoot: x.l2StateRoot,
        oracleProof: x.oracleProof,
        preimage: x.preimage ?? "0x",
        l2AccountProof: x.l2AccountProofRlp ?? "0x",
        l2StorageProof: x.l2StorageProofRlp ?? "0x"
    });
    const chains: Record<string, unknown> = {};
    for (const name of chainsOf(p)) {
        const c = p.chains[name];
        chains[name] = {
            oracle: c.profile.oracle,
            oracleImplCodeHash: c.profile.oracleImplCodeHash,
            outputsSlot: Number(c.profile.outputsSlot),
            periodSource: c.profile.periodSource,
            finalizationPeriodSeconds: Number(c.finalizationPeriodSeconds),
            finalizationPeriodSlot: Number(c.profile.finalizationPeriodSlot),
            hasOptimisticMode: c.profile.hasOptimisticMode,
            optimisticModeSlot: Number(c.profile.optimisticModeSlot),
            optimisticModeOffset: Number(c.profile.optimisticModeOffset),
            accountFields: Number(c.chain.accountFormat.fields),
            accountStorageRootIndex: Number(c.chain.accountFormat.storageRootIndex),
            accountCodeHashIndex: Number(c.chain.accountFormat.codeHashIndex),
            length: Number(c.length),
            l2CodeHash: c.l2CodeHash,
            channelId: c.channelId,
            newest: caseOf(c.newest),
            finalized: caseOf(c.finalized),
            unpostedOracleProof: encodeOracleProof(c.unposted)
        };
    }
    return {
        note: "Generated by test/e2e/relay/buildOpOracleLiveProof.ts from test/e2e/fixtures/opadapters-live/capture.json",
        l1: {stateRoot: p.l1StateRoot, slot: Number(p.l1Slot), time: Number(p.l1Time), genesisTime: Number(p.l1GenesisTime)},
        l2Account: L2_ACCOUNT,
        chains
    };
}

/// Forge export with the REAL light-client proof: per chain, the pinned-profile fields to compare, the
/// trust anchor and the exact calldata arguments (`verifyBundle` / `verifyL2StateRoot` / `verifyOutput`).
export function realForgeFixture(p: OpOracleLiveProof): unknown {
    const caseOf = (x: OracleOutputCase) => ({
        index: Number(x.index),
        outputRoot: x.outputRoot,
        l1Timestamp: Number(x.l1Timestamp),
        l2BlockNumber: Number(x.l2BlockNumber),
        l2StateRoot: x.l2StateRoot,
        finalizedAtL1: x.finalizedAtL1,
        oracleProof: x.oracleProof,
        l2StateRootProof: x.l2StateRootProof ?? "0x",
        bundle: x.bundle ?? "0x"
    });
    const chains: Record<string, unknown> = {};
    for (const name of chainsOf(p)) {
        const c = p.chains[name];
        const pend = c.pendingFinalized.find((x) => x.bundle);
        chains[name] = {
            oracle: c.profile.oracle,
            oracleImplCodeHash: c.profile.oracleImplCodeHash,
            finalizationPeriodSeconds: Number(c.finalizationPeriodSeconds),
            length: Number(c.length),
            trustAnchor: c.trustAnchor ?? "0x",
            channelContext: c.channelContext,
            newest: caseOf(c.newest),
            finalized: caseOf(pend ?? c.finalized),
            unpostedOracleProof: encodeOracleProof(c.unposted)
        };
    }
    return {
        note: "Generated by test/e2e/relay/buildOpOracleLiveProof.ts --set <set> (real mainnet sync-committee signature)",
        l1: {stateRoot: p.l1StateRoot, slot: Number(p.l1Slot), time: Number(p.l1Time), genesisTime: Number(p.l1GenesisTime)},
        participants: p.lightClient.signed.participants,
        chains
    };
}

export function writeForgeFixture(p: OpOracleLiveProof, file = OPADAPTERS_FORGE_FIXTURE, kind: FixtureSet["forgeKind"] = "items"): void {
    mkdirSync(path.dirname(file), {recursive: true});
    writeFileSync(file, JSON.stringify(kind === "real" ? realForgeFixture(p) : forgeFixture(p), null, 1) + "\n");
}

function summarize(p: OpOracleLiveProof): string {
    const o = (x: OracleOutputCase) => `#${x.index} L2 ${x.l2BlockNumber} posted ${x.l1Timestamp} ` +
        `${x.finalizedAtL1 ? "final" : "not final"}, ${x.bundle ? "full bundle" : x.l2StateRootProof ? "to L2 state root" : "L1 output only"}`;
    const lines = [`L1 slot ${p.l1Slot} (time ${p.l1Time}), participation ${p.lightClient.signed.participants}/512`];
    for (const name of chainsOf(p)) {
        const c = p.chains[name];
        lines.push(`${name}: oracle ${c.profile.oracle} impl codeHash ${c.profile.oracleImplCodeHash}, length ${c.length}, ` +
            `period ${c.finalizationPeriodSeconds}s`);
        lines.push(`  newest     ${o(c.newest)}`);
        lines.push(`  finalized  ${o(c.finalized)}`);
        lines.push(`  pending finalized: ${c.pendingFinalized.length}`);
    }
    return lines.join("\n");
}

async function main(): Promise<void> {
    const args = process.argv.slice(2);
    const setIdx = args.indexOf("--set");
    const set = FIXTURE_SETS[setIdx >= 0 ? args[setIdx + 1] : "opadapters"];
    if (!set) throw new Error(`--set: one of ${Object.keys(FIXTURE_SETS).join(", ")}`);
    const PENDING_DIR = pendingDirOf(set);
    let capture: OpOracleLiveCapture;
    if (args.includes("--refresh")) {
        const waitIdx = args.indexOf("--wait-nonsigners");
        capture = await captureOpOracleLive({set, waitForNonSignersMs: waitIdx >= 0 ? Number(args[waitIdx + 1]) * 1000 : 0});
        const built = buildOpOracleLiveProof(capture); // validate before writing
        mkdirSync(PENDING_DIR, {recursive: true});
        writeFileSync(captureFile(set), JSON.stringify(capture, null, 1) + "\n");
        // Stage each chain's newest output whose finalized counterpart lacks a full bundle: its L2 proofs
        // are only fetchable now, and a refresh after its finalization period turns it into a full
        // FINALIZED bundle. Keep stages that are still not final, and the latest final one.
        const keep = new Set<string>();
        for (const name of set.chains) {
            const cc = capture.chains[name];
            const n = cc.outputs.newest;
            const b = built.chains[name];
            if (!b.finalized.bundle && !b.pendingFinalized.some((x) => x.bundle) && n.l2.proof) {
                const stage: PendingStage = {chain: name, index: n.index, outputRoot: n.outputRoot, l2BlockNumber: n.l2BlockNumber, l2: n.l2};
                writeFileSync(path.join(PENDING_DIR, `${name}-${n.index}.json`), JSON.stringify(stage, null, 1) + "\n");
                keep.add(`${name}-${n.index}`);
            }
            const lastFinal = b.pendingFinalized.at(-1);
            if (lastFinal) keep.add(`${name}-${lastFinal.index}`);
            for (const x of cc.outputs.pending) {
                if (!built.chains[name].pendingFinalized.some((f) => f.index === BigInt(x.index))) keep.add(`${name}-${x.index}`);
            }
        }
        for (const f of readdirSync(PENDING_DIR)) {
            if (f.endsWith(".json") && !keep.has(f.replace(/\.json$/, ""))) unlinkSync(path.join(PENDING_DIR, f));
        }
        console.log(`captured → ${path.relative(process.cwd(), captureFile(set))}`);
    } else {
        capture = loadOpOracleLiveCapture(captureFile(set));
    }
    const built = buildOpOracleLiveProof(capture);
    writeForgeFixture(built, set.forgeFile, set.forgeKind);
    console.log(summarize(built));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    main().catch((err) => {
        console.error(err);
        process.exit(1);
    });
}
