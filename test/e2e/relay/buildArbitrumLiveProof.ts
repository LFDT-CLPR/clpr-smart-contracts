import {mkdirSync, readFileSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {decodeEventLog, encodeEventTopics, keccak256, toHex, type Hex} from "viem";
import {rlpDecode, rlpEncode, hexToBuf} from "../lib/rlp.js";
import {deriveChannelSlots, encodeEthTrustAnchor, type EthGetProofResult} from "./buildEthMainnetProof.js";
import {
    buildLiveLightClient,
    captureBeaconLive,
    decodeCommittee,
    DEFAULT_EXECUTION_RPC,
    rpc,
    type BeaconCapture,
    type LiveLightClient
} from "./buildEthLiveProof.js";
import {
    assertionPreimage,
    assertionProofItem,
    assertionSlot,
    ASSERTION_STATUS,
    accountNodes,
    BOLD_LAYOUT,
    bundleItems,
    decodeAssertionNode,
    EIP1967_IMPLEMENTATION_SLOT,
    encodeArbitrumBundle,
    encodeArbitrumL2StateProof,
    encodeHeader,
    IMPLEMENTATION_SECONDARY_SLOT,
    LATEST_CONFIRMED_SLOT,
    MACHINE_STATUS,
    slotHex,
    storageEntries,
    type ArbitrumBundleParts,
    type ArbitrumProfile,
    type AssertionStateJson,
    type RpcHeader
} from "./arbitrum.js";

/// Live-data proof builder for `ArbitrumNitroVerifier`, on Arbitrum Sepolia (BoLD) settling on
/// Ethereum Sepolia, and on the Plume mainnet profile (Arbitrum Orbit, AnyTrust, BoLD) settling on
/// Ethereum mainnet (`--network plume`, fixture test/e2e/fixtures/plume-live/).
///
/// Chain of real data:
///   Sepolia sync committee (finality_update, bootstrap) → attested execution block B
///   → eth_getProof at B of Arbitrum Sepolia's RollupProxy: both logic slots, `_latestConfirmed`,
///     `_assertions[h]` slot 0 for the latest confirmed assertion, its pending child and a forged hash
///   → the `AssertionCreated` event of each (at the node's `createdAtBlock`) gives the preimage
///     `parent ‖ abi.encode(afterState) ‖ inboxAcc`, re-hashed off-chain to the assertion hash
///   → the assertion's L2 block hash → that L2 header (consensus RLP, re-hashed)
///   → eth_getProof on Arbitrum Sepolia at that L2 block (ClprService stand-in: Arbitrum Sepolia WETH,
///     a real contract with a populated storage trie whose code hash is pinned; the channel slots are
///     absent → genuine MPT exclusion proofs).
///
/// Arbitrum Sepolia confirms assertions after 20 L1 blocks (confirmPeriodBlocks), so the latest
/// confirmed assertion is at most a few hours old and its L2 state is servable by a public RPC that
/// keeps history (dRPC); Arbitrum One's period is 45,818 blocks (~6.4 days), see the README.
///
/// When the beacon API's rotation update is in the same signing period, the same chain of proofs is
/// also captured at THAT update's attested execution block, giving a full bundle that rotates the
/// trust anchor (needs an L1 RPC that serves eth_getProof that far back; skipped otherwise).
///
/// CLI:
///   npx tsx test/e2e/relay/buildArbitrumLiveProof.ts                     build from the fixture, print a summary
///   npx tsx test/e2e/relay/buildArbitrumLiveProof.ts --refresh [--wait-nonsigners SECS]
///   npx tsx test/e2e/relay/buildArbitrumLiveProof.ts --network plume [--refresh]

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ARBITRUM_FIXTURE_DIR = path.resolve(__dirname, "../fixtures/arbitrum-live");
export const ARBITRUM_LIVE_FIXTURE = path.join(ARBITRUM_FIXTURE_DIR, "capture.json");
/// Foundry copy (hex items only), read by test/verifiers/evm/arbitrum/ArbitrumNitroVerifier.t.sol.
export const ARBITRUM_FOUNDRY_FIXTURE = path.resolve(__dirname, "../../verifiers/evm/arbitrum/fixtures/live.json");

/// One Nitro chain + its parent chain: where to read, what to prove, where the fixtures go.
export interface ArbitrumLiveNetwork {
    name: string;
    l2ChainId: number;
    rollup: Hex;
    l1Rpcs: string[];
    l2Rpcs: string[];
    /// Beacon APIs of the parent chain (defaults to Sepolia's).
    beaconApis?: string[];
    /// L2 contract standing in for the ClprService (real code hash pinned, channel slots absent).
    l2Account: Hex;
    channelId: Hex;
    fixture: string;
    foundryFixture: string;
    layout: typeof BOLD_LAYOUT;
}

/// Arbitrum Sepolia (chain 421614) on Ethereum Sepolia. Rollup address: Arbitrum docs, and on-chain
/// `chainId()` == 421614.
export const ARBITRUM_SEPOLIA: ArbitrumLiveNetwork = {
    name: "arbitrum-sepolia on sepolia",
    l2ChainId: 421614,
    rollup: "0x042B2E6C5E99d4c521bd49beeD5E99651D9B0Cf4" as Hex,
    l1Rpcs: [DEFAULT_EXECUTION_RPC, "https://ethereum-sepolia-rpc.publicnode.com",
        /// keeps old state: serves the rotation update's attested block (up to a period back)
        "https://rpc.sepolia.ethpandaops.io"],
    /// eth_getProof at the confirmed L2 block needs history: dRPC serves it; the others keep ~recent state.
    l2Rpcs: ["https://arbitrum-sepolia.drpc.org", "https://sepolia-rollup.arbitrum.io/rpc",
        "https://arbitrum-sepolia-rpc.publicnode.com"],
    /// Arbitrum Sepolia WETH9 — real code and a large storage trie (realistic exclusion-proof depth).
    l2Account: "0x980B62Da83eFf3D4576C647993b0c1D7faf17c73",
    channelId: keccak256(toHex("clpr/arbitrum-live/arbitrum-sepolia")),
    fixture: ARBITRUM_LIVE_FIXTURE,
    foundryFixture: ARBITRUM_FOUNDRY_FIXTURE,
    layout: BOLD_LAYOUT
};
export const L2_ACCOUNT: Hex = ARBITRUM_SEPOLIA.l2Account;
export const ARBITRUM_LIVE_CHANNEL_ID: Hex = ARBITRUM_SEPOLIA.channelId;

/// Plume mainnet (chain 98866), an Arbitrum Orbit chain (AnyTrust, custom gas token PLUME) settling
/// directly on Ethereum mainnet with BoLD rollup contracts. Checked live on 2026-10-01:
///   - RollupProxy 0x4eD3…6eE8 (docs.plume.org contract list): `chainId()` 98866, `bridge()` = the
///     documented Bridge 0x3538…EF83; slot 116 == `latestConfirmed()` (bytes32 assertion hash, BoLD),
///     `_assertions[latestConfirmed]` (base 117) status byte 25 == Confirmed (2), as `getAssertion()`.
///   - Logic (EIP-1967 primary / secondary slots): RollupAdminLogic 0x16ad…b724, RollupUserLogic
///     0xa489…5451, the same BoLD logic as Reya.
///   - `confirmPeriodBlocks` 40,320 (~5.6 days), `anyTrustFastConfirmer` 0x0,
///     `validatorWhitelistDisabled` false with ONE whitelisted validator (see the README).
/// rpc.plume.org keeps historical state: it served eth_getProof ~1.3M L2 blocks (~6 days) back.
export const PLUME_MAINNET: ArbitrumLiveNetwork = {
    name: "plume on ethereum mainnet",
    l2ChainId: 98866,
    rollup: "0x4eD3F488a5a4417839BbC39712EB76D8Aaee6eE8",
    /// eth_getLogs + eth_getProof up to a sync period back (the rotation update's attested block).
    l1Rpcs: ["https://eth.drpc.org", "https://rpc.mevblocker.io", "https://eth-mainnet.public.blastapi.io", "https://1rpc.io/eth"],
    l2Rpcs: ["https://rpc.plume.org"],
    beaconApis: ["https://ethereum-beacon-api.publicnode.com", "https://lodestar-mainnet.chainsafe.io"],
    /// WPLUME (docs.plume.org: "Wrapped PLUME"), a WETH9-style contract with a large storage trie.
    l2Account: "0xEa237441c92CAe6FC17Caaf9a7acB3f953be4bd1",
    channelId: keccak256(toHex("clpr/arbitrum-live/plume")),
    fixture: path.resolve(__dirname, "../fixtures/plume-live/capture.json"),
    foundryFixture: path.resolve(__dirname, "../../verifiers/evm/arbitrum/fixtures/plume-live.json"),
    layout: BOLD_LAYOUT
};

export const ARBITRUM_LIVE_NETWORKS: Record<string, ArbitrumLiveNetwork> = {
    "arbitrum-sepolia": ARBITRUM_SEPOLIA,
    plume: PLUME_MAINNET
};

const ASSERTION_CREATED_ABI = [{
    type: "event",
    name: "AssertionCreated",
    inputs: [
        {name: "assertionHash", type: "bytes32", indexed: true},
        {name: "parentAssertionHash", type: "bytes32", indexed: true},
        {name: "assertion", type: "tuple", indexed: false, components: [
            {name: "beforeStateData", type: "tuple", components: [
                {name: "prevPrevAssertionHash", type: "bytes32"},
                {name: "sequencerBatchAcc", type: "bytes32"},
                {name: "configData", type: "tuple", components: [
                    {name: "wasmModuleRoot", type: "bytes32"},
                    {name: "requiredStake", type: "uint256"},
                    {name: "challengeManager", type: "address"},
                    {name: "confirmPeriodBlocks", type: "uint64"},
                    {name: "nextInboxPosition", type: "uint64"}
                ]}
            ]},
            {name: "beforeState", type: "tuple", components: ASSERTION_STATE()},
            {name: "afterState", type: "tuple", components: ASSERTION_STATE()}
        ]},
        {name: "afterInboxBatchAcc", type: "bytes32", indexed: false},
        {name: "inboxMaxCount", type: "uint256", indexed: false},
        {name: "wasmModuleRoot", type: "bytes32", indexed: false},
        {name: "requiredStake", type: "uint256", indexed: false},
        {name: "challengeManager", type: "address", indexed: false},
        {name: "confirmPeriodBlocks", type: "uint64", indexed: false}
    ]
}] as const;

function ASSERTION_STATE() {
    return [
        {name: "globalState", type: "tuple", components: [
            {name: "bytes32Vals", type: "bytes32[2]"},
            {name: "u64Vals", type: "uint64[2]"}
        ]},
        {name: "machineStatus", type: "uint8"},
        {name: "endHistoryRoot", type: "bytes32"}
    ] as const;
}
const ASSERTION_CREATED_TOPIC: Hex = encodeEventTopics({abi: ASSERTION_CREATED_ABI, eventName: "AssertionCreated"})[0]!;

// ── Capture shapes (JSON; bigints as decimal strings) ──────────────────────
type GetProof = EthGetProofResult & {storageHash: Hex};

export interface AssertionCapture {
    hash: Hex;
    parent: Hex;
    inboxAcc: Hex;
    afterState: {blockHash: Hex; sendRoot: Hex; inboxPosition: string; positionInMessage: string;
        machineStatus: number; endHistoryRoot: Hex};
    /// AssertionNode slot 0 at the L1 block.
    node: Hex;
    createdAtL1Block: string;
    l2Header: RpcHeader;
    /// eth_getProof of L2_ACCOUNT with the channel slots at the L2 block; null when no RPC served it.
    l2Proof: GetProof | null;
}

export interface L1Capture {
    blockNumber: string;
    stateRoot: Hex;
    /// eth_getProof of the rollup: impl, secondary impl, _latestConfirmed, and _assertions[h] for every
    /// assertion below (+ the forged hash).
    rollupProof: GetProof;
    confirmed: AssertionCapture;
    /// The latest confirmed assertion's first child, Pending at this L1 block (absent if none yet).
    pending: AssertionCapture | null;
}

export interface ArbitrumLiveCapture {
    network: string;
    capturedAt: string;
    sources: {beaconApi: string; l1Rpc: string; l2Rpc: string};
    beacon: BeaconCapture;
    l1: L1Capture;
    /// The same at the rotation update's attested block, when available.
    rotation: L1Capture | null;
}

// ── RPC helpers ────────────────────────────────────────────────────────────
async function firstOk<T>(urls: string[], method: string, params: unknown[]): Promise<{result: T; url: string}> {
    let lastErr: unknown;
    for (const url of urls) {
        try {
            return {result: await rpc<T>(url, method, params), url};
        } catch (err) {
            lastErr = err;
        }
    }
    throw new Error(`${method} failed on every RPC: ${String(lastErr)}`);
}

function hexBlock(n: bigint): Hex {
    return ("0x" + n.toString(16)) as Hex;
}

async function assertionAt(net: ArbitrumLiveNetwork, hash: Hex, node: Hex, parentFilter?: Hex): Promise<AssertionCapture> {
    const {l1Rpcs, l2Rpcs, rollup} = net;
    const n = decodeAssertionNode(node);
    const createdAt = hexBlock(n.createdAtBlock);
    const topics: (Hex | null)[] = [ASSERTION_CREATED_TOPIC, hash];
    if (parentFilter) topics.push(parentFilter);
    const {result: logs} = await firstOk<{data: Hex; topics: Hex[]}[]>(l1Rpcs, "eth_getLogs",
        [{address: rollup, fromBlock: createdAt, toBlock: createdAt, topics}]);
    if (logs.length !== 1) throw new Error(`AssertionCreated(${hash}) at L1 block ${n.createdAtBlock}: ${logs.length} logs`);
    const ev = decodeEventLog({abi: ASSERTION_CREATED_ABI, data: logs[0].data, topics: logs[0].topics as [Hex, ...Hex[]]});
    const a = ev.args;
    const st = a.assertion.afterState;
    const afterState: AssertionStateJson = {
        blockHash: st.globalState.bytes32Vals[0],
        sendRoot: st.globalState.bytes32Vals[1],
        inboxPosition: st.globalState.u64Vals[0],
        positionInMessage: st.globalState.u64Vals[1],
        machineStatus: st.machineStatus,
        endHistoryRoot: st.endHistoryRoot
    };
    const {hash: recomputed} = assertionPreimage(a.parentAssertionHash, afterState, a.afterInboxBatchAcc);
    if (recomputed !== hash.toLowerCase()) throw new Error(`assertion preimage hashes to ${recomputed}, expected ${hash}`);

    const {result: l2Header} = await firstOk<RpcHeader>(l2Rpcs, "eth_getBlockByHash", [afterState.blockHash, false]);
    encodeHeader(l2Header); // throws unless the consensus RLP re-hashes to the block hash
    let l2Proof: GetProof | null = null;
    // dRPC load-balances over nodes with different history depths: retry a few rounds.
    for (let attempt = 0; attempt < 4 && !l2Proof; attempt++) {
        try {
            ({result: l2Proof} = await firstOk<GetProof>(l2Rpcs, "eth_getProof",
                [net.l2Account, deriveChannelSlots(net.channelId), l2Header.number]));
        } catch (err) {
            if (attempt === 3) console.warn(`L2 eth_getProof at #${BigInt(l2Header.number)} unavailable: ${String(err).slice(0, 160)}`);
            else await new Promise((r) => setTimeout(r, 3_000));
        }
    }
    return {
        hash,
        parent: a.parentAssertionHash,
        inboxAcc: a.afterInboxBatchAcc,
        afterState: {...afterState, inboxPosition: afterState.inboxPosition.toString(),
            positionInMessage: afterState.positionInMessage.toString()},
        node,
        createdAtL1Block: n.createdAtBlock.toString(),
        l2Header: {...l2Header, transactions: undefined} as RpcHeader,
        l2Proof
    };
}

function stateOf(a: AssertionCapture): AssertionStateJson {
    return {...a.afterState, inboxPosition: BigInt(a.afterState.inboxPosition),
        positionInMessage: BigInt(a.afterState.positionInMessage)};
}

/// A hash no assertion has: the confirmed preimage with `inboxAcc` flipped (its header still valid).
function forged(a: AssertionCapture): {preimage: Hex; hash: Hex} {
    const acc = ("0x" + (BigInt(a.inboxAcc) ^ 1n).toString(16).padStart(64, "0")) as Hex;
    return assertionPreimage(a.parent, stateOf(a), acc);
}

/// Every rollup read at one L1 block.
async function captureL1(net: ArbitrumLiveNetwork, blockTag: Hex): Promise<L1Capture> {
    const {l1Rpcs, rollup} = net;
    const base = [EIP1967_IMPLEMENTATION_SLOT, IMPLEMENTATION_SECONDARY_SLOT, slotHex(LATEST_CONFIRMED_SLOT)];
    const {result: p0} = await firstOk<GetProof>(l1Rpcs, "eth_getProof", [rollup, base, blockTag]);
    const latest = slotHex(BigInt(p0.storageProof[2].value));
    const {result: p1} = await firstOk<GetProof>(l1Rpcs, "eth_getProof", [rollup, [assertionSlot(latest)], blockTag]);
    const latestNode = slotHex(BigInt(p1.storageProof[0].value));
    if (decodeAssertionNode(latestNode).status !== ASSERTION_STATUS.CONFIRMED) throw new Error("latestConfirmed not Confirmed?");
    const confirmed = await assertionAt(net, latest, latestNode);

    // The first child (if any) is Pending at this block: newer than the latest confirmed.
    let pending: AssertionCapture | null = null;
    const n = decodeAssertionNode(latestNode);
    if (n.firstChildBlock !== 0n) {
        const at = hexBlock(n.firstChildBlock);
        const {result: logs} = await firstOk<{topics: Hex[]}[]>(l1Rpcs, "eth_getLogs",
            [{address: rollup, fromBlock: at, toBlock: at, topics: [ASSERTION_CREATED_TOPIC, null, latest]}]);
        if (logs.length > 0) {
            const child = logs[0].topics[1];
            const {result: pc} = await firstOk<GetProof>(l1Rpcs, "eth_getProof", [rollup, [assertionSlot(child)], blockTag]);
            pending = await assertionAt(net, child, slotHex(BigInt(pc.storageProof[0].value)), latest);
        }
    }

    const keys = [...base, assertionSlot(latest), assertionSlot(forged(confirmed).hash)];
    if (pending) keys.push(assertionSlot(pending.hash));
    const {result: rollupProof, url} = await firstOk<GetProof>(l1Rpcs, "eth_getProof", [rollup, keys, blockTag]);
    const {result: block} = await rpc<{stateRoot: Hex; number: Hex}>(url, "eth_getBlockByNumber", [blockTag, false])
        .then((result) => ({result}));
    return {blockNumber: BigInt(block.number).toString(), stateRoot: block.stateRoot, rollupProof, confirmed, pending};
}

export async function captureArbitrumSepoliaLive(opts: {waitForNonSignersMs?: number} = {}): Promise<ArbitrumLiveCapture> {
    return captureArbitrumLive(ARBITRUM_SEPOLIA, opts);
}

export async function captureArbitrumLive(c: ArbitrumLiveNetwork, opts: {waitForNonSignersMs?: number} = {}):
    Promise<ArbitrumLiveCapture> {
    const {beacon, extra: l1} = await captureBeaconLive({...opts, beaconApis: c.beaconApis}, (_execution, blockTag) =>
        captureL1(c, blockTag));
    let rotation: L1Capture | null = null;
    const ru = beacon.rotationUpdate;
    if (ru) {
        try {
            rotation = await captureL1(c, hexBlock(BigInt(ru.data.attested_header.execution.block_number)));
        } catch (err) {
            console.warn(`rotation-block capture skipped: ${String(err).slice(0, 200)}`);
        }
    }
    return {
        network: c.name,
        capturedAt: new Date().toISOString(),
        sources: {beaconApi: beacon.sources.beaconApi, l1Rpc: c.l1Rpcs.join(" | "), l2Rpc: c.l2Rpcs.join(" | ")},
        beacon,
        l1,
        rotation
    };
}

// ── Offline build ──────────────────────────────────────────────────────────
export interface AssertionCase {
    assertionHash: Hex;
    status: number;
    preimage: Hex;
    l2Header: Hex;
    l2BlockHash: Hex;
    l2StateRoot: Hex;
    l2BlockNumber: bigint;
    sendRoot: Hex;
    assertionProof: unknown[];
    /// Present when the L2 proofs were captured.
    bundle?: {parts: ArbitrumBundleParts; proofBytes: Hex; items: Hex[]};
    l2StateProof: Hex;
}

export interface ArbitrumLiveProof {
    lightClient: LiveLightClient;
    l1StateRoot: Hex;
    attestedSlot: bigint;
    profile: ArbitrumProfile;
    trustAnchor: Hex;
    channelContext: Hex;
    channelId: Hex;
    l2Account: Hex;
    l2CodeHash: Hex;
    confirmed: AssertionCase;
    pending: AssertionCase | null;
    forged: {assertionHash: Hex; preimage: Hex; assertionProof: unknown[]};
    rotation: {lightClientProof: Hex; l1StateRoot: Hex; confirmed: AssertionCase; nextPeriod: bigint} | null;
}

function l2Parts(a: AssertionCapture, slots: Hex[]): Pick<ArbitrumBundleParts, "l2AccountProof" | "l2StorageProof"> | null {
    if (!a.l2Proof) return null;
    if (a.l2Proof.storageProof.length !== slots.length) throw new Error("L2 proof slot count");
    return {l2AccountProof: accountNodes(a.l2Proof), l2StorageProof: storageEntries(a.l2Proof, slots)};
}

function assertionCase(a: AssertionCapture, l1: L1Capture, lightClientProof: Hex, slots: Hex[]): AssertionCase {
    const {preimage, hash} = assertionPreimage(a.parent, stateOf(a), a.inboxAcc);
    if (hash !== a.hash.toLowerCase()) throw new Error("assertion hash");
    if (a.afterState.machineStatus !== MACHINE_STATUS.FINISHED) throw new Error("machine not FINISHED");
    const l2Header = encodeHeader(a.l2Header);
    if (a.l2Header.hash.toLowerCase() !== a.afterState.blockHash.toLowerCase()) throw new Error("L2 block hash");
    const assertionProof = assertionProofItem(l1.rollupProof, a.hash);
    const base = {lightClientProof, assertionProof, assertionPreimage: preimage, l2Header};
    const out: AssertionCase = {
        assertionHash: a.hash,
        status: decodeAssertionNode(a.node).status,
        preimage,
        l2Header,
        l2BlockHash: a.afterState.blockHash,
        l2StateRoot: a.l2Header.stateRoot,
        l2BlockNumber: BigInt(a.l2Header.number),
        sendRoot: a.afterState.sendRoot,
        assertionProof,
        l2StateProof: encodeArbitrumL2StateProof(base)
    };
    const l2 = l2Parts(a, slots);
    if (l2) {
        const parts: ArbitrumBundleParts = {...base, ...l2, bundleContent: "0x"};
        out.bundle = {parts, proofBytes: encodeArbitrumBundle(parts), items: bundleItems(parts)};
    }
    return out;
}

function checkL1(l1: L1Capture, executionStateRoot: string, blockNumber: string): void {
    if (l1.stateRoot.toLowerCase() !== executionStateRoot.toLowerCase() || l1.blockNumber !== BigInt(blockNumber).toString()) {
        throw new Error(`L1 capture at #${l1.blockNumber} != attested execution block #${blockNumber}`);
    }
}

/// Light-client proof that also rotates: the rotation update's attested header / aggregate / execution
/// branch, with `next_sync_committee` + branch in items 4–5 (EthBeaconLightClient.verifyRotation).
function rotationLightClient(beacon: BeaconCapture): {lc: LiveLightClient; proof: Hex; nextPeriod: bigint} {
    const ru = beacon.rotationUpdate!;
    const lc = buildLiveLightClient({...beacon, finalityUpdate: {version: ru.version, data: {...ru.data}}});
    const items = rlpDecode(hexToBuf(lc.lightClientProof)) as unknown[];
    const next = decodeCommittee(ru.data.next_sync_committee);
    items[4] = [next.pubkeys, next.aggregate];
    items[5] = ru.data.next_sync_committee_branch.map(hexToBuf);
    const spp = BigInt(beacon.spec.SLOTS_PER_EPOCH) * BigInt(beacon.spec.EPOCHS_PER_SYNC_COMMITTEE_PERIOD);
    return {
        lc,
        proof: ("0x" + rlpEncode(items as never).toString("hex")) as Hex,
        nextPeriod: BigInt(ru.data.attested_header.beacon.slot) / spp + 1n
    };
}

/// Pure/offline: the capture → verifier inputs, cross-checking every link.
export function buildArbitrumLiveProof(c: ArbitrumLiveCapture, net: ArbitrumLiveNetwork = ARBITRUM_SEPOLIA): ArbitrumLiveProof {
    if (c.network !== net.name) throw new Error(`capture is for "${c.network}", not "${net.name}"`);
    const lightClient = buildLiveLightClient(c.beacon);
    const exec = c.beacon.finalityUpdate.data.attested_header.execution;
    checkL1(c.l1, exec.state_root, exec.block_number);
    const p = c.l1.rollupProof;
    const profile: ArbitrumProfile = {
        rollup: net.rollup,
        rollupAdminLogic: slotHex(BigInt(p.storageProof[0].value)).replace(/^0x0{24}/, "0x") as Hex,
        rollupUserLogic: slotHex(BigInt(p.storageProof[1].value)).replace(/^0x0{24}/, "0x") as Hex,
        layout: net.layout
    };
    const channelId = net.channelId;
    const slots = deriveChannelSlots(channelId);
    const lcProof = lightClient.lightClientProof;
    const confirmed = assertionCase(c.l1.confirmed, c.l1, lcProof, slots);
    if (confirmed.status !== ASSERTION_STATUS.CONFIRMED) throw new Error("confirmed case not Confirmed");
    let pending = c.l1.pending ? assertionCase(c.l1.pending, c.l1, lcProof, slots) : null;
    const f = forged(c.l1.confirmed);
    const l2CodeHash = (c.l1.confirmed.l2Proof?.codeHash ?? "0x") as Hex;
    if (!c.l1.confirmed.l2Proof) throw new Error("capture lacks the confirmed assertion's L2 proof");

    let rotation: ArbitrumLiveProof["rotation"] = null;
    const ru = c.beacon.rotationUpdate;
    const spp = BigInt(c.beacon.spec.SLOTS_PER_EPOCH) * BigInt(c.beacon.spec.EPOCHS_PER_SYNC_COMMITTEE_PERIOD);
    if (c.rotation && ru && BigInt(ru.data.signature_slot) / spp === lightClient.period) {
        const r = rotationLightClient(c.beacon);
        const rexec = ru.data.attested_header.execution;
        checkL1(c.rotation, rexec.state_root, rexec.block_number);
        rotation = {lightClientProof: r.proof, l1StateRoot: c.rotation.stateRoot,
            confirmed: assertionCase(c.rotation.confirmed, c.rotation, r.proof, slots), nextPeriod: r.nextPeriod};
        // No child at the main block: the rotation block's Pending child (under the rotating proof) serves.
        if (!pending && c.rotation.pending) pending = assertionCase(c.rotation.pending, c.rotation, r.proof, slots);
    }

    const trustAnchor = encodeEthTrustAnchor(channelId, l2CodeHash, lightClient.committee,
        {gvr: c.beacon.genesisValidatorsRoot as Hex, forkVersion: lightClient.signed.forkVersion});
    return {
        lightClient,
        l1StateRoot: c.l1.stateRoot,
        attestedSlot: BigInt(c.beacon.finalityUpdate.data.attested_header.beacon.slot),
        profile,
        trustAnchor,
        channelContext: (channelId + net.l2Account.slice(2).toLowerCase()) as Hex,
        channelId,
        l2Account: net.l2Account,
        l2CodeHash,
        confirmed,
        pending,
        forged: {assertionHash: f.hash, preimage: f.preimage, assertionProof: assertionProofItem(c.l1.rollupProof, f.hash)},
        rotation
    };
}

const encItem = (x: unknown) => ("0x" + rlpEncode(x as never).toString("hex")) as Hex;

/// The Foundry fixture: everything as hex, top-level bundle items pre-encoded for splicing.
export function foundryFixture(p: ArbitrumLiveProof): Record<string, unknown> {
    // Only what the Foundry tests read: spliceable items for the main case, bundles where replayed.
    const caseJson = (a: AssertionCase, withBundle = false, withItems = false) => ({
        assertionHash: a.assertionHash,
        status: a.status,
        preimage: a.preimage,
        l2Header: a.l2Header,
        l2BlockHash: a.l2BlockHash,
        l2StateRoot: a.l2StateRoot,
        l2BlockNumber: a.l2BlockNumber.toString(),
        sendRoot: a.sendRoot,
        assertionProofItem: encItem(a.assertionProof),
        l2StateProof: a.l2StateProof,
        bundle: withBundle ? a.bundle?.proofBytes ?? "0x" : "0x",
        items: withItems ? a.bundle?.items ?? [] : []
    });
    return {
        note: "generated by test/e2e/relay/buildArbitrumLiveProof.ts from test/e2e/fixtures/arbitrum-live/capture.json",
        l1StateRoot: p.l1StateRoot,
        attestedSlot: p.attestedSlot.toString(),
        rollup: p.profile.rollup,
        rollupAdminLogic: p.profile.rollupAdminLogic,
        rollupUserLogic: p.profile.rollupUserLogic,
        trustAnchor: p.trustAnchor,
        channelContext: p.channelContext,
        channelId: p.channelId,
        l2Account: p.l2Account,
        l2CodeHash: p.l2CodeHash,
        lightClientProof: p.lightClient.lightClientProof,
        confirmed: caseJson(p.confirmed, true, true),
        hasPending: p.pending !== null,
        pending: p.pending ? caseJson(p.pending) : caseJson(p.confirmed),
        forged: {assertionHash: p.forged.assertionHash, preimage: p.forged.preimage,
            assertionProofItem: encItem(p.forged.assertionProof)},
        hasRotation: p.rotation !== null,
        hasRotationBundle: p.rotation !== null && p.rotation.confirmed.bundle !== undefined,
        rotation: p.rotation
            ? {lightClientProof: p.rotation.lightClientProof, l1StateRoot: p.rotation.l1StateRoot,
                nextPeriod: p.rotation.nextPeriod.toString(), confirmed: caseJson(p.rotation.confirmed, true)}
            : {lightClientProof: "0x", l1StateRoot: "0x" + "00".repeat(32), nextPeriod: "0", confirmed: caseJson(p.confirmed)}
    };
}

export function loadArbitrumLiveCapture(file = ARBITRUM_LIVE_FIXTURE): ArbitrumLiveCapture {
    return JSON.parse(readFileSync(file, "utf8")) as ArbitrumLiveCapture;
}

export function loadArbitrumLiveCaptureFor(net: ArbitrumLiveNetwork): ArbitrumLiveCapture {
    return loadArbitrumLiveCapture(net.fixture);
}

function summarize(p: ArbitrumLiveProof): string {
    const a = (x: AssertionCase) => `${x.assertionHash.slice(0, 18)}… status ${x.status} L2 #${x.l2BlockNumber} ` +
        `${x.bundle ? `full bundle ${(x.bundle.proofBytes.length - 2) / 2} B` : "to L2 state root"}`;
    return [
        `L1 slot ${p.attestedSlot}, state_root ${p.l1StateRoot}, participation ${p.lightClient.signed.participants}/512`,
        `rollup ${p.profile.rollup} admin ${p.profile.rollupAdminLogic} user ${p.profile.rollupUserLogic}`,
        `confirmed ${a(p.confirmed)}`,
        `pending   ${p.pending ? a(p.pending) : "none"}`,
        `rotation  ${p.rotation ? `next period ${p.rotation.nextPeriod}, ${a(p.rotation.confirmed)}` : "none"}`
    ].join("\n");
}

async function main(): Promise<void> {
    const args = process.argv.slice(2);
    const netIdx = args.indexOf("--network");
    const net = ARBITRUM_LIVE_NETWORKS[netIdx >= 0 ? args[netIdx + 1] : "arbitrum-sepolia"];
    if (!net) throw new Error(`unknown --network; one of ${Object.keys(ARBITRUM_LIVE_NETWORKS).join(", ")}`);
    let capture!: ArbitrumLiveCapture;
    if (args.includes("--refresh")) {
        const waitIdx = args.indexOf("--wait-nonsigners");
        // --require-pending MINS: re-capture until the latest confirmed assertion has a (Pending) child at
        // the attested block, so the fixture carries a real Pending assertion for the negative test. A
        // child exists for the ~20+ L1 blocks between its creation and its confirmation.
        const pendIdx = args.indexOf("--require-pending");
        const pendDeadline = Date.now() + (pendIdx >= 0 ? Number(args[pendIdx + 1]) * 60_000 : 0);
        for (;;) {
            capture = await captureArbitrumLive(net, {waitForNonSignersMs: waitIdx >= 0 ? Number(args[waitIdx + 1]) * 1000 : 0});
            // A finality update below 2/3 participation (seen once on mainnet: 315/512) cannot verify: take the next.
            const participants = buildLiveLightClient(capture.beacon).signed.participants;
            if (3 * participants < 2 * 512) {
                console.log(`participation ${participants}/512 is below 2/3: re-capturing`);
                continue;
            }
            const hasPending = capture.l1.pending !== null || (capture.rotation?.pending ?? null) !== null;
            if ((hasPending && capture.l1.confirmed.l2Proof) || Date.now() > pendDeadline) break;
            console.log(`retrying in 60 s (pending: ${hasPending}, confirmed L2 proof: ${capture.l1.confirmed.l2Proof !== null})`);
            await new Promise((r) => setTimeout(r, 60_000));
        }
        buildArbitrumLiveProof(capture, net); // validate before writing
        mkdirSync(path.dirname(net.fixture), {recursive: true});
        writeFileSync(net.fixture, JSON.stringify(capture, null, 1) + "\n");
        console.log(`captured → ${path.relative(process.cwd(), net.fixture)}`);
    } else {
        capture = loadArbitrumLiveCaptureFor(net);
    }
    const built = buildArbitrumLiveProof(capture, net);
    mkdirSync(path.dirname(net.foundryFixture), {recursive: true});
    writeFileSync(net.foundryFixture, JSON.stringify(foundryFixture(built), null, 1) + "\n");
    console.log(summarize(built));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    main().catch((err) => {
        console.error(err);
        process.exit(1);
    });
}
