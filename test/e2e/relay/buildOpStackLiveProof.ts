import {existsSync, mkdirSync, readdirSync, readFileSync, unlinkSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {decodeAbiParameters, encodeFunctionData, keccak256, toHex, type Hex} from "viem";
import {deriveChannelSlots, encodeEthTrustAnchor, type EthGetProofResult} from "./buildEthMainnetProof.js";
import {
    buildLiveLightClient,
    captureBeaconLive,
    DEFAULT_BEACON_APIS,
    DEFAULT_EXECUTION_RPC,
    getJson,
    rpc,
    type BeaconCapture,
    type LiveLightClient
} from "./buildEthLiveProof.js";
import {
    accountNodes,
    asrSlots,
    BASE_SEPOLIA_LAYOUT,
    dgfGameSlot,
    encodeOpStackBundle,
    encodeOpStackL2StateRootProof,
    GAME_STATUS,
    gameUuid,
    MODE,
    outputRootPreimage,
    ROOT_FORMAT,
    slotHex,
    storageEntries,
    type DisputeProofParts,
    type OpStackProfile
} from "./opstack.js";

/// Live-data proof builder for the OP Stack verifiers, on Base Sepolia settling on Ethereum Sepolia.
///
/// Chain of real data:
///   Sepolia sync committee (finality_update, bootstrap) → attested execution block B
///   → eth_getProof at B of Base Sepolia's AnchorStateRegistry (+ its implementation), the
///     DisputeGameFactory `_disputeGames[uuid]` entries and each dispute game's slot 0 (+ code)
///   → the game's root claim == keccak(0 ‖ L2 stateRoot ‖ withdrawalsRoot ‖ L2 blockHash) of the L2
///     block it claims (since Isthmus the header's withdrawalsRoot is the L2ToL1MessagePasser storage
///     root, so the preimage comes straight from the L2 header)
///   → eth_getProof on Base Sepolia at that block (ClprService stand-in: the L2ToL1MessagePasser
///     predeploy, whose real code hash is pinned; the channel slots are absent → exclusion proofs).
///
/// Which games the fixture carries:
///   - `anchor`   ASR.anchorGame: ANCHOR mode and GAME mode (it is a resolved DEFENDER_WINS game).
///                Its L2 block is ≥ the chain's proof-maturity age (~5 days on Base Sepolia), outside
///                every public RPC's eth_getProof window, so its L2 account proof is usually absent and
///                the FINALIZED path is checked on-chain up to the L2 state root (`verifyL2StateRoot`).
///   - `newest`   the newest DGF game at B (IN_PROGRESS): full `verifyBundle` through the PROPOSED tier,
///                L2 proofs included; the FINALIZED tier rejects it.
///   - `pending`  games staged by an EARLIER refresh (their L2 proofs captured while recent) that have
///                since finalized: full FINALIZED `verifyBundle`. Every refresh stages its `newest` game
///                under `pending/`, so a refresh ≥ the finality period later yields this case.
///
/// CLI:
///   npx tsx test/e2e/relay/buildOpStackLiveProof.ts                     build from the fixture, print a summary
///   npx tsx test/e2e/relay/buildOpStackLiveProof.ts --refresh [--wait-nonsigners SECS]

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const BASE_SEPOLIA_FIXTURE_DIR = path.resolve(__dirname, "../fixtures/base-sepolia-live");
export const BASE_SEPOLIA_LIVE_FIXTURE = path.join(BASE_SEPOLIA_FIXTURE_DIR, "capture.json");
const PENDING_DIR = path.join(BASE_SEPOLIA_FIXTURE_DIR, "pending");

/// Base Sepolia (Superchain registry, chain 84532) on Ethereum Sepolia.
export const BASE_SEPOLIA = {
    l2ChainId: 84532,
    optimismPortal: "0x49f53e41452C74589E85cA1677426Ba426459e85" as Hex,
    anchorStateRegistry: "0x2fF5cC82dBf333Ea30D8ee462178ab1707315355" as Hex,
    l2Rpcs: ["https://sepolia.base.org", "https://base-sepolia-rpc.publicnode.com"],
    layout: BASE_SEPOLIA_LAYOUT
};
/// L2ToL1MessagePasser predeploy: a real contract with real code and storage on every OP Stack chain.
export const L2_ACCOUNT: Hex = "0x4200000000000000000000000000000000000016";
export const OPSTACK_LIVE_CHANNEL_ID: Hex = keccak256(toHex("clpr/opstack-live/base-sepolia"));
export const L1_SECONDS_PER_SLOT = 12n;

// ── ABI fragments ──────────────────────────────────────────────────────────
const ABI = [
    {type: "function", name: "gameCount", inputs: [], outputs: [{type: "uint256"}], stateMutability: "view"},
    {type: "function", name: "gameAtIndex", inputs: [{type: "uint256"}],
        outputs: [{type: "uint32"}, {type: "uint64"}, {type: "address"}], stateMutability: "view"},
    {type: "function", name: "gameImpls", inputs: [{type: "uint32"}], outputs: [{type: "address"}], stateMutability: "view"},
    {type: "function", name: "disputeGameFinalityDelaySeconds", inputs: [], outputs: [{type: "uint256"}], stateMutability: "view"},
    {type: "function", name: "anchorStateRegistry", inputs: [], outputs: [{type: "address"}], stateMutability: "view"},
    {type: "function", name: "gameType", inputs: [], outputs: [{type: "uint32"}], stateMutability: "view"},
    {type: "function", name: "rootClaim", inputs: [], outputs: [{type: "bytes32"}], stateMutability: "view"},
    {type: "function", name: "extraData", inputs: [], outputs: [{type: "bytes"}], stateMutability: "view"},
    {type: "function", name: "l2SequenceNumber", inputs: [], outputs: [{type: "uint256"}], stateMutability: "view"}
] as const;

async function call<T>(url: string, to: Hex, fn: string, args: unknown[], blockTag: Hex | "latest"): Promise<T> {
    const item = ABI.find((a) => a.name === fn)!;
    const data = encodeFunctionData({abi: [item], functionName: fn as never, args: args as never});
    const out = await rpc<Hex>(url, "eth_call", [{to, data}, blockTag]);
    const decoded = decodeAbiParameters(item.outputs, out);
    return (decoded.length === 1 ? decoded[0] : decoded) as T;
}

async function l2rpc<T>(method: string, params: unknown[]): Promise<T> {
    let lastErr: unknown;
    for (const url of BASE_SEPOLIA.l2Rpcs) {
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

export interface CapturedGame {
    address: Hex;
    gameType: number;
    rootClaim: Hex;
    extraData: Hex;
    l2BlockNumber: string;
    code: Hex;
    proof: EthGetProofResult; // slot 0 at B
    l2: L2Output;
}

export interface OpStackLiveCapture {
    network: string;
    capturedAt: string;
    sources: {beaconApi: string; l1Rpc: string; l2Rpcs: string[]};
    beacon: BeaconCapture;
    l1: {
        genesisTime: string;
        block: {number: string; hash: Hex; stateRoot: Hex; timestamp: string};
        anchorStateRegistry: Hex;
        asrImplementation: Hex;
        disputeGameFinalityDelaySeconds: string;
        disputeGameFactory: Hex;
        respectedGameType: number;
        gameImplementation: Hex;
        asrProof: EthGetProofResult;
        asrImplProof: EthGetProofResult;
        dgfProof: EthGetProofResult;
    };
    games: {anchor: CapturedGame; newest: CapturedGame; pending: CapturedGame[]};
}

interface PendingStage {
    address: Hex;
    gameType: number;
    rootClaim: Hex;
    extraData: Hex;
    l2BlockNumber: string;
    l2: L2Output;
}

async function captureL2Output(blockNumber: bigint, withProof: boolean): Promise<L2Output> {
    const tag = "0x" + blockNumber.toString(16);
    const h = await l2rpc<{hash: Hex; stateRoot: Hex; withdrawalsRoot: Hex}>("eth_getBlockByNumber", [tag, false]);
    let proof: L2Output["proof"] = null;
    if (withProof) {
        try {
            proof = await l2rpc<NonNullable<L2Output["proof"]>>("eth_getProof", [L2_ACCOUNT, deriveChannelSlots(OPSTACK_LIVE_CHANNEL_ID), tag]);
        } catch (err) {
            console.error(`L2 eth_getProof at ${blockNumber} unavailable: ${String(err).slice(0, 120)}`);
        }
    }
    return {blockNumber: blockNumber.toString(), header: {hash: h.hash, stateRoot: h.stateRoot, withdrawalsRoot: h.withdrawalsRoot}, proof};
}

function loadPending(): PendingStage[] {
    if (!existsSync(PENDING_DIR)) return [];
    return readdirSync(PENDING_DIR).filter((f) => f.endsWith(".json"))
        .map((f) => JSON.parse(readFileSync(path.join(PENDING_DIR, f), "utf8")) as PendingStage);
}

/// Capture everything at one attested L1 block. L1 reads happen inside the beacon hook (non-archive
/// window); L2 reads follow (Base Sepolia's public RPC serves eth_getProof ~5,000 blocks back).
export async function captureBaseSepoliaLive(opts: {
    beaconApis?: string[];
    l1Rpc?: string;
    waitForNonSignersMs?: number;
} = {}): Promise<OpStackLiveCapture> {
    const l1Rpc = opts.l1Rpc ?? DEFAULT_EXECUTION_RPC;
    const L = BASE_SEPOLIA.layout;
    const asr = BASE_SEPOLIA.anchorStateRegistry;
    const pending = loadPending();

    const {beacon, extra} = await captureBeaconLive(opts, async (_execution, B) => {
        const portalAsr = await call<Hex>(l1Rpc, BASE_SEPOLIA.optimismPortal, "anchorStateRegistry", [], B);
        if (portalAsr.toLowerCase() !== asr.toLowerCase()) throw new Error(`portal ASR moved to ${portalAsr}`);
        const head = await rpc<EthGetProofResult>(l1Rpc, "eth_getProof", [asr, asrSlots(L), B]);
        const v = new Map(head.storageProof.map((sp) => [BigInt(sp.key), BigInt(sp.value)]));
        const dgf = slotHex(v.get(L.asrDisputeGameFactorySlot)!).replace(/^0x0{24}/, "0x") as Hex;
        const respectedGameType = Number(v.get(L.asrRespectedGameTypeSlot)! & 0xffffffffn);
        const impl = ("0x" + v.get(BigInt(asrSlots(L)[2]))!.toString(16).padStart(40, "0")) as Hex;
        const anchorGame = ("0x" + v.get(L.asrAnchorGameSlot)!.toString(16).padStart(40, "0")) as Hex;
        const count = await call<bigint>(l1Rpc, dgf, "gameCount", [], B);
        const [, , newestAddr] = await call<[number, bigint, Hex]>(l1Rpc, dgf, "gameAtIndex", [count - 1n], B);

        const readGame = async (address: Hex) => {
            const [gameType, rootClaim, extraData, l2BlockNumber] = await Promise.all([
                call<number>(l1Rpc, address, "gameType", [], B),
                call<Hex>(l1Rpc, address, "rootClaim", [], B),
                call<Hex>(l1Rpc, address, "extraData", [], B),
                call<bigint>(l1Rpc, address, "l2SequenceNumber", [], B)
            ]);
            const proof = await rpc<EthGetProofResult>(l1Rpc, "eth_getProof", [address, [slotHex(L.gameStateSlot)], B]);
            const code = await rpc<Hex>(l1Rpc, "eth_getCode", [address, B]);
            return {address, gameType, rootClaim, extraData, l2BlockNumber: l2BlockNumber.toString(), code, proof};
        };
        const anchor = await readGame(anchorGame);
        const newest = await readGame(newestAddr);
        const pend = await Promise.all(pending.map((p) => readGame(p.address)));
        const all = [anchor, newest, ...pend];

        const asrProof = await rpc<EthGetProofResult>(l1Rpc, "eth_getProof", [asr, asrSlots(L, all.map((g) => g.address)), B]);
        const asrImplProof = await rpc<EthGetProofResult>(l1Rpc, "eth_getProof", [impl, [], B]);
        const dgfProof = await rpc<EthGetProofResult>(l1Rpc, "eth_getProof",
            [dgf, all.map((g) => dgfGameSlot(gameUuid(g.gameType, g.rootClaim, g.extraData), L)), B]);
        const block = await rpc<{number: string; hash: Hex; stateRoot: Hex; timestamp: string}>(
            l1Rpc, "eth_getBlockByNumber", [B, false]);
        const delay = await call<bigint>(l1Rpc, asr, "disputeGameFinalityDelaySeconds", [], B);
        const gameImplementation = await call<Hex>(l1Rpc, dgf, "gameImpls", [respectedGameType], B);
        return {
            anchor, newest, pend,
            l1: {
                block: {number: block.number, hash: block.hash, stateRoot: block.stateRoot, timestamp: block.timestamp},
                anchorStateRegistry: asr,
                asrImplementation: impl,
                disputeGameFinalityDelaySeconds: delay.toString(),
                disputeGameFactory: dgf,
                respectedGameType,
                gameImplementation,
                asrProof, asrImplProof, dgfProof
            }
        };
    });

    const {json: genesis} = await getJson<{data: {genesis_time: string}}>(
        [beacon.sources.beaconApi, ...(opts.beaconApis ?? DEFAULT_BEACON_APIS)], "/eth/v1/beacon/genesis");
    const l2Of = async (g: {l2BlockNumber: string}, withProof: boolean) => captureL2Output(BigInt(g.l2BlockNumber), withProof);
    const anchor = {...extra.anchor, l2: await l2Of(extra.anchor, true)};
    const newest = {...extra.newest, l2: await l2Of(extra.newest, true)};
    const pend = extra.pend.map((g) => {
        const stage = pending.find((p) => p.address.toLowerCase() === g.address.toLowerCase())!;
        return {...g, l2: stage.l2};
    });

    return {
        network: "base-sepolia on " + beacon.network,
        capturedAt: new Date().toISOString(),
        sources: {beaconApi: beacon.sources.beaconApi, l1Rpc, l2Rpcs: BASE_SEPOLIA.l2Rpcs},
        beacon: {...beacon, sources: {beaconApi: beacon.sources.beaconApi, executionRpc: l1Rpc}},
        l1: {genesisTime: genesis.data.genesis_time, ...extra.l1},
        games: {anchor, newest, pending: pend}
    };
}

// ── Pure builder ───────────────────────────────────────────────────────────
export interface OpStackLiveGameCase {
    game: Hex;
    gameType: number;
    status: number;
    createdAt: bigint;
    resolvedAt: bigint;
    l2BlockNumber: bigint;
    outputRoot: Hex;
    l2StateRoot: Hex;
    dispute: DisputeProofParts;
    /// `verifyL2StateRoot` input (items 0–2).
    l2StateRootProof: Hex;
    /// Full `verifyBundle` proof, when the L2 account proof is available.
    bundle: Hex | null;
}

export interface OpStackLiveProof {
    lightClient: LiveLightClient;
    l1Time: bigint;
    l1GenesisTime: bigint;
    profile: OpStackProfile;
    trustAnchor: Hex;
    channelContext: Hex;
    channelId: Hex;
    l2Account: Hex;
    l2CodeHash: Hex;
    respectedGameType: number;
    anchorMode: OpStackLiveGameCase;
    anchorGame: OpStackLiveGameCase;
    newest: OpStackLiveGameCase;
    pendingFinalized: OpStackLiveGameCase[];
}

function unpackGameState(word: bigint) {
    const L = BASE_SEPOLIA.layout;
    const f = (off: bigint, bits: bigint) => (word >> (off * 8n)) & ((1n << bits) - 1n);
    return {
        createdAt: f(L.gameCreatedAtOffset, 64n),
        resolvedAt: f(L.gameResolvedAtOffset, 64n),
        status: Number(f(L.gameStatusOffset, 8n)),
        wasRespected: f(L.gameWasRespectedOffset, 8n) !== 0n
    };
}

/// Pure/offline: turn a capture into verifier inputs, cross-checking every link off-chain.
export function buildOpStackLiveProof(c: OpStackLiveCapture): OpStackLiveProof {
    const L = BASE_SEPOLIA.layout;
    const lightClient = buildLiveLightClient(c.beacon);
    const attested = c.beacon.finalityUpdate.data.attested_header;

    // L1 binding: the proofs were taken at the attested execution block, whose time is the slot's.
    if (BigInt(c.l1.block.number) !== BigInt(attested.execution.block_number)) throw new Error("L1 block != attested block");
    if (c.l1.block.stateRoot.toLowerCase() !== attested.execution.state_root.toLowerCase()) throw new Error("L1 stateRoot mismatch");
    const l1GenesisTime = BigInt(c.l1.genesisTime);
    const l1Time = l1GenesisTime + BigInt(attested.beacon.slot) * L1_SECONDS_PER_SLOT;
    if (l1Time !== BigInt(attested.execution.timestamp) || l1Time !== BigInt(c.l1.block.timestamp)) {
        throw new Error("genesis_time + slot × 12 != execution timestamp");
    }

    const profile: OpStackProfile = {
        rootFormat: ROOT_FORMAT.OUTPUT_ROOT,
        l2ChainId: BigInt(BASE_SEPOLIA.l2ChainId),
        anchorStateRegistry: c.l1.anchorStateRegistry,
        anchorStateRegistryImplCodeHash: c.l1.asrImplProof.codeHash as Hex,
        disputeGameFinalityDelaySeconds: BigInt(c.l1.disputeGameFinalityDelaySeconds),
        gameImplementation: c.l1.gameImplementation,
        layout: L
    };

    const all = [c.games.anchor, c.games.newest, ...c.games.pending];
    const asrKeys = asrSlots(L, all.map((g) => g.address));
    const dgfKeys = all.map((g) => dgfGameSlot(gameUuid(g.gameType, g.rootClaim, g.extraData), L));
    const base = {
        asrAccountProof: accountNodes(c.l1.asrProof),
        asrStorageProof: storageEntries(c.l1.asrProof, asrKeys),
        asrImplAccountProof: accountNodes(c.l1.asrImplProof),
        dgfAccountProof: accountNodes(c.l1.dgfProof),
        dgfStorageProof: storageEntries(c.l1.dgfProof, dgfKeys)
    };

    // The L2 account whose code hash the anchor pins: taken from any available L2 proof.
    const withProof = all.find((g) => g.l2.proof)?.l2.proof;
    if (!withProof) throw new Error("capture has no L2 account proof");
    const l2CodeHash = withProof.codeHash as Hex;
    const channelId = OPSTACK_LIVE_CHANNEL_ID;
    const trustAnchor = encodeEthTrustAnchor(channelId, l2CodeHash, lightClient.committee, {
        gvr: c.beacon.genesisValidatorsRoot as Hex, forkVersion: lightClient.signed.forkVersion
    });
    const channelContext = (channelId + L2_ACCOUNT.slice(2).toLowerCase()) as Hex;
    const chSlots = deriveChannelSlots(channelId);

    const gameCase = (g: CapturedGame, mode: number): OpStackLiveGameCase => {
        const {preimage, outputRoot} = outputRootPreimage(g.l2.header.stateRoot, g.l2.header.withdrawalsRoot, g.l2.header.hash);
        if (outputRoot !== g.rootClaim.toLowerCase() && outputRoot !== g.rootClaim) {
            throw new Error(`game ${g.address}: output root ${outputRoot} != rootClaim ${g.rootClaim}`);
        }
        const st = unpackGameState(BigInt(g.proof.storageProof[0].value));
        if (g.l2.proof && g.l2.proof.storageHash.toLowerCase() !== g.l2.header.withdrawalsRoot.toLowerCase()) {
            throw new Error("L2ToL1MessagePasser storage root != header withdrawalsRoot");
        }
        const dispute: DisputeProofParts = {
            ...base,
            mode,
            gameType: g.gameType,
            extraData: g.extraData,
            gameAccountProof: mode === MODE.GAME ? accountNodes(g.proof) : [],
            gameCode: mode === MODE.GAME ? g.code : "0x",
            gameStorageProof: mode === MODE.GAME ? storageEntries(g.proof, [slotHex(L.gameStateSlot)]) : []
        };
        const common = {lightClientProof: lightClient.lightClientProof, dispute, outputRootPreimage: preimage};
        return {
            game: g.address,
            gameType: g.gameType,
            status: st.status,
            createdAt: st.createdAt,
            resolvedAt: st.resolvedAt,
            l2BlockNumber: BigInt(g.l2BlockNumber),
            outputRoot,
            l2StateRoot: g.l2.header.stateRoot,
            dispute,
            l2StateRootProof: encodeOpStackL2StateRootProof(common),
            bundle: g.l2.proof ? encodeOpStackBundle({
                ...common,
                l2AccountProof: accountNodes(g.l2.proof),
                l2StorageProof: storageEntries(g.l2.proof, chSlots),
                bundleContent: "0x"
            }) : null
        };
    };

    const finalizedAt = (x: OpStackLiveGameCase) => x.status === GAME_STATUS.DEFENDER_WINS && x.resolvedAt !== 0n
        && l1Time - x.resolvedAt > profile.disputeGameFinalityDelaySeconds;
    return {
        lightClient,
        l1Time,
        l1GenesisTime,
        profile,
        trustAnchor,
        channelContext,
        channelId,
        l2Account: L2_ACCOUNT,
        l2CodeHash,
        respectedGameType: c.l1.respectedGameType,
        anchorMode: gameCase(c.games.anchor, MODE.ANCHOR),
        anchorGame: gameCase(c.games.anchor, MODE.GAME),
        newest: gameCase(c.games.newest, MODE.GAME),
        pendingFinalized: c.games.pending.map((g) => gameCase(g, MODE.GAME)).filter(finalizedAt)
    };
}

export function loadOpStackLiveCapture(file = BASE_SEPOLIA_LIVE_FIXTURE): OpStackLiveCapture {
    return JSON.parse(readFileSync(file, "utf8")) as OpStackLiveCapture;
}

function summarize(p: OpStackLiveProof): string {
    const g = (x: OpStackLiveGameCase) =>
        `${x.game} type ${x.gameType} status ${x.status} L2 #${x.l2BlockNumber} root ${x.outputRoot.slice(0, 18)}… ` +
        `${x.bundle ? "full bundle" : "to L2 state root"}`;
    return [
        `L1 slot ${(p.l1Time - p.l1GenesisTime) / L1_SECONDS_PER_SLOT} (time ${p.l1Time}), ` +
            `participation ${p.lightClient.signed.participants}/512`,
        `ASR ${p.profile.anchorStateRegistry} impl codeHash ${p.profile.anchorStateRegistryImplCodeHash}`,
        `respected game type ${p.respectedGameType}, finality delay ${p.profile.disputeGameFinalityDelaySeconds}s, ` +
            `game impl ${p.profile.gameImplementation}`,
        `anchor  ${g(p.anchorGame)}`,
        `newest  ${g(p.newest)}`,
        `pending finalized: ${p.pendingFinalized.length}`
    ].join("\n");
}

async function main(): Promise<void> {
    const args = process.argv.slice(2);
    let capture: OpStackLiveCapture;
    if (args.includes("--refresh")) {
        const waitIdx = args.indexOf("--wait-nonsigners");
        capture = await captureBaseSepoliaLive({
            waitForNonSignersMs: waitIdx >= 0 ? Number(args[waitIdx + 1]) * 1000 : 0
        });
        const built = buildOpStackLiveProof(capture); // validate before writing
        mkdirSync(PENDING_DIR, {recursive: true});
        writeFileSync(BASE_SEPOLIA_LIVE_FIXTURE, JSON.stringify(capture, null, 1) + "\n");
        // Stage the newest game (its L2 proofs are only fetchable now) for a later FINALIZED capture.
        const n = capture.games.newest;
        if (n.l2.proof) {
            const stage: PendingStage = {address: n.address, gameType: n.gameType, rootClaim: n.rootClaim,
                extraData: n.extraData, l2BlockNumber: n.l2BlockNumber, l2: n.l2};
            writeFileSync(path.join(PENDING_DIR, `${n.address.toLowerCase()}.json`), JSON.stringify(stage, null, 1) + "\n");
        }
        // Prune the stage: keep games still in progress and the most recent finalized one.
        const keep = new Set<string>([n.address.toLowerCase()]);
        const lastFinal = built.pendingFinalized.at(-1);
        if (lastFinal) keep.add(lastFinal.game.toLowerCase());
        for (const g of capture.games.pending) {
            if (unpackGameState(BigInt(g.proof.storageProof[0].value)).status === GAME_STATUS.IN_PROGRESS) {
                keep.add(g.address.toLowerCase());
            }
        }
        for (const f of readdirSync(PENDING_DIR)) {
            if (f.endsWith(".json") && !keep.has(f.replace(/\.json$/, ""))) unlinkSync(path.join(PENDING_DIR, f));
        }
        console.log(`captured → ${path.relative(process.cwd(), BASE_SEPOLIA_LIVE_FIXTURE)}`);
    } else {
        capture = loadOpStackLiveCapture();
    }
    console.log(summarize(buildOpStackLiveProof(capture)));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    main().catch((err) => {
        console.error(err);
        process.exit(1);
    });
}
