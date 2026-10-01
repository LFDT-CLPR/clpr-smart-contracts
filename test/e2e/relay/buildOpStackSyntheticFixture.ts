import {spawn, type ChildProcess} from "node:child_process";
import {mkdirSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {encodeAbiParameters, encodePacked, keccak256, toHex, type Hex} from "viem";
import {rlpEncode} from "../lib/rlp.js";
import {deriveChannelSlots, type EthGetProofResult} from "./buildEthMainnetProof.js";
import {
    accountNodes,
    asrSlots,
    BASE_SEPOLIA_LAYOUT,
    cloneCode,
    dgfGameSlot,
    disputeProofItem,
    EIP1967_IMPLEMENTATION_SLOT,
    GAME_STATUS,
    gameUuid,
    MODE,
    outputRootPreimage,
    packGameId,
    slotHex,
    storageEntries,
    SUPER_FAULT_DISPUTE_GAME_LAYOUT,
    superRootPreimage,
    type DisputeProofParts
} from "./opstack.js";

/// Synthetic-state fixture for the Foundry `OpStackVerifier` unit tests.
///
/// Two throw-away anvils stand in for the chains: an "L2" holding a ClprService-shaped account with a
/// populated channel, and an "L1" holding an AnchorStateRegistry, a DisputeGameFactory and one dispute
/// game per scenario (finalized, inside the finality delay, CHALLENGER_WINS, IN_PROGRESS, blacklisted,
/// retired, wrong game type, not respected when created, wrong implementation). State is written with
/// `anvil_setStorageAt` / `anvil_setCode` using the SAME layout the verifier derives slots from, and
/// every proof comes from anvil's `eth_getProof`, so the MPT proofs are genuine. The Foundry test swaps
/// the Ethereum light client for a mock that returns this L1 state root (the BLS half is covered on
/// live data by the vitest spec).
///
/// Run: npx tsx test/e2e/relay/buildOpStackSyntheticFixture.ts   (writes the JSON fixture below)

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const SYNTHETIC_FIXTURE = path.resolve(__dirname, "../../verifiers/evm/opstack/fixtures/synthetic.json");

const L = BASE_SEPOLIA_LAYOUT;

// ── Chain parameters ───────────────────────────────────────────────────────
const RESPECTED_TYPE = 621;
const OTHER_TYPE = 1;
const RETIREMENT = 1_700_000_000n;
const FINALITY_DELAY = 302_400n; // 3.5 days
const L1_SLOT = 166_666_666n; // L1 time = slot × 12 with genesis 0
const L1_TIME = L1_SLOT * 12n;
const DAY = 86_400n;

const ASR: Hex = "0xa5a5000000000000000000000000000000000001";
const ASR_STARTING_ONLY: Hex = "0xa5a5000000000000000000000000000000000002";
const ASR_IMPL: Hex = "0xa5a5000000000000000000000000000000001111";
const ASR_IMPL_CODE: Hex = "0x6080604052348015600f57600080fd5b50"; // stand-in runtime
const DGF: Hex = "0xd6f0000000000000000000000000000000000001";
const GAME_IMPL: Hex = "0x6a3e000000000000000000000000000000000001";
const OTHER_IMPL: Hex = "0x6a3e000000000000000000000000000000000002";
const PROPOSER: Hex = "0x9999000000000000000000000000000000000001";

const SERVICE: Hex = "0x5e7c1ce1acce5e7c1ce1acce5e7c1ce1acce5e7c";
const SERVICE_CODE: Hex = "0x60806040526004361061001e5760003560e01c80";
const CHANNEL_ID: Hex = keccak256(toHex("clpr/opstack/synthetic"));
const MESSAGE_PASSER: Hex = "0x4200000000000000000000000000000000000016";
/// Super-root scenario: our chain and one other chain in the dependency set.
const L2_CHAIN_ID = 8453n;
const OTHER_CHAIN_ID = 10n;
const SUPER_GAME: Hex = "0x6a3e000000000000000000000000000000002000";
const SL = SUPER_FAULT_DISPUTE_GAME_LAYOUT;

interface GameSpec {
    name: string;
    gameType: number;
    createdAt: bigint;
    resolvedAt: bigint;
    status: number;
    wasRespected: boolean;
    impl: Hex;
    blacklisted?: boolean;
}

const GAMES: GameSpec[] = [
    {name: "finalized", gameType: RESPECTED_TYPE, createdAt: L1_TIME - 20n * DAY, resolvedAt: L1_TIME - 10n * DAY,
        status: GAME_STATUS.DEFENDER_WINS, wasRespected: true, impl: GAME_IMPL},
    {name: "insideDelay", gameType: RESPECTED_TYPE, createdAt: L1_TIME - 6n * DAY, resolvedAt: L1_TIME - FINALITY_DELAY / 2n,
        status: GAME_STATUS.DEFENDER_WINS, wasRespected: true, impl: GAME_IMPL},
    {name: "challengerWins", gameType: RESPECTED_TYPE, createdAt: L1_TIME - 20n * DAY, resolvedAt: L1_TIME - 10n * DAY,
        status: GAME_STATUS.CHALLENGER_WINS, wasRespected: true, impl: GAME_IMPL},
    {name: "inProgress", gameType: RESPECTED_TYPE, createdAt: L1_TIME - 3600n, resolvedAt: 0n,
        status: GAME_STATUS.IN_PROGRESS, wasRespected: true, impl: GAME_IMPL},
    {name: "blacklisted", gameType: RESPECTED_TYPE, createdAt: L1_TIME - 20n * DAY, resolvedAt: L1_TIME - 10n * DAY,
        status: GAME_STATUS.DEFENDER_WINS, wasRespected: true, impl: GAME_IMPL, blacklisted: true},
    {name: "retired", gameType: RESPECTED_TYPE, createdAt: RETIREMENT, resolvedAt: L1_TIME - 10n * DAY,
        status: GAME_STATUS.DEFENDER_WINS, wasRespected: true, impl: GAME_IMPL},
    {name: "wrongType", gameType: OTHER_TYPE, createdAt: L1_TIME - 20n * DAY, resolvedAt: L1_TIME - 10n * DAY,
        status: GAME_STATUS.DEFENDER_WINS, wasRespected: true, impl: GAME_IMPL},
    {name: "notRespected", gameType: RESPECTED_TYPE, createdAt: L1_TIME - 20n * DAY, resolvedAt: L1_TIME - 10n * DAY,
        status: GAME_STATUS.DEFENDER_WINS, wasRespected: false, impl: GAME_IMPL},
    {name: "wrongImpl", gameType: RESPECTED_TYPE, createdAt: L1_TIME - 20n * DAY, resolvedAt: L1_TIME - 10n * DAY,
        status: GAME_STATUS.DEFENDER_WINS, wasRespected: true, impl: OTHER_IMPL}
];

function gameAddress(i: number): Hex {
    return ("0x6a3e" + (0x1000 + i).toString(16).padStart(36, "0")) as Hex;
}

function extraDataFor(name: string): Hex {
    // l2BlockNumber (32) ‖ a per-game tag, so every game can claim the SAME output root.
    return encodePacked(["uint256", "bytes32"], [100n, keccak256(toHex(name))]);
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

const setStorage = (url: string, a: Hex, slot: Hex, v: Hex) => rpc(url, "anvil_setStorageAt", [a, slot, v]);
const setCode = (url: string, a: Hex, code: Hex) => rpc(url, "anvil_setCode", [a, code]);

function hexOf(parts: unknown): Hex {
    return ("0x" + rlpEncode(parts as never).toString("hex")) as Hex;
}

export async function buildOpStackSyntheticFixture(ports = {l2: 8611, l1: 8612}) {
    const l2 = await startAnvil(ports.l2);
    const l1 = await startAnvil(ports.l1);
    try {
        // ── L2: ClprService-shaped account with a populated channel ────────────
        await setCode(l2.url, SERVICE, SERVICE_CODE);
        const chSlots = deriveChannelSlots(CHANNEL_ID);
        const verifierAddr = 0x1234n;
        const status = 1n;
        const nextMessageId = 3n;
        const receivedMessageId = 2n;
        const sentRunningHash = keccak256(toHex("sent"));
        const receivedRunningHash = keccak256(toHex("received"));
        const manifestVersion = 1n;
        const values: Hex[] = [
            slotHex((nextMessageId << 168n) | (status << 160n) | verifierAddr),
            slotHex(receivedMessageId << 64n),
            sentRunningHash,
            receivedRunningHash,
            slotHex(manifestVersion)
        ];
        for (let i = 0; i < chSlots.length; i++) await setStorage(l2.url, SERVICE, chSlots[i], values[i]);
        await rpc(l2.url, "evm_mine", []);
        const l2Block = await rpc<{stateRoot: Hex; hash: Hex; number: Hex}>(l2.url, "eth_getBlockByNumber", ["latest", false]);
        const svc = await rpc<EthGetProofResult>(l2.url, "eth_getProof", [SERVICE, chSlots, l2Block.number]);
        const mp = await rpc<{storageHash: Hex}>(l2.url, "eth_getProof", [MESSAGE_PASSER, [], l2Block.number]);
        const {preimage, outputRoot} = outputRootPreimage(l2Block.stateRoot, mp.storageHash, l2Block.hash);
        // A preimage whose root no game claims (flip the block hash) and a non-zero-version preimage.
        const tampered = outputRootPreimage(l2Block.stateRoot, mp.storageHash, keccak256(l2Block.hash));
        const badVersion = ("0x" + "00".repeat(31) + "01" + preimage.slice(66)) as Hex;

        // ── L1: ASR + DGF + one game per scenario ─────────────────────────────
        await setCode(l1.url, ASR_IMPL, ASR_IMPL_CODE);
        const games = GAMES.map((g, i) => ({...g, address: gameAddress(i), extraData: extraDataFor(g.name)}));
        for (const g of games) {
            const args = encodePacked(["address", "bytes32", "bytes32", "bytes"], [PROPOSER, outputRoot, slotHex(0n), g.extraData]);
            await setCode(l1.url, g.address, cloneCode(g.impl, (args + "0000") as Hex));
            const state = g.createdAt | (g.resolvedAt << 64n) | (BigInt(g.status) << 128n) | (1n << 136n)
                | ((g.wasRespected ? 1n : 0n) << 144n);
            await setStorage(l1.url, g.address, slotHex(L.gameStateSlot), slotHex(state));
            await setStorage(l1.url, DGF, dgfGameSlot(gameUuid(g.gameType, outputRoot, g.extraData), L),
                packGameId(g.gameType, g.createdAt, g.address));
        }
        // Super-root game (SuperFaultDisputeGame layout: wasRespected in slot 9), claiming a super root
        // over [other chain, our chain].
        const otherRoot = keccak256(toHex("other chain output root"));
        const superTs = 1_999_000_000n;
        const sup = superRootPreimage(superTs, [
            {chainId: OTHER_CHAIN_ID, outputRoot: otherRoot}, {chainId: L2_CHAIN_ID, outputRoot}
        ]);
        const supWithoutUs = superRootPreimage(superTs, [{chainId: OTHER_CHAIN_ID, outputRoot: otherRoot}]);
        const superExtra = encodePacked(["uint256"], [superTs]);
        const superCreated = L1_TIME - 20n * DAY;
        await setCode(l1.url, SUPER_GAME, cloneCode(GAME_IMPL, (encodePacked(["address", "bytes32", "bytes32", "bytes"],
            [PROPOSER, sup.superRoot, slotHex(0n), superExtra]) + "0000") as Hex));
        await setStorage(l1.url, SUPER_GAME, slotHex(SL.gameStateSlot),
            slotHex(superCreated | ((L1_TIME - 10n * DAY) << 64n) | (BigInt(GAME_STATUS.DEFENDER_WINS) << 128n) | (1n << 136n)));
        await setStorage(l1.url, SUPER_GAME, slotHex(SL.gameWasRespectedSlot), slotHex(1n));
        await setStorage(l1.url, DGF, dgfGameSlot(gameUuid(RESPECTED_TYPE, sup.superRoot, superExtra), L),
            packGameId(RESPECTED_TYPE, superCreated, SUPER_GAME));

        const finalized = games.find((g) => g.name === "finalized")!;
        for (const asr of [ASR, ASR_STARTING_ONLY]) {
            await setStorage(l1.url, asr, slotHex(L.asrDisputeGameFactorySlot), slotHex(BigInt(DGF)));
            await setStorage(l1.url, asr, slotHex(L.asrRespectedGameTypeSlot),
                slotHex((RETIREMENT << (L.asrRetirementTimestampOffset * 8n)) | BigInt(RESPECTED_TYPE)));
            await setStorage(l1.url, asr, EIP1967_IMPLEMENTATION_SLOT, slotHex(BigInt(ASR_IMPL)));
        }
        // ASR: anchor = the finalized game, a different starting root. ASR_STARTING_ONLY: no anchor
        // game yet, starting anchor root = our output root.
        await setStorage(l1.url, ASR, slotHex(L.asrAnchorGameSlot), slotHex(BigInt(finalized.address)));
        await setStorage(l1.url, ASR, slotHex(L.asrStartingAnchorRootSlot), keccak256(toHex("genesis-root")));
        await setStorage(l1.url, ASR_STARTING_ONLY, slotHex(L.asrStartingAnchorRootSlot), outputRoot);
        for (const g of games.filter((x) => x.blacklisted)) {
            await setStorage(l1.url, ASR, keccak256(encodeAbiParameters([{type: "address"}, {type: "uint256"}],
                [g.address, L.asrBlacklistSlot])), slotHex(1n));
        }
        await rpc(l1.url, "evm_mine", []);
        const l1Block = await rpc<{stateRoot: Hex; number: Hex}>(l1.url, "eth_getBlockByNumber", ["latest", false]);
        const at = l1Block.number;

        const asrKeys = asrSlots(L, [...games.map((g) => g.address), SUPER_GAME]);
        const asrProof = await rpc<EthGetProofResult>(l1.url, "eth_getProof", [ASR, asrKeys, at]);
        const asr2Proof = await rpc<EthGetProofResult>(l1.url, "eth_getProof", [ASR_STARTING_ONLY, asrKeys, at]);
        const implProof = await rpc<EthGetProofResult>(l1.url, "eth_getProof", [ASR_IMPL, [], at]);
        // Registered uuids + the uuids a lying relayer would need (tampered root / wrong type claimed as respected).
        const uuidOf = (t: number, root: Hex, x: Hex) => dgfGameSlot(gameUuid(t, root, x), L);
        const wrongType = games.find((g) => g.name === "wrongType")!;
        const dgfKeys = [
            ...games.map((g) => uuidOf(g.gameType, outputRoot, g.extraData)),
            uuidOf(RESPECTED_TYPE, tampered.outputRoot, finalized.extraData),
            uuidOf(RESPECTED_TYPE, outputRoot, wrongType.extraData),
            uuidOf(RESPECTED_TYPE, sup.superRoot, superExtra)
        ];
        const dgfProof = await rpc<EthGetProofResult>(l1.url, "eth_getProof", [DGF, dgfKeys, at]);
        const dgfEntries = storageEntries(dgfProof, dgfKeys);

        const base = (asrP: EthGetProofResult): Omit<DisputeProofParts, "mode" | "gameType" | "extraData"> => ({
            asrAccountProof: accountNodes(asrP),
            asrStorageProof: storageEntries(asrP, asrKeys),
            asrImplAccountProof: accountNodes(implProof),
            dgfAccountProof: accountNodes(dgfProof),
            dgfStorageProof: dgfEntries,
            gameAccountProof: [],
            gameCode: "0x",
            gameStorageProof: []
        });

        const cases: {name: string; preimage: Hex; disputeProof: Hex}[] = [];
        for (const g of games) {
            const gp = await rpc<EthGetProofResult>(l1.url, "eth_getProof", [g.address, [slotHex(L.gameStateSlot)], at]);
            const code = await rpc<Hex>(l1.url, "eth_getCode", [g.address, at]);
            const gameParts: DisputeProofParts = {
                ...base(asrProof),
                mode: MODE.GAME,
                gameType: g.gameType,
                extraData: g.extraData,
                gameAccountProof: accountNodes(gp),
                gameCode: code,
                gameStorageProof: storageEntries(gp, [slotHex(L.gameStateSlot)])
            };
            cases.push({name: `game:${g.name}`, preimage, disputeProof: hexOf(disputeProofItem(gameParts))});
            if (g.name === "finalized") {
                cases.push({name: "game:finalized:tamperedPreimage", preimage: tampered.preimage,
                    disputeProof: hexOf(disputeProofItem(gameParts))});
                cases.push({name: "game:finalized:badVersion", preimage: badVersion,
                    disputeProof: hexOf(disputeProofItem(gameParts))});
                cases.push({name: "game:finalized:mode7", preimage,
                    disputeProof: hexOf(disputeProofItem({...gameParts, mode: 7}))});
                // Game code not matching the account's code hash.
                cases.push({name: "game:finalized:forgedCode", preimage,
                    disputeProof: hexOf(disputeProofItem({...gameParts, gameCode: cloneCode(GAME_IMPL, "0x00")}))});
            }
            if (g.name === "wrongType") {
                // Relayer claims the respected type for a game registered under another type.
                cases.push({name: "game:wrongType:claimedRespected", preimage,
                    disputeProof: hexOf(disputeProofItem({...gameParts, gameType: RESPECTED_TYPE}))});
            }
        }
        // Super-root cases (verified by a SUPER_ROOT_V1 verifier with l2ChainId = L2_CHAIN_ID).
        const sgp = await rpc<EthGetProofResult>(l1.url, "eth_getProof",
            [SUPER_GAME, [slotHex(SL.gameStateSlot), slotHex(SL.gameWasRespectedSlot)], at]);
        const superParts: DisputeProofParts = {
            ...base(asrProof),
            mode: MODE.GAME,
            gameType: RESPECTED_TYPE,
            extraData: superExtra,
            gameAccountProof: accountNodes(sgp),
            gameCode: await rpc<Hex>(l1.url, "eth_getCode", [SUPER_GAME, at]),
            gameStorageProof: storageEntries(sgp, [slotHex(SL.gameStateSlot), slotHex(SL.gameWasRespectedSlot)]),
            superRootPreimage: sup.preimage
        };
        cases.push({name: "super:finalized", preimage, disputeProof: hexOf(disputeProofItem(superParts))});
        cases.push({name: "super:withoutOurChain", preimage,
            disputeProof: hexOf(disputeProofItem({...superParts, superRootPreimage: supWithoutUs.preimage}))});
        cases.push({name: "super:badVersion", preimage,
            disputeProof: hexOf(disputeProofItem({...superParts, superRootPreimage: ("0x02" + sup.preimage.slice(4)) as Hex}))});
        cases.push({name: "super:missing", preimage,
            disputeProof: hexOf(disputeProofItem({...superParts, superRootPreimage: "0x"}))});
        // Our entry present but with another output root (a different L2 block).
        cases.push({name: "super:tamperedPreimage", preimage: tampered.preimage,
            disputeProof: hexOf(disputeProofItem(superParts))});

        const anchorParts: DisputeProofParts = {
            ...base(asrProof), mode: MODE.ANCHOR, gameType: RESPECTED_TYPE, extraData: finalized.extraData
        };
        cases.push({name: "anchor:game", preimage, disputeProof: hexOf(disputeProofItem(anchorParts))});
        cases.push({name: "anchor:game:tamperedPreimage", preimage: tampered.preimage,
            disputeProof: hexOf(disputeProofItem(anchorParts))});
        // The in-progress game is registered but is not the anchor.
        const inProgress = games.find((g) => g.name === "inProgress")!;
        cases.push({name: "anchor:notAnchorGame", preimage,
            disputeProof: hexOf(disputeProofItem({...anchorParts, extraData: inProgress.extraData}))});
        cases.push({name: "anchor:startingRoot", preimage,
            disputeProof: hexOf(disputeProofItem({...base(asr2Proof), mode: MODE.ANCHOR, gameType: 0, extraData: "0x"}))});

        return {
            description: "Synthetic L1/L2 state (anvil eth_getProof) for OpStackVerifier unit tests. Regenerate with "
                + "`npx tsx test/e2e/relay/buildOpStackSyntheticFixture.ts`.",
            l1: {
                stateRoot: l1Block.stateRoot,
                slot: L1_SLOT.toString(),
                time: L1_TIME.toString(),
                anchorStateRegistry: ASR,
                anchorStateRegistryStartingOnly: ASR_STARTING_ONLY,
                anchorStateRegistryImplCodeHash: implProof.codeHash,
                gameImplementation: GAME_IMPL,
                finalityDelaySeconds: FINALITY_DELAY.toString(),
                respectedGameType: RESPECTED_TYPE,
                games: Object.fromEntries(games.map((g) => [g.name, g.address])),
                superGame: SUPER_GAME,
                l2ChainId: L2_CHAIN_ID.toString()
            },
            l2: {
                stateRoot: l2Block.stateRoot,
                outputRoot,
                service: SERVICE,
                serviceCodeHash: svc.codeHash,
                channelId: CHANNEL_ID,
                accountProof: hexOf(accountNodes(svc)),
                storageProof: hexOf(storageEntries(svc, chSlots)),
                expected: {
                    status: Number(status),
                    nextMessageId: nextMessageId.toString(),
                    receivedMessageId: receivedMessageId.toString(),
                    sentRunningHash,
                    receivedRunningHash,
                    endpointManifestVersion: manifestVersion.toString()
                }
            },
            cases
        };
    } finally {
        l1.proc.kill("SIGTERM");
        l2.proc.kill("SIGTERM");
    }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    const l2Port = Number(process.env.CLPR_ANVIL_PORT_A ?? 8611);
    const l1Port = Number(process.env.CLPR_ANVIL_PORT_B ?? 8612);
    buildOpStackSyntheticFixture({l2: l2Port, l1: l1Port}).then((f) => {
        mkdirSync(path.dirname(SYNTHETIC_FIXTURE), {recursive: true});
        writeFileSync(SYNTHETIC_FIXTURE, JSON.stringify(f, null, 1) + "\n");
        console.log(`wrote ${path.relative(process.cwd(), SYNTHETIC_FIXTURE)} (${f.cases.length} cases)`);
    }).catch((err) => {
        console.error(err);
        process.exit(1);
    });
}
