import {spawn, type ChildProcess} from "node:child_process";
import {mkdirSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {keccak256, toHex, type Hex} from "viem";
import {rlpEncode} from "../lib/rlp.js";
import {deriveChannelSlots, type EthGetProofResult} from "./buildEthMainnetProof.js";
import {accountNodes, EIP1967_IMPLEMENTATION_SLOT, outputRootPreimage, slotHex, storageEntries} from "./opstack.js";
import {encodeOracleProof, oracleSlots, outputElementSlot, PERIOD_SOURCE, type OracleProfile} from "./opOracle.js";

/// Synthetic-state fixture for the Foundry output-oracle tests: the states the live chains do not show
/// on demand. Two throw-away anvils stand in for the chains:
///
///   L2  a ClprService-shaped account with a populated channel (non-zero metadata, unlike the live
///       exclusion proofs), and the L2ToL1MessagePasser.
///   L1  three output oracles sharing one implementation, written with the SAME layout the verifier
///       derives slots from (`anvil_setStorageAt`), every proof from anvil's `eth_getProof`:
///       - `oracle`     Mantle layout (period in slot 8 = 1 h, optimistic flag slot 16 clear), outputs
///                      #0 other root, final; #1 our root, final; #2 our root, inside the period;
///                      #3 our root left in storage PAST `length` = 3 (what `deleteL2Outputs` leaves).
///       - `optimistic` the same, with the optimistic flag set.
///       - `katana`     Katana layout (outputs at slot 116, period 0, flag slot 124 offset 0 clear with
///                      a non-zero optimisticModeManager packed at offset 1).
///
/// Run: npx tsx test/e2e/relay/buildOpOracleSyntheticFixture.ts   (writes the JSON fixture below)

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ORACLE_SYNTHETIC_FIXTURE = path.resolve(__dirname, "../../verifiers/evm/opstack/oracle/fixtures/synthetic.json");

const L1_SLOT = 150_000_000n; // L1 time = slot × 12 with genesis 0
const L1_TIME = L1_SLOT * 12n;
const PERIOD = 3600n;

const ORACLE: Hex = "0x0c1e000000000000000000000000000000000001";
const ORACLE_OPTIMISTIC: Hex = "0x0c1e000000000000000000000000000000000002";
const ORACLE_KATANA: Hex = "0x0c1e000000000000000000000000000000000003";
const IMPL: Hex = "0x0c1e000000000000000000000000000000001111";
const IMPL_CODE: Hex = "0x6080604052348015600f57600080fd5b50"; // stand-in runtime
const MANAGER = 0xd0673f989bc3ba9314d0aaf28bfc84e99b7898ccn;

const SERVICE: Hex = "0x5e7c1ce1acce5e7c1ce1acce5e7c1ce1acce5e7c";
const SERVICE_CODE: Hex = "0x60806040526004361061001e5760003560e01c80";
const CHANNEL_ID: Hex = keccak256(toHex("clpr/opadapters/synthetic"));
const MESSAGE_PASSER: Hex = "0x4200000000000000000000000000000000000016";

export const MANTLE_LIKE: Omit<OracleProfile, "oracle" | "oracleImplCodeHash"> = {
    outputsSlot: 3n, periodSource: PERIOD_SOURCE.STORAGE, finalizationPeriodSeconds: 0n, finalizationPeriodSlot: 8n,
    hasOptimisticMode: true, optimisticModeSlot: 16n, optimisticModeOffset: 0n
};
export const KATANA_LIKE: Omit<OracleProfile, "oracle" | "oracleImplCodeHash"> = {
    outputsSlot: 116n, periodSource: PERIOD_SOURCE.IMMUTABLE, finalizationPeriodSeconds: 0n, finalizationPeriodSlot: 0n,
    hasOptimisticMode: true, optimisticModeSlot: 124n, optimisticModeOffset: 0n
};

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

const setStorage = (url: string, a: Hex, slot: Hex | bigint, v: Hex | bigint) =>
    rpc(url, "anvil_setStorageAt", [a, typeof slot === "bigint" ? slotHex(slot) : slot, typeof v === "bigint" ? slotHex(v) : v]);
const hexOf = (parts: unknown) => ("0x" + rlpEncode(parts as never).toString("hex")) as Hex;

interface Out {root: Hex; ts: bigint; l2Block: bigint}

async function writeOracle(url: string, oracle: Hex, layout: typeof MANTLE_LIKE, outputs: Out[], length: bigint,
    extra: [bigint, bigint][]): Promise<void> {
    await setStorage(url, oracle, EIP1967_IMPLEMENTATION_SLOT, BigInt(IMPL));
    await setStorage(url, oracle, layout.outputsSlot, length);
    for (let i = 0; i < outputs.length; i++) {
        const e = outputElementSlot(layout.outputsSlot, BigInt(i));
        await setStorage(url, oracle, e, outputs[i].root);
        await setStorage(url, oracle, e + 1n, (outputs[i].l2Block << 128n) | outputs[i].ts);
    }
    for (const [slot, value] of extra) await setStorage(url, oracle, slot, value);
}

export async function buildOpOracleSyntheticFixture(ports = {l2: 8621, l1: 8622}) {
    const l2 = await startAnvil(ports.l2);
    const l1 = await startAnvil(ports.l1);
    try {
        // ── L2: ClprService with a populated channel ───────────────────────────
        await rpc(l2.url, "anvil_setCode", [SERVICE, SERVICE_CODE]);
        const chSlots = deriveChannelSlots(CHANNEL_ID);
        const values: Hex[] = [
            slotHex((3n << 168n) | (1n << 160n) | 0x1234n), // nextMessageId 3 | status 1 | verifier
            slotHex(2n << 64n), // receivedMessageId 2
            keccak256(toHex("sent")),
            keccak256(toHex("received")),
            slotHex(1n) // endpointManifestVersion
        ];
        for (let i = 0; i < chSlots.length; i++) await setStorage(l2.url, SERVICE, chSlots[i], values[i]);
        await rpc(l2.url, "evm_mine", []);
        const l2Block = await rpc<{stateRoot: Hex; hash: Hex; number: Hex}>(l2.url, "eth_getBlockByNumber", ["latest", false]);
        const svc = await rpc<EthGetProofResult>(l2.url, "eth_getProof", [SERVICE, chSlots, l2Block.number]);
        const mp = await rpc<{storageHash: Hex}>(l2.url, "eth_getProof", [MESSAGE_PASSER, [], l2Block.number]);
        const {preimage, outputRoot} = outputRootPreimage(l2Block.stateRoot, mp.storageHash, l2Block.hash);

        // ── L1: three oracles, one implementation ─────────────────────────────
        await rpc(l1.url, "anvil_setCode", [IMPL, IMPL_CODE]);
        const other = keccak256(toHex("some other output"));
        const outputs: Out[] = [
            {root: other, ts: L1_TIME - 2n * 86_400n, l2Block: 100n},
            {root: outputRoot, ts: L1_TIME - 2n * PERIOD, l2Block: 200n},
            {root: outputRoot, ts: L1_TIME - PERIOD / 2n, l2Block: 300n},
            {root: outputRoot, ts: L1_TIME - 60n, l2Block: 400n} // deleted: index 3 ≥ length 3
        ];
        await writeOracle(l1.url, ORACLE, MANTLE_LIKE, outputs, 3n, [[8n, PERIOD], [16n, 0n]]);
        await writeOracle(l1.url, ORACLE_OPTIMISTIC, MANTLE_LIKE, outputs, 3n, [[8n, PERIOD], [16n, 1n]]);
        await writeOracle(l1.url, ORACLE_KATANA, KATANA_LIKE, outputs.slice(0, 3), 3n, [[124n, MANAGER << 8n]]);
        await rpc(l1.url, "evm_mine", []);
        const l1Block = await rpc<{stateRoot: Hex; number: Hex}>(l1.url, "eth_getBlockByNumber", ["latest", false]);
        const implProof = await rpc<EthGetProofResult>(l1.url, "eth_getProof", [IMPL, [], l1Block.number]);
        const implCodeHash = implProof.codeHash as Hex;

        const proofsFor = async (oracle: Hex, layout: typeof MANTLE_LIKE, indices: bigint[]) => {
            const profile: OracleProfile = {...layout, oracle, oracleImplCodeHash: implCodeHash};
            const keys = [...new Set(indices.flatMap((i) => oracleSlots(profile, i)))];
            const proof = await rpc<EthGetProofResult>(l1.url, "eth_getProof", [oracle, keys, l1Block.number]);
            const out: Record<string, Hex> = {};
            for (const i of indices) {
                out[`i${i}`] = encodeOracleProof({
                    outputIndex: i, oracleAccountProof: accountNodes(proof), oracleImplAccountProof: accountNodes(implProof),
                    oracleStorageProof: storageEntries(proof, oracleSlots(profile, i))
                });
            }
            // A proof that omits the period slot (the verifier must not fall back to a default).
            if (layout.periodSource === PERIOD_SOURCE.STORAGE) {
                const keysNoPeriod = oracleSlots(profile, 1n).filter((k) => BigInt(k) !== layout.finalizationPeriodSlot);
                out.i1NoPeriod = encodeOracleProof({
                    outputIndex: 1n, oracleAccountProof: accountNodes(proof), oracleImplAccountProof: accountNodes(implProof),
                    oracleStorageProof: storageEntries(proof, keysNoPeriod)
                });
            }
            return out;
        };

        const fixture = {
            note: "Generated by test/e2e/relay/buildOpOracleSyntheticFixture.ts (anvil eth_getProof; synthetic state).",
            l1: {stateRoot: l1Block.stateRoot, slot: Number(L1_SLOT), time: Number(L1_TIME), period: Number(PERIOD)},
            impl: IMPL,
            implCodeHash,
            oracle: ORACLE,
            oracleOptimistic: ORACLE_OPTIMISTIC,
            oracleKatana: ORACLE_KATANA,
            outputRoot,
            otherRoot: other,
            outputTimestamps: outputs.map((o) => Number(o.ts)),
            proofs: {
                oracle: await proofsFor(ORACLE, MANTLE_LIKE, [0n, 1n, 2n, 3n]),
                optimistic: await proofsFor(ORACLE_OPTIMISTIC, MANTLE_LIKE, [1n]),
                katana: await proofsFor(ORACLE_KATANA, KATANA_LIKE, [1n, 2n])
            },
            l2: {
                stateRoot: l2Block.stateRoot,
                preimage,
                service: SERVICE,
                serviceCodeHash: svc.codeHash,
                channelId: CHANNEL_ID,
                accountProof: hexOf(accountNodes(svc)),
                storageProof: hexOf(storageEntries(svc, chSlots))
            }
        };
        mkdirSync(path.dirname(ORACLE_SYNTHETIC_FIXTURE), {recursive: true});
        writeFileSync(ORACLE_SYNTHETIC_FIXTURE, JSON.stringify(fixture, null, 1) + "\n");
        return fixture;
    } finally {
        l1.proc.kill("SIGTERM");
        l2.proc.kill("SIGTERM");
    }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    buildOpOracleSyntheticFixture().then((f) => {
        console.log(`wrote ${path.relative(process.cwd(), ORACLE_SYNTHETIC_FIXTURE)} (L1 ${f.l1.stateRoot})`);
    }).catch((err) => {
        console.error(err);
        process.exit(1);
    });
}
