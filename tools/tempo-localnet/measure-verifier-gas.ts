// Measure the QBFT, Ethereum, Sei and Tempo verifiers (and, as a calibration, the Hiero verifier) on a
// live chain without sending a transaction. Each contract's constructor runs through `eth_call`, and the
// returned runtime code is injected at a fixed address with a state override. `gasUsed` is the top frame
// of `debug_traceCall` (callTracer), which equals a receipt's gasUsed: the Hiero calibration call gives
// the 6,214,551 its receipt showed on both chains. `estimate` is `eth_estimateGas`, the gas limit a
// sender needs. With `--opcodes`, it also records an opcode histogram (struct logger) and projects every
// scenario to the TIP-1102 draft schedule.
//
// The sender is the funded first mnemonic account with its nonce overridden to 1: on Tempo a nonce-0
// sender pays the 250,000-gas account-creation charge, which a real relay never pays.
//
// usage: [RUNTIME_RPC=<url>] npx tsx tools/tempo-localnet/measure-verifier-gas.ts <label> <rpcUrl> <dumpLog> <outJson> [--opcodes]
//   <dumpLog>: output of
//   CLPR_DUMP_VERIFIER_INPUTS=1 FOUNDRY_PROFILE=test forge test --match-path test/gas/TempoVerifierInputs.t.sol -vv
//   RUNTIME_RPC: a chain without the EIP-170 limit (anvil --code-size-limit) that builds the runtime of a
//   test harness too large to create on <rpcUrl>; the harness is then injected, never deployed.
import {readFileSync, writeFileSync} from "node:fs";
import path from "node:path";
import {decodeAbiParameters, encodeDeployData, encodeFunctionData, getAddress, type Hex} from "viem";

const ROOT = path.resolve(import.meta.dirname, "../..");
const FROM = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" as const;
const [label, rpcUrl, dumpLog, outJson, ...flags] = process.argv.slice(2);
if (!outJson) throw new Error("usage: measure-verifier-gas.ts <label> <rpcUrl> <dumpLog> <outJson> [--opcodes]");
const withOpcodes = flags.includes("--opcodes");
const RUNTIME_RPC = process.env.RUNTIME_RPC;

let rpcId = 0;
async function rpc(method: string, params: unknown[], url = rpcUrl): Promise<any> {
    const res = await fetch(url, {
        method: "POST",
        headers: {"content-type": "application/json"},
        body: JSON.stringify({jsonrpc: "2.0", id: ++rpcId, method, params})
    });
    const body = JSON.parse(await res.text());
    if (body.error) throw new Error(`${method}: ${body.error.message}`);
    return body.result;
}

function artifact(file: string, name: string): {abi: any[]; bytecode: Hex} {
    const j = JSON.parse(readFileSync(path.join(ROOT, "out", file, `${name}.json`), "utf8"));
    return {abi: j.abi, bytecode: j.bytecode.object};
}

const toHex = (b: Buffer) => `0x${b.toString("hex")}` as Hex;
const hexBytes = (h: string) => (h.length - 2) / 2;
function calldataGas(data: Hex): number {
    let g = 0;
    for (let i = 2; i < data.length; i += 2) g += data.slice(i, i + 2) === "00" ? 4 : 16;
    return g;
}

// ── Contracts, in dependency order ───────────────────────────────────────────
type Spec = {name: string; file: string; stack: string; args?: (a: Record<string, Hex>) => unknown[]};
const HIERO_LEDGER_ID = toHex(readFileSync(path.join(ROOT, "test/verifiers/hiero/fixtures/trustAnchor.bin")));
const HIERO_PROOF = toHex(readFileSync(path.join(ROOT, "test/verifiers/hiero/fixtures/stateProof.bin")));
// channelId ‖ remoteServiceAddress of the fixture's ClprChannel leaf, as in test/verifiers/hiero/GasUsage.t.sol.
const HIERO_CHANNEL_CONTEXT =
    "0xe1022276af73c7a88c9fa00f7e844bbc4a8fda0cc6051d9c99926b74cf9c3d84ade986b5973ec38f3996f3a128f7d8c3e8ffcd9d" as Hex;
const CONTRACTS: Spec[] = [
    {name: "QbftHeaderModeVerifier", file: "QbftHeaderModeVerifier.sol", stack: "qbft"},
    {name: "QbftContractModeVerifier", file: "QbftContractModeVerifier.sol", stack: "qbft"},
    {name: "QBFTVerifier", file: "QBFTVerifier.sol", stack: "qbft-legacy", args: () => [1]},
    {name: "EthMainnetVerifier", file: "EthMainnetVerifier.sol", stack: "eth"},
    {name: "Ed25519Verifier", file: "Ed25519Verifier.sol", stack: "sei"},
    {name: "SeiCometBftVerifier", file: "SeiCometBftVerifier.sol", stack: "sei", args: (a) => [a.Ed25519Verifier]},
    {name: "SeiGasHarness", file: "GasUsage.t.sol", stack: "harness", args: (a) => [a.Ed25519Verifier]},
    {name: "TempoVerifier", file: "TempoVerifier.sol", stack: "tempo"},
    {name: "TempoGasHarness", file: "TempoGasReport.t.sol", stack: "harness"},
    {name: "PoseidonPermuteA", file: "PoseidonPermuteA.sol", stack: "hiero"},
    {name: "PoseidonPermuteB", file: "PoseidonPermuteB.sol", stack: "hiero"},
    {name: "PoseidonBN254Contract", file: "PoseidonBN254Contract.sol", stack: "hiero", args: (a) => [a.PoseidonPermuteA, a.PoseidonPermuteB]},
    {name: "WRAPSVerifierContract", file: "WRAPSVerifierContract.sol", stack: "hiero", args: (a) => [a.PoseidonBN254Contract]},
    {name: "TSSVerifier", file: "TSSVerifier.sol", stack: "hiero", args: (a) => [a.WRAPSVerifierContract]},
    {name: "HieroVerifier", file: "HieroVerifier.sol", stack: "hiero", args: (a) => [HIERO_LEDGER_ID, a.TSSVerifier]}
];

// ── TIP-1102 draft schedule (tips.sh/1102) ───────────────────────────────────
const OPCODE_DELTA: Record<string, number> = {
    MOD: 35, SMOD: 32, DIV: 19, SDIV: 29, ADDMOD: 28, MULMOD: 57, SHL: 6, SHR: 6, SAR: 7, ISZERO: 2, SELFBALANCE: 8
};
function word(input: Hex, offset: number): bigint {
    const s = input.slice(2 + offset * 2, 2 + (offset + 32) * 2).padEnd(64, "0");
    return BigInt(`0x${s}`);
}
function modexpTip1102(input: Hex): number {
    const bLen = Number(word(input, 0)), eLen = Number(word(input, 32)), mLen = Number(word(input, 64));
    const maxLen = Math.max(bLen, mLen);
    const words = Math.ceil(maxLen / 8);
    const mult = maxLen <= 32 ? 81 : 2 * words * words;
    const headLen = Math.min(32, eLen);
    const headHex = input.slice(2 + (96 + bLen) * 2, 2 + (96 + bLen + headLen) * 2).padEnd(headLen * 2, "0");
    const head = headLen === 0 ? 0n : BigInt(`0x${headHex}`);
    const bits = head === 0n ? 0 : head.toString(2).length;
    let iter: number;
    if (eLen <= 32 && head === 0n) iter = 1;
    else if (eLen <= 32) iter = Math.max(bits - 1, 1);
    else iter = Math.max(20 * (eLen - 32) + Math.max(bits, 1) - 1, 1);
    return Math.max(500, mult * iter);
}
function precompileTip1102(addr: number, input: Hex, oldGas: number): number {
    const n = hexBytes(input), words = Math.ceil(n / 32);
    switch (addr) {
        case 0x01: return 25_000;
        case 0x02: return 104 + 13 * words;
        case 0x04: return 50 + words;
        case 0x05: return modexpTip1102(input);
        case 0x06: return 750;
        case 0x07: return 30_000;
        case 0x08: return 285_000 + 243_000 * (n / 192);
        case 0x0b: return 2_300;
        case 0x0c: return Math.floor((oldGas * 78_000) / 12_000); // same k and discount, new base
        case 0x0d: return 3_500;
        case 0x0e: return Math.floor((oldGas * 143_000) / 22_500);
        case 0x0f: return 230_000 + 167_000 * (n / 384);
        case 0x10: return 26_000;
        case 0x11: return 95_000;
        default: return oldGas; // 0x03 RIPEMD, 0x09 BLAKE2F: unchanged
    }
}
const PRECOMPILE_NAME: Record<number, string> = {
    0x01: "ECRECOVER", 0x02: "SHA256", 0x03: "RIPEMD160", 0x04: "IDENTITY", 0x05: "MODEXP", 0x06: "BN254_ADD",
    0x07: "BN254_MUL", 0x08: "BN254_PAIRING", 0x09: "BLAKE2F", 0x0a: "KZG", 0x0b: "BLS_G1ADD", 0x0c: "BLS_G1MSM",
    0x0d: "BLS_G2ADD", 0x0e: "BLS_G2MSM", 0x0f: "BLS_PAIRING", 0x10: "BLS_MAP_FP_TO_G1", 0x11: "BLS_MAP_FP2_TO_G2"
};

async function main() {
    const chainId = parseInt(await rpc("eth_chainId", []), 16);
    const out: any = {label, rpcUrl, chainId, from: FROM, deploys: {}, calls: {}};
    const addrs: Record<string, Hex> = {};
    const overrides: Record<string, any> = {[FROM]: {nonce: "0x1"}};
    const abis: Record<string, any[]> = {};

    CONTRACTS.forEach((c, i) => {
        addrs[c.name] = getAddress(`0x${(0xc1a50000 + i + 1).toString(16).padStart(40, "0")}`);
    });
    for (const c of CONTRACTS) {
        const {abi, bytecode} = artifact(c.file, c.name);
        abis[c.name] = abi;
        const data = encodeDeployData({abi, bytecode, args: c.args ? c.args(addrs) : []});
        let gasUsed: number | null = null;
        let estimate: number | null = null;
        let buildRpc = rpcUrl;
        try {
            estimate = parseInt(await rpc("eth_estimateGas", [{from: FROM, data}, "latest", overrides]), 16);
            const t = await rpc("debug_traceCall", [{from: FROM, data}, "latest", {tracer: "callTracer", stateOverrides: overrides}]);
            gasUsed = parseInt(t.gasUsed, 16);
        } catch (e) {
            if (c.stack !== "harness" || !RUNTIME_RPC || !String(e).includes("CreateContractSizeLimit")) throw e;
            buildRpc = RUNTIME_RPC;
        }
        const runtime: Hex = await rpc("eth_call", [{from: FROM, data}, "latest", overrides], buildRpc);
        // Storage the constructor writes (e.g. HieroVerifier's ledger id) travels with the code.
        const diff = await rpc("debug_traceCall", [
            {from: FROM, data}, "latest", {tracer: "prestateTracer", tracerConfig: {diffMode: true}, stateOverrides: overrides}
        ], buildRpc);
        const created = Object.entries<any>(diff.post ?? {}).find(([, v]) => v.code && v.code !== "0x");
        const storage = created?.[1].storage ?? {};
        overrides[addrs[c.name]] = Object.keys(storage).length ? {code: runtime, state: storage} : {code: runtime};
        out.deploys[c.name] = {
            stack: c.stack, gasUsed, estimate, codeBytes: hexBytes(runtime), initcodeBytes: hexBytes(data), storageSlots: Object.keys(storage).length
        };
        console.error(`[${label}] deploy ${c.name}: ${gasUsed ?? `over EIP-170, runtime built on ${buildRpc}`} gas, ${hexBytes(runtime)} B`);
    }

    const scenarios: {target: string; id: string; data: Hex}[] = [];
    for (const line of readFileSync(dumpLog, "utf8").split("\n")) {
        const m = line.match(/DUMP (\S+) (\S+) (0x[0-9a-f]*)/);
        if (m) scenarios.push({target: m[1], id: m[2], data: m[3] as Hex});
    }
    scenarios.push({
        target: "HieroVerifier",
        id: "calibration-verifyBundle",
        data: encodeFunctionData({abi: abis.HieroVerifier, functionName: "verifyBundle", args: [HIERO_PROOF, HIERO_LEDGER_ID, HIERO_CHANNEL_CONTEXT]})
    });
    if (scenarios.length === 1) throw new Error(`no DUMP lines in ${dumpLog}`);

    for (const s of scenarios) {
        const tx = {from: FROM, to: addrs[s.target], data: s.data};
        const key = `${s.target} ${s.id}`;
        const trace = await rpc("debug_traceCall", [tx, "latest", {tracer: "callTracer", stateOverrides: overrides}]);
        if (trace.error) throw new Error(`${key} reverted: ${trace.error} ${trace.output ?? ""}`);
        const gasUsed = parseInt(trace.gasUsed, 16);
        const estimate = parseInt(await rpc("eth_estimateGas", [tx, "latest", overrides]), 16);
        const precompiles: Record<string, {calls: number; gas: number; tip1102: number}> = {};
        const walk = (c: any) => {
            for (const sub of c.calls ?? []) {
                const a = parseInt(sub.to, 16);
                if (a >= 1 && a <= 0x11) {
                    const name = PRECOMPILE_NAME[a];
                    const g = parseInt(sub.gasUsed, 16);
                    precompiles[name] ??= {calls: 0, gas: 0, tip1102: 0};
                    precompiles[name].calls++;
                    precompiles[name].gas += g;
                    precompiles[name].tip1102 += precompileTip1102(a, sub.input, g);
                }
                walk(sub);
            }
        };
        walk(trace);
        const rec: any = {
            gasUsed, estimate, calldataBytes: hexBytes(s.data),
            calldataGas: calldataGas(s.data), precompiles
        };
        if (s.target === "SeiGasHarness") {
            const ret: Hex = await rpc("eth_call", [tx, "latest", overrides]);
            rec.returns = s.id === "signed-header"
                ? Object.fromEntries(decodeAbiParameters([{type: "uint256"}, {type: "uint256"}], ret).map((v, i) => [["edPerSig", "signedHeaderTotal"][i], Number(v)]))
                : {perSlot: Number(decodeAbiParameters([{type: "uint256"}], ret)[0])};
        }
        if (withOpcodes) {
            const logs = await rpc("debug_traceCall", [
                tx, "latest", {disableStack: true, disableStorage: true, enableMemory: false, stateOverrides: overrides}
            ]);
            const counts: Record<string, number> = {};
            let keccakCount = 0, keccakGas = 0;
            for (const l of logs.structLogs) {
                counts[l.op] = (counts[l.op] ?? 0) + 1;
                if (l.op === "KECCAK256" || l.op === "SHA3") {
                    keccakCount++;
                    keccakGas += l.gasCost;
                }
            }
            // KECCAK256 costs 30 + 6/word (+ memory expansion, counted here as words: a slight overestimate).
            const keccakWords = (keccakGas - 30 * keccakCount) / 6;
            let opcodeDelta = 175 * keccakCount + 35 * keccakWords;
            for (const [op, d] of Object.entries(OPCODE_DELTA)) opcodeDelta += (counts[op] ?? 0) * d;
            const precompileDelta = Object.values(precompiles).reduce((a, p) => a + p.tip1102 - p.gas, 0);
            rec.steps = logs.structLogs.length;
            rec.opcodes = Object.fromEntries(
                [...Object.keys(OPCODE_DELTA), "KECCAK256"].map((op) => [op, op === "KECCAK256" ? keccakCount : counts[op] ?? 0])
            );
            rec.keccakWords = Math.round(keccakWords);
            rec.tip1102 = {opcodeDelta: Math.round(opcodeDelta), precompileDelta: Math.round(precompileDelta),
                gasUsed: Math.round(gasUsed + opcodeDelta + precompileDelta)};
        }
        out.calls[key] = rec;
        console.error(`[${label}] ${key}: gasUsed=${gasUsed} estimate=${estimate}${rec.tip1102 ? ` tip1102=${rec.tip1102.gasUsed}` : ""}`);
    }
    writeFileSync(outJson, JSON.stringify(out, null, 2));
    console.error(`[${label}] wrote ${outJson}`);
}
main().catch((e) => {
    console.error(e);
    process.exit(1);
});
