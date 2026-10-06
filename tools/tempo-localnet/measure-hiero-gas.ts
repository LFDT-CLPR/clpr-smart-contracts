// Measure the Hiero verifier stack on a live chain: deployment gas, verifyBundle gas, per-callee
// breakdown from debug_traceTransaction (callTracer), harness component txs, and an SSTORE probe.
// usage: npx tsx tools/tempo-localnet/measure-hiero-gas.ts <label> <rpcUrl> <outJson>
import {readFileSync, writeFileSync} from "node:fs";
import path from "node:path";
import {encodeFunctionData, getAddress} from "viem";
import {makeDeployClients} from "../../script/deploy/client.ts";

const WT = path.resolve(import.meta.dirname, "../..");
const KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;
const [label, rpcUrl, outJson] = process.argv.slice(2);

function artifact(file: string, name: string) {
    const j = JSON.parse(readFileSync(path.join(WT, "out", file, `${name}.json`), "utf8"));
    return {abi: j.abi, bytecode: j.bytecode.object as `0x${string}`};
}
function hexConst(src: string, name: string): `0x${string}` {
    const m = src.match(new RegExp(`${name}\\s*=\\s*hex"([0-9a-fA-F]+)"`));
    if (!m) throw new Error(`constant ${name} not found`);
    return `0x${m[1]}`;
}
const toHex = (b: Buffer) => `0x${b.toString("hex")}` as `0x${string}`;
function intrinsic(data: `0x${string}`): number {
    const bytes = Buffer.from(data.slice(2), "hex");
    let z = 0, nz = 0;
    for (const b of bytes) b === 0 ? z++ : nz++;
    return 21000 + 4 * z + 16 * nz;
}

async function main() {
    const clients = await makeDeployClients({rpcUrl, privateKey: KEY});
    const {publicClient, walletClient, account} = clients;
    const chainId = await publicClient.getChainId();
    const out: any = {label, rpcUrl, chainId, deploys: {}, txs: {}};

    async function deploy(file: string, name: string, args: unknown[] = []) {
        const {abi, bytecode} = artifact(file, name);
        const hash = await walletClient.deployContract({abi, bytecode, args, account, chain: clients.chain});
        const r = await publicClient.waitForTransactionReceipt({hash});
        if (r.status !== "success" || !r.contractAddress) throw new Error(`deploy ${name} failed`);
        const code = await publicClient.getCode({address: r.contractAddress});
        const codeBytes = (code!.length - 2) / 2;
        out.deploys[name] = {gasUsed: Number(r.gasUsed), codeBytes, initcodeBytes: (bytecode.length - 2) / 2};
        console.error(`[${label}] ${name} @ ${r.contractAddress} gas=${r.gasUsed} code=${codeBytes}B`);
        return {address: r.contractAddress, abi};
    }
    async function send(tag: string, to: `0x${string}`, data: `0x${string}`, gas?: bigint) {
        const est = await publicClient.estimateGas({account: account.address, to, data});
        const hash = await walletClient.sendTransaction({account, chain: clients.chain, to, data, gas: gas ?? est + est / 5n});
        const r = await publicClient.waitForTransactionReceipt({hash});
        let trace: any = null;
        try {
            trace = await publicClient.request({method: "debug_traceTransaction" as any, params: [hash, {tracer: "callTracer"}] as any});
        } catch (e) { console.error(`[${label}] no callTracer: ${(e as Error).message.slice(0, 80)}`); }
        const byCallee: Record<string, {calls: number; gas: number}> = {};
        const walk = (c: any, depth: number) => {
            if (depth > 0) {
                const k = `${getAddress(c.to)}${c.type !== "CALL" && c.type !== "STATICCALL" ? ":" + c.type : ""}`;
                byCallee[k] ??= {calls: 0, gas: 0};
                byCallee[k].calls++;
                byCallee[k].gas += parseInt(c.gasUsed, 16);
            }
            for (const s of c.calls ?? []) walk(s, depth + 1);
        };
        if (trace) walk(trace, 0);
        const rec = {
            status: r.status, gasUsed: Number(r.gasUsed), estimateGas: Number(est), intrinsic: intrinsic(data),
            calldataBytes: (data.length - 2) / 2, topFrameGas: trace ? parseInt(trace.gasUsed, 16) : null,
            directChildren: trace ? (trace.calls ?? []).map((c: any) => ({to: getAddress(c.to), type: c.type, gasUsed: parseInt(c.gasUsed, 16)})) : null,
            byCallee
        };
        out.txs[tag] = rec;
        console.error(`[${label}] ${tag}: status=${r.status} gasUsed=${r.gasUsed} est=${est}`);
        return rec;
    }

    // ── Stack ────────────────────────────────────────────────────────────────
    const ledgerId = toHex(readFileSync(path.join(WT, "test/verifiers/hiero/fixtures/trustAnchor.bin")));
    const proof = toHex(readFileSync(path.join(WT, "test/verifiers/hiero/fixtures/stateProof.bin")));
    const a = await deploy("PoseidonPermuteA.sol", "PoseidonPermuteA");
    const b = await deploy("PoseidonPermuteB.sol", "PoseidonPermuteB");
    const poseidon = await deploy("PoseidonBN254Contract.sol", "PoseidonBN254Contract", [a.address, b.address]);
    const wraps = await deploy("WRAPSVerifierContract.sol", "WRAPSVerifierContract", [poseidon.address]);
    const tss = await deploy("TSSVerifier.sol", "TSSVerifier", [wraps.address]);
    const hiero = await deploy("HieroVerifier.sol", "HieroVerifier", [ledgerId, tss.address]);
    out.addresses = {poseidonA: a.address, poseidonB: b.address, poseidon: poseidon.address, wraps: wraps.address, tss: tss.address, hiero: hiero.address};

    // ── verifyBundle, twice ──────────────────────────────────────────────────
    const vb = encodeFunctionData({abi: hiero.abi, functionName: "verifyBundle", args: [proof, ledgerId, "0x"]});
    await send("verifyBundle#1", hiero.address, vb);
    await send("verifyBundle#2", hiero.address, vb);

    // ── Components via the Foundry harnesses, same inputs as test/verifiers/hiero/GasUsage.t.sol ──
    const src = readFileSync(path.join(WT, "test/verifiers/hiero/GasUsage.t.sol"), "utf8");
    const HINTS_VK_N8 = hexConst(src, "HINTS_VK_N8"), HINTS_SIG_N8 = hexConst(src, "HINTS_SIG_N8"), BLOCK_ROOT_N8 = hexConst(src, "BLOCK_ROOT_N8");
    const raw = Buffer.from(proof.slice(2), "hex");
    const hintsVk = toHex(raw.subarray(raw.length - 3432, raw.length - 3432 + 1096));
    const abProof = toHex(raw.subarray(raw.length - 704));
    const tssH = await deploy("TSSVerifierHarness.sol", "TSSVerifierHarness");
    const wrapsH = await deploy("WrapsVerifierHarness.sol", "WRAPSVerifierHarness");
    await send("hinTS n=8 (harness)", tssH.address, encodeFunctionData({abi: tssH.abi, functionName: "verifyHintsAggregate", args: [HINTS_VK_N8, HINTS_SIG_N8, BLOCK_ROOT_N8]}));
    await send("WRAPS Groth16+KZG (harness)", wrapsH.address, encodeFunctionData({abi: wrapsH.abi, functionName: "verify", args: [abProof, hintsVk, ledgerId, poseidon.address]}));

    // ── SSTORE probe: runtime = PUSH1 1, PUSH0, CALLDATALOAD, SSTORE, STOP ──
    const initcode = "0x6006600a5f3960065ff360015f355500" as `0x${string}`;
    {
        const hash = await walletClient.sendTransaction({account, chain: clients.chain, data: initcode});
        const r = await publicClient.waitForTransactionReceipt({hash});
        out.deploys["SstoreProbe(6-byte runtime)"] = {gasUsed: Number(r.gasUsed), codeBytes: 6, initcodeBytes: 16};
        const key = "0x" + "11".repeat(32) as `0x${string}`;
        await send("SSTORE zero->nonzero (new slot)", r.contractAddress!, key);
        await send("SSTORE nonzero->nonzero (same slot, new tx)", r.contractAddress!, key);
        const key2 = "0x" + "22".repeat(32) as `0x${string}`;
        await send("SSTORE zero->nonzero (second new slot)", r.contractAddress!, key2);
    }
    writeFileSync(outJson, JSON.stringify(out, null, 2));
    console.error(`[${label}] wrote ${outJson}`);
}
main().catch((e) => { console.error(e); process.exit(1); });
