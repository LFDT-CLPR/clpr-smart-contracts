// Same breakdown as test/verifiers/hiero/GasUsage.t.sol, read from a live chain via eth_call.
// usage: npx tsx tools/tempo-localnet/measure-hiero-steps.ts <label> <rpcUrl>
import {readFileSync} from "node:fs";
import path from "node:path";
import {makeDeployClients} from "../../script/deploy/client.ts";

const WT = path.resolve(import.meta.dirname, "../..");
const KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;
const [label, rpcUrl] = process.argv.slice(2);
const art = (file: string, name: string) => {
    const j = JSON.parse(readFileSync(path.join(WT, "out", file, `${name}.json`), "utf8"));
    return {abi: j.abi, bytecode: j.bytecode.object as `0x${string}`};
};
const hexConst = (src: string, name: string) => `0x${src.match(new RegExp(`${name}\\s*=\\s*hex"([0-9a-fA-F]+)"`))![1]}` as `0x${string}`;
const toHex = (b: Buffer) => `0x${b.toString("hex")}` as `0x${string}`;

const c = await makeDeployClients({rpcUrl, privateKey: KEY});
async function deploy(file: string, name: string, args: unknown[] = []) {
    const {abi, bytecode} = art(file, name);
    const hash = await c.walletClient.deployContract({abi, bytecode, args, account: c.account, chain: c.chain});
    const r = await c.publicClient.waitForTransactionReceipt({hash});
    return {address: r.contractAddress!, abi};
}
const a = await deploy("PoseidonPermuteA.sol", "PoseidonPermuteA");
const b = await deploy("PoseidonPermuteB.sol", "PoseidonPermuteB");
const poseidon = await deploy("PoseidonBN254Contract.sol", "PoseidonBN254Contract", [a.address, b.address]);
const hints = await deploy("TSSVerifierHarness.sol", "TSSVerifierHarness");
const wraps = await deploy("WrapsVerifierHarness.sol", "WRAPSVerifierHarness");
const steps = await deploy("HieroGasStepsHarness.sol", "HieroGasStepsHarness");

const raw = readFileSync(path.join(WT, "test/verifiers/hiero/fixtures/stateProof.bin"));
const ledgerId = toHex(readFileSync(path.join(WT, "test/verifiers/hiero/fixtures/trustAnchor.bin")));
const src = readFileSync(path.join(WT, "test/verifiers/hiero/GasUsage.t.sol"), "utf8");
const input = {
    rawProof: toHex(raw), ledgerId,
    hintsVk: toHex(raw.subarray(raw.length - 3432, raw.length - 3432 + 1096)),
    abProof: toHex(raw.subarray(raw.length - 704)),
    hintsVkN8: hexConst(src, "HINTS_VK_N8"), hintsSigN8: hexConst(src, "HINTS_SIG_N8"), blockRootN8: hexConst(src, "BLOCK_ROOT_N8"),
    hints: hints.address, wraps: wraps.address, poseidon: poseidon.address
};
const g = (await c.publicClient.readContract({address: steps.address, abi: steps.abi, functionName: "breakdown", args: [input]})) as bigint[];
const names = ["Protobuf decode", "Merkle path 1", "Merkle path 2", "hinTS BLS12-381", "WRAPS Groth16+KZG", "TOTAL"];
console.log(`=== ${label} (chain ${await c.publicClient.getChainId()})`);
names.forEach((n, k) => console.log(`${n.padEnd(20)} ${g[k].toString().padStart(10)}`));
