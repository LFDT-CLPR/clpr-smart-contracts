// HieroVerifier.verifyBundle with (a) a non-matching trust anchor (first bundle / after a hinTS key
// rotation: WRAPS re-hashes the VK with Poseidon) and (b) the matching keccak256(hintsVk) anchor
// (steady state: Poseidon skipped). Reuses the stack deployed by measure-hiero-gas.ts.
// usage: npx tsx tools/tempo-localnet/measure-hiero-anchor.ts <rpcUrl> <measure-hiero-gas.json>
import {readFileSync} from "node:fs";
import path from "node:path";
import {encodeFunctionData, keccak256} from "viem";
import {makeDeployClients} from "../../script/deploy/client.ts";
const WT = path.resolve(import.meta.dirname, "../..");
const [rpcUrl, prevJson] = process.argv.slice(2);
const prev = JSON.parse(readFileSync(prevJson, "utf8"));
const c = await makeDeployClients({rpcUrl, privateKey: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"});
const abi = JSON.parse(readFileSync(path.join(WT, "out/HieroVerifier.sol/HieroVerifier.json"), "utf8")).abi;
const raw = readFileSync(path.join(WT, "test/verifiers/hiero/fixtures/stateProof.bin"));
const proof = `0x${raw.toString("hex")}` as `0x${string}`;
const ledgerId = `0x${readFileSync(path.join(WT, "test/verifiers/hiero/fixtures/trustAnchor.bin")).toString("hex")}` as `0x${string}`;
const hintsVk = `0x${raw.subarray(raw.length - 3432, raw.length - 3432 + 1096).toString("hex")}` as `0x${string}`;
async function run(tag: string, anchor: `0x${string}`) {
    const data = encodeFunctionData({abi, functionName: "verifyBundle", args: [proof, anchor, "0x"]});
    const h = await c.walletClient.sendTransaction({account: c.account, chain: c.chain, to: prev.addresses.hiero, data, gas: 12_000_000n});
    const r = await c.publicClient.waitForTransactionReceipt({hash: h});
    console.log(`${tag.padEnd(58)} status=${r.status} gasUsed=${r.gasUsed}`);
}
await run("verifyBundle, anchor = ledgerId (first bundle / after key rotation)", ledgerId);
await run("verifyBundle, anchor = keccak256(hintsVk) (steady state)", keccak256(hintsVk));
