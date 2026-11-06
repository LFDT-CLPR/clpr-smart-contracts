// SSTORE transition probe. Runtime: PUSH1 0x20 CALLDATALOAD PUSH0 CALLDATALOAD SSTORE STOP -> storage[calldata[0:32]] = calldata[32:64]
// usage: npx tsx tools/tempo-localnet/probe-sstore.ts <rpcUrl>
import {makeDeployClients} from "../../script/deploy/client.ts";
const KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;
const rpcUrl = process.argv[2];
const runtime = "6020355f355500"; // 7 bytes
const initcode = `0x6007600a5f3960075ff3${runtime}` as `0x${string}`;
const c = await makeDeployClients({rpcUrl, privateKey: KEY});
const dep = await c.walletClient.sendTransaction({account: c.account, chain: c.chain, data: initcode});
const r0 = await c.publicClient.waitForTransactionReceipt({hash: dep});
const probe = r0.contractAddress!;
const word = (h: string) => h.padStart(64, "0");
async function tx(tag: string, key: string, val: string) {
    const data = `0x${word(key)}${word(val)}` as `0x${string}`;
    const h = await c.walletClient.sendTransaction({account: c.account, chain: c.chain, to: probe, data, gas: 400000n});
    const r = await c.publicClient.waitForTransactionReceipt({hash: h});
    console.log(`${tag.padEnd(34)} gasUsed=${r.gasUsed}`);
    return Number(r.gasUsed);
}
const k = "aa".repeat(32);
await tx("0 -> 1 (new slot)", k, "1");
await tx("1 -> 2 (update)", k, "2");
await tx("2 -> 0 (clear, refund)", k, "0");
await tx("0 -> 3 (re-create cleared slot)", k, "3");
await tx("3 -> 3 (no-op write)", k, "3");
