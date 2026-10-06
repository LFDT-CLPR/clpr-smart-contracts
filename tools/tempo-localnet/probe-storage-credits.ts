// Does clearing a slot pay for creating a different slot later? Two probe contracts, several transactions.
// usage: npx tsx tools/tempo-localnet/probe-storage-credits.ts <rpcUrl>
import {makeDeployClients} from "../../script/deploy/client.ts";
const KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;
const rpcUrl = process.argv[2];
const initcode = "0x6007600a5f3960075ff36020355f355500" as `0x${string}`; // storage[calldata[0:32]] = calldata[32:64]
const c = await makeDeployClients({rpcUrl, privateKey: KEY});
async function deployProbe() {
    const h = await c.walletClient.sendTransaction({account: c.account, chain: c.chain, data: initcode});
    return (await c.publicClient.waitForTransactionReceipt({hash: h})).contractAddress!;
}
const word = (h: string) => h.padStart(64, "0");
async function tx(tag: string, probe: `0x${string}`, key: string, val: string) {
    const data = `0x${word(key)}${word(val)}` as `0x${string}`;
    const h = await c.walletClient.sendTransaction({account: c.account, chain: c.chain, to: probe, data, gas: 400000n});
    const r = await c.publicClient.waitForTransactionReceipt({hash: h});
    console.log(`${tag.padEnd(58)} gasUsed=${r.gasUsed}`);
}
const A = await deployProbe(), B = await deployProbe();
await tx("A: create slot 1", A, "01", "1");
await tx("A: create slot 2", A, "02", "1");
await tx("A: clear slot 1", A, "01", "0");
await tx("A: create slot 3 (different key, after one clear)", A, "03", "1");
await tx("A: create slot 4 (no credit left?)", A, "04", "1");
await tx("A: clear slot 2", A, "02", "0");
await tx("B: create slot 1 (other contract, after A cleared one)", B, "01", "1");
await tx("A: create slot 5 (credit from clearing slot 2 still here?)", A, "05", "1");
await tx("A: clear slot 3", A, "03", "0");
await tx("A: clear slot 4", A, "04", "0");
await tx("A: create slot 6 (two credits available)", A, "06", "1");
await tx("A: create slot 7", A, "07", "1");
await tx("A: create slot 8 (credits exhausted)", A, "08", "1");
