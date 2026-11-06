// List every tx sent by the deployer in [fromBlock, toBlock]: gas used, created contract and its code size.
// usage: npx tsx tools/tempo-localnet/scan-deploy-gas.ts <rpcUrl> <fromBlock> <toBlock> <outJson>
import {writeFileSync} from "node:fs";
import {createPublicClient, http} from "viem";
const [rpcUrl, fromS, toS, outJson] = process.argv.slice(2);
const DEPLOYER = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
const pc = createPublicClient({transport: http(rpcUrl)});
const rows: any[] = [];
for (let n = BigInt(fromS); n <= BigInt(toS); n++) {
    const b = await pc.getBlock({blockNumber: n, includeTransactions: true});
    for (const tx of b.transactions as any[]) {
        if (tx.from.toLowerCase() !== DEPLOYER) continue;
        const r = await pc.getTransactionReceipt({hash: tx.hash});
        let codeBytes = 0, name = "call";
        if (r.contractAddress) {
            const code = await pc.getCode({address: r.contractAddress});
            codeBytes = (code!.length - 2) / 2; name = "create";
        }
        rows.push({block: Number(n), kind: name, to: tx.to, contract: r.contractAddress, gasUsed: Number(r.gasUsed), codeBytes, inputBytes: (tx.input.length - 2) / 2, status: r.status});
    }
}
writeFileSync(outJson, JSON.stringify(rows, null, 2));
console.log(JSON.stringify({txs: rows.length, totalGas: rows.reduce((a, r) => a + r.gasUsed, 0), creates: rows.filter(r => r.kind === "create").map(r => [r.codeBytes, r.gasUsed])}));
