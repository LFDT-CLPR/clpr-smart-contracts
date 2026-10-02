/**
 * One-shot fetcher for the BitcoinVerifier mainnet fixtures. The output JSON files are committed;
 * this script only documents where they came from and lets them be regenerated.
 *
 *   npx tsx test/verifiers/bitcoin/fixtures/fetch-mainnet.ts
 *
 * Source: blockstream.info/api (Esplora). All hashes in the JSON are in Bitcoin's *internal* byte
 * order (the order they appear inside headers / hashed by the verifier), with the usual
 * human-facing "display" order alongside for readability.
 */
import {writeFileSync} from "node:fs";
import {join, dirname} from "node:path";
import {fileURLToPath} from "node:url";

const API = "https://blockstream.info/api";
const OUT = dirname(fileURLToPath(import.meta.url));

async function get(path: string): Promise<string> {
    for (let attempt = 0; attempt < 5; attempt++) {
        const r = await fetch(API + path);
        if (r.ok) return (await r.text()).trim();
        await new Promise((res) => setTimeout(res, 1000 * (attempt + 1)));
    }
    throw new Error(`GET ${path} failed`);
}

const rev = (hex: string) => hex.match(/../g)!.reverse().join("");

async function headerAt(height: number) {
    const hash = await get(`/block-height/${height}`);
    const header = await get(`/block/${hash}/header`);
    const time = parseInt(rev(header.slice(136, 144)), 16);
    const bits = "0x" + rev(header.slice(144, 152));
    return {height, hashDisplay: hash, hashInternal: "0x" + rev(hash), header: "0x" + header, time, bits};
}

/** Headers [from, to] around a 2016-block retarget boundary plus the period-start header. */
async function boundaryFixture(name: string, boundary: number, before: number, after: number) {
    const from = boundary - before;
    const headers = [];
    for (let h = from; h <= boundary + after; h++) headers.push(await headerAt(h));
    // Period start of the period that contains `from` (the retarget at `boundary` measures from it).
    const periodStart = await headerAt(boundary - 2016);
    const fixture = {
        description: `Bitcoin mainnet headers ${from}..${boundary + after} around the retarget at ${boundary}`,
        boundary,
        startHeight: from,
        periodStart,
        headersConcat: "0x" + headers.map((h) => h.header.slice(2)).join(""),
        headers
    };
    writeFileSync(join(OUT, `${name}.json`), JSON.stringify(fixture, null, 2) + "\n");
    console.log(`wrote ${name}.json (${headers.length} headers)`);
}

/** A real transaction with its Esplora merkle proof and block header. */
async function txFixture(name: string, txid: string) {
    const raw = await get(`/tx/${txid}/hex`);
    const status = JSON.parse(await get(`/tx/${txid}/status`));
    const proof = JSON.parse(await get(`/tx/${txid}/merkle-proof`));
    const header = await get(`/block/${status.block_hash}/header`);
    const fixture = {
        description: `Real mainnet transaction ${txid} with its merkle branch`,
        txidDisplay: txid,
        txidInternal: "0x" + rev(txid),
        raw: "0x" + raw,
        blockHeight: status.block_height,
        blockHeader: "0x" + header,
        txIndex: proof.pos,
        // Esplora returns siblings in display order; convert to internal order for hashing.
        branch: proof.merkle.map((h: string) => "0x" + rev(h))
    };
    writeFileSync(join(OUT, `${name}.json`), JSON.stringify(fixture, null, 2) + "\n");
    console.log(`wrote ${name}.json`);
}

async function firstTxs(height: number): Promise<string[]> {
    const hash = await get(`/block-height/${height}`);
    return JSON.parse(await get(`/block/${hash}/txids`));
}

await boundaryFixture("mainnet-2016", 2016, 2, 14);
await boundaryFixture("mainnet-32256", 32256, 2, 14);
await boundaryFixture("mainnet-967680", 967680, 2, 14);

// A segwit tx and a legacy tx from recent blocks (picked by scanning for the serialization type).
const txids = await firstTxs(967680);
let segwit: string | undefined;
let legacy: string | undefined;
for (const id of txids.slice(1, 400)) {
    const raw = await get(`/tx/${id}/hex`);
    const isSegwit = raw.slice(8, 12) === "0001";
    if (isSegwit && !segwit) segwit = id;
    if (!isSegwit && !legacy) legacy = id;
    if (segwit && legacy) break;
}
if (!segwit || !legacy) throw new Error("could not find both tx kinds");
await txFixture("mainnet-tx-segwit", segwit);
await txFixture("mainnet-tx-legacy", legacy);
