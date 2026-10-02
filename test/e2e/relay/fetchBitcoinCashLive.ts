/**
 * Refresh script for the Bitcoin Cash live fixtures (test/e2e/fixtures/bitcoin-cash-live/).
 *
 *   npx tsx test/e2e/relay/fetchBitcoinCashLive.ts     (or: npm run bitcoin-cash-live:refresh)
 *
 * Source: public Electrum Cash (Fulcrum) servers over TLS, protocol 1.4
 * (`blockchain.block.headers`, `blockchain.transaction.id_from_pos`, `blockchain.transaction.get`).
 * Every header is fetched from two servers and must match byte for byte; the script also checks
 * double-SHA256 linkage, proof of work and the ASERT nBits of every header before writing.
 *
 * Fixtures:
 *   asert-activation.json  headers 661646..661670: the ASERT anchor block 661647 (BCHN mainnet
 *                          chainparams) with its parent and the first 23 ASERT blocks.
 *   mainnet-recent.json    145 consecutive recent headers starting 2 below a Bitcoin 2016-block
 *                          boundary (969694..969838 at capture time).
 *   mainnet-tx.json        a real transaction from the boundary block with its Merkle branch.
 *
 * All hashes are stored in Bitcoin's internal byte order (as hashed by the verifier), with the
 * display order alongside where useful.
 */
import {createHash} from "node:crypto";
import {mkdirSync, writeFileSync} from "node:fs";
import {dirname, join} from "node:path";
import {connect} from "node:tls";
import {fileURLToPath} from "node:url";

const OUT = join(dirname(fileURLToPath(import.meta.url)), "../fixtures/bitcoin-cash-live");
const SERVERS: [string, number][] = [
    ["bch.imaginary.cash", 50002],
    ["fulcrum.greyh.at", 50002],
    ["bch.loping.net", 50002]
];

// BCHN src/chainparams.cpp, mainnet.
export const BCH_POW_LIMIT = (1n << 224n) - 1n;
export const BCH_ASERT_ANCHOR = {height: 661647, bits: 0x1804dafe, prevBlockTime: 1605447844};
export const BCH_ASERT_HALF_LIFE = 2 * 24 * 60 * 60;
export const BCH_CAIP2 = "bip122:000000000000000000651ef99cb9fcbe";

function electrum(host: string, port: number, method: string, params: unknown[]): Promise<any> {
    return new Promise((resolve, reject) => {
        const sock = connect({host, port, servername: host, rejectUnauthorized: false}, () => {
            sock.write(JSON.stringify({id: 0, method: "server.version", params: ["clpr-fixture", "1.4"]}) + "\n");
            sock.write(JSON.stringify({id: 1, method, params}) + "\n");
        });
        let buf = "";
        const timer = setTimeout(() => {
            sock.destroy();
            reject(new Error(`${host}: timeout`));
        }, 30_000);
        sock.on("data", (d) => {
            buf += d.toString();
            let nl;
            while ((nl = buf.indexOf("\n")) >= 0) {
                const line = buf.slice(0, nl);
                buf = buf.slice(nl + 1);
                const msg = JSON.parse(line);
                if (msg.id !== 1) continue;
                clearTimeout(timer);
                sock.end();
                if (msg.error) reject(new Error(`${host}: ${JSON.stringify(msg.error)}`));
                else resolve(msg.result);
            }
        });
        sock.on("error", (e) => {
            clearTimeout(timer);
            reject(e);
        });
    });
}

/** Call two different servers and require identical results. */
async function call2(method: string, params: unknown[]): Promise<any> {
    const results: any[] = [];
    for (const [host, port] of SERVERS) {
        try {
            results.push(await electrum(host, port, method, params));
        } catch (e) {
            console.warn(`  ${host} failed: ${(e as Error).message}`);
        }
        if (results.length === 2) break;
    }
    if (results.length < 2) throw new Error(`${method}: fewer than two servers answered`);
    // `max` (the server's batch limit) is configuration, not chain data.
    const strip = (x: any) => (x && typeof x === "object" && !Array.isArray(x) ? {...x, max: undefined} : x);
    if (JSON.stringify(strip(results[0])) !== JSON.stringify(strip(results[1]))) {
        throw new Error(`${method}: servers disagree`);
    }
    return results[0];
}

const rev = (hex: string) => hex.match(/../g)!.reverse().join("");
const hash256 = (hex: string) =>
    createHash("sha256").update(createHash("sha256").update(Buffer.from(hex, "hex")).digest()).digest("hex");
const le32 = (hex: string, off: number) => parseInt(rev(hex.slice(off * 2, off * 2 + 8)), 16);

function bitsToTarget(bits: number): bigint {
    const size = BigInt(bits >>> 24);
    const word = BigInt(bits & 0x7fffff);
    return size <= 3n ? word >> (8n * (3n - size)) : word << (8n * (size - 3n));
}

function targetToBits(t: bigint): number {
    let size = 0n;
    for (let x = t; x > 0n; x >>= 8n) size++;
    let c = size <= 3n ? t << (8n * (3n - size)) : t >> (8n * (size - 3n));
    if (c & 0x800000n) {
        c >>= 8n;
        size++;
    }
    return Number(c | (size << 24n));
}

/** BCHN CalculateASERT + GetCompact (mirror of BitcoinLib.asertBits). */
export function asertBits(parentHeight: number, parentTime: number): number {
    const a = BCH_ASERT_ANCHOR;
    const timeDiff = BigInt(parentTime - a.prevBlockTime);
    const heightDiff = BigInt(parentHeight - a.height);
    const num = (timeDiff - 600n * (heightDiff + 1n)) * 65536n;
    const exponent = num / BigInt(BCH_ASERT_HALF_LIFE); // BigInt division truncates toward zero, like C++
    let shifts = exponent >> 16n; // floor
    const frac = exponent - shifts * 65536n;
    const factor =
        65536n + ((195766423245049n * frac + 971821376n * frac * frac + 5127n * frac ** 3n + (1n << 47n)) >> 48n);
    let next = bitsToTarget(a.bits) * factor;
    shifts -= 16n;
    next = shifts <= 0n ? next >> -shifts : next << shifts;
    if (next === 0n) next = 1n;
    else if (next > BCH_POW_LIMIT) next = BCH_POW_LIMIT;
    return targetToBits(next);
}

interface Header {
    height: number;
    hashDisplay: string;
    hashInternal: string;
    header: string;
    time: number;
    bits: string;
}

async function headers(from: number, count: number): Promise<Header[]> {
    const out: Header[] = [];
    for (let start = from; start < from + count; start += 2016) {
        const n = Math.min(2016, from + count - start);
        const r = await call2("blockchain.block.headers", [start, n]);
        if (r.count !== n) throw new Error(`asked ${n} headers at ${start}, got ${r.count}`);
        for (let i = 0; i < n; i++) {
            const h: string = r.hex.slice(i * 160, (i + 1) * 160);
            const internal = hash256(h);
            out.push({
                height: start + i,
                hashDisplay: rev(internal),
                hashInternal: "0x" + internal,
                header: "0x" + h,
                time: le32(h, 68),
                bits: "0x" + le32(h, 72).toString(16).padStart(8, "0")
            });
        }
    }
    // Linkage, proof of work and ASERT, checked before anything is written.
    for (let i = 0; i < out.length; i++) {
        const h = out[i];
        if (BigInt("0x" + h.hashDisplay) > bitsToTarget(Number(h.bits))) throw new Error(`PoW fails at ${h.height}`);
        if (i === 0) continue;
        if (h.header.slice(10, 74) !== out[i - 1].hashInternal.slice(2)) throw new Error(`linkage at ${h.height}`);
        if (out[i - 1].height >= BCH_ASERT_ANCHOR.height) {
            const expected = asertBits(out[i - 1].height, out[i - 1].time);
            if (expected !== Number(h.bits)) throw new Error(`ASERT mismatch at ${h.height}`);
        }
    }
    return out;
}

function write(name: string, obj: unknown) {
    writeFileSync(join(OUT, name), JSON.stringify(obj, null, 1) + "\n");
    console.log(`wrote ${name}`);
}

async function main() {
    mkdirSync(OUT, {recursive: true});
    const capturedAt = new Date().toISOString();
    const source = "Electrum Cash (Fulcrum) servers " + SERVERS.map(([h]) => h).join(", ") + "; two must agree";

    // 1. ASERT activation: anchor parent 661646, anchor 661647, first ASERT blocks.
    const act = await headers(BCH_ASERT_ANCHOR.height - 1, 25);
    if (act[0].time !== BCH_ASERT_ANCHOR.prevBlockTime) throw new Error("anchor parent time != chainparams");
    if (Number(act[1].bits) !== BCH_ASERT_ANCHOR.bits) throw new Error("anchor bits != chainparams");
    write("asert-activation.json", {
        description: "Bitcoin Cash mainnet headers around the ASERT anchor block 661647",
        capturedAt,
        source,
        asertAnchor: BCH_ASERT_ANCHOR,
        halfLife: BCH_ASERT_HALF_LIFE,
        startHeight: act[0].height,
        headersConcat: "0x" + act.map((h) => h.header.slice(2)).join(""),
        headers: act
    });

    // 2. Recent headers starting 2 below the latest Bitcoin-style 2016 boundary that has 143 blocks on top.
    const tip = (await call2("blockchain.headers.get_tip", [])).height as number;
    const boundary = Math.floor((tip - 150) / 2016) * 2016;
    const recent = await headers(boundary - 2, 145);
    write("mainnet-recent.json", {
        description: `Bitcoin Cash mainnet headers ${boundary - 2}..${boundary + 142} (a Bitcoin 2016-block boundary at ${boundary})`,
        capturedAt,
        source,
        tipAtCapture: tip,
        boundary,
        startHeight: recent[0].height,
        headersConcat: "0x" + recent.map((h) => h.header.slice(2)).join(""),
        headers: recent
    });

    // 3. A real transaction from the boundary block (position 1: the first non-coinbase).
    const pos = 1;
    const r = await call2("blockchain.transaction.id_from_pos", [boundary, pos, true]);
    const raw: string = await call2("blockchain.transaction.get", [r.tx_hash, false]);
    if (hash256(raw) !== rev(r.tx_hash)) throw new Error("txid mismatch");
    write("mainnet-tx.json", {
        description: `Real Bitcoin Cash transaction ${r.tx_hash} (block ${boundary}, position ${pos}) with its Merkle branch`,
        capturedAt,
        source,
        txidDisplay: r.tx_hash,
        txidInternal: "0x" + rev(r.tx_hash),
        raw: "0x" + raw,
        blockHeight: boundary,
        blockHeader: recent[2].header,
        txIndex: pos,
        // Electrum returns siblings in display order; convert to internal order.
        branch: (r.merkle as string[]).map((h) => "0x" + rev(h))
    });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
    await main();
}
