/**
 * buildWavesLiveFixture.ts — record a live Waves TESTNET finalization for WavesFinalityVerifier.
 *
 *   npm run waves-live:refresh
 *
 * Deterministic Finality (feature 25) is active on Waves testnet (since height 4,044,000) and still
 * in voting on mainnet, so testnet is the only network with BLS endorsements to record.
 *
 * Writes test/e2e/fixtures/waves-live/waves.json with raw REST responses:
 *   finality     GET /blockchain/finality: generation period, generators (address, commit tx, balance)
 *   commits      GET /transactions/info/{id} of each CommitToGeneration tx (the BLS endorser key)
 *   endorsed     header P (the block proven final)
 *   voting       header B = P + 1, whose finalizationVoting endorses P with ≥ 2/3 of the balance
 *                from BLS endorsers alone (the producer's own weight is not counted on-chain)
 *   finalized    header F at the voting's finalizedHeight (its id is part of the signed message)
 * Checked off-chain before writing: P's id recomputed from its protobuf header, B.reference = P.id,
 * the aggregated BLS signature verified with @noble/curves over F.id ‖ BE32(F.height) ‖ P.id.
 */

import {bls12_381} from "@noble/curves/bls12-381";
import {blake2b} from "@noble/hashes/blake2b";
import {mkdirSync, writeFileSync} from "node:fs";
import https from "node:https";
import path from "node:path";

export const FIXTURE_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../fixtures/waves-live");
export const NODE = "https://nodes-testnet.wavesnodes.com";
export const CHAIN_ID = "T".charCodeAt(0);

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export function b58(s: string): Buffer {
    let n = 0n;
    for (const c of s) {
        const v = B58.indexOf(c);
        if (v < 0) throw new Error(`bad base58 ${s}`);
        n = n * 58n + BigInt(v);
    }
    let hex = n === 0n ? "" : n.toString(16);
    if (hex.length % 2) hex = "0" + hex;
    let pad = 0;
    while (s[pad] === "1") pad++;
    return Buffer.concat([Buffer.alloc(pad), Buffer.from(hex, "hex")]);
}

// ── Protobuf (waves/block.proto Block.Header, proto3: defaults omitted, repeated scalars packed) ──
function varint(v: bigint): Buffer {
    if (v < 0n) v += 1n << 64n;
    const out: number[] = [];
    do {
        let b = Number(v & 0x7fn);
        v >>= 7n;
        if (v !== 0n) b |= 0x80;
        out.push(b);
    } while (v !== 0n);
    return Buffer.from(out);
}
const key = (f: number, w: number) => varint(BigInt((f << 3) | w));
const vi = (f: number, v: bigint | number) => (BigInt(v) === 0n ? Buffer.alloc(0) : Buffer.concat([key(f, 0), varint(BigInt(v))]));
const by = (f: number, b: Buffer) => (b.length === 0 ? Buffer.alloc(0) : Buffer.concat([key(f, 2), varint(BigInt(b.length)), b]));
function packed(f: number, xs: number[]): Buffer {
    if (!xs || xs.length === 0) return Buffer.alloc(0);
    const body = Buffer.concat(xs.map((x) => varint(BigInt(x))));
    return Buffer.concat([key(f, 2), varint(BigInt(body.length)), body]);
}

/** `PBBlocks.protobuf(header)` from the REST header JSON (version 5, no challenged header). */
export function headerProtobuf(h: any, chainId = CHAIN_ID): Buffer {
    if (h.version !== 5) throw new Error(`block version ${h.version}`);
    if (h.challengedHeader) throw new Error("challenged headers are not encoded");
    const fv = h.finalizationVoting;
    let fvb = Buffer.alloc(0);
    if (fv) {
        if ((fv.conflictEndorsements ?? []).length) throw new Error("conflict endorsements are not encoded");
        fvb = Buffer.concat([packed(1, fv.endorserIndexes), vi(2, fv.finalizedHeight), by(3, b58(fv.aggregatedEndorsementSignature))]);
    }
    return Buffer.concat([
        vi(1, chainId), by(2, b58(h.reference)), vi(3, h["nxt-consensus"]["base-target"]),
        by(4, b58(h["nxt-consensus"]["generation-signature"])), packed(5, h.features ?? []), vi(6, h.timestamp),
        vi(7, h.version), by(8, b58(h.generatorPublicKey)), vi(9, h.desiredReward), by(10, b58(h.transactionsRoot)),
        by(11, b58(h.stateHash)), fv ? by(13, fvb) : Buffer.alloc(0)
    ]);
}

export const blockId = (h: any) => Buffer.from(blake2b(headerProtobuf(h), {dkLen: 32}));

export function endorsementMessage(finalizedId: Buffer, finalizedHeight: number, endorsedId: Buffer): Buffer {
    const hb = Buffer.alloc(4);
    hb.writeUInt32BE(finalizedHeight);
    return Buffer.concat([finalizedId, hb, endorsedId]);
}

/** One GET on a fresh connection (agent: false): the public endpoint balances connections over
 *  nodes that can lag by days, so a reused keep-alive connection would pin a lagging node. */
function getOnce(p: string): Promise<{status: number; json: any}> {
    return new Promise((resolve, reject) => {
        const req = https.get(NODE + p, {agent: false, timeout: 30_000}, (res) => {
            let body = "";
            res.on("data", (c) => (body += c));
            res.on("end", () => {
                try {
                    resolve({status: res.statusCode ?? 0, json: JSON.parse(body)});
                } catch (e) {
                    reject(e);
                }
            });
        });
        req.on("error", reject);
        req.on("timeout", () => req.destroy(new Error("timeout")));
    });
}

async function get(p: string): Promise<any> {
    for (let attempt = 0; ; attempt++) {
        const r = await getOnce(p).catch((e) => ({status: 0, json: {error: String(e)}}));
        if (r.status === 200 && !r.json.error) return r.json;
        if (attempt >= 10) throw new Error(`${p}: ${r.status} ${JSON.stringify(r.json)}`);
        await new Promise((res) => setTimeout(res, 1000));
    }
}

export async function capture() {
    const finality = await get("/blockchain/finality");
    const gens = finality.currentGenerators as any[];
    const commits = [];
    for (const g of gens) commits.push(await get(`/transactions/info/${g.transactionId}`));
    const pks = commits.map((c) => b58(c.endorserPublicKey));
    const total = gens.reduce((a, g) => a + BigInt(g.balance), 0n);
    const start = Number(finality.currentGenerationPeriod.start);

    const tip = Number((await get("/blocks/height")).height) - 2;
    const from = Math.max(start, tip - 99);
    let headers: any[] = [];
    for (let attempt = 0; ; attempt++) {
        // Behind the load balancer some nodes lag; keep the answer of one that has the whole range.
        headers = (await get(`/blocks/headers/seq/${from}/${tip}`)) as any[];
        if (headers.length === tip - from + 1 && headers[headers.length - 1].height === tip) break;
        if (attempt >= 10) throw new Error("no node served the full header range");
        await new Promise((res) => setTimeout(res, 1500));
    }
    for (let i = headers.length - 1; i > 0; i--) {
        const B = headers[i];
        const P = headers[i - 1];
        const fv = B.finalizationVoting;
        if (!fv || (fv.conflictEndorsements ?? []).length || P.height < start) continue;
        const endorsed = (fv.endorserIndexes as number[]).reduce((a, k) => a + BigInt(gens[k].balance), 0n);
        if (endorsed * 3n < total * 2n) continue;
        if (!blockId(P).equals(b58(P.id))) throw new Error(`P ${P.height}: recomputed id != id`);
        if (B.reference !== P.id) throw new Error("B does not reference P");
        const F = await get(`/blocks/headers/at/${fv.finalizedHeight}`);
        const msg = endorsementMessage(b58(F.id), fv.finalizedHeight, b58(P.id));
        const agg = bls12_381.aggregatePublicKeys(fv.endorserIndexes.map((k: number) => pks[k]));
        if (!bls12_381.verify(b58(fv.aggregatedEndorsementSignature), msg, agg)) throw new Error("BLS aggregate does not verify off-chain");
        return {
            chain: "waves-testnet",
            node: NODE,
            capturedAt: new Date().toISOString(),
            meta: {
                endorsedHeight: P.height, votingHeight: B.height, finalizedHeight: fv.finalizedHeight,
                endorsers: fv.endorserIndexes, endorsedBalance: endorsed.toString(), totalBalance: total.toString(),
                generators: gens.length, period: finality.currentGenerationPeriod
            },
            raw: {finality, commits, endorsed: P, voting: B, finalized: F}
        };
    }
    throw new Error("no block in the last 100 whose BLS endorsers alone reach 2/3");
}

if (process.argv[1] && import.meta.url.endsWith(path.basename(process.argv[1]))) {
    mkdirSync(FIXTURE_DIR, {recursive: true});
    const f = await capture();
    writeFileSync(path.join(FIXTURE_DIR, "waves.json"), JSON.stringify(f, null, 1) + "\n");
    console.log("waves:", JSON.stringify(f.meta));
}
