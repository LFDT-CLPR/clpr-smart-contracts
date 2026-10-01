/**
 * buildInitiaLiveFixture.ts — record live Initia mainnet (interwoven-1) data for InitiaMoveVerifier.
 *
 *   npm run initia-live:refresh
 *
 * Writes test/e2e/fixtures/initia-live/initia.json with the RAW public-RPC responses (the spec
 * re-derives every proof from them with relay/cometbft.ts) and a small `meta`.
 *
 * What it captures, all at one header H (tip − 5):
 *   commit H + validators H   checked off-chain by cometbft.ts.encodeSignedHeader: header hash ==
 *                             block_id.hash, validator-set hash == validators_hash, every selected
 *                             Ed25519 signature verifies, more than 2/3 of the power signed.
 *   resource proof at H−1     `0x21 ‖ 0x1 ‖ 0x02 ‖ BCS(StructTag{0x1, "dex", "ModuleStore", []})`: a
 *                             real Move resource whose first field is a `Table` (handle ‖ length),
 *                             the same shape as the CLPR `Service` resource.
 *   table-entry proof at H−1  `0x21 ‖ handle ‖ 0x03 ‖ BCS(PairKey)` for the first entry of that
 *                             table: a real Move table entry, the same shape as `channels[channelId]`.
 * The state at H−1 is committed in header H's app_hash (ABCI query semantics).
 *   rotation rate             validator-set changes (validators_hash ≠ next_validators_hash) in the
 *                             4,000 headers below H (/blockchain), for the rotation-cost estimate.
 * No CLPR Service is deployed on Initia, so these real Move items stand in for the CLPR ones; the
 * on-chain key derivation (InitiaMoveVerifier.resourceKey / tableEntryKey) is checked against them.
 */

import {mkdirSync, writeFileSync} from "node:fs";
import path from "node:path";
import {encodeSignedHeader, fetchAbciProof, fetchCommit, fetchStatus, fetchValidators} from "./cometbft.js";

export const FIXTURE_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../fixtures/initia-live");
export const RPC = "https://rpc.initia.xyz";
export const REST = "https://rest.initia.xyz";
export const MOVE_STORE = "move";

const STD = Buffer.alloc(32);
STD[31] = 1;

function uleb(n: number): Buffer {
    const out: number[] = [];
    do {
        let b = n & 0x7f;
        n >>>= 7;
        if (n !== 0) b |= 0x80;
        out.push(b);
    } while (n !== 0);
    return Buffer.from(out);
}

/** `0x21 ‖ addr ‖ 0x02 ‖ BCS(StructTag{addr, module, name, []})` (initia x/move/types/keys.go). */
export function resourceKey(addr: Buffer, module: string, name: string): Buffer {
    const m = Buffer.from(module, "utf8");
    const n = Buffer.from(name, "utf8");
    return Buffer.concat([Buffer.from([0x21]), addr, Buffer.from([0x02]), addr, uleb(m.length), m, uleb(n.length), n, Buffer.from([0])]);
}

/** `0x21 ‖ handle ‖ 0x03 ‖ BCS(key)`. */
export function tableEntryKey(handle: Buffer, bcsKey: Buffer): Buffer {
    return Buffer.concat([Buffer.from([0x21]), handle, Buffer.from([0x03]), bcsKey]);
}

/** Validator-set changes among the `window` headers below `H`, with the time span they cover. */
async function rotationRate(H: bigint, window = 4000n): Promise<{blocks: number; changes: number; from: string; to: string}> {
    let changes = 0;
    let blocks = 0;
    let from = "";
    let to = "";
    for (let hi = H - 1n; hi > H - 1n - window; hi -= 20n) {
        const r = await fetch(`${RPC}/blockchain?minHeight=${hi - 19n}&maxHeight=${hi}`, {signal: AbortSignal.timeout(30_000)});
        const metas = ((await r.json()) as any).result.block_metas as any[];
        for (const m of metas) {
            blocks++;
            if (m.header.validators_hash !== m.header.next_validators_hash) changes++;
            if (!to) to = m.header.time;
            from = m.header.time;
        }
    }
    return {blocks, changes, from, to};
}

async function restJson(p: string): Promise<any> {
    const r = await fetch(REST + p, {signal: AbortSignal.timeout(30_000)});
    if (!r.ok) throw new Error(`${p}: ${r.status}`);
    return r.json();
}

export async function capture() {
    const st = await fetchStatus(RPC);
    const H = BigInt(st.sync_info.latest_block_height) - 5n;
    const [commit, vals] = await Promise.all([fetchCommit(RPC, H), fetchValidators(RPC, H)]);
    const enc = encodeSignedHeader(commit.sh, vals.vals); // throws unless hash, set and >2/3 check out

    const resKey = resourceKey(STD, "dex", "ModuleStore");
    const res = await fetchAbciProof(RPC, MOVE_STORE, resKey, H - 1n);
    if (res.proof.value.length < 40) throw new Error("dex::ModuleStore missing");
    const handle = res.proof.value.subarray(0, 32);

    const entries = await restJson(`/initia/move/v1/tables/0x${handle.toString("hex")}/entries?pagination.limit=1`);
    const keyBytes = Buffer.from(entries.table_entries[0].key_bytes, "base64");
    const entKey = tableEntryKey(handle, keyBytes);
    const ent = await fetchAbciProof(RPC, MOVE_STORE, entKey, H - 1n);
    if (ent.proof.value.length === 0) throw new Error("table entry missing");

    const rotations = await rotationRate(H);
    const h = commit.sh.header;
    return {
        chain: "initia",
        chainId: h.chain_id,
        rpc: RPC,
        nodeVersion: st.node_info.version,
        capturedAt: new Date().toISOString(),
        meta: {
            height: H.toString(),
            stateHeight: (H - 1n).toString(),
            headerHash: "0x" + enc.headerHash.toString("hex"),
            appHash: "0x" + String(h.app_hash).toLowerCase(),
            validatorsHash: "0x" + String(h.validators_hash).toLowerCase(),
            nextValidatorsHash: "0x" + String(h.next_validators_hash).toLowerCase(),
            validators: vals.vals.length,
            signers: enc.signerIndices.length,
            signedPower: enc.signedPower.toString(),
            totalPower: enc.totalPower.toString(),
            tableHandle: "0x" + handle.toString("hex"),
            resourceKey: "0x" + resKey.toString("hex"),
            tableKeyBytes: "0x" + keyBytes.toString("hex"),
            tableEntryKey: "0x" + entKey.toString("hex"),
            rotations
        },
        raw: {commit: commit.json, validators: vals.json, resource: res.json, entry: ent.json}
    };
}

if (process.argv[1] && import.meta.url.endsWith(path.basename(process.argv[1]))) {
    mkdirSync(FIXTURE_DIR, {recursive: true});
    const f = await capture();
    writeFileSync(path.join(FIXTURE_DIR, "initia.json"), JSON.stringify(f, null, 1) + "\n");
    console.log("initia:", JSON.stringify(f.meta));
}
