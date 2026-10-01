/**
 * buildProvenanceLiveFixture.ts — record a live Provenance (pio-mainnet-1) bundle for CosmWasmVerifier.
 *
 *   npm run provenance-live:refresh
 *
 * Writes test/e2e/fixtures/provenance-live/provenance.json with the RAW public-RPC responses (the spec
 * re-derives every proof from them with relay/cometbft.ts + relay/cosmwasm.ts) and a small `meta`.
 *
 * What it captures:
 *   R      the most recent validator-set rotation header (next_validators_hash ≠ validators_hash),
 *          found by scanning /blockchain back from the tip. Its commit is signed by the OLD set; a
 *          bundle at R returns the new anchor. Commit + validators at R.
 *   B      a header 2 blocks after R, signed by the NEW set. Commit + validators at B. A bundle at B
 *          from an anchor that still trusts the old set needs R as a hop (two commits).
 *   proofs ABCI ICS-23 proofs at R-1 and B-1 (state committed in the app_hash of R and B) for the
 *          real contract below:
 *            queue   0x03 ‖ contract ‖ 0x000a "clpr_queue" ‖ channelId   (absent → non-existence)
 *            cw2     0x03 ‖ contract ‖ "contract_info"                   (cw2 Item, exists)
 *            map     0x03 ‖ contract ‖ 0x0003 "sb1" ‖ <bech32 owner>     (cw-storage-plus Map, exists)
 * Every capture is cross-checked off-chain first (header hash == block id, set hash ==
 * validators_hash, every selected signature verifies, >2/3 power). The ICS-23 proofs are checked
 * on-chain by the spec (test/e2e/tests/verifiers/provenance-live.spec.ts).
 */

import {mkdirSync, writeFileSync} from "node:fs";
import path from "node:path";
import {keccak256, type Hex} from "viem";
import {encodeSignedHeader, fetchAbciProof, fetchCommit, fetchStatus, fetchValidators} from "./cometbft.js";
import {canonicalAddress, contractStoreKey, mapKey, queueRecordKey, WASM_STORE} from "./cosmwasm.js";

export const FIXTURE_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../fixtures/provenance-live");
export const RPC = "https://rpc.provenance.io";
export const CHANNEL_ID = keccak256(new TextEncoder().encode("clpr-provenance-live")) as Hex;

/** Figure "Crypto-Backed Loan" pool (code 52, cw2 democratized_prime_pool_v2 1.0.0). */
export const CONTRACT = "pb1msvy4f0vcdm9kx4x56lrk5ctlnh88ag84k4ggskywzwvf2nzlmtqnm5ged";
export const MAP_NAMESPACE = "sb1";
export const MAP_KEY = "pb1whzz6j94tfsz2nyhqd2xu4ctfru28lj4zaa5npr5w39r6yy2slnsvyft3v";

/** A CometBFT + wasmd chain and the real contract whose storage the fixture proves. */
export interface CosmWasmChainSpec {
    name: string;
    rpc: string;
    channelId: Hex;
    contract: string; // bech32, 32-byte address
    mapNamespace: string; // cw-storage-plus Map namespace with a known live entry
    mapKey: string; // that entry's key (UTF-8)
}

export const PROVENANCE: CosmWasmChainSpec = {
    name: "provenance", rpc: RPC, channelId: CHANNEL_ID, contract: CONTRACT, mapNamespace: MAP_NAMESPACE, mapKey: MAP_KEY
};

export function fixtureKeys(c: CosmWasmChainSpec = PROVENANCE): {name: string; key: Buffer}[] {
    const a = canonicalAddress(c.contract);
    return [
        {name: "queue", key: queueRecordKey(a, Buffer.from(c.channelId.slice(2), "hex"))},
        {name: "cw2", key: contractStoreKey(a, Buffer.from("contract_info"))},
        {name: "map", key: contractStoreKey(a, mapKey(c.mapNamespace, Buffer.from(c.mapKey)))}
    ];
}

async function rpcJson(rpc: string, p: string): Promise<any> {
    const r = await fetch(rpc + p, {signal: AbortSignal.timeout(30_000)});
    if (!r.ok) throw new Error(`${p}: ${r.status}`);
    return r.json();
}

/** Most recent height ≤ tip-5 whose header changes the validator set, scanning `maxBlocks` back. */
async function findRotation(rpc: string, tip: bigint, maxBlocks = 6000n): Promise<bigint | undefined> {
    for (let max = tip - 5n; max > tip - maxBlocks; max -= 20n) {
        const j = await rpcJson(rpc, `/blockchain?minHeight=${max - 19n}&maxHeight=${max}`);
        const metas = j.result.block_metas as any[];
        for (const m of metas) {
            if (m.header.validators_hash !== m.header.next_validators_hash) return BigInt(m.header.height);
        }
    }
    return undefined;
}

async function captureHeight(c: CosmWasmChainSpec, H: bigint) {
    const [commit, vals] = await Promise.all([fetchCommit(c.rpc, H), fetchValidators(c.rpc, H)]);
    const enc = encodeSignedHeader(commit.sh, vals.vals); // throws unless hash, set and >2/3 check out
    const abci = [];
    for (const k of fixtureKeys(c)) abci.push((await fetchAbciProof(c.rpc, WASM_STORE, k.key, H - 1n)).json);
    return {commit: commit.json, validators: vals.json, abci, signers: enc.signerIndices.length, n: vals.vals.length};
}

export async function capture(c: CosmWasmChainSpec = PROVENANCE) {
    const st = await fetchStatus(c.rpc);
    const tip = BigInt(st.sync_info.latest_block_height);
    const R = await findRotation(c.rpc, tip);
    if (R === undefined) throw new Error("no validator-set rotation in the scanned window");
    const B = R + 2n;
    const r = await captureHeight(c, R);
    const b = await captureHeight(c, B);
    const rh = r.commit.result.signed_header.header;
    const bh = b.commit.result.signed_header.header;
    if (bh.validators_hash !== rh.next_validators_hash) throw new Error("B is not signed by R's next set");
    return {
        chain: c.name,
        chainId: rh.chain_id,
        rpc: c.rpc,
        nodeVersion: st.node_info.version,
        capturedAt: new Date().toISOString(),
        channelId: c.channelId,
        contract: c.contract,
        mapNamespace: c.mapNamespace,
        mapKey: c.mapKey,
        keys: fixtureKeys(c).map((k) => ({name: k.name, key: "0x" + k.key.toString("hex")})),
        meta: {
            rotationHeight: R.toString(), bundleHeight: B.toString(),
            validators: r.n, signersAtR: r.signers, signersAtB: b.signers,
            oldSet: rh.validators_hash, newSet: rh.next_validators_hash
        },
        raw: {
            rotation: {commit: r.commit, validators: r.validators, abci: r.abci},
            bundle: {commit: b.commit, validators: b.validators, abci: b.abci}
        }
    };
}

if (process.argv[1] && import.meta.url.endsWith(path.basename(process.argv[1]))) {
    mkdirSync(FIXTURE_DIR, {recursive: true});
    const f = await capture();
    writeFileSync(path.join(FIXTURE_DIR, "provenance.json"), JSON.stringify(f, null, 1) + "\n");
    console.log("provenance:", JSON.stringify(f.meta));
}
