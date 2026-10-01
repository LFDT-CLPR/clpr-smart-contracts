/**
 * buildThorchainLiveFixture.ts — record a live THORChain (thorchain-1) bundle for CosmWasmVerifier.
 *
 *   npm run thorchain-live:refresh
 *
 * Writes test/e2e/fixtures/thorchain-live/thorchain.json with the RAW public-RPC responses (the spec
 * re-derives every proof with relay/cometbft.ts + relay/cosmwasm.ts) and a small `meta`.
 *
 * THORChain validators all have power 100, so >2/3 needs 64 of 95 / 67 of 99 Ed25519 signatures
 * (~41-43M gas): every commit goes through CometBftCommitAccumulator over 4 transactions.
 *
 * What it captures:
 *   R   the last validator-set change (THORChain churn). Located from the newest Asgard vault's
 *       `status_since` (thornode API) and the exact header found by scanning /blockchain around it.
 *       Signed by the OLD set; a bundle at R returns the new anchor.
 *   B   a recent header (tip - 1), signed by the CURRENT set, which must be R's next set.
 *   proofs ABCI ICS-23 proofs from store `wasm` at R-1 and B-1 for a live App Layer contract,
 *       Rujira `rujira-thorchain-swap` (code 198, cw2 1.3.0):
 *         queue   0x03 ‖ contract ‖ 0x000a "clpr_queue" ‖ channelId   (absent → non-existence)
 *         cw2     0x03 ‖ contract ‖ "contract_info"                   (cw2 Item, exists)
 *         map     0x03 ‖ contract ‖ 0x0006 "vaults" ‖ "avax-avax"      (cw-storage-plus Map, exists)
 * The public node at gateway.liquify.com keeps full history (proofs at the June 2026 churn work).
 */

import {mkdirSync, writeFileSync} from "node:fs";
import path from "node:path";
import {keccak256, type Hex} from "viem";
import {encodeSignedHeader, fetchAbciProof, fetchCommit, fetchStatus, fetchValidators} from "./cometbft.js";
import {canonicalAddress, contractStoreKey, mapKey, queueRecordKey, WASM_STORE} from "./cosmwasm.js";

export const FIXTURE_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../fixtures/thorchain-live");
/** Public endpoints tried in order (several others were unresponsive on 2026-10-01: ninerealms, publicnode). */
export const RPCS = ["https://gateway.liquify.com/chain/thorchain_rpc", "https://rpc.ninerealms.com", "https://thorchain-rpc.publicnode.com"];
export const API = "https://gateway.liquify.com/chain/thorchain_api";
export const CHANNEL_ID = keccak256(new TextEncoder().encode("clpr-thorchain-live")) as Hex;

/** Rujira swap router on the THORChain App Layer (code 198). */
export const CONTRACT = "thor1n5a08r0zvmqca39ka2tgwlkjy9ugalutk7fjpzptfppqcccnat2ska5t4g";
export const MAP_NAMESPACE = "vaults";
export const MAP_KEY = "avax-avax";

export function fixtureKeys(): {name: string; key: Buffer}[] {
    const c = canonicalAddress(CONTRACT);
    return [
        {name: "queue", key: queueRecordKey(c, Buffer.from(CHANNEL_ID.slice(2), "hex"))},
        {name: "cw2", key: contractStoreKey(c, Buffer.from("contract_info"))},
        {name: "map", key: contractStoreKey(c, mapKey(MAP_NAMESPACE, Buffer.from(MAP_KEY)))}
    ];
}

async function pickRpc(): Promise<string> {
    for (const url of RPCS) {
        try {
            const st = await fetchStatus(url);
            if (st.node_info.network === "thorchain-1") return url;
        } catch {
            /* next */
        }
    }
    throw new Error("no THORChain RPC answered");
}

async function json(url: string): Promise<any> {
    for (let attempt = 0; ; attempt++) {
        try {
            const r = await fetch(url, {signal: AbortSignal.timeout(30_000)});
            if (!r.ok) throw new Error(`${url}: ${r.status}`);
            return await r.json();
        } catch (e) {
            if (attempt >= 4) throw e;
            await new Promise((res) => setTimeout(res, 2000 * (attempt + 1)));
        }
    }
}

/** The last churn: newest Asgard vault's status_since, then the exact header with next ≠ current set. */
async function findRotation(rpc: string): Promise<bigint> {
    const vaults = (await json(`${API}/thorchain/vaults/asgard`)) as any[];
    const since = vaults.reduce((m, v) => (BigInt(v.status_since) > m ? BigInt(v.status_since) : m), 0n);
    for (let lo = since - 60n; lo <= since + 60n; lo += 20n) {
        const j = await json(`${rpc}/blockchain?minHeight=${lo}&maxHeight=${lo + 19n}`);
        for (const m of j.result.block_metas as any[]) {
            if (m.header.validators_hash !== m.header.next_validators_hash) return BigInt(m.header.height);
        }
    }
    throw new Error(`no validator-set change within ±60 blocks of churn ${since}`);
}

async function captureHeight(rpc: string, H: bigint) {
    const [commit, vals] = await Promise.all([fetchCommit(rpc, H), fetchValidators(rpc, H)]);
    const enc = encodeSignedHeader(commit.sh, vals.vals); // throws unless hash, set and >2/3 check out
    const abci = [];
    for (const k of fixtureKeys()) abci.push((await fetchAbciProof(rpc, WASM_STORE, k.key, H - 1n)).json);
    return {commit: commit.json, validators: vals.json, abci, signers: enc.signerIndices.length, n: vals.vals.length};
}

export async function capture() {
    const rpc = await pickRpc();
    const st = await fetchStatus(rpc);
    const R = await findRotation(rpc);
    const B = BigInt(st.sync_info.latest_block_height) - 1n;
    const r = await captureHeight(rpc, R);
    const b = await captureHeight(rpc, B);
    const rh = r.commit.result.signed_header.header;
    const bh = b.commit.result.signed_header.header;
    if (bh.validators_hash !== rh.next_validators_hash) throw new Error("B is not signed by R's next set (a later churn?)");
    const mimir = await json(`${API}/thorchain/mimir`);
    return {
        chain: "thorchain",
        chainId: rh.chain_id,
        rpc,
        nodeVersion: st.node_info.version,
        capturedAt: new Date().toISOString(),
        channelId: CHANNEL_ID,
        contract: CONTRACT,
        mapNamespace: MAP_NAMESPACE,
        mapKey: MAP_KEY,
        keys: fixtureKeys().map((k) => ({name: k.name, key: "0x" + k.key.toString("hex")})),
        wasmMimir: Object.fromEntries(Object.entries(mimir).filter(([k]) => k.includes("WASM"))),
        meta: {
            rotationHeight: R.toString(), bundleHeight: B.toString(),
            validatorsAtR: r.n, validatorsAtB: b.n, signersAtR: r.signers, signersAtB: b.signers,
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
    writeFileSync(path.join(FIXTURE_DIR, "thorchain.json"), JSON.stringify(f, null, 1) + "\n");
    console.log("thorchain:", JSON.stringify(f.meta));
}
