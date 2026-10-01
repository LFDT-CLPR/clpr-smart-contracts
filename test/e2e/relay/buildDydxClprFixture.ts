/**
 * buildDydxClprFixture.ts — record fixtures for CosmosModuleVerifier (src/verifiers/evm/dydx).
 *
 *   npm run dydx-xclpr:refresh            # both
 *   npm run dydx-xclpr:refresh localnet   # needs modules/x-clpr localnet + scripts/send-demo.sh
 *   npm run dydx-xclpr:refresh mainnet    # public dYdX RPC
 *
 * localnet.json  A real x/clpr chain (modules/x-clpr, built on dYdX v9.7.1's cosmos-sdk, store,
 *                IAVL and CometBFT forks): commit + validators at H, and ABCI ICS-23 proofs at H-1
 *                from store "clpr" for the queue record, the service item, messages 1..3 (exist)
 *                and message 4 (absent).
 * mainnet.json   dYdX mainnet (dydx-mainnet-1): commit + validators at H and an ICS-23 proof of
 *                bank supply `0x00 ‖ "adydx"` at H-1. It shows that dYdX's live multistore and
 *                IAVL proofs verify through the same pipeline, with a different store key.
 * Raw RPC JSON is stored; the spec re-derives every proof from it.
 */

import {mkdirSync, writeFileSync} from "node:fs";
import path from "node:path";
import {encodeSignedHeader, fetchAbciProof, fetchCommit, fetchStatus, fetchValidators} from "./cometbft.js";

export const FIXTURE_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../fixtures/dydx-xclpr");
export const LOCAL_RPC = process.env.CLPRD_RPC ?? "http://127.0.0.1:36657";
export const MAINNET_RPC = process.env.DYDX_RPC ?? "https://dydx-rpc.publicnode.com";
export const CLPR_STORE = "clpr";

/** modules/x-clpr/x/clpr/types/keys.go */
export const queueRecordKey = (ch: Buffer) => Buffer.concat([Buffer.from([0x01]), ch]);
export const serviceItemKey = () => Buffer.from([0x03]);
export function messageKey(ch: Buffer, id: bigint): Buffer {
    const b = Buffer.alloc(8);
    b.writeBigUInt64BE(id);
    return Buffer.concat([Buffer.from([0x02]), ch, b]);
}

/** scripts/send-demo.sh: channel = sha256("clpr-dydx-hiero-demo"). */
export const DEMO_CHANNEL = "5296cb261aa9315e0fe0609334f2ed8fe13801ccd28bf5f84d7c0e79c678e741";

export function localKeys(ch: Buffer): {name: string; key: Buffer}[] {
    return [
        {name: "queue", key: queueRecordKey(ch)},
        {name: "service", key: serviceItemKey()},
        {name: "msg1", key: messageKey(ch, 1n)},
        {name: "msg2", key: messageKey(ch, 2n)},
        {name: "msg3", key: messageKey(ch, 3n)},
        {name: "msg4", key: messageKey(ch, 4n)}
    ];
}
export const MAINNET_KEY = {store: "bank", name: "supply_adydx", key: Buffer.concat([Buffer.from([0x00]), Buffer.from("adydx")])};

async function captureAt(rpc: string, H: bigint, store: string, keys: {name: string; key: Buffer}[]) {
    const [commit, vals] = await Promise.all([fetchCommit(rpc, H), fetchValidators(rpc, H)]);
    const enc = encodeSignedHeader(commit.sh, vals.vals); // throws unless hash, set and >2/3 check out
    const abci = [];
    for (const k of keys) abci.push((await fetchAbciProof(rpc, store, k.key, H - 1n)).json);
    return {commit: commit.json, validators: vals.json, abci, signers: enc.signerIndices.length, n: vals.vals.length};
}

export async function captureLocal() {
    const st = await fetchStatus(LOCAL_RPC);
    const H = BigInt(st.sync_info.latest_block_height) - 1n;
    const keys = localKeys(Buffer.from(DEMO_CHANNEL, "hex"));
    const c = await captureAt(LOCAL_RPC, H, CLPR_STORE, keys);
    return {
        chain: "x-clpr-localnet",
        chainId: c.commit.result.signed_header.header.chain_id,
        rpc: LOCAL_RPC,
        nodeVersion: st.node_info.version,
        capturedAt: new Date().toISOString(),
        store: CLPR_STORE,
        channelId: "0x" + DEMO_CHANNEL,
        manifest: "0x08011214a88f550db4433c59b3322bca3a2c233cfdd69adc",
        keys: keys.map((k) => ({name: k.name, key: "0x" + k.key.toString("hex")})),
        meta: {height: H.toString(), validators: c.n, signers: c.signers},
        raw: {commit: c.commit, validators: c.validators, abci: c.abci}
    };
}

export async function captureMainnet() {
    const st = await fetchStatus(MAINNET_RPC);
    const H = BigInt(st.sync_info.latest_block_height) - 2n;
    const c = await captureAt(MAINNET_RPC, H, MAINNET_KEY.store, [MAINNET_KEY]);
    return {
        chain: "dydx",
        chainId: c.commit.result.signed_header.header.chain_id,
        rpc: MAINNET_RPC,
        nodeVersion: st.node_info.version,
        capturedAt: new Date().toISOString(),
        store: MAINNET_KEY.store,
        keys: [{name: MAINNET_KEY.name, key: "0x" + MAINNET_KEY.key.toString("hex")}],
        meta: {height: H.toString(), validators: c.n, signers: c.signers},
        raw: {commit: c.commit, validators: c.validators, abci: c.abci}
    };
}

if (process.argv[1] && import.meta.url.endsWith(path.basename(process.argv[1]))) {
    mkdirSync(FIXTURE_DIR, {recursive: true});
    const which = process.argv[2];
    for (const [name, fn] of [["localnet", captureLocal], ["mainnet", captureMainnet]] as const) {
        if (which && which !== name) continue;
        const f = await fn();
        writeFileSync(path.join(FIXTURE_DIR, `${name}.json`), JSON.stringify(f, null, 1) + "\n");
        console.log(name + ":", JSON.stringify(f.meta));
    }
}
