/**
 * buildPolygonLiveFixture.ts — record a live Polygon PoS bundle (Heimdall v2 milestone → Bor MPT)
 * for PolygonPosVerifier.
 *
 *   npm run polygon-live:refresh                 # waits for a Heimdall validator-set change (≤ 90 min)
 *   POLYGON_ROTATION_WAIT_MIN=0 npm run polygon-live:refresh   # typical bundle only
 *
 * Writes test/e2e/fixtures/polygon-live/polygon.json with the RAW public-RPC responses; the spec
 * re-derives every proof from them with relay/cometbft.ts, relay/cosmwasm.ts and relay/polygon.ts.
 *
 * For each captured Heimdall height H:
 *   commit + validators at H                       (secp256k1eth; >2/3 checked off-chain here)
 *   abci_query /store/milestone at H-1            count (0x83) and the milestone 0x81‖count with
 *                                                  ICS-23 proofs against header H's app_hash
 *   eth_getBlockByNumber(milestone.end_block)      keccak(RLP header) must equal milestone.hash
 *   eth_getProof(SERVICE, slots, end_block)        the 5 channel slots (absent: no ClprService on
 *                                                  Polygon yet) + WPOL slots 0-2 (name, symbol,
 *                                                  decimals: real, non-zero)
 * Public Bor nodes keep recent state only (~128 blocks), so every Bor read happens right after the
 * milestone is read. A rotation (header R with next_validators_hash ≠ validators_hash) cannot be
 * recorded after the fact for the same reason: the builder watches the tip for the next one
 * (Heimdall's set hash includes voting power, so it changes every ~20-40 min) and records R and
 * B = R + 2 (signed by the new set).
 */

import {mkdirSync, writeFileSync} from "node:fs";
import path from "node:path";
import {keccak256, toHex as viemHex, type Hex} from "viem";
import {deriveChannelSlots} from "./buildEthMainnetProof.js";
import {encodeSignedHeader, fetchAbciProof, fetchCommit, fetchStatus, fetchValidators} from "./cometbft.js";
import {decodeCount, decodeMilestone, encodeBorHeader, MILESTONE_COUNT_KEY, MILESTONE_STORE, milestoneKey, type EthProof} from "./polygon.js";

export const FIXTURE_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../fixtures/polygon-live");
export const HEIMDALL_RPC = "https://polygon-heimdall-rpc.publicnode.com";
export const BOR_RPCS = ["https://polygon-bor-rpc.publicnode.com", "https://polygon.drpc.org", "https://1rpc.io/matic"];
export const CHANNEL_ID = keccak256(viemHex("clpr-polygon-live")) as Hex;
/** WPOL (formerly WMATIC), a real Bor contract; no ClprService is deployed on Polygon yet. */
export const SERVICE: Hex = "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270";
export const EXTRA_SLOTS: Hex[] = ["0x0", "0x1", "0x2"];
export const fixtureSlots = (): Hex[] => [...deriveChannelSlots(CHANNEL_ID), ...EXTRA_SLOTS];

async function borRpc(method: string, params: unknown[]): Promise<any> {
    let last: unknown;
    for (const url of BOR_RPCS) {
        try {
            const r = await fetch(url, {
                method: "POST", headers: {"content-type": "application/json"},
                body: JSON.stringify({jsonrpc: "2.0", id: 1, method, params}), signal: AbortSignal.timeout(30_000)
            });
            const j = (await r.json()) as any;
            if (j.error || j.result === undefined || j.result === null) throw new Error(JSON.stringify(j.error ?? "null result"));
            return {url, result: j.result};
        } catch (e) {
            last = e;
        }
    }
    throw new Error(`${method}: every Bor RPC failed (${(last as Error).message})`);
}

async function captureHeight(H: bigint) {
    const count = await fetchAbciProof(HEIMDALL_RPC, MILESTONE_STORE, MILESTONE_COUNT_KEY, H - 1n);
    const n = decodeCount(count.proof.value);
    const ms = await fetchAbciProof(HEIMDALL_RPC, MILESTONE_STORE, milestoneKey(n), H - 1n);
    const m = decodeMilestone(ms.proof.value);
    const tag = "0x" + m.endBlock.toString(16);
    // Bor reads first: public nodes prune state after ~128 blocks.
    const [proof, block] = await Promise.all([
        borRpc("eth_getProof", [SERVICE, fixtureSlots(), tag]),
        borRpc("eth_getBlockByNumber", [tag, false])
    ]);
    if (String(block.result.hash).toLowerCase() !== "0x" + m.hash.toString("hex")) throw new Error("Bor block hash != milestone.hash");
    encodeBorHeader(block.result); // throws unless the RLP hashes to block.hash
    delete block.result.transactions;
    const [commit, vals] = await Promise.all([fetchCommit(HEIMDALL_RPC, H), fetchValidators(HEIMDALL_RPC, H)]);
    const enc = encodeSignedHeader(commit.sh, vals.vals); // throws unless hash, set and >2/3 check out
    return {
        height: H.toString(), milestoneCount: n.toString(), borBlock: m.endBlock.toString(), borRpc: proof.url,
        signers: enc.signerIndices.length, validators: vals.vals.length,
        raw: {commit: commit.json, validators: vals.json, abci: {count: count.json, milestone: ms.json}, borBlock: block.result, borProof: proof.result as EthProof}
    };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const tip = async () => BigInt((await fetchStatus(HEIMDALL_RPC)).sync_info.latest_block_height);

async function headerAt(h: bigint): Promise<any> {
    const r = await fetch(`${HEIMDALL_RPC}/blockchain?minHeight=${h}&maxHeight=${h}`, {signal: AbortSignal.timeout(30_000)});
    return ((await r.json()) as any).result.block_metas[0].header;
}

/** Watch new Heimdall headers until one changes the validator set; returns its height. */
async function waitForRotation(minutes: number): Promise<bigint | undefined> {
    const deadline = Date.now() + minutes * 60_000;
    let next = await tip();
    while (Date.now() < deadline) {
        const t = await tip();
        for (; next <= t; next++) {
            const h = await headerAt(next);
            if (h.validators_hash !== h.next_validators_hash) return next;
        }
        await sleep(2_000);
    }
    return undefined;
}

export async function capture() {
    const st = await fetchStatus(HEIMDALL_RPC);
    const typical = await captureHeight(BigInt(st.sync_info.latest_block_height) - 1n);
    console.log("typical:", typical.height, "milestone", typical.milestoneCount, "bor", typical.borBlock, "signers", typical.signers);

    const waitMin = Number(process.env.POLYGON_ROTATION_WAIT_MIN ?? 90);
    let rotation: Awaited<ReturnType<typeof captureHeight>> | undefined;
    let afterRotation: typeof rotation;
    if (waitMin > 0) {
        console.log(`waiting up to ${waitMin} min for a Heimdall validator-set change…`);
        const R = await waitForRotation(waitMin);
        if (R !== undefined) {
            while ((await tip()) < R + 3n) await sleep(1_000);
            rotation = await captureHeight(R);
            afterRotation = await captureHeight(R + 2n);
            const rh = rotation.raw.commit.result.signed_header.header;
            const bh = afterRotation.raw.commit.result.signed_header.header;
            if (bh.validators_hash !== rh.next_validators_hash) throw new Error("R+2 is not signed by R's next set");
            console.log("rotation:", rotation.height, "→", afterRotation.height);
        } else console.log("no rotation within the window; fixture has the typical bundle only");
    }
    return {
        chain: "polygon-pos",
        chainId: typical.raw.commit.result.signed_header.header.chain_id,
        borChainId: "137",
        heimdallRpc: HEIMDALL_RPC,
        nodeVersion: st.node_info.version,
        capturedAt: new Date().toISOString(),
        channelId: CHANNEL_ID,
        service: SERVICE,
        slots: fixtureSlots(),
        typical,
        rotation,
        afterRotation
    };
}

if (process.argv[1] && import.meta.url.endsWith(path.basename(process.argv[1]))) {
    mkdirSync(FIXTURE_DIR, {recursive: true});
    const f = await capture();
    writeFileSync(path.join(FIXTURE_DIR, "polygon.json"), JSON.stringify(f, null, 1) + "\n");
    console.log("written", path.join(FIXTURE_DIR, "polygon.json"));
}
