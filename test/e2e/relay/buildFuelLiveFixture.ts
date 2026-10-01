/**
 * buildFuelLiveFixture.ts — record a live Fuel Ignition message proof together with the Ethereum
 * mainnet sync-committee proof of the FuelChainState commit it hangs from, for FuelVerifier.
 *
 *   npm run fuel-live:refresh
 *
 * Writes test/e2e/fixtures/fuel-live/fuel.json with raw public responses:
 *   fuel.commit       the newest FuelChainState commit whose finalization delay has passed
 *                     (eth_getStorageAt on the commit ring) and its Fuel block (GraphQL)
 *   fuel.messageBlock the newest Fuel block below that commit with a MessageOut receipt (scanned
 *                     backwards 100 headers per GraphQL query) and the transaction that emitted it
 *   fuel.messageProof GraphQL `messageProof(transactionId, nonce, commitBlockHeight)`
 *   l1                buildEthLiveProof.ts `captureSepoliaLive` pointed at Ethereum MAINNET (beacon
 *                     finality_update, bootstrap, committee updates, account proof) …
 *   l1ChainState      … plus `eth_getProof(FuelChainState, [commit id, commit time, _paused, ERC-1967
 *                     impl])` at the same execution block, taken right after.
 * Every link is cross-checked off-chain before the file is written (header ids recomputed, Merkle
 * proofs folded, committed id == commit header id, delay passed at the signed slot).
 *
 * No CLPR Service exists on Fuel, so the message is a real one from Fuel's own bridge contracts;
 * FuelVerifier.verifyFuelMessage runs the same pipeline as verifyBundle minus the record checks.
 */

import {createHash} from "node:crypto";
import {mkdirSync, writeFileSync} from "node:fs";
import path from "node:path";
import type {Hex} from "viem";
import {captureSepoliaLive} from "./buildEthLiveProof.js";

export const FIXTURE_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../fixtures/fuel-live");
export const FUEL_GRAPHQL = "https://mainnet.fuel.network/v1/graphql";
export const ETH_RPC = "https://ethereum-rpc.publicnode.com";
export const BEACON_APIS = ["https://ethereum-beacon-api.publicnode.com", "https://lodestar-mainnet.chainsafe.io"];

/** Fuel Ignition's FuelChainState on Ethereum mainnet and its layout (read from the chain, 2026-10-01). */
export const CHAIN_STATE = {
    address: "0xf3D20Db1D16A4D0ad2f280A5e594FF3c7790f130" as Hex,
    commitSlotsBase: 301n, // OZ v4 upgradeable gaps: Initializable 1 + Context 50 + Pausable 50 + ERC165 50 + AccessControl 50 + ERC1967Upgrade 50 + UUPS 50
    pausedSlot: 51n,
    implementationSlot: "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" as Hex,
    numCommitSlots: 240n,
    blocksPerCommitInterval: 10800n,
    timeToFinalize: 86400n
};
export const MAINNET_GENESIS_TIME = 1606824023n;
export const SECONDS_PER_SLOT = 12n;

const sha = (...b: Buffer[]) => createHash("sha256").update(Buffer.concat(b)).digest();
const hb = (h: string) => Buffer.from(h.replace(/^0x/, ""), "hex");
const be = (v: bigint | number | string, n: number) => {
    const b = Buffer.alloc(n);
    let x = BigInt(v);
    for (let i = n - 1; i >= 0; i--, x >>= 8n) b[i] = Number(x & 0xffn);
    return b;
};

export const HEADER_FIELDS = "id version height prevRoot time applicationHash daHeight consensusParametersVersion stateTransitionBytecodeVersion transactionsCount messageReceiptCount transactionsRoot messageOutboxRoot eventInboxRoot";

/** 76-byte consensus header; sha256 of it is the block id. */
export function consensusHeader(h: any): Buffer {
    return Buffer.concat([hb(h.prevRoot), be(h.height, 4), be(h.time, 8), hb(h.applicationHash)]);
}

/** 162-byte full header `consensus[0:44] ‖ application`. */
export function fullHeader(h: any): Buffer {
    return Buffer.concat([
        hb(h.prevRoot), be(h.height, 4), be(h.time, 8),
        be(h.daHeight, 8), be(h.consensusParametersVersion, 4), be(h.stateTransitionBytecodeVersion, 4),
        be(h.transactionsCount, 2), be(h.messageReceiptCount, 4),
        hb(h.transactionsRoot), hb(h.messageOutboxRoot), hb(h.eventInboxRoot)
    ]);
}

export function checkHeader(h: any): void {
    if (h.version !== "V1") throw new Error(`header version ${h.version} (only V1 is supported)`);
    const full = fullHeader(h);
    if (!sha(full.subarray(44)).equals(hb(h.applicationHash))) throw new Error("applicationHash mismatch");
    if (!sha(consensusHeader(h)).equals(hb(h.id))) throw new Error("block id mismatch");
}

/** RFC 9162 inclusion fold (fuel-merkle binary tree), siblings leaf → root. */
export function foldInclusion(leafData: Buffer, index: bigint, size: bigint, proof: Buffer[]): Buffer {
    let fn = index;
    let sn = size - 1n;
    let r = sha(Buffer.from([0]), leafData);
    for (const p of proof) {
        if (sn === 0n) throw new Error("proof too long");
        if ((fn & 1n) === 1n || fn === sn) {
            r = sha(Buffer.from([1]), p, r);
            while ((fn & 1n) === 0n && fn !== 0n) {
                fn >>= 1n;
                sn >>= 1n;
            }
        } else {
            r = sha(Buffer.from([1]), r, p);
        }
        fn >>= 1n;
        sn >>= 1n;
    }
    if (sn !== 0n) throw new Error("proof too short");
    return r;
}

export function fuelMessageId(m: {sender: string; recipient: string; nonce: string; amount: string; data: string}): Buffer {
    return sha(hb(m.sender), hb(m.recipient), hb(m.nonce), be(m.amount, 8), hb(m.data ?? "0x"));
}

async function gql(query: string): Promise<any> {
    for (let attempt = 0; ; attempt++) {
        try {
            const r = await fetch(FUEL_GRAPHQL, {method: "POST", headers: {"content-type": "application/json"},
                body: JSON.stringify({query}), signal: AbortSignal.timeout(60_000)});
            const j = (await r.json()) as any;
            if (j.errors) throw new Error(JSON.stringify(j.errors));
            return j.data;
        } catch (e) {
            if (attempt >= 3) throw e;
            await new Promise((res) => setTimeout(res, 2000 * (attempt + 1)));
        }
    }
}

let rpcId = 0;
async function eth(method: string, params: unknown[]): Promise<any> {
    for (let attempt = 0; ; attempt++) {
        try {
            const r = await fetch(ETH_RPC, {method: "POST", headers: {"content-type": "application/json"},
                body: JSON.stringify({jsonrpc: "2.0", id: ++rpcId, method, params}), signal: AbortSignal.timeout(60_000)});
            const j = (await r.json()) as any;
            if (j.error) throw new Error(`${method}: ${j.error.message}`);
            return j.result;
        } catch (e) {
            if (attempt >= 3) throw e;
            await new Promise((res) => setTimeout(res, 2000 * (attempt + 1)));
        }
    }
}

export function chainStateSlots(commitHeight: bigint): Hex[] {
    const s = CHAIN_STATE.commitSlotsBase + 2n * (commitHeight % CHAIN_STATE.numCommitSlots);
    const hex32 = (v: bigint) => ("0x" + v.toString(16).padStart(64, "0")) as Hex;
    return [hex32(s), hex32(s + 1n), hex32(CHAIN_STATE.pausedSlot), CHAIN_STATE.implementationSlot];
}

/** Newest commit whose delay has passed by `nowSec` (one-hour margin). */
async function finalCommit(nowSec: bigint): Promise<{c: bigint; id: string; timestamp: bigint}> {
    const tip = BigInt((await gql("{ chain { latestBlock { height } } }")).chain.latestBlock.height);
    for (let c = tip / CHAIN_STATE.blocksPerCommitInterval; c > 0n; c--) {
        const [idSlot, tsSlot] = chainStateSlots(c);
        const id = await eth("eth_getStorageAt", [CHAIN_STATE.address, idSlot, "latest"]);
        const ts = BigInt(await eth("eth_getStorageAt", [CHAIN_STATE.address, tsSlot, "latest"])) & 0xffffffffn;
        if (BigInt(id) === 0n) continue;
        if (ts + CHAIN_STATE.timeToFinalize + 3600n <= nowSec) return {c, id, timestamp: ts};
    }
    throw new Error("no final commit");
}

/** Newest block below `below` with a MessageOut receipt (100 headers per query). */
async function findMessageBlock(below: bigint, maxBlocks = 400_000n): Promise<bigint> {
    for (let hi = below; hi > below - maxBlocks; hi -= 100n) {
        const d = await gql(`{ blocks(last: 100, before: "${hi}") { nodes { height header { messageReceiptCount } } } }`);
        const hit = (d.blocks.nodes as any[]).filter((n) => Number(n.header.messageReceiptCount) > 0);
        if (hit.length) return BigInt(hit[hit.length - 1].height);
    }
    throw new Error("no MessageOut in the scanned window");
}

export async function capture() {
    const nowSec = BigInt(Math.floor(Date.now() / 1000));
    const commit = await finalCommit(nowSec);
    const commitHeight = commit.c * CHAIN_STATE.blocksPerCommitInterval;
    const commitBlock = (await gql(`{ block(height: "${commitHeight}") { header { ${HEADER_FIELDS} } } }`)).block;
    checkHeader(commitBlock.header);
    if (commitBlock.header.id.toLowerCase() !== commit.id.toLowerCase()) throw new Error("committed id != block id at c × interval");

    const msgHeight = await findMessageBlock(commitHeight);
    const blk = (await gql(`{ block(height: "${msgHeight}") { header { ${HEADER_FIELDS} } transactions { id status { ... on SuccessStatus { receipts { receiptType sender recipient amount nonce data } } } } } }`)).block;
    let txId = "";
    let nonce = "";
    for (const tx of blk.transactions) {
        const r = (tx.status?.receipts ?? []).find((x: any) => x.receiptType === "MESSAGE_OUT");
        if (r) {
            txId = tx.id;
            nonce = r.nonce;
            break;
        }
    }
    if (!txId) throw new Error(`no MESSAGE_OUT receipt found in block ${msgHeight}`);
    const mp = (await gql(`{ messageProof(transactionId: "${txId}", nonce: "${nonce}", commitBlockHeight: "${commitHeight}") {
        messageProof { proofSet proofIndex } blockProof { proofSet proofIndex }
        messageBlockHeader { ${HEADER_FIELDS} } commitBlockHeader { ${HEADER_FIELDS} }
        sender recipient nonce amount data } }`)).messageProof;

    // Off-chain checks of the Fuel half.
    checkHeader(mp.messageBlockHeader);
    checkHeader(mp.commitBlockHeader);
    if (mp.commitBlockHeader.id !== commitBlock.header.id) throw new Error("messageProof commit header != committed block");
    const blockRoot = foldInclusion(hb(mp.messageBlockHeader.id), BigInt(mp.blockProof.proofIndex), commitHeight,
        mp.blockProof.proofSet.map(hb));
    if (!blockRoot.equals(hb(mp.commitBlockHeader.prevRoot))) throw new Error("block proof does not fold to prevRoot");
    const msgRoot = foldInclusion(fuelMessageId(mp), BigInt(mp.messageProof.proofIndex),
        BigInt(mp.messageBlockHeader.messageReceiptCount), mp.messageProof.proofSet.map(hb));
    if (!msgRoot.equals(hb(mp.messageBlockHeader.messageOutboxRoot))) throw new Error("message proof does not fold to outbox root");

    // L1 half: sync-committee proof, then FuelChainState storage at the same execution block.
    const l1 = await captureSepoliaLive({beaconApis: BEACON_APIS, executionRpc: ETH_RPC, account: CHAIN_STATE.address});
    const blockTag = "0x" + BigInt(l1.account.blockNumber).toString(16);
    const l1ChainState = await eth("eth_getProof", [CHAIN_STATE.address, chainStateSlots(commit.c), blockTag]);
    const signedSlot = BigInt(l1.finalityUpdate.data.attested_header.beacon.slot);
    const l1Time = MAINNET_GENESIS_TIME + signedSlot * SECONDS_PER_SLOT;
    if (commit.timestamp + CHAIN_STATE.timeToFinalize > l1Time) throw new Error("commit not final at the signed slot");
    if (BigInt(l1ChainState.storageProof[0].value) !== BigInt(commit.id)) throw new Error("commit changed under the capture");

    return {
        chain: "fuel-ignition",
        capturedAt: new Date().toISOString(),
        sources: {fuel: FUEL_GRAPHQL, ethRpc: ETH_RPC, beacon: l1.sources.beaconApi},
        meta: {
            commitIndex: commit.c.toString(), commitHeight: commitHeight.toString(), commitId: commit.id,
            commitTimestamp: commit.timestamp.toString(), messageBlockHeight: msgHeight.toString(), transactionId: txId,
            nonce, signedSlot: signedSlot.toString(), l1Time: l1Time.toString(),
            executionBlock: BigInt(l1.account.blockNumber).toString()
        },
        fuel: {commitBlock: commitBlock.header, messageBlock: blk.header, messageProof: mp},
        l1,
        l1ChainState
    };
}

if (process.argv[1] && import.meta.url.endsWith(path.basename(process.argv[1]))) {
    mkdirSync(FIXTURE_DIR, {recursive: true});
    const f = await capture();
    writeFileSync(path.join(FIXTURE_DIR, "fuel.json"), JSON.stringify(f, null, 1) + "\n");
    console.log("fuel:", JSON.stringify(f.meta));
}
