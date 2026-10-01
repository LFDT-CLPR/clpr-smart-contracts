/**
 * buildPlasmaLiveFixture.ts — record live Plasma mainnet (PlasmaBFT) data for PlasmaBftVerifier.
 *
 *   npm run plasma-live:refresh       # writes test/e2e/fixtures/plasma-live/mainnet.json
 *
 * PlasmaBFT has no public consensus API: consensus blocks (with QCs) are only on libp2p gossip.
 * This script builds and runs the passive gossip listener in ./plasma-tap (Go, needs `go`) against
 * the public mainnet observer bootnodes for ~90 s. Meanwhile it polls the EVM head and takes
 * `eth_getProof` for the stand-in service at each head block (rpc.plasma.to serves proofs only at
 * the head). It then keeps the newest height N with a proof whose consensus blocks N, N+1, N+2
 * were all received: N+1 carries the QC on N, N+2 the QC on N+1 (2-chain finality of N).
 *
 * Raw gossip bytes and raw RPC JSON are stored; the spec re-derives everything with relay/plasma.ts.
 * Off-chain checks before writing: each block re-hashes to its gossip envelope hash, its payload
 * state_root/block_hash equal the EVM block's, both QCs verify against the committee from
 * `getValidators()` at N (pubkey-sorted), and that committee's SSZ root equals the header fields.
 */

import {execFileSync, spawn} from "node:child_process";
import {mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync, existsSync} from "node:fs";
import {tmpdir} from "node:os";
import path from "node:path";
import {decodeAbiParameters, type Hex} from "viem";
import {rpc, slotKey} from "./evmHeader.js";
import {committeeRoot, decodeBlockV1, decodeGossip, hx, sortKeys, toHex, verifyQc} from "./plasma.js";
import {channelSlots, LIVE_CHANNEL_ID} from "./buildCometBftLiveFixture.js";

const HERE = path.dirname(new URL(import.meta.url).pathname);
export const PLASMA_FIXTURE_DIR = path.resolve(HERE, "../fixtures/plasma-live");
const RPC = "https://rpc.plasma.to";
/** Aquila validator-set contract (ERC-1967 proxy). Also the stand-in "service" (no ClprService on Plasma). */
export const PLASMA_COMMITTEE_CONTRACT: Hex = "0x6c50b8ca8EeAa1c75dEe5b5EA79772AcAbc92F48";
const IMPL_SLOT: Hex = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
/** Public mainnet observer bootnodes (PlasmaLaboratories/node-templates config/mainnet/non-validator.toml). */
const BOOTNODES = [
    "/dns4/plasma-mainnet-observer-cs-1.plasmalabs.tech/tcp/34070/p2p/16Uiu2HAm4WdZmik6PVsRvcbCzc1eHuNfQHgj52CxUAjmdC7W5dXi",
    "/dns4/plasma-mainnet-observer-cs-4.plasmalabs.tech/tcp/34070/p2p/16Uiu2HAmGmnMycTkjnMoxcyVAF8cUFpVoVKKCAGTpwEBJMs181yM",
    "/dns4/plasma-mainnet-observer-cs-9.plasmalabs.tech/tcp/34070/p2p/16Uiu2HAm2PVfZRoyXXLASVzVX3gyBEQd3mRAzZytjv3esD9kWumD"
];

async function committeeAt(n: bigint): Promise<Uint8Array[]> {
    const out = await rpc(RPC, "eth_call", [{to: PLASMA_COMMITTEE_CONTRACT, data: "0xb7ab4db5"}, `0x${n.toString(16)}`]);
    const [vals] = decodeAbiParameters([{type: "tuple[]", components: [{type: "bytes", name: "key"}]}], out) as any;
    return vals.map((v: any) => hx(v.key));
}

export async function capturePlasma(seconds = 90) {
    const work = mkdtempSync(path.join(tmpdir(), "plasma-tap-"));
    const bin = path.join(work, "plasmatap");
    execFileSync("go", ["build", "-o", bin, "."], {cwd: path.join(HERE, "plasma-tap"), stdio: "inherit"});
    const caps = path.join(work, "captures");
    const tap = spawn(bin, ["-out", caps, "-peers", BOOTNODES.join(","), "-topics", "consensus-block", "-dur", `${seconds}s`], {stdio: "ignore"});
    const done = new Promise((r) => tap.on("exit", r));

    const serviceSlots = [...channelSlots(LIVE_CHANNEL_ID), IMPL_SLOT, slotKey(25n)];
    const proofs = new Map<bigint, {block: any; proof: any}>();
    const t0 = Date.now();
    while (Date.now() - t0 < seconds * 1000) {
        try {
            const block = await rpc(RPC, "eth_getBlockByNumber", ["latest", false]);
            const proof = await rpc(RPC, "eth_getProof", [PLASMA_COMMITTEE_CONTRACT, serviceSlots, {blockHash: block.hash}]);
            delete block.transactions;
            proofs.set(BigInt(block.number), {block, proof});
        } catch {
            /* head moved past the proof window; try again */
        }
        await new Promise((r) => setTimeout(r, 400));
    }
    await done;

    const blocks = new Map<bigint, {raw: Uint8Array; d: ReturnType<typeof decodeBlockV1>}>();
    for (const f of existsSync(caps) ? readdirSync(caps) : []) {
        const raw = Uint8Array.from(readFileSync(path.join(caps, f)));
        const g = decodeGossip(raw);
        const d = decodeBlockV1(g.block);
        if (toHex(d.hash) !== toHex(g.blockHash)) throw new Error(`${f}: block hash mismatch`);
        blocks.set(d.evm.number, {raw, d});
    }
    const heights = [...proofs.keys()].filter((n) => blocks.has(n) && blocks.has(n + 1n) && blocks.has(n + 2n)).sort((a, b) => (a < b ? 1 : -1));
    if (!heights.length) throw new Error(`no height with proof + 3 consecutive blocks (${blocks.size} blocks, ${proofs.size} proofs)`);
    const N = heights[0];
    const [b0, b1, b2] = [N, N + 1n, N + 2n].map((n) => blocks.get(n)!);
    const {block, proof} = proofs.get(N)!;

    // Off-chain checks.
    if (toHex(b0.d.evm.stateRoot) !== block.stateRoot || toHex(b0.d.evm.blockHash) !== block.hash) throw new Error("payload != EVM block");
    const keys = sortKeys(await committeeAt(N));
    const root = toHex(committeeRoot(keys));
    for (const b of [b0, b1, b2]) if (toHex(b.d.leaves[9]) !== root || toHex(b.d.leaves[10]) !== root) throw new Error("committee root != header");
    if (toHex(b1.d.qc.blockHash) !== toHex(b0.d.hash) || toHex(b2.d.qc.blockHash) !== toHex(b1.d.hash)) throw new Error("QC chain broken");
    if (b1.d.view !== b0.d.view + 1n) throw new Error("views not consecutive");
    if (!verifyQc(b1.d.qc, keys) || !verifyQc(b2.d.qc, keys)) throw new Error("QC signature does not verify");

    return {
        network: "mainnet",
        chainId: 9745,
        capturedAt: new Date().toISOString(),
        rpc: RPC,
        target: PLASMA_COMMITTEE_CONTRACT,
        existenceSlot: IMPL_SLOT,
        channelId: LIVE_CHANNEL_ID,
        height: N.toString(),
        committee: keys.map(toHex),
        committeeRoot: root,
        gossip: [b0, b1, b2].map((b) => toHex(b.raw)),
        evmBlock: block,
        serviceProof: proof,
        checks: {view: b0.d.view.toString(), qc1Votes: b1.d.qc.votes, qc2Votes: b2.d.qc.votes, blocksSeen: blocks.size, proofsTaken: proofs.size}
    };
}

if (process.argv[1] && import.meta.url.endsWith(path.basename(process.argv[1]))) {
    mkdirSync(PLASMA_FIXTURE_DIR, {recursive: true});
    const f = await capturePlasma(Number(process.argv[2] ?? 90));
    writeFileSync(path.join(PLASMA_FIXTURE_DIR, "mainnet.json"), JSON.stringify(f, null, 1) + "\n");
    console.log(`mainnet: height ${f.height}`, JSON.stringify(f.checks));
}
