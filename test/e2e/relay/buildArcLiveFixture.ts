/**
 * buildArcLiveFixture.ts — record live Arc (Malachite) data for ArcMalachiteVerifier.
 *
 *   npm run arc-live:refresh            # writes test/e2e/fixtures/arc-live/testnet.json
 *
 * Public Arc RPCs serve `eth_getProof` only at the head block (proof window 0), so each snapshot is
 * built from staggered JSON-RPC batches {latest block, registry proof, service proof} until two land
 * on consecutive blocks H-1, H (each batch checked for a common state root), then completed with
 * `arc_getCertificate(H)` from the official RPC. Two snapshots (H1 < H2) let the spec replay a
 * rotation hop at H1 and a bundle at H2.
 *
 * Every capture is cross-checked off-chain before it is written: header RLP hashes to the block
 * hash, the certificate certifies that hash, every certificate signature verifies (Ed25519 over the
 * SSZ precommit), >2/3 of the power signed, and the set derived from the registry storage PROOF
 * at H-1 equals `getActiveValidatorSet()` at H-1 (the set Arc uses for height H).
 */

import {mkdirSync, writeFileSync} from "node:fs";
import path from "node:path";
import {createPublicClient, http, keccak256, parseAbi, type Hex} from "viem";
import {encodeHeader, rpc, rpcBatch, slotKey, type ProofJson} from "./evmHeader.js";
import {ARC_REGISTRY, arcSetHash, selectSignatures, validatorsFromProof, walkRegistry, type ArcCertificate} from "./arc.js";
import {channelSlots, LIVE_CHANNEL_ID} from "./buildCometBftLiveFixture.js";

export const ARC_FIXTURE_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../fixtures/arc-live");

export const ARC_NETWORKS = {
    testnet: {
        chainId: 5042002,
        certRpc: "https://rpc.testnet.arc.network",
        proofRpcs: ["https://rpc.blockdaemon.testnet.arc.network", "https://arc-testnet-rpc.publicnode.com"],
        /** Stand-in for the peer ClprService (none is deployed on Arc): the 0x3600…0001 system proxy. */
        target: "0x3600000000000000000000000000000000000001" as Hex,
        /** Its ERC-1967 implementation slot (non-zero → existence proof). */
        existenceSlot: "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" as Hex
    }
} as const;

const REGISTRY_ABI = parseAbi([
    "struct V { uint8 status; bytes publicKey; uint64 votingPower; }",
    "function getActiveValidatorSet() view returns (V[])"
]);

async function certificate(url: string, H: bigint): Promise<ArcCertificate> {
    for (let i = 0; i < 20; i++) {
        try {
            const c = await rpc(url, "arc_getCertificate", [`0x${H.toString(16)}`]);
            if (c) return c;
        } catch {
            /* not decided yet */
        }
        await new Promise((r) => setTimeout(r, 1000));
    }
    throw new Error(`no certificate for ${H}`);
}

/** One JSON-RPC batch at "latest": block + registry proof + service proof, all at one state root. */
async function probe(proofRpc: string, slots: bigint[], serviceSlots: Hex[], target: Hex) {
    try {
        const [block, regProof, svcProof] = (await rpcBatch(proofRpc, [
            {method: "eth_getBlockByNumber", params: ["latest", false]},
            {method: "eth_getProof", params: [ARC_REGISTRY, slots.map(slotKey), "latest"]},
            {method: "eth_getProof", params: [target, serviceSlots, "latest"]}
        ])) as [any, ProofJson, ProofJson];
        if (keccak256(regProof.accountProof[0]) !== block.stateRoot || keccak256(svcProof.accountProof[0]) !== block.stateRoot) return undefined;
        return {block, registryProof: regProof, serviceProof: svcProof};
    } catch {
        return undefined;
    }
}

/**
 * Public Arc RPCs serve eth_getProof only at the head (proof window 0), but a step needs the registry
 * proof at H-1 AND the proofs at H. So fire staggered "latest" probes until two land on consecutive
 * blocks (L-1, L); return that pair.
 */
async function consecutivePair(net: (typeof ARC_NETWORKS)["testnet"], slots: bigint[], serviceSlots: Hex[]) {
    const seen = new Map<bigint, any>();
    for (let round = 0; round < 10; round++) {
        const probes: Promise<any>[] = [];
        for (let i = 0; i < 16; i++) {
            const url = net.proofRpcs[i % net.proofRpcs.length];
            probes.push(new Promise((r) => setTimeout(r, i * 60)).then(() => probe(url, slots, serviceSlots, net.target)));
        }
        for (const p of await Promise.all(probes)) if (p) seen.set(BigInt(p.block.number), p);
        const hs = [...seen.keys()].sort((x, y) => (x < y ? 1 : -1));
        for (const h of hs) if (seen.has(h - 1n)) return {parent: seen.get(h - 1n), child: seen.get(h)};
    }
    throw new Error("no consecutive proof snapshots");
}

async function snapshot(net: (typeof ARC_NETWORKS)["testnet"]) {
    const serviceSlots = [...channelSlots(LIVE_CHANNEL_ID), net.existenceSlot, slotKey(25n)]; // + ClprService `_config.serviceAddress` slot (verifyConfig)
    const {slots} = await walkRegistry(async (s) => BigInt(await rpc(net.proofRpcs[0], "eth_getStorageAt", [ARC_REGISTRY, slotKey(s), "latest"])));
    const {parent, child} = await consecutivePair(net, slots, serviceSlots);
    const fromProof = await validatorsFromProof(child.registryProof);
    if (fromProof.slots.length !== slots.length) throw new Error("registry changed during capture; re-run");
    const block = child.block;
    const H = BigInt(block.number);
    if (parent.block.hash !== block.parentHash) throw new Error("parent hash mismatch");
    const cert = await certificate(net.certRpc, H);
    if (cert.block_hash.toLowerCase() !== block.hash.toLowerCase()) throw new Error("certificate block_hash != block hash");
    encodeHeader(block);
    encodeHeader(parent.block);
    // The set that signs H is getActiveValidatorSet() at H-1; its registry storage is parent.registryProof.
    const parentSet = await validatorsFromProof(parent.registryProof);
    const pc = createPublicClient({transport: http(net.certRpc)});
    const live = (await pc.readContract({address: ARC_REGISTRY, abi: REGISTRY_ABI, functionName: "getActiveValidatorSet", blockNumber: H - 1n})) as any[];
    const callSet = live.filter((v) => v.status === 2 && v.votingPower > 0n && (v.publicKey.length - 2) / 2 === 32).map((v) => ({publicKey: v.publicKey as Hex, votingPower: v.votingPower as bigint}));
    const sel = selectSignatures(cert, parentSet.validators);
    return {
        height: H.toString(),
        block,
        parentBlock: parent.block,
        certificate: cert,
        parentRegistryProof: {...parent.registryProof, storageProof: []},
        registryProof: child.registryProof,
        serviceProof: child.serviceProof,
        checks: {
            setFromParentProof: arcSetHash(parentSet.validators),
            setFromCallAtParent: arcSetHash(callSet),
            setForNextFromProof: arcSetHash(fromProof.validators),
            validators: parentSet.validators.length,
            certificateSignatures: cert.signatures.length,
            minimalSigners: sel.sigs.length,
            signedPower: sel.signedPower.toString(),
            totalPower: sel.totalPower.toString()
        }
    };
}

export async function captureArc(name: keyof typeof ARC_NETWORKS = "testnet") {
    const net = ARC_NETWORKS[name];
    const first = await snapshot(net);
    await new Promise((r) => setTimeout(r, 5000));
    const second = await snapshot(net);
    for (const s of [first, second]) {
        if (s.checks.setFromParentProof !== s.checks.setFromCallAtParent) throw new Error(`registry set at ${s.height}-1 != getActiveValidatorSet at parent`);
    }
    return {
        network: name,
        chainId: net.chainId,
        capturedAt: new Date().toISOString(),
        registry: ARC_REGISTRY,
        target: net.target,
        existenceSlot: net.existenceSlot,
        channelId: LIVE_CHANNEL_ID,
        snapshots: [first, second]
    };
}

if (process.argv[1] && import.meta.url.endsWith(path.basename(process.argv[1]))) {
    const names = (process.argv.slice(2).length ? process.argv.slice(2) : ["testnet"]) as (keyof typeof ARC_NETWORKS)[];
    mkdirSync(ARC_FIXTURE_DIR, {recursive: true});
    for (const n of names) {
        const f = await captureArc(n);
        writeFileSync(path.join(ARC_FIXTURE_DIR, `${n}.json`), JSON.stringify(f, null, 1) + "\n");
        console.log(`${n}: heights ${f.snapshots.map((s) => s.height).join(", ")}`, JSON.stringify(f.snapshots.map((s) => s.checks)));
    }
}
