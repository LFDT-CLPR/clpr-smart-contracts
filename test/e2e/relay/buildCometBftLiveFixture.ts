/**
 * buildCometBftLiveFixture.ts — record live CometBFT / Malachite data for the CometBFT verifier family.
 *
 *   npm run cometbft-live:refresh                    # all chains
 *   npx tsx test/e2e/relay/buildCometBftLiveFixture.ts cronos mezo
 *
 * Writes test/e2e/fixtures/cometbft-live/<chain>.json holding the RAW public-RPC responses (so the
 * spec re-derives every proof with relay/cometbft.ts and nothing derived is trusted) plus a small
 * `meta` block. Before writing, every capture is cross-checked off-chain: header hash == block_id,
 * validator-set hash == validators_hash, every selected signature verifies, >2/3 power.
 *
 * Kinds:
 *   evm-bundle   (Cronos, Mezo)  commit at H, a second commit at H-5 (used as a hop), validators,
 *                                and ABCI ICS-23 proofs at H-1 (state committed in H's app_hash) for
 *                                the five channel slots of a real contract plus one non-zero slot.
 *   commit       (Heimdall v2, dYdX, Provenance, THORChain)  commit + validators at H; if the set
 *                                changes at H (next != validators) it is a real rotation.
 *   malachite    (Arc)          arc_getCertificate at H + ValidatorRegistry.getActiveValidatorSet at
 *                                H-1, verified off-chain only (different wire format, see README).
 */

import {mkdirSync, writeFileSync} from "node:fs";
import path from "node:path";
import {createPublicClient, encodeAbiParameters, http, keccak256, parseAbi, type Hex} from "viem";
import {ed25519} from "@noble/curves/ed25519";
import {
    encodeSignedHeader,
    evmStorageKey,
    fetchAbciProof,
    fetchCommit,
    fetchStatus,
    fetchValidators,
    validatorSetHash
} from "./cometbft.js";

export const FIXTURE_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../fixtures/cometbft-live");
export const LIVE_CHANNEL_ID = keccak256(new TextEncoder().encode("clpr-cometbft-live")) as Hex;
const CHANNELS_SLOT = 15n;
const CHANNEL_OFFSETS = [1n, 2n, 4n, 5n, 16n];

export interface ChainSpec {
    name: string;
    kind: "evm-bundle" | "commit" | "malachite";
    rpc: string;
    storeKey?: string;
    evmStateKeyPrefix?: number;
    /** Contract standing in for the peer ClprService (no ClprService is deployed on these chains). */
    target?: Hex;
    /** A slot of `target` that is non-zero (existence proof). */
    existenceSlot?: Hex;
}

export const CHAINS: Record<string, ChainSpec> = {
    cronos: {
        name: "cronos", kind: "evm-bundle", rpc: "https://cronos-rpc.publicnode.com",
        storeKey: "evm", evmStateKeyPrefix: 0x02,
        target: "0x5c7f8a570d578ed84e63fdfa7b1ee72deae1ae23", // WCRO
        existenceSlot: "0x00" // name() short string "Wrapped CRO"
    },
    mezo: {
        name: "mezo", kind: "evm-bundle", rpc: "https://rpc.lavenderfive.com/mezo",
        storeKey: "evm", evmStateKeyPrefix: 0x02,
        target: "0x69710c87447405cea8bb088381905ce133e4dd42",
        existenceSlot: "0x00"
    },
    heimdall: {name: "heimdall", kind: "commit", rpc: "https://polygon-heimdall-rpc.publicnode.com"},
    dydx: {name: "dydx", kind: "commit", rpc: "https://dydx-rpc.publicnode.com"},
    provenance: {name: "provenance", kind: "commit", rpc: "https://rpc.provenance.io"},
    thorchain: {name: "thorchain", kind: "commit", rpc: "https://gateway.liquify.com/chain/thorchain_rpc"},
    arc: {name: "arc", kind: "malachite", rpc: "https://rpc.testnet.arc.network"}
};

export function channelSlots(channelId: Hex): Hex[] {
    const base = BigInt(keccak256(encodeAbiParameters([{type: "bytes32"}, {type: "uint256"}], [channelId, CHANNELS_SLOT])));
    return CHANNEL_OFFSETS.map((o) => ("0x" + ((base + o) % (1n << 256n)).toString(16).padStart(64, "0")) as Hex);
}

async function captureEvmBundle(c: ChainSpec) {
    const st = await fetchStatus(c.rpc);
    const H = BigInt(st.sync_info.latest_block_height) - 3n;
    const hopH = H - 5n;
    const [commit, hopCommit, vals, hopVals] = await Promise.all([
        fetchCommit(c.rpc, H), fetchCommit(c.rpc, hopH), fetchValidators(c.rpc, H), fetchValidators(c.rpc, hopH)
    ]);
    const enc = encodeSignedHeader(commit.sh, vals.vals);
    encodeSignedHeader(hopCommit.sh, hopVals.vals);
    const keys = [...channelSlots(LIVE_CHANNEL_ID), c.existenceSlot!].map((s) => evmStorageKey(c.evmStateKeyPrefix!, c.target!, s));
    const abci = [];
    for (const k of keys) abci.push((await fetchAbciProof(c.rpc, c.storeKey!, k, H - 1n)).json);
    return {
        meta: {height: H.toString(), hopHeight: hopH.toString(), signers: enc.signerIndices.length, validators: vals.vals.length},
        raw: {commit: commit.json, hopCommit: hopCommit.json, validators: vals.json, hopValidators: hopVals.json, abci}
    };
}

async function captureCommit(c: ChainSpec) {
    const st = await fetchStatus(c.rpc);
    let H = BigInt(st.sync_info.latest_block_height) - 10n;
    // Prefer a recent height whose set changes (a real rotation hop), else the latest.
    let pick: bigint | undefined;
    for (let h = H; h > H - 30n && pick === undefined; h--) {
        const {sh} = await fetchCommit(c.rpc, h);
        if (sh.header.next_validators_hash !== sh.header.validators_hash) pick = h;
    }
    H = pick ?? H;
    const [commit, vals] = await Promise.all([fetchCommit(c.rpc, H), fetchValidators(c.rpc, H)]);
    const enc = encodeSignedHeader(commit.sh, vals.vals);
    return {
        meta: {
            height: H.toString(), signers: enc.signerIndices.length, validators: vals.vals.length,
            rotation: commit.sh.header.next_validators_hash !== commit.sh.header.validators_hash,
            scheme: vals.vals[0].scheme
        },
        raw: {commit: commit.json, validators: vals.json}
    };
}

const ARC_REGISTRY = "0x3600000000000000000000000000000000000002" as const;
const ARC_ABI = parseAbi([
    "struct V { uint8 status; bytes publicKey; uint64 votingPower; }",
    "function getActiveValidatorSet() view returns (V[])"
]);

/** Arc (Malachite) vote sign bytes: SSZ(Vote{type, height, round: Option<u32>, value: Option<B256>, address}). */
export function arcPrecommitSignBytes(height: bigint, round: number, blockHash: Hex, address: Hex): Buffer {
    const le = (n: bigint, len: number) => {
        const b = Buffer.alloc(len);
        for (let i = 0; i < len; i++) b[i] = Number((n >> BigInt(8 * i)) & 0xffn);
        return b;
    };
    const fixedLen = 1 + 8 + 4 + 4 + 20;
    const r = Buffer.concat([Buffer.from([1]), le(BigInt(round), 4)]);
    const v = Buffer.concat([Buffer.from([1]), Buffer.from(blockHash.slice(2), "hex")]);
    return Buffer.concat([
        Buffer.from([1]), // Precommit
        le(height, 8), le(BigInt(fixedLen), 4), le(BigInt(fixedLen + r.length), 4),
        Buffer.from(address.slice(2), "hex"), r, v
    ]);
}

export function verifyArcCertificate(cert: any, validators: {publicKey: Hex; votingPower: string}[]) {
    const byAddr = new Map(validators.map((v) => [keccak256(v.publicKey).slice(0, 42), v]));
    const total = validators.reduce((a, v) => a + BigInt(v.votingPower), 0n);
    let signed = 0n;
    let verified = 0;
    for (const s of cert.signatures) {
        const v = byAddr.get(s.address.toLowerCase());
        if (!v) throw new Error(`unknown Arc signer ${s.address}`);
        const msg = arcPrecommitSignBytes(BigInt(cert.height), cert.round, cert.block_hash, s.address);
        if (!ed25519.verify(Buffer.from(s.signature, "base64"), msg, Buffer.from(v.publicKey.slice(2), "hex"))) {
            throw new Error(`Arc signature from ${s.address} does not verify`);
        }
        signed += BigInt(v.votingPower);
        verified++;
    }
    return {verified, signed, total, quorum: signed * 3n > total * 2n};
}

async function captureArc(c: ChainSpec) {
    const pc = createPublicClient({transport: http(c.rpc)});
    const H = (await pc.getBlockNumber()) - 5n;
    const res = await fetch(c.rpc, {
        method: "POST", headers: {"content-type": "application/json"},
        body: JSON.stringify({jsonrpc: "2.0", id: 1, method: "arc_getCertificate", params: [`0x${H.toString(16)}`]})
    });
    const cert = ((await res.json()) as any).result;
    const block = await pc.getBlock({blockNumber: H});
    if (cert.block_hash !== block.hash) throw new Error("certificate block_hash != eth block hash");
    const vs = (await pc.readContract({address: ARC_REGISTRY, abi: ARC_ABI, functionName: "getActiveValidatorSet", blockNumber: H - 1n})) as any[];
    const validators = vs.map((v) => ({publicKey: v.publicKey as Hex, votingPower: v.votingPower.toString(), status: Number(v.status)}));
    const chk = verifyArcCertificate(cert, validators);
    if (!chk.quorum) throw new Error("Arc certificate below 2/3");
    return {
        meta: {height: H.toString(), validators: validators.length, signatures: chk.verified, blockHash: block.hash, stateRoot: block.stateRoot},
        raw: {certificate: cert, validators, block: {hash: block.hash, stateRoot: block.stateRoot, number: H.toString()}}
    };
}

export async function capture(name: string) {
    const c = CHAINS[name];
    if (!c) throw new Error(`unknown chain ${name}`);
    const body = c.kind === "evm-bundle" ? await captureEvmBundle(c) : c.kind === "commit" ? await captureCommit(c) : await captureArc(c);
    return {
        chain: name, kind: c.kind, rpc: c.rpc, capturedAt: new Date().toISOString(),
        storeKey: c.storeKey, evmStateKeyPrefix: c.evmStateKeyPrefix, target: c.target, existenceSlot: c.existenceSlot,
        channelId: LIVE_CHANNEL_ID,
        ...body
    };
}

if (process.argv[1] && import.meta.url.endsWith(path.basename(process.argv[1]))) {
    const names = process.argv.slice(2).length ? process.argv.slice(2) : Object.keys(CHAINS);
    mkdirSync(FIXTURE_DIR, {recursive: true});
    for (const n of names) {
        try {
            const f = await capture(n);
            writeFileSync(path.join(FIXTURE_DIR, `${n}.json`), JSON.stringify(f, null, 1) + "\n");
            console.log(`${n}: height ${f.meta.height}`, JSON.stringify(f.meta));
        } catch (e) {
            console.error(`${n}: FAILED ${(e as Error).message}`);
            process.exitCode = 1;
        }
    }
    // Keep the unused-import check honest for tooling that tree-shakes.
    void validatorSetHash;
}
