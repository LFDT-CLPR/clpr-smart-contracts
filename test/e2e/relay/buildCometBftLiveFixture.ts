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
 *   evm-state    (Stable)       no public CometBFT RPC, so no commit. eth_getProof (cosmos/evm returns
 *                                the ICS-23 IAVL + multistore proofs) for the same six slots at H, and
 *                                blocks H and H+1 from eth_getBlockByNumber. Checked off-chain: every
 *                                proof's key is prefix ‖ target ‖ slot, the IAVL root is the "evm"
 *                                store root, and the multistore root equals block H+1's stateRoot
 *                                (cosmos/evm reports the CometBFT app_hash there).
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
    ics23Root,
    validatorSetHash
} from "./cometbft.js";

export const FIXTURE_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../fixtures/cometbft-live");
export const LIVE_CHANNEL_ID = keccak256(new TextEncoder().encode("clpr-cometbft-live")) as Hex;
const CHANNELS_SLOT = 15n;
const CHANNEL_OFFSETS = [1n, 2n, 4n, 5n, 16n];

export interface ChainSpec {
    name: string;
    kind: "evm-bundle" | "commit" | "malachite" | "evm-state";
    rpc: string;
    storeKey?: string;
    evmStateKeyPrefix?: number;
    /** Contract standing in for the peer ClprService (no ClprService is deployed on these chains). */
    target?: Hex;
    /** A slot of `target` that is non-zero (existence proof). */
    existenceSlot?: Hex;
    /**
     * evm-bundle only: look back up to this many blocks for a ROTATION header R (next_validators_hash !=
     * validators_hash, same set over R-10..R so the H-5 hop still applies) and record the bundle at R.
     */
    rotationSearch?: number;
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
    // RWA profiles. MANTRA: cosmos/evm (MANTRA-Chain/evm v0.6.3-v8-mantra-1) x/vm StoreKey "evm",
    // KeyPrefixStorage 0x02. Injective: injective-core v1.20.3-safeharbor.2 (last public source)
    // injective-chain/modules/evm StoreKey "evm", KeyPrefixStorage 0x02. Both store 32-byte words.
    mantra: {
        name: "mantra", kind: "evm-bundle", rpc: "https://rpc.mantrachain.io",
        storeKey: "evm", evmStateKeyPrefix: 0x02,
        target: "0xe3047710ef6cb36bcf1e58145529778ea7cb5598", // wMANTRA ("Wrapped MANTRA")
        existenceSlot: "0x00", // non-zero (0x01), equal to eth_getStorageAt at the same height
        rotationSearch: 3000 // the set hash changes ~7×/h (delegations move voting power)
    },
    injective: {
        name: "injective", kind: "evm-bundle", rpc: "https://injective-rpc.polkachu.com", // sentry.tm.injective.network serves ABCI proofs only ~100 blocks back
        storeKey: "evm", evmStateKeyPrefix: 0x02,
        target: "0x0000000088827d2d103ee2d9a6b781773ae03ffb", // wINJ ("Wrapped INJ")
        existenceSlot: "0x05", // slots 0-4 are zero; slot 5 holds 0x64 (eth_getStorageAt)
        rotationSearch: 3000 // the set hash changes ~12×/h
    },
    // Kava: kava v0.28.2 pins kava-labs/ethermint v0.21.0-kava-v27.0, x/evm StoreKey "evm",
    // KeyPrefixStorage 0x02 (iota+1 after code). statedb.Commit writes value.Bytes() (32 B, zero
    // words stored, not deleted). CometBFT kava-labs fork v0.37.18-kava.1 (node reports 0.37.16).
    kava: {
        name: "kava", kind: "evm-bundle", rpc: "https://kava-rpc.polkachu.com",
        storeKey: "evm", evmStateKeyPrefix: 0x02,
        target: "0xc86c7c0efbd6a49b35e8714c5f59d99de09a225b", // WKAVA ("Wrapped Kava")
        existenceSlot: "0x00", // name() short string "Wrapped Kava", equal to eth_getStorageAt
        rotationSearch: 2000
    },
    // Stable: StableBFT (CometBFT-based) + Cosmos EVM; stabled source is not public (binaries only).
    // No public CometBFT RPC (docs list only the EVM endpoint), so only state is recorded, through
    // eth_getProof. The live proofs show store "evm", key 0x02‖addr‖slot, 32-byte words.
    stable: {
        name: "stable", kind: "evm-state", rpc: "https://rpc.stable.xyz",
        storeKey: "evm", evmStateKeyPrefix: 0x02,
        target: "0x779ded0c9e1022225f8e0630b35a9b54be713736", // USDT0 (proxy), stablelabs/stable-tokenlist
        existenceSlot: "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" // EIP-1967 implementation
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

/** Newest rotation header R <= top with an unchanged set over R-10..R (see ChainSpec.rotationSearch). */
async function findRotation(rpcUrl: string, top: bigint, window: number): Promise<bigint | undefined> {
    const vh = new Map<bigint, [string, string]>();
    for (let hi = top; hi > top - BigInt(window); hi -= 20n) {
        const res = await fetch(`${rpcUrl}/blockchain?minHeight=${hi - 19n}&maxHeight=${hi}`, {signal: AbortSignal.timeout(30_000)});
        const metas = ((await res.json()) as any).result.block_metas as any[];
        for (const m of metas) vh.set(BigInt(m.header.height), [m.header.validators_hash, m.header.next_validators_hash]);
        for (let r = hi; r > hi - 20n; r--) {
            const cur = vh.get(r);
            if (!cur || cur[0] === cur[1]) continue;
            let stable = true;
            for (let k = r - 10n; k < r && stable; k++) {
                const x = vh.get(k);
                if (x === undefined) stable = r - 10n > hi - 20n; // not fetched yet: check next round
                else if (x[0] !== cur[0]) stable = false;
            }
            if (stable && [...Array(10).keys()].every((i) => vh.has(r - 10n + BigInt(i)))) return r;
        }
    }
    return undefined;
}

async function captureEvmBundle(c: ChainSpec) {
    const st = await fetchStatus(c.rpc);
    const top = BigInt(st.sync_info.latest_block_height) - 3n;
    const R = c.rotationSearch ? await findRotation(c.rpc, top, c.rotationSearch) : undefined;
    if (c.rotationSearch && R === undefined) console.warn(`${c.name}: no rotation header in the last ${c.rotationSearch} blocks`);
    const H = R ?? top;
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
        meta: {
            height: H.toString(), hopHeight: hopH.toString(), signers: enc.signerIndices.length, validators: vals.vals.length,
            rotation: commit.sh.header.next_validators_hash !== commit.sh.header.validators_hash
        },
        raw: {commit: commit.json, hopCommit: hopCommit.json, validators: vals.json, hopValidators: hopVals.json, abci}
    };
}

async function evmRpc(url: string, method: string, params: unknown[]): Promise<any> {
    const res = await fetch(url, {
        method: "POST", headers: {"content-type": "application/json"},
        body: JSON.stringify({jsonrpc: "2.0", id: 1, method, params}), signal: AbortSignal.timeout(30_000)
    });
    const j = (await res.json()) as any;
    if (j.error) throw new Error(`${method}: ${JSON.stringify(j.error)}`);
    return j.result;
}

/** Check one eth_getProof storage entry against the store layout and block H+1's stateRoot. */
export function checkEvmStateProof(entry: {key: string; proof: string[]}, prefix: number, target: Hex, storeKey: string, appHash: string) {
    const want = evmStorageKey(prefix, target, entry.key as Hex);
    if (entry.proof.length !== 2) throw new Error("expected IAVL + multistore proofs");
    const iavl = ics23Root(Buffer.from(entry.proof[0].slice(2), "hex"));
    const ms = ics23Root(Buffer.from(entry.proof[1].slice(2), "hex"));
    const provenKey = iavl.absentKey ?? iavl.key;
    if (!provenKey.equals(want)) throw new Error(`key ${provenKey.toString("hex")} != ${want.toString("hex")}`);
    if (ms.key.toString() !== storeKey || !ms.value.equals(iavl.root)) throw new Error("IAVL root is not the store root");
    if ("0x" + ms.root.toString("hex") !== appHash.toLowerCase()) throw new Error("multistore root != app hash");
    return {exists: iavl.absentKey === undefined, value: iavl.absentKey ? Buffer.alloc(0) : iavl.value, iavlRoot: iavl.root, appHash: ms.root};
}

async function captureEvmState(c: ChainSpec) {
    const H = BigInt(await evmRpc(c.rpc, "eth_blockNumber", [])) - 5n;
    const at = "0x" + H.toString(16);
    const slots = [...channelSlots(LIVE_CHANNEL_ID), c.existenceSlot!];
    const [proof, storageAt, block, next, chainId] = await Promise.all([
        evmRpc(c.rpc, "eth_getProof", [c.target, slots, at]),
        evmRpc(c.rpc, "eth_getStorageAt", [c.target, c.existenceSlot, at]),
        evmRpc(c.rpc, "eth_getBlockByNumber", [at, false]),
        evmRpc(c.rpc, "eth_getBlockByNumber", ["0x" + (H + 1n).toString(16), false]),
        evmRpc(c.rpc, "eth_chainId", [])
    ]);
    const checked = proof.storageProof.map((e: any) => checkEvmStateProof(e, c.evmStateKeyPrefix!, c.target!, c.storeKey!, next.stateRoot));
    if (checked.slice(0, 5).some((x: any) => x.exists)) throw new Error("a channel slot exists");
    if (!checked[5].exists || "0x" + checked[5].value.toString("hex") !== storageAt) throw new Error("existence value != eth_getStorageAt");
    const pick = (b: any) => ({number: b.number, hash: b.hash, parentHash: b.parentHash, stateRoot: b.stateRoot, timestamp: b.timestamp});
    return {
        meta: {height: H.toString(), evmChainId: Number(chainId), appHash: next.stateRoot},
        raw: {proof, storageAt, block: pick(block), nextBlock: pick(next)}
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
    const body =
        c.kind === "evm-bundle" ? await captureEvmBundle(c)
        : c.kind === "commit" ? await captureCommit(c)
        : c.kind === "evm-state" ? await captureEvmState(c)
        : await captureArc(c);
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
