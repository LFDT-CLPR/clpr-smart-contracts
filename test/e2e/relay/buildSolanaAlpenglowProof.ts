import {bls12_381} from "@noble/curves/bls12-381";
import {mkdirSync, readFileSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {encodeAbiParameters, keccak256, type Hex} from "viem";
import {g1ToUncompressed, g2ToUncompressed, BLS_POP_DST} from "./bls.js";

/// Live-data builder for Solana Alpenglow certificates (`AlpenglowFinalityVerifier` / `SolanaVerifier`).
///
/// Data sources, all public JSON-RPC (Agave 4.3.0, Oct 2026):
///   - `getAgGenesisCert` — the cluster's Alpenglow genesis certificate (rpc/src/rpc.rs
///     `get_ag_genesis_cert`): block {slot, blockId}, 192-byte uncompressed G2 aggregate signature and
///     the solana-signer-store base2 bitmap. It is the only certificate public RPC exposes today:
///     finalization certificates ride in block footers (entry/src/block_component.rs
///     `BlockFooterV1.block_final_cert`), which `getBlock` does not return.
///   - `getVoteAccounts` + `getMultipleAccounts` — stake and VoteStateV4 bytes; the BLS key is the
///     `Option<[u8;48]>` at byte 144 (u32 version tag 3, four 32-byte keys, u16, u16, u64).
///   - `getClusterNodes` (shred version) and `getEpochSchedule`.
///
/// The rank map is rebuilt exactly as `BLSPubkeyToRankMap::new` does (runtime/src/epoch_stakes.rs):
/// staked accounts with a BLS key, duplicate BLS keys / node ids dropped, sorted by stake desc then
/// compressed key asc. CAVEAT: public RPC only serves *current* stakes, so a certificate from an
/// earlier epoch is checked against the current ranking. The BLS check stays exact — a wrong
/// rank→key mapping fails the pairing — while the stake weights are the capture epoch's.
///
/// CLI:
///   npx tsx test/e2e/relay/buildSolanaAlpenglowProof.ts                 build from fixtures, print summary
///   npx tsx test/e2e/relay/buildSolanaAlpenglowProof.ts --refresh devnet [--rpc URL]   re-capture

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const SOLANA_LIVE_DIR = path.resolve(__dirname, "../fixtures/solana-live");

const G1 = bls12_381.G1.ProjectivePoint;
const G2 = bls12_381.G2.ProjectivePoint;

export interface SolanaGenesisCapture {
    cluster: string;
    rpc: string;
    capturedAt: string;
    captureEpoch: {epoch: number; absoluteSlot: number};
    epochSchedule: {slotsPerEpoch: number; firstNormalEpoch: number; firstNormalSlot: number; warmup: boolean};
    shredVersion: number;
    genesisCert: {block: {slot: number; blockId: number[]}; signature: {signature: number[]; bitmap: number[]}};
    validators: {vote: string; node: string; stake: string; bls: string | null}[];
}

export interface RankedEntry {
    rank: number;
    vote: string;
    voteBytes: Buffer;
    stake: bigint;
    blsCompressed: string;
    pubkey: Buffer; // EIP-2537 128 bytes
}

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export function base58Decode(s: string): Buffer {
    let n = 0n;
    for (const c of s) {
        const v = B58.indexOf(c);
        if (v < 0) throw new Error(`bad base58 ${s}`);
        n = n * 58n + BigInt(v);
    }
    let hex = n.toString(16);
    if (hex.length % 2) hex = "0" + hex;
    const body = n === 0n ? Buffer.alloc(0) : Buffer.from(hex, "hex");
    let zeros = 0;
    while (zeros < s.length && s[zeros] === "1") zeros++;
    return Buffer.concat([Buffer.alloc(zeros), body]);
}

/// BLSPubkeyToRankMap::new (runtime/src/epoch_stakes.rs).
export function rankMap(validators: SolanaGenesisCapture["validators"]): RankedEntry[] {
    const cand = validators.filter((v) => v.bls && BigInt(v.stake) > 0n);
    const blsCount = new Map<string, number>();
    const nodeCount = new Map<string, number>();
    for (const v of cand) {
        blsCount.set(v.bls!, (blsCount.get(v.bls!) ?? 0) + 1);
        nodeCount.set(v.node, (nodeCount.get(v.node) ?? 0) + 1);
    }
    const kept = cand.filter((v) => blsCount.get(v.bls!) === 1 && nodeCount.get(v.node) === 1);
    kept.sort((a, b) => {
        const sa = BigInt(a.stake), sb = BigInt(b.stake);
        if (sa !== sb) return sb > sa ? 1 : -1;
        return a.bls! < b.bls! ? -1 : a.bls! > b.bls! ? 1 : 0;
    });
    return kept.map((v, rank) => ({
        rank,
        vote: v.vote,
        voteBytes: base58Decode(v.vote),
        stake: BigInt(v.stake),
        blsCompressed: v.bls!,
        pubkey: g1ToUncompressed(G1.fromHex(v.bls!))
    }));
}

export function leafHash(e: RankedEntry): Buffer {
    const rank = Buffer.alloc(2);
    rank.writeUInt16BE(e.rank);
    const stake = Buffer.alloc(8);
    stake.writeBigUInt64BE(e.stake);
    return Buffer.from(keccak256(Buffer.concat([rank, e.voteBytes, stake, e.pubkey])).slice(2), "hex");
}

/// Power-of-two keccak tree over zero-padded leaves (AlpenglowCert._verifyMerkle).
export function merkle(leaves: Buffer[]): {root: Buffer; depth: number; proof: (i: number) => Buffer[]} {
    let depth = 0;
    while (1 << depth < leaves.length) depth++;
    const levels: Buffer[][] = [];
    let level = [...leaves];
    while (level.length < 1 << depth) level.push(Buffer.alloc(32));
    levels.push(level);
    for (let d = 0; d < depth; d++) {
        const next: Buffer[] = [];
        for (let i = 0; i < level.length; i += 2) {
            next.push(Buffer.from(keccak256(Buffer.concat([level[i], level[i + 1]])).slice(2), "hex"));
        }
        level = next;
        levels.push(level);
    }
    return {
        root: level[0],
        depth,
        proof: (i: number) => {
            const out: Buffer[] = [];
            let idx = i;
            for (let d = 0; d < depth; d++) {
                out.push(levels[d][idx ^ 1]);
                idx >>= 1;
            }
            return out;
        }
    };
}

export function epochOfSlot(s: SolanaGenesisCapture["epochSchedule"], slot: number): {epoch: number; first: number; last: number} {
    if (s.warmup && slot < s.firstNormalSlot) throw new Error("warmup epochs not supported");
    const off = slot - s.firstNormalSlot;
    const epoch = s.firstNormalEpoch + Math.floor(off / s.slotsPerEpoch);
    const first = s.firstNormalSlot + (epoch - s.firstNormalEpoch) * s.slotsPerEpoch;
    return {epoch, first, last: first + s.slotsPerEpoch - 1};
}

export function decodeBitmapBase2(bm: Buffer): {nbits: number; signers: number[]} {
    if (bm[0] !== 0) throw new Error("not base2");
    const nbits = bm.readUInt16LE(1);
    const signers: number[] = [];
    for (let i = 0; i < nbits; i++) if ((bm[3 + (i >> 3)] >> (i & 7)) & 1) signers.push(i);
    return {nbits, signers};
}

/// VotePayloadToSign wincode bytes (votor-messages/src/wire.rs).
export function votePayload(tag: number, slot: bigint, blockId: Buffer | null, shredVersion: number): Buffer {
    const s = Buffer.alloc(8);
    s.writeBigUInt64LE(slot);
    const sv = Buffer.alloc(2);
    sv.writeUInt16LE(shredVersion);
    return Buffer.concat([Buffer.from([tag]), s, blockId ?? Buffer.alloc(0), sv]);
}

const EPOCH_SET = {
    type: "tuple",
    components: [
        {name: "epoch", type: "uint64"},
        {name: "firstSlot", type: "uint64"},
        {name: "lastSlot", type: "uint64"},
        {name: "shredVersion", type: "uint16"},
        {name: "size", type: "uint16"},
        {name: "depth", type: "uint8"},
        {name: "totalStake", type: "uint64"},
        {name: "root", type: "bytes32"},
        {name: "aggregatePubkey", type: "bytes"}
    ]
} as const;
const SET_ENTRY = {
    type: "tuple[]",
    components: [
        {name: "rank", type: "uint16"},
        {name: "voteAccount", type: "bytes32"},
        {name: "stake", type: "uint64"},
        {name: "pubkey", type: "bytes"},
        {name: "proof", type: "bytes32[]"}
    ]
} as const;
const FINALITY = {
    type: "tuple",
    components: [
        {name: "kind", type: "uint8"},
        {name: "slot", type: "uint64"},
        {name: "blockId", type: "bytes32"},
        {
            name: "aggregates",
            type: "tuple[]",
            components: [
                {name: "signature", type: "bytes"},
                {name: "bitmap", type: "bytes"},
                {name: "complement", type: "bool"},
                {name: "entries", ...SET_ENTRY}
            ]
        }
    ]
} as const;
export const ABI = {EPOCH_SET, FINALITY};

const hx = (b: Buffer): Hex => `0x${b.toString("hex")}`;

export interface EntryArg {rank: number; voteAccount: Hex; stake: bigint; pubkey: Hex; proof: Hex[]}
export interface AggregateArg {signature: Hex; bitmap: Hex; complement: boolean; entries: EntryArg[]}
export interface FinalityArg {kind: number; slot: bigint; blockId: Hex; aggregates: AggregateArg[]}
export interface EpochSetArg {
    epoch: bigint; firstSlot: bigint; lastSlot: bigint; shredVersion: number; size: number; depth: number;
    totalStake: bigint; root: Hex; aggregatePubkey: Hex;
}

export interface SolanaGenesisProof {
    set: EpochSetArg;
    finality: FinalityArg;
    /// abi.encode(FinalityProof, EpochSet) — SolanaVerifier's `finality` field and the forge fixture.
    encoded: Hex;
    meta: {
        cluster: string; slot: number; epoch: number; captureEpoch: number; setSize: number; nbits: number;
        signers: number; complement: boolean; signedStake: bigint; totalStake: bigint; offchainVerified: boolean;
    };
    ranked: RankedEntry[];
    tree: ReturnType<typeof merkle>;
}

export function entryArg(e: RankedEntry, tree: ReturnType<typeof merkle>): EntryArg {
    return {rank: e.rank, voteAccount: hx(e.voteBytes), stake: e.stake, pubkey: hx(e.pubkey), proof: tree.proof(e.rank).map(hx)};
}

export function buildGenesisProof(c: SolanaGenesisCapture): SolanaGenesisProof {
    const ranked = rankMap(c.validators);
    const bm = Buffer.from(c.genesisCert.signature.bitmap);
    const {nbits, signers} = decodeBitmapBase2(bm);
    if (nbits > ranked.length) throw new Error(`bitmap ${nbits} > set ${ranked.length}`);
    const tree = merkle(ranked.map(leafHash));
    let apkAll = G1.ZERO;
    for (const e of ranked) apkAll = apkAll.add(G1.fromHex(e.blsCompressed));
    const totalStake = ranked.reduce((a, e) => a + e.stake, 0n);
    const signerSet = new Set(signers);
    const complement = ranked.length - signers.length < signers.length;
    const chosen = ranked.filter((e) => signerSet.has(e.rank) !== complement);
    const signedStake = ranked.filter((e) => signerSet.has(e.rank)).reduce((a, e) => a + e.stake, 0n);

    // Off-chain cross-check with noble before handing anything to the contract.
    const slot = BigInt(c.genesisCert.block.slot);
    const blockId = Buffer.from(c.genesisCert.block.blockId);
    const msg = votePayload(6, slot, blockId, c.shredVersion);
    const sig = G2.fromHex(Buffer.from(c.genesisCert.signature.signature).toString("hex"));
    let apk = G1.ZERO;
    for (const r of signers) apk = apk.add(G1.fromHex(ranked[r].blsCompressed));
    const H = bls12_381.G2.hashToCurve(msg, {DST: BLS_POP_DST}) as unknown as InstanceType<typeof G2>;
    const offchainVerified = bls12_381.verify(sig, H, apk);

    const ep = epochOfSlot(c.epochSchedule, c.genesisCert.block.slot);
    const set: EpochSetArg = {
        epoch: BigInt(ep.epoch), firstSlot: BigInt(ep.first), lastSlot: BigInt(ep.last), shredVersion: c.shredVersion,
        size: ranked.length, depth: tree.depth, totalStake, root: hx(tree.root),
        aggregatePubkey: hx(g1ToUncompressed(apkAll))
    };
    const finality: FinalityArg = {
        kind: 3, // KIND_GENESIS
        slot,
        blockId: hx(blockId),
        aggregates: [{signature: hx(g2ToUncompressed(sig)), bitmap: hx(bm), complement, entries: chosen.map((e) => entryArg(e, tree))}]
    };
    const encoded = encodeAbiParameters([FINALITY, EPOCH_SET], [finality, set] as never);
    return {
        set, finality, encoded, ranked, tree,
        meta: {
            cluster: c.cluster, slot: c.genesisCert.block.slot, epoch: ep.epoch, captureEpoch: c.captureEpoch.epoch,
            setSize: ranked.length, nbits, signers: signers.length, complement, signedStake, totalStake, offchainVerified
        }
    };
}

// ── Capture ───────────────────────────────────────────────────────────────

async function rpcCall<T>(rpc: string, method: string, params: unknown[] = []): Promise<T> {
    const r = await fetch(rpc, {method: "POST", headers: {"content-type": "application/json"},
        body: JSON.stringify({jsonrpc: "2.0", id: 1, method, params})});
    const j = (await r.json()) as {result?: T; error?: unknown};
    if (j.error) throw new Error(`${method}: ${JSON.stringify(j.error)}`);
    return j.result as T;
}

export async function captureGenesis(cluster: string, rpc: string): Promise<SolanaGenesisCapture> {
    const cert = await rpcCall<SolanaGenesisCapture["genesisCert"] | null>(rpc, "getAgGenesisCert");
    if (!cert) throw new Error(`${cluster}: no Alpenglow genesis certificate (cluster not migrated)`);
    const epochSchedule = await rpcCall<SolanaGenesisCapture["epochSchedule"]>(rpc, "getEpochSchedule");
    const ei = await rpcCall<{epoch: number; absoluteSlot: number}>(rpc, "getEpochInfo", [{commitment: "finalized"}]);
    const nodes = await rpcCall<{shredVersion: number}[]>(rpc, "getClusterNodes");
    const counts = new Map<number, number>();
    for (const n of nodes) counts.set(n.shredVersion, (counts.get(n.shredVersion) ?? 0) + 1);
    const shredVersion = [...counts.entries()].sort((a, b) => b[1] - a[1])[0][0];
    const va = await rpcCall<{current: {votePubkey: string; nodePubkey: string; activatedStake: number}[];
        delinquent: {votePubkey: string; nodePubkey: string; activatedStake: number}[]}>(rpc, "getVoteAccounts", [{commitment: "finalized"}]);
    const all = [...va.current, ...va.delinquent];
    const validators: SolanaGenesisCapture["validators"] = [];
    for (let i = 0; i < all.length; i += 100) {
        const chunk = all.slice(i, i + 100);
        const accs = await rpcCall<{value: ({data: [string, string]} | null)[]}>(rpc, "getMultipleAccounts",
            [chunk.map((v) => v.votePubkey), {encoding: "base64", commitment: "finalized"}]);
        accs.value.forEach((a, j) => {
            const v = chunk[j];
            let bls: string | null = null;
            if (a) {
                const d = Buffer.from(a.data[0], "base64");
                if (d.readUInt32LE(0) === 3 && d[144] === 1) bls = d.subarray(145, 193).toString("hex");
            }
            validators.push({vote: v.votePubkey, node: v.nodePubkey, stake: BigInt(v.activatedStake).toString(), bls});
        });
    }
    return {cluster, rpc, capturedAt: new Date().toISOString(), captureEpoch: ei, epochSchedule, shredVersion,
        genesisCert: cert, validators};
}

export function fixturePath(cluster: string): string {
    return path.join(SOLANA_LIVE_DIR, `${cluster}-genesis.json`);
}

export function loadGenesisCapture(cluster = "devnet"): SolanaGenesisCapture {
    return JSON.parse(readFileSync(fixturePath(cluster), "utf8")) as SolanaGenesisCapture;
}

const DEFAULT_RPC: Record<string, string> = {
    devnet: "https://api.devnet.solana.com",
    testnet: "https://api.testnet.solana.com"
};

async function main() {
    const args = process.argv.slice(2);
    const i = args.indexOf("--refresh");
    if (i >= 0) {
        const cluster = args[i + 1] ?? "devnet";
        const r = args.indexOf("--rpc");
        const rpc = r >= 0 ? args[r + 1] : DEFAULT_RPC[cluster];
        const cap = await captureGenesis(cluster, rpc);
        const proof = buildGenesisProof(cap);
        if (!proof.meta.offchainVerified) {
            throw new Error(`${cluster}: genesis cert does not verify against the current rank map ` +
                `(stake ranking drifted since epoch ${proof.meta.epoch}); not writing a fixture`);
        }
        mkdirSync(SOLANA_LIVE_DIR, {recursive: true});
        writeFileSync(fixturePath(cluster), JSON.stringify(cap, null, 1) + "\n");
        writeFileSync(path.join(SOLANA_LIVE_DIR, `${cluster}-genesis.proof.hex`), proof.encoded + "\n");
        console.log(`wrote ${fixturePath(cluster)}`);
    }
    for (const cluster of ["devnet"]) {
        const p = buildGenesisProof(loadGenesisCapture(cluster));
        console.log(JSON.stringify(p.meta, (_k, v) => (typeof v === "bigint" ? v.toString() : v)));
    }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
    main().catch((e) => {
        console.error(e);
        process.exit(1);
    });
}
