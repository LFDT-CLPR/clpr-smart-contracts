import {mkdirSync, readFileSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {type Hex, keccak256, recoverAddress, toHex} from "viem";
import {hexToBuf, hexToTrimmedBuf, rlpDecode, rlpEncode} from "../lib/rlp.js";
import {type Input} from "@ethereumjs/rlp";
import {
    anyRpc,
    channelSlots,
    encodeChannelContext,
    hexNum,
    ledgerConfigPayload,
    liveChannelId,
    proofItems,
    type RpcProof
} from "./liveCommon.js";

/// Live fixtures for SignerReplayVerifier (Clique / Congress / Bitkub PoS chains).
///
/// Capture (`--refresh`): for each network, two consecutive boundary blocks B0 < B1, a run of real
/// headers starting at B1 that carries seals from a majority of B0's signer set, and eth_getProof for
/// a real contract at B1. Build (offline): the config proof (B0), the rotation bundle (run from B1,
/// B0 anchor → B1 anchor) and the same bundle under the rotated anchor (no rotation).
///
/// Run: npx tsx test/e2e/relay/buildSignerReplayLiveProof.ts --refresh [--network <name>]

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const SIGNER_REPLAY_LIVE_DIR = path.resolve(__dirname, "../fixtures/signer-replay-live");

export interface ReplayProfile {
    epochLength: bigint;
    boundaryOffset: bigint;
    sealFields: number; // 0 = all fields
    entrySize: number;
    trailerSize: number;
    trailerSignerOffset: number; // 255 = none
}

export type SignerReplayNetwork =
    | "immutable-mainnet"
    | "immutable-testnet"
    | "kub-mainnet"
    | "kub-testnet"
    | "grx-mainnet";

const CLIQUE_30000: ReplayProfile = {epochLength: 30000n, boundaryOffset: 0n, sealFields: 0, entrySize: 20, trailerSize: 0, trailerSignerOffset: 255};
const KUB: ReplayProfile = {epochLength: 50n, boundaryOffset: 1n, sealFields: 0, entrySize: 40, trailerSize: 60, trailerSignerOffset: 40};
const GRX: ReplayProfile = {epochLength: 200n, boundaryOffset: 0n, sealFields: 15, entrySize: 20, trailerSize: 0, trailerSignerOffset: 255};

export const NETWORKS: Record<SignerReplayNetwork, {
    chainId: bigint; rpcs: string[]; profile: ReplayProfile; insecureTls?: boolean; maxRun: number; account?: Hex;
}> = {
    "immutable-mainnet": {chainId: 13371n, rpcs: ["https://rpc.immutable.com"], profile: CLIQUE_30000, maxRun: 8},
    "immutable-testnet": {chainId: 13473n, rpcs: ["https://rpc.testnet.immutable.com"], profile: CLIQUE_30000, maxRun: 8},
    "kub-mainnet": {chainId: 96n, rpcs: ["https://rpc.bitkubchain.io"], profile: KUB, maxRun: 120},
    "kub-testnet": {chainId: 25925n, rpcs: ["https://rpc-testnet.bitkubchain.io"], profile: KUB, maxRun: 120},
    // rpc.grxchain.io serves an expired TLS certificate (seen 2026-10-01). The data is public and every
    // header is checked by hash links and seals offline, so the capture skips certificate validation.
    "grx-mainnet": {chainId: 1110n, rpcs: ["https://rpc.grxchain.io"], profile: GRX, insecureTls: true, maxRun: 16,
        // Congress system contract "Validators" (no user transactions in recent blocks to pick from).
        account: "0x000000000000000000000000000000000000f000"}
};

export interface RpcBlock {
    hash: Hex;
    parentHash: Hex;
    sha3Uncles: Hex;
    miner: Hex;
    stateRoot: Hex;
    transactionsRoot: Hex;
    receiptsRoot: Hex;
    logsBloom: Hex;
    difficulty: Hex;
    number: Hex;
    gasLimit: Hex;
    gasUsed: Hex;
    timestamp: Hex;
    extraData: Hex;
    mixHash: Hex;
    nonce: Hex;
    baseFeePerGas?: Hex;
    withdrawalsRoot?: Hex;
    blobGasUsed?: Hex;
    excessBlobGas?: Hex;
    parentBeaconBlockRoot?: Hex;
    requestsHash?: Hex;
}

export interface SignerReplayCapture {
    network: SignerReplayNetwork;
    chainId: string;
    capturedAt: string;
    account: Hex;
    channelId: Hex;
    b0: string;
    b1: string;
    run: string[];
    configRun: string[]; // B0 … : the bootstrap run (B0's set must seal a majority)
    blocks: Record<string, RpcBlock>;
    proof: RpcProof;
}

export interface SignerReplayLiveProof {
    network: SignerReplayNetwork;
    chainId: bigint;
    channelId: Hex;
    channelContext: Hex;
    configProof: Hex;
    trustAnchor: Hex;
    rotatedAnchor: Hex;
    proofBytes: Hex;
    proofBytesNoRotation: Hex;
    parts: BundleParts;
    meta: {
        b0: bigint;
        b1: bigint;
        runLength: number;
        signersB0: Hex[];
        signersB1: Hex[];
        distinctAnchorSealers: number;
        required: number;
        setChanged: boolean;
        codeHash: Hex;
        stateRoot: Hex;
    };
}

export interface BundleParts {
    signers: Buffer;
    headers: Input[]; // decoded header lists (embedded as RLP lists, not byte strings)
    accountProof: Buffer[];
    storageProof: [Buffer, Buffer[]][];
    bundleContent: Buffer;
}

// ── Header encoding and seals ───────────────────────────────────────────────

export function headerFields(b: RpcBlock): Buffer[] {
    const f = [hexToBuf(b.parentHash), hexToBuf(b.sha3Uncles), hexToBuf(b.miner), hexToBuf(b.stateRoot),
        hexToBuf(b.transactionsRoot), hexToBuf(b.receiptsRoot), hexToBuf(b.logsBloom), hexToTrimmedBuf(b.difficulty),
        hexToTrimmedBuf(b.number), hexToTrimmedBuf(b.gasLimit), hexToTrimmedBuf(b.gasUsed), hexToTrimmedBuf(b.timestamp),
        hexToBuf(b.extraData), hexToBuf(b.mixHash), hexToBuf(b.nonce)];
    if (b.baseFeePerGas !== undefined) f.push(hexToTrimmedBuf(b.baseFeePerGas));
    if (b.withdrawalsRoot !== undefined) f.push(hexToBuf(b.withdrawalsRoot));
    if (b.blobGasUsed !== undefined) f.push(hexToTrimmedBuf(b.blobGasUsed), hexToTrimmedBuf(b.excessBlobGas));
    if (b.parentBeaconBlockRoot !== undefined) f.push(hexToBuf(b.parentBeaconBlockRoot));
    if (b.requestsHash !== undefined) f.push(hexToBuf(b.requestsHash));
    return f;
}

export function headerRlp(b: RpcBlock): Buffer {
    const enc = rlpEncode(headerFields(b));
    const h = keccak256(enc);
    if (h !== b.hash) throw new Error(`header ${BigInt(b.number)} re-encodes to ${h}, RPC hash ${b.hash}`);
    return enc;
}

export async function sealSigner(b: RpcBlock, p: ReplayProfile): Promise<Hex> {
    const f = headerFields(b);
    const extra = f[12];
    const sig = extra.subarray(extra.length - 65);
    f[12] = extra.subarray(0, extra.length - 65);
    const fields = p.sealFields === 0 ? f : f.slice(0, p.sealFields);
    const digest = keccak256(rlpEncode(fields));
    const v = sig[64];
    if (v > 1) throw new Error("seal v out of range");
    return (await recoverAddress({
        hash: digest,
        signature: toHex(Buffer.concat([sig.subarray(0, 64), Buffer.from([v + 27])]))
    })).toLowerCase() as Hex;
}

export function isBoundary(n: bigint, p: ReplayProfile): boolean {
    return (n + p.boundaryOffset) % p.epochLength === 0n;
}

/// ClprSignerReplay.parseSigners: distinct entry addresses (+ trailer signer), ascending.
export function parseSigners(b: RpcBlock, p: ReplayProfile): Hex[] {
    const extra = hexToBuf(b.extraData);
    const listLen = extra.length - 32 - 65 - p.trailerSize;
    if (listLen <= 0 || listLen % p.entrySize !== 0) throw new Error(`block ${BigInt(b.number)} carries no signer list`);
    const out = new Set<string>();
    for (let i = 0; i < listLen / p.entrySize; i++) {
        out.add("0x" + extra.subarray(32 + i * p.entrySize, 32 + i * p.entrySize + 20).toString("hex"));
    }
    if (p.trailerSignerOffset !== 255) {
        const off = 32 + listLen + p.trailerSignerOffset;
        out.add("0x" + extra.subarray(off, off + 20).toString("hex"));
    }
    return [...out].sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : 1)) as Hex[];
}

export function signersBytes(s: Hex[]): Buffer {
    return Buffer.concat(s.map(hexToBuf));
}

export function encodeAnchor(codeHash: Hex, signers: Hex[], setBlock: bigint): Hex {
    const b = Buffer.alloc(74);
    hexToBuf(codeHash).copy(b, 0);
    hexToBuf(keccak256(signersBytes(signers))).copy(b, 32);
    b.writeBigUInt64BE(setBlock, 64);
    b.writeUInt16BE(signers.length, 72);
    return toHex(b);
}

export function encodeBundle(p: BundleParts, overrides: Partial<BundleParts> = {}): Hex {
    const q = {...p, ...overrides};
    return toHex(rlpEncode([q.signers, q.headers, q.accountProof, q.storageProof, q.bundleContent]));
}

// ── Build (offline) ─────────────────────────────────────────────────────────

function blk(c: SignerReplayCapture, n: bigint | string): RpcBlock {
    const b = c.blocks[String(n)];
    if (!b) throw new Error(`capture is missing block ${n}`);
    return b;
}

export async function buildSignerReplayLiveProof(c: SignerReplayCapture): Promise<SignerReplayLiveProof> {
    const net = NETWORKS[c.network];
    const p = net.profile;
    const chainId = BigInt(c.chainId);
    const b0 = BigInt(c.b0);
    const b1 = BigInt(c.b1);
    if (!isBoundary(b0, p) || !isBoundary(b1, p) || b1 - b0 !== p.epochLength) throw new Error("bad boundary pair");

    const s0 = parseSigners(blk(c, b0), p);
    const s1 = parseSigners(blk(c, b1), p);
    const run = c.run.map((n) => blk(c, n));
    if (BigInt(run[0].number) !== b1) throw new Error("run must start at B1");
    const headers = run.map((b) => rlpDecode(headerRlp(b)) as Input);
    for (let i = 1; i < run.length; i++) {
        if (run[i].parentHash !== run[i - 1].hash) throw new Error(`run broken at ${i}`);
    }
    const seen = new Set<string>();
    for (const b of run) {
        const s = await sealSigner(b, p);
        if (s0.includes(s)) seen.add(s);
    }
    const required = Math.floor(s0.length / 2) + 1;
    if (seen.size < required) throw new Error(`run has ${seen.size}/${required} distinct anchor sealers`);

    const codeHash = c.proof.codeHash;
    const slots = channelSlots(c.channelId);
    const {accountProof, storageProof} = proofItems(c.proof, slots);
    const configRun = c.configRun.map((n) => blk(c, n));
    if (BigInt(configRun[0].number) !== b0) throw new Error("config run must start at B0");
    const cfgSeen = new Set<string>();
    for (const b of configRun) {
        const s = await sealSigner(b, p);
        if (s0.includes(s)) cfgSeen.add(s);
    }
    if (cfgSeen.size < required) throw new Error(`config run has ${cfgSeen.size}/${required} distinct B0 sealers`);
    const configProof = toHex(rlpEncode([
        ledgerConfigPayload(chainId, c.account), configRun.map((b) => rlpDecode(headerRlp(b)) as Input), hexToBuf(codeHash)
    ]));
    const parts: BundleParts = {
        signers: signersBytes(s0), headers, accountProof, storageProof, bundleContent: Buffer.alloc(0)
    };
    const proofBytes = encodeBundle(parts);
    const proofBytesNoRotation = encodeBundle(parts, {signers: signersBytes(s1)});
    return {
        network: c.network,
        chainId,
        channelId: c.channelId,
        channelContext: encodeChannelContext(c.channelId, c.account),
        configProof,
        trustAnchor: encodeAnchor(codeHash, s0, b0),
        rotatedAnchor: encodeAnchor(codeHash, s1, b1),
        proofBytes,
        proofBytesNoRotation,
        parts,
        meta: {
            b0, b1, runLength: run.length, signersB0: s0, signersB1: s1, distinctAnchorSealers: seen.size, required,
            setChanged: keccak256(signersBytes(s0)) !== keccak256(signersBytes(s1)), codeHash, stateRoot: run[0].stateRoot
        }
    };
}

// ── Capture (live) ──────────────────────────────────────────────────────────

const KEEP: (keyof RpcBlock)[] = ["hash", "parentHash", "sha3Uncles", "miner", "stateRoot", "transactionsRoot",
    "receiptsRoot", "logsBloom", "difficulty", "number", "gasLimit", "gasUsed", "timestamp", "extraData", "mixHash",
    "nonce", "baseFeePerGas", "withdrawalsRoot", "blobGasUsed", "excessBlobGas", "parentBeaconBlockRoot", "requestsHash"];

function stripBlock(b: Record<string, unknown>): RpcBlock {
    const out: Record<string, unknown> = {};
    for (const k of KEEP) if (b[k] !== undefined) out[k] = b[k];
    return out as unknown as RpcBlock;
}

const EMPTY_TRIE_ROOT = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";

/// A recently called contract with storage: the `to` of a transaction in a recent block that has code.
async function findContract(rpc: <T>(m: string, p: unknown[]) => Promise<T>, from: bigint): Promise<Hex> {
    for (let n = from; n > from - 400n && n > 0n; n--) {
        const b = await rpc<{transactions: {to: Hex | null}[]}>("eth_getBlockByNumber", [hexNum(n), true]);
        for (const tx of b.transactions) {
            if (!tx.to) continue;
            const code = await rpc<Hex>("eth_getCode", [tx.to, hexNum(n)]);
            if (code === "0x") continue;
            // Needs non-empty storage: an empty storage trie has no node to prove exclusion against.
            const p = await rpc<RpcProof>("eth_getProof", [tx.to, [], hexNum(n)]);
            if (p.storageHash !== EMPTY_TRIE_ROOT) return tx.to.toLowerCase() as Hex;
        }
    }
    throw new Error("no contract found in recent blocks");
}

export async function captureSignerReplayLive(network: SignerReplayNetwork, opts: {account?: Hex; waitMs?: number} = {}): Promise<SignerReplayCapture> {
    const net = NETWORKS[network];
    const p = net.profile;
    const rpc = <T>(m: string, params: unknown[]) => anyRpc<T>(net.rpcs, m, params, net.insecureTls);
    const chainId = BigInt(await rpc<Hex>("eth_chainId", []));
    if (chainId !== net.chainId) throw new Error(`${network}: chain id ${chainId}`);
    const latest = BigInt(await rpc<Hex>("eth_blockNumber", []));
    // Newest boundary B1 ≤ latest.
    const b1 = latest - ((latest + p.boundaryOffset) % p.epochLength);
    const b0 = b1 - p.epochLength;
    const blocks: Record<string, RpcBlock> = {};
    const get = async (n: bigint): Promise<RpcBlock> => {
        const key = String(n);
        if (!blocks[key]) blocks[key] = stripBlock(await rpc<Record<string, unknown>>("eth_getBlockByNumber", [hexNum(n), false]));
        return blocks[key];
    };
    await get(b0);
    const s0 = parseSigners(await get(b1 - p.epochLength), p);
    parseSigners(await get(b1), p);
    // State proof at B1 first: non-archive RPCs keep only recent state.
    const account = opts.account ?? net.account ?? await findContract(rpc, latest);
    const channelId = liveChannelId("signer-replay-verifier");
    const proof = await rpc<RpcProof>("eth_getProof", [account, channelSlots(channelId), hexNum(b1)]);

    const required = Math.floor(s0.length / 2) + 1;
    // Bootstrap run from B0 until a majority of B0's own set has sealed.
    const configRun: string[] = [];
    {
        const cfgSeen = new Set<string>();
        for (let n = b0; cfgSeen.size < required; n++) {
            if (configRun.length >= net.maxRun || n >= b1) throw new Error(`${network}: config run too long`);
            const b = await get(n);
            configRun.push(String(n));
            const s = await sealSigner(b, p);
            if (s0.includes(s)) cfgSeen.add(s);
        }
    }
    // Grow the run from B1 until a majority of B0's set has sealed (wait for new blocks if needed).
    const run: string[] = [];
    const seen = new Set<string>();
    const deadline = Date.now() + (opts.waitMs ?? 15 * 60_000);
    for (let n = b1; ; n++) {
        if (run.length >= net.maxRun) throw new Error(`${network}: ${seen.size}/${required} sealers after ${run.length} headers`);
        let b: RpcBlock | undefined;
        while (!b) {
            try {
                b = await get(n);
            } catch (e) {
                if (Date.now() > deadline) throw e;
                await new Promise((r) => setTimeout(r, 3000));
            }
        }
        run.push(String(n));
        const s = await sealSigner(b, p);
        if (s0.includes(s)) seen.add(s);
        if (seen.size >= required) break;
    }
    return {
        network, chainId: String(chainId), capturedAt: new Date().toISOString(), account, channelId,
        b0: String(b0), b1: String(b1), run, configRun, blocks, proof
    };
}

// ── Files ───────────────────────────────────────────────────────────────────

export function fixturePath(network: SignerReplayNetwork): string {
    return path.join(SIGNER_REPLAY_LIVE_DIR, `${network}.json`);
}

export function vectorsPath(network: SignerReplayNetwork): string {
    return path.join(SIGNER_REPLAY_LIVE_DIR, `${network}-vectors.json`);
}

export function loadSignerReplayCapture(network: SignerReplayNetwork): SignerReplayCapture {
    return JSON.parse(readFileSync(fixturePath(network), "utf8")) as SignerReplayCapture;
}

/// Flat hex vectors for the Foundry live-data test (test/verifiers/evm/signer/SignerReplayLive.t.sol).
export function writeVectors(p: SignerReplayLiveProof): void {
    const v = {
        chainId: Number(p.chainId),
        configProof: p.configProof,
        trustAnchor: p.trustAnchor,
        rotatedAnchor: p.rotatedAnchor,
        proofBytes: p.proofBytes,
        proofBytesNoRotation: p.proofBytesNoRotation,
        channelContext: p.channelContext,
        channelId: p.channelId,
        b0: Number(p.meta.b0),
        b1: Number(p.meta.b1),
        runLength: p.meta.runLength,
        signers: p.meta.signersB0.length
    };
    writeFileSync(vectorsPath(p.network), JSON.stringify(v, null, 1) + "\n");
}

function summarize(p: SignerReplayLiveProof): string {
    const m = p.meta;
    const len = (h: Hex) => (h.length - 2) / 2;
    return [
        `network      ${p.network} (chainId ${p.chainId})`,
        `boundaries   B0 ${m.b0} (${m.signersB0.length} signers) → B1 ${m.b1} (${m.signersB1.length} signers), set ${m.setChanged ? "CHANGED" : "unchanged"}`,
        `run          ${m.runLength} headers from B1, ${m.distinctAnchorSealers}/${m.required} distinct anchor sealers`,
        `proofBytes   ${len(p.proofBytes)} B, configProof ${len(p.configProof)} B`
    ].join("\n");
}

async function main(): Promise<void> {
    const args = process.argv.slice(2);
    const nIdx = args.indexOf("--network");
    const networks = (nIdx >= 0 ? [args[nIdx + 1]] : Object.keys(NETWORKS)) as SignerReplayNetwork[];
    for (const network of networks) {
        let capture: SignerReplayCapture;
        if (args.includes("--refresh")) {
            try {
                capture = await captureSignerReplayLive(network);
            } catch (e) {
                console.error(`[${network}] capture failed: ${(e as Error).message}`);
                continue;
            }
            const built = await buildSignerReplayLiveProof(capture); // validate before overwriting
            mkdirSync(SIGNER_REPLAY_LIVE_DIR, {recursive: true});
            writeFileSync(fixturePath(network), JSON.stringify(capture, null, 1) + "\n");
            writeVectors(built);
            console.log(`captured → ${path.relative(process.cwd(), fixturePath(network))}`);
        } else {
            capture = loadSignerReplayCapture(network);
            if (args.includes("--vectors")) writeVectors(await buildSignerReplayLiveProof(capture));
        }
        console.log(summarize(await buildSignerReplayLiveProof(capture)));
    }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    main().catch((err) => {
        console.error(err);
        process.exit(1);
    });
}

