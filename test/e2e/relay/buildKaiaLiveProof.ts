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

/// Live fixtures for KaiaIstanbulVerifier.
///
/// Capture (`--refresh`): on Kaia mainnet, the most recent change of the qualified validator set
/// (block C, found by bisection; C−1 carries the old set) and a recent header R; on Kairos a header
/// ~10 000 blocks back and a recent header R. eth_getProof of the AddressBook system contract
/// (0x…0400) at C (mainnet, archive RPC) and at R.
/// Build (offline): config proof (C−1 or the older Kairos header), the rotation bundle [C] (mainnet)
/// and a plain bundle [R] under the resulting anchor.
///
/// Run: npx tsx test/e2e/relay/buildKaiaLiveProof.ts --refresh [--network kaia-mainnet|kairos]

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const KAIA_LIVE_DIR = path.resolve(__dirname, "../fixtures/kaia-live");
export const ADDRESS_BOOK: Hex = "0x0000000000000000000000000000000000000400";

export type KaiaNetwork = "kaia-mainnet" | "kairos";
export const NETWORKS: Record<KaiaNetwork, {chainId: bigint; rpcs: string[]; rotationSearch: boolean}> = {
    "kaia-mainnet": {chainId: 8217n, rpcs: ["https://public-en.node.kaia.io"], rotationSearch: true},
    kairos: {chainId: 1001n, rpcs: ["https://public-en-kairos.node.kaia.io"], rotationSearch: false}
};

export interface KaiaRpcBlock {
    hash: Hex;
    parentHash: Hex;
    reward: Hex;
    stateRoot: Hex;
    transactionsRoot: Hex;
    receiptsRoot: Hex;
    logsBloom: Hex;
    blockScore: Hex;
    number: Hex;
    gasUsed: Hex;
    timestamp: Hex;
    timestampFoS: Hex;
    extraData: Hex;
    governanceData: Hex;
    voteData: Hex;
    baseFeePerGas?: Hex;
    randomReveal?: Hex;
    mixHash?: Hex;
    blobGasUsed?: Hex;
    excessBlobGas?: Hex;
    vrank?: Hex;
}

export interface KaiaCapture {
    network: KaiaNetwork;
    chainId: string;
    capturedAt: string;
    account: Hex;
    channelId: Hex;
    anchorBlock: string; // header whose set bootstraps the channel
    rotationBlock?: string; // first header with the new set (mainnet)
    recentBlock: string;
    blocks: Record<string, KaiaRpcBlock>;
    proofs: Record<string, RpcProof>; // by block number
}

export interface KaiaBundleParts {
    validators: Buffer;
    headers: Input[]; // decoded header lists (embedded as RLP lists, not byte strings)
    accountProof: Buffer[];
    storageProof: [Buffer, Buffer[]][];
    bundleContent: Buffer;
}

export interface KaiaLiveProof {
    network: KaiaNetwork;
    chainId: bigint;
    channelId: Hex;
    channelContext: Hex;
    configProof: Hex;
    trustAnchor: Hex;
    rotatedAnchor?: Hex;
    rotationProof?: Hex;
    plainAnchor: Hex;
    plainProof: Hex;
    plainParts: KaiaBundleParts;
    rotationParts?: KaiaBundleParts;
    meta: {
        anchorBlock: bigint;
        rotationBlock?: bigint;
        recentBlock: bigint;
        anchorSet: number;
        rotatedSet?: number;
        recentSeals: number;
        rotationVouch?: number;
        codeHash: Hex;
    };
}

// ── Header encoding and seals ───────────────────────────────────────────────

export function headerFields(b: KaiaRpcBlock): Buffer[] {
    const f = [hexToBuf(b.parentHash), hexToBuf(b.reward), hexToBuf(b.stateRoot), hexToBuf(b.transactionsRoot),
        hexToBuf(b.receiptsRoot), hexToBuf(b.logsBloom), hexToTrimmedBuf(b.blockScore), hexToTrimmedBuf(b.number),
        hexToTrimmedBuf(b.gasUsed), hexToTrimmedBuf(b.timestamp), hexToTrimmedBuf(b.timestampFoS),
        hexToBuf(b.extraData), hexToBuf(b.governanceData), hexToBuf(b.voteData)];
    if (b.baseFeePerGas !== undefined) f.push(hexToTrimmedBuf(b.baseFeePerGas));
    if (b.randomReveal !== undefined) f.push(hexToBuf(b.randomReveal), hexToBuf(b.mixHash));
    if (b.blobGasUsed !== undefined) f.push(hexToTrimmedBuf(b.blobGasUsed), hexToTrimmedBuf(b.excessBlobGas));
    if (b.vrank !== undefined) f.push(hexToBuf(b.vrank));
    return f;
}

export interface IstanbulExtra {
    vanity: Buffer;
    validators: Hex[];
    seal: Buffer;
    committedSeals: Buffer[];
}

export function parseExtra(b: KaiaRpcBlock): IstanbulExtra {
    const extra = hexToBuf(b.extraData);
    const [vals, seal, cs] = rlpDecode(extra.subarray(32)) as [Uint8Array[], Uint8Array, Uint8Array[]];
    return {
        vanity: Buffer.from(extra.subarray(0, 32)),
        validators: vals.map((v) => ("0x" + Buffer.from(v).toString("hex")) as Hex),
        seal: Buffer.from(seal),
        committedSeals: cs.map((s) => Buffer.from(s))
    };
}

/// Istanbul block hash: committed seals removed, round byte (vanity[31]) zeroed.
export function blockHash(b: KaiaRpcBlock): Hex {
    const e = parseExtra(b);
    const vanity = Buffer.from(e.vanity);
    vanity[31] = 0;
    const f = headerFields(b);
    f[11] = Buffer.concat([vanity, rlpEncode([e.validators.map(hexToBuf), e.seal, []])]);
    return keccak256(rlpEncode(f));
}

export function headerRlp(b: KaiaRpcBlock): Buffer {
    const h = blockHash(b);
    if (h !== b.hash) throw new Error(`Kaia header ${BigInt(b.number)} hashes to ${h}, RPC hash ${b.hash}`);
    return rlpEncode(headerFields(b));
}

export async function committers(b: KaiaRpcBlock): Promise<Hex[]> {
    const digest = keccak256(Buffer.concat([hexToBuf(b.hash), Buffer.from([2])]));
    const out: Hex[] = [];
    for (const s of parseExtra(b).committedSeals) {
        const sig = toHex(Buffer.concat([s.subarray(0, 64), Buffer.from([s[64] + 27])]));
        out.push((await recoverAddress({hash: digest, signature: sig})).toLowerCase() as Hex);
    }
    return out;
}

export const faultBound = (n: number) => Math.floor((n + 2) / 3) - 1;
export const quorum = (n: number) => 2 * faultBound(n) + 1;

export function validatorsBytes(v: Hex[]): Buffer {
    return Buffer.concat(v.map(hexToBuf));
}

export function encodeAnchor(codeHash: Hex, validators: Hex[], setBlock: bigint): Hex {
    const b = Buffer.alloc(74);
    hexToBuf(codeHash).copy(b, 0);
    hexToBuf(keccak256(validatorsBytes(validators))).copy(b, 32);
    b.writeBigUInt64BE(setBlock, 64);
    b.writeUInt16BE(validators.length, 72);
    return toHex(b);
}

export function encodeBundle(p: KaiaBundleParts, overrides: Partial<KaiaBundleParts> = {}): Hex {
    const q = {...p, ...overrides};
    return toHex(rlpEncode([q.validators, q.headers, q.accountProof, q.storageProof, q.bundleContent]));
}

// ── Build (offline) ─────────────────────────────────────────────────────────

function blk(c: KaiaCapture, n: string): KaiaRpcBlock {
    const b = c.blocks[n];
    if (!b) throw new Error(`capture is missing block ${n}`);
    return b;
}

async function checkQuorum(b: KaiaRpcBlock): Promise<number> {
    const set = new Set(parseExtra(b).validators.map((v) => v.toLowerCase()));
    const got = new Set((await committers(b)).filter((c) => set.has(c))).size;
    if (got < quorum(set.size)) throw new Error(`block ${BigInt(b.number)}: ${got} seals < quorum ${quorum(set.size)}`);
    return got;
}

export async function buildKaiaLiveProof(c: KaiaCapture): Promise<KaiaLiveProof> {
    const chainId = BigInt(c.chainId);
    const slots = channelSlots(c.channelId);
    const anchorHdr = blk(c, c.anchorBlock);
    await checkQuorum(anchorHdr);
    const anchorSet = parseExtra(anchorHdr).validators;
    const codeHash = c.proofs[c.recentBlock].codeHash;
    const configProof = toHex(rlpEncode([ledgerConfigPayload(chainId, c.account), rlpDecode(headerRlp(anchorHdr)) as Input, hexToBuf(codeHash)]));
    const trustAnchor = encodeAnchor(codeHash, anchorSet, BigInt(c.anchorBlock));

    let rotatedAnchor: Hex | undefined;
    let rotationProof: Hex | undefined;
    let rotationParts: KaiaBundleParts | undefined;
    let rotationVouch: number | undefined;
    let currentSet = anchorSet;
    let currentAnchor = trustAnchor;
    if (c.rotationBlock) {
        const r = blk(c, c.rotationBlock);
        await checkQuorum(r);
        const newSet = parseExtra(r).validators;
        const old = new Set(anchorSet.map((v) => v.toLowerCase()));
        rotationVouch = new Set((await committers(r)).filter((x) => old.has(x))).size;
        if (rotationVouch < faultBound(anchorSet.length) + 1) throw new Error("rotation header lacks f+1 old-set seals");
        const {accountProof, storageProof} = proofItems(c.proofs[c.rotationBlock], slots);
        rotationParts = {validators: validatorsBytes(anchorSet), headers: [rlpDecode(headerRlp(r)) as Input], accountProof, storageProof, bundleContent: Buffer.alloc(0)};
        rotationProof = encodeBundle(rotationParts);
        rotatedAnchor = encodeAnchor(codeHash, newSet, BigInt(c.rotationBlock));
        currentSet = newSet;
        currentAnchor = rotatedAnchor;
    }

    const recent = blk(c, c.recentBlock);
    const recentSeals = await checkQuorum(recent);
    if (keccak256(validatorsBytes(parseExtra(recent).validators)) !== keccak256(validatorsBytes(currentSet))) {
        throw new Error("recent header's set differs from the anchor set; re-capture");
    }
    const {accountProof, storageProof} = proofItems(c.proofs[c.recentBlock], slots);
    const plainParts: KaiaBundleParts = {
        validators: validatorsBytes(currentSet), headers: [rlpDecode(headerRlp(recent)) as Input], accountProof, storageProof, bundleContent: Buffer.alloc(0)
    };
    return {
        network: c.network,
        chainId,
        channelId: c.channelId,
        channelContext: encodeChannelContext(c.channelId, c.account),
        configProof,
        trustAnchor,
        rotatedAnchor,
        rotationProof,
        rotationParts,
        plainAnchor: currentAnchor,
        plainProof: encodeBundle(plainParts),
        plainParts,
        meta: {
            anchorBlock: BigInt(c.anchorBlock),
            rotationBlock: c.rotationBlock ? BigInt(c.rotationBlock) : undefined,
            recentBlock: BigInt(c.recentBlock),
            anchorSet: anchorSet.length,
            rotatedSet: rotatedAnchor ? currentSet.length : undefined,
            recentSeals,
            rotationVouch,
            codeHash
        }
    };
}

// ── Capture (live) ──────────────────────────────────────────────────────────

const KEEP: (keyof KaiaRpcBlock)[] = ["hash", "parentHash", "reward", "stateRoot", "transactionsRoot", "receiptsRoot",
    "logsBloom", "blockScore", "number", "gasUsed", "timestamp", "timestampFoS", "extraData", "governanceData",
    "voteData", "baseFeePerGas", "randomReveal", "mixHash", "blobGasUsed", "excessBlobGas", "vrank"];

function stripBlock(b: Record<string, unknown>): KaiaRpcBlock {
    const out: Record<string, unknown> = {};
    for (const k of KEEP) if (b[k] !== undefined) out[k] = b[k];
    return out as unknown as KaiaRpcBlock;
}

export async function captureKaiaLive(network: KaiaNetwork): Promise<KaiaCapture> {
    const net = NETWORKS[network];
    const rpc = <T>(m: string, p: unknown[]) => anyRpc<T>(net.rpcs, m, p);
    const chainId = BigInt(await rpc<Hex>("eth_chainId", []));
    if (chainId !== net.chainId) throw new Error(`${network}: chain id ${chainId}`);
    const blocks: Record<string, KaiaRpcBlock> = {};
    const get = async (n: bigint): Promise<KaiaRpcBlock> => {
        const key = String(n);
        if (!blocks[key]) blocks[key] = stripBlock(await rpc<Record<string, unknown>>("kaia_getBlockByNumber", [hexNum(n), false]));
        return blocks[key];
    };
    const setKey = async (n: bigint) => keccak256(validatorsBytes(parseExtra(await get(n)).validators));
    const channelId = liveChannelId("kaia-istanbul-verifier");
    const slots = channelSlots(channelId);
    const proofs: Record<string, RpcProof> = {};

    const latest = BigInt(await rpc<Hex>("eth_blockNumber", []));
    const recent = latest - 5n;
    await get(recent);
    proofs[String(recent)] = await rpc<RpcProof>("eth_getProof", [ADDRESS_BOOK, slots, hexNum(recent)]);
    const current = await setKey(recent);

    let anchorBlock: bigint;
    let rotationBlock: bigint | undefined;
    if (net.rotationSearch) {
        // Bisect for the newest set change in [recent − 2,000,000, recent].
        let lo = recent - 2_000_000n; // set differs here (checked below)
        let hi = recent; // set equals current here
        if ((await setKey(lo)) === current) throw new Error("no validator-set change in the search window");
        while (hi - lo > 1n) {
            const mid = (lo + hi) / 2n;
            if ((await setKey(mid)) === current) hi = mid;
            else lo = mid;
        }
        rotationBlock = hi;
        anchorBlock = hi - 1n;
        await get(anchorBlock);
        proofs[String(rotationBlock)] = await rpc<RpcProof>("eth_getProof", [ADDRESS_BOOK, slots, hexNum(rotationBlock)]);
        // Keep only the blocks the fixture uses.
        for (const k of Object.keys(blocks)) {
            if (![String(anchorBlock), String(rotationBlock), String(recent)].includes(k)) delete blocks[k];
        }
    } else {
        anchorBlock = recent - 10_000n;
        await get(anchorBlock);
        if ((await setKey(anchorBlock)) !== current) throw new Error("Kairos set changed in the last 10 000 blocks; extend the builder");
    }
    return {
        network, chainId: String(chainId), capturedAt: new Date().toISOString(), account: ADDRESS_BOOK, channelId,
        anchorBlock: String(anchorBlock), rotationBlock: rotationBlock !== undefined ? String(rotationBlock) : undefined,
        recentBlock: String(recent), blocks, proofs
    };
}

// ── Files ───────────────────────────────────────────────────────────────────

export function fixturePath(network: KaiaNetwork): string {
    return path.join(KAIA_LIVE_DIR, `${network}.json`);
}

export function vectorsPath(network: KaiaNetwork): string {
    return path.join(KAIA_LIVE_DIR, `${network}-vectors.json`);
}

export function loadKaiaCapture(network: KaiaNetwork): KaiaCapture {
    return JSON.parse(readFileSync(fixturePath(network), "utf8")) as KaiaCapture;
}

/// Flat hex vectors for the Foundry live-data test (test/verifiers/evm/kaia/KaiaIstanbulLive.t.sol).
export function writeVectors(p: KaiaLiveProof): void {
    const v = {
        chainId: Number(p.chainId),
        configProof: p.configProof,
        trustAnchor: p.trustAnchor,
        rotatedAnchor: p.rotatedAnchor ?? "0x",
        rotationProof: p.rotationProof ?? "0x",
        plainAnchor: p.plainAnchor,
        plainProof: p.plainProof,
        channelContext: p.channelContext,
        channelId: p.channelId,
        anchorBlock: Number(p.meta.anchorBlock),
        rotationBlock: Number(p.meta.rotationBlock ?? 0n),
        recentBlock: Number(p.meta.recentBlock)
    };
    writeFileSync(vectorsPath(p.network), JSON.stringify(v, null, 1) + "\n");
}

function summarize(p: KaiaLiveProof): string {
    const m = p.meta;
    const len = (h?: Hex) => (h ? (h.length - 2) / 2 : 0);
    return [
        `network      ${p.network} (chainId ${p.chainId})`,
        `anchor       block ${m.anchorBlock}, ${m.anchorSet} qualified validators`,
        m.rotationBlock !== undefined
            ? `rotation     block ${m.rotationBlock} → ${m.rotatedSet} validators, ${m.rotationVouch} old-set seals (need ${faultBound(m.anchorSet) + 1})`
            : "rotation     none in fixture",
        `recent       block ${m.recentBlock}, ${m.recentSeals} committed seals in set`,
        `proof bytes  rotation ${len(p.rotationProof)} B, plain ${len(p.plainProof)} B, config ${len(p.configProof)} B`
    ].join("\n");
}

async function main(): Promise<void> {
    const args = process.argv.slice(2);
    const nIdx = args.indexOf("--network");
    const networks = (nIdx >= 0 ? [args[nIdx + 1]] : Object.keys(NETWORKS)) as KaiaNetwork[];
    for (const network of networks) {
        let capture: KaiaCapture;
        if (args.includes("--refresh")) {
            capture = await captureKaiaLive(network);
            const built = await buildKaiaLiveProof(capture); // validate before overwriting
            mkdirSync(KAIA_LIVE_DIR, {recursive: true});
            writeFileSync(fixturePath(network), JSON.stringify(capture, null, 1) + "\n");
            writeVectors(built);
            console.log(`captured → ${path.relative(process.cwd(), fixturePath(network))}`);
        } else {
            capture = loadKaiaCapture(network);
            if (args.includes("--vectors")) writeVectors(await buildKaiaLiveProof(capture));
        }
        console.log(summarize(await buildKaiaLiveProof(capture)));
    }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    main().catch((err) => {
        console.error(err);
        process.exit(1);
    });
}
