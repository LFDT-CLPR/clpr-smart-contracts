import {bls12_381} from "@noble/curves/bls12-381";
import {mkdirSync, readFileSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {type Hex, encodeAbiParameters, keccak256, toHex} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {rlpEncode, hexToBuf, hexToTrimmedBuf, bigintToTrimmedBuf} from "../lib/rlp.js";
import {BLS_POP_DST, g2ToUncompressed} from "./bls.js";
import {deriveChannelSlots} from "./buildEthMainnetProof.js";

/// Live-data proof builder for `AvalancheWarpVerifier`, fed by the Avalanche Fuji C-Chain.
///
/// Every cryptographic input comes from the network:
///   - the C-Chain block header (`eth_getBlockByNumber`), re-encoded to RLP in coreth's
///     `HeaderSerializable` field order and checked against the block hash;
///   - the Primary Network validator set at a P-Chain height (`platform.getValidatorsAt`), flattened to
///     avalanchego's canonical Warp set (keys merged, sorted by uncompressed key), with the P-Chain
///     block timestamp at that height (`platform.getBlockByHeight`);
///   - a real Warp `BitSetSignature` over `payload.Hash(blockHash)`, aggregated by the validators via
///     ACP-118 (public signature-aggregator API, pinned to that P-Chain height);
///   - an earlier P-Chain height whose set differs, for a real validator-set rotation;
///   - `eth_getProof` for a real Fuji contract at the block whose post-state the header commits to
///     (ACP-194 SAE: `header.settledHeight`, a few blocks back). No ClprService exists on Fuji, so
///     the channelId-derived slots are absent there and the storage proofs are MPT exclusion proofs.
///
/// The ONE non-chain input is the rotation attestation: the verifier trusts K-of-N attestors for the
/// P-Chain set (no chain proof exists, see the README). The fixture signs it with deterministic test
/// keys (anvil accounts 0–2, threshold 2).
///
/// Two phases, so tests are deterministic offline:
///   `captureFujiLive()` → raw API responses (`capture.json`)
///   `buildAvalancheLiveProof(capture)` → verifier wire format, pure/offline, every step cross-checked;
///   `--vectors` additionally writes `vectors.json` for the Foundry live test.
///
/// CLI:
///   npx tsx test/e2e/relay/buildAvalancheLiveProof.ts             build from the fixture, print a summary
///   npx tsx test/e2e/relay/buildAvalancheLiveProof.ts --refresh   re-capture from Fuji, then write vectors
///   npx tsx test/e2e/relay/buildAvalancheLiveProof.ts --vectors   rebuild vectors.json from capture.json

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const AVALANCHE_LIVE_DIR = path.resolve(__dirname, "../fixtures/avalanche-live");
export const AVALANCHE_LIVE_FIXTURE = path.join(AVALANCHE_LIVE_DIR, "capture.json");
export const AVALANCHE_LIVE_VECTORS = path.join(AVALANCHE_LIVE_DIR, "vectors.json");

/// One Warp network the live builder can capture from.
export interface NetworkSpec {
    network: string;
    networkId: number;
    evmChainId: number;
    cChainCb58: string;
    primaryNetwork: string;
    cRpc: string;
    proofRpcs: string[];
    pApi: string;
    /// ACP-118 signature aggregator endpoint.
    aggregator: string;
    /// "glacier": Ava Labs' hosted API (`{message, pChainHeight}`). "local": a self-run
    /// ava-labs/icm-services signature-aggregator (`{message, "pchain-height"}`).
    aggregatorApi: "glacier" | "local";
    /// Long-lived contract whose account/storage proofs stand in for a ClprService.
    account: Hex;
    channelId: Hex;
    maxSetAge: bigint;
    fixtureDir: string;
}

export const FUJI = {
    network: "fuji",
    networkId: 5,
    evmChainId: 43113,
    cChainCb58: "yH8D7ThNJkxmtkuv2jgBa4P1Rn3Qpr4pPr7QYNfcdoS6k6HWp",
    primaryNetwork: "11111111111111111111111111111111LpoYY",
    cRpc: "https://api.avax-test.network/ext/bc/C/rpc",
    // The Ava Labs endpoint does not serve eth_getProof; these do.
    proofRpcs: [
        "https://avalanche-fuji-c-chain-rpc.publicnode.com",
        "https://avalanche-fuji.gateway.tenderly.co",
        "https://avalanche-fuji.drpc.org"
    ],
    // The Ava Labs endpoint rejects numeric heights for platform.getValidatorsAt.
    pApi: "https://avalanche-fuji-p-chain-rpc.publicnode.com",
    aggregator: "https://glacier-api.avax.network/v1/signatureAggregator/fuji/aggregateSignatures",
    aggregatorApi: "glacier" as const
};
/// WAVAX on Fuji: a long-lived contract with code and a populated storage trie.
export const DEFAULT_ACCOUNT: Hex = "0xd00ae08403B9bbb9124bB305C09058E32C39A48c";
export const LIVE_CHANNEL_ID: Hex = keccak256(toHex("clpr/avalanche-warp/fuji"));
/// Fuji MinStakeDuration after Helicon is 12 h; a set is accepted for at most that long.
export const LIVE_MAX_SET_AGE = 12n * 3600n;
/// Rotation attestors: anvil accounts 0..2 (test-only keys), threshold 2.
export const ATTESTOR_KEYS: Hex[] = [
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9e0e17b1d7365"
];
export const ATTESTOR_THRESHOLD = 2n;

/// Flare networks (go-flare, avalanchego v1.14 fork). No public aggregator serves them, so the capture
/// talks to our own ava-labs/icm-services signature-aggregator, which dials the validators over p2p
/// (see src/verifiers/evm/avalanche/README.md, "Flare live test"). `FLARE_AGGREGATOR` overrides the URL.
/// MinStakeDuration on both is 60 days (go-flare `inflation_settings.go`, Granite); the fixtures use a
/// 7-day window because Coston2's P-Chain can go hours without a block.
const FLARE_LIVE_DIR = path.resolve(__dirname, "../fixtures/flare-live");
export const NETWORKS: Record<string, NetworkSpec> = {
    fuji: {...FUJI, account: DEFAULT_ACCOUNT, channelId: LIVE_CHANNEL_ID, maxSetAge: LIVE_MAX_SET_AGE,
        fixtureDir: AVALANCHE_LIVE_DIR},
    coston2: {
        network: "coston2",
        networkId: 114,
        evmChainId: 114,
        cChainCb58: "vE8M98mEQH6wk56sStD1ML8HApTgSqfJZLk9gQ3Fsd4i6m3Bi",
        primaryNetwork: "11111111111111111111111111111111LpoYY",
        cRpc: "https://coston2-api.flare.network/ext/bc/C/rpc",
        proofRpcs: ["https://coston2-api.flare.network/ext/bc/C/rpc"],
        pApi: "https://coston2-api.flare.network/ext/bc/P",
        aggregator: process.env.FLARE_AGGREGATOR ?? "http://127.0.0.1:18480/aggregate-signatures",
        aggregatorApi: "local",
        // WC2FLR (wrapped native token) on Coston2.
        account: "0xC67DCE33D7A8efA5FfEB961899C73fe01bCe9273",
        channelId: keccak256(toHex("clpr/avalanche-warp/coston2")),
        maxSetAge: 7n * 24n * 3600n,
        fixtureDir: path.join(FLARE_LIVE_DIR, "coston2")
    },
    flare: {
        network: "flare",
        networkId: 14,
        evmChainId: 14,
        cChainCb58: "umkbhSrjVw5nUvy1eo25AdrjRkPBdtzAMewuxA2rqEx4YMo4c",
        primaryNetwork: "11111111111111111111111111111111LpoYY",
        cRpc: "https://flare-api.flare.network/ext/bc/C/rpc",
        proofRpcs: ["https://flare-api.flare.network/ext/bc/C/rpc"],
        pApi: "https://flare-api.flare.network/ext/bc/P",
        aggregator: process.env.FLARE_AGGREGATOR ?? "http://127.0.0.1:18483/aggregate-signatures",
        aggregatorApi: "local",
        // WFLR (wrapped native token) on Flare.
        account: "0x1D80c49BbBCd1C0911346656B529DF9E5c2F783d",
        channelId: keccak256(toHex("clpr/avalanche-warp/flare")),
        maxSetAge: 7n * 24n * 3600n,
        fixtureDir: path.join(FLARE_LIVE_DIR, "flare")
    }
};

const ENTRY_LENGTH = 104;
const VALIDATOR_SET_TYPEHASH = keccak256(toHex(
    "ClprAvalancheValidatorSet(uint32 networkId,bytes32 sourceChainId,uint64 pChainHeight,uint64 pChainTimestamp,bytes32 setHash,uint256 totalWeight)"
));

// ── Raw capture shapes ─────────────────────────────────────────────────────
export type BlockJson = Record<string, string>;
export type ValidatorsAtJson = Record<string, {publicKey?: string | null; weight: string}>;
export interface PChainSetCapture {
    height: number;
    timestamp: number;
    validators: ValidatorsAtJson;
}
export interface GetProofJson {
    address: string;
    accountProof: string[];
    codeHash: string;
    storageHash: string;
    storageProof: {key: string; value: string; proof: string[]}[];
}
export interface LiveCapture {
    network: string;
    capturedAt: string;
    sources: Record<string, string>;
    networkId: number;
    evmChainId: number;
    sourceChainIdCb58: string;
    block: BlockJson;
    set: PChainSetCapture;
    previousSet: PChainSetCapture;
    aggregate: {pChainHeight: number; unsignedMessage: Hex; signedMessage: Hex};
    account: {address: Hex; blockNumber: string; proof: GetProofJson};
    channelId: Hex;
    /// Set-age window for the anchors (absent in older Fuji captures: 12 h).
    maxSetAge?: string;
}

// ── Avalanche encodings ────────────────────────────────────────────────────
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// cb58 → 32-byte id (base58, last 4 bytes are a sha256 checksum, dropped here).
export function cb58ToId(s: string): Buffer {
    let n = 0n;
    for (const c of s) n = n * 58n + BigInt(B58.indexOf(c));
    const b = Buffer.from(n.toString(16).padStart(72, "0"), "hex");
    return b.subarray(0, 32);
}

/// `UnsignedMessage{networkID, sourceChainID, payload.Hash(blockHash)}`, linear codec v0 (80 bytes).
export function blockHashMessage(networkId: number, sourceChainId: Buffer, blockHash: Buffer): Buffer {
    const payload = Buffer.concat([Buffer.from([0, 0]), u32(0), blockHash]);
    return Buffer.concat([Buffer.from([0, 0]), u32(networkId), sourceChainId, u32(payload.length), payload]);
}

function u32(n: number): Buffer {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n);
    return b;
}

function u64(n: bigint): Buffer {
    const b = Buffer.alloc(8);
    b.writeBigUInt64BE(n);
    return b;
}

function u256(n: bigint): Buffer {
    return Buffer.from(n.toString(16).padStart(64, "0"), "hex");
}

function hex(b: Buffer | Uint8Array): Hex {
    return ("0x" + Buffer.from(b).toString("hex")) as Hex;
}

/// Coreth `HeaderSerializable` RLP field order (graft/coreth/plugin/evm/customtypes). Fields after
/// `extDataHash` are `rlp:"optional"`: emitted up to the last present one.
const HEADER_FIELDS: {key: string; kind: "hash" | "addr" | "bytes" | "int" | "nonce" | "bloom"}[] = [
    {key: "parentHash", kind: "hash"},
    {key: "sha3Uncles", kind: "hash"},
    {key: "miner", kind: "addr"},
    {key: "stateRoot", kind: "hash"},
    {key: "transactionsRoot", kind: "hash"},
    {key: "receiptsRoot", kind: "hash"},
    {key: "logsBloom", kind: "bloom"},
    {key: "difficulty", kind: "int"},
    {key: "number", kind: "int"},
    {key: "gasLimit", kind: "int"},
    {key: "gasUsed", kind: "int"},
    {key: "timestamp", kind: "int"},
    {key: "extraData", kind: "bytes"},
    {key: "mixHash", kind: "hash"},
    {key: "nonce", kind: "nonce"},
    {key: "extDataHash", kind: "hash"},
    {key: "baseFeePerGas", kind: "int"},
    {key: "extDataGasUsed", kind: "int"},
    {key: "blockGasCost", kind: "int"},
    {key: "blobGasUsed", kind: "int"},
    {key: "excessBlobGas", kind: "int"},
    {key: "parentBeaconBlockRoot", kind: "hash"},
    {key: "timestampMilliseconds", kind: "int"},
    {key: "minDelayExcess", kind: "int"},
    {key: "targetExponent", kind: "int"},
    {key: "minPriceExponent", kind: "int"},
    {key: "settledHeight", kind: "int"},
    {key: "settledGasUnix", kind: "int"},
    {key: "settledGasNumerator", kind: "int"},
    {key: "settledExcess", kind: "int"}
];
const FIRST_OPTIONAL = 16;

export function encodeCorethHeader(b: BlockJson): Buffer {
    let last = FIRST_OPTIONAL - 1;
    HEADER_FIELDS.forEach((f, i) => {
        if (b[f.key] !== undefined && b[f.key] !== null) last = Math.max(last, i);
    });
    const items = HEADER_FIELDS.slice(0, last + 1).map((f) => {
        const v = b[f.key];
        if (v === undefined || v === null) return Buffer.alloc(0);
        return f.kind === "int" ? hexToTrimmedBuf(v) : hexToBuf(v);
    });
    return rlpEncode(items);
}

// ── Canonical Warp validator set ───────────────────────────────────────────
export interface CanonicalSet {
    /// n × (x48 ‖ y48 ‖ weight8), canonical order.
    packed: Buffer;
    keys: InstanceType<typeof bls12_381.G1.ProjectivePoint>[];
    weights: bigint[];
    totalWeight: bigint;
    nodeCount: number;
}

/// avalanchego `FlattenValidatorSet`: drop keyless validators (their weight still counts in the total),
/// merge validators sharing a key, sort by the 96-byte uncompressed key.
export function canonicalSet(v: ValidatorsAtJson): CanonicalSet {
    const byKey = new Map<string, {raw: Buffer; pt: InstanceType<typeof bls12_381.G1.ProjectivePoint>; w: bigint}>();
    let totalWeight = 0n;
    for (const val of Object.values(v)) {
        const w = BigInt(val.weight);
        totalWeight += w;
        if (!val.publicKey) continue;
        const pt = bls12_381.G1.ProjectivePoint.fromHex(val.publicKey.replace(/^0x/, ""));
        const raw = Buffer.from(pt.toRawBytes(false));
        const k = raw.toString("hex");
        const e = byKey.get(k);
        if (e) e.w += w;
        else byKey.set(k, {raw, pt, w});
    }
    const sorted = [...byKey.values()].sort((a, b) => Buffer.compare(a.raw, b.raw));
    return {
        packed: Buffer.concat(sorted.map((e) => Buffer.concat([e.raw, u64(e.w)]))),
        keys: sorted.map((e) => e.pt),
        weights: sorted.map((e) => e.w),
        totalWeight,
        nodeCount: Object.keys(v).length
    };
}

export interface ParsedSignedMessage {
    unsigned: Buffer;
    signers: Buffer;
    signatureCompressed: Buffer;
}

/// Split a serialized Warp `Message{UnsignedMessage, BitSetSignature}` (type id 0).
export function parseSignedMessage(signed: Buffer, unsignedLength: number): ParsedSignedMessage {
    const r = signed.subarray(unsignedLength);
    if (r.readUInt32BE(0) !== 0) throw new Error("not a BitSetSignature");
    const n = r.readUInt32BE(4);
    const signers = r.subarray(8, 8 + n);
    const sig = r.subarray(8 + n);
    if (sig.length !== 96) throw new Error(`signature length ${sig.length}`);
    return {unsigned: signed.subarray(0, unsignedLength), signers, signatureCompressed: sig};
}

export function signerIndices(signers: Buffer): number[] {
    const big = signers.length === 0 ? 0n : BigInt("0x" + signers.toString("hex"));
    const out: number[] = [];
    for (let i = 0; (big >> BigInt(i)) > 0n; i++) if ((big >> BigInt(i)) & 1n) out.push(i);
    return out;
}

function verifyOffchain(set: CanonicalSet, signers: Buffer, sigCompressed: Buffer, msg: Buffer): {weight: bigint} {
    let agg = bls12_381.G1.ProjectivePoint.ZERO;
    let weight = 0n;
    for (const i of signerIndices(signers)) {
        if (i >= set.keys.length) throw new Error(`signer index ${i} ≥ n`);
        agg = agg.add(set.keys[i]);
        weight += set.weights[i];
    }
    const H = bls12_381.G2.hashToCurve(msg, {DST: BLS_POP_DST}) as unknown as InstanceType<typeof bls12_381.G2.ProjectivePoint>;
    const sig = bls12_381.G2.ProjectivePoint.fromHex(sigCompressed.toString("hex"));
    const Fp12 = bls12_381.fields.Fp12;
    if (!Fp12.eql(bls12_381.pairing(agg, H), bls12_381.pairing(bls12_381.G1.ProjectivePoint.BASE, sig))) {
        throw new Error("Warp aggregate signature does not verify off-chain");
    }
    if (67n * set.totalWeight > 100n * weight) throw new Error("signed weight below 67%");
    return {weight};
}

export function encodeTrustAnchor(a: {
    networkId: number;
    sourceChainId: Buffer;
    channelId: Hex;
    codeHash: Hex;
    setHash: Hex;
    totalWeight: bigint;
    pChainHeight: bigint;
    pChainTimestamp: bigint;
    maxSetAge: bigint;
    attestorsHash: Hex;
}): Hex {
    return hex(Buffer.concat([
        u32(a.networkId), a.sourceChainId, hexToBuf(a.channelId), hexToBuf(a.codeHash), hexToBuf(a.setHash),
        u256(a.totalWeight), u64(a.pChainHeight), u64(a.pChainTimestamp), u64(a.maxSetAge), hexToBuf(a.attestorsHash)
    ]));
}

export function attestors(): {addresses: Hex[]; keys: Hex[]} {
    const pairs = ATTESTOR_KEYS.map((k) => ({k, a: privateKeyToAccount(k).address}));
    pairs.sort((x, y) => (BigInt(x.a) < BigInt(y.a) ? -1 : 1));
    return {addresses: pairs.map((p) => p.a), keys: pairs.map((p) => p.k)};
}

export function attestorsHash(threshold: bigint, addrs: Hex[]): Hex {
    return keccak256(encodeAbiParameters([{type: "uint256"}, {type: "address[]"}], [threshold, addrs]));
}

export function validatorSetDigest(networkId: number, sourceChainId: Buffer, height: bigint, ts: bigint, setHash: Hex,
    totalWeight: bigint): Hex {
    return keccak256(encodeAbiParameters(
        [{type: "bytes32"}, {type: "uint32"}, {type: "bytes32"}, {type: "uint64"}, {type: "uint64"}, {type: "bytes32"},
            {type: "uint256"}],
        [VALIDATOR_SET_TYPEHASH, networkId, hex(sourceChainId), height, ts, setHash, totalWeight]
    ));
}

/// EIP-191 signatures over the digest by the first `count` attestors (ascending address order).
export async function attest(digest: Hex, count: number): Promise<Buffer[]> {
    const {keys} = attestors();
    const out: Buffer[] = [];
    for (const k of keys.slice(0, count)) {
        out.push(hexToBuf(await privateKeyToAccount(k).signMessage({message: {raw: digest}})));
    }
    return out;
}

// ── Build ──────────────────────────────────────────────────────────────────
export interface AvalancheLiveProof {
    meta: {
        network: string;
        blockNumber: bigint;
        blockHash: Hex;
        blockTime: bigint;
        pChainHeight: number;
        previousPChainHeight: number;
        validators: number;
        previousValidators: number;
        signers: number;
        signedWeightBps: number;
        accountProofNodes: number;
    };
    channelId: Hex;
    codeHash: Hex;
    sourceChainId: Hex;
    networkId: number;
    channelContext: Hex;
    /// Anchor at the signing P-Chain height (no rotation needed).
    trustAnchor: Hex;
    /// Anchor at the earlier P-Chain height; the rotation bundle advances it to `trustAnchor`.
    previousTrustAnchor: Hex;
    proofBytes: Hex;
    rotationProofBytes: Hex;
    parts: {
        header: Buffer;
        warpSignature: [Buffer, Buffer];
        validatorSet: Buffer;
        previousValidatorSet: Buffer;
        rotation: (Buffer | Buffer[])[];
        accountProof: Buffer[];
        storageProof: (Buffer | Buffer[])[][];
        bundleContent: Buffer;
    };
    maxSetAge: bigint;
    set: {totalWeight: bigint; height: bigint; timestamp: bigint; setHash: Hex};
    previousSet: {totalWeight: bigint; height: bigint; timestamp: bigint; setHash: Hex};
    attestors: Hex[];
}

export async function buildAvalancheLiveProof(c: LiveCapture): Promise<AvalancheLiveProof> {
    const sourceChainId = cb58ToId(c.sourceChainIdCb58);

    // Header → hash, re-derived exactly as coreth hashes it.
    const header = encodeCorethHeader(c.block);
    const blockHash = keccak256(header);
    if (blockHash !== c.block.hash) throw new Error(`header RLP hash ${blockHash} != block hash ${c.block.hash}`);

    // The Warp message the validators signed is the one we rebuild from (networkId, chain, hash).
    const msg = blockHashMessage(c.networkId, sourceChainId, hexToBuf(blockHash));
    if (hex(msg) !== c.aggregate.unsignedMessage) throw new Error("rebuilt UnsignedMessage != requested message");
    const signed = parseSignedMessage(hexToBuf(c.aggregate.signedMessage), msg.length);
    if (!signed.unsigned.equals(msg)) throw new Error("signed message carries a different UnsignedMessage");
    if (c.aggregate.pChainHeight !== c.set.height) throw new Error("aggregate pinned to another P-Chain height");

    const set = canonicalSet(c.set.validators);
    const prev = canonicalSet(c.previousSet.validators);
    if (set.packed.equals(prev.packed) && set.totalWeight === prev.totalWeight) {
        throw new Error("previous set equals the signing set — no real rotation captured");
    }
    const {weight} = verifyOffchain(set, signed.signers, signed.signatureCompressed, msg);
    const sigUncompressed = g2ToUncompressed(bls12_381.G2.ProjectivePoint.fromHex(signed.signatureCompressed.toString("hex")));

    const blockTime = BigInt(c.block.timestamp);
    if (BigInt(c.set.timestamp) > blockTime) throw new Error("P-Chain set timestamp is after the block");

    // MPT account + storage (exclusion) proofs at the same block.
    const stateBlock = BigInt(c.block.settledHeight ?? c.block.number);
    if (BigInt(c.account.blockNumber) !== stateBlock) throw new Error("getProof not at the header's state block");
    if (keccak256(hexToBuf(c.account.proof.accountProof[0])) !== c.block.stateRoot) {
        throw new Error("account proof root != header stateRoot");
    }
    const slots = deriveChannelSlots(c.channelId);
    const byKey = new Map(c.account.proof.storageProof.map((sp) => [BigInt(sp.key), sp]));
    const storageProof = slots.map((k) => {
        const sp = byKey.get(BigInt(k));
        if (!sp) throw new Error(`capture missing storage proof for slot ${k}`);
        return [hexToBuf(k), sp.proof.map(hexToBuf)];
    });
    const accountProof = c.account.proof.accountProof.map(hexToBuf);
    const codeHash = c.account.proof.codeHash as Hex;

    const att = attestors();
    const aHash = attestorsHash(ATTESTOR_THRESHOLD, att.addresses);
    const setHash = keccak256(set.packed);
    const prevHash = keccak256(prev.packed);
    const maxSetAge = BigInt(c.maxSetAge ?? LIVE_MAX_SET_AGE);
    const base = {networkId: c.networkId, sourceChainId, channelId: c.channelId, codeHash,
        maxSetAge, attestorsHash: aHash};
    const trustAnchor = encodeTrustAnchor({...base, setHash, totalWeight: set.totalWeight,
        pChainHeight: BigInt(c.set.height), pChainTimestamp: BigInt(c.set.timestamp)});
    const previousTrustAnchor = encodeTrustAnchor({...base, setHash: prevHash, totalWeight: prev.totalWeight,
        pChainHeight: BigInt(c.previousSet.height), pChainTimestamp: BigInt(c.previousSet.timestamp)});

    const digest = validatorSetDigest(c.networkId, sourceChainId, BigInt(c.set.height), BigInt(c.set.timestamp),
        setHash, set.totalWeight);
    const sigs = await attest(digest, Number(ATTESTOR_THRESHOLD));
    const rotation = [
        bigintToTrimmedBuf(BigInt(c.set.height)),
        bigintToTrimmedBuf(BigInt(c.set.timestamp)),
        bigintToTrimmedBuf(set.totalWeight),
        bigintToTrimmedBuf(ATTESTOR_THRESHOLD),
        att.addresses.map(hexToBuf),
        sigs
    ] as (Buffer | Buffer[])[];

    const warpSignature: [Buffer, Buffer] = [signed.signers, sigUncompressed];
    const bundleContent = Buffer.alloc(0);
    const items = (rot: unknown) => [header, warpSignature, set.packed, rot, accountProof, storageProof, bundleContent];
    const proofBytes = hex(rlpEncode(items(Buffer.alloc(0)) as never));
    const rotationProofBytes = hex(rlpEncode(items(rotation) as never));

    // ClprTypes.encodeChannelContext: abi.encodePacked(channelId, remoteServiceAddress).
    const channelContext = hex(Buffer.concat([hexToBuf(c.channelId), hexToBuf(c.account.address)]));

    return {
        meta: {
            network: c.network,
            blockNumber: BigInt(c.block.number),
            blockHash,
            blockTime,
            pChainHeight: c.set.height,
            previousPChainHeight: c.previousSet.height,
            validators: set.keys.length,
            previousValidators: prev.keys.length,
            signers: signerIndices(signed.signers).length,
            signedWeightBps: Number((weight * 10000n) / set.totalWeight),
            accountProofNodes: accountProof.length
        },
        channelId: c.channelId,
        codeHash,
        sourceChainId: hex(sourceChainId),
        networkId: c.networkId,
        channelContext,
        trustAnchor,
        previousTrustAnchor,
        proofBytes,
        rotationProofBytes,
        parts: {header, warpSignature, validatorSet: set.packed, previousValidatorSet: prev.packed, rotation,
            accountProof, storageProof, bundleContent},
        maxSetAge,
        set: {totalWeight: set.totalWeight, height: BigInt(c.set.height), timestamp: BigInt(c.set.timestamp), setHash},
        previousSet: {totalWeight: prev.totalWeight, height: BigInt(c.previousSet.height),
            timestamp: BigInt(c.previousSet.timestamp), setHash: prevHash},
        attestors: att.addresses
    };
}

/// Re-encode a bundle with some parts replaced (negative tests).
export function reencodeBundle(p: AvalancheLiveProof["parts"], o: Partial<AvalancheLiveProof["parts"]> & {
    rotationItem?: unknown;
}): Hex {
    const q = {...p, ...o};
    const rot = o.rotationItem === undefined ? Buffer.alloc(0) : o.rotationItem;
    return hex(rlpEncode([q.header, q.warpSignature, q.validatorSet, rot, q.accountProof, q.storageProof,
        q.bundleContent] as never));
}

// ── Live capture ───────────────────────────────────────────────────────────
let rpcId = 0;
async function jsonRpc<T>(url: string, method: string, params: unknown): Promise<T> {
    for (let attempt = 0; ; attempt++) {
        try {
            const res = await fetch(url, {
                method: "POST",
                headers: {"content-type": "application/json"},
                body: JSON.stringify({jsonrpc: "2.0", id: ++rpcId, method, params})
            });
            const j = (await res.json()) as {result?: T; error?: {message: string}};
            if (j.error) throw new Error(`${method}: ${j.error.message}`);
            return j.result as T;
        } catch (err) {
            if (attempt >= 3) throw err;
            await new Promise((r) => setTimeout(r, 1000 * (attempt + 1)));
        }
    }
}

async function validatorsAt(net: NetworkSpec, height: number): Promise<ValidatorsAtJson> {
    return jsonRpc(net.pApi, "platform.getValidatorsAt", {height: String(height), subnetID: net.primaryNetwork});
}

async function pChainTime(net: NetworkSpec, height: number): Promise<number> {
    const r = await jsonRpc<{block: {time?: number}}>(net.pApi, "platform.getBlockByHeight",
        {height: String(height), encoding: "json"});
    if (r.block.time === undefined) throw new Error(`P-Chain block ${height} has no timestamp (pre-Banff?)`);
    return r.block.time;
}

function setKey(v: ValidatorsAtJson): string {
    const s = canonicalSet(v);
    return keccak256(Buffer.concat([s.packed, u256(s.totalWeight)]));
}

/// Most recent P-Chain height below `top` whose validator set differs from the set at `top`.
async function previousDifferentSet(net: NetworkSpec, top: number, topKey: string): Promise<number> {
    let step = 16;
    let hi = top; // same set as top
    let lo = -1; // differs
    while (lo < 0) {
        const h = Math.max(0, top - step);
        if (setKey(await validatorsAt(net, h)) !== topKey) lo = h;
        else hi = h;
        if (h === 0 && lo < 0) throw new Error("no earlier set change found");
        step *= 2;
    }
    while (hi - lo > 1) {
        const mid = Math.floor((lo + hi) / 2);
        if (setKey(await validatorsAt(net, mid)) !== topKey) lo = mid;
        else hi = mid;
    }
    return lo;
}

export async function captureFujiLive(opts: {account?: Hex} = {}): Promise<LiveCapture> {
    return captureLive(NETWORKS.fuji, opts);
}

export async function captureLive(net: NetworkSpec, opts: {account?: Hex} = {}): Promise<LiveCapture> {
    const account = opts.account ?? net.account;
    const sourceChainId = cb58ToId(net.cChainCb58);

    // The newest accepted block (Avalanche's "latest" is last-accepted, i.e. final). Public nodes keep
    // only a few recent states, so fetch the proof immediately and retry with a fresh block if the
    // state was already pruned.
    let block: BlockJson | undefined;
    let proof: GetProofJson | undefined;
    let proofRpc = "";
    let stateBlock = "";
    const slots = deriveChannelSlots(net.channelId);
    for (let attempt = 0; attempt < 8 && !proof; attempt++) {
        if (attempt > 0) await new Promise((r) => setTimeout(r, 1500));
        block = await jsonRpc<BlockJson>(net.cRpc, "eth_getBlockByNumber", ["latest", false]);
        delete (block as Record<string, unknown>).transactions;
        // Under ACP-194 (SAE, live on Fuji) a header's stateRoot is the post-execution root of the last
        // SETTLED block (`settledHeight`), not of the block itself; pre-SAE it is the block's own root.
        stateBlock = block.settledHeight ?? block.number;
        for (const url of net.proofRpcs) {
            try {
                const p = await jsonRpc<GetProofJson>(url, "eth_getProof", [account, slots, stateBlock]);
                if (keccak256(p.accountProof[0] as Hex) !== block.stateRoot) {
                    throw new Error(`proof root != header stateRoot (block ${block.number}, state block ${stateBlock})`);
                }
                proof = p;
                proofRpc = url;
                break;
            } catch (err) {
                console.warn(`[avalanche-live] eth_getProof on ${url}: ${String(err).slice(0, 160)}`);
            }
        }
    }
    if (!proof || !block) throw new Error("eth_getProof failed on every RPC");

    // Signing set: the newest P-Chain height whose timestamp is not after the block.
    let height = Number((await jsonRpc<{height: string}>(net.pApi, "platform.getHeight", {})).height);
    let timestamp = await pChainTime(net, height);
    while (timestamp > Number(BigInt(block.timestamp))) timestamp = await pChainTime(net, --height);
    const validators = await validatorsAt(net, height);

    const prevHeight = await previousDifferentSet(net, height, setKey(validators));
    const previousSet = {height: prevHeight, timestamp: await pChainTime(net, prevHeight),
        validators: await validatorsAt(net, prevHeight)};

    const msg = blockHashMessage(net.networkId, sourceChainId, hexToBuf(block.hash));
    let signedMessage: Hex | undefined;
    for (let attempt = 0; attempt < 5 && !signedMessage; attempt++) {
        const body = net.aggregatorApi === "glacier"
            ? {message: msg.toString("hex"), pChainHeight: height}
            : {message: msg.toString("hex"), "pchain-height": height};
        const res = await fetch(net.aggregator, {
            method: "POST",
            headers: {"content-type": "application/json"},
            body: JSON.stringify(body)
        });
        const j = (await res.json()) as {signedMessage?: string; "signed-message"?: string; message?: unknown};
        const sm = j.signedMessage ?? j["signed-message"];
        if (sm) signedMessage = ("0x" + sm.replace(/^0x/, "")) as Hex;
        else {
            console.warn(`[avalanche-live] aggregator: ${JSON.stringify(j).slice(0, 200)}`);
            await new Promise((r) => setTimeout(r, 3000));
        }
    }
    if (!signedMessage) throw new Error("signature aggregation failed");

    return {
        network: net.network,
        capturedAt: new Date().toISOString(),
        sources: {cRpc: net.cRpc, proofRpc, pApi: net.pApi, aggregator: net.aggregator},
        networkId: net.networkId,
        evmChainId: net.evmChainId,
        sourceChainIdCb58: net.cChainCb58,
        block,
        set: {height, timestamp, validators},
        previousSet,
        aggregate: {pChainHeight: height, unsignedMessage: hex(msg), signedMessage},
        account: {address: account, blockNumber: stateBlock, proof},
        channelId: net.channelId,
        ...(net.maxSetAge === LIVE_MAX_SET_AGE ? {} : {maxSetAge: net.maxSetAge.toString()})
    };
}

export function loadLiveCapture(file = AVALANCHE_LIVE_FIXTURE): LiveCapture {
    return JSON.parse(readFileSync(file, "utf8")) as LiveCapture;
}

/// Flat hex vectors for `test/verifiers/evm/avalanche/AvalancheWarpLive.t.sol`.
export function writeVectors(p: AvalancheLiveProof, c: LiveCapture, file = AVALANCHE_LIVE_VECTORS): void {
    const v = {
        network: p.meta.network,
        blockNumber: p.meta.blockNumber.toString(),
        blockHash: p.meta.blockHash,
        blockTime: p.meta.blockTime.toString(),
        networkId: p.networkId,
        evmChainId: c.evmChainId,
        sourceChainId: p.sourceChainId,
        channelId: p.channelId,
        codeHash: p.codeHash,
        serviceAddress: c.account.address.toLowerCase(),
        channelContext: p.channelContext,
        trustAnchor: p.trustAnchor,
        previousTrustAnchor: p.previousTrustAnchor,
        proofBytes: p.proofBytes,
        rotationProofBytes: p.rotationProofBytes,
        validatorSet: hex(p.parts.validatorSet),
        previousValidatorSet: hex(p.parts.previousValidatorSet),
        totalWeight: p.set.totalWeight.toString(),
        previousTotalWeight: p.previousSet.totalWeight.toString(),
        pChainHeight: p.set.height.toString(),
        pChainTimestamp: p.set.timestamp.toString(),
        previousPChainHeight: p.previousSet.height.toString(),
        previousPChainTimestamp: p.previousSet.timestamp.toString(),
        maxSetAge: p.maxSetAge.toString(),
        attestorThreshold: ATTESTOR_THRESHOLD.toString(),
        attestors: p.attestors,
        signers: hex(p.parts.warpSignature[0]),
        signature: hex(p.parts.warpSignature[1]),
        header: hex(p.parts.header)
    };
    writeFileSync(file, JSON.stringify(v, null, 2) + "\n");
}

function summarize(p: AvalancheLiveProof): string {
    const m = p.meta;
    return [
        `[avalanche-live] ${m.network} C-Chain block ${m.blockNumber} (${m.blockHash})`,
        `  P-Chain set @${m.pChainHeight}: ${m.validators} keys, ${m.signers} signers, ${m.signedWeightBps / 100}% of stake`,
        `  rotation from P-Chain @${m.previousPChainHeight} (${m.previousValidators} keys)`,
        `  proofBytes ${(p.proofBytes.length - 2) / 2} B, rotation bundle ${(p.rotationProofBytes.length - 2) / 2} B, ` +
        `account MPT nodes ${m.accountProofNodes}`
    ].join("\n");
}

async function main(): Promise<void> {
    const args = process.argv.slice(2);
    const ni = args.indexOf("--network");
    const net = NETWORKS[ni >= 0 ? args[ni + 1] : "fuji"];
    if (!net) throw new Error(`unknown --network; one of ${Object.keys(NETWORKS).join(", ")}`);
    const fixture = path.join(net.fixtureDir, "capture.json");
    const vectors = path.join(net.fixtureDir, "vectors.json");
    let capture: LiveCapture;
    if (args.includes("--refresh")) {
        capture = await captureLive(net);
        mkdirSync(net.fixtureDir, {recursive: true});
        writeFileSync(fixture, JSON.stringify(capture, null, 2) + "\n");
        console.log(`[avalanche-live] wrote ${fixture}`);
    } else {
        capture = loadLiveCapture(fixture);
    }
    const proof = await buildAvalancheLiveProof(capture);
    if (args.includes("--refresh") || args.includes("--vectors")) {
        writeVectors(proof, capture, vectors);
        console.log(`[avalanche-live] wrote ${vectors}`);
    }
    console.log(summarize(proof));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    main().catch((err) => {
        console.error(err);
        process.exit(1);
    });
}
