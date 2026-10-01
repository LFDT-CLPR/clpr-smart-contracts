import {bls12_381} from "@noble/curves/bls12-381";
import {RLP} from "@ethereumjs/rlp";
import {mkdirSync, readFileSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {type Hex, keccak256, recoverAddress, toHex} from "viem";
import {bigintToTrimmedBuf, hexToBuf, hexToTrimmedBuf, rlpEncode} from "../lib/rlp.js";
import {pbBytes, pbInt, pbLen, pbStr} from "../lib/proto.js";
import {g1ToUncompressed, g2ToUncompressed} from "./bls.js";
import {deriveChannelSlots} from "./buildEthMainnetProof.js";

/// Live-data proof builder for `BscParliaVerifier` (BNB Smart Chain, Parlia + BEP-126 fast finality).
///
/// Two phases, so tests are deterministic offline:
///   `captureBscLive(network)` → raw JSON-RPC responses (headers + eth_getProof), saved as a fixture
///   `buildBscLiveProof(capture)` → verifier wire format, pure/offline, every step cross-checked
///                                  (header hashes, ECDSA seals, BLS aggregate signatures with noble).
///
/// What the capture contains (all real chain data):
///   - three consecutive epoch blocks E_pp, E_prev, E_cur (epoch length 1000). E_prev is the
///     configured anchor (verifyConfig input); E_pp only fixes the anchor's `activeFrom`
///     (E_prev + checkLen(E_pp set) + 1). E_cur is rotated into, finalized by the E_prev set;
///   - the header carrying the attestation that finalizes E_cur (source E_cur, target E_cur + 1);
///   - a recent state block S in E_cur's tenure, the header carrying its finalizing attestation,
///     and `eth_getProof` at S for a long-lived account (WBNB) and the channelId-derived slots
///     (absent there → MPT exclusion proofs → zeroed queue metadata, as in the Sepolia live test).
///
/// CLI:
///   npx tsx test/e2e/relay/buildBscLiveProof.ts [--network chapel|mainnet|botchain|core] [--vectors] summary from fixture
///                                                     (--vectors rewrites the Foundry hex vectors)
///   npx tsx test/e2e/relay/buildBscLiveProof.ts --refresh [--network chapel|mainnet|botchain|core]  re-capture

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const BSC_LIVE_DIR = path.resolve(__dirname, "../fixtures/bsc-live");

export type BscNetwork = "chapel" | "mainnet" | "botchain" | "core";

export const NETWORKS: Record<BscNetwork, {chainId: bigint; rpcs: string[]; account: Hex; epochLength: bigint; lag?: number}> = {
    chapel: {
        chainId: 97n,
        rpcs: [
            "https://bsc-testnet-rpc.publicnode.com",
            "https://bsc-testnet.drpc.org",
            "https://data-seed-prebsc-1-s1.bnbchain.org:8545",
            "https://data-seed-prebsc-2-s1.bnbchain.org:8545"
        ],
        account: "0xae13d989daC2f0dEbFf460aC112a837C89BAa7cd", // WBNB (Chapel)
        epochLength: 1000n
    },
    mainnet: {
        chainId: 56n,
        rpcs: ["https://bsc-rpc.publicnode.com", "https://bsc.drpc.org", "https://bsc-dataseed.bnbchain.org"],
        account: "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", // WBNB (mainnet)
        epochLength: 1000n
    },
    // BOT Chain (BSC-derived Geth v1.5.x, Parlia + fast finality). Only one public RPC exists; it
    // serves eth_getProof with deep history. Probe account: the ValidatorSet system contract.
    botchain: {
        chainId: 677n,
        rpcs: ["https://rpc.botchain.ai"],
        account: "0x0000000000000000000000000000000000001000",
        epochLength: 1000n
    },
    // Core (Satoshi Plus, coredao-org/core-chain): 200-block epochs, ~3 s blocks, turnLength 1.
    // rpc.coredao.org prunes state after a few thousand blocks; drpc/ankr keep more.
    core: {
        chainId: 1116n,
        rpcs: ["https://rpc.coredao.org", "https://core.drpc.org", "https://rpc.ankr.com/core"],
        account: "0x40375C92d9FAf44d2f9db9Bd9ba41a3317a2404f", // WCORE
        epochLength: 200n,
        lag: 30
    }
};

export const LIVE_CHANNEL_ID: Hex = keccak256(toHex("clpr/bsc-parlia-verifier/live"));
export const EPOCH_LENGTH = 1000n; // Maxwell (BEP-524) epoch length on mainnet and Chapel (default)

// ── Parlia constants (mirror ClprParlia.sol / bsc consensus/parlia) ─────────
const EXTRA_VANITY = 32;
const EXTRA_SEAL = 65;
const VALIDATOR_BYTES = 68;
const BLS_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

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
    balHash?: Hex;
    slotNumber?: Hex;
}

export interface BscLiveCapture {
    network: BscNetwork;
    chainId: string;
    capturedAt: string;
    epochLength: string;
    account: Hex;
    channelId: Hex;
    /// Raw headers by decimal block number.
    blocks: Record<string, RpcBlock>;
    epochs: {pp: number; prev: number; cur: number};
    rotation: {chain: number[]; carrier: number};
    state: {chain: number[]; carrier: number};
    proof: {codeHash: Hex; storageHash: Hex; accountProof: Hex[]; storageProof: {key: Hex; proof: Hex[]}[]};
}

export interface Attestation {
    voteAddressSet: bigint;
    signature: Buffer; // 96-byte compressed (as carried in the header)
    sourceNumber: bigint;
    sourceHash: Hex;
    targetNumber: bigint;
    targetHash: Hex;
}

export interface EpochSet {
    number: bigint;
    addrs: Hex[];
    compressed: Buffer[];
    uncompressed: Buffer[];
    turnLength: number;
    validatorsHash: Hex;
}

export interface BscLiveProof {
    network: BscNetwork;
    chainId: bigint;
    configProof: Hex;
    trustAnchor: Hex; // what verifyConfig must return
    rotatedAnchor: Hex; // what verifyBundle must return
    proofBytes: Hex; // rotation (keys elided: set unchanged → empty list, else keys) + state
    proofBytesWithKeys: Hex; // same, rotation always carrying the uncompressed keys
    proofBytesNoRotation: Hex; // anchored at E_cur directly (rotatedAnchor as the input anchor)
    channelContext: Hex;
    channelId: Hex;
    account: Hex;
    codeHash: Hex;
    parts: BundleParts;
    meta: {
        anchorEpoch: bigint;
        rotationEpoch: bigint;
        stateBlock: bigint;
        stateRoot: Hex;
        validators: number;
        rotationVotes: number;
        stateVotes: number;
        setChanged: boolean;
        turnLength: number;
        activeFromPrev: bigint;
        activeFromCur: bigint;
        blockIntervalMs: number;
    };
}

/// RLP item tree as `@ethereumjs/rlp` takes it.
type Item = Buffer | Item[];

export interface BundleParts {
    rotations: Item[];
    validators: Buffer; // n × (address20 ‖ uncompressedKey128)
    finality: Item[];
    accountProof: Buffer[];
    storageProof: Item[];
    bundleContent: Buffer;
}

// ── Headers ─────────────────────────────────────────────────────────────────

/// `core/types.Header` RLP field list, mirroring go-ethereum's optional-field rule.
export function headerFields(b: RpcBlock): Buffer[] {
    const f: Buffer[] = [
        hexToBuf(b.parentHash), hexToBuf(b.sha3Uncles), hexToBuf(b.miner), hexToBuf(b.stateRoot),
        hexToBuf(b.transactionsRoot), hexToBuf(b.receiptsRoot), hexToBuf(b.logsBloom), hexToTrimmedBuf(b.difficulty),
        hexToTrimmedBuf(b.number), hexToTrimmedBuf(b.gasLimit), hexToTrimmedBuf(b.gasUsed), hexToTrimmedBuf(b.timestamp),
        hexToBuf(b.extraData), hexToBuf(b.mixHash), hexToBuf(b.nonce)
    ];
    const opt: [keyof RpcBlock, boolean][] = [
        ["baseFeePerGas", true], ["withdrawalsRoot", false], ["blobGasUsed", true], ["excessBlobGas", true],
        ["parentBeaconBlockRoot", false], ["requestsHash", false], ["balHash", false], ["slotNumber", true]
    ];
    for (const [k, isInt] of opt) {
        const v = b[k];
        if (v === undefined) break;
        f.push(isInt ? hexToTrimmedBuf(v) : hexToBuf(v));
    }
    return f;
}

export function headerRlp(b: RpcBlock): Buffer {
    const enc = rlpEncode(headerFields(b));
    if (keccak256(enc) !== b.hash) throw new Error(`header ${BigInt(b.number)}: RLP does not hash to ${b.hash}`);
    return enc;
}

/// `types.SealHash(header, chainId)` — see ClprParlia.sealSigner.
export function sealHash(b: RpcBlock, chainId: bigint): Hex {
    const f = headerFields(b);
    const extra = hexToBuf(b.extraData);
    const parts: Buffer[] = [bigintToTrimmedBuf(chainId), ...f.slice(0, 12), extra.subarray(0, extra.length - EXTRA_SEAL),
        f[13], f[14]];
    if (f.length > 19) parts.push(...f.slice(15, 20));
    if (f.length > 20) parts.push(f[20]);
    return keccak256(rlpEncode(parts));
}

export async function sealSigner(b: RpcBlock, chainId: bigint): Promise<Hex> {
    const extra = hexToBuf(b.extraData);
    const sig = Buffer.from(extra.subarray(extra.length - EXTRA_SEAL));
    sig[64] += 27;
    return (await recoverAddress({hash: sealHash(b, chainId), signature: toHex(sig)})).toLowerCase() as Hex;
}

// ── Epoch blocks and attestations ───────────────────────────────────────────

export function parseEpoch(b: RpcBlock): EpochSet {
    const extra = hexToBuf(b.extraData);
    const n = extra[EXTRA_VANITY];
    const start = EXTRA_VANITY + 1;
    const end = start + n * VALIDATOR_BYTES;
    if (n === 0 || extra.length < end + 1 + EXTRA_SEAL) throw new Error(`block ${BigInt(b.number)} is not an epoch block`);
    const addrs: Hex[] = [];
    const compressed: Buffer[] = [];
    const uncompressed: Buffer[] = [];
    for (let i = 0; i < n; i++) {
        const o = start + i * VALIDATOR_BYTES;
        addrs.push(toHex(extra.subarray(o, o + 20)));
        const pk = extra.subarray(o + 20, o + VALIDATOR_BYTES);
        compressed.push(Buffer.from(pk));
        uncompressed.push(g1ToUncompressed(bls12_381.G1.ProjectivePoint.fromHex(pk)));
    }
    for (let i = 1; i < n; i++) {
        if (BigInt(addrs[i]) <= BigInt(addrs[i - 1])) throw new Error("validators not ascending");
    }
    return {
        number: BigInt(b.number), addrs, compressed, uncompressed, turnLength: extra[end],
        validatorsHash: keccak256(extra.subarray(start, end))
    };
}

/// The vote attestation embedded in a header's extraData (non-epoch or epoch layout).
export function headerAttestation(b: RpcBlock, epochLength = EPOCH_LENGTH): Attestation | undefined {
    const extra = hexToBuf(b.extraData);
    let start = EXTRA_VANITY;
    if (BigInt(b.number) % epochLength === 0n) start += 1 + extra[EXTRA_VANITY] * VALIDATOR_BYTES + 1;
    const end = extra.length - EXTRA_SEAL;
    if (end <= start) return undefined;
    const d = RLP.decode(extra.subarray(start, end)) as unknown as [Uint8Array, Uint8Array, Uint8Array[], Uint8Array];
    const num = (u: Uint8Array) => (u.length ? BigInt(toHex(u)) : 0n);
    return {
        voteAddressSet: num(d[0]),
        signature: Buffer.from(d[1]),
        sourceNumber: num(d[2][0]),
        sourceHash: toHex(d[2][1]),
        targetNumber: num(d[2][2]),
        targetHash: toHex(d[2][3])
    };
}

export function voteDataHash(a: Attestation): Hex {
    return keccak256(rlpEncode([bigintToTrimmedBuf(a.sourceNumber), hexToBuf(a.sourceHash),
        bigintToTrimmedBuf(a.targetNumber), hexToBuf(a.targetHash)]));
}

/// Off-chain FastAggregateVerify (noble) — the same check the contract runs with EIP-2537.
export function verifyAttestationOffchain(a: Attestation, set: EpochSet): number {
    const G1 = bls12_381.G1.ProjectivePoint;
    let agg = G1.ZERO;
    let votes = 0;
    for (let i = 0; i < set.compressed.length; i++) {
        if ((a.voteAddressSet >> BigInt(i)) & 1n) {
            agg = agg.add(G1.fromHex(set.compressed[i]));
            votes++;
        }
    }
    if (a.voteAddressSet >> BigInt(set.compressed.length) !== 0n) throw new Error("vote bit beyond validator set");
    if (votes * 3 < 2 * set.compressed.length) throw new Error(`quorum not met: ${votes}/${set.compressed.length}`);
    const H = bls12_381.G2.hashToCurve(hexToBuf(voteDataHash(a)), {DST: BLS_DST}) as unknown as
        InstanceType<typeof bls12_381.G2.ProjectivePoint>;
    const sig = bls12_381.G2.ProjectivePoint.fromHex(a.signature);
    const ok = bls12_381.fields.Fp12.eql(bls12_381.pairing(agg, H), bls12_381.pairing(G1.BASE, sig));
    if (!ok) throw new Error(`BLS attestation ${a.sourceNumber}→${a.targetNumber} does not verify`);
    return votes;
}

export function attestationItem(a: Attestation): Item {
    const sig = g2ToUncompressed(bls12_381.G2.ProjectivePoint.fromHex(a.signature));
    return [bigintToTrimmedBuf(a.voteAddressSet), sig, bigintToTrimmedBuf(a.sourceNumber), hexToBuf(a.sourceHash),
        bigintToTrimmedBuf(a.targetNumber), hexToBuf(a.targetHash)];
}

/// minerHistoryCheckLen = (n/2 + 1) · turnLength − 1.
export function checkLen(n: number, turnLength: number): bigint {
    return BigInt((Math.floor(n / 2) + 1) * turnLength - 1);
}

// ── Wire encodings ──────────────────────────────────────────────────────────

export function encodeAnchor(a: {
    channelId: Hex; codeHash: Hex; validatorsHash: Hex; keysHash: Hex; chainId: bigint; epochLength: bigint;
    epochBlock: bigint; activeFrom: bigint; turnLength: number; validatorCount: number;
}): Hex {
    const u64 = (v: bigint) => v.toString(16).padStart(16, "0");
    const u8 = (v: number) => v.toString(16).padStart(2, "0");
    return ("0x" + [a.channelId, a.codeHash, a.validatorsHash, a.keysHash].map((h) => h.slice(2)).join("") +
        u64(a.chainId) + u64(a.epochLength) + u64(a.epochBlock) + u64(a.activeFrom) + u8(a.turnLength) +
        u8(a.validatorCount)) as Hex;
}

export function keysHash(set: EpochSet): Hex {
    return keccak256(Buffer.concat(set.addrs.map((a, i) => Buffer.concat([hexToBuf(a), set.uncompressed[i]]))));
}

export function validatorEntries(set: EpochSet): Buffer {
    return Buffer.concat(set.addrs.map((a, i) => Buffer.concat([hexToBuf(a), set.uncompressed[i]])));
}

/// `ClprMessagePayload{control{config_update{configuration}}}` as ClprProtobuf.encodeControlMessage.
export function ledgerConfigPayload(chainId: bigint, serviceAddress: Hex): Buffer {
    const throttles = Buffer.concat([pbInt(1, 100n), pbInt(2, 10_000n), pbInt(3, 1_000_000n), pbInt(4, 1000n),
        pbInt(5, 1_000_000n), pbInt(6, 8n), pbInt(7, 8n)]);
    const config = Buffer.concat([
        pbInt(1, 1n), pbStr(2, `eip155:${chainId}`), pbBytes(3, serviceAddress),
        pbLen(4, pbInt(1, 1_760_000_000n)), pbLen(5, throttles)
    ]);
    return pbLen(3, pbLen(1, pbLen(1, config)));
}

/// ClprTypes.encodeChannelContext = abi.encodePacked(channelId, remoteServiceAddress).
export function encodeChannelContext(channelId: Hex, service: Hex): Hex {
    return (channelId + service.slice(2).toLowerCase()) as Hex;
}

export function encodeBundle(p: BundleParts, overrides: Partial<BundleParts> = {}): Hex {
    const q = {...p, ...overrides};
    return toHex(rlpEncode([q.rotations, q.validators, q.finality, q.accountProof, q.storageProof, q.bundleContent]));
}

// ── Build (offline) ─────────────────────────────────────────────────────────

function blk(c: BscLiveCapture, n: number | bigint): RpcBlock {
    const b = c.blocks[String(n)];
    if (!b) throw new Error(`capture is missing block ${n}`);
    return b;
}

export function buildBscLiveProof(c: BscLiveCapture): BscLiveProof {
    const chainId = BigInt(c.chainId);
    const L = BigInt(c.epochLength);
    const setPP = parseEpoch(blk(c, c.epochs.pp));
    const setPrev = parseEpoch(blk(c, c.epochs.prev));
    const setCur = parseEpoch(blk(c, c.epochs.cur));
    if (setPrev.number !== setPP.number + L || setCur.number !== setPrev.number + L) throw new Error("epochs not consecutive");
    const activeFromPrev = setPrev.number + checkLen(setPP.addrs.length, setPP.turnLength) + 1n;
    const activeFromCur = setCur.number + checkLen(setPrev.addrs.length, setPrev.turnLength) + 1n;
    const lastTargetPrev = setCur.number + checkLen(setPrev.addrs.length, setPrev.turnLength);
    const lastTargetCur = setCur.number + L + checkLen(setCur.addrs.length, setCur.turnLength);

    const chainOf = (nums: number[]) => {
        nums.forEach((n, i) => {
            if (i > 0 && blk(c, n).parentHash !== blk(c, nums[i - 1]).hash) throw new Error(`chain broken at ${n}`);
        });
        // Decoded so each header nests as an RLP list (not a byte string) inside the bundle.
        return nums.map((n) => RLP.decode(headerRlp(blk(c, n))) as unknown as Item);
    };

    // Rotation: E_cur finalized by the E_prev set.
    const rotAtt = headerAttestation(blk(c, c.rotation.carrier), L)!;
    const rotHead = blk(c, c.rotation.chain[c.rotation.chain.length - 1]);
    if (c.rotation.chain[0] !== Number(setCur.number)) throw new Error("rotation chain must start at the epoch block");
    if (rotAtt.sourceHash !== rotHead.hash || rotAtt.targetNumber !== rotAtt.sourceNumber + 1n) {
        throw new Error("rotation attestation does not finalize the chain head");
    }
    if (rotAtt.sourceNumber < activeFromPrev || rotAtt.targetNumber > lastTargetPrev) throw new Error("rotation attestation outside E_prev tenure");
    const rotationVotes = verifyAttestationOffchain(rotAtt, setPrev);

    // State block S finalized by the E_cur set.
    const stAtt = headerAttestation(blk(c, c.state.carrier), L)!;
    const stHead = blk(c, c.state.chain[c.state.chain.length - 1]);
    if (stAtt.sourceHash !== stHead.hash || stAtt.targetNumber !== stAtt.sourceNumber + 1n) {
        throw new Error("state attestation does not finalize the chain head");
    }
    if (stAtt.sourceNumber < activeFromCur || stAtt.targetNumber > lastTargetCur) throw new Error("state attestation outside E_cur tenure");
    const stateVotes = verifyAttestationOffchain(stAtt, setCur);
    const stateBlock = blk(c, c.state.chain[0]);
    if (c.proof.codeHash === "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470") {
        throw new Error("proof account has no code");
    }

    const setChanged = setCur.validatorsHash !== setPrev.validatorsHash;
    const packedCur = Buffer.concat(setCur.uncompressed);
    const rotationWithKeys: Item[] = [chainOf(c.rotation.chain), attestationItem(rotAtt), packedCur];
    const rotation: Item[] = [chainOf(c.rotation.chain), attestationItem(rotAtt), setChanged ? packedCur : Buffer.alloc(0)];

    const slots = deriveChannelSlots(c.channelId);
    const byKey = new Map(c.proof.storageProof.map((sp) => [BigInt(sp.key), sp]));
    const storageProof: Item[] = slots.map((k) => {
        const sp = byKey.get(BigInt(k));
        if (!sp) throw new Error(`proof missing slot ${k}`);
        return [hexToBuf(k), sp.proof.map((n) => hexToBuf(n))];
    });
    const parts: BundleParts = {
        rotations: [rotation],
        validators: validatorEntries(setPrev),
        finality: [chainOf(c.state.chain), attestationItem(stAtt)],
        accountProof: c.proof.accountProof.map((n) => hexToBuf(n)),
        storageProof,
        bundleContent: Buffer.alloc(0)
    };

    const anchorBase = {channelId: c.channelId, codeHash: c.proof.codeHash, chainId, epochLength: L};
    const trustAnchor = encodeAnchor({
        ...anchorBase, validatorsHash: setPrev.validatorsHash, keysHash: keysHash(setPrev), epochBlock: setPrev.number,
        activeFrom: activeFromPrev, turnLength: setPrev.turnLength, validatorCount: setPrev.addrs.length
    });
    const rotatedAnchor = encodeAnchor({
        ...anchorBase, validatorsHash: setCur.validatorsHash, keysHash: keysHash(setCur), epochBlock: setCur.number,
        activeFrom: activeFromCur, turnLength: setCur.turnLength, validatorCount: setCur.addrs.length
    });
    const configProof = toHex(rlpEncode([
        ledgerConfigPayload(chainId, c.account), bigintToTrimmedBuf(chainId), bigintToTrimmedBuf(L),
        RLP.decode(headerRlp(blk(c, c.epochs.prev))) as unknown as Item, bigintToTrimmedBuf(activeFromPrev),
        Buffer.concat(setPrev.uncompressed), hexToBuf(c.proof.codeHash)
    ] as never));

    const t0 = BigInt(blk(c, c.state.chain[0]).timestamp);
    const t1 = BigInt(blk(c, c.state.carrier).timestamp);
    const dn = c.state.carrier - c.state.chain[0];
    const ms = (b: RpcBlock) => Number(BigInt(b.mixHash) & 0xffffn); // BEP-520: ms part in mixHash
    const blockIntervalMs = dn > 0
        ? Number(((t1 - t0) * 1000n + BigInt(ms(blk(c, c.state.carrier)) - ms(stateBlock)))) / dn
        : 0;

    return {
        network: c.network,
        chainId,
        configProof,
        trustAnchor,
        rotatedAnchor,
        proofBytes: encodeBundle(parts),
        proofBytesWithKeys: encodeBundle(parts, {rotations: [rotationWithKeys]}),
        proofBytesNoRotation: encodeBundle(parts, {rotations: [], validators: validatorEntries(setCur)}),
        channelContext: encodeChannelContext(c.channelId, c.account),
        channelId: c.channelId,
        account: c.account,
        codeHash: c.proof.codeHash,
        parts,
        meta: {
            anchorEpoch: setPrev.number,
            rotationEpoch: setCur.number,
            stateBlock: BigInt(stateBlock.number),
            stateRoot: stateBlock.stateRoot,
            validators: setCur.addrs.length,
            rotationVotes,
            stateVotes,
            setChanged,
            turnLength: setCur.turnLength,
            activeFromPrev,
            activeFromCur,
            blockIntervalMs
        }
    };
}

// ── Capture (live) ──────────────────────────────────────────────────────────

async function rpcCall<T>(url: string, method: string, params: unknown[]): Promise<T> {
    const r = await fetch(url, {
        method: "POST",
        headers: {"content-type": "application/json"},
        body: JSON.stringify({jsonrpc: "2.0", id: 1, method, params}),
        signal: AbortSignal.timeout(20_000)
    });
    const j = (await r.json()) as {result?: T; error?: unknown};
    if (j.error !== undefined || j.result === undefined || j.result === null) {
        throw new Error(`${url} ${method}: ${JSON.stringify(j.error ?? "null result")}`);
    }
    return j.result;
}

async function anyRpc<T>(rpcs: string[], method: string, params: unknown[], tries = 3): Promise<T> {
    let last: unknown;
    for (let t = 0; t < tries; t++) {
        for (const u of rpcs) {
            try {
                return await rpcCall<T>(u, method, params);
            } catch (e) {
                last = e;
            }
        }
        await new Promise((r) => setTimeout(r, 1000));
    }
    throw last;
}

function stripBlock(b: RpcBlock & Record<string, unknown>): RpcBlock {
    const keep: (keyof RpcBlock)[] = ["hash", "parentHash", "sha3Uncles", "miner", "stateRoot", "transactionsRoot",
        "receiptsRoot", "logsBloom", "difficulty", "number", "gasLimit", "gasUsed", "timestamp", "extraData", "mixHash",
        "nonce", "baseFeePerGas", "withdrawalsRoot", "blobGasUsed", "excessBlobGas", "parentBeaconBlockRoot",
        "requestsHash", "balHash", "slotNumber"];
    const out: Record<string, unknown> = {};
    for (const k of keep) if (b[k] !== undefined) out[k] = b[k];
    return out as unknown as RpcBlock;
}

/// Find a header in (from, to] carrying an attestation with `target = source + 1` and
/// `source ≥ minSource`; returns the carrier and the chain [minSource … source].
async function findFinalizing(
    get: (n: bigint) => Promise<RpcBlock>, minSource: bigint, maxTarget: bigint, epochLength: bigint, limit = 12
): Promise<{carrier: bigint; chain: bigint[]}> {
    for (let k = minSource + 2n; k <= minSource + BigInt(limit); k++) {
        const a = headerAttestation(await get(k), epochLength);
        if (!a || a.targetNumber !== a.sourceNumber + 1n || a.sourceNumber < minSource || a.targetNumber > maxTarget) continue;
        const chain: bigint[] = [];
        for (let n = minSource; n <= a.sourceNumber; n++) chain.push(n);
        return {carrier: k, chain};
    }
    throw new Error(`no finalizing attestation found for block ${minSource}`);
}

export async function captureBscLive(network: BscNetwork, opts: {account?: Hex; rpcs?: string[]; lag?: number} = {}): Promise<BscLiveCapture> {
    const net = NETWORKS[network];
    const rpcs = opts.rpcs ?? net.rpcs;
    const account = (opts.account ?? net.account).toLowerCase() as Hex;
    const L = net.epochLength;
    const chainId = BigInt(await anyRpc<Hex>(rpcs, "eth_chainId", []));
    if (chainId !== net.chainId) throw new Error(`unexpected chainId ${chainId}`);

    for (let attempt = 0; attempt < 8; attempt++) {
        const blocks: Record<string, RpcBlock> = {};
        const get = async (n: bigint) => {
            const key = String(n);
            if (!blocks[key]) {
                blocks[key] = stripBlock(await anyRpc(rpcs, "eth_getBlockByNumber", [toHex(n), false]));
                headerRlp(blocks[key]); // hash cross-check
            }
            return blocks[key];
        };
        const latest = BigInt((await anyRpc<RpcBlock>(rpcs, "eth_getBlockByNumber", ["latest", false])).number);
        // Some public nodes sit a few dozen blocks behind the load-balanced head and refuse eth_getProof
        // for blocks they have not reached yet; a state block ~1 minute old is served reliably.
        const S = latest - BigInt(opts.lag ?? net.lag ?? 120);
        const eCur = S - (S % L);
        const ePrev = eCur - L;
        const ePP = ePrev - L;
        const [setPP, setPrev, setCur] = [parseEpoch(await get(ePP)), parseEpoch(await get(ePrev)), parseEpoch(await get(eCur))];
        const activeFromCur = eCur + checkLen(setPrev.addrs.length, setPrev.turnLength) + 1n;
        if (S < activeFromCur) {
            console.log(`state block ${S} precedes the E_cur set's tenure (${activeFromCur}); waiting…`);
            await new Promise((r) => setTimeout(r, 15_000));
            continue;
        }
        void setPP;
        const lastTargetPrev = eCur + checkLen(setPrev.addrs.length, setPrev.turnLength);
        const lastTargetCur = eCur + L + checkLen(setCur.addrs.length, setCur.turnLength);
        const rot = await findFinalizing(get, eCur, lastTargetPrev, L);
        const st = await findFinalizing(get, S, lastTargetCur, L);
        for (const n of [...rot.chain, ...st.chain]) await get(n);

        const slots = deriveChannelSlots(LIVE_CHANNEL_ID);
        let proof: BscLiveCapture["proof"];
        try {
            proof = await anyRpc(rpcs, "eth_getProof", [account, slots, toHex(S)], 3);
        } catch (e) {
            console.log(`eth_getProof at ${S} failed (${(e as Error).message.slice(0, 120)}); retrying with a fresh block`);
            continue;
        }
        const stateRoot = (await get(S)).stateRoot;
        const capture: BscLiveCapture = {
            network,
            chainId: chainId.toString(),
            capturedAt: new Date().toISOString(),
            epochLength: L.toString(),
            account,
            channelId: LIVE_CHANNEL_ID,
            blocks,
            epochs: {pp: Number(ePP), prev: Number(ePrev), cur: Number(eCur)},
            rotation: {chain: rot.chain.map(Number), carrier: Number(rot.carrier)},
            state: {chain: st.chain.map(Number), carrier: Number(st.carrier)},
            proof: {
                codeHash: proof.codeHash,
                storageHash: proof.storageHash,
                accountProof: proof.accountProof,
                storageProof: proof.storageProof.map((s) => ({key: s.key, proof: s.proof}))
            }
        };
        // Account proof must root at the finalized state root.
        if (keccak256(proof.accountProof[0]) !== stateRoot) {
            console.log(`eth_getProof root mismatch at ${S} (load-balanced RPC head skew?); retrying`);
            continue;
        }
        const signer = await sealSigner(blocks[String(st.chain[st.chain.length - 1])], chainId);
        if (!setCur.addrs.includes(signer)) throw new Error(`state head sealed by non-validator ${signer}`);
        return capture;
    }
    throw new Error("could not capture a consistent live bundle");
}

export function fixturePath(network: BscNetwork): string {
    return path.join(BSC_LIVE_DIR, `${network}.json`);
}

export function vectorsPath(network: BscNetwork): string {
    return path.join(BSC_LIVE_DIR, `${network}-vectors.json`);
}

export function loadBscCapture(network: BscNetwork): BscLiveCapture {
    return JSON.parse(readFileSync(fixturePath(network), "utf8")) as BscLiveCapture;
}

/// Flat hex vectors for the Foundry live-data test (test/verifiers/evm/bsc/BscParliaLive.t.sol).
export function writeVectors(p: BscLiveProof): void {
    const v = {
        configProof: p.configProof,
        trustAnchor: p.trustAnchor,
        rotatedAnchor: p.rotatedAnchor,
        proofBytes: p.proofBytes,
        proofBytesNoRotation: p.proofBytesNoRotation,
        channelContext: p.channelContext,
        channelId: p.channelId,
        stateRoot: p.meta.stateRoot,
        anchorEpoch: Number(p.meta.anchorEpoch),
        rotationEpoch: Number(p.meta.rotationEpoch),
        stateBlock: Number(p.meta.stateBlock),
        validators: p.meta.validators
    };
    writeFileSync(vectorsPath(p.network), JSON.stringify(v, null, 1) + "\n");
}

function summarize(p: BscLiveProof): string {
    const m = p.meta;
    const len = (h: Hex) => (h.length - 2) / 2;
    return [
        `network        ${p.network} (chainId ${p.chainId}), ${m.validators} validators, turnLength ${m.turnLength}`,
        `anchor epoch   ${m.anchorEpoch} (activeFrom ${m.activeFromPrev}) → rotation epoch ${m.rotationEpoch} (activeFrom ${m.activeFromCur}), set ${m.setChanged ? "CHANGED" : "unchanged"}`,
        `rotation votes ${m.rotationVotes}/${m.validators}; state block ${m.stateBlock} votes ${m.stateVotes}/${m.validators}`,
        `block interval ~${m.blockIntervalMs.toFixed(0)} ms`,
        `proofBytes     ${len(p.proofBytes)} B (with keys ${len(p.proofBytesWithKeys)} B, no rotation ${len(p.proofBytesNoRotation)} B)`,
        `configProof    ${len(p.configProof)} B, trustAnchor ${len(p.trustAnchor)} B`
    ].join("\n");
}

async function main(): Promise<void> {
    const args = process.argv.slice(2);
    const nIdx = args.indexOf("--network");
    const networks: BscNetwork[] = nIdx >= 0 ? [args[nIdx + 1] as BscNetwork] : ["chapel", "mainnet", "botchain", "core"];
    for (const network of networks) {
        let capture: BscLiveCapture;
        if (args.includes("--refresh")) {
            capture = await captureBscLive(network);
            const built = buildBscLiveProof(capture); // validate before overwriting
            mkdirSync(BSC_LIVE_DIR, {recursive: true});
            writeFileSync(fixturePath(network), JSON.stringify(capture, null, 1) + "\n");
            writeVectors(built);
            console.log(`captured → ${path.relative(process.cwd(), fixturePath(network))}`);
        } else {
            capture = loadBscCapture(network);
            if (args.includes("--vectors")) writeVectors(buildBscLiveProof(capture));
        }
        console.log(summarize(buildBscLiveProof(capture)));
    }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    main().catch((err) => {
        console.error(err);
        process.exit(1);
    });
}
