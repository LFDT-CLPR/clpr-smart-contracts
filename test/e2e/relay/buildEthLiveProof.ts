import {bls12_381} from "@noble/curves/bls12-381";
import {createHash} from "node:crypto";
import {mkdirSync, readFileSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {type Hex, keccak256, toHex} from "viem";
import {type Input} from "@ethereumjs/rlp";
import {rlpEncode, hexToBuf, bigintToTrimmedBuf} from "../lib/rlp.js";
import {g1ToUncompressed, g2ToUncompressed, hashToG2} from "./bls.js";
import {
    beaconBlockHeaderRoot,
    computeSigningRoot,
    computeSyncCommitteeDomain,
    syncCommitteeRootFromCompressed
} from "./signingRoot.js";
import {
    committeeMerkleRoot,
    deriveChannelSlots,
    encodeEthTrustAnchor,
    foldSszBranch,
    nonSignerProofEntries,
    type EthGetProofResult
} from "./buildEthMainnetProof.js";

/// Live-data proof builder for `EthMainnetVerifier`, fed by a real beacon chain (Sepolia by default).
///
/// Everything the synthetic builder (`buildEthMainnetProof.ts`) fabricates is taken from the chain:
///   - the sync committee comes from `light_client/bootstrap` (or `light_client/updates` when the
///     signature slot is in the next period) — 512 compressed 48-byte G1 keys, decompressed here to
///     EIP-2537 uncompressed 128-byte points and committed with `ClprCommitteeMerkle`'s keccak tree;
///   - the attested header, participation bits and aggregate signature come from
///     `light_client/finality_update`; the signature is decompressed to an uncompressed G2 point;
///   - the signing domain uses the fork version at the signature slot (`compute_fork_version`
///     over the chain's `config/spec` schedule) and the chain's `genesis_validators_root`;
///   - the execution `state_root` → `body_root` SSZ branch is rebuilt: the ExecutionPayloadHeader
///     field tree (Deneb/Electra/Fulu, 17 fields → 32 leaves, depth 5, `state_root` at index 2)
///     proves `state_root` into the payload-header root, and the light-client `execution_branch`
///     (depth 4, gindex 25) proves that into `body_root`. Concatenated: depth 9, gindex 25·32+2 = 802
///     — exactly `ClprBeaconSsz.GINDEX_EXECUTION_STATE_ROOT_IN_BODY`;
///   - the MPT account proof (and exclusion proofs for the channelId-derived slots) come from
///     `eth_getProof` at the attested execution block.
///
/// The verifier authenticates the header the sync committee signed (the attested header); the
/// update's finalized header is used here solely to locate the bootstrap committee.
///
/// Two phases, so tests are deterministic offline:
///   `captureSepoliaLive()` → raw API responses (a `LiveCapture`, saved as JSON fixture)
///   `buildEthLiveProof(capture)` → verifier wire format, pure/offline, with every step cross-checked.
///
/// CLI:
///   npx tsx test/e2e/relay/buildEthLiveProof.ts            build from the fixture, print a summary
///   npx tsx test/e2e/relay/buildEthLiveProof.ts --refresh [--wait-nonsigners SECS] [--account 0x..] [--out FILE]
///                                                         re-capture live data into the fixture

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const SEPOLIA_LIVE_FIXTURE = path.resolve(__dirname, "../fixtures/sepolia-live/capture.json");

export const DEFAULT_BEACON_APIS = [
    "https://ethereum-sepolia-beacon-api.publicnode.com",
    "https://lodestar-sepolia.chainsafe.io"
];
export const DEFAULT_EXECUTION_RPC = "https://0xrpc.io/sep";
/// Sepolia beacon deposit contract — a long-lived account with real code and a populated storage
/// trie. Any account works for the beacon/BLS/SSZ/account-MPT path; a real ClprService on Sepolia
/// is only needed to prove non-empty channel storage.
export const DEFAULT_ACCOUNT: Hex = "0x7f02C3E3c98b133055B8B348B2Ac625669Ed295D";
/// Fixed test channel id; its derived `Channel` slots are absent in the target account, so the
/// storage proofs are genuine MPT exclusion proofs (the verifier reads them as zero).
export const LIVE_CHANNEL_ID: Hex = keccak256(toHex("clpr/eth-live-beacon-proofs/sepolia"));

// ── Verifier constants (mirror EthMainnetVerifier / ClprBeaconSsz) ─────────
const SYNC_COMMITTEE_SIZE = 512;
const SYNC_BITS_LENGTH = 64;
const EXECUTION_PAYLOAD_GINDEX_IN_BODY = 25n; // light-client execution_branch (depth 4)
const EXECUTION_PAYLOAD_HEADER_DEPTH = 5; // 17 fields → 32 leaves (Deneb, Electra, Fulu)
const STATE_ROOT_FIELD_INDEX = 2;
const GINDEX_EXECUTION_STATE_ROOT_IN_BODY = 802n; // (25 << 5) | 2
const EXECUTION_BRANCH_DEPTH = 9;
const GINDEX_NEXT_SYNC_COMMITTEE_IN_STATE = 87n; // Electra+ BeaconState (depth 6)
const NEXT_COMMITTEE_BRANCH_DEPTH = 6;
/// Forks whose light-client header carries a 17-field (Deneb-layout) ExecutionPayloadHeader and a
/// depth-6 BeaconState (the only layouts EthMainnetVerifier's constants accept).
const SUPPORTED_FORKS = new Set(["electra", "fulu"]);

// ── Raw API shapes (only the fields we use) ────────────────────────────────
export interface BeaconHeaderJson {
    slot: string;
    proposer_index: string;
    parent_root: string;
    state_root: string;
    body_root: string;
}

export interface ExecutionPayloadHeaderJson {
    parent_hash: string;
    fee_recipient: string;
    state_root: string;
    receipts_root: string;
    logs_bloom: string;
    prev_randao: string;
    block_number: string;
    gas_limit: string;
    gas_used: string;
    timestamp: string;
    extra_data: string;
    base_fee_per_gas: string;
    block_hash: string;
    transactions_root: string;
    withdrawals_root: string;
    blob_gas_used: string;
    excess_blob_gas: string;
}

export interface LightClientHeaderJson {
    beacon: BeaconHeaderJson;
    execution: ExecutionPayloadHeaderJson;
    execution_branch: string[];
}

export interface SyncCommitteeJson {
    pubkeys: string[];
    aggregate_pubkey: string;
}

export interface SyncAggregateJson {
    sync_committee_bits: string;
    sync_committee_signature: string;
}

export interface FinalityUpdateJson {
    version: string;
    data: {
        attested_header: LightClientHeaderJson;
        finalized_header: LightClientHeaderJson;
        finality_branch: string[];
        sync_aggregate: SyncAggregateJson;
        signature_slot: string;
    };
}

export interface BootstrapJson {
    version: string;
    data: {
        header: LightClientHeaderJson;
        current_sync_committee: SyncCommitteeJson;
        current_sync_committee_branch: string[];
    };
}

export interface LightClientUpdateJson {
    version: string;
    data: {
        attested_header: LightClientHeaderJson;
        next_sync_committee: SyncCommitteeJson;
        next_sync_committee_branch: string[];
        finalized_header: LightClientHeaderJson;
        finality_branch: string[];
        sync_aggregate: SyncAggregateJson;
        signature_slot: string;
    };
}

/// Everything a light-client proof needs (no execution-layer proofs).
export interface BeaconCapture {
    network: string;
    capturedAt: string;
    sources: {beaconApi: string; executionRpc: string};
    genesisValidatorsRoot: string;
    /// Subset of `/eth/v1/config/spec`: every `*_FORK_VERSION` / `*_FORK_EPOCH` plus the period constants.
    spec: Record<string, string>;
    finalityUpdate: FinalityUpdateJson;
    /// `light_client/bootstrap/{hash_tree_root(finalized_header)}` — current committee of that period.
    bootstrap: BootstrapJson;
    /// Present only when the signature slot is one period past the bootstrap: that period's update,
    /// whose `next_sync_committee` is the signing committee.
    committeeUpdate?: LightClientUpdateJson;
    /// `light_client/updates?start_period={signing period}` — a real rotation (`next_sync_committee`
    /// + branch against the attested state root), signed by the same committee.
    rotationUpdate?: LightClientUpdateJson;
}

export interface LiveCapture extends BeaconCapture {
    account: {
        address: string;
        blockNumber: string;
        block: {hash: string; stateRoot: string; number: string};
        proof: EthGetProofResult & {address: string; balance: string; nonce: string; storageHash: string};
        storageKeys: string[];
    };
}

// ── SSZ helpers ────────────────────────────────────────────────────────────
function sha256(...parts: Buffer[]): Buffer {
    const h = createHash("sha256");
    for (const p of parts) h.update(p);
    return h.digest();
}

function uint64Chunk(dec: string): Buffer {
    const b = Buffer.alloc(32);
    b.writeBigUInt64LE(BigInt(dec), 0);
    return b;
}

function uint256Chunk(dec: string): Buffer {
    let v = BigInt(dec);
    const b = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) {
        b[i] = Number(v & 0xffn);
        v >>= 8n;
    }
    return b;
}

function rightPad32(buf: Buffer): Buffer {
    if (buf.length > 32) throw new Error("rightPad32: input longer than 32 bytes");
    return Buffer.concat([buf, Buffer.alloc(32 - buf.length)]);
}

/// Merkle levels (leaves first) over `leaves` zero-padded to `width` (a power of two).
function merkleLevels(leaves: Buffer[], width: number): Buffer[][] {
    if (width & (width - 1)) throw new Error("merkle width must be a power of two");
    if (leaves.length > width) throw new Error("too many leaves");
    const base = [...leaves];
    while (base.length < width) base.push(Buffer.alloc(32));
    const levels = [base];
    while (levels[levels.length - 1].length > 1) {
        const prev = levels[levels.length - 1];
        const next: Buffer[] = [];
        for (let i = 0; i < prev.length; i += 2) next.push(sha256(prev[i], prev[i + 1]));
        levels.push(next);
    }
    return levels;
}

function merkleRoot(leaves: Buffer[], width: number): Buffer {
    const lv = merkleLevels(leaves, width);
    return lv[lv.length - 1][0];
}

function merkleBranch(levels: Buffer[][], index: number): Buffer[] {
    const out: Buffer[] = [];
    let idx = index;
    for (let l = 0; l < levels.length - 1; l++) {
        out.push(levels[l][idx ^ 1]);
        idx >>= 1;
    }
    return out;
}

/// SSZ ByteVector[N] root (N a multiple of 32).
function byteVectorRoot(buf: Buffer): Buffer {
    const chunks: Buffer[] = [];
    for (let i = 0; i < buf.length; i += 32) chunks.push(rightPad32(buf.subarray(i, i + 32)));
    let width = 1;
    while (width < chunks.length) width <<= 1;
    return merkleRoot(chunks, width);
}

/// SSZ ByteList[32] root: mix_in_length(merkleize(pack(data), limit=1 chunk), len).
function extraDataRoot(buf: Buffer): Buffer {
    if (buf.length > 32) throw new Error("extra_data exceeds MAX_EXTRA_DATA_BYTES (32)");
    return sha256(rightPad32(buf), uint64Chunk(String(buf.length)));
}

/// The 17 ExecutionPayloadHeader field roots (Deneb layout; unchanged in Electra and Fulu).
export function executionPayloadHeaderLeaves(e: ExecutionPayloadHeaderJson): Buffer[] {
    return [
        hexToBuf(e.parent_hash),
        rightPad32(hexToBuf(e.fee_recipient)),
        hexToBuf(e.state_root),
        hexToBuf(e.receipts_root),
        byteVectorRoot(hexToBuf(e.logs_bloom)),
        hexToBuf(e.prev_randao),
        uint64Chunk(e.block_number),
        uint64Chunk(e.gas_limit),
        uint64Chunk(e.gas_used),
        uint64Chunk(e.timestamp),
        extraDataRoot(hexToBuf(e.extra_data)),
        uint256Chunk(e.base_fee_per_gas),
        hexToBuf(e.block_hash),
        hexToBuf(e.transactions_root),
        hexToBuf(e.withdrawals_root),
        uint64Chunk(e.blob_gas_used),
        uint64Chunk(e.excess_blob_gas)
    ];
}

/// Build the 9-sibling `state_root → body_root` branch the verifier expects (gindex 802), checking
/// every intermediate root against the header. Throws on any mismatch.
export function buildExecutionStateRootBranch(h: LightClientHeaderJson): {
    stateRoot: Buffer;
    branch: Buffer[];
    payloadHeaderRoot: Buffer;
} {
    const leaves = executionPayloadHeaderLeaves(h.execution);
    const levels = merkleLevels(leaves, 1 << EXECUTION_PAYLOAD_HEADER_DEPTH);
    const payloadHeaderRoot = levels[EXECUTION_PAYLOAD_HEADER_DEPTH][0];
    const bodyRoot = hexToBuf(h.beacon.body_root);
    const lcBranch = h.execution_branch.map(hexToBuf);
    if (lcBranch.length !== 4) throw new Error(`execution_branch depth ${lcBranch.length} != 4`);
    if (!foldSszBranch(payloadHeaderRoot, lcBranch, EXECUTION_PAYLOAD_GINDEX_IN_BODY).equals(bodyRoot)) {
        throw new Error("rebuilt ExecutionPayloadHeader root does not fold to body_root via execution_branch");
    }
    const inner = merkleBranch(levels, STATE_ROOT_FIELD_INDEX);
    const branch = [...inner, ...lcBranch];
    const stateRoot = hexToBuf(h.execution.state_root);
    if (branch.length !== EXECUTION_BRANCH_DEPTH) throw new Error("execution state-root branch depth != 9");
    if (!foldSszBranch(stateRoot, branch, GINDEX_EXECUTION_STATE_ROOT_IN_BODY).equals(bodyRoot)) {
        throw new Error("state_root does not fold to body_root at gindex 802");
    }
    return {stateRoot, branch, payloadHeaderRoot};
}

// ── Fork / domain helpers ──────────────────────────────────────────────────
const FORK_ORDER = ["GENESIS", "ALTAIR", "BELLATRIX", "CAPELLA", "DENEB", "ELECTRA", "FULU", "GLOAS"];

/// Spec `compute_fork_version(epoch)` over the `config/spec` schedule.
export function computeForkVersion(spec: Record<string, string>, epoch: bigint): Hex {
    let version = spec.GENESIS_FORK_VERSION;
    for (const fork of FORK_ORDER.slice(1)) {
        const ep = spec[`${fork}_FORK_EPOCH`];
        const v = spec[`${fork}_FORK_VERSION`];
        if (ep === undefined || v === undefined) continue;
        if (epoch >= BigInt(ep)) version = v;
    }
    return version as Hex;
}

/// Light-client `fork_version` for a sync aggregate: `compute_fork_version(epoch(max(signature_slot, 1) - 1))`.
export function signatureForkVersion(spec: Record<string, string>, signatureSlot: bigint): Hex {
    const slot = (signatureSlot > 1n ? signatureSlot : 1n) - 1n;
    return computeForkVersion(spec, slot / BigInt(spec.SLOTS_PER_EPOCH));
}

function slotsPerPeriod(spec: Record<string, string>): bigint {
    return BigInt(spec.SLOTS_PER_EPOCH) * BigInt(spec.EPOCHS_PER_SYNC_COMMITTEE_PERIOD);
}

// ── BLS helpers ────────────────────────────────────────────────────────────
const G1 = bls12_381.G1.ProjectivePoint;
const G2 = bls12_381.G2.ProjectivePoint;

export interface DecodedCommittee {
    pubkeys: Buffer[]; // 128-byte EIP-2537 uncompressed
    aggregate: Buffer; // 128-byte EIP-2537 uncompressed
    compressedPubkeys: Buffer[];
    compressedAggregate: Buffer;
    points: InstanceType<typeof G1>[];
}

/// Decompress a beacon SyncCommittee (48-byte keys) to EIP-2537 uncompressed points, and check the
/// published aggregate equals Σ pubkeys.
export function decodeCommittee(c: SyncCommitteeJson): DecodedCommittee {
    if (c.pubkeys.length !== SYNC_COMMITTEE_SIZE) throw new Error(`committee has ${c.pubkeys.length} keys`);
    const compressedPubkeys = c.pubkeys.map(hexToBuf);
    const points = compressedPubkeys.map((k) => G1.fromHex(k)); // validates on-curve + subgroup
    let sum = G1.ZERO;
    for (const p of points) sum = sum.add(p);
    const compressedAggregate = hexToBuf(c.aggregate_pubkey);
    const agg = G1.fromHex(compressedAggregate);
    if (!agg.equals(sum)) throw new Error("aggregate_pubkey != Σ committee pubkeys");
    return {
        pubkeys: points.map(g1ToUncompressed),
        aggregate: g1ToUncompressed(agg),
        compressedPubkeys,
        compressedAggregate,
        points
    };
}

/// Bitvector[512] (LSB-first within each byte) → per-member participation flags.
export function participationFromBits(bits: Buffer): boolean[] {
    if (bits.length !== SYNC_BITS_LENGTH) throw new Error(`sync bits length ${bits.length} != 64`);
    return Array.from({length: SYNC_COMMITTEE_SIZE}, (_, i) => ((bits[i >> 3] >> (i & 7)) & 1) === 1);
}

/// Off-chain check that `signature` is the participants' aggregate over `signingRoot` (POP DST):
/// e(Σpk, H(m)) == e(G1, sig).
function blsVerifyOffchain(
    committee: DecodedCommittee,
    participants: boolean[],
    signingRoot: Buffer,
    signature: InstanceType<typeof G2>
): boolean {
    let aggPk = G1.ZERO;
    committee.points.forEach((p, i) => {
        if (participants[i]) aggPk = aggPk.add(p);
    });
    const lhs = bls12_381.pairing(aggPk, hashToG2(signingRoot));
    const rhs = bls12_381.pairing(G1.BASE, signature);
    return bls12_381.fields.Fp12.eql(lhs, rhs);
}

function headerRoot(h: BeaconHeaderJson): Buffer {
    return beaconBlockHeaderRoot(
        BigInt(h.slot),
        BigInt(h.proposer_index),
        hexToBuf(h.parent_root),
        hexToBuf(h.state_root),
        hexToBuf(h.body_root)
    );
}

function hex(b: Buffer): Hex {
    return ("0x" + b.toString("hex")) as Hex;
}

/// Beacon SSZ `hash_tree_root(BeaconBlockHeader)` from the API JSON.
export function beaconHeaderRoot(h: BeaconHeaderJson): Hex {
    return hex(headerRoot(h));
}

// ── Sync-aggregate → verifier inputs ───────────────────────────────────────
export interface SignedHeaderInputs {
    attestedHeaderRlp: Input;
    beaconBlockRoot: Buffer;
    bits: Buffer;
    signatureUncompressed: Buffer;
    participants: number;
    nonSignerEntries: Buffer[];
    forkVersion: Hex;
    signingRoot: Buffer;
}

function signedHeaderInputs(
    capture: BeaconCapture,
    committee: DecodedCommittee,
    attested: BeaconHeaderJson,
    agg: SyncAggregateJson,
    signatureSlot: bigint
): SignedHeaderInputs {
    const bits = hexToBuf(agg.sync_committee_bits);
    const participantsArr = participationFromBits(bits);
    const participants = participantsArr.filter(Boolean).length;
    const sig = G2.fromHex(hexToBuf(agg.sync_committee_signature)); // 96-byte compressed → point
    const forkVersion = signatureForkVersion(capture.spec, signatureSlot);
    const beaconBlockRoot = headerRoot(attested);
    const domain = computeSyncCommitteeDomain(hexToBuf(forkVersion), hexToBuf(capture.genesisValidatorsRoot));
    const signingRoot = computeSigningRoot(beaconBlockRoot, domain);
    if (!blsVerifyOffchain(committee, participantsArr, signingRoot, sig)) {
        throw new Error(`off-chain BLS check failed for attested slot ${attested.slot} (fork ${forkVersion})`);
    }
    return {
        attestedHeaderRlp: [
            bigintToTrimmedBuf(BigInt(attested.slot)),
            bigintToTrimmedBuf(BigInt(attested.proposer_index)),
            hexToBuf(attested.parent_root),
            hexToBuf(attested.state_root),
            hexToBuf(attested.body_root)
        ],
        beaconBlockRoot,
        bits,
        signatureUncompressed: g2ToUncompressed(sig),
        participants,
        nonSignerEntries: nonSignerProofEntries(committee.pubkeys, participantsArr),
        forkVersion,
        signingRoot
    };
}

// ── Committee selection ────────────────────────────────────────────────────
/// SSZ `current_sync_committee` gindex in BeaconState: 54 (depth 5) through Deneb, 86 (depth 6) from Electra.
function currentCommitteeGindex(version: string): bigint {
    return SUPPORTED_FORKS.has(version) ? 86n : 54n;
}

/// The committee that signed the finality update, authenticated off-chain against the bootstrap
/// header's state root (or the committee update's attested state root).
export function signingCommittee(capture: BeaconCapture): {committee: DecodedCommittee; period: bigint} {
    const spp = slotsPerPeriod(capture.spec);
    const sigPeriod = BigInt(capture.finalityUpdate.data.signature_slot) / spp;
    const boot = capture.bootstrap.data;
    const bootPeriod = BigInt(boot.header.beacon.slot) / spp;
    if (sigPeriod === bootPeriod) {
        const root = syncCommitteeRootFromCompressed(
            boot.current_sync_committee.pubkeys.map(hexToBuf),
            hexToBuf(boot.current_sync_committee.aggregate_pubkey)
        );
        const gi = currentCommitteeGindex(capture.bootstrap.version);
        if (!foldSszBranch(root, boot.current_sync_committee_branch.map(hexToBuf), gi)
            .equals(hexToBuf(boot.header.beacon.state_root))) {
            throw new Error("bootstrap current_sync_committee_branch does not verify against its state_root");
        }
        return {committee: decodeCommittee(boot.current_sync_committee), period: sigPeriod};
    }
    if (sigPeriod === bootPeriod + 1n && capture.committeeUpdate) {
        const u = capture.committeeUpdate.data;
        verifyNextCommitteeBranch(u);
        return {committee: decodeCommittee(u.next_sync_committee), period: sigPeriod};
    }
    throw new Error(`no committee for signature period ${sigPeriod} (bootstrap period ${bootPeriod})`);
}

function verifyNextCommitteeBranch(u: LightClientUpdateJson["data"]): void {
    const root = syncCommitteeRootFromCompressed(
        u.next_sync_committee.pubkeys.map(hexToBuf),
        hexToBuf(u.next_sync_committee.aggregate_pubkey)
    );
    const branch = u.next_sync_committee_branch.map(hexToBuf);
    if (branch.length !== NEXT_COMMITTEE_BRANCH_DEPTH) {
        throw new Error(`next_sync_committee_branch depth ${branch.length} != ${NEXT_COMMITTEE_BRANCH_DEPTH}`);
    }
    if (!foldSszBranch(root, branch, GINDEX_NEXT_SYNC_COMMITTEE_IN_STATE)
        .equals(hexToBuf(u.attested_header.beacon.state_root))) {
        throw new Error("next_sync_committee_branch does not verify at gindex 87");
    }
}

// ── Main builder ───────────────────────────────────────────────────────────
export interface EthLiveProof {
    /// `verifyBundle(proofBytes, trustAnchor, channelContext)` inputs.
    proofBytes: Hex;
    trustAnchor: Hex;
    channelContext: Hex;
    channelId: Hex;
    account: Hex;
    codeHash: Hex;
    meta: {
        network: string;
        forkName: string;
        attestedSlot: bigint;
        signatureSlot: bigint;
        period: bigint;
        forkVersion: Hex;
        genesisValidatorsRoot: Hex;
        participants: number;
        nonSigners: number;
        executionBlockNumber: bigint;
        executionStateRoot: Hex;
        beaconBlockRoot: Hex;
        committeeMerkleRoot: Hex;
        accountProofNodes: number;
    };
    /// Pieces reused by the negative tests / harness.
    parts: {
        attestedHeader: Input;
        syncAggregate: [Buffer, Buffer];
        executionStateRoot: Buffer;
        executionBranch: Buffer[];
        accountProof: Buffer[];
        storageProof: Input;
        nonSignerEntries: Buffer[];
    };
    /// A real sync-committee rotation (from `light_client/updates`), for the rotation harness.
    rotation?: {
        rotationRlp: Hex; // RLP[nextCommittee(uncompressed), nextCommitteeBranch]
        attestedStateRoot: Hex;
        beaconBlockRoot: Hex;
        bits: Hex;
        signature: Hex;
        nonSignerWrapperRlp: Hex; // RLP[[entries]]
        forkVersion: Hex;
        participants: number;
        nextPeriod: bigint;
        nextCommitteeMerkleRoot: Hex;
        nextAggregate: Hex;
    };
}

/// The light-client half of a live proof: the signed attested header and the execution state_root
/// branch, cross-checked (committee branch, aggregate, off-chain BLS, SSZ folds). Shared by
/// `EthMainnetVerifier` bundles and the `EthL1StateVerifier` proofs of the OP Stack verifiers.
export interface LiveLightClient {
    committee: DecodedCommittee;
    period: bigint;
    signatureSlot: bigint;
    signed: SignedHeaderInputs;
    exec: {stateRoot: Buffer; branch: Buffer[]};
    /// `EthL1StateVerifier.verifyL1State` proof: RLP `[attestedHeader, syncAggregate, executionStateRoot,
    /// executionBranch, nextCommittee(empty), nextCommitteeBranch(empty), nonSignerProofs]`.
    lightClientProof: Hex;
}

export function buildLiveLightClient(capture: BeaconCapture): LiveLightClient {
    const fu = capture.finalityUpdate;
    if (!SUPPORTED_FORKS.has(fu.version)) {
        throw new Error(`unsupported light-client fork "${fu.version}" (supported: ${[...SUPPORTED_FORKS]})`);
    }
    const attested = fu.data.attested_header;
    const signatureSlot = BigInt(fu.data.signature_slot);
    const {committee, period} = signingCommittee(capture);
    const signed = signedHeaderInputs(capture, committee, attested.beacon, fu.data.sync_aggregate, signatureSlot);
    const exec = buildExecutionStateRootBranch(attested);
    const lightClientProof = hex(rlpEncode([
        signed.attestedHeaderRlp,
        [signed.bits, signed.signatureUncompressed],
        exec.stateRoot,
        exec.branch,
        Buffer.alloc(0),
        [],
        signed.nonSignerEntries
    ]));
    return {committee, period, signatureSlot, signed, exec, lightClientProof};
}

/// A real sync-committee rotation as an `EthL1StateVerifier.verifyL1State` proof: the capture's
/// `rotationUpdate` (signed by the same committee as the finality update) with its next_sync_committee
/// and branch, so the verifier returns the successor anchor. Undefined when the capture has no
/// same-period update.
export interface LiveRotationLightClient {
    lightClientProof: Hex;
    executionBlockNumber: bigint;
    executionStateRoot: Hex;
    participants: number;
    nextPeriod: bigint;
    nextCommitteeMerkleRoot: Hex;
    nextAggregate: Hex;
}

export function buildLiveRotationLightClient(capture: BeaconCapture): LiveRotationLightClient | undefined {
    const ru = capture.rotationUpdate;
    if (!ru || !SUPPORTED_FORKS.has(ru.version)) return undefined;
    const {committee, period} = signingCommittee(capture);
    const spp = slotsPerPeriod(capture.spec);
    const u = ru.data;
    if (BigInt(u.signature_slot) / spp !== period) return undefined;
    verifyNextCommitteeBranch(u);
    const rs = signedHeaderInputs(capture, committee, u.attested_header.beacon, u.sync_aggregate, BigInt(u.signature_slot));
    const exec = buildExecutionStateRootBranch(u.attested_header);
    const next = decodeCommittee(u.next_sync_committee);
    const lightClientProof = hex(rlpEncode([
        rs.attestedHeaderRlp,
        [rs.bits, rs.signatureUncompressed],
        exec.stateRoot,
        exec.branch,
        [next.pubkeys, next.aggregate],
        u.next_sync_committee_branch.map(hexToBuf),
        rs.nonSignerEntries
    ]));
    return {
        lightClientProof,
        executionBlockNumber: BigInt(u.attested_header.execution.block_number),
        executionStateRoot: u.attested_header.execution.state_root as Hex,
        participants: rs.participants,
        nextPeriod: BigInt(u.attested_header.beacon.slot) / spp + 1n,
        nextCommitteeMerkleRoot: hex(committeeMerkleRoot(next.pubkeys)),
        nextAggregate: hex(next.aggregate)
    };
}

/// Pure/offline: turn a `LiveCapture` into the verifier's wire format, cross-checking every step
/// (committee branch, aggregate, off-chain BLS, SSZ folds, execution block binding).
export function buildEthLiveProof(capture: LiveCapture): EthLiveProof {
    const fu = capture.finalityUpdate;
    const attested = fu.data.attested_header;
    const {committee, period, signatureSlot, signed, exec} = buildLiveLightClient(capture);

    // Execution-layer binding: eth_getProof was taken at the attested header's execution block.
    const acct = capture.account;
    if (BigInt(acct.block.number) !== BigInt(attested.execution.block_number)) {
        throw new Error("captured execution block != attested execution block_number");
    }
    if (acct.block.stateRoot.toLowerCase() !== attested.execution.state_root.toLowerCase()) {
        throw new Error("execution block stateRoot != attested execution.state_root");
    }
    if (acct.block.hash.toLowerCase() !== attested.execution.block_hash.toLowerCase()) {
        throw new Error("execution block hash != attested execution.block_hash");
    }

    const channelId = LIVE_CHANNEL_ID;
    const slots = deriveChannelSlots(channelId);
    const byKey = new Map(acct.proof.storageProof.map((sp) => [BigInt(sp.key), sp]));
    const storageProof = slots.map((k) => {
        const sp = byKey.get(BigInt(k));
        if (!sp) throw new Error(`capture missing storage proof for slot ${k}`);
        return [hexToBuf(k), sp.proof.map(hexToBuf)];
    });
    const accountProof = acct.proof.accountProof.map(hexToBuf);
    const syncAggregate: [Buffer, Buffer] = [signed.bits, signed.signatureUncompressed];

    const proofBytes = rlpEncode([
        signed.attestedHeaderRlp, // 0 attested header
        syncAggregate, // 1 [bits, uncompressed G2 signature]
        exec.stateRoot, // 2 execution state root
        exec.branch, // 3 9 SSZ siblings (gindex 802)
        Buffer.alloc(0), // 4 no rotation (empty string)
        [], // 5 no rotation branch (empty list)
        accountProof, // 6
        storageProof, // 7 channelId-derived slots (exclusion proofs here)
        Buffer.alloc(0), // 8 empty ClprBundleContent
        signed.nonSignerEntries // 9 one key‖proof per clear bit
    ]);

    const gvr = capture.genesisValidatorsRoot as Hex;
    const codeHash = acct.proof.codeHash as Hex;
    const trustAnchor = encodeEthTrustAnchor(channelId, codeHash, committee, {gvr, forkVersion: signed.forkVersion});
    const account = acct.address.toLowerCase() as Hex;
    const channelContext = (channelId + account.slice(2)) as Hex;

    const out: EthLiveProof = {
        proofBytes: hex(proofBytes),
        trustAnchor,
        channelContext,
        channelId,
        account,
        codeHash,
        meta: {
            network: capture.network,
            forkName: fu.version,
            attestedSlot: BigInt(attested.beacon.slot),
            signatureSlot,
            period,
            forkVersion: signed.forkVersion,
            genesisValidatorsRoot: gvr,
            participants: signed.participants,
            nonSigners: SYNC_COMMITTEE_SIZE - signed.participants,
            executionBlockNumber: BigInt(attested.execution.block_number),
            executionStateRoot: hex(exec.stateRoot),
            beaconBlockRoot: hex(signed.beaconBlockRoot),
            committeeMerkleRoot: hex(committeeMerkleRoot(committee.pubkeys)),
            accountProofNodes: accountProof.length
        },
        parts: {
            attestedHeader: signed.attestedHeaderRlp,
            syncAggregate,
            executionStateRoot: exec.stateRoot,
            executionBranch: exec.branch,
            accountProof,
            storageProof,
            nonSignerEntries: signed.nonSignerEntries
        }
    };

    // Optional real rotation, signed by the same committee (same period).
    const ru = capture.rotationUpdate;
    if (ru && SUPPORTED_FORKS.has(ru.version)) {
        const spp = slotsPerPeriod(capture.spec);
        const u = ru.data;
        if (BigInt(u.signature_slot) / spp === period) {
            verifyNextCommitteeBranch(u);
            const rs = signedHeaderInputs(
                capture, committee, u.attested_header.beacon, u.sync_aggregate, BigInt(u.signature_slot)
            );
            const next = decodeCommittee(u.next_sync_committee);
            out.rotation = {
                rotationRlp: hex(rlpEncode([[next.pubkeys, next.aggregate], u.next_sync_committee_branch.map(hexToBuf)])),
                attestedStateRoot: u.attested_header.beacon.state_root as Hex,
                beaconBlockRoot: hex(rs.beaconBlockRoot),
                bits: hex(rs.bits),
                signature: hex(rs.signatureUncompressed),
                nonSignerWrapperRlp: hex(rlpEncode([rs.nonSignerEntries])),
                forkVersion: rs.forkVersion,
                participants: rs.participants,
                nextPeriod: BigInt(u.attested_header.beacon.slot) / spp + 1n,
                nextCommitteeMerkleRoot: hex(committeeMerkleRoot(next.pubkeys)),
                nextAggregate: hex(next.aggregate)
            };
        }
    }
    return out;
}

/// Re-encode the bundle with one part replaced (negative tests).
export function reencodeBundle(p: EthLiveProof["parts"], override: Partial<EthLiveProof["parts"]>): Hex {
    const q = {...p, ...override};
    return hex(rlpEncode([
        q.attestedHeader,
        q.syncAggregate,
        q.executionStateRoot,
        q.executionBranch,
        Buffer.alloc(0),
        [],
        q.accountProof,
        q.storageProof,
        Buffer.alloc(0),
        q.nonSignerEntries
    ]));
}

// ── Live capture ───────────────────────────────────────────────────────────
export async function getJson<T>(bases: string[], p: string): Promise<{json: T; base: string}> {
    let lastErr: unknown;
    for (const base of bases) {
        try {
            const res = await fetch(base + p, {headers: {accept: "application/json"}});
            if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
            return {json: (await res.json()) as T, base};
        } catch (err) {
            lastErr = err;
        }
    }
    throw new Error(`GET ${p} failed on all beacon APIs: ${String(lastErr)}`);
}

let rpcId = 0;
export async function rpc<T>(url: string, method: string, params: unknown[]): Promise<T> {
    const res = await fetch(url, {
        method: "POST",
        headers: {"content-type": "application/json"},
        body: JSON.stringify({jsonrpc: "2.0", id: ++rpcId, method, params})
    });
    const j = (await res.json()) as {result?: T; error?: {message: string}};
    if (j.error) throw new Error(`${method}: ${j.error.message}`);
    return j.result as T;
}

/// Capture a consistent beacon dataset: finality update → `onAttested` (execution-layer reads at the
/// attested block, run immediately while a non-archive node still has that state) → signing committee
/// → a same-period rotation update.
export async function captureBeaconLive<T>(opts: {
    beaconApis?: string[];
    /// Poll (one slot at a time) for up to this long for an update with at least one non-signer, so
    /// the fixture exercises the non-signer Merkle proofs + complement aggregation. Sepolia usually
    /// runs at 512/512; a partial aggregate shows up every few minutes. 0 = take the first update.
    waitForNonSignersMs?: number;
}, onAttested: (execution: ExecutionPayloadHeaderJson, blockTag: Hex) => Promise<T>): Promise<{
    beacon: BeaconCapture;
    extra: T;
}> {
    const apis = opts.beaconApis ?? DEFAULT_BEACON_APIS;
    const deadline = Date.now() + (opts.waitForNonSignersMs ?? 0);
    let fu: FinalityUpdateJson;
    let base: string;
    let lastSig = "";
    for (;;) {
        ({json: fu, base} = await getJson<FinalityUpdateJson>(apis, "/eth/v1/beacon/light_client/finality_update"));
        const n = participationFromBits(hexToBuf(fu.data.sync_aggregate.sync_committee_bits)).filter(Boolean).length;
        if (fu.data.signature_slot !== lastSig) {
            console.error(`finality_update signature_slot ${fu.data.signature_slot}: ${n}/512`);
            lastSig = fu.data.signature_slot;
        }
        if (n < SYNC_COMMITTEE_SIZE || Date.now() >= deadline) break;
        await new Promise((r) => setTimeout(r, 4000));
    }
    const order = [base, ...apis.filter((a) => a !== base)];
    const execution = fu.data.attested_header.execution;
    const blockTag = ("0x" + BigInt(execution.block_number).toString(16)) as Hex;
    const extra = await onAttested(execution, blockTag);

    const {json: genesis} = await getJson<{data: {genesis_validators_root: string}}>(order, "/eth/v1/beacon/genesis");
    const {json: specRaw} = await getJson<{data: Record<string, string>}>(order, "/eth/v1/config/spec");
    const spec: Record<string, string> = {};
    for (const [k, v] of Object.entries(specRaw.data)) {
        if (/_FORK_(VERSION|EPOCH)$/.test(k) || ["CONFIG_NAME", "PRESET_BASE", "SLOTS_PER_EPOCH",
            "EPOCHS_PER_SYNC_COMMITTEE_PERIOD", "SYNC_COMMITTEE_SIZE"].includes(k)) {
            spec[k] = v;
        }
    }

    const finalizedRoot = beaconHeaderRoot(fu.data.finalized_header.beacon);
    const {json: bootstrap} = await getJson<BootstrapJson>(order, `/eth/v1/beacon/light_client/bootstrap/${finalizedRoot}`);

    const spp = slotsPerPeriod(spec);
    const sigPeriod = BigInt(fu.data.signature_slot) / spp;
    const bootPeriod = BigInt(bootstrap.data.header.beacon.slot) / spp;
    let committeeUpdate: LightClientUpdateJson | undefined;
    if (sigPeriod === bootPeriod + 1n) {
        const {json} = await getJson<LightClientUpdateJson[]>(
            order, `/eth/v1/beacon/light_client/updates?start_period=${bootPeriod}&count=1`
        );
        committeeUpdate = json[0];
    }
    let rotationUpdate: LightClientUpdateJson | undefined;
    try {
        const {json} = await getJson<LightClientUpdateJson[]>(
            order, `/eth/v1/beacon/light_client/updates?start_period=${sigPeriod}&count=1`
        );
        rotationUpdate = json[0];
    } catch {
        rotationUpdate = undefined;
    }

    return {
        beacon: {
            network: spec.CONFIG_NAME ?? "unknown",
            capturedAt: new Date().toISOString(),
            sources: {beaconApi: base, executionRpc: ""},
            genesisValidatorsRoot: genesis.data.genesis_validators_root,
            spec,
            finalityUpdate: fu,
            bootstrap,
            committeeUpdate,
            rotationUpdate
        },
        extra
    };
}

/// Capture a consistent live dataset: the beacon part plus `eth_getProof` of `account` (with the
/// channelId-derived slots) at the attested execution block.
export async function captureSepoliaLive(opts: {
    beaconApis?: string[];
    executionRpc?: string;
    account?: Hex;
    waitForNonSignersMs?: number;
} = {}): Promise<LiveCapture> {
    const rpcUrl = opts.executionRpc ?? DEFAULT_EXECUTION_RPC;
    const address = opts.account ?? DEFAULT_ACCOUNT;
    const storageKeys = deriveChannelSlots(LIVE_CHANNEL_ID);
    const {beacon, extra: account} = await captureBeaconLive(opts, async (execution, blockTag) => {
        const proof = await rpc<LiveCapture["account"]["proof"]>(rpcUrl, "eth_getProof", [address, storageKeys, blockTag]);
        const block = await rpc<{hash: string; stateRoot: string; number: string}>(
            rpcUrl, "eth_getBlockByNumber", [blockTag, false]
        );
        return {address, blockNumber: execution.block_number, block, proof, storageKeys};
    });
    return {...beacon, sources: {beaconApi: beacon.sources.beaconApi, executionRpc: rpcUrl}, account};
}

export function loadLiveCapture(file = SEPOLIA_LIVE_FIXTURE): LiveCapture {
    return JSON.parse(readFileSync(file, "utf8")) as LiveCapture;
}

function summarize(p: EthLiveProof): string {
    const m = p.meta;
    return [
        `network            ${m.network} (${m.forkName}, fork version ${m.forkVersion})`,
        `attested slot      ${m.attestedSlot} (signature slot ${m.signatureSlot}, period ${m.period})`,
        `participation      ${m.participants}/512 (${m.nonSigners} non-signer proofs)`,
        `execution block    ${m.executionBlockNumber} state_root ${m.executionStateRoot}`,
        `account            ${p.account} codeHash ${p.codeHash} (${m.accountProofNodes} MPT nodes)`,
        `proofBytes         ${(p.proofBytes.length - 2) / 2} bytes`,
        `trustAnchor        ${(p.trustAnchor.length - 2) / 2} bytes`,
        `rotation           ${p.rotation ? `next period ${p.rotation.nextPeriod}, ${(p.rotation.rotationRlp.length - 2) / 2} bytes` : "none"}`
    ].join("\n");
}

async function main(): Promise<void> {
    const args = process.argv.slice(2);
    const outIdx = args.indexOf("--out");
    const file = outIdx >= 0 ? path.resolve(args[outIdx + 1]) : SEPOLIA_LIVE_FIXTURE;
    let capture: LiveCapture;
    if (args.includes("--refresh")) {
        const accIdx = args.indexOf("--account");
        const waitIdx = args.indexOf("--wait-nonsigners");
        capture = await captureSepoliaLive({
            account: accIdx >= 0 ? (args[accIdx + 1] as Hex) : undefined,
            waitForNonSignersMs: waitIdx >= 0 ? Number(args[waitIdx + 1]) * 1000 : 0
        });
        buildEthLiveProof(capture); // validate before overwriting the fixture
        mkdirSync(path.dirname(file), {recursive: true});
        writeFileSync(file, JSON.stringify(capture, null, 1) + "\n");
        console.log(`captured → ${path.relative(process.cwd(), file)}`);
    } else {
        capture = loadLiveCapture(file);
    }
    console.log(summarize(buildEthLiveProof(capture)));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    main().catch((err) => {
        console.error(err);
        process.exit(1);
    });
}
