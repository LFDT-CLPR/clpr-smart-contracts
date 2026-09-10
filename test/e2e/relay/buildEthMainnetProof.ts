import {type Hex, keccak256, encodeAbiParameters} from "viem";
import {type Input} from "@ethereumjs/rlp";
import {createHash} from "node:crypto";
import {pbBytes} from "../lib/proto.js";
import {rlpEncode, hexToBuf} from "../lib/rlp.js";
import {type BlsCommittee, aggregateSign} from "./bls.js";
import {
    beaconBlockHeaderRoot,
    computeSyncCommitteeDomain,
    computeSigningRoot,
    syncCommitteeRootFromCompressed
} from "./signingRoot.js";

/// Relay-side builder for `EthMainnetVerifier.verifyBundle` proofs.
///
/// Mirrors the Solidity verifier's 11-item RLP layout byte-for-byte — `EthMainnetVerifier`'s
/// `_encodeTrustAnchor` names this file as the reference, so the two must not drift:
///   [ 0: attestedHeader        [slot, proposerIndex, parentRoot, stateRoot, bodyRoot]
///     1: signatureSlot         the slot the committee SIGNED at (strictly after the attested
///                              header's slot); its period selects the window member
///     2: syncAggregate         [bits(64), signature(256)]
///     3: executionStateRoot
///     4: executionBranch       9 SSZ siblings (gindex 802)
///     5: nextCommittee         [uncompressedPubkeys[512], aggregate] or absent (empty RLP string)
///     6: nextCommitteeBranch   6 SSZ siblings (gindex 87) or absent (empty RLP list)
///     7: accountProof
///     8: storageProof
///     9: bundleContent
///    10: nonSignerProofs       one entry per clear participation bit (empty list at 512/512) ]
/// and the FLAT packed WINDOW trust anchor (428 B), holding `{ current, next }`:
///   gvr(32) ‖ forkVersion(4) ‖ channelId(32) ‖ codeHash(32) ‖ period(8)
///     ‖ [aggregate(128) ‖ committeeMerkleRoot(32)] × 2.
///
/// Pass `bls` to attach a real sync-committee signature (a committee + aggregate signature generated
/// with @noble/curves over the exact SSZ signing root); omit it to synthesize a placeholder committee
/// for tests that don't exercise BLS. Everything downstream of BLS is REAL either way:
///   - the SSZ execution branch is folded bottom-up so `verifyProof(stateRoot, branch, bodyRoot, 802)`
///     holds against the synthesized `bodyRoot`;
///   - the MPT account + channel-storage proofs come straight from `eth_getProof` against the live
///     chain, bound to the channelId-derived slots exactly as the verifier re-derives them.

export interface StorageProofEntry {
    key: string;
    value: string;
    proof: string[];
}

export interface EthGetProofResult {
    codeHash: string;
    accountProof: string[];
    storageProof: StorageProofEntry[];
}

export interface EthBundleProof {
    proofBytes: Hex;
    trustAnchor: Hex;
    channelId: Hex;
    codeHash: Hex;
}

// ── CLPR storage layout (matches ClprEvmBundleVerifier) ────────────────────
const CHANNELS_SLOT = 15n;
const MESSAGE_QUEUES_SLOT = 1n;
const MESSAGE_RUNNING_HASH_OFFSET = 1n;
const PROVEN_STRUCT_OFFSETS = [1n, 2n, 4n, 5n, 16n];

// ── Verifier constants ─────────────────────────────────────────────────────
const SYNC_COMMITTEE_SIZE = 512;
// Depth of the committee Merkle tree — derived so it cannot drift from the size (mirrors
// ClprCommitteeMerkle.sol's DEPTH = log2(COMMITTEE_SIZE)).
const COMMITTEE_MERKLE_DEPTH = Math.log2(SYNC_COMMITTEE_SIZE);
const BLS_PUBKEY_LENGTH = 128; // uncompressed EIP-2537 G1
const BLS_SIGNATURE_LENGTH = 256; // uncompressed EIP-2537 G2
const SYNC_BITS_LENGTH = 64; // Bitvector[512] / 8
const EXECUTION_BRANCH_DEPTH = 9;
const GINDEX_EXECUTION_STATE_ROOT_IN_BODY = 802n;
const NEXT_COMMITTEE_BRANCH_DEPTH = 6;
const GINDEX_NEXT_SYNC_COMMITTEE_IN_STATE = 87n;
const FORK_VERSION: Hex = "0x04000000"; // Deneb mainnet
const GVR = ("0x" + "11".repeat(32)) as Hex; // arbitrary genesis validators root

function mask256(n: bigint): bigint {
    return n & ((1n << 256n) - 1n);
}

function slotHex(n: bigint): Hex {
    return ("0x" + mask256(n).toString(16).padStart(64, "0")) as Hex;
}

function deriveChannelSlots(channelId: Hex): Hex[] {
    const cBase = BigInt(keccak256(encodeAbiParameters(
        [{type: "bytes32"}, {type: "uint256"}], [channelId, CHANNELS_SLOT]
    )));
    return PROVEN_STRUCT_OFFSETS.map((off) => slotHex(cBase + off));
}

function deriveMessageRunningHashSlot(channelId: Hex, messageId: bigint): Hex {
    const outer = BigInt(keccak256(encodeAbiParameters(
        [{type: "bytes32"}, {type: "uint256"}], [channelId, MESSAGE_QUEUES_SLOT]
    )));
    const inner = BigInt(keccak256(encodeAbiParameters(
        [{type: "uint256"}, {type: "uint256"}], [messageId, outer]
    )));
    return slotHex(inner + MESSAGE_RUNNING_HASH_OFFSET);
}

function sha256(...parts: Buffer[]): Buffer {
    const h = createHash("sha256");
    for (const p of parts) h.update(p);
    return h.digest();
}

/// Fold a leaf up to its SSZ Merkle root using the same rule as ClprBeaconSsz.verifyProof:
/// at each level, the gindex LSB selects whether the sibling is on the left.
function foldSszBranch(leaf: Buffer, branch: Buffer[], gindex: bigint): Buffer {
    let computed = leaf;
    let idx = gindex;
    for (const sib of branch) {
        computed = (idx & 1n) === 1n ? sha256(sib, computed) : sha256(computed, sib);
        idx >>= 1n;
    }
    return computed;
}

/// Synthetic 512-pubkey committee (BLS is bypassed by the harness, so the bytes are arbitrary; only
/// the lengths and 512-count must match what _decodeCommittee enforces).
function syntheticCommittee(): {pubkeys: Buffer[]; aggregate: Buffer} {
    const pubkeys: Buffer[] = [];
    for (let i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
        const pk = Buffer.alloc(BLS_PUBKEY_LENGTH, 0);
        pk.writeUInt16BE(i + 1, BLS_PUBKEY_LENGTH - 2); // non-zero, distinct
        pubkeys.push(pk);
    }
    return {pubkeys, aggregate: Buffer.alloc(BLS_PUBKEY_LENGTH, 0x07)};
}

// ── Committee Merkle commitment (mirrors ClprCommitteeMerkle.sol byte-for-byte) ──
// leaf_i = keccak256(uncompressedKey_i); parent = keccak256(left ‖ right); depth 9.

function keccakBuf(b: Buffer): Buffer {
    return hexToBuf(keccak256(("0x" + b.toString("hex")) as Hex));
}

/// All 10 levels of the tree, leaves (512) up to the root (1).
export function committeeMerkleLevels(keys: Buffer[]): Buffer[][] {
    if (keys.length !== SYNC_COMMITTEE_SIZE) throw new Error("committee must have exactly 512 keys");
    const levels: Buffer[][] = [keys.map((k) => keccakBuf(k))];
    while (levels[levels.length - 1].length > 1) {
        const prev = levels[levels.length - 1];
        const next: Buffer[] = [];
        for (let i = 0; i < prev.length; i += 2) {
            next.push(keccakBuf(Buffer.concat([prev[i], prev[i + 1]])));
        }
        levels.push(next);
    }
    return levels;
}

export function committeeMerkleRoot(keys: Buffer[]): Buffer {
    return committeeMerkleLevels(keys)[COMMITTEE_MERKLE_DEPTH][0];
}

/// 288-byte inclusion proof (9 bottom-up siblings) for the key at `index`.
export function committeeMerkleProof(levels: Buffer[][], index: number): Buffer {
    const sibs: Buffer[] = [];
    let idx = index;
    for (let level = 0; level < COMMITTEE_MERKLE_DEPTH; level++) {
        sibs.push(levels[level][idx ^ 1]);
        idx >>= 1;
    }
    return Buffer.concat(sibs);
}

/// Payload item 10: one `key(128) ‖ proof(288)` entry per clear participation bit, ascending order.
function nonSignerProofEntries(keys: Buffer[], participants: boolean[]): Buffer[] {
    const levels = committeeMerkleLevels(keys);
    const entries: Buffer[] = [];
    for (let i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
        if (!participants[i]) entries.push(Buffer.concat([keys[i], committeeMerkleProof(levels, i)]));
    }
    return entries;
}

/// Encode the FLAT packed trust anchor
///
/// Pass real committees to anchor against actual BLS pubkeys; otherwise a synthetic 512-committee is
/// used (only the lengths matter when BLS is bypassed by the harness).
export function encodeEthTrustAnchor(
    channelId: Hex,
    codeHash: Hex,
    committee?: {pubkeys: Buffer[]; aggregate: Buffer},
    nextCommittee?: {pubkeys: Buffer[]; aggregate: Buffer},
    period: bigint = 0n
): Hex {
    const current = committee ?? syntheticCommittee();
    const next = nextCommittee ?? syntheticCommittee();
    for (const c of [current, next]) {
        if (c.pubkeys.length !== SYNC_COMMITTEE_SIZE) throw new Error("trust anchor: expected 512 pubkeys");
    }
    const periodBytes = Buffer.alloc(8);
    periodBytes.writeBigUInt64BE(period);
    const anchor = Buffer.concat([
        hexToBuf(GVR),
        hexToBuf(FORK_VERSION),
        hexToBuf(channelId),
        hexToBuf(codeHash),
        periodBytes,
        current.aggregate,
        committeeMerkleRoot(current.pubkeys),
        next.aggregate,
        committeeMerkleRoot(next.pubkeys)
    ]);
    return ("0x" + anchor.toString("hex")) as Hex;
}

/// Beacon slots per sync-committee period — mirrors EthMainnetVerifier's mainnet preset.
export const SLOTS_PER_SYNC_COMMITTEE_PERIOD = 8192n;

/// Minimal big-endian RLP integer encoding: zero is the empty string, otherwise no leading zero byte.
function bigintToMinimalBuf(v: bigint): Buffer {
    if (v === 0n) return Buffer.alloc(0);
    let hex = v.toString(16);
    if (hex.length % 2 === 1) hex = "0" + hex;
    return Buffer.from(hex, "hex");
}

// Attested-header fields the verifier checks (bodyRoot) and that feed the BLS signing root. The
// slot/proposer here MUST equal the RLP-encoded values below so the signing root matches on-chain.
const DEFAULT_HEADER_SLOT = 1n;
const HEADER_PROPOSER_INDEX = 1n;

function bundleContentProto(payloads: Hex[]): Buffer {
    // ClprBundleContent: repeated field 2 (LEN) = message payloads.
    return Buffer.concat(payloads.map((p) => pbBytes(2, hexToBuf(p))));
}

let _rpcId = 0;
async function rpcCall<T>(rpcUrl: string, method: string, params: unknown[]): Promise<T> {
    const res = await fetch(rpcUrl, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({jsonrpc: "2.0", method, params, id: ++_rpcId})
    });
    const json = (await res.json()) as {result?: T; error?: {message: string}};
    if (json.error) throw new Error(`RPC ${method}: ${json.error.message}`);
    return json.result as T;
}

/// Build a verifyBundle proof for the given channel against the chain's current head.
/// `withMessages: true` adds the 5th (last-message running-hash) slot.
export async function buildEthMainnetProof(opts: {
    rpcUrl: string;
    serviceAddr: Hex;
    channelId: Hex;
    payloads: Hex[];
    lastMessageId?: bigint;
    /// When set, the trust anchor uses the real committee and the sync aggregate carries a real
    /// participation bitvector + aggregate BLS signature over the attested header's signing root, so
    /// `EthMainnetVerifier._verifyBls` (real EIP-2537 pairing) is exercised. When omitted, a synthetic
    /// committee + placeholder signature is used (for callers that don't exercise BLS).
    bls?: {
        committee: BlsCommittee;
        participants: boolean[];
        /// Sign with a different committee than the one in the trust anchor — yields a well-formed but
        /// cryptographically invalid signature (for negative tests). Defaults to `committee`.
        signWith?: BlsCommittee;
    };
    /// When set, the bundle carries a next-sync-committee rotation: `nextCommittee` holds both the
    /// compressed (proof-matching) and uncompressed (anchor-stored) keys, and the beacon stateRoot is
    /// folded so the synthesized `nextCommitteeBranch` proves the committee root at gindex 87. The
    /// returned bundle's successor anchor is the uncompressed `rotation.committee`.
    /// `mismatchUncompressed: true` corrupts one uncompressed key so the on-chain compress-and-compare
    /// fails (for negative tests).
    rotation?: {committee: BlsCommittee; mismatchUncompressed?: boolean};
    /// Slot of the attested beacon header. `signatureSlot` is always this + 1, so both sit in the same
    /// sync-committee period. Defaults to slot 1 (period 0).
    headerSlot?: bigint;
    /// The anchor's window. When omitted, `current` is the BLS committee (or a synthetic one), `next`
    /// is synthetic, and the window starts at the header slot's period.
    window?: {current: BlsCommittee; next: BlsCommittee; period: bigint};
}): Promise<EthBundleProof> {
    const {rpcUrl, serviceAddr, channelId, payloads} = opts;
    const headerSlot = opts.headerSlot ?? DEFAULT_HEADER_SLOT;
    const signatureSlot = headerSlot + 1n;

    const blockTag = await rpcCall<string>(rpcUrl, "eth_blockNumber", []);
    const block = await rpcCall<{stateRoot: string}>(rpcUrl, "eth_getBlockByNumber", [blockTag, false]);
    const executionStateRoot = hexToBuf(block.stateRoot);

    const channelSlots = deriveChannelSlots(channelId);
    const storageKeys: Hex[] = opts.lastMessageId !== undefined
        ? [...channelSlots, deriveMessageRunningHashSlot(channelId, opts.lastMessageId)]
        : [...channelSlots];

    const proof = await rpcCall<EthGetProofResult>(rpcUrl, "eth_getProof", [
        serviceAddr.toLowerCase(),
        storageKeys,
        blockTag
    ]);
    if (proof.storageProof.length !== storageKeys.length) {
        throw new Error(`eth_getProof returned ${proof.storageProof.length} entries (expected ${storageKeys.length})`);
    }

    // Re-order by requested key so each entry's slot matches what the verifier re-derives.
    const byKey = new Map(proof.storageProof.map((sp) => [BigInt(sp.key), sp]));
    const storageProof = storageKeys.map((k) => {
        const sp = byKey.get(BigInt(k));
        if (!sp) throw new Error(`eth_getProof response missing storage key ${k}`);
        return [hexToBuf(k), sp.proof.map((n) => hexToBuf(n))];
    });
    const accountProof = proof.accountProof.map((n) => hexToBuf(n));

    // Synthetic SSZ execution branch: pick distinct siblings, then fold the (real) execution state
    // root up to the bodyRoot the verifier will check against.
    const branch: Buffer[] = [];
    for (let i = 0; i < EXECUTION_BRANCH_DEPTH; i++) {
        branch.push(sha256(Buffer.from(`clpr-eth-exec-branch-${i}`)));
    }
    const bodyRoot = foldSszBranch(executionStateRoot, branch, GINDEX_EXECUTION_STATE_ROOT_IN_BODY);

    // Optional rotation. The beacon stateRoot must be fixed BEFORE the signing root (which commits to
    // it), so the next-committee branch is folded here. nextCommittee is UNCOMPRESSED-only —
    //   [ uncompressedPubkeys[512], uncompressedAggregate ]
    // the contract re-derives the compressed form on-chain (compressG1) to reconstruct the committee
    // root the branch commits to. We still compute the expected root from the compressed keys here (they
    // equal compressG1(uncompressed)).
    const parentRoot = Buffer.alloc(32, 0);
    let beaconStateRoot: Buffer = Buffer.alloc(32, 0);
    let nextCommitteeItem: Input = Buffer.alloc(0); // absent → empty RLP string
    let nextCommitteeBranchItem: Input = []; // absent → empty RLP list
    if (opts.rotation) {
        const c = opts.rotation.committee;
        const committeeRoot = syncCommitteeRootFromCompressed(c.compressedPubkeys, c.compressedAggregate);
        const nextBranch: Buffer[] = [];
        for (let i = 0; i < NEXT_COMMITTEE_BRANCH_DEPTH; i++) {
            nextBranch.push(sha256(Buffer.from(`clpr-eth-next-committee-${i}`)));
        }
        beaconStateRoot = foldSszBranch(committeeRoot, nextBranch, GINDEX_NEXT_SYNC_COMMITTEE_IN_STATE);

        // Uncompressed keys are both sent (item 4) and stored in the successor anchor; optionally corrupt
        // one so its on-chain compression no longer matches the proven root (negative test).
        const uncompressedPubkeys = [...c.pubkeys];
        if (opts.rotation.mismatchUncompressed) {
            uncompressedPubkeys[0] = c.pubkeys[1]; // a valid point, but not the one compressed[0] commits to
        }
        nextCommitteeItem = [uncompressedPubkeys, c.aggregate];
        nextCommitteeBranchItem = nextBranch;
    }

    // attestedHeader [slot, proposerIndex, parentRoot, stateRoot, bodyRoot] — bodyRoot is checked by
    // the execution branch; slot/proposer/parentRoot/stateRoot feed the BLS signing root.
    const attestedHeader = [
        bigintToMinimalBuf(headerSlot), // slot (must match the value fed to the signing root)
        Buffer.from([Number(HEADER_PROPOSER_INDEX)]), // proposerIndex (must match HEADER_PROPOSER_INDEX)
        parentRoot,
        beaconStateRoot,
        bodyRoot
    ];

    // syncAggregate [bits(64), signature(256)] + item 10 (non-signer keys, Merkle-authenticated
    // against the anchor's committee root — ALWAYS the anchor committee, even when signWith differs).
    let syncAggregate: Buffer[];
    let nonSignerProofsItem: Buffer[] = []; // empty RLP list at full participation
    let trustAnchorCommittee: {pubkeys: Buffer[]; aggregate: Buffer} | undefined;
    if (opts.bls) {
        // Real path: derive the exact signing root the committee signs, then aggregate-sign it.
        const headerRoot = beaconBlockHeaderRoot(
            headerSlot, HEADER_PROPOSER_INDEX, parentRoot, beaconStateRoot, bodyRoot
        );
        const domain = computeSyncCommitteeDomain(hexToBuf(FORK_VERSION), hexToBuf(GVR));
        const signingRoot = computeSigningRoot(headerRoot, domain);
        const {bits, signature} = aggregateSign(
            opts.bls.signWith ?? opts.bls.committee, opts.bls.participants, signingRoot
        );
        syncAggregate = [bits, signature];
        nonSignerProofsItem = nonSignerProofEntries(opts.bls.committee.pubkeys, opts.bls.participants);
        trustAnchorCommittee = {pubkeys: opts.bls.committee.pubkeys, aggregate: opts.bls.committee.aggregate};
    } else {
        // Harness path: all bits set → zero non-signers → item 10 stays an empty list.
        syncAggregate = [Buffer.alloc(SYNC_BITS_LENGTH, 0xff), Buffer.alloc(BLS_SIGNATURE_LENGTH, 0)];
    }
    const executionBranch = branch; // 9 × 32-byte siblings

    const topLevel = rlpEncode([
        attestedHeader, // 0
        bigintToMinimalBuf(signatureSlot), // 1 signatureSlot — selects the window member
        syncAggregate, // 2
        executionStateRoot, // 3
        executionBranch, // 4
        nextCommitteeItem, // 5 nextCommittee (dual-encoding) or absent (empty RLP string)
        nextCommitteeBranchItem, // 6 nextCommitteeBranch or absent (empty RLP list)
        accountProof, // 7
        storageProof, // 8
        bundleContentProto(payloads), // 9
        nonSignerProofsItem // 10 non-signer key+proof entries (empty list at 512/512)
    ]);

    return {
        proofBytes: ("0x" + topLevel.toString("hex")) as Hex,
        trustAnchor: encodeEthTrustAnchor(
            channelId,
            proof.codeHash as Hex,
            opts.window?.current ?? trustAnchorCommittee,
            opts.window?.next,
            opts.window?.period ?? headerSlot / SLOTS_PER_SYNC_COMMITTEE_PERIOD
        ),
        channelId,
        codeHash: proof.codeHash as Hex
    };
}
