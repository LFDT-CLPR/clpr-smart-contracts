import {blake2b} from "@noble/hashes/blake2b";
import {keccak_256} from "@noble/hashes/sha3";
import {secp256k1} from "@noble/curves/secp256k1";
import {encodeAbiParameters, type Hex} from "viem";
import {deriveChannelFieldSlots, deriveMessageRunningHashSlot} from "../lib/storageSlots.js";

/// Relay-side helpers for the Substrate verifiers (src/verifiers/evm/grandpa): SCALE, hashing,
/// storage keys, GRANDPA justification and BEEFY commitment re-packing, MMR inclusion paths, the
/// ABI payloads the contracts decode, and a small LayoutV1 trie builder for synthetic fixtures.
/// Every format here mirrors the Solidity libraries in src/libraries/proof/substrate.

// ── bytes / hashing ──────────────────────────────────────────────────────────

export const fromHex = (h: string): Buffer => Buffer.from(h.replace(/^0x/, ""), "hex");
export const toHex = (b: Uint8Array): Hex => ("0x" + Buffer.from(b).toString("hex")) as Hex;
export const blake2_256 = (b: Uint8Array): Buffer => Buffer.from(blake2b(b, {dkLen: 32}));
export const blake2_128 = (b: Uint8Array): Buffer => Buffer.from(blake2b(b, {dkLen: 16}));
export const keccak = (...b: Uint8Array[]): Buffer => Buffer.from(keccak_256(Buffer.concat(b)));

const M64 = (1n << 64n) - 1n;
const P1 = 11400714785074694791n, P2 = 14029467366897019727n, P3 = 1609587929392839161n;
const P4 = 9650029242287828579n, P5 = 2870177450012600261n;
const rotl = (x: bigint, r: number) => ((x << BigInt(r)) | (x >> BigInt(64 - r))) & M64;
const rd64 = (b: Buffer, i: number) => b.readBigUInt64LE(i);
const rd32 = (b: Buffer, i: number) => BigInt(b.readUInt32LE(i));
const xxRound = (acc: bigint, inp: bigint) => (rotl((acc + inp * P2) & M64, 31) * P1) & M64;
const xxMerge = (acc: bigint, v: bigint) => ((acc ^ xxRound(0n, v)) * P1 + P4) & M64;

/// xxHash64 (the hash behind Substrate's twox_64 / twox_128).
export function xxh64(b: Buffer, seed: bigint): bigint {
    let i = 0, h: bigint;
    const n = b.length;
    if (n >= 32) {
        let v1 = (seed + P1 + P2) & M64, v2 = (seed + P2) & M64, v3 = seed, v4 = (seed - P1) & M64;
        while (i + 32 <= n) {
            v1 = xxRound(v1, rd64(b, i)); v2 = xxRound(v2, rd64(b, i + 8));
            v3 = xxRound(v3, rd64(b, i + 16)); v4 = xxRound(v4, rd64(b, i + 24)); i += 32;
        }
        h = (rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18)) & M64;
        h = xxMerge(xxMerge(xxMerge(xxMerge(h, v1), v2), v3), v4);
    } else h = (seed + P5) & M64;
    h = (h + BigInt(n)) & M64;
    while (i + 8 <= n) { h ^= xxRound(0n, rd64(b, i)); h = (rotl(h, 27) * P1 + P4) & M64; i += 8; }
    if (i + 4 <= n) { h ^= (rd32(b, i) * P1) & M64; h = (rotl(h, 23) * P2 + P3) & M64; i += 4; }
    while (i < n) { h ^= (BigInt(b[i]) * P5) & M64; h = (rotl(h, 11) * P1) & M64; i++; }
    h ^= h >> 33n; h = (h * P2) & M64; h ^= h >> 29n; h = (h * P3) & M64; h ^= h >> 32n;
    return h;
}
const le64 = (v: bigint) => { const o = Buffer.alloc(8); o.writeBigUInt64LE(v); return o; };
export const twox64 = (b: Uint8Array) => le64(xxh64(Buffer.from(b), 0n));
export const twox128 = (s: string | Uint8Array) => {
    const b = typeof s === "string" ? Buffer.from(s) : Buffer.from(s);
    return Buffer.concat([le64(xxh64(b, 0n)), le64(xxh64(b, 1n))]);
};
export const storageKey = (pallet: string, item: string) => Buffer.concat([twox128(pallet), twox128(item)]);

// ── SCALE ────────────────────────────────────────────────────────────────────

export class Scale {
    constructor(public b: Buffer, public o = 0) {}
    u8() { return this.b[this.o++]; }
    u32() { const v = this.b.readUInt32LE(this.o); this.o += 4; return v; }
    u64() { const v = this.b.readBigUInt64LE(this.o); this.o += 8; return v; }
    bytes(n: number) { const v = this.b.subarray(this.o, this.o + n); this.o += n; if (v.length !== n) throw new Error("scale: eof"); return v; }
    compact(): number {
        const b0 = this.b[this.o], m = b0 & 3;
        if (m === 0) { this.o += 1; return b0 >> 2; }
        if (m === 1) { const v = this.b.readUInt16LE(this.o) >> 2; this.o += 2; return v; }
        if (m === 2) { const v = this.b.readUInt32LE(this.o) >>> 2; this.o += 4; return v; }
        throw new Error("scale: big compact");
    }
    vec() { return this.bytes(this.compact()); }
    done() { return this.o === this.b.length; }
}

export function compact(n: number): Buffer {
    if (n < 64) return Buffer.from([n << 2]);
    if (n < 16384) { const b = Buffer.alloc(2); b.writeUInt16LE((n << 2) | 1); return b; }
    if (n < 2 ** 30) { const b = Buffer.alloc(4); b.writeUInt32LE(((n << 2) | 2) >>> 0); return b; }
    throw new Error("compact too large");
}
export const u32le = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
export const u64le = (n: bigint) => le64(n);

// ── Headers ──────────────────────────────────────────────────────────────────

export type RpcHeader = {parentHash: string; number: string; stateRoot: string; extrinsicsRoot: string; digest: {logs: string[]}};

/// SCALE(Header): parent ‖ Compact(number) ‖ state_root ‖ extrinsics_root ‖ Vec<DigestItem>.
/// RPC digest logs are already SCALE-encoded DigestItems.
export function encodeHeader(h: RpcHeader): Buffer {
    return Buffer.concat([
        fromHex(h.parentHash), compact(parseInt(h.number, 16)), fromHex(h.stateRoot), fromHex(h.extrinsicsRoot),
        compact(h.digest.logs.length), ...h.digest.logs.map(fromHex)
    ]);
}

export type DecodedHeader = {parentHash: Buffer; number: number; stateRoot: Buffer; digest: Buffer[]; end: number};

/// Decodes a SCALE header starting at `off` (used for votes_ancestries, which are concatenated).
export function decodeHeader(b: Buffer, off = 0): DecodedHeader {
    const r = new Scale(b, off);
    const parentHash = r.bytes(32), number = r.compact(), stateRoot = r.bytes(32);
    r.bytes(32);
    const n = r.compact(), digest: Buffer[] = [];
    for (let i = 0; i < n; i++) {
        const s = r.o, kind = r.u8();
        if (kind === 0) r.vec();
        else if (kind === 4 || kind === 5 || kind === 6) { r.bytes(4); r.vec(); }
        else if (kind !== 8) throw new Error("bad digest item " + kind);
        digest.push(b.subarray(s, r.o));
    }
    return {parentHash, number, stateRoot, digest, end: r.o};
}

/// GRANDPA ScheduledChange in a header digest: {authorities (packed key‖weight), delay}.
export function grandpaScheduledChange(header: Buffer): {authorities: Buffer; delay: number} | null {
    for (const item of decodeHeader(header).digest) {
        if (item[0] !== 4 || item.subarray(1, 5).toString() !== "FRNK") continue;
        const r = new Scale(item, 5);
        const data = r.vec();
        if (data[0] === 2) throw new Error("ForcedChange");
        if (data[0] !== 1) continue;
        const d = new Scale(data, 1);
        const n = d.compact();
        const authorities = d.bytes(40 * n);
        return {authorities: Buffer.from(authorities), delay: d.u32()};
    }
    return null;
}

// ── GRANDPA ──────────────────────────────────────────────────────────────────

export type Precommit = {targetHash: Buffer; targetNumber: number; signature: Buffer; id: Buffer};
export type Justification = {round: bigint; targetHash: Buffer; targetNumber: number; precommits: Precommit[]; ancestries: Buffer[]};

/// sc_consensus_grandpa::GrandpaJustification<Block> SCALE.
export function decodeJustification(b: Buffer): Justification {
    const r = new Scale(b);
    const round = r.u64(), targetHash = Buffer.from(r.bytes(32)), targetNumber = r.u32();
    const n = r.compact(), precommits: Precommit[] = [];
    for (let i = 0; i < n; i++) {
        precommits.push({targetHash: Buffer.from(r.bytes(32)), targetNumber: r.u32(), signature: Buffer.from(r.bytes(64)), id: Buffer.from(r.bytes(32))});
    }
    const na = r.compact(), ancestries: Buffer[] = [];
    for (let i = 0; i < na; i++) {
        const h = decodeHeader(b, r.o);
        ancestries.push(Buffer.from(b.subarray(r.o, h.end)));
        r.o = h.end;
    }
    if (!r.done()) throw new Error("justification: trailing bytes");
    return {round, targetHash, targetNumber, precommits, ancestries};
}

/// `Grandpa::Authorities` storage value (BoundedVec<(key, u64)>) → packed (key ‖ weight LE) list.
export function packGrandpaAuthorities(storageValue: string): Buffer {
    const r = new Scale(fromHex(storageValue));
    const n = r.compact();
    const out = Buffer.from(r.bytes(40 * n));
    if (!r.done()) throw new Error("authorities: trailing bytes");
    return out;
}

export const grandpaThreshold = (total: bigint) => total - (total - 1n) / 3n;

/// Re-packs a justification into GrandpaLib's vote format, keeping just enough precommits (by
/// authority index) to pass the threshold and preferring ones on the commit target itself.
export function packGrandpaVotes(j: Justification, authorities: Buffer, opts: {all?: boolean} = {}): {votes: Buffer; ancestry: Buffer[]; signed: bigint; threshold: bigint} {
    const n = authorities.length / 40;
    const keys = [...Array(n)].map((_, i) => authorities.subarray(40 * i, 40 * i + 32).toString("hex"));
    const weight = (i: number) => authorities.readBigUInt64LE(40 * i + 32);
    let total = 0n;
    for (let i = 0; i < n; i++) total += weight(i);
    const threshold = grandpaThreshold(total);
    const seen = new Set<number>();
    const entries = j.precommits
        .map((p) => ({p, idx: keys.indexOf(p.id.toString("hex"))}))
        .filter(({idx}) => idx >= 0 && !seen.has(idx) && (seen.add(idx), true))
        .sort((a, b) => Number(!a.p.targetHash.equals(j.targetHash)) - Number(!b.p.targetHash.equals(j.targetHash)) || a.idx - b.idx);
    const chosen: typeof entries = [];
    let signed = 0n;
    for (const e of entries) {
        if (!opts.all && signed >= threshold) break;
        chosen.push(e);
        signed += weight(e.idx);
    }
    chosen.sort((a, b) => a.idx - b.idx);
    const votes = Buffer.concat(chosen.map(({p, idx}) => {
        const v = Buffer.alloc(102);
        v.writeUInt16BE(idx, 0); p.targetHash.copy(v, 2); v.writeUInt32BE(p.targetNumber, 34); p.signature.copy(v, 38);
        return v;
    }));
    const needsAncestry = chosen.some(({p}) => !p.targetHash.equals(j.targetHash));
    return {votes, ancestry: needsAncestry ? j.ancestries : [], signed, threshold};
}

/// The 53-byte GRANDPA precommit signing payload.
export function grandpaMessage(targetHash: Buffer, targetNumber: number, round: bigint, setId: bigint): Buffer {
    return Buffer.concat([Buffer.from([1]), targetHash, u32le(targetNumber), u64le(round), u64le(setId)]);
}

// ── BEEFY ────────────────────────────────────────────────────────────────────

export type SignedCommitment = {commitment: Buffer; blockNumber: number; setId: bigint; mmrRoot: Buffer; validatorSetLen: number; signatures: (Buffer | null)[]};

/// VersionedFinalityProof::V1(SignedCommitment) as stored in block justifications ("BEEF"):
/// the CompactSignedCommitment encoding (bitfield MSB-first + compact signature list).
export function decodeBeefyJustification(b: Buffer): SignedCommitment {
    const r = new Scale(b);
    if (r.u8() !== 1) throw new Error("beefy: not V1");
    const start = r.o;
    const np = r.compact();
    let mmrRoot = Buffer.alloc(0);
    for (let i = 0; i < np; i++) {
        const id = r.bytes(2).toString(), data = r.vec();
        if (id === "mh") mmrRoot = Buffer.from(data);
    }
    const blockNumber = r.u32(), setId = r.u64();
    const commitment = Buffer.from(b.subarray(start, r.o));
    const bits = r.vec(), validatorSetLen = r.u32(), ns = r.compact();
    const sigs: Buffer[] = [];
    for (let i = 0; i < ns; i++) sigs.push(Buffer.from(r.bytes(65)));
    if (!r.done()) throw new Error("beefy: trailing bytes");
    const signatures: (Buffer | null)[] = [];
    let s = 0;
    for (let i = 0; i < validatorSetLen; i++) signatures.push(bits[i >> 3] & (0x80 >> (i & 7)) ? sigs[s++] : null);
    return {commitment, blockNumber, setId, mmrRoot, validatorSetLen, signatures};
}

/// `Beefy::Authorities` (Vec of 33-byte compressed secp256k1 keys) → packed 20-byte addresses.
export function beefyAddresses(storageValue: string): Buffer {
    const r = new Scale(fromHex(storageValue));
    const n = r.compact(), out: Buffer[] = [];
    for (let i = 0; i < n; i++) out.push(ethAddressOfCompressed(r.bytes(33)));
    return Buffer.concat(out);
}
export function ethAddressOfCompressed(pk: Uint8Array): Buffer {
    const raw = secp256k1.ProjectivePoint.fromHex(pk).toRawBytes(false).subarray(1);
    return keccak(raw).subarray(12);
}

export const beefyThreshold = (n: number) => n - Math.floor((n - 1) / 3);

/// The first `threshold` signatures (by index) as BeefyLib's signers bitfield + packed signatures.
export function packBeefySignatures(sc: SignedCommitment, count = beefyThreshold(sc.validatorSetLen)): {signers: Buffer; signatures: Buffer} {
    const signers = Buffer.alloc(Math.ceil(sc.validatorSetLen / 8));
    const sigs: Buffer[] = [];
    for (let i = 0; i < sc.validatorSetLen && sigs.length < count; i++) {
        const s = sc.signatures[i];
        if (!s) continue;
        signers[i >> 3] |= 0x80 >> (i & 7);
        sigs.push(s);
    }
    if (sigs.length < count) throw new Error(`beefy: only ${sigs.length} signatures`);
    return {signers, signatures: Buffer.concat(sigs)};
}

/// keyset_commitment: binary_merkle_tree::merkle_root::<Keccak256> over 20-byte addresses.
export function keysetRoot(addresses: Buffer): Buffer {
    let row: Buffer[] = [];
    for (let i = 0; i < addresses.length; i += 20) row.push(keccak(addresses.subarray(i, i + 20)));
    while (row.length > 1) {
        const next: Buffer[] = [];
        for (let i = 0; i < row.length; i += 2) next.push(i + 1 < row.length ? keccak(row[i], row[i + 1]) : row[i]);
        row = next;
    }
    return row[0];
}

export type MmrLeaf = {version: number; parentNumber: number; parentHash: Buffer; next: {id: bigint; len: number; root: Buffer}; leafExtra: Buffer};
export function decodeMmrLeaf(b: Buffer): MmrLeaf {
    const r = new Scale(b);
    const leaf = {version: r.u8(), parentNumber: r.u32(), parentHash: Buffer.from(r.bytes(32)), next: {id: r.u64(), len: r.u32(), root: Buffer.from(r.bytes(32))}, leafExtra: Buffer.from(r.bytes(32))};
    if (!r.done()) throw new Error("mmr leaf: unexpected length");
    return leaf;
}

/// `mmr_generateProof` result for one leaf → BeefyLib inclusion path. The ckb-MMR proof lists the
/// left peaks, then the leaf's mountain siblings, then (if any) the bagged right peaks. Peaks are
/// bagged right-to-left as keccak(right ‖ left), so on the way up: siblings by position, then
/// keccak(rightBag ‖ acc), then keccak(acc ‖ leftPeak) from the nearest left peak outwards.
export function mmrPath(rpcProof: {leaves: string; proof: string}): {leaf: Buffer; path: Buffer[]; sides: bigint; leafIndex: bigint; leafCount: bigint} {
    const lv = new Scale(fromHex(rpcProof.leaves));
    if (lv.compact() !== 1) throw new Error("mmr: expected one leaf");
    const leaf = Buffer.from(lv.vec());
    const p = new Scale(fromHex(rpcProof.proof));
    if (p.compact() !== 1) throw new Error("mmr: expected one index");
    const leafIndex = p.u64(), leafCount = p.u64();
    const n = p.compact(), items: Buffer[] = [];
    for (let i = 0; i < n; i++) items.push(Buffer.from(p.bytes(32)));
    // Mountains: one perfect tree per set bit of leafCount, largest (leftmost) first.
    const peaks: {start: bigint; h: number}[] = [];
    let start = 0n;
    for (let b = 63; b >= 0; b--) if ((leafCount >> BigInt(b)) & 1n) { peaks.push({start, h: b}); start += 1n << BigInt(b); }
    const ti = peaks.findIndex((pk) => leafIndex >= pk.start && leafIndex < pk.start + (1n << BigInt(pk.h)));
    const tp = peaks[ti];
    const left = items.slice(0, ti), siblings = items.slice(ti, ti + tp.h), right = items.slice(ti + tp.h);
    if (right.length > 1) throw new Error("mmr: unexpected proof shape");
    const path: Buffer[] = [];
    let sides = 0n;
    const off = leafIndex - tp.start;
    for (let k = 0; k < tp.h; k++) { if ((off >> BigInt(k)) & 1n) sides |= 1n << BigInt(path.length); path.push(siblings[k]); }
    if (right.length) { sides |= 1n << BigInt(path.length); path.push(right[0]); }
    for (let k = left.length - 1; k >= 0; k--) path.push(left[k]);
    return {leaf, path, sides, leafIndex, leafCount};
}

// ── Storage keys ─────────────────────────────────────────────────────────────

export const EVM_PALLET_PREFIX = twox128("EVM");

/// Frontier pallet_evm::AccountStorages key (Blake2_128Concat H160, Blake2_128Concat H256).
export function accountStorageKey(address: Hex, slot: Hex, pallet = EVM_PALLET_PREFIX): Buffer {
    const a = fromHex(address), s = fromHex(slot.replace(/^0x/, "").padStart(64, "0"));
    return Buffer.concat([pallet, twox128("AccountStorages"), blake2_128(a), a, blake2_128(s), s]);
}

/// Polkadot `Paras::Heads(paraId)` key (Twox64Concat ParaId).
export function paraHeadKey(paraId: number): Buffer {
    const id = u32le(paraId);
    return Buffer.concat([storageKey("Paras", "Heads"), twox64(id), id]);
}

/// The ClprService slots a bundle proves for `channelId` (5 Channel slots, + last message hash).
export function channelSlots(channelId: Hex, lastMessageId?: bigint): Hex[] {
    const s = deriveChannelFieldSlots(channelId);
    return lastMessageId === undefined ? s : [...s, deriveMessageRunningHashSlot(channelId, lastMessageId)];
}

// ── ABI payloads (GrandpaVerifier / BeefyParachainVerifier) ──────────────────

const GRANDPA_STEP = {type: "tuple[]", components: [
    {name: "headers", type: "bytes[]"}, {name: "round", type: "uint64"}, {name: "votes", type: "bytes"},
    {name: "ancestry", type: "bytes[]"}, {name: "authorities", type: "bytes"}
]} as const;
const BEEFY_COMMIT = {type: "tuple[]", components: [
    {name: "commitment", type: "bytes"}, {name: "signers", type: "bytes"}, {name: "signatures", type: "bytes"},
    {name: "authorities", type: "bytes"}, {name: "mmrLeaf", type: "bytes"}, {name: "mmrPath", type: "bytes32[]"},
    {name: "mmrPathSides", type: "uint256"}
]} as const;

export type GrandpaStep = {headers: Buffer[]; round: bigint; votes: Buffer; ancestry: Buffer[]; authorities: Buffer};
export type BeefyCommit = {commitment: Buffer; signers: Buffer; signatures: Buffer; authorities: Buffer; mmrLeaf: Buffer; mmrPath: Buffer[]; mmrPathSides: bigint};

const stepAbi = (s: GrandpaStep) => ({headers: s.headers.map(toHex), round: s.round, votes: toHex(s.votes), ancestry: s.ancestry.map(toHex), authorities: toHex(s.authorities)});
const commitAbi = (c: BeefyCommit) => ({commitment: toHex(c.commitment), signers: toHex(c.signers), signatures: toHex(c.signatures), authorities: toHex(c.authorities), mmrLeaf: toHex(c.mmrLeaf), mmrPath: c.mmrPath.map(toHex), mmrPathSides: c.mmrPathSides});

export function encodeGrandpaBundle(p: {steps: GrandpaStep[]; stateProof: Buffer[]; lastMessageSlot?: boolean; bundleContent?: Buffer; manifestPreimage?: Buffer}): Hex {
    return encodeAbiParameters([{type: "tuple", components: [
        {...GRANDPA_STEP, name: "steps"}, {name: "stateProof", type: "bytes[]"}, {name: "lastMessageSlot", type: "bool"},
        {name: "bundleContent", type: "bytes"}, {name: "manifestPreimage", type: "bytes"}
    ]}], [{steps: p.steps.map(stepAbi), stateProof: p.stateProof.map(toHex), lastMessageSlot: !!p.lastMessageSlot,
        bundleContent: toHex(p.bundleContent ?? Buffer.alloc(0)), manifestPreimage: toHex(p.manifestPreimage ?? Buffer.alloc(0))}]);
}

export function encodeGrandpaConfig(p: {steps: GrandpaStep[]; stateProof: Buffer[]; ledgerConfig: Buffer}): Hex {
    return encodeAbiParameters([{type: "tuple", components: [
        {...GRANDPA_STEP, name: "steps"}, {name: "stateProof", type: "bytes[]"}, {name: "ledgerConfig", type: "bytes"}
    ]}], [{steps: p.steps.map(stepAbi), stateProof: p.stateProof.map(toHex), ledgerConfig: toHex(p.ledgerConfig)}]);
}

export function encodeBeefyBundle(p: {commits: BeefyCommit[]; relayHeader: Buffer; relayStateProof: Buffer[]; paraStateProof: Buffer[]; lastMessageSlot?: boolean; bundleContent?: Buffer; manifestPreimage?: Buffer}): Hex {
    return encodeAbiParameters([{type: "tuple", components: [
        {...BEEFY_COMMIT, name: "commits"}, {name: "relayHeader", type: "bytes"}, {name: "relayStateProof", type: "bytes[]"},
        {name: "paraStateProof", type: "bytes[]"}, {name: "lastMessageSlot", type: "bool"}, {name: "bundleContent", type: "bytes"},
        {name: "manifestPreimage", type: "bytes"}
    ]}], [{commits: p.commits.map(commitAbi), relayHeader: toHex(p.relayHeader), relayStateProof: p.relayStateProof.map(toHex),
        paraStateProof: p.paraStateProof.map(toHex), lastMessageSlot: !!p.lastMessageSlot,
        bundleContent: toHex(p.bundleContent ?? Buffer.alloc(0)), manifestPreimage: toHex(p.manifestPreimage ?? Buffer.alloc(0))}]);
}

export function encodeBeefyConfig(p: {commits: BeefyCommit[]; relayHeader: Buffer; relayStateProof: Buffer[]; paraStateProof: Buffer[]; ledgerConfig: Buffer}): Hex {
    return encodeAbiParameters([{type: "tuple", components: [
        {...BEEFY_COMMIT, name: "commits"}, {name: "relayHeader", type: "bytes"}, {name: "relayStateProof", type: "bytes[]"},
        {name: "paraStateProof", type: "bytes[]"}, {name: "ledgerConfig", type: "bytes"}
    ]}], [{commits: p.commits.map(commitAbi), relayHeader: toHex(p.relayHeader), relayStateProof: p.relayStateProof.map(toHex),
        paraStateProof: p.paraStateProof.map(toHex), ledgerConfig: toHex(p.ledgerConfig)}]);
}

// ── GrandpaPalletVerifier (native pallet storage, e.g. Chainflip) ───────────

/// Proposed `pallet-clpr` storage keys (GrandpaPalletVerifier.sol): Queues (Blake2_128Concat H256)
/// and Service (StorageValue), under the pallet name of the deployment profile.
export const palletQueueKey = (pallet: Buffer, channelId: Hex): Buffer => {
    const c = fromHex(channelId);
    return Buffer.concat([pallet, twox128("Queues"), blake2_128(c), c]);
};
export const palletServiceKey = (pallet: Buffer): Buffer => Buffer.concat([pallet, twox128("Service")]);
/// SCALE QueueRecord (89 B): status u8, three u64 LE, two 32-byte running hashes.
export function palletQueueRecord(r: {status: number; next: bigint; received: bigint; manifestVersion: bigint; sent: Buffer; receivedHash: Buffer}): Buffer {
    return Buffer.concat([Buffer.from([r.status]), u64le(r.next), u64le(r.received), u64le(r.manifestVersion), r.sent, r.receivedHash]);
}
/// SCALE ServiceRecord (80 B): AccountId32, manifest commitment, config nanos u128 LE.
export function palletServiceRecord(service: Buffer, commitment: Buffer, nanos: bigint): Buffer {
    return Buffer.concat([service, commitment, u64le(nanos & ((1n << 64n) - 1n)), u64le(nanos >> 64n)]);
}

export function encodeGrandpaPalletBundle(p: {steps: GrandpaStep[]; stateProof: Buffer[]; bundleContent?: Buffer; manifestPreimage?: Buffer}): Hex {
    return encodeAbiParameters([{type: "tuple", components: [
        {...GRANDPA_STEP, name: "steps"}, {name: "stateProof", type: "bytes[]"},
        {name: "bundleContent", type: "bytes"}, {name: "manifestPreimage", type: "bytes"}
    ]}], [{steps: p.steps.map(stepAbi), stateProof: p.stateProof.map(toHex),
        bundleContent: toHex(p.bundleContent ?? Buffer.alloc(0)), manifestPreimage: toHex(p.manifestPreimage ?? Buffer.alloc(0))}]);
}

/// GrandpaPalletVerifier.EntryProof (verifyStorageEntry).
export function encodeGrandpaEntryProof(p: {steps: GrandpaStep[]; stateProof: Buffer[]}): Hex {
    return encodeAbiParameters([{type: "tuple", components: [{...GRANDPA_STEP, name: "steps"}, {name: "stateProof", type: "bytes[]"}]}],
        [{steps: p.steps.map(stepAbi), stateProof: p.stateProof.map(toHex)}]);
}

/// Splits re-packed GRANDPA votes (102-byte entries, sorted) into batches for GrandpaCommitAccumulator.
export function splitVotes(votes: Buffer, perBatch: number): Buffer[] {
    const out: Buffer[] = [];
    for (let o = 0; o < votes.length; o += 102 * perBatch) out.push(votes.subarray(o, Math.min(votes.length, o + 102 * perBatch)));
    return out;
}

/// GrandpaVerifier anchor: setId(u64 BE) ‖ authoritiesHash ‖ minHeight(u32 BE).
export function grandpaAnchor(setId: bigint, authorities: Buffer, minHeight: number): Hex {
    const b = Buffer.alloc(44);
    b.writeBigUInt64BE(setId, 0); keccak(authorities).copy(b, 8); b.writeUInt32BE(minHeight, 40);
    return toHex(b);
}

export type BeefySet = {id: bigint; len: number; root: Buffer};
/// `BeefyMmrLeaf::BeefyAuthorities` / `BeefyNextAuthorities` storage value.
export function decodeBeefySet(storageValue: string): BeefySet {
    const r = new Scale(fromHex(storageValue));
    return {id: r.u64(), len: r.u32(), root: Buffer.from(r.bytes(32))};
}
/// BeefyParachainVerifier anchor (92 bytes, big-endian integers).
export function beefyAnchor(current: BeefySet, next: BeefySet, minRelayBlock: number): Hex {
    const b = Buffer.alloc(92);
    b.writeBigUInt64BE(current.id, 0); b.writeUInt32BE(current.len, 8); current.root.copy(b, 12);
    b.writeBigUInt64BE(next.id, 44); b.writeUInt32BE(next.len, 52); next.root.copy(b, 56);
    b.writeUInt32BE(minRelayBlock, 88);
    return toHex(b);
}

// ── Synthetic LayoutV1 trie (fixtures only) ──────────────────────────────────

const nibblesOf = (k: Buffer) => [...k].flatMap((x) => [x >> 4, x & 15]);

function headerBytes(kind: "leaf" | "branch" | "branchValue" | "hashedLeaf" | "hashedBranch", count: number): Buffer {
    const [prefix, maskBits] = {leaf: [0x40, 2], branch: [0x80, 2], branchValue: [0xc0, 2], hashedLeaf: [0x20, 3], hashedBranch: [0x10, 4]}[kind] as [number, number];
    const max = 255 >> maskBits;
    if (count < max) return Buffer.from([prefix + count]);
    const out = [prefix + max];
    let rem = count - (max - 1);
    while (rem >= 256) { out.push(255); rem -= 255; }
    out.push(rem - 1);
    return Buffer.from(out);
}
function partialBytes(n: number[]): Buffer {
    const out: number[] = [];
    let i = 0;
    if (n.length % 2 === 1) out.push(n[i++]);
    for (; i < n.length; i += 2) out.push((n[i] << 4) | n[i + 1]);
    return Buffer.from(out);
}

/// Builds a Substrate LayoutV1 trie (values ≥ 33 bytes stored as hashed value nodes) and returns its
/// root plus every hashed node — a superset of any read proof, which the verifier accepts.
export function buildTrie(entries: [Buffer, Buffer][]): {root: Buffer; nodes: Buffer[]} {
    const nodes: Buffer[] = [];
    const items = entries.map(([k, v]) => ({n: nibblesOf(k), v})).sort((a, b) => Buffer.compare(Buffer.from(a.n), Buffer.from(b.n)));
    const valueEnc = (v: Buffer) => {
        if (v.length >= 33) { nodes.push(v); return {hashed: true, enc: blake2_256(v)}; }
        return {hashed: false, enc: Buffer.concat([compact(v.length), v])};
    };
    const ref = (enc: Buffer) => {
        if (enc.length >= 32) { nodes.push(enc); return Buffer.concat([compact(32), blake2_256(enc)]); }
        return Buffer.concat([compact(enc.length), enc]);
    };
    const build = (its: {n: number[]; v: Buffer}[], depth: number): Buffer => {
        if (its.length === 1) {
            const p = its[0].n.slice(depth), val = valueEnc(its[0].v);
            return Buffer.concat([headerBytes(val.hashed ? "hashedLeaf" : "leaf", p.length), partialBytes(p), val.enc]);
        }
        let cp = 0;
        while (its.every((x) => x.n.length > depth + cp && x.n[depth + cp] === its[0].n[depth + cp])) cp++;
        const at = depth + cp;
        const here = its.find((x) => x.n.length === at);
        const children: Buffer[] = [];
        let bitmap = 0;
        for (let c = 0; c < 16; c++) {
            const g = its.filter((x) => x.n.length > at && x.n[at] === c);
            if (!g.length) continue;
            bitmap |= 1 << c;
            children.push(ref(build(g, at + 1)));
        }
        const val = here ? valueEnc(here.v) : null;
        const kind = !val ? "branch" : val.hashed ? "hashedBranch" : "branchValue";
        const bm = Buffer.alloc(2); bm.writeUInt16LE(bitmap);
        return Buffer.concat([headerBytes(kind, cp), partialBytes(its[0].n.slice(depth, at)), bm, val ? val.enc : Buffer.alloc(0), ...children]);
    };
    const rootNode = items.length ? build(items, 0) : Buffer.from([0]);
    nodes.push(rootNode);
    return {root: blake2_256(rootNode), nodes};
}
