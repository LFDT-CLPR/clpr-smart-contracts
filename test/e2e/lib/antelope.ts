import {createHash} from "node:crypto";
import {base58, base64urlnopad} from "@scure/base";
import {ripemd160} from "@noble/hashes/ripemd160";
import {secp256k1} from "@noble/curves/secp256k1";
import * as blsLib from "@noble/curves/bls12-381";

/// Antelope (Spring / Leap) encodings, digests and Merkle trees for the Antelope verifiers.
/// Mirrors src/verifiers/evm/antelope/AntelopeLib.sol; every rule is from AntelopeIO/spring v1.2.2
/// and AntelopeIO/leap v3.1.2 / v5.0.3 (see the README in that directory).

export const sha256 = (...parts: Uint8Array[]): Buffer => {
    const h = createHash("sha256");
    for (const p of parts) h.update(p);
    return h.digest();
};

export const hex = (b: Uint8Array): `0x${string}` => `0x${Buffer.from(b).toString("hex")}`;
export const unhex = (h: string): Buffer => Buffer.from(h.replace(/^0x/, ""), "hex");

export function u8(v: number): Buffer {
    return Buffer.from([v & 0xff]);
}
export function u16(v: number): Buffer {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(v);
    return b;
}
export function u32(v: number): Buffer {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(v >>> 0);
    return b;
}
export function u64(v: bigint): Buffer {
    const b = Buffer.alloc(8);
    b.writeBigUInt64LE(BigInt.asUintN(64, v));
    return b;
}
export function varuint(v: number | bigint): Buffer {
    let x = BigInt(v);
    const out: number[] = [];
    do {
        let byte = Number(x & 0x7fn);
        x >>= 7n;
        if (x !== 0n) byte |= 0x80;
        out.push(byte);
    } while (x !== 0n);
    return Buffer.from(out);
}
export const packBytes = (b: Uint8Array): Buffer => Buffer.concat([varuint(b.length), Buffer.from(b)]);
export const packString = (s: string): Buffer => packBytes(Buffer.from(s, "utf8"));

// ── Names ────────────────────────────────────────────────────────────────────

const NAME_CHARS = ".12345abcdefghijklmnopqrstuvwxyz";

export function nameToU64(s: string): bigint {
    let v = 0n;
    for (let i = 0; i < 13; i++) {
        const c = i < s.length ? BigInt(NAME_CHARS.indexOf(s[i])) : 0n;
        if (c < 0n) throw new Error(`bad name ${s}`);
        if (i < 12) v |= (c & 0x1fn) << BigInt(64 - 5 * (i + 1));
        else v |= c & 0x0fn;
    }
    return v;
}

export function u64ToName(v: bigint): string {
    const chars: string[] = [];
    let tmp = v;
    for (let i = 0; i <= 12; i++) {
        const c = i === 0 ? tmp & 0x0fn : tmp & 0x1fn;
        chars.unshift(NAME_CHARS[Number(c)]);
        tmp >>= i === 0 ? 4n : 5n;
    }
    return chars.join("").replace(/\.+$/, "");
}

export const packName = (s: string): Buffer => u64(nameToU64(s));

// ── Keys and signatures ─────────────────────────────────────────────────────

function decodeChecked(data: string, suffix: string): Buffer {
    const raw = Buffer.from(base58.decode(data));
    const body = raw.subarray(0, raw.length - 4);
    const check = Buffer.from(ripemd160(Buffer.concat([body, Buffer.from(suffix)]))).subarray(0, 4);
    if (!check.equals(raw.subarray(raw.length - 4))) throw new Error("bad key checksum");
    return body;
}

/// Compressed 33-byte secp256k1 key from "EOS..." (legacy) or "PUB_K1_..." text.
export function k1KeyBytes(key: string): Buffer {
    if (key.startsWith("PUB_K1_")) return decodeChecked(key.slice(7), "K1");
    const prefix = key.startsWith("EOS") ? 3 : key.startsWith("XPR") ? 3 : -1;
    if (prefix < 0) throw new Error(`unsupported key ${key}`);
    const raw = Buffer.from(base58.decode(key.slice(prefix)));
    const body = raw.subarray(0, 33);
    const check = Buffer.from(ripemd160(body)).subarray(0, 4);
    if (!check.equals(raw.subarray(33))) throw new Error("bad legacy key checksum");
    return body;
}

/// Uncompressed x || y (64 bytes) of a compressed key.
export function k1Uncompressed(compressed: Uint8Array): Buffer {
    const p = secp256k1.ProjectivePoint.fromHex(compressed);
    return Buffer.from(p.toRawBytes(false)).subarray(1);
}

/// EVM address of a K1 key (keccak of x || y), lower-case hex.
export async function k1Address(compressed: Uint8Array): Promise<`0x${string}`> {
    const {keccak_256} = await import("@noble/hashes/sha3");
    const h = keccak_256(k1Uncompressed(compressed));
    return hex(h.subarray(12));
}

/// 65-byte SIG_K1 payload: recovery byte (27 + 4 + recid) || r || s.
export function k1SigBytes(sig: string): Buffer {
    if (!sig.startsWith("SIG_K1_")) throw new Error(`unsupported signature ${sig}`);
    return decodeChecked(sig.slice(7), "K1");
}

/// 96-byte affine little-endian G1 key from "PUB_BLS_<base64url>" (Spring bls_public_key).
export function blsKeyBytes(key: string): Buffer {
    if (!key.startsWith("PUB_BLS_")) throw new Error(`not a BLS key ${key}`);
    const raw = Buffer.from(base64urlnopad.decode(key.slice(8)));
    if (raw.length === 100) return raw.subarray(0, 96); // + 4-byte checksum
    if (raw.length !== 96) throw new Error(`bad BLS key length ${raw.length}`);
    return raw;
}

/// 192-byte affine little-endian G2 signature from "SIG_BLS_<base64url>".
export function blsSigBytes(sig: string): Buffer {
    if (!sig.startsWith("SIG_BLS_")) throw new Error(`not a BLS signature`);
    const raw = Buffer.from(base64urlnopad.decode(sig.slice(8)));
    if (raw.length === 196) return raw.subarray(0, 192);
    if (raw.length !== 192) throw new Error(`bad BLS signature length ${raw.length}`);
    return raw;
}

// ── Actions ──────────────────────────────────────────────────────────────────

export interface PermissionLevel {
    actor: string;
    permission: string;
}

export function packActionBase(account: string, name: string, auth: PermissionLevel[]): Buffer {
    return Buffer.concat([
        packName(account),
        packName(name),
        varuint(auth.length),
        ...auth.map((a) => Buffer.concat([packName(a.actor), packName(a.permission)]))
    ]);
}

/// generate_action_digest: sha256(sha256(pack(action_base)) || sha256(pack(data) || pack(return_value))).
export function actionDigest(actionBase: Buffer, data: Buffer, returnValue: Buffer): Buffer {
    return sha256(sha256(actionBase), sha256(packBytes(data), packBytes(returnValue)));
}

export interface AuthSequence {
    account: string;
    sequence: bigint;
}

/// Packed receipt fields after act_digest (legacy digest): global_sequence, recv_sequence,
/// auth_sequence (flat_map<name,uint64>, sorted by name), code_sequence, abi_sequence.
export function legacyReceiptTail(
    globalSequence: bigint,
    recvSequence: bigint,
    authSequence: AuthSequence[],
    codeSequence: number,
    abiSequence: number
): Buffer {
    const sorted = [...authSequence].sort((a, b) => (nameToU64(a.account) < nameToU64(b.account) ? -1 : 1));
    return Buffer.concat([
        u64(globalSequence),
        u64(recvSequence),
        varuint(sorted.length),
        ...sorted.map((a) => Buffer.concat([packName(a.account), u64(a.sequence)])),
        varuint(codeSequence),
        varuint(abiSequence)
    ]);
}

export const legacyReceiptDigest = (receiver: string, actDigest: Buffer, tail: Buffer): Buffer =>
    sha256(packName(receiver), actDigest, tail);

/// savanna_witness_hash: sha256(global_sequence, auth_sequence, code_sequence, abi_sequence).
export function savannaWitnessHash(
    globalSequence: bigint,
    authSequence: AuthSequence[],
    codeSequence: number,
    abiSequence: number
): Buffer {
    const sorted = [...authSequence].sort((a, b) => (nameToU64(a.account) < nameToU64(b.account) ? -1 : 1));
    return sha256(
        u64(globalSequence),
        varuint(sorted.length),
        ...sorted.map((a) => Buffer.concat([packName(a.account), u64(a.sequence)])),
        varuint(codeSequence),
        varuint(abiSequence)
    );
}

export const savannaReceiptDigest = (
    receiver: string,
    recvSequence: bigint,
    account: string,
    name: string,
    actDigest: Buffer,
    witness: Buffer
): Buffer => sha256(packName(receiver), u64(recvSequence), packName(account), packName(name), actDigest, witness);

// ── Merkle trees ─────────────────────────────────────────────────────────────

/// Savanna `calculate_merkle`.
export function savannaMerkle(leaves: Buffer[]): Buffer {
    if (leaves.length === 0) return Buffer.alloc(32);
    let layer = leaves;
    while (layer.length > 1) {
        const next: Buffer[] = [];
        for (let i = 0; i < layer.length; i += 2) next.push(i + 1 < layer.length ? sha256(layer[i], layer[i + 1]) : layer[i]);
        layer = next;
    }
    return layer[0];
}

/// Siblings for leaf `index`, bottom-up, matching AntelopeLib.savannaMerkleRoot.
export function savannaMerkleProof(leaves: Buffer[], index: number): Buffer[] {
    const out: Buffer[] = [];
    let layer = leaves;
    let idx = index;
    while (layer.length > 1) {
        const pair = idx ^ 1;
        if (pair < layer.length) out.push(layer[pair]);
        const next: Buffer[] = [];
        for (let i = 0; i < layer.length; i += 2) next.push(i + 1 < layer.length ? sha256(layer[i], layer[i + 1]) : layer[i]);
        layer = next;
        idx >>= 1;
    }
    return out;
}

const canonL = (h: Buffer) => {
    const c = Buffer.from(h);
    c[0] &= 0x7f;
    return c;
};
const canonR = (h: Buffer) => {
    const c = Buffer.from(h);
    c[0] |= 0x80;
    return c;
};
const legacyPair = (l: Buffer, r: Buffer) => sha256(canonL(l), canonR(r));

/// Legacy `merkle` / `calculate_merkle_legacy`.
export function legacyMerkle(leaves: Buffer[]): Buffer {
    if (leaves.length === 0) return Buffer.alloc(32);
    let layer = [...leaves];
    while (layer.length > 1) {
        if (layer.length % 2) layer.push(layer[layer.length - 1]);
        const next: Buffer[] = [];
        for (let i = 0; i < layer.length; i += 2) next.push(legacyPair(layer[i], layer[i + 1]));
        layer = next;
    }
    return layer[0];
}

/// Siblings for leaf `index` (the duplicated last node of an odd layer is implied, not listed).
export function legacyMerkleProof(leaves: Buffer[], index: number): Buffer[] {
    const out: Buffer[] = [];
    let layer = [...leaves];
    let idx = index;
    while (layer.length > 1) {
        const pair = idx ^ 1;
        if (pair < layer.length) out.push(layer[pair]);
        if (layer.length % 2) layer.push(layer[layer.length - 1]);
        const next: Buffer[] = [];
        for (let i = 0; i < layer.length; i += 2) next.push(legacyPair(layer[i], layer[i + 1]));
        layer = next;
        idx >>= 1;
    }
    return out;
}

/// Legacy incremental_merkle (blockroot_merkle): append + root, as in leap incremental_merkle.hpp.
export class IncrementalMerkle {
    constructor(
        public nodeCount: bigint,
        public activeNodes: Buffer[]
    ) {}

    static maxDepth(count: bigint): number {
        if (count === 0n) return 0;
        let p = 1n;
        while (p < count) p <<= 1n;
        let depth = 0;
        while (p > 1n) {
            p >>= 1n;
            depth++;
        }
        return depth + 1;
    }

    append(digest: Buffer): Buffer {
        let partial = false;
        const maxDepth = IncrementalMerkle.maxDepth(this.nodeCount + 1n);
        let depth = maxDepth - 1;
        let index = this.nodeCount;
        let top = digest;
        let it = 0;
        const updated: Buffer[] = [];
        while (depth > 0) {
            if ((index & 1n) === 0n) {
                if (!partial) updated.push(top);
                top = legacyPair(top, top);
                partial = true;
            } else {
                const left = this.activeNodes[it++];
                if (partial) updated.push(left);
                top = legacyPair(left, top);
            }
            depth--;
            index >>= 1n;
        }
        updated.push(top);
        this.activeNodes = updated;
        this.nodeCount++;
        return top;
    }

    root(): Buffer {
        return this.nodeCount > 0n ? this.activeNodes[this.activeNodes.length - 1] : Buffer.alloc(32);
    }
}

// ── Legacy block headers ─────────────────────────────────────────────────────

export interface BlockHeaderJson {
    timestamp: string;
    producer: string;
    confirmed: number;
    previous: string;
    transaction_mroot: string;
    action_mroot: string;
    schedule_version: number;
    new_producers: unknown;
    header_extensions: [number, string][];
}

/// block_timestamp_type slot: half-seconds since 2000-01-01T00:00:00Z.
export function blockTimestampSlot(ts: string): number {
    const ms = Date.parse(ts.endsWith("Z") ? ts : ts + "Z");
    return Math.round((ms - Date.UTC(2000, 0, 1)) / 500);
}

export function packHeader(h: BlockHeaderJson): Buffer {
    if (h.new_producers) throw new Error("legacy new_producers not supported");
    return Buffer.concat([
        u32(blockTimestampSlot(h.timestamp)),
        packName(h.producer),
        u16(h.confirmed),
        unhex(h.previous),
        unhex(h.transaction_mroot),
        unhex(h.action_mroot),
        u32(h.schedule_version),
        u8(0),
        varuint((h.header_extensions ?? []).length),
        ...(h.header_extensions ?? []).map(([id, data]) => Buffer.concat([u16(id), packBytes(unhex(data))]))
    ]);
}

export function blockIdOf(raw: Buffer, num: number): Buffer {
    const id = sha256(raw);
    id.writeUInt32BE(num >>> 0, 0);
    return id;
}

/// sig_digest = sha256(sha256(sha256(header) || bmroot) || pending_schedule_hash).
export const legacySigDigest = (raw: Buffer, bmroot: Buffer, scheduleHash: Buffer): Buffer =>
    sha256(sha256(sha256(raw), bmroot), scheduleHash);

/// Recover the EVM-style address of a SIG_K1 signer over `digest`.
export async function recoverK1Address(sig65: Buffer, digest: Buffer): Promise<`0x${string}`> {
    const recid = sig65[0] - 31;
    const s = secp256k1.Signature.fromCompact(sig65.subarray(1)).addRecoveryBit(recid);
    const pub = s.recoverPublicKey(digest).toRawBytes(true);
    return k1Address(pub);
}

// ── Savanna finalizer policies ──────────────────────────────────────────────

export interface FinalizerJson {
    description: string;
    weight: number;
    public_key: string;
}

export interface FinalizerPolicyJson {
    generation: number;
    threshold: number;
    finalizers: FinalizerJson[];
}

export function packFinalizerPolicy(p: FinalizerPolicyJson): Buffer {
    return Buffer.concat([
        u32(p.generation),
        u64(BigInt(p.threshold)),
        varuint(p.finalizers.length),
        ...p.finalizers.map((f) =>
            Buffer.concat([packString(f.description), u64(BigInt(f.weight)), packBytes(blsKeyBytes(f.public_key))])
        )
    ]);
}

/// finality digest (block_header_state::compute_finality_digest), given l2 inputs.
export function finalityDigest(
    activeGen: number,
    lastPendingGen: number,
    finalityMroot: Buffer,
    lastPendingPolicyDigest: Buffer,
    lastPendingStartTs: number,
    l3Digest: Buffer
): Buffer {
    const l2 = sha256(lastPendingPolicyDigest, u32(lastPendingStartTs), l3Digest);
    return sha256(u32(1), u32(0), u32(activeGen), u32(lastPendingGen), finalityMroot, l2);
}

/// finality_leaf_node_t digest.
export const finalityLeaf = (blockNum: number, ts: number, parentTs: number, fd: Buffer, actionMroot: Buffer): Buffer =>
    sha256(u32(1), u32(0), u32(blockNum), u32(ts), u32(parentTs), fd, actionMroot);

/// Root of a Savanna incremental Merkle tree from its perfect-subtree roots, largest (leftmost)
/// first (spring incremental_merkle_tree::get_root): root = H(t0, H(t1, ... H(tn-2, tn-1))).
export function savannaRootFromSubtrees(subtrees: Buffer[]): Buffer {
    let r = subtrees[subtrees.length - 1];
    for (let i = subtrees.length - 2; i >= 0; i--) r = sha256(subtrees[i], r);
    return r;
}

/// QC strong-vote bitset from its JSON string (fc::dynamic_bitset: character i is bit size-1-i)
/// to the verifier's form: bit i (byte i/8, bit i%8, LSB first) = finalizer i.
export function qcBitsetFromString(s: string, finalizers: number): Buffer {
    if (s.length !== finalizers) throw new Error(`bitset has ${s.length} bits for ${finalizers} finalizers`);
    const out = Buffer.alloc((finalizers + 7) >> 3);
    for (let i = 0; i < finalizers; i++) if (s[s.length - 1 - i] === "1") out[i >> 3] |= 1 << (i & 7);
    return out;
}

const leToBig = (b: Uint8Array): bigint => BigInt("0x" + Buffer.from(b).reverse().toString("hex"));

/// BLS (Spring NUL ciphersuite) check of an aggregate signature over `message`, with keys and
/// signature in Spring's affine little-endian encodings: e(sum(pk), H(m)) == e(G1, sig).
export function verifyBlsAggregate(keys: Buffer[], sig: Buffer, message: Buffer): boolean {
    const {bls12_381: bls} = blsLib;
    let agg = bls.G1.ProjectivePoint.ZERO;
    for (const k of keys) {
        agg = agg.add(bls.G1.ProjectivePoint.fromAffine({x: leToBig(k.subarray(0, 48)), y: leToBig(k.subarray(48, 96))}));
    }
    const Fp2 = bls.fields.Fp2;
    const s = bls.G2.ProjectivePoint.fromAffine({
        x: Fp2.create({c0: leToBig(sig.subarray(0, 48)), c1: leToBig(sig.subarray(48, 96))}),
        y: Fp2.create({c0: leToBig(sig.subarray(96, 144)), c1: leToBig(sig.subarray(144, 192))})
    });
    s.assertValidity();
    const h = bls.G2.hashToCurve(message, {DST: "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"}) as any;
    return bls.fields.Fp12.eql(bls.pairing(agg, h), bls.pairing(bls.G1.ProjectivePoint.BASE, s));
}
