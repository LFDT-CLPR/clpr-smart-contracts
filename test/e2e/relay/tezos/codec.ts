import {createHash} from "node:crypto";
import {blake2b} from "@noble/hashes/blake2b";

/// Tezos encodings used by the Tezos verifier's relayer: base58check, BLAKE2b, key and signature
/// prefixes, block-header and attestation byte layouts (octez `src/proto_025_PsUshuai`).

export type Bytes = Uint8Array;

export const hex = (b: Bytes): `0x${string}` => ("0x" + Buffer.from(b).toString("hex")) as `0x${string}`;
export const unhex = (h: string): Buffer => Buffer.from(h.replace(/^0x/, ""), "hex");
export const cat = (...xs: Bytes[]): Buffer => Buffer.concat(xs.map((x) => Buffer.from(x)));

export const blake2b256 = (b: Bytes): Buffer => Buffer.from(blake2b(b, {dkLen: 32}));
export const blake2b160 = (b: Bytes): Buffer => Buffer.from(blake2b(b, {dkLen: 20}));

export const u8 = (n: number): Buffer => Buffer.from([n & 0xff]);
export const u16 = (n: number): Buffer => {
    const b = Buffer.alloc(2);
    b.writeUInt16BE(n);
    return b;
};
export const i32 = (n: number): Buffer => {
    const b = Buffer.alloc(4);
    b.writeInt32BE(n);
    return b;
};
export const u32 = (n: number): Buffer => {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n);
    return b;
};
export const u64 = (n: bigint | number): Buffer => {
    const b = Buffer.alloc(8);
    b.writeBigUInt64BE(BigInt(n));
    return b;
};
export const i64 = (n: bigint | number): Buffer => {
    const b = Buffer.alloc(8);
    b.writeBigInt64BE(BigInt(n));
    return b;
};

// ── base58check ────────────────────────────────────────────────────────────

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const sha256 = (b: Bytes): Buffer => createHash("sha256").update(b).digest();

export function b58checkDecode(s: string): Buffer {
    let n = 0n;
    for (const c of s) {
        const v = B58.indexOf(c);
        if (v < 0) throw new Error(`base58: bad character in ${s}`);
        n = n * 58n + BigInt(v);
    }
    let h = n.toString(16);
    if (h.length % 2) h = "0" + h;
    let zeros = 0;
    while (s[zeros] === "1") zeros++;
    const raw = Buffer.concat([Buffer.alloc(zeros), n === 0n ? Buffer.alloc(0) : Buffer.from(h, "hex")]);
    const body = raw.subarray(0, raw.length - 4);
    if (!sha256(sha256(body)).subarray(0, 4).equals(raw.subarray(raw.length - 4))) {
        throw new Error(`base58check: bad checksum in ${s}`);
    }
    return body;
}

export function b58checkEncode(prefix: number[], payload: Bytes): string {
    const body = cat(Buffer.from(prefix), payload);
    const raw = cat(body, sha256(sha256(body)).subarray(0, 4));
    let n = BigInt("0x" + (raw.toString("hex") || "0"));
    let s = "";
    while (n > 0n) {
        s = B58[Number(n % 58n)] + s;
        n /= 58n;
    }
    for (const b of raw) {
        if (b !== 0) break;
        s = "1" + s;
    }
    return s;
}

/// Payload of a base58check value whose payload has a known size (drops the prefix bytes).
export const b58payload = (s: string, size: number): Buffer => {
    const b = b58checkDecode(s);
    return b.subarray(b.length - size);
};

// ── keys and signatures ───────────────────────────────────────────────────

/// Tezos signature scheme tags, as in `Signature.Public_key.encoding` (tz1, tz2, tz3, tz4).
export enum Scheme {
    Ed25519 = 0,
    Secp256k1 = 1,
    P256 = 2,
    Bls = 3,
}

export const PK_LEN: Record<number, number> = {0: 32, 1: 33, 2: 33, 3: 48};

export function decodePublicKey(s: string): {scheme: Scheme; key: Buffer} {
    if (s.startsWith("edpk")) return {scheme: Scheme.Ed25519, key: b58payload(s, 32)};
    if (s.startsWith("sppk")) return {scheme: Scheme.Secp256k1, key: b58payload(s, 33)};
    if (s.startsWith("p2pk")) return {scheme: Scheme.P256, key: b58payload(s, 33)};
    if (s.startsWith("BLpk")) return {scheme: Scheme.Bls, key: b58payload(s, 48)};
    throw new Error(`unknown public key ${s}`);
}

/// A generic "sig…" signature is 64 bytes; a BLS "BLsig…" signature is 96 bytes (compressed G2).
export function decodeSignature(s: string): Buffer {
    if (s.startsWith("BLsig")) return b58payload(s, 96);
    if (s.startsWith("sig")) return b58payload(s, 64);
    if (s.startsWith("edsig") || s.startsWith("spsig1") || s.startsWith("p2sig")) return b58payload(s, 64);
    throw new Error(`unknown signature ${s}`);
}

export const chainIdBytes = (s: string): Buffer => b58payload(s, 4);
export const blockHashBytes = (s: string): Buffer => b58payload(s, 32);

// ── block header ───────────────────────────────────────────────────────────

export interface ShellHeaderJson {
    level: number;
    proto: number;
    predecessor: string;
    timestamp: string;
    validation_pass: number;
    operations_hash: string;
    fitness: string[];
    context: string;
}

/// Offsets inside a raw block header (shell header || protocol data), octez `Block_header.shell_header_encoding`.
export function parseHeader(raw: Bytes): {level: number; predecessor: Buffer; context: Buffer; contextOffset: number} {
    const b = Buffer.from(raw);
    const level = b.readInt32BE(0);
    const predecessor = b.subarray(5, 37);
    const fitnessLen = b.readUInt32BE(78);
    const contextOffset = 82 + fitnessLen;
    return {level, predecessor, context: b.subarray(contextOffset, contextOffset + 32), contextOffset};
}

// ── attestations ───────────────────────────────────────────────────────────

export const ATTESTATION_WATERMARK = 0x13;
export const TAG_ATTESTATION = 21;
export const TAG_ATTESTATION_WITH_DAL = 23;
export const TAG_BLS_MODE_ATTESTATION = 41;

/// Zarith natural (`Data_encoding.n`): little-endian 7-bit groups, continuation bit 0x80.
export function zarithN(v: bigint): Buffer {
    const out: number[] = [];
    do {
        let byte = Number(v & 0x7fn);
        v >>= 7n;
        if (v > 0n) byte |= 0x80;
        out.push(byte);
    } while (v > 0n);
    return Buffer.from(out);
}

/// `Z.to_bits` on a 64-bit host: little-endian, padded to a multiple of 8 bytes, empty for zero.
export function zToBits(v: bigint): Buffer {
    if (v === 0n) return Buffer.alloc(0);
    const bytes: number[] = [];
    while (v > 0n) {
        bytes.push(Number(v & 0xffn));
        v >>= 8n;
    }
    while (bytes.length % 8) bytes.push(0);
    return Buffer.from(bytes);
}

/// Zarith integer (`Data_encoding.z`, used by `Bitset.encoding`): first byte carries 6 bits, the sign
/// bit 0x40 and the continuation bit 0x80; then 7-bit groups.
export function zarithZ(v: bigint): Buffer {
    if (v < 0n) throw new Error("zarithZ: negative bitset");
    const out: number[] = [];
    let first = Number(v & 0x3fn);
    v >>= 6n;
    if (v > 0n) first |= 0x80;
    out.push(first);
    while (v > 0n) {
        let byte = Number(v & 0x7fn);
        v >>= 7n;
        if (v > 0n) byte |= 0x80;
        out.push(byte);
    }
    return Buffer.from(out);
}

/// The bytes a tz1/tz2/tz3 attester signs (before BLAKE2b): watermark ‖ chain id ‖ branch ‖ contents.
export function attestationSigningBytes(a: {
    chainId: Bytes;
    branch: Bytes;
    slot: number;
    level: number;
    round: number;
    payloadHash: Bytes;
    dal?: bigint;
}): Buffer {
    const contents =
        a.dal === undefined
            ? cat(u8(TAG_ATTESTATION), u16(a.slot), i32(a.level), i32(a.round), a.payloadHash)
            : cat(u8(TAG_ATTESTATION_WITH_DAL), u16(a.slot), i32(a.level), i32(a.round), a.payloadHash, zarithZ(a.dal));
    return cat(u8(ATTESTATION_WATERMARK), a.chainId, a.branch, contents);
}

/// The unsigned BLS-mode attestation (no watermark): branch ‖ 41 ‖ level ‖ round ‖ payload hash.
export function blsModeAttestation(a: {branch: Bytes; level: number; round: number; payloadHash: Bytes}): Buffer {
    return cat(a.branch, u8(TAG_BLS_MODE_ATTESTATION), i32(a.level), i32(a.round), a.payloadHash);
}
