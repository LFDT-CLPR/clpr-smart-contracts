import {keccak_256} from "@noble/hashes/sha3";
import {matrix} from "./sumhash.js";

/// SumHash512 nibble table for ClprSumHash512Engine: entry (p, v) for nibble position p (0..255 over the
/// 128-byte compression input; byte p/2, low nibble when p is even) and nibble value v (0..15) is the
/// 8-lane sum Σ_{bit b of v} A[i][4p + b] (mod 2^64), stored as two 32-byte words: word 0 = lanes 0..3,
/// word 1 = lanes 4..7, lane k of a word in bits [64k, 64k + 64) counted from the least significant bit.
/// The 256 KiB table is split into 16 chunks of 16 nibble positions (16 KiB), each deployed as the
/// runtime code `0x00 ‖ chunk` of a data contract.

export const CHUNKS = 16;
export const CHUNK_BYTES = 16384;

export function nibbleTable(): Buffer {
    const A = matrix();
    const out = Buffer.alloc(256 * 16 * 64);
    const M = (1n << 64n) - 1n;
    for (let p = 0; p < 256; p++) {
        for (let v = 1; v < 16; v++) {
            const lanes = new Array<bigint>(8).fill(0n);
            for (let b = 0; b < 4; b++) {
                if (!((v >> b) & 1)) continue;
                const col = 4 * p + b;
                for (let i = 0; i < 8; i++) lanes[i] = (lanes[i] + A[i * 1024 + col]) & M;
            }
            let w0 = 0n;
            let w1 = 0n;
            for (let k = 0; k < 4; k++) {
                w0 |= lanes[k] << BigInt(64 * k);
                w1 |= lanes[4 + k] << BigInt(64 * k);
            }
            const off = (p * 16 + v) * 64;
            Buffer.from(w0.toString(16).padStart(64, "0"), "hex").copy(out, off);
            Buffer.from(w1.toString(16).padStart(64, "0"), "hex").copy(out, off + 32);
        }
    }
    return out;
}

/// Runtime code of chunk i: 0x00 (STOP) ‖ 16 KiB of table.
export function chunkCode(table: Buffer, i: number): Buffer {
    return Buffer.concat([Buffer.from([0]), table.subarray(i * CHUNK_BYTES, (i + 1) * CHUNK_BYTES)]);
}

export function chunkCodeHashes(table = nibbleTable()): string[] {
    return Array.from({length: CHUNKS}, (_, i) => "0x" + Buffer.from(keccak_256(chunkCode(table, i))).toString("hex"));
}
