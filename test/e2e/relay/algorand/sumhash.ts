import {shake256} from "@noble/hashes/sha3";

/// SumHash512 (algorand/go-sumhash): subset-sum compression A·x mod 2^64 with an 8 × 1024 matrix
/// expanded by SHAKE256(u16 64 ‖ u16 8 ‖ u16 1024 ‖ "Algorand"), Merkle–Damgård with a zero IV,
/// 64-byte blocks and padding `0x01 0… ‖ bitlen LE64 ‖ 0 LE64` (to a 48 mod 64 boundary first).

let MATRIX: BigUint64Array | null = null;
export function matrix(): BigUint64Array {
    if (MATRIX) return MATRIX;
    const seed = Buffer.concat([Buffer.from([64, 0, 8, 0, 0, 4]), Buffer.from("Algorand")]);
    const bytes = shake256(seed, {dkLen: 8 * 1024 * 8});
    MATRIX = new BigUint64Array(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.length));
    return MATRIX; // row-major: A[i][j] = MATRIX[i*1024 + j] (little-endian words)
}

export function compress(h: Uint8Array, block: Uint8Array): Uint8Array {
    const A = matrix();
    const msg = Buffer.concat([h, block]);
    const out = Buffer.alloc(64);
    for (let i = 0; i < 8; i++) {
        let x = 0n;
        for (let j = 0; j < 128; j++) {
            const byte = msg[j];
            if (!byte) continue;
            for (let b = 0; b < 8; b++) if ((byte >> b) & 1) x += A[i * 1024 + 8 * j + b];
        }
        out.writeBigUInt64LE(BigInt.asUintN(64, x), 8 * i);
    }
    return out;
}

export function sumhash512(data: Uint8Array): Uint8Array {
    const len = data.length;
    const B = 64;
    const P = B - 16;
    const padLen = len % B < P ? P - (len % B) : B + P - (len % B);
    const pad = Buffer.alloc(padLen);
    pad[0] = 0x01;
    const tail = Buffer.alloc(16);
    tail.writeBigUInt64LE(BigInt(len) * 8n, 0);
    const all = Buffer.concat([data, pad, tail]);
    let h: Uint8Array = Buffer.alloc(64);
    for (let off = 0; off < all.length; off += B) h = compress(h, all.subarray(off, off + B));
    return h;
}
