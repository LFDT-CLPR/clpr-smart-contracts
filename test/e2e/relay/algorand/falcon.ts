import {shake256} from "@noble/hashes/sha3";

/// Reference verifier for Algorand's deterministic Falcon-1024 (algorand/falcon `deterministic1024.c`,
/// `falcon_det1024_verify_compressed`): the 1-byte salt version replaces Falcon's 40-byte nonce, the
/// fixed salt is `version ‖ 0x0a ‖ "FALCON_DET" ‖ 0…` (40 bytes), c = HashToPoint(SHAKE256(salt ‖ msg)),
/// s1 = c − s2·h mod (q, x^1024 + 1), accept iff ‖(s1, s2)‖² ≤ 70265242.

export const Q = 12289;
export const N = 1024;
export const L2BOUND = 70265242;

export function decodePubkey(pk: Uint8Array): Int32Array {
    if (pk.length !== 1793 || pk[0] !== 0x0a) throw new Error("falcon: bad public key header");
    const h = new Int32Array(N);
    let acc = 0;
    let accLen = 0;
    let u = 0;
    for (let i = 1; i < pk.length && u < N; i++) {
        acc = ((acc << 8) | pk[i]) >>> 0;
        accLen += 8;
        if (accLen >= 14) {
            accLen -= 14;
            const w = (acc >>> accLen) & 0x3fff;
            if (w >= Q) throw new Error("falcon: coefficient ≥ q");
            h[u++] = w;
        }
        acc &= (1 << accLen) - 1;
    }
    if (u !== N) throw new Error("falcon: short key");
    return h;
}

/// Compressed s2 (after the 2-byte header ‖ salt-version).
export function decodeCompressed(buf: Uint8Array): Int32Array {
    const x = new Int32Array(N);
    let acc = 0;
    let accLen = 0;
    let v = 0;
    for (let u = 0; u < N; u++) {
        if (v >= buf.length) throw new Error("falcon: short sig");
        acc = ((acc << 8) | buf[v++]) & 0xffff;
        const b = acc >>> accLen;
        const s = b & 128;
        let m = b & 127;
        for (;;) {
            if (accLen === 0) {
                if (v >= buf.length) throw new Error("falcon: short sig");
                acc = ((acc << 8) | buf[v++]) & 0xffff;
                accLen = 8;
            }
            accLen--;
            if (((acc >>> accLen) & 1) !== 0) break;
            m += 128;
            if (m > 2047) throw new Error("falcon: coefficient too large");
        }
        if (s && m === 0) throw new Error("falcon: -0");
        x[u] = s ? -m : m;
    }
    if ((acc & ((1 << accLen) - 1)) !== 0) throw new Error("falcon: trailing bits");
    if (v !== buf.length) throw new Error("falcon: trailing bytes");
    return x;
}

export function detSalt(version: number): Uint8Array {
    const s = new Uint8Array(40);
    s[0] = version;
    s[1] = 10;
    s.set(Buffer.from("FALCON_DET"), 2);
    return s;
}

export function hashToPoint(salt: Uint8Array, msg: Uint8Array): Int32Array {
    const c = new Int32Array(N);
    let stream = shake256(Buffer.concat([salt, msg]), {dkLen: 4096});
    let off = 0;
    let n = 0;
    while (n < N) {
        if (off + 2 > stream.length) stream = shake256(Buffer.concat([salt, msg]), {dkLen: stream.length * 2});
        const w = (stream[off] << 8) | stream[off + 1];
        off += 2;
        if (w < 61445) c[n++] = w % Q;
    }
    return c;
}

/// Bytes of SHAKE256 output consumed by hash-to-point (for gas accounting).
export function hashToPointBytes(salt: Uint8Array, msg: Uint8Array): number {
    const stream = shake256(Buffer.concat([salt, msg]), {dkLen: 8192});
    let off = 0;
    let n = 0;
    while (n < N) {
        const w = (stream[off] << 8) | stream[off + 1];
        off += 2;
        if (w < 61445) n++;
    }
    return off;
}

export function verifyDet1024(pk: Uint8Array, sig: Uint8Array, msg: Uint8Array): boolean {
    if (sig.length < 3 || sig[0] !== 0xba) return false;
    const h = decodePubkey(pk);
    const s2 = decodeCompressed(sig.subarray(2));
    const c = hashToPoint(detSalt(sig[1]), msg);
    // t = s2·h mod (x^N + 1, q)
    const t = new Float64Array(N);
    const tt = new Array<number>(N).fill(0);
    for (let i = 0; i < N; i++) {
        if (s2[i] === 0) continue;
        for (let j = 0; j < N; j++) {
            const k = i + j;
            const p = s2[i] * h[j];
            if (k < N) tt[k] += p;
            else tt[k - N] -= p;
        }
    }
    void t;
    let norm = 0;
    for (let i = 0; i < N; i++) {
        let s1 = (((c[i] - tt[i]) % Q) + Q) % Q;
        if (s1 > Q >> 1) s1 -= Q;
        norm += s1 * s1 + s2[i] * s2[i];
    }
    return norm <= L2BOUND;
}

/// Compressed → CT ("constant-time") encoding: header 0xDA ‖ salt version ‖ 1024 × 12-bit two's complement.
export function toCT(sig: Uint8Array): Uint8Array {
    const s2 = decodeCompressed(sig.subarray(2));
    const out = new Uint8Array(1538);
    out[0] = 0xda;
    out[1] = sig[1];
    let acc = 0;
    let accLen = 0;
    let p = 2;
    for (let i = 0; i < N; i++) {
        acc = (acc << 12) | (s2[i] & 0xfff);
        accLen += 12;
        while (accLen >= 8) {
            accLen -= 8;
            out[p++] = (acc >>> accLen) & 0xff;
        }
        acc &= (1 << accLen) - 1;
    }
    if (accLen > 0) out[p++] = (acc << (8 - accLen)) & 0xff;
    return out;
}
