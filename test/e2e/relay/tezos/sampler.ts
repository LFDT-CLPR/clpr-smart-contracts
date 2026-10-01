import {blake2b256, cat, i32, PK_LEN, type Bytes} from "./codec.js";

/// The per-cycle delegate sampler (`Storage.Delegate_sampler_state`, `Sampler.encoding
/// Raw_context.consensus_pk_encoding`) and the attestation-slot owner draw
/// (`Delegate_sampler.Random.owner`), octez src/proto_025_PsUshuai/lib_protocol.

export interface ConsensusPk {
    scheme: number; // 0 ed25519, 1 secp256k1, 2 p256, 3 bls
    key: Buffer; // raw public key (32 / 33 / 33 / 48 bytes)
    delegate?: Buffer; // 21-byte pkh (tag ‖ hash) when it differs from the consensus key's
    companion?: Buffer; // 48-byte BLS companion key (tz4 bakers with DAL)
    offset: number; // byte offset of the entry inside the encoded sampler
}

export interface Sampler {
    total: bigint;
    support: ConsensusPk[];
    p: bigint[];
    alias: number[];
    /// Byte offsets of the three arrays' element lists (for the on-chain parser checks).
    pOffset: number;
    aliasOffset: number;
}

class Reader {
    o = 0;
    constructor(readonly b: Buffer) {}
    take(n: number): Buffer {
        if (this.o + n > this.b.length) throw new Error("sampler: truncated");
        const v = this.b.subarray(this.o, this.o + n);
        this.o += n;
        return v;
    }
    u8 = () => this.take(1)[0];
    u32 = () => this.take(4).readUInt32BE(0);
    i64 = () => this.take(8).readBigInt64BE(0);
}

function readPk(r: Reader): ConsensusPk {
    const offset = r.o;
    const scheme = r.u8();
    const key = Buffer.from(r.take(PK_LEN[scheme]));
    const delegate = r.u8() ? Buffer.from(r.take(21)) : undefined;
    const companion = r.u8() ? Buffer.from(r.take(48)) : undefined;
    return {scheme, key, delegate, companion, offset};
}

export function parseSampler(bytes: Bytes): Sampler {
    const r = new Reader(Buffer.from(bytes));
    const total = r.i64();
    const arr = <T>(f: (r: Reader) => T): {els: T[]; listOffset: number} => {
        const n = r.u32();
        f(r); // fallback element
        const size = r.u32();
        const listOffset = r.o;
        const end = r.o + size;
        const els: T[] = [];
        while (r.o < end) els.push(f(r));
        if (els.length !== n) throw new Error(`sampler: array length ${els.length} != ${n}`);
        return {els, listOffset};
    };
    const support = arr(readPk).els;
    const p = arr((r) => r.i64());
    const alias = arr((r) => r.u32() | 0);
    if (r.o !== r.b.length) throw new Error("sampler: trailing bytes");
    return {total, support, p: p.els, alias: alias.els, pOffset: p.listOffset, aliasOffset: alias.listOffset};
}

const INT64_MAX = (1n << 63n) - 1n;

function takeInt64(bound: bigint, state: {b: Buffer; n: number}): bigint {
    const dropIfOver = INT64_MAX - (INT64_MAX % bound);
    for (;;) {
        if (state.n > state.b.length - 8) {
            state.b = blake2b256(state.b);
            state.n = 0;
            continue;
        }
        let r = state.b.readBigInt64BE(state.n);
        r = r === -(1n << 63n) ? 0n : r < 0n ? -r : r;
        if (r >= dropIfOver) {
            state.n += 8;
            continue;
        }
        state.n += 8;
        return r % bound;
    }
}

/// Index into `support` of the owner of attestation slot `slot` at the level whose position in its
/// cycle is `cyclePosition`.
export function slotOwner(s: Sampler, seed: Bytes, cyclePosition: number, slot: number): number {
    const state = {b: blake2b256(cat(seed, i32(cyclePosition), i32(slot))), n: 0};
    const i = Number(takeInt64(BigInt(s.support.length), state));
    const elt = takeInt64(s.total, state);
    return elt < s.p[i] ? i : s.alias[i];
}
