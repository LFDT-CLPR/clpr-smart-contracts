/// Minimal CBOR (RFC 8949) reader that keeps byte offsets, so proof builders can slice the exact
/// original encodings that Cardano hashes (block header, transaction body).

export type Cbor =
    | {t: "uint"; v: bigint}
    | {t: "nint"; v: bigint}
    | {t: "bytes"; v: Uint8Array}
    | {t: "text"; v: string}
    | {t: "array"; v: Item[]}
    | {t: "map"; v: [Item, Item][]}
    | {t: "tag"; tag: bigint; v: Item}
    | {t: "simple"; v: number};

export type Item = Cbor & {start: number; end: number};

export class NeedMore extends Error {}

export function decode(b: Uint8Array, off = 0): Item {
    const need = (n: number) => {
        if (off + n > b.length) throw new NeedMore("cbor: need more bytes");
    };
    const start = off;
    need(1);
    const ib = b[off++];
    const major = ib >> 5;
    const ai = ib & 0x1f;
    const readArg = (): bigint | null => {
        if (ai < 24) return BigInt(ai);
        const n = ai === 24 ? 1 : ai === 25 ? 2 : ai === 26 ? 4 : ai === 27 ? 8 : ai === 31 ? -1 : -2;
        if (n === -2) throw new Error("cbor: bad additional info");
        if (n === -1) return null; // indefinite
        need(n);
        let v = 0n;
        for (let i = 0; i < n; i++) v = (v << 8n) | BigInt(b[off++]);
        return v;
    };
    const arg = readArg();
    const fin = (c: Cbor): Item => ({...c, start, end: off}) as Item;
    switch (major) {
        case 0:
            return fin({t: "uint", v: arg!});
        case 1:
            return fin({t: "nint", v: -1n - arg!});
        case 2:
        case 3: {
            let bytes: Uint8Array;
            if (arg === null) {
                const parts: Uint8Array[] = [];
                for (;;) {
                    need(1);
                    if (b[off] === 0xff) {
                        off++;
                        break;
                    }
                    const p = decode(b, off);
                    off = p.end;
                    parts.push(p.t === "bytes" ? p.v : Buffer.from((p as any).v));
                }
                bytes = Buffer.concat(parts);
            } else {
                need(Number(arg));
                bytes = b.subarray(off, off + Number(arg));
                off += Number(arg);
            }
            return major === 2 ? fin({t: "bytes", v: bytes}) : fin({t: "text", v: Buffer.from(bytes).toString("utf8")});
        }
        case 4: {
            const v: Item[] = [];
            if (arg === null) {
                for (;;) {
                    need(1);
                    if (b[off] === 0xff) {
                        off++;
                        break;
                    }
                    const x = decode(b, off);
                    off = x.end;
                    v.push(x);
                }
            } else
                for (let i = 0n; i < arg; i++) {
                    const x = decode(b, off);
                    off = x.end;
                    v.push(x);
                }
            return fin({t: "array", v});
        }
        case 5: {
            const v: [Item, Item][] = [];
            const one = () => {
                const k = decode(b, off);
                off = k.end;
                const x = decode(b, off);
                off = x.end;
                v.push([k, x]);
            };
            if (arg === null) {
                for (;;) {
                    need(1);
                    if (b[off] === 0xff) {
                        off++;
                        break;
                    }
                    one();
                }
            } else for (let i = 0n; i < arg; i++) one();
            return fin({t: "map", v});
        }
        case 6: {
            const x = decode(b, off);
            off = x.end;
            return fin({t: "tag", tag: arg!, v: x});
        }
        default:
            return fin({t: "simple", v: Number(arg ?? 31n)});
    }
}

export const raw = (b: Uint8Array, it: Item) => b.subarray(it.start, it.end);

// ── Encoder (definite lengths, canonical heads) ─────────────────────────────

function head(major: number, n: bigint): Buffer {
    if (n < 24n) return Buffer.from([(major << 5) | Number(n)]);
    const sizes: [number, number][] = [
        [24, 1],
        [25, 2],
        [26, 4],
        [27, 8],
    ];
    for (const [ai, len] of sizes) {
        if (n < 1n << BigInt(8 * len)) {
            const b = Buffer.alloc(1 + len);
            b[0] = (major << 5) | ai;
            for (let i = 0; i < len; i++) b[len - i] = Number((n >> BigInt(8 * i)) & 0xffn);
            return b;
        }
    }
    throw new Error("cbor: too large");
}
export const encUint = (n: bigint | number) => head(0, BigInt(n));
export const encInt = (n: bigint | number) => (BigInt(n) >= 0n ? head(0, BigInt(n)) : head(1, -1n - BigInt(n)));
export const encBytes = (b: Uint8Array) => Buffer.concat([head(2, BigInt(b.length)), b]);
export const encText = (s: string) => Buffer.concat([head(3, BigInt(Buffer.byteLength(s))), Buffer.from(s)]);
export const encArray = (items: Uint8Array[]) => Buffer.concat([head(4, BigInt(items.length)), ...items]);
export const encMap = (pairs: [Uint8Array, Uint8Array][]) => Buffer.concat([head(5, BigInt(pairs.length)), ...pairs.flat()]);
export const encTag = (tag: bigint | number, item: Uint8Array) => Buffer.concat([head(6, BigInt(tag)), item]);
