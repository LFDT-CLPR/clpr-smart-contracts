/// Minimal MessagePack reader that keeps byte offsets (go-algorand msgp canonical encoding: maps
/// with sorted keys, omitempty, minimal integers, bin8/16/32 for byte slices).

export type Mp = {t: "int"; v: bigint} | {t: "bin"; v: Uint8Array} | {t: "str"; v: string} | {t: "arr"; v: Node[]} | {t: "map"; v: [Node, Node][]} | {t: "nil"} | {t: "bool"; v: boolean};
export type Node = Mp & {start: number; end: number};

export function mpDecode(b: Uint8Array, off = 0): Node {
    const start = off;
    const t = b[off++];
    const be = (n: number) => {
        let v = 0n;
        for (let i = 0; i < n; i++) v = (v << 8n) | BigInt(b[off++]);
        return v;
    };
    const fin = (x: Mp): Node => ({...x, start, end: off}) as Node;
    const arr = (n: number) => {
        const v: Node[] = [];
        for (let i = 0; i < n; i++) {
            const x = mpDecode(b, off);
            off = x.end;
            v.push(x);
        }
        return fin({t: "arr", v});
    };
    const map = (n: number) => {
        const v: [Node, Node][] = [];
        for (let i = 0; i < n; i++) {
            const k = mpDecode(b, off);
            off = k.end;
            const x = mpDecode(b, off);
            off = x.end;
            v.push([k, x]);
        }
        return fin({t: "map", v});
    };
    const bin = (n: number, str: boolean) => {
        const v = b.subarray(off, off + n);
        off += n;
        return fin(str ? {t: "str", v: Buffer.from(v).toString("latin1")} : {t: "bin", v});
    };
    if (t <= 0x7f) return fin({t: "int", v: BigInt(t)});
    if (t >= 0x80 && t <= 0x8f) return map(t & 0xf);
    if (t >= 0x90 && t <= 0x9f) return arr(t & 0xf);
    if (t >= 0xa0 && t <= 0xbf) return bin(t & 0x1f, true);
    if (t >= 0xe0) return fin({t: "int", v: BigInt(t - 256)});
    switch (t) {
        case 0xc0:
            return fin({t: "nil"});
        case 0xc2:
            return fin({t: "bool", v: false});
        case 0xc3:
            return fin({t: "bool", v: true});
        case 0xc4:
            return bin(Number(be(1)), false);
        case 0xc5:
            return bin(Number(be(2)), false);
        case 0xc6:
            return bin(Number(be(4)), false);
        case 0xcc:
            return fin({t: "int", v: be(1)});
        case 0xcd:
            return fin({t: "int", v: be(2)});
        case 0xce:
            return fin({t: "int", v: be(4)});
        case 0xcf:
            return fin({t: "int", v: be(8)});
        case 0xd9:
            return bin(Number(be(1)), true);
        case 0xda:
            return bin(Number(be(2)), true);
        case 0xdc:
            return arr(Number(be(2)));
        case 0xdd:
            return arr(Number(be(4)));
        case 0xde:
            return map(Number(be(2)));
        case 0xdf:
            return map(Number(be(4)));
    }
    throw new Error(`msgpack: tag 0x${t.toString(16)} at ${start}`);
}

export function get(n: Node, key: string): Node | undefined {
    if (n.t !== "map") throw new Error("msgpack: not a map");
    return n.v.find(([k]) => k.t === "str" && k.v === key)?.[1];
}
export const bin = (n: Node | undefined): Uint8Array => (n ? (n as any).v : new Uint8Array());
export const int = (n: Node | undefined): bigint => (n ? (n as any).v : 0n);

// ── canonical encoder (subset) ──────────────────────────────────────────────
export function encUint(v: bigint): Buffer {
    if (v < 128n) return Buffer.from([Number(v)]);
    if (v < 256n) return Buffer.from([0xcc, Number(v)]);
    if (v < 65536n) return Buffer.from([0xcd, Number(v >> 8n), Number(v & 0xffn)]);
    if (v < 1n << 32n) {
        const b = Buffer.alloc(5);
        b[0] = 0xce;
        b.writeUInt32BE(Number(v), 1);
        return b;
    }
    const b = Buffer.alloc(9);
    b[0] = 0xcf;
    b.writeBigUInt64BE(v, 1);
    return b;
}
export function encBin(x: Uint8Array): Buffer {
    if (x.length < 256) return Buffer.concat([Buffer.from([0xc4, x.length]), x]);
    const h = Buffer.alloc(3);
    h[0] = 0xc5;
    h.writeUInt16BE(x.length, 1);
    return Buffer.concat([h, x]);
}
export const encStr = (s: string) => Buffer.concat([Buffer.from([0xa0 | s.length]), Buffer.from(s)]);
