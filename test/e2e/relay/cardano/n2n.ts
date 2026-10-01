import {connect, type Socket} from "node:net";
import {decode, encArray, encBytes, encMap, encUint, NeedMore, type Item} from "./cbor.js";

/// Minimal Ouroboros node-to-node client (handshake + BlockFetch) used to download whole blocks from a
/// public Cardano relay — Cardano's public HTTP APIs expose neither block headers nor raw block bodies.
/// Network-mux framing per ouroboros-network `Network.Mux.Codec`: u32 timestamp ‖ u16 (mode bit ‖
/// mini-protocol number) ‖ u16 length ‖ payload.

const HANDSHAKE = 0;
const BLOCK_FETCH = 3;

export interface Point {
    slot: bigint;
    hash: Uint8Array;
}

class Mux {
    private buf = Buffer.alloc(0);
    private per = new Map<number, Buffer>();
    private waiters: (() => void)[] = [];
    constructor(private sock: Socket) {
        sock.on("data", (d) => {
            this.buf = Buffer.concat([this.buf, d]);
            while (this.buf.length >= 8) {
                const proto = this.buf.readUInt16BE(4) & 0x7fff;
                const len = this.buf.readUInt16BE(6);
                if (this.buf.length < 8 + len) break;
                const payload = this.buf.subarray(8, 8 + len);
                this.per.set(proto, Buffer.concat([this.per.get(proto) ?? Buffer.alloc(0), payload]));
                this.buf = this.buf.subarray(8 + len);
            }
            this.waiters.splice(0).forEach((w) => w());
        });
    }
    send(proto: number, payload: Buffer) {
        for (let off = 0; off < payload.length || off === 0; off += 0xffff) {
            const chunk = payload.subarray(off, off + 0xffff);
            const h = Buffer.alloc(8);
            h.writeUInt32BE(Number(BigInt(Date.now()) * 1000n & 0xffffffffn), 0);
            h.writeUInt16BE(proto, 4);
            h.writeUInt16BE(chunk.length, 6);
            this.sock.write(Buffer.concat([h, chunk]));
            if (payload.length === 0) break;
        }
    }
    async recv(proto: number, timeoutMs = 60_000): Promise<Item> {
        const deadline = Date.now() + timeoutMs;
        for (;;) {
            const b = this.per.get(proto);
            if (b && b.length) {
                try {
                    const it = decode(b, 0);
                    this.per.set(proto, b.subarray(it.end));
                    return it;
                } catch (e) {
                    if (!(e instanceof NeedMore)) throw e;
                }
            }
            if (Date.now() > deadline) throw new Error(`n2n: timeout on protocol ${proto}`);
            await new Promise<void>((r) => {
                this.waiters.push(r);
                setTimeout(r, 1000);
            });
        }
    }
}

/// Fetch the raw CBOR of the blocks in [from, to] from `host:port` (network magic e.g. 1 = preprod).
export async function fetchBlocks(host: string, port: number, magic: number, from: Point, to: Point): Promise<Uint8Array[]> {
    const sock = connect({host, port});
    await new Promise<void>((res, rej) => {
        sock.once("connect", () => res());
        sock.once("error", rej);
    });
    const mux = new Mux(sock);
    try {
        // MsgProposeVersions: versions 13 and 14, params [magic, initiatorOnlyDiffusionMode, peerSharing, query]
        const params = encArray([encUint(magic), Buffer.from([0xf5]), encUint(0), Buffer.from([0xf4])]);
        mux.send(HANDSHAKE, encArray([encUint(0), encMap([[encUint(13), params], [encUint(14), params]])]));
        const hs = await mux.recv(HANDSHAKE);
        if (hs.t !== "array" || (hs.v[0] as any).v !== 1n) throw new Error(`n2n: handshake refused ${JSON.stringify(hs, (_k, v) => (typeof v === "bigint" ? v.toString() : v)).slice(0, 300)}`);
        const pt = (p: Point) => encArray([encUint(p.slot), encBytes(p.hash)]);
        mux.send(BLOCK_FETCH, encArray([encUint(0), pt(from), pt(to)]));
        const out: Uint8Array[] = [];
        for (;;) {
            const m = await mux.recv(BLOCK_FETCH);
            if (m.t !== "array") throw new Error("n2n: bad message");
            const tag = Number((m.v[0] as any).v);
            if (tag === 3) throw new Error("n2n: MsgNoBlocks");
            if (tag === 2) continue; // MsgStartBatch
            if (tag === 5) break; // MsgBatchDone
            if (tag === 4) {
                const wrapped = m.v[1];
                if (wrapped.t !== "tag" || wrapped.tag !== 24n || wrapped.v.t !== "bytes") throw new Error("n2n: block not tag24");
                out.push(Uint8Array.from(wrapped.v.v));
            }
        }
        mux.send(BLOCK_FETCH, encArray([encUint(1)])); // MsgClientDone
        return out;
    } finally {
        sock.destroy();
    }
}
