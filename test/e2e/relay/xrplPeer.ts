/// Minimal XRP Ledger peer-protocol client, used only to read SHAMap state nodes.
///
/// No public JSON-RPC method returns SHAMap inner nodes (`ledger_entry` returns the leaf only), but
/// every rippled peer serves them over the overlay with `TMGetLedger` (liAS_NODE). This client does
/// the rippled handshake (rippled src/xrpld/overlay/detail/Handshake.cpp) with a throwaway node
/// identity, then asks for the inner nodes on the path to one key.
///
/// Handshake: TLS 1.2, then `GET /` with `Upgrade: XRPL/2.2`. `Session-Signature` is a secp256k1
/// DER signature over sha512Half(sha512(finished) XOR sha512(peerFinished)) with the node key, sent
/// with `Public-Key` (base58 node public key, token type 28). Messages are framed as a 4-byte size and
/// a 2-byte type (ProtocolMessage.h), payload protobuf (include/xrpl/proto/xrpl.proto).
import tls from "node:tls";
import {createHash, randomBytes} from "node:crypto";
import {secp256k1} from "@noble/curves/secp256k1";

const ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

export function xrplBase58(payload: Buffer): string {
    const sum = createHash("sha256").update(createHash("sha256").update(payload).digest()).digest();
    const data = Buffer.concat([payload, sum.subarray(0, 4)]);
    let n = BigInt("0x" + data.toString("hex"));
    let out = "";
    while (n > 0n) {
        out = ALPHABET[Number(n % 58n)] + out;
        n /= 58n;
    }
    for (const b of data) {
        if (b !== 0) break;
        out = ALPHABET[0] + out;
    }
    return out;
}

export function xrplBase58Decode(s: string): Buffer {
    let n = 0n;
    for (const c of s) {
        const i = ALPHABET.indexOf(c);
        if (i < 0) throw new Error(`bad base58 char ${c}`);
        n = n * 58n + BigInt(i);
    }
    let hex = n.toString(16);
    if (hex.length % 2) hex = "0" + hex;
    let lead = 0;
    for (const c of s) {
        if (c !== ALPHABET[0]) break;
        lead++;
    }
    const data = Buffer.concat([Buffer.alloc(lead), Buffer.from(hex, "hex")]);
    const body = data.subarray(0, data.length - 4);
    const sum = createHash("sha256").update(createHash("sha256").update(body).digest()).digest();
    if (!sum.subarray(0, 4).equals(data.subarray(data.length - 4))) throw new Error("bad base58 checksum");
    return body;
}

export const sha512Half = (b: Buffer) => createHash("sha512").update(b).digest().subarray(0, 32);

// ── protobuf (just enough) ───────────────────────────────────────────────

function varint(n: number | bigint): Buffer {
    let v = BigInt(n);
    const out: number[] = [];
    do {
        let b = Number(v & 0x7fn);
        v >>= 7n;
        if (v > 0n) b |= 0x80;
        out.push(b);
    } while (v > 0n);
    return Buffer.from(out);
}
const fieldVarint = (f: number, v: number | bigint) => Buffer.concat([varint((f << 3) | 0), varint(v)]);
const fieldBytes = (f: number, b: Buffer) => Buffer.concat([varint((f << 3) | 2), varint(b.length), b]);

type PbField = {f: number; wt: number; v: bigint | Buffer};
function pbDecode(buf: Buffer): PbField[] {
    const out: PbField[] = [];
    let i = 0;
    const rv = (): bigint => {
        let r = 0n;
        let s = 0n;
        for (;;) {
            const b = buf[i++];
            r |= BigInt(b & 0x7f) << s;
            if (!(b & 0x80)) return r;
            s += 7n;
        }
    };
    while (i < buf.length) {
        const key = Number(rv());
        const f = key >> 3;
        const wt = key & 7;
        if (wt === 0) out.push({f, wt, v: rv()});
        else if (wt === 2) {
            const len = Number(rv());
            out.push({f, wt, v: buf.subarray(i, i + len)});
            i += len;
        } else if (wt === 5) {
            out.push({f, wt, v: BigInt(buf.readUInt32LE(i))});
            i += 4;
        } else if (wt === 1) {
            out.push({f, wt, v: buf.readBigUInt64LE(i)});
            i += 8;
        } else throw new Error(`wire type ${wt}`);
    }
    return out;
}

const MT_PING = 3;
const MT_GET_LEDGER = 31;
const MT_LEDGER_DATA = 32;

export class XrplPeer {
    private sock!: tls.TLSSocket;
    private buf = Buffer.alloc(0);
    private waiters: {type: number; resolve: (b: Buffer) => void; match?: (b: Buffer) => boolean}[] = [];
    private cookie = 1;
    public serverHeaders: Record<string, string> = {};

    constructor(
        private host: string,
        private port = 51235,
        private networkId?: number
    ) {}

    async connect(timeoutMs = 20_000): Promise<void> {
        const priv = randomBytes(32);
        const pub = Buffer.from(secp256k1.getPublicKey(priv, true));
        this.sock = tls.connect({
            host: this.host,
            port: this.port,
            rejectUnauthorized: false, // peers use self-signed certs; identity is the node key below
            maxVersion: "TLSv1.2",
            servername: undefined
        });
        await new Promise<void>((res, rej) => {
            const t = setTimeout(() => rej(new Error(`TLS timeout ${this.host}`)), timeoutMs);
            this.sock.once("secureConnect", () => {
                clearTimeout(t);
                res();
            });
            this.sock.once("error", (e) => {
                clearTimeout(t);
                rej(e);
            });
        });
        const fin = this.sock.getFinished()!;
        const peerFin = this.sock.getPeerFinished()!;
        const c1 = createHash("sha512").update(fin).digest();
        const c2 = createHash("sha512").update(peerFin).digest();
        const x = Buffer.alloc(64);
        for (let i = 0; i < 64; i++) x[i] = c1[i] ^ c2[i];
        const shared = sha512Half(x);
        const sig = secp256k1.sign(shared, priv, {lowS: true}).toDERRawBytes();
        const headers = [
            "GET / HTTP/1.1",
            "User-Agent: clpr-verifier-fixture/0.1",
            "Upgrade: XRPL/2.2",
            "Connection: Upgrade",
            "Connect-As: Peer",
            "Crawl: private",
            ...(this.networkId !== undefined ? [`Network-ID: ${this.networkId}`] : []),
            `Public-Key: ${xrplBase58(Buffer.concat([Buffer.from([28]), pub]))}`,
            `Session-Signature: ${Buffer.from(sig).toString("base64")}`,
            "",
            ""
        ].join("\r\n");
        this.sock.write(headers);
        const head = await new Promise<string>((res, rej) => {
            let acc = Buffer.alloc(0);
            const t = setTimeout(() => rej(new Error(`handshake timeout ${this.host}`)), timeoutMs);
            const onData = (d: Buffer) => {
                acc = Buffer.concat([acc, d]);
                const end = acc.indexOf("\r\n\r\n");
                if (end >= 0) {
                    clearTimeout(t);
                    this.sock.off("data", onData);
                    this.buf = acc.subarray(end + 4);
                    res(acc.subarray(0, end).toString());
                }
            };
            this.sock.on("data", onData);
            this.sock.once("close", () => rej(new Error(`closed during handshake ${this.host}: ${acc.toString().slice(0, 300)}`)));
        });
        const lines = head.split("\r\n");
        if (!/ 101 /.test(lines[0])) {
            const body = this.buf.toString().slice(0, 400);
            this.sock.destroy();
            throw new Error(`peer refused (${lines[0]}): ${body}`);
        }
        for (const l of lines.slice(1)) {
            const k = l.indexOf(":");
            if (k > 0) this.serverHeaders[l.slice(0, k).toLowerCase()] = l.slice(k + 1).trim();
        }
        this.sock.on("data", (d: Buffer) => {
            this.buf = Buffer.concat([this.buf, d]);
            this.pump();
        });
        this.pump();
    }

    private pump() {
        for (;;) {
            if (this.buf.length < 6) return;
            if (this.buf[0] & 0x80) throw new Error("compressed message (not requested)");
            const size = this.buf.readUInt32BE(0) & 0x03ffffff;
            if (this.buf.length < 6 + size) return;
            const type = this.buf.readUInt16BE(4);
            const payload = this.buf.subarray(6, 6 + size);
            this.buf = this.buf.subarray(6 + size);
            if (type === MT_PING) {
                const f = pbDecode(payload);
                const isPing = f.find((x) => x.f === 1)?.v === 0n;
                if (isPing) {
                    const seq = f.find((x) => x.f === 2)?.v as bigint | undefined;
                    this.send(MT_PING, Buffer.concat([fieldVarint(1, 1), ...(seq !== undefined ? [fieldVarint(2, seq)] : [])]));
                }
                continue;
            }
            const i = this.waiters.findIndex((w) => w.type === type && (!w.match || w.match(payload)));
            if (i >= 0) {
                const [w] = this.waiters.splice(i, 1);
                w.resolve(Buffer.from(payload));
            }
        }
    }

    private send(type: number, payload: Buffer) {
        const h = Buffer.alloc(6);
        h.writeUInt32BE(payload.length, 0);
        h.writeUInt16BE(type, 4);
        this.sock.write(Buffer.concat([h, payload]));
    }

    /// Request account-state SHAMap nodes by node id (33 bytes: 32-byte masked path + depth).
    /// Returns [nodeid, wire node data] pairs.
    async getStateNodes(ledgerHash: Buffer, nodeIds: Buffer[], timeoutMs = 15_000): Promise<{id: Buffer; data: Buffer}[]> {
        const cookie = this.cookie++;
        const msg = Buffer.concat([
            fieldVarint(1, 2), // itype = liAS_NODE
            fieldBytes(3, ledgerHash),
            ...nodeIds.map((id) => fieldBytes(5, id)),
            fieldVarint(6, cookie)
        ]);
        const reply = new Promise<Buffer>((resolve, reject) => {
            const t = setTimeout(() => reject(new Error(`TMLedgerData timeout from ${this.host}`)), timeoutMs);
            this.waiters.push({
                type: MT_LEDGER_DATA,
                match: (b) => pbDecode(b).some((x) => x.f === 5 && x.v === BigInt(cookie)),
                resolve: (b) => {
                    clearTimeout(t);
                    resolve(b);
                }
            });
        });
        this.send(MT_GET_LEDGER, msg);
        const fields = pbDecode(await reply);
        const err = fields.find((x) => x.f === 6);
        if (err) throw new Error(`peer ${this.host} TMLedgerData error ${err.v}`);
        return fields
            .filter((x) => x.f === 4)
            .map((x) => {
                const n = pbDecode(x.v as Buffer);
                return {data: n.find((y) => y.f === 1)!.v as Buffer, id: (n.find((y) => y.f === 2)?.v as Buffer) ?? Buffer.alloc(0)};
            });
    }

    close() {
        this.sock?.destroy();
    }
}

/// SHAMapNodeID wire form: 32-byte key masked to `depth` nibbles, then the depth byte.
export function nodeId(key: Buffer, depth: number): Buffer {
    const id = Buffer.alloc(33);
    key.copy(id, 0, 0, Math.ceil(depth / 2));
    if (depth % 2) id[Math.floor(depth / 2)] &= 0xf0;
    id[32] = depth;
    return id;
}

export const nibble = (key: Buffer, depth: number) => (depth % 2 ? key[depth >> 1] & 0x0f : key[depth >> 1] >> 4);

/// Parse a wire inner node (SHAMapInnerNode::serializeForWire) into its 16 child hashes.
export function parseWireInner(data: Buffer): Buffer[] | null {
    const t = data[data.length - 1];
    const kids = Array.from({length: 16}, () => Buffer.alloc(32));
    if (t === 2) {
        if (data.length !== 16 * 32 + 1) throw new Error("bad full inner");
        for (let i = 0; i < 16; i++) kids[i] = data.subarray(i * 32, i * 32 + 32);
        return kids;
    }
    if (t === 3) {
        const n = (data.length - 1) / 33;
        for (let i = 0; i < n; i++) kids[data[i * 33 + 32]] = data.subarray(i * 33, i * 33 + 32);
        return kids;
    }
    return null; // a leaf
}

const PREFIX_INNER = Buffer.from("MIN\0", "latin1");
const PREFIX_LEAF = Buffer.from("MLN\0", "latin1");
export const innerHash = (kids: Buffer[]) => sha512Half(Buffer.concat([PREFIX_INNER, ...kids]));
export const stateLeafHash = (data: Buffer, key: Buffer) => sha512Half(Buffer.concat([PREFIX_LEAF, data, key]));

/// Walk from the state root to `key` over the overlay. Returns the 16 child hashes of each inner node
/// on the path (root first) and the leaf's serialized ledger entry, all checked against `accountHash`.
export async function fetchStateProof(
    peer: XrplPeer,
    ledgerHash: Buffer,
    accountHash: Buffer,
    key: Buffer
): Promise<{inners: Buffer[][]; leafData: Buffer}> {
    const inners: Buffer[][] = [];
    let expect = accountHash;
    for (let depth = 0; depth < 64; depth++) {
        const nodes = await peer.getStateNodes(ledgerHash, [nodeId(key, depth)]);
        if (nodes.length === 0) throw new Error(`no node at depth ${depth}`);
        // The reply may carry extra (descendant) nodes; take the one whose hash is the expected one.
        let hit: Buffer[] | null | undefined;
        let leaf: Buffer | undefined;
        for (const n of nodes) {
            const kids = parseWireInner(n.data);
            if (kids) {
                if (innerHash(kids).equals(expect)) hit = kids;
            } else if (n.data[n.data.length - 1] === 1) {
                const body = n.data.subarray(0, n.data.length - 1);
                const k = body.subarray(body.length - 32);
                const d = body.subarray(0, body.length - 32);
                if (k.equals(key) && stateLeafHash(d, k).equals(expect)) leaf = d;
            }
        }
        if (leaf) return {inners, leafData: leaf};
        if (!hit) throw new Error(`depth ${depth}: no node matches the expected hash`);
        inners.push(hit);
        expect = hit[nibble(key, depth)];
        if (expect.equals(Buffer.alloc(32))) throw new Error(`key not present (empty branch at depth ${depth})`);
    }
    throw new Error("path deeper than 64");
}
