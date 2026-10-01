import {createCipheriv, createHash, randomBytes, type Cipheriv} from "node:crypto";
import {Socket} from "node:net";
import {ed25519, edwardsToMontgomeryPriv, edwardsToMontgomeryPub, x25519} from "@noble/curves/ed25519";

/// Minimal TON liteserver client (ADNL over TCP + TL), enough to record the TON live fixtures.
///
/// Public HTTP gateways (tonapi, toncenter) cannot decode the `liteServer.signatureSet.simplex`
/// signature sets that TON mainnet and testnet now return, so the fixture builder talks to a public
/// liteserver from ton.org/global.config.json directly. Protocol: docs.ton.org "ADNL TCP — liteserver";
/// TL constructor ids are crc32 of the schema lines in ton-blockchain/ton `tl/generate/scheme/lite_api.tl`.

const sha256 = (b: Uint8Array): Buffer => createHash("sha256").update(b).digest();

export const TL = {
    adnlMessageQuery: 0xb48bf97a,
    adnlMessageAnswer: 0x0fac8416,
    liteServerQuery: 0x798c06df,
    liteServerError: 0xbba9e148,
    getMasterchainInfo: 0x89b5e62e,
    masterchainInfo: 0x85832881,
    getBlockHeader: 0x21ec069e,
    blockHeader: 0x752d8219,
    lookupBlock: 0xfac8f71e,
    getBlockProof: 0x8aea9c44,
    partialBlockProof: 0x8ed0d2c1,
    blockLinkBack: 0xef7e1bef,
    blockLinkForward: 0x520fce1c,
    signatureSetOrdinary: 0xf644a6e6,
    signatureSetSimplex: 0xac249800,
    signature: 0xa3def855,
    getAccountState: 0x6b890e25,
    getAccountStatePrunned: 0x5a698507,
    accountState: 0x7079c751,
    accountId: 0x75a0e2c5,
    getConfigParams: 0x2a111c19,
    configInfo: 0xae7b272f,
    getBlock: 0x6377cf0d,
    blockData: 0xa574ed6c,
    boolTrue: 0x997275b5,
    boolFalse: 0xbc799737,
} as const;

// ── TL ──────────────────────────────────────────────────────────────────────

export class TlWriter {
    private parts: Buffer[] = [];
    u32(v: number): this {
        const b = Buffer.alloc(4);
        b.writeUInt32LE(v >>> 0);
        this.parts.push(b);
        return this;
    }
    i32(v: number): this {
        const b = Buffer.alloc(4);
        b.writeInt32LE(v);
        this.parts.push(b);
        return this;
    }
    i64(v: bigint): this {
        const b = Buffer.alloc(8);
        b.writeBigInt64LE(v);
        this.parts.push(b);
        return this;
    }
    raw(b: Uint8Array): this {
        this.parts.push(Buffer.from(b));
        return this;
    }
    bytes(b: Uint8Array): this {
        let head: Buffer;
        if (b.length <= 253) head = Buffer.from([b.length]);
        else {
            head = Buffer.alloc(4);
            head[0] = 0xfe;
            head.writeUIntLE(b.length, 1, 3);
        }
        const len = head.length + b.length;
        this.parts.push(head, Buffer.from(b), Buffer.alloc((4 - (len % 4)) % 4));
        return this;
    }
    blockIdExt(id: BlockIdExt): this {
        return this.i32(id.workchain).i64(id.shard).i32(id.seqno).raw(id.rootHash).raw(id.fileHash);
    }
    build(): Buffer {
        return Buffer.concat(this.parts);
    }
}

export class TlReader {
    off = 0;
    constructor(readonly b: Buffer) {}
    u32(): number {
        const v = this.b.readUInt32LE(this.off);
        this.off += 4;
        return v;
    }
    i32(): number {
        const v = this.b.readInt32LE(this.off);
        this.off += 4;
        return v;
    }
    i64(): bigint {
        const v = this.b.readBigInt64LE(this.off);
        this.off += 8;
        return v;
    }
    raw(n: number): Buffer {
        if (this.off + n > this.b.length) throw new Error("tl: out of bounds");
        const v = this.b.subarray(this.off, this.off + n);
        this.off += n;
        return Buffer.from(v);
    }
    bytes(): Buffer {
        let len = this.b[this.off];
        let head = 1;
        if (len === 0xfe) {
            len = this.b.readUIntLE(this.off + 1, 3);
            head = 4;
        }
        this.off += head;
        const v = this.raw(len);
        this.off += (4 - ((head + len) % 4)) % 4;
        return v;
    }
    bool(): boolean {
        const c = this.u32();
        if (c === TL.boolTrue) return true;
        if (c === TL.boolFalse) return false;
        throw new Error(`tl: bad Bool ${c.toString(16)}`);
    }
    blockIdExt(): BlockIdExt {
        return {
            workchain: this.i32(),
            shard: this.i64(),
            seqno: this.i32(),
            rootHash: this.raw(32),
            fileHash: this.raw(32),
        };
    }
    expect(c: number): void {
        const got = this.u32();
        if (got === TL.liteServerError) {
            const code = this.i32();
            throw new Error(`liteServer.error ${code}: ${this.bytes().toString()}`);
        }
        if (got !== c) throw new Error(`tl: expected ${c.toString(16)}, got ${got.toString(16)}`);
    }
}

export interface BlockIdExt {
    workchain: number;
    shard: bigint; // signed int64 as TL serializes it (masterchain: -0x8000000000000000)
    seqno: number;
    rootHash: Buffer;
    fileHash: Buffer;
}

export const MC_SHARD = -0x8000000000000000n;

export interface TonSignature {
    nodeIdShort: Buffer;
    signature: Buffer;
}

export type SignatureSet =
    | {kind: "ordinary"; validatorSetHash: number; ccSeqno: number; signatures: TonSignature[]}
    | {
          kind: "simplex";
          ccSeqno: number;
          validatorSetHash: number;
          signatures: TonSignature[];
          sessionId: Buffer;
          slot: number;
          candidate: Buffer;
      };

export interface BlockLinkForward {
    kind: "forward";
    toKeyBlock: boolean;
    from: BlockIdExt;
    to: BlockIdExt;
    destProof: Buffer;
    configProof: Buffer;
    signatures: SignatureSet;
}

export interface BlockLinkBack {
    kind: "back";
    toKeyBlock: boolean;
    from: BlockIdExt;
    to: BlockIdExt;
    destProof: Buffer;
    proof: Buffer;
    stateProof: Buffer;
}

function readSignatureSet(r: TlReader): SignatureSet {
    const c = r.u32();
    const sigs = (): TonSignature[] => {
        const n = r.u32();
        const out: TonSignature[] = [];
        for (let i = 0; i < n; i++) {
            const nodeIdShort = r.raw(32);
            out.push({nodeIdShort, signature: r.bytes()});
        }
        return out;
    };
    if (c === TL.signatureSetOrdinary) {
        const validatorSetHash = r.u32();
        const ccSeqno = r.i32();
        return {kind: "ordinary", validatorSetHash, ccSeqno, signatures: sigs()};
    }
    if (c === TL.signatureSetSimplex) {
        const ccSeqno = r.i32();
        const validatorSetHash = r.u32();
        const signatures = sigs();
        const sessionId = r.raw(32);
        const slot = r.i32();
        const candidate = r.bytes();
        return {kind: "simplex", ccSeqno, validatorSetHash, signatures, sessionId, slot, candidate};
    }
    throw new Error(`tl: unknown SignatureSet ${c.toString(16)}`);
}

// ── ADNL TCP ────────────────────────────────────────────────────────────────

export interface LiteServerInfo {
    ip: number;
    port: number;
    key: string; // base64 ed25519 public key
}

const ipString = (ip: number): string => [24, 16, 8, 0].map((s) => ((ip >>> s) & 255).toString()).join(".");

export class LiteClient {
    private sock!: Socket;
    private enc!: Cipheriv;
    private dec!: Cipheriv;
    private buf = Buffer.alloc(0);
    private waiters: ((pkt: Buffer) => void)[] = [];
    private pending = new Map<string, {resolve: (b: Buffer) => void; reject: (e: Error) => void}>();
    private closed = false;

    static async connect(server: LiteServerInfo, timeoutMs = 15_000): Promise<LiteClient> {
        const c = new LiteClient();
        await c.open(server, timeoutMs);
        return c;
    }

    private async open(server: LiteServerInfo, timeoutMs: number): Promise<void> {
        const serverPub = Buffer.from(server.key, "base64");
        const params = randomBytes(160);
        const priv = ed25519.utils.randomPrivateKey();
        const pub = ed25519.getPublicKey(priv);
        const shared = Buffer.from(
            x25519.getSharedSecret(edwardsToMontgomeryPriv(priv), edwardsToMontgomeryPub(serverPub)),
        );
        const h = sha256(params);
        const key = Buffer.concat([shared.subarray(0, 16), h.subarray(16, 32)]);
        const iv = Buffer.concat([h.subarray(0, 4), shared.subarray(20, 32)]);
        const hsCipher = createCipheriv("aes-256-ctr", key, iv);
        const encParams = Buffer.concat([hsCipher.update(params), hsCipher.final()]);
        const serverKeyId = sha256(Buffer.concat([Buffer.from("c6b41348", "hex"), serverPub]));

        // Client → server uses params[32:64] / params[80:96]; server → client params[0:32] / params[64:80].
        this.dec = createCipheriv("aes-256-ctr", params.subarray(0, 32), params.subarray(64, 80));
        this.enc = createCipheriv("aes-256-ctr", params.subarray(32, 64), params.subarray(80, 96));

        this.sock = new Socket();
        this.sock.setNoDelay(true);
        await new Promise<void>((resolve, reject) => {
            const t = setTimeout(() => reject(new Error("liteserver: connect timeout")), timeoutMs);
            this.sock.once("error", (e) => {
                clearTimeout(t);
                reject(e);
            });
            this.sock.connect(server.port, ipString(server.ip), () => {
                clearTimeout(t);
                resolve();
            });
        });
        this.sock.on("data", (d) => this.onData(d));
        this.sock.on("close", () => {
            this.closed = true;
            for (const p of this.pending.values()) p.reject(new Error("liteserver: closed"));
        });
        this.sock.write(Buffer.concat([serverKeyId, Buffer.from(pub), h, encParams]));
        // The server confirms the handshake with an empty packet.
        const first = await this.nextPacket(timeoutMs);
        if (first.length !== 0) throw new Error("liteserver: bad handshake");
    }

    private nextPacket(timeoutMs: number): Promise<Buffer> {
        return new Promise((resolve, reject) => {
            const t = setTimeout(() => reject(new Error("liteserver: packet timeout")), timeoutMs);
            this.waiters.push((p) => {
                clearTimeout(t);
                resolve(p);
            });
        });
    }

    private onData(d: Buffer): void {
        this.buf = Buffer.concat([this.buf, this.dec.update(d)]);
        for (;;) {
            if (this.buf.length < 4) return;
            const size = this.buf.readUInt32LE(0);
            if (this.buf.length < 4 + size) return;
            const body = this.buf.subarray(4, 4 + size);
            this.buf = this.buf.subarray(4 + size);
            const nonce = body.subarray(0, 32);
            const payload = body.subarray(32, size - 32);
            const check = body.subarray(size - 32);
            if (!sha256(Buffer.concat([nonce, payload])).equals(check)) throw new Error("liteserver: bad checksum");
            this.dispatch(Buffer.from(payload));
        }
    }

    private dispatch(payload: Buffer): void {
        if (this.waiters.length) {
            this.waiters.shift()!(payload);
            return;
        }
        if (payload.length === 0) return;
        const r = new TlReader(payload);
        const c = r.u32();
        if (c !== TL.adnlMessageAnswer) return; // tcp.pong etc.
        const qid = r.raw(32).toString("hex");
        const answer = r.bytes();
        const p = this.pending.get(qid);
        if (p) {
            this.pending.delete(qid);
            p.resolve(answer);
        }
    }

    private send(payload: Buffer): void {
        const nonce = randomBytes(32);
        const size = Buffer.alloc(4);
        size.writeUInt32LE(32 + payload.length + 32);
        const pkt = Buffer.concat([size, nonce, payload, sha256(Buffer.concat([nonce, payload]))]);
        this.sock.write(this.enc.update(pkt));
    }

    /// Send a raw lite-API query (TL-serialized function) and return the raw TL answer.
    query(data: Buffer, timeoutMs = 30_000): Promise<Buffer> {
        if (this.closed) return Promise.reject(new Error("liteserver: closed"));
        const qid = randomBytes(32);
        const inner = new TlWriter().u32(TL.liteServerQuery).bytes(data).build();
        const msg = new TlWriter().u32(TL.adnlMessageQuery).raw(qid).bytes(inner).build();
        return new Promise((resolve, reject) => {
            const t = setTimeout(() => {
                this.pending.delete(qid.toString("hex"));
                reject(new Error("liteserver: query timeout"));
            }, timeoutMs);
            this.pending.set(qid.toString("hex"), {
                resolve: (b) => {
                    clearTimeout(t);
                    resolve(b);
                },
                reject: (e) => {
                    clearTimeout(t);
                    reject(e);
                },
            });
            this.send(msg);
        });
    }

    close(): void {
        this.closed = true;
        this.sock?.destroy();
    }

    // ── Typed queries ─────────────────────────────────────────────────────

    async getMasterchainInfo(): Promise<{last: BlockIdExt; stateRootHash: Buffer}> {
        const r = new TlReader(await this.query(new TlWriter().u32(TL.getMasterchainInfo).build()));
        r.expect(TL.masterchainInfo);
        const last = r.blockIdExt();
        return {last, stateRootHash: r.raw(32)};
    }

    async lookupBlock(workchain: number, shard: bigint, seqno: number): Promise<{id: BlockIdExt; headerProof: Buffer}> {
        const q = new TlWriter().u32(TL.lookupBlock).u32(1).i32(workchain).i64(shard).i32(seqno).build();
        const r = new TlReader(await this.query(q));
        r.expect(TL.blockHeader);
        const id = r.blockIdExt();
        r.u32();
        return {id, headerProof: r.bytes()};
    }

    async getBlockHeader(id: BlockIdExt, mode = 0): Promise<Buffer> {
        const q = new TlWriter().u32(TL.getBlockHeader).blockIdExt(id).u32(mode).build();
        const r = new TlReader(await this.query(q));
        r.expect(TL.blockHeader);
        r.blockIdExt();
        r.u32();
        return r.bytes();
    }

    async getBlock(id: BlockIdExt): Promise<Buffer> {
        const r = new TlReader(await this.query(new TlWriter().u32(TL.getBlock).blockIdExt(id).build()));
        r.expect(TL.blockData);
        r.blockIdExt();
        return r.bytes();
    }

    async getBlockProof(
        known: BlockIdExt,
        target?: BlockIdExt,
    ): Promise<{complete: boolean; from: BlockIdExt; to: BlockIdExt; steps: (BlockLinkForward | BlockLinkBack)[]}> {
        const w = new TlWriter()
            .u32(TL.getBlockProof)
            .u32(target ? 1 : 0)
            .blockIdExt(known);
        if (target) w.blockIdExt(target);
        const r = new TlReader(await this.query(w.build(), 60_000));
        r.expect(TL.partialBlockProof);
        const complete = r.bool();
        const from = r.blockIdExt();
        const to = r.blockIdExt();
        const n = r.u32();
        const steps: (BlockLinkForward | BlockLinkBack)[] = [];
        for (let i = 0; i < n; i++) {
            const c = r.u32();
            const toKeyBlock = r.bool();
            const f = r.blockIdExt();
            const t = r.blockIdExt();
            const destProof = r.bytes();
            if (c === TL.blockLinkForward) {
                const configProof = r.bytes();
                steps.push({kind: "forward", toKeyBlock, from: f, to: t, destProof, configProof, signatures: readSignatureSet(r)});
            } else if (c === TL.blockLinkBack) {
                const proof = r.bytes();
                steps.push({kind: "back", toKeyBlock, from: f, to: t, destProof, proof, stateProof: r.bytes()});
            } else throw new Error(`tl: unknown BlockLink ${c.toString(16)}`);
        }
        return {complete, from, to, steps};
    }

    async getAccountState(
        id: BlockIdExt,
        workchain: number,
        account: Buffer,
        prunned = false,
    ): Promise<{id: BlockIdExt; shardblk: BlockIdExt; shardProof: Buffer; proof: Buffer; state: Buffer}> {
        const q = new TlWriter()
            .u32(prunned ? TL.getAccountStatePrunned : TL.getAccountState)
            .blockIdExt(id) // account:liteServer.accountId is a bare type: no constructor id
            .i32(workchain)
            .raw(account)
            .build();
        const r = new TlReader(await this.query(q));
        r.expect(TL.accountState);
        const bid = r.blockIdExt();
        const shardblk = r.blockIdExt();
        return {id: bid, shardblk, shardProof: r.bytes(), proof: r.bytes(), state: r.bytes()};
    }

    async getConfigParams(id: BlockIdExt, params: number[], mode = 0): Promise<{stateProof: Buffer; configProof: Buffer}> {
        const w = new TlWriter().u32(TL.getConfigParams).u32(mode).blockIdExt(id).u32(params.length);
        for (const p of params) w.i32(p);
        const r = new TlReader(await this.query(w.build()));
        r.expect(TL.configInfo);
        r.u32();
        r.blockIdExt();
        return {stateProof: r.bytes(), configProof: r.bytes()};
    }
}

/// Fetch the liteserver list from ton.org's global config.
export async function liteServers(net: "mainnet" | "testnet"): Promise<LiteServerInfo[]> {
    const url = net === "mainnet" ? "https://ton.org/global.config.json" : "https://ton.org/testnet-global.config.json";
    const cfg = (await (await fetch(url)).json()) as {liteservers: {ip: number; port: number; id: {key: string}}[]};
    return cfg.liteservers.map((l) => ({ip: l.ip, port: l.port, key: l.id.key}));
}

/// Connect to the first liteserver that answers.
export async function connectAny(net: "mainnet" | "testnet"): Promise<LiteClient> {
    const errors: string[] = [];
    for (const s of await liteServers(net)) {
        try {
            const c = await LiteClient.connect(s, 8000);
            await c.getMasterchainInfo();
            return c;
        } catch (e) {
            errors.push(`${ipString(s.ip)}:${s.port} ${(e as Error).message}`);
        }
    }
    throw new Error(`no liteserver answered:\n${errors.join("\n")}`);
}
