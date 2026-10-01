import {createHash} from "node:crypto";
import {gunzipSync} from "node:zlib";
import {ed25519} from "@noble/curves/ed25519";
import {rlpEncode} from "../lib/rlp.js";

/// Stellar XDR, history-archive and proof-encoding helpers shared by the live fixture builder
/// (buildStellarLiveProof.ts) and the synthetic fixture generator (buildStellarSyntheticFixture.ts).
///
/// Only the structures StellarScpVerifier reads are decoded. Layouts follow stellar/stellar-xdr
/// (Stellar-SCP.x, Stellar-ledger.x, Stellar-transaction.x); every hash below is re-checked against
/// the archive, so a decoding mistake shows up as a mismatch, not as a wrong fixture.

export const sha256 = (b: Uint8Array): Buffer => createHash("sha256").update(b).digest();
export const hex = (b: Uint8Array): `0x${string}` => `0x${Buffer.from(b).toString("hex")}`;
export const unhex = (h: string): Buffer => Buffer.from(h.replace(/^0x/, ""), "hex");

export const ENVELOPE_TYPE_SCP = 1;
export const ENVELOPE_TYPE_TX = 2;
export const SCP_ST_EXTERNALIZE = 2;

export const networkIdOf = (passphrase: string): Buffer => sha256(Buffer.from(passphrase, "utf8"));

// ── XDR primitives ─────────────────────────────────────────────────────────────

export class XdrReader {
    o = 0;
    constructor(readonly b: Buffer) {}
    u32(): number {
        const v = this.b.readUInt32BE(this.o);
        this.o += 4;
        return v;
    }
    u64(): bigint {
        const v = this.b.readBigUInt64BE(this.o);
        this.o += 8;
        return v;
    }
    fixed(n: number): Buffer {
        if (this.o + n > this.b.length) throw new Error("XDR out of bounds");
        const v = this.b.subarray(this.o, this.o + n);
        this.o += n;
        return v;
    }
    opaque(): Buffer {
        const n = this.u32();
        const v = this.fixed(n);
        this.o += (4 - (n % 4)) % 4;
        return v;
    }
    nodeId(): Buffer {
        if (this.u32() !== 0) throw new Error("non-ed25519 key");
        return this.fixed(32);
    }
}

export const u32be = (v: number): Buffer => {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(v >>> 0);
    return b;
};
export const u64be = (v: bigint): Buffer => {
    const b = Buffer.alloc(8);
    b.writeBigUInt64BE(v);
    return b;
};
export const xdrOpaque = (data: Uint8Array): Buffer =>
    Buffer.concat([u32be(data.length), Buffer.from(data), Buffer.alloc((4 - (data.length % 4)) % 4)]);

/// Split an archive XDR stream (RFC 5531 record marks) into records.
export function xdrRecords(b: Buffer): Buffer[] {
    const out: Buffer[] = [];
    let o = 0;
    while (o < b.length) {
        const n = b.readUInt32BE(o) & 0x7fffffff;
        out.push(b.subarray(o + 4, o + 4 + n));
        o += 4 + n;
    }
    return out;
}

// ── Quorum sets ────────────────────────────────────────────────────────────────

export interface QuorumSet {
    threshold: number;
    validators: string[]; // hex node ids (no 0x)
    innerSets: QuorumSet[];
}

export function readQuorumSet(r: XdrReader): QuorumSet {
    const threshold = r.u32();
    const nv = r.u32();
    const validators: string[] = [];
    for (let i = 0; i < nv; i++) validators.push(r.nodeId().toString("hex"));
    const ni = r.u32();
    const innerSets: QuorumSet[] = [];
    for (let i = 0; i < ni; i++) innerSets.push(readQuorumSet(r));
    return {threshold, validators, innerSets};
}

export function encodeQuorumSet(q: QuorumSet): Buffer {
    return Buffer.concat([
        u32be(q.threshold),
        u32be(q.validators.length),
        ...q.validators.map((v) => Buffer.concat([u32be(0), unhex(v)])),
        u32be(q.innerSets.length),
        ...q.innerSets.map(encodeQuorumSet)
    ]);
}

export const qsetMembers = (q: QuorumSet): string[] => [...q.validators, ...q.innerSets.flatMap(qsetMembers)];

/// The cheapest set of signers (from `have`) that satisfies `q`, or undefined.
export function minimalSlice(q: QuorumSet, have: Set<string>): string[] | undefined {
    const options: string[][] = [];
    for (const v of [...q.validators].sort()) if (have.has(v)) options.push([v]);
    for (const inner of q.innerSets) {
        const s = minimalSlice(inner, have);
        if (s) options.push(s);
    }
    if (options.length < q.threshold) return undefined;
    options.sort((a, b) => a.length - b.length);
    return options.slice(0, q.threshold).flat();
}

export function isSatisfied(q: QuorumSet, signers: Set<string>): boolean {
    let n = q.validators.filter((v) => signers.has(v)).length;
    n += q.innerSets.filter((s) => isSatisfied(s, signers)).length;
    return n >= q.threshold;
}

// ── SCP envelopes ──────────────────────────────────────────────────────────────

export interface Envelope {
    nodeId: string; // hex
    slot: bigint;
    type: number;
    value?: Buffer; // externalize: commit.value (StellarValue XDR)
    qsetHash?: string; // externalize: commitQuorumSetHash (hex)
    statement: Buffer; // XDR(SCPStatement)
    signature: Buffer;
}

export function readEnvelope(r: XdrReader): Envelope {
    const start = r.o;
    const nodeId = r.nodeId().toString("hex");
    const slot = r.u64();
    const type = r.u32();
    let value: Buffer | undefined;
    let qsetHash: string | undefined;
    if (type === SCP_ST_EXTERNALIZE) {
        r.u32(); // commit.counter
        value = r.opaque();
        r.u32(); // nH
        qsetHash = r.fixed(32).toString("hex");
    } else if (type === 1) {
        // CONFIRM { ballot; nPrepared; nCommit; nH; quorumSetHash }: some archived entries hold a
        // node's last CONFIRM instead of its EXTERNALIZE. Decoded only to be skipped.
        r.u32();
        r.opaque();
        r.fixed(12);
        qsetHash = r.fixed(32).toString("hex");
    } else if (type === 0) {
        // PREPARE { quorumSetHash; ballot; prepared*; preparedPrime*; nC; nH }
        qsetHash = r.fixed(32).toString("hex");
        r.u32();
        r.opaque();
        for (let k = 0; k < 2; k++) {
            if (r.u32() === 1) {
                r.u32();
                r.opaque();
            }
        }
        r.fixed(8);
    } else if (type === 3) {
        // NOMINATE { quorumSetHash; votes<>; accepted<> }
        qsetHash = r.fixed(32).toString("hex");
        for (let k = 0; k < 2; k++) {
            const n = r.u32();
            for (let i = 0; i < n; i++) r.opaque();
        }
    } else {
        throw new Error(`unknown SCP statement type ${type}`);
    }
    const statement = r.b.subarray(start, r.o);
    const signature = r.opaque();
    return {nodeId, slot, type, value, qsetHash, statement, signature};
}

export const scpSignedMessage = (networkId: Buffer, statement: Buffer): Buffer =>
    Buffer.concat([networkId, u32be(ENVELOPE_TYPE_SCP), statement]);

export function verifyEnvelope(networkId: Buffer, e: Envelope): boolean {
    return ed25519.verify(e.signature, scpSignedMessage(networkId, e.statement), unhex(e.nodeId));
}

/// One archived SCPHistoryEntry (v0): the quorum sets it introduces and one ledger's envelopes.
export interface ScpHistory {
    ledgerSeq: number;
    quorumSets: Map<string, {xdr: Buffer; qset: QuorumSet}>; // by sha256 hex
    envelopes: Envelope[];
}

export function readScpHistory(rec: Buffer): ScpHistory {
    const r = new XdrReader(rec);
    if (r.u32() !== 0) throw new Error("SCPHistoryEntry v != 0");
    const nq = r.u32();
    const quorumSets = new Map<string, {xdr: Buffer; qset: QuorumSet}>();
    for (let i = 0; i < nq; i++) {
        const s = r.o;
        const qset = readQuorumSet(r);
        const xdr = rec.subarray(s, r.o);
        quorumSets.set(sha256(xdr).toString("hex"), {xdr, qset});
    }
    const ledgerSeq = r.u32();
    const n = r.u32();
    const envelopes: Envelope[] = [];
    for (let i = 0; i < n; i++) envelopes.push(readEnvelope(r));
    if (r.o !== rec.length) throw new Error("trailing bytes in SCP history entry");
    return {ledgerSeq, quorumSets, envelopes};
}

// ── Ledger headers ─────────────────────────────────────────────────────────────

export interface Header {
    xdr: Buffer;
    hash: Buffer;
    ledgerVersion: number;
    previousLedgerHash: Buffer;
    scpValue: Buffer;
    txSetHash: Buffer;
    txSetResultHash: Buffer;
    bucketListHash: Buffer;
    ledgerSeq: number;
}

function skipStellarValue(r: XdrReader): void {
    r.fixed(40);
    const n = r.u32();
    for (let i = 0; i < n; i++) r.opaque();
    const ext = r.u32();
    if (ext === 1) {
        r.nodeId();
        r.opaque();
    } else if (ext === 2) {
        r.fixed(68);
        r.nodeId();
        r.opaque();
    } else if (ext !== 0) throw new Error(`StellarValue ext ${ext}`);
}

export function parseHeader(xdr: Buffer): Header {
    const r = new XdrReader(xdr);
    const ledgerVersion = r.u32();
    const previousLedgerHash = r.fixed(32);
    const s = r.o;
    skipStellarValue(r);
    const scpValue = xdr.subarray(s, r.o);
    const txSetResultHash = r.fixed(32);
    const bucketListHash = r.fixed(32);
    const ledgerSeq = r.u32();
    return {
        xdr,
        hash: sha256(xdr),
        ledgerVersion,
        previousLedgerHash,
        scpValue,
        txSetHash: scpValue.subarray(0, 32),
        txSetResultHash,
        bucketListHash,
        ledgerSeq
    };
}

// ── History archives ───────────────────────────────────────────────────────────

export interface Checkpoint {
    checkpoint: number;
    headers: Map<number, Header>;
    txSets: Map<number, Buffer>; // GeneralizedTransactionSet XDR
    resultSets: Map<number, Buffer>; // TransactionResultSet XDR
    scp: Map<number, ScpHistory>;
}

export const checkpointOf = (ledger: number): number => Math.floor(ledger / 64) * 64 + 63;

export async function fetchArchiveFile(archive: string, category: string, checkpoint: number): Promise<Buffer> {
    const h = checkpoint.toString(16).padStart(8, "0");
    const url = `${archive}/${category}/${h.slice(0, 2)}/${h.slice(2, 4)}/${h.slice(4, 6)}/${category}-${h}.xdr.gz`;
    for (let attempt = 0; ; attempt++) {
        const res = await fetch(url);
        if (res.ok) return gunzipSync(Buffer.from(await res.arrayBuffer()));
        if (attempt >= 4) throw new Error(`${url}: HTTP ${res.status}`);
        await new Promise((z) => setTimeout(z, 1500 * (attempt + 1)));
    }
}

export async function archiveCurrentLedger(archive: string): Promise<number> {
    const res = await fetch(`${archive}/.well-known/stellar-history.json`);
    if (!res.ok) throw new Error(`HAS: HTTP ${res.status}`);
    return ((await res.json()) as {currentLedger: number}).currentLedger;
}

/// Fetch and cross-check one checkpoint: every header hashes to its recorded hash, and every tx set
/// and result set hashes to the value its header commits to.
export async function loadCheckpoint(archive: string, checkpoint: number): Promise<Checkpoint> {
    const [ledger, txs, results, scp] = await Promise.all(
        ["ledger", "transactions", "results", "scp"].map((c) => fetchArchiveFile(archive, c, checkpoint))
    );
    const cp: Checkpoint = {checkpoint, headers: new Map(), txSets: new Map(), resultSets: new Map(), scp: new Map()};
    for (const rec of xdrRecords(ledger)) {
        // LedgerHeaderHistoryEntry { Hash hash; LedgerHeader header; ext (v 0) }
        const h = parseHeader(rec.subarray(32, rec.length - 4));
        if (!h.hash.equals(rec.subarray(0, 32))) throw new Error(`header hash mismatch at ${h.ledgerSeq}`);
        cp.headers.set(h.ledgerSeq, h);
    }
    for (const rec of xdrRecords(txs)) {
        // TransactionHistoryEntry { uint32 ledgerSeq; TransactionSet txSet; ext (v 1: GeneralizedTransactionSet) }
        const seq = rec.readUInt32BE(0);
        if (rec.readUInt32BE(36) !== 0 || rec.readUInt32BE(40) !== 1) throw new Error(`legacy tx set at ${seq}`);
        const gts = rec.subarray(44);
        const h = cp.headers.get(seq);
        if (!h || !sha256(gts).equals(h.txSetHash)) throw new Error(`tx set hash mismatch at ${seq}`);
        cp.txSets.set(seq, gts);
    }
    for (const rec of xdrRecords(results)) {
        // TransactionHistoryResultEntry { uint32 ledgerSeq; TransactionResultSet txResultSet; ext (v 0) }
        const seq = rec.readUInt32BE(0);
        const rs = rec.subarray(4, rec.length - 4);
        const h = cp.headers.get(seq);
        if (!h || !sha256(rs).equals(h.txSetResultHash)) throw new Error(`result set hash mismatch at ${seq}`);
        cp.resultSets.set(seq, rs);
    }
    for (const rec of xdrRecords(scp)) {
        const e = readScpHistory(rec);
        cp.scp.set(e.ledgerSeq, e);
    }
    // A ledger without transactions may have no results record; its result set is empty.
    for (const [seq, h] of cp.headers) {
        if (!cp.resultSets.has(seq) && sha256(u32be(0)).equals(h.txSetResultHash)) cp.resultSets.set(seq, u32be(0));
    }
    return cp;
}

// ── Transactions and Soroban results (from Stellar RPC) ────────────────────────

/// The signature payload of a v1 transaction (its hash preimage):
/// networkID || ENVELOPE_TYPE_TX || XDR(Transaction). The envelope is ENVELOPE_TYPE_TX ||
/// Transaction || DecoratedSignature signatures<20>; the split point is found by the hash.
export function txPayloadFromEnvelope(networkId: Buffer, envelope: Buffer, txHash: Buffer): Buffer {
    if (envelope.readUInt32BE(0) !== ENVELOPE_TYPE_TX) throw new Error("not a v1 transaction envelope");
    for (let end = envelope.length - 4; end > 4; end -= 4) {
        const payload = Buffer.concat([networkId, u32be(ENVELOPE_TYPE_TX), envelope.subarray(4, end)]);
        if (sha256(payload).equals(txHash)) return payload;
    }
    throw new Error("transaction payload not found");
}

/// InvokeHostFunction success hash of a TransactionResult (txSUCCESS, one opINNER result), or undefined.
export function invokeSuccessHash(result: Buffer): Buffer | undefined {
    const r = new XdrReader(result);
    r.fixed(8);
    if (r.u32() !== 0 || r.u32() !== 1 || r.u32() !== 0 || r.u32() !== 24 || r.u32() !== 0) return undefined;
    return r.fixed(32);
}

/// InvokeHostFunctionSuccessPreImage { SCVal returnValue; ContractEvent events<> } for a void return.
export const voidSuccessPreimage = (events: Buffer[]): Buffer =>
    Buffer.concat([u32be(1), u32be(events.length), ...events]);

// ── Proof encodings (StellarScpVerifier) ───────────────────────────────────────

export interface ScpProof {
    envelopes: {statement: Buffer; signature: Buffer}[];
    txSet: Buffer;
    newQset?: Buffer;
}

export interface Attestation {
    txPayload: Buffer;
    resultSet: Buffer;
    offset: number;
    preimage: Buffer;
}

const intBuf = (n: number | bigint): Buffer => {
    let h = BigInt(n).toString(16);
    if (h === "0") return Buffer.alloc(0);
    if (h.length % 2) h = "0" + h;
    return Buffer.from(h, "hex");
};

export const scpProofItem = (s: ScpProof | undefined) =>
    s ? [s.envelopes.map((e) => [e.statement, e.signature]), s.txSet, s.newQset ?? Buffer.alloc(0)] : [];

export const attestationItem = (a: Attestation | undefined) =>
    a ? [a.txPayload, a.resultSet, intBuf(a.offset), a.preimage] : [];

export function encodeBundle(p: {
    qset: Buffer;
    scp?: ScpProof;
    headers: Buffer[];
    attestation?: Attestation;
    lastMetadata?: Buffer;
    bundleContent?: Buffer;
    manifest?: Buffer;
}): Buffer {
    return rlpEncode([
        p.qset,
        scpProofItem(p.scp),
        p.headers,
        attestationItem(p.attestation),
        p.lastMetadata ?? Buffer.alloc(0),
        p.bundleContent ?? Buffer.alloc(0),
        p.manifest ?? Buffer.alloc(0)
    ]);
}

export function encodeConfigProof(qset: Buffer, scp: ScpProof, controlMessage: Buffer): Buffer {
    return rlpEncode([qset, scpProofItem(scp), controlMessage]);
}

/// abi.encode(bytes32 qsetHash, uint64 lastSlot, uint32 checkpointSeq, bytes32 checkpointHash,
///            bytes32 lastMetadataHash)
export function encodeAnchor(a: {
    qsetHash: Buffer;
    lastSlot: bigint | number;
    checkpointSeq: number;
    checkpointHash: Buffer;
    lastMetadataHash: Buffer;
}): Buffer {
    const w = (b: Buffer) => Buffer.concat([Buffer.alloc(32 - b.length), b]);
    return Buffer.concat([
        w(a.qsetHash),
        w(u64be(BigInt(a.lastSlot))),
        w(u32be(a.checkpointSeq)),
        w(a.checkpointHash),
        w(a.lastMetadataHash)
    ]);
}

// ── CLPR attestation events (the format StellarScpVerifier expects) ────────────

const scSymbol = (s: string): Buffer => Buffer.concat([u32be(15), xdrOpaque(Buffer.from(s, "ascii"))]);
const scBytes = (b: Buffer): Buffer => Buffer.concat([u32be(13), xdrOpaque(b)]);

/// ContractEvent { ext v0; contractID present; type CONTRACT; body v0 { topics; data } }.
export function contractEvent(contractId: Buffer, topics: Buffer[], data: Buffer): Buffer {
    return Buffer.concat([u32be(0), u32be(1), contractId, u32be(1), u32be(0), u32be(topics.length), ...topics, data]);
}

export interface QueueMetadata {
    nextMessageId: bigint;
    sentRunningHash: Buffer;
    receivedMessageId: bigint;
    receivedRunningHash: Buffer;
    status: number;
    endpointManifestVersion: bigint;
    manifestCommitment: Buffer;
}

export function queueEvent(contractId: Buffer, channelId: Buffer, m: QueueMetadata): Buffer {
    const data = Buffer.concat([
        u64be(m.nextMessageId),
        m.sentRunningHash,
        u64be(m.receivedMessageId),
        m.receivedRunningHash,
        u32be(m.status),
        u64be(m.endpointManifestVersion),
        m.manifestCommitment
    ]);
    if (data.length !== 124) throw new Error("queue data length");
    return contractEvent(contractId, [scSymbol("clpr_queue"), scBytes(channelId)], scBytes(data));
}

export const manifestEvent = (contractId: Buffer, commitment: Buffer): Buffer =>
    contractEvent(contractId, [scSymbol("clpr_manifest")], scBytes(commitment));
