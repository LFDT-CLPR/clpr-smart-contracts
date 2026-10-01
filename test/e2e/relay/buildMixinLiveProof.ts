/// Mixin kernel live fixture and proof builder for MixinKernelVerifier.
///
///   tsx test/e2e/relay/buildMixinLiveProof.ts --refresh   (capture from kernel.mixin.dev)
///
/// Captures, from the public kernel RPC:
///   - the last two kernel node changes (NodeAccept / NodeRemove) and the ready signer list just
///     before the first of them (listallnodes at that time: ACCEPTED, accepted > 12 h earlier,
///     ordered by timestamp then id), each change with its final snapshot;
///   - a later final snapshot signed under the list those changes produce, and one of its
///     transactions that spends output 0 of an earlier transaction (so it can play a record
///     thread's next link).
/// Every CoSi signature is checked offline against the summed keys, and every payload is derived
/// from the kernel's own encodings and checked against the hash the kernel reports. Kernel
/// timestamps are nanoseconds above 2^53, so they are kept as decimal strings.
import {readFileSync, writeFileSync, mkdirSync} from "node:fs";
import path from "node:path";
import {ed25519} from "@noble/curves/ed25519";
import {blake3} from "@noble/hashes/blake3";
import {rlpEncode} from "../lib/rlp.js";

const KERNEL = process.env.MIXIN_KERNEL ?? "https://kernel.mixin.dev";
const FILE = path.join(import.meta.dirname, "..", "fixtures", "mixin-live", "mainnet.json");
const hb = (h: string) => Buffer.from(h.replace(/^0x/, ""), "hex");
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Public spend key of a Mixin address: "XIN" + base58(spend(32) ‖ view(32) ‖ checksum(4)).
export function spendKey(addr: string): Buffer {
    let n = 0n;
    for (const c of addr.slice(3)) n = n * 58n + BigInt(B58.indexOf(c));
    return hb(n.toString(16).padStart(136, "0")).subarray(0, 32);
}

async function rpc(method: string, params: unknown[]): Promise<any> {
    const r = await fetch(KERNEL, {method: "POST", body: JSON.stringify({method, params})});
    const text = (await r.text()).replace(/"timestamp":(\d+)/g, '"timestamp":"$1"');
    const j = JSON.parse(text) as any;
    if (j.error) throw new Error(`${method}: ${JSON.stringify(j.error)}`);
    return j.data;
}

/// Snapshot payload from VersionedMarshal hex: drop CoSi (mask 8 + sig 64) and topology (8), then
/// append the absent-signature marker (u64 0), as EncodeSnapshotPayload writes it.
export const snapshotPayload = (hex: Buffer) => Buffer.concat([hex.subarray(0, hex.length - 80), Buffer.alloc(8)]);

/// Transaction payload: the encoding up to and including extra, then an empty signature map (u16 0).
export function txPayload(hex: Buffer): Buffer {
    let at = 36;
    const u16 = () => {
        const v = hex.readUInt16BE(at);
        at += 2;
        return v;
    };
    const present = () => {
        const v = hex.readUInt16BE(at);
        at += 2;
        if (v === 0x7777) return true;
        if (v === 0) return false;
        throw new Error("bad presence marker");
    };
    const skipLen = () => {
        const n = u16();
        at += n;
    };
    const skipKeys = () => {
        const n = u16();
        at += 32 * n;
    };
    const il = u16();
    for (let i = 0; i < il; i++) {
        at += 34;
        skipLen();
        if (present()) {
            at += 32;
            skipLen();
            skipLen();
            at += 8;
            skipLen();
        }
        if (present()) {
            skipLen();
            at += 8;
            skipLen();
        }
    }
    const ol = u16();
    for (let i = 0; i < ol; i++) {
        at += 2;
        skipLen();
        skipKeys();
        at += 32;
        skipLen();
        if (present()) {
            skipLen();
            skipLen();
        }
    }
    skipKeys(); // references
    const el = hex.readUInt32BE(at);
    at += 4 + el;
    return Buffer.concat([hex.subarray(0, at), Buffer.alloc(2)]);
}

export const loadMixinFixture = () => JSON.parse(readFileSync(FILE, "utf8"));

export const ACCEPT_PERIOD = 43_200_000_000_000n; // 12 h in ns (config KernelNodeAcceptPeriodMinimum)
export const XIN = "a99c2e0e2b1da4d648755ef19bd95139acbbe6564cfb06dec7cd34931ca72cdc";

const byKernelOrder = (a: any, b: any) =>
    BigInt(a.timestamp) < BigInt(b.timestamp) ? -1 : BigInt(a.timestamp) > BigInt(b.timestamp) ? 1 : a.id < b.id ? -1 : 1;

/// The kernel's view at time t: node states recorded strictly before t (NodesListWithoutState).
async function nodesAt(t: bigint) {
    return ((await rpc("listallnodes", [(t - 1n).toString(), false])) as any[]).sort(byKernelOrder);
}

/// The CoSi signer list at t (ConsensusKeys): ACCEPTED and accepted more than 12 h before t.
const readyAt = (nodes: any[], t: bigint) =>
    nodes.filter((n) => n.state === "ACCEPTED" && BigInt(n.timestamp) + ACCEPT_PERIOD < t);

/// x coordinate (32 bytes, big-endian) of a compressed ed25519 key.
export const xOf = (key: Buffer) => hb(ed25519.ExtendedPoint.fromHex(key).toAffine().x.toString(16).padStart(64, "0"));

/// CoSi check: sum the masked keys of `keys`, then one ed25519 verification of the snapshot hash.
function cosiOk(keys: Buffer[], sigHex: string, payload: Buffer): {ok: boolean; count: number} {
    const sig = hb(sigHex.slice(0, 128));
    const mask = BigInt("0x" + sigHex.slice(128));
    let A = ed25519.ExtendedPoint.ZERO;
    let count = 0;
    for (let i = 0; i < 64; i++) {
        if ((mask >> BigInt(i)) & 1n) {
            if (i >= keys.length) return {ok: false, count};
            A = A.add(ed25519.ExtendedPoint.fromHex(keys[i]));
            count++;
        }
    }
    return {ok: ed25519.verify(sig, Buffer.from(blake3(payload)), A.toRawBytes(), {zip215: false}), count};
}

const maskHex = (m: string) => {
    let h = BigInt("0x" + m).toString(16);
    if (h.length % 2) h = "0" + h;
    return hb(h);
};

/// [signerXs, payload, signature, mask] for a snapshot signed under `keys`.
export function finality(keys: Buffer[], snap: {payload: string; signature: string; mask: string}): unknown[] {
    const mask = BigInt("0x" + snap.mask);
    const xs: Buffer[] = [];
    for (let i = 0; i < 64; i++) if ((mask >> BigInt(i)) & 1n) xs.push(xOf(keys[i]));
    return [xs, hb(snap.payload), hb(snap.signature), maskHex(snap.mask)];
}

/// The verifier's node-set state machine (MixinKernelVerifier._applyChanges / _promote), used to
/// pick the signer list of each change and of the record snapshot.
export class NodeSetModel {
    ready: Buffer[];
    pendingKey: Buffer | null;
    pendingAt: bigint;
    changedAt: bigint;
    constructor(ready: Buffer[], pendingKey: Buffer | null, pendingAt: bigint, changedAt: bigint) {
        Object.assign(this, {ready: [...ready], pendingKey, pendingAt, changedAt});
    }
    promote(t: bigint) {
        if (this.pendingKey && this.pendingAt + ACCEPT_PERIOD < t) {
            this.ready.push(this.pendingKey);
            this.pendingKey = null;
            this.pendingAt = 0n;
        }
    }
    signers(t: bigint, extra?: Buffer) {
        const keys = [...this.ready];
        if (this.pendingKey && this.pendingAt + ACCEPT_PERIOD < t) keys.push(this.pendingKey);
        if (extra) keys.push(extra);
        return keys;
    }
    apply(kind: string, key: Buffer, t: bigint) {
        this.changedAt = t;
        this.promote(t);
        if (kind === "accept") {
            this.pendingKey = key;
            this.pendingAt = t;
        } else {
            this.ready = this.ready.filter((k) => !k.equals(key));
        }
    }
}

export const baseModel = (f: any) =>
    new NodeSetModel(
        f.base.ready.map((n: any) => hb(n.key)),
        f.base.pending ? hb(f.base.pending.key) : null,
        f.base.pending ? BigInt(f.base.pending.acceptedAt) : 0n,
        BigInt(f.base.changedAt)
    );

/// The node changes of the fixture as bundle field [1], and the model after them.
export function changesRlp(f: any): {changes: unknown[]; model: NodeSetModel} {
    const m = baseModel(f);
    const changes = f.changes.map((c: any) => {
        const t = BigInt(c.snapshot.timestamp);
        const keys = m.signers(t, c.kind === "accept" ? hb(c.key) : undefined);
        const item = [...finality(keys, c.snapshot), hb(c.transaction.payload)];
        m.apply(c.kind, hb(c.key), t);
        return item;
    });
    return {changes, model: m};
}

/// Bundle-shaped proof: [baseKeys, changes, recordFinality, thread, checkpoint, content].
export function mixinProof(f: any, thread: Buffer[], withChanges = true, checkpoint = 0): `0x${string}` {
    const {changes, model} = withChanges ? changesRlp(f) : {changes: [], model: null};
    const anchorKeys = withChanges ? f.base.ready.map((n: any) => hb(n.key)) : f.nodes.map((n: any) => hb(n.key));
    const signerKeys = model ? model.signers(BigInt(f.snapshot.timestamp)) : anchorKeys;
    return `0x${rlpEncode([anchorKeys, changes as never, finality(signerKeys, f.snapshot) as never, thread, checkpoint ? Buffer.from([1]) : Buffer.alloc(0), Buffer.alloc(0)]).toString("hex")}`;
}

async function snapshotRecord(hash: string, keys: Buffer[]) {
    const s = await rpc("getsnapshot", [hash]);
    const payload = snapshotPayload(hb(s.hex));
    if (Buffer.from(blake3(payload)).toString("hex") !== s.hash) throw new Error(`snapshot ${hash}: payload hash mismatch`);
    const {ok, count} = cosiOk(keys, s.signature, payload);
    if (!ok) throw new Error(`snapshot ${hash}: CoSi does not verify under the expected signer list`);
    return {
        rec: {hash: s.hash, round: s.round, topology: s.topology, timestamp: s.timestamp, payload: payload.toString("hex"), signature: s.signature.slice(0, 128), mask: s.signature.slice(128), signers: count, listSize: keys.length},
        s
    };
}

async function txRecord(hash: string) {
    const tx = await rpc("gettransaction", [hash]);
    const p = txPayload(hb(tx.hex));
    if (Buffer.from(blake3(p)).toString("hex") !== hash) throw new Error(`tx ${hash}: payload hash mismatch`);
    return {tx, rec: {hash, payload: p.toString("hex")}};
}

async function refresh() {
    const info = await rpc("getinfo", []);
    const now = await nodesAt(BigInt(Date.now()) * 1_000_000n + 1n);
    // node changes, newest first: an ACCEPTED node's (timestamp, transaction) is its accept, a
    // REMOVED node's is its removal
    const events = now
        .filter((n: any) => n.state === "ACCEPTED" || n.state === "REMOVED")
        .map((n: any) => ({kind: n.state === "ACCEPTED" ? "accept" : "remove", at: BigInt(n.timestamp), tx: n.transaction, signer: n.signer}))
        .sort((a: any, b: any) => (a.at < b.at ? 1 : -1))
        .slice(0, 2)
        .reverse();
    const first = events[0].at;
    const before = await nodesAt(first);
    const baseReady = readyAt(before, first);
    const pendingNode = before.find((n: any) => n.state === "ACCEPTED" && BigInt(n.timestamp) + ACCEPT_PERIOD >= first);
    const base = {
        ready: baseReady.map((n: any) => ({id: n.id, timestamp: n.timestamp, key: spendKey(n.signer).toString("hex")})),
        pending: pendingNode ? {key: spendKey(pendingNode.signer).toString("hex"), acceptedAt: pendingNode.timestamp} : null,
        changedAt: (first - 1n).toString()
    };
    const model = new NodeSetModel(baseReady.map((n: any) => spendKey(n.signer)), base.pending ? hb(base.pending.key) : null, base.pending ? BigInt(base.pending.acceptedAt) : 0n, first - 1n);
    const changes = [];
    for (const e of events) {
        const {tx, rec: txRec} = await txRecord(e.tx);
        const key = hb(tx.extra.slice(0, 64));
        if (!key.equals(spendKey(e.signer))) throw new Error(`change ${e.tx}: extra does not name the node's signer`);
        const keys = model.signers(e.at, e.kind === "accept" ? key : undefined);
        const {rec, s} = await snapshotRecord(tx.snapshot, keys);
        if (BigInt(s.timestamp) !== e.at) throw new Error(`change ${e.tx}: snapshot time ${s.timestamp} != node time ${e.at}`);
        changes.push({kind: e.kind, key: key.toString("hex"), snapshot: rec, transaction: txRec});
        model.apply(e.kind, key, e.at);
        console.log(`${e.kind} ${key.toString("hex").slice(0, 16)}… at ${e.at}: ${rec.signers}/${keys.length} signers`);
    }

    // a record-shaped transaction, final after the changes and signed under the resulting list
    const topo = Number(info.graph.topology);
    for (let start = topo - 2000; start > topo - 20000; start -= 200) {
        const snaps = await rpc("listsnapshots", [start, 200, true, true]);
        for (const s of snaps) {
            const ts = BigInt(s.timestamp);
            if (ts <= model.changedAt) continue;
            const m = new NodeSetModel(model.ready, model.pendingKey, model.pendingAt, model.changedAt);
            const keys = m.signers(ts);
            const payload = snapshotPayload(hb(s.hex));
            if (Buffer.from(blake3(payload)).toString("hex") !== s.hash) throw new Error("snapshot payload hash mismatch");
            const {ok, count} = cosiOk(keys, s.signature, payload);
            if (!ok) continue;
            for (const t of s.transactions) {
                if (t.inputs[0]?.index !== 0 || !t.inputs[0]?.hash) continue;
                const {tx, rec: txRec} = await txRecord(t.hash);
                m.promote(ts);
                const at = await nodesAt(ts);
                const nodes = m.ready.map((k) => at.find((n: any) => spendKey(n.signer).equals(k)));
                mkdirSync(path.dirname(FILE), {recursive: true});
                writeFileSync(
                    FILE,
                    JSON.stringify(
                        {
                            chain: "mixin-mainnet",
                            kernel: KERNEL,
                            version: info.version,
                            capturedAt: new Date().toISOString(),
                            base,
                            changes,
                            threshold: Math.floor((keys.length * 2) / 3) + 1,
                            nodes: nodes.map((n: any) => ({id: n.id, timestamp: n.timestamp, key: spendKey(n.signer).toString("hex")})),
                            snapshot: {hash: s.hash, topology: s.topology, timestamp: s.timestamp, payload: payload.toString("hex"), signature: s.signature.slice(0, 128), mask: s.signature.slice(128), signers: count, listSize: keys.length},
                            transaction: {...txRec, input0: t.inputs[0].hash, extra: tx.extra}
                        },
                        null,
                        1
                    ) + "\n"
                );
                console.log(`snapshot ${s.hash} (${count}/${keys.length} signers), tx ${t.hash} spends (${t.inputs[0].hash}, 0)`);
                return;
            }
        }
    }
    throw new Error("no suitable snapshot");
}

if (process.argv.includes("--refresh")) {
    refresh().catch((e) => {
        console.error(e);
        process.exit(1);
    });
}
