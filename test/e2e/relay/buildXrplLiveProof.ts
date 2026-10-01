/// Build XrplVerifier / XrplLightClient proofs from the live XRPL fixtures in
/// test/e2e/fixtures/xrpl-live:
///   mainnet.json   35-validator UNL, 35 full validations of one ledger, all its tx+meta, a memo
///                  Payment (tesSUCCESS) and the sender's AccountRoot path (captureXrplLive.ts)
///   testnet.json   6-validator UNL, 6 validations of ledger 21187460, the outbox AccountRoot path,
///                  and the skip list linking back to the message ledgers (linkXrplMessages.ts)
///   messages.json  five clpr/v1 outbox messages (2-of-3 multisig AccountSets) from
///                  tools/xrpl-clpr-emitter (branch feat/xrpl-design), with their full ledgers
import {readFileSync} from "node:fs";
import path from "node:path";
import {secp256k1} from "@noble/curves/secp256k1";
import {keccak_256} from "@noble/hashes/sha3";
import {rlpEncode} from "../lib/rlp.js";
import {walk, top, txId, txLeafHash, shamapProof} from "./xrplCodec.js";

const DIR = path.join(import.meta.dirname, "..", "fixtures", "xrpl-live");
export const loadXrplFixture = (name: string) => JSON.parse(readFileSync(path.join(DIR, `${name}.json`), "utf8"));

const hb = (h: string) => Buffer.from(h, "hex");
/// RLP scalar: minimal big-endian bytes, empty for zero.
function u(n: number | bigint): Buffer {
    let h = BigInt(n).toString(16);
    if (h === "0") return Buffer.alloc(0);
    if (h.length % 2) h = "0" + h;
    return hb(h);
}

export function secpAddress(compressed: Buffer): Buffer {
    const p = secp256k1.ProjectivePoint.fromHex(compressed).toRawBytes(false);
    return Buffer.from(keccak_256(p.subarray(1))).subarray(12);
}

type Entry = {master: string; signing: string; seq: number; manifest: string};

/// UNL as the anchor commits to it: [master, signingAddress, seq].
export const unlAnchor = (es: Entry[]) => es.map((e) => [hb(e.master), secpAddress(hb(e.signing)), u(e.seq)]);
/// UNL as verifyConfig takes it: [master, compressedSigningKey, seq].
export const unlConfig = (es: Entry[]) => es.map((e) => [hb(e.master), hb(e.signing), u(e.seq)]);

export function unlHash(es: Entry[]): `0x${string}` {
    const acc = Buffer.concat(es.flatMap((e) => [hb(e.master), secpAddress(hb(e.signing)), Buffer.from([0, 0, 0, 0].map((_, i) => (e.seq >>> (24 - 8 * i)) & 255))]));
    return `0x${Buffer.from(keccak_256(acc)).toString("hex")}`;
}

/// [[unlIndex, STValidation], ...] ordered by UNL index, at most `limit` of them.
export function validations(f: any, limit = Infinity) {
    const idx = new Map<string, number>(f.unl.entries.map((e: Entry, i: number) => [e.signing, i]));
    return f.validations
        .map((v: any) => [idx.get(v.signing)!, hb(v.data)] as [number, Buffer])
        .filter(([i]: [number, Buffer]) => i !== undefined)
        .sort((a: [number, Buffer], b: [number, Buffer]) => a[0] - b[0])
        .slice(0, limit)
        .map(([i, d]: [number, Buffer]) => [u(i), d]);
}

/// [ledgerRef, tx, meta, inners] for transaction `index` of a ledger given as [{tx, meta}] hex.
export function txEntry(ledgerTxs: {tx: string; meta: string}[], index: number, ref: number) {
    const items = ledgerTxs.map((t) => {
        const tx = hb(t.tx);
        const id = txId(tx);
        return {key: id, leafHash: txLeafHash(tx, hb(t.meta), id)};
    });
    const {root, path: p} = shamapProof(items, items[index].key);
    return {entry: [u(ref), hb(ledgerTxs[index].tx), hb(ledgerTxs[index].meta), p.map((k) => Buffer.concat(k))], root};
}

const hex = (b: Buffer) => `0x${b.toString("hex")}` as `0x${string}`;

/// Mainnet: prove the memo transaction (txField 5) and, separately, the sender's AccountRoot.
export function mainnetProofs(f: any, opts: {quorumOnly?: boolean} = {}) {
    const n = f.unl.entries.length;
    const vals = validations(f, opts.quorumOnly ? f.unl.quorum : Infinity);
    const {entry} = txEntry(f.txs, f.memoTx.index, 0);
    const prefix = [unlAnchor(f.unl.entries), [], hb(f.ledger.header), vals, []];
    const txProof = hex(rlpEncode([...prefix, [entry]]));
    const stateProof = hex(rlpEncode([...prefix, f.accountState.inners.map(hb), hb(f.accountState.key), hb(f.accountState.leaf)]));
    return {txProof, stateProof, unlHash: unlHash(f.unl.entries), unlCount: BigInt(n), validationCount: vals.length};
}

/// A manifest-rotation case on live data: anchor validator 0 at (sequence - 1, a stale signing key)
/// and supply its real manifest, signed by its real ed25519 master key.
export function mainnetRotation(f: any) {
    const es: Entry[] = f.unl.entries.map((e: Entry) => ({...e}));
    // stale signing key: the secp256k1 generator (a valid point nobody validates with)
    const stale = {...es[0], seq: es[0].seq - 1, signing: Buffer.from(secp256k1.ProjectivePoint.BASE.toRawBytes(true)).toString("hex")};
    const anchored = [stale, ...es.slice(1)];
    const vals = validations(f);
    const {entry} = txEntry(f.txs, f.memoTx.index, 0);
    const proof = hex(rlpEncode([unlAnchor(anchored), [hb(es[0].manifest)], hb(f.ledger.header), vals, [], [entry]]));
    return {proof, unlHash: unlHash(anchored), rotatedHash: unlHash(es), unlCount: BigInt(es.length)};
}

/// Testnet outbox: config proof (outbox AccountRoot in a validated ledger) and the bundle of the
/// five recorded messages, linked to the validated ledger through its skip list.
export function testnetOutbox(f: any, m: any, controlMessage: `0x${string}`, opts: {messages?: number} = {}) {
    const msgs = m.messages.slice(0, opts.messages ?? m.messages.length);
    const configProof = hex(
        rlpEncode([
            unlConfig(f.unl.entries),
            hb(f.ledger.header),
            validations(f),
            f.accountState.inners.map(hb),
            hb(f.accountState.leaf),
            u(m.seq_base),
            hb(controlMessage.slice(2)),
            Buffer.alloc(0)
        ])
    );
    // ancestors: one entry per distinct message ledger, the first carrying the skip list proof
    const ledgerSeqs = [...new Set(msgs.map((x: any) => String(x.ledger_index)))] as string[];
    const sk = f.messageLink.skipList;
    const ancestors = ledgerSeqs.map((s, i) =>
        i === 0 ? [hb(f.messageLink.headers[s]), sk.inners.map(hb), hb(sk.leaf)] : [hb(f.messageLink.headers[s]), Buffer.alloc(0)]
    );
    const txs = msgs.map((x: any) => {
        const L = m.ledgers[String(x.ledger_index)];
        const lt = L.transactions.map((t: any) => ({tx: t.tx_blob, meta: t.meta_blob}));
        const i = lt.findIndex((t: any) => t.tx.toUpperCase() === x.tx_blob.toUpperCase());
        const {entry, root} = txEntry(lt, i, ledgerSeqs.indexOf(String(x.ledger_index)) + 1);
        if (!root.equals(hb(L.header.transaction_hash))) throw new Error(`tx root mismatch ${x.ledger_index}`);
        return entry;
    });
    const bundleProof = hex(rlpEncode([unlAnchor(f.unl.entries), [], hb(f.ledger.header), validations(f, f.unl.quorum), ancestors, txs, Buffer.alloc(32)]));
    return {configProof, bundleProof, messages: msgs};
}

/// Decode helpers for assertions.
export function txFields(txHex: string) {
    const fs = walk(hb(txHex));
    return {account: top(fs, 8, 1)!.value.toString("hex"), sequence: top(fs, 2, 4)!.value.readUInt32BE(0)};
}
