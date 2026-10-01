import {bls12_381} from "@noble/curves/bls12-381";
import {sha3_256} from "@noble/hashes/sha3";
import {mkdirSync, readFileSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {type Hex, keccak256} from "viem";
import {hexToBuf, rlpEncode} from "../lib/rlp.js";

/// Live-data proof builder for `ConfluxPosLightClient` (Conflux mainnet, public RPC only).
///
/// Captured from https://main.confluxrpc.com (core space) and https://evm.confluxrpc.com (eSpace):
///   - `pos_getStatus` → the current PoS epoch E;
///   - `pos_getLedgerInfoByEpoch(E-2)` → its `next_epoch_state` is the committee of epoch E-1
///     (the bootstrap committee; `nextEpochValidators` carries the keys uncompressed);
///   - `pos_getLedgerInfoByEpoch(E-1)` → the last ledger info of E-1, signed by the E-1 committee,
///     which carries the E committee (a real rotation);
///   - `pos_getLedgerInfoByBlockNumber(latestCommitted)` → a ledger info of epoch E with a pivot
///     decision (stepping back until the pivot block has blame 0);
///   - `cfx_getBlockByHash(pivot)` and eSpace `eth_getBlockByNumber(height)` → the pivot header
///     (rebuilt as RLP) and the eSpace stateRoot used as a cross-check.
///
/// CLI:
///   npx tsx test/e2e/relay/buildConfluxLiveProof.ts --refresh   re-capture mainnet, write vectors
///   npx tsx test/e2e/relay/buildConfluxLiveProof.ts --vectors   rebuild vectors.json from capture.json

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const CONFLUX_LIVE_DIR = path.resolve(__dirname, "../fixtures/conflux-live");
const CAPTURE = path.join(CONFLUX_LIVE_DIR, "capture.json");
const VECTORS = path.join(CONFLUX_LIVE_DIR, "vectors.json");

export const CONFLUX = {
    coreRpc: "https://main.confluxrpc.com",
    evmRpc: "https://evm.confluxrpc.com",
    dst: "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
};

type J = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

async function rpc<T>(url: string, method: string, params: unknown[]): Promise<T> {
    for (let attempt = 0; ; attempt++) {
        try {
            const res = await fetch(url, {
                method: "POST",
                headers: {"content-type": "application/json"},
                body: JSON.stringify({jsonrpc: "2.0", id: 1, method, params})
            });
            const j = (await res.json()) as {result?: T; error?: {code: number; message: string}};
            if (j.error) throw new Error(`${method}: ${j.error.code} ${j.error.message}`);
            return j.result as T;
        } catch (err) {
            if (attempt >= 3) throw err;
            await new Promise((r) => setTimeout(r, 1000 * (attempt + 1)));
        }
    }
}

const hx = (n: bigint | number) => "0x" + BigInt(n).toString(16);

export async function captureConfluxLive(): Promise<J> {
    const status = await rpc<J>(CONFLUX.coreRpc, "pos_getStatus", []);
    const E = BigInt(status.epoch);
    const liBoot = await rpc<J>(CONFLUX.coreRpc, "pos_getLedgerInfoByEpoch", [hx(E - 2n)]);
    const liRot = await rpc<J>(CONFLUX.coreRpc, "pos_getLedgerInfoByEpoch", [hx(E - 1n)]);
    let n = BigInt(status.latestCommitted);
    for (let tries = 0; tries < 50; tries++, n -= 1n) {
        const li = await rpc<J>(CONFLUX.coreRpc, "pos_getLedgerInfoByBlockNumber", [hx(n)]);
        const ci = li?.ledgerInfo?.commitInfo;
        if (!ci || BigInt(ci.epoch) !== E || !ci.pivot || ci.nextEpochState) continue;
        const block = await rpc<J>(CONFLUX.coreRpc, "cfx_getBlockByHash", [ci.pivot.blockHash, false]);
        if (BigInt(block.blame) !== 0n) continue;
        const eblock = await rpc<J>(CONFLUX.evmRpc, "eth_getBlockByNumber", [ci.pivot.height, false]);
        return {capturedAt: new Date().toISOString(), status, liBoot, liRot, liBundle: li, block, eblock};
    }
    throw new Error("no epoch-E ledger info with a blame-0 pivot block found");
}

// ── BCS (conflux-rust crates/pos/types) ─────────────────────────────────────────────────────

function uleb(n: number): Buffer {
    const out: number[] = [];
    for (;;) {
        const b = n & 0x7f;
        n >>>= 7;
        if (n) out.push(b | 0x80);
        else return Buffer.from([...out, b]);
    }
}
const u64 = (h: string) => {
    const b = Buffer.alloc(8);
    b.writeBigUInt64LE(BigInt(h));
    return b;
};
const bytesField = (h: string) => {
    const b = hexToBuf(h);
    return Buffer.concat([uleb(b.length), b]);
};
const h256Field = (h: string) => {
    const s = Buffer.from(h.toLowerCase(), "ascii");
    return Buffer.concat([uleb(s.length), s]);
};

function epochStateBcs(es: J): Buffer {
    const parts: Buffer[] = [u64(es.epoch)];
    const m = es.verifier.addressToValidatorInfo;
    const keys = Object.keys(m).sort();
    parts.push(uleb(keys.length));
    for (const k of keys) {
        const v = m[k];
        parts.push(hexToBuf(k), bytesField(v.publicKey));
        parts.push(v.vrfPublicKey ? Buffer.concat([Buffer.from([1]), bytesField(v.vrfPublicKey)]) : Buffer.from([0]));
        parts.push(u64(v.votingPower));
    }
    parts.push(u64(es.verifier.quorumVotingPower), u64(es.verifier.totalVotingPower), bytesField(es.vrfSeed));
    return Buffer.concat(parts);
}

export function ledgerInfoBcs(li: J): Buffer {
    const c = li.commitInfo;
    const parts: Buffer[] = [
        u64(c.epoch), u64(c.round), bytesField(c.id), bytesField(c.executedStateId), u64(c.version), u64(c.timestampUsecs)
    ];
    parts.push(c.nextEpochState ? Buffer.concat([Buffer.from([1]), epochStateBcs(c.nextEpochState)]) : Buffer.from([0]));
    parts.push(c.pivot ? Buffer.concat([Buffer.from([1]), u64(c.pivot.height), h256Field(c.pivot.blockHash)]) : Buffer.from([0]));
    parts.push(bytesField(li.consensusDataHash));
    return Buffer.concat(parts);
}

// ── BLS encodings ───────────────────────────────────────────────────────────────────────────

/// Big-endian 48-byte field element → EIP-2537 64-byte slot.
const pad64 = (b: Buffer) => Buffer.concat([Buffer.alloc(16), b]);

/// RPC `nextEpochValidators` key: uncompressed `x(48) ‖ y(48)` → EIP-2537 G1 (128 B).
const g1Eip2537 = (h: string) => {
    const b = hexToBuf(h);
    if (b.length !== 96) throw new Error("expected 96-byte uncompressed G1 key");
    return Buffer.concat([pad64(b.subarray(0, 48)), pad64(b.subarray(48, 96))]);
};

/// ZCash-serialized uncompressed G2 (192 B: x.c1 ‖ x.c0 ‖ y.c1 ‖ y.c0) → EIP-2537 (c0 before c1).
export function g2Eip2537(h: string): Buffer {
    const b = hexToBuf(h);
    if (b.length !== 192 || (b[0] & 0xe0) !== 0) throw new Error("expected 192-byte uncompressed G2");
    return Buffer.concat([pad64(b.subarray(48, 96)), pad64(b.subarray(0, 48)), pad64(b.subarray(144, 192)), pad64(b.subarray(96, 144))]);
}

interface CommitteeV {
    epoch: string;
    addresses: string[];
    keys: Hex; // n·128
    weights: string[];
    quorum: string;
    hash: Hex;
}

function committeeFrom(liWithNext: J): CommitteeV {
    const es = liWithNext.ledgerInfo.commitInfo.nextEpochState;
    const m = es.verifier.addressToValidatorInfo;
    const unc = liWithNext.nextEpochValidators as Record<string, string>;
    const addresses = Object.keys(m).sort();
    const keys = Buffer.concat(addresses.map((a) => g1Eip2537(unc[a])));
    // Cross-check: the uncompressed key is the compressed key the epoch state certifies.
    addresses.forEach((a) => {
        const p = bls12_381.G1.ProjectivePoint.fromHex(hexToBuf(m[a].publicKey).toString("hex"));
        const u = hexToBuf(unc[a]);
        if (p.toAffine().x !== BigInt("0x" + u.subarray(0, 48).toString("hex"))) throw new Error(`key mismatch ${a}`);
    });
    const weights = addresses.map((a) => BigInt(m[a].votingPower).toString());
    const quorum = BigInt(es.verifier.quorumVotingPower).toString();
    const w = Buffer.concat(weights.map((x) => {
        const b = Buffer.alloc(8);
        b.writeBigUInt64BE(BigInt(x));
        return b;
    }));
    const e = Buffer.alloc(8);
    e.writeBigUInt64BE(BigInt(es.epoch));
    const qb = Buffer.alloc(8);
    qb.writeBigUInt64BE(BigInt(quorum));
    const hash = keccak256(Buffer.concat([e, qb, keys, w]));
    return {epoch: BigInt(es.epoch).toString(), addresses, keys: ("0x" + keys.toString("hex")) as Hex, weights, quorum, hash};
}

function bitmap(addresses: string[], signers: string[]): Buffer {
    const out = Buffer.alloc(Math.ceil(addresses.length / 8));
    const set = new Set(signers.map((s) => s.toLowerCase()));
    addresses.forEach((a, i) => {
        if (set.has(a.toLowerCase())) out[i >> 3] |= 1 << (i & 7);
    });
    return out;
}

// ── pivot header RLP (crates/primitives/src/block_header.rs stream_rlp) ────────────────────

const B32 = "abcdefghjkmnprstuvwxyz0123456789";
function cfxAddressToHex(a: string): Buffer {
    const p = a.split(":").pop()!;
    const bits = [...p.slice(0, -8)].map((c) => B32.indexOf(c).toString(2).padStart(5, "0")).join("");
    const bytes: number[] = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
    return Buffer.from(bytes.slice(1, 21)); // drop the version byte
}
const q = (h: string | bigint) => {
    const n = BigInt(h);
    if (n === 0n) return Buffer.alloc(0);
    let s = n.toString(16);
    if (s.length % 2) s = "0" + s;
    return Buffer.from(s, "hex");
};

export function pivotHeaderRlp(b: J, eb: J): Buffer {
    const items: unknown[] = [
        hexToBuf(b.parentHash), q(b.height), q(b.timestamp), cfxAddressToHex(b.miner), hexToBuf(b.transactionsRoot),
        hexToBuf(b.deferredStateRoot), hexToBuf(b.deferredReceiptsRoot), hexToBuf(b.deferredLogsBloomHash), q(b.blame),
        q(b.difficulty), q(b.adaptive ? 1n : 0n),
        // cfx_getBlockByHash reports 90% of the header gas limit (the core-space share).
        q((BigInt(b.gasLimit) * 10n) / 9n),
        (b.refereeHashes as string[]).map(hexToBuf), q(b.nonce)
    ];
    if (b.posReference) items.push([hexToBuf(b.posReference)]);
    if (b.baseFeePerGas) items.push([[q(b.baseFeePerGas), q(eb.baseFeePerGas)]]);
    const enc = rlpEncode(items as never);
    // `custom` items are appended raw (each already one RLP string) inside the outer list.
    const custom = Buffer.concat((b.custom as string[]).map((c) => rlpEncode(hexToBuf(c))));
    const {offset} = listHeader(enc);
    const body = Buffer.concat([enc.subarray(offset), custom]);
    return Buffer.concat([lenPrefix(body.length), body]);
}
function listHeader(enc: Buffer): {offset: number} {
    const b0 = enc[0];
    return {offset: b0 <= 0xf7 ? 1 : 1 + (b0 - 0xf7)};
}
function lenPrefix(n: number): Buffer {
    if (n < 56) return Buffer.from([0xc0 + n]);
    const l = q(BigInt(n));
    return Buffer.concat([Buffer.from([0xf7 + l.length]), l]);
}

// ── vectors ─────────────────────────────────────────────────────────────────────────────────

const hexOf = (b: Buffer) => ("0x" + b.toString("hex")) as Hex;

export interface ConfluxVectors {
    capturedAt: string;
    bootstrap: CommitteeV;
    next: CommitteeV;
    rotation: {ledgerInfo: Hex; bitmap: Hex; signature: Hex; signers: number};
    bundle: {
        ledgerInfo: Hex; bitmap: Hex; signature: Hex; signers: number; epoch: string; round: string;
        pivotHeight: string; pivotHash: Hex; header: Hex; deferredStateRoot: Hex; espaceStateRoot: Hex;
    };
    proofs: {catchUp: Hex; bundleWithRotation: Hex; bundle: Hex};
}

function verifyOffline(keys: Buffer, bm: Buffer, sig: Buffer, msg: Buffer): void {
    const G1 = bls12_381.G1.ProjectivePoint;
    let agg = G1.ZERO;
    for (let i = 0; i < keys.length / 128; i++) {
        if (!((bm[i >> 3] >> (i & 7)) & 1)) continue;
        const k = keys.subarray(i * 128, i * 128 + 128);
        agg = agg.add(G1.fromAffine({x: BigInt(hexOf(k.subarray(16, 64))), y: BigInt(hexOf(k.subarray(80, 128)))}));
    }
    const Fp2 = bls12_381.fields.Fp2;
    const f = (o: number) => BigInt(hexOf(sig.subarray(o + 16, o + 64)));
    const s = bls12_381.G2.ProjectivePoint.fromAffine({x: Fp2.fromBigTuple([f(0), f(64)]), y: Fp2.fromBigTuple([f(128), f(192)])});
    const h = bls12_381.G2.hashToCurve(msg, {DST: CONFLUX.dst}) as never;
    const ok = bls12_381.fields.Fp12.eql(bls12_381.pairing(agg, h), bls12_381.pairing(G1.BASE, s));
    if (!ok) throw new Error("offline BLS check failed");
}

export function buildConfluxVectors(c: J): ConfluxVectors {
    const seed = Buffer.from(sha3_256(Buffer.from("DIEM::LedgerInfo")));
    if (seed.toString("hex") !== "cd510d1ab583c33b54fa949014601df0664857c18c4cfb228c862dd869df1b62") throw new Error("seed");
    const boot = committeeFrom(c.liBoot);
    const next = committeeFrom(c.liRot);

    const rotBcs = ledgerInfoBcs(c.liRot.ledgerInfo);
    const rotBm = bitmap(boot.addresses, Object.keys(c.liRot.signatures));
    const rotSig = g2Eip2537(c.liRot.aggregatedSignature);
    verifyOffline(hexToBuf(boot.keys), rotBm, rotSig, Buffer.concat([seed, rotBcs]));

    const li = c.liBundle;
    const ci = li.ledgerInfo.commitInfo;
    const bBcs = ledgerInfoBcs(li.ledgerInfo);
    const bBm = bitmap(next.addresses, Object.keys(li.signatures));
    const bSig = g2Eip2537(li.aggregatedSignature);
    verifyOffline(hexToBuf(next.keys), bBm, bSig, Buffer.concat([seed, bBcs]));

    const header = pivotHeaderRlp(c.block, c.eblock);
    if (keccak256(header) !== c.block.hash) throw new Error("pivot header hash mismatch");
    if (c.block.deferredStateRoot !== c.eblock.stateRoot) throw new Error("deferred state root != eSpace stateRoot");

    const committeeItem = (cv: CommitteeV) => [hexToBuf(cv.keys), cv.weights.map((w) => q(BigInt(w))), q(BigInt(cv.quorum))];
    const transition = [rotBcs, rotBm, rotSig, hexToBuf(next.keys)];
    const tail = [bBcs, bBm, bSig, header];
    return {
        capturedAt: c.capturedAt,
        bootstrap: boot,
        next,
        rotation: {ledgerInfo: hexOf(rotBcs), bitmap: hexOf(rotBm), signature: hexOf(rotSig), signers: Object.keys(c.liRot.signatures).length},
        bundle: {
            ledgerInfo: hexOf(bBcs), bitmap: hexOf(bBm), signature: hexOf(bSig), signers: Object.keys(li.signatures).length,
            epoch: BigInt(ci.epoch).toString(), round: BigInt(ci.round).toString(),
            pivotHeight: BigInt(ci.pivot.height).toString(), pivotHash: ci.pivot.blockHash, header: hexOf(header),
            deferredStateRoot: c.block.deferredStateRoot, espaceStateRoot: c.eblock.stateRoot
        },
        proofs: {
            catchUp: hexOf(rlpEncode([committeeItem(boot), [transition]] as never)),
            bundleWithRotation: hexOf(rlpEncode([committeeItem(boot), [transition], ...tail] as never)),
            bundle: hexOf(rlpEncode([committeeItem(next), [], ...tail] as never))
        }
    };
}

export function loadConfluxVectors(): ConfluxVectors {
    return JSON.parse(readFileSync(VECTORS, "utf8")) as ConfluxVectors;
}

async function main() {
    const args = process.argv.slice(2);
    mkdirSync(CONFLUX_LIVE_DIR, {recursive: true});
    if (args.includes("--refresh")) {
        const cap = await captureConfluxLive();
        writeFileSync(CAPTURE, JSON.stringify(cap, null, 1) + "\n");
        console.log(`captured epoch ${BigInt(cap.status.epoch)} at ${cap.capturedAt}`);
    }
    if (args.includes("--refresh") || args.includes("--vectors")) {
        const v = buildConfluxVectors(JSON.parse(readFileSync(CAPTURE, "utf8")));
        writeFileSync(VECTORS, JSON.stringify(v, null, 1) + "\n");
        console.log(`vectors: bootstrap epoch ${v.bootstrap.epoch} (${v.bootstrap.addresses.length} validators), pivot ${v.bundle.pivotHeight}, stateRoot ${v.bundle.deferredStateRoot}`);
    }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
    main().catch((e) => {
        console.error(e);
        process.exit(1);
    });
}
