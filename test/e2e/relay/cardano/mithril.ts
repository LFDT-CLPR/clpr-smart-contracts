import {bls12_381} from "@noble/curves/bls12-381";
import {blake2b} from "@noble/hashes/blake2b";
import {sha256} from "@noble/hashes/sha2";

/// Reference (off-chain) model of Mithril certificate verification, written against mithril-stm
/// 0.12.x and mithril-common (IntersectMBO/mithril @ 321f8d8, 30 Sep 2026). It decodes the
/// aggregator's certificate JSON and re-checks exactly what CardanoMithrilVerifier checks on-chain, so
/// fixtures are validated twice (here and in the EVM).

const G1 = bls12_381.G1.ProjectivePoint;
const G2 = bls12_381.G2.ProjectivePoint;
const P = bls12_381.fields.Fp.ORDER;

export type Hexish = string;

/// `ProtocolMessagePartKey` in declaration order (the BTreeMap order used by the legacy hash).
export const PART_KEYS = [
    "snapshot_digest",
    "cardano_transactions_merkle_root",
    "cardano_blocks_transactions_merkle_root",
    "next_aggregate_verification_key",
    "next_protocol_parameters",
    "current_epoch",
    "latest_block_number",
    "cardano_blocks_transactions_block_number_offset",
    "cardano_stake_distribution_epoch",
    "cardano_stake_distribution_merkle_root",
    "cardano_database_merkle_root",
    "next_aggregate_verification_key_snark",
] as const;

export interface Avk {
    root: Uint8Array; // Blake2b-256 batch-commitment root
    nrLeaves: number;
    totalStake: bigint;
}

export interface Params {
    k: bigint;
    m: bigint;
    phiF: number;
}

export interface SignerEntry {
    sigma: Uint8Array; // 48-byte compressed G1
    indexes: bigint[];
    signerIndex: number;
    vk: Uint8Array; // 96-byte compressed G2
    stake: bigint;
}

export interface Certificate {
    hash: string;
    previousHash: string;
    epoch: bigint;
    params: Params;
    parts: [string, string][]; // ordered (key, value)
    signedMessage: string; // 64 hex chars — the bytes the STM signs are this ASCII string
    avk: Avk;
    signers: SignerEntry[];
    batchValues: Uint8Array[];
    batchIndices: number[];
    signedEntityType: unknown;
}

export const avkJson = (a: Avk): string =>
    `{"mt_commitment":{"root":[${Array.from(a.root).join(",")}],"nr_leaves":${a.nrLeaves},"hasher":null},"total_stake":${a.totalStake}}`;

export function parseAvk(hexJson: string): Avk {
    const s = Buffer.from(hexJson, "hex").toString("utf8");
    // Integer-exact parse (total_stake can exceed 2^53).
    const m = s.match(/^\{"mt_commitment":\{"root":\[([0-9,]+)\],"nr_leaves":(\d+),"hasher":null\},"total_stake":(\d+)\}$/);
    if (!m) throw new Error(`unexpected AVK encoding: ${s.slice(0, 120)}`);
    const avk = {root: Uint8Array.from(m[1].split(",").map(Number)), nrLeaves: Number(m[2]), totalStake: BigInt(m[3])};
    if (avk.root.length !== 32) throw new Error("avk root length");
    if (Buffer.from(avkJson(avk)).toString("hex") !== hexJson) throw new Error("AVK does not round-trip");
    return avk;
}

export function parseCertificate(c: any): Certificate {
    const raw = Buffer.from(c.multi_signature, "hex").toString("utf8");
    // Keep big integers exact: stakes can exceed 2^53.
    const ms = JSON.parse(raw.replace(/("stake"|\]),\s*(\d{16,})\]/g, (_m, a, n) => `${a},"${n}"]`));
    const msBig = JSON.parse(raw.replace(/(\d{16,})/g, '"$1"'));
    const signers: SignerEntry[] = msBig.signatures.map((s: any) => ({
        sigma: Uint8Array.from(s[0].sigma.map(Number)),
        indexes: s[0].indexes.map((x: any) => BigInt(x)),
        signerIndex: Number(s[0].signer_index),
        vk: Uint8Array.from(s[1][0].map(Number)),
        stake: BigInt(s[1][1]),
    }));
    void ms;
    const parts = Object.entries(c.protocol_message.message_parts as Record<string, string>);
    parts.sort((a, b) => PART_KEYS.indexOf(a[0] as never) - PART_KEYS.indexOf(b[0] as never));
    for (const [k] of parts) if (!PART_KEYS.includes(k as never)) throw new Error(`unknown part ${k}`);
    return {
        hash: c.hash,
        previousHash: c.previous_hash,
        epoch: BigInt(c.epoch),
        params: {k: BigInt(c.metadata.parameters.k), m: BigInt(c.metadata.parameters.m), phiF: c.metadata.parameters.phi_f},
        parts: parts as [string, string][],
        signedMessage: c.signed_message,
        avk: parseAvk(c.aggregate_verification_key),
        signers,
        batchValues: msBig.batch_proof.values.map((v: any) => Uint8Array.from(v.map(Number))),
        batchIndices: msBig.batch_proof.indices.map(Number),
        signedEntityType: c.signed_entity_type,
    };
}

export const part = (c: Certificate, k: string): string | undefined => c.parts.find(([kk]) => kk === k)?.[1];

/// Legacy protocol-message hash: SHA-256 over key‖value for each part in key order.
export function protocolMessageHash(parts: [string, string][]): string {
    const chunks = parts.flatMap(([k, v]) => [Buffer.from(k), Buffer.from(v)]);
    return Buffer.from(sha256(Buffer.concat(chunks))).toString("hex");
}

/// `ProtocolParameters::compute_hash`: SHA-256(k BE8 ‖ m BE8 ‖ U8F24(phi_f) BE4), hex.
export function protocolParametersHash(p: Params): string {
    const b = Buffer.alloc(20);
    b.writeBigUInt64BE(p.k, 0);
    b.writeBigUInt64BE(p.m, 8);
    b.writeUInt32BE(phiFixed(p.phiF), 16);
    return Buffer.from(sha256(b)).toString("hex");
}

/// fixed::U8F24::from_num(f64): round to nearest, ties to even.
export function phiFixed(phi: number): number {
    const x = phi * 2 ** 24; // exact (power-of-two scaling)
    const f = Math.floor(x);
    const r = x - f;
    if (r > 0.5) return f + 1;
    if (r < 0.5) return f;
    return f % 2 === 0 ? f : f + 1;
}

/// f64 → (mantissa, exponent) with value = mantissa · 2^exponent, mantissa odd or zero.
export function f64Parts(x: number): {neg: boolean; mant: bigint; exp: number} {
    const dv = new DataView(new ArrayBuffer(8));
    dv.setFloat64(0, x);
    const bits = dv.getBigUint64(0);
    const neg = bits >> 63n === 1n;
    const e = Number((bits >> 52n) & 0x7ffn);
    let mant = bits & ((1n << 52n) - 1n);
    let exp: number;
    if (e === 0) exp = -1074;
    else {
        mant |= 1n << 52n;
        exp = e - 1075;
    }
    while (mant > 0n && (mant & 1n) === 0n) {
        mant >>= 1n;
        exp += 1;
    }
    return {neg, mant, exp};
}

/// The constant `c = ln(1 − phi_f)` exactly as the num-integer backend sees it (an f64).
export const lotteryConstant = (phiF: number) => f64Parts(Math.log(1.0 - phiF));

// ── Hashes ───────────────────────────────────────────────────────────────────

export const blake2b256 = (d: Uint8Array) => blake2b(d, {dkLen: 32});

export function denseMapping(msgp: Uint8Array, index: bigint, sigma: Uint8Array): Uint8Array {
    const ib = Buffer.alloc(8);
    ib.writeBigUInt64LE(index);
    return blake2b(Buffer.concat([Buffer.from("map"), msgp, ib, sigma]), {dkLen: 64});
}

/// Exact lottery check (num-integer backend semantics: q < exp(-w·c) via a rational Taylor bound).
export function isLotteryWon(phiF: number, ev: Uint8Array, stake: bigint, totalStake: bigint): boolean {
    if (phiF === 1) return true;
    const evInt = BigInt("0x" + Buffer.from(ev).reverse().toString("hex"));
    const evMax = 1n << 512n;
    // p = ev/2^512 < 1 − exp(x) with x = (stake/total)·c, c = ln(1−phi) < 0 (exact f64).
    const {mant, exp} = lotteryConstant(phiF);
    // Evaluate exp(−|x|) to 2^-400 with integers.
    const S = 1n << 400n;
    const xNum = stake * mant; // |x| = stake·mant / (total·2^-exp)
    const xDen = totalStake * (1n << BigInt(-exp));
    const xs = (xNum * S) / xDen;
    let term = S;
    let sum = S;
    for (let n = 1n; n < 400n; n++) {
        term = (term * xs) / (S * n);
        if (term === 0n) break;
        sum += n % 2n === 1n ? -term : term;
    }
    const t = S - sum; // 1 − exp(−|x|), scaled by S
    return evInt * S < t * evMax;
}

// ── STM Merkle batch path (Blake2b-256, heap layout, padding = H(0x00)) ─────

export function leafBytes(vk: Uint8Array, stake: bigint): Uint8Array {
    const b = Buffer.alloc(104);
    Buffer.from(vk).copy(b, 0);
    b.writeBigUInt64BE(stake, 96);
    return b;
}

export function verifyBatchPath(root: Uint8Array, nrLeaves: number, leaves: Uint8Array[], indices: number[], values: Uint8Array[]): boolean {
    let pow2 = 1;
    while (pow2 < nrLeaves) pow2 *= 2;
    const nrNodes = pow2 + nrLeaves - 1;
    let idxs = indices.map((i) => pow2 + i - 1);
    let hs = leaves.map((l) => blake2b256(l));
    const vals = values.slice();
    const pad = blake2b256(Uint8Array.of(0));
    let idx = idxs[0];
    const H = (a: Uint8Array, b: Uint8Array) => blake2b256(Buffer.concat([a, b]));
    while (idx > 0) {
        const nh: Uint8Array[] = [];
        const ni: number[] = [];
        idx = Math.floor((idx - 1) / 2);
        for (let i = 0; i < idxs.length; i++) {
            ni.push(Math.floor((idxs[i] - 1) / 2));
            if (idxs[i] % 2 === 0) {
                nh.push(H(vals.shift()!, hs[i]));
            } else {
                const sib = idxs[i] + 1;
                if (i < idxs.length - 1 && idxs[i + 1] === sib) {
                    nh.push(H(hs[i], hs[i + 1]));
                    i++;
                } else if (sib < nrNodes) {
                    nh.push(H(hs[i], vals.shift()!));
                } else {
                    nh.push(H(hs[i], pad));
                }
            }
        }
        hs = nh;
        idxs = ni;
    }
    return hs.length === 1 && Buffer.from(hs[0]).equals(Buffer.from(root)) && vals.length === 0;
}

// ── BLS (min_sig: signatures in G1, keys in G2; hash-to-G1 with an EMPTY DST) ──

export function hashToG1(msg: Uint8Array) {
    return bls12_381.G1.hashToCurve(msg, {DST: new Uint8Array(0)} as never) as unknown as InstanceType<typeof G1>;
}

/// Aggregation scalars r_i = LE(Blake2b-128(σ_1‖…‖σ_n ‖ i as BE u64)) — mithril-stm `BlsSignature::aggregate`.
export function aggregationScalars(sigmas: Uint8Array[]): bigint[] {
    if (sigmas.length < 2) return [1n];
    const base = Buffer.concat(sigmas);
    return sigmas.map((_, i) => {
        const ib = Buffer.alloc(8);
        ib.writeBigUInt64BE(BigInt(i));
        // Blake2b<U16>: an incremental hasher over all sigmas then the index (same bytes as one concat).
        const h = blake2b(Buffer.concat([base, ib]), {dkLen: 16});
        return BigInt("0x" + Buffer.from(h).reverse().toString("hex"));
    });
}

export interface StmCheck {
    nrIndices: number;
    ok: boolean;
    reason?: string;
}

export function verifyStm(cert: Certificate, avk: Avk = cert.avk, params: Params = cert.params): StmCheck {
    const msg = Buffer.from(cert.signedMessage, "ascii");
    const msgp = Buffer.concat([msg, avk.root]);
    const seen = new Set<bigint>();
    let nr = 0;
    for (const s of cert.signers) {
        for (const ix of s.indexes) {
            if (ix > params.m) return {nrIndices: nr, ok: false, reason: "index > m"};
            if (!isLotteryWon(params.phiF, denseMapping(msgp, ix, s.sigma), s.stake, avk.totalStake))
                return {nrIndices: nr, ok: false, reason: `lottery lost ${s.signerIndex}/${ix}`};
            if (seen.has(ix)) return {nrIndices: nr, ok: false, reason: "dup index"};
            seen.add(ix);
            nr++;
        }
    }
    if (BigInt(nr) < params.k) return {nrIndices: nr, ok: false, reason: "below k"};
    const leaves = cert.signers.map((s) => leafBytes(s.vk, s.stake));
    if (!verifyBatchPath(avk.root, avk.nrLeaves, leaves, cert.batchIndices, cert.batchValues))
        return {nrIndices: nr, ok: false, reason: "batch path"};
    const sigmas = cert.signers.map((s) => s.sigma);
    const r = aggregationScalars(sigmas);
    let aggSig = G1.ZERO;
    let aggVk = G2.ZERO;
    cert.signers.forEach((s, i) => {
        aggSig = aggSig.add(G1.fromHex(s.sigma).multiply(r[i]));
        aggVk = aggVk.add(G2.fromHex(s.vk).multiply(r[i]));
    });
    const h = hashToG1(msgp);
    const lhs = bls12_381.pairing(aggSig, G2.BASE);
    const rhs = bls12_381.pairing(h, aggVk);
    if (!bls12_381.fields.Fp12.eql(lhs, rhs)) return {nrIndices: nr, ok: false, reason: "pairing"};
    return {nrIndices: nr, ok: true};
}

export {P};
