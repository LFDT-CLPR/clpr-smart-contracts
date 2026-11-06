import {bls12_381} from "@noble/curves/bls12-381";
import {createHash} from "node:crypto";

/// Real BLS12-381 sync-committee vectors for the Ethereum mainnet verifier e2e tests.
///
/// The on-chain verifier (`ClprBeaconBls.aggregateVerifyComplement`) checks, with EIP-2537 precompiles:
///   e(aggregate(participant_pubkeys), H(signingRoot)) * e(-G1, aggregate_signature) == 1
/// (recovering the participant aggregate as committeeAggregate − Σ(non-participants)).
/// where H is hash-to-G2 under the ETH2 POP ciphersuite DST. This module produces matching vectors
/// with @noble/curves: deterministic committee keys, an aggregate signature over the signing root,
/// and EIP-2537 *uncompressed* encodings (the relayer's wire format — see the eth-mainnet-bls notes).
///
/// NOTE: noble's default `sign` uses the `..._NUL_` DST; ETH2 (and the contract) use `..._POP_`.
/// So we never call `sign()` — we hash-to-G2 with the POP DST and sign manually as `H(m) · sk`.

const G1 = bls12_381.G1.ProjectivePoint;
const G2 = bls12_381.G2.ProjectivePoint;

/// ETH2 sync-committee signature ciphersuite — must equal `ClprBeaconBls.BLS_DST`.
export const BLS_POP_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

type G1Point = InstanceType<typeof G1>;
type G2Point = InstanceType<typeof G2>;

export interface BlsCommittee {
    /// EIP-2537 uncompressed G1 pubkeys, 128 bytes each (committee order).
    pubkeys: Buffer[];
    /// EIP-2537 uncompressed aggregate of all members, 128 bytes.
    aggregate: Buffer;
    /// ZCash/beacon compressed G1 pubkeys, 48 bytes each (committee order). The encoding the beacon
    /// `SyncCommittee` SSZ root + `next_sync_committee` proof commit to.
    compressedPubkeys: Buffer[];
    /// Compressed aggregate pubkey, 48 bytes.
    compressedAggregate: Buffer;
    /// Per-member secret scalars (for signing). Not serialized anywhere on-chain.
    scalars: bigint[];
}

/// Right-align a 48-byte big-endian Fp coordinate into a 64-byte EIP-2537 slot (16 zero bytes first).
function fpTo64(x: bigint): Buffer {
    const out = Buffer.alloc(64);
    Buffer.from(x.toString(16).padStart(96, "0"), "hex").copy(out, 16);
    return out;
}

/// EIP-2537 uncompressed G1: pad64(x) || pad64(y) (128 bytes).
export function g1ToUncompressed(pt: G1Point): Buffer {
    const a = pt.toAffine();
    return Buffer.concat([fpTo64(a.x), fpTo64(a.y)]);
}

/// EIP-2537 uncompressed G2: pad64(x.c0) || pad64(x.c1) || pad64(y.c0) || pad64(y.c1) (256 bytes).
export function g2ToUncompressed(pt: G2Point): Buffer {
    const a = pt.toAffine();
    return Buffer.concat([fpTo64(a.x.c0), fpTo64(a.x.c1), fpTo64(a.y.c0), fpTo64(a.y.c1)]);
}

/// ZCash/beacon compressed G1, 48 bytes (the encoding the SyncCommittee SSZ root commits to).
export function g1ToCompressed(pt: G1Point): Buffer {
    return Buffer.from(pt.toRawBytes(true));
}

/// Hash a 32-byte signing root to a G2 point under the ETH2 POP ciphersuite (matches `ClprBls12381.hashToG2`).
export function hashToG2(signingRoot: Buffer): G2Point {
    const raw = bls12_381.G2.hashToCurve(Uint8Array.from(signingRoot), {DST: BLS_POP_DST});
    return G2.fromAffine(raw.toAffine());
}

/// Deterministic committee: member `i`'s scalar is `sha256(seed || i) mod r`. Reproducible across runs
/// so failures are debuggable; the secret material is throwaway test-only.
export function deriveCommittee(size = 512, seed = "clpr-eth-bls"): BlsCommittee {
    const pubkeys: Buffer[] = [];
    const compressedPubkeys: Buffer[] = [];
    const scalars: bigint[] = [];
    let agg = G1.ZERO;
    for (let i = 0; i < size; i++) {
        const sk = createHash("sha256").update(`${seed}:${i}`).digest();
        const s = bls12_381.G1.normPrivateKeyToScalar(sk);
        const pk = G1.BASE.multiply(s);
        scalars.push(s);
        pubkeys.push(g1ToUncompressed(pk));
        compressedPubkeys.push(g1ToCompressed(pk));
        agg = agg.add(pk);
    }
    return {
        pubkeys,
        aggregate: g1ToUncompressed(agg),
        compressedPubkeys,
        compressedAggregate: g1ToCompressed(agg),
        scalars
    };
}

/// Aggregate-sign `signingRoot` with the committee members selected by `participants` (a boolean per
/// member). Returns the 64-byte participation bitvector (LSB-first within each byte, matching
/// `_selectParticipants`) and the 256-byte uncompressed aggregate G2 signature.
export function aggregateSign(
    committee: BlsCommittee,
    participants: boolean[],
    signingRoot: Buffer
): {bits: Buffer; signature: Buffer; count: number} {
    const size = committee.scalars.length;
    if (participants.length !== size) {
        throw new Error(`participants length ${participants.length} != committee size ${size}`);
    }
    const H = hashToG2(signingRoot);
    const bits = Buffer.alloc(size / 8);
    let aggSig = G2.ZERO;
    let count = 0;
    for (let i = 0; i < size; i++) {
        if (!participants[i]) continue;
        aggSig = aggSig.add(H.multiply(committee.scalars[i]));
        bits[i >> 3] |= 1 << (i & 7);
        count++;
    }
    if (count === 0) throw new Error("aggregateSign: no participants selected");
    return {bits, signature: g2ToUncompressed(aggSig), count};
}

/// Convenience: the first `n` members participate (the rest sit out).
export function firstNParticipants(size: number, n: number): boolean[] {
    return Array.from({length: size}, (_, i) => i < n);
}
