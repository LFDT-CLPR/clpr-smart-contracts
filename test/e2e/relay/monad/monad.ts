import {bls12_381 as bls} from "@noble/curves/bls12-381";
import {secp256k1} from "@noble/curves/secp256k1";
import {keccak_256} from "@noble/hashes/sha3";
import {RLP, type Input} from "@ethereumjs/rlp";
import {blake3, pageCommit, type Page} from "./blake3.js";
import {Trie} from "./mpt.js";

/// Builders for MonadVerifier proofs. Every encoding mirrors the Monad sources cited in
/// src/verifiers/evm/monad/README.md (monad-bft for consensus, monad for execution / MIP-8).

export const DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
export const VOTE_PREFIX = new TextEncoder().encode("\x0dmonad/vote/1\n");
export const EXECUTION_DELAY = 3n;
export const STAKING = hex("0x0000000000000000000000000000000000001000");
const R = bls.fields.Fr.ORDER;

// ── bytes helpers ────────────────────────────────────────────────────────────

export function hex(h: string): Uint8Array {
    const s = h.startsWith("0x") ? h.slice(2) : h;
    return Uint8Array.from(Buffer.from(s.length % 2 ? "0" + s : s, "hex"));
}
export const toHex = (b: Uint8Array): `0x${string}` => `0x${Buffer.from(b).toString("hex")}`;
export const cat = (...xs: Uint8Array[]) => Uint8Array.from(Buffer.concat(xs));
export function be(v: bigint, len: number): Uint8Array {
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) out[len - 1 - i] = Number((v >> BigInt(8 * i)) & 0xffn);
    return out;
}
export const word = (v: bigint) => be(v, 32);
export const keccak = (b: Uint8Array) => keccak_256(b);
export const rlp = (x: Input) => RLP.encode(x);
/// Minimal big-endian integer for RLP.
export const int = (v: bigint | number) => (BigInt(v) === 0n ? new Uint8Array(0) : hex(BigInt(v).toString(16)));
export const big = (b: Uint8Array) => (b.length === 0 ? 0n : BigInt(toHex(b)));

// ── BLS ──────────────────────────────────────────────────────────────────────

export function g1Eip2537(p: InstanceType<typeof bls.G1.ProjectivePoint>): Uint8Array {
    const a = p.toAffine();
    return cat(be(a.x, 64), be(a.y, 64));
}
export function g2Eip2537(p: InstanceType<typeof bls.G2.ProjectivePoint>): Uint8Array {
    const a = p.toAffine();
    return cat(be(a.x.c0, 64), be(a.x.c1, 64), be(a.y.c0, 64), be(a.y.c1, 64));
}
export const g1FromCompressed = (c: Uint8Array) => bls.G1.ProjectivePoint.fromHex(c);
export const g2FromCompressed = (c: Uint8Array) => bls.G2.ProjectivePoint.fromHex(c);

export function hashVote(voteRlp: Uint8Array) {
    return bls.G2.hashToCurve(cat(VOTE_PREFIX, voteRlp), {DST}) as unknown as InstanceType<typeof bls.G2.ProjectivePoint>;
}

// ── Validators ───────────────────────────────────────────────────────────────

export type Validator = {secp: Uint8Array; blsPk: Uint8Array /* compressed 48 */; stake: bigint; sk?: bigint; id?: bigint};

/// Deterministic synthetic validator `i`.
export function makeValidator(i: number, stake: bigint, salt = 0): Validator {
    const seed = keccak(cat(new TextEncoder().encode("monad-test-validator"), be(BigInt(i), 8), be(BigInt(salt), 8)));
    const sk = (BigInt(toHex(seed)) % (R - 1n)) + 1n;
    const secpSk = keccak(cat(seed, new Uint8Array([1])));
    return {
        secp: secp256k1.getPublicKey(secpSk, true),
        blsPk: bls.G1.ProjectivePoint.BASE.multiply(sk).toRawBytes(true),
        stake,
        sk
    };
}

/// Consensus order: BTreeMap<NodeId<secp PubKey>> = ascending compressed secp key (secp256k1_ec_pubkey_cmp).
export function sortValidators(vs: Validator[]): Validator[] {
    return [...vs].sort((a, b) => Buffer.compare(Buffer.from(a.secp), Buffer.from(b.secp)));
}

/// Bundle validator-set blob: n × (EIP-2537 G1 key 128 || stake 32), in consensus order.
export function valsetBlob(sorted: Validator[]): Uint8Array {
    return cat(...sorted.map((v) => cat(g1Eip2537(g1FromCompressed(v.blsPk)), word(v.stake))));
}

/// SignerMap RLP payload [num_bits, bytes]: validator 0 is the most significant bit.
export function signerMap(n: number, signers: Set<number>): Input {
    const nb = Math.ceil(n / 8);
    const buf = new Uint8Array(nb);
    for (const i of signers) {
        const p = n - 1 - i;
        buf[nb - 1 - Math.floor(p / 8)] |= 1 << (p % 8);
    }
    return [int(n), buf];
}

// ── Consensus headers / QCs ──────────────────────────────────────────────────

export type Vote = {id: Uint8Array; round: bigint; epoch: bigint};
export const voteRlp = (v: Vote) => rlp([v.id, int(v.round), int(v.epoch)]);

export type SignedQc = {
    vote: Vote;
    qcRlp: Uint8Array; // QuorumCertificate RLP [vote, [[nbits, bitmap], sig96]]
    qcItem: Input; // same, as a nested structure
    sigUncompressed: Uint8Array; // 256-byte EIP-2537 G2
};

/// Sign `vote` by the validators at `signers` (indices into the sorted set).
export function signQc(vote: Vote, sorted: Validator[], signers: Set<number>): SignedQc {
    let skSum = 0n;
    for (const i of signers) skSum = (skSum + sorted[i].sk!) % R;
    const sigPt = hashVote(voteRlp(vote)).multiply(skSum);
    const qcItem: Input = [[vote.id, int(vote.round), int(vote.epoch)], [signerMap(sorted.length, signers), sigPt.toRawBytes(true)]];
    return {vote, qcRlp: rlp(qcItem), qcItem, sigUncompressed: g2Eip2537(sigPt)};
}

export type HeaderFields = {
    round: bigint;
    epoch: bigint;
    qc: Input; // QC on the parent
    seq: bigint;
    delayed: Uint8Array[]; // raw eth header RLPs
    timestampNs?: bigint;
};

/// RLP `ConsensusBlockHeader` (monad-consensus-types block.rs field order).
export function consensusHeader(h: HeaderFields): Uint8Array {
    const author = cat(new Uint8Array([2]), keccak(be(h.round, 8)));
    const proposed: Input = [
        keccak(new TextEncoder().encode("ommers")), new Uint8Array(20), keccak(be(h.seq, 8)), int(0), int(h.seq),
        int(200_000_000), int(1_760_000_000n + h.seq), new Uint8Array(32), keccak(be(h.round, 8)), new Uint8Array(8),
        int(100_000_000_000n), keccak(new TextEncoder().encode("withdrawals")), int(0), int(0), new Uint8Array(32), new Uint8Array(32)
    ];
    return rlp([
        int(h.round), int(h.epoch), h.qc, author, int(h.seq), int(h.timestampNs ?? 1_760_000_000_000_000_000n + h.seq),
        bls.G2.ProjectivePoint.BASE.multiply(h.round + 7n).toRawBytes(true),
        h.delayed.map((d) => RLP.decode(d) as Input), proposed, keccak(be(h.seq, 32)),
        int(100_000_000_000n), int(0), int(0)
    ]);
}

export const blockId = (headerRlp: Uint8Array) => blake3(headerRlp);

/// A Monad-shaped Ethereum header (21 fields, as served by eth_getBlockByNumber) with `stateRoot`/`number`.
export function ethHeader(stateRoot: Uint8Array, number: bigint, template?: Uint8Array): Uint8Array {
    if (template) {
        const f = RLP.decode(template) as Uint8Array[];
        f[3] = stateRoot;
        f[8] = int(number);
        return rlp(f);
    }
    return rlp([
        keccak(be(number - 1n, 8)), keccak(new Uint8Array(0)), new Uint8Array(20), stateRoot, keccak(be(number, 8)),
        keccak(be(number + 1n, 8)), new Uint8Array(256), int(0), int(number), int(200_000_000), int(21_000),
        int(1_760_000_000n + number), new Uint8Array(32), keccak(be(number + 2n, 8)), new Uint8Array(8),
        int(100_000_000_000n), keccak(new Uint8Array([1])), int(0), int(0), new Uint8Array(32), new Uint8Array(32)
    ]);
}

export type FinalityChain = {
    headerP: Uint8Array;
    headerB: Uint8Array;
    qcOnB: SignedQc;
    finalityItem: Input; // [headerP, headerB, qcOnB, sig]
    ethHeader: Uint8Array;
};

/// Build P (carrying the delayed eth header), B (QC on P) and a QC on B in the next round.
export function finalityChain(args: {
    sorted: Validator[];
    signers: Set<number>;
    epoch: bigint;
    seqP: bigint;
    roundP: bigint;
    ethHeaderRlp: Uint8Array;
    roundGap?: bigint; // round(QC on B) - round(QC on P); 1 commits P
}): FinalityChain {
    const parentQc = signQc({id: keccak(be(args.seqP, 8)), round: args.roundP - 1n, epoch: args.epoch}, args.sorted, args.signers);
    const headerP = consensusHeader({round: args.roundP, epoch: args.epoch, qc: parentQc.qcItem, seq: args.seqP, delayed: [args.ethHeaderRlp]});
    const qcOnP = signQc({id: blockId(headerP), round: args.roundP, epoch: args.epoch}, args.sorted, args.signers);
    const roundB = args.roundP + (args.roundGap ?? 1n);
    const headerB = consensusHeader({round: roundB, epoch: args.epoch, qc: qcOnP.qcItem, seq: args.seqP + 1n, delayed: [ethHeader(keccak(be(args.seqP, 32)), args.seqP - 2n)]});
    const qcOnB = signQc({id: blockId(headerB), round: roundB, epoch: args.epoch}, args.sorted, args.signers);
    return {
        headerP, headerB, qcOnB, ethHeader: args.ethHeaderRlp,
        finalityItem: [headerP, headerB, qcOnB.qcItem, qcOnB.sigUncompressed]
    };
}

// ── State: accounts + MIP-8 page storage ─────────────────────────────────────

export type Storage = Map<bigint, bigint>; // slot → value (non-zero)

export class PagedStorage {
    readonly pages = new Map<bigint, Page>();
    readonly trie: Trie;
    constructor(readonly slots: Storage) {
        for (const [s, v] of slots) {
            if (v === 0n) continue;
            const k = s >> 7n;
            if (!this.pages.has(k)) this.pages.set(k, new Map());
            this.pages.get(k)!.set(Number(s & 127n), word(v));
        }
        this.trie = new Trie([...this.pages].map(([k, p]) => [keccak(word(k)), cat(new Uint8Array([0xa0]), pageCommit(p))]));
    }
    get root() {
        return this.trie.root;
    }
    /// Pooled page proofs covering `slots`: [nodePool, [[pageKey, nodeIndices, bitmap, values], ...]].
    pagesFor(slots: bigint[]): Input {
        const keys = [...new Set(slots.map((s) => s >> 7n))];
        const pool: Uint8Array[] = [];
        const index = new Map<string, number>();
        const entries = keys.map((k) => {
            const p = this.pages.get(k) ?? new Map<number, Uint8Array>();
            let bm = 0n;
            const offs = [...p.keys()].sort((a, b) => a - b);
            for (const o of offs) bm |= 1n << BigInt(o);
            const idx = this.trie.proof(keccak(word(k))).map((n) => {
                const h = Buffer.from(n).toString("hex");
                if (!index.has(h)) { index.set(h, pool.length); pool.push(n); }
                return int(index.get(h)!);
            });
            return [word(k), idx, int(bm), offs.map((o) => p.get(o)!)];
        });
        return [pool, entries];
    }
}

export type Account = {nonce: bigint; balance: bigint; storage: PagedStorage; codeHash: Uint8Array};
export const accountRlp = (a: Account) => rlp([int(a.nonce), int(a.balance), a.storage.root, a.codeHash]);

const EMPTY_ROOT = hex("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");

export class StateTrie {
    readonly trie: Trie;
    constructor(readonly accounts: Map<string, Account>, filler = 64) {
        const kv: Array<[Uint8Array, Uint8Array]> = [...accounts].map(([addr, a]) => [keccak(hex(addr)), accountRlp(a)]);
        for (let i = 0; i < filler; i++) {
            const addr = keccak(be(BigInt(i), 32)).slice(0, 20);
            kv.push([keccak(addr), rlp([int(i), int(BigInt(i) * 10n ** 18n), EMPTY_ROOT, keccak(new Uint8Array(0))])]);
        }
        this.trie = new Trie(kv);
    }
    get root() {
        return this.trie.root;
    }
    accountProof(addr: string): Uint8Array[] {
        return this.trie.proof(keccak(hex(addr)));
    }
}

// ── CLPR channel storage (storage-layout.json: _channels slot 15, _endpointManifest.commitment 18) ──

export function channelBase(channelId: Uint8Array): bigint {
    return BigInt(toHex(keccak(cat(channelId, word(15n)))));
}
export function channelSlots(channelId: Uint8Array): bigint[] {
    const b = channelBase(channelId);
    return [b + 1n, b + 2n, b + 4n, b + 5n, b + 16n];
}
export type ChannelState = {status: number; nextMessageId: bigint; ackedMessageId: bigint; receivedMessageId: bigint;
    sentRunningHash: bigint; receivedRunningHash: bigint; endpointManifestVersion: bigint; verifier: bigint};
export function channelStorage(channelId: Uint8Array, c: ChannelState): Storage {
    const [s1, s2, s4, s5, s16] = channelSlots(channelId);
    const st: Storage = new Map();
    st.set(s1, c.verifier | (BigInt(c.status) << 160n) | (c.nextMessageId << 168n));
    st.set(s2, c.ackedMessageId | (c.receivedMessageId << 64n));
    st.set(s4, c.sentRunningHash);
    st.set(s5, c.receivedRunningHash);
    st.set(s16, c.endpointManifestVersion);
    // the rest of the Channel struct, so pages look like a live service
    const b = channelBase(channelId);
    st.set(b, 0x1234n);
    st.set(b + 3n, 7n);
    return st;
}

// ── Staking precompile storage (staking_contract.hpp layout) ─────────────────

export const SLOT_VALSET_CONSENSUS = 0x02n << 248n;
export const stakeSlot = (id: bigint) => (0x04n << 248n) | (id << 184n);
export const valExecBase = (id: bigint) => (0x09n << 248n) | (id << 184n);

/// Staking storage in epoch `epoch`'s delay period with `next` (array order) as valset_consensus.
export function stakingStorage(epoch: bigint, next: Validator[], inDelay = true): Storage {
    const st: Storage = new Map();
    st.set(1n, epoch << 192n);
    if (inDelay) st.set(2n, 1n << 248n);
    st.set(3n, BigInt(next.length + 50) << 192n);
    st.set(SLOT_VALSET_CONSENSUS, BigInt(next.length) << 192n);
    next.forEach((v, i) => {
        const id = v.id!;
        st.set(SLOT_VALSET_CONSENSUS + 1n + BigInt(i), id << 192n);
        st.set(stakeSlot(id), v.stake);
        st.set(stakeSlot(id) + 1n, 5n * 10n ** 16n); // commission
        const base = valExecBase(id);
        const keys = cat(v.secp, v.blsPk, new Uint8Array(15)); // 33 + 48 + 15 = 96
        st.set(base, v.stake + 12345n);
        st.set(base + 1n, 999n);
        st.set(base + 2n, 5n * 10n ** 16n);
        st.set(base + 3n, big(keys.slice(0, 32)));
        st.set(base + 4n, big(keys.slice(32, 64)));
        st.set(base + 5n, big(keys.slice(64, 96)));
        st.set(base + 6n, BigInt(toHex(keccak(be(id, 8)).slice(0, 20))) << 96n);
        st.set(base + 7n, 777n);
    });
    // unrelated staking state: the execution set, delegators
    for (let j = 0; j < 40; j++) st.set((0x0bn << 248n) | (BigInt(j + 1) << 184n) | 5n, BigInt(j + 1) * 10n ** 18n);
    return st;
}

/// Key registry (array order of the set it was built for): n × (id8 || secp33 || bls48).
export const registryBlob = (set: Validator[]) => cat(...set.map((v) => cat(be(v.id!, 8), v.secp, v.blsPk)));

/// Rotation chunk item [ids, registry, hints, stakingPages, count] for array indices [start, start+count).
/// Validators found in `prev` (the current set's registry, array order) reuse their keys; others are proven.
export function chunkItem(next: Validator[], prev: Validator[] | null, staking: PagedStorage, start: number, count: number): Input {
    const slots: bigint[] = [];
    const hints: Uint8Array[] = [];
    for (let i = start; i < start + count; i++) {
        const id = next[i].id!;
        slots.push(stakeSlot(id));
        const j = prev ? prev.findIndex((v) => v.id === id) : -1;
        if (j < 0) slots.push(valExecBase(id) + 3n);
        hints.push(be(j < 0 ? 0xffffn : BigInt(j), 2));
    }
    return [idsBlob(next), prev ? registryBlob(prev) : new Uint8Array(0), cat(...hints), staking.pagesFor(slots), int(count)];
}

/// Slots a cold chunk must cover (keys proven for every validator).
export function chunkSlots(next: Validator[], start: number, count: number): bigint[] {
    const out: bigint[] = [];
    for (let i = start; i < start + count; i++) {
        const id = next[i].id!;
        out.push(stakeSlot(id), valExecBase(id) + 3n);
    }
    return out;
}

/// Slots the rotation start must cover: epoch, delay flag, and the whole valset_consensus array.
export function startSlots(n: number): bigint[] {
    return [1n, 2n, ...Array.from({length: n + 1}, (_, i) => SLOT_VALSET_CONSENSUS + BigInt(i))];
}

/// Packed u64 ids of valset_consensus (chunk calldata, bound by Anchor.pendingIds).
export const idsBlob = (next: Validator[]) => cat(...next.map((v) => be(v.id!, 8)));

/// Rotation finalize item: [sortedBlob (secp33 || G1 128 || stake32), permutation (u16 array index each)].
export function finalizeItem(next: Validator[]): Input {
    const sorted = sortValidators(next);
    const blob = cat(...sorted.map((v) => cat(v.secp, g1Eip2537(g1FromCompressed(v.blsPk)), word(v.stake))));
    const perm = cat(...sorted.map((v) => be(BigInt(next.indexOf(v)), 2)));
    return [blob, perm, idsBlob(next)];
}

// ── Anchor / proofs ──────────────────────────────────────────────────────────

export type Anchor = {epoch: bigint; valsetHash: Uint8Array; codeHash: Uint8Array; pendingEpoch?: bigint; pendingBlock?: bigint;
    stakingRoot?: Uint8Array; serviceRoot?: Uint8Array; pendingLength?: bigint; pendingProven?: bigint; pendingAcc?: Uint8Array; pendingIds?: Uint8Array; keysHash?: Uint8Array};

export function encodeAnchor(a: Anchor): Uint8Array {
    const z = new Uint8Array(32);
    return cat(word(a.epoch), a.valsetHash, a.codeHash, word(a.pendingEpoch ?? 0n), word(a.pendingBlock ?? 0n),
        a.stakingRoot ?? z, a.serviceRoot ?? z, word(a.pendingLength ?? 0n), word(a.pendingProven ?? 0n), a.pendingAcc ?? z, a.pendingIds ?? z, a.keysHash ?? z);
}

/// Running accumulator over (secp33, bls48, stake32) in array order (as the verifier computes it).
export function rotationAcc(next: Validator[], upto = next.length): Uint8Array {
    let acc: Uint8Array = new Uint8Array(32);
    for (let i = 0; i < upto; i++) acc = keccak(cat(acc, next[i].secp, next[i].blsPk, word(next[i].stake)));
    return acc;
}

/// ClprBundleContent protobuf with field-2 message payloads.
export function bundleContent(messages: Uint8Array[]): Uint8Array {
    const parts: Uint8Array[] = [];
    for (const m of messages) {
        const len: number[] = [];
        let l = m.length;
        do { let b = l & 0x7f; l >>= 7; if (l) b |= 0x80; len.push(b); } while (l);
        parts.push(new Uint8Array([0x12, ...len]), m);
    }
    return cat(...parts);
}

export function channelContext(channelId: Uint8Array, service: Uint8Array): Uint8Array {
    return cat(channelId, service); // ClprTypes.encodeChannelContext = abi.encodePacked(channelId, address)
}
