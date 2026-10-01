import {encodeAbiParameters, type Hex} from "viem";

/// Linea state-trie helpers (off-chain mirror of LineaStateTrieVerifier).
///
/// Linea's world state is a Sparse Merkle Tree (depth 40) of sorted, doubly linked leaves, hashed with
/// Poseidon2 over the KoalaBear field (p = 2^31 - 2^24 + 1), state width 16, x^3 S-box, 6 full and 21
/// partial rounds. A 32-byte word is 8 field elements (big-endian 32-bit limbs). Hashing is
/// Merkle-Damgard over 32-byte blocks with the Poseidon2 feed-forward compression
/// `h' = m + perm(h ‖ m)[8..16]`, starting from h = 0.
///
/// The round constants and matrix diagonals are those of the Apache-2.0 `Poseidon2.sol` in
/// Consensys/linea-monorepo (contracts/src/libraries/Poseidon2.sol, ConsenSys Software Inc.).
/// script/zkrollup/generatePoseidon2.ts turns them into src/libraries/proof/linea/LineaPoseidon2.sol.

export const KOALABEAR_P = 2130706433n;
const P = KOALABEAR_P;

export const FULL_ROUND_KEYS: bigint[][] = [
    "0x747e80c97d5ff3d179440df5000413c541d0a44f0a1c440d4d06e84c5c15b822",
    "0x4734c87b4d3a8a8e078f1df51a1cd0b879bffc5d60b1b050583a8f517a64f2cc",
    "0x310042f41c53094b1c5cba696d6ffbdf0901f29c325e35b30f56ce7d016a13d6",
    "0x735b0fea6340a19359973615451586193b15995317fa62952d9bdf646488ca54",
    "0x2c58464623f97e046792307e19a4384b16dd8606260ba9654202495b7ea189de",
    "0x2830cef50de1216556f3b44502c06c3b632610e36d42c9e970946c65540dcc05",
    "0x11218dc0167014be7c8eb2e23a6c3b9b7a033707120e62e50e3b6de86f58ab9c",
    "0x1f79642b294d9199367cc09f1b12a5d96fc835223df8b572654b046e68c005fa",
    "0x09b4f5ef60c076d7231e594c7ba2a2692c9185f83a2840fd718175b52eaf5475",
    "0x2324d022013e8d86701e300c22d1a4b0273731494f0bb2c7703e164c5cb8526d",
    "0x52a0a9505c2abe9833fd545013ce64d563a948284730b1264e15994247931fcc",
    "0x65b9070333c90dc57e45ae51298fb39a4ed1df724fbb42a63d33c0e65d61e9df"
].reduce<bigint[][]>((rounds, w, i) => {
    if (i % 2 === 0) rounds.push([]);
    rounds[rounds.length - 1].push(...limbs(BigInt(w)));
    return rounds;
}, []);
export const PARTIAL_ROUND_KEYS = [
    271263440n, 648183298n, 1662653166n, 1984135584n, 594964655n, 108023522n, 849546096n, 1961993938n,
    1546336947n, 1036613726n, 452088758n, 275827416n, 763236035n, 1068717067n, 1580958419n, 1376393748n,
    892777736n, 1345121022n, 908739241n, 908871000n, 1053550888n
];
/// Internal matrix: 1 + diag(d), d below (mod p).
export const INTERNAL_DIAG = [
    P - 2n, 1n, 2n, 1065353217n, 3n, 4n, 1065353216n, P - 3n,
    P - 4n, 2122383361n, 1864368129n, 2130706306n, 8323072n, 266338304n, 133169152n, 127n
];

function limbs(w: bigint): bigint[] {
    const out: bigint[] = [];
    for (let i = 7; i >= 0; i--) out.push((w >> BigInt(32 * i)) & 0xffffffffn);
    return out;
}

function pack(l: bigint[]): bigint {
    return l.reduce((acc, x) => (acc << 32n) | x, 0n);
}

function m4(v: bigint[]): bigint[] {
    const [a, b, c, d] = v;
    return [(2n * a + 3n * b + c + d) % P, (a + 2n * b + 3n * c + d) % P, (a + b + 2n * c + 3n * d) % P, (3n * a + b + c + 2n * d) % P];
}

function external(s: bigint[]): bigint[] {
    const groups = [0, 4, 8, 12].map((o) => m4(s.slice(o, o + 4)));
    const t = [0, 1, 2, 3].map((j) => groups.reduce((acc, g) => acc + g[j], 0n) % P);
    return groups.flatMap((g) => g.map((x, j) => (x + t[j]) % P));
}

function internal(s: bigint[]): bigint[] {
    const sum = s.reduce((a, b) => a + b, 0n) % P;
    return s.map((x, i) => (sum + INTERNAL_DIAG[i] * x) % P);
}

const sbox = (x: bigint): bigint => (x * x % P) * x % P;

export function permutation(state: bigint[]): bigint[] {
    let s = external(state.map((x) => x % P));
    for (let r = 0; r < 3; r++) s = external(s.map((x, i) => sbox((x + FULL_ROUND_KEYS[r][i]) % P)));
    for (const k of PARTIAL_ROUND_KEYS) {
        s[0] = sbox((s[0] + k) % P);
        s = internal(s);
    }
    for (let r = 3; r < 6; r++) s = external(s.map((x, i) => sbox((x + FULL_ROUND_KEYS[r][i]) % P)));
    return s;
}

/// One Merkle-Damgard step: h' = m + perm(h ‖ m)[8..16].
export function compress(h: bigint, m: bigint): bigint {
    const out = permutation([...limbs(h), ...limbs(m)]).slice(8);
    const ml = limbs(m);
    return pack(out.map((x, i) => (x + ml[i]) % P));
}

/// Poseidon2 hash of 32-byte words.
export function poseidon2(words: bigint[]): bigint {
    if (words.length === 0) throw new Error("empty input");
    return words.reduce((h, m) => compress(h, m), 0n);
}

export function poseidon2Bytes(data: Hex): bigint {
    const hex = data.slice(2);
    if (hex.length % 64 !== 0) throw new Error("input is not a multiple of 32 bytes");
    const words: bigint[] = [];
    for (let i = 0; i < hex.length; i += 64) words.push(BigInt("0x" + hex.slice(i, i + 64)));
    return poseidon2(words);
}

/// Split a 32-byte word into 16 two-byte limbs, each in its own 4-byte element (2 words).
export function padBytes32(w: bigint): [bigint, bigint] {
    const parts: bigint[] = [];
    for (let i = 15; i >= 0; i--) parts.push((w >> BigInt(16 * i)) & 0xffffn);
    return [pack(parts.slice(0, 8)), pack(parts.slice(8))];
}

export function isCanonical(w: bigint): boolean {
    return limbs(w).every((x) => x < P);
}

export const hex32 = (x: bigint): Hex => ("0x" + x.toString(16).padStart(64, "0")) as Hex;

/// Account key: the 20-byte address as 10 two-byte limbs (40 bytes), the partial last block left-padded.
export function hashAccountKey(address: Hex): bigint {
    const [w1, w2] = padBytes32(BigInt(address) << 96n);
    return poseidon2([w1, w2 >> 192n]);
}

/// Storage key / value: the 32-byte word as 16 two-byte limbs (2 blocks).
export function hashStorageWord(w: bigint): bigint {
    return poseidon2(padBytes32(w));
}

export interface LineaAccount {
    nonce: bigint;
    balance: bigint;
    storageRoot: bigint;
    snarkCodeHash: bigint;
    keccakCodeHash: bigint;
    codeSize: bigint;
}

export function decodeAccount(value: Hex): LineaAccount {
    const w = (i: number) => BigInt("0x" + value.slice(2 + 64 * i, 2 + 64 * (i + 1)));
    if (value.length !== 2 + 6 * 64) throw new Error("account value must be 192 bytes");
    return {nonce: w(0), balance: w(1), storageRoot: w(2), snarkCodeHash: w(3), keccakCodeHash: w(4), codeSize: w(5)};
}

export function hashAccountValue(a: LineaAccount): bigint {
    return poseidon2([
        ...padBytes32(a.nonce), ...padBytes32(a.balance), a.storageRoot, a.snarkCodeHash,
        ...padBytes32(a.keccakCodeHash), ...padBytes32(a.codeSize)
    ]);
}

// ── linea_getProof shapes ─────────────────────────────────────────────────
export interface LineaMerkleProof {
    value: Hex;
    proofRelatedNodes: Hex[];
}
export interface LineaInclusion {
    key: Hex;
    leafIndex: number;
    proof: LineaMerkleProof;
}
export interface LineaExclusion {
    key: Hex;
    leftLeafIndex: number;
    leftProof: LineaMerkleProof;
    rightLeafIndex: number;
    rightProof: LineaMerkleProof;
}
export type LineaStorageProof = LineaInclusion | LineaExclusion;
export interface LineaGetProofResult {
    accountProof: LineaInclusion;
    storageProofs: LineaStorageProof[];
}

export const TREE_DEPTH = 40;

/// A leaf opening in verifier form: the leaf's fields, its index, the 40 sibling hashes (leaf level
/// first) and the tree's nextFreeNode (2 words). Sibling hashes are computed here from the RPC's node
/// openings, so the verifier hashes 40 pairs instead of 80 node preimages.
export interface LeafOpening {
    leafIndex: bigint;
    prev: [bigint, bigint];
    next: [bigint, bigint];
    hKey: bigint;
    hValue: bigint;
    siblings: bigint[];
    nextFreeNode: [bigint, bigint];
}

function words(h: Hex): bigint[] {
    const out: bigint[] = [];
    for (let i = 2; i < h.length; i += 64) out.push(BigInt("0x" + h.slice(i, i + 64)));
    return out;
}

export function leafOpening(leafIndex: number, p: LineaMerkleProof): LeafOpening {
    const nodes = p.proofRelatedNodes;
    if (nodes.length !== TREE_DEPTH + 2) throw new Error(`expected ${TREE_DEPTH + 2} proof nodes, got ${nodes.length}`);
    const [nf0, nf1] = words(nodes[0]);
    const leaf = words(nodes[TREE_DEPTH + 1]);
    if (leaf.length !== 6) throw new Error("leaf must be 192 bytes");
    const siblings: bigint[] = [];
    // nodes[TREE_DEPTH] is the sibling at height 0 (a leaf; all-zero means the empty leaf, hash 0),
    // nodes[1] the sibling just below the sub-tree root.
    for (let h = 0; h < TREE_DEPTH; h++) {
        const n = nodes[TREE_DEPTH - h];
        if (h === 0 && /^0x0*$/.test(n)) siblings.push(0n);
        else siblings.push(poseidon2Bytes(n));
    }
    return {
        leafIndex: BigInt(leafIndex),
        prev: [leaf[0], leaf[1]],
        next: [leaf[2], leaf[3]],
        hKey: leaf[4],
        hValue: leaf[5],
        siblings,
        nextFreeNode: [nf0, nf1]
    };
}

export function leafHash(o: Pick<LeafOpening, "prev" | "next" | "hKey" | "hValue">): bigint {
    return poseidon2([o.prev[0], o.prev[1], o.next[0], o.next[1], o.hKey, o.hValue]);
}

export function foldOpening(o: LeafOpening): bigint {
    let h = leafHash(o);
    for (let i = 0; i < TREE_DEPTH; i++) {
        h = ((o.leafIndex >> BigInt(i)) & 1n) === 1n ? poseidon2([o.siblings[i], h]) : poseidon2([h, o.siblings[i]]);
    }
    return poseidon2([o.nextFreeNode[0], o.nextFreeNode[1], h]);
}

/// The leaf's prev/next pointers as indices (each a padded uint64 in 2 words).
export function unpadIndex(w: [bigint, bigint]): bigint {
    const l = [...limbs(w[0]), ...limbs(w[1])];
    return l.reduce((acc, x) => (acc << 16n) | (x & 0xffffn), 0n);
}


// ── Verifier encoding (ILineaStateTrieVerifier) ──────────────────────────────

export interface MultiProof {
    nextFreeNode: [bigint, bigint];
    leaves: {index: bigint; prev: [bigint, bigint]; next: [bigint, bigint]; hKey: bigint; hValue: bigint}[];
    siblings: bigint[];
}

const LEAF_T = {
    type: "tuple", components: [
        {name: "index", type: "uint256"}, {name: "prev", type: "uint256[2]"}, {name: "next", type: "uint256[2]"},
        {name: "hKey", type: "uint256"}, {name: "hValue", type: "uint256"}
    ]
} as const;
const MULTIPROOF_T = {
    type: "tuple", components: [
        {name: "nextFreeNode", type: "uint256[2]"}, {name: "leaves", type: "tuple[]", components: LEAF_T.components},
        {name: "siblings", type: "uint256[]"}
    ]
} as const;
const ACCOUNT_T = {
    type: "tuple", components: [
        {name: "nonce", type: "uint256"}, {name: "balance", type: "uint256"}, {name: "storageRoot", type: "uint256"},
        {name: "snarkCodeHash", type: "uint256"}, {name: "keccakCodeHash", type: "uint256"}, {name: "codeSize", type: "uint256"}
    ]
} as const;
const CLAIMS_T = {
    type: "tuple[]", components: [
        {name: "slot", type: "uint256"}, {name: "value", type: "uint256"}, {name: "absent", type: "bool"},
        {name: "leaf", type: "uint256"}, {name: "right", type: "uint256"}
    ]
} as const;

/// Merge leaf openings of one tree into a multiproof: leaves sorted by index (duplicates merged), and
/// the sibling stream in the verifier's fold order. Cross-checks that the fold reaches `root`.
export function buildMultiProof(openings: LeafOpening[], root: bigint): MultiProof {
    const byIndex = new Map<bigint, LeafOpening>();
    for (const o of openings) {
        const prev = byIndex.get(o.leafIndex);
        if (prev && leafHash(prev) !== leafHash(o)) throw new Error(`conflicting openings of leaf ${o.leafIndex}`);
        byIndex.set(o.leafIndex, o);
    }
    const leaves = [...byIndex.values()].sort((a, b) => (a.leafIndex < b.leafIndex ? -1 : 1));
    const nf = leaves[0].nextFreeNode;
    for (const l of leaves) {
        if (l.nextFreeNode[0] !== nf[0] || l.nextFreeNode[1] !== nf[1]) throw new Error("openings from different trees");
    }
    let nodes = leaves.map((l) => ({idx: l.leafIndex, h: leafHash(l), rep: l}));
    const siblings: bigint[] = [];
    for (let level = 0; level < TREE_DEPTH; level++) {
        const next: typeof nodes = [];
        for (let i = 0; i < nodes.length;) {
            const n = nodes[i];
            if ((n.idx & 1n) === 0n && i + 1 < nodes.length && nodes[i + 1].idx === n.idx + 1n) {
                next.push({idx: n.idx >> 1n, h: poseidon2([n.h, nodes[i + 1].h]), rep: n.rep});
                i += 2;
            } else {
                const s = n.rep.siblings[level];
                siblings.push(s);
                next.push({idx: n.idx >> 1n, h: (n.idx & 1n) === 0n ? poseidon2([n.h, s]) : poseidon2([s, n.h]), rep: n.rep});
                i += 1;
            }
        }
        nodes = next;
    }
    if (poseidon2([nf[0], nf[1], nodes[0].h]) !== root) throw new Error("multiproof does not fold to the root");
    return {
        nextFreeNode: nf,
        leaves: leaves.map((l) => ({index: l.leafIndex, prev: l.prev, next: l.next, hKey: l.hKey, hValue: l.hValue})),
        siblings
    };
}

export function encodeAccountProof(account: LineaAccount, mp: MultiProof): Hex {
    return encodeAbiParameters([ACCOUNT_T, MULTIPROOF_T], [account, mp] as never);
}

export interface SlotClaim {
    slot: bigint;
    value: bigint;
    absent: boolean;
    leaf: bigint;
    right: bigint;
}

export function encodeStorageProof(mp: MultiProof, claims: SlotClaim[]): Hex {
    return encodeAbiParameters([MULTIPROOF_T, CLAIMS_T], [mp, claims] as never);
}

/// Account proof in verifier form from a `linea_getProof` result, checked against `stateRoot`.
export function lineaAccountProof(r: LineaGetProofResult, address: Hex, stateRoot: bigint): {
    account: LineaAccount;
    encoded: Hex;
    multiProof: MultiProof;
} {
    const o = leafOpening(r.accountProof.leafIndex, r.accountProof.proof);
    if (o.hKey !== hashAccountKey(address)) throw new Error("account hKey mismatch");
    const account = decodeAccount(r.accountProof.proof.value);
    if (o.hValue !== hashAccountValue(account)) throw new Error("account hValue mismatch");
    const multiProof = buildMultiProof([o], stateRoot);
    return {account, encoded: encodeAccountProof(account, multiProof), multiProof};
}

/// Storage proof in verifier form for `keys` (all in one multiproof), checked against `storageRoot`.
export function lineaStorageProof(r: LineaGetProofResult, keys: Hex[], storageRoot: bigint): {
    encoded: Hex;
    claims: SlotClaim[];
    multiProof: MultiProof;
} {
    const byKey = new Map(r.storageProofs.map((s) => [BigInt(s.key), s]));
    const openings: LeafOpening[] = [];
    const pending: {slot: bigint; value: bigint; absent: boolean; a: bigint; b: bigint}[] = [];
    for (const k of keys) {
        const s = byKey.get(BigInt(k));
        if (!s) throw new Error(`no linea_getProof entry for ${k}`);
        const hk = hashStorageWord(BigInt(k));
        if ("proof" in s) {
            const o = leafOpening(s.leafIndex, s.proof);
            const value = BigInt(s.proof.value);
            if (o.hKey !== hk || o.hValue !== hashStorageWord(value)) throw new Error(`inclusion leaf mismatch for ${k}`);
            openings.push(o);
            pending.push({slot: BigInt(k), value, absent: false, a: o.leafIndex, b: 0n});
        } else {
            const l = leafOpening(s.leftLeafIndex, s.leftProof);
            const rr = leafOpening(s.rightLeafIndex, s.rightProof);
            if (!(l.hKey < hk && hk < rr.hKey)) throw new Error(`exclusion leaves do not bracket ${k}`);
            openings.push(l, rr);
            pending.push({slot: BigInt(k), value: 0n, absent: true, a: l.leafIndex, b: rr.leafIndex});
        }
    }
    const multiProof = buildMultiProof(openings, storageRoot);
    const pos = new Map(multiProof.leaves.map((l, i) => [l.index, BigInt(i)]));
    const claims = pending.map((p) => ({
        slot: p.slot, value: p.value, absent: p.absent, leaf: pos.get(p.a)!, right: p.absent ? pos.get(p.b)! : 0n
    }));
    return {encoded: encodeStorageProof(multiProof, claims), claims, multiProof};
}
