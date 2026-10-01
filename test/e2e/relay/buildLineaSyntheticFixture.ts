import {mkdirSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {encodeAbiParameters, keccak256, toHex, type Hex} from "viem";
import {deriveChannelSlots} from "./buildEthMainnetProof.js";
import {
    encodeStorageProof,
    hashStorageWord,
    hex32,
    KOALABEAR_P,
    leafHash,
    padBytes32,
    poseidon2,
    TREE_DEPTH,
    type MultiProof,
    type SlotClaim
} from "./linea.js";

/// SYNTHETIC Linea storage tries for LineaStateTrieVerifier gas and shape tests, where the channel slots
/// are PRESENT (the live fixture's stand-in has none). Values are made up; the trie construction is
/// Linea's (depth 40, empty subtree Z_{h+1} = H(Z_h ‖ Z_h) with Z_0 = 0, root = H(nextFreeNode ‖ subRoot),
/// all checked against Linea mainnet by the live fixture). Hashes of subtrees that hold only other
/// (unopened) leaves are random canonical values: the verifier only folds them.
///
/// Cases (leaf indices are what drives the cost: paths of leaves inserted together share nodes):
///   fresh   5 channel slots written in one transaction (indices 40..44) + the last message (45)
///   busy    the same 5 channel slots, last message at index 1,000,000 (a long-lived service)
///   partial 3 channel slots present (40..42), receivedRunningHash and the manifest version absent
///
///   npx tsx test/e2e/relay/buildLineaSyntheticFixture.ts

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.resolve(__dirname, "../../verifiers/evm/zkrollup/fixtures/linea-synthetic.json");

const CHANNEL_ID = keccak256(toHex("clpr/zkrollup-synthetic/linea"));
const NEXT_MESSAGE_ID = 5n;
const P = KOALABEAR_P;

/// Deterministic canonical pseudo-random word (8 limbs < p).
function rnd(seed: string): bigint {
    const h = BigInt(keccak256(toHex(seed)));
    let w = 0n;
    for (let i = 0n; i < 8n; i++) w = (w << 32n) | (((h >> (32n * i)) & 0xffffffffn) % P);
    return w;
}

function messageRunningHashSlot(channelId: Hex, messageId: bigint): bigint {
    const outer = BigInt(keccak256(encodeAbiParameters([{type: "bytes32"}, {type: "uint256"}], [channelId, 1n])));
    const inner = BigInt(keccak256(encodeAbiParameters([{type: "uint256"}, {type: "uint256"}], [messageId, outer])));
    return inner + 1n;
}

const Z: bigint[] = [0n];
for (let h = 1; h <= TREE_DEPTH; h++) Z.push(poseidon2([Z[h - 1], Z[h - 1]]));

interface SynLeaf {
    index: bigint;
    prev: [bigint, bigint];
    next: [bigint, bigint];
    hKey: bigint;
    hValue: bigint;
}

/// Fold a sparse set of known leaves; any node with no known leaf below it and index < nextFree gets a
/// random "other leaves" hash, beyond nextFree an empty-subtree hash. Returns the multiproof and root.
function build(leaves: SynLeaf[], nextFree: bigint, tag: string): {mp: MultiProof; root: bigint} {
    const sorted = [...leaves].sort((a, b) => (a.index < b.index ? -1 : 1));
    let nodes = sorted.map((l) => ({idx: l.index, h: leafHash(l)}));
    const siblings: bigint[] = [];
    for (let level = 0; level < TREE_DEPTH; level++) {
        const next: typeof nodes = [];
        for (let i = 0; i < nodes.length;) {
            const n = nodes[i];
            if ((n.idx & 1n) === 0n && i + 1 < nodes.length && nodes[i + 1].idx === n.idx + 1n) {
                next.push({idx: n.idx >> 1n, h: poseidon2([n.h, nodes[i + 1].h])});
                i += 2;
                continue;
            }
            const sibIdx = n.idx ^ 1n;
            const firstLeafBelow = sibIdx << BigInt(level);
            const s = firstLeafBelow >= nextFree ? Z[level] : rnd(`${tag}/${level}/${sibIdx}`);
            siblings.push(s);
            next.push({idx: n.idx >> 1n, h: (n.idx & 1n) === 0n ? poseidon2([n.h, s]) : poseidon2([s, n.h])});
            i += 1;
        }
        nodes = next;
    }
    const nf = padBytes32(nextFree);
    const root = poseidon2([nf[0], nf[1], nodes[0].h]);
    return {
        mp: {nextFreeNode: nf, leaves: sorted.map((l) => ({...l})), siblings},
        root
    };
}

function present(slot: bigint, value: bigint, index: bigint): {leaf: SynLeaf; claim: Omit<SlotClaim, "leaf">} {
    return {
        leaf: {index, prev: padBytes32(index + 100n), next: padBytes32(index + 200n), hKey: hashStorageWord(slot),
            hValue: hashStorageWord(value)},
        claim: {slot, value, absent: false, right: 0n}
    };
}

function channelValues(): bigint[] {
    const verifier = 0x1234567890abcdef1234567890abcdef12345678n;
    const status = 1n;
    return [
        verifier | (status << 160n) | (NEXT_MESSAGE_ID << 168n), // verifier|status|nextMessageId
        3n | (4n << 64n) | (2n << 128n), // ackedMessageId|receivedMessageId|nextExpectedReplyId
        BigInt(keccak256(toHex("sent"))), // sentRunningHash
        BigInt(keccak256(toHex("received"))), // receivedRunningHash
        1n // endpointManifestVersion
    ];
}

interface Case {
    name: string;
    storageRoot: Hex;
    proof: Hex;
    leaves: number;
    siblings: number;
    slots: number;
}

function makeCase(name: string, opts: {msgIndex?: bigint; absent?: number[]; nextFree: bigint}): Case {
    const slots = deriveChannelSlots(CHANNEL_ID).map((s) => BigInt(s));
    const values = channelValues();
    const leaves: SynLeaf[] = [];
    const claims: Omit<SlotClaim, "leaf">[] = [];
    const claimLeafIndex: bigint[] = [];
    const claimRightIndex: bigint[] = [];
    let idx = 40n;
    slots.forEach((s, i) => {
        if (opts.absent?.includes(i)) {
            // Bracketing leaves far away in the trie, hKeys just below and above the slot's hKey.
            const hk = hashStorageWord(s);
            const li = 500_000n + BigInt(i) * 7n;
            const ri = 900_000n + BigInt(i) * 11n;
            leaves.push({index: li, prev: padBytes32(1n), next: padBytes32(ri), hKey: hk - 1n, hValue: rnd(`v${i}l`)});
            leaves.push({index: ri, prev: padBytes32(li), next: padBytes32(2n), hKey: hk + 1n, hValue: rnd(`v${i}r`)});
            claims.push({slot: s, value: 0n, absent: true, right: 0n});
            claimLeafIndex.push(li);
            claimRightIndex.push(ri);
        } else {
            const p = present(s, values[i], idx);
            leaves.push(p.leaf);
            claims.push(p.claim);
            claimLeafIndex.push(idx);
            claimRightIndex.push(0n);
            idx += 1n;
        }
    });
    if (opts.msgIndex !== undefined) {
        const s = messageRunningHashSlot(CHANNEL_ID, NEXT_MESSAGE_ID - 1n);
        const p = present(s, BigInt(keccak256(toHex("last message"))), opts.msgIndex);
        leaves.push(p.leaf);
        claims.push(p.claim);
        claimLeafIndex.push(opts.msgIndex);
        claimRightIndex.push(0n);
    }
    const {mp, root} = build(leaves, opts.nextFree, name);
    const pos = new Map(mp.leaves.map((l, i) => [l.index, BigInt(i)]));
    const full: SlotClaim[] = claims.map((c, i) => ({
        ...c, leaf: pos.get(claimLeafIndex[i])!, right: c.absent ? pos.get(claimRightIndex[i])! : 0n
    }));
    return {
        name, storageRoot: hex32(root), proof: encodeStorageProof(mp, full), leaves: mp.leaves.length,
        siblings: mp.siblings.length, slots: full.length
    };
}

const cases = [
    makeCase("fresh", {msgIndex: 45n, nextFree: 60n}),
    makeCase("busy", {msgIndex: 1_000_000n, nextFree: 1_000_100n}),
    makeCase("partial", {absent: [3, 4], nextFree: 1_000_000n})
];
const out = {
    channelId: CHANNEL_ID,
    nextMessageId: Number(NEXT_MESSAGE_ID),
    cases: Object.fromEntries(cases.map((c) => [c.name, c]))
};
mkdirSync(path.dirname(OUT), {recursive: true});
writeFileSync(OUT, JSON.stringify(out, null, 1) + "\n");
for (const c of cases) console.log(`${c.name}: ${c.slots} slots, ${c.leaves} leaves, ${c.siblings} siblings, ${(c.proof.length - 2) / 2} B`);
console.log(`→ ${path.relative(process.cwd(), OUT)}`);
