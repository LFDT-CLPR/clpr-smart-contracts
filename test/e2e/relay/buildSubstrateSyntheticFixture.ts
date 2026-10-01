import {mkdirSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {ed25519} from "@noble/curves/ed25519";
import {secp256k1} from "@noble/curves/secp256k1";
import {keccak256, toBytes, type Hex} from "viem";
import {
    accountStorageKey,
    blake2_256,
    buildTrie,
    channelSlots,
    compact,
    grandpaMessage,
    keccak,
    keysetRoot,
    palletQueueKey,
    palletQueueRecord,
    palletServiceKey,
    palletServiceRecord,
    paraHeadKey,
    toHex,
    twox128,
    u32le,
    u64le
} from "./substrate.js";

/// Deterministic synthetic chains for the forge tests of the Substrate verifiers
/// (test/verifiers/evm/grandpa). Writes test/verifiers/evm/grandpa/fixtures/synthetic.json:
///   - an EVM state trie holding a ClprService's channel, manifest and config slots (plus inline
///     nodes, a branch with a value and a hashed value node, so every node kind is exercised);
///   - a GRANDPA chain: 4-authority sets, real ed25519 justifications, a ScheduledChange with delay
///     0 and one with delay 2, a precommit on a descendant (votes_ancestries) and a ForcedChange;
///   - a BEEFY relay chain: 4-authority secp256k1 sets, MMRs with multiple mountains, a relay
///     header whose state holds Paras::Heads(2034), and the parachain header above the EVM trie.
/// Run: npx tsx test/e2e/relay/buildSubstrateSyntheticFixture.ts

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.resolve(__dirname, "..", "..", "verifiers", "evm", "grandpa", "fixtures", "synthetic.json");

export const SERVICE: Hex = "0x00000000000000000000000000000000c1a5e001";
export const CHANNEL_ID: Hex = keccak256(toBytes("clpr/grandpa-synthetic/channel"));
export const PARA_ID = 2034;
const word = (x: bigint) => Buffer.from(x.toString(16).padStart(64, "0"), "hex");
const h32 = (s: string) => keccak(Buffer.from(s));

// ── EVM state (ClprService storage) ──────────────────────────────────────────

const VERIFIER = 0xbeefn;
const NEXT_MESSAGE_ID = 3n, RECEIVED_MESSAGE_ID = 2n, STATUS_ACTIVE = 1n;
const CONFIG_NANOS = 1_750_000_000_123_456_789n;
const manifestPreimage = Buffer.concat([Buffer.from([0x08, 0x01, 0x12, 0x14]), Buffer.from(SERVICE.slice(2), "hex")]);

function evmState() {
    const [s1, s2, s4, s5, s16, sLast] = channelSlots(CHANNEL_ID, NEXT_MESSAGE_ID - 1n);
    const slots: [Hex, Buffer][] = [
        [s1, word((NEXT_MESSAGE_ID << 168n) | (STATUS_ACTIVE << 160n) | VERIFIER)],
        [s2, word(RECEIVED_MESSAGE_ID << 64n)],
        [s4, h32("sentRunningHash")],
        [s5, h32("receivedRunningHash")],
        [s16, word(1n)],
        [sLast, h32("message 2 running hash")],
        [toHex(word(18n)), keccak(manifestPreimage)],
        [toHex(word(25n)), Buffer.concat([Buffer.from(SERVICE.slice(2), "hex"), Buffer.alloc(11), Buffer.from([0x28])])],
        [toHex(word(26n)), word(CONFIG_NANOS)]
    ];
    const entries: [Buffer, Buffer][] = slots.map(([s, v]) => [accountStorageKey(SERVICE, s), v]);
    // Neighbours: another contract's slots, plus short keys that produce inline nodes, a branch
    // carrying a value, and a ≥33-byte value stored as a hashed value node.
    for (let i = 0n; i < 6n; i++) entries.push([accountStorageKey("0x00000000000000000000000000000000000000aa", toHex(word(i))), word(i + 1n)]);
    entries.push([Buffer.from([0x01]), Buffer.from([0x07])], [Buffer.from([0x01, 0x02]), Buffer.from([0x08])], [Buffer.from([0x01, 0x03]), Buffer.from([0x09])]);
    entries.push([Buffer.from("long-value-key"), Buffer.alloc(40, 0x5a)]);
    return {trie: buildTrie(entries), slots};
}

// ── Headers ──────────────────────────────────────────────────────────────────

function header(parent: Buffer, number: number, stateRoot: Buffer, extra: Buffer[] = []): Buffer {
    const digest = [
        Buffer.concat([Buffer.from([6]), Buffer.from("aura"), compact(8), u64le(BigInt(number) * 2n)]),
        ...extra,
        Buffer.concat([Buffer.from([5]), Buffer.from("aura"), compact(64), Buffer.alloc(64, number & 0xff)])
    ];
    return Buffer.concat([parent, compact(number), stateRoot, h32(`extrinsics ${number}`), compact(digest.length), ...digest]);
}
const consensus = (engine: string, data: Buffer) => Buffer.concat([Buffer.from([4]), Buffer.from(engine), compact(data.length), data]);
const scheduledChange = (authorities: Buffer, delay: number) =>
    consensus("FRNK", Buffer.concat([Buffer.from([1]), compact(authorities.length / 40), authorities, u32le(delay)]));
const forcedChange = (authorities: Buffer) =>
    consensus("FRNK", Buffer.concat([Buffer.from([2]), u32le(0), compact(authorities.length / 40), authorities, u32le(0)]));

// ── GRANDPA ──────────────────────────────────────────────────────────────────

const edKey = (i: number) => Buffer.alloc(32, i + 1);
const edSet = (ids: number[]) => Buffer.concat(ids.map((i) => Buffer.concat([Buffer.from(ed25519.getPublicKey(edKey(i))), u64le(1n)])));

function votes(entries: {idx: number; key: number; target: Buffer; number: number}[], round: bigint, setId: bigint): Buffer {
    return Buffer.concat(entries.map(({idx, key, target, number}) => {
        const v = Buffer.alloc(102);
        v.writeUInt16BE(idx, 0); target.copy(v, 2); v.writeUInt32BE(number, 34);
        Buffer.from(ed25519.sign(grandpaMessage(target, number, round, setId), edKey(key))).copy(v, 38);
        return v;
    }));
}

function grandpa(stateRoot: Buffer) {
    const set0 = [0, 1, 2, 3], set1 = [4, 5, 6, 7], set2 = [8, 9, 10, 11];
    const auth0 = edSet(set0), auth1 = edSet(set1), auth2 = edSet(set2);
    const round = 7n;
    const sign = (h: Buffer, n: number, set: number[], setId: bigint, idxs = [0, 1, 2]) =>
        votes(idxs.map((i) => ({idx: i, key: set[i], target: blake2_256(h), number: n})), round, setId);

    // Set 0: plain block, then a precommit on a descendant (needs votes_ancestries).
    const b100 = header(h32("parent 99"), 100, stateRoot);
    const b101 = header(blake2_256(b100), 101, stateRoot);
    const ancestryVotes = votes([
        {idx: 0, key: set0[0], target: blake2_256(b100), number: 100},
        {idx: 1, key: set0[1], target: blake2_256(b100), number: 100},
        {idx: 3, key: set0[3], target: blake2_256(b101), number: 101}
    ], round, 0n);
    // Set 0 → 1 with delay 0 at #120.
    const b120 = header(h32("parent 119"), 120, stateRoot, [scheduledChange(auth1, 0)]);
    // Set 1 justifies #130.
    const b130 = header(h32("parent 129"), 130, stateRoot);
    // Set 1 → 2 signalled at #140 with delay 2; set 1 justifies #142 (the enacting block).
    const b140 = header(h32("parent 139"), 140, stateRoot, [scheduledChange(auth2, 2)]);
    const b141 = header(blake2_256(b140), 141, stateRoot);
    const b142 = header(blake2_256(b141), 142, stateRoot);
    // #143 is past the enactment block (142): set 1 must not justify it as part of that change.
    const b143 = header(blake2_256(b142), 143, stateRoot);
    // ForcedChange at #150 (set 1).
    const b150 = header(h32("parent 149"), 150, stateRoot, [forcedChange(auth2)]);
    // Set 2 justifies #160.
    const b160 = header(h32("parent 159"), 160, stateRoot);

    return {
        round: Number(round),
        authorities: {set0: toHex(auth0), set1: toHex(auth1), set2: toHex(auth2)},
        b100: {header: toHex(b100), votes: toHex(sign(b100, 100, set0, 0n)), votesAll: toHex(sign(b100, 100, set0, 0n, [0, 1, 2, 3]))},
        b101: {header: toHex(b101), ancestryVotes: toHex(ancestryVotes)},
        b120: {header: toHex(b120), votes: toHex(sign(b120, 120, set0, 0n))},
        b130: {header: toHex(b130), votes: toHex(sign(b130, 130, set1, 1n))},
        b140: {header: toHex(b140)},
        b141: {header: toHex(b141)},
        b142: {header: toHex(b142), votes: toHex(sign(b142, 142, set1, 1n))},
        b143: {header: toHex(b143), votes: toHex(sign(b143, 143, set1, 1n))},
        b150: {header: toHex(b150), votes: toHex(sign(b150, 150, set1, 1n))},
        b160: {header: toHex(b160), votes: toHex(sign(b160, 160, set2, 2n))}
    };
}

// ── BEEFY ────────────────────────────────────────────────────────────────────

const secKey = (i: number) => Buffer.alloc(32, 0x40 + i);
const secAddrs = (ids: number[]) => Buffer.concat(ids.map((i) => keccak(Buffer.from(secp256k1.getPublicKey(secKey(i), false)).subarray(1)).subarray(12)));

function mmr(leaves: Buffer[]) {
    const hashes = leaves.map((l) => keccak(l));
    const peaks: {start: number; h: number; root: Buffer}[] = [];
    let start = 0;
    for (let b = 31; b >= 0; b--) if ((leaves.length >> b) & 1) {
        let row = hashes.slice(start, start + (1 << b));
        while (row.length > 1) row = row.reduce<Buffer[]>((acc, x, i) => (i % 2 ? (acc.push(keccak(row[i - 1], x)), acc) : acc), []);
        peaks.push({start, h: b, root: row[0]});
        start += 1 << b;
    }
    const bag = (ps: Buffer[]) => { let acc = ps[ps.length - 1]; for (let i = ps.length - 2; i >= 0; i--) acc = keccak(acc, ps[i]); return acc; };
    const root = bag(peaks.map((p) => p.root));
    const pathFor = (idx: number) => {
        const t = peaks.findIndex((p) => idx >= p.start && idx < p.start + (1 << p.h));
        const p = peaks[t], path: Buffer[] = [];
        let sides = 0n, row = hashes.slice(p.start, p.start + (1 << p.h)), pos = idx - p.start;
        for (let k = 0; k < p.h; k++) {
            const sib = pos % 2 ? row[pos - 1] : row[pos + 1];
            if (pos % 2) sides |= 1n << BigInt(path.length);
            path.push(sib);
            row = row.reduce<Buffer[]>((acc, x, i) => (i % 2 ? (acc.push(keccak(row[i - 1], x)), acc) : acc), []);
            pos >>= 1;
        }
        const right = peaks.slice(t + 1).map((q) => q.root);
        if (right.length) { sides |= 1n << BigInt(path.length); path.push(bag(right)); }
        for (let i = t - 1; i >= 0; i--) path.push(peaks[i].root);
        return {path: path.map(toHex), sides: "0x" + sides.toString(16)};
    };
    return {root, pathFor};
}

const leafOf = (parentNumber: number, parentHash: Buffer, next: {id: bigint; len: number; root: Buffer}, extra: Buffer) =>
    Buffer.concat([Buffer.from([0]), u32le(parentNumber), parentHash, u64le(next.id), u32le(next.len), next.root, extra]);

function commitmentBytes(mmrRoot: Buffer, block: number, setId: bigint): Buffer {
    return Buffer.concat([compact(1), Buffer.from("mh"), compact(32), mmrRoot, u32le(block), u64le(setId)]);
}
function beefySign(c: Buffer, ids: number[], signers: number[], n: number) {
    const bits = Buffer.alloc(Math.ceil(n / 8));
    const sigs = signers.map((i) => {
        bits[i >> 3] |= 0x80 >> (i & 7);
        const s = secp256k1.sign(keccak(c), secKey(ids[i]), {lowS: true});
        return Buffer.concat([Buffer.from(s.toCompactRawBytes()), Buffer.from([s.recovery!])]);
    });
    return {signers: toHex(bits), signatures: toHex(Buffer.concat(sigs))};
}

function beefy(evmRoot: Buffer) {
    const ids10 = [0, 1, 2, 3], ids11 = [4, 5, 6, 7], ids12 = [8, 9, 10, 11];
    const set = (id: bigint, ids: number[]) => ({id, len: ids.length, root: keysetRoot(secAddrs(ids))});
    const set10 = set(10n, ids10), set11 = set(11n, ids11), set12 = set(12n, ids12);

    const paraHeader = header(h32("para parent"), 5000, evmRoot);
    const headData = Buffer.concat([compact(paraHeader.length), paraHeader]);
    const relayTrie = buildTrie([
        [paraHeadKey(PARA_ID), headData],
        [paraHeadKey(1000), Buffer.concat([compact(40), Buffer.alloc(40, 1)])],
        [paraHeadKey(3367), Buffer.concat([compact(40), Buffer.alloc(40, 2)])],
        [Buffer.from("relay-system-key"), Buffer.alloc(32, 3)]
    ]);
    const relay205 = header(h32("relay 204"), 205, relayTrie.root);
    const relay206 = header(blake2_256(relay205), 206, relayTrie.root);

    // MMR A: leaves for blocks 201..206 (mountains 4 + 2); commitment at #206 by set 10.
    const leavesA = [201, 202, 203, 204, 205].map((b) => leafOf(b - 1, h32(`relay ${b - 1}`), set11, h32(`extra ${b}`)));
    leavesA.push(leafOf(205, blake2_256(relay205), set11, h32("extra 206")));
    const mA = mmr(leavesA);
    const cA = commitmentBytes(mA.root, 206, 10n);
    // MMR B: blocks 201..207 (4 + 2 + 1); commitment at #207 by set 11 (rotation), leaf next = set 12.
    const leavesB = [...leavesA, leafOf(206, blake2_256(relay206), set12, h32("extra 207"))];
    const mB = mmr(leavesB);
    const cB = commitmentBytes(mB.root, 207, 11n);

    // MMR C: like A, but the commitment leaf names set 13 as next (≠ 10 + 1).
    const leavesC = [...leavesA.slice(0, 5), leafOf(205, blake2_256(relay205), set(13n, ids12), h32("extra 206"))];
    const mC = mmr(leavesC);
    const cC = commitmentBytes(mC.root, 206, 10n);

    const pack = (s: typeof set10) => ({id: s.id.toString(), len: s.len, root: toHex(s.root)});
    return {
        paraId: PARA_ID,
        paraHeadKey: toHex(paraHeadKey(PARA_ID)),
        sets: {set10: pack(set10), set11: pack(set11), set12: pack(set12)},
        addresses: {set10: toHex(secAddrs(ids10)), set11: toHex(secAddrs(ids11))},
        paraHeader: toHex(paraHeader),
        relayStateProof: relayTrie.nodes.map(toHex),
        relay205: toHex(relay205),
        relay206: toHex(relay206),
        commitA: {commitment: toHex(cA), ...beefySign(cA, ids10, [0, 1, 2], 4), all: beefySign(cA, ids10, [0, 1, 2, 3], 4), leaf: toHex(leavesA[5]), ...mA.pathFor(5)},
        commitC: {commitment: toHex(cC), ...beefySign(cC, ids10, [0, 1, 2], 4), leaf: toHex(leavesC[5]), ...mC.pathFor(5)},
        absentParaHeadKey: toHex(paraHeadKey(1001)),
        commitB: {commitment: toHex(cB), ...beefySign(cB, ids11, [1, 2, 3], 4), leaf: toHex(leavesB[6]), ...mB.pathFor(6)},
        // A leaf inside a mountain (index 2 of MMR A) for the MMR library test.
        mmrInner: {root: toHex(mA.root), leaf: toHex(leavesA[2]), ...mA.pathFor(2)}
    };
}

// ── Native pallet (GrandpaPalletVerifier) ────────────────────────────────────

export const PALLET = twox128("Clpr");
export const PALLET_SERVICE = keccak(Buffer.from("clpr/grandpa-synthetic/pallet-account"));
export const BAD_LENGTH_CHANNEL: Hex = keccak256(toBytes("clpr/grandpa-synthetic/bad-length"));
export const BAD_STATUS_CHANNEL: Hex = keccak256(toBytes("clpr/grandpa-synthetic/bad-status"));
const palletManifest = Buffer.concat([Buffer.from([0x08, 0x01, 0x12, 0x20]), PALLET_SERVICE]);

function palletChain() {
    const record = palletQueueRecord({status: Number(STATUS_ACTIVE), next: NEXT_MESSAGE_ID, received: RECEIVED_MESSAGE_ID, manifestVersion: 1n, sent: h32("sentRunningHash"), receivedHash: h32("receivedRunningHash")});
    const entries: [Buffer, Buffer][] = [
        [palletQueueKey(PALLET, CHANNEL_ID), record],
        [palletQueueKey(PALLET, BAD_LENGTH_CHANNEL), record.subarray(0, 88)],
        [palletQueueKey(PALLET, BAD_STATUS_CHANNEL), Buffer.concat([Buffer.from([9]), record.subarray(1)])],
        [palletServiceKey(PALLET), palletServiceRecord(PALLET_SERVICE, keccak(palletManifest), CONFIG_NANOS)],
        // Neighbours in other pallets: a Blake2_128Concat map entry and a plain value.
        [Buffer.concat([twox128("System"), twox128("Account"), Buffer.alloc(16, 0x11), Buffer.alloc(32, 0x22)]), Buffer.alloc(80, 0x33)],
        [Buffer.concat([twox128("Grandpa"), twox128("CurrentSetId")]), u64le(9n)]
    ];
    const trie = buildTrie(entries);

    const set0 = [0, 1, 2, 3], set1 = [4, 5, 6, 7], setW = [12, 13, 14, 15, 16];
    const auth0 = edSet(set0), auth1 = edSet(set1);
    // Weighted set: weights 1, 1, 1, 1, 4 (total 8, threshold 6), like Chainflip's one weight-4 authority.
    const authW = Buffer.concat(setW.map((k, i) => Buffer.concat([Buffer.from(ed25519.getPublicKey(edKey(k))), u64le(i === 4 ? 4n : 1n)])));
    const round = 7n;
    const sign = (h: Buffer, n: number, set: number[], setId: bigint, idxs = [0, 1, 2]) =>
        votes(idxs.map((i) => ({idx: i, key: set[i], target: blake2_256(h), number: n})), round, setId);

    const p200 = header(h32("pallet parent 199"), 200, trie.root);
    const p220 = header(h32("pallet parent 219"), 220, trie.root, [scheduledChange(auth1, 0)]);
    const p230 = header(h32("pallet parent 229"), 230, trie.root);
    const p300 = header(h32("pallet parent 299"), 300, trie.root);
    return {
        pallet: toHex(PALLET),
        service: toHex(PALLET_SERVICE),
        manifestPreimage: toHex(palletManifest),
        badLengthChannel: BAD_LENGTH_CHANNEL,
        badStatusChannel: BAD_STATUS_CHANNEL,
        root: toHex(trie.root),
        nodes: trie.nodes.map(toHex),
        systemAccountKey: toHex(entries[4][0]),
        currentSetIdKey: toHex(entries[5][0]),
        authorities: {set0: toHex(auth0), set1: toHex(auth1), setW: toHex(authW)},
        p200: {header: toHex(p200), votes: toHex(sign(p200, 200, set0, 0n))},
        p220: {header: toHex(p220), votes: toHex(sign(p220, 220, set0, 0n))},
        p230: {header: toHex(p230), votes: toHex(sign(p230, 230, set1, 1n))},
        // Set id 9; one 102-byte vote per authority index, for batching.
        p300: {header: toHex(p300), hash: toHex(blake2_256(p300)), votesW: [0, 1, 2, 3, 4].map((i) => toHex(sign(p300, 300, setW, 9n, [i])))}
    };
}

// ── main ─────────────────────────────────────────────────────────────────────

const evm = evmState();
const fixture = {
    service: SERVICE,
    channelId: CHANNEL_ID,
    configNanos: CONFIG_NANOS.toString(),
    manifestPreimage: toHex(manifestPreimage),
    evm: {root: toHex(evm.trie.root), nodes: evm.trie.nodes.map(toHex), slotNumbers: evm.slots.map(([s]) => s), slotValues: evm.slots.map(([, v]) => toHex(v))},
    grandpa: grandpa(evm.trie.root),
    beefy: beefy(evm.trie.root),
    pallet: palletChain()
};
mkdirSync(path.dirname(OUT), {recursive: true});
writeFileSync(OUT, JSON.stringify(fixture, null, 1) + "\n");
console.log(`wrote ${path.relative(process.cwd(), OUT)}`);
