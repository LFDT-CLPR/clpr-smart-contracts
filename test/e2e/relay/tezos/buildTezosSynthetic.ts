import {writeFileSync, mkdirSync} from "node:fs";
import {dirname, resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {decodeAbiParameters, encodeAbiParameters, keccak256, type Hex} from "viem";
import {bls12_381 as bls} from "@noble/curves/bls12-381";
import {ed25519} from "@noble/curves/ed25519";
import {p256} from "@noble/curves/p256";
import {secp256k1} from "@noble/curves/secp256k1";
import * as C from "./codec.js";
import {pathProof, treeHash, type Tree} from "./irmin.js";
import {parseSampler, slotOwner} from "./sampler.js";
import {pbBytes, pbInt, pbLen, pbStr} from "../../lib/proto.js";
import {CACHE_ENTRY_TYPE} from "../buildTezosLiveFixture.js";

/// Synthetic Tezos chain for the TezosVerifier unit tests: five delegates (tz1, tz2, tz3, and two
/// tz4, one with a DAL companion key), a delegate sampler built with octez's alias method, context
/// trees with the CLPR Service big_map, a predecessor header, a commit, and signed attestations.
/// Committee 100 slots, threshold 67.
///
/// Run: npx tsx test/e2e/relay/tezos/buildTezosSynthetic.ts  → test/verifiers/evm/tezos/fixtures/synthetic.json

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = resolve(HERE, "../../../verifiers/evm/tezos/fixtures/synthetic.json");

const CHAIN_ID = Buffer.from("7a06a770", "hex");
const PROTO = 25;
const ERA = {firstLevel: 1, firstCycle: 0, blocksPerCycle: 200};
const COMMITTEE = 100;
const THRESHOLD = 67;
const BIG_MAP = 7;
const SERVICE = Buffer.from("01" + "11".repeat(20) + "00", "hex");
const CHANNEL = Buffer.from("c1".repeat(32), "hex");
const ANCHOR_LEVEL = 1000; // cycle 4
const L = 1012; // cycle 5
const CYCLE = 5;
const POS = (L - ERA.firstLevel) % ERA.blocksPerCycle;
const DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

const sk = (tag: string) => C.blake2b256(Buffer.from(`clpr-tezos-synthetic-${tag}`));
const blsSk = (tag: string) => BigInt("0x" + sk(tag).toString("hex")) % bls.params.r;
const pad64 = (v: bigint): Buffer => Buffer.from(v.toString(16).padStart(128, "0"), "hex");
const g1 = (pk: Uint8Array) => {
    const a = bls.G1.ProjectivePoint.fromHex(pk).toAffine();
    return C.cat(pad64(a.x), pad64(a.y));
};
const g2 = (p: any) => {
    const a = p.toAffine();
    return C.cat(pad64(a.x.c0), pad64(a.x.c1), pad64(a.y.c0), pad64(a.y.c1));
};

interface Delegate {
    scheme: number;
    key: Buffer;
    stake: bigint;
    companion?: Buffer;
    sk: any;
    companionSk?: bigint;
}

function delegates(variant: string): Delegate[] {
    const edSk = sk(`ed${variant}`);
    const spSk = sk(`sp${variant}`);
    const p2Sk = sk(`p2${variant}`);
    const b1 = blsSk(`bls1${variant}`);
    const b1c = blsSk(`bls1c${variant}`);
    const b2 = blsSk(`bls2${variant}`);
    return [
        {scheme: 0, key: Buffer.from(ed25519.getPublicKey(edSk)), stake: 30n, sk: edSk},
        {scheme: 1, key: Buffer.from(secp256k1.getPublicKey(spSk, true)), stake: 15n, sk: spSk},
        {scheme: 2, key: Buffer.from(p256.getPublicKey(p2Sk, true)), stake: 15n, sk: p2Sk},
        {
            scheme: 3,
            key: Buffer.from(bls.getPublicKey(b1)),
            stake: 25n,
            companion: Buffer.from(bls.getPublicKey(b1c)),
            sk: b1,
            companionSk: b1c,
        },
        {scheme: 3, key: Buffer.from(bls.getPublicKey(b2)), stake: 15n, sk: b2},
    ];
}

/// octez `Sampler.create` (alias method) and `Sampler.encoding`.
function encodeSampler(ds: Delegate[]): Buffer {
    const measure = [...ds].reverse(); // check_and_cleanup folds into a reversed list
    const total = measure.reduce((n, d) => n + d.stake, 0n);
    const n = BigInt(measure.length);
    let small: [bigint, number][] = [];
    let large: [bigint, number][] = [];
    measure.forEach((d, i) => {
        const q = d.stake * n;
        if (q < total) small = [[q, i], ...small];
        else large = [[q, i], ...large];
    });
    const p: bigint[] = measure.map(() => 0n);
    const alias: number[] = measure.map(() => -1);
    for (;;) {
        if (small.length === 0) {
            for (const [, i] of large) p[i] = total;
            break;
        }
        if (large.length === 0) {
            for (const [, i] of small) p[i] = total;
            break;
        }
        const [qi, i] = small[0];
        const [qj, j] = large[0];
        p[i] = qi;
        alias[i] = j;
        const qj2 = qi + qj - total;
        if (qj2 < total) {
            small = [[qj2, j], ...small.slice(1)];
            large = large.slice(1);
        } else {
            small = small.slice(1);
            large = [[qj2, j], ...large.slice(1)];
        }
    }
    const pk = (d: Delegate) =>
        C.cat(C.u8(d.scheme), d.key, C.u8(0), d.companion ? C.cat(C.u8(0xff), d.companion) : C.u8(0));
    const arr = (fallback: Buffer, els: Buffer[]) => {
        const body = C.cat(...els);
        return C.cat(C.u32(els.length), fallback, C.u32(body.length), body);
    };
    return C.cat(
        C.i64(total),
        arr(pk(measure[0]), measure.map(pk)),
        arr(C.i64(0), p.map((x) => C.i64(x))),
        arr(C.u32(0xffffffff), alias.map((x) => C.u32(x >>> 0))),
    );
}

// ── context trees ─────────────────────────────────────────────────────────

type Dir = {[k: string]: Dir | Buffer};
const toTree = (d: Dir | Buffer): Tree =>
    Buffer.isBuffer(d)
        ? {t: "value", v: d}
        : {t: "node", entries: Object.keys(d).map((k) => [k, toTree(d[k] as Dir | Buffer)] as [string, Tree])};

const micheBytes = (b: Buffer) => C.cat(Buffer.from([0x0a]), C.u32(b.length), b);
const keyHashHex = (key: Buffer) => C.blake2b256(C.cat(Buffer.from([0x05, 0x0a]), C.u32(key.length), key)).toString("hex");

function controlMessage(): Buffer {
    const ts = pbInt(1, 1_790_000_000n);
    const throttles = C.cat(pbInt(1, 50n), pbInt(2, 4096n), pbInt(3, 500000n), pbInt(4, 1000n), pbInt(5, 65536n), pbInt(6, 8n), pbInt(7, 8n));
    const cfg = C.cat(pbInt(1, 1n), pbStr(2, "tezos:NetXdQprcVkpaWU"), pbBytes(3, SERVICE), pbLen(4, ts), pbLen(5, throttles));
    return pbLen(3, pbLen(1, pbLen(1, cfg)));
}

function manifest(): Buffer {
    const ep = C.cat(pbLen(1, C.cat(pbStr(1, "203.0.113.7"), pbInt(2, 50211n))), pbBytes(2, Buffer.from("cert")), pbBytes(3, Buffer.from("acct")));
    return C.cat(pbInt(1, 3n), pbBytes(2, SERVICE), pbLen(3, ep));
}

// QueueMetadata record: status, next id, received id, sent hash, received hash, manifest version.
const RECORD = C.cat(
    C.u8(1),
    C.u64(5),
    C.u64(4),
    Buffer.from("aa".repeat(32), "hex"),
    Buffer.from("bb".repeat(32), "hex"),
    C.u64(3),
);

function cycleDir(sampler: Buffer, seed: Buffer): Dir {
    return {delegate_sampler_state: sampler, random_seed: seed, issuance_bonus: Buffer.from("00", "hex")};
}

function build() {
    const ds = delegates("");
    const sampler = encodeSampler(ds);
    const seed = C.blake2b256(Buffer.from("synthetic-seed"));
    const parsed = parseSampler(sampler);
    // support index of each delegate (the encoding reverses the input order)
    const idx = (i: number) => ds.length - 1 - i;
    const owners = [...Array(COMMITTEE).keys()].map((s) => slotOwner(parsed, seed, POS, s));
    const power = [0, 1, 2, 3, 4].map((i) => owners.filter((o) => o === idx(i)).length);

    const anchorDir: Dir = {data: {cycle: {"4": cycleDir(Buffer.from("00", "hex"), C.blake2b256(Buffer.from("s4"))), "5": cycleDir(sampler, seed)}}, protocol: Buffer.from("aa", "hex")};
    const anchorTree = toTree(anchorDir);
    const [, anchorRoot] = treeHash(anchorTree);

    // An anchor state that schedules "all bakers attest" (the verifier must refuse it).
    const abaaTree = toTree({
        data: {all_bakers_attest_first_level: Buffer.from("00000fa0", "hex"), cycle: {"5": cycleDir(sampler, seed)}},
    });
    const [, abaaRoot] = treeHash(abaaTree);

    // A different validator set under another anchor (same cycle).
    const alt = delegates("-alt");
    const altSampler = encodeSampler(alt);
    const altTree = toTree({data: {cycle: {"5": cycleDir(altSampler, seed)}}});
    const [, altRoot] = treeHash(altTree);

    const ctl = controlMessage();
    const man = manifest();
    const kQ = keyHashHex(C.cat(Buffer.from("q"), CHANNEL));
    const kM = keyHashHex(Buffer.from("m"));
    const kC = keyHashHex(Buffer.from("c"));
    const keccak = (b: Buffer) => Buffer.from(keccak256(b).slice(2), "hex");
    const stateDir: Dir = {
        data: {
            big_maps: {
                index: {
                    [String(BIG_MAP)]: {
                        contents: {
                            [kQ]: {data: micheBytes(RECORD), len: Buffer.from("00000059", "hex")},
                            [kM]: {data: micheBytes(keccak(man))},
                            [kC]: {data: micheBytes(keccak(ctl))},
                        },
                        key_type: Buffer.from("0369", "hex"),
                    },
                    "8": {contents: {}},
                },
            },
            contracts: {index: {[SERVICE.toString("hex")]: {data: {storage: C.cat(Buffer.from([0]), C.zarithZ(BigInt(BIG_MAP)))}}}},
            cycle: {"5": cycleDir(sampler, seed)},
        },
    };
    const stateTree = toTree(stateDir);
    const [, stateRoot] = treeHash(stateTree);

    // Predecessor header (level L−1) committing to the state root.
    const tail = C.cat(C.u64(1), C.u64(32), C.blake2b256(Buffer.from("parent")), C.i64(1_790_000_000n), C.u64(5), Buffer.from("Tezos"), C.u64(3), Buffer.from("msg"));
    const commit = C.blake2b256(C.cat(C.u64(32), stateRoot, tail));
    const fitness = C.cat(C.u32(5), C.u32(1), C.u8(2)); // fitness list (opaque to the verifier)
    const shell = (ctx: Buffer, proto = PROTO, level = L - 1) =>
        C.cat(C.i32(level), C.u8(proto), C.blake2b256(Buffer.from("pred")), C.i64(1_790_000_000n), C.u8(4), C.blake2b256(Buffer.from("ops")), fitness, ctx);
    const protoData = C.cat(Buffer.alloc(32, 0x55), C.i32(0), Buffer.alloc(8), C.u8(0), C.u8(0), Buffer.alloc(64, 0x66));
    const header = C.cat(shell(commit), protoData);
    const opsHash = C.blake2b256(Buffer.from("payload-ops"));
    const payloadRound = 0;
    const round = 0;
    const payload = C.blake2b256(C.cat(C.blake2b256(header), C.i32(payloadRound), opsHash));

    // Attestations.
    const branch = C.blake2b256(Buffer.from("branch"));
    const firstSlot = (i: number) => owners.indexOf(idx(i));
    const indiv = (i: number, withDal: boolean, dal = 5n, highS = false) => {
        const d = ds[i];
        const bytes = C.attestationSigningBytes({chainId: CHAIN_ID, branch, slot: firstSlot(i), level: L, round, payloadHash: payload, dal: withDal ? dal : undefined});
        const digest = C.blake2b256(bytes);
        let sig: Buffer;
        let y = Buffer.alloc(32);
        if (d.scheme === 0) sig = Buffer.from(ed25519.sign(digest, d.sk));
        else if (d.scheme === 1) {
            sig = Buffer.from(secp256k1.sign(digest, d.sk).toCompactRawBytes());
            y = pad64(secp256k1.ProjectivePoint.fromHex(d.key).toAffine().y).subarray(32);
        } else {
            const s = p256.sign(digest, d.sk);
            const sv = highS ? p256.CURVE.n - s.s : s.s;
            sig = C.cat(Buffer.from(s.r.toString(16).padStart(64, "0"), "hex"), Buffer.from(sv.toString(16).padStart(64, "0"), "hex"));
            y = pad64(p256.ProjectivePoint.fromHex(d.key).toAffine().y).subarray(32);
        }
        return {
            signer: idx(i),
            slot: firstSlot(i),
            branch: C.hex(branch),
            withDal,
            dal: C.hex(withDal ? C.zarithZ(dal) : Buffer.alloc(0)),
            signature: C.hex(sig),
            y: C.hex(y),
            scheme: d.scheme,
            key: C.hex(d.key),
            digest: C.hex(digest),
        };
    };
    const opb = C.blsModeAttestation({branch, level: L, round, payloadHash: payload});
    const msg = C.cat(Buffer.from([0x13]), CHAIN_ID, opb);
    const H = bls.G2.hashToCurve(msg, {DST});
    const sign = (s: bigint) => (H as any).multiply(s);
    const d3 = ds[3];
    const d4 = ds[4];
    const bits = C.zToBits(40964n);
    const z = C.blake2b256(C.cat(C.blake2b160(d3.key), C.blake2b160(d3.companion!), opb, bits));
    let zi = 0n;
    for (let i = z.length - 1; i >= 0; i--) zi = (zi << 8n) | BigInt(z[i]);
    zi %= bls.params.r;
    const aggSig = sign(d3.sk).add(sign(d3.companionSk!).multiply(zi)).add(sign(d4.sk));
    const aggregate = (members: number[], sig = aggSig) => ({
        branch: C.hex(branch),
        signers: members.map(idx),
        keys: members.map((i) => C.hex(g1(ds[i].key))),
        dal: members.map((i) => (i === 3 ? C.hex(C.cat(Buffer.from([1]), bits)) : ("0x" as Hex))),
        companionKeys: members.map((i) => (i === 3 ? C.hex(g1(ds[i].companion!)) : ("0x" as Hex))),
        signature: C.hex(g2(sig)),
    });

    const a0 = indiv(0, false);
    const a1 = indiv(1, true);
    const a2 = indiv(2, true, 7n, true); // high-s P-256
    const strip = ({scheme: _s, key: _k, digest: _d, ...rest}: any) => rest;

    const FIN = [
        {
            type: "tuple",
            components: [
                {name: "level", type: "uint32"},
                {name: "round", type: "uint32"},
                {name: "payloadRound", type: "uint32"},
                {name: "operationsHash", type: "bytes32"},
                {name: "predecessorHeader", type: "bytes"},
                {name: "contextRoot", type: "bytes32"},
                {name: "commitTail", type: "bytes"},
                {name: "samplerProof", type: "bytes"},
                {name: "seedProof", type: "bytes"},
                {name: "attestations", type: "tuple[]", components: [
                    {name: "signer", type: "uint16"}, {name: "slot", type: "uint16"}, {name: "branch", type: "bytes32"},
                    {name: "withDal", type: "bool"}, {name: "dal", type: "bytes"}, {name: "signature", type: "bytes"}, {name: "y", type: "bytes32"},
                ]},
                {name: "aggregates", type: "tuple[]", components: [
                    {name: "branch", type: "bytes32"}, {name: "signers", type: "uint16[]"}, {name: "keys", type: "bytes[]"},
                    {name: "dal", type: "bytes[]"}, {name: "companionKeys", type: "bytes[]"}, {name: "signature", type: "bytes"},
                ]},
            ],
        },
    ] as const;

    const cycSteps = (leaf: string) => ["data", "cycle", String(CYCLE), leaf];
    const fin = (o: {atts?: any[]; aggs?: any[]; tree?: Tree; hdr?: Buffer; tailBytes?: Buffer; level?: number} = {}) => {
        const tree = o.tree ?? anchorTree;
        return encodeAbiParameters(FIN, [
            {
                level: o.level ?? L,
                round,
                payloadRound,
                operationsHash: C.hex(opsHash),
                predecessorHeader: C.hex(o.hdr ?? header),
                contextRoot: C.hex(stateRoot),
                commitTail: C.hex(o.tailBytes ?? tail),
                samplerProof: C.hex(pathProof(tree, cycSteps("delegate_sampler_state")).proof),
                seedProof: C.hex(pathProof(tree, cycSteps("random_seed")).proof),
                attestations: (o.atts ?? [a0, a1, a2]).map(strip),
                aggregates: o.aggs ?? [aggregate([3, 4])],
            },
        ]);
    };

    const bigMapProof = (key: Buffer) => C.hex(pathProof(stateTree, ["data", "big_maps", "index", String(BIG_MAP), "contents", keyHashHex(key), "data"]).proof);
    const content = C.cat(pbLen(2, Buffer.from("payload-one")), pbLen(2, Buffer.from("payload-two")));
    const BUNDLE = [
        {type: "tuple", components: [
            {name: "finality", type: FIN[0].type, components: FIN[0].components},
            {name: "queueProof", type: "bytes"},
            {name: "bundleContent", type: "bytes"},
            {name: "manifestProof", type: "bytes"},
            {name: "manifestPreimage", type: "bytes"},
        ]},
    ] as const;
    const decodeFin = (f: Hex) => decodeAbiParameters(FIN, f)[0];
    const bundle = (f: Hex, withManifest = true, queueKey = C.cat(Buffer.from("q"), CHANNEL)) =>
        encodeAbiParameters(BUNDLE as any, [
            {
                finality: decodeFin(f),
                queueProof: bigMapProof(queueKey),
                bundleContent: C.hex(content),
                manifestProof: withManifest ? bigMapProof(Buffer.from("m")) : "0x",
                manifestPreimage: withManifest ? C.hex(man) : "0x",
            },
        ]);
    const CONFIG = [
        {type: "tuple", components: [
            {name: "finality", type: FIN[0].type, components: FIN[0].components},
            {name: "storageProof", type: "bytes"},
            {name: "configProof", type: "bytes"},
            {name: "controlMessage", type: "bytes"},
        ]},
    ] as const;
    const storageProof = C.hex(pathProof(stateTree, ["data", "contracts", "index", SERVICE.toString("hex"), "data", "storage"]).proof);
    const config = encodeAbiParameters(CONFIG as any, [
        {finality: decodeFin(fin()), storageProof, configProof: bigMapProof(Buffer.from("c")), controlMessage: C.hex(ctl)},
    ]);
    const MANIFEST = [{type: "tuple", components: [{name: "manifestProof", type: "bytes"}, {name: "manifestPreimage", type: "bytes"}]}] as const;

    const badSig = {...a0, signature: C.hex(Buffer.from(C.unhex(a0.signature).map((b, i) => (i === 10 ? b ^ 1 : b))))};
    const cacheEntries = encodeAbiParameters(CACHE_ENTRY_TYPE, [
        [a0, a2].map((a) => ({scheme: a.scheme, key: a.key, y: a.y, digest: a.digest, signature: a.signature})),
    ]);
    const anchorEnc = (lvl: number, root: Buffer) => encodeAbiParameters([{type: "uint32"}, {type: "bytes32"}], [lvl, C.hex(root)]);

    return {
        profile: {chainId: C.hex(CHAIN_ID), protocolLevel: PROTO, eraFirstLevel: ERA.firstLevel, eraFirstCycle: ERA.firstCycle, blocksPerCycle: ERA.blocksPerCycle, committeeSize: COMMITTEE, threshold: THRESHOLD},
        caip2: "tezos:NetXdQprcVkpaWU",
        service: C.hex(SERVICE),
        bigMapId: BIG_MAP,
        channelId: C.hex(CHANNEL),
        level: L,
        anchorLevel: ANCHOR_LEVEL,
        anchorRoot: C.hex(anchorRoot),
        anchor: anchorEnc(ANCHOR_LEVEL, anchorRoot),
        altAnchor: anchorEnc(ANCHOR_LEVEL, altRoot),
        staleAnchor: anchorEnc(L - 2, anchorRoot),
        stateRoot: C.hex(stateRoot),
        newAnchor: anchorEnc(L - 2, stateRoot),
        power,
        supportIndex: [0, 1, 2, 3, 4].map(idx),
        record: C.hex(RECORD),
        manifest: C.hex(man),
        controlMessage: C.hex(ctl),
        sampler: C.hex(sampler),
        seed: C.hex(seed),
        position: POS,
        owners,
        finality: fin(),
        finalityAltSet: fin({tree: altTree}),
        finalityAbaa: fin({tree: abaaTree}),
        abaaAnchor: anchorEnc(ANCHOR_LEVEL, abaaRoot),
        finalityBadSig: fin({atts: [badSig, a1, a2]}),
        finalityWeak: fin({atts: [a1], aggs: [aggregate([4], sign(d4.sk))]}),
        finalityCached: fin({atts: [{...a0, signature: "0x"}, a1, {...a2, signature: "0x"}]}),
        finalityBadAggKey: fin({aggs: [{...aggregate([3, 4]), keys: [C.hex(g1(ds[4].key)), C.hex(g1(ds[4].key))]}]}),
        finalityTwoAggs: fin({aggs: [aggregate([3, 4]), aggregate([3, 4])]}),
        finalityBadTail: fin({tailBytes: C.cat(tail, Buffer.from("x"))}),
        finalityWrongProto: fin({hdr: C.cat(shell(commit, 26), protoData)}),
        finalityWrongLevel: fin({level: L + 1}),
        cacheEntries,
        bundle: bundle(fin()),
        bundleNoManifest: bundle(fin(), false),
        config,
        configManifest: encodeAbiParameters(MANIFEST as any, [{manifestProof: bigMapProof(Buffer.from("m")), manifestPreimage: C.hex(man)}]),
        queueSteps: ["data", "big_maps", "index", String(BIG_MAP), "contents", kQ, "data"],
        queueProof: bigMapProof(C.cat(Buffer.from("q"), CHANNEL)),
    };
}

const out = build();
mkdirSync(dirname(OUT), {recursive: true});
writeFileSync(OUT, JSON.stringify(out, null, 1) + "\n");
console.log(`[tezos-synthetic] power by delegate ${out.power} (threshold ${THRESHOLD}); wrote ${OUT}`);
