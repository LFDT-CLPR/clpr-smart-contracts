import {mkdirSync, openSync, readFileSync, readSync, writeFileSync, closeSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {
    blsKeyBytes,
    blsSigBytes,
    hex,
    packFinalizerPolicy,
    qcBitsetFromString,
    savannaRootFromSubtrees,
    sha256,
    unhex,
    verifyBlsAggregate,
    type FinalizerPolicyJson
} from "../lib/antelope.js";
import {rlpEncode} from "../lib/rlp.js";

/// Live Savanna (Spring 1.x) capture for SavannaVerifier, from public data only:
///   - a Spring v8 snapshot (public snapshot services publish these for Vaulta, Jungle4 and Telos),
///   - the chain's public HTTP RPC (get_block, get_finalizer_info).
///
/// What it records and checks (all offline-verifiable):
///   1. From the snapshot's block_state (head block H): the finality core's block refs (block id,
///      timestamp, finality digest, policy generations of the reversible blocks), the validation
///      tree (incremental Merkle tree of finality leaves since Savanna genesis: mask + subtree
///      roots) and the last pending finalizer policy digest.
///   2. The QC carried in block H's quorum_certificate_extension, which certifies block H-1: its
///      strong-vote bitset and aggregate BLS signature, checked here (noble BLS12-381, NUL
///      ciphersuite) against the snapshot's finality digest of H-1 and the active policy.
///   3. The active finalizer policy from get_finalizer_info, packed as Spring packs it; its
///      sha256 must equal the snapshot's last pending policy digest.
///   4. The validation tree root equals the finality_mroot in block H+1's header (Savanna stores
///      finality_mroot in the header's action_mroot field), which is the root through H.
///
/// Not recorded: the level-3 commitments (base digest) of a block and the action receipts, which
/// public HTTP RPC does not serve. A full verifyBundle on live Savanna data needs a SHiP endpoint
/// with finality data (state_history_plugin, finality-data-history = true): see the README.
///
/// Usage: tsx buildSavannaLiveProof.ts --snapshot <file.bin> [--network jungle4] [--rpc <url>]
///        tsx buildSavannaLiveProof.ts --emit-foundry [--network jungle4]

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const FIXTURE_DIR = path.join(HERE, "..", "fixtures", "vaulta-live");
export const FOUNDRY_DIR = path.join(HERE, "..", "..", "verifiers", "evm", "antelope", "fixtures");

export const NETWORKS: Record<string, {rpc: string; caip2: string}> = {
    jungle4: {rpc: "https://jungle4.greymass.com", caip2: "antelope:73e4385a2708e6d7048834fbc1079f2f"},
    vaulta: {rpc: "https://eos.greymass.com", caip2: "antelope:aca376f206b8fc25a6ed44dbdc66547c"},
    telos: {rpc: "https://telos.greymass.com", caip2: "antelope:4667b205c6838ef70ff7988f6e8257e8"}
};

export interface BlockRef {
    num: number;
    id: string;
    timestamp: number;
    finalityDigest: string;
    activeGen: number;
    pendingGen: number;
}

export interface SavannaCapture {
    network: string;
    caip2: string;
    chainId: string;
    capturedAt: string;
    snapshot: {headNum: number; headId: string; headTime: string};
    refs: BlockRef[];
    validationTree: {mask: number; subtrees: string[]; validationMroots: string[]};
    lastPendingPolicyDigest: string;
    lastPendingStartTimestamp: number;
    policy: FinalizerPolicyJson;
    policyPack: string;
    /// One QC per snapshot ref: the QC in block ref+1's quorum_certificate_extension.
    qcs: {carrierBlock: number; certifiedBlock: number; strongVotes: string; sig: string}[];
    nextHeaderFinalityMroot: string;
}

// ── Snapshot parsing ─────────────────────────────────────────────────────────

class Reader {
    constructor(
        public b: Buffer,
        public o = 0
    ) {}
    u8() {
        return this.b[this.o++];
    }
    u16() {
        const v = this.b.readUInt16LE(this.o);
        this.o += 2;
        return v;
    }
    u32() {
        const v = this.b.readUInt32LE(this.o);
        this.o += 4;
        return v;
    }
    bytes(n: number) {
        const v = this.b.subarray(this.o, this.o + n);
        this.o += n;
        return v;
    }
    varuint() {
        let v = 0;
        let shift = 0;
        for (;;) {
            const x = this.u8();
            v += (x & 0x7f) * 2 ** shift;
            if (!(x & 0x80)) return v;
            shift += 7;
        }
    }
}

/// The `eosio::chain::block_state` section of a Spring v8 snapshot (rows only).
function readBlockStateSection(file: string): Buffer {
    const fd = openSync(file, "r");
    try {
        const head = Buffer.alloc(8);
        readSync(fd, head, 0, 8, 0);
        if (head.readUInt32LE(4) !== 1) throw new Error("not a binary Spring snapshot");
        let pos = 8;
        for (;;) {
            const h = Buffer.alloc(16);
            readSync(fd, h, 0, 16, pos);
            const size = h.readBigUInt64LE(0);
            if (size === 0xffffffffffffffffn) throw new Error("no block_state section");
            const body = Buffer.alloc(Number(size));
            readSync(fd, body, 0, body.length, pos + 8);
            const name = body.subarray(8, body.indexOf(0, 8)).toString();
            const rows = body.subarray(8 + name.length + 1);
            if (name === "eosio::chain::chain_snapshot_header" && rows.readUInt32LE(0) !== 8) {
                throw new Error(`snapshot format v${rows.readUInt32LE(0)} (need v8, Spring 1.x)`);
            }
            if (name === "eosio::chain::block_state") return rows;
            pos += 8 + Number(size);
        }
    } finally {
        closeSync(fd);
    }
}

export function parseSnapshotBlockState(file: string) {
    const row = readBlockStateSection(file);
    const r = new Reader(row);
    if (r.u8() !== 0) throw new Error("legacy block_header_state present: not a Savanna snapshot");
    if (r.u8() !== 1) throw new Error("no Savanna block_state in snapshot");
    const headId = r.bytes(32);
    const headNum = headId.readUInt32BE(0);
    // block_header
    r.o += 4 + 8 + 2;
    const previous = r.bytes(32);
    r.o += 32 + 32 + 4;
    if (r.u8() !== 0) throw new Error("unexpected new_producers");
    const nExt = r.varuint();
    for (let i = 0; i < nExt; i++) {
        r.u16();
        const len = r.varuint();
        r.o += len;
    }
    // activated_protocol_features: shared_ptr (presence byte) to { flat_set<digest> }
    if (r.u8() !== 1) throw new Error("activated_protocol_features missing");
    const nFeatures = r.varuint();
    r.o += 32 * nFeatures;
    // finality_core { links, refs, genesis_timestamp }
    const nLinks = r.varuint();
    r.o += 9 * nLinks;
    const nRefs = r.varuint();
    const refs: BlockRef[] = [];
    for (let i = 0; i < nRefs; i++) {
        const id = r.bytes(32);
        refs.push({
            num: id.readUInt32BE(0),
            id: hex(id),
            timestamp: r.u32(),
            finalityDigest: hex(r.bytes(32)),
            activeGen: r.u32(),
            pendingGen: r.u32()
        });
    }
    if (refs.length === 0 || refs[refs.length - 1].id !== hex(previous)) throw new Error("core refs do not end at the head's parent");

    // valid_t is the last member: optional(1) | mask u64 | trees[] | validation_mroots[]. Find it
    // from the end and accept it only if the subtree roots fold to the last validation root.
    const end = row.length;
    for (let m = 1; m < 64; m++) {
        const p = end - 32 * m;
        if (row[p - 1] !== m) continue;
        const mroots = Array.from({length: m}, (_, i) => row.subarray(p + 32 * i, p + 32 * i + 32));
        for (let n = 1; n < 64; n++) {
            const tq = p - 1 - 32 * n;
            if (row[tq - 1] !== n) continue;
            const mask = row.readBigUInt64LE(tq - 9);
            if (mask.toString(2).replace(/0/g, "").length !== n || row[tq - 10] !== 1) continue;
            const subtrees = Array.from({length: n}, (_, i) => row.subarray(tq + 32 * i, tq + 32 * i + 32));
            if (!savannaRootFromSubtrees(subtrees).equals(mroots[m - 1])) continue;
            const o = tq - 10;
            return {
                headNum,
                headId: hex(headId),
                refs,
                mask: Number(mask),
                subtrees: subtrees.map(hex),
                validationMroots: mroots.map(hex),
                lastPendingStartTimestamp: row.readUInt32LE(o - 4),
                lastPendingPolicyDigest: hex(row.subarray(o - 36, o - 4)),
                finalizerPolicyGeneration: row.readUInt32LE(o - 40)
            };
        }
    }
    throw new Error("validation tree not found in block_state");
}

// ── RPC ──────────────────────────────────────────────────────────────────────

async function rpc(base: string, p: string, body: unknown): Promise<any> {
    for (let attempt = 0; ; attempt++) {
        try {
            const r = await fetch(base + p, {method: "POST", body: JSON.stringify(body), signal: AbortSignal.timeout(20_000)});
            const j = await r.json();
            if (j && (j as any).error) throw new Error(JSON.stringify((j as any).error).slice(0, 300));
            return j;
        } catch (e) {
            if (attempt >= 4) throw e;
            await new Promise((res) => setTimeout(res, 1000 * (attempt + 1)));
        }
    }
}

// ── Capture and checks ───────────────────────────────────────────────────────

/// Re-checks a capture offline: policy digest, every QC signature, validation tree root.
export function checkCapture(c: SavannaCapture): {digest: string; voters: number; qc: string}[] {
    const pack = packFinalizerPolicy(c.policy);
    if (hex(pack) !== c.policyPack) throw new Error("policy pack mismatch");
    if (hex(sha256(pack)) !== c.lastPendingPolicyDigest) throw new Error("policy digest != snapshot last pending policy digest");
    const root = savannaRootFromSubtrees(c.validationTree.subtrees.map(unhex));
    if (hex(root) !== c.nextHeaderFinalityMroot) throw new Error("validation tree root != next header's finality_mroot");
    return c.qcs.map((q) => {
        const ref = c.refs.find((r) => r.num === q.certifiedBlock);
        if (!ref) throw new Error("certified block not among the snapshot's refs");
        if (ref.activeGen !== c.policy.generation) throw new Error("policy generation differs from the certified block's");
        const bits = qcBitsetFromString(q.strongVotes, c.policy.finalizers.length);
        const voters = c.policy.finalizers.filter((_, i) => (bits[i >> 3] >> (i & 7)) & 1);
        const weight = voters.reduce((w, f) => w + f.weight, 0);
        if (weight < c.policy.threshold) throw new Error("QC below threshold");
        const sig = blsSigBytes(q.sig);
        if (!verifyBlsAggregate(voters.map((f) => blsKeyBytes(f.public_key)), sig, unhex(ref.finalityDigest))) {
            throw new Error(`QC on ${q.certifiedBlock} does not verify`);
        }
        return {digest: ref.finalityDigest, voters: voters.length, qc: hex(rlpEncode([bits, sig]))};
    });
}

export async function captureSavanna(network: string, snapshot: string, rpcUrl?: string): Promise<SavannaCapture> {
    const net = NETWORKS[network];
    const base = rpcUrl ?? net.rpc;
    const s = parseSnapshotBlockState(snapshot);
    const info = await rpc(base, "/v1/chain/get_info", {});
    if (!net.caip2.endsWith(info.chain_id.slice(0, 32))) throw new Error(`RPC chain ${info.chain_id} is not ${network}`);
    const qcs: SavannaCapture["qcs"] = [];
    let headTime = "";
    for (const ref of s.refs) {
        const carrier = await rpc(base, "/v1/chain/get_block", {block_num_or_id: ref.num + 1});
        if (ref.num + 1 === s.headNum) {
            if ("0x" + carrier.id !== s.headId) throw new Error("RPC head block differs from snapshot head");
            headTime = carrier.timestamp;
        }
        const qc = carrier.qc_extension?.qc;
        if (!qc || qc.block_num !== ref.num) throw new Error(`block ${ref.num + 1} carries no QC on ${ref.num}`);
        if (qc.pending_policy_sig || qc.active_policy_sig.weak_votes) throw new Error("QC has weak votes or a pending policy signature");
        qcs.push({carrierBlock: ref.num + 1, certifiedBlock: ref.num, strongVotes: qc.active_policy_sig.strong_votes, sig: qc.active_policy_sig.sig});
    }
    const next = await rpc(base, "/v1/chain/get_block", {block_num_or_id: s.headNum + 1});
    const fin = await rpc(base, "/v1/chain/get_finalizer_info", {});
    const policy = fin.active_finalizer_policy as FinalizerPolicyJson;
    if (policy.generation !== s.finalizerPolicyGeneration) {
        throw new Error(`finalizer policy rotated since the snapshot (${s.finalizerPolicyGeneration} -> ${policy.generation}); use a newer snapshot`);
    }
    const cap: SavannaCapture = {
        network,
        caip2: net.caip2,
        chainId: info.chain_id,
        capturedAt: new Date().toISOString(),
        snapshot: {headNum: s.headNum, headId: s.headId, headTime},
        refs: s.refs,
        validationTree: {mask: s.mask, subtrees: s.subtrees, validationMroots: s.validationMroots},
        lastPendingPolicyDigest: s.lastPendingPolicyDigest,
        lastPendingStartTimestamp: s.lastPendingStartTimestamp,
        policy,
        policyPack: hex(packFinalizerPolicy(policy)),
        qcs,
        nextHeaderFinalityMroot: "0x" + next.action_mroot
    };
    checkCapture(cap);
    return cap;
}

export function loadSavannaCapture(network = "jungle4"): SavannaCapture {
    return JSON.parse(readFileSync(path.join(FIXTURE_DIR, `${network}.json`), "utf8"));
}

/// Verifier inputs: the packed policy and, per QC, RLP([bitset, sig192]) with the signed digest.
export function savannaLiveInputs(c: SavannaCapture) {
    const checked = checkCapture(c);
    return {
        policyPack: c.policyPack as `0x${string}`,
        generation: c.policy.generation,
        threshold: c.policy.threshold,
        finalizers: c.policy.finalizers.length,
        policyDigest: c.lastPendingPolicyDigest as `0x${string}`,
        qcs: c.qcs.map((q, i) => ({
            certifiedBlock: q.certifiedBlock,
            voters: checked[i].voters,
            qc: checked[i].qc as `0x${string}`,
            digest: checked[i].digest as `0x${string}`
        }))
    };
}

export function emitFoundryFixture(c: SavannaCapture): string {
    const out = {network: c.network, caip2: c.caip2, ...savannaLiveInputs(c)};
    mkdirSync(FOUNDRY_DIR, {recursive: true});
    const file = path.join(FOUNDRY_DIR, `vaulta-${c.network}.json`);
    writeFileSync(file, JSON.stringify(out, null, 1) + "\n");
    return file;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
    const arg = (k: string) => (process.argv.includes(k) ? process.argv[process.argv.indexOf(k) + 1] : undefined);
    const network = arg("--network") ?? "jungle4";
    const snapshot = arg("--snapshot");
    if (snapshot) {
        const cap = await captureSavanna(network, snapshot, arg("--rpc"));
        mkdirSync(FIXTURE_DIR, {recursive: true});
        writeFileSync(path.join(FIXTURE_DIR, `${network}.json`), JSON.stringify(cap, null, 1) + "\n");
        console.log(`${network}: snapshot head ${cap.snapshot.headNum}, ${cap.qcs.length} QCs (${cap.qcs.map((q) => q.certifiedBlock).join(", ")}) verified, policy gen ${cap.policy.generation}`);
    }
    console.log(`wrote ${emitFoundryFixture(loadSavannaCapture(network))}`);
}
