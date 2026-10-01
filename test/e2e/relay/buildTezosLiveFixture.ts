import {mkdirSync, readFileSync, writeFileSync} from "node:fs";
import {dirname, resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {encodeAbiParameters, type Hex} from "viem";
import {bls12_381 as bls} from "@noble/curves/bls12-381";
import {p256} from "@noble/curves/p256";
import {secp256k1} from "@noble/curves/secp256k1";
import {ed25519} from "@noble/curves/ed25519";
import * as C from "./tezos/codec.js";
import {pathProof, proofRoot} from "./tezos/irmin.js";
import {parseSampler, slotOwner, type Sampler} from "./tezos/sampler.js";

/// Tezos live fixture: capture (`--refresh`) and proof building for TezosVerifier.
///
/// The context commit in header N+1 is `commit(tree(post-state of N), parents = [header(N).context],
/// date = timestamp(N), author "Tezos", message "lvl N, fit:(…), round r, k ops")`.
///
/// Capture from a public Tezos mainnet RPC that serves `context/merkle_tree_v2`:
///  - rotation anchor (one cycle before L): its state already fixed L's cycle rights, so a bundle
///    verified from it moves the anchor across a cycle boundary (the Tezos "validator-set rotation");
///  - anchor block A (head − 30): the context tree root of its post-state and the proofs of the
///    attested cycle's delegate sampler and random seed under it;
///  - attested level L (head − 8): block L's payload fields, the raw header of block L−1, block
///    L−2's commit fields, and every attestation for L (included in block L+1);
///  - proofs under the post-state of block L−2 (committed by header L−1): a tzBTC ledger big_map
///    entry and the Etherlink smart rollup's last cemented commitment.
///
/// Built: the ABI-encoded `TezosLightClient.FinalityProof` with (a) a one-transaction signature set
/// (the tz4 aggregate, tz2, tz3 and the largest tz1 attesters inline) and (b) a cached set (all
/// tz1/tz3 signatures recorded in TezosSignatureCache first), plus the context value proofs.
///
/// Run: npx tsx test/e2e/relay/buildTezosLiveFixture.ts --refresh   (or without flag: rebuild from capture)

const HERE = dirname(fileURLToPath(import.meta.url));
export const TEZOS_FIXTURE_DIR = resolve(HERE, "../fixtures/tezos-live");
const RPC = process.env.TEZOS_RPC ?? "https://rpc.tzbeta.net";

export const TZBTC = {contract: "KT1PWx2mnDueood7fEmfbBDKx1D9BAnnXitn", bigMap: 31};
export const ETHERLINK_ROLLUP = "sr1Ghq66tYK9y3r8CC1Tf8i8m5nxh8nTvZEf";

// Mainnet constants (GET /chains/main/blocks/head/context/constants, protocol 025 PsUshuai).
export const PROFILE = {committeeSize: 7000, threshold: 4667, consensusRightsDelay: 2};

// ── RPC ─────────────────────────────────────────────────────────────────────

async function get(path: string): Promise<any> {
    for (let attempt = 0; ; attempt++) {
        const r = await fetch(`${RPC}${path}`);
        if (r.ok) return r.json();
        if (attempt >= 4) throw new Error(`${path}: HTTP ${r.status}`);
        await new Promise((res) => setTimeout(res, 1000 * (attempt + 1)));
    }
}

const contractHex = (kt1: string): string => "01" + C.b58payload(kt1, 20).toString("hex") + "00";
const rollupHex = (sr1: string): string => C.b58payload(sr1, 20).toString("hex");

async function capture() {
    const head = await get("/chains/main/blocks/head/header");
    const A = head.level - 30;
    const L = head.level - 8;
    const meta = await get(`/chains/main/blocks/${L}/metadata`);
    const cycle: number = meta.level_info.cycle;
    const cyclePosition: number = meta.level_info.cycle_position;
    const metaA = await get(`/chains/main/blocks/${A}/metadata`);
    const constants = await get(`/chains/main/blocks/${L}/context/constants`);

    const anchorSampler = await get(`/chains/main/blocks/${A}/context/merkle_tree_v2/cycle/${cycle}/delegate_sampler_state`);
    const anchorSeed = await get(`/chains/main/blocks/${A}/context/merkle_tree_v2/cycle/${cycle}/random_seed`);
    // Rotation: an anchor one cycle earlier, whose state already fixed cycle `cycle`'s rights.
    const P = L - constants.blocks_per_cycle - 50;
    const metaP = await get(`/chains/main/blocks/${P}/metadata`);
    const prevSampler = await get(`/chains/main/blocks/${P}/context/merkle_tree_v2/cycle/${cycle}/delegate_sampler_state`);
    const prevSeed = await get(`/chains/main/blocks/${P}/context/merkle_tree_v2/cycle/${cycle}/random_seed`);

    const blockL = await get(`/chains/main/blocks/${L}`);
    const blockL1 = await get(`/chains/main/blocks/${L + 1}`);
    const rawHeaderPrev: string = await get(`/chains/main/blocks/${L - 1}/header/raw`);
    const headerPrev = await get(`/chains/main/blocks/${L - 1}/header`);
    const blockS = await get(`/chains/main/blocks/${L - 2}`); // state block

    // tzBTC ledger entry that exists at the state block.
    const keys = await (await fetch(`https://api.tzkt.io/v1/bigmaps/${TZBTC.bigMap}/keys?active=true&limit=1&sort.desc=lastLevel&lastLevel.lt=${L - 2}`)).json();
    const keyHash: string = keys[0].hash;
    const keyHex = C.b58payload(keyHash, 32).toString("hex");
    const tzbtcProof = await get(`/chains/main/blocks/${L - 2}/context/merkle_tree_v2/big_maps/index/${TZBTC.bigMap}/contents/${keyHex}/data`);
    const tzbtcStorage = await get(`/chains/main/blocks/${L - 2}/context/merkle_tree_v2/contracts/index/${contractHex(TZBTC.contract)}/data/storage`);
    const sr = rollupHex(ETHERLINK_ROLLUP);
    const lccProof = await get(`/chains/main/blocks/${L - 2}/context/merkle_tree_v2/smart_rollup/index/${sr}/data/last_cemented_commitment`);
    const lccRoot = proofRoot(lccProof);
    const lcc = pathProof(lccRoot.tree, ["data", "smart_rollup", "index", sr, "data", "last_cemented_commitment"]).value;
    const commitmentProof = await get(`/chains/main/blocks/${L - 2}/context/merkle_tree_v2/smart_rollup/index/${sr}/commitments/${lcc.toString("hex")}/data`);

    return {
        rpc: RPC,
        capturedAt: new Date().toISOString(),
        chainId: blockL.chain_id,
        protocol: blockL.protocol,
        anchorLevel: A,
        anchorCycle: metaA.level_info.cycle,
        level: L,
        cycle,
        cyclePosition,
        constants: {
            blocks_per_cycle: constants.blocks_per_cycle,
            consensus_committee_size: constants.consensus_committee_size,
            consensus_threshold_size: constants.consensus_threshold_size,
            consensus_rights_delay: constants.consensus_rights_delay,
        },
        anchorSampler,
        anchorSeed,
        prevAnchorLevel: P,
        prevAnchorCycle: metaP.level_info.cycle,
        prevSampler,
        prevSeed,
        blockLHeader: blockL.header,
        blockLPayloadOps: blockL.operations.slice(1).map((pass: any[]) => pass.map((o: any) => o.hash)),
        attestationOps: blockL1.operations[0],
        rawHeaderPrev,
        headerPrev,
        stateBlock: {
            header: blockS.header,
            opCount: blockS.operations.reduce((n: number, p: any[]) => n + p.length, 0),
        },
        tzbtc: {keyHash, key: keys[0].key, proof: tzbtcProof, storageProof: tzbtcStorage},
        etherlink: {rollup: ETHERLINK_ROLLUP, lccProof, commitmentProof},
    };
}

// ── derivation ────────────────────────────────────────────────────────────

function operationListHash(opHashes: string[]): Buffer {
    const leaves = opHashes.map((h) => C.blake2b256(C.b58payload(h, 32)));
    if (leaves.length === 0) return C.blake2b256(Buffer.alloc(0));
    if (leaves.length === 1) return leaves[0];
    const node = (x: Buffer, y: Buffer) => C.blake2b256(C.cat(x, y));
    const a: Buffer[] = [...leaves, leaves[leaves.length - 1]];
    const step = (n: number): Buffer => {
        const m = Math.floor((n + 1) / 2);
        for (let i = 0; i < m; i++) a[i] = node(a[2 * i], a[2 * i + 1]);
        a[m] = node(a[n], a[n]);
        if (m === 1) return a[0];
        if (m % 2 === 0) return step(m);
        a[m + 1] = a[m];
        return step(m + 1);
    };
    return step(leaves.length);
}

function commitTail(state: any): {tail: Buffer; message: string} {
    const h = state.header;
    const fit: string[] = h.fitness;
    const lvl = h.level;
    const locked = fit[2] === "" ? "unlocked" : `locked: ${parseInt(fit[2], 16)}`;
    const predRaw = Buffer.from(fit[3], "hex").readInt32BE(0);
    const predRound = -1 - predRaw;
    const round = parseInt(fit[4], 16);
    const message = `lvl ${lvl}, fit:(${lvl}, ${locked}, ${predRound === 0 ? "" : "-"}${predRound}, ${round}), round ${round}, ${state.opCount} ops`;
    const ts = BigInt(Math.floor(Date.parse(h.timestamp) / 1000));
    const msg = Buffer.from(message, "utf8");
    const tail = C.cat(C.u64(1), C.u64(32), C.b58payload(h.context, 32), C.i64(ts), C.u64(5), Buffer.from("Tezos"), C.u64(msg.length), msg);
    return {tail, message};
}

const pad64 = (v: bigint): Buffer => Buffer.from(v.toString(16).padStart(128, "0"), "hex");
const g1Uncompressed = (k: Bytes): Buffer => {
    const a = bls.G1.ProjectivePoint.fromHex(k).toAffine();
    return C.cat(pad64(a.x), pad64(a.y));
};
const g2Uncompressed = (s: Bytes): Buffer => {
    const a = bls.G2.ProjectivePoint.fromHex(s).toAffine();
    return C.cat(pad64(a.x.c0), pad64(a.x.c1), pad64(a.y.c0), pad64(a.y.c1));
};
type Bytes = Uint8Array;

export interface AttesterEntry {
    signer: number;
    slot: number;
    branch: Hex;
    withDal: boolean;
    dal: Hex;
    signature: Hex;
    y: Hex;
    scheme: number;
    key: Hex;
    digest: Hex;
    power: number;
}

export const FINALITY_TYPE = [
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
            {
                name: "attestations",
                type: "tuple[]",
                components: [
                    {name: "signer", type: "uint16"},
                    {name: "slot", type: "uint16"},
                    {name: "branch", type: "bytes32"},
                    {name: "withDal", type: "bool"},
                    {name: "dal", type: "bytes"},
                    {name: "signature", type: "bytes"},
                    {name: "y", type: "bytes32"},
                ],
            },
            {
                name: "aggregates",
                type: "tuple[]",
                components: [
                    {name: "branch", type: "bytes32"},
                    {name: "signers", type: "uint16[]"},
                    {name: "keys", type: "bytes[]"},
                    {name: "dal", type: "bytes[]"},
                    {name: "companionKeys", type: "bytes[]"},
                    {name: "signature", type: "bytes"},
                ],
            },
        ],
    },
] as const;

export const CACHE_ENTRY_TYPE = [
    {
        type: "tuple[]",
        components: [
            {name: "scheme", type: "uint8"},
            {name: "key", type: "bytes"},
            {name: "y", type: "bytes32"},
            {name: "digest", type: "bytes32"},
            {name: "signature", type: "bytes"},
        ],
    },
] as const;

const ZERO32 = ("0x" + "00".repeat(32)) as Hex;

export function derive(raw: any) {
    const chainId = C.chainIdBytes(raw.chainId);
    // 1. rights under the anchor
    const samp = proofRoot(raw.anchorSampler);
    const seedP = proofRoot(raw.anchorSeed);
    if (!samp.root.equals(seedP.root)) throw new Error("anchor proofs disagree on the root");
    const cyc = String(raw.cycle);
    const sp = pathProof(samp.tree, ["data", "cycle", cyc, "delegate_sampler_state"]);
    const sd = pathProof(seedP.tree, ["data", "cycle", cyc, "random_seed"]);
    const sampler: Sampler = parseSampler(sp.value);
    const owners = [...Array(PROFILE.committeeSize).keys()].map((s) => slotOwner(sampler, sd.value, raw.cyclePosition, s));
    const power = new Map<number, number>();
    for (const o of owners) power.set(o, (power.get(o) ?? 0) + 1);

    // 2. payload
    const hdr = C.unhex(raw.rawHeaderPrev);
    const ph = C.parseHeader(hdr);
    if (ph.level !== raw.level - 1) throw new Error("predecessor header level");
    const blockHash = C.blake2b256(hdr);
    if (!blockHash.equals(C.blockHashBytes(raw.blockLHeader.predecessor))) throw new Error("predecessor hash");
    const opsHash = operationListHash(raw.blockLPayloadOps.flat());
    const payloadRound: number = raw.blockLHeader.payload_round;
    const payload = C.blake2b256(C.cat(blockHash, C.i32(payloadRound), opsHash));
    if (!payload.equals(C.b58payload(raw.blockLHeader.payload_hash, 32))) throw new Error("payload hash");

    // 3. attestations
    const attesters: AttesterEntry[] = [];
    let aggregate: any = undefined;
    let round = -1;
    for (const op of raw.attestationOps) {
        const branch = C.blockHashBytes(op.branch);
        const sig = C.decodeSignature(op.signature);
        for (const c of op.contents) {
            const cc = c.kind === "attestations_aggregate" ? c.consensus_content : c;
            if (cc.level !== raw.level) continue;
            if (!C.b58payload(cc.block_payload_hash, 32).equals(payload)) throw new Error("attestation payload");
            if (round === -1) round = cc.round;
            if (cc.round !== round) throw new Error("mixed rounds");
            if (c.kind === "attestations_aggregate") {
                const opb = C.blsModeAttestation({branch, level: cc.level, round: cc.round, payloadHash: payload});
                const signers: number[] = [];
                const keys: Hex[] = [];
                const dal: Hex[] = [];
                const comps: Hex[] = [];
                let agg = bls.G1.ProjectivePoint.ZERO;
                for (const m of c.committee) {
                    const idx = owners[m.slot];
                    const e = sampler.support[idx];
                    if (e.scheme !== C.Scheme.Bls) throw new Error("aggregate member is not tz4");
                    signers.push(idx);
                    keys.push(C.hex(g1Uncompressed(e.key)));
                    agg = agg.add(bls.G1.ProjectivePoint.fromHex(e.key));
                    if (m.dal_attestation !== undefined) {
                        const bits = C.zToBits(BigInt(m.dal_attestation));
                        dal.push(C.hex(C.cat(Buffer.from([1]), bits)));
                        comps.push(C.hex(g1Uncompressed(e.companion!)));
                        const z = C.blake2b256(C.cat(C.blake2b160(e.key), C.blake2b160(e.companion!), opb, bits));
                        let zi = 0n;
                        for (let i = z.length - 1; i >= 0; i--) zi = (zi << 8n) | BigInt(z[i]);
                        agg = agg.add(bls.G1.ProjectivePoint.fromHex(e.companion!).multiply(zi % bls.params.r || bls.params.r));
                    } else {
                        dal.push("0x");
                        comps.push("0x");
                    }
                }
                const msg = C.cat(Buffer.from([0x13]), chainId, opb);
                const H = bls.G2.hashToCurve(msg, {DST: "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"});
                if (!bls.verify(sig, H as never, agg)) throw new Error("aggregate signature (off-chain check)");
                aggregate = {
                    branch: C.hex(branch),
                    signers,
                    keys,
                    dal,
                    companionKeys: comps,
                    signature: C.hex(g2Uncompressed(sig)),
                    power: signers.reduce((n, i) => n + (power.get(i) ?? 0), 0),
                };
                continue;
            }
            const withDal = c.kind === "attestation_with_dal";
            const dalZ = withDal ? C.zarithZ(BigInt(c.dal_attestation)) : Buffer.alloc(0);
            const bytes = C.attestationSigningBytes({
                chainId,
                branch,
                slot: c.slot,
                level: c.level,
                round: c.round,
                payloadHash: payload,
                dal: withDal ? BigInt(c.dal_attestation) : undefined,
            });
            const digest = C.blake2b256(bytes);
            const idx = owners[c.slot];
            const e = sampler.support[idx];
            let y = ZERO32;
            let ok = false;
            if (e.scheme === C.Scheme.Ed25519) ok = ed25519.verify(sig, digest, e.key);
            else if (e.scheme === C.Scheme.Secp256k1) {
                ok = secp256k1.verify(sig, digest, e.key, {lowS: false});
                y = C.hex(pad64(secp256k1.ProjectivePoint.fromHex(e.key).toAffine().y).subarray(32));
            } else if (e.scheme === C.Scheme.P256) {
                ok = p256.verify(sig, digest, e.key, {lowS: false});
                y = C.hex(pad64(p256.ProjectivePoint.fromHex(e.key).toAffine().y).subarray(32));
            }
            if (!ok) throw new Error(`attestation slot ${c.slot}: off-chain signature check failed`);
            attesters.push({
                signer: idx,
                slot: c.slot,
                branch: C.hex(branch),
                withDal,
                dal: C.hex(dalZ),
                signature: C.hex(sig),
                y,
                scheme: e.scheme,
                key: C.hex(e.key),
                digest: C.hex(digest),
                power: power.get(idx) ?? 0,
            });
        }
    }
    if (!aggregate) throw new Error("no tz4 aggregate in the block");

    // 4. state root and commit
    const valueProof = (json: any, steps: string[]) => {
        const r = proofRoot(json);
        const pp = pathProof(r.tree, steps);
        return {root: r.root, steps, proof: C.hex(pp.proof), value: C.hex(pp.value)};
    };
    const keyHex = C.b58payload(raw.tzbtc.keyHash, 32).toString("hex");
    const tzbtc = valueProof(raw.tzbtc.proof, ["data", "big_maps", "index", String(TZBTC.bigMap), "contents", keyHex, "data"]);
    const storage = valueProof(raw.tzbtc.storageProof, ["data", "contracts", "index", contractHex(TZBTC.contract), "data", "storage"]);
    const sr = rollupHex(raw.etherlink.rollup);
    const lcc = valueProof(raw.etherlink.lccProof, ["data", "smart_rollup", "index", sr, "data", "last_cemented_commitment"]);
    const commitment = valueProof(raw.etherlink.commitmentProof, [
        "data",
        "smart_rollup",
        "index",
        sr,
        "commitments",
        lcc.value.slice(2),
        "data",
    ]);
    for (const v of [storage, lcc, commitment]) if (!v.root.equals(tzbtc.root)) throw new Error("state proofs disagree on the root");
    const root = tzbtc.root;
    const {tail, message} = commitTail(raw.stateBlock);
    if (!C.blake2b256(C.cat(C.u64(32), root, tail)).equals(ph.context)) throw new Error(`commit preimage (${message})`);

    // Etherlink commitment: version byte ‖ compressed_state ‖ inbox_level ‖ predecessor ‖ ticks.
    const cv = C.unhex(commitment.value);
    if (!C.blake2b256(cv.subarray(1)).equals(C.unhex(lcc.value))) throw new Error("etherlink commitment hash");

    // 5. signature sets
    const thr = PROFILE.threshold;
    const tz2 = attesters.filter((a) => a.scheme === 1);
    const tz3 = attesters.filter((a) => a.scheme === 2).sort((a, b) => b.power - a.power);
    const tz1 = attesters.filter((a) => a.scheme === 0).sort((a, b) => b.power - a.power);
    const inline: AttesterEntry[] = [...tz2];
    let pw = aggregate.power + tz2.reduce((n, a) => n + a.power, 0);
    for (const a of [...tz3, ...tz1]) {
        if (pw >= thr + 20) break;
        inline.push(a);
        pw += a.power;
    }
    const totalPower = aggregate.power + attesters.reduce((n, a) => n + a.power, 0);

    const prevS = proofRoot(raw.prevSampler);
    const prevD = proofRoot(raw.prevSeed);
    if (!prevS.root.equals(prevD.root)) throw new Error("rotation anchor proofs disagree on the root");
    const prevSp = pathProof(prevS.tree, ["data", "cycle", cyc, "delegate_sampler_state"]);
    const prevSd = pathProof(prevD.tree, ["data", "cycle", cyc, "random_seed"]);
    if (!prevSp.value.equals(sp.value) || !prevSd.value.equals(sd.value)) throw new Error("rights differ between anchors");

    const finality = (atts: AttesterEntry[], cached: boolean, rights = {sampler: sp.proof, seed: sd.proof}) =>
        encodeAbiParameters(FINALITY_TYPE, [
            {
                level: raw.level,
                round,
                payloadRound,
                operationsHash: C.hex(opsHash),
                predecessorHeader: C.hex(hdr),
                contextRoot: C.hex(root),
                commitTail: C.hex(tail),
                samplerProof: C.hex(rights.sampler),
                seedProof: C.hex(rights.seed),
                attestations: atts.map((a) => ({
                    signer: a.signer,
                    slot: a.slot,
                    branch: a.branch,
                    withDal: a.withDal,
                    dal: a.dal,
                    signature: cached && a.scheme !== 1 ? "0x" : a.signature,
                    y: a.y,
                })),
                aggregates: [
                    {
                        branch: aggregate.branch,
                        signers: aggregate.signers,
                        keys: aggregate.keys,
                        dal: aggregate.dal,
                        companionKeys: aggregate.companionKeys,
                        signature: aggregate.signature,
                    },
                ],
            },
        ]);
    const cachedSet = attesters;
    const cacheBatches = (scheme: number, per: number) => {
        const xs = cachedSet.filter((a) => a.scheme === scheme);
        const out: Hex[] = [];
        for (let i = 0; i < xs.length; i += per) {
            out.push(
                encodeAbiParameters(CACHE_ENTRY_TYPE, [
                    xs.slice(i, i + per).map((a) => ({scheme: a.scheme, key: a.key, y: a.y, digest: a.digest, signature: a.signature})),
                ]),
            );
        }
        return out;
    };

    const anchorRoot = samp.root;
    return {
        network: "mainnet",
        chainId: raw.chainId,
        chainIdBytes: C.hex(chainId),
        caip2: `tezos:${raw.chainId}`,
        protocolLevel: raw.blockLHeader.proto,
        profile: {
            eraFirstLevel: raw.level - raw.cyclePosition,
            eraFirstCycle: raw.cycle,
            blocksPerCycle: raw.constants.blocks_per_cycle,
            committeeSize: raw.constants.consensus_committee_size,
            threshold: raw.constants.consensus_threshold_size,
        },
        anchorLevel: raw.anchorLevel,
        anchorRoot: C.hex(anchorRoot),
        anchor: encodeAbiParameters([{type: "uint32"}, {type: "bytes32"}], [raw.anchorLevel, C.hex(anchorRoot)]),
        level: raw.level,
        cycle: raw.cycle,
        cyclePosition: raw.cyclePosition,
        stateLevel: raw.level - 2,
        stateRoot: C.hex(root),
        newAnchor: encodeAbiParameters([{type: "uint32"}, {type: "bytes32"}], [raw.level - 2, C.hex(root)]),
        commitMessage: message,
        samplerSize: sampler.support.length,
        samplerValue: C.hex(sp.value),
        seed: C.hex(sd.value),
        signerSupport: [...new Set([...attesters.map((a) => a.signer), ...aggregate.signers])],
        samplerBytes: sp.value.length,
        supportBySchemes: [0, 1, 2, 3].map((k) => sampler.support.filter((s) => s.scheme === k).length),
        attesters: attesters.length,
        aggregateMembers: aggregate.signers.length,
        aggregatePower: aggregate.power,
        powerByScheme: [0, 1, 2].map((k) => attesters.filter((a) => a.scheme === k).reduce((n, a) => n + a.power, 0)),
        totalPower,
        inlineSchemes: [0, 1, 2].map((k) => inline.filter((a) => a.scheme === k).length),
        inlinePower: pw,
        finalityInline: finality(inline, false),
        finalityCached: finality(cachedSet, true),
        prevAnchorLevel: raw.prevAnchorLevel,
        prevAnchorCycle: raw.prevAnchorCycle,
        prevAnchor: encodeAbiParameters([{type: "uint32"}, {type: "bytes32"}], [raw.prevAnchorLevel, C.hex(prevS.root)]),
        finalityRotationInline: finality(inline, false, {sampler: prevSp.proof, seed: prevSd.proof}),
        finalityRotationCached: finality(cachedSet, true, {sampler: prevSp.proof, seed: prevSd.proof}),
        cacheEd25519: cacheBatches(0, 20),
        cacheP256: cacheBatches(2, 40),
        tzbtc: {steps: tzbtc.steps, proof: tzbtc.proof, value: tzbtc.value},
        tzbtcStorage: {steps: storage.steps, proof: storage.proof, value: storage.value},
        etherlink: {
            rollup: raw.etherlink.rollup,
            rollupHex: "0x" + sr,
            lccSteps: lcc.steps,
            lccProof: lcc.proof,
            lcc: lcc.value,
            commitmentSteps: commitment.steps,
            commitmentProof: commitment.proof,
            commitment: commitment.value,
            compressedState: C.hex(cv.subarray(1, 33)),
            inboxLevel: cv.readInt32BE(33),
        },
    };
}

async function main() {
    mkdirSync(TEZOS_FIXTURE_DIR, {recursive: true});
    const capturePath = resolve(TEZOS_FIXTURE_DIR, "capture.json");
    let raw: any;
    if (process.argv.includes("--refresh")) {
        raw = await capture();
        writeFileSync(capturePath, JSON.stringify(raw));
    } else {
        raw = JSON.parse(readFileSync(capturePath, "utf8"));
    }
    const derived = derive(raw);
    writeFileSync(resolve(TEZOS_FIXTURE_DIR, "mainnet.json"), JSON.stringify({derived}, null, 1) + "\n");
    console.log(
        `[tezos-live] L=${derived.level} cycle=${derived.cycle} anchor=${derived.anchorLevel} attesters=${derived.attesters}+agg(${derived.aggregateMembers}) ` +
            `power=${derived.totalPower} inline=${derived.inlineSchemes} (${derived.inlinePower})`,
    );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    main().catch((e) => {
        console.error(e);
        process.exit(1);
    });
}
