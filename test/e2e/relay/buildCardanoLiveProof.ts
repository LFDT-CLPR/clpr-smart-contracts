import {readFileSync, writeFileSync} from "node:fs";
import {bls12_381} from "@noble/curves/bls12-381";
import {blake2b} from "@noble/hashes/blake2b";
import {g1ToUncompressed, g2ToUncompressed} from "./bls.js";
import {bigintToTrimmedBuf, rlpEncode} from "../lib/rlp.js";
import {
    PART_KEYS,
    lotteryConstant,
    parseAvk,
    parseCertificate,
    part,
    phiFixed,
    protocolMessageHash,
    protocolParametersHash,
    verifyStm,
    type Certificate,
    type Params,
} from "./cardano/mithril.js";
import {decodeMKMapProof, verifyMKMapProof, type MKProof} from "./cardano/mkproof.js";
import {decode, raw, type Item} from "./cardano/cbor.js";
import {fetchBlocks} from "./cardano/n2n.js";

/// Builds CardanoMithrilVerifier proofs from REAL Mithril/Cardano data.
///
///   capture (--refresh): Mithril aggregator certificates + a CardanoBlocksTransactions proof (preprod),
///   the block itself from a public relay over Ouroboros node-to-node BlockFetch, and the mainnet
///   epoch-boundary certificates; written to test/e2e/fixtures/cardano-live/{preprod,mainnet}.json.
///   build: everything the verifier needs (anchor, RLP proofs), re-checked with the TS reference model.
///
///   npx tsx test/e2e/relay/buildCardanoLiveProof.ts --refresh

const FIX = new URL("../fixtures/cardano-live/", import.meta.url);
const AGG = (net: string) => `https://aggregator.release-${net}.api.mithril.network/aggregator`;
const KOIOS = "https://preprod.koios.rest/api/v1";
const RELAY = {host: "preprod-node.play.dev.cardano.org", port: 3001, magic: 1};

const G1 = bls12_381.G1.ProjectivePoint;
const G2 = bls12_381.G2.ProjectivePoint;
const int = (v: bigint | number) => bigintToTrimmedBuf(BigInt(v));
const be = (v: bigint, n: number) => Buffer.from(v.toString(16).padStart(n * 2, "0"), "hex");
export const hx = (b: Uint8Array) => "0x" + Buffer.from(b).toString("hex");

async function getJson(url: string, init?: RequestInit): Promise<any> {
    const r = await fetch(url, {...init, signal: AbortSignal.timeout(60_000)});
    if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
    return r.json();
}

// ── Anchor ───────────────────────────────────────────────────────────────────

export function anchorOf(epoch: bigint, cert: Certificate, params: Params = cert.params): Buffer {
    const {mant, exp} = lotteryConstant(params.phiF);
    return Buffer.concat([
        be(epoch, 8),
        Buffer.from(cert.avk.root),
        be(BigInt(cert.avk.nrLeaves), 8),
        be(cert.avk.totalStake, 8),
        be(params.k, 8),
        be(params.m, 8),
        be(BigInt(phiFixed(params.phiF)), 4),
        be(mant, 8),
        be(BigInt(-exp), 2),
    ]);
}

// ── Certificate encoding ([keyIds, values, signers, batchValues]) ───────────

/// `nextParams` (when known) renders next_protocol_parameters as k‖m‖φ (rotation); else the hash.
export function encodeCert(c: Certificate, nextParams?: Params): Buffer[] | any[] {
    const ids: Buffer[] = [];
    const vals: Buffer[] = [];
    for (const [k, v] of c.parts) {
        const id = PART_KEYS.indexOf(k as never);
        ids.push(int(id));
        if (k === "next_aggregate_verification_key") {
            const a = parseAvk(v);
            vals.push(Buffer.concat([Buffer.from(a.root), be(BigInt(a.nrLeaves), 8), be(a.totalStake, 8)]));
        } else if (k === "next_protocol_parameters") {
            if (nextParams && protocolParametersHash(nextParams) === v) {
                vals.push(Buffer.concat([be(nextParams.k, 8), be(nextParams.m, 8), be(BigInt(phiFixed(nextParams.phiF)), 4)]));
            } else vals.push(Buffer.from(v, "hex"));
        } else if (["current_epoch", "latest_block_number", "cardano_blocks_transactions_block_number_offset", "cardano_stake_distribution_epoch"].includes(k)) {
            vals.push(be(BigInt(v), 8));
        } else if (k === "next_aggregate_verification_key_snark") {
            vals.push(Buffer.from(v));
        } else {
            if (v.length !== 64) throw new Error(`part ${k}: unexpected length`);
            vals.push(Buffer.from(v, "hex"));
        }
    }
    const signers = c.signers.map((s, i) => {
        const leaf = c.batchIndices[i];
        const ix = s.indexes.map((x) => be(x, 4));
        return Buffer.concat([
            g1ToUncompressed(G1.fromHex(s.sigma)),
            g2ToUncompressed(G2.fromHex(s.vk)),
            Buffer.from(s.sigma), // the compressed bytes Mithril hashes
            Buffer.from(s.vk),
            be(s.stake, 8),
            be(BigInt(leaf), 4),
            ...ix,
        ]);
    });
    return [ids, vals, signers, Buffer.concat(c.batchValues.map((v) => Buffer.from(v)))];
}

// ── Inclusion / block / transaction ─────────────────────────────────────────

function singleLeaf(p: MKProof) {
    if (p.leaves.length !== 1) throw new Error("expected a single-leaf MKProof");
    return p.leaves[0];
}

export interface PreprodCapture {
    network: "preprod";
    rotationCert: any; // epoch e (carries next AVK for e+1)
    stateCert: any; // epoch e+1, CardanoBlocksTransactions
    nextCert: any; // a certificate of epoch e+1 (its metadata carries the e+1 parameters)
    proof: any; // /proof/v2/cardano-transaction response
    block: string; // hex CBOR [era, block]
    txHash: string;
    outputIndex: number;
    koiosOutput: any; // Koios view of that output (cross-check only)
}

export interface CardanoLiveProof {
    anchor: string;
    anchorEpoch: string;
    rotatedEpoch: string;
    txProof: string; // verifyTransactionOutput proof (7 items)
    txHash: string;
    blockHash: string;
    blockNumber: string;
    output: string;
    datum: string;
    scriptHash: string;
    stateEpochCertProof: string; // verifyCertificate([[], stateCert]) with the rotated anchor
    rotatedAnchor: string;
    nrIndices: number;
}

export function buildPreprod(cap: PreprodCapture): CardanoLiveProof {
    const rot = parseCertificate(cap.rotationCert);
    const st = parseCertificate(cap.stateCert);
    const nxt = parseCertificate(cap.nextCert);
    if (st.epoch !== rot.epoch + 1n) throw new Error("state cert must be one epoch after the rotation cert");
    // reference checks
    for (const c of [rot, st]) if (protocolMessageHash(c.parts) !== c.signedMessage) throw new Error("message hash");
    const r1 = verifyStm(rot);
    const r2 = verifyStm(st);
    if (!r1.ok || !r2.ok) throw new Error(`STM: ${r1.reason ?? ""} ${r2.reason ?? ""}`);
    const nextAvk = parseAvk(part(rot, "next_aggregate_verification_key")!);
    if (!Buffer.from(nextAvk.root).equals(Buffer.from(st.avk.root))) throw new Error("AVK chaining");
    if (protocolParametersHash(nxt.params) !== part(rot, "next_protocol_parameters")) throw new Error("params chaining");

    const anchor = anchorOf(rot.epoch, rot);
    const rotated = anchorOf(st.epoch, st, nxt.params);

    const mp = decodeMKMapProof(cap.proof.certified_transactions.proof);
    const root = verifyMKMapProof(mp);
    if (Buffer.from(root).toString("hex") !== part(st, "cardano_blocks_transactions_merkle_root")) throw new Error("MKMap root");
    if (mp.subs.length !== 1) throw new Error("expected one block range");
    const sub = mp.subs[0];
    const inner = singleLeaf(sub.proof.master);
    const outer = singleLeaf(mp.master);
    const item = cap.proof.certified_transactions.items[0];
    if (Buffer.from(inner.node).toString() !== `Tx/${item.transaction_hash}/${item.block_hash}/${item.block_number}/${item.slot_number}`)
        throw new Error("leaf string");

    const blk = Buffer.from(cap.block, "hex");
    const top = decode(blk) as Item & {t: "array"};
    const b = top.v[1] as Item & {t: "array"};
    const header = raw(blk, b.v[0]);
    const H = (x: Item) => Buffer.from(blake2b(raw(blk, x), {dkLen: 32}));
    if (H(b.v[0]).toString("hex") !== item.block_hash) throw new Error("block hash");
    const bodies = b.v[1] as Item & {t: "array"};
    const txIndex = bodies.v.findIndex((tb) => H(tb).toString("hex") === cap.txHash);
    if (txIndex < 0) throw new Error("tx not in block");
    const invalid = raw(blk, b.v[4]);
    const emptyInvalid = invalid.length === 1 && invalid[0] === 0x80;
    const txBody = raw(blk, bodies.v[txIndex]);

    const inclusion = [
        int(item.block_number),
        int(item.slot_number),
        int(inner.pos),
        int(sub.proof.master.mmrSize),
        sub.proof.master.items.map((x) => Buffer.from(x)),
        int(sub.start),
        int(sub.end),
        int(outer.pos),
        int(mp.master.mmrSize),
        mp.master.items.map((x) => Buffer.from(x)),
    ];
    const body = [emptyInvalid ? H(bodies) : Buffer.from(raw(blk, bodies)), H(b.v[2]), H(b.v[3]), Buffer.from(invalid), int(txIndex)];
    const txProof = rlpEncode([
        [encodeCert(rot, nxt.params)],
        encodeCert(st),
        inclusion,
        Buffer.from(header),
        body,
        Buffer.from(txBody),
        int(cap.outputIndex),
    ] as never);

    // Output CBOR (map form) and its inline datum
    const tb = decode(txBody) as Item & {t: "map"};
    const outs = tb.v.find(([k]) => (k as any).v === 1n)![1] as Item & {t: "array"};
    const out = outs.v[cap.outputIndex] as Item & {t: "map"};
    const addr = out.v.find(([k]) => (k as any).v === 0n)![1] as any;
    const dopt = out.v.find(([k]) => (k as any).v === 2n)?.[1] as any;
    const datum = dopt ? Buffer.from(dopt.v[1].v.v) : Buffer.alloc(0);

    return {
        anchor: hx(anchor),
        anchorEpoch: rot.epoch.toString(),
        rotatedEpoch: st.epoch.toString(),
        txProof: hx(txProof),
        txHash: "0x" + cap.txHash,
        blockHash: "0x" + item.block_hash,
        blockNumber: String(item.block_number),
        output: hx(raw(txBody, out)),
        datum: hx(datum),
        scriptHash: hx(Buffer.from(addr.v).subarray(1, 29)),
        stateEpochCertProof: hx(rlpEncode([[], encodeCert(st)] as never)),
        rotatedAnchor: hx(rotated),
        nrIndices: r2.nrIndices,
    };
}

export interface MainnetCapture {
    network: "mainnet";
    rotationCert: any;
    stateCert: any;
    nextCert: any;
}

export function buildMainnet(cap: MainnetCapture) {
    const rot = parseCertificate(cap.rotationCert);
    const st = parseCertificate(cap.stateCert);
    const nxt = parseCertificate(cap.nextCert);
    for (const c of [rot, st]) {
        const r = verifyStm(c);
        if (!r.ok) throw new Error(`mainnet STM ${r.reason}`);
    }
    return {
        anchor: hx(anchorOf(rot.epoch, rot)),
        anchorEpoch: rot.epoch.toString(),
        rotatedAnchor: hx(anchorOf(st.epoch, st, nxt.params)),
        // one certificate, no rotation (typical bundle certificate cost)
        certProof: hx(rlpEncode([[], encodeCert(rot)] as never)),
        // rotation + a certificate of the next epoch
        rotationProof: hx(rlpEncode([[encodeCert(rot, nxt.params)], encodeCert(st)] as never)),
        signedMessage: "0x" + Buffer.from(st.signedMessage).toString("hex"),
        signers: st.signers.length,
        nrIndices: st.signers.reduce((a, s) => a + s.indexes.length, 0),
        params: {k: st.params.k.toString(), m: st.params.m.toString(), phiF: st.params.phiF},
    };
}

export const loadCapture = <T>(name: string): T => JSON.parse(readFileSync(new URL(`${name}.json`, FIX), "utf8"));

// ── Capture ──────────────────────────────────────────────────────────────────

async function boundaryCerts(net: string) {
    const msd = await getJson(`${AGG(net)}/artifact/mithril-stake-distributions`);
    const latest = msd.reduce((a: any, b: any) => (b.epoch > a.epoch ? b : a));
    const first = await getJson(`${AGG(net)}/certificate/${latest.certificate_hash}`);
    const prev = await getJson(`${AGG(net)}/certificate/${first.previous_hash}`);
    if (prev.epoch !== first.epoch - 1) throw new Error(`${net}: previous of the first epoch cert is epoch ${prev.epoch}`);
    return {rotationCert: prev, nextCert: first, epoch: first.epoch};
}

async function capturePreprod(): Promise<PreprodCapture> {
    const {rotationCert, nextCert, epoch} = await boundaryCerts("preprod");
    const certs = await getJson(`${AGG("preprod")}/certificates`);
    const bt = certs.find((c: any) => c.signed_entity_type.CardanoBlocksTransactions && c.epoch === epoch);
    if (!bt) throw new Error("no CardanoBlocksTransactions certificate in the current epoch yet");
    const latest = bt.signed_entity_type.CardanoBlocksTransactions[1];
    // a recent block (well inside the certified range) with a transaction that has an inline datum
    const blocks = await getJson(`${KOIOS}/blocks?block_height=lte.${latest - 50}&tx_count=gt.0&select=hash,block_height&limit=40`);
    for (const blk of blocks) {
        const txs = await getJson(`${KOIOS}/block_txs`, {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify({_block_hashes: [blk.hash]})});
        const infos = await getJson(`${KOIOS}/tx_info`, {
            method: "POST",
            headers: {"content-type": "application/json"},
            body: JSON.stringify({_tx_hashes: txs.map((t: any) => t.tx_hash), _inputs: false, _metadata: false, _assets: true, _withdrawals: false, _certs: false, _scripts: true, _bytecode: false}),
        });
        for (const t of infos) {
            const o = t.outputs.find((o: any) => o.inline_datum && o.payment_addr.bech32.startsWith("addr_test1z") && (o.asset_list ?? []).length);
            if (!o) continue;
            const proof = await getJson(`${AGG("preprod")}/proof/v2/cardano-transaction?transaction_hashes=${t.tx_hash}`);
            if (!proof.certified_transactions?.items?.length) continue;
            const stateCert = await getJson(`${AGG("preprod")}/certificate/${proof.certificate_hash}`);
            if (stateCert.epoch !== epoch) continue;
            const it = proof.certified_transactions.items[0];
            const pt = {slot: BigInt(it.slot_number), hash: Buffer.from(it.block_hash, "hex")};
            const [block] = await fetchBlocks(RELAY.host, RELAY.port, RELAY.magic, pt, pt);
            return {network: "preprod", rotationCert, stateCert, nextCert, proof, block: Buffer.from(block).toString("hex"), txHash: t.tx_hash, outputIndex: o.tx_index, koiosOutput: o};
        }
    }
    throw new Error("no suitable preprod transaction found");
}

async function captureMainnet(): Promise<MainnetCapture> {
    const {rotationCert, nextCert} = await boundaryCerts("mainnet");
    return {network: "mainnet", rotationCert, stateCert: nextCert, nextCert};
}

if (import.meta.url === `file://${process.argv[1]}`) {
    const refresh = process.argv.includes("--refresh");
    if (refresh) {
        writeFileSync(new URL("preprod.json", FIX), JSON.stringify(await capturePreprod(), null, 1));
        writeFileSync(new URL("mainnet.json", FIX), JSON.stringify(await captureMainnet(), null, 1));
    }
    const pp = buildPreprod(loadCapture<PreprodCapture>("preprod"));
    const mn = buildMainnet(loadCapture<MainnetCapture>("mainnet"));
    writeFileSync(new URL("vectors.json", FIX), JSON.stringify({preprod: pp, mainnet: mn}, null, 1));
    console.log(`preprod tx ${pp.txHash} block ${pp.blockNumber}: proof ${(pp.txProof.length - 2) / 2} B; mainnet rotation proof ${(mn.rotationProof.length - 2) / 2} B, ${mn.signers} signers / ${mn.nrIndices} indexes`);
}
