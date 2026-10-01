import {createHash} from "node:crypto";
import {readFileSync, writeFileSync, mkdirSync} from "node:fs";
import {dirname, resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {encodeAbiParameters, keccak256, type Hex} from "viem";
import {ed25519} from "@noble/curves/ed25519";
import {Cell, mergeProofs, pruneExcept, readLabel, parseBoc, serializeBoc, unwrapProof, hashmapLookup, bitsOf, CELL_MERKLE_UPDATE, CELL_PRUNED} from "./tonCells.js";
import {connectAny, MC_SHARD, type BlockIdExt, type BlockLinkForward, type LiteClient, type SignatureSet} from "./tonLiteClient.js";

/// TON live fixture: capture (`--refresh`) and proof building for TonVerifier.
///
/// From a public liteserver (ADNL; HTTP gateways cannot decode Simplex signature sets):
///  - the latest masterchain block L, its previous key block K and K's previous key block K0;
///  - `getBlockProof(K0 → L)`: forward links K0→K and K→L with Simplex signature sets, the K0 and K
///    config proofs (ConfigParam 34) and the K / L header proofs;
///  - `getAccountStatePrunned(L, account)`: the masterchain block + state proofs, the shard block +
///    state proofs, and the account cell (code/data pruned).
///
/// Built: the anchor at K0 (rotates through key block K) and the anchor at K; the key block K proof
/// (header ∪ config, merged), the block L proof (header ∪ state_update, merged), the state chain.
///
/// Run: npx tsx test/e2e/relay/buildTonLiveFixture.ts --refresh [mainnet|testnet]

const HERE = dirname(fileURLToPath(import.meta.url));
export const TON_FIXTURE_DIR = resolve(HERE, "../fixtures/ton-live");
const sha256 = (b: Uint8Array): Buffer => createHash("sha256").update(b).digest();
const hx = (b: Uint8Array): Hex => ("0x" + Buffer.from(b).toString("hex")) as Hex;
const unhex = (h: string): Buffer => Buffer.from(h.replace(/^0x/, ""), "hex");

/// Accounts proven by the live fixture (no CLPR Service exists on TON yet).
export const TON_TARGETS: Record<string, {account: string; chainId: string}> = {
    // USDT jetton master (basechain)
    mainnet: {account: "0:b113a994b5024a16719f69139328eb759596c38a25f59028b146fecdc3621dfe", chainId: "ton:mainnet"},
    // an active basechain contract (testnet masterchain only hosts system contracts too large for a
    // liteserver account query; the workchain −1 path is covered by the synthetic Foundry tests)
    testnet: {account: "0:36508b900e21ca762f04a590ddb0ec8aa392a402d32da8bbfd16649f8cc76fdd", chainId: "ton:testnet"},
};

// ── capture ─────────────────────────────────────────────────────────────────

type J = Record<string, unknown>;
const ser = (o: unknown): unknown =>
    Buffer.isBuffer(o)
        ? o.toString("hex")
        : typeof o === "bigint"
          ? o.toString()
          : Array.isArray(o)
            ? o.map(ser)
            : o && typeof o === "object"
              ? Object.fromEntries(Object.entries(o).map(([k, v]) => [k, ser(v)]))
              : o;

export interface TonCapture {
    network: string;
    capturedAt: string;
    account: string;
    chainId: string;
    k0: number;
    k: number;
    last: J;
    links: J[]; // forward links K0→K, K→L (serialized)
    accountState: J; // getAccountStatePrunned at L
}

function prevKeySeqno(headerProof: Buffer): number {
    const blk = unwrapProof(parseBoc(headerProof)[0]);
    const info = blk.refs[0].slice();
    info.skip(32 + 32 + 8 + 8 + 32 + 32 + 104 + 32 + 128 + 32 + 32 + 32);
    return info.num(32);
}

export async function captureTon(network: "mainnet" | "testnet"): Promise<TonCapture> {
    const c: LiteClient = await connectAny(network);
    try {
        const {last} = await c.getMasterchainInfo();
        const k = prevKeySeqno(await c.getBlockHeader(last));
        const kId = (await c.lookupBlock(-1, MC_SHARD, k)).id;
        const k0 = prevKeySeqno(await c.getBlockHeader(kId));
        const k0Id = (await c.lookupBlock(-1, MC_SHARD, k0)).id;
        const links: BlockLinkForward[] = [];
        let from = k0Id;
        for (let guard = 0; guard < 8; guard++) {
            const pr = await c.getBlockProof(from, last);
            for (const s of pr.steps) {
                if (s.kind !== "forward") throw new Error("unexpected backward link");
                links.push(s);
            }
            from = pr.to;
            if (pr.complete) break;
        }
        const [wc, addr] = TON_TARGETS[network].account.split(":");
        const acc = await c.getAccountState(last, Number(wc), Buffer.from(addr, "hex"), true);
        return {
            network,
            capturedAt: new Date().toISOString(),
            account: TON_TARGETS[network].account,
            chainId: TON_TARGETS[network].chainId,
            k0,
            k,
            last: ser(last) as J,
            links: ser(links) as J[],
            accountState: ser(acc) as J,
        };
    } finally {
        c.close();
    }
}

// ── building ────────────────────────────────────────────────────────────────

/// The smallest key-block proof TonVerifier needs: header, extra → McBlockExtra → config path to
/// ConfigParam 34 → validator list cells whose key range starts below `main` (TonBlocks._collect).
function minimalKeyBlock(block: Cell): Cell {
    const keep = new Set<Cell>([block, block.refs[0]]);
    const extra = block.refs[3];
    const mce = extra.refs[3];
    keep.add(extra).add(mce);
    const ms = mce.slice();
    ms.skip(17);
    let ri = 0;
    if (ms.bit()) ri++;
    if (ms.bit()) ri++;
    const cc = () => {
        ms.skip(ms.num(4) * 8);
        if (ms.bit()) ri++;
    };
    cc();
    cc();
    ri++;
    const cfg = mce.refs[ri];
    const r = hashmapLookup(cfg, bitsOf(34n, 32), 32)!;
    r.path.forEach((x) => keep.add(x));
    const vsCell = r.leaf.loadRef();
    keep.add(vsCell);
    const vs = vsCell.slice();
    const vtag = vs.num(8);
    vs.skip(64);
    vs.num(16);
    const main = vs.num(16);
    if (vtag === 0x12) {
        vs.skip(64);
        vs.bit();
    }
    const walk = (c: Cell, prefix: number, m: number) => {
        if (prefix * 2 ** m >= main || c.type === CELL_PRUNED) return;
        keep.add(c);
        const sl = c.slice();
        const label = readLabel(sl, m);
        for (const bit of label) prefix = prefix * 2 + bit;
        const mm = m - label.length;
        if (mm === 0) return;
        walk(c.refs[0], prefix * 2, mm - 1);
        walk(c.refs[1], prefix * 2 + 1, mm - 1);
    };
    walk(vs.loadRef(), 0, 16);
    const out = pruneExcept(block, keep);
    if (!out.hash().equals(block.hash())) throw new Error("minimal key block hash");
    return out;
}

/// Packed `pubkey ‖ uint64 weight` of the first `main` validators of ConfigParam 34 in a key block.
function validatorsFromKeyBlock(block: Cell): Buffer {
    const extra = block.refs[3];
    const es = extra.slice();
    const tag = es.uint(32);
    if (tag !== 0x4a33f6fdn) throw new Error(`block_extra tag ${tag.toString(16)}`);
    const mce = extra.refs[3];
    const ms = mce.slice();
    if (ms.uint(16) !== 0xcca5n || ms.bit() !== 1) throw new Error("not a key block extra");
    let ri = 0;
    if (ms.bit()) ri++;
    if (ms.bit()) ri++;
    const cc = () => {
        const l = ms.num(4);
        ms.skip(l * 8);
        if (ms.bit()) ri++;
    };
    cc();
    cc();
    ri++;
    ms.skip(256);
    const cfg = mce.refs[ri];
    const vs = hashmapLookup(cfg, bitsOf(34n, 32), 32)!.leaf.loadRef().slice();
    const vtag = vs.num(8);
    vs.skip(64);
    vs.num(16);
    const main = vs.num(16);
    if (vtag === 0x12) {
        vs.skip(64);
        vs.bit();
    }
    const list = vs.loadRef();
    const out: Buffer[] = [];
    for (let i = 0; i < main; i++) {
        const s = hashmapLookup(list, bitsOf(BigInt(i), 16), 16)!.leaf;
        s.num(8);
        if (s.uint(32) !== 0x8e81278an) throw new Error("pubkey tag");
        const pk = s.bytes(32);
        const w = Buffer.alloc(8);
        w.writeBigUInt64BE(s.uint(64));
        out.push(pk, w);
    }
    return Buffer.concat(out);
}

function signedMessage(sig: SignatureSet | J, rootHash: Buffer, fileHash: Buffer): {mode: number; msg: Buffer} {
    const s = sig as any;
    if (s.kind === "ordinary") return {mode: 0, msg: Buffer.concat([unhex("706e0bc5"), rootHash, fileHash])};
    const cand = unhex(s.candidate);
    const slot = Buffer.alloc(4);
    slot.writeInt32LE(s.slot);
    const inner = Buffer.concat([unhex("05e1a740"), unhex("3fcd91b6"), slot, sha256(cand)]);
    return {mode: 1, msg: Buffer.concat([unhex("f83de3a8"), unhex(s.sessionId), Buffer.from([inner.length]), inner, Buffer.alloc(3)])};
}

const MC_BLOCK_T = {
    type: "tuple",
    components: [
        {name: "boc", type: "bytes"},
        {
            name: "sigs",
            type: "tuple",
            components: [
                {name: "mode", type: "uint8"},
                {name: "fileHash", type: "bytes32"},
                {name: "sessionId", type: "bytes32"},
                {name: "slot", type: "uint32"},
                {name: "candidate", type: "bytes"},
                {name: "signers", type: "uint256[]"},
                {name: "signatures", type: "bytes[]"},
            ],
        },
    ],
} as const;
export const MC_BLOCK_ABI = [MC_BLOCK_T] as const;
export const MC_BLOCKS_ABI = [{...MC_BLOCK_T, type: "tuple[]"}] as const;
export const STATE_CHAIN_ABI = [
    {
        type: "tuple",
        components: [
            {name: "mcState", type: "bytes"},
            {name: "shardBlock", type: "bytes"},
            {name: "shardState", type: "bytes"},
            {name: "account", type: "bytes"},
        ],
    },
] as const;

export interface McBlockArg {
    boc: Hex;
    sigs: {mode: number; fileHash: Hex; sessionId: Hex; slot: number; candidate: Hex; signers: bigint[]; signatures: Hex[]};
}

interface SignedBlock {
    arg: McBlockArg; // inline signatures
    cached: McBlockArg; // empty signatures (pre-recorded)
    message: Hex;
    keys: Hex[];
    sigs: Hex[];
    chosen: number;
    signed: number;
}

function signBlock(boc: Buffer, link: any, validators: Buffer): SignedBlock {
    const rootHash = unhex(link.to.rootHash);
    const fileHash = unhex(link.to.fileHash);
    const {mode, msg} = signedMessage(link.signatures, rootHash, fileHash);
    const n = validators.length / 40;
    const pks = Array.from({length: n}, (_, i) => validators.subarray(i * 40, i * 40 + 32));
    const ws = Array.from({length: n}, (_, i) => validators.readBigUInt64BE(i * 40 + 32));
    const total = ws.reduce((a, b) => a + b, 0n);
    const byId = new Map(pks.map((pk, i) => [sha256(Buffer.concat([unhex("c6b41348"), pk])).toString("hex"), i]));
    const signed: {i: number; sig: Buffer}[] = [];
    for (const s of link.signatures.signatures) {
        const i = byId.get(s.nodeIdShort);
        if (i === undefined) throw new Error("signer not in validator set");
        const sig = unhex(s.signature);
        if (!ed25519.verify(sig, msg, pks[i])) throw new Error(`bad signature from validator ${i}`);
        signed.push({i, sig});
    }
    signed.sort((a, b) => (ws[b.i] > ws[a.i] ? 1 : ws[b.i] < ws[a.i] ? -1 : a.i - b.i));
    const chosen: typeof signed = [];
    let acc = 0n;
    for (const x of signed) {
        chosen.push(x);
        acc += ws[x.i];
        if (acc * 3n > total * 2n) break;
    }
    if (acc * 3n <= total * 2n) throw new Error("signatures below 2/3");
    chosen.sort((a, b) => a.i - b.i);
    const s = link.signatures;
    const base = {
        mode,
        fileHash: hx(mode === 0 ? fileHash : Buffer.alloc(32)),
        sessionId: hx(mode === 1 ? unhex(s.sessionId) : Buffer.alloc(32)),
        slot: mode === 1 ? s.slot : 0,
        candidate: hx(mode === 1 ? unhex(s.candidate) : Buffer.alloc(0)),
        signers: chosen.map((x) => BigInt(x.i)),
    };
    return {
        arg: {boc: hx(boc), sigs: {...base, signatures: chosen.map((x) => hx(x.sig))}},
        cached: {boc: hx(boc), sigs: {...base, signatures: chosen.map(() => "0x" as Hex)}},
        message: hx(msg),
        keys: chosen.map((x) => hx(pks[x.i])),
        sigs: chosen.map((x) => hx(x.sig)),
        chosen: chosen.length,
        signed: signed.length,
    };
}

/// `Account` → `StateInit.data` (block.tlb `account$1`), mirroring TonBlocks.accountData.
export function accountDataCell(account: Cell, wc: number, addr: Buffer): Cell {
    const s = account.slice();
    if (s.bit() !== 1) throw new Error("account_none");
    if (s.num(2) !== 2 || s.bit() !== 0) throw new Error("not addr_std");
    if (Number(s.int(8)) !== wc || !s.bytes(32).equals(addr)) throw new Error("account address");
    const varU = (lenBits: number) => s.skip(s.num(lenBits) * 8);
    varU(3);
    varU(3);
    const extra = s.num(3);
    if (extra === 1) s.skip(256);
    else if (extra !== 0) throw new Error("storage_extra");
    s.skip(32);
    if (s.bit()) varU(4);
    s.skip(64);
    varU(4);
    if (s.bit()) s.loadRef();
    if (s.bit() !== 1) throw new Error("not active");
    if (s.bit()) s.skip(5);
    if (s.bit()) s.skip(2);
    if (s.bit()) s.loadRef();
    if (s.bit() !== 1) throw new Error("no data");
    return s.loadRef();
}

export interface TonLiveProof {
    network: string;
    chainId: string;
    serviceAddress: Hex;
    anchorPrev: Hex;
    anchorCur: Hex;
    validatorsPrev: Hex;
    validatorsCur: Hex;
    keyBlocks: Hex; // abi McBlock[] with K (inline sigs)
    keyBlocksCached: Hex;
    block: Hex; // abi McBlock L (inline)
    blockCached: Hex;
    stateChain: Hex;
    dataHash: Hex;
    seqno: number;
    keySeqno: number;
    cacheBatches: {message: Hex; keys: Hex[]; sigs: Hex[]}[];
    meta: {mcValidatorsPrev: number; mcValidatorsCur: number; signersK: number; signersL: number; signedL: number; mode: number};
}

export function buildTonLiveProof(c: TonCapture): TonLiveProof {
    const links = c.links as any[];
    if (links.length !== 2) throw new Error(`expected 2 forward links (K0→K→L), got ${links.length}`);
    const [lk, ll] = links;
    if (lk.to.seqno !== c.k || ll.to.seqno !== (c.last as any).seqno) throw new Error("link targets");

    // Anchor at K0: validators from K0's config proof.
    const k0Block = unwrapProof(parseBoc(unhex(lk.configProof))[0]);
    if (!k0Block.hash().equals(unhex(lk.from.rootHash))) throw new Error("K0 config proof root");
    const valsPrev = validatorsFromKeyBlock(k0Block);

    // Key block K: header (dest proof of link 1) ∪ config (config proof of link 2).
    const kHeader = unwrapProof(parseBoc(unhex(lk.destProof))[0]);
    const kConfig = unwrapProof(parseBoc(unhex(ll.configProof))[0]);
    const kBlock = minimalKeyBlock(mergeProofs(kHeader, kConfig));
    if (!kBlock.hash().equals(unhex(lk.to.rootHash))) throw new Error("K root");
    const valsCur = validatorsFromKeyBlock(kBlock);

    // Block L: header (dest proof of link 2) ∪ state_update (first root of the account shard_proof).
    const a = c.accountState as any;
    const lHeader = unwrapProof(parseBoc(unhex(ll.destProof))[0]);
    const wcAccount = Number(c.account.split(":")[0]);
    const mcProofBoc = unhex(wcAccount === -1 ? a.proof : a.shardProof);
    const mcRoots = parseBoc(mcProofBoc).map(unwrapProof);
    const lBlock = mergeProofs(lHeader, mcRoots[0]);
    if (!lBlock.hash().equals(unhex(ll.to.rootHash))) throw new Error("L root");
    const su = lBlock.refs[2];
    if (su.type !== CELL_MERKLE_UPDATE) throw new Error("L state_update not in proof");
    const mcState = mcRoots[1];
    if (!mcState.hash().equals(su.data.subarray(33, 65))) throw new Error("mc state hash");

    let shardBlock = Buffer.alloc(0);
    let shardState = Buffer.alloc(0);
    if (wcAccount !== -1) {
        const roots = parseBoc(unhex(a.proof)).map(unwrapProof);
        if (roots[0].refs[2].type !== CELL_MERKLE_UPDATE) throw new Error("shard state_update");
        if (!roots[1].hash().equals(roots[0].refs[2].data.subarray(33, 65))) throw new Error("shard state hash");
        shardBlock = serializeBoc(roots[0]);
        shardState = serializeBoc(roots[1]);
    }
    const account = unwrapProof(parseBoc(unhex(a.state))[0]);
    const dataRef = accountDataCell(account, Number(c.account.split(":")[0]), unhex(c.account.split(":")[1]));
    const signedK = signBlock(serializeBoc(kBlock), lk, valsPrev);
    const signedL = signBlock(serializeBoc(lBlock), ll, valsCur);
    const [wc, addr] = c.account.split(":");
    const serviceAddress = Buffer.concat([Buffer.from([Number(wc) & 0xff]), unhex(addr)]);
    const anchor = (seq: number, v: Buffer) => {
        const b = Buffer.alloc(4);
        b.writeUInt32BE(seq);
        return hx(Buffer.concat([b, unhex(keccak256(v))]));
    };
    const enc = (abi: any, v: any) => encodeAbiParameters(abi, [v]);
    const batches = (sb: SignedBlock) => {
        const out: {message: Hex; keys: Hex[]; sigs: Hex[]}[] = [];
        for (let i = 0; i < sb.keys.length; i += 20) out.push({message: sb.message, keys: sb.keys.slice(i, i + 20), sigs: sb.sigs.slice(i, i + 20)});
        return out;
    };
    return {
        network: c.network,
        chainId: c.chainId,
        serviceAddress: hx(serviceAddress),
        anchorPrev: anchor(c.k0, valsPrev),
        anchorCur: anchor(c.k, valsCur),
        validatorsPrev: hx(valsPrev),
        validatorsCur: hx(valsCur),
        keyBlocks: enc(MC_BLOCKS_ABI, [signedK.arg]),
        keyBlocksCached: enc(MC_BLOCKS_ABI, [signedK.cached]),
        block: enc(MC_BLOCK_ABI, signedL.arg),
        blockCached: enc(MC_BLOCK_ABI, signedL.cached),
        stateChain: enc(STATE_CHAIN_ABI, {
            mcState: hx(serializeBoc(mcState)),
            shardBlock: hx(shardBlock),
            shardState: hx(shardState),
            account: hx(serializeBoc(account)),
        }),
        dataHash: hx(dataRef.hash()),
        seqno: (c.last as any).seqno,
        keySeqno: c.k,
        cacheBatches: [...batches(signedK), ...batches(signedL)],
        meta: {
            mcValidatorsPrev: valsPrev.length / 40,
            mcValidatorsCur: valsCur.length / 40,
            signersK: signedK.chosen,
            signersL: signedL.chosen,
            signedL: signedL.signed,
            mode: signedL.arg.sigs.mode,
        },
    };
}

export function loadTonCapture(network: string): TonCapture {
    return JSON.parse(readFileSync(resolve(TON_FIXTURE_DIR, `${network}.json`), "utf8")).capture;
}

export function writeTonFixture(c: TonCapture): TonLiveProof {
    const p = buildTonLiveProof(c);
    mkdirSync(TON_FIXTURE_DIR, {recursive: true});
    writeFileSync(resolve(TON_FIXTURE_DIR, `${c.network}.json`), JSON.stringify({derived: p, capture: c}, null, 1) + "\n");
    return p;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    const nets = process.argv.slice(2).filter((x) => !x.startsWith("--"));
    const refresh = process.argv.includes("--refresh");
    for (const net of nets.length ? nets : ["mainnet", "testnet"]) {
        const c = refresh ? await captureTon(net as "mainnet" | "testnet") : loadTonCapture(net);
        const p = writeTonFixture(c);
        console.log(`[ton-live] ${net}: block ${p.seqno}, key ${p.keySeqno}, ${JSON.stringify(p.meta)}`);
    }
    process.exit(0);
}
