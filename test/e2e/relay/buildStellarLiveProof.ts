import {mkdirSync, readFileSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {
    archiveCurrentLedger,
    checkpointOf,
    encodeAnchor,
    encodeBundle,
    encodeConfigProof,
    fetchArchiveFile,
    hex,
    invokeSuccessHash,
    isSatisfied,
    loadCheckpoint,
    minimalSlice,
    networkIdOf,
    qsetMembers,
    readScpHistory,
    sha256,
    txPayloadFromEnvelope,
    unhex,
    verifyEnvelope,
    voidSuccessPreimage,
    xdrRecords,
    type Checkpoint,
    type Envelope,
    type QuorumSet,
    type ScpProof
} from "./stellar.js";

/// Live-data proof builder for `StellarScpVerifier`, fed only by public sources:
///   - SDF's history archives (ledger headers, tx sets, result sets, and the SCP EXTERNALIZE envelopes
///     with the quorum sets they reference: `scp/` category, one SCPHistoryEntry per ledger);
///   - a public Stellar RPC (`getTransactions`) for one transaction's envelope and contract events,
///     which the archive does not hold in a decoded form.
/// Every piece is cross-checked before it is written: header hashes, tx-set and result-set hashes,
/// each Ed25519 envelope signature, the transaction hash, and the Soroban success hash.
///
/// Capture (`--refresh`) records, per network:
///   finality     an EXTERNALIZE quorum for slot S (the cheapest signer set satisfying the tier-1 quorum
///                set) and the tx set of S, which proves the hash of ledger S-1;
///   headers      ledger headers S-1 back to N;
///   attestation  a successful Soroban transaction in ledger N with a void return and contract events
///                (the first one found in a ledger that fits). No CLPR service exists on Stellar, so
///                this event stands in for `clpr_queue`: the emitter becomes the channel's service.
///   rotation     (pubnet) the real tier-1 change of September 2026 (7 → 10 organizations): a slot where
///                the old quorum set's members that already declare the new set satisfy the old set.
/// Pubnet tx sets are 100–430 KB, so S is a ledger whose tx set fits Hedera's 128 KB (about 1.4 % of
/// ledgers), and the pubnet bundle is split in two transactions (checkpoint, then headers + event).
///
/// CLI:
///   npx tsx test/e2e/relay/buildStellarLiveProof.ts [--network testnet|pubnet]            summary
///   npx tsx test/e2e/relay/buildStellarLiveProof.ts --refresh [--network testnet|pubnet]  re-capture

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const STELLAR_LIVE_DIR = path.resolve(__dirname, "../fixtures/stellar-live");

export interface StellarNetwork {
    name: "testnet" | "pubnet";
    archive: string;
    rpc: string;
    passphrase: string;
    caip2: string;
}

export const NETWORKS: Record<string, StellarNetwork> = {
    testnet: {
        name: "testnet",
        archive: "https://history.stellar.org/prd/core-testnet/core_testnet_001",
        rpc: "https://soroban-testnet.stellar.org",
        passphrase: "Test SDF Network ; September 2015",
        caip2: "stellar:testnet"
    },
    pubnet: {
        name: "pubnet",
        archive: "https://history.stellar.org/prd/core-live/core_live_001",
        rpc: "https://mainnet.sorobanrpc.com",
        passphrase: "Public Global Stellar Network ; September 2015",
        caip2: "stellar:pubnet"
    }
};

/// Hedera allows 128 KiB of calldata; keep each proof below this (ABI framing adds ~0.5 KB).
export const MAX_PROOF_BYTES = 128_000;
/// The real pubnet tier-1 expansion: the last checkpoint where every validator still declared the
/// 7-organization set, and how far to scan for the rotation slot (found by binary search over the
/// archive's SCP history).
const PUBNET_ROTATION_FROM = 64_146_367;
const PUBNET_ROTATION_SCAN_CHECKPOINTS = 260;

export interface CapturedEnvelope {
    nodeId: `0x${string}`;
    qsetHash: `0x${string}`;
    statement: `0x${string}`;
    signature: `0x${string}`;
}

export interface CapturedScp {
    slot: number;
    txSet: `0x${string}`;
    previousLedgerHash: `0x${string}`;
    envelopesAvailable: number;
    envelopes: CapturedEnvelope[];
}

export interface StellarCapture {
    network: string;
    archive: string;
    rpc: string;
    capturedAt: string;
    passphrase: string;
    networkId: `0x${string}`;
    caip2: string;
    qset: `0x${string}`;
    qsetHash: `0x${string}`;
    qsetSummary: string;
    finality: CapturedScp;
    headers: `0x${string}`[];
    attestation: {
        ledger: number;
        txHash: `0x${string}`;
        txPayload: `0x${string}`;
        resultSet: `0x${string}`;
        resultSetTxCount: number;
        offset: number;
        preimage: `0x${string}`;
        contractId: `0x${string}`;
        eventCount: number;
    };
    rotation?: CapturedScp & {
        oldQset: `0x${string}`;
        oldQsetHash: `0x${string}`;
        newQset: `0x${string}`;
        newQsetHash: `0x${string}`;
        oldSummary: string;
        newSummary: string;
        endorsersAvailable: number;
    };
}

const summarize = (q: QuorumSet): string =>
    `threshold ${q.threshold} of ${q.validators.length + q.innerSets.length}` +
    (q.innerSets.length
        ? ` [${q.innerSets.map((s) => `${s.threshold}/${s.validators.length + s.innerSets.length}`).join(", ")}]`
        : "") +
    `, ${qsetMembers(q).length} validators`;

// ── RPC ────────────────────────────────────────────────────────────────────────

interface RpcTx {
    status: string;
    txHash: string;
    feeBump: boolean;
    envelopeXdr: string;
    resultXdr: string;
    ledger: number;
    events?: {contractEventsXdr?: string[][]};
}

async function rpc<T>(url: string, method: string, params: unknown): Promise<T> {
    for (let attempt = 0; ; attempt++) {
        const res = await fetch(url, {
            method: "POST",
            headers: {"content-type": "application/json"},
            body: JSON.stringify({jsonrpc: "2.0", id: 1, method, params})
        });
        const body = (await res.json().catch(() => ({}))) as {result?: T; error?: {message: string}};
        if (res.ok && body.result) return body.result;
        if (attempt >= 3) throw new Error(`${method}: ${res.status} ${body.error?.message ?? ""}`);
        await new Promise((z) => setTimeout(z, 2000 * (attempt + 1)));
    }
}

async function ledgerTransactions(net: StellarNetwork, ledger: number): Promise<RpcTx[]> {
    const out: RpcTx[] = [];
    let cursor: string | undefined;
    for (;;) {
        const params = cursor
            ? {pagination: {cursor, limit: 200}, xdrFormat: "base64"}
            : {startLedger: ledger, pagination: {limit: 200}, xdrFormat: "base64"};
        const r = await rpc<{transactions: RpcTx[]; cursor: string}>(net.rpc, "getTransactions", params);
        const txs = r.transactions ?? [];
        for (const t of txs) if (t.ledger === ledger) out.push(t);
        if (txs.length === 0 || txs[txs.length - 1].ledger > ledger) return out;
        cursor = r.cursor;
    }
}

// ── Capture ────────────────────────────────────────────────────────────────────

/// The quorum-set XDR most envelopes of `seq` declare (D), from the checkpoint's SCP history.
function declaredQset(cps: Checkpoint[], envs: Envelope[]): {xdr: Buffer; qset: QuorumSet; hash: string} {
    const counts = new Map<string, number>();
    for (const e of envs) counts.set(e.qsetHash!, (counts.get(e.qsetHash!) ?? 0) + 1);
    const hash = [...counts.entries()].sort((a, b) => b[1] - a[1])[0][0];
    for (const cp of cps) for (const h of cp.scp.values()) {
        const q = h.quorumSets.get(hash);
        if (q) return {...q, hash};
    }
    throw new Error(`quorum set ${hash} not in the archive's SCP history`);
}

/// Externalize envelopes of slot `seq` for the header's value, signature-checked, sorted by node id,
/// reduced to the cheapest signer set that satisfies `q` (restricted to `eligible`, if given).
function scpFor(
    net: StellarNetwork,
    cp: Checkpoint,
    seq: number,
    q: QuorumSet,
    eligible?: (e: Envelope) => boolean
): {scp: CapturedScp; available: number} | undefined {
    const h = cp.headers.get(seq);
    const hist = cp.scp.get(seq);
    const txSet = cp.txSets.get(seq);
    if (!h || !hist || !txSet) return undefined;
    const nid = networkIdOf(net.passphrase);
    const members = new Set(qsetMembers(q));
    const good = hist.envelopes.filter(
        (e) =>
            e.type === 2 &&
            e.slot === BigInt(seq) &&
            e.value!.equals(h.scpValue) &&
            members.has(e.nodeId) &&
            (!eligible || eligible(e)) &&
            verifyEnvelope(nid, e)
    );
    const slice = minimalSlice(q, new Set(good.map((e) => e.nodeId)));
    if (!slice) return undefined;
    const chosen = good.filter((e) => slice.includes(e.nodeId)).sort((a, b) => a.nodeId.localeCompare(b.nodeId));
    if (!isSatisfied(q, new Set(chosen.map((e) => e.nodeId)))) throw new Error("slice check");
    return {
        available: good.length,
        scp: {
            slot: seq,
            txSet: hex(txSet),
            previousLedgerHash: hex(txSet.subarray(4, 36)),
            envelopesAvailable: hist.envelopes.length,
            envelopes: chosen.map((e) => ({
                nodeId: hex(unhex(e.nodeId)),
                qsetHash: hex(unhex(e.qsetHash!)),
                statement: hex(e.statement),
                signature: hex(e.signature)
            }))
        }
    };
}

const scpBytes = (s: CapturedScp) => 300 * s.envelopes.length + (s.txSet.length - 2) / 2;

async function findAttestation(net: StellarNetwork, cp: Checkpoint, ledger: number, networkId: Buffer) {
    const resultSet = cp.resultSets.get(ledger);
    if (!resultSet) return undefined;
    for (const t of await ledgerTransactions(net, ledger)) {
        const events = t.events?.contractEventsXdr;
        if (t.status !== "SUCCESS" || t.feeBump || !events || events.length !== 1 || events[0].length === 0) continue;
        const success = invokeSuccessHash(Buffer.from(t.resultXdr, "base64"));
        if (!success) continue;
        const preimage = voidSuccessPreimage(events[0].map((e) => Buffer.from(e, "base64")));
        if (!sha256(preimage).equals(success)) continue; // non-void return value
        const txHash = unhex(t.txHash);
        const offset = resultSet.indexOf(txHash);
        if (offset < 0 || resultSet.indexOf(txHash, offset + 1) >= 0) continue;
        const result = Buffer.from(t.resultXdr, "base64");
        if (!resultSet.subarray(offset + 32, offset + 32 + result.length).equals(result)) continue;
        const txPayload = txPayloadFromEnvelope(networkId, Buffer.from(t.envelopeXdr, "base64"), txHash);
        return {
            ledger,
            txHash: hex(txHash),
            txPayload: hex(txPayload),
            resultSet: hex(resultSet),
            resultSetTxCount: resultSet.readUInt32BE(0),
            offset,
            preimage: hex(preimage),
            contractId: hex(preimage.subarray(16, 48)),
            eventCount: preimage.readUInt32BE(4)
        };
    }
    return undefined;
}

export async function capture(net: StellarNetwork): Promise<StellarCapture> {
    const networkId = networkIdOf(net.passphrase);
    const current = await archiveCurrentLedger(net.archive);
    const latest = checkpointOf(current) === current ? current : checkpointOf(current) - 64;
    const txSetLimit = net.name === "pubnet" ? 122_000 : MAX_PROOF_BYTES - 10_000;

    for (let k = 0; k < 40; k++) {
        const cpNum = latest - 64 * k;
        const cp = await loadCheckpoint(net.archive, cpNum);
        const ledgers = [...cp.headers.keys()].sort((a, b) => b - a);
        for (const S of ledgers) {
            const txSet = cp.txSets.get(S);
            if (!txSet || txSet.length > txSetLimit || !cp.headers.has(S - 1)) continue;
            const hist = cp.scp.get(S);
            if (!hist) continue;
            const q = declaredQset([cp], hist.envelopes);
            const found = scpFor(net, cp, S, q.qset);
            if (!found) continue;
            const single = net.name === "testnet";
            const headerList: Buffer[] = [];
            for (let N = S - 1; N >= cpNum - 63 && N >= S - 40; N--) {
                headerList.push(cp.headers.get(N)!.xdr);
                const rs = cp.resultSets.get(N);
                if (!rs) continue;
                const headerBytes = headerList.reduce((a, b) => a + b.length + 3, 0);
                const budget = q.xdr.length + headerBytes + rs.length + 4_000 + (single ? scpBytes(found.scp) : 0);
                if (budget > MAX_PROOF_BYTES) continue;
                const att = await findAttestation(net, cp, N, networkId);
                if (!att) continue;
                console.log(`[${net.name}] slot ${S} (tx set ${txSet.length} B), attestation in ${N} (results ${rs.length} B)`);
                const c: StellarCapture = {
                    network: net.name,
                    archive: net.archive,
                    rpc: net.rpc,
                    capturedAt: new Date().toISOString(),
                    passphrase: net.passphrase,
                    networkId: hex(networkId),
                    caip2: net.caip2,
                    qset: hex(q.xdr),
                    qsetHash: hex(unhex(q.hash)),
                    qsetSummary: summarize(q.qset),
                    finality: found.scp,
                    headers: headerList.map((b) => hex(b)),
                    attestation: att
                };
                if (net.name === "pubnet") c.rotation = await captureRotation(net);
                return c;
            }
        }
    }
    throw new Error(`[${net.name}] no suitable slot found`);
}

/// The September 2026 pubnet tier-1 expansion. Scans forward from the last all-old checkpoint for
/// the first slot whose tx set fits and where the old set's members that declare the new set (D)
/// satisfy the old set.
async function captureRotation(net: StellarNetwork): Promise<StellarCapture["rotation"]> {
    const first = await loadCheckpoint(net.archive, PUBNET_ROTATION_FROM);
    const oldQ = declaredQset([first], first.scp.get(PUBNET_ROTATION_FROM)!.envelopes);
    const oldMembers = new Set(qsetMembers(oldQ.qset));
    // Screen with the (small) SCP files only; load a full checkpoint once the old set endorses.
    for (let k = 1; k <= PUBNET_ROTATION_SCAN_CHECKPOINTS; k++) {
        const cpNum = PUBNET_ROTATION_FROM + 64 * k;
        const scp = xdrRecords(await fetchArchiveFile(net.archive, "scp", cpNum)).map(readScpHistory);
        const endorses = scp.some((h) => {
            const byD = new Map<string, Set<string>>();
            for (const e of h.envelopes) {
                if (e.type !== 2 || !oldMembers.has(e.nodeId) || e.qsetHash === oldQ.hash) continue;
                if (!byD.has(e.qsetHash!)) byD.set(e.qsetHash!, new Set());
                byD.get(e.qsetHash!)!.add(e.nodeId);
            }
            return [...byD.values()].some((signers) => isSatisfied(oldQ.qset, signers));
        });
        if (!endorses) continue;
        const cp = await loadCheckpoint(net.archive, cpNum);
        for (const S of [...cp.headers.keys()].sort((a, b) => a - b)) {
            const hist = cp.scp.get(S);
            const txSet = cp.txSets.get(S);
            if (!hist || !txSet || txSet.length > 122_000) continue;
            const newHashes = new Set(hist.envelopes.map((e) => e.qsetHash!).filter((d) => d !== oldQ.hash));
            for (const d of newHashes) {
                const found = scpFor(net, cp, S, oldQ.qset, (e) => e.qsetHash === d);
                if (!found) continue;
                const newQ = [...cp.scp.values()].map((h) => h.quorumSets.get(d)).find((x) => x);
                if (!newQ) continue;
                console.log(`[pubnet] rotation slot ${S}: ${summarize(oldQ.qset)} -> ${summarize(newQ.qset)}`);
                return {
                    ...found.scp,
                    oldQset: hex(oldQ.xdr),
                    oldQsetHash: hex(unhex(oldQ.hash)),
                    newQset: hex(newQ.xdr),
                    newQsetHash: hex(sha256(newQ.xdr)),
                    oldSummary: summarize(oldQ.qset),
                    newSummary: summarize(newQ.qset),
                    endorsersAvailable: found.available
                };
            }
        }
    }
    throw new Error("rotation slot not found");
}

// ── Proof building ─────────────────────────────────────────────────────────────

const scpProofOf = (s: CapturedScp, newQset?: string): ScpProof => ({
    envelopes: s.envelopes.map((e) => ({statement: unhex(e.statement), signature: unhex(e.signature)})),
    txSet: unhex(s.txSet),
    newQset: newQset ? unhex(newQset) : undefined
});

export interface StellarLiveProof {
    serviceContract: `0x${string}`;
    channelContext: `0x${string}`;
    /// Anchor before the finality step (last slot well below S, no checkpoint yet).
    anchor0: `0x${string}`;
    /// Anchor after the finality step (checkpoint = ledger S-1).
    anchor1: `0x${string}`;
    /// Single-transaction bundle: SCP + tx set + headers + attestation (testnet sizes).
    full: `0x${string}`;
    /// Two-step pubnet form: (1) SCP + tx set only, (2) headers + attestation from the checkpoint.
    step1: `0x${string}`;
    step2: `0x${string}`;
    rotation?: {anchor: `0x${string}`; bundle: `0x${string}`; newQsetHash: `0x${string}`};
    configProof: `0x${string}`;
}

export const CHANNEL_ID = sha256(Buffer.from("clpr-stellar-live-channel"));

export function buildStellarLiveProof(c: StellarCapture, controlMessage: Buffer): StellarLiveProof {
    const qset = unhex(c.qset);
    const zero = Buffer.alloc(32);
    const S = c.finality.slot;
    const anchor0 = encodeAnchor({
        qsetHash: unhex(c.qsetHash),
        lastSlot: S - 1000,
        checkpointSeq: 0,
        checkpointHash: zero,
        lastMetadataHash: zero
    });
    const anchor1 = encodeAnchor({
        qsetHash: unhex(c.qsetHash),
        lastSlot: S,
        checkpointSeq: S - 1,
        checkpointHash: unhex(c.finality.previousLedgerHash),
        lastMetadataHash: zero
    });
    const att = {
        txPayload: unhex(c.attestation.txPayload),
        resultSet: unhex(c.attestation.resultSet),
        offset: c.attestation.offset,
        preimage: unhex(c.attestation.preimage)
    };
    const headers = c.headers.map(unhex);
    const scp = scpProofOf(c.finality);
    const out: StellarLiveProof = {
        serviceContract: c.attestation.contractId,
        channelContext: hex(Buffer.concat([CHANNEL_ID, unhex(c.attestation.contractId)])),
        anchor0: hex(anchor0),
        anchor1: hex(anchor1),
        full: hex(encodeBundle({qset, scp, headers, attestation: att})),
        step1: hex(encodeBundle({qset, scp, headers: []})),
        step2: hex(encodeBundle({qset, headers, attestation: att})),
        configProof: hex(encodeConfigProof(qset, scp, controlMessage))
    };
    if (c.rotation) {
        const r = c.rotation;
        out.rotation = {
            anchor: hex(
                encodeAnchor({
                    qsetHash: unhex(r.oldQsetHash),
                    lastSlot: r.slot - 1,
                    checkpointSeq: 0,
                    checkpointHash: zero,
                    lastMetadataHash: zero
                })
            ),
            bundle: hex(encodeBundle({qset: unhex(r.oldQset), scp: scpProofOf(r, r.newQset), headers: []})),
            newQsetHash: r.newQsetHash
        };
    }
    return out;
}

export function loadStellarCapture(network: string): StellarCapture {
    return JSON.parse(readFileSync(path.join(STELLAR_LIVE_DIR, `${network}.json`), "utf8")) as StellarCapture;
}

// ── CLI ────────────────────────────────────────────────────────────────────────

async function main() {
    const args = process.argv.slice(2);
    const ni = args.indexOf("--network");
    const net = NETWORKS[ni >= 0 ? args[ni + 1] : "testnet"];
    if (!net) throw new Error("unknown --network");
    if (args.includes("--refresh")) {
        const c = await capture(net);
        mkdirSync(STELLAR_LIVE_DIR, {recursive: true});
        writeFileSync(path.join(STELLAR_LIVE_DIR, `${net.name}.json`), JSON.stringify(c, null, 2) + "\n");
    }
    const c = loadStellarCapture(net.name);
    const p = buildStellarLiveProof(c, Buffer.alloc(0));
    const kb = (h: string) => ((h.length - 2) / 2 / 1024).toFixed(1) + " KB";
    console.log(`[${net.name}] qset ${c.qsetSummary}; slot ${c.finality.slot}: ${c.finality.envelopes.length} of ${c.finality.envelopesAvailable} envelopes`);
    console.log(`  headers ${c.headers.length}, attestation ledger ${c.attestation.ledger} (${c.attestation.resultSetTxCount} txs)`);
    console.log(`  full ${kb(p.full)}, step1 ${kb(p.step1)}, step2 ${kb(p.step2)}` + (p.rotation ? `, rotation ${kb(p.rotation.bundle)}` : ""));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
    main().catch((e) => {
        console.error(e);
        process.exit(1);
    });
}
