import {mkdirSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {ed25519} from "@noble/curves/ed25519";
import {keccak256} from "viem";
import {
    ENVELOPE_TYPE_TX,
    contractEvent,
    encodeQuorumSet,
    hex,
    manifestEvent,
    queueEvent,
    scpSignedMessage,
    sha256,
    u32be,
    u64be,
    unhex,
    voidSuccessPreimage,
    xdrOpaque,
    type QuorumSet,
    type QueueMetadata
} from "./stellar.js";

/// Deterministic synthetic Stellar chain for the Foundry tests of StellarScpVerifier
/// (test/verifiers/evm/stellar/fixtures/synthetic.json). forge 1.5 has no Ed25519 signing cheatcode,
/// so the signatures are made here (noble ed25519) and the tests only assemble and tamper.
///
/// Every structure uses the real XDR layouts (LedgerHeader with a SIGNED StellarValue,
/// GeneralizedTransactionSet v1, TransactionResultSet with classic and Soroban results,
/// InvokeHostFunctionSuccessPreImage, SCPStatement EXTERNALIZE), so nothing in the verifier is stubbed.
///
/// Chain: ledgers 100..122. Quorum sets: Q1 = 2 of 3 organizations {A, B, C}, each 2 of 3;
/// Q2 = 3 of 4 organizations {A, B, C, D}.
///   ledger 100   clpr_manifest event (config manifest proof; config SCP slot 101)
///   ledger 103   clpr_queue for the integration channel + negative-case transactions
///   ledger 110   clpr_queue again (a later attestation)
///   slots 101, 105, 112: Q1 externalizations; slot 120: Q1 members declaring Q2 (rotation);
///   slot 122: Q2 externalization.
/// The integration channel and running hash are the values IntegrationTestBase derives
/// (checked by IntegrationStellar.t.sol, which fails loudly if they drift).
///
/// Run: npx tsx test/e2e/relay/buildStellarSyntheticFixture.ts

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.resolve(__dirname, "../../verifiers/evm/stellar/fixtures/synthetic.json");

const NETWORK_ID = sha256(Buffer.from("CLPR synthetic Stellar network ; 2026"));
const SERVICE = sha256(Buffer.from("clpr-stellar-synthetic-service"));
const OTHER_CONTRACT = sha256(Buffer.from("some-other-soroban-contract"));
/// IntegrationTestBase: _deriveTestChannelId(_signerPubKey(), 0) and the DATA + REPLY running hash.
const CHANNEL_ID = unhex("648234dc700647fa4624239014c6f9b458e5cd406cbbdf3fe096b27170c761d7");
const SENT_RUNNING_HASH = unhex("21cde3da189153bcbf2b1cc4f3fcc2a5e8135441cbca33c21d22ecedefc96f8b");

// ── Validators and quorum sets ────────────────────────────────────────────────

const ORGS = ["A", "B", "C", "D"];
const keys = new Map<string, {priv: Buffer; pub: string}>();
for (const o of ORGS) {
    for (let i = 0; i < 3; i++) {
        const priv = sha256(Buffer.from(`stellar-synthetic-validator-${o}${i}`));
        keys.set(`${o}${i}`, {priv, pub: Buffer.from(ed25519.getPublicKey(priv)).toString("hex")});
    }
}
const pub = (n: string) => keys.get(n)!.pub;
const org = (o: string): QuorumSet => ({threshold: 2, validators: [0, 1, 2].map((i) => pub(`${o}${i}`)), innerSets: []});
const Q1: QuorumSet = {threshold: 2, validators: [], innerSets: ["A", "B", "C"].map(org)};
const Q2: QuorumSet = {threshold: 3, validators: [], innerSets: ["A", "B", "C", "D"].map(org)};
const Q1X = encodeQuorumSet(Q1);
const Q2X = encodeQuorumSet(Q2);

// ── Transactions, results and events ──────────────────────────────────────────

interface SorobanTx {
    name: string;
    payload: Buffer;
    preimage: Buffer;
}

const sorobanTx = (name: string, events: Buffer[]): SorobanTx => ({
    name,
    payload: Buffer.concat([NETWORK_ID, u32be(ENVELOPE_TYPE_TX), Buffer.from(`synthetic transaction ${name}`.padEnd(64, "."))]),
    preimage: voidSuccessPreimage(events)
});

/// TransactionResultPair of a successful single-operation Soroban transaction.
const sorobanPair = (t: SorobanTx): Buffer =>
    Buffer.concat([
        sha256(t.payload),
        u64be(57_123n), // feeCharged
        u32be(0), // txSUCCESS
        u32be(1),
        u32be(0), // opINNER
        u32be(24), // INVOKE_HOST_FUNCTION
        u32be(0), // SUCCESS
        sha256(t.preimage),
        u32be(0) // ext
    ]);

/// A successful classic payment, so the Soroban pair is not first in the set.
const classicPair = (tag: string): Buffer =>
    Buffer.concat([sha256(Buffer.from(tag)), u64be(100n), u32be(0), u32be(1), u32be(0), u32be(1), u32be(0), u32be(0)]);

const resultSet = (pairs: Buffer[]) => Buffer.concat([u32be(pairs.length), ...pairs]);

const meta = (status: number): QueueMetadata => ({
    nextMessageId: 3n,
    sentRunningHash: SENT_RUNNING_HASH,
    receivedMessageId: 1n,
    receivedRunningHash: Buffer.alloc(32),
    status,
    endpointManifestVersion: 0n,
    manifestCommitment: Buffer.alloc(32)
});

const MANIFEST = Buffer.concat([Buffer.from([0x08, 0x01, 0x12, 0x20]), SERVICE]); // version 1, service, no endpoints
const MANIFEST_COMMITMENT = unhex(keccak256(MANIFEST));

/// The manifests ClprVerifierComplianceTest commits to (`_buildManifest(version, service, endpoints)`
/// encoded by ClprProtobuf.encodeEndpointManifest): field 1 version (omitted when 0), field 2
/// service, then per endpoint {ip "10.0.0.1", port 50211 + i, accountId i + 1}.
const FOREIGN_SERVICE = unhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
function complianceManifest(version: number, service: Buffer, endpoints: number): Buffer {
    const parts: Buffer[] = [];
    if (version > 0) parts.push(Buffer.from([0x08, version]));
    parts.push(Buffer.from([0x12, service.length]), service);
    for (let i = 0; i < endpoints; i++) {
        const port = 50211 + i;
        const varint = Buffer.from([(port & 0x7f) | 0x80, ((port >> 7) & 0x7f) | 0x80, port >> 14]);
        const ep = Buffer.concat([Buffer.from([0x0a, 0x08]), Buffer.from("10.0.0.1"), Buffer.from([0x10]), varint]);
        const body = Buffer.concat([Buffer.from([0x0a, ep.length]), ep, Buffer.from([0x1a, 0x01, i + 1])]);
        parts.push(Buffer.from([0x1a, body.length]), body);
    }
    return Buffer.concat(parts);
}
const COMPLIANCE_MANIFESTS: Record<string, Buffer> = {
    cm_3_2: complianceManifest(3, SERVICE, 2),
    cm_1_1: complianceManifest(1, SERVICE, 1),
    cm_foreign: complianceManifest(1, FOREIGN_SERVICE, 1),
    cm_0_1: complianceManifest(0, SERVICE, 1),
    cm_1_0: complianceManifest(1, SERVICE, 0),
    cm_7_0: complianceManifest(7, SERVICE, 0)
};

/// ClprVerifierComplianceTest's running-hash vector: one DATA payload encodeDataMessage(01, 02, 03, 04).
const COMPLIANCE_PAYLOAD = unhex(
    "0a2b0a2001000000000000000000000000000000000000000000000000000000000000001201021a0103220104"
);
const COMPLIANCE_RUNNING_HASH = sha256(Buffer.concat([Buffer.alloc(32), sha256(COMPLIANCE_PAYLOAD)]));

const txs: Record<string, SorobanTx> = {
    ...Object.fromEntries(
        Object.entries(COMPLIANCE_MANIFESTS).map(([k, m]) => [
            k,
            sorobanTx(k, [manifestEvent(SERVICE, unhex(keccak256(m)))])
        ])
    ),
    queueRunningHash: sorobanTx("queueRunningHash", [
        queueEvent(SERVICE, CHANNEL_ID, {
            ...meta(1),
            nextMessageId: 2n,
            sentRunningHash: COMPLIANCE_RUNNING_HASH,
            receivedMessageId: 0n
        })
    ]),
    queueStale: sorobanTx("queueStale", [
        queueEvent(SERVICE, CHANNEL_ID, {...meta(1), nextMessageId: 1n, sentRunningHash: Buffer.alloc(32), receivedMessageId: 0n})
    ]),
    manifest: sorobanTx("manifest", [manifestEvent(SERVICE, MANIFEST_COMMITMENT)]),
    queue: sorobanTx("queue", [queueEvent(SERVICE, CHANNEL_ID, meta(1))]),
    wrongEmitter: sorobanTx("wrongEmitter", [queueEvent(OTHER_CONTRACT, CHANNEL_ID, meta(1))]),
    wrongChannel: sorobanTx("wrongChannel", [queueEvent(SERVICE, sha256(Buffer.from("other channel")), meta(1))]),
    badStatus: sorobanTx("badStatus", [queueEvent(SERVICE, CHANNEL_ID, meta(9))]),
    otherEvent: sorobanTx("otherEvent", [
        contractEvent(SERVICE, [Buffer.concat([u32be(15), xdrOpaque(Buffer.from("transfer"))])], Buffer.concat([u32be(1)]))
    ]),
    queueLater: sorobanTx("queueLater", [queueEvent(SERVICE, CHANNEL_ID, meta(1))])
};

const results = new Map<number, Buffer>();
const pairsAt = new Map<number, Buffer[]>([
    [100, [classicPair("c100"), sorobanPair(txs.manifest), ...Object.keys(COMPLIANCE_MANIFESTS).map((k) => sorobanPair(txs[k]))]],
    [
        103,
        [
            classicPair("c103"),
            sorobanPair(txs.queue),
            sorobanPair(txs.wrongEmitter),
            sorobanPair(txs.wrongChannel),
            sorobanPair(txs.badStatus),
            sorobanPair(txs.otherEvent),
            sorobanPair(txs.queueRunningHash)
        ]
    ],
    [110, [sorobanPair(txs.queueLater), classicPair("c110"), sorobanPair(txs.queueStale)]]
]);
const txLedger: Record<string, number> = {
    ...Object.fromEntries(Object.keys(COMPLIANCE_MANIFESTS).map((k) => [k, 100])),
    queueRunningHash: 103,
    queueStale: 110,
    manifest: 100,
    queue: 103,
    wrongEmitter: 103,
    wrongChannel: 103,
    badStatus: 103,
    otherEvent: 103,
    queueLater: 110
};

// ── Ledger chain ──────────────────────────────────────────────────────────────

const FIRST = 100;
const LAST = 122;
const headers = new Map<number, Buffer>();
const txSets = new Map<number, Buffer>();
const values = new Map<number, Buffer>();

function stellarValue(txSetHash: Buffer, closeTime: bigint): Buffer {
    // StellarValue { txSetHash; closeTime; upgrades<6> = []; ext SIGNED { NodeID; Signature } }
    const lcSig = Buffer.concat([u32be(0), unhex(pub("A0")), xdrOpaque(sha256(txSetHash).subarray(0, 32))]);
    return Buffer.concat([txSetHash, u64be(closeTime), u32be(0), u32be(1), lcSig]);
}

let prevHash = sha256(Buffer.from("synthetic genesis"));
for (let seq = FIRST; seq <= LAST; seq++) {
    const txSet = Buffer.concat([u32be(1), prevHash, u32be(0)]); // GeneralizedTransactionSet v1, no phases
    txSets.set(seq, txSet);
    const rs = resultSet(pairsAt.get(seq) ?? [classicPair(`c${seq}`)]);
    results.set(seq, rs);
    const sv = stellarValue(sha256(txSet), 1_790_000_000n + BigInt(seq) * 5n);
    values.set(seq, sv);
    const ext = seq === 104 ? Buffer.concat([u32be(1), u32be(0), u32be(0)]) : u32be(0); // one v1 extension
    const header = Buffer.concat([
        u32be(25),
        prevHash,
        sv,
        sha256(rs),
        sha256(Buffer.from(`bucket list ${seq}`)),
        u32be(seq),
        u64be(1_054_439_020_873_472_865n), // totalCoins
        u64be(1_000_000n), // feePool
        u32be(0), // inflationSeq
        u64be(BigInt(seq) * 1000n), // idPool
        u32be(100), // baseFee
        u32be(5_000_000), // baseReserve
        u32be(1000), // maxTxSetSize
        Buffer.alloc(128), // skipList
        ext
    ]);
    headers.set(seq, header);
    prevHash = sha256(header);
}

// ── SCP envelopes ─────────────────────────────────────────────────────────────

function externalize(node: string, slot: number, qset: Buffer, value = values.get(slot)!) {
    const statement = Buffer.concat([
        u32be(0),
        unhex(pub(node)),
        u64be(BigInt(slot)),
        u32be(2), // EXTERNALIZE
        u32be(1), // commit.counter
        xdrOpaque(value),
        u32be(1), // nH
        sha256(qset)
    ]);
    const signature = Buffer.from(ed25519.sign(scpSignedMessage(NETWORK_ID, statement), keys.get(node)!.priv));
    return {node, nodeId: hex(unhex(pub(node))), statement: hex(statement), signature: hex(signature)};
}

const slot = (s: number, nodes: string[], qset: Buffer) =>
    nodes.map((n) => externalize(n, s, qset)).sort((a, b) => a.nodeId.localeCompare(b.nodeId));

const slots = {
    "101": slot(101, ["A0", "A1", "B0", "B1"], Q1X),
    "105": slot(105, ["A0", "A1", "A2", "B0", "B1", "C0", "C1"], Q1X),
    "105D": slot(105, ["D0"], Q1X),
    "105other": [externalize("C2", 105, Q1X, values.get(106)!)],
    "112": slot(112, ["A0", "A1", "B0", "B1"], Q1X),
    "120": slot(120, ["A0", "A1", "B0", "B1", "C0"], Q2X),
    "120old": slot(120, ["C1", "C2"], Q1X),
    "122": slot(122, ["A0", "A1", "B0", "B1", "D0", "D1"], Q2X)
};
const all = ["A0", "A1", "A2", "B0", "B1", "B2", "C0", "C1", "C2", "D0", "D1", "D2"];
const fixture = {
    networkId: hex(NETWORK_ID),
    serviceContract: hex(SERVICE),
    otherContract: hex(OTHER_CONTRACT),
    channelId: hex(CHANNEL_ID),
    q1: hex(Q1X),
    q1Hash: hex(sha256(Q1X)),
    q2: hex(Q2X),
    q2Hash: hex(sha256(Q2X)),
    validators: Object.fromEntries(all.map((n) => [n, hex(unhex(pub(n)))])),
    headers: Object.fromEntries([...headers].map(([k, v]) => [String(k), hex(v)])),
    headerHashes: Object.fromEntries([...headers].map(([k, v]) => [String(k), hex(sha256(v))])),
    txSets: Object.fromEntries([...txSets].map(([k, v]) => [String(k), hex(v)])),
    slots,
    slotNodes: Object.fromEntries(Object.entries(slots).map(([k, v]) => [k, v.map((e) => e.node)])),
    attestations: Object.fromEntries(
        Object.entries(txs).map(([name, t]) => {
            const rs = results.get(txLedger[name])!;
            return [
                name,
                {
                    ledger: txLedger[name],
                    txPayload: hex(t.payload),
                    resultSet: hex(rs),
                    offset: rs.indexOf(sha256(t.payload)),
                    preimage: hex(t.preimage)
                }
            ];
        })
    ),
    manifest: hex(MANIFEST),
    complianceManifests: Object.fromEntries(Object.entries(COMPLIANCE_MANIFESTS).map(([k, m]) => [k, hex(m)])),
    complianceRunningHash: hex(COMPLIANCE_RUNNING_HASH),
    manifestCommitment: hex(MANIFEST_COMMITMENT),
    queueEventData: {
        nextMessageId: 3,
        sentRunningHash: hex(SENT_RUNNING_HASH),
        receivedMessageId: 1,
        status: 1
    }
};

mkdirSync(path.dirname(OUT), {recursive: true});
writeFileSync(OUT, JSON.stringify(fixture, null, 2) + "\n");
console.log(`wrote ${OUT}`);
