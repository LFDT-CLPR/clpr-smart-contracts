/// CLPR operator relay for Canton <-> Hiero (release-today trust model: t-of-n CLPR operators).
///
/// Canton -> Hiero: each operator reads the channel's queue head from its own participant through
/// the JSON Ledger API, re-checks the running-hash chain over the payloads it is about to attest, and
/// signs the head as EIP-712 typed data (secp256k1). A coordinator collects t signatures and builds
/// the `CantonAttestedVerifier.BundleProof` that a Hiero endpoint submits to ClprService.submitBundle.
///
/// Hiero -> Canton: each operator checks the Hiero bundle with a `HieroProofChecker`, then creates a
/// `Confirmation` of the matching `DeliverInbound` action on Canton; once t exist, any operator
/// executes `ClprRules_DeliverInbound`. NOTE: there is no Hiero proof source yet, so the only checker
/// shipped here is `UnverifiedHieroProofChecker`, which checks the running-hash chain locally and
/// reports `proofVerified: false`. Swap in a real checker (HieroVerifier off-ledger, or a Daml
/// EXTERNAL_CALL extension once LF 2.4 is stable) before relying on this direction.

import {
    concat,
    encodeAbiParameters,
    getAddress,
    keccak256,
    sha256,
    toHex,
    type Address,
    type Hex,
    type TypedDataDomain
} from "viem";
import {privateKeyToAccount, type PrivateKeyAccount} from "viem/accounts";
import {CantonLedger, T, type Contract} from "./cantonLedger.js";

// ── Daml payload shapes (Daml-LF JSON) ───────────────────────────────────────

export type RunningHashScheme = "SpecDirect" | "PayloadDigest";
export const CHANNEL_STATUSES = ["Pending", "Active", "Paused", "Closing", "Drained", "Closed"] as const;
export type ChannelStatus = (typeof CHANNEL_STATUSES)[number];

export interface ChannelPayload {
    clpr: string;
    channelId: string;
    peerChainId: string;
    hashScheme: RunningHashScheme;
    status: ChannelStatus;
    nextMessageId: string;
    sentRunningHash: string;
    receivedMessageId: string;
    receivedRunningHash: string;
    ackedMessageId: string;
    endpointManifestVersion: string;
}

export interface OutboundPayload {
    clpr: string;
    channelId: string;
    messageId: string;
    sender: string;
    payloadHex: string;
    runningHashAfter: string;
}

export interface RulesPayload {
    clpr: string;
    operators: string[];
    attestationKeys: string[];
    threshold: string;
    epoch: string;
}

// ── Hashing (must match Clpr.Codec on Canton and BundleLib on Hiero) ────────

export const ZERO32: Hex = `0x${"00".repeat(32)}`;

export function nextRunningHash(scheme: RunningHashScheme, prev: Hex, payload: Hex): Hex {
    return scheme === "SpecDirect" ? sha256(concat([prev, payload])) : sha256(concat([prev, sha256(payload)]));
}

export function runningHashChain(scheme: RunningHashScheme, prev: Hex, payloads: Hex[]): Hex {
    return payloads.reduce<Hex>((h, p) => nextRunningHash(scheme, h, p), prev);
}

const hx = (s: string): Hex => (s.startsWith("0x") ? (s as Hex) : (`0x${s}` as Hex));
const unhx = (h: Hex): string => h.slice(2).toLowerCase();

// ── EIP-712 (must match CantonAttestedVerifier) ─────────────────────────────

export const EIP712_TYPES = {
    QueueHead: [
        {name: "cantonParty", type: "bytes32"},
        {name: "epoch", type: "uint64"},
        {name: "channelId", type: "bytes32"},
        {name: "messageId", type: "uint64"},
        {name: "runningHash", type: "bytes32"},
        {name: "receivedMessageId", type: "uint64"},
        {name: "receivedRunningHash", type: "bytes32"},
        {name: "status", type: "uint8"},
        {name: "endpointManifestVersion", type: "uint64"},
        {name: "payloads", type: "bytes[]"},
        {name: "manifest", type: "bytes"}
    ],
    Rotation: [
        {name: "cantonParty", type: "bytes32"},
        {name: "epoch", type: "uint64"},
        {name: "newEpoch", type: "uint64"},
        {name: "newThreshold", type: "uint16"},
        {name: "newOperators", type: "address[]"}
    ]
} as const;

export function verifierDomain(chainId: number, verifier: Address): TypedDataDomain {
    return {name: "CLPR Canton Operators", version: "1", chainId, verifyingContract: verifier};
}

export interface QueueHead {
    channelId: Hex;
    messageId: bigint;
    runningHash: Hex;
    receivedMessageId: bigint;
    receivedRunningHash: Hex;
    status: number;
    endpointManifestVersion: bigint;
}

export interface OperatorSetView {
    cantonParty: Hex;
    epoch: bigint;
    threshold: number;
    /// Sorted ascending, as the verifier requires.
    operators: Address[];
}

export interface Rotation {
    newThreshold: number;
    newOperators: Address[];
    signatures: Hex;
}

export interface AttestedHead {
    head: QueueHead;
    payloads: Hex[];
    manifest: Hex;
}

/// One 66-byte entry of the verifier's packed signature format: index || r || s || v.
export interface IndexedSig {
    index: number;
    sig: Hex; // 65-byte r||s||v
}

export function packSignatures(sigs: IndexedSig[]): Hex {
    const sorted = [...sigs].sort((a, b) => a.index - b.index);
    return concat(sorted.map((s) => concat([toHex(s.index, {size: 1}), s.sig])));
}

export function sortAddresses(addrs: Address[]): Address[] {
    return addrs.map((a) => getAddress(a)).sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : 1));
}

export const cantonPartyHash = (clprParty: string): Hex => keccak256(toHex(clprParty));

const BUNDLE_PROOF_ABI = [
    {
        type: "tuple",
        components: [
            {name: "version", type: "uint8"},
            {
                name: "rotations",
                type: "tuple[]",
                components: [
                    {name: "newThreshold", type: "uint16"},
                    {name: "newOperators", type: "address[]"},
                    {name: "signatures", type: "bytes"}
                ]
            },
            {
                name: "head",
                type: "tuple",
                components: [
                    {name: "channelId", type: "bytes32"},
                    {name: "messageId", type: "uint64"},
                    {name: "runningHash", type: "bytes32"},
                    {name: "receivedMessageId", type: "uint64"},
                    {name: "receivedRunningHash", type: "bytes32"},
                    {name: "status", type: "uint8"},
                    {name: "endpointManifestVersion", type: "uint64"}
                ]
            },
            {name: "payloads", type: "bytes[]"},
            {name: "manifest", type: "bytes"},
            {name: "signatures", type: "bytes"}
        ]
    }
] as const;

export const TRUST_ANCHOR_ABI = [
    {
        type: "tuple",
        components: [
            {name: "cantonParty", type: "bytes32"},
            {name: "epoch", type: "uint64"},
            {name: "threshold", type: "uint16"},
            {name: "operators", type: "address[]"}
        ]
    }
] as const;

export function encodeTrustAnchor(s: OperatorSetView): Hex {
    return encodeAbiParameters(TRUST_ANCHOR_ABI, [
        {cantonParty: s.cantonParty, epoch: s.epoch, threshold: s.threshold, operators: s.operators}
    ]);
}

export function encodeBundle(a: AttestedHead, rotations: Rotation[], signatures: Hex): Hex {
    return encodeAbiParameters(BUNDLE_PROOF_ABI, [
        {version: 1, rotations, head: a.head, payloads: a.payloads, manifest: a.manifest, signatures}
    ]);
}

// ── Canton reads ─────────────────────────────────────────────────────────────

export async function readChannel(ledger: CantonLedger, reader: string, channelIdHex: string) {
    const chans = await ledger.query<ChannelPayload>(reader, T.channel);
    const ch = chans.find((c) => c.payload.channelId === channelIdHex.toLowerCase());
    if (!ch) throw new Error(`channel ${channelIdHex} not found on Canton`);
    return ch;
}

export async function readRules(ledger: CantonLedger, reader: string): Promise<Contract<RulesPayload>> {
    const rules = await ledger.query<RulesPayload>(reader, T.rules);
    if (rules.length !== 1) throw new Error(`expected one ClprRules, found ${rules.length}`);
    return rules[0];
}

export function operatorSetView(rules: RulesPayload): OperatorSetView {
    return {
        cantonParty: cantonPartyHash(rules.clpr),
        epoch: BigInt(rules.epoch),
        threshold: Number(rules.threshold),
        operators: sortAddresses(rules.attestationKeys.map((k) => hx(k) as Address))
    };
}

/// The queue head an operator is willing to attest: everything after `peerReceivedMessageId`
/// (the peer's acknowledged position) up to the current head, capped at `maxMessages`.
export async function readQueueHead(
    ledger: CantonLedger,
    reader: string,
    channelIdHex: string,
    peerReceivedMessageId: bigint,
    maxMessages = 50
): Promise<AttestedHead & {scheme: RunningHashScheme; prevRunningHash: Hex}> {
    const ch = (await readChannel(ledger, reader, channelIdHex)).payload;
    const headId = BigInt(ch.nextMessageId) - 1n;
    const all = (await ledger.query<OutboundPayload>(reader, T.outbound))
        .map((c) => c.payload)
        .filter((m) => m.channelId === ch.channelId)
        .sort((a, b) => Number(BigInt(a.messageId) - BigInt(b.messageId)));
    const from = peerReceivedMessageId + 1n;
    if (headId - from + 1n > BigInt(maxMessages)) throw new Error("backlog exceeds maxMessages; page it");
    const msgs = all.filter((m) => BigInt(m.messageId) >= from && BigInt(m.messageId) <= headId);
    const prev = from === 1n ? ZERO32 : hx(all.find((m) => BigInt(m.messageId) === from - 1n)?.runningHashAfter ?? "");
    if (prev.length !== 66) throw new Error(`missing running hash before message ${from}`);
    const payloads = msgs.map((m) => hx(m.payloadHex));
    // Independent check: the stored per-message hashes and the channel head chain over the payloads.
    let h = prev;
    for (const m of msgs) {
        h = nextRunningHash(ch.hashScheme, h, hx(m.payloadHex));
        if (unhx(h) !== m.runningHashAfter) throw new Error(`running hash mismatch at message ${m.messageId}`);
    }
    if (unhx(h) !== ch.sentRunningHash) throw new Error("channel head does not match the message chain");
    return {
        scheme: ch.hashScheme,
        prevRunningHash: prev,
        payloads,
        manifest: "0x",
        head: {
            channelId: hx(ch.channelId),
            messageId: headId,
            runningHash: hx(ch.sentRunningHash),
            receivedMessageId: BigInt(ch.receivedMessageId),
            receivedRunningHash: hx(ch.receivedRunningHash),
            status: CHANNEL_STATUSES.indexOf(ch.status),
            endpointManifestVersion: BigInt(ch.endpointManifestVersion)
        }
    };
}

// ── Operator ─────────────────────────────────────────────────────────────────

export class CantonOperator {
    readonly account: PrivateKeyAccount;

    constructor(
        readonly party: string,
        attestationKey: Hex,
        readonly ledger: CantonLedger,
        readonly clprParty: string
    ) {
        this.account = privateKeyToAccount(attestationKey);
    }

    get address(): Address {
        return this.account.address;
    }

    private index(set: OperatorSetView): number {
        const i = set.operators.indexOf(getAddress(this.address));
        if (i < 0) throw new Error(`${this.address} is not in the operator set`);
        return i;
    }

    /// Sign a queue head this operator read itself.
    async signHead(domain: TypedDataDomain, set: OperatorSetView, a: AttestedHead): Promise<IndexedSig> {
        const sig = await this.account.signTypedData({
            domain,
            types: EIP712_TYPES,
            primaryType: "QueueHead",
            message: {
                cantonParty: set.cantonParty,
                epoch: set.epoch,
                ...a.head,
                payloads: a.payloads,
                manifest: a.manifest
            }
        });
        return {index: this.index(set), sig};
    }

    async signRotation(
        domain: TypedDataDomain,
        set: OperatorSetView,
        newThreshold: number,
        newOperators: Address[]
    ): Promise<IndexedSig> {
        const sig = await this.account.signTypedData({
            domain,
            types: EIP712_TYPES,
            primaryType: "Rotation",
            message: {
                cantonParty: set.cantonParty,
                epoch: set.epoch,
                newEpoch: set.epoch + 1n,
                newThreshold,
                newOperators
            }
        });
        return {index: this.index(set), sig};
    }

    /// Hiero -> Canton: check the inbound message, then confirm it on Canton.
    async confirmInbound(
        rulesCid: string,
        checker: HieroProofChecker,
        msg: HieroInboundMessage,
        recipient: string
    ): Promise<{confirmationCid: string; check: HieroCheckResult}> {
        const check = await checker.check(msg);
        if (!check.accepted) throw new Error(`Hiero check rejected message ${msg.messageId}: ${check.reason}`);
        const evs = await this.ledger.exercise(this.party, [this.clprParty], T.rules, rulesCid, "ClprRules_Confirm", {
            confirmer: this.party,
            action: {tag: "DeliverInbound", value: deliverInboundFields(msg, recipient)}
        });
        return {confirmationCid: evs.find((e) => e.templateId.endsWith(":Clpr.Rules:Confirmation"))!.contractId, check};
    }

    async executeInbound(
        rulesCid: string,
        channelCid: string,
        confirmationCids: string[],
        msg: HieroInboundMessage,
        recipient: string
    ) {
        const f = deliverInboundFields(msg, recipient);
        return this.ledger.exercise(this.party, [this.clprParty], T.rules, rulesCid, "ClprRules_DeliverInbound", {
            executor: this.party,
            confirmationCids,
            channelCid,
            messageId: f.messageId,
            payloadHex: f.payloadHex,
            runningHashAfter: f.runningHashAfter,
            peerReceivedMessageId: f.peerReceivedMessageId,
            recipient
        });
    }
}

/// Collect t head signatures from operators that each read Canton independently, and build the
/// Hiero bundle. Throws if the operators disagree on the head.
export async function buildHieroBundle(
    operators: CantonOperator[],
    domain: TypedDataDomain,
    set: OperatorSetView,
    channelIdHex: string,
    peerReceivedMessageId: bigint,
    rotations: Rotation[] = []
): Promise<{proof: Hex; attested: AttestedHead}> {
    const views = await Promise.all(
        // Each operator's participant hosts the decentralized clpr party, so it reads as clpr.
        operators.map((op) => readQueueHead(op.ledger, op.clprParty, channelIdHex, peerReceivedMessageId))
    );
    const key = (v: AttestedHead) => keccak256(encodeBundle(v, [], "0x"));
    if (new Set(views.map(key)).size !== 1) throw new Error("operators disagree on the queue head");
    const sigs = await Promise.all(operators.map((op, i) => op.signHead(domain, set, views[i])));
    if (sigs.length < set.threshold) throw new Error(`only ${sigs.length} of ${set.threshold} signatures`);
    return {proof: encodeBundle(views[0], rotations, packSignatures(sigs)), attested: views[0]};
}

// ── Hiero -> Canton proof checking (stubbed) ────────────────────────────────

export interface HieroInboundMessage {
    channelId: Hex;
    messageId: bigint;
    payload: Hex;
    /// Running hash after this message on the Hiero queue (spec running_hash_after_processing).
    runningHashAfter: Hex;
    /// Hiero's received_message_id for the Canton -> Hiero direction (its ack).
    peerReceivedMessageId: bigint;
    /// Opaque Hiero state proof (block proof + state Merkle path). Unused by the stub.
    stateProof?: Hex;
}

export interface HieroCheckResult {
    accepted: boolean;
    /// True only when a real Hiero state proof was verified.
    proofVerified: boolean;
    reason: string;
}

/// Checks a Hiero message before an operator confirms it on Canton.
export interface HieroProofChecker {
    check(msg: HieroInboundMessage): Promise<HieroCheckResult>;
}

/// STUB. There is no Hiero proof source for off-ledger checking yet, so this checker cannot verify
/// Hiero finality or state. It only recomputes the running hash from the Channel's stored
/// `receivedRunningHash` (which Canton re-checks anyway) and always reports proofVerified: false.
/// Each operator using it is trusting whatever fed it the message.
export class UnverifiedHieroProofChecker implements HieroProofChecker {
    constructor(
        private readonly prevRunningHash: () => Promise<Hex>,
        private readonly scheme: RunningHashScheme
    ) {}

    async check(msg: HieroInboundMessage): Promise<HieroCheckResult> {
        const expect = nextRunningHash(this.scheme, await this.prevRunningHash(), msg.payload);
        if (expect.toLowerCase() !== msg.runningHashAfter.toLowerCase()) {
            return {accepted: false, proofVerified: false, reason: "running hash does not chain"};
        }
        return {
            accepted: true,
            proofVerified: false,
            reason: "STUB: no Hiero proof source; state proof NOT verified, running hash chain checked only"
        };
    }
}

function deliverInboundFields(msg: HieroInboundMessage, recipient: string) {
    return {
        channelId: unhx(msg.channelId),
        messageId: msg.messageId.toString(),
        payloadHex: unhx(msg.payload),
        runningHashAfter: unhx(msg.runningHashAfter),
        peerReceivedMessageId: msg.peerReceivedMessageId.toString(),
        recipient
    };
}
