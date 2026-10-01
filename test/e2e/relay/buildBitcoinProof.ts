/// Relay-side proof builder for BitcoinVerifier (Bitcoin L1 → Hiero).
///
/// Reads blocks/transactions from a Bitcoin Core JSON-RPC endpoint and produces the ABI-encoded
/// `ConfigProof` / `BundleProof` that `BitcoinVerifier.verifyConfig` / `verifyBundle` consume, plus
/// helpers to build the CLPR OP_RETURN commitment and DATA payloads on the sender side.
///
/// Byte order: Bitcoin RPC shows hashes in "display" order; the verifier works in "internal" order
/// (byte-reversed). Everything this module hands to the verifier is internal order.
import {createHash} from "node:crypto";
import {decodeAbiParameters, encodeAbiParameters, type Hex} from "viem";

// ── Bitcoin Core JSON-RPC ───────────────────────────────────────────────────

export interface BitcoinRpc {
    call<T = unknown>(method: string, params?: unknown[]): Promise<T>;
}

export function bitcoinRpc(url: string, user: string, password: string, wallet?: string): BitcoinRpc {
    const endpoint = wallet ? `${url}/wallet/${wallet}` : url;
    const auth = "Basic " + Buffer.from(`${user}:${password}`).toString("base64");
    let id = 0;
    return {
        async call<T>(method: string, params: unknown[] = []): Promise<T> {
            const res = await fetch(endpoint, {
                method: "POST",
                headers: {"content-type": "application/json", authorization: auth},
                body: JSON.stringify({jsonrpc: "1.0", id: ++id, method, params})
            });
            const body = (await res.json()) as {result: T; error: {message: string} | null};
            if (body.error) throw new Error(`bitcoind ${method}: ${body.error.message}`);
            return body.result;
        }
    };
}

// ── Byte helpers ────────────────────────────────────────────────────────────

export const strip0x = (h: string) => (h.startsWith("0x") ? h.slice(2) : h);
export const reverseHex = (h: string) => strip0x(h).match(/../g)!.reverse().join("");
/** Display-order hash (RPC) → internal-order bytes32 (verifier). */
export const toInternal = (display: string): Hex => `0x${reverseHex(display)}`;

export function sha256(data: Buffer): Buffer {
    return createHash("sha256").update(data).digest();
}

export function hash256(data: Buffer): Buffer {
    return sha256(sha256(data));
}

// ── CLPR commitment + payload (sender side) ─────────────────────────────────

export const CLPR_MAGIC = Buffer.from("CLPR", "ascii");
export const CLPR_VERSION = 1;

/** 53-byte OP_RETURN data: "CLPR" ‖ 0x01 ‖ channelTag(8) ‖ sha256(payload)(32) ‖ id(8, BE). */
export function clprCommitment(channelId: Hex, payloadHash: Buffer, messageId: bigint): Buffer {
    const tag = Buffer.from(strip0x(channelId), "hex").subarray(0, 8);
    const id = Buffer.alloc(8);
    id.writeBigUInt64BE(messageId);
    const out = Buffer.concat([CLPR_MAGIC, Buffer.from([CLPR_VERSION]), tag, payloadHash, id]);
    if (out.length !== 53) throw new Error("commitment must be 53 bytes");
    return out;
}

function varint(n: number): Buffer {
    const bytes: number[] = [];
    do {
        let b = n & 0x7f;
        n >>>= 7;
        if (n) b |= 0x80;
        bytes.push(b);
    } while (n);
    return Buffer.from(bytes);
}

function pbBytes(field: number, value: Buffer): Buffer {
    return Buffer.concat([varint((field << 3) | 2), varint(value.length), value]);
}

/** `ClprMessage { data: DataMessage { connectorId, targetApplication, sender, messageData } }`. */
export function encodeClprDataMessage(connectorId: Hex, targetApplication: Hex, sender: Hex, messageData: Buffer): Buffer {
    const inner = Buffer.concat([
        pbBytes(1, Buffer.from(strip0x(connectorId), "hex")),
        pbBytes(2, Buffer.from(strip0x(targetApplication), "hex")),
        pbBytes(3, Buffer.from(strip0x(sender), "hex")),
        pbBytes(4, messageData)
    ]);
    return pbBytes(1, inner);
}

/** BundleLib's running hash: h = sha256(h ‖ sha256(payload)), seeded with `prev`. */
export function runningHash(prev: Hex, payloads: Buffer[]): Hex {
    let h: Buffer = Buffer.from(strip0x(prev), "hex");
    for (const p of payloads) h = sha256(Buffer.concat([h, sha256(p)]));
    return `0x${h.toString("hex")}`;
}

// ── Merkle ──────────────────────────────────────────────────────────────────

/** Merkle branch (internal order, leaf-first) for `index` in a block's txid list (display order). */
export function merkleBranch(txidsDisplay: string[], index: number): {branch: Hex[]; root: Hex} {
    let level: Buffer[] = txidsDisplay.map((t) => Buffer.from(reverseHex(t), "hex"));
    const branch: Hex[] = [];
    let i = index;
    while (level.length > 1) {
        const sib = i ^ 1;
        branch.push(`0x${(sib < level.length ? level[sib] : level[i]).toString("hex")}`);
        const next: Buffer[] = [];
        for (let j = 0; j < level.length; j += 2) {
            const r = j + 1 < level.length ? level[j + 1] : level[j];
            next.push(hash256(Buffer.concat([level[j], r])));
        }
        level = next;
        i >>= 1;
    }
    return {branch, root: `0x${level[0].toString("hex")}`};
}

// ── ABI shapes (mirror BitcoinVerifier structs) ─────────────────────────────

const TX_PROOF = {
    type: "tuple",
    components: [
        {name: "headerIndex", type: "uint32"},
        {name: "txIndex", type: "uint32"},
        {name: "merkleBranch", type: "bytes32[]"},
        {name: "rawTx", type: "bytes"},
        {name: "payload", type: "bytes"}
    ]
} as const;

const CONFIG_PROOF = [
    {
        type: "tuple",
        components: [
            {name: "startHeight", type: "uint32"},
            {name: "headers", type: "bytes"},
            {...TX_PROOF, name: "genesis"}
        ]
    }
] as const;

const BUNDLE_PROOF = [
    {
        type: "tuple",
        components: [
            {name: "startHeight", type: "uint32"},
            {name: "headers", type: "bytes"},
            {...TX_PROOF, name: "messages", type: "tuple[]"}
        ]
    }
] as const;

export const CHECKPOINT = {
    type: "tuple",
    components: [
        {name: "blockHash", type: "bytes32"},
        {name: "height", type: "uint32"},
        {name: "chainWork", type: "uint256"},
        {name: "bits", type: "uint32"},
        {name: "time", type: "uint32"},
        {name: "periodStartTime", type: "uint32"}
    ]
} as const;

const TRUST_ANCHOR = [
    {
        type: "tuple",
        components: [
            {...CHECKPOINT, name: "checkpoint"},
            {name: "cursorTxid", type: "bytes32"},
            {name: "cursorVout", type: "uint32"},
            {name: "lastMessageId", type: "uint64"},
            {name: "runningHash", type: "bytes32"},
            {name: "confirmations", type: "uint8"}
        ]
    }
] as const;

export interface Checkpoint {
    blockHash: Hex;
    height: number;
    chainWork: bigint;
    bits: number;
    time: number;
    periodStartTime: number;
}

export interface TrustAnchor {
    checkpoint: Checkpoint;
    cursorTxid: Hex;
    cursorVout: number;
    lastMessageId: bigint;
    runningHash: Hex;
    confirmations: number;
}

export function decodeTrustAnchor(anchor: Hex): TrustAnchor {
    const [a] = decodeAbiParameters(TRUST_ANCHOR, anchor);
    return a as unknown as TrustAnchor;
}

interface TxProof {
    headerIndex: number;
    txIndex: number;
    merkleBranch: Hex[];
    rawTx: Hex;
    payload: Hex;
}

// ── Chain reads ─────────────────────────────────────────────────────────────

interface BlockHeaderInfo {
    hash: string;
    height: number;
    time: number;
    bits: string;
    chainwork: string;
}

/** A checkpoint (for the verifier constructor) at `height`, straight from bitcoind. */
export async function checkpointAt(rpc: BitcoinRpc, height: number, retargetInterval = 2016): Promise<Checkpoint> {
    const hash = await rpc.call<string>("getblockhash", [height]);
    const h = await rpc.call<BlockHeaderInfo>("getblockheader", [hash, true]);
    const periodStartHash = await rpc.call<string>("getblockhash", [height - (height % retargetInterval)]);
    const ps = await rpc.call<BlockHeaderInfo>("getblockheader", [periodStartHash, true]);
    return {
        blockHash: toInternal(hash),
        height,
        chainWork: BigInt("0x" + h.chainwork),
        bits: parseInt(h.bits, 16),
        time: h.time,
        periodStartTime: ps.time
    };
}

/** Concatenated raw 80-byte headers for heights [from, to]. */
export async function headersRange(rpc: BitcoinRpc, from: number, to: number): Promise<Hex> {
    const parts: string[] = [];
    for (let h = from; h <= to; h++) {
        const hash = await rpc.call<string>("getblockhash", [h]);
        parts.push(await rpc.call<string>("getblockheader", [hash, false]));
    }
    return `0x${parts.join("")}`;
}

interface TxLocation {
    height: number;
    index: number;
    branch: Hex[];
    raw: Hex;
}

/** Locate a confirmed tx and build its Merkle branch. Uses `getrawtransaction` verbose (txindex or wallet). */
export async function locateTx(rpc: BitcoinRpc, txidDisplay: string): Promise<TxLocation> {
    const tx = await rpc.call<{blockhash?: string; hex: string}>("getrawtransaction", [txidDisplay, true]);
    if (!tx.blockhash) throw new Error(`tx ${txidDisplay} is unconfirmed`);
    const block = await rpc.call<{height: number; tx: string[]; merkleroot: string}>("getblock", [tx.blockhash, 1]);
    const index = block.tx.indexOf(txidDisplay);
    const {branch, root} = merkleBranch(block.tx, index);
    if (root !== toInternal(block.merkleroot)) throw new Error("merkle root mismatch (relay bug)");
    // The raw tx is passed as-is (segwit serialization included); the verifier strips the witness.
    return {height: block.height, index, branch, raw: `0x${tx.hex}`};
}

// ── Proof builders ──────────────────────────────────────────────────────────

/// Config proof: headers from the verifier's deployment checkpoint + 1 up to the current tip, and the
/// genesis cursor tx with its inclusion proof.
export async function buildBitcoinConfigProof(
    rpc: BitcoinRpc,
    deploymentCheckpointHeight: number,
    genesisTxidDisplay: string,
    tipHeight?: number
): Promise<Hex> {
    const tip = tipHeight ?? (await rpc.call<number>("getblockcount"));
    const start = deploymentCheckpointHeight + 1;
    const g = await locateTx(rpc, genesisTxidDisplay);
    const genesis: TxProof = {
        headerIndex: g.height - start,
        txIndex: g.index,
        merkleBranch: g.branch,
        rawTx: g.raw,
        payload: "0x"
    };
    return encodeAbiParameters(CONFIG_PROOF, [
        {startHeight: start, headers: await headersRange(rpc, start, tip), genesis}
    ]);
}

export interface BitcoinMessage {
    /** txid in display (RPC) order */
    txid: string;
    /** payload preimage committed by the tx's OP_RETURN */
    payload: Buffer;
}

/// Bundle proof: headers from the anchor checkpoint + 1 (or from the lowest message block, when a
/// message sits at/below the checkpoint) to the tip, plus each message tx in queue order.
export async function buildBitcoinBundleProof(
    rpc: BitcoinRpc,
    trustAnchor: Hex,
    messages: BitcoinMessage[],
    tipHeight?: number
): Promise<{proof: Hex; startHeight: number; tipHeight: number; headerCount: number}> {
    const anchor = decodeTrustAnchor(trustAnchor);
    const tip = tipHeight ?? (await rpc.call<number>("getblockcount"));
    const located = await Promise.all(messages.map((m) => locateTx(rpc, m.txid)));
    let start = Number(anchor.checkpoint.height) + 1;
    for (const l of located) start = Math.min(start, l.height);
    const proofs: TxProof[] = located.map((l, i) => ({
        headerIndex: l.height - start,
        txIndex: l.index,
        merkleBranch: l.branch,
        rawTx: l.raw,
        payload: `0x${messages[i].payload.toString("hex")}`
    }));
    const proof = encodeAbiParameters(BUNDLE_PROOF, [
        {startHeight: start, headers: await headersRange(rpc, start, tip), messages: proofs}
    ]);
    return {proof, startHeight: start, tipHeight: tip, headerCount: tip - start + 1};
}
