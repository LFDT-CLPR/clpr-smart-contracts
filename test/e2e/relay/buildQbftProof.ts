import {type Hex, keccak256, encodeAbiParameters} from "viem";
import {pbInt, pbBytes, pbLen} from "../lib/proto";
import {rlpEncode, rlpDecode, hexToBuf} from "../lib/rlp.js";
import {rpcCall, encodeTrustAnchor, headerValidators} from "../lib/qbft.js";

export {waitForBlock} from "../lib/qbft.js";

export interface NativeBundleMetadata {
    nextMessageId: bigint;
    sentRunningHash: Hex;
    receivedMessageId: bigint;
    receivedRunningHash: Hex;
    state: number;
}

export interface StorageProofEntry {
    key: string;
    value: string;
    proof: string[];
}

export interface EthProofResult {
    nonce: string;
    balance: string;
    storageHash: string;
    codeHash: string;
    accountProof: string[];
    storageProof: StorageProofEntry[];
}

export interface QbftProofPayload {
    proofBytes: Hex;
    trustAnchor: Hex;
    codeHash: Hex;
}

const CHANNELS_SLOT = 15n;
const MESSAGE_QUEUES_SLOT = 1n;
const MESSAGE_RUNNING_HASH_OFFSET = 1n;

function deriveMessageRunningHashSlot(channelId: Hex, messageId: bigint): Hex {
    const outer = BigInt(keccak256(encodeAbiParameters(
        [{type: "bytes32"}, {type: "uint256"}], [channelId, MESSAGE_QUEUES_SLOT]
    )));
    const inner = BigInt(keccak256(encodeAbiParameters(
        [{type: "uint256"}, {type: "uint256"}], [messageId, outer]
    )));
    const slot = (inner + MESSAGE_RUNNING_HASH_OFFSET) & ((1n << 256n) - 1n);
    return ("0x" + slot.toString(16).padStart(64, "0")) as Hex;
}

// slot+1, +2, +4, +5 relative to cBase — the four proven Channel fields.
// slot+0 (channelId self-reference) is no longer part of the storage proof;
// channelId is now carried in the ChannelContext passed to verifyBundle.
const PROVEN_STRUCT_OFFSETS = [1n, 2n, 4n, 5n, 16n];

function deriveChannelSlots(channelId: Hex): Hex[] {
    const encoded = encodeAbiParameters(
        [{type: "bytes32"}, {type: "uint256"}],
        [channelId, CHANNELS_SLOT]
    );
    const cBase = BigInt(keccak256(encoded)) & ((1n << 256n) - 1n);
    return PROVEN_STRUCT_OFFSETS.map((off) => {
        const slot = (cBase + off) & ((1n << 256n) - 1n);
        return ("0x" + slot.toString(16).padStart(64, "0")) as Hex;
    });
}

function bundleContentProto(payloads: Hex[], metadata?: NativeBundleMetadata): Buffer {
    const parts: Buffer[] = [];
    if (metadata) {
        parts.push(pbLen(1, encodeQueueMetadata(metadata)));
    }
    for (const p of payloads) {
        const inner = hexToBuf(p);
        const tag = Buffer.from([0x12]);
        const len = encodeVarint(inner.length);
        parts.push(Buffer.concat([tag, len, inner]));
    }
    return Buffer.concat(parts);
}

function encodeQueueMetadata(m: NativeBundleMetadata): Buffer {
    return Buffer.concat([
        pbInt(1, m.nextMessageId),
        pbBytes(2, hexToBuf(m.sentRunningHash)),
        pbInt(3, m.receivedMessageId),
        pbBytes(4, hexToBuf(m.receivedRunningHash)),
        pbInt(5, BigInt(m.state)),
    ]);
}

function encodeVarint(n: number): Buffer {
    const out: number[] = [];
    while (n > 0x7f) {
        out.push((n & 0x7f) | 0x80);
        n >>>= 7;
    }
    out.push(n & 0x7f);
    return Buffer.from(out);
}

export async function buildQbftProof(opts: {
    rpcUrl: string;
    serviceAddr: Hex;
    channelId: Hex;
    payloads: Hex[];
    lastMessageId?: bigint;
    metadata?: NativeBundleMetadata;
}): Promise<QbftProofPayload> {
    const {rpcUrl, serviceAddr, channelId, payloads} = opts;

    const blockTag = await rpcCall<string>(rpcUrl, "eth_blockNumber");

    const channelSlots = deriveChannelSlots(channelId);
    const msgHashSlot = opts.lastMessageId !== undefined
        ? deriveMessageRunningHashSlot(channelId, opts.lastMessageId)
        : null;

    // 5 mandatory channel-state slots + optional outbound-message hash slot.
    const storageKeys: Hex[] = msgHashSlot !== null
        ? [...channelSlots, msgHashSlot]
        : [...channelSlots];

    const proof = await rpcCall<EthProofResult>(rpcUrl, "eth_getProof", [
        serviceAddr.toLowerCase(),
        storageKeys,
        blockTag
    ]);

    if (proof.storageProof.length !== storageKeys.length) {
        throw new Error(
            `eth_getProof returned ${proof.storageProof.length} storage proof entries ` +
            `(expected ${storageKeys.length})`
        );
    }

    // Re-order by requested key to match the verifier's slot validation order.
    const storageByKey = new Map(proof.storageProof.map((sp) => [BigInt(sp.key), sp]));
    const orderedStorageProof = storageKeys.map((key) => {
        const sp = storageByKey.get(BigInt(key));
        if (!sp) throw new Error(`eth_getProof response missing requested storage key ${key}`);
        return sp;
    });

    let rawHeaderHex: string | null = null;
    try {
        rawHeaderHex = await rpcCall<string>(rpcUrl, "debug_getRawHeader", [blockTag]);
    } catch (e) {
        throw new Error(
            `debug_getRawHeader failed — the QBFT proof requires the raw header with committed seals.\n` +
                `Make sure Besu is started with --rpc-http-api=...,DEBUG and is a QBFT node.\n` +
                `Underlying error: ${String(e)}`
        );
    }
    const headerRlp = hexToBuf(rawHeaderHex);

    const accountProof = proof.accountProof.map((h) => hexToBuf(h));
    const storageProof = orderedStorageProof.map((sp) => [
        hexToBuf(sp.key),
        sp.proof.map((n) => hexToBuf(n))
    ]);
    const bundleContent = bundleContentProto(payloads, opts.metadata);

    const header = rlpDecode(headerRlp);
    const validators = headerValidators(headerRlp);
    const validatorSource = [validators.map((v) => hexToBuf(v)), []];
    const topLevel = rlpEncode([header, validatorSource, accountProof, storageProof, bundleContent]);
    const proofBytes = ("0x" + topLevel.toString("hex")) as Hex;

    const blockNum = BigInt(parseInt(blockTag, 16));
    const trustAnchor = encodeTrustAnchor(validators, proof.codeHash as Hex, blockNum - 1n);

    return {proofBytes, trustAnchor, codeHash: proof.codeHash as Hex};
}
