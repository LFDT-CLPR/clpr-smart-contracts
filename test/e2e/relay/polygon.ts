/**
 * polygon.ts — Heimdall v2 milestone + Bor MPT → PolygonPosVerifier proof encoding
 * (src/verifiers/evm/polygon).
 *
 *   PolygonPosProof { 1 bundle_content, 2 header: HeaderRef, repeated 3 hop: HeaderRef,
 *                     4 multistore CommitmentProof (store "milestone"), 5 milestone: StorageProofEntry,
 *                     6 bor_header (RLP), 7 account_proof (RLP list of nodes),
 *                     8 storage_proof (RLP list of [slot(32), [nodes]]),
 *                     9 manifest_storage_proof (same shape, one entry), 10 manifest_preimage,
 *                     11 ledger_configuration }
 *   HeaderRef / StorageProofEntry: as in cosmwasm.ts.
 *
 * Layout sources (verified 2026-10-01):
 *   heimdall-v2 ae3de38 x/milestone/types/keys.go   MilestoneMapPrefixKey 0x81, CountPrefixKey 0x83
 *   heimdall-v2 x/milestone/keeper/keeper.go        collections.NewMap(…, Uint64Key, CollValue[Milestone])
 *   heimdall-v2 proto/heimdallv2/milestone/milestone.proto  Milestone{1 proposer … 3 end_block, 4 hash, 5 bor_chain_id …}
 *   heimdall-v2 app/abci.go PreBlocker               milestone added only on a >2/3 vote-extension majority;
 *                                                    Hash = hash of the end block
 *   0xPolygon/bor core/types/block.go Header         15 legacy fields + rlp:"optional" BaseFee, WithdrawalsHash, …
 */

import {keccak256, type Hex} from "viem";
import {pbLen} from "../lib/proto.js";
import {hexToBuf, hexToTrimmedBuf, rlpEncode} from "../lib/rlp.js";

export const MILESTONE_STORE = "milestone";
export const MILESTONE_PREFIX = 0x81;
export const MILESTONE_COUNT_KEY = Buffer.from([0x83]);

export function milestoneKey(count: bigint): Buffer {
    const b = Buffer.alloc(9);
    b[0] = MILESTONE_PREFIX;
    b.writeBigUInt64BE(count, 1);
    return b;
}

/** collections.Uint64Value: 8-byte big-endian. */
export function decodeCount(value: Buffer): bigint {
    if (value.length !== 8) throw new Error(`milestone count is ${value.length} bytes`);
    return value.readBigUInt64BE(0);
}

export interface Milestone {
    startBlock: bigint;
    endBlock: bigint;
    hash: Buffer;
    borChainId: string;
}

/** Minimal protobuf reader for heimdallv2.milestone.Milestone. */
export function decodeMilestone(b: Buffer): Milestone {
    const m: Milestone = {startBlock: 0n, endBlock: 0n, hash: Buffer.alloc(0), borChainId: ""};
    let off = 0;
    const varint = (): bigint => {
        let r = 0n;
        let s = 0n;
        for (;;) {
            const x = b[off++];
            r |= BigInt(x & 0x7f) << s;
            if (!(x & 0x80)) return r;
            s += 7n;
        }
    };
    while (off < b.length) {
        const tag = Number(varint());
        const f = tag >> 3;
        const wt = tag & 7;
        if (wt === 0) {
            const v = varint();
            if (f === 2) m.startBlock = v;
            if (f === 3) m.endBlock = v;
        } else if (wt === 2) {
            const n = Number(varint());
            const d = b.subarray(off, off + n);
            off += n;
            if (f === 4) m.hash = Buffer.from(d);
            if (f === 5) m.borChainId = d.toString("utf8");
        } else throw new Error(`unexpected wire type ${wt}`);
    }
    return m;
}

const OPTIONAL_HEADER_FIELDS = ["baseFeePerGas", "withdrawalsRoot", "blobGasUsed", "excessBlobGas", "parentBeaconBlockRoot", "requestsHash"] as const;

/** go-ethereum header RLP from eth_getBlockByNumber JSON; throws unless keccak256 == block.hash. */
export function encodeBorHeader(b: Record<string, any>): Buffer {
    const fields: Buffer[] = [
        hexToBuf(b.parentHash), hexToBuf(b.sha3Uncles), hexToBuf(b.miner), hexToBuf(b.stateRoot),
        hexToBuf(b.transactionsRoot), hexToBuf(b.receiptsRoot), hexToBuf(b.logsBloom),
        hexToTrimmedBuf(b.difficulty), hexToTrimmedBuf(b.number), hexToTrimmedBuf(b.gasLimit),
        hexToTrimmedBuf(b.gasUsed), hexToTrimmedBuf(b.timestamp), hexToBuf(b.extraData),
        hexToBuf(b.mixHash), hexToBuf(b.nonce)
    ];
    // rlp:"optional" fields: present up to the last one set.
    const opt = OPTIONAL_HEADER_FIELDS.map((k) => b[k]);
    const last = opt.reduce((acc, v, i) => (v !== undefined && v !== null ? i : acc), -1);
    for (let i = 0; i <= last; i++) {
        const k = OPTIONAL_HEADER_FIELDS[i];
        const v = opt[i];
        if (v === undefined || v === null) throw new Error(`header has ${OPTIONAL_HEADER_FIELDS[last]} but not ${k}`);
        fields.push(k.endsWith("Root") || k.endsWith("Hash") ? hexToBuf(v) : hexToTrimmedBuf(v));
    }
    const rlp = rlpEncode(fields);
    if (keccak256(rlp).toLowerCase() !== String(b.hash).toLowerCase()) throw new Error(`Bor header RLP does not hash to ${b.hash}`);
    return rlp;
}

export interface EthProof {
    address: string;
    accountProof: string[];
    storageHash: string;
    codeHash: string;
    storageProof: {key: string; value: string; proof: string[]}[];
}

export const encodeAccountProof = (p: EthProof): Buffer => rlpEncode(p.accountProof.map(hexToBuf));

const slot32 = (k: string | bigint): Buffer => Buffer.from(BigInt(k).toString(16).padStart(64, "0"), "hex");

/** RLP list of [slot(32), [nodes]] for `slots`, in that order, taken from an eth_getProof result. */
export function encodeStorageProof(p: EthProof, slots: (Hex | bigint)[]): Buffer {
    const byKey = new Map(p.storageProof.map((s) => [BigInt(s.key), s]));
    return rlpEncode(slots.map((k) => {
        const s = byKey.get(BigInt(k));
        if (!s) throw new Error(`no storage proof for slot ${k}`);
        return [slot32(k), s.proof.map(hexToBuf)];
    }));
}

export function storageValue(p: EthProof, slot: Hex | bigint): bigint {
    const s = p.storageProof.find((x) => BigInt(x.key) === BigInt(slot));
    if (!s) throw new Error(`no storage proof for slot ${slot}`);
    return BigInt(s.value);
}

export interface PolygonProofParts {
    bundleContent?: Buffer;
    header: Buffer;
    hops?: Buffer[];
    multistoreProof: Buffer;
    milestoneEntry: Buffer;
    borHeader: Buffer;
    accountProof: Buffer;
    storageProof: Buffer;
    manifestStorageProof?: Buffer;
    manifestPreimage?: Buffer;
    ledgerConfiguration?: Buffer;
}

export function encodePolygonProof(p: PolygonProofParts): Buffer {
    const opt = (f: number, b?: Buffer) => (b && b.length ? pbLen(f, b) : Buffer.alloc(0));
    return Buffer.concat([
        opt(1, p.bundleContent),
        pbLen(2, p.header),
        ...(p.hops ?? []).map((h) => pbLen(3, h)),
        pbLen(4, p.multistoreProof),
        pbLen(5, p.milestoneEntry),
        pbLen(6, p.borHeader),
        pbLen(7, p.accountProof),
        pbLen(8, p.storageProof),
        opt(9, p.manifestStorageProof),
        opt(10, p.manifestPreimage),
        opt(11, p.ledgerConfiguration)
    ]);
}
