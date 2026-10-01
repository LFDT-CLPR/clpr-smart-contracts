import {blake2s} from "@noble/hashes/blake2.js";
import {encodeAbiParameters, keccak256, type Hex} from "viem";
import {hexToBuf, rlpEncode} from "../lib/rlp.js";
import {type EthGetProofResult} from "./buildEthMainnetProof.js";

/// Relay-side helpers for ZkSyncEraVerifier / ZkSyncStateTreeVerifier: ZKsync Era's Blake2s sparse
/// Merkle tree (zksync-era core/lib/merkle_tree), the packed tree-entry format, the L1 diamond-proxy
/// storage layout (era-contracts ZKChainStorage) and the bundle encoders.

// ── L1: ZKChainStorage (diamond proxy, slot 0) ─────────────────────────────
/// Slots confirmed against era-contracts `ZKChainStorage.sol` and live storage (Sepolia, mainnet).
export const ZKCHAIN_STORAGE_LAYOUT = {
    totalBatchesExecutedSlot: 11n,
    storedBatchHashesSlot: 14n,
    protocolVersionSlot: 33n
} as const;

export interface ZkSyncProfile {
    diamondProxy: Hex;
    totalBatchesExecutedSlot: bigint;
    storedBatchHashesSlot: bigint;
    protocolVersionSlot: bigint;
    minProtocolVersion: bigint;
    maxProtocolVersion: bigint;
}

/// Packed semver as stored in `ZKChainStorage.protocolVersion`: `minor << 32 | patch` (major 0).
export const packedProtocolVersion = (minor: number, patch: number) => (BigInt(minor) << 32n) | BigInt(patch);

export function slotHex(n: bigint): Hex {
    return ("0x" + n.toString(16).padStart(64, "0")) as Hex;
}

export function storedBatchHashSlot(batchNumber: bigint, baseSlot = ZKCHAIN_STORAGE_LAYOUT.storedBatchHashesSlot): Hex {
    return keccak256(encodeAbiParameters([{type: "uint256"}, {type: "uint256"}], [batchNumber, baseSlot]));
}

/// The three diamond slots a proof of batch `n` carries.
export function diamondSlots(batchNumber: bigint, p: Pick<ZkSyncProfile, "totalBatchesExecutedSlot" | "storedBatchHashesSlot" | "protocolVersionSlot"> = ZKCHAIN_STORAGE_LAYOUT): Hex[] {
    return [slotHex(p.totalBatchesExecutedSlot), storedBatchHashSlot(batchNumber, p.storedBatchHashesSlot), slotHex(p.protocolVersionSlot)];
}

export interface StoredBatchInfo {
    batchNumber: bigint;
    batchHash: Hex;
    indexRepeatedStorageChanges: bigint;
    numberOfLayer1Txs: bigint;
    priorityOperationsHash: Hex;
    dependencyRootsRollingHash: Hex;
    l2LogsTreeRoot: Hex;
    timestamp: bigint;
    commitment: Hex;
}

/// `abi.encode(StoredBatchInfo)` (era-contracts IExecutor, v27+; 288 bytes).
export function encodeStoredBatchInfo(b: StoredBatchInfo): Hex {
    return encodeAbiParameters(
        [{type: "uint64"}, {type: "bytes32"}, {type: "uint64"}, {type: "uint256"}, {type: "bytes32"}, {type: "bytes32"},
            {type: "bytes32"}, {type: "uint256"}, {type: "bytes32"}],
        [b.batchNumber, b.batchHash, b.indexRepeatedStorageChanges, b.numberOfLayer1Txs, b.priorityOperationsHash,
            b.dependencyRootsRollingHash, b.l2LogsTreeRoot, b.timestamp, b.commitment]
    );
}

// ── L2: the Blake2s sparse Merkle tree ─────────────────────────────────────
export const ACCOUNT_CODE_STORAGE: Hex = "0x0000000000000000000000000000000000008002";
const TREE_DEPTH = 256;

const b2 = (...parts: Uint8Array[]) => Buffer.from(blake2s(Buffer.concat(parts)));
const pad32 = (h: Hex) => hexToBuf(("0x" + h.slice(2).padStart(64, "0")) as Hex);

/// `StorageKey::raw_hashed_key`: blake2s(address left-padded to 32 ‖ slot).
export function treeKey(address: Hex, slot: Hex): Buffer {
    return b2(pad32(address), pad32(slot));
}

/// Bit `depth` of the key read as a little-endian U256 (depth 0 = leaf level).
export function keyBit(key: Buffer, depth: number): number {
    return (key[depth >> 3] >> (depth & 7)) & 1;
}

export function leafHash(leafIndex: bigint, value: Hex): Buffer {
    const idx = Buffer.alloc(8);
    idx.writeBigUInt64BE(leafIndex);
    return b2(idx, pad32(value));
}

let EMPTY: Buffer[] | undefined;
export function emptySubtreeHashes(): Buffer[] {
    if (!EMPTY) {
        EMPTY = [b2(Buffer.alloc(40))];
        for (let d = 1; d <= TREE_DEPTH; d++) EMPTY.push(b2(EMPTY[d - 1], EMPTY[d - 1]));
    }
    return EMPTY;
}

/// A `zks_getProof` storage-proof entry.
export interface ZkStorageProof {
    key: Hex;
    value: Hex;
    index: number;
    /// Siblings ROOT-TO-LEAF, leaf-side empty subtrees omitted.
    proof: Hex[];
}

/// Fold a `zks_getProof` entry to its root (TreeEntryWithProof::verify).
export function foldZkProof(address: Hex, sp: ZkStorageProof): Hex {
    const key = treeKey(address, sp.key);
    const e = emptySubtreeHashes();
    const given = sp.proof.map(hexToBuf).reverse(); // leaf-to-root
    const full = [...e.slice(0, TREE_DEPTH - given.length), ...given];
    let h = leafHash(BigInt(sp.index), sp.value);
    for (let d = 0; d < TREE_DEPTH; d++) h = keyBit(key, d) ? b2(full[d], h) : b2(h, full[d]);
    return ("0x" + h.toString("hex")) as Hex;
}

/// W-form: every 4-byte group byte-reversed (the eight little-endian Blake2s message words).
export function toWordForm(h: Buffer): Buffer {
    const out = Buffer.alloc(32);
    for (let j = 0; j < 8; j++) for (let b = 0; b < 4; b++) out[4 * j + b] = h[4 * j + 3 - b];
    return out;
}

/// One packed entry for IZkSyncStateTreeVerifier: value ‖ leafIndex(8) ‖ pathLen(2) ‖ W-form siblings.
export function packEntry(sp: Pick<ZkStorageProof, "value" | "index" | "proof">): Buffer {
    const idx = Buffer.alloc(8);
    idx.writeBigUInt64BE(BigInt(sp.index));
    const len = Buffer.alloc(2);
    len.writeUInt16BE(sp.proof.length);
    return Buffer.concat([pad32(sp.value), idx, len, ...sp.proof.map((s) => toWordForm(hexToBuf(s)))]);
}

export function packEntries(entries: Pick<ZkStorageProof, "value" | "index" | "proof">[]): Hex {
    return ("0x" + Buffer.concat(entries.map(packEntry)).toString("hex")) as Hex;
}

/// Entries proven earlier through `recordStorage`: value ‖ leafIndex 0 ‖ pathLen 0xffff, no siblings.
export function packRecordedEntries(values: Hex[]): Hex {
    return ("0x" + values.map((v) => v.slice(2).padStart(64, "0") + "0".repeat(16) + "ffff").join("")) as Hex;
}

/// In-memory sparse tree (few leaves) producing zks_getProof-shaped proofs, for synthetic fixtures.
export class SparseTree {
    private leaves = new Map<string, {key: Buffer; index: bigint; value: Hex}>();
    private nextIndex = 1n;

    set(address: Hex, slot: Hex, value: Hex): void {
        const key = treeKey(address, slot);
        const id = key.toString("hex");
        const prev = this.leaves.get(id);
        this.leaves.set(id, {key, index: prev?.index ?? this.nextIndex++, value});
    }

    /// Hash of the subtree at `depth` (0 = leaf) whose keys agree with `prefixKey` on bits > depth.
    private node(depth: number, members: {key: Buffer; index: bigint; value: Hex}[]): Buffer {
        if (members.length === 0) return emptySubtreeHashes()[depth];
        if (depth === 0) return leafHash(members[0].index, members[0].value);
        const left = members.filter((m) => keyBit(m.key, depth - 1) === 0);
        const right = members.filter((m) => keyBit(m.key, depth - 1) === 1);
        return b2(this.node(depth - 1, left), this.node(depth - 1, right));
    }

    root(): Hex {
        return ("0x" + this.node(TREE_DEPTH, [...this.leaves.values()]).toString("hex")) as Hex;
    }

    proof(address: Hex, slot: Hex): ZkStorageProof {
        const key = treeKey(address, slot);
        const leaf = this.leaves.get(key.toString("hex"));
        let members = [...this.leaves.values()];
        const siblings: Buffer[] = []; // root-to-leaf
        for (let depth = TREE_DEPTH; depth > 0; depth--) {
            const bit = keyBit(key, depth - 1);
            const same = members.filter((m) => keyBit(m.key, depth - 1) === bit);
            const other = members.filter((m) => keyBit(m.key, depth - 1) !== bit);
            siblings.push(this.node(depth - 1, other));
            members = same;
        }
        // zks_getProof omits the leaf-side run of empty-subtree siblings.
        const e = emptySubtreeHashes();
        let keep = siblings.length;
        while (keep > 0 && siblings[keep - 1].equals(e[TREE_DEPTH - keep])) keep--;
        return {
            key: slot,
            value: leaf?.value ?? slotHex(0n),
            index: Number(leaf?.index ?? 0n),
            proof: siblings.slice(0, keep).map((s) => ("0x" + s.toString("hex")) as Hex)
        };
    }
}

// ── Bundle encoding ────────────────────────────────────────────────────────
/// `[slot32, proofNodes]` entries for the requested keys, from an `eth_getProof` result.
export function l1StorageEntries(proof: EthGetProofResult, keys: Hex[]): unknown[] {
    const byKey = new Map(proof.storageProof.map((sp) => [BigInt(sp.key), sp]));
    return keys.map((k) => {
        const sp = byKey.get(BigInt(k));
        if (!sp) throw new Error(`missing storage proof for slot ${k}`);
        return [hexToBuf(slotHex(BigInt(k))), sp.proof.map(hexToBuf)];
    });
}

export function diamondProofItem(proof: EthGetProofResult, batchNumber: bigint, p?: ZkSyncProfile): unknown[] {
    return [proof.accountProof.map(hexToBuf), l1StorageEntries(proof, diamondSlots(batchNumber, p))];
}

export interface ZkSyncBundleParts {
    lightClientProof: Hex; // RLP of the 7-item light-client list (wrapped as a string)
    diamondProof: unknown[];
    storedBatchInfo: Hex;
    l2StorageProof: Hex; // packed entries
    bundleContent: Hex;
    manifest?: {proof: Hex; preimage: Hex};
}

export function encodeZkSyncBundle(p: ZkSyncBundleParts): Hex {
    const items: unknown[] = [
        hexToBuf(p.lightClientProof),
        p.diamondProof,
        hexToBuf(p.storedBatchInfo),
        hexToBuf(p.l2StorageProof),
        hexToBuf(p.bundleContent)
    ];
    if (p.manifest) items.push(hexToBuf(p.manifest.proof), hexToBuf(p.manifest.preimage));
    return ("0x" + rlpEncode(items as never).toString("hex")) as Hex;
}

/// Items 0–2 only — the `verifyL2StateRoot` input.
export function encodeZkSyncL2StateRootProof(p: Pick<ZkSyncBundleParts, "lightClientProof" | "diamondProof" | "storedBatchInfo">): Hex {
    return ("0x" + rlpEncode([hexToBuf(p.lightClientProof), p.diamondProof as never, hexToBuf(p.storedBatchInfo)])
        .toString("hex")) as Hex;
}
