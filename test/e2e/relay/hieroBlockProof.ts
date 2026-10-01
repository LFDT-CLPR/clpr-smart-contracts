import {createHash} from "node:crypto";
import type {Hex} from "viem";
import {getBlockAt, type BlockNodeBlock} from "../lib/blockNodeClient.js";
import {pbBool, pbBytes, pbFindField, pbInt, pbLen, pbScanLen} from "../lib/proto.js";

/// Hiero block-root reconstruction and block-item inclusion proofs, built from the raw
/// block stream a Solo block node serves over `BlockAccessService.getBlock`.
///
/// This does not need HIP-1081 `ProofService` (absent on block node v0.33.x): the block
/// root is recomputed from the block's own items exactly as consensus node v0.74
/// `BlockStreamManagerImpl.combine` does, and checked against the successor block's
/// `BlockFooter.previous_block_root_hash`. The root is what the block's TSS (hinTS)
/// signature signs, so a block-item path to it plus that signature is an end-to-end
/// authenticated statement about anything in the block.

/// `BlockItem` oneof field numbers (block/stream/block_item.proto).
export const BI = {
    BLOCK_HEADER: 1,
    EVENT_HEADER: 2,
    ROUND_HEADER: 3,
    SIGNED_TRANSACTION: 4,
    TRANSACTION_RESULT: 5,
    TRANSACTION_OUTPUT: 6,
    STATE_CHANGES: 7,
    BLOCK_PROOF: 9,
    TRACE_DATA: 11,
    BLOCK_FOOTER: 12
} as const;

/// Which streaming sub-tree each item kind feeds (BlockStreamManagerImpl.SequentialTask).
const SUBTREE_KINDS = {
    consensusHeaders: [BI.EVENT_HEADER, BI.ROUND_HEADER],
    inputs: [BI.SIGNED_TRANSACTION],
    outputs: [BI.BLOCK_HEADER, BI.TRANSACTION_RESULT, BI.TRANSACTION_OUTPUT],
    stateChanges: [BI.STATE_CHANGES],
    traceData: [BI.TRACE_DATA]
} as const;

type SubtreeName = keyof typeof SUBTREE_KINDS;

export interface Sibling {
    isLeft: boolean;
    /// Empty = single-child (unary, `0x01`) climb.
    hash: Buffer;
}

const sha384 = (...parts: Buffer[]): Buffer => createHash("sha384").update(Buffer.concat(parts)).digest();
export const hashLeaf = (data: Buffer): Buffer => sha384(Buffer.from([0x00]), data);
const hashSingle = (child: Buffer): Buffer => sha384(Buffer.from([0x01]), child);
const hashNode = (l: Buffer, r: Buffer): Buffer => sha384(Buffer.from([0x02]), l, r);
/// `BlockStreamManager.HASH_OF_ZERO_BYTES` — root of an empty streaming tree.
const EMPTY_TREE_ROOT = sha384(Buffer.from([0x00]));

export function itemKind(item: Buffer): number {
    const first = pbScanLen(item)[0];
    if (!first) throw new Error("empty BlockItem");
    return first.field;
}

/// Perfect sub-trees left by `IncrementalStreamingHasher` after `n` leaves (largest first).
function perfectRanges(n: number): {start: number; size: number}[] {
    const out: {start: number; size: number}[] = [];
    let start = 0;
    for (let bit = 31; bit >= 0; bit--) {
        const size = 2 ** bit;
        if (n & size) {
            out.push({start, size});
            start += size;
        }
    }
    return out;
}

function perfectRoot(hashes: Buffer[]): Buffer {
    let level = hashes;
    while (level.length > 1) {
        const next: Buffer[] = [];
        for (let i = 0; i < level.length; i += 2) next.push(hashNode(level[i], level[i + 1]));
        level = next;
    }
    return level[0];
}

/// Root of an `IncrementalStreamingHasher` over `leaves`, plus the sibling path for `index`.
export function streamingTree(leaves: Buffer[], index?: number): {root: Buffer; siblings: Sibling[]} {
    if (leaves.length === 0) return {root: EMPTY_TREE_ROOT, siblings: []};
    const hashes = leaves.map(hashLeaf);
    const ranges = perfectRanges(hashes.length);
    const roots = ranges.map((r) => perfectRoot(hashes.slice(r.start, r.start + r.size)));

    // Right fold: root = p0 ∘ (p1 ∘ (p2 ∘ …)).
    const suffix: Buffer[] = new Array(roots.length);
    suffix[roots.length - 1] = roots[roots.length - 1];
    for (let k = roots.length - 2; k >= 0; k--) suffix[k] = hashNode(roots[k], suffix[k + 1]);
    const root = suffix[0];

    const siblings: Sibling[] = [];
    if (index === undefined) return {root, siblings};
    if (index < 0 || index >= hashes.length) throw new Error(`leaf index ${index} out of range`);

    const k = ranges.findIndex((r) => index >= r.start && index < r.start + r.size);
    const {start, size} = ranges[k];
    let level = hashes.slice(start, start + size);
    let pos = index - start;
    while (level.length > 1) {
        const sibPos = pos ^ 1;
        siblings.push({isLeft: sibPos < pos, hash: level[sibPos]});
        const next: Buffer[] = [];
        for (let i = 0; i < level.length; i += 2) next.push(hashNode(level[i], level[i + 1]));
        level = next;
        pos >>= 1;
    }
    if (k < roots.length - 1) siblings.push({isLeft: false, hash: suffix[k + 1]});
    for (let j = k - 1; j >= 0; j--) siblings.push({isLeft: true, hash: roots[j]});
    return {root, siblings};
}

export interface BlockRootParts {
    root: Buffer;
    /// Sub-tree roots and fixed-tree inputs, keyed for sibling lookup.
    prevBlockRoot: Buffer;
    prevBlockRootsHash: Buffer;
    startStateRoot: Buffer;
    timestampLeafHash: Buffer;
    subtrees: Record<SubtreeName, Buffer>;
}

function footerOf(block: BlockNodeBlock): Buffer {
    const item = block.items.find((it) => itemKind(it) === BI.BLOCK_FOOTER);
    const footer = item && pbFindField(item, BI.BLOCK_FOOTER);
    if (!footer) throw new Error(`block ${block.blockNumber}: no BlockFooter item`);
    return footer;
}

function subtreeLeaves(block: BlockNodeBlock, name: SubtreeName): Buffer[] {
    const kinds = SUBTREE_KINDS[name] as readonly number[];
    return block.items.filter((it) => kinds.includes(itemKind(it)));
}

/// Recompute the block root hash (consensus node v0.74 `BlockStreamManagerImpl.combine`).
export function computeBlockRoot(block: BlockNodeBlock): BlockRootParts {
    const footer = footerOf(block);
    const prevBlockRoot = pbFindField(footer, 1) ?? Buffer.alloc(0);
    const prevBlockRootsHash = pbFindField(footer, 2) ?? Buffer.alloc(0);
    const startStateRoot = pbFindField(footer, 3) ?? Buffer.alloc(0);

    const headerItem = block.items.find((it) => itemKind(it) === BI.BLOCK_HEADER);
    const header = headerItem && pbFindField(headerItem, BI.BLOCK_HEADER);
    if (!header) throw new Error(`block ${block.blockNumber}: no BlockHeader item`);
    const timestamp = pbFindField(header, 4) ?? Buffer.alloc(0);

    const subtrees = {} as Record<SubtreeName, Buffer>;
    for (const name of Object.keys(SUBTREE_KINDS) as SubtreeName[]) {
        subtrees[name] = streamingTree(subtreeLeaves(block, name)).root;
    }

    const d5n1 = hashNode(prevBlockRoot, prevBlockRootsHash);
    const d5n2 = hashNode(startStateRoot, subtrees.consensusHeaders);
    const d5n3 = hashNode(subtrees.inputs, subtrees.outputs);
    const d5n4 = hashNode(subtrees.stateChanges, subtrees.traceData);
    const d3 = hashNode(hashNode(d5n1, d5n2), hashNode(d5n3, d5n4));
    const timestampLeafHash = hashLeaf(timestamp);
    const root = hashNode(timestampLeafHash, hashSingle(d3));
    return {root, prevBlockRoot, prevBlockRootsHash, startStateRoot, timestampLeafHash, subtrees};
}

/// Sibling path from `block.items[itemIndex]` up to the block root.
export function blockItemPath(block: BlockNodeBlock, itemIndex: number): {leaf: Buffer; siblings: Sibling[]; root: Buffer} {
    const leaf = block.items[itemIndex];
    const kind = itemKind(leaf);
    const name = (Object.keys(SUBTREE_KINDS) as SubtreeName[]).find((n) =>
        (SUBTREE_KINDS[n] as readonly number[]).includes(kind)
    );
    if (!name) throw new Error(`BlockItem kind ${kind} is not hashed into the block root`);

    const leaves = subtreeLeaves(block, name);
    const idx = leaves.indexOf(leaf);
    const {siblings} = streamingTree(leaves, idx);
    const p = computeBlockRoot(block);
    const s = p.subtrees;
    const d5n1 = hashNode(p.prevBlockRoot, p.prevBlockRootsHash);
    const d5n2 = hashNode(p.startStateRoot, s.consensusHeaders);
    const d5n3 = hashNode(s.inputs, s.outputs);
    const d5n4 = hashNode(s.stateChanges, s.traceData);
    const d4n1 = hashNode(d5n1, d5n2);
    const d4n2 = hashNode(d5n3, d5n4);

    // Depth 6 → 5: pair within the fixed 8-leaf data tree.
    const depth6: Record<SubtreeName, Sibling> = {
        consensusHeaders: {isLeft: true, hash: p.startStateRoot},
        inputs: {isLeft: false, hash: s.outputs},
        outputs: {isLeft: true, hash: s.inputs},
        stateChanges: {isLeft: false, hash: s.traceData},
        traceData: {isLeft: true, hash: s.stateChanges}
    };
    const depth5: Record<SubtreeName, Sibling> = {
        consensusHeaders: {isLeft: true, hash: d5n1},
        inputs: {isLeft: false, hash: d5n4},
        outputs: {isLeft: false, hash: d5n4},
        stateChanges: {isLeft: true, hash: d5n3},
        traceData: {isLeft: true, hash: d5n3}
    };
    const depth4: Sibling = name === "consensusHeaders" ? {isLeft: false, hash: d4n2} : {isLeft: true, hash: d4n1};

    siblings.push(depth6[name], depth5[name], depth4);
    siblings.push({isLeft: false, hash: Buffer.alloc(0)}); // reserved roots 9–16: single-child climb
    siblings.push({isLeft: true, hash: p.timestampLeafHash});
    return {leaf, siblings, root: p.root};
}

/// Walk a sibling path the way `ClprMerkleProof.computeRootOfSiblings` does.
export function walkPath(leaf: Buffer, siblings: Sibling[]): Buffer {
    let acc = hashLeaf(leaf);
    for (const s of siblings) {
        if (s.hash.length === 0) acc = hashSingle(acc);
        else acc = s.isLeft ? hashNode(s.hash, acc) : hashNode(acc, s.hash);
    }
    return acc;
}

/// `MerklePath.next_path_index` terminator (`ClprMerkleProof.TERMINATOR`).
const TERMINATOR = 0xffffffffn;

export type LeafField = "block_item_leaf" | "state_item_leaf";

/// Encode a single-path Hiero `StateProof` (block/stream/state_proof.proto) carrying
/// `leaf` under `leafField` and the block's `TssSignedBlockProof`.
export function encodeStateProof(opts: {
    leaf: Buffer;
    siblings: Sibling[];
    blockSignature: Buffer;
    leafField?: LeafField;
}): Hex {
    const siblingsWire = opts.siblings.map((s) =>
        pbLen(1, Buffer.concat([s.isLeft ? pbBool(1, true) : Buffer.alloc(0), s.hash.length ? pbBytes(2, s.hash) : Buffer.alloc(0)]))
    );
    const leafFieldNum = (opts.leafField ?? "block_item_leaf") === "block_item_leaf" ? 5 : 4;
    const path = Buffer.concat([...siblingsWire, pbInt(2, TERMINATOR), pbBytes(leafFieldNum, opts.leaf)]);
    const sbp = pbBytes(1, opts.blockSignature);
    return `0x${Buffer.concat([pbLen(1, path), pbLen(2, sbp)]).toString("hex")}` as Hex;
}

/// `TssSignedBlockProof.block_signature` of a block.
export function blockSignatureOf(block: BlockNodeBlock): Buffer {
    const sig = pbFindField(block.signedBlockProof, 1);
    if (!sig) throw new Error(`block ${block.blockNumber}: signed_block_proof has no block_signature`);
    return sig;
}

/// Successor block's `BlockFooter.previous_block_root_hash` — the independent statement of
/// `block`'s root that the recomputation must match.
export async function successorAttestedRoot(blockNodeGrpc: string, blockNumber: bigint): Promise<Buffer> {
    const next = await getBlockAt(blockNodeGrpc, blockNumber + 1n);
    const prev = pbFindField(footerOf(next), 1);
    if (!prev) throw new Error(`block ${blockNumber + 1n}: footer has no previous_block_root_hash`);
    return prev;
}

/// Scan `[from, to]` for the first block item satisfying `match`.
export async function findBlockItem(
    blockNodeGrpc: string,
    from: bigint,
    to: bigint,
    match: (item: Buffer, block: BlockNodeBlock) => boolean
): Promise<{block: BlockNodeBlock; itemIndex: number} | undefined> {
    for (let n = from; n <= to; n++) {
        let block: BlockNodeBlock;
        try {
            block = await getBlockAt(blockNodeGrpc, n);
        } catch {
            continue;
        }
        const itemIndex = block.items.findIndex((it) => match(it, block));
        if (itemIndex >= 0) return {block, itemIndex};
    }
    return undefined;
}
