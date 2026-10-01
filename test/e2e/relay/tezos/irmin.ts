import {b58payload, blake2b256, cat, u8, u16, u32, u64, type Bytes} from "./codec.js";

/// Tezos context (Irmin) Merkle proofs: the `merkle_tree_v2` RPC's JSON tree proof
/// (octez src/lib_context/merkle_proof_encoding, V2 compact encoding) re-hashed with the Tezos
/// context hashing (src/lib_context/encoding/context.ml, irmin/lib_irmin_pack/inode.ml), and turned
/// into the compact top-down path proof that `TezosContextProof.sol` checks.
///
/// Hashing (BLAKE2b-256 everywhere):
///  - contents:          H(u64be(len) ‖ value)
///  - stable node (root of a directory with ≤ 256 entries, "V1"):
///                       H(u64be(n) ‖ Σ sorted-by-name [kind8 ‖ varint(len) ‖ name ‖ u64be(32) ‖ hash])
///                       kind8 = ff00…00 for contents, 00…00 for a node
///  - inode tree (directory with > 256 entries, or below its root):
///                       H(0x01 ‖ varint(depth) ‖ varint(length) ‖ varint(k) ‖ Σ [varint(index) ‖ hash])
///  - inode values (leaf inode, ≤ 32 entries):
///                       H(0x00 ‖ varint(k) ‖ Σ [varint(len) ‖ step ‖ tag ‖ hash])  tag 0 node, 1 contents

export type Kind = "node" | "contents";

export type Tree =
    | {t: "value"; v: Buffer}
    | {t: "blinded_value"; h: Buffer}
    | {t: "node"; entries: [string, Tree][]}
    | {t: "blinded_node"; h: Buffer}
    | {t: "inode"; length: number; proofs: [number, ITree][]};

export type ITree =
    | {t: "blinded_inode"; h: Buffer}
    | {t: "inode_tree"; length: number; proofs: [number, ITree][]}
    | {t: "inode_values"; entries: [string, Tree][]}
    | {t: "inode_extender"; length: number; segment: number[]; proof: ITree};

const chash = (s: string): Buffer => b58payload(s, 32);

function varint(n: number): Buffer {
    const out: number[] = [];
    for (;;) {
        const x = n & 0x7f;
        n = Math.floor(n / 128);
        if (n) out.push(x | 0x80);
        else {
            out.push(x);
            return Buffer.from(out);
        }
    }
}

// ── JSON → typed tree ─────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type J = any;

function norm(t: J): J {
    while (t && typeof t === "object" && Object.keys(t).length === 1) {
        const k = Object.keys(t)[0];
        if (k !== "other_trees" && k !== "other_inode_trees") break;
        t = t[k];
    }
    return t;
}

/// The 5-bit index list of an inode extender segment (V2 `segment_encoding_32`).
function decodeSegment(hexStr: string): number[] {
    const b = Buffer.from(hexStr, "hex");
    const last = b[b.length - 1];
    let lastBit = 0;
    while (!(last & (1 << lastBit))) lastBit++;
    const bits = b.length * 8 - (lastBit + 1);
    const n = bits / 5;
    const out: number[] = [];
    for (let i = 0; i < n; i++) {
        let v = 0;
        for (let j = 0; j < 5; j++) {
            const bit = i * 5 + j;
            v = (v << 1) | ((b[bit >> 3] >> (7 - (bit & 7))) & 1);
        }
        out.push(v);
    }
    return out;
}

function proofsList(p: J): [number, J][] {
    p = norm(p);
    if (p.sparse_proof) return p.sparse_proof.map((x: J) => [Number(x[0]), x[1]]);
    if (p.dense_proof) {
        const out: [number, J][] = [];
        p.dense_proof.forEach((x: J, i: number) => {
            const n = norm(x);
            if (!("none" in n)) out.push([i, x]);
        });
        return out;
    }
    throw new Error("inode proofs");
}

export function parseTree(j: J): Tree {
    const t = norm(j);
    const k = Object.keys(t)[0];
    const v = t[k];
    switch (k) {
        case "value":
            return {t: "value", v: Buffer.from(v, "hex")};
        case "blinded_value":
            return {t: "blinded_value", h: chash(v)};
        case "blinded_node":
            return {t: "blinded_node", h: chash(v)};
        case "node":
            return {t: "node", entries: v.map((e: J) => [Buffer.from(e[0], "hex").toString("latin1"), parseTree(e[1])])};
        case "inode":
            return {t: "inode", length: Number(v.length), proofs: proofsList(v.proofs).map(([i, s]) => [i, parseITree(s)])};
        case "extender":
            throw new Error("irmin: extender at a directory root is not supported");
        default:
            throw new Error(`tree kind ${k}`);
    }
}

function parseITree(j: J): ITree {
    const t = norm(j);
    const k = Object.keys(t)[0];
    const v = t[k];
    switch (k) {
        case "blinded_inode":
            return {t: "blinded_inode", h: chash(v)};
        case "inode_tree":
            return {t: "inode_tree", length: Number(v.length), proofs: proofsList(v.proofs).map(([i, s]) => [i, parseITree(s)])};
        case "inode_values":
            return {t: "inode_values", entries: v.map((e: J) => [Buffer.from(e[0], "hex").toString("latin1"), parseTree(e[1])])};
        case "inode_extender":
            return {t: "inode_extender", length: Number(v.length), segment: decodeSegment(v.segment), proof: parseITree(v.proof)};
        default:
            throw new Error(`inode kind ${k}`);
    }
}

// ── hashing ────────────────────────────────────────────────────────────────

const KIND_CONTENTS = Buffer.from("ff00000000000000", "hex");
const KIND_NODE = Buffer.alloc(8);

export const contentsHash = (v: Bytes): Buffer => blake2b256(cat(u64(v.length), v));

export function v1Preimage(entries: [string, Kind, Buffer][]): Buffer {
    const sorted = [...entries].sort((a, b) => Buffer.compare(Buffer.from(a[0], "latin1"), Buffer.from(b[0], "latin1")));
    const parts: Buffer[] = [u64(sorted.length)];
    for (const [name, kind, h] of sorted) {
        const n = Buffer.from(name, "latin1");
        parts.push(kind === "contents" ? KIND_CONTENTS : KIND_NODE, varint(n.length), n, u64(32), h);
    }
    return cat(...parts);
}

export function valuesPreimage(entries: [string, Kind, Buffer][]): Buffer {
    const parts: Buffer[] = [u8(0), varint(entries.length)];
    for (const [name, kind, h] of entries) {
        const n = Buffer.from(name, "latin1");
        parts.push(varint(n.length), n, u8(kind === "node" ? 0 : 1), h);
    }
    return cat(...parts);
}

export function treePreimage(depth: number, length: number, ptrs: [number, Buffer][]): Buffer {
    const parts: Buffer[] = [u8(1), varint(depth), varint(length), varint(ptrs.length)];
    for (const [i, h] of ptrs) parts.push(varint(i), h);
    return cat(...parts);
}

export function treeHash(t: Tree): [Kind, Buffer] {
    switch (t.t) {
        case "value":
            return ["contents", contentsHash(t.v)];
        case "blinded_value":
            return ["contents", t.h];
        case "blinded_node":
            return ["node", t.h];
        case "node":
            return ["node", blake2b256(v1Preimage(t.entries.map(([n, s]) => [n, ...treeHash(s)])))];
        case "inode":
            return ["node", inodeHash({t: "inode_tree", length: t.length, proofs: t.proofs}, 0)];
    }
}

function inodeHash(t: ITree, depth: number): Buffer {
    switch (t.t) {
        case "blinded_inode":
            return t.h;
        case "inode_tree":
            return blake2b256(treePreimage(depth, t.length, t.proofs.map(([i, s]) => [i, inodeHash(s, depth + 1)])));
        case "inode_values":
            return blake2b256(valuesPreimage(t.entries.map(([n, s]) => [n, ...treeHash(s)])));
        case "inode_extender": {
            // An extender stands for single-pointer inode trees along `segment`.
            let h = inodeHash(t.proof, depth + t.segment.length);
            for (let i = t.segment.length - 1; i >= 0; i--) {
                h = blake2b256(treePreimage(depth + i, t.length, [[t.segment[i], h]]));
            }
            return h;
        }
    }
}

// ── compact path proof (TezosContextProof.sol) ────────────────────────────

/// Level kinds of the on-chain path proof.
export const LEVEL_V1 = 0;
export const LEVEL_INODE_TREE = 1;
export const LEVEL_INODE_VALUES = 2;

/// Compact top-down proof of the value at `path` under the tree root:
///   level*  := kind(1) ‖ len(u16) ‖ preimage ‖ [ptrPos(1) for inode trees]
///   value   := len(u32) ‖ bytes
/// A V1 or inode-values level is searched for the next path step by name; an inode-tree level
/// names the pointer to follow.
export function pathProof(root: Tree, path: string[]): {proof: Buffer; value: Buffer} {
    const out: Buffer[] = [];
    let cur: Tree = root;
    for (let s = 0; s < path.length; s++) {
        const step = path[s];
        let found: Tree | undefined;
        if (cur.t === "node") {
            const entries = cur.entries.map(([n, st]) => [n, ...treeHash(st)] as [string, Kind, Buffer]);
            const pre = v1Preimage(entries);
            out.push(u8(LEVEL_V1), u16(pre.length), pre);
            found = cur.entries.find(([n]) => n === step)?.[1];
        } else if (cur.t === "inode") {
            found = descendInode({t: "inode_tree", length: cur.length, proofs: cur.proofs}, 0, step, out);
        } else {
            throw new Error(`path ${path.slice(0, s + 1).join("/")}: not a directory in the proof (${cur.t})`);
        }
        if (!found) throw new Error(`path step ${step} not in proof`);
        cur = found;
    }
    if (cur.t !== "value") throw new Error(`path ${path.join("/")}: leaf is ${cur.t}`);
    out.push(u32(cur.v.length), cur.v);
    return {proof: cat(...out), value: cur.v};
}

function descendInode(t: ITree, depth: number, step: string, out: Buffer[]): Tree | undefined {
    switch (t.t) {
        case "inode_tree": {
            const ptrs = t.proofs.map(([i, s]) => [i, inodeHash(s, depth + 1)] as [number, Buffer]);
            const pre = treePreimage(depth, t.length, ptrs);
            for (let k = 0; k < t.proofs.length; k++) {
                const child = t.proofs[k][1];
                if (child.t === "blinded_inode") continue;
                const mark = out.length;
                out.push(u8(LEVEL_INODE_TREE), u16(pre.length), pre, u8(k));
                const r = descendInode(child, depth + 1, step, out);
                if (r) return r;
                out.length = mark;
            }
            return undefined;
        }
        case "inode_values": {
            const entries = t.entries.map(([n, s]) => [n, ...treeHash(s)] as [string, Kind, Buffer]);
            const hit = t.entries.find(([n]) => n === step);
            if (!hit) return undefined;
            const pre = valuesPreimage(entries);
            out.push(u8(LEVEL_INODE_VALUES), u16(pre.length), pre);
            return hit[1];
        }
        case "inode_extender": {
            for (let i = 0; i < t.segment.length; i++) {
                // expanded single-pointer levels
                let h = inodeHash(t.proof, depth + t.segment.length);
                for (let j = t.segment.length - 1; j > i; j--) h = blake2b256(treePreimage(depth + j, t.length, [[t.segment[j], h]]));
                const pre = treePreimage(depth + i, t.length, [[t.segment[i], h]]);
                out.push(u8(LEVEL_INODE_TREE), u16(pre.length), pre, u8(0));
            }
            return descendInode(t.proof, depth + t.segment.length, step, out);
        }
        default:
            return undefined;
    }
}

/// Tree root hash of a `merkle_tree_v2` RPC response (checked against its `before` hash).
export function proofRoot(json: J): {tree: Tree; root: Buffer} {
    const tree = parseTree(json.state);
    const [, root] = treeHash(tree);
    if (!root.equals(chash(json.before.node))) throw new Error("irmin: recomputed root differs from the RPC's");
    return {tree, root};
}

/// Merge two proof trees of the same root (union of revealed branches).
export function mergeTrees(a: Tree, b: Tree): Tree {
    if (a.t === "node" && b.t === "node") {
        return {
            t: "node",
            entries: a.entries.map(([n, s], i) => [n, mergeTrees(s, b.entries[i][1])]),
        };
    }
    if (a.t === "inode" && b.t === "inode") {
        return {t: "inode", length: a.length, proofs: mergeProofs(a.proofs, b.proofs)};
    }
    if (a.t.startsWith("blinded")) return b;
    return a;
}

function mergeProofs(a: [number, ITree][], b: [number, ITree][]): [number, ITree][] {
    return a.map(([i, s], k) => [i, mergeITrees(s, b[k][1])]);
}

function mergeITrees(a: ITree, b: ITree): ITree {
    if (a.t === "blinded_inode") return b;
    if (b.t === "blinded_inode") return a;
    if (a.t === "inode_tree" && b.t === "inode_tree") return {...a, proofs: mergeProofs(a.proofs, b.proofs)};
    if (a.t === "inode_values" && b.t === "inode_values") {
        return {t: "inode_values", entries: a.entries.map(([n, s], i) => [n, mergeTrees(s, b.entries[i][1])])};
    }
    return a;
}
