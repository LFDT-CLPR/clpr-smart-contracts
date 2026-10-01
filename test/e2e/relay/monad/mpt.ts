import {keccak_256} from "@noble/hashes/sha3";
import {RLP} from "@ethereumjs/rlp";

/// Minimal Merkle-Patricia trie builder (Ethereum hex-prefix encoding, keccak node hashing) used to
/// synthesise Monad state / page-storage tries and their inclusion proofs for tests.
///
/// Keys are 32-byte trie paths (already hashed by the caller); values are the leaf payload bytes
/// (e.g. an account RLP, or `0xa0 || pageCommitment` for a MIP-8 storage page).

type Entry = {nibbles: number[]; value: Uint8Array};

function toNibbles(k: Uint8Array): number[] {
    const out: number[] = [];
    for (const b of k) out.push(b >> 4, b & 15);
    return out;
}

function hexPrefix(nibbles: number[], leaf: boolean): Uint8Array {
    const odd = nibbles.length % 2 === 1;
    const flag = (leaf ? 2 : 0) + (odd ? 1 : 0);
    const all = odd ? [flag, ...nibbles] : [flag, 0, ...nibbles];
    const out = new Uint8Array(all.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = (all[2 * i] << 4) | all[2 * i + 1];
    return out;
}

export class Trie {
    readonly nodes = new Map<string, Uint8Array>();
    readonly root: Uint8Array;
    private readonly entries: Entry[];

    constructor(kv: Array<[Uint8Array, Uint8Array]>) {
        this.entries = kv.map(([k, v]) => ({nibbles: toNibbles(k), value: v}));
        if (this.entries.length === 0) {
            this.root = keccak_256(RLP.encode(new Uint8Array(0)));
            return;
        }
        const enc = this.build(this.entries, 0);
        this.root = keccak_256(enc);
        this.nodes.set(Buffer.from(this.root).toString("hex"), enc);
    }

    /// Encoded node; registers hashed children. Reference = hash (all nodes here are ≥ 32 bytes).
    private build(es: Entry[], depth: number): Uint8Array {
        if (es.length === 1) {
            return RLP.encode([hexPrefix(es[0].nibbles.slice(depth), true), es[0].value]);
        }
        // Common prefix beyond depth → extension.
        let cp = 0;
        for (;;) {
            const n = es[0].nibbles[depth + cp];
            if (depth + cp >= 64 || !es.every((e) => e.nibbles[depth + cp] === n)) break;
            cp++;
        }
        if (cp > 0) {
            const child = this.build(es, depth + cp);
            return RLP.encode([hexPrefix(es[0].nibbles.slice(depth, depth + cp), false), this.ref(child)]);
        }
        const items: Uint8Array[] = [];
        for (let n = 0; n < 16; n++) {
            const sub = es.filter((e) => e.nibbles[depth] === n);
            items.push(sub.length === 0 ? new Uint8Array(0) : this.ref(this.build(sub, depth + 1)));
        }
        items.push(new Uint8Array(0));
        return RLP.encode(items);
    }

    private ref(enc: Uint8Array): Uint8Array {
        if (enc.length < 32) throw new Error("inline trie node (unsupported by the verifier)");
        const h = keccak_256(enc);
        this.nodes.set(Buffer.from(h).toString("hex"), enc);
        return h;
    }

    /// Proof nodes from the root along `key` (inclusion or exclusion).
    proof(key: Uint8Array): Uint8Array[] {
        const nib = toNibbles(key);
        const out: Uint8Array[] = [];
        let h = Buffer.from(this.root).toString("hex");
        let depth = 0;
        for (;;) {
            const enc = this.nodes.get(h);
            if (!enc) return out;
            out.push(enc);
            const items = RLP.decode(enc) as Uint8Array[];
            if (items.length === 17) {
                const c = items[nib[depth]];
                if (c.length === 0) return out;
                h = Buffer.from(c).toString("hex");
                depth++;
            } else {
                const path = toNibbles(items[0]);
                const flag = path[0];
                const p = flag & 1 ? path.slice(1) : path.slice(2);
                if (flag & 2) return out; // leaf
                if (p.some((x, i) => nib[depth + i] !== x)) return out;
                depth += p.length;
                h = Buffer.from(items[1]).toString("hex");
            }
        }
    }
}
