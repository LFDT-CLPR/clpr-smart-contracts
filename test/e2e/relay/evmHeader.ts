/**
 * evmHeader.ts — RLP-encode an execution block header from `eth_getBlockByNumber` JSON, and helpers
 * for `eth_getProof` output. Shared by the Arc and Plasma relays (both run reth).
 *
 * Field order is the Ethereum header order; the post-London fields are appended only when the JSON
 * carries them, which is exactly how reth/alloy encodes `Header` (each optional field present only if
 * every earlier one is). `encodeHeader` checks keccak256(rlp) against `block.hash`.
 */

import {keccak256, toRlp, type Hex} from "viem";

export type RpcBlock = Record<string, any> & {hash: Hex; number: Hex; stateRoot: Hex};

/** Minimal-big-endian integer as RLP expects (0 → empty string). */
export function rlpInt(v: Hex | bigint | number): Hex {
    const n = BigInt(v);
    if (n === 0n) return "0x";
    let s = n.toString(16);
    if (s.length % 2) s = "0" + s;
    return `0x${s}`;
}

const REQUIRED = [
    ["parentHash", "b"], ["sha3Uncles", "b"], ["miner", "b"], ["stateRoot", "b"], ["transactionsRoot", "b"],
    ["receiptsRoot", "b"], ["logsBloom", "b"], ["difficulty", "i"], ["number", "i"], ["gasLimit", "i"],
    ["gasUsed", "i"], ["timestamp", "i"], ["extraData", "b"], ["mixHash", "b"], ["nonce", "b"]
] as const;
const OPTIONAL = [
    ["baseFeePerGas", "i"], ["withdrawalsRoot", "b"], ["blobGasUsed", "i"], ["excessBlobGas", "i"],
    ["parentBeaconBlockRoot", "b"], ["requestsHash", "b"]
] as const;

export function encodeHeader(block: RpcBlock): Hex {
    const items: Hex[] = REQUIRED.map(([k, t]) => (t === "i" ? rlpInt(block[k]) : (block[k] as Hex)));
    for (const [k, t] of OPTIONAL) {
        if (block[k] === undefined || block[k] === null) break;
        items.push(t === "i" ? rlpInt(block[k]) : (block[k] as Hex));
    }
    const rlp = toRlp(items);
    if (keccak256(rlp) !== block.hash) throw new Error(`header RLP does not hash to ${block.hash}`);
    return rlp;
}

export interface StorageProofJson {
    key: Hex;
    value: Hex;
    proof: Hex[];
}

export interface ProofJson {
    address: Hex;
    accountProof: Hex[];
    storageHash: Hex;
    codeHash: Hex;
    storageProof: StorageProofJson[];
}

/** 32-byte slot key as the verifier expects it (eth_getProof may return it unpadded). */
export function slotKey(k: Hex | bigint): Hex {
    return `0x${BigInt(k).toString(16).padStart(64, "0")}`;
}

/** ClprEvmBundleVerifier storage-proof list: RLP [[slot, [node…]], …] (values come from the leaves). */
export function storageEntries(sp: StorageProofJson[]): [Hex, Hex[]][] {
    return sp.map((s) => [slotKey(s.key), s.proof]);
}

/** Deduplicated multiproof for {MptMultiProof}: `lookups` in the exact order the verifier performs them. */
export function encodeMultiProof(lookups: Hex[][]): [Hex[], Hex] {
    const index = new Map<string, number>();
    const nodes: Hex[] = [];
    const path: number[] = [];
    for (const proof of lookups) {
        if (proof.length === 0 || proof.length > 255) throw new Error("bad proof length");
        path.push(proof.length);
        for (const n of proof) {
            const key = n.toLowerCase();
            let i = index.get(key);
            if (i === undefined) {
                i = nodes.length;
                index.set(key, i);
                nodes.push(n);
            }
            path.push(i >> 8, i & 0xff);
        }
    }
    return [nodes, `0x${Buffer.from(path).toString("hex")}`];
}

/** JSON-RPC batch POST. */
export async function rpcBatch(url: string, calls: {method: string; params: unknown[]}[]): Promise<any[]> {
    const body = calls.map((c, i) => ({jsonrpc: "2.0", id: i + 1, method: c.method, params: c.params}));
    const res = await fetch(url, {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify(body)});
    const json = (await res.json()) as any[];
    if (!Array.isArray(json)) throw new Error(`batch failed: ${JSON.stringify(json).slice(0, 300)}`);
    return calls.map((_, i) => {
        const r = json.find((x) => x.id === i + 1);
        if (!r || r.error) throw new Error(`${calls[i].method}: ${JSON.stringify(r?.error ?? "missing")}`);
        return r.result;
    });
}

export async function rpc(url: string, method: string, params: unknown[]): Promise<any> {
    return (await rpcBatch(url, [{method, params}]))[0];
}
