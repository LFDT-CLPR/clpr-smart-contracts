/// HyperEVM live fixture and proof builder for HyperEvmVerifier.
///
///   tsx test/e2e/relay/buildHyperEvmLiveProof.ts --refresh   (capture from rpc.hyperliquid.xyz/evm)
///
/// Captures a recent block that has a successful transaction with logs: the header fields (re-encoded
/// and checked against the block hash), and every receipt (eth_getBlockReceipts), so the receipts
/// trie is rebuilt locally and checked against the header's receiptsRoot. No HyperEVM node offers
/// eth_getProof, and receipts tries are not served by any RPC, so the proof is built here.
///
/// The block attestation is signed by TEST attestor keys: the attestors are a CLPR role, not a
/// Hyperliquid one, and none exists yet. Everything else is real chain data.
import {readFileSync, writeFileSync, mkdirSync} from "node:fs";
import path from "node:path";
import {keccak_256} from "@noble/hashes/sha3";
import {rlpEncode} from "../lib/rlp.js";

const RPC = process.env.HYPEREVM_RPC ?? "https://rpc.hyperliquid.xyz/evm";
const FILE = path.join(import.meta.dirname, "..", "fixtures", "hyperevm-live", "mainnet.json");
const hb = (h: string) => Buffer.from(h.replace(/^0x/, ""), "hex");
const keccak = (b: Buffer) => Buffer.from(keccak_256(b));

function q(n: string | number | bigint): Buffer {
    let h = BigInt(n).toString(16);
    if (h === "0") return Buffer.alloc(0);
    if (h.length % 2) h = "0" + h;
    return hb(h);
}

async function rpc(method: string, params: unknown[]): Promise<any> {
    const r = await fetch(RPC, {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify({jsonrpc: "2.0", id: 1, method, params})});
    const j = (await r.json()) as any;
    if (j.error) throw new Error(`${method}: ${JSON.stringify(j.error)}`);
    return j.result;
}

/// Header RLP in Cancun field order; fields absent from the JSON block are omitted from the tail.
export function encodeHeader(b: any): Buffer {
    const f: Buffer[] = [
        hb(b.parentHash),
        hb(b.sha3Uncles),
        hb(b.miner),
        hb(b.stateRoot),
        hb(b.transactionsRoot),
        hb(b.receiptsRoot),
        hb(b.logsBloom),
        q(b.difficulty),
        q(b.number),
        q(b.gasLimit),
        q(b.gasUsed),
        q(b.timestamp),
        hb(b.extraData),
        hb(b.mixHash),
        hb(b.nonce)
    ];
    const tail: [string, (v: string) => Buffer][] = [
        ["baseFeePerGas", q],
        ["withdrawalsRoot", hb],
        ["blobGasUsed", q],
        ["excessBlobGas", q],
        ["parentBeaconBlockRoot", hb],
        ["requestsHash", hb]
    ];
    for (const [k, enc] of tail) if (b[k] !== undefined) f.push(enc(b[k]));
    return rlpEncode(f);
}

export function encodeReceipt(r: any): Buffer {
    const body = rlpEncode([
        q(r.status),
        q(r.cumulativeGasUsed),
        hb(r.logsBloom),
        r.logs.map((l: any) => [hb(l.address), l.topics.map(hb), hb(l.data)])
    ]);
    const t = Number(r.type);
    return t === 0 ? body : Buffer.concat([Buffer.from([t]), body]);
}

// ── minimal Merkle-Patricia trie (build + proof) ──────────────────────────

type Item = {nib: number[]; val: Buffer};
const toNibbles = (b: Buffer) => [...b].flatMap((x) => [x >> 4, x & 15]);
function hp(nibs: number[], leaf: boolean): Buffer {
    const odd = nibs.length % 2;
    const flag = (leaf ? 2 : 0) + odd;
    const all = odd ? [flag, ...nibs] : [flag, 0, ...nibs];
    const out = Buffer.alloc(all.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = (all[2 * i] << 4) | all[2 * i + 1];
    return out;
}

/// Returns the node's RLP and, when `target` lies under it, the encoded nodes on its path.
function build(items: Item[], depth: number, target: number[] | null, proof: Buffer[]): Buffer {
    let enc: Buffer;
    const onPath = target !== null;
    const myIdx = proof.length;
    if (onPath) proof.push(Buffer.alloc(0));
    if (items.length === 1) {
        enc = rlpEncode([hp(items[0].nib.slice(depth), true), items[0].val]);
    } else {
        let pre = 0;
        while (items.every((it) => it.nib.length > depth + pre && it.nib[depth + pre] === items[0].nib[depth + pre])) pre++;
        if (pre > 0) {
            const child = build(items, depth + pre, target, proof);
            enc = rlpEncode([hp(items[0].nib.slice(depth, depth + pre), false), ref(child)]);
        } else {
            const slots: (Buffer | Buffer[] | any)[] = Array.from({length: 17}, () => Buffer.alloc(0));
            for (let n = 0; n < 16; n++) {
                const g = items.filter((it) => it.nib.length > depth && it.nib[depth] === n);
                if (g.length) {
                    const t = target && target[depth] === n ? target : null;
                    slots[n] = ref(build(g, depth + 1, t, proof));
                }
            }
            const v = items.find((it) => it.nib.length === depth);
            if (v) slots[16] = v.val;
            enc = rlpEncode(slots);
        }
    }
    if (onPath) proof[myIdx] = enc;
    return enc;
}
function ref(enc: Buffer): Buffer {
    if (enc.length < 32) throw new Error("inline trie node (unsupported by the verifier)");
    return keccak(enc);
}

export function receiptProof(receipts: Buffer[], index: number): {root: Buffer; nodes: Buffer[]} {
    const items = receipts.map((val, i) => ({nib: toNibbles(rlpEncode(q(i))), val}));
    const proof: Buffer[] = [];
    const rootEnc = build(items, 0, toNibbles(rlpEncode(q(index))), proof);
    return {root: keccak(rootEnc), nodes: proof.filter((n) => n.length > 0)};
}

export const loadHyperEvmFixture = () => JSON.parse(readFileSync(FILE, "utf8"));

async function refresh() {
    const head = BigInt(await rpc("eth_blockNumber", []));
    for (let n = head - 5n; n > head - 200n; n--) {
        const b = await rpc("eth_getBlockByNumber", [`0x${n.toString(16)}`, false]);
        const header = encodeHeader(b);
        if (!keccak(header).equals(hb(b.hash))) throw new Error(`header re-encoding mismatch at ${n}`);
        const receipts = (await rpc("eth_getBlockReceipts", [`0x${n.toString(16)}`])) as any[];
        const pick = receipts.findIndex((r) => Number(r.status) === 1 && r.logs.length > 0 && receipts.length > 2);
        if (pick < 0) continue;
        const encoded = receipts.map(encodeReceipt);
        const {root} = receiptProof(encoded, pick);
        if (!root.equals(hb(b.receiptsRoot))) throw new Error(`receipts root mismatch at ${n}`);
        mkdirSync(path.dirname(FILE), {recursive: true});
        writeFileSync(
            FILE,
            JSON.stringify(
                {
                    chain: "hyperevm-mainnet",
                    chainId: 999,
                    rpc: RPC,
                    capturedAt: new Date().toISOString(),
                    block: {number: Number(n), hash: b.hash, stateRoot: b.stateRoot, receiptsRoot: b.receiptsRoot, header: `0x${header.toString("hex")}`},
                    receipts: encoded.map((r) => `0x${r.toString("hex")}`),
                    pick: {transactionIndex: pick, logIndex: 0, txHash: receipts[pick].transactionHash, log: receipts[pick].logs[0]}
                },
                null,
                1
            ) + "\n"
        );
        console.log(`block ${n}: ${receipts.length} receipts, proving tx ${pick} (${receipts[pick].transactionHash}), stateRoot ${b.stateRoot}`);
        return;
    }
    throw new Error("no suitable block");
}

if (process.argv.includes("--refresh")) {
    refresh().catch((e) => {
        console.error(e);
        process.exit(1);
    });
}
