/**
 * cometbft.ts — CometBFT RPC → CometBftVerifier proof encoding.
 *
 * Turns the JSON a public CometBFT RPC serves (`/commit`, `/validators`, `/abci_query`) into the
 * protobuf layouts CometBftVerifier (src/verifiers/evm/cometbft) and SeiCometBftVerifier decode:
 *
 *   SignedHeader  { 1: Header (relay layout, see encodeHeader), 2: Commit (relay layout) }
 *   ValidatorSet  { repeated bytes 1: SimpleValidator leaf }        (CometBftVerifier only)
 *   StateProof    { 1: SignedHeader, 2: store key, 3: multistore CommitmentProof,
 *                   repeated 4: StorageProofEntry { 1: key, 2: value, 3: IAVL CommitmentProof } }
 *
 * Every hash/signature the contract checks is also checked here first (header hash == block_id,
 * validator-set hash == validators_hash, every selected signature verifies), so a fixture that
 * builds is a fixture whose cryptography is real.
 *
 * Sources (verified 2026-10-01):
 *   - Header hash / canonical vote: cometbft v0.38 types/block.go Header.Hash, types/canonical.go
 *   - SimpleValidator leaf:         types/validator.go Validator.Bytes, proto/tendermint/types/validator.proto
 *   - secp256k1eth (Heimdall v2):   github.com/0xPolygon/cometbft v0.3.8-polygon crypto/secp256k1 —
 *                                   PubKey 65 B uncompressed in PublicKey oneof field 3, sign =
 *                                   go-ethereum crypto.Sign(keccak256(signBytes)) → r‖s‖v (65 B)
 */

import {ed25519} from "@noble/curves/ed25519";
import {secp256k1} from "@noble/curves/secp256k1";
import {sha256} from "@noble/hashes/sha256";
import {keccak256, type Hex} from "viem";
import {pbLen, pbVarint} from "../lib/proto.js";

// ─── Types ──────────────────────────────────────────────────────────────────

export type KeyScheme = "ed25519" | "secp256k1eth";

export interface RpcValidator {
    address: string;
    pub_key: {type: string; value: string};
    voting_power: string;
}

export interface RpcSignedHeader {
    header: Record<string, any>;
    commit: {
        height: string;
        round: number;
        block_id: {hash: string; parts: {total: number; hash: string}};
        signatures: {block_id_flag: number; validator_address: string; timestamp: string; signature: string | null}[];
    };
}

export interface LiveValidator {
    pubKey: Buffer;
    power: bigint;
    scheme: KeyScheme;
    address: string;
}

// ─── Small helpers ──────────────────────────────────────────────────────────

const hexBuf = (h: string): Buffer => Buffer.from(h.replace(/^0x/, ""), "hex");
const b64 = (s: string): Buffer => Buffer.from(s, "base64");
export const toHex = (b: Buffer | Uint8Array): Hex => ("0x" + Buffer.from(b).toString("hex")) as Hex;
const sha = (b: Buffer): Buffer => Buffer.from(sha256(b));

/** proto3 varint field, omitted when zero. */
function pbU(field: number, v: bigint): Buffer {
    if (v === 0n) return Buffer.alloc(0);
    return Buffer.concat([pbVarint(BigInt(field << 3)), pbVarint(v)]);
}

/** proto3 bytes field, omitted when empty. */
function pbB(field: number, b: Buffer): Buffer {
    return b.length === 0 ? Buffer.alloc(0) : pbLen(field, b);
}

/** RFC 3339 with up to 9 fractional digits → [unix seconds, nanos]. */
export function parseRfc3339(t: string): [bigint, bigint] {
    const m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/.exec(t);
    if (!m) throw new Error(`bad timestamp ${t}`);
    const secs = BigInt(Date.parse(m[1] + "Z") / 1000);
    const nanos = BigInt((m[2] ?? "").padEnd(9, "0") || "0");
    return [secs, nanos];
}

function timestampProto(t: string): Buffer {
    const [s, n] = parseRfc3339(t);
    return Buffer.concat([pbU(1, s), pbU(2, n)]);
}

// ─── Tendermint simple Merkle tree (RFC 6962) ───────────────────────────────

export function simpleMerkleRoot(items: Buffer[]): Buffer {
    if (items.length === 0) return sha(Buffer.alloc(0));
    if (items.length === 1) return sha(Buffer.concat([Buffer.from([0]), items[0]]));
    let k = 1;
    while (k * 2 < items.length) k *= 2;
    return sha(Buffer.concat([Buffer.from([1]), simpleMerkleRoot(items.slice(0, k)), simpleMerkleRoot(items.slice(k))]));
}

// ─── Validators ─────────────────────────────────────────────────────────────

export function parseRpcValidator(v: RpcValidator): LiveValidator {
    const pk = b64(v.pub_key.value);
    if (v.pub_key.type === "tendermint/PubKeyEd25519") {
        if (pk.length !== 32) throw new Error("ed25519 key length");
        return {pubKey: pk, power: BigInt(v.voting_power), scheme: "ed25519", address: v.address};
    }
    if (v.pub_key.type === "cometbft/PubKeySecp256k1eth") {
        if (pk.length !== 65 || pk[0] !== 4) throw new Error("secp256k1eth key must be 65 B uncompressed");
        return {pubKey: pk, power: BigInt(v.voting_power), scheme: "secp256k1eth", address: v.address};
    }
    throw new Error(`unsupported key type ${v.pub_key.type}`);
}

/** SimpleValidator{ pub_key: PublicKey{oneof}, voting_power } — the exact validator-set Merkle leaf. */
export function validatorLeaf(v: LiveValidator): Buffer {
    const oneofField = v.scheme === "ed25519" ? 1 : 3; // ed25519 = 1, secp256k1_uncompressed = 3 (Polygon fork)
    return Buffer.concat([pbLen(1, pbLen(oneofField, v.pubKey)), pbU(2, v.power)]);
}

export function validatorSetHash(vals: LiveValidator[]): Buffer {
    return simpleMerkleRoot(vals.map(validatorLeaf));
}

/** CometBftVerifier ValidatorSet proto: repeated bytes leaf = 1. */
export function encodeValidatorSet(vals: LiveValidator[]): Buffer {
    return Buffer.concat(vals.map((v) => pbLen(1, validatorLeaf(v))));
}

// ─── Header ─────────────────────────────────────────────────────────────────

function blockIdCanonical(hash: Buffer, partTotal: bigint, partHash: Buffer): Buffer {
    // BlockID{hash=1, part_set_header=2{total=1, hash=2}} — part_set_header is non-nullable.
    return Buffer.concat([pbB(1, hash), pbLen(2, Buffer.concat([pbU(1, partTotal), pbB(2, partHash)]))]);
}

/** CometBFT Header.Hash(): simple Merkle root over 14 cdc-encoded fields. */
export function headerHash(h: Record<string, any>): Buffer {
    const bz = (f: number, b: Buffer) => pbB(f, b);
    const fields: Buffer[] = [
        Buffer.concat([pbU(1, BigInt(h.version.block)), pbU(2, BigInt(h.version.app ?? 0))]),
        bz(1, Buffer.from(h.chain_id, "utf8")),
        pbU(1, BigInt(h.height)),
        timestampProto(h.time),
        blockIdCanonical(hexBuf(h.last_block_id.hash), BigInt(h.last_block_id.parts.total), hexBuf(h.last_block_id.parts.hash)),
        bz(1, hexBuf(h.last_commit_hash)),
        bz(1, hexBuf(h.data_hash)),
        bz(1, hexBuf(h.validators_hash)),
        bz(1, hexBuf(h.next_validators_hash)),
        bz(1, hexBuf(h.consensus_hash)),
        bz(1, hexBuf(h.app_hash)),
        bz(1, hexBuf(h.last_results_hash)),
        bz(1, hexBuf(h.evidence_hash)),
        bz(1, hexBuf(h.proposer_address))
    ];
    return simpleMerkleRoot(fields);
}

/**
 * Relay header layout (SeiHeader, clpr-evm-endpoint #180): version split into two scalars and a
 * FLAT last_block_id {hash=1, part_set_total=2, part_set_hash=3}. The contract rebuilds the
 * canonical layout for hashing.
 */
export function encodeHeader(h: Record<string, any>): Buffer {
    const fixed32 = (name: string, b: Buffer) => {
        if (b.length !== 32) throw new Error(`header.${name} is ${b.length} bytes; the verifier expects 32`);
        return b;
    };
    const lb = h.last_block_id;
    return Buffer.concat([
        pbU(1, BigInt(h.version.block)),
        pbU(2, BigInt(h.version.app ?? 0)),
        pbLen(3, Buffer.from(h.chain_id, "utf8")),
        pbU(4, BigInt(h.height)),
        pbLen(5, timestampProto(h.time)),
        pbLen(6, Buffer.concat([pbB(1, hexBuf(lb.hash)), pbU(2, BigInt(lb.parts.total)), pbB(3, hexBuf(lb.parts.hash))])),
        pbLen(7, fixed32("last_commit_hash", hexBuf(h.last_commit_hash))),
        pbLen(8, fixed32("data_hash", hexBuf(h.data_hash))),
        pbLen(9, fixed32("validators_hash", hexBuf(h.validators_hash))),
        pbLen(10, fixed32("next_validators_hash", hexBuf(h.next_validators_hash))),
        pbLen(11, fixed32("consensus_hash", hexBuf(h.consensus_hash))),
        pbLen(12, fixed32("app_hash", hexBuf(h.app_hash))),
        pbLen(13, fixed32("last_results_hash", hexBuf(h.last_results_hash))),
        pbLen(14, fixed32("evidence_hash", hexBuf(h.evidence_hash))),
        pbLen(15, hexBuf(h.proposer_address))
    ]);
}

// ─── Votes ──────────────────────────────────────────────────────────────────

function sfixed64(field: number, v: bigint): Buffer {
    if (v === 0n) return Buffer.alloc(0);
    const b = Buffer.alloc(8);
    b.writeBigInt64LE(v);
    return Buffer.concat([pbVarint(BigInt((field << 3) | 1)), b]);
}

/** types.VoteSignBytes for a PRECOMMIT on (header hash, parts) — protoio.MarshalDelimited(CanonicalVote). */
export function precommitSignBytes(
    chainId: string,
    height: bigint,
    round: bigint,
    blockHash: Buffer,
    partTotal: bigint,
    partHash: Buffer,
    timestamp: string
): Buffer {
    const vote = Buffer.concat([
        pbU(1, 2n),
        sfixed64(2, height),
        sfixed64(3, round),
        pbLen(4, blockIdCanonical(blockHash, partTotal, partHash)),
        pbLen(5, timestampProto(timestamp)),
        pbB(6, Buffer.from(chainId, "utf8"))
    ]);
    return Buffer.concat([pbVarint(BigInt(vote.length)), vote]);
}

export function verifyVote(v: LiveValidator, signBytes: Buffer, sig: Buffer): boolean {
    if (v.scheme === "ed25519") return sig.length === 64 && ed25519.verify(sig, signBytes, v.pubKey);
    if (sig.length !== 65) return false;
    const digest = hexBuf(keccak256(signBytes));
    return secp256k1.verify(sig.subarray(0, 64), digest, v.pubKey, {prehash: false, lowS: true});
}

// ─── Signed header with a chosen signer subset ──────────────────────────────

export interface EncodedCommit {
    signedHeader: Buffer;
    headerHash: Buffer;
    signerIndices: number[];
    signedPower: bigint;
    totalPower: bigint;
}

/**
 * Encode `sh` with the smallest set of COMMIT signatures that clears >2/3 of `vals`' power.
 * CometBFT sorts a validator set by voting power (desc), so taking committed signers in index order
 * is taking them by power — the same order the verifier walks, so it stops at the quorum point too.
 * Every selected signature is verified here. `extra` adds that many signatures past the quorum
 * point, `all` takes every committed signature, and `only` takes exactly the given indices without
 * checking the quorum (negative tests).
 */
export function encodeSignedHeader(
    sh: RpcSignedHeader,
    vals: LiveValidator[],
    opts: {all?: boolean; extra?: number; only?: number[]} = {}
): EncodedCommit {
    const h = sh.header;
    const c = sh.commit;
    const hh = headerHash(h);
    if (!hh.equals(hexBuf(c.block_id.hash))) throw new Error("header hash != commit.block_id.hash");
    if (!validatorSetHash(vals).equals(hexBuf(h.validators_hash))) throw new Error("validator set hash mismatch");
    if (c.signatures.length !== vals.length) throw new Error("commit size != validator set size");

    const total = vals.reduce((a, v) => a + v.power, 0n);
    const chosen: number[] = [];
    let signed = 0n;
    let extra = opts.extra ?? 0;
    for (let i = 0; i < vals.length; i++) {
        const s = c.signatures[i];
        if (s.block_id_flag !== 2 || !s.signature) continue; // only COMMIT votes sign this block
        if (opts.only && !opts.only.includes(i)) continue;
        if (signed * 3n > total * 2n && !opts.all && !opts.only) {
            if (extra === 0) break;
            extra--;
        }
        const sb = precommitSignBytes(h.chain_id, BigInt(h.height), BigInt(c.round), hh, BigInt(c.block_id.parts.total), hexBuf(c.block_id.parts.hash), s.timestamp);
        if (!verifyVote(vals[i], sb, b64(s.signature))) throw new Error(`signature ${i} does not verify off-chain`);
        chosen.push(i);
        signed += vals[i].power;
    }
    if (signed * 3n <= total * 2n && !opts.only) throw new Error("commit does not reach 2/3");

    const bits = Buffer.alloc(Math.ceil(vals.length / 8));
    for (const i of chosen) bits[i >> 3] |= 0x80 >> (i & 7);
    const sigs = chosen.map((i) => pbLen(5, Buffer.concat([pbLen(1, timestampProto(c.signatures[i].timestamp)), pbLen(2, b64(c.signatures[i].signature!))])));
    const commit = Buffer.concat([
        pbU(1, BigInt(c.round)),
        pbU(2, BigInt(c.block_id.parts.total)),
        pbB(3, hexBuf(c.block_id.parts.hash)),
        pbLen(4, bits),
        ...sigs
    ]);
    return {
        signedHeader: Buffer.concat([pbLen(1, encodeHeader(h)), pbLen(2, commit)]),
        headerHash: hh,
        signerIndices: chosen,
        signedPower: signed,
        totalPower: total
    };
}

// ─── State proofs (ABCI) ────────────────────────────────────────────────────

export interface AbciStoreProof {
    key: Buffer;
    value: Buffer; // empty for an absent key
    iavlProof: Buffer; // ICS-23 CommitmentProof, IAVL spec (existence or non-existence)
    multistoreProof: Buffer; // ICS-23 CommitmentProof, Tendermint spec (store name → store root)
    height: bigint;
}

export function decodeAbciProof(resp: any, key: Buffer): AbciStoreProof {
    const r = resp.result?.response;
    if (!r || r.code !== 0) throw new Error(`abci_query failed: ${JSON.stringify(r ?? resp)}`);
    const ops = r.proofOps?.ops ?? [];
    if (ops.length !== 2 || ops[0].type !== "ics23:iavl" || ops[1].type !== "ics23:simple") {
        throw new Error(`unexpected proof ops ${ops.map((o: any) => o.type)}`);
    }
    return {
        key,
        value: r.value ? b64(r.value) : Buffer.alloc(0),
        iavlProof: b64(ops[0].data),
        multistoreProof: b64(ops[1].data),
        height: BigInt(r.height)
    };
}

export function encodeStateProof(signedHeader: Buffer, storeKey: string, entries: AbciStoreProof[]): Buffer {
    if (entries.length === 0) throw new Error("no storage entries");
    const ms = entries[0].multistoreProof;
    for (const e of entries) if (!e.multistoreProof.equals(ms)) throw new Error("entries span different heights");
    return Buffer.concat([
        pbLen(1, signedHeader),
        pbLen(2, Buffer.from(storeKey, "utf8")),
        pbLen(3, ms),
        ...entries.map((e) => pbLen(4, Buffer.concat([pbLen(1, e.key), pbB(2, e.value), pbLen(3, e.iavlProof)])))
    ]);
}

/**
 * Off-chain ICS-23 root of one CommitmentProof (existence, or the neighbour of a non-existence
 * proof), for the IAVL and Tendermint specs: leaf = sha256(prefix ‖ varint(len k) ‖ k ‖
 * varint(32) ‖ sha256(v)), inner = sha256(prefix ‖ child ‖ suffix). Used where no CometBFT RPC is
 * public (Stable) to tie `eth_getProof` output to a block's app hash; the on-chain path is Ics23Lib.
 */
export function ics23Root(commitmentProof: Buffer): {key: Buffer; value: Buffer; root: Buffer; absentKey?: Buffer} {
    const varint = (b: Buffer, i: number): [bigint, number] => {
        let x = 0n;
        for (let s = 0n; ; s += 7n) {
            const c = b[i++];
            x |= BigInt(c & 0x7f) << s;
            if (!(c & 0x80)) return [x, i];
        }
    };
    const fields = (b: Buffer): [number, Buffer][] => {
        const out: [number, Buffer][] = [];
        for (let i = 0; i < b.length; ) {
            let t: bigint, l: bigint;
            [t, i] = varint(b, i);
            if ((t & 7n) === 0n) {
                [, i] = varint(b, i);
                continue;
            }
            if ((t & 7n) !== 2n) throw new Error("unexpected wire type");
            [l, i] = varint(b, i);
            out.push([Number(t >> 3n), b.subarray(i, i + Number(l))]);
            i += Number(l);
        }
        return out;
    };
    const get = (fs: [number, Buffer][], f: number) => fs.filter((x) => x[0] === f).map((x) => x[1]);
    const exist = (ex: Buffer) => {
        const fs = fields(ex);
        const [key, value] = [get(fs, 1)[0], get(fs, 2)[0] ?? Buffer.alloc(0)];
        const prefix = get(fields(get(fs, 3)[0]), 5)[0] ?? Buffer.alloc(0);
        const hv = Buffer.from(sha256(value));
        let h = Buffer.from(sha256(Buffer.concat([prefix, pbVarint(BigInt(key.length)), key, pbVarint(BigInt(hv.length)), hv])));
        for (const op of get(fs, 4)) {
            const f = fields(op);
            h = Buffer.from(sha256(Buffer.concat([get(f, 2)[0] ?? Buffer.alloc(0), h, get(f, 3)[0] ?? Buffer.alloc(0)])));
        }
        return {key, value, root: h};
    };
    const top = fields(commitmentProof);
    const ex = get(top, 1)[0];
    if (ex) return exist(ex);
    const ne = fields(get(top, 2)[0]);
    const neighbour = get(ne, 2)[0] ?? get(ne, 3)[0];
    return {...exist(neighbour), absentKey: get(ne, 1)[0]};
}

export function evmStorageKey(prefix: number, address: Hex, slot: Hex): Buffer {
    return Buffer.concat([Buffer.from([prefix]), hexBuf(address.toLowerCase()), hexBuf(slot.replace(/^0x/, "").padStart(64, "0"))]);
}

// ─── RPC ────────────────────────────────────────────────────────────────────

async function rpc(url: string, path: string): Promise<any> {
    for (let attempt = 0; ; attempt++) {
        try {
            const r = await fetch(url.replace(/\/$/, "") + path, {signal: AbortSignal.timeout(30_000)});
            if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
            const j = (await r.json()) as any;
            if (j.error) throw new Error(JSON.stringify(j.error));
            return j;
        } catch (e) {
            if (attempt >= 3) throw new Error(`${url}${path}: ${(e as Error).message}`);
            await new Promise((res) => setTimeout(res, 1500 * (attempt + 1)));
        }
    }
}

export async function fetchStatus(url: string): Promise<any> {
    return (await rpc(url, "/status")).result;
}

export async function fetchCommit(url: string, height: bigint): Promise<{json: any; sh: RpcSignedHeader}> {
    const json = await rpc(url, `/commit?height=${height}`);
    if (!json.result.canonical) throw new Error(`commit at ${height} is not canonical yet`);
    return {json, sh: json.result.signed_header};
}

export async function fetchValidators(url: string, height: bigint): Promise<{json: any[]; vals: LiveValidator[]}> {
    const pages: any[] = [];
    const all: RpcValidator[] = [];
    for (let page = 1; ; page++) {
        const j = await rpc(url, `/validators?height=${height}&per_page=100&page=${page}`);
        pages.push(j);
        all.push(...j.result.validators);
        if (all.length >= Number(j.result.total)) break;
    }
    return {json: pages, vals: all.map(parseRpcValidator)};
}

export async function fetchAbciProof(url: string, storeName: string, key: Buffer, height: bigint): Promise<{json: any; proof: AbciStoreProof}> {
    const json = await rpc(url, `/abci_query?path=%22/store/${storeName}/key%22&data=0x${key.toString("hex")}&prove=true&height=${height}`);
    return {json, proof: decodeAbciProof(json, key)};
}
