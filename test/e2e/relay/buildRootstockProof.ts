import {mkdirSync, readFileSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {
    concat,
    encodeAbiParameters,
    type Hex,
    keccak256,
    pad,
    toHex,
    toRlp,
    createWalletClient,
    http,
    defineChain,
    sha256
} from "viem";
import {privateKeyToAccount} from "viem/accounts";

/// Live-data proof builder for `RootstockVerifier`.
///
/// Two sources, two fixtures (test/e2e/fixtures/rootstock-live/):
///   - mainnet.json: a run of consecutive REAL Rootstock mainnet headers with their merged-mining
///     proofs (bitcoin header, compressed coinbase, RSKIP92 branch) from a public node. Public RSK
///     nodes (RSKj 9.x) expose neither eth_getProof nor raw headers, so each header's hash preimage
///     is rebuilt from eth_getBlockByNumber with RSKj's exact (partly non-minimal) RLP rules and
///     checked against the block hash.
///   - regtest.json: a real RSKj node (regtest, V0 headers, merged-mined by its own miner) with a
///     contract whose storage holds a CLPR Channel record at the exact ClprService slots, plus
///     Unitrie proofs built from the node's own trie store (dumped by UnitrieDump.java).
///
/// CLI:
///   npx tsx test/e2e/relay/buildRootstockProof.ts --refresh-mainnet [--rpc URL] [--count N]
///   npx tsx test/e2e/relay/buildRootstockProof.ts --capture-regtest --rpc http://127.0.0.1:4454
///   npx tsx test/e2e/relay/buildRootstockProof.ts --proofs-regtest --dump unitrie-dump.txt
///   npx tsx test/e2e/relay/buildRootstockProof.ts --capture-compliance --rpc http://127.0.0.1:4454
///   npx tsx test/e2e/relay/buildRootstockProof.ts --proofs-compliance --dump unitrie-dump.txt
/// (`rootstock/refresh-regtest.sh [regtest|compliance]` runs the regtest steps end to end.)

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const FIXTURE_DIR = path.resolve(__dirname, "../fixtures/rootstock-live");
export const MAINNET_FIXTURE = path.join(FIXTURE_DIR, "mainnet.json");
export const REGTEST_FIXTURE = path.join(FIXTURE_DIR, "regtest.json");

export const MAINNET_RPC = "https://public-node.rsk.co";

// ── Types ──────────────────────────────────────────────────────────────────

export interface MinedHeader {
    number: number;
    hash: Hex;
    header: Hex; // hash preimage
    coinbase: Hex;
    merkleProof: Hex;
    stateRoot: Hex;
    difficulty: string;
    timestamp: number;
}

export interface Checkpoint {
    blockHash: Hex;
    number: bigint;
    difficulty: bigint;
    timestamp: bigint;
    work: bigint;
}

export interface MainnetCapture {
    rpc: string;
    capturedAt: string;
    clientVersion: string;
    checkpoint: {hash: Hex; number: number; difficulty: string; timestamp: number};
    headers: MinedHeader[];
}

export interface RegtestCapture {
    rpc: string;
    capturedAt: string;
    clientVersion: string;
    channelId: Hex;
    service: Hex;
    slots: {slot: Hex; value: Hex}[]; // the 5 channel slots, the last-message slot, the manifest slot
    manifestPreimage: Hex;
    checkpoint: {hash: Hex; number: number; difficulty: string; timestamp: number};
    headers: MinedHeader[];
    stateIndex: number;
    proofs?: {code: Hex[]; slots: Hex[][]; manifest: Hex[]};
}

// ── JSON-RPC ───────────────────────────────────────────────────────────────

async function rpc<T>(url: string, method: string, params: unknown[]): Promise<T> {
    for (let attempt = 0; ; attempt++) {
        try {
            const r = await fetch(url, {
                method: "POST",
                headers: {"content-type": "application/json"},
                body: JSON.stringify({jsonrpc: "2.0", id: 1, method, params})
            });
            const j = (await r.json()) as {result?: T; error?: unknown};
            if (j.error) throw new Error(`${method}: ${JSON.stringify(j.error)}`);
            return j.result as T;
        } catch (e) {
            if (attempt >= 4 || String(e).includes("does not exist")) throw e;
            await new Promise((res) => setTimeout(res, 500 * (attempt + 1)));
        }
    }
}

// ── Header preimage (RSKj BlockHeader#getEncoded, V0, RSKIP92 form) ─────────

const minimal = (q: Hex): Hex => {
    const n = BigInt(q);
    if (n === 0n) return "0x";
    let h = n.toString(16);
    if (h.length % 2) h = "0" + h;
    return `0x${h}`;
};
/// BigInteger.toByteArray(): two's complement, so a leading 0x00 when the top bit is set.
const signedBytes = (q: Hex): Hex => {
    let h = BigInt(q).toString(16);
    if (h.length % 2) h = "0" + h;
    if (parseInt(h.slice(0, 2), 16) >= 0x80) h = "00" + h;
    return `0x${h}`;
};

interface RpcBlock {
    number: Hex;
    hash: Hex;
    parentHash: Hex;
    sha3Uncles: Hex;
    miner: Hex;
    stateRoot: Hex;
    transactionsRoot: Hex;
    receiptsRoot: Hex;
    logsBloom: Hex;
    difficulty: Hex;
    gasLimit: Hex;
    gasUsed: Hex;
    timestamp: Hex;
    extraData: Hex;
    paidFees: Hex;
    minimumGasPrice: Hex;
    uncles: Hex[];
    bitcoinMergedMiningHeader: Hex;
    bitcoinMergedMiningCoinbaseTransaction: Hex;
    bitcoinMergedMiningMerkleProof: Hex;
    rskPteEdges?: unknown;
    baseEvent?: unknown;
}

/// Rebuild the hash preimage from eth_getBlockByNumber (BlockHeader.java#getEncoded):
/// difficulty and gasLimit as BigInteger.toByteArray() bytes, minimumGasPrice zero as 0x00,
/// ummRoot (empty) present from RSKIPUMM. Throws unless keccak256 equals the block hash.
export function rebuildHeader(b: RpcBlock): Hex {
    const mgp = BigInt(b.minimumGasPrice) === 0n ? "0x00" : signedBytes(b.minimumGasPrice);
    const base: Hex[] = [
        b.parentHash, b.sha3Uncles, b.miner, b.stateRoot, b.transactionsRoot, b.receiptsRoot, b.logsBloom,
        signedBytes(b.difficulty), minimal(b.number), signedBytes(b.gasLimit), minimal(b.gasUsed), minimal(b.timestamp),
        b.extraData, minimal(b.paidFees), mgp, minimal(toHex(b.uncles.length))
    ];
    for (const withUmm of [true, false]) {
        const f = withUmm ? [...base, "0x" as Hex, b.bitcoinMergedMiningHeader] : [...base, b.bitcoinMergedMiningHeader];
        const enc = toRlp(f);
        if (keccak256(enc) === b.hash) return enc;
    }
    throw new Error(`cannot rebuild header preimage of block ${BigInt(b.number)} (${b.hash})`);
}

async function fetchMinedHeader(url: string, n: number): Promise<MinedHeader> {
    const b = await rpc<RpcBlock>(url, "eth_getBlockByNumber", [toHex(n), false]);
    let header: Hex;
    try {
        header = await rpc<Hex>(url, "rsk_getRawBlockHeaderByNumber", [toHex(n)]);
        if (keccak256(header) !== b.hash) throw new Error("raw header hash mismatch");
    } catch {
        header = rebuildHeader(b);
    }
    return {
        number: n,
        hash: b.hash,
        header,
        coinbase: b.bitcoinMergedMiningCoinbaseTransaction,
        merkleProof: b.bitcoinMergedMiningMerkleProof ?? "0x",
        stateRoot: b.stateRoot,
        difficulty: BigInt(b.difficulty).toString(),
        timestamp: Number(BigInt(b.timestamp))
    };
}

async function fetchRange(url: string, from: number, count: number): Promise<MinedHeader[]> {
    const out: MinedHeader[] = [];
    for (let i = 0; i < count; i++) out.push(await fetchMinedHeader(url, from + i));
    return out;
}

// ── Mainnet capture ────────────────────────────────────────────────────────

export async function captureMainnet(url = MAINNET_RPC, count = 40, depth = 60): Promise<MainnetCapture> {
    const tip = Number(BigInt(await rpc<Hex>(url, "eth_blockNumber", [])));
    const cpNum = tip - depth;
    const cp = await rpc<RpcBlock>(url, "eth_getBlockByNumber", [toHex(cpNum), false]);
    return {
        rpc: url,
        capturedAt: new Date().toISOString(),
        clientVersion: await rpc<string>(url, "web3_clientVersion", []),
        checkpoint: {hash: cp.hash, number: cpNum, difficulty: BigInt(cp.difficulty).toString(), timestamp: Number(BigInt(cp.timestamp))},
        headers: await fetchRange(url, cpNum + 1, count)
    };
}

// ── Regtest capture: a contract holding a CLPR Channel record ───────────────

const CHANNELS_BASE_SLOT = 15n;
const MESSAGE_QUEUES_BASE_SLOT = 1n;
const ENDPOINT_MANIFEST_COMMITMENT_SLOT = 18n;
/// RSKj regtest "cow" account: keccak256("cow"), funded in the regtest genesis (seedCowAccounts).
const COW_KEY = keccak256(toHex("cow"));

export function channelSlots(channelId: Hex, nextMessageId: bigint) {
    const cBase = BigInt(keccak256(encodeAbiParameters([{type: "bytes32"}, {type: "uint256"}], [channelId, CHANNELS_BASE_SLOT])));
    const qBase = keccak256(encodeAbiParameters([{type: "bytes32"}, {type: "uint256"}], [channelId, MESSAGE_QUEUES_BASE_SLOT]));
    const msgBase = BigInt(keccak256(encodeAbiParameters([{type: "uint64"}, {type: "bytes32"}], [nextMessageId - 1n, qBase])));
    const s = (n: bigint) => pad(toHex(n), {size: 32});
    return {
        channel: [s(cBase + 1n), s(cBase + 2n), s(cBase + 4n), s(cBase + 5n), s(cBase + 16n)],
        lastMessage: s(msgBase + 1n),
        manifest: s(ENDPOINT_MANIFEST_COMMITMENT_SLOT)
    };
}

/// initcode: SSTORE each (slot, value), then return a 64-byte runtime (long Unitrie value → code hash).
function storageInitcode(kv: {slot: Hex; value: Hex}[], runtime: Hex = ("0x" + "fe".repeat(64)) as Hex): Hex {
    let body = "";
    for (const {slot, value} of kv) body += "7f" + value.slice(2) + "7f" + slot.slice(2) + "55";
    // PUSH1 64 PUSH2 off PUSH1 0 CODECOPY PUSH1 64 PUSH1 0 RETURN
    const tailLen = 2 + 3 + 2 + 1 + 2 + 2 + 1;
    const off = body.length / 2 + tailLen;
    body += "6040" + "61" + off.toString(16).padStart(4, "0") + "6000" + "39" + "6040" + "6000" + "f3";
    return ("0x" + body + runtime.slice(2)) as Hex;
}

export async function captureRegtest(url: string, k = 3): Promise<RegtestCapture> {
    const channelId = keccak256(toHex("clpr/rootstock-live/regtest"));
    const nextMessageId = 3n;
    const sl = channelSlots(channelId, nextMessageId);
    const verifier = "0x00000000000000000000000000000000000c1a9e";
    // Channel slot +1: verifier(20) | status(1)=ACTIVE | nextMessageId(8)
    const w1 = (nextMessageId << 168n) | (1n << 160n) | BigInt(verifier);
    // slot +2: ackedMessageId(8) | receivedMessageId(8) | nextExpectedReplyId(8)
    const w2 = (1n << 128n) | (2n << 64n) | 2n;
    const manifestPreimage = "0x" as Hex; // no manifest commitment (slot stays absent)
    const kv = [
        {slot: sl.channel[0], value: pad(toHex(w1), {size: 32})},
        {slot: sl.channel[1], value: pad(toHex(w2), {size: 32})},
        {slot: sl.channel[2], value: keccak256(toHex("sent running hash"))},
        {slot: sl.channel[3], value: keccak256(toHex("received running hash"))},
        // slot +16 endpointManifestVersion stays 0 → proven by exclusion
        {slot: sl.lastMessage, value: keccak256(toHex("sent running hash"))}
    ];
    const chain = defineChain({id: 33, name: "rsk-regtest", nativeCurrency: {name: "RBTC", symbol: "RBTC", decimals: 18},
        rpcUrls: {default: {http: [url]}}});
    const wallet = createWalletClient({account: privateKeyToAccount(COW_KEY), chain, transport: http(url)});
    const hash = await wallet.sendTransaction({data: storageInitcode(kv), gas: 1_000_000n, gasPrice: 0n, type: "legacy"});
    let receipt: {blockNumber: Hex; contractAddress: Hex; status: Hex} | null = null;
    const deadline = Date.now() + 120_000;
    while (!receipt) {
        if (Date.now() > deadline) throw new Error("deploy not mined within 2 minutes");
        await new Promise((r) => setTimeout(r, 1000));
        receipt = await rpc(url, "eth_getTransactionReceipt", [hash]);
    }
    if (receipt.status !== "0x1") throw new Error("deploy failed");
    const deployBlock = Number(BigInt(receipt.blockNumber));
    const need = deployBlock + k;
    while (Number(BigInt(await rpc<Hex>(url, "eth_blockNumber", []))) < need) {
        if (Date.now() > deadline) throw new Error("regtest chain not advancing");
        await new Promise((r) => setTimeout(r, 1000));
    }
    const cp = await rpc<RpcBlock>(url, "eth_getBlockByNumber", [toHex(deployBlock - 1), false]);
    const headers = await fetchRange(url, deployBlock, k + 1);
    return {
        rpc: url,
        capturedAt: new Date().toISOString(),
        clientVersion: await rpc<string>(url, "web3_clientVersion", []),
        channelId,
        service: receipt.contractAddress,
        slots: [...kv.slice(0, 4), {slot: sl.channel[4], value: pad("0x00", {size: 32})}, kv[4],
            {slot: sl.manifest, value: pad("0x00", {size: 32})}],
        manifestPreimage,
        checkpoint: {hash: cp.hash, number: deployBlock - 1, difficulty: BigInt(cp.difficulty).toString(), timestamp: Number(BigInt(cp.timestamp))},
        headers,
        stateIndex: 0
    };
}

// ── Compliance capture: one service, one state per manifest ─────────────────

export const COMPLIANCE_FIXTURE = path.join(FIXTURE_DIR, "compliance.json");

/// Runtime that SSTOREs every 64-byte (slot, value) pair of its calldata, padded to 64 bytes so the
/// code is a long Unitrie value:
///   PUSH1 0; L: JUMPDEST; CALLDATASIZE DUP2 LT ISZERO PUSH1 E JUMPI;
///   DUP1 PUSH1 32 ADD CALLDATALOAD DUP2 CALLDATALOAD SSTORE PUSH1 64 ADD PUSH1 L JUMP; E: JUMPDEST STOP
export const SETTER_RUNTIME = ("0x6000" + "5b" + "36" + "81" + "10" + "15" + "6018" + "57" + "80" + "6020" + "01" + "35" + "81" +
    "35" + "55" + "6040" + "01" + "6002" + "56" + "5b" + "00").padEnd(2 + 128, "f") as Hex;

const FOREIGN_SERVICE: Hex = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

// Protobuf, as ClprProtobuf.encodeEndpointManifest (proto3: zero / empty fields omitted).
const pbVarint = (v: bigint): number[] => {
    const out: number[] = [];
    do {
        let b = Number(v & 0x7fn);
        v >>= 7n;
        if (v) b |= 0x80;
        out.push(b);
    } while (v);
    return out;
};
const pbKey = (f: number, w: number) => pbVarint(BigInt((f << 3) | w));
const pbBytes = (f: number, b: number[]) => (b.length ? [...pbKey(f, 2), ...pbVarint(BigInt(b.length)), ...b] : []);
const pbUint = (f: number, v: bigint) => (v ? [...pbKey(f, 0), ...pbVarint(v)] : []);

/// The manifest ClprVerifierComplianceTest._buildManifest builds: endpoint i = 10.0.0.1:(50211+i), account [i+1].
export function complianceManifest(version: number, service: Hex, endpoints: number): Hex {
    const out = [...pbUint(1, BigInt(version)), ...pbBytes(2, [...bytes(service)])];
    for (let i = 0; i < endpoints; i++) {
        const svc = [...pbBytes(1, [...Buffer.from("10.0.0.1")]), ...pbUint(2, BigInt(50211 + i))];
        const body = [...pbKey(1, 2), ...pbVarint(BigInt(svc.length)), ...svc, ...pbBytes(3, [i + 1])];
        out.push(...pbKey(3, 2), ...pbVarint(BigInt(body.length)), ...body);
    }
    return hexOf(Uint8Array.from(out));
}

export interface ComplianceStage {
    label: string;
    block: number;
    manifestPreimage: Hex;
    proofs?: {code: Hex[]; slots: Hex[][]; manifest: Hex[]};
}

export interface ComplianceCapture {
    rpc: string;
    capturedAt: string;
    clientVersion: string;
    channelId: Hex;
    service: Hex;
    bundleContent: Hex; // two payloads; the channel's sentRunningHash is their sha256 chain from zero
    slots: {slot: Hex; value: Hex}[]; // 5 channel slots + the last message slot (all stages)
    checkpoint: {hash: Hex; number: number; difficulty: string; timestamp: number};
    headers: MinedHeader[]; // checkpoint + 1 … last stage + k
    stages: ComplianceStage[];
}

async function waitReceipt(url: string, hash: Hex, deadline: number) {
    for (;;) {
        if (Date.now() > deadline) throw new Error("transaction not mined in time");
        const r = await rpc<{blockNumber: Hex; contractAddress: Hex; status: Hex} | null>(url, "eth_getTransactionReceipt", [hash]);
        if (r) {
            if (r.status !== "0x1") throw new Error("transaction failed");
            return r;
        }
        await new Promise((res) => setTimeout(res, 1000));
    }
}

/// A RSKj regtest node: deploy the setter, write the channel record and the first manifest commitment,
/// then one new commitment per block. Every state the IClprVerifier compliance suite asks for exists in
/// its own block, under the same service address.
export async function captureCompliance(url: string, k = 3): Promise<ComplianceCapture> {
    const deadline = Date.now() + 300_000;
    const chain = defineChain({id: 33, name: "rsk-regtest", nativeCurrency: {name: "RBTC", symbol: "RBTC", decimals: 18},
        rpcUrls: {default: {http: [url]}}});
    const account = privateKeyToAccount(COW_KEY);
    const wallet = createWalletClient({account, chain, transport: http(url)});
    const send = (data: Hex, to?: Hex) =>
        wallet.sendTransaction({to, data, gas: 1_000_000n, gasPrice: 0n, type: "legacy"} as never);

    const deploy = await waitReceipt(url, await send(storageInitcode([], SETTER_RUNTIME)), deadline);
    const service = deploy.contractAddress;
    const deployBlock = Number(BigInt(deploy.blockNumber));

    const channelId = keccak256(toHex("clpr/rootstock-live/compliance"));
    const payloads: Hex[] = ["0x0a0401020304", "0x0a03050607"];
    let running = pad("0x00", {size: 32});
    for (const p of payloads) running = sha256(concat([running, sha256(p)]));
    const bundleContent = concat(payloads.map((p) => concat(["0x12", toHex((p.length - 2) / 2, {size: 1}), p]))) as Hex;
    const sl = channelSlots(channelId, 3n);
    const w1 = (3n << 168n) | (1n << 160n) | 0xc1a9en; // nextMessageId 3 | ACTIVE | verifier
    const slots = [
        {slot: sl.channel[0], value: pad(toHex(w1), {size: 32})},
        {slot: sl.channel[1], value: pad("0x00", {size: 32})},
        {slot: sl.channel[2], value: running},
        {slot: sl.channel[3], value: pad("0x00", {size: 32})},
        {slot: sl.channel[4], value: pad("0x00", {size: 32})},
        {slot: sl.lastMessage, value: running},
    ];
    const manifests: [string, Hex][] = [
        ["v3-2-endpoints", complianceManifest(3, service, 2)],
        ["v1-1-endpoint", complianceManifest(1, service, 1)],
        ["v1-foreign-service", complianceManifest(1, FOREIGN_SERVICE, 1)],
        ["v0-1-endpoint", complianceManifest(0, service, 1)],
        ["v1-no-endpoints", complianceManifest(1, service, 0)],
        ["v7-no-endpoints", complianceManifest(7, service, 0)],
    ];
    const kv = (xs: {slot: Hex; value: Hex}[]) => concat(xs.flatMap(({slot, value}) => [slot, value])) as Hex;
    const stages: ComplianceStage[] = [];
    for (const [i, [label, m]] of manifests.entries()) {
        const writes = [{slot: sl.manifest, value: keccak256(m)}];
        if (i === 0) writes.unshift(...slots.filter((s) => BigInt(s.value) !== 0n));
        const r = await waitReceipt(url, await send(kv(writes), service), deadline);
        stages.push({label, block: Number(BigInt(r.blockNumber)), manifestPreimage: m});
    }
    const last = stages[stages.length - 1].block;
    while (Number(BigInt(await rpc<Hex>(url, "eth_blockNumber", []))) < last + k) {
        if (Date.now() > deadline) throw new Error("regtest chain not advancing");
        await new Promise((res) => setTimeout(res, 1000));
    }
    const cp = await rpc<RpcBlock>(url, "eth_getBlockByNumber", [toHex(deployBlock - 1), false]);
    return {
        rpc: url,
        capturedAt: new Date().toISOString(),
        clientVersion: await rpc<string>(url, "web3_clientVersion", []),
        channelId,
        service,
        bundleContent,
        slots,
        checkpoint: {hash: cp.hash, number: deployBlock - 1, difficulty: BigInt(cp.difficulty).toString(), timestamp: Number(BigInt(cp.timestamp))},
        headers: await fetchRange(url, deployBlock, last + k - deployBlock + 1),
        stages,
    };
}

// ── Unitrie proofs from a node dump ────────────────────────────────────────

export type NodeStore = Map<string, Uint8Array>;

export function loadDump(file: string): NodeStore {
    const m: NodeStore = new Map();
    for (const line of readFileSync(file, "utf8").split("\n")) {
        if (!line) continue;
        const [k, v] = line.split(" ");
        m.set(k.toLowerCase(), Buffer.from(v, "hex"));
    }
    return m;
}

const bytes = (h: Hex) => Buffer.from(h.slice(2), "hex");
const hexOf = (b: Uint8Array): Hex => `0x${Buffer.from(b).toString("hex")}`;
const bit = (b: Uint8Array, i: number) => (b[i >> 3] >> (7 - (i & 7))) & 1;

export function accountKey(addr: Hex): Uint8Array {
    return bytes(concat(["0x00", keccak256(addr).slice(0, 22) as Hex, addr]));
}
export function codeKey(addr: Hex): Uint8Array {
    return Buffer.concat([accountKey(addr), Buffer.from([0x80])]);
}
export function storageKey(addr: Hex, slot: Hex): Uint8Array {
    let s = BigInt(slot).toString(16);
    if (s.length % 2) s = "0" + s;
    return Buffer.concat([accountKey(addr), Buffer.from([0x00]), bytes(keccak256(slot)).subarray(0, 10), Buffer.from(s, "hex")]);
}

interface ParsedNode {
    pathBits: number;
    path: Uint8Array;
    left?: {embedded?: Uint8Array; hash?: Uint8Array};
    right?: {embedded?: Uint8Array; hash?: Uint8Array};
    value?: Uint8Array;
    longValue?: {hash: Uint8Array; length: number};
}

function readVarInt(b: Uint8Array, o: number): [number, number] {
    const f = b[o];
    if (f < 0xfd) return [f, o + 1];
    const n = f === 0xfd ? 2 : f === 0xfe ? 4 : 8;
    let v = 0;
    for (let i = 0; i < n; i++) v += b[o + 1 + i] * 2 ** (8 * i);
    return [v, o + 1 + n];
}

export function parseNode(m: Uint8Array): ParsedNode {
    const flags = m[0];
    if ((flags & 0xc0) !== 0x40) throw new Error("not an RSKIP107 node");
    let o = 1;
    const n: ParsedNode = {pathBits: 0, path: new Uint8Array()};
    if (flags & 0x10) {
        const f = m[o];
        let bits: number;
        if (f <= 31) [bits, o] = [f + 1, o + 1];
        else if (f <= 254) [bits, o] = [f + 128, o + 1];
        else [bits, o] = readVarInt(m, o + 1);
        n.pathBits = bits;
        n.path = m.subarray(o, o + Math.ceil(bits / 8));
        o += Math.ceil(bits / 8);
    }
    const ref = (embedded: boolean) => {
        if (embedded) {
            const len = m[o];
            const r = {embedded: m.subarray(o + 1, o + 1 + len)};
            o += 1 + len;
            return r;
        }
        const r = {hash: m.subarray(o, o + 32)};
        o += 32;
        return r;
    };
    if (flags & 0x08) n.left = ref((flags & 0x02) !== 0);
    if (flags & 0x04) n.right = ref((flags & 0x01) !== 0);
    if (n.left || n.right) o = readVarInt(m, o)[1];
    if (flags & 0x20) n.longValue = {hash: m.subarray(o, o + 32), length: (m[o + 32] << 16) | (m[o + 33] << 8) | m[o + 34]};
    else if (o < m.length) n.value = m.subarray(o);
    return n;
}

/// Walk `key` from `root`; returns the non-embedded node messages on the path (root first) and the value.
export function unitrieProof(store: NodeStore, root: Hex, key: Uint8Array): {nodes: Hex[]; value?: Uint8Array; valueHash?: Uint8Array} {
    const get = (h: Uint8Array) => {
        const m = store.get(Buffer.from(h).toString("hex"));
        if (!m) throw new Error(`node ${hexOf(h)} missing from dump`);
        if (keccak256(m) !== hexOf(h)) throw new Error("dump entry hash mismatch");
        return m;
    };
    let msg = get(bytes(root));
    const nodes: Hex[] = [hexOf(msg)];
    let pos = 0;
    const keyBits = key.length * 8;
    for (;;) {
        const n = parseNode(msg);
        if (pos + n.pathBits > keyBits) return {nodes};
        for (let i = 0; i < n.pathBits; i++) if (bit(n.path, i) !== bit(key, pos + i)) return {nodes};
        pos += n.pathBits;
        if (pos === keyBits) {
            if (n.longValue) return {nodes, valueHash: n.longValue.hash};
            return {nodes, value: n.value, valueHash: n.value ? bytes(keccak256(n.value)) : undefined};
        }
        const child = bit(key, pos) ? n.right : n.left;
        pos += 1;
        if (!child) return {nodes};
        if (child.embedded) {
            msg = child.embedded;
        } else {
            msg = get(child.hash!);
            nodes.push(hexOf(msg));
        }
    }
}

export function buildRegtestProofs(cap: RegtestCapture, store: NodeStore): NonNullable<RegtestCapture["proofs"]> {
    const root = cap.headers[cap.stateIndex].stateRoot;
    const code = unitrieProof(store, root, codeKey(cap.service));
    if (!code.valueHash) throw new Error("service code not found in trie");
    const slots = cap.slots.slice(0, 6).map(({slot, value}) => {
        const p = unitrieProof(store, root, storageKey(cap.service, slot));
        const got = p.value ? pad(hexOf(p.value), {size: 32}) : pad("0x00", {size: 32});
        if (got !== value) throw new Error(`slot ${slot}: trie has ${got}, expected ${value}`);
        return p.nodes;
    });
    const manifest = unitrieProof(store, root, storageKey(cap.service, cap.slots[6].slot)).nodes;
    return {code: code.nodes, slots, manifest};
}

export function buildComplianceProofs(cap: ComplianceCapture, store: NodeStore) {
    const sl = channelSlots(cap.channelId, 3n);
    for (const st of cap.stages) {
        const root = cap.headers[st.block - (cap.checkpoint.number + 1)].stateRoot;
        const code = unitrieProof(store, root, codeKey(cap.service));
        if (!code.valueHash || hexOf(code.valueHash) !== keccak256(SETTER_RUNTIME)) throw new Error("service code mismatch");
        const slots = cap.slots.map(({slot, value}) => {
            const p = unitrieProof(store, root, storageKey(cap.service, slot));
            const got = p.value ? pad(hexOf(p.value), {size: 32}) : pad("0x00", {size: 32});
            if (got !== value) throw new Error(`${st.label}: slot ${slot} has ${got}, expected ${value}`);
            return p.nodes;
        });
        const m = unitrieProof(store, root, storageKey(cap.service, sl.manifest));
        if (!m.value || pad(hexOf(m.value), {size: 32}) !== keccak256(st.manifestPreimage)) {
            throw new Error(`${st.label}: manifest commitment mismatch`);
        }
        st.proofs = {code: code.nodes, slots, manifest: m.nodes};
    }
    return cap;
}

// ── Wire encoding ──────────────────────────────────────────────────────────

const MINED_HEADER = {type: "tuple[]", components: [{name: "header", type: "bytes"}, {name: "coinbase", type: "bytes"}, {name: "merkleProof", type: "bytes"}]} as const;
export const CHECKPOINT_ABI = {type: "tuple", components: [
    {name: "blockHash", type: "bytes32"}, {name: "number", type: "uint256"}, {name: "difficulty", type: "uint256"},
    {name: "timestamp", type: "uint256"}, {name: "work", type: "uint256"}]} as const;
export const ANCHOR_ABI = [{type: "tuple", components: [{name: "checkpoint", ...CHECKPOINT_ABI}, {name: "codeHash", type: "bytes32"}]}] as const;

export const minedHeaders = (hs: MinedHeader[]) => hs.map((h) => ({header: h.header, coinbase: h.coinbase, merkleProof: h.merkleProof}));

export function checkpointOf(c: {hash: Hex; number: number; difficulty: string; timestamp: number}, work = 0n): Checkpoint {
    return {blockHash: c.hash, number: BigInt(c.number), difficulty: BigInt(c.difficulty), timestamp: BigInt(c.timestamp), work};
}

export function encodeAnchor(cp: Checkpoint, codeHash: Hex): Hex {
    return encodeAbiParameters(ANCHOR_ABI, [{checkpoint: cp, codeHash} as never]);
}

export const ZERO_CHECKPOINT: Checkpoint = {blockHash: `0x${"00".repeat(32)}`, number: 0n, difficulty: 0n, timestamp: 0n, work: 0n};

/// `start` = where the headers begin: ZERO_CHECKPOINT for the anchor, else a checkpoint recorded by `extend`.
export function encodeBundleProof(p: {headers: MinedHeader[]; stateIndex: number; codeProof: Hex[]; slotProofs: Hex[][];
    bundleContent: Hex; manifestPreimage: Hex; manifestProof: Hex[]; start?: Checkpoint}): Hex {
    return encodeAbiParameters([{type: "tuple", components: [
        {name: "headers", ...MINED_HEADER}, {name: "stateIndex", type: "uint256"}, {name: "codeProof", type: "bytes[]"},
        {name: "slotProofs", type: "bytes[][]"}, {name: "bundleContent", type: "bytes"}, {name: "manifestPreimage", type: "bytes"},
        {name: "manifestProof", type: "bytes[]"}, {name: "start", ...CHECKPOINT_ABI}]}],
    [{...p, headers: minedHeaders(p.headers), stateIndex: BigInt(p.stateIndex), start: p.start ?? ZERO_CHECKPOINT} as never]);
}

export function encodeConfigProof(p: {headers: MinedHeader[]; stateIndex: number; service: Hex; codeProof: Hex[]; peerConfigNanos: bigint}): Hex {
    const throttles = {maxMessagesPerBundle: 16, maxMessagePayloadBytes: 4096n, maxGasPerMessage: 1_000_000n, maxQueueDepth: 1024,
        maxSyncBytes: 65536n, maxLocalEndpoints: 8, maxPeerEndpoints: 8};
    return encodeAbiParameters([{type: "tuple", components: [
        {name: "headers", ...MINED_HEADER}, {name: "stateIndex", type: "uint256"}, {name: "service", type: "address"},
        {name: "codeProof", type: "bytes[]"}, {name: "peerConfigNanos", type: "uint96"},
        {name: "throttles", type: "tuple", components: [
            {name: "maxMessagesPerBundle", type: "uint32"}, {name: "maxMessagePayloadBytes", type: "uint64"},
            {name: "maxGasPerMessage", type: "uint64"}, {name: "maxQueueDepth", type: "uint32"}, {name: "maxSyncBytes", type: "uint64"},
            {name: "maxLocalEndpoints", type: "uint32"}, {name: "maxPeerEndpoints", type: "uint32"}]}]}],
    [{...p, headers: minedHeaders(p.headers), stateIndex: BigInt(p.stateIndex), throttles} as never]);
}

/// ClprBundleContent with two DATA-shaped payloads (field 2, LEN). The verifier passes them through;
/// the CLPR Service authenticates them against the proven sent running hash.
export function sampleBundleContent(): Hex {
    const m1 = "0a0401020304";
    const m2 = "0a03050607";
    const f = (h: string) => "12" + (h.length / 2).toString(16).padStart(2, "0") + h;
    return `0x${f(m1)}${f(m2)}`;
}

// ── CLI ────────────────────────────────────────────────────────────────────

function arg(name: string): string | undefined {
    const i = process.argv.indexOf(name);
    return i >= 0 ? process.argv[i + 1] : undefined;
}

function save(file: string, obj: unknown) {
    mkdirSync(FIXTURE_DIR, {recursive: true});
    writeFileSync(file, JSON.stringify(obj, null, 2) + "\n");
    console.log(`wrote ${path.relative(process.cwd(), file)}`);
}

async function main() {
    if (process.argv.includes("--refresh-mainnet")) {
        const cap = await captureMainnet(arg("--rpc") ?? MAINNET_RPC, Number(arg("--count") ?? 40));
        save(MAINNET_FIXTURE, cap);
    } else if (process.argv.includes("--capture-regtest")) {
        save(REGTEST_FIXTURE, await captureRegtest(arg("--rpc") ?? "http://127.0.0.1:4454"));
    } else if (process.argv.includes("--capture-compliance")) {
        save(COMPLIANCE_FIXTURE, await captureCompliance(arg("--rpc") ?? "http://127.0.0.1:4454"));
    } else if (process.argv.includes("--proofs-compliance")) {
        const cap = JSON.parse(readFileSync(COMPLIANCE_FIXTURE, "utf8")) as ComplianceCapture;
        save(COMPLIANCE_FIXTURE, buildComplianceProofs(cap, loadDump(arg("--dump")!)));
    } else if (process.argv.includes("--proofs-regtest")) {
        const cap = JSON.parse(readFileSync(REGTEST_FIXTURE, "utf8")) as RegtestCapture;
        cap.proofs = buildRegtestProofs(cap, loadDump(arg("--dump")!));
        save(REGTEST_FIXTURE, cap);
    } else {
        const m = JSON.parse(readFileSync(MAINNET_FIXTURE, "utf8")) as MainnetCapture;
        console.log(`mainnet: ${m.headers.length} headers from ${m.checkpoint.number + 1}, captured ${m.capturedAt}`);
    }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
    main().catch((e) => {
        console.error(e);
        process.exit(1);
    });
}

