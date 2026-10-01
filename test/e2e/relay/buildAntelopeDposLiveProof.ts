import {mkdirSync, readFileSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {
    IncrementalMerkle,
    actionDigest,
    blockIdOf,
    hex,
    k1Address,
    k1KeyBytes,
    k1SigBytes,
    k1Uncompressed,
    legacyMerkle,
    legacyMerkleProof,
    legacyReceiptDigest,
    legacyReceiptTail,
    legacySigDigest,
    nameToU64,
    packActionBase,
    packHeader,
    recoverK1Address,
    unhex
} from "../lib/antelope.js";
import {rlpEncode} from "../lib/rlp.js";

/// Live XPR Network (legacy Antelope DPoS) capture and proof builder for AntelopeDposVerifier.
///
/// Capture (`--refresh --network mainnet|testnet`) records, from public RPC + Hyperion only:
///   - a target block T just above the LIB, still reversible, so get_block_header_state(T) gives
///     T's active schedule, block-root accumulator and pending schedule hash;
///   - the headers T .. T+k up to the point where the DPoS LIB rule makes T irreversible, with
///     signatures (and the per-block accumulator root, rebuilt by appending block ids) on the
///     headers the rule counts; every signature is recovered and checked here before saving;
///   - every action receipt of T (from Hyperion get_transaction), checked to rebuild T's
///     action_mroot, and one top-level action with its raw data.
///
/// The fixture lives in test/e2e/fixtures/xpr-live/<network>.json.

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const FIXTURE_DIR = path.join(HERE, "..", "fixtures", "xpr-live");

export const NETWORKS: Record<string, {rpc: string; hyperion: string; caip2: string}> = {
    mainnet: {rpc: "https://proton.eosusa.io", hyperion: "https://proton.eosusa.io", caip2: "antelope:384da888112027f0321850a169f737c3"},
    testnet: {rpc: "https://test.proton.eosusa.io", hyperion: "https://test.proton.eosusa.io", caip2: "antelope:71ee83bcf52142d61019d95f9cc5427b"}
};

export interface DposHeader {
    num: number;
    id: string;
    producer: string;
    confirmed: number;
    raw: string;
    sig?: string; // 65-byte payload
    bmroot?: string;
    scheduleHash?: string;
}

export interface DposCapture {
    network: string;
    chainId: string;
    caip2: string;
    capturedAt: string;
    serverVersion: string;
    scheduleVersion: number;
    schedule: {producer: string; key: string; signer: string; xy: string}[];
    headers: DposHeader[];
    action: {
        trxId: string;
        account: string;
        name: string;
        receiver: string;
        actionBase: string;
        data: string;
        returnValue: string;
        receiptTail: string;
        index: number;
        count: number;
        siblings: string[];
        actDigest: string;
        receiptCount: number;
    };
}

async function rpc(base: string, p: string, body: unknown): Promise<any> {
    for (let attempt = 0; ; attempt++) {
        try {
            const r = await fetch(base + p, {method: "POST", body: JSON.stringify(body), signal: AbortSignal.timeout(20_000)});
            const j = await r.json();
            if (j && (j as any).error) throw new Error(JSON.stringify((j as any).error).slice(0, 300));
            return j;
        } catch (e) {
            if (attempt >= 4) throw e;
            await new Promise((res) => setTimeout(res, 500 * (attempt + 1)));
        }
    }
}

async function getJson(url: string): Promise<any> {
    for (let attempt = 0; ; attempt++) {
        try {
            const r = await fetch(url, {signal: AbortSignal.timeout(30_000)});
            return await r.json();
        } catch (e) {
            if (attempt >= 4) throw e;
            await new Promise((res) => setTimeout(res, 500 * (attempt + 1)));
        }
    }
}

/// The DPoS LIB rule (AntelopeDposVerifier._requireIrreversible): which header indexes it counts,
/// or null when the chain is not long enough yet.
export function lirIndexes(headers: {num: number; producer: string; confirmed: number}[], n: number): number[] | null {
    const r1 = Math.floor((n * 2) / 3) + 1;
    const r2 = n - Math.floor((n - 1) / 3);
    const target = headers[0].num;
    const s1 = new Set<string>();
    const s2 = new Set<string>();
    const used: number[] = [];
    for (let i = 0; i < headers.length; i++) {
        const h = headers[i];
        if (s1.size < r1) {
            if (h.num <= target + h.confirmed && h.num - target < 1024 && !s1.has(h.producer)) {
                s1.add(h.producer);
                used.push(i);
            }
        } else if (!s2.has(h.producer)) {
            s2.add(h.producer);
            used.push(i);
            if (s2.size === r2) return used;
        }
    }
    return null;
}

async function blockReceipts(net: {rpc: string; hyperion: string}, num: number, block: any) {
    const listed = await getJson(`${net.hyperion}/v2/history/get_actions?block_num=${num}&limit=1000`);
    const txids = [...new Set<string>(listed.actions.map((a: any) => a.trx_id))];
    const full: any[] = [];
    for (const t of txids) {
        const tx = await getJson(`${net.hyperion}/v2/history/get_transaction?id=${t}`);
        full.push(...tx.actions.filter((a: any) => a.block_num === num));
    }
    const receipts: {gs: bigint; digest: Buffer; tail: Buffer; receiver: string; act: any; actDigest: string; trxId: string}[] = [];
    for (const a of full) {
        for (const r of a.receipts) {
            const tail = legacyReceiptTail(
                BigInt(r.global_sequence),
                BigInt(r.recv_sequence),
                (r.auth_sequence ?? []).map((x: any) => ({account: x.account, sequence: BigInt(x.sequence)})),
                a.code_sequence ?? 0,
                a.abi_sequence ?? 0
            );
            receipts.push({
                gs: BigInt(r.global_sequence),
                digest: legacyReceiptDigest(r.receiver, unhex(a.act_digest), tail),
                tail,
                receiver: r.receiver,
                act: a.act,
                actDigest: a.act_digest.toLowerCase(),
                trxId: a.trx_id
            });
        }
    }
    receipts.sort((x, y) => (x.gs < y.gs ? -1 : x.gs > y.gs ? 1 : 0));
    const root = legacyMerkle(receipts.map((r) => r.digest));
    return {receipts, ok: hex(root) === "0x" + block.action_mroot};
}

export async function captureDpos(network: string): Promise<DposCapture> {
    const net = NETWORKS[network];
    const info = await rpc(net.rpc, "/v1/chain/get_info", {});
    let num = info.last_irreversible_block_num + 40;
    let target: {num: number; block: any; state: any; receipts: any; pick: any} | undefined;
    for (let tries = 0; tries < 30 && !target; tries++, num++) {
        const block = await rpc(net.rpc, "/v1/chain/get_block", {block_num_or_id: num});
        const tops = (block.transactions ?? []).filter((t: any) => typeof t.trx === "object");
        if (tops.length === 0) continue;
        const state = await rpc(net.rpc, "/v1/chain/get_block_header_state", {block_num_or_id: num});
        const rc = await blockReceipts(net, num, block);
        if (!rc.ok) {
            console.warn(`block ${num}: Hyperion receipts do not rebuild action_mroot, skipping`);
            continue;
        }
        // A top-level action (first receipt of its account) whose raw data we have from the block.
        for (const t of tops) {
            for (const a of t.trx.transaction.actions) {
                const base = packActionBase(a.account, a.name, a.authorization);
                const ad = hex(actionDigest(base, unhex(a.hex_data), Buffer.alloc(0)));
                const ri = rc.receipts.findIndex((r: any) => r.trxId === t.trx.id && r.actDigest === ad.slice(2) && r.receiver === a.account);
                if (ri >= 0) {
                    target = {num, block, state, receipts: rc.receipts, pick: {a, base, ad, ri, trxId: t.trx.id}};
                    break;
                }
            }
            if (target) break;
        }
    }
    if (!target) throw new Error("no suitable target block found");
    const {state} = target;
    const version: number = state.active_schedule.version;
    const schedule = [] as DposCapture["schedule"];
    for (const p of state.active_schedule.producers) {
        const auth = p.authority[1];
        const k = auth.keys.find((x: any) => x.weight >= auth.threshold);
        const key = k1KeyBytes(k.key);
        schedule.push({producer: p.producer_name, key: hex(key), signer: await k1Address(key), xy: hex(k1Uncompressed(key))});
    }

    // Headers from T, until the LIB rule is met (waiting at most ~2 minutes for new blocks).
    const im = new IncrementalMerkle(BigInt(state.blockroot_merkle._node_count), state.blockroot_merkle._active_nodes.map(unhex));
    const scheduleHash = unhex(state.pending_schedule.schedule_hash);
    const headers: (DposHeader & {sigText: string})[] = [];
    const deadline = Date.now() + 120_000;
    let cur = target.num;
    let block = target.block;
    for (;;) {
        const raw = packHeader(block);
        const id = blockIdOf(raw, cur);
        if (hex(id) !== "0x" + block.id) throw new Error(`id mismatch at ${cur}`);
        if (block.schedule_version !== version) throw new Error(`schedule changed inside the window at ${cur}`);
        if ((block.header_extensions ?? []).some((e: any) => e[0] === 1)) throw new Error(`schedule proposal inside the window at ${cur}`);
        headers.push({num: cur, id: hex(id), producer: block.producer, confirmed: block.confirmed, raw: hex(raw), bmroot: hex(im.root()), scheduleHash: hex(scheduleHash), sigText: block.producer_signature});
        im.append(id);
        if (lirIndexes(headers, schedule.length)) break;
        cur++;
        for (;;) {
            try {
                block = await rpc(net.rpc, "/v1/chain/get_block", {block_num_or_id: cur});
                break;
            } catch (e) {
                if (Date.now() > deadline) throw new Error(`gave up waiting for block ${cur}`);
                await new Promise((r) => setTimeout(r, 1000));
            }
        }
    }
    const used = new Set(lirIndexes(headers, schedule.length)!);
    for (let i = 0; i < headers.length; i++) {
        const h = headers[i];
        if (!used.has(i)) {
            delete h.bmroot;
            delete h.scheduleHash;
            continue;
        }
        const sig = k1SigBytes(h.sigText);
        const signer = await recoverK1Address(sig, legacySigDigest(unhex(h.raw), unhex(h.bmroot!), unhex(h.scheduleHash!)));
        const want = schedule.find((s) => s.producer === h.producer)!.signer;
        if (signer !== want) throw new Error(`signature check failed at ${h.num}: ${signer} != ${want}`);
        h.sig = hex(sig);
    }

    const {receipts, pick} = target;
    const leaves = receipts.map((r: any) => r.digest);
    return {
        network,
        chainId: info.chain_id,
        caip2: net.caip2,
        capturedAt: new Date().toISOString(),
        serverVersion: info.server_version_string,
        scheduleVersion: version,
        schedule,
        headers: headers.map(({sigText, ...h}) => h),
        action: {
            trxId: pick.trxId,
            account: pick.a.account,
            name: pick.a.name,
            receiver: receipts[pick.ri].receiver,
            actionBase: hex(pick.base),
            data: "0x" + pick.a.hex_data,
            returnValue: "0x",
            receiptTail: hex(receipts[pick.ri].tail),
            index: pick.ri,
            count: receipts.length,
            siblings: legacyMerkleProof(leaves, pick.ri).map(hex),
            actDigest: pick.ad,
            receiptCount: receipts.length
        }
    };
}

export function loadDposCapture(network: string): DposCapture {
    return JSON.parse(readFileSync(path.join(FIXTURE_DIR, `${network}.json`), "utf8"));
}

const bnum = (v: number | bigint) => {
    let x = BigInt(v);
    const out: number[] = [];
    while (x > 0n) {
        out.unshift(Number(x & 0xffn));
        x >>= 8n;
    }
    return Buffer.from(out);
};

export const scheduleRlp = (c: DposCapture) => c.schedule.map((s) => [bnum(nameToU64(s.producer)), unhex(s.signer)]);

export const headerChainRlp = (c: DposCapture) =>
    c.headers.map((h) => (h.sig ? [unhex(h.raw), unhex(h.sig), unhex(h.bmroot!), unhex(h.scheduleHash!)] : [unhex(h.raw)]));

export const actionRlp = (c: DposCapture) => [
    unhex(c.action.actionBase),
    unhex(c.action.data),
    unhex(c.action.returnValue),
    bnum(nameToU64(c.action.receiver)),
    unhex(c.action.receiptTail),
    bnum(c.action.index),
    bnum(c.action.count),
    c.action.siblings.map(unhex)
];

export interface DposLiveProof {
    trustAnchor: `0x${string}`;
    bundleProof: `0x${string}`;
    chain: `0x${string}`;
    action: `0x${string}`;
    schedule: `0x${string}`;
}

/// Build the verifier inputs from a capture. The bundle wraps the live action as if it were
/// `queuestate`; the verifier proves finality and inclusion, then rejects it as not a CLPR action.
export async function buildDposLiveProof(c: DposCapture): Promise<DposLiveProof> {
    const {encodeAbiParameters, keccak256} = await import("viem");
    const producers = c.schedule.map((s) => nameToU64(s.producer));
    const signers = c.schedule.map((s) => s.signer as `0x${string}`);
    const scheduleHash = keccak256(
        encodeAbiParameters([{type: "uint32"}, {type: "uint64[]"}, {type: "address[]"}], [c.scheduleVersion, producers, signers])
    );
    const trustAnchor = encodeAbiParameters([{type: "uint32"}, {type: "bytes32"}], [c.scheduleVersion, scheduleHash]);
    const bundleProof = hex(rlpEncode([scheduleRlp(c), [], headerChainRlp(c), actionRlp(c), Buffer.alloc(0), Buffer.alloc(0)]));
    return {
        trustAnchor,
        bundleProof,
        chain: hex(rlpEncode(headerChainRlp(c))),
        action: hex(rlpEncode(actionRlp(c))),
        schedule: hex(rlpEncode(scheduleRlp(c)))
    };
}

/// Foundry copy of the encoded proof pieces (test/verifiers/evm/antelope/fixtures/xpr-<network>.json),
/// read by AntelopeDposVerifier.t.sol. `sigOffset` points at a signature byte inside `chain`.
export const FOUNDRY_DIR = path.join(HERE, "..", "..", "verifiers", "evm", "antelope", "fixtures");

export async function emitFoundryFixture(c: DposCapture): Promise<string> {
    const live = await buildDposLiveProof(c);
    const chain = unhex(live.chain);
    const firstSig = c.headers.find((h) => h.sig)!.sig!;
    const sigOffset = chain.indexOf(unhex(firstSig)) + 40; // a byte inside s
    const out = {
        network: c.network,
        caip2: c.caip2,
        target: c.headers[0].num,
        headers: c.headers.length,
        signedHeaders: c.headers.filter((h) => h.sig).length,
        scheduleVersion: c.scheduleVersion,
        account: c.action.account,
        name: c.action.name,
        trustAnchor: live.trustAnchor,
        schedule: live.schedule,
        chain: live.chain,
        action: live.action,
        sigOffset
    };
    mkdirSync(FOUNDRY_DIR, {recursive: true});
    const file = path.join(FOUNDRY_DIR, `xpr-${c.network}.json`);
    writeFileSync(file, JSON.stringify(out, null, 1) + "\n");
    return file;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
    const network = process.argv.includes("--network") ? process.argv[process.argv.indexOf("--network") + 1] : "mainnet";
    if (process.argv.includes("--refresh")) {
        const cap = await captureDpos(network);
        mkdirSync(FIXTURE_DIR, {recursive: true});
        writeFileSync(path.join(FIXTURE_DIR, `${network}.json`), JSON.stringify(cap, null, 1) + "\n");
        const signed = cap.headers.filter((h) => h.sig).length;
        console.log(`${network}: target ${cap.headers[0].num}, ${cap.headers.length} headers (${signed} signed), action ${cap.action.account}::${cap.action.name} (${cap.action.index}/${cap.action.count})`);
    }
    console.log(`wrote ${await emitFoundryFixture(loadDposCapture(network))}`);
}
