import {mkdirSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {ed25519} from "@noble/curves/ed25519";
import {keccak256, toBytes, type Hex} from "viem";
import {
    accountStorageKey,
    beefyAddresses,
    blake2_256,
    channelSlots,
    decodeBeefyJustification,
    decodeBeefySet,
    decodeHeader,
    decodeJustification,
    decodeMmrLeaf,
    encodeHeader,
    fromHex,
    grandpaMessage,
    grandpaScheduledChange,
    keysetRoot,
    mmrPath,
    packGrandpaAuthorities,
    palletQueueKey,
    palletServiceKey,
    paraHeadKey,
    Scale,
    storageKey,
    toHex,
    twox128,
    type RpcHeader
} from "./substrate.js";

/// Records live Bittensor, Bifrost Network and Chainflip (GRANDPA) and Hydration (Polkadot BEEFY)
/// data from public RPCs into
/// test/e2e/fixtures/grandpa-live/*.json. The fixtures keep raw RPC responses; the spec
/// (tests/verifiers/grandpa-live.spec.ts) re-derives every proof from them. Each piece is checked
/// off-chain here first (signatures, header hashes, MMR root, para head) so a bad recording fails
/// loudly. Run: npm run grandpa-live:refresh [-- bittensor|hydration|bifrost|chainflip]

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const FIXTURE_DIR = path.resolve(__dirname, "..", "fixtures", "grandpa-live");

export const BITTENSOR_RPC = process.env.BITTENSOR_RPC ?? "https://archive.chain.opentensor.ai";
export const POLKADOT_RPC = process.env.POLKADOT_RPC ?? "https://rpc.polkadot.io";
/// Needs offchain indexing for mmr_generateProof (rpc.polkadot.io answers LeafNotFound).
export const POLKADOT_MMR_RPC = process.env.POLKADOT_MMR_RPC ?? "https://dot-rpc.stakeworld.io";
export const HYDRATION_RPC = process.env.HYDRATION_RPC ?? "https://rpc.hydradx.cloud";
export const HYDRATION_PARA_ID = 2034;
export const BIFROST_RPC = process.env.BIFROST_RPC ?? "https://public-01.mainnet.bifrostnetwork.com/rpc";
export const CHAINFLIP_RPC = process.env.CHAINFLIP_RPC ?? "https://mainnet-archive.chainflip.io";

/// Live EVM contracts with storage used as the "service" (no ClprService is deployed on either
/// chain): their channel slots are absent (proven by non-existence), and a few real slots are
/// proven separately.
export const BITTENSOR_CONTRACT: Hex = "0x6647dcbeb030dc8e227d8b1a2cb6a49f3c887e3c";
export const HYDRATION_CONTRACT: Hex = "0xc91808c129c9766b13d22c9f0cd53db459c0bc48";
/// Bifrost Network: a live EVM contract with storage (no ClprService is deployed there either).
export const BIFROST_CONTRACT: Hex = "0xb461b71dc9c379c686fb839e3d351b537028bdee";
/// Chainflip has no EVM and no CLPR pallet: the profile names a pallet "Clpr" whose keys are
/// proven absent, and real storage items are proven next to it.
export const CHAINFLIP_PALLET = twox128("Clpr");
export const CHANNEL_ID: Hex = keccak256(toBytes("clpr/grandpa-live/channel"));

let rpcId = 0;
export async function rpc<T = any>(url: string, method: string, params: unknown[] = []): Promise<T> {
    for (let attempt = 0; ; attempt++) {
        try {
            const r = await fetch(url, {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify({id: ++rpcId, jsonrpc: "2.0", method, params})});
            const j = await r.json();
            if (j.error) throw new Error(`${method}: ${JSON.stringify(j.error)}`);
            return j.result as T;
        } catch (e) {
            if (attempt >= 3) throw e;
            await new Promise((res) => setTimeout(res, 1000 * (attempt + 1)));
        }
    }
}

const blockHash = (url: string, n: number) => rpc<string>(url, "chain_getBlockHash", [n]);
const storageAt = (url: string, key: Buffer, at: string) => rpc<string | null>(url, "state_getStorage", [toHex(key), at]);
const readProof = async (url: string, keys: Buffer[], at: string) =>
    (await rpc<{at: string; proof: string[]}>(url, "state_getReadProof", [keys.map(toHex), at])).proof;

/// Keys a bundle proves for `contract`: the 5 channel slots, plus `realSlotCount` existing slots.
async function evmKeys(url: string, contract: Hex, at: string, realSlotCount: number) {
    const prefix = toHex(accountStorageKey(contract, "0x00").subarray(0, 32 + 16 + 20));
    const existing = await rpc<string[]>(url, "state_getKeysPaged", [prefix, realSlotCount, null, at]);
    const realSlots = existing.map((k) => ("0x" + k.slice(-64)) as Hex);
    const slots = [...channelSlots(CHANNEL_ID), ...realSlots];
    return {realSlots, keys: slots.map((s) => accountStorageKey(contract, s))};
}

async function justificationAt(url: string, n: number): Promise<{hash: string; header: RpcHeader; justification: string} | null> {
    const hash = await blockHash(url, n);
    const b = await rpc<any>(url, "chain_getBlock", [hash]);
    const j = b.justifications?.find((x: [number[], number[]]) => Buffer.from(x[0]).toString() === "FRNK");
    return j ? {hash, header: b.block.header, justification: toHex(Buffer.from(j[1]))} : null;
}

/// Off-chain check of a GRANDPA justification (every precommit) against `authorities`.
function checkGrandpa(rec: {hash: string; header: RpcHeader; justification: string}, authorities: Buffer, setId: bigint) {
    const header = encodeHeader(rec.header);
    if (toHex(blake2_256(header)) !== rec.hash) throw new Error("header encoding mismatch");
    const j = decodeJustification(fromHex(rec.justification));
    if (toHex(j.targetHash) !== rec.hash) throw new Error("justification target mismatch");
    const keys = new Set([...Array(authorities.length / 40)].map((_, i) => authorities.subarray(40 * i, 40 * i + 32).toString("hex")));
    for (const p of j.precommits) {
        if (!keys.has(p.id.toString("hex"))) throw new Error("precommit by non-authority");
        if (!ed25519.verify(p.signature, grandpaMessage(p.targetHash, p.targetNumber, j.round, setId), p.id)) throw new Error("bad precommit signature");
    }
    return j.precommits.length;
}

// ── Bittensor ────────────────────────────────────────────────────────────────

export async function recordBittensor() {
    const U = BITTENSOR_RPC;
    const setIdKey = storageKey("Grandpa", "CurrentSetId"), authKey = storageKey("Grandpa", "Authorities");
    const finalized = await rpc<string>(U, "chain_getFinalizedHead");
    const head = parseInt((await rpc<RpcHeader>(U, "chain_getHeader", [finalized])).number, 16);
    const setIdAt = async (n: number) => {
        const v = await storageAt(U, setIdKey, await blockHash(U, n));
        return v ? fromHex(v).readBigUInt64LE() : 0n;
    };

    // Rotation: the first block of the current set carries ScheduledChange and is justified by the old set.
    const currentSet = await setIdAt(head);
    let lo = 1, hi = head;
    while (hi - lo > 1) { const m = (lo + hi) >> 1; if ((await setIdAt(m)) >= currentSet) hi = m; else lo = m; }
    const signal = await justificationAt(U, hi);
    if (!signal) throw new Error(`no justification at set-change block ${hi}`);
    const prevAuthorities = (await storageAt(U, authKey, await blockHash(U, hi - 1)))!;
    const change = grandpaScheduledChange(encodeHeader(signal.header));
    if (!change) throw new Error("set-change block has no ScheduledChange");
    const rotationVotes = checkGrandpa(signal, packGrandpaAuthorities(prevAuthorities), currentSet - 1n);
    console.log(`bittensor: set ${currentSet - 1n} → ${currentSet} at #${hi} (delay ${change.delay}), ${rotationVotes} precommits`);

    // Typical: the newest stored justification (Bittensor nodes keep one every 512 blocks or so).
    let typical: Awaited<ReturnType<typeof justificationAt>> = null;
    for (let n = head - (head % 512); n > head - 512 * 16 && !typical; n -= 512) typical = await justificationAt(U, n);
    if (!typical) throw new Error("no recent justification");
    const typicalNumber = parseInt(typical.header.number, 16);
    const authorities = (await storageAt(U, authKey, typical.hash))!;
    const typicalSet = fromHex((await storageAt(U, setIdKey, typical.hash))!).readBigUInt64LE();
    const typicalVotes = checkGrandpa(typical, packGrandpaAuthorities(authorities), typicalSet);
    console.log(`bittensor: justification at #${typicalNumber} (set ${typicalSet}), ${typicalVotes} precommits`);

    const ev = await evmKeys(U, BITTENSOR_CONTRACT, typical.hash, 3);
    const rotationEv = await evmKeys(U, BITTENSOR_CONTRACT, signal.hash, 0);
    const fx = {
        chain: "Bittensor (finney)",
        recordedAt: new Date().toISOString(),
        rpc: U,
        evmChainId: "eip155:964",
        contract: BITTENSOR_CONTRACT,
        channelId: CHANNEL_ID,
        rotation: {
            setIdBefore: (currentSet - 1n).toString(),
            authoritiesBefore: prevAuthorities,
            block: signal,
            stateProof: await readProof(U, rotationEv.keys, signal.hash)
        },
        typical: {
            setId: typicalSet.toString(),
            authorities,
            block: typical,
            realSlots: ev.realSlots,
            stateProof: await readProof(U, ev.keys, typical.hash)
        }
    };
    write("bittensor", fx);
}

// ── Hydration (Polkadot BEEFY) ───────────────────────────────────────────────

async function beefyJustificationAt(n: number) {
    const hash = await blockHash(POLKADOT_RPC, n);
    const b = await rpc<any>(POLKADOT_RPC, "chain_getBlock", [hash]);
    const j = b.justifications?.find((x: [number[], number[]]) => Buffer.from(x[0]).toString() === "BEEF");
    return j ? {hash, justification: toHex(Buffer.from(j[1]))} : null;
}

/// Everything one BEEFY commitment at relay block `n` needs, through the Hydration state proof.
async function recordBeefyCommit(n: number, evmRealSlots: number) {
    const rec = await beefyJustificationAt(n);
    if (!rec) throw new Error(`no BEEFY justification at #${n}`);
    const sc = decodeBeefyJustification(fromHex(rec.justification));
    const authorities = (await storageAt(POLKADOT_RPC, storageKey("Beefy", "Authorities"), rec.hash))!;
    const addrs = beefyAddresses(authorities);
    const current = decodeBeefySet((await storageAt(POLKADOT_RPC, storageKey("BeefyMmrLeaf", "BeefyAuthorities"), rec.hash))!);
    if (current.id !== sc.setId || !keysetRoot(addrs).equals(current.root)) throw new Error("BEEFY set mismatch");

    const mmrProof = await rpc<{blockHash: string; leaves: string; proof: string}>(POLKADOT_MMR_RPC, "mmr_generateProof", [[n], n]);
    const m = mmrPath(mmrProof);
    const leaf = decodeMmrLeaf(m.leaf);
    if (leaf.parentNumber + 1 !== n || leaf.next.id !== sc.setId + 1n) throw new Error("unexpected MMR leaf");

    const relayHeader = await rpc<RpcHeader>(POLKADOT_RPC, "chain_getHeader", [toHex(leaf.parentHash)]);
    if (!blake2_256(encodeHeader(relayHeader)).equals(leaf.parentHash)) throw new Error("relay header mismatch");
    const headKey = paraHeadKey(HYDRATION_PARA_ID);
    const relayStateProof = await readProof(POLKADOT_RPC, [headKey], toHex(leaf.parentHash));
    const headData = new Scale(fromHex((await storageAt(POLKADOT_RPC, headKey, toHex(leaf.parentHash)))!)).vec();
    const paraHash = toHex(blake2_256(headData));
    const paraNumber = decodeHeader(Buffer.from(headData)).number;

    const ev = await evmKeys(HYDRATION_RPC, HYDRATION_CONTRACT, paraHash, evmRealSlots);
    console.log(`hydration: BEEFY #${n} set ${sc.setId} (${sc.signatures.filter(Boolean).length}/${sc.validatorSetLen} sigs) → relay #${leaf.parentNumber} → Hydration #${paraNumber}`);
    return {
        relayBlock: n,
        relayBlockHash: rec.hash,
        justification: rec.justification,
        beefyAuthorities: authorities,
        mmrProof,
        relayHeader,
        relayStateProof,
        paraBlockHash: paraHash,
        paraBlockNumber: paraNumber,
        realSlots: ev.realSlots,
        paraStateProof: await readProof(HYDRATION_RPC, ev.keys, paraHash)
    };
}

export async function recordHydration() {
    const setKey = storageKey("Beefy", "ValidatorSetId");
    const finalized = parseInt((await rpc<RpcHeader>(POLKADOT_RPC, "chain_getHeader", [await rpc(POLKADOT_RPC, "beefy_getFinalizedHead")])).number, 16);
    const setIdAt = async (n: number) => fromHex((await storageAt(POLKADOT_RPC, setKey, await blockHash(POLKADOT_RPC, n)))!).readBigUInt64LE();

    // Typical: the newest BEEFY-justified block (justifications are kept every few blocks).
    let n = finalized;
    while (!(await beefyJustificationAt(n))) n--;
    const typical = await recordBeefyCommit(n, 3);

    // Rotation: the first block of the current BEEFY set, signed by the new set.
    const current = await setIdAt(n);
    let lo = n - 20_000, hi = n;
    while (hi - lo > 1) { const m = (lo + hi) >> 1; if ((await setIdAt(m)) >= current) hi = m; else lo = m; }
    const before = await blockHash(POLKADOT_RPC, hi - 1);
    const anchorBefore = {
        current: (await storageAt(POLKADOT_RPC, storageKey("BeefyMmrLeaf", "BeefyAuthorities"), before))!,
        next: (await storageAt(POLKADOT_RPC, storageKey("BeefyMmrLeaf", "BeefyNextAuthorities"), before))!,
        block: hi - 1
    };
    const rotation = await recordBeefyCommit(hi, 0);
    const sessionLength = hi - (await (async () => {
        let l = hi - 20_000, h = hi - 1;
        while (h - l > 1) { const m = (l + h) >> 1; if ((await setIdAt(m)) >= current - 1n) h = m; else l = m; }
        return h;
    })());
    console.log(`hydration: BEEFY set ${current - 1n} → ${current} at #${hi} (session ≈ ${sessionLength} blocks)`);

    write("hydration", {
        chain: "Hydration (Polkadot para 2034) via Polkadot BEEFY",
        recordedAt: new Date().toISOString(),
        rpc: {polkadot: POLKADOT_RPC, mmr: POLKADOT_MMR_RPC, hydration: HYDRATION_RPC},
        evmChainId: "eip155:222222",
        paraId: HYDRATION_PARA_ID,
        contract: HYDRATION_CONTRACT,
        channelId: CHANNEL_ID,
        sessionLengthBlocks: sessionLength,
        typical: {
            anchor: {
                current: (await storageAt(POLKADOT_RPC, storageKey("BeefyMmrLeaf", "BeefyAuthorities"), typical.relayBlockHash))!,
                next: (await storageAt(POLKADOT_RPC, storageKey("BeefyMmrLeaf", "BeefyNextAuthorities"), typical.relayBlockHash))!
            },
            ...typical
        },
        rotation: {anchorBefore, ...rotation}
    });
}

// ── GRANDPA solo chains with grandpa_proveFinality (Bifrost Network, Chainflip) ──

/// The newest justification the node holds (grandpa_proveFinality returns a FinalityProof
/// {block, justification, unknown_headers} for the latest justified block at or after `n`).
async function provenJustification(url: string, n: number): Promise<{hash: string; header: RpcHeader; justification: string}> {
    const r = new Scale(fromHex(await rpc<string>(url, "grandpa_proveFinality", [n])));
    const hash = toHex(r.bytes(32));
    const justification = toHex(r.vec());
    const header = await rpc<RpcHeader>(url, "chain_getHeader", [hash]);
    return {hash, header, justification};
}

/// Finds the first block of the current GRANDPA set (it carries the ScheduledChange and is justified
/// by the previous set), searching back at most `window` blocks.
async function currentSetStart(url: string, head: number, window: number) {
    const setIdKey = storageKey("Grandpa", "CurrentSetId");
    const setIdAt = async (n: number) => fromHex((await storageAt(url, setIdKey, await blockHash(url, n)))!).readBigUInt64LE();
    const current = await setIdAt(head);
    let lo = head - window, hi = head;
    if ((await setIdAt(lo)) >= current) throw new Error(`set ${current} started more than ${window} blocks ago`);
    while (hi - lo > 1) { const m = (lo + hi) >> 1; if ((await setIdAt(m)) >= current) hi = m; else lo = m; }
    // Length of the previous set, for the docs (sessions/epochs between changes).
    let plo = hi - 2 * window, phi = hi - 1;
    if ((await setIdAt(plo)) >= current - 1n) plo = -1;
    else while (phi - plo > 1) { const m = (plo + phi) >> 1; if ((await setIdAt(m)) >= current - 1n) phi = m; else plo = m; }
    return {current, start: hi, previousSetLength: plo < 0 ? null : hi - phi};
}

/// Rotation (first block of the current set, justified by the previous set) and a typical (newest)
/// justification of the current set, both checked off-chain.
async function recordGrandpaSolo(url: string, label: string, window: number) {
    const setIdKey = storageKey("Grandpa", "CurrentSetId"), authKey = storageKey("Grandpa", "Authorities");
    for (let attempt = 0; attempt < 3; attempt++) {
        const finalized = await rpc<string>(url, "chain_getFinalizedHead");
        const head = parseInt((await rpc<RpcHeader>(url, "chain_getHeader", [finalized])).number, 16);
        const {current, start, previousSetLength} = await currentSetStart(url, head, window);
        const signal = await justificationAt(url, start);
        if (!signal) throw new Error(`${label}: no stored justification at set-change block ${start}`);
        const prevAuthorities = (await storageAt(url, authKey, await blockHash(url, start - 1)))!;
        const change = grandpaScheduledChange(encodeHeader(signal.header));
        if (!change) throw new Error(`${label}: set-change block has no ScheduledChange`);
        const rotationVotes = checkGrandpa(signal, packGrandpaAuthorities(prevAuthorities), current - 1n);

        const typical = await provenJustification(url, head);
        const typicalSet = fromHex((await storageAt(url, setIdKey, typical.hash))!).readBigUInt64LE();
        if (typicalSet !== current) { console.log(`${label}: set changed while recording, retrying`); continue; }
        const authorities = (await storageAt(url, authKey, typical.hash))!;
        const typicalVotes = checkGrandpa(typical, packGrandpaAuthorities(authorities), typicalSet);
        console.log(`${label}: set ${current - 1n} → ${current} at #${start} (delay ${change.delay}, ${rotationVotes} precommits); justification at #${parseInt(typical.header.number, 16)} (${typicalVotes} precommits); previous set lasted ${previousSetLength} blocks`);
        return {current, start, previousSetLength, signal, prevAuthorities, typical, typicalSet, authorities};
    }
    throw new Error(`${label}: the set kept changing while recording`);
}

export async function recordBifrost() {
    const U = BIFROST_RPC;
    const r = await recordGrandpaSolo(U, "bifrost", 2_000);
    const ev = await evmKeys(U, BIFROST_CONTRACT, r.typical.hash, 3);
    const rotationEv = await evmKeys(U, BIFROST_CONTRACT, r.signal.hash, 0);
    write("bifrost", {
        chain: "Bifrost Network mainnet",
        recordedAt: new Date().toISOString(),
        rpc: U,
        evmChainId: `eip155:${parseInt(await rpc<string>(U, "eth_chainId"), 16)}`,
        runtime: await rpc(U, "state_getRuntimeVersion"),
        contract: BIFROST_CONTRACT,
        channelId: CHANNEL_ID,
        setLengthBlocks: r.previousSetLength,
        rotation: {
            setIdBefore: (r.current - 1n).toString(),
            authoritiesBefore: r.prevAuthorities,
            block: r.signal,
            stateProof: await readProof(U, rotationEv.keys, r.signal.hash)
        },
        typical: {
            setId: r.typicalSet.toString(),
            authorities: r.authorities,
            block: r.typical,
            realSlots: ev.realSlots,
            stateProof: await readProof(U, ev.keys, r.typical.hash)
        }
    });
}

export async function recordChainflip() {
    const U = CHAINFLIP_RPC;
    const r = await recordGrandpaSolo(U, "chainflip", 150_000);
    const genesis = await blockHash(U, 0);
    // Keys: the CLPR pallet's queue and service records (absent: no CLPR pallet on Chainflip), plus
    // real items proven next to them: Grandpa::CurrentSetId and the first System::Account entry.
    const accountPrefix = storageKey("System", "Account");
    const [accountKey] = await rpc<string[]>(U, "state_getKeysPaged", [toHex(accountPrefix), 1, null, r.typical.hash]);
    const realKeys = [toHex(storageKey("Grandpa", "CurrentSetId")), accountKey];
    const clprKeys = [palletQueueKey(CHAINFLIP_PALLET, CHANNEL_ID), palletServiceKey(CHAINFLIP_PALLET)];
    for (const k of clprKeys) if (await storageAt(U, k, r.typical.hash)) throw new Error("unexpected CLPR record on Chainflip");
    const keys = [...clprKeys, ...realKeys.map(fromHex)];
    write("chainflip", {
        chain: "Chainflip mainnet (Berghain)",
        recordedAt: new Date().toISOString(),
        rpc: U,
        chainId: `polkadot:${genesis.slice(2, 34)}`,
        genesisHash: genesis,
        runtime: await rpc(U, "state_getRuntimeVersion"),
        pallet: toHex(CHAINFLIP_PALLET),
        channelId: CHANNEL_ID,
        setLengthBlocks: r.previousSetLength,
        rotation: {
            setIdBefore: (r.current - 1n).toString(),
            authoritiesBefore: r.prevAuthorities,
            block: r.signal,
            stateProof: await readProof(U, clprKeys, r.signal.hash)
        },
        typical: {
            setId: r.typicalSet.toString(),
            authorities: r.authorities,
            block: r.typical,
            realKeys,
            realValues: await Promise.all(realKeys.map((k) => storageAt(U, fromHex(k), r.typical.hash))),
            stateProof: await readProof(U, keys, r.typical.hash)
        }
    });
}

function write(name: string, fx: unknown) {
    mkdirSync(FIXTURE_DIR, {recursive: true});
    const file = path.join(FIXTURE_DIR, `${name}.json`);
    writeFileSync(file, JSON.stringify(fx, null, 1) + "\n");
    console.log(`wrote ${path.relative(process.cwd(), file)}`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
    const which = process.argv[2];
    if (!which || which === "bittensor") await recordBittensor();
    if (!which || which === "hydration") await recordHydration();
    if (!which || which === "bifrost") await recordBifrost();
    if (!which || which === "chainflip") await recordChainflip();
}
