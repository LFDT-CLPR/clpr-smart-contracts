/// Captures live Monad data for the MonadVerifier live-data fixture
/// (test/e2e/fixtures/monad-live/capture.json). Public sources only:
///   - forkpoints (the node's latest high QC, published once a minute) and validators.toml from the
///     Monad Foundation bucket used by node operators (https://bucket.monadinfra.com, see
///     docs.monad.xyz node-ops "soft reset"): a real QuorumCertificate + the epoch's validator set;
///   - the public RPC: raw storage of the staking precompile (0x1000) at a pinned block — the slots a
///     validator-set rotation proves — and the raw Ethereum header of that block.
/// Monad's RPC has no eth_getProof and no endpoint for consensus headers, so the capture cannot contain
/// Merkle proofs or a full finality chain (see src/verifiers/evm/monad/README.md "Live data").
///
/// Run: npm run monad-live:refresh   (or: npx tsx test/e2e/relay/monad/refreshMonadLive.ts)
import {mkdirSync, writeFileSync} from "node:fs";
import path from "node:path";
import {RLP} from "@ethereumjs/rlp";
import {bls12_381 as bls} from "@noble/curves/bls12-381";
import {keccak_256} from "@noble/hashes/sha3";
import {DST, VOTE_PREFIX, g1Eip2537, g2Eip2537, hex, toHex, cat, word} from "./monad.js";

const BUCKET = "https://bucket.monadinfra.com";
const NETWORKS = {
    mainnet: {rpc: "https://rpc.monad.xyz", chainId: 143},
    testnet: {rpc: "https://testnet-rpc.monad.xyz", chainId: 10143}
} as const;
type Net = keyof typeof NETWORKS;
const OUT = path.join(process.cwd(), "test/e2e/fixtures/monad-live/capture.json");

async function get(url: string): Promise<string | null> {
    const r = await fetch(url);
    return r.ok ? r.text() : null;
}

/// Forkpoint file names are minute stamps in America/New_York (see the operator download script).
function stamp(minutesAgo: number): string {
    const d = new Date(Date.now() - minutesAgo * 60_000);
    const parts = new Intl.DateTimeFormat("en-US", {
        timeZone: "America/New_York", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false
    }).formatToParts(d);
    const v = (t: string) => parts.find((p) => p.type === t)!.value;
    const hh = v("hour") === "24" ? "00" : v("hour");
    return `${v("year")}${v("month")}${v("day")}${hh}${v("minute")}01`;
}

async function latestForkpoint(net: Net): Promise<{url: string; toml: string}> {
    for (let m = 1; m < 90; m++) {
        const url = `${BUCKET}/forkpoint/${net}/forkpoint_${stamp(m)}.toml`;
        const toml = await get(url);
        if (toml && toml.includes("[high_certificate.Qc]")) return {url, toml};
    }
    throw new Error(`no QC forkpoint found for ${net}`);
}

type TomlValidator = {node_id: string; stake: string; cert_pubkey: string};

function validatorSet(toml: string, epoch: bigint): TomlValidator[] {
    const sec = toml.split("[[validator_sets]]").slice(1).find((s) => BigInt(s.match(/epoch = (\d+)/)![1]) === epoch);
    if (!sec) throw new Error(`validators.toml has no set for epoch ${epoch}`);
    return [...sec.matchAll(/node_id = "(0x[0-9a-f]+)"\s*\nstake = "(0x[0-9a-f]+)"\s*\ncert_pubkey = "(0x[0-9a-f]+)"/g)]
        .map((m) => ({node_id: m[1], stake: m[2], cert_pubkey: m[3]}));
}

async function rpc(net: Net, calls: Array<{method: string; params: unknown[]}>): Promise<unknown[]> {
    const out: unknown[] = [];
    for (let i = 0; i < calls.length; i += 40) {
        const batch = calls.slice(i, i + 40).map((c, j) => ({jsonrpc: "2.0", id: i + j, ...c}));
        for (let attempt = 0; ; attempt++) {
            const r = await fetch(NETWORKS[net].rpc, {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify(batch)});
            const j = (await r.json()) as Array<{id: number; result?: unknown; error?: unknown}>;
            if (Array.isArray(j) && j.every((x) => x.result !== undefined)) {
                j.sort((a, b) => a.id - b.id).forEach((x) => out.push(x.result));
                break;
            }
            if (attempt > 5) throw new Error(`rpc batch failed: ${JSON.stringify(j).slice(0, 300)}`);
            await new Promise((res) => setTimeout(res, 1000 * (attempt + 1)));
        }
    }
    return out;
}

async function captureNetwork(net: Net) {
    const fp = await latestForkpoint(net);
    const qcSigHex = fp.toml.match(/\[high_certificate\.Qc\]\s*\nsignatures = "(0x[0-9a-f]+)"/)![1];
    const info = fp.toml.split("[high_certificate.Qc.info]")[1];
    const id = info.match(/id = "(0x[0-9a-f]+)"/)![1];
    const round = BigInt(info.match(/round = (\d+)/)![1]);
    const epoch = BigInt(info.match(/epoch = (\d+)/)![1]);
    const validatorsToml = (await get(`${BUCKET}/validators/${net}/validators.toml`))!;
    const set = validatorSet(validatorsToml, epoch)
        .sort((a, b) => Buffer.compare(Buffer.from(hex(a.node_id)), Buffer.from(hex(b.node_id))));

    // QuorumCertificate RLP exactly as serialized by monad-bft: [vote [id, round, epoch], signatures].
    const sigs = RLP.decode(hex(qcSigHex)) as [[Uint8Array, Uint8Array], Uint8Array];
    const int = (v: bigint) => (v === 0n ? new Uint8Array(0) : hex(v.toString(16)));
    const voteRlp = RLP.encode([hex(id), int(round), int(epoch)]);
    const qcRlp = RLP.encode([[hex(id), int(round), int(epoch)], sigs]);
    const sigPoint = bls.G2.ProjectivePoint.fromHex(sigs[1]);
    const blob = cat(...set.map((v) => cat(g1Eip2537(bls.G1.ProjectivePoint.fromHex(hex(v.cert_pubkey))), word(BigInt(v.stake)))));

    // Off-chain sanity check (the on-chain check is the vitest spec).
    const n = Number(BigInt(toHex(sigs[0][0])));
    const bitmap = BigInt(toHex(sigs[0][1]));
    let apk = bls.G1.ProjectivePoint.ZERO;
    let signed = 0n;
    let total = 0n;
    set.forEach((v, i) => {
        total += BigInt(v.stake);
        if ((bitmap >> BigInt(n - 1 - i)) & 1n) {
            apk = apk.add(bls.G1.ProjectivePoint.fromHex(hex(v.cert_pubkey)));
            signed += BigInt(v.stake);
        }
    });
    const H = bls.G2.hashToCurve(cat(VOTE_PREFIX, voteRlp), {DST}) as unknown as InstanceType<typeof bls.G2.ProjectivePoint>;
    const ok = bls.fields.Fp12.eql(bls.pairing(apk, H), bls.pairing(bls.G1.ProjectivePoint.BASE, sigPoint));
    if (!ok || n !== set.length) throw new Error(`${net}: live QC does not verify off-chain`);

    // Staking precompile storage at a pinned block (the slots a rotation proves).
    const [bnHex] = (await rpc(net, [{method: "eth_blockNumber", params: []}])) as string[];
    const at = bnHex;
    const S = "0x0000000000000000000000000000000000001000";
    const sl = (k: bigint) => toHex(word(k));
    const head = (await rpc(net, [1n, 2n, 0x02n << 248n].map((k) => ({method: "eth_getStorageAt", params: [S, sl(k), at]})))) as string[];
    const length = Number(BigInt(head[2]) >> 192n);
    const idWords = (await rpc(net, Array.from({length}, (_, i) => ({method: "eth_getStorageAt", params: [S, sl((0x02n << 248n) + 1n + BigInt(i)), at]})))) as string[];
    const ids = idWords.map((w) => BigInt(w) >> 192n);
    const perId = (await rpc(net, ids.flatMap((vid) => {
        const st = (0x04n << 248n) | (vid << 184n);
        const ke = ((0x09n << 248n) | (vid << 184n)) + 3n;
        return [st, ke, ke + 1n, ke + 2n].map((k) => ({method: "eth_getStorageAt", params: [S, sl(k), at]}));
    }))) as string[];
    const [rawHeader, block] = (await rpc(net, [
        {method: "debug_getRawHeader", params: [at]},
        {method: "eth_getBlockByNumber", params: [at, false]}
    ])) as [string, {hash: string; stateRoot: string; number: string}];

    return {
        network: net,
        chainId: NETWORKS[net].chainId,
        forkpointUrl: fp.url,
        forkpointToml: fp.toml,
        qc: {id, round: round.toString(), epoch: epoch.toString(), qcRlp: toHex(qcRlp), voteRlp: toHex(voteRlp),
            signatureCompressed: toHex(sigs[1]), signatureUncompressed: toHex(g2Eip2537(sigPoint))},
        validatorSet: {epoch: epoch.toString(), sorted: set, blob: toHex(blob), blobHash: toHex(keccak_256(blob))},
        // every set published in validators.toml (current and, in the delay period, next epoch), consensus order
        validatorSets: Object.fromEntries([...validatorsToml.matchAll(/\[\[validator_sets\]\]\s*\nepoch = (\d+)/g)].map((m) => [m[1],
            validatorSet(validatorsToml, BigInt(m[1])).sort((a, b) => Buffer.compare(Buffer.from(hex(a.node_id)), Buffer.from(hex(b.node_id))))])),
        offchain: {signers: [...Array(n).keys()].filter((i) => (bitmap >> BigInt(n - 1 - i)) & 1n).length,
            signedStake: signed.toString(), totalStake: total.toString()},
        staking: {block: BigInt(at).toString(), epochWord: head[0], inDelayWord: head[1], lengthWord: head[2], ids: ids.map(String),
            words: perId},
        ethHeader: {number: BigInt(block.number).toString(), hash: block.hash, stateRoot: block.stateRoot, raw: rawHeader},
        capturedAt: new Date().toISOString()
    };
}

if (import.meta.url === `file://${process.argv[1]}`) {
    const out: Record<string, unknown> = {};
    for (const net of Object.keys(NETWORKS) as Net[]) {
        out[net] = await captureNetwork(net);
        const c = out[net] as Awaited<ReturnType<typeof captureNetwork>>;
        console.log(`${net}: QC round ${c.qc.round} epoch ${c.qc.epoch}, ${c.offchain.signers}/${c.validatorSet.sorted.length} signers,` +
            ` staking@${c.staking.block} (${c.staking.ids.length} ids)`);
    }
    mkdirSync(path.dirname(OUT), {recursive: true});
    writeFileSync(OUT, JSON.stringify(out, null, 1));
    console.log("wrote", OUT);
}

