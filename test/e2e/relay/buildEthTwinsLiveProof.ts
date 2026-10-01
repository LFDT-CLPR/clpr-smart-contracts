import {mkdirSync, readFileSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {type Hex} from "viem";
import {
    buildEthLiveProof,
    captureSepoliaLive,
    signingCommittee,
    LIVE_CHANNEL_ID,
    participationFromBits,
    type BeaconHeaderJson,
    type EthLiveProof,
    type ExecutionPayloadHeaderJson,
    type LightClientHeaderJson,
    type LiveCapture,
    type SyncAggregateJson
} from "./buildEthLiveProof.js";
import {deriveChannelSlots} from "./buildEthMainnetProof.js";
import {rlpEncode} from "../lib/rlp.js";
import {capellaTypes, containerFieldProof} from "./ssz.js";
import {hexToBuf} from "../lib/rlp.js";

/// Live-data captures for the Ethereum-derived beacon chains served by EthBeaconTwinVerifier.
///
///   Gnosis / Chiado (Fulu): public Lighthouse nodes serve the standard light-client API, so the
///     capture is the same as Sepolia's (`captureSepoliaLive` with Gnosis endpoints).
///   PulseChain / PulseChain testnet v4 (Capella): the public Lighthouse-Pulse v2.5.1 nodes answer 404
///     on every `/eth/v1/beacon/light_client/*` route, but serve SSZ `debug/beacon/states` and
///     `beacon/blocks`. The capture rebuilds the light-client objects itself:
///       - signature block S = the head block; its `sync_aggregate` signs S's parent P (the attested
///         header), under the fork version of epoch(S.slot − 1);
///       - the full BeaconState at P (≈18 MB SSZ) is re-merkleized; it must hash to P.state_root.
///         `current_sync_committee` (gindex 54) is the signing committee, `next_sync_committee`
///         (gindex 55) the real rotation — both with branches against P.state_root;
///       - P's BeaconBlockBody is re-merkleized (must hash to P.body_root) to get the Capella
///         ExecutionPayloadHeader and its 4-sibling `execution_branch` (gindex 25);
///       - `eth_getProof` at P's execution block, fetched immediately (non-archive RPCs).
///     Because the rotation is taken from the SAME attested state, the fixture also yields a full
///     rotation bundle that goes through `verifyBundle`.
///
/// CLI:
///   npx tsx test/e2e/relay/buildEthTwinsLiveProof.ts --chain gnosis|chiado|pulsechain|pulsechain-testnet [--refresh] [--wait-nonsigners SECS]

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ETHTWINS_FIXTURE_DIR = path.resolve(__dirname, "../fixtures/ethtwins-live");
/// Compact verifier inputs for the Foundry suite (test/verifiers/evm/ethtwins), derived from the capture.
/// The Foundry suite replays the two mainnets; the testnets are covered by the vitest spec only.
const FOUNDRY_NETWORKS = ["gnosis", "pulsechain"];
export const ETHTWINS_FOUNDRY_DIR = path.resolve(__dirname, "../../verifiers/evm/ethtwins/fixtures");

export interface TwinNetwork {
    name: string;
    mode: "light-client-api" | "beacon-state-ssz";
    beaconApis: string[];
    executionRpc: string;
    /// The chain's beacon deposit contract (`DEPOSIT_CONTRACT_ADDRESS`): long-lived, real code + storage.
    account: Hex;
    genesisValidatorsRoot: Hex;
}

export const TWIN_NETWORKS: Record<string, TwinNetwork> = {
    gnosis: {
        name: "gnosis",
        mode: "light-client-api",
        beaconApis: ["https://gnosis-beacon-api.publicnode.com", "https://rpc-gbc.gnosischain.com"],
        executionRpc: "https://gnosis-rpc.publicnode.com",
        account: "0x0B98057eA310F4d31F2a452B414647007d1645d9",
        genesisValidatorsRoot: "0xf5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47"
    },
    chiado: {
        name: "chiado",
        mode: "light-client-api",
        beaconApis: ["https://rpc-gbc.chiadochain.net"],
        executionRpc: "https://rpc.chiadochain.net",
        account: "0xb97036A26259B7147018913bD58a774cf91acf25",
        genesisValidatorsRoot: "0x9d642dac73058fbf39c0ae41ab1e34e4d889043cb199851ded7095bc99eb4c1e"
    },
    pulsechain: {
        name: "pulsechain",
        mode: "beacon-state-ssz",
        beaconApis: ["https://rpc-pulsechain.g4mm4.io/beacon-api"],
        executionRpc: "https://rpc.pulsechain.com",
        account: "0x3693693693693693693693693693693693693693",
        genesisValidatorsRoot: "0x3357ba0018a2582aeabe4ae847aa17d50a3a99aaeb66293c01f80a83aecd0c90"
    },
    "pulsechain-testnet": {
        name: "pulsechain-testnet",
        mode: "beacon-state-ssz",
        beaconApis: ["https://rpc-testnet-pulsechain.g4mm4.io/beacon-api"],
        executionRpc: "https://rpc.v4.testnet.pulsechain.com",
        account: "0x3693693693693693693693693693693693693693",
        genesisValidatorsRoot: "0xd81664ba97279a6fa0832041b4aee6009172b4750a99467ff670a9faf3a34e64"
    }
};

export function twinFixturePath(network: string): string {
    return path.join(ETHTWINS_FIXTURE_DIR, `${network}.json`);
}

export function loadTwinCapture(network: string): LiveCapture {
    return JSON.parse(readFileSync(twinFixturePath(network), "utf8")) as LiveCapture;
}

// ── HTTP helpers ───────────────────────────────────────────────────────────
async function getJson<T>(base: string, p: string): Promise<T> {
    const res = await fetch(base + p, {headers: {accept: "application/json"}});
    if (!res.ok) throw new Error(`GET ${base}${p}: ${res.status} ${res.statusText}`);
    return (await res.json()) as T;
}

async function getSsz(base: string, p: string): Promise<Buffer> {
    const res = await fetch(base + p, {headers: {accept: "application/octet-stream"}});
    if (!res.ok) throw new Error(`GET ${base}${p} (ssz): ${res.status} ${res.statusText}`);
    return Buffer.from(await res.arrayBuffer());
}

let rpcId = 0;
async function rpc<T>(url: string, method: string, params: unknown[]): Promise<T> {
    const res = await fetch(url, {
        method: "POST",
        headers: {"content-type": "application/json"},
        body: JSON.stringify({jsonrpc: "2.0", id: ++rpcId, method, params})
    });
    const j = (await res.json()) as {result?: T; error?: {message: string}};
    if (j.error) throw new Error(`${method}: ${j.error.message}`);
    return j.result as T;
}

// ── SSZ → light-client JSON ────────────────────────────────────────────────
const hx = (b: Buffer): string => "0x" + b.toString("hex");
const leU64 = (b: Buffer): string => b.readBigUInt64LE(0).toString();
function leU256(b: Buffer): string {
    let v = 0n;
    for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
    return v.toString();
}

function committeeJson(T: ReturnType<typeof capellaTypes>, bytes: Buffer): {pubkeys: string[]; aggregate_pubkey: string} {
    const [pubkeys, agg] = T.syncCommittee.split(bytes);
    const keys: string[] = [];
    for (let i = 0; i < pubkeys.length; i += 48) keys.push(hx(pubkeys.subarray(i, i + 48)));
    return {pubkeys: keys, aggregate_pubkey: hx(agg)};
}

/// Capella LightClientHeader (beacon + ExecutionPayloadHeader + execution_branch) from the SSZ block.
function capellaLightClientHeader(
    T: ReturnType<typeof capellaTypes>,
    header: BeaconHeaderJson,
    signedBlock: Buffer
): LightClientHeaderJson {
    const [msg] = T.signedBeaconBlock.split(signedBlock);
    const blk = T.beaconBlock.split(msg);
    if (leU64(blk[0]) !== header.slot) throw new Error("block slot != header slot");
    const body = blk[4];
    const outer = containerFieldProof(T.beaconBlockBody, body, "execution_payload");
    if (hx(outer.root) !== header.body_root) throw new Error("re-merkleized BeaconBlockBody != header.body_root");
    if (outer.gindex !== 25n) throw new Error(`execution_payload gindex ${outer.gindex} != 25`);
    const payload = T.beaconBlockBody.split(body)[outer.index];
    const f = T.executionPayload.split(payload);
    const roots = T.executionPayload.fieldRoots(payload);
    const execution: ExecutionPayloadHeaderJson = {
        parent_hash: hx(f[0]),
        fee_recipient: hx(f[1]),
        state_root: hx(f[2]),
        receipts_root: hx(f[3]),
        logs_bloom: hx(f[4]),
        prev_randao: hx(f[5]),
        block_number: leU64(f[6]),
        gas_limit: leU64(f[7]),
        gas_used: leU64(f[8]),
        timestamp: leU64(f[9]),
        extra_data: hx(f[10]),
        base_fee_per_gas: leU256(f[11]),
        block_hash: hx(f[12]),
        transactions_root: hx(roots[13]),
        withdrawals_root: hx(roots[14])
    };
    return {beacon: header, execution, execution_branch: outer.branch.map(hx)};
}

/// PulseChain-style capture: no light-client API, rebuild everything from SSZ state + blocks.
export async function captureFromBeaconState(net: TwinNetwork, opts: {waitForNonSignersMs?: number} = {}): Promise<LiveCapture> {
    const base = net.beaconApis[0];
    const specRaw = (await getJson<{data: Record<string, string>}>(base, "/eth/v1/config/spec")).data;
    const T = capellaTypes(specRaw);
    const spp = BigInt(specRaw.SLOTS_PER_EPOCH) * BigInt(specRaw.EPOCHS_PER_SYNC_COMMITTEE_PERIOD);
    const genesis = (await getJson<{data: {genesis_validators_root: string}}>(base, "/eth/v1/beacon/genesis")).data;
    if (genesis.genesis_validators_root !== net.genesisValidatorsRoot) throw new Error("unexpected GVR");

    // 1. Signature block S (head), with ≥1 non-signer if requested, in the same period as its parent.
    const deadline = Date.now() + (opts.waitForNonSignersMs ?? 0);
    let sBlock: {version: string; data: {message: {slot: string; parent_root: string; body: {sync_aggregate: SyncAggregateJson}}}};
    let sRoot: string;
    let parent: {root: string; header: {message: BeaconHeaderJson}};
    for (;;) {
        const head = (await getJson<{data: {root: string}}>(base, "/eth/v1/beacon/headers/head")).data;
        sRoot = head.root;
        sBlock = await getJson(base, `/eth/v2/beacon/blocks/${sRoot}`);
        if (sBlock.version !== "capella") throw new Error(`signature block fork ${sBlock.version} (capture expects capella)`);
        parent = (await getJson<{data: typeof parent}>(base, `/eth/v1/beacon/headers/${sBlock.data.message.parent_root}`)).data;
        const agg = sBlock.data.message.body.sync_aggregate;
        const n = participationFromBits(hexToBuf(agg.sync_committee_bits)).filter(Boolean).length;
        const samePeriod = BigInt(sBlock.data.message.slot) / spp === BigInt(parent.header.message.slot) / spp;
        console.error(`signature slot ${sBlock.data.message.slot}: ${n}/512, attested slot ${parent.header.message.slot}`);
        if (samePeriod && (n < 512 || Date.now() >= deadline)) break;
        await new Promise((r) => setTimeout(r, 5000));
    }
    const attested = parent.header.message;
    const sigSlot = sBlock.data.message.slot;

    // 2. Attested block (SSZ) → Capella LightClientHeader; execution proof right away.
    const pBlock = await getSsz(base, `/eth/v2/beacon/blocks/${parent.root}`);
    const lcHeader = capellaLightClientHeader(T, attested, pBlock);
    const blockTag = "0x" + BigInt(lcHeader.execution.block_number).toString(16);
    const storageKeys = deriveChannelSlots(LIVE_CHANNEL_ID);
    const proof = await rpc<LiveCapture["account"]["proof"]>(net.executionRpc, "eth_getProof", [net.account, storageKeys, blockTag]);
    const block = await rpc<{hash: string; stateRoot: string; number: string}>(
        net.executionRpc, "eth_getBlockByNumber", [blockTag, false]
    );

    // 3. Attested state (SSZ, by state root) → both committees + branches against P.state_root.
    const state = await getSsz(base, `/eth/v2/debug/beacon/states/${attested.state_root}`);
    const cur = containerFieldProof(T.beaconState, state, "current_sync_committee");
    const next = containerFieldProof(T.beaconState, state, "next_sync_committee");
    if (hx(cur.root) !== attested.state_root) throw new Error("re-merkleized BeaconState != attested state_root");
    if (cur.gindex !== 54n || next.gindex !== 55n) throw new Error(`committee gindices ${cur.gindex}/${next.gindex} != 54/55`);
    const fields = T.beaconState.split(state);
    const currentCommittee = committeeJson(T, fields[cur.index]);
    const nextCommittee = committeeJson(T, fields[next.index]);

    const spec: Record<string, string> = {};
    for (const [k, v] of Object.entries(specRaw)) {
        if (v === null) continue;
        if (/_FORK_(VERSION|EPOCH)$/.test(k) || ["CONFIG_NAME", "PRESET_BASE", "SLOTS_PER_EPOCH", "SECONDS_PER_SLOT",
            "EPOCHS_PER_SYNC_COMMITTEE_PERIOD", "SYNC_COMMITTEE_SIZE", "DEPOSIT_CHAIN_ID", "DEPOSIT_CONTRACT_ADDRESS"].includes(k)) {
            spec[k] = v;
        }
    }
    const syncAggregate = sBlock.data.message.body.sync_aggregate;
    return {
        network: specRaw.CONFIG_NAME ?? net.name,
        capturedAt: new Date().toISOString(),
        sources: {beaconApi: base, executionRpc: net.executionRpc},
        genesisValidatorsRoot: genesis.genesis_validators_root,
        spec,
        derivedFrom: {
            method: "beacon-state-ssz",
            signatureBlockRoot: sRoot,
            note: "No light-client API on this chain's public beacon nodes. finalityUpdate/bootstrap/rotationUpdate " +
                "were rebuilt from the SSZ BeaconState and BeaconBlock at the attested slot; finalized_header repeats " +
                "the attested header and finality_branch is empty."
        },
        finalityUpdate: {
            version: "capella",
            data: {
                attested_header: lcHeader,
                finalized_header: lcHeader,
                finality_branch: [],
                sync_aggregate: syncAggregate,
                signature_slot: sigSlot
            }
        },
        bootstrap: {
            version: "capella",
            data: {header: lcHeader, current_sync_committee: currentCommittee, current_sync_committee_branch: cur.branch.map(hx)}
        },
        rotationUpdate: {
            version: "capella",
            data: {
                attested_header: lcHeader,
                next_sync_committee: nextCommittee,
                next_sync_committee_branch: next.branch.map(hx),
                finalized_header: lcHeader,
                finality_branch: [],
                sync_aggregate: syncAggregate,
                signature_slot: sigSlot
            }
        },
        account: {address: net.account, blockNumber: lcHeader.execution.block_number, block, proof, storageKeys}
    };
}

export async function captureTwin(network: string, opts: {waitForNonSignersMs?: number} = {}): Promise<LiveCapture> {
    const net = TWIN_NETWORKS[network];
    if (!net) throw new Error(`unknown network ${network} (${Object.keys(TWIN_NETWORKS)})`);
    if (net.mode === "beacon-state-ssz") return captureFromBeaconState(net, opts);
    return captureSepoliaLive({
        beaconApis: net.beaconApis,
        executionRpc: net.executionRpc,
        account: net.account,
        waitForNonSignersMs: opts.waitForNonSignersMs
    });
}

/// Verifier-level inputs for Foundry (`vm.parseJson`): the bundle, the anchor, the signing committee
/// (uncompressed, RLP `[pubkeys, aggregate]`, for verifyConfig) and the rotation inputs.
export function foundryFixture(capture: LiveCapture): Record<string, unknown> {
    const p = buildEthLiveProof(capture);
    const committee = signingCommitteeUncompressed(capture);
    const r = p.rotation;
    return {
        network: p.meta.network,
        fork: p.meta.forkName,
        attestedSlot: Number(p.meta.attestedSlot),
        participants: p.meta.participants,
        nonSigners: p.meta.nonSigners,
        genesisValidatorsRoot: p.meta.genesisValidatorsRoot,
        forkVersion: p.meta.forkVersion,
        channelId: p.channelId,
        codeHash: p.codeHash,
        account: p.account,
        executionStateRoot: p.meta.executionStateRoot,
        proofBytes: p.proofBytes,
        // Byte strings the negative tests locate inside proofBytes and corrupt in place.
        bits: "0x" + p.parts.syncAggregate[0].toString("hex"),
        signature: "0x" + p.parts.syncAggregate[1].toString("hex"),
        accountProofLastNode: "0x" + p.parts.accountProof[p.parts.accountProof.length - 1].toString("hex"),
        storageProofFirstNode: "0x" + ((p.parts.storageProof as [Buffer, Buffer[]][])[0][1][0]).toString("hex"),
        trustAnchor: p.trustAnchor,
        channelContext: p.channelContext,
        committeeRlp: committee,
        rotationProofBytes: p.rotationProofBytes ?? "0x",
        rotationRlp: r?.rotationRlp ?? "0x",
        rotationAttestedStateRoot: r?.attestedStateRoot ?? "0x" + "00".repeat(32),
        rotationBeaconBlockRoot: r?.beaconBlockRoot ?? "0x" + "00".repeat(32),
        rotationBits: r?.bits ?? "0x",
        rotationSignature: r?.signature ?? "0x",
        rotationNonSignerWrapperRlp: r?.nonSignerWrapperRlp ?? "0x",
        rotationForkVersion: r?.forkVersion ?? "0x00000000",
        rotationNextAggregate: r?.nextAggregate ?? "0x",
        rotationNextCommitteeMerkleRoot: r?.nextCommitteeMerkleRoot ?? "0x" + "00".repeat(32)
    };
}

function signingCommitteeUncompressed(capture: LiveCapture): Hex {
    const c = signingCommittee(capture).committee;
    return ("0x" + rlpEncode([c.pubkeys, c.aggregate]).toString("hex")) as Hex;
}

function summarize(p: EthLiveProof): string {
    const m = p.meta;
    return [
        `network            ${m.network} (${m.forkName}, fork version ${m.forkVersion}, GVR ${m.genesisValidatorsRoot})`,
        `layout             exec state_root gindex ${m.layout.executionStateRootGindex} (depth ${m.layout.executionBranchDepth}), next committee gindex ${m.layout.nextSyncCommitteeGindex} (depth ${m.layout.nextCommitteeBranchDepth})`,
        `attested slot      ${m.attestedSlot} (signature slot ${m.signatureSlot}, period ${m.period})`,
        `participation      ${m.participants}/512 (${m.nonSigners} non-signer proofs)`,
        `execution block    ${m.executionBlockNumber} state_root ${m.executionStateRoot}`,
        `account            ${p.account} (${m.accountProofNodes} MPT nodes)`,
        `proofBytes         ${(p.proofBytes.length - 2) / 2} bytes`,
        `rotation bundle    ${p.rotationProofBytes ? `${(p.rotationProofBytes.length - 2) / 2} bytes` : "none (harness only)"}`
    ].join("\n");
}

async function main(): Promise<void> {
    const args = process.argv.slice(2);
    const chainIdx = args.indexOf("--chain");
    const networks = chainIdx >= 0 ? [args[chainIdx + 1]] : Object.keys(TWIN_NETWORKS);
    const waitIdx = args.indexOf("--wait-nonsigners");
    for (const network of networks) {
        let capture: LiveCapture;
        if (args.includes("--refresh")) {
            capture = await captureTwin(network, {waitForNonSignersMs: waitIdx >= 0 ? Number(args[waitIdx + 1]) * 1000 : 0});
            buildEthLiveProof(capture); // validate before overwriting the fixture
            mkdirSync(ETHTWINS_FIXTURE_DIR, {recursive: true});
            writeFileSync(twinFixturePath(network), JSON.stringify(capture, null, 1) + "\n");
            console.log(`captured → ${path.relative(process.cwd(), twinFixturePath(network))}`);
        } else {
            capture = loadTwinCapture(network);
        }
        console.log(summarize(buildEthLiveProof(capture)));
        if (!FOUNDRY_NETWORKS.includes(network)) continue;
        mkdirSync(ETHTWINS_FOUNDRY_DIR, {recursive: true});
        const out = path.join(ETHTWINS_FOUNDRY_DIR, `${network}.json`);
        writeFileSync(out, JSON.stringify(foundryFixture(capture), null, 1) + "\n");
        console.log(`foundry fixture → ${path.relative(process.cwd(), out)}`);
    }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    main().catch((err) => {
        console.error(err);
        process.exit(1);
    });
}
