import {mkdirSync, readFileSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {decodeAbiParameters, decodeFunctionData, keccak256, toHex, type Hex} from "viem";
import {deriveChannelSlots, encodeEthTrustAnchor, type EthGetProofResult} from "./buildEthMainnetProof.js";
import {
    buildLiveLightClient,
    captureBeaconLive,
    DEFAULT_EXECUTION_RPC,
    rpc,
    type BeaconCapture,
    type LiveLightClient
} from "./buildEthLiveProof.js";
import {
    ACCOUNT_CODE_STORAGE,
    diamondProofItem,
    diamondSlots,
    encodeStoredBatchInfo,
    encodeZkSyncBundle,
    encodeZkSyncL2StateRootProof,
    foldZkProof,
    packEntries,
    slotHex,
    ZKCHAIN_STORAGE_LAYOUT,
    type StoredBatchInfo,
    type ZkStorageProof,
    type ZkSyncProfile
} from "./zksync.js";

/// Live-data proof builder for ZkSyncEraVerifier: ZKsync Sepolia (chain 300, EraVM) settling on
/// Ethereum Sepolia.
///
/// Chain of real data:
///   Sepolia sync committee (finality_update, bootstrap) → attested execution block B
///   → eth_getProof at B of ZKsync Sepolia's diamond proxy: totalBatchesExecuted, storedBatchHashes[n]
///     and protocolVersion, for n = the newest batch executed at B
///   → StoredBatchInfo of batch n, decoded from its L1 executeBatchesSharedBridge calldata, whose keccak
///     is storedBatchHashes[n] and whose batchHash is the L2 state-tree root
///   → zks_getProof at batch n (Blake2s sparse Merkle tree) of the ClprService stand-in.
///
/// There is no ClprService on ZKsync Sepolia, so the stand-in is the L2BaseToken system contract
/// (0x…800a): its real versioned bytecode hash (AccountCodeStorage) is pinned, and the channel slots are
/// absent there (genuine exclusion proofs → zeroed metadata). Every tree proof costs the same 256 levels
/// whether it proves inclusion or exclusion.
///
/// CLI:
///   npx tsx test/e2e/relay/buildZkSyncLiveProof.ts                       build from the fixture, print a summary
///   npx tsx test/e2e/relay/buildZkSyncLiveProof.ts --refresh [--wait-nonsigners SECS]

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ZKSYNC_SEPOLIA_FIXTURE = path.resolve(__dirname, "../fixtures/zksync-sepolia-live/capture.json");

/// ZKsync Sepolia (era-contracts deployment on Ethereum Sepolia).
export const ZKSYNC_SEPOLIA = {
    l2ChainId: 300,
    diamondProxy: "0x9A6DE0f62Aa270A8bCB1e2610078650D539B1Ef9" as Hex,
    bridgehub: "0x35A54c8C757806eB6820629bc82d90E056394C92" as Hex,
    l2Rpcs: ["https://sepolia.era.zksync.dev"],
    /// Protocol versions whose ZKChainStorage layout was checked (0.29.x on Sepolia, 0.30.x on mainnet).
    minProtocolVersion: (29n << 32n),
    maxProtocolVersion: (30n << 32n) | 0xffffffffn
};
/// ClprService stand-in: the L2BaseToken system contract.
export const L2_ACCOUNT: Hex = "0x000000000000000000000000000000000000800a";
export const ZKSYNC_LIVE_CHANNEL_ID: Hex = keccak256(toHex("clpr/zksync-live/zksync-sepolia"));

const EXECUTE_ABI = [{
    type: "function", name: "executeBatchesSharedBridge", stateMutability: "nonpayable", outputs: [],
    inputs: [{type: "address"}, {type: "uint256"}, {type: "uint256"}, {type: "bytes"}]
}] as const;
const STORED_BATCH_INFO_ARRAY = [{
    type: "tuple[]", components: [
        {type: "uint64", name: "batchNumber"}, {type: "bytes32", name: "batchHash"},
        {type: "uint64", name: "indexRepeatedStorageChanges"}, {type: "uint256", name: "numberOfLayer1Txs"},
        {type: "bytes32", name: "priorityOperationsHash"}, {type: "bytes32", name: "dependencyRootsRollingHash"},
        {type: "bytes32", name: "l2LogsTreeRoot"}, {type: "uint256", name: "timestamp"}, {type: "bytes32", name: "commitment"}
    ]
}] as const;

async function l2rpc<T>(method: string, params: unknown[]): Promise<T> {
    let lastErr: unknown;
    for (const url of ZKSYNC_SEPOLIA.l2Rpcs) {
        try {
            return await rpc<T>(url, method, params);
        } catch (err) {
            lastErr = err;
        }
    }
    throw lastErr;
}

export interface ZkSyncLiveCapture {
    network: string;
    capturedAt: string;
    sources: {beaconApi: string; l1Rpc: string; l2Rpcs: string[]};
    beacon: BeaconCapture;
    l1: {
        block: {number: string; hash: Hex; stateRoot: Hex; timestamp: string};
        diamondProxy: Hex;
        batchNumber: string;
        totalBatchesExecuted: string;
        protocolVersion: string;
        executeTxHash: Hex;
        storedBatchInfo: Hex;
        diamondProof: EthGetProofResult;
    };
    l2: {
        batchDetails: {number: number; rootHash: Hex; commitment: Hex; status: string; executedAt: string};
        account: Hex;
        keys: Hex[];
        proof: {address: Hex; storageProof: ZkStorageProof[]};
    };
}

/// The decoded StoredBatchInfo of batch `n` from its L1 execute transaction.
async function storedBatchInfoFromExecuteTx(l1Rpc: string, txHash: Hex, n: bigint): Promise<StoredBatchInfo> {
    const tx = await rpc<{input: Hex}>(l1Rpc, "eth_getTransactionByHash", [txHash]);
    const {args} = decodeFunctionData({abi: EXECUTE_ABI, data: tx.input});
    const data = args[3] as Hex;
    // data = version byte (0x01) ‖ abi.encode(StoredBatchInfo[], …): the first head word is the array.
    if (!data.startsWith("0x01")) throw new Error(`unexpected execute data version ${data.slice(0, 4)}`);
    const [infos] = decodeAbiParameters(STORED_BATCH_INFO_ARRAY, ("0x" + data.slice(4)) as Hex);
    const info = (infos as readonly StoredBatchInfo[]).find((b) => BigInt(b.batchNumber) === n);
    if (!info) throw new Error(`batch ${n} not in execute tx ${txHash}`);
    return {...info, batchNumber: BigInt(info.batchNumber), indexRepeatedStorageChanges: BigInt(info.indexRepeatedStorageChanges)};
}

export async function captureZkSyncSepoliaLive(opts: {
    beaconApis?: string[];
    l1Rpc?: string;
    waitForNonSignersMs?: number;
} = {}): Promise<ZkSyncLiveCapture> {
    const l1Rpc = opts.l1Rpc ?? DEFAULT_EXECUTION_RPC;
    const diamond = ZKSYNC_SEPOLIA.diamondProxy;

    const {beacon, extra} = await captureBeaconLive(opts, async (_execution, B) => {
        const executed = BigInt(await rpc<Hex>(l1Rpc, "eth_getStorageAt",
            [diamond, slotHex(ZKCHAIN_STORAGE_LAYOUT.totalBatchesExecutedSlot), B]));
        const n = executed;
        const diamondProof = await rpc<EthGetProofResult>(l1Rpc, "eth_getProof", [diamond, diamondSlots(n), B]);
        const block = await rpc<{number: string; hash: Hex; stateRoot: Hex; timestamp: string}>(
            l1Rpc, "eth_getBlockByNumber", [B, false]);
        return {n, executed, diamondProof, block};
    });

    const n = extra.n;
    const details = await l2rpc<ZkSyncLiveCapture["l2"]["batchDetails"] & {executeTxHash: Hex}>(
        "zks_getL1BatchDetails", [Number(n)]);
    const info = await storedBatchInfoFromExecuteTx(l1Rpc, details.executeTxHash, n);
    const keys = [...deriveChannelSlots(ZKSYNC_LIVE_CHANNEL_ID)];
    const proof = await l2rpc<ZkSyncLiveCapture["l2"]["proof"]>("zks_getProof", [L2_ACCOUNT, keys, Number(n)]);
    const codeProof = await l2rpc<ZkSyncLiveCapture["l2"]["proof"]>("zks_getProof",
        [ACCOUNT_CODE_STORAGE, [slotHex(BigInt(L2_ACCOUNT))], Number(n)]);
    const pv = extra.diamondProof.storageProof.find((s) => BigInt(s.key) === ZKCHAIN_STORAGE_LAYOUT.protocolVersionSlot)!;

    return {
        network: "zksync-sepolia on " + beacon.network,
        capturedAt: new Date().toISOString(),
        sources: {beaconApi: beacon.sources.beaconApi, l1Rpc, l2Rpcs: ZKSYNC_SEPOLIA.l2Rpcs},
        beacon: {...beacon, sources: {beaconApi: beacon.sources.beaconApi, executionRpc: l1Rpc}},
        l1: {
            block: extra.block,
            diamondProxy: diamond,
            batchNumber: n.toString(),
            totalBatchesExecuted: extra.executed.toString(),
            protocolVersion: BigInt(pv.value).toString(),
            executeTxHash: details.executeTxHash,
            storedBatchInfo: encodeStoredBatchInfo(info),
            diamondProof: extra.diamondProof
        },
        l2: {
            batchDetails: {number: details.number, rootHash: details.rootHash, commitment: details.commitment,
                status: details.status, executedAt: details.executedAt},
            account: L2_ACCOUNT,
            keys,
            proof: {address: L2_ACCOUNT, storageProof: [...codeProof.storageProof, ...proof.storageProof]}
        }
    };
}

// ── Pure builder ───────────────────────────────────────────────────────────
export interface ZkSyncLiveProof {
    lightClient: LiveLightClient;
    profile: ZkSyncProfile;
    batchNumber: bigint;
    l2Root: Hex;
    trustAnchor: Hex;
    channelContext: Hex;
    channelId: Hex;
    l2Account: Hex;
    l2CodeHash: Hex;
    storedBatchInfo: Hex;
    diamondProof: unknown[];
    l2StorageProof: Hex;
    /// `verifyL2StateRoot` input (items 0–2).
    l2StateRootProof: Hex;
    bundle: Hex;
}

/// Pure/offline: turn a capture into verifier inputs, cross-checking every link off-chain.
export function buildZkSyncLiveProof(c: ZkSyncLiveCapture): ZkSyncLiveProof {
    const lightClient = buildLiveLightClient(c.beacon);
    const attested = c.beacon.finalityUpdate.data.attested_header;
    if (BigInt(c.l1.block.number) !== BigInt(attested.execution.block_number)) throw new Error("L1 block != attested block");
    if (c.l1.block.stateRoot.toLowerCase() !== attested.execution.state_root.toLowerCase()) throw new Error("L1 stateRoot mismatch");

    const n = BigInt(c.l1.batchNumber);
    if (n > BigInt(c.l1.totalBatchesExecuted)) throw new Error("batch not executed at the attested L1 block");
    const stored = c.l1.diamondProof.storageProof.find((s) => BigInt(s.key) === BigInt(diamondSlots(n)[1]))!;
    if (BigInt(keccak256(c.l1.storedBatchInfo)) !== BigInt(stored.value)) throw new Error("keccak(StoredBatchInfo) != storedBatchHashes[n]");
    const l2Root = ("0x" + c.l1.storedBatchInfo.slice(2 + 64, 2 + 128)) as Hex;
    if (l2Root.toLowerCase() !== c.l2.batchDetails.rootHash.toLowerCase()) throw new Error("StoredBatchInfo.batchHash != batch rootHash");

    const [codeEntry, ...channelEntries] = c.l2.proof.storageProof;
    if (foldZkProof(ACCOUNT_CODE_STORAGE, codeEntry) !== l2Root.toLowerCase()) throw new Error("code-hash proof does not fold to the root");
    for (const sp of channelEntries) {
        if (foldZkProof(c.l2.account, sp) !== l2Root.toLowerCase()) throw new Error(`proof of ${sp.key} does not fold to the root`);
    }
    const l2CodeHash = codeEntry.value;

    const profile: ZkSyncProfile = {
        diamondProxy: c.l1.diamondProxy,
        ...ZKCHAIN_STORAGE_LAYOUT,
        minProtocolVersion: ZKSYNC_SEPOLIA.minProtocolVersion,
        maxProtocolVersion: ZKSYNC_SEPOLIA.maxProtocolVersion
    };
    const pv = BigInt(c.l1.protocolVersion);
    if (pv < profile.minProtocolVersion || pv > profile.maxProtocolVersion) throw new Error(`protocol version ${pv} outside the profile`);

    const channelId = ZKSYNC_LIVE_CHANNEL_ID;
    const trustAnchor = encodeEthTrustAnchor(channelId, l2CodeHash, lightClient.committee, {
        gvr: c.beacon.genesisValidatorsRoot as Hex, forkVersion: lightClient.signed.forkVersion
    });
    const channelContext = (channelId + c.l2.account.slice(2).toLowerCase()) as Hex;
    const diamondProof = diamondProofItem(c.l1.diamondProof, n);
    const l2StorageProof = packEntries([codeEntry, ...channelEntries]);
    const parts = {lightClientProof: lightClient.lightClientProof, diamondProof, storedBatchInfo: c.l1.storedBatchInfo};
    return {
        lightClient,
        profile,
        batchNumber: n,
        l2Root,
        trustAnchor,
        channelContext,
        channelId,
        l2Account: c.l2.account,
        l2CodeHash,
        storedBatchInfo: c.l1.storedBatchInfo,
        diamondProof,
        l2StorageProof,
        l2StateRootProof: encodeZkSyncL2StateRootProof(parts),
        bundle: encodeZkSyncBundle({...parts, l2StorageProof, bundleContent: "0x"})
    };
}

export function loadZkSyncLiveCapture(file = ZKSYNC_SEPOLIA_FIXTURE): ZkSyncLiveCapture {
    return JSON.parse(readFileSync(file, "utf8")) as ZkSyncLiveCapture;
}

function summarize(p: ZkSyncLiveProof, c: ZkSyncLiveCapture): string {
    const pathLens = c.l2.proof.storageProof.map((s) => s.proof.length).join("/");
    return [
        `L1 block ${BigInt(c.l1.block.number)}, participation ${p.lightClient.signed.participants}/512`,
        `diamond ${p.profile.diamondProxy}, protocol ${BigInt(c.l1.protocolVersion) >> 32n}.${BigInt(c.l1.protocolVersion) & 0xffffffffn}, ` +
            `batch ${p.batchNumber} (executed ${c.l1.totalBatchesExecuted}) at ${c.l2.batchDetails.executedAt}`,
        `L2 root ${p.l2Root}, code hash ${p.l2CodeHash}`,
        `tree path lengths ${pathLens}; bundle ${(p.bundle.length - 2) / 2} B`
    ].join("\n");
}

async function main(): Promise<void> {
    const args = process.argv.slice(2);
    let capture: ZkSyncLiveCapture;
    if (args.includes("--refresh")) {
        const waitIdx = args.indexOf("--wait-nonsigners");
        capture = await captureZkSyncSepoliaLive({waitForNonSignersMs: waitIdx >= 0 ? Number(args[waitIdx + 1]) * 1000 : 0});
        buildZkSyncLiveProof(capture); // validate before writing
        mkdirSync(path.dirname(ZKSYNC_SEPOLIA_FIXTURE), {recursive: true});
        writeFileSync(ZKSYNC_SEPOLIA_FIXTURE, JSON.stringify(capture, null, 1) + "\n");
        console.log(`captured → ${path.relative(process.cwd(), ZKSYNC_SEPOLIA_FIXTURE)}`);
    } else {
        capture = loadZkSyncLiveCapture();
    }
    console.log(summarize(buildZkSyncLiveProof(capture), capture));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    main().catch((err) => {
        console.error(err);
        process.exit(1);
    });
}
