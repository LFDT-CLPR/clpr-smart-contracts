import {spawn, type ChildProcess} from "node:child_process";
import {createHash} from "node:crypto";
import {mkdirSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {encodeAbiParameters, keccak256, toHex, type Hex} from "viem";
import {rlpEncode} from "../lib/rlp.js";
import {pbBytes, pbInt, pbLen, pbStr} from "../lib/proto.js";
import {deriveChannelSlots, type EthGetProofResult} from "./buildEthMainnetProof.js";
import {
    ACCOUNT_CODE_STORAGE,
    diamondProofItem,
    diamondSlots,
    encodeStoredBatchInfo,
    packedProtocolVersion,
    packEntries,
    slotHex,
    SparseTree,
    storedBatchHashSlot,
    ZKCHAIN_STORAGE_LAYOUT,
    type StoredBatchInfo,
    type ZkStorageProof
} from "./zksync.js";

/// Synthetic-state fixture for the Foundry ZkSyncEraVerifier / ZkSyncStateTreeVerifier tests.
///
/// L2: an in-memory ZKsync state tree (Blake2s SMT, same hashing as zksync-era; the reference root of
/// zksync-era's `compute_tree_hash_works_correctly` is reproduced by test/e2e/relay/zksync.ts) holding a
/// ClprService-shaped account with a populated channel, its AccountCodeStorage entry, an endpoint-manifest
/// commitment and unrelated noise leaves. Two tree versions: batch N−1 (older channel state) and batch N.
///
/// L1: one throw-away anvil holding a "diamond proxy" whose ZKChainStorage slots are written with
/// `anvil_setStorageAt` (totalBatchesExecuted = N, protocolVersion = 0.29.1, storedBatchHashes for
/// N−2 (legacy 256-byte encoding), N−1, N, and N+1 (committed, not executed)). The diamond's MPT proofs come
/// from anvil's `eth_getProof`, so they are genuine.
///
/// Run: npx tsx test/e2e/relay/buildZkSyncSyntheticFixture.ts

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ZKSYNC_SYNTHETIC_FIXTURE = path.resolve(__dirname, "../../verifiers/evm/zksync/fixtures/synthetic.json");

const DIAMOND: Hex = "0xd1a0000000000000000000000000000000000324";
const OTHER_DIAMOND: Hex = "0xd1a0000000000000000000000000000000000325";
const DIAMOND_CODE: Hex = "0x6080604052348015600f57600080fd5b50";
const SERVICE: Hex = "0x5e7c1ce1acce5e7c1ce1acce5e7c1ce1acce5e7c";
/// A versioned EraVM bytecode hash: version 1, constructed (0), length 0x0123 words, sha256 tail.
const SERVICE_CODE_HASH: Hex = "0x01000123" + "9b".repeat(28) as Hex;
const CHANNEL_ID: Hex = keccak256(toHex("clpr/zksync/synthetic"));
const N = 1000n;
const PROTOCOL_VERSION = packedProtocolVersion(29, 1);

// ── anvil plumbing ─────────────────────────────────────────────────────────
async function startAnvil(port: number): Promise<{proc: ChildProcess; url: string}> {
    const proc = spawn("anvil", ["--port", String(port), "--silent"], {stdio: "ignore"});
    const url = `http://127.0.0.1:${port}`;
    const deadline = Date.now() + 15_000;
    for (;;) {
        try {
            await rpc(url, "eth_chainId", []);
            return {proc, url};
        } catch (err) {
            if (Date.now() > deadline) throw err;
            await new Promise((r) => setTimeout(r, 200));
        }
    }
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

const word = (n: bigint) => slotHex(n);
const hexOf = (parts: unknown) => ("0x" + rlpEncode(parts as never).toString("hex")) as Hex;

/// `_lastMessageRunningHashSlot(channelId, messageId)`.
function messageRunningHashSlot(channelId: Hex, messageId: bigint): Hex {
    const qBase = BigInt(keccak256(encodeAbiParameters([{type: "bytes32"}, {type: "uint256"}], [channelId, 1n])));
    const msgBase = BigInt(keccak256(encodeAbiParameters([{type: "uint256"}, {type: "uint256"}], [messageId, qBase])));
    return slotHex(msgBase + 1n);
}

interface ChannelState {
    status: bigint;
    nextMessageId: bigint;
    receivedMessageId: bigint;
    sent: Hex;
    received: Hex;
    manifestVersion: bigint;
}

/// The five Channel slot values in ClprEvmBundleVerifier's packing.
function channelValues(c: ChannelState): Hex[] {
    const verifier = 0x1234n;
    return [
        word(verifier | (c.status << 160n) | (c.nextMessageId << 168n)),
        word((c.receivedMessageId << 64n) | 7n),
        c.sent,
        c.received,
        word(c.manifestVersion)
    ];
}

function manifestPreimage(version: bigint): Hex {
    const endpoint = Buffer.concat([
        pbLen(1, Buffer.concat([pbStr(1, "10.0.0.7"), pbInt(2, 50211n)])),
        pbBytes(2, "0xc0ffee"),
        pbBytes(3, "0x000000000000000000000000000000000000abcd")
    ]);
    return ("0x" + Buffer.concat([pbInt(1, version), pbBytes(2, SERVICE), pbLen(3, endpoint)]).toString("hex")) as Hex;
}

function buildTree(c: ChannelState, manifest: Hex, noise: number): SparseTree {
    const t = new SparseTree();
    // Noise first so the service's leaves get non-trivial enumeration indices.
    for (let i = 0; i < noise; i++) {
        t.set(("0x" + (0xa000 + i).toString(16).padStart(40, "0")) as Hex, word(BigInt(i)), keccak256(toHex(`noise ${i}`)));
    }
    t.set(ACCOUNT_CODE_STORAGE, word(BigInt(SERVICE)), SERVICE_CODE_HASH);
    const slots = deriveChannelSlots(CHANNEL_ID);
    channelValues(c).forEach((v, i) => t.set(SERVICE, slots[i], v));
    for (let m = 1n; m < c.nextMessageId; m++) t.set(SERVICE, messageRunningHashSlot(CHANNEL_ID, m), keccak256(toHex(`msg ${m}`)));
    t.set(SERVICE, word(18n), keccak256(manifest));
    return t;
}

/// Packed L2 proofs for one tree version.
function l2Proofs(t: SparseTree, c: ChannelState) {
    const slots = deriveChannelSlots(CHANNEL_ID);
    const code = t.proof(ACCOUNT_CODE_STORAGE, word(BigInt(SERVICE)));
    const ch = slots.map((s) => t.proof(SERVICE, s));
    const msg = t.proof(SERVICE, messageRunningHashSlot(CHANNEL_ID, c.nextMessageId - 1n));
    const manifest = t.proof(SERVICE, word(18n));
    const pack = (es: ZkStorageProof[]) => packEntries(es);
    return {
        root: t.root(),
        ack: pack([code, ...ch]),
        withMessage: pack([code, ...ch, msg]),
        unpinned: pack(ch),
        manifest: pack([manifest]),
        manifestWithCode: pack([code, manifest]),
        // Single entries for the state-tree unit tests.
        entries: {code, ch0: ch[0], msg, absent: t.proof(SERVICE, word(0xdeadn))}
    };
}

function batch(n: bigint, root: Hex): StoredBatchInfo {
    return {
        batchNumber: n,
        batchHash: root,
        indexRepeatedStorageChanges: 4242n + n,
        numberOfLayer1Txs: 2n,
        priorityOperationsHash: keccak256(toHex(`prio ${n}`)),
        dependencyRootsRollingHash: word(0n),
        l2LogsTreeRoot: keccak256(toHex(`logs ${n}`)),
        timestamp: 1_790_000_000n + n,
        commitment: keccak256(toHex(`commitment ${n}`))
    };
}

/// abi.encode of the legacy (pre-v27) StoredBatchInfo: no dependencyRootsRollingHash.
function encodeLegacy(b: StoredBatchInfo): Hex {
    return encodeAbiParameters(
        [{type: "uint64"}, {type: "bytes32"}, {type: "uint64"}, {type: "uint256"}, {type: "bytes32"}, {type: "bytes32"},
            {type: "uint256"}, {type: "bytes32"}],
        [b.batchNumber, b.batchHash, b.indexRepeatedStorageChanges, b.numberOfLayer1Txs, b.priorityOperationsHash,
            b.l2LogsTreeRoot, b.timestamp, b.commitment]
    );
}

export async function buildZkSyncSyntheticFixture(port = Number(process.env.CLPR_ANVIL_PORT_A ?? 8741)) {
    const older: ChannelState = {status: 1n, nextMessageId: 3n, receivedMessageId: 2n,
        sent: keccak256(toHex("sent v1")), received: keccak256(toHex("received v1")), manifestVersion: 1n};
    // The current bundle carries two payloads; sentRunningHash chains them from zero
    // (sha256(prev ‖ sha256(payload)), the CLPR running hash).
    const payloads = [Buffer.from("clpr payload one"), Buffer.from("clpr payload two")];
    const sha = (...b: Buffer[]) => createHash("sha256").update(Buffer.concat(b)).digest();
    let running = Buffer.alloc(32);
    for (const pl of payloads) running = sha(running, sha(pl));
    const bundleContent = ("0x" + Buffer.concat(payloads.map((pl) => pbBytes(2, pl))).toString("hex")) as Hex;
    const current: ChannelState = {status: 1n, nextMessageId: 5n, receivedMessageId: 4n,
        sent: ("0x" + running.toString("hex")) as Hex, received: keccak256(toHex("received v2")), manifestVersion: 2n};
    const manifest = manifestPreimage(2n);
    const treeOld = buildTree(older, manifestPreimage(1n), 24);
    const treeNew = buildTree(current, manifest, 40);
    const pOld = l2Proofs(treeOld, older);
    const pNew = l2Proofs(treeNew, current);

    const infos = {
        legacy: batch(N - 2n, pOld.root),
        older: batch(N - 1n, pOld.root),
        current: batch(N, pNew.root),
        notExecuted: batch(N + 1n, pNew.root)
    };
    const enc = {
        legacy: encodeLegacy(infos.legacy),
        older: encodeStoredBatchInfo(infos.older),
        current: encodeStoredBatchInfo(infos.current),
        notExecuted: encodeStoredBatchInfo(infos.notExecuted)
    };

    const l1 = await startAnvil(port);
    try {
        for (const d of [DIAMOND, OTHER_DIAMOND]) {
            await rpc(l1.url, "anvil_setCode", [d, DIAMOND_CODE]);
            await rpc(l1.url, "anvil_setStorageAt", [d, slotHex(ZKCHAIN_STORAGE_LAYOUT.totalBatchesExecutedSlot), word(N)]);
            await rpc(l1.url, "anvil_setStorageAt", [d, slotHex(ZKCHAIN_STORAGE_LAYOUT.protocolVersionSlot), word(PROTOCOL_VERSION)]);
        }
        for (const [k, b] of Object.entries(infos) as [keyof typeof infos, StoredBatchInfo][]) {
            await rpc(l1.url, "anvil_setStorageAt", [DIAMOND, storedBatchHashSlot(b.batchNumber), keccak256(enc[k])]);
        }
        await rpc(l1.url, "evm_mine", []);
        const block = await rpc<{number: Hex; stateRoot: Hex}>(l1.url, "eth_getBlockByNumber", ["latest", false]);
        const all = [N - 2n, N - 1n, N, N + 1n].flatMap((n) => diamondSlots(n));
        const proof = await rpc<EthGetProofResult>(l1.url, "eth_getProof", [DIAMOND, [...new Set(all)], block.number]);

        const diamondProof = (n: bigint) => hexOf(diamondProofItem(proof, n));
        const e = pNew.entries;
        const fixture = {
            description: "Synthetic L1/L2 state for ZkSyncEraVerifier unit tests (anvil eth_getProof for the L1 diamond, "
                + "an in-memory Blake2s SMT for L2). Regenerate with npx tsx test/e2e/relay/buildZkSyncSyntheticFixture.ts",
            l1: {
                stateRoot: block.stateRoot,
                diamond: DIAMOND,
                otherDiamond: OTHER_DIAMOND,
                protocolVersion: word(PROTOCOL_VERSION),
                totalBatchesExecuted: Number(N)
            },
            l2: {
                service: SERVICE,
                serviceCodeHash: SERVICE_CODE_HASH,
                channelId: CHANNEL_ID,
                root: pNew.root,
                olderRoot: pOld.root,
                manifestPreimage: manifest,
                bundleContent,
                payloadCount: payloads.length,
                expected: {
                    status: Number(current.status),
                    nextMessageId: Number(current.nextMessageId),
                    receivedMessageId: Number(current.receivedMessageId),
                    sentRunningHash: current.sent,
                    receivedRunningHash: current.received,
                    endpointManifestVersion: Number(current.manifestVersion)
                },
                expectedOlder: {
                    nextMessageId: Number(older.nextMessageId),
                    sentRunningHash: older.sent
                }
            },
            batches: {
                current: {number: Number(N), info: enc.current, diamondProof: diamondProof(N)},
                older: {number: Number(N - 1n), info: enc.older, diamondProof: diamondProof(N - 1n)},
                legacy: {number: Number(N - 2n), info: enc.legacy, diamondProof: diamondProof(N - 2n)},
                notExecuted: {number: Number(N + 1n), info: enc.notExecuted, diamondProof: diamondProof(N + 1n)}
            },
            proofs: {
                current: {ack: pNew.ack, withMessage: pNew.withMessage, unpinned: pNew.unpinned, manifest: pNew.manifest,
                    manifestWithCode: pNew.manifestWithCode},
                older: {ack: pOld.ack}
            },
            // Single packed entries (with their account and slot) for ZkSyncStateTreeVerifier tests.
            entries: [
                {name: "code", account: ACCOUNT_CODE_STORAGE, key: word(BigInt(SERVICE)), proof: packEntries([e.code]), value: e.code.value, pathLen: e.code.proof.length},
                {name: "channel+1", account: SERVICE, key: deriveChannelSlots(CHANNEL_ID)[0], proof: packEntries([e.ch0]), value: e.ch0.value, pathLen: e.ch0.proof.length},
                {name: "absent", account: SERVICE, key: word(0xdeadn), proof: packEntries([e.absent]), value: e.absent.value, pathLen: e.absent.proof.length}
            ]
        };
        mkdirSync(path.dirname(ZKSYNC_SYNTHETIC_FIXTURE), {recursive: true});
        writeFileSync(ZKSYNC_SYNTHETIC_FIXTURE, JSON.stringify(fixture, null, 1) + "\n");
        console.log(`wrote ${path.relative(process.cwd(), ZKSYNC_SYNTHETIC_FIXTURE)} (L1 root ${block.stateRoot}, L2 root ${pNew.root})`);
    } finally {
        l1.proc.kill();
    }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    buildZkSyncSyntheticFixture().catch((err) => {
        console.error(err);
        process.exit(1);
    });
}
