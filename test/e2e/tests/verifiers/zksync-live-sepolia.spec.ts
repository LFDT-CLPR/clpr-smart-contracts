import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {
    createPublicClient,
    createWalletClient,
    encodeFunctionData,
    http,
    keccak256,
    toHex,
    type Hex,
    type PublicClient,
    type WalletClient
} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {loadArtifact} from "../../../../script/deploy/artifacts.js";
import {
    buildZkSyncLiveProof,
    loadZkSyncLiveCapture,
    ZKSYNC_SEPOLIA,
    type ZkSyncLiveCapture,
    type ZkSyncLiveProof
} from "../../relay/buildZkSyncLiveProof.js";
import {
    ACCOUNT_CODE_STORAGE,
    encodeZkSyncBundle,
    encodeZkSyncL2StateRootProof,
    packEntries,
    packRecordedEntries,
    slotHex,
    type ZkSyncProfile
} from "../../relay/zksync.js";
import {deriveChannelSlots} from "../../relay/buildEthMainnetProof.js";
import {hexToBuf, rlpDecode, rlpEncode} from "../../lib/rlp.js";

/// ZkSyncEraVerifier against REAL ZKsync Sepolia data settled on Ethereum Sepolia, replayed offline from
/// test/e2e/fixtures/zksync-sepolia-live/capture.json (re-capture: `npm run zksync-live:refresh`).
///
/// Every link is live data: the Sepolia sync committee's signature over the attested header (with its
/// real non-signers), the execution state_root branch, eth_getProof at that L1 block of ZKsync Sepolia's
/// diamond proxy (totalBatchesExecuted, storedBatchHashes[n], protocolVersion), the StoredBatchInfo
/// of batch n decoded from its L1 execute transaction, and zks_getProof (Blake2s sparse Merkle tree) at
/// batch n.
///
/// There is no ClprService on ZKsync Sepolia, so the L2 account is the L2BaseToken system contract with
/// ITS real versioned bytecode hash pinned (an inclusion proof in AccountCodeStorage); the channel slots
/// are absent there (genuine exclusion proofs → zeroed metadata). Inclusion and exclusion proofs cost the
/// same 256 Blake2s levels.
///
/// Run: forge build && npm run test:e2e:zksync-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8742);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HEDERA_GAS_LIMIT = 15_000_000n;
const HEDERA_TX_BYTES = 128 * 1024;

type Metadata = {state: number; nextMessageId: bigint; receivedMessageId: bigint; sentRunningHash: Hex;
    receivedRunningHash: Hex};

const byteLen = (h: Hex) => (h.length - 2) / 2;
const calldataGas = (data: Hex) => hexToBuf(data).reduce((acc, b) => acc + (b === 0 ? 4 : 16), 0);

describe("ZkSyncEraVerifier on live ZKsync Sepolia data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let capture: ZkSyncLiveCapture;
    let live: ZkSyncLiveProof;
    let l1Verifier: Hex;
    let tree: Hex;
    let verifier: Hex;
    const l1Art = loadArtifact("EthL1StateVerifier");
    const treeArt = loadArtifact("ZkSyncStateTreeVerifier");
    const zkArt = loadArtifact("ZkSyncEraVerifier");
    // Errors raised inside the helpers bubble up through the verifier: decode them too.
    const errorsOf = (a: {abi: readonly unknown[]}) => (a.abi as {type: string}[]).filter((e) => e.type === "error");
    const abi = [...zkArt.abi, ...treeArt.abi, ...errorsOf(l1Art)] as readonly unknown[];
    const gasReport: string[] = [];

    async function deploy(art: {abi: readonly unknown[]; bytecode: Hex}, args: unknown[]): Promise<Hex> {
        const hash = await wallet.deployContract({
            abi: art.abi as never, bytecode: art.bytecode, args: args as never, account: wallet.account!, chain: null
        });
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error("deploy failed");
        return r.contractAddress;
    }

    const deployVerifier = (profile: ZkSyncProfile) => deploy(zkArt, [l1Verifier, tree, profile]);

    function read<T>(address: Hex, functionName: string, args: unknown[]): Promise<T> {
        return pub.readContract({address, abi: abi as never, functionName, args}) as Promise<T>;
    }

    /// eth_estimateGas and calldata size of a call; `enforce` asserts Hedera's per-transaction limits.
    async function measure(label: string, address: Hex, functionName: string, args: unknown[], enforce = true): Promise<bigint> {
        const gas = await pub.estimateContractGas({address, abi: abi as never, functionName, args, account: wallet.account!});
        const data = encodeFunctionData({abi, functionName, args} as never);
        const cd = calldataGas(data);
        const fits = gas < HEDERA_GAS_LIMIT && byteLen(data) < HEDERA_TX_BYTES;
        gasReport.push(`${label}: eth_estimateGas ${gas} (= 21000 + ${cd} calldata + ~${gas - 21000n - BigInt(cd)} execution), ` +
            `calldata ${byteLen(data)} B${fits ? "" : "  ← over Hedera's limit"}`);
        if (enforce) {
            expect(gas).toBeLessThan(HEDERA_GAS_LIMIT);
            expect(byteLen(data)).toBeLessThan(HEDERA_TX_BYTES);
        }
        return gas;
    }

    /// The bundle's (account, key) pairs: AccountCodeStorage[service], then the five Channel slots.
    function entryKeys(): {accounts: Hex[]; keys: Hex[]} {
        return {
            accounts: [ACCOUNT_CODE_STORAGE, ...capture.l2.keys.map(() => live.l2Account)],
            keys: [slotHex(BigInt(live.l2Account)), ...capture.l2.keys]
        };
    }

    beforeAll(async () => {
        capture = loadZkSyncLiveCapture();
        live = buildZkSyncLiveProof(capture);

        anvil = spawn("anvil", ["--port", String(ANVIL_PORT), "--silent", "--code-size-limit", "24576"], {stdio: "ignore"});
        const rpc = `http://127.0.0.1:${ANVIL_PORT}`;
        pub = createPublicClient({transport: http(rpc), pollingInterval: 100}) as PublicClient;
        const deadline = Date.now() + 15_000;
        for (;;) {
            try {
                await pub.getChainId();
                break;
            } catch (err) {
                if (Date.now() > deadline) throw err;
                await new Promise((r) => setTimeout(r, 200));
            }
        }
        wallet = createWalletClient({account: privateKeyToAccount(ANVIL_KEY), transport: http(rpc)});
        // Electra/Fulu beacon layout: execution state_root gindex 802 (depth 9), next_sync_committee 87 (depth 6).
        l1Verifier = await deploy(l1Art, [802n, 9n, 87n, 6n, 8192n]);
        tree = await deploy(treeArt, []);
        verifier = await deployVerifier(live.profile);
    });

    afterAll(() => {
        anvil?.kill("SIGTERM");
        if (gasReport.length) console.log(["[zksync-live] gas (Hedera: ≤ 15M gas, ≤ 128 KB tx)", ...gasReport].join("\n  "));
    });

    it("builder: every off-chain cross-check holds on the live capture", () => {
        expect(capture.beacon.finalityUpdate.version).toBe("fulu");
        expect(live.profile.diamondProxy.toLowerCase()).toBe(ZKSYNC_SEPOLIA.diamondProxy.toLowerCase());
        expect(BigInt(capture.l1.batchNumber)).toBeLessThanOrEqual(BigInt(capture.l1.totalBatchesExecuted));
        expect(capture.l2.batchDetails.status).toBe("verified");
        expect(live.l2Root).toBe(capture.l2.batchDetails.rootHash);
        // An EraVM versioned bytecode hash: version 1, constructed.
        expect(live.l2CodeHash.slice(0, 6)).toBe("0x0100");
        expect(3 * live.lightClient.signed.participants).toBeGreaterThanOrEqual(2 * 512);
    });

    it("L1: the sync committee authenticates the attested execution state root", async () => {
        const [stateRoot] = (await pub.readContract({
            address: l1Verifier, abi: l1Art.abi as never, functionName: "verifyL1State",
            args: [live.lightClient.lightClientProof, live.trustAnchor]
        })) as [Hex, bigint, Hex, Hex];
        expect(stateRoot).toBe(capture.l1.block.stateRoot);
    });

    it("executed batch: diamond storage → StoredBatchInfo → the L2 state-tree root", async () => {
        const [root, n, na, naId] = await read<[Hex, bigint, Hex, Hex]>(verifier, "verifyL2StateRoot",
            [live.l2StateRootProof, live.trustAnchor]);
        expect(root).toBe(live.l2Root);
        expect(n).toBe(live.batchNumber);
        expect(na).toBe("0x");
        expect(naId).toBe("0x");
        await measure("verifyL2StateRoot (L1 light client + diamond proof)", verifier, "verifyL2StateRoot",
            [live.l2StateRootProof, live.trustAnchor]);
    });

    it("full verifyBundle in one call: code hash + 5 channel slots in the Blake2s tree", async () => {
        const [metadata, payloads, na, naId] = await read<[Metadata, Hex[], Hex, Hex]>(verifier, "verifyBundle",
            [live.bundle, live.trustAnchor, live.channelContext]);
        expect(metadata.nextMessageId).toBe(0n);
        expect(metadata.receivedMessageId).toBe(0n);
        expect(metadata.sentRunningHash).toBe(toHex(0n, {size: 32}));
        expect(payloads).toEqual([]);
        expect(na).toBe("0x");
        expect(naId).toBe("0x");
        // Reported, not enforced: six inline tree proofs sit at Hedera's limit (see the split path below).
        await measure("verifyBundle, all 6 tree entries inline", verifier, "verifyBundle",
            [live.bundle, live.trustAnchor, live.channelContext], false);
    });

    it("split delivery: recordStorage (tx 1) + verifyBundle with RECORDED entries (tx 2)", async () => {
        const {accounts, keys} = entryKeys();
        const args = [live.l2Root, accounts, keys, live.l2StorageProof];
        await measure("tx 1: ZkSyncStateTreeVerifier.recordStorage (6 entries)", tree, "recordStorage", args);
        const hash = await wallet.writeContract({address: tree, abi: abi as never, functionName: "recordStorage",
            args: args as never, account: wallet.account!, chain: null, gas: HEDERA_GAS_LIMIT});
        expect((await pub.waitForTransactionReceipt({hash})).status).toBe("success");

        const rec = packRecordedEntries(capture.l2.proof.storageProof.map((sp) => sp.value));
        const bundle = encodeZkSyncBundle({lightClientProof: live.lightClient.lightClientProof, diamondProof: live.diamondProof,
            storedBatchInfo: live.storedBatchInfo, l2StorageProof: rec, bundleContent: "0x"});
        const [metadata] = await read<[Metadata]>(verifier, "verifyBundle", [bundle, live.trustAnchor, live.channelContext]);
        expect(metadata.nextMessageId).toBe(0n);
        await measure("tx 2: verifyBundle, 6 RECORDED entries", verifier, "verifyBundle",
            [bundle, live.trustAnchor, live.channelContext]);
    });

    it("state tree alone: one live zks_getProof entry", async () => {
        const sp = capture.l2.proof.storageProof[0];
        const values = await read<Hex[]>(tree, "verifyStorage",
            [live.l2Root, [ACCOUNT_CODE_STORAGE], [slotHex(BigInt(live.l2Account))], packEntries([sp])]);
        expect(values).toEqual([live.l2CodeHash]);
        await measure("ZkSyncStateTreeVerifier.verifyStorage (1 entry)", tree, "verifyStorage",
            [live.l2Root, [ACCOUNT_CODE_STORAGE], [slotHex(BigInt(live.l2Account))], packEntries([sp])]);
    });

    it("rejects when a different (e.g. ClprService) code hash is pinned", async () => {
        const anchor = hexToBuf(live.trustAnchor);
        hexToBuf(keccak256(toHex("some ClprService bytecode hash"))).copy(anchor, 228);
        await expect(read(verifier, "verifyBundle", [live.bundle, "0x" + anchor.toString("hex"), live.channelContext]))
            .rejects.toThrow(/CodeHashMismatch/);
    });

    it("rejects a tampered StoredBatchInfo (e.g. a substituted state root)", async () => {
        const info = hexToBuf(live.storedBatchInfo);
        info[63] ^= 1; // batchHash
        const proof = encodeZkSyncL2StateRootProof({lightClientProof: live.lightClient.lightClientProof,
            diamondProof: live.diamondProof, storedBatchInfo: ("0x" + info.toString("hex")) as Hex});
        await expect(read(verifier, "verifyL2StateRoot", [proof, live.trustAnchor])).rejects.toThrow(/StoredBatchHashMismatch/);
    });

    it("rejects a tampered tree sibling", async () => {
        const entries = [...capture.l2.proof.storageProof];
        const p = [...entries[1].proof];
        p[3] = keccak256(p[3]);
        entries[1] = {...entries[1], proof: p};
        const bundle = encodeZkSyncBundle({lightClientProof: live.lightClient.lightClientProof, diamondProof: live.diamondProof,
            storedBatchInfo: live.storedBatchInfo, l2StorageProof: packEntries(entries), bundleContent: "0x"});
        await expect(read(verifier, "verifyBundle", [bundle, live.trustAnchor, live.channelContext]))
            .rejects.toThrow(/StorageProofRootMismatch/);
    });

    it("rejects the slots of another channel", async () => {
        const otherId = keccak256(toHex("another channel"));
        expect(deriveChannelSlots(otherId)[0]).not.toBe(capture.l2.keys[0]);
        const anchor = hexToBuf(live.trustAnchor);
        hexToBuf(otherId).copy(anchor, 36);
        await expect(read(verifier, "verifyBundle",
            [live.bundle, "0x" + anchor.toString("hex"), (otherId + live.l2Account.slice(2)) as Hex]))
            .rejects.toThrow(/StorageProofRootMismatch/);
    });

    it("rejects when the protocol version is outside the profile (upgrade fails closed)", async () => {
        const other = await deployVerifier({...live.profile, minProtocolVersion: 31n << 32n, maxProtocolVersion: 31n << 32n});
        await expect(read(other, "verifyL2StateRoot", [live.l2StateRootProof, live.trustAnchor]))
            .rejects.toThrow(/UnsupportedProtocolVersion/);
    });

    it("rejects a verifier pinned to another chain's diamond", async () => {
        const other = await deployVerifier({...live.profile, diamondProxy: "0x32400084C286CF3E17e7B677ea9583e60a000324"});
        await expect(read(other, "verifyL2StateRoot", [live.l2StateRootProof, live.trustAnchor])).rejects.toThrow();
    });

    it("rejects when a non-signer proof is dropped", async (ctx) => {
        if (live.lightClient.signed.nonSignerEntries.length === 0) ctx.skip();
        const p = hexToBuf(live.lightClient.lightClientProof);
        expect(p.length).toBeGreaterThan(0);
        const items = rlpDecode(p) as Uint8Array[];
        items[6] = (items[6] as unknown as Uint8Array[]).slice(1) as unknown as Uint8Array;
        const lc = ("0x" + rlpEncode(items as never).toString("hex")) as Hex;
        const proof = encodeZkSyncL2StateRootProof({lightClientProof: lc, diamondProof: live.diamondProof,
            storedBatchInfo: live.storedBatchInfo});
        await expect(read(verifier, "verifyL2StateRoot", [proof, live.trustAnchor])).rejects.toThrow(/NonSignerProofCountMismatch/);
    });

    it("rejects the real signature under the previous fork version (Electra)", async () => {
        const anchor = hexToBuf(live.trustAnchor);
        hexToBuf(capture.beacon.spec.ELECTRA_FORK_VERSION).copy(anchor, 32);
        await expect(read(verifier, "verifyL2StateRoot", [live.l2StateRootProof, "0x" + anchor.toString("hex")]))
            .rejects.toThrow(/BlsSignatureInvalid|BlsPrecompileCallFailed/);
    });
});
