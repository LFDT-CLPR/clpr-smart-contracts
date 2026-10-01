import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {existsSync, readFileSync} from "node:fs";
import path from "node:path";
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
    buildStarknetLiveProof,
    loadStarknetLiveCapture,
    STARKNET_LIVE_CHANNEL_ID,
    STARKNET_LIVE_FIXTURE,
    STARKNET_SEPOLIA,
    type StarknetLiveCapture,
    type StarknetLiveProof
} from "../../relay/buildStarknetLiveProof.js";
import {channelKeys} from "../../relay/starknet.js";
import {hexToBuf} from "../../lib/rlp.js";

/// StarknetVerifier against REAL Starknet Sepolia data settled on Ethereum Sepolia, replayed offline
/// from test/e2e/fixtures/starknet-sepolia-live/capture.json (re-capture: `npm run starknet-live:stage`
/// while the L2 head passes the next posted block, then `npm run starknet-live:refresh`).
///
/// Every link is live data: the Sepolia sync committee's signature over the attested header (with its
/// real non-signers), the execution state_root branch, eth_getProof at that L1 block of the Starknet
/// core contract (StarknetState.globalRoot/blockNumber, the StarkWare proxy's implementation — code hash
/// pinned — and the programHash / aggregatorProgramHash slots, pinned), and starknet_getStorageProof at
/// exactly the Starknet block the core contract holds.
///
/// There is no ClprService on Starknet Sepolia: the stand-in is the STRK token with ITS real class hash
/// pinned. The CLPR channel keys are absent there (real Patricia non-membership proofs → zeroed
/// metadata); the token's total supply is proven present through the same prover.
///
/// Run: forge build && npm run test:e2e:starknet-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8655);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HEDERA_GAS_LIMIT = 15_000_000n;
const HEDERA_TX_BYTES = 128 * 1024;

type Metadata = {state: number; nextMessageId: bigint; receivedMessageId: bigint; sentRunningHash: Hex;
    receivedRunningHash: Hex; endpointManifestVersion: bigint};

const byteLen = (h: Hex) => (h.length - 2) / 2;
const calldataGas = (data: Hex) => hexToBuf(data).reduce((acc, b) => acc + (b === 0 ? 4 : 16), 0);

function tableArtifact(name: string): {abi: readonly unknown[]; bytecode: Hex} {
    const j = JSON.parse(readFileSync(path.resolve("out/StarkTables.sol", `${name}.json`), "utf8"));
    return {abi: j.abi, bytecode: j.bytecode.object};
}

// capture.json exists only after a refresh that caught the core contract at a staged block (see the
// README, "Relaying and live data"); until then the spec is skipped, not failed.
describe.skipIf(!existsSync(STARKNET_LIVE_FIXTURE))("StarknetVerifier on live Starknet Sepolia data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let capture: StarknetLiveCapture;
    let live: StarknetLiveProof;
    let l1Verifier: Hex;
    let prover: Hex;
    let verifier: Hex;
    const l1Art = loadArtifact("EthL1StateVerifier");
    const proverArt = loadArtifact("StarknetStateProver");
    const verifierArt = loadArtifact("StarknetVerifier");
    // Errors raised in the L1 light client and the prover bubble up through the verifier: decode them too.
    const errorsOf = (a: {abi: readonly unknown[]}) => (a.abi as {type: string}[]).filter((e) => e.type === "error");
    const abi = [...verifierArt.abi, ...errorsOf(l1Art), ...errorsOf(proverArt)] as readonly unknown[];
    const gasReport: string[] = [];

    async function deploy(art: {abi: readonly unknown[]; bytecode: Hex}, args: unknown[]): Promise<Hex> {
        const hash = await wallet.deployContract({
            abi: art.abi as never, bytecode: art.bytecode, args: args as never, account: wallet.account!, chain: null
        });
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error("deploy failed");
        return r.contractAddress;
    }

    const deployVerifier = (profile: StarknetLiveProof["profile"]) => deploy(verifierArt, [l1Verifier, prover, profile, live.layout]);

    function read<T>(address: Hex, functionName: string, args: unknown[], useAbi = abi): Promise<T> {
        return pub.readContract({address, abi: useAbi as never, functionName, args}) as Promise<T>;
    }

    async function measure(label: string, address: Hex, functionName: string, args: unknown[], useAbi = abi): Promise<bigint> {
        const gas = await pub.estimateContractGas({address, abi: useAbi as never, functionName, args, account: wallet.account!});
        const data = encodeFunctionData({abi: useAbi, functionName, args} as never);
        const cd = calldataGas(data);
        gasReport.push(`${label}: eth_estimateGas ${gas} (= 21000 + ${cd} calldata + ~${gas - 21000n - BigInt(cd)} execution), ` +
            `calldata ${byteLen(data)} B`);
        expect(gas).toBeLessThan(HEDERA_GAS_LIMIT);
        expect(byteLen(data)).toBeLessThan(HEDERA_TX_BYTES);
        return gas;
    }

    beforeAll(async () => {
        capture = loadStarknetLiveCapture();
        live = buildStarknetLiveProof(capture);

        anvil = spawn("anvil", ["--port", String(ANVIL_PORT), "--silent"], {stdio: "ignore"});
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
        const tableA = await deploy(tableArtifact("StarkPedersenTableA"), []);
        const tableB = await deploy(tableArtifact("StarkPedersenTableB"), []);
        prover = await deploy(proverArt, [tableA, tableB]);
        verifier = await deployVerifier(live.profile);
    });

    afterAll(() => {
        anvil?.kill("SIGTERM");
        if (gasReport.length) console.log(["[starknet-live] gas (Hedera: ≤ 15M gas, ≤ 128 KB tx)", ...gasReport].join("\n  "));
    });

    it("builder: every off-chain cross-check holds on the live capture", () => {
        expect(capture.beacon.finalityUpdate.version).toBe("fulu");
        expect(3 * live.lightClient.signed.participants).toBeGreaterThanOrEqual(2 * 512);
        expect(live.profile.core.toLowerCase()).toBe(STARKNET_SEPOLIA.core.toLowerCase());
        expect(live.starknetBlock).toBe(BigInt(capture.starknet.blockNumber));
        expect(live.totalSupply).toBeGreaterThan(0n);
        // The pinned program hashes are the live, non-zero values.
        for (const v of live.profile.pinnedValues) expect(BigInt(v)).toBeGreaterThan(0n);
    });

    it("L1: sync committee → core contract → the Starknet global root and block", async () => {
        const [root, block, na, naId] = await read<[bigint, bigint, Hex, Hex]>(verifier, "verifyStarknetState",
            [live.stateProof, live.trustAnchor]);
        expect(root).toBe(live.globalRoot);
        expect(root).toBe(BigInt(capture.starknet.header.new_root));
        expect(block).toBe(live.starknetBlock);
        expect(na).toBe("0x");
        expect(naId).toBe("0x");
        await measure("verifyStarknetState (L1 light client + core contract)", verifier, "verifyStarknetState",
            [live.stateProof, live.trustAnchor]);
    });

    it("Starknet: contract trie → STRK leaf → storage trie (total supply present, CLPR keys absent)", async () => {
        const [classHash, , values] = await read<[bigint, bigint, bigint[]]>(prover, "verifyStorage",
            [live.globalRoot, BigInt(live.service), live.storage.keys, live.storage.proof], proverArt.abi);
        expect(toHex(classHash, {size: 32})).toBe(live.classHash);
        expect(values).toEqual(live.storage.values);
        expect(values[values.length - 1]).toBe(live.totalSupply);
        expect(values.slice(0, -1).every((v) => v === 0n)).toBe(true);
        await measure(`StarknetStateProver.verifyStorage (${live.storage.keys.length} keys)`, prover, "verifyStorage",
            [live.globalRoot, BigInt(live.service), live.storage.keys, live.storage.proof], proverArt.abi);
    });

    it("full verifyBundle: real Starknet non-membership proofs → zeroed queue metadata", async () => {
        const [metadata, payloads, na, naId] = await read<[Metadata, Hex[], Hex, Hex]>(verifier, "verifyBundle",
            [live.bundle, live.trustAnchor, live.channelContext]);
        expect(metadata.nextMessageId).toBe(0n);
        expect(metadata.receivedMessageId).toBe(0n);
        expect(metadata.sentRunningHash).toBe(toHex(0n, {size: 32}));
        expect(metadata.endpointManifestVersion).toBe(0n);
        expect(payloads).toEqual([]);
        expect(na).toBe("0x");
        expect(naId).toBe("0x");
        await measure("StarknetVerifier.verifyBundle (ACK-only, 8 channel keys)", verifier, "verifyBundle",
            [live.bundle, live.trustAnchor, live.channelContext]);
    });

    it("rejects a different pinned class hash (e.g. a ClprService class)", async () => {
        const anchor = hexToBuf(live.trustAnchor);
        hexToBuf(keccak256(toHex("some ClprService class"))).copy(anchor, 228);
        anchor[228] &= 0x07; // a felt
        await expect(read(verifier, "verifyBundle", [live.bundle, "0x" + anchor.toString("hex"), live.channelContext]))
            .rejects.toThrow(/ClassHashMismatch/);
    });

    it("rejects the proof for another channel (keys derived from channelId leave the node set)", async () => {
        const other = keccak256(toHex("another channel"));
        expect(channelKeys(other)[0]).not.toBe(channelKeys(STARKNET_LIVE_CHANNEL_ID)[0]);
        await expect(read(verifier, "verifyBundle", [live.bundle, live.trustAnchor, other + live.service.slice(2)]))
            .rejects.toThrow(/MissingTrieNode/);
    });

    it("rejects when the core implementation is not the pinned one", async () => {
        const v = await deployVerifier({...live.profile, coreImplCodeHash: keccak256(toHex("other implementation"))});
        await expect(read(v, "verifyStarknetState", [live.stateProof, live.trustAnchor]))
            .rejects.toThrow(/CoreImplementationMismatch/);
    });

    it("rejects when governance changed a pinned slot (programHash)", async () => {
        const pinnedValues = [...live.profile.pinnedValues];
        pinnedValues[0] = keccak256(toHex("another Starknet OS"));
        const v = await deployVerifier({...live.profile, pinnedValues});
        await expect(read(v, "verifyStarknetState", [live.stateProof, live.trustAnchor]))
            .rejects.toThrow(/CorePinnedSlotMismatch/);
    });

    it("rejects the real signature under the previous fork version (Electra)", async () => {
        const anchor = hexToBuf(live.trustAnchor);
        hexToBuf(capture.beacon.spec.ELECTRA_FORK_VERSION).copy(anchor, 32);
        await expect(read(verifier, "verifyStarknetState", [live.stateProof, "0x" + anchor.toString("hex")]))
            .rejects.toThrow(/BlsSignatureInvalid|BlsPrecompileCallFailed/);
    });
});
