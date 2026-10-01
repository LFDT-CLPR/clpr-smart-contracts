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
    buildOpOracleLiveProof,
    CHAIN_NAMES,
    L1_SECONDS_PER_SLOT,
    loadOpOracleLiveCapture,
    ORACLE_CHAINS,
    type ChainName,
    type OpOracleLiveCapture,
    type OpOracleLiveProof
} from "../../relay/buildOpOracleLiveProof.js";
import {encodeOracleL2StateRootProof, type L2AccountFormat, type OracleProfile} from "../../relay/opOracle.js";
import {hexToBuf} from "../../lib/rlp.js";

/// OpOutputOracleVerifier / OpOutputOracleProposedVerifier against REAL Ethereum-mainnet data for Blast
/// (L2OutputOracle), Mantle (OPSuccinctL2OutputOracle) and Katana (AggLayer AggchainFEP), replayed
/// offline from test/e2e/fixtures/opadapters-live/capture.json (re-capture: `npm run opadapters-live:refresh`).
///
/// Every link is live data: the mainnet sync committee's signature over the attested header (with its
/// real non-signers), the execution state_root branch, eth_getProof at that L1 block of each chain's
/// output oracle (length, element, implementation + code hash, period, optimistic flag), the
/// output-root preimage from the L2 header (Blast: the message-passer root from L2 eth_getProof), and
/// eth_getProof on the L2 at the output's block — through Blast's 7-field account leaf.
///
/// There is no ClprService on these chains, so the L2 account is the L2ToL1MessagePasser predeploy with
/// ITS real code hash pinned; the channel slots are absent (genuine MPT exclusion proofs → zeroed
/// metadata). Blast's finalized output is 7 days old — past its public RPC's 10,000-block eth_getProof
/// window — so its FINALIZED path is checked on L1 (`verifyOutput` on the light-client-proven state
/// root) and its full FINALIZED bundle runs once a refresh finds an output staged ≥ 7 days earlier.
///
/// Run: forge build && npm run test:e2e:opadapters-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8631);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HEDERA_GAS_LIMIT = 15_000_000n;
const HEDERA_TX_BYTES = 128 * 1024;

type Metadata = {state: number; nextMessageId: bigint; receivedMessageId: bigint; sentRunningHash: Hex};

const byteLen = (h: Hex) => (h.length - 2) / 2;
const calldataGas = (data: Hex) => hexToBuf(data).reduce((acc, b) => acc + (b === 0 ? 4 : 16), 0);

describe("output-oracle verifiers on live mainnet data: Blast, Mantle, Katana (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let capture: OpOracleLiveCapture;
    let live: OpOracleLiveProof;
    let l1Verifier: Hex;
    const finalized = {} as Record<ChainName, Hex>;
    const proposed = {} as Record<ChainName, Hex>;
    const l1Art = loadArtifact("EthL1StateVerifier");
    const finArt = loadArtifact("OpOutputOracleVerifier");
    const propArt = loadArtifact("OpOutputOracleProposedVerifier");
    const abi = [...finArt.abi, ...(l1Art.abi as {type: string}[]).filter((e) => e.type === "error")] as readonly unknown[];
    const gasReport: string[] = [];

    async function deploy(art: {abi: readonly unknown[]; bytecode: Hex}, args: unknown[]): Promise<Hex> {
        const hash = await wallet.deployContract({
            abi: art.abi as never, bytecode: art.bytecode, args: args as never, account: wallet.account!, chain: null
        });
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error("deploy failed");
        return r.contractAddress;
    }

    const deployTier = (art: typeof finArt, profile: OracleProfile, format: L2AccountFormat) =>
        deploy(art, [l1Verifier, live.l1GenesisTime, L1_SECONDS_PER_SLOT, profile, format]);

    function read<T>(address: Hex, functionName: string, args: unknown[]): Promise<T> {
        return pub.readContract({address, abi: abi as never, functionName, args}) as Promise<T>;
    }

    async function measure(label: string, address: Hex, functionName: string, args: unknown[]): Promise<bigint> {
        const gas = await pub.estimateContractGas({address, abi: abi as never, functionName, args, account: wallet.account!});
        const data = encodeFunctionData({abi, functionName, args} as never);
        const cd = calldataGas(data);
        gasReport.push(`${label}: eth_estimateGas ${gas} (= 21000 + ${cd} calldata + ~${gas - 21000n - BigInt(cd)} execution), ` +
            `calldata ${byteLen(data)} B`);
        expect(gas).toBeLessThan(HEDERA_GAS_LIMIT);
        expect(byteLen(data)).toBeLessThan(HEDERA_TX_BYTES);
        return gas;
    }

    const bundleArgs = (name: ChainName, which: "newest" | "finalized") => {
        const c = live.chains[name];
        expect(c[which].bundle).not.toBeNull();
        return [c[which].bundle!, c.trustAnchor!, c.channelContext];
    };

    beforeAll(async () => {
        capture = loadOpOracleLiveCapture();
        live = buildOpOracleLiveProof(capture);

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
        for (const name of CHAIN_NAMES) {
            const c = live.chains[name];
            finalized[name] = await deployTier(finArt, c.profile, c.chain.accountFormat);
            proposed[name] = await deployTier(propArt, c.profile, c.chain.accountFormat);
        }
    });

    afterAll(() => {
        anvil?.kill("SIGTERM");
        if (gasReport.length) console.log(["[opadapters-live] gas (Hedera: ≤ 15M gas, ≤ 128 KB tx)", ...gasReport].join("\n  "));
    });

    it("builder: every off-chain cross-check holds on the live capture", () => {
        expect(capture.beacon.finalityUpdate.version).toBe("fulu");
        expect(capture.beacon.network).toBe("mainnet");
        expect(3 * live.lightClient.signed.participants).toBeGreaterThanOrEqual(2 * 512);
        // The chains' own finalization rules, as read at the proven L1 block.
        expect(live.chains.blast.finalizationPeriodSeconds).toBe(604_800n); // L2OutputOracle immutable
        expect(live.chains.mantle.finalizationPeriodSeconds).toBe(43_200n); // OPSuccinctL2OutputOracle slot 8
        expect(live.chains.katana.finalizationPeriodSeconds).toBe(0n); // AggchainFEP: no deletion
        expect(capture.chains.mantle.optimisticMode).toBe(false);
        expect(capture.chains.katana.optimisticMode).toBe(false);
        expect(live.chains.blast.newest.finalizedAtL1).toBe(false);
        expect(live.chains.mantle.newest.finalizedAtL1).toBe(false);
        expect(live.chains.katana.newest.finalizedAtL1).toBe(true);
        for (const name of CHAIN_NAMES) {
            expect(live.chains[name].profile.oracle).toBe(ORACLE_CHAINS[name].oracle);
            expect(live.chains[name].finalized.finalizedAtL1).toBe(true);
        }
    });

    it("L1: the mainnet sync committee authenticates the attested execution state root", async () => {
        const [stateRoot, slot, na, naId] = (await pub.readContract({
            address: l1Verifier, abi: l1Art.abi as never, functionName: "verifyL1State",
            args: [live.lightClient.lightClientProof, live.chains.mantle.trustAnchor]
        })) as [Hex, bigint, Hex, Hex];
        expect(stateRoot).toBe(capture.l1.block.stateRoot);
        expect(slot).toBe(live.l1Slot);
        expect(na).toBe("0x");
        expect(naId).toBe("0x");
    });

    it("Mantle FINALIZED: full verifyBundle on an OP Succinct output past the 12 h period", async () => {
        const [m, payloads] = await read<[Metadata, Hex[]]>(finalized.mantle, "verifyBundle", bundleArgs("mantle", "finalized"));
        expect(m.nextMessageId).toBe(0n);
        expect(m.sentRunningHash).toBe(toHex(0n, {size: 32}));
        expect(payloads).toEqual([]);
        await measure("Mantle FINALIZED verifyBundle", finalized.mantle, "verifyBundle", bundleArgs("mantle", "finalized"));
    });

    it("Katana FINALIZED: full verifyBundle on the newest AggchainFEP output (final once appended)", async () => {
        const [m] = await read<[Metadata]>(finalized.katana, "verifyBundle", bundleArgs("katana", "finalized"));
        expect(m.nextMessageId).toBe(0n);
        await measure("Katana FINALIZED verifyBundle", finalized.katana, "verifyBundle", bundleArgs("katana", "finalized"));
        // Period 0 and no deletion: both tiers accept exactly the same outputs.
        await read(proposed.katana, "verifyBundle", bundleArgs("katana", "finalized"));
    });

    it("Blast PROPOSED: full verifyBundle on the newest output, through the 7-field account leaf", async () => {
        const [m] = await read<[Metadata]>(proposed.blast, "verifyBundle", bundleArgs("blast", "newest"));
        expect(m.nextMessageId).toBe(0n);
        await measure("Blast PROPOSED verifyBundle", proposed.blast, "verifyBundle", bundleArgs("blast", "newest"));
    });

    it("Blast FINALIZED: the 7-day-old output on the light-client-proven L1 state", async () => {
        const [stateRoot] = (await pub.readContract({
            address: l1Verifier, abi: l1Art.abi as never, functionName: "verifyL1State",
            args: [live.lightClient.lightClientProof, live.chains.blast.trustAnchor]
        })) as [Hex];
        const f = live.chains.blast.finalized;
        const out = await read<{index: bigint; l1Timestamp: bigint}>(finalized.blast, "verifyOutput",
            [f.oracleProof, stateRoot, live.l1Time, f.outputRoot]);
        expect(out.index).toBe(f.index);
        expect(live.l1Time - out.l1Timestamp).toBeGreaterThan(604_800n);
    });

    it("Blast FINALIZED: full verifyBundle on an output staged by an earlier refresh", async (ctx) => {
        const g = live.chains.blast.pendingFinalized.find((x) => x.bundle);
        if (!g) ctx.skip();
        const c = live.chains.blast;
        await read(finalized.blast, "verifyBundle", [g!.bundle, c.trustAnchor, c.channelContext]);
        await measure("Blast FINALIZED verifyBundle", finalized.blast, "verifyBundle", [g!.bundle, c.trustAnchor, c.channelContext]);
    });

    it("Mantle PROPOSED accepts the newest (SP1-proven, inside the challenge window); FINALIZED rejects it", async () => {
        await read(proposed.mantle, "verifyBundle", bundleArgs("mantle", "newest"));
        await measure("Mantle PROPOSED verifyBundle", proposed.mantle, "verifyBundle", bundleArgs("mantle", "newest"));
        await expect(read(finalized.mantle, "verifyBundle", bundleArgs("mantle", "newest"))).rejects.toThrow(/OutputNotFinalized/);
        await expect(read(finalized.blast, "verifyBundle", bundleArgs("blast", "newest"))).rejects.toThrow(/OutputNotFinalized/);
    });

    it("rejects an index the oracle has not posted (or has deleted)", async () => {
        for (const name of CHAIN_NAMES) {
            const c = live.chains[name];
            const n = c.newest;
            const proof = encodeOracleL2StateRootProof({
                lightClientProof: live.lightClient.lightClientProof,
                oracle: c.unposted,
                outputRootPreimage: preimageOf(name)
            });
            await expect(read(proposed[name], "verifyL2StateRoot", [proof, c.trustAnchor])).rejects.toThrow(/OutputNotPosted/);
            expect(n.index + 1n).toBe(c.length);
        }
    });

    it("rejects the wrong L2 account format (Blast leaf under an Ethereum-format deployment)", async () => {
        const c = live.chains.blast;
        const other = await deployTier(propArt, c.profile, ORACLE_CHAINS.mantle.accountFormat);
        await expect(read(other, "verifyBundle", bundleArgs("blast", "newest"))).rejects.toThrow(/InvalidL2Account/);
    });

    it("rejects an unpinned oracle implementation", async () => {
        const c = live.chains.katana;
        const other = await deployTier(finArt, {...c.profile, oracleImplCodeHash: keccak256(toHex("AggchainFEP v4"))}, c.chain.accountFormat);
        await expect(read(other, "verifyBundle", bundleArgs("katana", "finalized"))).rejects.toThrow(/OracleImplMismatch/);
    });

    it("fails ONLY at the L2 code-hash binding when a different (e.g. ClprService) code hash is pinned", async () => {
        const anchor = hexToBuf(live.chains.mantle.trustAnchor!);
        hexToBuf(keccak256(toHex("some ClprService runtime"))).copy(anchor, 228);
        const [proof, , ctxBytes] = bundleArgs("mantle", "finalized");
        await expect(read(finalized.mantle, "verifyBundle", [proof, "0x" + anchor.toString("hex"), ctxBytes]))
            .rejects.toThrow(/CodeHashMismatch/);
    });

    it("rejects the real signature under the previous fork version (Electra) and under another chain's GVR", async () => {
        const [proof, a, ctxBytes] = bundleArgs("katana", "finalized");
        const fork = hexToBuf(a as Hex);
        hexToBuf(capture.beacon.spec.ELECTRA_FORK_VERSION).copy(fork, 32);
        await expect(read(finalized.katana, "verifyBundle", [proof, "0x" + fork.toString("hex"), ctxBytes]))
            .rejects.toThrow(/BlsSignatureInvalid|BlsPrecompileCallFailed/);
        const gvr = hexToBuf(a as Hex);
        gvr[0] ^= 1;
        await expect(read(finalized.katana, "verifyBundle", [proof, "0x" + gvr.toString("hex"), ctxBytes]))
            .rejects.toThrow(/BlsSignatureInvalid|BlsPrecompileCallFailed/);
    });

    /// The newest output's preimage, recomputed from the L2 header (Blast: message-passer root from the proof).
    function preimageOf(name: ChainName): Hex {
        const o = capture.chains[name].outputs.newest;
        const mp = ORACLE_CHAINS[name].withdrawalsRootIsMessagePasser ? o.l2.header.withdrawalsRoot : o.l2.proof!.storageHash;
        return ("0x" + "00".repeat(32) + o.l2.header.stateRoot.slice(2) + mp.slice(2) + o.l2.header.hash.slice(2)) as Hex;
    }
});
