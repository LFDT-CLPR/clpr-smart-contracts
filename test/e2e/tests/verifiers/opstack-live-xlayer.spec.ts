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
    buildOpStackLiveProof,
    L1_SECONDS_PER_SLOT,
    loadOpStackLiveCapture,
    XLAYER,
    type OpStackLiveCapture,
    type OpStackLiveGameCase,
    type OpStackLiveProof
} from "../../relay/buildOpStackLiveProof.js";
import {
    encodeOpStackL2StateRootProof,
    outputRootPreimage,
    profileTuple,
    XLAYER_MAINNET_PROFILE,
    type OpStackProfile
} from "../../relay/opstack.js";
import {hexToBuf} from "../../lib/rlp.js";

/// OpStackVerifier / OpStackProposedVerifier with the X LAYER profile, against REAL X Layer (chain 196)
/// data settled on Ethereum MAINNET, replayed offline from test/e2e/fixtures/xlayer-live/capture.json
/// (re-capture: `npm run opstack-live:refresh:xlayer`; stage L2 proofs: `npm run opstack-live:stage:xlayer`).
///
/// X Layer moved to the OP Stack; since 2026-06-30 its OptimismPortal's AnchorStateRegistry respects
/// OP Succinct Lite games (OPSuccinctFaultDisputeGame 2.0.0, game type 42). Those L1 contracts hold its
/// provable state: the AggLayer side (AggchainECDSAMultisig, rollup 3 in the RollupManager) keeps only
/// exit and pessimistic roots, never an L2 state or output root.
///
/// Every link is live data: the mainnet sync committee's signature over the attested header (with its
/// real non-signers), the execution state_root branch, eth_getProof at that L1 block of X Layer's ASR
/// (3.5.0) and its implementation (code hash pinned in XLAYER_MAINNET_PROFILE, which binds the 3.5-day
/// finality delay), the DGF 1.3.0 registration of each game, each game's slots 0 and 9 and its code, and
/// the output-root preimage from the X Layer header. The verifiers are deployed with the PINNED profile
/// constant, not with values read from the capture.
///
/// FINALIZED needs a game ≥ 3.5 days past resolution; X Layer's only public eth_getProof endpoint
/// serves "latest" only, so FINALIZED is checked up to the L2 state root (`verifyL2StateRoot`, the code
/// verifyBundle runs first) unless a game whose L2 proof was staged ≥ 3.6 days earlier has finalized.
/// The full bundle down to L2 storage runs through PROPOSED on a staged game.
///
/// Run: forge build && npm run test:e2e:opstack-live:xlayer

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_B ?? 8614);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HEDERA_GAS_LIMIT = 15_000_000n;
const HEDERA_TX_BYTES = 128 * 1024;

type Metadata = {state: number; nextMessageId: bigint; receivedMessageId: bigint; sentRunningHash: Hex;
    receivedRunningHash: Hex};

function byteLen(h: Hex): number {
    return (h.length - 2) / 2;
}

function calldataGas(data: Hex): number {
    return hexToBuf(data).reduce((acc, b) => acc + (b === 0 ? 4 : 16), 0);
}

describe("OP Stack verifiers, X Layer profile, on live Ethereum mainnet data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let capture: OpStackLiveCapture;
    let live: OpStackLiveProof;
    let l1Verifier: Hex;
    let finalized: Hex;
    let proposed: Hex;
    const l1Art = loadArtifact("EthL1StateVerifier");
    const finArt = loadArtifact("OpStackVerifier");
    const propArt = loadArtifact("OpStackProposedVerifier");
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

    const deployTier = (art: typeof finArt, profile: OpStackProfile) =>
        deploy(art, [l1Verifier, live.l1GenesisTime, L1_SECONDS_PER_SLOT, profileTuple(profile)]);

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

    /// A game case with a full bundle that the PROPOSED tier accepts (staged L2 proofs).
    const proposedBundleCase = (): OpStackLiveGameCase | undefined =>
        [live.newest, ...(live.resolved ? [live.resolved] : [])].find((g) => g.bundle);

    beforeAll(async () => {
        capture = loadOpStackLiveCapture(XLAYER.name);
        live = buildOpStackLiveProof(capture);

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
        finalized = await deployTier(finArt, XLAYER_MAINNET_PROFILE);
        proposed = await deployTier(propArt, XLAYER_MAINNET_PROFILE);
    });

    afterAll(() => {
        anvil?.kill("SIGTERM");
        if (gasReport.length) console.log(["[opstack-live xlayer] gas (Hedera: ≤ 15M gas, ≤ 128 KB tx)", ...gasReport].join("\n  "));
    });

    it("builder: the live chain matches the pinned X Layer profile, and every off-chain cross-check holds", () => {
        expect(capture.chain).toBe("xlayer");
        expect(capture.beacon.spec.CONFIG_NAME).toBe("mainnet");
        expect(capture.beacon.finalityUpdate.version).toBe("fulu");
        expect(live.respectedGameType).toBe(42);
        // Everything the profile pins, read back from the chain at the attested L1 block.
        expect(live.profile.l2ChainId).toBe(XLAYER_MAINNET_PROFILE.l2ChainId);
        expect(live.profile.anchorStateRegistry.toLowerCase()).toBe(XLAYER_MAINNET_PROFILE.anchorStateRegistry.toLowerCase());
        expect(live.profile.anchorStateRegistryImplCodeHash).toBe(XLAYER_MAINNET_PROFILE.anchorStateRegistryImplCodeHash);
        expect(live.profile.disputeGameFinalityDelaySeconds).toBe(302_400n);
        expect(live.profile.gameImplementation.toLowerCase()).toBe(XLAYER_MAINNET_PROFILE.gameImplementation.toLowerCase());
        expect(live.anchorGame.status).toBe(2); // DEFENDER_WINS
        expect(live.l1Time - live.anchorGame.resolvedAt).toBeGreaterThan(302_400n);
        expect(live.newest.status).toBe(0); // IN_PROGRESS
        expect(live.resolved).not.toBeNull();
        expect(live.resolved!.status).toBe(2);
        expect(live.l1Time - live.resolved!.resolvedAt).toBeLessThanOrEqual(302_400n); // inside the delay
        expect(3 * live.lightClient.signed.participants).toBeGreaterThanOrEqual(2 * 512);
    });

    it("L1: the mainnet sync committee authenticates the attested execution state root", async () => {
        const [stateRoot, slot] = (await pub.readContract({
            address: l1Verifier, abi: l1Art.abi as never, functionName: "verifyL1State",
            args: [live.lightClient.lightClientProof, live.trustAnchor]
        })) as [Hex, bigint, Hex, Hex];
        expect(stateRoot).toBe(capture.l1.block.stateRoot);
        expect(slot).toBe(BigInt(capture.beacon.finalityUpdate.data.attested_header.beacon.slot));
    });

    it("FINALIZED, anchor mode: the ASR anchor root → the X Layer state root", async () => {
        const [l2StateRoot] = await read<[Hex, Hex, Hex]>(finalized, "verifyL2StateRoot",
            [live.anchorMode.l2StateRootProof, live.trustAnchor]);
        expect(l2StateRoot).toBe(live.anchorMode.l2StateRoot);
        await measure("FINALIZED verifyL2StateRoot, ANCHOR mode", finalized, "verifyL2StateRoot",
            [live.anchorMode.l2StateRootProof, live.trustAnchor]);
    });

    it("FINALIZED, game mode: the anchor game (DEFENDER_WINS, > 3.5 days resolved) → the X Layer state root", async () => {
        const [l2StateRoot] = await read<[Hex, Hex, Hex]>(finalized, "verifyL2StateRoot",
            [live.anchorGame.l2StateRootProof, live.trustAnchor]);
        expect(l2StateRoot).toBe(live.anchorGame.l2StateRoot);
        await measure("FINALIZED verifyL2StateRoot, GAME mode", finalized, "verifyL2StateRoot",
            [live.anchorGame.l2StateRootProof, live.trustAnchor]);
    });

    it("FINALIZED, full verifyBundle on a staged game that has since finalized", async (ctx) => {
        const g = live.pendingFinalized.find((x) => x.bundle) ?? (live.anchorGame.bundle ? live.anchorGame : undefined);
        if (!g) ctx.skip();
        const [metadata] = await read<[Metadata]>(finalized, "verifyBundle", [g!.bundle, live.trustAnchor, live.channelContext]);
        expect(metadata.nextMessageId).toBe(0n);
        await measure("FINALIZED verifyBundle", finalized, "verifyBundle", [g!.bundle, live.trustAnchor, live.channelContext]);
    });

    it("FINALIZED rejects a resolved game still inside the 3.5-day delay; PROPOSED accepts it", async () => {
        await expect(read(finalized, "verifyL2StateRoot", [live.resolved!.l2StateRootProof, live.trustAnchor]))
            .rejects.toThrow(/GameNotFinalized/);
        const [l2StateRoot] = await read<[Hex]>(proposed, "verifyL2StateRoot", [live.resolved!.l2StateRootProof, live.trustAnchor]);
        expect(l2StateRoot).toBe(live.resolved!.l2StateRoot);
    });

    it("FINALIZED rejects the newest (IN_PROGRESS) game; PROPOSED accepts it", async () => {
        await expect(read(finalized, "verifyL2StateRoot", [live.newest.l2StateRootProof, live.trustAnchor]))
            .rejects.toThrow(/GameNotResolved/);
        const [l2StateRoot] = await read<[Hex]>(proposed, "verifyL2StateRoot", [live.newest.l2StateRootProof, live.trustAnchor]);
        expect(l2StateRoot).toBe(live.newest.l2StateRoot);
        await measure("PROPOSED verifyL2StateRoot, newest game", proposed, "verifyL2StateRoot",
            [live.newest.l2StateRootProof, live.trustAnchor]);
    });

    it("PROPOSED: full verifyBundle down to X Layer storage on a game whose L2 proof was staged", async (ctx) => {
        const g = proposedBundleCase();
        if (!g) ctx.skip();
        const [metadata, payloads] = await read<[Metadata, Hex[], Hex, Hex]>(proposed, "verifyBundle",
            [g!.bundle, live.trustAnchor, live.channelContext]);
        // The channel slots are absent in the L2ToL1MessagePasser → exclusion proofs → zeroed metadata.
        expect(metadata.nextMessageId).toBe(0n);
        expect(metadata.receivedMessageId).toBe(0n);
        expect(metadata.sentRunningHash).toBe(toHex(0n, {size: 32}));
        expect(payloads).toEqual([]);
        await measure("PROPOSED verifyBundle (full, L2 account + 5 storage proofs)", proposed, "verifyBundle",
            [g!.bundle, live.trustAnchor, live.channelContext]);
        await expect(read(finalized, "verifyBundle", [g!.bundle, live.trustAnchor, live.channelContext]))
            .rejects.toThrow(/GameNotResolved|GameNotFinalized/);
        // A different pinned L2 code hash fails only at the account binding.
        const anchor = hexToBuf(live.trustAnchor);
        hexToBuf(keccak256(toHex("some ClprService runtime"))).copy(anchor, 228);
        await expect(read(proposed, "verifyBundle", [g!.bundle, "0x" + anchor.toString("hex"), live.channelContext]))
            .rejects.toThrow(/CodeHashMismatch/);
    });

    it("rejects the other game type hosted by the same DisputeGameFactory (1961)", async () => {
        const proof = encodeOpStackL2StateRootProof({
            lightClientProof: live.lightClient.lightClientProof,
            dispute: {...live.anchorGame.dispute, gameType: 1961},
            outputRootPreimage: preimageOf(capture.games.anchor.l2.header)
        });
        await expect(read(proposed, "verifyL2StateRoot", [proof, live.trustAnchor])).rejects.toThrow(/GameTypeNotRespected/);
    });

    it("rejects a wrong output-root preimage", async () => {
        const g = capture.games.anchor.l2.header;
        const wrong = outputRootPreimage(g.stateRoot, keccak256(g.withdrawalsRoot), g.hash).preimage;
        const proof = encodeOpStackL2StateRootProof({
            lightClientProof: live.lightClient.lightClientProof, dispute: live.anchorGame.dispute, outputRootPreimage: wrong
        });
        await expect(read(finalized, "verifyL2StateRoot", [proof, live.trustAnchor])).rejects.toThrow(/SlotNotProven/);
    });

    it("rejects one game's dispute proof with another game's preimage", async () => {
        const proof = encodeOpStackL2StateRootProof({
            lightClientProof: live.lightClient.lightClientProof, dispute: live.anchorGame.dispute,
            outputRootPreimage: preimageOf(capture.games.resolved!.l2.header)
        });
        await expect(read(proposed, "verifyL2StateRoot", [proof, live.trustAnchor])).rejects.toThrow(/SlotNotProven|GameNotRegistered/);
    });

    it("rejects forged game code (not the account's code hash)", async () => {
        const code = hexToBuf(live.anchorGame.dispute.gameCode);
        code[code.length - 3] ^= 1;
        const proof = encodeOpStackL2StateRootProof({
            lightClientProof: live.lightClient.lightClientProof,
            dispute: {...live.anchorGame.dispute, gameCode: ("0x" + code.toString("hex")) as Hex},
            outputRootPreimage: preimageOf(capture.games.anchor.l2.header)
        });
        await expect(read(finalized, "verifyL2StateRoot", [proof, live.trustAnchor])).rejects.toThrow(/GameCodeMismatch/);
    });

    it("fails closed when the ASR implementation is not the pinned one (e.g. after an upgrade)", async () => {
        const other = await deployTier(finArt, {...XLAYER_MAINNET_PROFILE, anchorStateRegistryImplCodeHash: keccak256(toHex("x"))});
        await expect(read(other, "verifyL2StateRoot", [live.anchorGame.l2StateRootProof, live.trustAnchor]))
            .rejects.toThrow(/AnchorStateRegistryImplMismatch/);
    });

    it("fails closed when games are not clones of the pinned implementation (e.g. a new gameImpls[42])", async () => {
        const other = await deployTier(finArt, {...XLAYER_MAINNET_PROFILE, gameImplementation: "0x000000000000000000000000000000000000dEaD"});
        await expect(read(other, "verifyL2StateRoot", [live.anchorGame.l2StateRootProof, live.trustAnchor]))
            .rejects.toThrow(/GameImplementationMismatch/);
    });

    it("rejects the real signature under the previous fork version (Electra)", async () => {
        const anchor = hexToBuf(live.trustAnchor);
        hexToBuf(capture.beacon.spec.ELECTRA_FORK_VERSION).copy(anchor, 32);
        await expect(read(finalized, "verifyL2StateRoot",
            [live.anchorGame.l2StateRootProof, "0x" + anchor.toString("hex")])).rejects.toThrow(/BlsSignatureInvalid|BlsPrecompileCallFailed/);
    });

    function preimageOf(h: {stateRoot: Hex; withdrawalsRoot: Hex; hash: Hex}): Hex {
        return outputRootPreimage(h.stateRoot, h.withdrawalsRoot, h.hash).preimage;
    }
});
