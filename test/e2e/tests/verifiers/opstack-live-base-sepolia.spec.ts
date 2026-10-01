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
    BASE_SEPOLIA,
    buildOpStackLiveProof,
    L1_SECONDS_PER_SLOT,
    loadOpStackLiveCapture,
    type OpStackLiveCapture,
    type OpStackLiveProof
} from "../../relay/buildOpStackLiveProof.js";
import {encodeOpStackL2StateRootProof, outputRootPreimage, profileTuple, type OpStackProfile} from "../../relay/opstack.js";
import {hexToBuf} from "../../lib/rlp.js";

/// OpStackVerifier / OpStackProposedVerifier against REAL Base Sepolia data settled on Ethereum
/// Sepolia, replayed offline from test/e2e/fixtures/base-sepolia-live/capture.json
/// (re-capture: `npm run opstack-live:refresh`).
///
/// Every link is live data: the Sepolia sync committee's signature over the attested header (with its
/// real non-signers), the execution state_root branch, eth_getProof at that L1 block of Base Sepolia's
/// AnchorStateRegistry (v3.7.0 + its implementation, whose code hash the verifier pins), the
/// DisputeGameFactory registration of each game and the game's own storage and code (Base's
/// AggregateVerifier, game type 621), the output-root preimage from the L2 header, and eth_getProof on
/// Base Sepolia at the L2 block the game claims.
///
/// There is no ClprService on Base Sepolia, so the L2 account is the L2ToL1MessagePasser predeploy with
/// ITS real code hash pinned; the channel slots are absent there (genuine MPT exclusion proofs →
/// zeroed metadata). The finalized anchor game's L2 block is ~5 days old — outside every public RPC's
/// eth_getProof window — so the FINALIZED path is checked on-chain up to the L2 state root
/// (`verifyL2StateRoot`, the same code verifyBundle runs); the full FINALIZED bundle runs when a refresh
/// finds a game staged by an earlier refresh that has since finalized.
///
/// Run: forge build && npm run test:e2e:opstack-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8613);
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

describe("OP Stack verifiers on live Base Sepolia data (fixture replay)", () => {
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
    // Errors raised inside the L1 light client bubble up through the verifier: decode them too.
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

    beforeAll(async () => {
        capture = loadOpStackLiveCapture();
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
        finalized = await deployTier(finArt, live.profile);
        proposed = await deployTier(propArt, live.profile);
    });

    afterAll(() => {
        anvil?.kill("SIGTERM");
        if (gasReport.length) console.log(["[opstack-live] gas (Hedera: ≤ 15M gas, ≤ 128 KB tx)", ...gasReport].join("\n  "));
    });

    it("builder: every off-chain cross-check holds on the live capture", () => {
        expect(capture.beacon.finalityUpdate.version).toBe("fulu");
        expect(live.respectedGameType).toBe(621);
        expect(live.profile.anchorStateRegistry.toLowerCase()).toBe(BASE_SEPOLIA.anchorStateRegistry.toLowerCase());
        // Base Sepolia's ASR is deployed with DISPUTE_GAME_FINALITY_DELAY_SECONDS = 0; the pinned
        // implementation code hash binds that immutable.
        expect(live.profile.disputeGameFinalityDelaySeconds).toBe(0n);
        expect(live.anchorGame.status).toBe(2); // DEFENDER_WINS
        expect(live.anchorGame.resolvedAt).toBeGreaterThan(0n);
        expect(live.newest.status).toBe(0); // IN_PROGRESS
        expect(live.newest.bundle).not.toBeNull();
        expect(3 * live.lightClient.signed.participants).toBeGreaterThanOrEqual(2 * 512);
    });

    it("L1: the sync committee authenticates the attested execution state root", async () => {
        const [stateRoot, slot, na, naId] = (await pub.readContract({
            address: l1Verifier, abi: l1Art.abi as never, functionName: "verifyL1State",
            args: [live.lightClient.lightClientProof, live.trustAnchor]
        })) as [Hex, bigint, Hex, Hex];
        expect(stateRoot).toBe(capture.l1.block.stateRoot);
        expect(slot).toBe(BigInt(capture.beacon.finalityUpdate.data.attested_header.beacon.slot));
        expect(na).toBe("0x");
        expect(naId).toBe("0x");
    });

    it("FINALIZED, anchor mode: the ASR anchor root → the L2 state root", async () => {
        const [l2StateRoot] = await read<[Hex, Hex, Hex]>(finalized, "verifyL2StateRoot",
            [live.anchorMode.l2StateRootProof, live.trustAnchor]);
        expect(l2StateRoot).toBe(live.anchorMode.l2StateRoot);
        await measure("FINALIZED verifyL2StateRoot, ANCHOR mode", finalized, "verifyL2StateRoot",
            [live.anchorMode.l2StateRootProof, live.trustAnchor]);
    });

    it("FINALIZED, game mode: resolved DEFENDER_WINS game past the finality delay → the L2 state root", async () => {
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

    it("PROPOSED: full verifyBundle on the newest (unresolved) game, through the L2 storage proofs", async () => {
        const [metadata, payloads, na, naId] = await read<[Metadata, Hex[], Hex, Hex]>(proposed, "verifyBundle",
            [live.newest.bundle, live.trustAnchor, live.channelContext]);
        // The channel slots are absent in the L2ToL1MessagePasser → exclusion proofs → zeroed metadata.
        expect(metadata.nextMessageId).toBe(0n);
        expect(metadata.receivedMessageId).toBe(0n);
        expect(metadata.sentRunningHash).toBe(toHex(0n, {size: 32}));
        expect(payloads).toEqual([]);
        expect(na).toBe("0x");
        expect(naId).toBe("0x");
        await measure("PROPOSED verifyBundle (full, L2 account + 5 storage proofs)", proposed, "verifyBundle",
            [live.newest.bundle, live.trustAnchor, live.channelContext]);
    });

    it("the fast tier accepts what the finalized tier rejects: the unresolved game", async () => {
        await expect(read(finalized, "verifyBundle", [live.newest.bundle, live.trustAnchor, live.channelContext]))
            .rejects.toThrow(/GameNotResolved/);
        await read(proposed, "verifyBundle", [live.newest.bundle, live.trustAnchor, live.channelContext]);
        // Both tiers accept the finalized anchor.
        await read(proposed, "verifyL2StateRoot", [live.anchorMode.l2StateRootProof, live.trustAnchor]);
    });

    it("fails ONLY at the L2 code-hash binding when a different (e.g. ClprService) code hash is pinned", async () => {
        const anchor = hexToBuf(live.trustAnchor);
        hexToBuf(keccak256(toHex("some ClprService runtime"))).copy(anchor, 228);
        await expect(read(proposed, "verifyBundle", [live.newest.bundle, "0x" + anchor.toString("hex"), live.channelContext]))
            .rejects.toThrow(/CodeHashMismatch/);
    });

    it("rejects a wrong game type", async () => {
        const proof = encodeOpStackL2StateRootProof({
            lightClientProof: live.lightClient.lightClientProof,
            dispute: {...live.anchorGame.dispute, gameType: 0}, // the permissionless Cannon type
            outputRootPreimage: preimageOf(live.anchorGame.l2StateRoot)
        });
        await expect(read(finalized, "verifyL2StateRoot", [proof, live.trustAnchor])).rejects.toThrow(/GameTypeNotRespected/);
    });

    it("rejects a wrong output-root preimage", async () => {
        const g = capture.games.anchor.l2.header;
        const wrong = outputRootPreimage(g.stateRoot, keccak256(g.withdrawalsRoot), g.hash).preimage;
        const proof = encodeOpStackL2StateRootProof({
            lightClientProof: live.lightClient.lightClientProof, dispute: live.anchorGame.dispute, outputRootPreimage: wrong
        });
        // Its root has no registration: the DGF entry the verifier derives is not in the proof.
        await expect(read(finalized, "verifyL2StateRoot", [proof, live.trustAnchor])).rejects.toThrow(/SlotNotProven/);
    });

    it("rejects forged game code (not the account's code hash)", async () => {
        const code = hexToBuf(live.anchorGame.dispute.gameCode);
        code[code.length - 3] ^= 1;
        const proof = encodeOpStackL2StateRootProof({
            lightClientProof: live.lightClient.lightClientProof,
            dispute: {...live.anchorGame.dispute, gameCode: ("0x" + code.toString("hex")) as Hex},
            outputRootPreimage: preimageOf(live.anchorGame.l2StateRoot)
        });
        await expect(read(finalized, "verifyL2StateRoot", [proof, live.trustAnchor])).rejects.toThrow(/GameCodeMismatch/);
    });

    it("rejects when the AnchorStateRegistry implementation is not the pinned one", async () => {
        const other = await deployTier(finArt, {...live.profile, anchorStateRegistryImplCodeHash: keccak256(toHex("x"))});
        await expect(read(other, "verifyL2StateRoot", [live.anchorGame.l2StateRootProof, live.trustAnchor]))
            .rejects.toThrow(/AnchorStateRegistryImplMismatch/);
    });

    it("rejects when the game is not a clone of the pinned implementation", async () => {
        const other = await deployTier(finArt, {...live.profile, gameImplementation: "0x000000000000000000000000000000000000dEaD"});
        await expect(read(other, "verifyL2StateRoot", [live.anchorGame.l2StateRootProof, live.trustAnchor]))
            .rejects.toThrow(/GameImplementationMismatch/);
    });

    it("rejects the real signature under the previous fork version (Electra)", async () => {
        const anchor = hexToBuf(live.trustAnchor);
        hexToBuf(capture.beacon.spec.ELECTRA_FORK_VERSION).copy(anchor, 32);
        await expect(read(finalized, "verifyL2StateRoot",
            [live.anchorGame.l2StateRootProof, "0x" + anchor.toString("hex")])).rejects.toThrow(/BlsSignatureInvalid|BlsPrecompileCallFailed/);
    });

    /// Recompute the anchor game's preimage from the capture (for re-encoded proofs).
    function preimageOf(stateRoot: Hex): Hex {
        const h = capture.games.anchor.l2.header;
        expect(h.stateRoot).toBe(stateRoot);
        return outputRootPreimage(h.stateRoot, h.withdrawalsRoot, h.hash).preimage;
    }
});
