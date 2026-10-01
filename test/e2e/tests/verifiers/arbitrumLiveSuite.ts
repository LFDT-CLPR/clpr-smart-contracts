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
    buildArbitrumLiveProof,
    loadArbitrumLiveCaptureFor,
    type ArbitrumLiveCapture,
    type ArbitrumLiveNetwork,
    type ArbitrumLiveProof
} from "../../relay/buildArbitrumLiveProof.js";
import {encodeArbitrumL2StateProof, profileTuple, type ArbitrumProfile} from "../../relay/arbitrum.js";
import {hexToBuf} from "../../lib/rlp.js";

/// ArbitrumNitroVerifier against REAL data of one Nitro chain profile (Arbitrum Sepolia on Sepolia, Plume
/// on Ethereum mainnet), replayed offline from that network's capture.json (re-capture:
/// `npm run arbitrum-live:refresh`, `npm run plume-live:refresh`). Shared by arbitrum-live-sepolia.spec.ts
/// and plume-live.spec.ts.
///
/// Every link is live data: the parent chain's sync committee's signature over the attested header (with its
/// real non-signers), the execution state_root branch, eth_getProof at that L1 block of Arbitrum
/// Sepolia's RollupProxy (both logic slots, `_assertions[h]` of the latest confirmed assertion), the
/// `AssertionCreated` preimage, the L2 header of the assertion's block, and eth_getProof on Arbitrum
/// Sepolia at that L2 block.
///
/// There is no ClprService on these chains, so the L2 account is a WETH9-style token (WETH, WPLUME) with
/// ITS real code hash pinned; the channel slots are absent there (genuine MPT exclusion proofs → zeroed
/// metadata).
///
/// Run: forge build && npm run test:e2e:arbitrum-live (or test:e2e:plume-live)

const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HEDERA_GAS_LIMIT = 15_000_000n;
const HEDERA_TX_BYTES = 128 * 1024;

type Metadata = {state: number; nextMessageId: bigint; receivedMessageId: bigint; sentRunningHash: Hex;
    receivedRunningHash: Hex};
type Confirmed = {assertionHash: Hex; l2BlockHash: Hex; l2StateRoot: Hex; l2BlockNumber: bigint; sendRoot: Hex};

function byteLen(h: Hex): number {
    return (h.length - 2) / 2;
}

function calldataGas(data: Hex): number {
    return hexToBuf(data).reduce((acc, b) => acc + (b === 0 ? 4 : 16), 0);
}

export function arbitrumLiveSuite(net: ArbitrumLiveNetwork, anvilPort: number): void {
describe(`ArbitrumNitroVerifier on live ${net.name} data (fixture replay)`, () => {
    const ANVIL_PORT = anvilPort;
    const L2_ACCOUNT = net.l2Account;
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let capture: ArbitrumLiveCapture;
    let live: ArbitrumLiveProof;
    let l1Verifier: Hex;
    let verifier: Hex;
    const l1Art = loadArtifact("EthL1StateVerifier");
    const art = loadArtifact("ArbitrumNitroVerifier");
    // Errors raised inside the L1 light client bubble up through the verifier: decode them too.
    const abi = [...art.abi, ...(l1Art.abi as {type: string}[]).filter((e) => e.type === "error")] as readonly unknown[];
    const gasReport: string[] = [];

    async function deploy(a: {abi: readonly unknown[]; bytecode: Hex}, args: unknown[]): Promise<Hex> {
        const hash = await wallet.deployContract({
            abi: a.abi as never, bytecode: a.bytecode, args: args as never, account: wallet.account!, chain: null
        });
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error("deploy failed");
        return r.contractAddress;
    }

    const deployVerifier = (profile: ArbitrumProfile) => deploy(art, [l1Verifier, profileTuple(profile)]);

    function read<T>(address: Hex, functionName: string, args: unknown[]): Promise<T> {
        return pub.readContract({address, abi: abi as never, functionName, args}) as Promise<T>;
    }

    async function measure(label: string, functionName: string, args: unknown[]): Promise<bigint> {
        const gas = await pub.estimateContractGas({address: verifier, abi: abi as never, functionName, args,
            account: wallet.account!});
        const data = encodeFunctionData({abi, functionName, args} as never);
        const cd = calldataGas(data);
        gasReport.push(`${label}: eth_estimateGas ${gas} (= 21000 + ${cd} calldata + ~${gas - 21000n - BigInt(cd)} execution), ` +
            `calldata ${byteLen(data)} B`);
        expect(gas).toBeLessThan(HEDERA_GAS_LIMIT);
        expect(byteLen(data)).toBeLessThan(HEDERA_TX_BYTES);
        return gas;
    }

    beforeAll(async () => {
        capture = loadArbitrumLiveCaptureFor(net);
        live = buildArbitrumLiveProof(capture, net);

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
        verifier = await deployVerifier(live.profile);
    });

    afterAll(() => {
        anvil?.kill("SIGTERM");
        if (gasReport.length) console.log([`[${net.name}] gas (Hedera: ≤ 15M gas, ≤ 128 KB tx)`, ...gasReport].join("\n  "));
    });

    it("builder: every off-chain cross-check holds on the live capture", () => {
        expect(capture.beacon.finalityUpdate.version).toBe("fulu");
        expect(live.profile.rollup).toBe(net.rollup);
        expect(live.confirmed.status).toBe(2); // Confirmed
        expect(live.confirmed.bundle).toBeDefined();
        expect(3 * live.lightClient.signed.participants).toBeGreaterThanOrEqual(2 * 512);
    });

    it("L1: the sync committee authenticates the attested execution state root", async () => {
        const [stateRoot, slot, na, naId] = (await pub.readContract({
            address: l1Verifier, abi: l1Art.abi as never, functionName: "verifyL1State",
            args: [live.lightClient.lightClientProof, live.trustAnchor]
        })) as [Hex, bigint, Hex, Hex];
        expect(stateRoot).toBe(live.l1StateRoot);
        expect(slot).toBe(live.attestedSlot);
        expect(na).toBe("0x");
        expect(naId).toBe("0x");
    });

    it("verifyL2State: L1 → confirmed assertion → L2 header → L2 state root", async () => {
        const [s, na] = await read<[Confirmed, Hex, Hex]>(verifier, "verifyL2State", [live.confirmed.l2StateProof, live.trustAnchor]);
        expect(s.assertionHash).toBe(live.confirmed.assertionHash);
        expect(s.l2BlockHash).toBe(live.confirmed.l2BlockHash);
        expect(s.l2StateRoot).toBe(live.confirmed.l2StateRoot);
        expect(s.l2BlockNumber).toBe(live.confirmed.l2BlockNumber);
        expect(s.sendRoot).toBe(live.confirmed.sendRoot);
        expect(na).toBe("0x");
        await measure("verifyL2State (to the confirmed L2 state root)", "verifyL2State", [live.confirmed.l2StateProof, live.trustAnchor]);
    });

    it("verifyBundle: full chain down to the ClprService storage slots", async () => {
        const b = live.confirmed.bundle!.proofBytes;
        const [metadata, payloads, na, naId] = await read<[Metadata, Hex[], Hex, Hex]>(verifier, "verifyBundle",
            [b, live.trustAnchor, live.channelContext]);
        // The channel slots are absent in the stand-in → exclusion proofs → zeroed metadata.
        expect(metadata.nextMessageId).toBe(0n);
        expect(metadata.receivedMessageId).toBe(0n);
        expect(metadata.sentRunningHash).toBe(toHex(0n, {size: 32}));
        expect(payloads).toEqual([]);
        expect(na).toBe("0x");
        expect(naId).toBe("0x");
        await measure("verifyBundle (typical bundle, no rotation)", "verifyBundle", [b, live.trustAnchor, live.channelContext]);
    });

    it("rotation: a real sync-committee rotation through the confirmed L2 state root", async (ctx) => {
        if (!live.rotation) ctx.skip();
        const r = live.rotation!;
        const [s, na, naId] = await read<[Confirmed, Hex, Hex]>(verifier, "verifyL2State",
            [r.confirmed.l2StateProof, live.trustAnchor]);
        expect(s.l2StateRoot).toBe(r.confirmed.l2StateRoot);
        expect(byteLen(na)).toBe(260);
        expect(BigInt(naId)).toBe(r.nextPeriod);
        await measure("verifyL2State + committee rotation", "verifyL2State", [r.confirmed.l2StateProof, live.trustAnchor]);
        // A rotating full bundle = this + the L2 account/storage part of the typical bundle.
        if (r.confirmed.bundle) {
            await measure("verifyBundle + committee rotation", "verifyBundle",
                [r.confirmed.bundle.proofBytes, live.trustAnchor, live.channelContext]);
        } else {
            gasReport.push(`(rotating bundle: the L2 state at L2 #${r.confirmed.l2BlockNumber} was outside the public RPC ` +
                `window; a full rotating bundle ≈ the line above + the typical bundle's L2 account/storage part)`);
        }
    });

    it("rejects a Pending (not yet confirmed) assertion", async (ctx) => {
        if (!live.pending) ctx.skip();
        await expect(read(verifier, "verifyL2State", [live.pending!.l2StateProof, live.trustAnchor]))
            .rejects.toThrow(/AssertionNotConfirmed/);
    });

    it("rejects an assertion that was never created (MPT exclusion of _assertions[h])", async () => {
        const proof = encodeArbitrumL2StateProof({lightClientProof: live.lightClient.lightClientProof,
            assertionProof: live.forged.assertionProof, assertionPreimage: live.forged.preimage, l2Header: live.confirmed.l2Header});
        await expect(read(verifier, "verifyL2State", [proof, live.trustAnchor])).rejects.toThrow(/AssertionNotConfirmed/);
    });

    it("rejects a header that is not the assertion's L2 block", async () => {
        const h = hexToBuf(live.confirmed.l2Header);
        h[h.length - 1] ^= 1;
        const proof = encodeArbitrumL2StateProof({...live.confirmed.bundle!.parts, l2Header: ("0x" + h.toString("hex")) as Hex});
        await expect(read(verifier, "verifyL2State", [proof, live.trustAnchor])).rejects.toThrow(/L2HeaderHashMismatch/);
    });

    it("rejects when the rollup logic is not the pinned one", async () => {
        const other = await deployVerifier({...live.profile, rollupUserLogic: "0x000000000000000000000000000000000000dEaD"});
        await expect(read(other, "verifyL2State", [live.confirmed.l2StateProof, live.trustAnchor])).rejects.toThrow(/RollupLogicMismatch/);
    });

    it("fails ONLY at the L2 code-hash binding when a different (e.g. ClprService) code hash is pinned", async () => {
        const anchor = hexToBuf(live.trustAnchor);
        hexToBuf(keccak256(toHex("some ClprService runtime"))).copy(anchor, 228);
        await expect(read(verifier, "verifyBundle",
            [live.confirmed.bundle!.proofBytes, "0x" + anchor.toString("hex"), live.channelContext])).rejects.toThrow(/CodeHashMismatch/);
    });

    it("rejects the real signature under the previous fork version (Electra)", async () => {
        const anchor = hexToBuf(live.trustAnchor);
        hexToBuf(capture.beacon.spec.ELECTRA_FORK_VERSION).copy(anchor, 32);
        await expect(read(verifier, "verifyL2State", [live.confirmed.l2StateProof, "0x" + anchor.toString("hex")]))
            .rejects.toThrow(/BlsSignatureInvalid|BlsPrecompileCallFailed/);
    });

    it("the stand-in L2 account is the one the channel context names", () => {
        expect(live.channelContext.endsWith(L2_ACCOUNT.slice(2).toLowerCase())).toBe(true);
    });
});
}
