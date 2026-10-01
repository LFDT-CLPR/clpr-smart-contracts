import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {createPublicClient, createWalletClient, encodeFunctionData, http, type Hex, type PublicClient, type WalletClient} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {loadArtifact} from "../../../../script/deploy/artifacts.js";
import {
    buildOpStackLiveProof,
    L1_SECONDS_PER_SLOT,
    loadOpStackLiveCapture,
    type OpStackLiveProof
} from "../../relay/buildOpStackLiveProof.js";
import {profileTuple} from "../../relay/opstack.js";
import {
    buildOpOracleLiveProof,
    FIXTURE_SETS,
    loadOpOracleLiveCapture,
    ORACLE_CHAINS,
    type OpOracleLiveProof
} from "../../relay/buildOpOracleLiveProof.js";
import {hexToBuf} from "../../lib/rlp.js";
import path from "node:path";

/// Anvil replay of the ranks 51-100 OP Stack captures, with the REAL mainnet sync-committee signature:
///   - dispute-game profiles (OpStackVerifier / OpStackProposedVerifier): RISE, Ronin, BOB, Unichain, MegaETH,
///     from test/e2e/fixtures/<chain>-live/capture.json;
///   - output-oracle profile (OpOutputOracleVerifier / …Proposed): Fraxtal, from test/e2e/fixtures/fraxtal-live/.
/// The verifiers are deployed with the profile the builder reads back from the chain at the captured L1
/// block; OpStackMainnetLive.t.sol and OpOutputOracleFraxtalLive.t.sol check that the PINNED Solidity
/// profiles equal it. Each case is measured with eth_estimateGas against Hedera's limits.
///
/// Re-capture: `npx tsx test/e2e/relay/buildOpStackLiveProof.ts --chain <chain> --refresh`,
/// `npm run opadapters-live:refresh:fraxtal`. Run: forge build && npm run test:e2e:opstack-live:sweep51

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8641);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HEDERA_GAS_LIMIT = 15_000_000n;
const HEDERA_TX_BYTES = 128 * 1024;
const DISPUTE_CHAINS = ["rise", "ronin", "bob", "unichain", "megaeth"] as const;

const byteLen = (h: Hex) => (h.length - 2) / 2;
const calldataGas = (data: Hex) => hexToBuf(data).reduce((acc, b) => acc + (b === 0 ? 4 : 16), 0);

describe("OP Stack ranks 51-100 on live mainnet data (anvil fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let l1Verifier: Hex;
    const l1Art = loadArtifact("EthL1StateVerifier");
    const finArt = loadArtifact("OpStackVerifier");
    const propArt = loadArtifact("OpStackProposedVerifier");
    const oFinArt = loadArtifact("OpOutputOracleVerifier");
    const oPropArt = loadArtifact("OpOutputOracleProposedVerifier");
    const l1Errors = (l1Art.abi as {type: string}[]).filter((e) => e.type === "error");
    const abi = [...finArt.abi, ...l1Errors] as readonly unknown[];
    const oAbi = [...oFinArt.abi, ...l1Errors] as readonly unknown[];
    const gasReport: string[] = [];
    const live = {} as Record<(typeof DISPUTE_CHAINS)[number], {p: OpStackLiveProof; fin: Hex; prop: Hex}>;
    let frax: {p: OpOracleLiveProof; fin: Hex; prop: Hex};

    async function deploy(art: {abi: readonly unknown[]; bytecode: Hex}, args: unknown[]): Promise<Hex> {
        const hash = await wallet.deployContract({
            abi: art.abi as never, bytecode: art.bytecode, args: args as never, account: wallet.account!, chain: null
        });
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error("deploy failed");
        return r.contractAddress;
    }

    const read = <T>(a: readonly unknown[], address: Hex, functionName: string, args: unknown[]) =>
        pub.readContract({address, abi: a as never, functionName, args}) as Promise<T>;

    async function measure(label: string, a: readonly unknown[], address: Hex, functionName: string, args: unknown[]) {
        const gas = await pub.estimateContractGas({address, abi: a as never, functionName, args, account: wallet.account!});
        const data = encodeFunctionData({abi: a, functionName, args} as never);
        const cd = calldataGas(data);
        gasReport.push(`${label}: eth_estimateGas ${gas} (= 21000 + ${cd} calldata + ~${gas - 21000n - BigInt(cd)} execution), ` +
            `calldata ${byteLen(data)} B`);
        expect(gas).toBeLessThan(HEDERA_GAS_LIMIT);
        expect(byteLen(data)).toBeLessThan(HEDERA_TX_BYTES);
    }

    beforeAll(async () => {
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
        for (const name of DISPUTE_CHAINS) {
            const p = buildOpStackLiveProof(loadOpStackLiveCapture(name));
            const args = [l1Verifier, p.l1GenesisTime, L1_SECONDS_PER_SLOT, profileTuple(p.profile)];
            live[name] = {p, fin: await deploy(finArt, args), prop: await deploy(propArt, args)};
        }
        const fp = buildOpOracleLiveProof(loadOpOracleLiveCapture(path.join(FIXTURE_SETS.fraxtal.dir, "capture.json")));
        const fc = fp.chains.fraxtal;
        const oargs = [l1Verifier, fp.l1GenesisTime, L1_SECONDS_PER_SLOT, fc.profile, ORACLE_CHAINS.fraxtal.accountFormat];
        frax = {p: fp, fin: await deploy(oFinArt, oargs), prop: await deploy(oPropArt, oargs)};
    }, 120_000);

    afterAll(() => {
        anvil?.kill("SIGTERM");
        if (gasReport.length) console.log(["[opstack-live sweep51] gas (Hedera: ≤ 15M gas, ≤ 128 KB tx)", ...gasReport].join("\n  "));
    });

    for (const name of DISPUTE_CHAINS) {
        it(`${name}: FINALIZED anchor root or final game → L2 state root; ANCHOR rejected without one`, async () => {
            const {p, fin, prop} = live[name];
            const args = [p.anchorMode.l2StateRootProof, p.trustAnchor];
            if (!p.anchorRootExists) {
                await expect(read(abi, fin, "verifyL2StateRoot", args)).rejects.toThrow(/OutputRootNotAnchor/);
                await expect(read(abi, prop, "verifyL2StateRoot", args)).rejects.toThrow(/OutputRootNotAnchor/);
            } else {
                const [root] = await read<[Hex]>(abi, fin, "verifyL2StateRoot", args);
                expect(root).toBe(p.anchorMode.l2StateRoot);
                await measure(`${name} FINALIZED verifyL2StateRoot, ANCHOR mode`, abi, fin, "verifyL2StateRoot", args);
            }
            const g = p.finalized ?? p.anchorGame;
            if (g) {
                const gargs = [g.l2StateRootProof, p.trustAnchor];
                const [root] = await read<[Hex]>(abi, fin, "verifyL2StateRoot", gargs);
                expect(root).toBe(g.l2StateRoot);
                await measure(`${name} FINALIZED verifyL2StateRoot, GAME mode`, abi, fin, "verifyL2StateRoot", gargs);
            }
        });

        it(`${name}: the newest game is PROPOSED-only; a full bundle runs where the L2 RPC served proofs`, async () => {
            const {p, fin, prop} = live[name];
            const args = [p.newest.l2StateRootProof, p.trustAnchor];
            await expect(read(abi, fin, "verifyL2StateRoot", args)).rejects.toThrow(/GameNotResolved/);
            const [root] = await read<[Hex]>(abi, prop, "verifyL2StateRoot", args);
            expect(root).toBe(p.newest.l2StateRoot);
            await measure(`${name} PROPOSED verifyL2StateRoot, newest game`, abi, prop, "verifyL2StateRoot", args);
            if (p.resolved && p.l1Time - p.resolved.resolvedAt <= p.profile.disputeGameFinalityDelaySeconds) {
                await expect(read(abi, fin, "verifyL2StateRoot", [p.resolved.l2StateRootProof, p.trustAnchor]))
                    .rejects.toThrow(/GameNotFinalized/);
            }
            const final = [p.finalized, p.anchorGame].find((x) => x?.bundle);
            if (final) {
                const b = [final.bundle, p.trustAnchor, p.channelContext];
                await read(abi, fin, "verifyBundle", b);
                await measure(`${name} FINALIZED verifyBundle`, abi, fin, "verifyBundle", b);
            }
            if (p.newest.bundle) {
                const b = [p.newest.bundle, p.trustAnchor, p.channelContext];
                await read(abi, prop, "verifyBundle", b);
                await measure(`${name} PROPOSED verifyBundle`, abi, prop, "verifyBundle", b);
            }
        });
    }

    it("fraxtal: FINALIZED full verifyBundle on an output past 7 days; the newest is PROPOSED-only", async () => {
        const c = frax.p.chains.fraxtal;
        expect(c.finalized.finalizedAtL1).toBe(true);
        expect(c.finalized.bundle).not.toBeNull();
        const fb = [c.finalized.bundle, c.trustAnchor, c.channelContext];
        await read(oAbi, frax.fin, "verifyBundle", fb);
        await measure("fraxtal FINALIZED verifyBundle", oAbi, frax.fin, "verifyBundle", fb);
        const nb = [c.newest.bundle, c.trustAnchor, c.channelContext];
        await expect(read(oAbi, frax.fin, "verifyBundle", nb)).rejects.toThrow(/OutputNotFinalized/);
        await read(oAbi, frax.prop, "verifyBundle", nb);
        await measure("fraxtal PROPOSED verifyBundle", oAbi, frax.prop, "verifyBundle", nb);
    });
});
