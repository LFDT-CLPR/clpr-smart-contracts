import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {readFileSync} from "node:fs";
import path from "node:path";
import {
    createPublicClient,
    createWalletClient,
    encodeFunctionData,
    http,
    type Hex,
    type PublicClient,
    type WalletClient
} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {loadArtifact, REPO_ROOT} from "../../../../script/deploy/artifacts.js";
import {buildEthLiveProof, reencodeBundle, type EthLiveProof, type LiveCapture} from "../../relay/buildEthLiveProof.js";
import {loadTwinCapture} from "../../relay/buildEthTwinsLiveProof.js";
import {hexToBuf} from "../../lib/rlp.js";

/// EthBeaconTwinVerifier (EthMainnetVerifier parameterized per chain) against REAL beacon + execution
/// data from Gnosis, Chiado (Fulu), PulseChain and PulseChain testnet v4 (Capella), replayed offline
/// from test/e2e/fixtures/ethtwins-live/*.json (re-capture: `npm run ethtwins-live:refresh`).
///
/// Per network, one verifier is deployed on anvil with that chain's parameters (mirrors
/// src/verifiers/evm/ethtwins/EthTwinPresets.sol) and the real bundle goes through `verifyBundle`:
/// sync-committee BLS with real non-signers, the execution state-root SSZ branch, the account MPT proof
/// of the chain's beacon deposit contract, and MPT exclusion proofs for the channel slots.
/// PulseChain also verifies a full rotation bundle (real next_sync_committee, same attested state);
/// for Gnosis/Chiado the rotation comes from `light_client/updates` and runs through the harness.
///
/// Run: forge build && npm run test:e2e:ethtwins-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8611);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const VERIFIER = "EthBeaconTwinVerifier";
/// Hedera limits a bundle must fit (see ~/clpr/AGENT-BRIEF.md).
const HEDERA_GAS_LIMIT = 15_000_000n;
const HEDERA_CALLDATA_LIMIT = 128 * 1024;

interface ChainParams {
    genesisValidatorsRoot: Hex;
    forkVersion: Hex;
    slotsPerSyncCommitteePeriod: bigint;
    executionStateRootGindex: bigint;
    nextSyncCommitteeGindex: bigint;
}

/// Mirrors EthTwinPresets.sol.
const PRESETS: Record<string, ChainParams> = {
    gnosis: {
        genesisValidatorsRoot: "0xf5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47",
        forkVersion: "0x06000064",
        slotsPerSyncCommitteePeriod: 8192n,
        executionStateRootGindex: 802n,
        nextSyncCommitteeGindex: 87n
    },
    chiado: {
        genesisValidatorsRoot: "0x9d642dac73058fbf39c0ae41ab1e34e4d889043cb199851ded7095bc99eb4c1e",
        forkVersion: "0x0600006f",
        slotsPerSyncCommitteePeriod: 8192n,
        executionStateRootGindex: 802n,
        nextSyncCommitteeGindex: 87n
    },
    pulsechain: {
        genesisValidatorsRoot: "0x3357ba0018a2582aeabe4ae847aa17d50a3a99aaeb66293c01f80a83aecd0c90",
        forkVersion: "0x0000036c",
        slotsPerSyncCommitteePeriod: 8192n,
        executionStateRootGindex: 402n,
        nextSyncCommitteeGindex: 55n
    },
    "pulsechain-testnet": {
        genesisValidatorsRoot: "0xd81664ba97279a6fa0832041b4aee6009172b4750a99467ff670a9faf3a34e64",
        forkVersion: "0x00000946",
        slotsPerSyncCommitteePeriod: 8192n,
        executionStateRootGindex: 402n,
        nextSyncCommitteeGindex: 55n
    }
};

function loadHarnessArtifact(): {abi: readonly unknown[]; bytecode: Hex} {
    const file = path.join(REPO_ROOT, "out", "EthBeaconTwinVerifier.t.sol", "EthBeaconTwinVerifierHarness.json");
    const j = JSON.parse(readFileSync(file, "utf8")) as {abi: readonly unknown[]; bytecode: {object: Hex}};
    return {abi: j.abi, bytecode: j.bytecode.object};
}

const byteLen = (h: Hex) => (h.length - 2) / 2;
const calldataGas = (data: Hex) => hexToBuf(data).reduce((a, b) => a + (b === 0 ? 4 : 16), 0);

describe("EthBeaconTwinVerifier on live Gnosis / PulseChain data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    const verifierArt = loadArtifact(VERIFIER);
    const harnessArt = loadHarnessArtifact();
    const deployed: Record<string, {verifier: Hex; harness: Hex; capture: LiveCapture; live: EthLiveProof}> = {};

    async function deploy(abi: readonly unknown[], bytecode: Hex, args: unknown[]): Promise<Hex> {
        const hash = await wallet.deployContract({abi: abi as never, bytecode, args: args as never, account: wallet.account!, chain: null});
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error("deploy failed");
        return r.contractAddress;
    }

    const call = (address: Hex, fn: string, args: unknown[]) =>
        pub.readContract({address, abi: verifierArt.abi as never, functionName: fn, args} as never);

    beforeAll(async () => {
        anvil = spawn("anvil", ["--port", String(ANVIL_PORT), "--silent", "--code-size-limit", "50000"], {stdio: "ignore"});
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
        for (const [network, params] of Object.entries(PRESETS)) {
            const capture = loadTwinCapture(network);
            deployed[network] = {
                verifier: await deploy(verifierArt.abi, verifierArt.bytecode, [params]),
                harness: await deploy(harnessArt.abi, harnessArt.bytecode, [params]),
                capture,
                live: buildEthLiveProof(capture)
            };
        }
    });

    afterAll(() => {
        anvil?.kill("SIGTERM");
    });

    for (const network of Object.keys(PRESETS)) {
        describe(network, () => {
            it("preset matches the recorded chain (GVR, fork version at signature slot, period, SSZ layout)", () => {
                const {capture, live} = deployed[network];
                const p = PRESETS[network];
                expect(live.meta.genesisValidatorsRoot).toBe(p.genesisValidatorsRoot);
                expect(live.meta.forkVersion).toBe(p.forkVersion);
                expect(BigInt(capture.spec.SLOTS_PER_EPOCH) * BigInt(capture.spec.EPOCHS_PER_SYNC_COMMITTEE_PERIOD))
                    .toBe(p.slotsPerSyncCommitteePeriod);
                expect(live.meta.layout.executionStateRootGindex).toBe(p.executionStateRootGindex);
                expect(live.meta.layout.nextSyncCommitteeGindex).toBe(p.nextSyncCommitteeGindex);
                expect(3 * live.meta.participants).toBeGreaterThanOrEqual(2 * 512);
                expect(live.meta.nonSigners).toBeGreaterThan(0); // non-signer proofs exercised
            });

            it("verifyBundle succeeds on the real bundle, within Hedera's gas and calldata limits", async () => {
                const {verifier, live} = deployed[network];
                const args = [live.proofBytes, live.trustAnchor, live.channelContext];
                const [metadata, payloads, newAnchor] =
                    (await call(verifier, "verifyBundle", args)) as [{nextMessageId: bigint}, Hex[], Hex];
                expect(metadata.nextMessageId).toBe(0n);
                expect(payloads).toEqual([]);
                expect(newAnchor).toBe("0x");
                const gas = await pub.estimateContractGas({address: verifier, abi: verifierArt.abi as never,
                    functionName: "verifyBundle", args, account: wallet.account!} as never);
                const data = encodeFunctionData({abi: verifierArt.abi, functionName: "verifyBundle", args} as never);
                expect(gas).toBeLessThan(HEDERA_GAS_LIMIT);
                expect(byteLen(data)).toBeLessThan(HEDERA_CALLDATA_LIMIT);
                console.log(`[ethtwins] ${network} ${live.meta.forkName} slot ${live.meta.attestedSlot}: ` +
                    `${live.meta.participants}/512 | bundle eth_estimateGas ${gas} (calldata ${byteLen(data)} B, ` +
                    `${calldataGas(data)} calldata gas)`);
            });

            it("rotation: real next_sync_committee proven at the chain's gindex", async () => {
                const {verifier, harness, live} = deployed[network];
                const rot = live.rotation!;
                expect(rot).toBeDefined();
                if (live.rotationProofBytes) {
                    // Full rotation bundle through verifyBundle (state-derived capture).
                    const args = [live.rotationProofBytes, live.trustAnchor, live.channelContext];
                    const [, , newAnchor, newAnchorId] = (await call(verifier, "verifyBundle", args)) as [unknown, Hex[], Hex, Hex];
                    const a = hexToBuf(newAnchor);
                    expect(a.length).toBe(260);
                    expect("0x" + a.subarray(196, 228).toString("hex")).toBe(rot.nextCommitteeMerkleRoot);
                    expect(BigInt(newAnchorId)).toBe(rot.nextPeriod);
                    const gas = await pub.estimateContractGas({address: verifier, abi: verifierArt.abi as never,
                        functionName: "verifyBundle", args, account: wallet.account!} as never);
                    const data = encodeFunctionData({abi: verifierArt.abi, functionName: "verifyBundle", args} as never);
                    expect(gas).toBeLessThan(HEDERA_GAS_LIMIT);
                    expect(byteLen(data)).toBeLessThan(HEDERA_CALLDATA_LIMIT);
                    console.log(`[ethtwins] ${network} rotation bundle → period ${rot.nextPeriod}: eth_estimateGas ${gas} ` +
                        `(calldata ${byteLen(data)} B, ${calldataGas(data)} calldata gas)`);
                    // The successor committee did not sign the old bundle.
                    await expect(call(verifier, "verifyBundle", [live.proofBytes, newAnchor, live.channelContext]))
                        .rejects.toThrow(/NonSignerProofInvalid|BlsSignatureInvalid/);
                } else {
                    await pub.readContract({address: harness, abi: harnessArt.abi as never, functionName: "verifyBlsExt",
                        args: [live.trustAnchor, rot.nonSignerWrapperRlp, rot.signature, rot.bits, rot.beaconBlockRoot,
                            rot.forkVersion, live.meta.genesisValidatorsRoot]} as never);
                    const rargs = [rot.rotationRlp, rot.attestedStateRoot, live.meta.genesisValidatorsRoot,
                        live.meta.forkVersion, live.channelId, live.codeHash];
                    const newAnchor = (await pub.readContract({address: harness, abi: harnessArt.abi as never,
                        functionName: "verifyRotationExt", args: rargs} as never)) as Hex;
                    expect("0x" + hexToBuf(newAnchor).subarray(196, 228).toString("hex")).toBe(rot.nextCommitteeMerkleRoot);
                    const gas = await pub.estimateContractGas({address: harness, abi: harnessArt.abi as never,
                        functionName: "verifyRotationExt", args: rargs, account: wallet.account!} as never);
                    console.log(`[ethtwins] ${network} rotation (harness) → period ${rot.nextPeriod}: ` +
                        `_verifyRotation eth_estimateGas ${gas}, rotation items ${byteLen(rot.rotationRlp)} B`);
                }
            });

            it("rejects a tampered execution branch and a tampered signature", async () => {
                const {verifier, live} = deployed[network];
                const branch = live.parts.executionBranch.map((b) => Buffer.from(b));
                branch[branch.length - 1][0] ^= 1;
                await expect(call(verifier, "verifyBundle",
                    [reencodeBundle(live.parts, {executionBranch: branch}), live.trustAnchor, live.channelContext]))
                    .rejects.toThrow(/ExecutionBranchInvalid/);
                const sig = Buffer.from(live.parts.syncAggregate[1]);
                sig[255] ^= 1;
                await expect(call(verifier, "verifyBundle",
                    [reencodeBundle(live.parts, {syncAggregate: [live.parts.syncAggregate[0], sig]}), live.trustAnchor,
                        live.channelContext]))
                    .rejects.toThrow(/BlsPrecompileCallFailed|BlsSignatureInvalid/);
            });
        });
    }

    it("each chain's bundle is rejected by the other family's deployment (layout / committee mismatch)", async () => {
        const g = deployed.gnosis;
        const p = deployed.pulsechain;
        await expect(call(g.verifier, "verifyBundle", [p.live.proofBytes, p.live.trustAnchor, p.live.channelContext]))
            .rejects.toThrow(/InvalidBranch/);
        await expect(call(p.verifier, "verifyBundle", [g.live.proofBytes, g.live.trustAnchor, g.live.channelContext]))
            .rejects.toThrow(/InvalidBranch/);
        // Same layout, other chain: Chiado's bundle under Gnosis's anchor fails the committee check.
        const c = deployed.chiado;
        await expect(call(g.verifier, "verifyBundle", [c.live.proofBytes, g.live.trustAnchor, c.live.channelContext]))
            .rejects.toThrow(/NonSignerProofInvalid|BlsSignatureInvalid|NonSignerProofCountMismatch/);
    });
});
