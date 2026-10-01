import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {readFileSync} from "node:fs";
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
import {loadArtifact, REPO_ROOT} from "../../../../script/deploy/artifacts.js";
import {
    buildEthLiveProof,
    loadLiveCapture,
    reencodeBundle,
    type EthLiveProof,
    type LiveCapture
} from "../../relay/buildEthLiveProof.js";
import {hexToBuf} from "../../lib/rlp.js";

/// EthMainnetVerifier against REAL Sepolia (Fulu) beacon + execution data, replayed offline from
/// test/e2e/fixtures/sepolia-live/capture.json (re-capture: `npm run eth-live:refresh`).
///
/// The production `verifyBundle` runs unmodified. Its channel-storage step needs a ClprService on
/// Sepolia, which does not exist yet, so the bundle targets a real Sepolia contract (the beacon
/// deposit contract) with ITS code hash pinned in the anchor. The channelId-derived slots are empty
/// there, so the storage step checks genuine MPT exclusion proofs and yields zeroed queue metadata.
/// Every cryptographic link is therefore real data: sync-committee BLS (fork version at the signature
/// slot, real GVR, decompressed keys, real non-signers), the rebuilt state_root → bodyRoot SSZ branch
/// (gindex 802) and the account MPT proof. Swapping in any other code hash (e.g. a ClprService's)
/// fails exactly at the codeHash binding, after BLS and SSZ have passed.
///
/// A real `next_sync_committee` rotation from `light_client/updates` is checked through the existing
/// `EthMainnetVerifierProofHarness` (its attested block is too old for a non-archive eth_getProof, so
/// it cannot ride a full verifyBundle).
///
/// Run: forge build && npm run test:e2e:eth-live

const ANVIL_PORT = 8599;
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const VERIFIER = "EthMainnetVerifier";

function loadHarnessArtifact(): {abi: readonly unknown[]; bytecode: Hex} {
    const file = path.join(REPO_ROOT, "out", "EthMainnetVerifier.t.sol", "EthMainnetVerifierProofHarness.json");
    const j = JSON.parse(readFileSync(file, "utf8")) as {abi: readonly unknown[]; bytecode: {object: Hex}};
    return {abi: j.abi, bytecode: j.bytecode.object};
}

function byteLen(h: Hex): number {
    return (h.length - 2) / 2;
}

describe("EthMainnetVerifier on live Sepolia data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let verifier: Hex;
    let harness: Hex;
    let capture: LiveCapture;
    let live: EthLiveProof;
    const verifierAbi = loadArtifact(VERIFIER).abi;
    const harnessArt = loadHarnessArtifact();

    async function deploy(abi: readonly unknown[], bytecode: Hex): Promise<Hex> {
        const hash = await wallet.deployContract({
            abi: abi as never, bytecode, args: [], account: wallet.account!, chain: null
        });
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error("deploy failed");
        return r.contractAddress;
    }

    function verifyBundle(proofBytes: Hex, trustAnchor: Hex, channelContext: Hex) {
        return pub.readContract({
            address: verifier,
            abi: verifierAbi as never,
            functionName: "verifyBundle",
            args: [proofBytes, trustAnchor, channelContext]
        }) as Promise<[{state: number; nextMessageId: bigint; receivedMessageId: bigint;
            sentRunningHash: Hex; receivedRunningHash: Hex}, Hex[], Hex, Hex, unknown]>;
    }

    beforeAll(async () => {
        capture = loadLiveCapture();
        live = buildEthLiveProof(capture);

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
        verifier = await deploy(verifierAbi, loadArtifact(VERIFIER).bytecode);
        harness = await deploy(harnessArt.abi, harnessArt.bytecode);
    });

    afterAll(() => {
        anvil?.kill("SIGTERM");
    });

    it("builder: live inputs match the verifier's constants (Fulu, fork version at signature slot)", () => {
        expect(capture.finalityUpdate.version).toBe("fulu");
        expect(live.meta.forkVersion).toBe(capture.spec.FULU_FORK_VERSION);
        expect(live.meta.genesisValidatorsRoot).toBe(
            "0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078" // Sepolia GVR
        );
        expect(byteLen(live.trustAnchor)).toBe(260);
        expect(live.parts.executionBranch).toHaveLength(9);
        expect(live.meta.nonSigners).toBe(live.parts.nonSignerEntries.length);
        // 2/3 supermajority holds on the real bitvector.
        expect(3 * live.meta.participants).toBeGreaterThanOrEqual(2 * 512);
    });

    it("verifyBundle succeeds end-to-end on the real attested header, signature and account proof", async () => {
        const [metadata, payloads, newAnchor, newAnchorId] =
            await verifyBundle(live.proofBytes, live.trustAnchor, live.channelContext);
        // Channel slots are absent in the target account → MPT exclusion proofs → zeroed metadata.
        expect(metadata.nextMessageId).toBe(0n);
        expect(metadata.receivedMessageId).toBe(0n);
        expect(metadata.sentRunningHash).toBe(toHex(0n, {size: 32}));
        expect(payloads).toEqual([]);
        expect(newAnchor).toBe("0x");
        expect(newAnchorId).toBe("0x");

        const gas = await pub.estimateContractGas({
            address: verifier,
            abi: verifierAbi as never,
            functionName: "verifyBundle",
            args: [live.proofBytes, live.trustAnchor, live.channelContext],
            account: wallet.account!
        });
        const calldata = encodeFunctionData({
            abi: verifierAbi,
            functionName: "verifyBundle",
            args: [live.proofBytes, live.trustAnchor, live.channelContext]
        } as never);
        // Standard intrinsic calldata cost (16 gas per non-zero byte, 4 per zero byte).
        const cd = hexToBuf(calldata);
        const calldataGas = cd.reduce((acc, b) => acc + (b === 0 ? 4 : 16), 0);
        console.log(
            `[eth-live] ${live.meta.network} ${live.meta.forkName} slot ${live.meta.attestedSlot}: ` +
            `participation ${live.meta.participants}/512 (${live.meta.nonSigners} non-signers) | ` +
            `verifyBundle eth_estimateGas ${gas} = 21000 base + ${calldataGas} calldata + ~${gas - 21000n - BigInt(calldataGas)} execution | ` +
            `proofBytes ${byteLen(live.proofBytes)} B, calldata ${cd.length} B, account MPT nodes ${live.meta.accountProofNodes}`
        );
    });

    it("fails ONLY at the codeHash binding when a different (e.g. ClprService) code hash is pinned", async () => {
        const otherCodeHash = keccak256(toHex("some-other-runtime-code"));
        // Same real committee / GVR / fork version; only the pinned code hash (anchor bytes 228..260) differs.
        const realAnchor = hexToBuf(live.trustAnchor);
        hexToBuf(otherCodeHash).copy(realAnchor, 228);
        await expect(
            verifyBundle(live.proofBytes, ("0x" + realAnchor.toString("hex")) as Hex, live.channelContext)
        ).rejects.toThrow(/CodeHashMismatch/);
    });

    it("rejects the real signature under the previous fork version (Electra)", async () => {
        const anchor = hexToBuf(live.trustAnchor);
        hexToBuf(capture.spec.ELECTRA_FORK_VERSION).copy(anchor, 32);
        await expect(
            verifyBundle(live.proofBytes, ("0x" + anchor.toString("hex")) as Hex, live.channelContext)
        ).rejects.toThrow(/BlsSignatureInvalid|BlsPrecompileCallFailed/);
    });

    it("rejects a tampered execution branch sibling", async () => {
        const branch = live.parts.executionBranch.map((b) => Buffer.from(b));
        branch[8][0] ^= 1; // flip a bit in the light-client execution_branch part
        const proof = reencodeBundle(live.parts, {executionBranch: branch});
        await expect(verifyBundle(proof, live.trustAnchor, live.channelContext)).rejects.toThrow(/ExecutionBranchInvalid/);
    });

    it("rejects a flipped participation bit (signature no longer matches the participant set)", async () => {
        const bits = Buffer.from(live.parts.syncAggregate[0]);
        // Clear a set bit and add a (valid, Merkle-proven) non-signer entry would be needed to keep the
        // count consistent — without it the count check fires first; either way the proof is rejected.
        const firstSet = [...Array(512).keys()].find((i) => (bits[i >> 3] >> (i & 7)) & 1)!;
        bits[firstSet >> 3] &= ~(1 << (firstSet & 7));
        const proof = reencodeBundle(live.parts, {syncAggregate: [bits, live.parts.syncAggregate[1]]});
        await expect(verifyBundle(proof, live.trustAnchor, live.channelContext))
            .rejects.toThrow(/NonSignerProofCountMismatch|NonSignerProofInvalid|BlsSignatureInvalid/);
    });

    it("rejects when a non-signer proof is dropped", async (ctx) => {
        if (live.parts.nonSignerEntries.length === 0) ctx.skip();
        const proof = reencodeBundle(live.parts, {nonSignerEntries: live.parts.nonSignerEntries.slice(1)});
        await expect(verifyBundle(proof, live.trustAnchor, live.channelContext))
            .rejects.toThrow(/NonSignerProofCountMismatch/);
    });

    it("real sync-committee rotation: BLS over the update + next_sync_committee branch (gindex 87)", async (ctx) => {
        const rot = live.rotation;
        if (!rot) ctx.skip();
        // BLS of the LightClientUpdate's attested header with the SAME (current) committee anchor.
        await pub.readContract({
            address: harness,
            abi: harnessArt.abi as never,
            functionName: "verifyBlsExt",
            args: [live.trustAnchor, rot!.nonSignerWrapperRlp, rot!.signature, rot!.bits,
                rot!.beaconBlockRoot, rot!.forkVersion, live.meta.genesisValidatorsRoot]
        });
        const newAnchor = (await pub.readContract({
            address: harness,
            abi: harnessArt.abi as never,
            functionName: "verifyRotationExt",
            args: [rot!.rotationRlp, rot!.attestedStateRoot, live.meta.genesisValidatorsRoot,
                live.meta.forkVersion, live.channelId, live.codeHash]
        })) as Hex;
        const a = hexToBuf(newAnchor);
        expect(a.length).toBe(260);
        expect(("0x" + a.subarray(68, 196).toString("hex"))).toBe(rot!.nextAggregate);
        expect(("0x" + a.subarray(196, 228).toString("hex"))).toBe(rot!.nextCommitteeMerkleRoot);

        const gas = await pub.estimateContractGas({
            address: harness,
            abi: harnessArt.abi as never,
            functionName: "verifyRotationExt",
            args: [rot!.rotationRlp, rot!.attestedStateRoot, live.meta.genesisValidatorsRoot,
                live.meta.forkVersion, live.channelId, live.codeHash],
            account: wallet.account!
        });
        console.log(
            `[eth-live] rotation → period ${rot!.nextPeriod}: update participation ${rot!.participants}/512, ` +
            `_verifyRotation gas ${gas} (harness call, incl. base + calldata), rotation items ${byteLen(rot!.rotationRlp)} B`
        );
    });
});
