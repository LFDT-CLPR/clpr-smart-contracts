import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {
    createPublicClient,
    createWalletClient,
    encodeFunctionData,
    http,
    toHex,
    type Hex,
    type PublicClient,
    type WalletClient
} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {loadArtifact} from "../../../../script/deploy/artifacts.js";
import {
    buildBscLiveProof,
    encodeBundle,
    headerAttestation,
    loadBscCapture,
    NETWORKS,
    type BscLiveCapture,
    type BscLiveProof,
    type BscNetwork
} from "../../relay/buildBscLiveProof.js";
import {bigintToTrimmedBuf, hexToBuf} from "../../lib/rlp.js";

/// BscParliaVerifier against REAL BNB Smart Chain data, replayed offline on anvil from
/// test/e2e/fixtures/bsc-live/{chapel,mainnet,botchain,core}.json (re-capture: `npm run bsc-live:refresh`).
///
/// Per network the fixture holds three consecutive epoch blocks, the real vote attestations that
/// finalize the newest epoch block and a recent state block, and `eth_getProof` at that block. The
/// production contract runs unmodified:
///   verifyConfig  on the real anchor epoch block (validators + BLS keys from its extraData),
///   verifyBundle  rotating into the next epoch (finalized by the outgoing set's BLS attestation;
///                 the validator set really changed) and proving the account + channel slots
///                 against the finalized state root.
/// No ClprService exists on BSC yet, so the bundle targets WBNB with ITS code hash pinned; the
/// channelId-derived slots are empty there, so the storage step checks real MPT exclusion proofs.
///
/// Run: forge build && npm run test:e2e:bsc-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8617);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const VERIFIER = "BscParliaVerifier";

function byteLen(h: Hex): number {
    return (h.length - 2) / 2;
}

describe("BscParliaVerifier on live BSC data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let verifier: Hex;
    const abi = loadArtifact(VERIFIER).abi;

    function verifyBundle(proofBytes: Hex, trustAnchor: Hex, channelContext: Hex) {
        return pub.readContract({
            address: verifier, abi: abi as never, functionName: "verifyBundle",
            args: [proofBytes, trustAnchor, channelContext]
        }) as Promise<[{nextMessageId: bigint; receivedMessageId: bigint; sentRunningHash: Hex}, Hex[], Hex, Hex, unknown]>;
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
        const art = loadArtifact(VERIFIER);
        const hash = await wallet.deployContract({
            abi: art.abi as never, bytecode: art.bytecode, args: [], account: wallet.account!, chain: null
        });
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error("deploy failed");
        verifier = r.contractAddress;
        const code = await pub.getCode({address: verifier});
        console.log(`[bsc-live] BscParliaVerifier runtime ${byteLen(code!)} B, deploy gas ${r.gasUsed}`);
    });

    afterAll(() => {
        anvil?.kill("SIGTERM");
    });

    for (const network of ["chapel", "mainnet", "botchain", "core"] as BscNetwork[]) {
        describe(network, () => {
            let capture: BscLiveCapture;
            let live: BscLiveProof;

            beforeAll(() => {
                capture = loadBscCapture(network);
                live = buildBscLiveProof(capture);
            });

            it("builder: real headers hash, seals recover validators, BLS attestations verify off-chain", () => {
                expect(live.chainId).toBe(NETWORKS[network].chainId);
                expect(live.meta.rotationEpoch).toBe(live.meta.anchorEpoch + NETWORKS[network].epochLength);
                expect(3 * live.meta.rotationVotes).toBeGreaterThanOrEqual(2 * live.meta.validators);
                expect(3 * live.meta.stateVotes).toBeGreaterThanOrEqual(2 * live.meta.validators);
                // The attestation the bundle uses is the one carried in a real header's extraData.
                const carrier = capture.blocks[String(capture.state.carrier)];
                const att = headerAttestation(carrier, NETWORKS[network].epochLength)!;
                expect(att.targetNumber).toBe(att.sourceNumber + 1n);
            });

            it("verifyConfig bootstraps the anchor from the real epoch block", async () => {
                const res = (await pub.readContract({
                    address: verifier, abi: abi as never, functionName: "verifyConfig",
                    args: [live.configProof, live.channelId, "0x"]
                })) as [Hex, string, Hex, bigint, unknown, Hex, Hex, unknown];
                expect(res[1]).toBe(`eip155:${live.chainId}`);
                expect(res[5]).toBe(live.trustAnchor);
                expect(BigInt(res[6])).toBe(live.meta.anchorEpoch);
            });

            it("verifyBundle: real epoch rotation + finalized state + account/storage proofs", async () => {
                const [metadata, payloads, newAnchor, newAnchorId] =
                    await verifyBundle(live.proofBytes, live.trustAnchor, live.channelContext);
                expect(metadata.nextMessageId).toBe(0n);
                expect(metadata.sentRunningHash).toBe(toHex(0n, {size: 32}));
                expect(payloads).toEqual([]);
                expect(newAnchor).toBe(live.rotatedAnchor);
                expect(BigInt(newAnchorId)).toBe(live.meta.rotationEpoch);

                for (const [label, proof, anchor] of [
                    ["1 rotation", live.proofBytes, live.trustAnchor],
                    ["no rotation", live.proofBytesNoRotation, live.rotatedAnchor]
                ] as [string, Hex, Hex][]) {
                    const gas = await pub.estimateContractGas({
                        address: verifier, abi: abi as never, functionName: "verifyBundle",
                        args: [proof, anchor, live.channelContext], account: wallet.account!
                    });
                    const cd = hexToBuf(encodeFunctionData({
                        abi, functionName: "verifyBundle", args: [proof, anchor, live.channelContext]
                    } as never));
                    console.log(
                        `[bsc-live] ${network} ${label}: eth_estimateGas ${gas}, calldata ${cd.length} B ` +
                        `(validators ${live.meta.validators}, state block ${live.meta.stateBlock}, ` +
                        `votes ${live.meta.stateVotes}/${live.meta.validators})`
                    );
                    expect(gas).toBeLessThan(15_000_000n);
                    expect(cd.length).toBeLessThan(128 * 1024);
                }
            });

            it("rotation with explicit keys (same set) gives the same anchor", async () => {
                const [,, newAnchor] = await verifyBundle(live.proofBytesWithKeys, live.trustAnchor, live.channelContext);
                expect(newAnchor).toBe(live.rotatedAnchor);
            });

            it("rejects a tampered BLS signature", async () => {
                const fin = live.parts.finality as [unknown, Buffer[]];
                const att = fin[1].map((b) => Buffer.from(b));
                att[1][255] ^= 1;
                const proof = encodeBundle(live.parts, {finality: [fin[0], att] as never});
                await expect(verifyBundle(proof, live.trustAnchor, live.channelContext))
                    .rejects.toThrow(/BlsSignatureInvalid|BlsPrecompileCallFailed/);
            });

            it("rejects a dropped voter bit (signature no longer matches the voter set)", async () => {
                const fin = live.parts.finality as [unknown, Buffer[]];
                const att = [...fin[1]];
                const bits = BigInt("0x" + (att[0].toString("hex") || "0"));
                const lowest = bits & -bits;
                const nb = bits ^ lowest;
                att[0] = bigintToTrimmedBuf(nb);
                const proof = encodeBundle(live.parts, {finality: [fin[0], att] as never});
                await expect(verifyBundle(proof, live.trustAnchor, live.channelContext))
                    .rejects.toThrow(/BlsSignatureInvalid|InsufficientVotes/);
            });

            it("rejects the state proof against the pre-rotation anchor without the rotation step", async () => {
                const proof = encodeBundle(live.parts, {rotations: []});
                await expect(verifyBundle(proof, live.trustAnchor, live.channelContext))
                    .rejects.toThrow(/AttestationBeyondTenure|BlsSignatureInvalid|UnauthorizedSealer/);
            });

            it("rejects a tampered storage proof node", async () => {
                const sp = (live.parts.storageProof as [Buffer, Buffer[]][]).map(([k, nodes]) => [k, nodes.map((n) => Buffer.from(n))]);
                const nodes = sp[0][1] as Buffer[];
                nodes[nodes.length - 1][5] ^= 1;
                const proof = encodeBundle(live.parts, {storageProof: sp as never});
                await expect(verifyBundle(proof, live.trustAnchor, live.channelContext)).rejects.toThrow();
            });

            it("rejects a wrong validator set (keys not matching the anchor)", async () => {
                const v = Buffer.from(live.parts.validators);
                v[40] ^= 1;
                const proof = encodeBundle(live.parts, {validators: v});
                await expect(verifyBundle(proof, live.trustAnchor, live.channelContext)).rejects.toThrow(/ValidatorSetMismatch/);
            });
        });
    }
});
