import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {createPublicClient, createWalletClient, encodeFunctionData, http, toHex, type Hex, type PublicClient, type WalletClient} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {type Input} from "@ethereumjs/rlp";
import {loadArtifact} from "../../../../script/deploy/artifacts.js";
import {
    buildSignerReplayLiveProof,
    encodeBundle as encodeReplayBundle,
    loadSignerReplayCapture,
    NETWORKS as REPLAY_NETWORKS,
    type SignerReplayLiveProof,
    type SignerReplayNetwork
} from "../../relay/buildSignerReplayLiveProof.js";
import {
    buildKaiaLiveProof,
    encodeBundle as encodeKaiaBundle,
    loadKaiaCapture,
    type KaiaLiveProof,
    type KaiaNetwork
} from "../../relay/buildKaiaLiveProof.js";
import {hexToBuf, rlpDecode, rlpEncode} from "../../lib/rlp.js";

/// SignerReplayVerifier and KaiaIstanbulVerifier against REAL chain data, replayed offline on anvil
/// from test/e2e/fixtures/{signer-replay-live,kaia-live}/ (re-capture with the builders' --refresh).
/// The production contracts run unmodified; per network the spec checks verifyConfig, the rotation
/// bundle, the bundle under the rotated anchor, eth_estimateGas and calldata against Hedera's limits
/// (15M gas, 128 KB), and rejects tampered inputs.
///
/// Run: forge build && npm run test:e2e:signer-kaia-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8627);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

type Result = [{nextMessageId: bigint; sentRunningHash: Hex}, Hex[], Hex, Hex, unknown];

describe("signer-replay and Kaia verifiers on live data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;

    async function deploy(name: string, args: unknown[]): Promise<Hex> {
        const art = loadArtifact(name);
        const hash = await wallet.deployContract({abi: art.abi as never, bytecode: art.bytecode, args: args as never, account: wallet.account!, chain: null});
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error(`deploy ${name} failed`);
        return r.contractAddress;
    }

    async function measure(name: string, address: Hex, proof: Hex, anchor: Hex, ctx: Hex, label: string): Promise<void> {
        const abi = loadArtifact(name).abi;
        const gas = await pub.estimateContractGas({
            address, abi: abi as never, functionName: "verifyBundle", args: [proof, anchor, ctx], account: wallet.account!
        });
        const cd = hexToBuf(encodeFunctionData({abi, functionName: "verifyBundle", args: [proof, anchor, ctx]} as never));
        console.log(`[signer-kaia-live] ${label}: eth_estimateGas ${gas}, calldata ${cd.length} B`);
        expect(gas).toBeLessThan(15_000_000n);
        expect(cd.length).toBeLessThan(128 * 1024);
    }

    function call(name: string, address: Hex, fn: string, args: unknown[]): Promise<unknown> {
        return pub.readContract({address, abi: loadArtifact(name).abi as never, functionName: fn, args: args as never});
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
    });

    afterAll(() => {
        anvil?.kill("SIGTERM");
    });

    // ── SignerReplayVerifier ────────────────────────────────────────────────

    const V = "SignerReplayVerifier";
    for (const network of Object.keys(REPLAY_NETWORKS) as SignerReplayNetwork[]) {
        describe(network, () => {
            let live: SignerReplayLiveProof;
            let verifier: Hex;

            beforeAll(async () => {
                live = await buildSignerReplayLiveProof(loadSignerReplayCapture(network));
                const p = REPLAY_NETWORKS[network].profile;
                verifier = await deploy(V, [{
                    chainId: live.chainId, epochLength: p.epochLength, boundaryOffset: p.boundaryOffset, maxAnchorAge: 0n,
                    sealFields: p.sealFields, entrySize: p.entrySize, trailerSize: p.trailerSize, trailerSignerOffset: p.trailerSignerOffset
                }]);
            });

            it("verifyConfig bootstraps the anchor from the real boundary block", async () => {
                const res = (await call(V, verifier, "verifyConfig", [live.configProof, live.channelId, "0x"])) as unknown[];
                expect(res[1]).toBe(`eip155:${live.chainId}`);
                expect(res[5]).toBe(live.trustAnchor);
            });

            it("verifyBundle: real header run, boundary rotation, account/storage proofs", async () => {
                const [m, payloads, newAnchor, newId] =
                    (await call(V, verifier, "verifyBundle", [live.proofBytes, live.trustAnchor, live.channelContext])) as Result;
                expect(m.nextMessageId).toBe(0n);
                expect(m.sentRunningHash).toBe(toHex(0n, {size: 32}));
                expect(payloads).toEqual([]);
                expect(newAnchor).toBe(live.rotatedAnchor);
                expect(BigInt(newId)).toBe(live.meta.b1);
                const [,, plainAnchor] =
                    (await call(V, verifier, "verifyBundle", [live.proofBytesNoRotation, live.rotatedAnchor, live.channelContext])) as Result;
                expect(plainAnchor).toBe("0x");
                await measure(V, verifier, live.proofBytes, live.trustAnchor, live.channelContext,
                    `${network} rotation (${live.meta.runLength} headers, ${live.meta.signersB0.length} signers)`);
                await measure(V, verifier, live.proofBytesNoRotation, live.rotatedAnchor, live.channelContext, `${network} no rotation`);
            });

            it("rejects a run with its last (counting) header dropped when that breaks the majority", async () => {
                if (live.meta.runLength < 2) return; // single-signer chains: one header is the whole run
                const proof = encodeReplayBundle(live.parts, {headers: live.parts.headers.slice(0, -1)});
                await expect(call(V, verifier, "verifyBundle", [proof, live.trustAnchor, live.channelContext]))
                    .rejects.toThrow(/InsufficientSigners/);
            });

            it("rejects a tampered header (hash link or seal breaks)", async () => {
                const hs = live.parts.headers.map((h) => (h as Buffer[]).map((f) => Buffer.from(f)));
                hs[0][3][0] ^= 1; // h_0 stateRoot
                const proof = encodeReplayBundle(live.parts, {headers: hs as Input[]});
                await expect(call(V, verifier, "verifyBundle", [proof, live.trustAnchor, live.channelContext])).rejects.toThrow();
            });

            it("rejects a tampered storage proof node", async () => {
                const sp = live.parts.storageProof.map(([k, nodes]) => [k, nodes.map((n) => Buffer.from(n))] as [Buffer, Buffer[]]);
                const nodes = sp[0][1];
                nodes[nodes.length - 1][5] ^= 1;
                const proof = encodeReplayBundle(live.parts, {storageProof: sp});
                await expect(call(V, verifier, "verifyBundle", [proof, live.trustAnchor, live.channelContext])).rejects.toThrow();
            });
        });
    }

    // ── KaiaIstanbulVerifier ────────────────────────────────────────────────

    const K = "KaiaIstanbulVerifier";
    for (const network of ["kaia-mainnet", "kairos"] as KaiaNetwork[]) {
        describe(network, () => {
            let live: KaiaLiveProof;
            let verifier: Hex;

            beforeAll(async () => {
                live = await buildKaiaLiveProof(loadKaiaCapture(network));
                verifier = await deploy(K, [live.chainId]);
            });

            it("verifyConfig bootstraps the qualified set from a real header", async () => {
                const res = (await call(K, verifier, "verifyConfig", [live.configProof, live.channelId, "0x"])) as unknown[];
                expect(res[1]).toBe(`eip155:${live.chainId}`);
                expect(res[5]).toBe(live.trustAnchor);
            });

            it("verifyBundle: real committed seals, set rotation, Kaia account/storage proofs", async () => {
                if (live.rotationProof) {
                    const [m,, newAnchor] =
                        (await call(K, verifier, "verifyBundle", [live.rotationProof, live.trustAnchor, live.channelContext])) as Result;
                    expect(m.nextMessageId).toBe(0n);
                    expect(newAnchor).toBe(live.rotatedAnchor);
                    await measure(K, verifier, live.rotationProof, live.trustAnchor, live.channelContext,
                        `${network} rotation (${live.meta.anchorSet} → ${live.meta.rotatedSet} validators)`);
                }
                const [,, plain] = (await call(K, verifier, "verifyBundle", [live.plainProof, live.plainAnchor, live.channelContext])) as Result;
                expect(plain).toBe("0x");
                await measure(K, verifier, live.plainProof, live.plainAnchor, live.channelContext,
                    `${network} plain (${live.meta.recentSeals} seals)`);
            });

            it("rejects a header with committed seals removed below quorum", async () => {
                const hdr = (live.plainParts.headers[0] as Buffer[]).map((f) => Buffer.from(f));
                const extra = hdr[11];
                // Drop the committed-seal list: rebuild extra = vanity ‖ RLP([validators, seal, []]).
                const [vals, seal] = rlpDecode(extra.subarray(32)) as [Uint8Array[], Uint8Array];
                hdr[11] = Buffer.concat([extra.subarray(0, 32), rlpEncode([vals, seal, []])]);
                const proof = encodeKaiaBundle(live.plainParts, {headers: [hdr]});
                await expect(call(K, verifier, "verifyBundle", [proof, live.plainAnchor, live.channelContext]))
                    .rejects.toThrow(/InsufficientCommittedSeals/);
            });

            it("rejects a wrong anchor validator list", async () => {
                const v = Buffer.from(live.plainParts.validators);
                v[3] ^= 1;
                const proof = encodeKaiaBundle(live.plainParts, {validators: v});
                await expect(call(K, verifier, "verifyBundle", [proof, live.plainAnchor, live.channelContext]))
                    .rejects.toThrow(/ValidatorSetMismatch/);
            });
        });
    }
});
