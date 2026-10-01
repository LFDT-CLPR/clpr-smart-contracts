import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {readFileSync, readdirSync} from "node:fs";
import path from "node:path";
import {
    createPublicClient,
    createWalletClient,
    encodeFunctionData,
    http,
    keccak256,
    type Hex,
    type PublicClient,
    type WalletClient
} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {RLP} from "@ethereumjs/rlp";
import {loadArtifact, REPO_ROOT} from "../../../../script/deploy/artifacts.js";
import {hex, toHex, cat, word, g1Eip2537, g1FromCompressed} from "../../relay/monad/monad.js";
import {bls12_381 as bls} from "@noble/curves/bls12-381";

/// MonadVerifier against LIVE Monad data (mainnet + testnet), replayed offline from
/// test/e2e/fixtures/monad-live/capture.json (re-capture: `npm run monad-live:refresh`).
///
/// What is live: a real MonadBFT QuorumCertificate (from the Monad Foundation's published forkpoint), the
/// epoch's real validator set (validators.toml), the staking precompile's raw storage at a real block, and
/// that block's real Ethereum header. The QC is checked ON-CHAIN (anvil) by the production code path
/// (`verifyQuorumCertificate` → `_verifyQcSignature`, the same function `verifyBundle` uses): BLS12-381
/// aggregate over the signer bitmap, POP DST, vote signing domain, stake supermajority.
///
/// What is not live (and why): Monad's public RPC has no `eth_getProof` and no consensus-header endpoint,
/// so the full finality chain (consensus headers P/B) and the MIP-8 storage proofs come from the synthetic
/// 196-validator fixture, which this spec also runs end-to-end on anvil for gas.
///
/// Run: forge build && npm run test:e2e:monad-live

const PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8631);
const KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const CAPTURE = path.join(REPO_ROOT, "test/e2e/fixtures/monad-live/capture.json");
const SYNTH = path.join(REPO_ROOT, "test/verifiers/evm/monad/fixtures/synthetic");

type Capture = {
    network: string;
    qc: {id: Hex; round: string; epoch: string; qcRlp: Hex; voteRlp: Hex; signatureCompressed: Hex; signatureUncompressed: Hex};
    validatorSet: {epoch: string; sorted: Array<{node_id: Hex; stake: Hex; cert_pubkey: Hex}>; blob: Hex; blobHash: Hex};
    validatorSets: Record<string, Array<{node_id: Hex; stake: Hex; cert_pubkey: Hex}>>;
    offchain: {signers: number; signedStake: string; totalStake: string};
    staking: {block: string; epochWord: Hex; inDelayWord: Hex; lengthWord: Hex; ids: string[]; words: Hex[]};
    ethHeader: {number: string; hash: Hex; stateRoot: Hex; raw: Hex};
    forkpointToml: string;
};

const bytes = (h: Hex) => (h.length - 2) / 2;

describe("MonadVerifier on live Monad data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let verifier: Hex;
    const rotArt = loadArtifact("MonadValsetRotation");
    const verifierArt = loadArtifact("MonadVerifier");
    // Decode errors raised inside the rotation contract and the proof libraries too.
    const errorAbis = ["MonadValsetRotation", "MonadMpt", "MonadPageProof", "MonadBlake3", "MonadBls"]
        .flatMap((n) => (loadArtifact(n).abi as Array<{type: string}>).filter((e) => e.type === "error"));
    const art = {...verifierArt, abi: [...verifierArt.abi, ...errorAbis]};
    const capture = JSON.parse(readFileSync(CAPTURE, "utf8")) as Record<string, Capture>;

    async function deploy(abi: readonly unknown[], bytecode: Hex, args: unknown[] = []): Promise<Hex> {
        const hash = await wallet.deployContract({abi: abi as never, bytecode, args: args as never, account: wallet.account!, chain: null});
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error("deploy failed");
        return r.contractAddress;
    }

    const verifyQc = (c: Capture, qcRlp: Hex = c.qc.qcRlp, sig: Hex = c.qc.signatureUncompressed, blob: Hex = c.validatorSet.blob) =>
        pub.readContract({address: verifier, abi: art.abi as never, functionName: "verifyQuorumCertificate", args: [qcRlp, sig, blob]}) as
            Promise<[Hex, bigint, bigint]>;

    beforeAll(async () => {
        anvil = spawn("anvil", ["--port", String(PORT), "--silent", "--gas-limit", "300000000"], {stdio: "ignore"});
        const rpc = `http://127.0.0.1:${PORT}`;
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
        wallet = createWalletClient({account: privateKeyToAccount(KEY), transport: http(rpc)});
        const rotation = await deploy(rotArt.abi, rotArt.bytecode);
        verifier = await deploy(art.abi, art.bytecode, [rotation]);
    });

    afterAll(() => {
        anvil?.kill("SIGTERM");
    });

    for (const net of ["mainnet", "testnet"]) {
        describe(net, () => {
            it("verifies the live QuorumCertificate on-chain (BLS aggregate + 2/3 stake)", async () => {
                const c = capture[net];
                const [blockId, round, epoch] = await verifyQc(c);
                expect(blockId).toBe(c.qc.id);
                expect(round).toBe(BigInt(c.qc.round));
                expect(epoch).toBe(BigInt(c.qc.epoch));
                expect(3n * BigInt(c.offchain.signedStake)).toBeGreaterThan(2n * BigInt(c.offchain.totalStake));
                const gas = await pub.estimateContractGas({address: verifier, abi: art.abi as never, functionName: "verifyQuorumCertificate",
                    args: [c.qc.qcRlp, c.qc.signatureUncompressed, c.validatorSet.blob], account: wallet.account!});
                console.log(`[monad-live] ${net} QC round ${c.qc.round} epoch ${c.qc.epoch}: ${c.offchain.signers}/` +
                    `${c.validatorSet.sorted.length} signers, ${(Number((10000n * BigInt(c.offchain.signedStake)) / BigInt(c.offchain.totalStake)) / 100).toFixed(2)}% stake | ` +
                    `verifyQuorumCertificate eth_estimateGas ${gas}, calldata ${bytes(encodeFunctionData({abi: art.abi as never, functionName: "verifyQuorumCertificate",
                        args: [c.qc.qcRlp, c.qc.signatureUncompressed, c.validatorSet.blob]} as never))} B`);
            });

            it("rejects the live QC when the vote is altered (round + 1)", async () => {
                const c = capture[net];
                const q = RLP.decode(hex(c.qc.qcRlp)) as unknown as [[Uint8Array, Uint8Array, Uint8Array], unknown];
                const r = BigInt(toHex(q[0][1])) + 1n;
                const altered = toHex(RLP.encode([[q[0][0], hex(r.toString(16)), q[0][2]], q[1] as never]));
                await expect(verifyQc(c, altered)).rejects.toThrow(/BlsSignatureInvalid/);
            });

            it("rejects the live QC when a signer bit is cleared", async () => {
                const c = capture[net];
                const q = RLP.decode(hex(c.qc.qcRlp)) as unknown as [Uint8Array[], [[Uint8Array, Uint8Array], Uint8Array]];
                const bm = Uint8Array.from(q[1][0][1]);
                const k = bm.findIndex((b) => b !== 0);
                bm[k] &= bm[k] - 1; // clear the lowest set bit of the first non-zero byte
                const altered = toHex(RLP.encode([q[0], [[q[1][0][0], bm], q[1][1]]]));
                await expect(verifyQc(c, altered)).rejects.toThrow(/BlsSignatureInvalid|InsufficientStake/);
            });

            it("rejects the live QC against the wrong validator set (stakes or keys of another epoch)", async () => {
                const c = capture[net];
                const blob = hex(c.validatorSet.blob);
                const n = blob.length / 160;
                const q = RLP.decode(hex(c.qc.qcRlp)) as unknown as [Uint8Array[], [[Uint8Array, Uint8Array], Uint8Array]];
                const bits = BigInt(toHex(q[1][0][1]));
                const signed = (i: number) => ((bits >> BigInt(n - 1 - i)) & 1n) === 1n;
                const s0 = [...Array(n).keys()].find(signed)!;
                const u0 = [...Array(n).keys()].find((i) => !signed(i))!;
                // Same keys, most stake moved to a non-signer → the real signers lack 2/3.
                const skewed = Uint8Array.from(blob);
                skewed.set(word(10n ** 30n), u0 * 160 + 128);
                await expect(verifyQc(c, c.qc.qcRlp, c.qc.signatureUncompressed, toHex(skewed))).rejects.toThrow(/InsufficientStake/);
                // Keys of a signer and a non-signer swapped → the aggregate key differs.
                const swapped = Uint8Array.from(blob);
                swapped.set(blob.slice(u0 * 160, u0 * 160 + 128), s0 * 160);
                swapped.set(blob.slice(s0 * 160, s0 * 160 + 128), u0 * 160);
                await expect(verifyQc(c, c.qc.qcRlp, c.qc.signatureUncompressed, toHex(swapped))).rejects.toThrow(/BlsSignatureInvalid/);
            });

            it("rejects an uncompressed signature that does not match the QC's compressed signature", async () => {
                const c = capture[net];
                const other = bls.G2.ProjectivePoint.fromHex(hex(c.qc.signatureCompressed)).double().toAffine();
                const sig = toHex(cat(...[other.x.c0, other.x.c1, other.y.c0, other.y.c1].map((v) => {
                    const b = new Uint8Array(64);
                    for (let i = 0; i < 64; i++) b[63 - i] = Number((v >> BigInt(8 * i)) & 0xffn);
                    return b;
                })));
                await expect(verifyQc(c, c.qc.qcRlp, sig)).rejects.toThrow(/BlsSignatureEncoding/);
            });

            it("staking precompile storage (live) decodes to the published validator set (rotation layout)", () => {
                const c = capture[net];
                const st = c.staking;
                const contractEpoch = BigInt(st.epochWord) >> 192n;
                const inDelay = BigInt(st.inDelayWord) === 1n << 248n;
                // read_valset.cpp: valset_consensus is epoch+1's set in the delay period, else the current set.
                const setEpoch = inDelay ? contractEpoch + 1n : contractEpoch;
                expect(BigInt(st.lengthWord) >> 192n).toBe(BigInt(st.ids.length));
                const decoded = st.ids.map((id, i) => {
                    const [stake, k0, k1, k2] = st.words.slice(4 * i, 4 * i + 4).map((w) => hex(w.slice(2).padStart(64, "0")));
                    const keys = cat(k0, k1, k2);
                    expect(keys.slice(81).every((b) => b === 0)).toBe(true);
                    return {id, secp: toHex(keys.slice(0, 33)), bls: toHex(keys.slice(33, 81)), stake: BigInt(toHex(stake))};
                });
                expect(c.forkpointToml).toContain("high_certificate");
                // Compare with validators.toml's set for that epoch: the set consensus will use (or uses).
                const published = c.validatorSets[setEpoch.toString()];
                expect(published, `validators.toml has epoch ${setEpoch}`).toBeDefined();
                const sorted = [...decoded].sort((a, b) => Buffer.compare(Buffer.from(hex(a.secp)), Buffer.from(hex(b.secp))));
                expect(sorted.map((v) => v.secp)).toEqual(published.map((v) => v.node_id));
                expect(sorted.map((v) => v.bls)).toEqual(published.map((v) => v.cert_pubkey));
                expect(sorted.map((v) => v.stake)).toEqual(published.map((v) => BigInt(v.stake)));
                const blob = cat(...sorted.map((v) => cat(g1Eip2537(g1FromCompressed(hex(v.bls))), word(v.stake))));
                if (setEpoch === BigInt(c.validatorSet.epoch)) expect(keccak256(blob)).toBe(c.validatorSet.blobHash);
                console.log(`[monad-live] ${net}: staking@${st.block} contract epoch ${contractEpoch}, delay period ${inDelay} → ` +
                    `valset_consensus = epoch ${setEpoch} set (${sorted.length} validators) == validators.toml epoch ${setEpoch}`);
            });

            it("delayed-root header: the live Ethereum header RLP hashes to the block hash; fields at the verifier's indices", () => {
                const c = capture[net];
                expect(keccak256(c.ethHeader.raw)).toBe(c.ethHeader.hash);
                const f = RLP.decode(hex(c.ethHeader.raw)) as Uint8Array[];
                expect(toHex(f[3])).toBe(c.ethHeader.stateRoot);
                expect(BigInt(toHex(f[8]))).toBe(BigInt(c.ethHeader.number));
                expect(f.length).toBeGreaterThanOrEqual(15);
            });
        });
    }

    describe("synthetic 196-validator chain on anvil (full verifyBundle + rotation)", () => {
        const meta = JSON.parse(readFileSync(path.join(SYNTH, "meta.json"), "utf8"));
        const load = (name: string) => JSON.parse(readFileSync(path.join(SYNTH, `${name}.json`), "utf8"));
        const call = (proof: Hex, anchor: Hex) => pub.readContract({address: verifier, abi: art.abi as never, functionName: "verifyBundle",
            args: [proof, anchor, meta.channelContext]}) as Promise<[unknown, Hex[], Hex, Hex, unknown]>;
        const gasOf = (proof: Hex, anchor: Hex) => pub.estimateContractGas({address: verifier, abi: art.abi as never, functionName: "verifyBundle",
            args: [proof, anchor, meta.channelContext], account: wallet.account!});

        it("typical bundle, rotation (warm), next-epoch bundle — within Hedera limits", async () => {
            const report: string[] = [];
            const limit = 15_000_000n;
            const ok = load("bundle_ok");
            const g0 = await gasOf(ok.proof, ok.anchor);
            report.push(`typical bundle: ${g0} gas, ${bytes(ok.proof)} B proof`);
            expect(g0).toBeLessThan(limit);
            const start = load("rotation_start");
            let [, , anchor] = await call(start.proof, start.anchor);
            report.push(`rotation start: ${await gasOf(start.proof, start.anchor)} gas, ${bytes(start.proof)} B`);
            for (let i = 0; i < meta.rotationSteps; i++) {
                const st = load(`rotation_step_${i}`);
                const g = await gasOf(st.proof, anchor);
                expect(g).toBeLessThan(limit);
                expect(bytes(st.proof)).toBeLessThan(128 * 1024);
                report.push(`rotation step ${i}: ${g} gas, ${bytes(st.proof)} B`);
                [, , anchor] = await call(st.proof, anchor);
                expect(anchor).toBe(st.anchorAfter);
            }
            expect(anchor).toBe(meta.anchor1);
            const nxt = load("bundle_next_epoch");
            const [, payloads] = await call(nxt.proof, anchor);
            expect(payloads.length).toBe(2);
            console.log("[monad-synthetic] " + report.join(" | "));
        });

        it("every negative case in the fixture reverts with its expected error", async () => {
            const cases = readdirSync(SYNTH).filter((f) => !f.startsWith("rotation_") && f !== "meta.json").map((f) => f.replace(/\.json$/, ""));
            let checked = 0;
            for (const name of cases) {
                const c = load(name);
                if (!c.expect) continue;
                await expect(call(c.proof, c.anchor), name).rejects.toThrow(new RegExp(c.expect));
                checked++;
            }
            expect(checked).toBeGreaterThan(20);
        });
    });
});
