import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {readFileSync} from "node:fs";
import {resolve} from "node:path";
import {
    createPublicClient,
    createWalletClient,
    encodeFunctionData,
    http,
    type Hex,
    type PublicClient,
    type WalletClient,
} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {loadArtifact} from "../../../../script/deploy/artifacts.js";
import {NEAR_FIXTURE_DIR} from "../../relay/buildNearLiveFixture.js";
import {TON_FIXTURE_DIR} from "../../relay/buildTonLiveFixture.js";
import {AURORA_FIXTURE_DIR} from "../../relay/buildAuroraLiveFixture.js";

/// NearVerifier, TonVerifier and AuroraVerifier against REAL NEAR, TON and Aurora data, replayed
/// offline on anvil from test/e2e/fixtures/{near,ton,aurora}-live (re-record with
/// `npm run neartons-live:refresh`).
///
/// NEAR: a real light-client block (100 / 20 block producers) and a real view_state trie proof; the
/// same block verified from the epoch-E anchor and from the epoch-(E−1) anchor (real rotation).
/// TON: a real Simplex-finalized masterchain block (100 / 15 masterchain validators), a real key-block
/// rotation (ConfigParam 34) and a real basechain account proof (mc state → shard block → shard state
/// → account). Aurora: the same NEAR light client plus EVM storage slots of an ERC-20 inside a real
/// aurora-engine deployment (Aurora Cloud silo `0x4e45415c.c.aurora` on NEAR mainnet), four set and
/// two proven absent, under the contract's storage generation. No CLPR Service exists on these chains, so the generic entry points are used;
/// verifyBundle runs the same pipeline plus the CLPR record (Foundry synthetic suites).
///
/// Every measured call is a full transaction (`eth_estimateGas`: intrinsic + calldata + execution)
/// checked against Hedera's 15M gas / 128 KB calldata. Mainnet certificates exceed one transaction's
/// Ed25519 budget, so their signatures are first recorded in ClprEd25519SignatureCache (≤ 20 per tx).
///
/// Run: forge build && npm run test:e2e:neartons-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8653);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HEDERA_GAS = 15_000_000n;
const HEDERA_CALLDATA = 128 * 1024;

const load = (dir: string, net: string) => JSON.parse(readFileSync(resolve(dir, `${net}.json`), "utf8")).derived;

describe("NEAR and TON verifiers on live data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    const addr: Record<string, Hex> = {};
    const results: string[] = [];

    async function deploy(name: string, args: unknown[] = [], key = name): Promise<Hex> {
        const art = loadArtifact(name);
        const hash = await wallet.deployContract({
            abi: art.abi as never,
            bytecode: art.bytecode,
            args: args as never,
            account: wallet.account!,
            chain: null,
        });
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error(`deploy ${name}`);
        const code = await pub.getCode({address: r.contractAddress});
        console.log(`[neartons-live] ${key}: runtime ${(code!.length - 2) / 2} B`);
        addr[key] = r.contractAddress;
        return r.contractAddress;
    }

    function call(key: string, name: string, fn: string, args: unknown[]) {
        return pub.readContract({address: addr[key], abi: loadArtifact(name).abi as never, functionName: fn, args: args as never});
    }

    async function measure(key: string, name: string, fn: string, args: unknown[], label: string, fits = true) {
        const abi = loadArtifact(name).abi;
        const gas = await pub.estimateContractGas({
            address: addr[key],
            abi: abi as never,
            functionName: fn,
            args: args as never,
            account: wallet.account!,
        });
        const cd = (encodeFunctionData({abi, functionName: fn, args} as never).length - 2) / 2;
        const line = `${label}: ${gas} gas, ${cd} B calldata`;
        console.log(`[neartons-live] ${line}`);
        results.push(line);
        expect(cd).toBeLessThan(HEDERA_CALLDATA);
        if (fits) expect(gas).toBeLessThan(HEDERA_GAS);
        return gas;
    }

    /// Record signatures in the cache as real transactions (≤ 20 per tx); returns the gas of each.
    async function record(batches: {message: Hex; keys: Hex[]; sigs: Hex[]}[], label: string) {
        const abi = loadArtifact("ClprEd25519SignatureCache").abi;
        const gases: bigint[] = [];
        for (const b of batches) {
            const args = [b.message, b.keys, ("0x" + b.sigs.map((s) => s.slice(2)).join("")) as Hex];
            const hash = await wallet.writeContract({
                address: addr.ClprEd25519SignatureCache,
                abi: abi as never,
                functionName: "record",
                args: args as never,
                account: wallet.account!,
                chain: null,
                gas: 16_000_000n,
            });
            const r = await pub.waitForTransactionReceipt({hash});
            expect(r.status).toBe("success");
            expect(r.gasUsed).toBeLessThan(HEDERA_GAS);
            gases.push(r.gasUsed);
        }
        const line = `${label}: ${gases.length} tx, gas ${gases.join(" / ")}`;
        console.log(`[neartons-live] ${line}`);
        results.push(line);
    }

    beforeAll(async () => {
        anvil = spawn(
            "anvil",
            ["--port", String(ANVIL_PORT), "--silent", "--code-size-limit", "24576", "--gas-limit", "100000000"],
            {stdio: "ignore"},
        );
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
        await deploy("Ed25519Verifier");
        await deploy("ClprEd25519SignatureCache", [addr.Ed25519Verifier]);
    });

    afterAll(() => {
        console.log(`[neartons-live] summary\n  ${results.join("\n  ")}`);
        anvil?.kill("SIGTERM");
    });

    for (const net of ["testnet", "mainnet"]) {
        describe(`NEAR ${net}`, () => {
            const d = load(NEAR_FIXTURE_DIR, net);
            const key = `NearVerifier_${net}`;
            const cached = net === "mainnet";
            const proof = cached ? d.stateProofCached : d.stateProof;

            beforeAll(async () => {
                await deploy("NearVerifier", [d.chainId, d.checkpointPrev, addr.Ed25519Verifier, addr.ClprEd25519SignatureCache], key);
                if (cached) {
                    const batches = [];
                    for (let i = 0; i < d.signerKeys.length; i += 20) {
                        batches.push({message: d.message, keys: d.signerKeys.slice(i, i + 20), sigs: d.signerSignatures.slice(i, i + 20)});
                    }
                    await record(batches, `NEAR ${net}: pre-record ${d.signerKeys.length} approvals`);
                }
            });

            it(`light-client block + trie proof (${d.meta.chosenSigners} of ${d.meta.producers} producers, ${d.meta.shards} shards)`, async () => {
                const [value, h, , na] = (await call(key, "NearVerifier", "verifyStateValue", [proof, d.anchorCur])) as [Hex, Hex, bigint, Hex];
                expect(value).toBe(d.value);
                expect(h).toBe(d.lcHash);
                expect(na).toBe("0x");
                await measure(key, "NearVerifier", "verifyStateValue", [proof, d.anchorCur], `NEAR ${net} state proof${cached ? " (cached sigs)" : ""}`);
            });

            it("the same block from the previous epoch's anchor rotates it (real epoch change)", async () => {
                const [, , , na] = (await call(key, "NearVerifier", "verifyStateValue", [proof, d.anchorPrev])) as [Hex, Hex, bigint, Hex];
                expect(na).toBe(d.anchorCur);
                await measure(key, "NearVerifier", "verifyStateValue", [proof, d.anchorPrev], `NEAR ${net} state proof + epoch rotation${cached ? " (cached sigs)" : ""}`);
            });

            it("rejects a tampered value", async () => {
                const bad = proof.replace(d.value.slice(2), d.value.slice(2, -2) + (d.value.endsWith("00") ? "01" : "00"));
                await expect(call(key, "NearVerifier", "verifyStateValue", [bad, d.anchorCur])).rejects.toThrow();
            });

            if (!cached) {
                it("mainnet-scale inline approvals do not fit one transaction (why the cache exists)", async () => {
                    const m = load(NEAR_FIXTURE_DIR, "mainnet");
                    await deploy("NearVerifier", [m.chainId, m.checkpointPrev, addr.Ed25519Verifier, addr.ClprEd25519SignatureCache], "NearVerifier_mainnet_inline");
                    const g = await measure("NearVerifier_mainnet_inline", "NearVerifier", "verifyStateValue", [m.stateProof, m.anchorCur], `NEAR mainnet state proof, ${m.meta.chosenSigners} inline approvals`, false);
                    expect(g).toBeGreaterThan(HEDERA_GAS);
                });
            }
        });
    }

    describe("Aurora (silo engine on NEAR mainnet)", () => {
        const d = load(AURORA_FIXTURE_DIR, "mainnet");
        const key = "AuroraVerifier";

        beforeAll(async () => {
            await deploy(
                "AuroraVerifier",
                [d.chainId, d.checkpointPrev, addr.Ed25519Verifier, addr.ClprEd25519SignatureCache, ("0x" + Buffer.from(d.engineAccount).toString("hex")) as Hex, BigInt(d.evmChainId)],
                key,
            );
            const batches = [];
            for (let i = 0; i < d.signerKeys.length; i += 20) {
                batches.push({message: d.message, keys: d.signerKeys.slice(i, i + 20), sigs: d.signerSignatures.slice(i, i + 20)});
            }
            await record(batches, `Aurora: pre-record ${d.signerKeys.length} NEAR approvals`);
        });

        it(`light-client block + engine state + generation + 6 slots (${d.meta.chosenSigners} of ${d.meta.producers} producers)`, async () => {
            const [values, gen, h, , na] = (await call(key, "AuroraVerifier", "verifyEvmStorage", [d.storageProofCached, d.anchorCur])) as [Hex[], number, Hex, bigint, Hex];
            expect(values).toEqual(d.tokenValues);
            expect(gen).toBe(d.tokenGeneration);
            expect(h).toBe(d.lcHash);
            expect(na).toBe("0x");
            await measure(key, "AuroraVerifier", "verifyEvmStorage", [d.storageProofCached, d.anchorCur], "Aurora 6-slot storage proof (cached sigs)");
        });

        it("the same block from the previous epoch's anchor rotates it", async () => {
            const [, , , , na] = (await call(key, "AuroraVerifier", "verifyEvmStorage", [d.storageProofCached, d.anchorPrev])) as [Hex[], number, Hex, bigint, Hex];
            expect(na).toBe(d.anchorCur);
            await measure(key, "AuroraVerifier", "verifyEvmStorage", [d.storageProofCached, d.anchorPrev], "Aurora 6-slot storage proof + epoch rotation (cached sigs)");
        });

        it("an EOA: generation 0 and an absent slot (exclusion proofs)", async () => {
            const [values, gen] = (await call(key, "AuroraVerifier", "verifyEvmStorage", [d.eoaProofCached, d.anchorCur])) as [Hex[], number];
            expect(gen).toBe(0);
            expect(values).toEqual(["0x" + "00".repeat(32)]);
        });

        it("inline approvals: measured against one transaction", async () => {
            await measure(key, "AuroraVerifier", "verifyEvmStorage", [d.storageProof, d.anchorCur], `Aurora 6-slot storage proof, ${d.meta.chosenSigners} inline approvals`, false);
        });

        it("rejects a tampered slot value", async () => {
            const v = d.tokenValues[0].slice(2);
            const forged = v.slice(0, -2) + (v.endsWith("00") ? "01" : "00");
            const bad = d.storageProofCached.replace(v, forged);
            expect(bad).not.toBe(d.storageProofCached);
            await expect(call(key, "AuroraVerifier", "verifyEvmStorage", [bad, d.anchorCur])).rejects.toThrow();
        });
    });

    for (const net of ["testnet", "mainnet"]) {
        describe(`TON ${net}`, () => {
            const d = load(TON_FIXTURE_DIR, net);
            const key = `TonVerifier_${net}`;
            const cached = net === "mainnet";
            const blk = cached ? d.blockCached : d.block;
            const kb = cached ? d.keyBlocksCached : d.keyBlocks;

            beforeAll(async () => {
                const prevSeq = Number.parseInt(d.anchorPrev.slice(2, 10), 16);
                await deploy("TonVerifier", [d.chainId, prevSeq, "0x" + d.anchorPrev.slice(10), addr.Ed25519Verifier, addr.ClprEd25519SignatureCache], key);
                if (cached) await record(d.cacheBatches, `TON ${net}: pre-record ${d.meta.signersK} + ${d.meta.signersL} signatures`);
            });

            it(`Simplex-finalized masterchain block + account proof (${d.meta.signersL} of ${d.meta.mcValidatorsCur} validators)`, async () => {
                const args = [d.validatorsCur, "0x", blk, d.stateChain, d.serviceAddress, d.anchorCur];
                const [dh, seq, na] = (await call(key, "TonVerifier", "verifyAccountData", args)) as [Hex, number, Hex];
                expect(dh).toBe(d.dataHash);
                expect(seq).toBe(d.seqno);
                expect(na).toBe("0x");
                await measure(key, "TonVerifier", "verifyAccountData", args, `TON ${net} block + account proof${cached ? " (cached sigs)" : ""}`);
            });

            it("a real key block rotates the anchor (ConfigParam 34)", async () => {
                const args = [d.validatorsPrev, kb, blk, d.stateChain, d.serviceAddress, d.anchorPrev];
                const [dh, , na] = (await call(key, "TonVerifier", "verifyAccountData", args)) as [Hex, number, Hex];
                expect(na).toBe(d.anchorCur);
                expect(dh).toBe(d.dataHash);
                // testnet signs both blocks inline (2 × 10 signatures): 14.5M, too close to 15M, so the relay can cache one set
                await measure(key, "TonVerifier", "verifyAccountData", args, `TON ${net} key-block rotation + block + account proof${cached ? " (cached sigs)" : " (inline sigs)"}`, cached);
                if (!cached) {
                    // one pre-recorded transaction for the key block's signatures brings it under 15M
                    await record([d.cacheBatches[0]], `TON ${net}: pre-record the key block's ${d.meta.signersK} signatures`);
                    const args2 = [d.validatorsPrev, d.keyBlocksCached, d.block, d.stateChain, d.serviceAddress, d.anchorPrev];
                    await measure(key, "TonVerifier", "verifyAccountData", args2, `TON ${net} key-block rotation (cached) + block (inline) + account proof`);
                }
            });

            it("rejects the block against the wrong validator list", async () => {
                // mainnet's recorded key block kept the same validator set, so tamper one weight there
                const wrong: Hex =
                    d.validatorsPrev !== d.validatorsCur
                        ? d.validatorsPrev
                        : ((d.validatorsCur.slice(0, -2) + (d.validatorsCur.endsWith("00") ? "01" : "00")) as Hex);
                const args = [wrong, "0x", blk, d.stateChain, d.serviceAddress, d.anchorCur];
                await expect(call(key, "TonVerifier", "verifyAccountData", args)).rejects.toThrow();
            });
        });
    }
});
