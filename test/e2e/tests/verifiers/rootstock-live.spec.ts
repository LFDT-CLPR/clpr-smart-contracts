import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {readFileSync} from "node:fs";
import {createPublicClient, createWalletClient, decodeAbiParameters, encodeFunctionData, http, keccak256, type Hex,
    type PublicClient, type WalletClient} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {loadArtifact} from "../../../../script/deploy/artifacts.js";
import {ANCHOR_ABI, checkpointOf, encodeAnchor, encodeBundleProof, encodeConfigProof, MAINNET_FIXTURE, minedHeaders,
    REGTEST_FIXTURE, sampleBundleContent, type MainnetCapture, type RegtestCapture} from "../../relay/buildRootstockProof.js";

/// RootstockVerifier against recorded live data, replayed on anvil
/// (re-capture: `npm run rootstock-live:refresh` and `npm run rootstock-live:refresh-regtest`).
///   - mainnet.json: real RSK mainnet headers → merged-mining PoW (bitcoin header at RSK difficulty,
///     SHA-256 midstate coinbase, RSKIP92 branch, RSKIP110 fork-detection bytes) and the difficulty rule;
///   - regtest.json: a real RSKj node; full verifyConfig + verifyBundle with Unitrie proofs from its trie.
/// Run: forge build && npm run test:e2e:rootstock-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8641);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HEDERA_GAS = 15_000_000n;
const HEDERA_CALLDATA = 128 * 1024;

const mainnet = JSON.parse(readFileSync(MAINNET_FIXTURE, "utf8")) as MainnetCapture;
const regtest = JSON.parse(readFileSync(REGTEST_FIXTURE, "utf8")) as RegtestCapture;

const MAINNET_PARAMS = {chainId: "eip155:30", confirmations: 12n, minDifficulty: 7_000_000_000_000_000n, difficultyDivisor: 400n,
    durationLimit: 14n, forkDetectionFrom: 1_591_000n, maxBtcTimestampDiff: 300n};
const REGTEST_PARAMS = {chainId: "eip155:33", confirmations: 3n, minDifficulty: 1n, difficultyDivisor: 2048n,
    durationLimit: 10n, forkDetectionFrom: 0n, maxBtcTimestampDiff: 0n};

describe("RootstockVerifier on live data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    const abi = loadArtifact("RootstockVerifier").abi;
    let mainnetVerifier: Hex;
    let regtestVerifier: Hex;

    async function deploy(args: unknown[]): Promise<Hex> {
        const art = loadArtifact("RootstockVerifier");
        const hash = await wallet.deployContract({abi: art.abi as never, bytecode: art.bytecode, args: args as never,
            account: wallet.account!, chain: null});
        const r = await pub.waitForTransactionReceipt({hash});
        const code = await pub.getCode({address: r.contractAddress!});
        console.log(`[rootstock-live] RootstockVerifier runtime ${(code!.length - 2) / 2} B`);
        return r.contractAddress!;
    }

    const call = (address: Hex, fn: string, args: unknown[]) =>
        pub.readContract({address, abi: abi as never, functionName: fn, args: args as never});

    async function measure(address: Hex, fn: string, args: unknown[], label: string) {
        const gas = await pub.estimateContractGas({address, abi: abi as never, functionName: fn, args: args as never,
            account: wallet.account!});
        const cd = (encodeFunctionData({abi, functionName: fn, args} as never).length - 2) / 2;
        console.log(`[rootstock-live] ${label}: eth_estimateGas ${gas}, calldata ${cd} B`);
        expect(gas).toBeLessThan(HEDERA_GAS);
        expect(cd).toBeLessThan(HEDERA_CALLDATA);
    }

    beforeAll(async () => {
        anvil = spawn("anvil", ["--port", String(ANVIL_PORT), "--silent", "--code-size-limit", "24576"], {stdio: "ignore"});
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
        mainnetVerifier = await deploy([MAINNET_PARAMS, checkpointOf(mainnet.checkpoint)]);
        regtestVerifier = await deploy([REGTEST_PARAMS, checkpointOf(regtest.checkpoint)]);
    });

    afterAll(() => {
        anvil?.kill("SIGTERM");
    });

    describe("mainnet headers", () => {
        it("follows 40 real merged-mined headers to the k-final checkpoint", async () => {
            const f = await call(mainnetVerifier, "verifyHeaders", [checkpointOf(mainnet.checkpoint), minedHeaders(mainnet.headers)]) as
                {blockHash: Hex; number: bigint};
            expect(f.number).toBe(BigInt(mainnet.checkpoint.number + 40 - 12 + 1));
            expect(f.blockHash).toBe(mainnet.headers[40 - 12].hash);
            await measure(mainnetVerifier, "verifyHeaders", [checkpointOf(mainnet.checkpoint), minedHeaders(mainnet.headers)],
                "40 mainnet headers");
            await measure(mainnetVerifier, "verifyHeaders", [checkpointOf(mainnet.checkpoint), minedHeaders(mainnet.headers.slice(0, 12))],
                "12 mainnet headers (k = 12)");
        });

        it("extend records the k-final checkpoint of 40 real headers (catch-up, real transaction)", async () => {
            const args = [checkpointOf(mainnet.checkpoint), minedHeaders(mainnet.headers)];
            const hash = await wallet.writeContract({address: mainnetVerifier, abi: abi as never, functionName: "extend",
                args: args as never, account: wallet.account!, chain: null, gas: 14_000_000n});
            const r = await pub.waitForTransactionReceipt({hash});
            expect(r.status).toBe("success");
            const cd = (encodeFunctionData({abi, functionName: "extend", args} as never).length - 2) / 2;
            console.log(`[rootstock-live] extend, 40 mainnet headers: gasUsed ${r.gasUsed}, calldata ${cd} B`);
            expect(r.gasUsed).toBeLessThan(HEDERA_GAS);
            expect(cd).toBeLessThan(HEDERA_CALLDATA);
        });

        it("rejects a header whose bitcoin nonce was changed", async () => {
            const hs = minedHeaders(mainnet.headers.slice(0, 12));
            const h = hs[11].header;
            hs[11] = {...hs[11], header: (h.slice(0, -2) + (parseInt(h.slice(-2), 16) ^ 1).toString(16).padStart(2, "0")) as Hex};
            await expect(call(mainnetVerifier, "verifyHeaders", [checkpointOf(mainnet.checkpoint), hs])).rejects.toThrow();
        });
    });

    describe("regtest CLPR bundle", () => {
        const runtimeHash = keccak256(`0x${"fe".repeat(64)}`);
        const ctx = (channelId: Hex) => (channelId + regtest.service.slice(2)) as Hex;
        const bundle = () => encodeBundleProof({headers: regtest.headers, stateIndex: 0, codeProof: regtest.proofs!.code,
            slotProofs: regtest.proofs!.slots, bundleContent: sampleBundleContent(), manifestPreimage: "0x", manifestProof: []});

        it("verifyConfig anchors k-final and reads the code hash from the Unitrie", async () => {
            const cfg = encodeConfigProof({headers: regtest.headers, stateIndex: 0, service: regtest.service,
                codeProof: regtest.proofs!.code, peerConfigNanos: 1n});
            const res = await call(regtestVerifier, "verifyConfig", [cfg, regtest.channelId, "0x"]) as unknown[];
            expect(res[1]).toBe("eip155:33");
            const [a] = decodeAbiParameters(ANCHOR_ABI, res[5] as Hex) as unknown as [{codeHash: Hex}];
            expect(a.codeHash).toBe(runtimeHash);
        });

        it("verifyBundle proves the Channel record through RSK's Unitrie", async () => {
            const anchor = encodeAnchor(checkpointOf(regtest.checkpoint), runtimeHash);
            const res = await call(regtestVerifier, "verifyBundle", [bundle(), anchor, ctx(regtest.channelId)]) as
                [{nextMessageId: bigint; receivedMessageId: bigint; state: number; endpointManifestVersion: bigint}, Hex[]];
            expect(res[0].nextMessageId).toBe(3n);
            expect(res[0].receivedMessageId).toBe(2n);
            expect(res[0].state).toBe(1);
            expect(res[0].endpointManifestVersion).toBe(0n);
            expect(res[1].length).toBe(2);
            await measure(regtestVerifier, "verifyBundle", [bundle(), anchor, ctx(regtest.channelId)], "regtest bundle");
        });

        it("rejects the bundle for another channel", async () => {
            const anchor = encodeAnchor(checkpointOf(regtest.checkpoint), runtimeHash);
            await expect(call(regtestVerifier, "verifyBundle", [bundle(), anchor, ctx(keccak256("0x01"))])).rejects.toThrow();
        });
    });
});
