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

/// IcpVerifier against REAL Internet Computer mainnet certificates, replayed offline on anvil from
/// test/e2e/fixtures/icp-live/mainnet.json (re-record with `npm run icp-live:refresh`).
///
///   - a data certificate of the ckBTC ledger (icrc3_get_tip_certificate): NNS root key → delegation →
///     subnet key → /canister/<ledger>/certified_data → the ledger's witness tree → last_block_hash
///   - a read_state (v3) certificate whose delegation scopes the subnet with a /canister_ranges shard
///   - a read_state certificate of the NNS subnet, signed by the root key (no delegation)
///
/// No CLPR canister exists on ICP, so the generic entry points are used; verifyBundle runs the same
/// certificate and witness pipeline plus the CLPR queue record (Foundry synthetic suites).
///
/// Every measured call is a full transaction estimate (intrinsic + calldata + execution) checked
/// against Hedera's 15M gas / 128 KB calldata.
///
/// Run: forge build && npm run test:e2e:icp-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8663);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HEDERA_GAS = 15_000_000n;
const HEDERA_CALLDATA = 128 * 1024;
const ONE_DAY_NANOS = 86_400n * 1_000_000_000n;

const fx = JSON.parse(readFileSync(resolve("test/e2e/fixtures/icp-live/mainnet.json"), "utf8"));

describe("IcpVerifier on live Internet Computer mainnet certificates (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let verifier: Hex;
    const abi = loadArtifact("IcpVerifier").abi;
    const results: string[] = [];

    const call = (fn: string, args: unknown[]) =>
        pub.readContract({address: verifier, abi: abi as never, functionName: fn, args: args as never});

    async function measure(fn: string, args: unknown[], label: string) {
        const gas = await pub.estimateContractGas({
            address: verifier,
            abi: abi as never,
            functionName: fn,
            args: args as never,
            account: wallet.account!,
        });
        const cd = (encodeFunctionData({abi, functionName: fn, args} as never).length - 2) / 2;
        const line = `${label}: ${gas} gas, ${cd} B calldata`;
        console.log(`[icp-live] ${line}`);
        results.push(line);
        expect(gas).toBeLessThan(HEDERA_GAS);
        expect(cd).toBeLessThan(HEDERA_CALLDATA);
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
        const art = loadArtifact("IcpVerifier");
        const hash = await wallet.deployContract({
            abi: art.abi as never,
            bytecode: art.bytecode,
            args: ["icp:mainnet", fx.rootKeyDer, fx.rootKeyUncompressed, ONE_DAY_NANOS] as never,
            account: wallet.account!,
            chain: null,
        });
        const r = await pub.waitForTransactionReceipt({hash});
        verifier = r.contractAddress!;
        const code = await pub.getCode({address: verifier});
        console.log(`[icp-live] IcpVerifier runtime ${(code!.length - 2) / 2} B, deploy gas ${r.gasUsed}`);
    });

    afterAll(() => {
        console.log(`[icp-live] summary (recorded ${fx.recordedAt})\n  ${results.join("\n  ")}`);
        anvil?.kill("SIGTERM");
    });

    it("ckBTC ledger data certificate + witness → last_block_hash", async () => {
        const d = fx.dataCertificate;
        const args = [d.certificate, d.canisterId, d.witness, d.path];
        const [value, time] = (await call("verifyCertifiedValue", args)) as [Hex, bigint];
        expect(value).toBe(d.value);
        expect(time).toBe(BigInt(d.time));
        await measure("verifyCertifiedValue", args, `ckBTC data certificate (tip ${d.lastBlockIndex})`);
    });

    it("read_state v3 certificate, delegation scoped by a /canister_ranges shard", async () => {
        const d = fx.readStateDelegatedSharded;
        const args = [d.certificate, d.canisterId, d.path];
        const [value] = (await call("verifyStateValue", args)) as [Hex, bigint];
        expect(value).toBe(d.value);
        await measure("verifyStateValue", args, "read_state v3 (sharded canister ranges)");
    });

    it("read_state certificate of the NNS subnet, signed by the root key", async () => {
        const d = fx.readStateRootSubnet;
        const args = [d.certificate, d.canisterId, d.path];
        const [value] = (await call("verifyStateValue", args)) as [Hex, bigint];
        expect(value).toBe(d.value);
        await measure("verifyStateValue", args, "read_state root subnet (no delegation)");
    });

    it("rejects a tampered witness", async () => {
        const d = fx.dataCertificate;
        const w = d.witness as string;
        const bad = (w.slice(0, -2) + (w.endsWith("00") ? "01" : "00")) as Hex;
        await expect(call("verifyCertifiedValue", [d.certificate, d.canisterId, bad, d.path])).rejects.toThrow();
    });

    it("rejects a canister outside the delegated subnet's ranges", async () => {
        const d = fx.readStateDelegatedSharded;
        await expect(call("verifyStateValue", [d.certificate, fx.readStateRootSubnet.canisterId, d.path])).rejects.toThrow();
    });
});
