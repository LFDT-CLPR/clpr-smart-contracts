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

/// MvxMetachainVerifier against REAL MultiversX mainnet blocks, replayed offline on anvil from
/// test/e2e/fixtures/mvx-live/mainnet.json (re-record with `npm run mvx-live:refresh`):
///   - a metachain header: BLAKE2b-256(raw header) and its equivalent proof, an aggregated herumi BLS
///     signature of > 2/3 of the 400 metachain eligible validators
///   - a shard-0 header proof (400 shard-0 eligible validators)
///   - the leader's single signature over the previous random seed
/// The eligible lists are pinned at deployment (the API's ordered list for the block): proving them
/// from the previous epoch and proving contract storage are not possible with public endpoints.
///
/// Run: forge build && npm run test:e2e:mvx-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8664);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HEDERA_GAS = 15_000_000n;
const HEDERA_CALLDATA = 128 * 1024;

const fx = JSON.parse(readFileSync(resolve("test/e2e/fixtures/mvx-live/mainnet.json"), "utf8"));
const cat = (ks: Hex[]) => ("0x" + ks.map((k) => k.slice(2)).join("")) as Hex;

describe("MultiversX header proofs on live mainnet data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    const addr: Record<string, Hex> = {};
    const abi = loadArtifact("MvxMetachainVerifier").abi;
    const results: string[] = [];

    const call = (key: string, fn: string, args: unknown[]) =>
        pub.readContract({address: addr[key], abi: abi as never, functionName: fn, args: args as never});

    async function measure(key: string, fn: string, args: unknown[], label: string) {
        const gas = await pub.estimateContractGas({
            address: addr[key],
            abi: abi as never,
            functionName: fn,
            args: args as never,
            account: wallet.account!,
        });
        const cd = (encodeFunctionData({abi, functionName: fn, args} as never).length - 2) / 2;
        const line = `${label}: ${gas} gas, ${cd} B calldata`;
        console.log(`[mvx-live] ${line}`);
        results.push(line);
        expect(gas).toBeLessThan(HEDERA_GAS);
        expect(cd).toBeLessThan(HEDERA_CALLDATA);
    }

    async function deploy(key: string, c: {epoch: number; eligible: number; keysHash: Hex}) {
        const art = loadArtifact("MvxMetachainVerifier");
        const hash = await wallet.deployContract({
            abi: art.abi as never,
            bytecode: art.bytecode,
            args: [c.epoch, BigInt(c.eligible), c.keysHash] as never,
            account: wallet.account!,
            chain: null,
        });
        const r = await pub.waitForTransactionReceipt({hash});
        addr[key] = r.contractAddress!;
        const code = await pub.getCode({address: addr[key]});
        console.log(`[mvx-live] ${key}: runtime ${(code!.length - 2) / 2} B`);
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
        await deploy("meta", fx.meta);
        await deploy("shard0", fx.shard0);
    });

    afterAll(() => {
        console.log(`[mvx-live] summary (recorded ${fx.recordedAt})\n  ${results.join("\n  ")}`);
        anvil?.kill("SIGTERM");
    });

    it("metachain header + proof", async () => {
        const m = fx.meta;
        const args = [m.rawHeader, m.bitmap, m.signature, cat(m.keys)];
        const [hh, nonce, signers] = (await call("meta", "verifyHeader", args)) as [Hex, bigint, bigint];
        expect(hh).toBe(m.headerHash);
        expect(nonce).toBe(BigInt(m.nonce));
        expect(signers).toBe(BigInt(m.signers));
        await measure("meta", "verifyHeader", args, `metachain header ${m.nonce} (${m.signers}/${m.eligible} signers)`);
    });

    it("shard-0 header proof", async () => {
        const s = fx.shard0;
        const args = [s.headerHash, s.bitmap, s.signature, cat(s.keys)];
        expect(await call("shard0", "verifyHeaderHash", args)).toBe(BigInt(s.signers));
        await measure("shard0", "verifyHeaderHash", args, `shard 0 header ${s.nonce} (${s.signers}/${s.eligible} signers)`);
    });

    it("leader signature over the previous random seed", async () => {
        const l = fx.meta.leader;
        const args = [l.key, l.signature, l.message];
        expect(await call("meta", "verifySignature", args)).toBe(true);
        await measure("meta", "verifySignature", args, "single signature (leader randSeed)");
    });

    it("rejects the metachain proof against the shard-0 eligible list", async () => {
        const m = fx.meta;
        await expect(call("meta", "verifyHeaderHash", [m.headerHash, m.bitmap, m.signature, cat(fx.shard0.keys)])).rejects.toThrow();
    });

    it("rejects a tampered header", async () => {
        const m = fx.meta;
        const raw = m.rawHeader as string;
        const bad = (raw.slice(0, -2) + (raw.endsWith("00") ? "01" : "00")) as Hex;
        await expect(call("meta", "verifyHeader", [bad, m.bitmap, m.signature, cat(m.keys)])).rejects.toThrow();
    });
});
