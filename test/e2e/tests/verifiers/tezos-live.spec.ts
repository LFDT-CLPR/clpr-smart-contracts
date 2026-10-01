import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {readFileSync} from "node:fs";
import {resolve} from "node:path";
import {
    createPublicClient,
    createWalletClient,
    decodeAbiParameters,
    encodeFunctionData,
    http,
    type Hex,
    type PublicClient,
    type WalletClient,
} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {loadArtifact} from "../../../../script/deploy/artifacts.js";
import {CACHE_ENTRY_TYPE, FINALITY_TYPE, TEZOS_FIXTURE_DIR} from "../../relay/buildTezosLiveFixture.js";

/// TezosVerifier and EtherlinkCementedState against REAL Tezos mainnet data, replayed offline on
/// anvil from test/e2e/fixtures/tezos-live (re-record with `npm run tezos-live:refresh`).
///
/// One Tenderbake quorum (tz1 Ed25519, tz2 secp256k1, tz3 P-256 and the tz4 BLS aggregate), the
/// attestation rights re-drawn from the real delegate sampler of the attested cycle, the predecessor
/// header and context commit, and context proofs under the finalized state: a tzBTC ledger big_map
/// entry and the Etherlink smart rollup's last cemented commitment. The same quorum is verified from
/// a same-cycle anchor and from an anchor one cycle earlier (the per-cycle rights rotation).
/// No CLPR Service exists on Tezos, so the generic entry points are used; verifyBundle runs the same
/// pipeline plus the CLPR big_map record (Foundry synthetic suite).
///
/// Every measured call is a full transaction (`eth_estimateGas`: intrinsic + calldata + execution)
/// checked against Hedera's 15M gas / 128 KB calldata. Inline: the tz4 aggregate, tz2, tz3 and the
/// largest tz1 signatures in one transaction. Cached: every tz1/tz3 signature recorded first in
/// TezosSignatureCache, then a cheap final transaction.
///
/// Run: forge build && npm run test:e2e:tezos-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8663);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HEDERA_GAS = 15_000_000n;
const HEDERA_CALLDATA = 128 * 1024;

const d = JSON.parse(readFileSync(resolve(TEZOS_FIXTURE_DIR, "mainnet.json"), "utf8")).derived;
const fin = (h: Hex) => decodeAbiParameters(FINALITY_TYPE, h)[0];
const strBytes = (xs: string[]): Hex[] => xs.map((s) => ("0x" + Buffer.from(s, "latin1").toString("hex")) as Hex);

describe("Tezos verifier on live mainnet data (fixture replay)", () => {
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
        const line = `${key}: runtime ${(code!.length - 2) / 2} B`;
        console.log(`[tezos-live] ${line}`);
        results.push(line);
        expect((code!.length - 2) / 2).toBeLessThanOrEqual(24_576);
        addr[key] = r.contractAddress;
        return r.contractAddress;
    }

    function call(key: string, name: string, fn: string, args: unknown[]) {
        return pub.readContract({address: addr[key], abi: loadArtifact(name).abi as never, functionName: fn, args: args as never});
    }

    async function measure(key: string, name: string, fn: string, args: unknown[], label: string) {
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
        console.log(`[tezos-live] ${line}`);
        results.push(line);
        expect(cd).toBeLessThan(HEDERA_CALLDATA);
        expect(gas).toBeLessThan(HEDERA_GAS);
        return gas;
    }

    async function recordCache() {
        const abi = loadArtifact("TezosSignatureCache").abi;
        const gases: bigint[] = [];
        let bytes = 0;
        for (const batch of [...d.cacheEd25519, ...d.cacheP256] as Hex[]) {
            const entries = decodeAbiParameters(CACHE_ENTRY_TYPE, batch)[0];
            bytes = Math.max(bytes, (encodeFunctionData({abi, functionName: "record", args: [entries]} as never).length - 2) / 2);
            const hash = await wallet.writeContract({
                address: addr.TezosSignatureCache,
                abi: abi as never,
                functionName: "record",
                args: [entries] as never,
                account: wallet.account!,
                chain: null,
                gas: 16_000_000n,
            });
            const r = await pub.waitForTransactionReceipt({hash});
            expect(r.status).toBe("success");
            expect(r.gasUsed).toBeLessThan(HEDERA_GAS);
            gases.push(r.gasUsed);
        }
        const line = `cache.record: ${gases.length} tx, gas ${gases.join(" / ")}, max ${bytes} B calldata`;
        console.log(`[tezos-live] ${line}`);
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
        const profile = {
            chainId: d.chainIdBytes,
            protocolLevel: d.protocolLevel,
            eraFirstLevel: d.profile.eraFirstLevel,
            eraFirstCycle: d.profile.eraFirstCycle,
            blocksPerCycle: d.profile.blocksPerCycle,
            committeeSize: d.profile.committeeSize,
            threshold: d.profile.threshold,
        };
        await deploy("Ed25519Verifier");
        await deploy("TezosSignatureCache", [addr.Ed25519Verifier]);
        await deploy("TezosContextVerifier");
        await deploy("TezosVerifier", [
            profile,
            addr.Ed25519Verifier,
            addr.TezosSignatureCache,
            addr.TezosContextVerifier,
            d.caip2,
            "0x01e0d2b0c72e6767ff58e09b4ceb6b77b8ad6e922d00",
            31n,
            d.anchorLevel,
            d.anchorRoot,
        ]);
        await deploy("EtherlinkCementedState", [profile, addr.Ed25519Verifier, addr.TezosSignatureCache, addr.TezosContextVerifier, d.etherlink.rollupHex]);
    }, 120_000);

    afterAll(() => {
        console.log(`[tezos-live] summary (Tezos mainnet level ${d.level}, cycle ${d.cycle})\n  ${results.join("\n  ")}`);
        anvil?.kill("SIGTERM");
    });

    const tzbtc = () => [strBytes(d.tzbtc.steps), d.tzbtc.proof];

    it("verifies a real quorum and a tzBTC big_map entry in one transaction (inline signatures)", async () => {
        const args = [fin(d.finalityInline), d.anchor, ...tzbtc()];
        const [value, na] = (await call("TezosVerifier", "TezosVerifier", "verifyContextValue", args)) as [Hex, Hex];
        expect(value).toBe(d.tzbtc.value);
        expect(na).toBe(d.newAnchor);
        await measure("TezosVerifier", "TezosVerifier", "verifyContextValue", args, "bundle, inline signatures");
    });

    it("rotates the anchor across a cycle boundary (inline signatures)", async () => {
        const args = [fin(d.finalityRotationInline), d.prevAnchor, ...tzbtc()];
        const [value, na] = (await call("TezosVerifier", "TezosVerifier", "verifyContextValue", args)) as [Hex, Hex];
        expect(value).toBe(d.tzbtc.value);
        expect(na).toBe(d.newAnchor);
        await measure("TezosVerifier", "TezosVerifier", "verifyContextValue", args, `rotation cycle ${d.prevAnchorCycle}→${d.cycle}, inline`);
    });

    it("proves Etherlink's last cemented commitment (PVM state hash) from the same quorum", async () => {
        const args = [fin(d.finalityInline), d.anchor, d.etherlink.lccProof, d.etherlink.commitmentProof];
        const [stateHash, inboxLevel] = (await call("EtherlinkCementedState", "EtherlinkCementedState", "verifyCementedState", args)) as [Hex, number];
        expect(stateHash).toBe(d.etherlink.compressedState);
        expect(Number(inboxLevel)).toBe(d.etherlink.inboxLevel);
        await measure("EtherlinkCementedState", "EtherlinkCementedState", "verifyCementedState", args, "Etherlink cemented state, inline");
    });

    it("splits tz1/tz3 signatures through TezosSignatureCache", async () => {
        await recordCache();
        const args = [fin(d.finalityCached), d.anchor, ...tzbtc()];
        const [value] = (await call("TezosVerifier", "TezosVerifier", "verifyContextValue", args)) as [Hex, Hex];
        expect(value).toBe(d.tzbtc.value);
        await measure("TezosVerifier", "TezosVerifier", "verifyContextValue", args, "bundle, cached tz1/tz3");
        const rot = [fin(d.finalityRotationCached), d.prevAnchor, ...tzbtc()];
        await measure("TezosVerifier", "TezosVerifier", "verifyContextValue", rot, "rotation, cached tz1/tz3");
    });
});
