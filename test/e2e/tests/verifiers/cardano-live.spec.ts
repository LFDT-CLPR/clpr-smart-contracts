import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {createPublicClient, createWalletClient, encodeFunctionData, http, type Hex, type PublicClient, type WalletClient} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {loadArtifact} from "../../../../script/deploy/artifacts.js";
import {
    buildMainnet,
    buildPreprod,
    loadCapture,
    type CardanoLiveProof,
    type MainnetCapture,
    type PreprodCapture,
} from "../../relay/buildCardanoLiveProof.js";

/// CardanoMithrilVerifier against REAL Mithril + Cardano data, replayed offline on anvil from
/// test/e2e/fixtures/cardano-live/{preprod,mainnet}.json (re-capture with `npm run cardano-live:refresh`).
///
/// preprod: anchor = the real epoch-e aggregate key; the proof carries the real epoch-e certificate
/// (rotation to e+1), a real CardanoBlocksTransactions certificate of e+1, the aggregator's MKMap proof,
/// the real block (Ouroboros BlockFetch from a public relay) and the transaction body; the verifier must
/// return exactly the real output. mainnet: real 57-signer certificates (k = 1944) with and without
/// rotation. No CLPR Plutus script exists yet, so the generic entry points are used; verifyBundle runs
/// the same pipeline plus the queue-datum checks (Foundry tests).
///
/// Run: forge build && npm run test:e2e:cardano-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8641);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HEDERA_GAS = 15_000_000n;
const HEDERA_CALLDATA = 128 * 1024;

describe("CardanoMithrilVerifier on live Mithril data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    const addr: Record<string, Hex> = {};
    let pp: CardanoLiveProof;
    let mn: ReturnType<typeof buildMainnet>;

    async function deploy(name: string, args: unknown[] = []): Promise<Hex> {
        const art = loadArtifact(name);
        const hash = await wallet.deployContract({abi: art.abi as never, bytecode: art.bytecode, args: args as never,
            account: wallet.account!, chain: null});
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error(`deploy ${name}`);
        const code = await pub.getCode({address: r.contractAddress});
        console.log(`[cardano-live] ${name} runtime ${(code!.length - 2) / 2} B`);
        return r.contractAddress;
    }

    const abi = () => loadArtifact("CardanoMithrilVerifier").abi;
    const call = (fn: string, args: unknown[]) =>
        pub.readContract({address: addr.v, abi: abi() as never, functionName: fn, args: args as never});

    async function measure(fn: string, args: unknown[], label: string) {
        const gas = await pub.estimateContractGas({address: addr.v, abi: abi() as never, functionName: fn, args: args as never,
            account: wallet.account!});
        const cd = (encodeFunctionData({abi: abi(), functionName: fn, args} as never).length - 2) / 2;
        console.log(`[cardano-live] ${label}: eth_estimateGas ${gas}, calldata ${cd} B`);
        expect(gas).toBeLessThan(HEDERA_GAS);
        expect(cd).toBeLessThan(HEDERA_CALLDATA);
    }

    beforeAll(async () => {
        pp = buildPreprod(loadCapture<PreprodCapture>("preprod"));
        mn = buildMainnet(loadCapture<MainnetCapture>("mainnet"));
        anvil = spawn("anvil", ["--port", String(ANVIL_PORT), "--silent", "--code-size-limit", "24576", "--gas-limit", "30000000"], {stdio: "ignore"});
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
        const b2s = await deploy("ClprBlake2sHasher");
        const stm = await deploy("MithrilStmVerifier");
        addr.v = await deploy("CardanoMithrilVerifier", [stm, b2s]);
    });

    afterAll(() => {
        anvil?.kill("SIGTERM");
    });

    it("preprod: rotation + certificate + MKMap + block + transaction prove the real output", async () => {
        const [proven, output, newAnchor] = await call("verifyTransactionOutput", [pp.txProof, pp.anchor]) as
            [{txId: Hex; blockHash: Hex; blockNumber: bigint}, Hex, Hex];
        expect(proven.txId).toBe(pp.txHash);
        expect(proven.blockHash).toBe(pp.blockHash);
        expect(proven.blockNumber).toBe(BigInt(pp.blockNumber));
        expect(output).toBe(pp.output);
        expect(output.includes(pp.datum.slice(2))).toBe(true);
        expect(newAnchor).toBe(pp.rotatedAnchor);
        await measure("verifyTransactionOutput", [pp.txProof, pp.anchor], "preprod rotation + tx output");
    });

    it("preprod: the rotated anchor verifies the next-epoch certificate and rejects the old one", async () => {
        const [msg] = await call("verifyCertificate", [pp.stateEpochCertProof, pp.rotatedAnchor]) as [Hex, Hex];
        expect((msg.length - 2) / 2).toBe(64);
        await expect(call("verifyTransactionOutput", [pp.txProof, pp.rotatedAnchor])).rejects.toThrow(/CertificateEpochMismatch/);
    });

    it("preprod: a flipped byte in the transaction body is rejected", async () => {
        const p = Buffer.from(pp.txProof.slice(2), "hex");
        const out = Buffer.from(pp.output.slice(2), "hex");
        const at = p.indexOf(out);
        p[at + out.length - 3] ^= 1;
        await expect(call("verifyTransactionOutput", [("0x" + p.toString("hex")) as Hex, pp.anchor])).rejects.toThrow();
    });

    it("mainnet: a real 57-signer certificate (k = 1944) verifies", async () => {
        await call("verifyCertificate", [mn.certProof, mn.anchor]);
        await measure("verifyCertificate", [mn.certProof, mn.anchor], `mainnet certificate (${mn.signers} signers)`);
    });

    it("mainnet: real epoch rotation + next-epoch certificate", async () => {
        const [msg, newAnchor] = await call("verifyCertificate", [mn.rotationProof, mn.anchor]) as [Hex, Hex];
        expect(msg).toBe(mn.signedMessage);
        expect(newAnchor).toBe(mn.rotatedAnchor);
        await measure("verifyCertificate", [mn.rotationProof, mn.anchor], "mainnet rotation + certificate");
    });
});
