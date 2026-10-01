import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {readFileSync} from "node:fs";
import path from "node:path";
import {
    createPublicClient,
    createWalletClient,
    encodeFunctionData,
    http,
    type Hex,
    type PublicClient,
    type WalletClient
} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {REPO_ROOT} from "../../../../script/deploy/artifacts.js";
import {buildDposLiveProof, loadDposCapture, type DposCapture, type DposLiveProof} from "../../relay/buildAntelopeDposLiveProof.js";
import {checkCapture, loadSavannaCapture, savannaLiveInputs, type SavannaCapture} from "../../relay/buildSavannaLiveProof.js";
import {hexToBuf, rlpEncode} from "../../lib/rlp.js";
import {nameToU64} from "../../lib/antelope.js";

/// Antelope verifiers against REAL chain data, replayed offline on anvil from the recorded fixtures:
///
/// - XPR Network (legacy DPoS, Leap 5): test/e2e/fixtures/xpr-live/{mainnet,testnet}.json, recorded
///   from public RPC + Hyperion (`npm run antelope:xpr:refresh`). The production
///   AntelopeDposVerifier code proves a real action receipt in a real block: ~333 real headers,
///   30 real producer signatures (the DPoS last-irreversible-block rule), the legacy action Merkle
///   tree. XPR has no CLPR Service yet, so the action is an ordinary contract action:
///   `verifyBundle` passes finality and inclusion and then rejects it as not the service's
///   `queuestate` (NotServiceAction); the harness's `proveAction` returns it.
/// - Jungle4 (Vaulta's Savanna testnet): test/e2e/fixtures/vaulta-live/jungle4.json, recorded from
///   a public Spring snapshot + public RPC (`npm run antelope:jungle4:refresh -- --snapshot <file>`).
///   The live finalizer policy and two real QCs are checked by SavannaVerifier's own policy
///   parser and BLS QC check (EIP-2537 on anvil).
///
/// Run: forge build && npm run test:e2e:antelope-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8613);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

function harnessArtifact(file: string, name: string): {abi: readonly unknown[]; bytecode: Hex} {
    const j = JSON.parse(readFileSync(path.join(REPO_ROOT, "out", file, `${name}.json`), "utf8")) as {
        abi: readonly unknown[];
        bytecode: {object: Hex};
    };
    return {abi: j.abi, bytecode: j.bytecode.object};
}

const byteLen = (h: Hex) => (h.length - 2) / 2;
const calldataGas = (h: Hex) => hexToBuf(h).reduce((acc, b) => acc + (b === 0 ? 4 : 16), 0);
const channelContext = (): Hex =>
    ("0x" + "00".repeat(31) + "01" + Buffer.from(nameToU64("clpr.service").toString(16).padStart(16, "0"), "hex").reverse().toString("hex")) as Hex;

describe("Antelope verifiers on live chain data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    const dposArt = harnessArtifact("AntelopeDposVerifier.t.sol", "AntelopeDposHarness");
    const savArt = harnessArtifact("SavannaVerifier.t.sol", "SavannaVerifierHarness");
    const dpos: Record<string, {addr: Hex; cap: DposCapture; live: DposLiveProof}> = {};
    let savanna: Hex;
    let jungle4: SavannaCapture;

    async function deploy(art: {abi: readonly unknown[]; bytecode: Hex}, chainId: string): Promise<Hex> {
        const hash = await wallet.deployContract({abi: art.abi as never, bytecode: art.bytecode, args: [chainId], account: wallet.account!, chain: null});
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error("deploy failed");
        return r.contractAddress;
    }

    beforeAll(async () => {
        anvil = spawn("anvil", ["--port", String(ANVIL_PORT), "--silent", "--code-size-limit", "60000"], {stdio: "ignore"});
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
        for (const network of ["mainnet", "testnet"]) {
            const cap = loadDposCapture(network);
            dpos[network] = {addr: await deploy(dposArt, cap.caip2), cap, live: await buildDposLiveProof(cap)};
        }
        jungle4 = loadSavannaCapture("jungle4");
        savanna = await deploy(savArt, jungle4.caip2);
    });

    afterAll(() => {
        anvil?.kill("SIGTERM");
    });

    for (const network of ["mainnet", "testnet"]) {
        it(`XPR ${network}: proveAction passes on real headers, signatures and receipts`, async () => {
            const {addr, cap, live} = dpos[network];
            const args = [cap.scheduleVersion, live.schedule, live.chain, live.action] as const;
            const [receiver, account, name] = (await pub.readContract({address: addr, abi: dposArt.abi as never, functionName: "proveAction", args})) as [bigint, bigint, bigint, Hex];
            expect(account).toBe(nameToU64(cap.action.account));
            expect(name).toBe(nameToU64(cap.action.name));
            expect(receiver).toBe(nameToU64(cap.action.receiver));

            const gas = await pub.estimateContractGas({address: addr, abi: dposArt.abi as never, functionName: "proveAction", args, account: wallet.account!});
            const cd = encodeFunctionData({abi: dposArt.abi, functionName: "proveAction", args} as never);
            const full = encodeFunctionData({abi: dposArt.abi, functionName: "verifyBundle", args: [live.bundleProof, live.trustAnchor, channelContext()]} as never);
            console.log(
                `[antelope-live] XPR ${network} block ${cap.headers[0].num} (${cap.serverVersion}): ` +
                    `${cap.headers.length} headers, ${cap.headers.filter((h) => h.sig).length} signed | proveAction eth_estimateGas ${gas} ` +
                    `(calldata ${byteLen(cd)} B, ${calldataGas(cd)} gas) | verifyBundle calldata ${byteLen(full)} B`
            );
            expect(gas).toBeLessThan(15_000_000n);
            expect(byteLen(full)).toBeLessThan(128 * 1024);
        });
    }

    it("XPR mainnet: verifyBundle passes finality and inclusion, then rejects the non-CLPR action", async () => {
        const {addr, live} = dpos.mainnet;
        await expect(
            pub.readContract({address: addr, abi: dposArt.abi as never, functionName: "verifyBundle", args: [live.bundleProof, live.trustAnchor, channelContext()]})
        ).rejects.toThrow(/NotServiceAction/);
    });

    it("XPR mainnet: a tampered producer signature is rejected", async () => {
        const {addr, cap, live} = dpos.mainnet;
        const chain = hexToBuf(live.chain);
        const sig = hexToBuf(cap.headers.find((h) => h.sig)!.sig!);
        chain[chain.indexOf(sig) + 40] ^= 1;
        await expect(
            pub.readContract({address: addr, abi: dposArt.abi as never, functionName: "proveAction", args: [cap.scheduleVersion, live.schedule, ("0x" + chain.toString("hex")) as Hex, live.action]})
        ).rejects.toThrow(/SignerMismatch|BadSignature/);
    });

    it("XPR mainnet: the chain cut before the LIB rule completes is not irreversible", async () => {
        const {addr, cap, live} = dpos.mainnet;
        const short = {...cap, headers: cap.headers.slice(0, cap.headers.length - 1)};
        const cut = await buildDposLiveProof(short);
        await expect(
            pub.readContract({address: addr, abi: dposArt.abi as never, functionName: "proveAction", args: [cap.scheduleVersion, live.schedule, cut.chain, live.action]})
        ).rejects.toThrow(/NotIrreversible/);
    });

    it("Jungle4: live policy and QCs check offline (noble BLS) and on chain (EIP-2537)", async () => {
        const inputs = savannaLiveInputs(jungle4);
        expect(checkCapture(jungle4)).toHaveLength(2);
        const [gen, threshold, digest, n] = (await pub.readContract({address: savanna, abi: savArt.abi as never, functionName: "parsePolicy", args: [inputs.policyPack]})) as [number, bigint, Hex, bigint];
        expect(gen).toBe(inputs.generation);
        expect(threshold).toBe(BigInt(inputs.threshold));
        expect(digest).toBe(inputs.policyDigest);
        expect(n).toBe(BigInt(inputs.finalizers));
        for (const q of inputs.qcs) {
            const args = [inputs.policyPack, q.qc, q.digest] as const;
            await pub.readContract({address: savanna, abi: savArt.abi as never, functionName: "verifyStrongQc", args});
            const gas = await pub.estimateContractGas({address: savanna, abi: savArt.abi as never, functionName: "verifyStrongQc", args, account: wallet.account!});
            console.log(`[antelope-live] Jungle4 QC on block ${q.certifiedBlock}: ${q.voters}/${inputs.finalizers} strong votes, policy gen ${inputs.generation} | verifyStrongQc eth_estimateGas ${gas}`);
        }
    });

    it("Jungle4: a real QC does not verify another block's finality digest", async () => {
        const inputs = savannaLiveInputs(jungle4);
        await expect(
            pub.readContract({address: savanna, abi: savArt.abi as never, functionName: "verifyStrongQc", args: [inputs.policyPack, inputs.qcs[1].qc, inputs.qcs[0].digest]})
        ).rejects.toThrow(/BlsSignatureInvalid/);
    });

    it("Jungle4: dropping a voter from the bitset breaks the aggregate", async () => {
        const inputs = savannaLiveInputs(jungle4);
        const sig = Buffer.from(hexToBuf(inputs.qcs[1].qc)).subarray(-192);
        const bits = Buffer.from([0xfe, 0xff, 0x1f]);
        const qc = ("0x" + rlpEncode([bits, sig]).toString("hex")) as Hex;
        await expect(
            pub.readContract({address: savanna, abi: savArt.abi as never, functionName: "verifyStrongQc", args: [inputs.policyPack, qc, inputs.qcs[1].digest]})
        ).rejects.toThrow(/BlsSignatureInvalid/);
    });
});
