import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {readFileSync} from "node:fs";
import {createPublicClient, createWalletClient, encodeFunctionData, http, type Hex, type PublicClient,
    type WalletClient} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {loadArtifact} from "../../../../script/deploy/artifacts.js";
import {encodeAnchor, fromColumns, MAINNET_FIXTURE, mapEntryKey, nextKeysOf, signedHeaderOf, signerSetOf,
    type EntryCapture, type StacksCapture} from "../../relay/buildStacksProof.js";

/// StacksVerifier against recorded Stacks mainnet data, replayed on anvil
/// (re-capture: `npm run stacks-live:refresh`; offline re-check: `npx tsx test/e2e/relay/buildStacksProof.ts --check`).
///   1. deploy the SHA-512/256 hasher and StacksVerifier with the cycle-N signer set as genesis;
///   2. registerRotation: the cycle-N set signed the block that wrote `.signers` cycle-signer-set[N+1];
///      the verifier proves it through the MARF and derives the N+1 signer addresses (a real transaction);
///   3. verifyEntry: cycle-N+1 blocks prove a live Clarity map entry (1, 2 and 3 MARF segments),
///      walking from the genesis anchor through the recorded rotation.
/// Run: forge build && npm run test:e2e:stacks-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8642);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HEDERA_GAS = 15_000_000n;
const HEDERA_CALLDATA = 128 * 1024;

const cap = JSON.parse(readFileSync(MAINNET_FIXTURE, "utf8")) as StacksCapture;
const fromSet = fromColumns(cap.signerSets[cap.cycles.current]);
const toSet = fromColumns(cap.signerSets[cap.cycles.next]);

describe("StacksVerifier on live Stacks mainnet data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let verifier: Hex;
    const abi = loadArtifact("StacksVerifier").abi;

    async function deploy(name: string, args: unknown[]): Promise<Hex> {
        const art = loadArtifact(name);
        const hash = await wallet.deployContract({abi: art.abi as never, bytecode: art.bytecode, args: args as never,
            account: wallet.account!, chain: null});
        const r = await pub.waitForTransactionReceipt({hash});
        const code = await pub.getCode({address: r.contractAddress!});
        console.log(`[stacks-live] ${name} runtime ${(code!.length - 2) / 2} B`);
        return r.contractAddress!;
    }

    const call = (fn: string, args: unknown[]) =>
        pub.readContract({address: verifier, abi: abi as never, functionName: fn, args: args as never});

    const calldataLen = (fn: string, args: unknown[]) => (encodeFunctionData({abi, functionName: fn, args} as never).length - 2) / 2;

    const entryArgs = (e: EntryCapture) => [
        encodeAnchor(cap.cycles.current, fromSet),
        signerSetOf(cap.cycles.next, toSet),
        signedHeaderOf(e),
        e.proof,
        e.bindings,
        `0x${Buffer.from(mapEntryKey(e.contract, e.map, e.key), "latin1").toString("hex")}` as Hex,
        e.value,
    ];

    const rotationArgs = () => [{
        current: signerSetOf(cap.cycles.current, fromSet),
        block: signedHeaderOf(cap.rotation),
        marfProof: cap.rotation.proof,
        bindings: [],
        signerList: cap.rotation.value,
        nextKeys: nextKeysOf(toSet),
    }];

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
        const hasher = await deploy("ClprSha512t256Hasher", []);
        verifier = await deploy("StacksVerifier", [hasher, cap.chainId, "SP000000000000000000002Q6VF78.signers",
            cap.principalVersion, signerSetOf(cap.cycles.current, fromSet)]);
    });

    afterAll(() => {
        anvil?.kill("SIGTERM");
    });

    it("rejects a cycle N+1 block before the rotation is recorded", async () => {
        await expect(call("verifyEntry", entryArgs(cap.entry))).rejects.toThrow();
    });

    it("registerRotation proves the next cycle's signer set from .signers (real transaction)", async () => {
        const args = rotationArgs();
        const hash = await wallet.writeContract({address: verifier, abi: abi as never, functionName: "registerRotation",
            args: args as never, account: wallet.account!, chain: null, gas: 16_000_000n});
        const r = await pub.waitForTransactionReceipt({hash});
        expect(r.status).toBe("success");
        const cd = calldataLen("registerRotation", args);
        console.log(`[stacks-live] rotation ${cap.cycles.current}→${cap.cycles.next} (${toSet.length} signers): ` +
            `gasUsed ${r.gasUsed}, calldata ${cd} B`);
        expect(r.gasUsed).toBeLessThan(HEDERA_GAS);
        expect(cd).toBeLessThan(HEDERA_CALLDATA);
        const genesis = await call("GENESIS_SET_HASH", []) as Hex;
        const next = await call("successorOf", [genesis]) as Hex;
        expect(next).toBe(await call("setHash", [signerSetOf(cap.cycles.next, toSet)]));
    });

    for (const [name, segments, fits] of [["entry", 1n, true], ["hop1", 2n, false], ["hop2", 3n, false]] as const) {
        it(`verifyEntry proves a live map entry through ${segments} MARF segment(s)`, async () => {
            const e = cap[name];
            const args = entryArgs(e);
            const [blockId, chainLength, segs] = await call("verifyEntry", args) as [Hex, bigint, bigint];
            expect(blockId).toBe(e.blockId);
            expect(chainLength).toBe(BigInt(e.block.chainLength));
            expect(segs).toBe(segments);
            const gas = await pub.estimateContractGas({address: verifier, abi: abi as never, functionName: "verifyEntry",
                args: args as never, account: wallet.account!});
            const cd = calldataLen("verifyEntry", args);
            console.log(`[stacks-live] ${name} (${segments} segment(s), proof ${(e.proof.length - 2) / 2} B): ` +
                `eth_estimateGas ${gas}, calldata ${cd} B`);
            expect(cd).toBeLessThan(HEDERA_CALLDATA);
            if (fits) expect(gas).toBeLessThan(HEDERA_GAS);
            else expect(gas).toBeGreaterThan(HEDERA_GAS); // documented limit: prove at the block that wrote the record
        });
    }

    it("rejects the entry with one signature byte flipped", async () => {
        const args = entryArgs(cap.entry);
        const h = args[2] as {header: Hex; signatures: Hex};
        const s = h.signatures;
        args[2] = {...h, signatures: (s.slice(0, 90) + (parseInt(s.slice(90, 92), 16) ^ 1).toString(16).padStart(2, "0") + s.slice(92)) as Hex};
        await expect(call("verifyEntry", args)).rejects.toThrow();
    });

    it("rejects the entry with a different value", async () => {
        const args = entryArgs(cap.entry);
        const v = args[6] as Hex;
        args[6] = (v.slice(0, -2) + (parseInt(v.slice(-2), 16) ^ 1).toString(16).padStart(2, "0")) as Hex;
        await expect(call("verifyEntry", args)).rejects.toThrow();
    });
});
