import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {readFileSync} from "node:fs";
import path from "node:path";
import {blake3} from "@noble/hashes/blake3";
import {createPublicClient, createWalletClient, encodeAbiParameters, encodeFunctionData, http, keccak256, type Hex, type PublicClient, type WalletClient} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {loadArtifact, REPO_ROOT} from "../../../../script/deploy/artifacts.js";
import {loadMixinFixture, mixinProof, changesRlp} from "../../relay/buildMixinLiveProof.js";

/// MixinKernelVerifier on REAL Mixin mainnet kernel data, replayed on anvil
/// (re-capture: `npm run mixin-live:refresh`). Nothing is re-signed: every CoSi signature is the
/// kernel's own. The proof applies the two latest kernel node changes (a NodeAccept, then a
/// NodeRemove) to the signer list that preceded them, then checks a later snapshot under the list
/// those changes produce, and walks one real transaction that spends output 0 of its input.
/// Live Mixin transactions carry no ClprQueueRecord, so verifyBundle itself stops at the record
/// decode; the harness returns everything proven up to that point.

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8621);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const hb = (h: string) => Buffer.from(h.replace(/^0x/, ""), "hex");
const keysHash = (keys: string[]) => keccak256(`0x${keys.join("")}`);
const ANCHOR = [{type: "bytes32"}, {type: "bytes32"}, {type: "bytes32"}, {type: "uint64"}, {type: "uint64"}] as const;
const ZERO = `0x${"00".repeat(32)}` as Hex;

describe("MixinKernelVerifier on live Mixin kernel data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let harness: Hex;
    let verifier: Hex;
    const f = loadMixinFixture();
    const vArt = loadArtifact("MixinKernelVerifier");
    const eArt = loadArtifact("Ed25519Verifier");
    const hArt = JSON.parse(readFileSync(path.join(REPO_ROOT, "out", "MixinLiveHarness.sol", "MixinLiveHarness.json"), "utf8"));
    const gas: Record<string, {gas: number; calldata: number}> = {};
    const thread = [hb(f.transaction.payload)];
    const tip = `0x${f.transaction.input0}` as Hex;
    const baseKeys: string[] = f.base.ready.map((n: any) => n.key);
    const finalKeys: string[] = f.nodes.map((n: any) => n.key);
    const baseAnchor = encodeAbiParameters(ANCHOR, [keysHash(baseKeys), tip, f.base.pending ? `0x${f.base.pending.key}` : ZERO, f.base.pending ? BigInt(f.base.pending.acceptedAt) : 0n, BigInt(f.base.changedAt)]);
    const lastChange = BigInt(f.changes[f.changes.length - 1].snapshot.timestamp);
    const finalAnchor = encodeAbiParameters(ANCHOR, [keysHash(finalKeys), tip, ZERO, 0n, lastChange]);

    async function deploy(abi: unknown, bytecode: Hex, args: unknown[] = []) {
        const hash = await wallet.deployContract({abi: abi as never, bytecode, args: args as never, account: wallet.account!, chain: null});
        return (await pub.waitForTransactionReceipt({hash})).contractAddress!;
    }

    async function measure(label: string, proof: Hex, anchor: Hex) {
        const data = encodeFunctionData({abi: hArt.abi, functionName: "provenThread", args: [proof, anchor]});
        gas[label] = {gas: Number(await pub.estimateGas({to: harness, data})), calldata: (data.length - 2) / 2};
    }

    beforeAll(async () => {
        anvil = spawn("anvil", ["--port", String(ANVIL_PORT), "--silent", "--code-size-limit", "49152"], {stdio: "ignore"});
        const rpc = `http://127.0.0.1:${ANVIL_PORT}`;
        pub = createPublicClient({transport: http(rpc), pollingInterval: 100}) as PublicClient;
        for (const deadline = Date.now() + 15_000; ; ) {
            try {
                await pub.getChainId();
                break;
            } catch (e) {
                if (Date.now() > deadline) throw e;
                await new Promise((r) => setTimeout(r, 200));
            }
        }
        wallet = createWalletClient({account: privateKeyToAccount(ANVIL_KEY), transport: http(rpc)});
        const ed = await deploy(eArt.abi, eArt.bytecode);
        harness = await deploy(hArt.abi, hArt.bytecode.object, [ed]);
        verifier = await deploy(vArt.abi, vArt.bytecode, ["mixin:mainnet", ed]);
    }, 60_000);

    afterAll(() => {
        anvil?.kill("SIGTERM");
        console.table(gas);
    });

    it("payloads hash to the kernel's snapshot and transaction hashes", () => {
        expect(Buffer.from(blake3(hb(f.snapshot.payload))).toString("hex")).toBe(f.snapshot.hash);
        expect(Buffer.from(blake3(hb(f.transaction.payload))).toString("hex")).toBe(f.transaction.hash);
        for (const c of f.changes) {
            expect(Buffer.from(blake3(hb(c.snapshot.payload))).toString("hex")).toBe(c.snapshot.hash);
            expect(Buffer.from(blake3(hb(c.transaction.payload))).toString("hex")).toBe(c.transaction.hash);
        }
        expect(f.changes.map((c: any) => c.kind)).toEqual(["accept", "remove"]);
        // the model the verifier implements reproduces the kernel's list after the changes
        const {model} = changesRlp(f);
        model.promote(BigInt(f.snapshot.timestamp));
        expect(model.ready.map((k) => k.toString("hex"))).toEqual(finalKeys);
    });

    it("typical bundle: the record snapshot's CoSi under the current list, and the thread link", async () => {
        const proof = mixinProof(f, thread, false);
        const [anchor, lastTx, , ts] = (await pub.readContract({address: harness, abi: hArt.abi, functionName: "provenThread", args: [proof, finalAnchor]})) as any;
        expect(lastTx).toBe(`0x${f.transaction.hash}`);
        expect(ts).toBe(BigInt(f.snapshot.timestamp));
        expect(anchor).toBe(encodeAbiParameters(ANCHOR, [keysHash(finalKeys), lastTx, ZERO, 0n, lastChange]));
        await measure(`record snapshot, ${f.snapshot.signers}/${f.snapshot.listSize} signers`, proof, finalAnchor);
        // verifyBundle runs the same steps and stops at the record: a live tx extra is not a ClprQueueRecord
        const ctx = `0x${"11".repeat(32)}${"22".repeat(32)}` as Hex;
        await expect(pub.readContract({address: verifier, abi: vArt.abi, functionName: "verifyBundle", args: [proof, finalAnchor, ctx]})).rejects.toThrow();
    });

    it("rotation: applies the live NodeAccept and NodeRemove, then checks the record under the new list", async () => {
        const proof = mixinProof(f, thread, true);
        const [anchor] = (await pub.readContract({address: harness, abi: hArt.abi, functionName: "provenThread", args: [proof, baseAnchor]})) as any;
        expect(anchor).toBe(encodeAbiParameters(ANCHOR, [keysHash(finalKeys), `0x${f.transaction.hash}`, ZERO, 0n, lastChange]));
        await measure("record + accept + remove", proof, baseAnchor);
    });

    it("rejects: replayed changes, skipped changes, a tampered mask", async () => {
        const withChanges = mixinProof(f, thread, true);
        // the same changes again on top of the anchor they produced
        await expect(pub.readContract({address: harness, abi: hArt.abi, functionName: "provenThread", args: [withChanges, encodeAbiParameters(ANCHOR, [keysHash(baseKeys), tip, ZERO, 0n, lastChange])]})).rejects.toThrow(/StaleNodeChange/);
        // the record snapshot against the pre-change list (changes left out): the keys do not sum
        const noChanges = mixinProof({...f, nodes: f.base.ready}, thread, false);
        await expect(pub.readContract({address: harness, abi: hArt.abi, functionName: "provenThread", args: [noChanges, baseAnchor]})).rejects.toThrow(/BadCosiSignature|BadPoint/);
        // wrong node set for the anchor
        await expect(pub.readContract({address: harness, abi: hArt.abi, functionName: "provenThread", args: [mixinProof(f, thread, false), baseAnchor]})).rejects.toThrow(/NodeSetMismatch/);
        // drop one signer from the mask (and its x): the live snapshot has exactly the threshold
        const m = BigInt("0x" + f.snapshot.mask);
        const low = m & -m;
        const fewer = {...f, snapshot: {...f.snapshot, mask: (m ^ low).toString(16).padStart(16, "0")}};
        await expect(pub.readContract({address: harness, abi: hArt.abi, functionName: "provenThread", args: [mixinProof(fewer, thread, false), finalAnchor]})).rejects.toThrow(/BelowThreshold/);
        // move one signer bit to a non-signer: same count, wrong aggregate
        let free = 0n;
        for (let i = 0n; i < BigInt(f.snapshot.listSize); i++) if (!((m >> i) & 1n)) { free = 1n << i; break; }
        const moved = {...f, snapshot: {...f.snapshot, mask: ((m ^ low) | free).toString(16).padStart(16, "0")}};
        await expect(pub.readContract({address: harness, abi: hArt.abi, functionName: "provenThread", args: [mixinProof(moved, thread, false), finalAnchor]})).rejects.toThrow(/BadCosiSignature/);
        // a flipped signature byte
        const sig = hb(f.snapshot.signature);
        sig[40] ^= 1;
        const flipped = {...f, snapshot: {...f.snapshot, signature: sig.toString("hex")}};
        await expect(pub.readContract({address: harness, abi: hArt.abi, functionName: "provenThread", args: [mixinProof(flipped, thread, false), finalAnchor]})).rejects.toThrow(/BadCosiSignature/);
    });
});
