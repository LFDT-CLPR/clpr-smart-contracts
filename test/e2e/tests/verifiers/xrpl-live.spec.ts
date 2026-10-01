import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {readFileSync} from "node:fs";
import path from "node:path";
import {createPublicClient, createWalletClient, encodeAbiParameters, encodeFunctionData, http, type Hex, type PublicClient, type WalletClient} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {loadArtifact, REPO_ROOT} from "../../../../script/deploy/artifacts.js";
import {loadXrplFixture, mainnetProofs, mainnetRotation, testnetOutbox, txFields, unlHash} from "../../relay/buildXrplLiveProof.js";
import {xrplBase58Decode} from "../../relay/xrplPeer.js";
import {sha256} from "@noble/hashes/sha2";

/// XrplVerifier / XrplLightClient against REAL XRP Ledger data, replayed on anvil:
///   - mainnet: 35 UNL validations of ledger 107352581, a memo Payment proven with its metadata in
///     the transaction tree, the sender's AccountRoot in the state tree, and a validator manifest
///     rotation signed by a real ed25519 master key.
///   - testnet: the five clpr/v1 outbox messages from the feat/xrpl-design emitter (2-of-3
///     multisig AccountSets), linked through the skip list of a later UNL-validated ledger, through
///     verifyConfig (real outbox AccountRoot: master disabled) and verifyBundle end to end.
/// Re-capture: `npm run xrpl-live:refresh`. Run: forge build && npm run test:e2e:xrpl-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8617);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const byteLen = (h: Hex) => (h.length - 2) / 2;

function loadTestArtifact(name: string): {abi: readonly unknown[]; bytecode: Hex} {
    const j = JSON.parse(readFileSync(path.join(REPO_ROOT, "out", `${name}.sol`, `${name}.json`), "utf8"));
    return {abi: j.abi, bytecode: j.bytecode.object};
}

describe("XRPL verifier on live XRPL data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    const lcArt = loadArtifact("XrplLightClient");
    const vArt = loadArtifact("XrplVerifier");
    let lc: Hex;
    let verifierMain: Hex;
    let verifierTest: Hex;
    let harness: Hex;
    const gas: Record<string, {gas: bigint; calldata: number}> = {};

    async function deploy(art: {abi: readonly unknown[]; bytecode: Hex}, args: unknown[] = []): Promise<Hex> {
        const hash = await wallet.deployContract({abi: art.abi as never, bytecode: art.bytecode, args: args as never, account: wallet.account!, chain: null});
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error("deploy failed");
        return r.contractAddress;
    }
    const call = (at: Hex, abi: readonly unknown[], fn: string, args: unknown[]) =>
        pub.readContract({address: at, abi: abi as never, functionName: fn, args: args as never}) as Promise<any>;
    async function measure(label: string, at: Hex, abi: readonly unknown[], fn: string, args: unknown[]) {
        const data = encodeFunctionData({abi: abi as never, functionName: fn, args: args as never});
        const g = await pub.estimateGas({to: at, data, account: wallet.account!.address});
        gas[label] = {gas: g, calldata: byteLen(data)};
        return g;
    }

    beforeAll(async () => {
        anvil = spawn("anvil", ["--port", String(ANVIL_PORT), "--silent", "--gas-limit", "100000000"], {stdio: "ignore"});
        const rpc = `http://127.0.0.1:${ANVIL_PORT}`;
        pub = createPublicClient({transport: http(rpc), pollingInterval: 100}) as PublicClient;
        for (const deadline = Date.now() + 15_000; ; ) {
            try {
                await pub.getChainId();
                break;
            } catch (err) {
                if (Date.now() > deadline) throw err;
                await new Promise((r) => setTimeout(r, 200));
            }
        }
        wallet = createWalletClient({account: privateKeyToAccount(ANVIL_KEY), transport: http(rpc)});
        const ed = await deploy(loadArtifact("Ed25519Verifier"));
        const hasher = await deploy(loadArtifact("ClprSha512Hasher"));
        const keys = await deploy(loadArtifact("XrplUnlKeys"), [ed, hasher]);
        lc = await deploy(lcArt, [keys]);
        verifierMain = await deploy(vArt, ["xrpl:0", lc]);
        verifierTest = await deploy(vArt, ["xrpl:1", lc]);
        harness = await deploy(loadTestArtifact("XrplLiveHarness"));
    }, 60_000);

    afterAll(() => {
        anvil?.kill("SIGTERM");
        console.table(Object.fromEntries(Object.entries(gas).map(([k, v]) => [k, {gas: Number(v.gas), calldataBytes: v.calldata}])));
    });

    describe("mainnet", () => {
        const f = loadXrplFixture("mainnet");

        it("proves a memo transaction with its metadata in a UNL-validated ledger", async () => {
            const p = mainnetProofs(f, {quorumOnly: true});
            expect(p.validationCount).toBe(28);
            const [lg, txs] = await call(lc, lcArt.abi, "proveTransactions", [p.txProof, p.unlHash, p.unlCount, 0n, 5n]);
            expect(Number(lg.seq)).toBe(f.ledger.index);
            expect(txs[0].id.slice(2).toUpperCase()).toBe(f.memoTx.id);
            expect(txFields(txs[0].tx.slice(2)).account).toBe(f.memoTx.sender);
            await measure("mainnet memo tx (28/35 validations)", lc, lcArt.abi, "proveTransactions", [p.txProof, p.unlHash, p.unlCount, 0n, 5n]);
        });

        it("proves the sender's AccountRoot in the state tree", async () => {
            const p = mainnetProofs(f, {quorumOnly: true});
            const [seq, key, data] = await call(lc, lcArt.abi, "verifyLedgerEntry", [p.stateProof, p.unlHash, p.unlCount, 0n]);
            expect(Number(seq)).toBe(f.ledger.index);
            expect(key.slice(2)).toBe(f.accountState.key);
            expect(data.slice(2)).toBe(f.accountState.leaf);
            await measure("mainnet AccountRoot state proof", lc, lcArt.abi, "verifyLedgerEntry", [p.stateProof, p.unlHash, p.unlCount, 0n]);
        });

        it("rejects below quorum, a wrong UNL and a stale ledger", async () => {
            const few = mainnetProofs({...f, unl: {...f.unl, quorum: 27}}, {quorumOnly: true});
            await expect(call(lc, lcArt.abi, "proveTransactions", [few.txProof, few.unlHash, few.unlCount, 0n, 5n])).rejects.toThrow(/QuorumNotReached/);
            const p = mainnetProofs(f, {quorumOnly: true});
            await expect(call(lc, lcArt.abi, "proveTransactions", [p.txProof, `0x${"11".repeat(32)}`, p.unlCount, 0n, 5n])).rejects.toThrow(/UnlMismatch/);
            await expect(call(lc, lcArt.abi, "proveTransactions", [p.txProof, p.unlHash, p.unlCount, BigInt(f.ledger.index + 1), 5n])).rejects.toThrow(/StaleLedger/);
        });

        it("applies a real validator manifest (ed25519 master) and re-commits the UNL", async () => {
            const r = mainnetRotation(f);
            const [lg] = await call(lc, lcArt.abi, "proveTransactions", [r.proof, r.unlHash, r.unlCount, 0n, 5n]);
            expect(lg.newUnlHash).toBe(r.rotatedHash);
            await measure("mainnet + 1 manifest rotation", lc, lcArt.abi, "proveTransactions", [r.proof, r.unlHash, r.unlCount, 0n, 5n]);
        });
    });

    describe("testnet outbox (clpr/v1 messages)", () => {
        const f = loadXrplFixture("testnet");
        const m = loadXrplFixture("messages");
        const outbox = `0x${xrplBase58Decode(m.outbox).subarray(1).toString("hex")}` as Hex;
        const channelId = `0x${m.channel_id}` as Hex;
        let control: Hex;
        let anchor: Hex;
        let context: Hex;

        beforeAll(async () => {
            control = await call(harness, loadTestArtifact("XrplLiveHarness").abi, "controlMessage", ["xrpl:1", outbox, 1_790_000_000n * 1_000_000_000n]);
        });

        it("verifyConfig: the real outbox AccountRoot (master disabled) in a validated ledger", async () => {
            const {configProof} = testnetOutbox(f, m, control);
            const out = await call(verifierTest, vArt.abi, "verifyConfig", [configProof, channelId, "0x"]);
            expect(out[1]).toBe("xrpl:1");
            expect(out[2]).toBe(outbox);
            anchor = out[5];
            context = out[0];
            const [uh, count, seqBase] = [anchor.slice(0, 66), BigInt("0x" + anchor.slice(66, 130)), BigInt("0x" + anchor.slice(130, 194))];
            expect(uh).toBe(unlHash(f.unl.entries));
            expect(count).toBe(6n);
            expect(seqBase).toBe(BigInt(m.seq_base));
            await measure("testnet verifyConfig", verifierTest, vArt.abi, "verifyConfig", [configProof, channelId, "0x"]);
            // a mainnet-chain verifier rejects the testnet config
            await expect(call(verifierMain, vArt.abi, "verifyConfig", [configProof, channelId, "0x"])).rejects.toThrow(/WrongChain/);
        });

        it("verifyBundle: five live outbox messages end to end", async () => {
            const {bundleProof, messages} = testnetOutbox(f, m, control);
            const [meta, payloads, newAnchor] = await call(verifierTest, vArt.abi, "verifyBundle", [bundleProof, anchor, context]);
            expect(payloads.length).toBe(5);
            for (let i = 0; i < 5; i++) expect(payloads[i].slice(2)).toBe(messages[i].payload_hex);
            expect(meta.nextMessageId).toBe(6n);
            expect(meta.receivedMessageId).toBe(2n);
            let rh = Buffer.alloc(32);
            for (const x of messages) rh = Buffer.from(sha256(Buffer.concat([rh, sha256(Buffer.from(x.payload_hex, "hex"))])));
            expect(meta.sentRunningHash).toBe(`0x${rh.toString("hex")}`);
            expect(newAnchor).toBe("0x");
            await measure("testnet bundle, 5 messages", verifierTest, vArt.abi, "verifyBundle", [bundleProof, anchor, context]);
            const one = testnetOutbox(f, m, control, {messages: 1});
            await measure("testnet bundle, 1 message", verifierTest, vArt.abi, "verifyBundle", [one.bundleProof, anchor, context]);
        });

        it("rejects a gap, a foreign sender, a wrong channel and a wrong seq_base", async () => {
            const {bundleProof} = testnetOutbox(f, m, control);
            const seqBase = BigInt("0x" + anchor.slice(130, 194));
            const shifted = (delta: bigint) =>
                (anchor.slice(0, 130) + encodeAbiParameters([{type: "uint256"}], [seqBase + delta]).slice(2) + anchor.slice(194)) as Hex;
            // seq_base off by one: every record's next_message_id disagrees with Sequence - seq_base + 1
            await expect(call(verifierTest, vArt.abi, "verifyBundle", [bundleProof, shifted(1n), context])).rejects.toThrow(/SequenceGap|NextMessageIdMismatch/);
            const otherChannel = `0x${"ab".repeat(32)}${outbox.slice(2)}` as Hex; // abi.encodePacked(channelId, service)
            await expect(call(verifierTest, vArt.abi, "verifyBundle", [bundleProof, anchor, otherChannel])).rejects.toThrow(/ChannelMismatch/);
            const otherSender = `${channelId}${"22".repeat(20)}` as Hex;
            await expect(call(verifierTest, vArt.abi, "verifyBundle", [bundleProof, anchor, otherSender])).rejects.toThrow(/WrongSender/);
            // drop message 3: Sequence gap between messages 2 and 4
            const gap = testnetOutbox(f, {...m, messages: [m.messages[0], m.messages[1], m.messages[3]]}, control);
            await expect(call(verifierTest, vArt.abi, "verifyBundle", [gap.bundleProof, anchor, context])).rejects.toThrow(/SequenceGap/);
        });
    });
});
