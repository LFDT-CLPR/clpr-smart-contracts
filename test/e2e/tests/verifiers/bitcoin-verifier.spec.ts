import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {execFileSync} from "node:child_process";
import {createPublicClient, createWalletClient, http, keccak256, toHex, type Hex} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {foundry} from "viem/chains";
import {loadArtifact} from "../../../../script/deploy/artifacts.js";
import {AnvilNode} from "../../backend/anvil/AnvilNode.js";
import {
    bitcoinRpc,
    buildBitcoinBundleProof,
    buildBitcoinConfigProof,
    checkpointAt,
    clprCommitment,
    decodeTrustAnchor,
    encodeClprDataMessage,
    runningHash,
    sha256,
    toInternal,
    type BitcoinRpc
} from "../../relay/buildBitcoinProof.js";

/// End-to-end test for BitcoinVerifier on REAL Bitcoin Core (regtest, in Docker):
///
///   1. bitcoind -regtest runs in a throwaway container; a wallet mines 101 blocks.
///   2. BitcoinVerifier (regtest params, k = 6) is deployed on anvil with a checkpoint read from bitcoind.
///   3. The sender publishes the genesis cursor tx and 3 CLPR message txs (OP_RETURN commitments,
///      each spending the previous cursor) via createrawtransaction / signrawtransactionwithwallet.
///   4. The relay (test/e2e/relay/buildBitcoinProof.ts) builds the config and bundle proofs from RPC
///      data, and verifyConfig / verifyBundle are called on anvil.
///
/// Requires: docker (image bitcoin/bitcoin:28.1) and anvil. Skips when docker is unavailable.
/// Run: npm run test:e2e:bitcoin-verifier

const IMAGE = process.env.BITCOIND_IMAGE ?? "bitcoin/bitcoin:28.1";
const RPC_USER = "clpr";
const RPC_PASS = "clpr";
const K = 6;
const MAX_PAYLOAD = 4096n;
const REGTEST_POW_LIMIT = 0x7fffffn << 232n;
const REGTEST_CHAIN_ID = "bip122:0f9188f13cb7b2c71f2a335e3a4fc328";
const ANVIL_PORT = 8561;
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const CHANNEL_ID = keccak256(toHex("clpr e2e: bitcoin regtest -> hiero"));
const CONNECTOR_ID = keccak256(toHex("e2e connector"));
const TARGET_APP: Hex = "0x00000000000000000000000000000000000a11ce";

function dockerAvailable(): boolean {
    try {
        execFileSync("docker", ["info"], {stdio: "ignore"});
        return true;
    } catch {
        return false;
    }
}

const SKIP = process.env.CLPR_SKIP_BITCOIN_E2E === "1" || !dockerAvailable();

interface Utxo {
    txid: string;
    vout: number;
    amount: number;
}

const btc = (sats: bigint) => (Number(sats) / 1e8).toFixed(8);
const toSats = (amount: number) => BigInt(Math.round(amount * 1e8));

describe.skipIf(SKIP)("BitcoinVerifier e2e (bitcoind regtest → anvil)", () => {
    let container = "";
    let node: BitcoinRpc;
    let wallet: BitcoinRpc;
    let anvil: AnvilNode;
    let verifier: Hex;
    let senderAddress = "";
    let senderScript: Hex = "0x";
    let deployHeight = 0;
    let genesisTxid = "";
    const messages: {txid: string; payload: Buffer}[] = [];
    let spare: Utxo[] = [];

    const art = loadArtifact("BitcoinVerifier");
    const account = privateKeyToAccount(ANVIL_KEY);
    const pub = () => createPublicClient({transport: http(`http://127.0.0.1:${ANVIL_PORT}`)});
    const walletClient = () =>
        createWalletClient({account, transport: http(`http://127.0.0.1:${ANVIL_PORT}`), chain: foundry});

    async function mine(n: number) {
        await wallet.call("generatetoaddress", [n, senderAddress]);
    }

    /// Build, sign and broadcast a CLPR tx: input 0 = cursor (or funding for genesis), input 1 = fee
    /// funding, vout 0 = OP_RETURN commitment, vout 1 = new cursor to the sender, vout 2 = change.
    async function sendClprTx(cursor: {txid: string; vout: number; sats: bigint} | null, commitment: Buffer) {
        const funding = spare.shift()!;
        const inputs = [
            ...(cursor ? [{txid: cursor.txid, vout: cursor.vout}] : []),
            {txid: funding.txid, vout: funding.vout}
        ];
        const cursorSats = 100_000n;
        const fee = 10_000n;
        const inSats = toSats(funding.amount) + (cursor?.sats ?? 0n);
        const outputs = [
            {data: commitment.toString("hex")},
            {[senderAddress]: btc(cursorSats)},
            {[await wallet.call<string>("getrawchangeaddress")]: btc(inSats - cursorSats - fee)}
        ];
        const unsigned = await wallet.call<string>("createrawtransaction", [inputs, outputs]);
        const signed = await wallet.call<{hex: string; complete: boolean}>("signrawtransactionwithwallet", [unsigned]);
        expect(signed.complete).toBe(true);
        const txid = await wallet.call<string>("sendrawtransaction", [signed.hex]);
        return {txid, vout: 1, sats: cursorSats};
    }

    async function readVerifier<T>(functionName: string, args: unknown[]): Promise<T> {
        return (await pub().readContract({address: verifier, abi: art.abi as never, functionName, args})) as T;
    }

    beforeAll(async () => {
        // ── bitcoind (regtest) ──
        container = `clpr-bitcoind-e2e-${process.pid}`;
        execFileSync("docker", [
            "run", "-d", "--rm", "--name", container, "-p", "127.0.0.1::18443", IMAGE,
            "-regtest", "-server", "-txindex=1", "-fallbackfee=0.0002", "-printtoconsole=0",
            `-rpcuser=${RPC_USER}`, `-rpcpassword=${RPC_PASS}`, "-rpcbind=0.0.0.0", "-rpcallowip=0.0.0.0/0"
        ], {stdio: "ignore"});
        const hostPort = execFileSync("docker", ["port", container, "18443/tcp"]).toString().trim().split(":").pop();
        const url = `http://127.0.0.1:${hostPort}`;
        node = bitcoinRpc(url, RPC_USER, RPC_PASS);
        wallet = bitcoinRpc(url, RPC_USER, RPC_PASS, "clpr");
        const deadline = Date.now() + 60_000;
        for (;;) {
            try {
                await node.call("getblockchaininfo");
                break;
            } catch (err) {
                if (Date.now() > deadline) throw err;
                await new Promise((r) => setTimeout(r, 500));
            }
        }
        await node.call("createwallet", ["clpr"]);
        senderAddress = await wallet.call<string>("getnewaddress", ["sender", "bech32"]);
        const info = await wallet.call<{scriptPubKey: string}>("getaddressinfo", [senderAddress]);
        senderScript = `0x${info.scriptPubKey}`;
        await mine(110); // mature coinbases for fee funding
        spare = (await wallet.call<Utxo[]>("listunspent", [1])).filter((u) => u.amount >= 1);

        // ── anvil + verifier (checkpoint = current bitcoind tip) ──
        anvil = new AnvilNode(ANVIL_PORT, 31337);
        await anvil.start();
        deployHeight = await node.call<number>("getblockcount");
        const cp = await checkpointAt(node, deployHeight);
        const hash = await walletClient().deployContract({
            abi: art.abi as never,
            bytecode: art.bytecode,
            args: [REGTEST_POW_LIMIT, true, true, K, MAX_PAYLOAD, REGTEST_CHAIN_ID, cp]
        } as never);
        const receipt = await pub().waitForTransactionReceipt({hash});
        verifier = receipt.contractAddress as Hex;
    }, 180_000);

    afterAll(async () => {
        await anvil?.stop();
        if (container) execFileSync("docker", ["rm", "-f", container], {stdio: "ignore"});
    });

    it("verifies a real regtest channel: config + 3 messages", async () => {
        // ── Sender: genesis cursor tx (id 0, zero payload hash) ──
        const genesis = await sendClprTx(null, clprCommitment(CHANNEL_ID, Buffer.alloc(32), 0n));
        genesisTxid = genesis.txid;
        await mine(1);

        // ── Sender: 3 messages. #1 alone in a block; #2 and #3 chained in the next block. ──
        let cursor = genesis;
        for (let i = 1n; i <= 3n; i++) {
            const payload = encodeClprDataMessage(CONNECTOR_ID, TARGET_APP, senderScript, Buffer.from(`hello from bitcoin #${i}`));
            cursor = await sendClprTx(cursor, clprCommitment(CHANNEL_ID, sha256(payload), i));
            messages.push({txid: cursor.txid, payload});
            if (i !== 2n) await mine(1);
        }
        await mine(K - 1); // last message block now has exactly k confirmations

        // ── Relay: config proof → verifyConfig ──
        const configProof = await buildBitcoinConfigProof(node, deployHeight, genesisTxid);
        const cfg = await readVerifier<[Hex, string, Hex, bigint, unknown, Hex, Hex, unknown]>("verifyConfig", [
            configProof, CHANNEL_ID, "0x"
        ]);
        const [channelContext, chainId, serviceAddress, , , anchor0] = cfg;
        expect(chainId).toBe(REGTEST_CHAIN_ID);
        expect(serviceAddress).toBe(senderScript);
        const a0 = decodeTrustAnchor(anchor0);
        expect(a0.cursorTxid).toBe(toInternal(genesisTxid));
        expect(a0.lastMessageId).toBe(0n);

        // ── Relay: bundle proof → verifyBundle ──
        const bundle = await buildBitcoinBundleProof(node, anchor0, messages);
        const [meta, payloads, newAnchor] = await readVerifier<
            [{nextMessageId: bigint; sentRunningHash: Hex; receivedMessageId: bigint}, Hex[], Hex, Hex, unknown]
        >("verifyBundle", [bundle.proof, anchor0, channelContext]);

        expect(payloads).toEqual(messages.map((m) => `0x${m.payload.toString("hex")}`));
        expect(meta.nextMessageId).toBe(4n);
        expect(meta.receivedMessageId).toBe(0n);
        expect(meta.sentRunningHash).toBe(runningHash(`0x${"00".repeat(32)}`, messages.map((m) => m.payload)));
        const a1 = decodeTrustAnchor(newAnchor);
        expect(a1.lastMessageId).toBe(3n);
        expect(a1.cursorTxid).toBe(toInternal(messages[2].txid));
        const tip = await node.call<number>("getblockcount");
        expect(Number(a1.checkpoint.height)).toBe(tip - K + 1);
        const tipCpHash = await node.call<string>("getblockhash", [tip - K + 1]);
        expect(a1.checkpoint.blockHash).toBe(toInternal(tipCpHash));
        const hdr = await node.call<{chainwork: string}>("getblockheader", [tipCpHash, true]);
        expect(a1.checkpoint.chainWork).toBe(BigInt("0x" + hdr.chainwork));

        // ── Gas / calldata (eth_estimateGas includes the 21000 base + calldata cost) ──
        const {encodeFunctionData} = await import("viem");
        const data = encodeFunctionData({
            abi: art.abi as never,
            functionName: "verifyBundle",
            args: [bundle.proof, anchor0, channelContext]
        } as never);
        const gas = await pub().estimateGas({account: account.address, to: verifier, data});
        const calldataBytes = (data.length - 2) / 2;
        console.log(
            `[bitcoin e2e] verifyBundle: ${bundle.headerCount} headers + 3 msgs → estimateGas=${gas} calldata=${calldataBytes}B`
        );
        expect(gas).toBeLessThan(15_000_000n);
        expect(calldataBytes).toBeLessThan(128 * 1024);

        // ── Negative: a tampered payload preimage is rejected ──
        const tampered = await buildBitcoinBundleProof(node, anchor0, [
            {txid: messages[0].txid, payload: Buffer.from("not the committed payload")}
        ]);
        await expect(readVerifier("verifyBundle", [tampered.proof, anchor0, channelContext])).rejects.toThrow(
            /PayloadHashMismatch/
        );

        // ── Negative: replaying message #1 against the advanced anchor is rejected ──
        const replay = await buildBitcoinBundleProof(node, newAnchor, [messages[0]]);
        await expect(readVerifier("verifyBundle", [replay.proof, newAnchor, channelContext])).rejects.toThrow(
            /NotACursorSpend/
        );
    }, 180_000);

    it("gas with 6 and 12 headers + 3 messages (all 3 messages in the first new block)", async () => {
        // Fresh channel: genesis in block B; the 3 messages (chained in the mempool) in block B+1.
        const channelId = keccak256(toHex("clpr e2e gas channel"));
        const g = await sendClprTx(null, clprCommitment(channelId, Buffer.alloc(32), 0n));
        await mine(1);
        const B = await node.call<number>("getblockcount");
        const msgs: {txid: string; payload: Buffer}[] = [];
        let cursor = g;
        for (let i = 1n; i <= 3n; i++) {
            const payload = encodeClprDataMessage(CONNECTOR_ID, TARGET_APP, senderScript, Buffer.from(`gas #${i}`));
            cursor = await sendClprTx(cursor, clprCommitment(channelId, sha256(payload), i));
            msgs.push({txid: cursor.txid, payload});
        }
        await mine(12);

        // Config proof cut at B+k-1 → anchor checkpoint = B (the block right below the messages).
        const [ctx, , , , , anchor] = await readVerifier<[Hex, string, Hex, bigint, unknown, Hex]>("verifyConfig", [
            await buildBitcoinConfigProof(node, deployHeight, g.txid, B + K - 1),
            channelId,
            "0x"
        ]);
        expect(Number(decodeTrustAnchor(anchor).checkpoint.height)).toBe(B);

        const {encodeFunctionData} = await import("viem");
        for (const n of [6, 12]) {
            const b = await buildBitcoinBundleProof(node, anchor, msgs, B + n);
            expect(b.headerCount).toBe(n);
            const [meta] = await readVerifier<[{nextMessageId: bigint}]>("verifyBundle", [b.proof, anchor, ctx]);
            expect(meta.nextMessageId).toBe(4n);
            const data = encodeFunctionData({
                abi: art.abi as never,
                functionName: "verifyBundle",
                args: [b.proof, anchor, ctx]
            } as never);
            const gas = await pub().estimateGas({account: account.address, to: verifier, data});
            const calldataBytes = (data.length - 2) / 2;
            console.log(
                `[bitcoin e2e] verifyBundle: ${n} headers + 3 segwit msgs → estimateGas=${gas} calldata=${calldataBytes}B`
            );
            expect(gas).toBeLessThan(15_000_000n);
            expect(calldataBytes).toBeLessThan(128 * 1024);
        }
    }, 180_000);
});
