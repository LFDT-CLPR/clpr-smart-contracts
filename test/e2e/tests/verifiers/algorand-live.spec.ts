import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {createPublicClient, createWalletClient, encodeAbiParameters, encodeFunctionData, http, type Hex, type PublicClient, type WalletClient} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {loadArtifact} from "../../../../script/deploy/artifacts.js";
import {loadVectors, type Vectors} from "../../relay/buildAlgorandLiveProof.js";
import {CHUNKS, CHUNK_BYTES, nibbleTable} from "../../relay/algorand/sumhashTable.js";

/// AlgorandStateProofAccumulator + AlgorandStateProofVerifier against REAL Algorand mainnet and testnet state
/// proofs, replayed offline on anvil from test/e2e/fixtures/algorand-live/ (re-capture with
/// `npm run algorand-live:refresh`; testnet: `ALGORAND_NETWORK=testnet npm run algorand-live:refresh`).
///
/// Bootstrap from the message of interval i − 1, one `submitReveals` transaction per reveal (Falcon-1024
/// + SumHash512 paths), `finalize` (weights + SHAKE256 coins), then prove a real application call of
/// interval i through the light-header and SHA-256 transaction commitments. Gas is read from receipts.
///
/// Run: forge build && npm run test:e2e:algorand-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8643);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HEDERA_GAS = 15_000_000n;
const HEDERA_CALLDATA = 128 * 1024;

const MESSAGE = {type: "tuple", components: [
    {name: "blockHeadersCommitment", type: "bytes32"},
    {name: "votersCommitment", type: "bytes"},
    {name: "lnProvenWeight", type: "uint64"},
    {name: "firstAttestedRound", type: "uint64"},
    {name: "lastAttestedRound", type: "uint64"},
]} as const;
const TX_PROOF = [{type: "tuple", components: [
    {name: "intervalLastRound", type: "uint64"},
    {name: "blockHash", type: "bytes32"},
    {name: "round", type: "uint64"},
    {name: "txnCommitment", type: "bytes32"},
    {name: "headerPath", type: "bytes"},
    {name: "txIndex", type: "uint64"},
    {name: "txPath", type: "bytes"},
    {name: "txid", type: "bytes32"},
    {name: "stib", type: "bytes"},
]}] as const;

const msg = (m: Vectors["msg"]) => ({
    blockHeadersCommitment: m.blockHeadersCommitment as Hex,
    votersCommitment: m.votersCommitment as Hex,
    lnProvenWeight: BigInt(m.lnProvenWeight),
    firstAttestedRound: BigInt(m.firstAttestedRound),
    lastAttestedRound: BigInt(m.lastAttestedRound),
});

describe.each(["mainnet", "testnet"])("Algorand state proofs on live %s data (fixture replay)", (network) => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let v: Vectors;
    const addr: Record<string, Hex> = {};
    let root: Hex;

    async function deploy(name: string, args: unknown[] = []): Promise<Hex> {
        const art = loadArtifact(name);
        const hash = await wallet.deployContract({abi: art.abi as never, bytecode: art.bytecode, args: args as never,
            account: wallet.account!, chain: null, gas: 29_000_000n});
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress || r.status !== "success") throw new Error(`deploy ${name}`);
        return r.contractAddress;
    }

    async function send(name: string, to: Hex, fn: string, args: unknown[]) {
        const abi = loadArtifact(name).abi;
        const data = encodeFunctionData({abi, functionName: fn, args} as never);
        const hash = await wallet.sendTransaction({to, data, account: wallet.account!, chain: null, gas: 29_000_000n});
        const r = await pub.waitForTransactionReceipt({hash});
        if (r.status !== "success") throw new Error(`${fn} reverted`);
        return {gas: r.gasUsed, calldata: (data.length - 2) / 2};
    }

    beforeAll(async () => {
        v = loadVectors(network);
        anvil = spawn("anvil", ["--port", String(ANVIL_PORT), "--silent", "--code-size-limit", "24576", "--gas-limit", "30000000"], {stdio: "ignore"});
        const rpc = `http://127.0.0.1:${ANVIL_PORT}`;
        pub = createPublicClient({transport: http(rpc), pollingInterval: 50}) as PublicClient;
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
        addr.shake = await deploy("ClprShake256Engine");
        const table = nibbleTable();
        const chunks: Hex[] = [];
        for (let i = 0; i < CHUNKS; i++) {
            const code = Buffer.concat([Buffer.from([0]), table.subarray(i * CHUNK_BYTES, (i + 1) * CHUNK_BYTES)]);
            chunks.push(await deploy("ClprSumHashTableChunk", ["0x" + code.toString("hex")]));
        }
        addr.sumhash = await deploy("ClprSumHash512Engine", [chunks]);
        addr.falcon = await deploy("ClprFalconDet1024Engine", [addr.shake]);
        addr.acc = await deploy("AlgorandStateProofAccumulator", [addr.sumhash, addr.shake, addr.falcon]);
        addr.v = await deploy("AlgorandStateProofVerifier", [addr.acc]);
        for (const n of ["ClprShake256Engine", "ClprSumHash512Engine", "ClprFalconDet1024Engine", "AlgorandStateProofAccumulator", "AlgorandStateProofVerifier"]) {
            const key = {ClprShake256Engine: "shake", ClprSumHash512Engine: "sumhash", ClprFalconDet1024Engine: "falcon", AlgorandStateProofAccumulator: "acc", AlgorandStateProofVerifier: "v"}[n]!;
            const code = await pub.getCode({address: addr[key]});
            console.log(`[algorand-live ${network}] ${n} runtime ${(code!.length - 2) / 2} B`);
        }
    }, 600_000);

    afterAll(() => {
        anvil?.kill("SIGTERM");
    });

    it("accumulates a real state proof: bootstrap, one reveal per transaction, finalize", async () => {
        const accAbi = loadArtifact("AlgorandStateProofAccumulator").abi;
        await send("AlgorandStateProofAccumulator", addr.acc, "bootstrap", [msg(v.prev)]);
        // root = SHA-256 message hash of the bootstrap message (the Bootstrapped event's indexed topic)
        const logs = await pub.getLogs({address: addr.acc, fromBlock: 0n});
        root = logs[0].topics[1] as Hex;
        const header = {
            root,
            prevLastRound: BigInt(v.prev.lastAttestedRound),
            message: msg(v.msg),
            sigCommit: v.sigCommit as Hex,
            signedWeight: BigInt(v.signedWeight),
            saltVersion: v.saltVersion,
            treeDepth: v.sigDepth,
        };
        let total = 0n;
        let max = 0n;
        let maxCalldata = 0;
        for (const r of v.reveals) {
            const reveal = {
                pos: BigInt(r.pos), l: BigInt(r.l), weight: BigInt(r.weight), keyLifetime: BigInt(r.keyLifetime),
                commitment: r.commitment as Hex, sigCT: r.sigCT as Hex, vkey: r.vkey as Hex, vcIdx: BigInt(r.vcIdx),
                keyPath: r.keyPath as Hex, sigPath: r.sigPath as Hex, partPath: r.partPath as Hex,
            };
            const {gas, calldata} = await send("AlgorandStateProofAccumulator", addr.acc, "submitReveals", [header, [reveal]]);
            total += gas;
            if (gas > max) max = gas;
            if (calldata > maxCalldata) maxCalldata = calldata;
            expect(gas).toBeLessThan(HEDERA_GAS);
            expect(calldata).toBeLessThan(HEDERA_CALLDATA);
        }
        const fin = await send("AlgorandStateProofAccumulator", addr.acc, "finalize", [header, v.positions.map(BigInt)]);
        console.log(`[algorand-live ${network}] ${v.reveals.length} submitReveals transactions: max ${max} gas, total ${total} gas, max calldata ${maxCalldata} B`);
        console.log(`[algorand-live ${network}] finalize (${v.positions.length} coins): ${fin.gas} gas, ${fin.calldata} B`);
        expect(fin.gas).toBeLessThan(HEDERA_GAS);
        const iv = await pub.readContract({address: addr.acc, abi: accAbi as never, functionName: "interval",
            args: [root, BigInt(v.msg.lastAttestedRound)]}) as {blockHeadersCommitment: Hex};
        expect(iv.blockHeadersCommitment).toBe(v.msg.blockHeadersCommitment);
    }, 900_000);

    it("proves a real application call of the accumulated interval", async () => {
        const vAbi = loadArtifact("AlgorandStateProofVerifier").abi;
        const txProof = encodeAbiParameters(TX_PROOF, [{
            intervalLastRound: BigInt(v.msg.lastAttestedRound),
            blockHash: v.header.blockHash as Hex,
            round: BigInt(v.header.round),
            txnCommitment: v.header.txnCommitment as Hex,
            headerPath: v.header.path as Hex,
            txIndex: BigInt(v.tx.index),
            txPath: v.tx.path as Hex,
            txid: v.tx.txid as Hex,
            stib: v.tx.stib as Hex,
        }]);
        const anchor = (root + v.header.genesisHash.slice(2)) as Hex;
        const r = await pub.readContract({address: addr.v, abi: vAbi as never, functionName: "verifyTransaction", args: [txProof, anchor]}) as
            {round: bigint; appId: bigint; logs: Hex[]};
        expect(r.round).toBe(BigInt(v.header.round));
        expect(r.appId).toBe(BigInt(v.tx.appId));
        expect(r.logs).toEqual(v.tx.logs);
        const gas = await pub.estimateContractGas({address: addr.v, abi: vAbi as never, functionName: "verifyTransaction", args: [txProof, anchor], account: wallet.account!});
        console.log(`[algorand-live ${network}] verifyTransaction (live block ${v.header.round}): eth_estimateGas ${gas}, proof ${(txProof.length - 2) / 2} B`);
        expect(gas).toBeLessThan(HEDERA_GAS);
        // a flipped byte in the SignedTxnInBlock breaks the transaction commitment
        const at = txProof.indexOf(v.tx.stib.slice(2)) + v.tx.stib.length - 40; // inside the log bytes
        const bad = (txProof.slice(0, at) + (txProof.slice(at, at + 2) === "00" ? "01" : "00") + txProof.slice(at + 2)) as Hex;
        await expect(pub.readContract({address: addr.v, abi: vAbi as never, functionName: "verifyTransaction", args: [bad, anchor]})).rejects.toThrow();
    });
});
