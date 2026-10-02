import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {readFileSync} from "node:fs";
import {createPublicClient, createWalletClient, decodeAbiParameters, encodeAbiParameters, encodeFunctionData, http, keccak256, toHex, type Hex} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {foundry} from "viem/chains";
import {loadArtifact} from "../../../../script/deploy/artifacts.js";
import {AnvilNode} from "../../backend/anvil/AnvilNode.js";
import {BCH_ASERT_ANCHOR, BCH_ASERT_HALF_LIFE, BCH_CAIP2, BCH_POW_LIMIT} from "../../relay/fetchBitcoinCashLive.js";

/// BitcoinCashVerifier against REAL Bitcoin Cash mainnet headers, replayed offline on anvil from
/// test/e2e/fixtures/bitcoin-cash-live/ (re-capture: `npm run bitcoin-cash-live:refresh`).
///
/// The production contract is deployed with BCHN's mainnet ASERT anchor and a checkpoint at the
/// first fixture header; verifyBundle then validates real headers (linkage, ASERT nBits, proof of
/// work) and advances the checkpoint to tip - k + 1. No CLPR message has been sent on Bitcoin Cash,
/// so the bundles carry headers only; the message path is the unchanged BitcoinVerifier code.
///
/// Run: forge build && npm run test:e2e:bitcoin-cash-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8571);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const K = 6;
const FIXTURE = "test/e2e/fixtures/bitcoin-cash-live/mainnet-recent.json";

const CHECKPOINT = {
    type: "tuple",
    components: [
        {name: "blockHash", type: "bytes32"},
        {name: "height", type: "uint32"},
        {name: "chainWork", type: "uint256"},
        {name: "bits", type: "uint32"},
        {name: "time", type: "uint32"},
        {name: "periodStartTime", type: "uint32"}
    ]
} as const;
const TRUST_ANCHOR = [
    {
        type: "tuple",
        components: [
            {name: "checkpoint", ...CHECKPOINT},
            {name: "cursorTxid", type: "bytes32"},
            {name: "cursorVout", type: "uint32"},
            {name: "lastMessageId", type: "uint64"},
            {name: "runningHash", type: "bytes32"},
            {name: "confirmations", type: "uint8"}
        ]
    }
] as const;
const BUNDLE_PROOF = [
    {
        type: "tuple",
        components: [
            {name: "startHeight", type: "uint32"},
            {name: "headers", type: "bytes"},
            {
                name: "messages",
                type: "tuple[]",
                components: [
                    {name: "headerIndex", type: "uint32"},
                    {name: "txIndex", type: "uint32"},
                    {name: "merkleBranch", type: "bytes32[]"},
                    {name: "rawTx", type: "bytes"},
                    {name: "payload", type: "bytes"}
                ]
            }
        ]
    }
] as const;

interface FixtureHeader {
    height: number;
    hashInternal: Hex;
    header: Hex;
    time: number;
    bits: Hex;
}

describe("BitcoinCashVerifier on live Bitcoin Cash mainnet headers (fixture replay)", () => {
    const fx = JSON.parse(readFileSync(FIXTURE, "utf8")) as {startHeight: number; headers: FixtureHeader[]};
    const h0 = fx.headers[0];
    const checkpoint = {
        blockHash: h0.hashInternal,
        height: h0.height,
        chainWork: 10n ** 30n,
        bits: Number(h0.bits),
        time: h0.time,
        periodStartTime: 0
    };
    const trustAnchor = encodeAbiParameters(TRUST_ANCHOR, [
        {
            checkpoint,
            cursorTxid: keccak256(toHex("cursor")),
            cursorVout: 1,
            lastMessageId: 0n,
            runningHash: toHex(0n, {size: 32}),
            confirmations: K
        }
    ]);
    const channelContext = (keccak256(toHex("bch channel")) + "0014" + "00".repeat(20)) as Hex;
    const art = loadArtifact("BitcoinCashVerifier");
    const account = privateKeyToAccount(ANVIL_KEY);
    let anvil: AnvilNode;
    let verifier: Hex;
    const pub = () => createPublicClient({chain: foundry, transport: http(`http://127.0.0.1:${ANVIL_PORT}`)});

    const proofFor = (n: number, tamper?: (b: Buffer) => void): Hex => {
        const buf = Buffer.concat(fx.headers.slice(1, 1 + n).map((h) => Buffer.from(h.header.slice(2), "hex")));
        tamper?.(buf);
        return encodeAbiParameters(BUNDLE_PROOF, [
            {startHeight: fx.startHeight + 1, headers: ("0x" + buf.toString("hex")) as Hex, messages: []}
        ]);
    };
    const call = (proof: Hex) =>
        pub().readContract({
            address: verifier, abi: art.abi as never, functionName: "verifyBundle",
            args: [proof, trustAnchor, channelContext]
        }) as Promise<[{nextMessageId: bigint}, Hex[], Hex, Hex, unknown]>;

    beforeAll(async () => {
        anvil = new AnvilNode(ANVIL_PORT, 31337);
        await anvil.start();
        const wallet = createWalletClient({account, chain: foundry, transport: http(`http://127.0.0.1:${ANVIL_PORT}`)});
        const hash = await wallet.deployContract({
            abi: art.abi as never,
            bytecode: art.bytecode,
            args: [BCH_POW_LIMIT, K, 4096n, BCH_CAIP2, checkpoint, BCH_ASERT_ANCHOR, BCH_ASERT_HALF_LIFE]
        });
        const r = await pub().waitForTransactionReceipt({hash});
        verifier = r.contractAddress!;
        const code = await pub().getCode({address: verifier});
        console.log(`[bch-live] BitcoinCashVerifier runtime ${(code!.length - 2) / 2} B, deploy gas ${r.gasUsed}`);
    }, 60_000);

    afterAll(async () => {
        await anvil?.stop();
    });

    for (const n of [6, 144]) {
        it(`verifyBundle: ${n} real headers (ASERT nBits, PoW, linkage), checkpoint moves to tip - k + 1`, async () => {
            const proof = proofFor(n);
            const [meta, payloads, newAnchor] = await call(proof);
            expect(meta.nextMessageId).toBe(1n);
            expect(payloads).toEqual([]);
            const [a] = decodeAbiParameters(TRUST_ANCHOR, newAnchor);
            const cpIdx = n - K + 1;
            expect(a.checkpoint.height).toBe(fx.headers[cpIdx].height);
            expect(a.checkpoint.blockHash).toBe(fx.headers[cpIdx].hashInternal);
            expect(a.checkpoint.bits).toBe(Number(fx.headers[cpIdx].bits));

            const data = encodeFunctionData({
                abi: art.abi as never, functionName: "verifyBundle", args: [proof, trustAnchor, channelContext]
            } as never);
            const gas = await pub().estimateGas({account: account.address, to: verifier, data});
            const calldata = (data.length - 2) / 2;
            console.log(`[bch-live] ${n} headers: eth_estimateGas ${gas}, calldata ${calldata} B`);
            expect(gas).toBeLessThan(15_000_000n);
            expect(calldata).toBeLessThan(128 * 1024);
        });
    }

    it("rejects a header whose nBits is not the ASERT value", async () => {
        const proof = proofFor(6, (b) => {
            b[2 * 80 + 72] ^= 0x01;
        });
        await expect(call(proof)).rejects.toThrow(/WrongDifficultyBits/);
    });

    it("rejects a header that does not meet its target", async () => {
        const proof = proofFor(6, (b) => {
            b[2 * 80 + 76] ^= 0x01;
        });
        await expect(call(proof)).rejects.toThrow(/InsufficientProofOfWork/);
    });

    it("rejects headers that skip a block", async () => {
        const proof = proofFor(6, (b) => {
            b.copy(b, 2 * 80, 3 * 80, 4 * 80);
        });
        await expect(call(proof)).rejects.toThrow(/BrokenLinkage/);
    });
});
