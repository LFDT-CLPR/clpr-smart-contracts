import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {
    createPublicClient,
    createWalletClient,
    encodeAbiParameters,
    encodeFunctionData,
    http,
    keccak256,
    serializeSignature,
    type Hex,
    type PublicClient,
    type WalletClient
} from "viem";
import {privateKeyToAccount, sign} from "viem/accounts";
import {loadArtifact} from "../../../../script/deploy/artifacts.js";
import {
    ABI,
    buildGenesisProof,
    loadGenesisCapture,
    votePayload,
    type SolanaGenesisProof
} from "../../relay/buildSolanaAlpenglowProof.js";

/// Solana Alpenglow verifiers against REAL devnet data, replayed offline from
/// test/e2e/fixtures/solana-live/devnet-genesis.json (re-capture: `npm run solana-live:refresh`).
///
/// The fixture is devnet's Alpenglow genesis certificate (`getAgGenesisCert`, slot 504,148,999,
/// 11 of 17 ranked signers, BLS12-381 aggregate) and the vote accounts' on-chain BLS keys and stakes.
/// `AlpenglowFinalityVerifier` checks it with EIP-2537 exactly as Agave's `verify_certificate` does.
/// The same certificate then anchors a full `SolanaVerifier.verifyBundle` in ALPENGLOW mode; the
/// queue attestation is signed by a test committee, because no CLPR program exists on Solana yet.
///
/// Run: forge build && npx vitest run test/e2e/tests/verifiers/solana-live.spec.ts

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8597);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const COMMITTEE_KEYS: Hex[] = [1, 2, 3, 4, 5].map((i) => keccak256(`0x${i.toString(16).padStart(2, "0")}`));
const CHAIN = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const PROGRAM = keccak256("0x636c7072"); // stand-in CLPR program id
const CHANNEL = keccak256("0x01");

const COMMITTEE = {
    type: "tuple",
    components: [
        {name: "nonce", type: "uint64"},
        {name: "threshold", type: "uint16"},
        {name: "members", type: "address[]"}
    ]
} as const;
const SIGS = {type: "tuple", components: [{name: "memberIndex", type: "uint16[]"}, {name: "sigs", type: "bytes[]"}]} as const;
const QUEUE_ATT = {
    type: "tuple",
    components: [
        {name: "programId", type: "bytes32"}, {name: "channelId", type: "bytes32"}, {name: "slot", type: "uint64"},
        {name: "blockRef", type: "bytes32"}, {name: "status", type: "uint8"}, {name: "nextMessageId", type: "uint64"},
        {name: "sentRunningHash", type: "bytes32"}, {name: "receivedMessageId", type: "uint64"},
        {name: "receivedRunningHash", type: "bytes32"}, {name: "endpointManifestVersion", type: "uint64"},
        {name: "manifestCommitment", type: "bytes32"}
    ]
} as const;
const BUNDLE = {
    type: "tuple",
    components: [
        {name: "committee", ...COMMITTEE},
        {name: "rotations", type: "tuple[]", components: [{name: "next", ...COMMITTEE}, {name: "sigs", ...SIGS}]},
        {name: "setUpdates", type: "tuple[]", components: [{name: "set", ...ABI.EPOCH_SET}, {name: "sigs", ...SIGS}]},
        {name: "attestation", ...QUEUE_ATT},
        {name: "sigs", ...SIGS},
        {name: "finality", type: "bytes"},
        {name: "bundleContent", type: "bytes"},
        {name: "manifestPreimage", type: "bytes"}
    ]
} as const;
const ANCHOR = [
    {type: "uint8"}, {type: "bytes32"}, {type: "uint64"}, {type: "bytes32"}, {type: "bytes32"}, {type: "uint64"}
] as const;

function byteLen(h: Hex): number {
    return (h.length - 2) / 2;
}

describe("Solana Alpenglow verifiers on live devnet data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let ag: Hex;
    let sv: Hex;
    let live: SolanaGenesisProof;
    const agArt = loadArtifact("AlpenglowFinalityVerifier");
    const svArt = loadArtifact("SolanaVerifier");
    const members = COMMITTEE_KEYS.map((k) => ({k, a: privateKeyToAccount(k).address}))
        .sort((x, y) => (BigInt(x.a) < BigInt(y.a) ? -1 : 1));
    const committee = {nonce: 0n, threshold: 3, members: members.map((m) => m.a)};
    const committeeHash = keccak256(encodeAbiParameters(
        [{type: "uint64"}, {type: "uint16"}, {type: "address[]"}], [0n, 3, committee.members]));

    async function deploy(abi: readonly unknown[], bytecode: Hex, args: unknown[] = []): Promise<Hex> {
        const hash = await wallet.deployContract({abi: abi as never, bytecode, args: args as never,
            account: wallet.account!, chain: null});
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error("deploy failed");
        return r.contractAddress;
    }

    const read = (address: Hex, abi: readonly unknown[], functionName: string, args: unknown[]) =>
        pub.readContract({address, abi: abi as never, functionName, args: args as never});

    async function gasOf(address: Hex, abi: readonly unknown[], functionName: string, args: unknown[]) {
        const gas = await pub.estimateContractGas({address, abi: abi as never, functionName, args: args as never,
            account: wallet.account!});
        const calldata = encodeFunctionData({abi: abi as never, functionName, args: args as never});
        return {gas, calldataBytes: byteLen(calldata)};
    }

    beforeAll(async () => {
        live = buildGenesisProof(loadGenesisCapture("devnet"));
        anvil = spawn("anvil", ["--port", String(ANVIL_PORT), "--silent"], {stdio: "ignore"});
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
        ag = await deploy(agArt.abi, agArt.bytecode);
        sv = await deploy(svArt.abi, svArt.bytecode, [CHAIN, committeeHash, ag]);
    });

    afterAll(() => {
        anvil?.kill("SIGTERM");
    });

    it("builder: the live certificate verifies off-chain against the rebuilt rank map", () => {
        expect(live.meta.offchainVerified).toBe(true);
        expect(live.meta.slot).toBe(504_148_999);
        expect(live.meta.nbits).toBe(17);
        expect(live.meta.signers).toBe(11);
        expect(live.meta.signedStake * 100n).toBeGreaterThanOrEqual(82n * live.meta.totalStake);
    });

    it("builder: payload bytes match the contract (wire.rs VotePayloadToSign)", async () => {
        const p = votePayload(6, BigInt(live.meta.slot), Buffer.from(live.finality.blockId.slice(2), "hex"),
            live.set.shredVersion);
        const onchain = await read(ag, agArt.abi, "payload", [6, BigInt(live.meta.slot), live.finality.blockId, true,
            live.set.shredVersion]);
        expect(onchain).toBe(`0x${p.toString("hex")}`);
    });

    it("AlpenglowFinalityVerifier accepts the real devnet genesis certificate", async () => {
        const signed = await read(ag, agArt.abi, "verifyFinality", [live.finality, live.set]) as bigint;
        expect(signed).toBe(live.meta.signedStake);
        const {gas, calldataBytes} = await gasOf(ag, agArt.abi, "verifyFinality", [live.finality, live.set]);
        console.log(`[solana-live] devnet genesis cert slot ${live.meta.slot}: set ${live.meta.setSize}, ` +
            `${live.finality.aggregates[0].entries.length} non-signer entries | eth_estimateGas ${gas}, calldata ${calldataBytes} B`);
    });

    it("rejects the real signature under another shred version or block id", async () => {
        await expect(read(ag, agArt.abi, "verifyFinality", [live.finality, {...live.set, shredVersion: live.set.shredVersion ^ 1}]))
            .rejects.toThrow(/BlsSignatureInvalid/);
        const bad = {...live.finality, blockId: keccak256(live.finality.blockId)};
        await expect(read(ag, agArt.abi, "verifyFinality", [bad, live.set])).rejects.toThrow(/BlsSignatureInvalid/);
    });

    it("rejects a non-signer entry with a wrong stake (Merkle proof)", async () => {
        const agg = live.finality.aggregates[0];
        const entries = agg.entries.map((e, i) => (i === 0 ? {...e, stake: e.stake + 1n} : e));
        const bad = {...live.finality, aggregates: [{...agg, entries}]};
        await expect(read(ag, agArt.abi, "verifyFinality", [bad, live.set])).rejects.toThrow(/EntryProofInvalid/);
    });

    async function bundle(blockRef: Hex) {
        const att = {
            programId: PROGRAM, channelId: CHANNEL, slot: BigInt(live.meta.slot), blockRef, status: 1,
            nextMessageId: 2n, sentRunningHash: keccak256("0xaa"), receivedMessageId: 0n,
            receivedRunningHash: `0x${"00".repeat(32)}` as Hex, endpointManifestVersion: 0n,
            manifestCommitment: `0x${"00".repeat(32)}` as Hex
        };
        const digest = await read(sv, svArt.abi, "queueDigest", [committeeHash, att]) as Hex;
        const sigs: Hex[] = [];
        for (const m of members.slice(0, 3)) sigs.push(serializeSignature(await sign({hash: digest, privateKey: m.k})));
        const finality = encodeAbiParameters([ABI.FINALITY, ABI.EPOCH_SET], [live.finality, live.set] as never);
        return encodeAbiParameters([BUNDLE], [{
            committee, rotations: [], setUpdates: [], attestation: att, sigs: {memberIndex: [0, 1, 2], sigs},
            finality, bundleContent: "0x120161", manifestPreimage: "0x"
        }] as never);
    }

    it("SolanaVerifier.verifyBundle (ALPENGLOW mode) accepts an attestation anchored by the live certificate", async () => {
        const setHash = await read(ag, agArt.abi, "setHash", [live.set]) as Hex;
        const anchor = encodeAbiParameters(ANCHOR, [2, committeeHash, 0n, `0x${"00".repeat(32)}`, setHash, live.set.epoch]);
        const ctx = `${CHANNEL}${PROGRAM.slice(2)}` as Hex;
        const proof = await bundle(live.finality.blockId);
        const [metadata, payloads] = await read(sv, svArt.abi, "verifyBundle", [proof, anchor, ctx]) as
            [{nextMessageId: bigint}, Hex[]];
        expect(metadata.nextMessageId).toBe(2n);
        expect(payloads).toEqual(["0x61"]);
        const {gas, calldataBytes} = await gasOf(sv, svArt.abi, "verifyBundle", [proof, anchor, ctx]);
        console.log(`[solana-live] ALPENGLOW-mode verifyBundle: eth_estimateGas ${gas}, calldata ${calldataBytes} B`);

        const forked = await bundle(keccak256("0x666f726b"));
        await expect(read(sv, svArt.abi, "verifyBundle", [forked, anchor, ctx])).rejects.toThrow(/FinalityTargetMismatch/);
    });
});
