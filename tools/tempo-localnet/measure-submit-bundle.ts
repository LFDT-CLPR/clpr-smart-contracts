// Full ClprService flow on one chain: deploy, wire a channel + connector + endpoint (zero economics),
// then measure sendMessage and submitBundle transactions from their receipts.
// usage: [FUND=1] npx tsx tools/tempo-localnet/measure-submit-bundle.ts <label> <rpcUrl> [outJson]
// FUND=1 stakes 0.1 ETH and prefunds the mock connector with 1 ETH (Ethereum happy path; impossible on Tempo).
import {createHash} from "node:crypto";
import {writeFileSync} from "node:fs";
import {decodeEventLog, encodeFunctionData, encodePacked, keccak256, type Hex} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {secp256k1} from "@noble/curves/secp256k1";
import {makeDeployClients} from "../../script/deploy/client.ts";
import {deployE2E} from "../../script/deploy/deployCore.ts";
import {applyInitialConfig} from "../../script/deploy/applyConfig.ts";
import {loadArtifact} from "../../script/deploy/artifacts.ts";
import {defaultThrottles, defaultEconomicConfig} from "../../script/deploy/index.ts";
import {deriveConnectorId, connectorCommitment, digestForConnectorReveal, uncompressedPubKey64} from "../../test/e2e/lib/ids.ts";

const KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;
const [label, rpcUrl, outJson] = process.argv.slice(2);
const ZERO32 = ("0x" + "00".repeat(32)) as Hex;
const PEER_CHAIN_ID = "eip155:31337";
const sha256 = (b: Buffer) => createHash("sha256").update(b).digest();
const hex = (b: Buffer) => ("0x" + b.toString("hex")) as Hex;
const buf = (h: Hex) => Buffer.from(h.slice(2), "hex");

const c = await makeDeployClients({rpcUrl, privateKey: KEY});
const chainId = await c.publicClient.getChainId();
const rows: {op: string; gasUsed: number; calldataBytes: number; events: string[]}[] = [];
let allAbi: unknown[] = [];

async function write(to: Hex, abi: unknown, functionName: string, args: unknown[], value = 0n, gas?: bigint) {
    const hash = await c.walletClient.writeContract({address: to, abi: abi as never, functionName, args, chain: c.chain, account: c.account, value, gas});
    const r = await c.publicClient.waitForTransactionReceipt({hash});
    if (r.status !== "success") throw new Error(`${functionName} reverted (${hash})`);
    return r;
}
async function measure(op: string, to: Hex, abi: unknown, functionName: string, args: unknown[]) {
    const data = encodeFunctionData({abi: abi as never, functionName, args});
    let r;
    try {
        // Explicit gas: eth_estimateGas runs with gasPrice 0 and skips the charge path, so it undershoots.
        r = await write(to, abi, functionName, args, 0n, 20_000_000n);
    } catch (e: any) {
        console.error(`[${label}] ${op}: FAILED ${e.shortMessage ?? e.message} ${e.cause?.data ?? e.cause?.reason ?? ""}`);
        throw e;
    }
    const events: string[] = [];
    for (const l of r.logs) {
        try {
            const ev: any = decodeEventLog({abi: allAbi as never, data: l.data, topics: l.topics});
            events.push(ev.eventName + (ev.args?.status !== undefined ? `(status=${ev.args.status})` : ""));
        } catch { events.push(`?${l.topics[0]?.slice(0, 10)}@${l.address.slice(0, 8)}`); }
    }
    rows.push({op, gasUsed: Number(r.gasUsed), calldataBytes: (data.length - 2) / 2, events});
    console.error(`[${label}] ${op.padEnd(52)} gasUsed=${String(r.gasUsed).padStart(8)}  ${events.join(", ")}`);
}

// ── Deploy + configure (zero economics: Tempo has no native value) ───────────
const params = {
    initialOwner: c.account.address, protocolVersion: 1, chainId: `eip155:${chainId}`, serviceAddress: "0x" as Hex,
    // Per-message gas limits raised for Tempo: a 250,000-gas slot makes Ethereum-sized limits fail inside the app.
    throttles: {...defaultThrottles, maxGasPerMessage: 8_000_000n}, trustAnchor: "0x" as Hex, trustAnchorId: "0x" as Hex,
    econ: {...defaultEconomicConfig, messageExecutionCost: 0n, minLockedStake: 0n, minEndpointBond: 0n, basePenalty: 0n, connectorInboundGasStipend: 3_000_000n}
};
const d = await deployE2E(c, params as never);
await applyInitialConfig(c, d.clprService, params as never, {autoEnable: true});
const svc = loadArtifact("ClprService"), e2e = loadArtifact("E2EVerifier"), app = loadArtifact("E2EApplication"), enc = loadArtifact("BundleEncoderHelper");
allAbi = [...(svc.abi as unknown[]), ...(loadArtifact("BundleLogic").abi as unknown[]), ...(loadArtifact("MessagingLogic").abi as unknown[]), ...(loadArtifact("MockClprConnector").abi as unknown[]), ...(app.abi as unknown[])];
await write(d.verifier, e2e.abi, "configure", [PEER_CHAIN_ID, "0x000000000000000000000000000000000000beef", 0n, params.throttles, "0x01", "0x01", []]);

// ── Channel ─────────────────────────────────────────────────────────────────
const peerPk = ("0x" + (0xc0de).toString(16).padStart(64, "0")) as Hex;
const peer = privateKeyToAccount(peerPk);
const peerPub = ("0x" + Buffer.from(secp256k1.getPublicKey(peerPk.slice(2), false).slice(1)).toString("hex")) as Hex;
const channelId = (await c.publicClient.readContract({address: d.clprService, abi: svc.abi as never, functionName: "deriveChannelId", args: [PEER_CHAIN_ID, peerPub, ZERO32]})) as Hex;
await write(d.clprService, svc.abi, "registerChannel", [channelId, keccak256(encodePacked(["bytes32", "bytes"], [channelId, peerPub]))]);
const chSig = await peer.signMessage({message: {raw: keccak256(encodePacked(["bytes32", "address"], [channelId, d.clprService]))}});
await write(d.clprService, svc.abi, "completeChannel", [channelId, peerPub, chSig, ZERO32, d.verifier, "0x", "0x"]);

// ── Endpoint + connector ────────────────────────────────────────────────────
await write(d.clprService, svc.abi, "registerEndpoint", [{ipAddress: "10.0.0.1", port: 50211, tlsCertificate: "0x", accountId: "0x"}]);
const FUND = process.env.FUND === "1";
async function wireConnector(seed: number): Promise<Hex> {
    const pk = ("0x" + seed.toString(16).padStart(64, "0")) as Hex;
    const acct = privateKeyToAccount(pk);
    const pub = uncompressedPubKey64(acct.publicKey);
    const id = deriveConnectorId({channelId, pubKey: pub, salt: ZERO32});
    await write(d.clprService, svc.abi, "registerConnector", [connectorCommitment(id, pub)]);
    const sig = await acct.signMessage({message: {raw: digestForConnectorReveal(id, d.clprService)}});
    await write(d.clprService, svc.abi, "completeConnector", [id, pub, sig, ZERO32, channelId, d.connectorContract, c.account.address], FUND ? 10n ** 17n : 0n);
    return id;
}
let connectorId = await wireConnector(0xc011);
if (FUND) {
    const h = await c.walletClient.sendTransaction({account: c.account, chain: c.chain, to: d.connectorContract, value: 10n ** 18n});
    await c.publicClient.waitForTransactionReceipt({hash: h});
}
console.error(`[${label}] service ${d.clprService} channel ${channelId} connector ${connectorId} funded=${FUND}`);

// ── Helpers ─────────────────────────────────────────────────────────────────
const target = d.application as Hex; // 20-byte target application
const payloadOf = async (id: number): Promise<Hex> => {
    const m: any = await c.publicClient.readContract({address: d.clprService, abi: svc.abi as never, functionName: "getMessage", args: [channelId, BigInt(id)]});
    return (m.payload ?? m[0]) as Hex;
};
let peerHash = Buffer.alloc(32); // the peer's running hash, starting at zero
let peerNext = 1; // the peer's next message id
async function inbound(op: string, payloads: Hex[], ackUpTo: number) {
    for (const p of payloads) peerHash = sha256(Buffer.concat([peerHash, sha256(buf(p))]));
    peerNext += payloads.length;
    const meta = {nextMessageId: BigInt(peerNext), sentRunningHash: hex(peerHash), receivedMessageId: BigInt(ackUpTo), receivedRunningHash: ZERO32, state: 1, endpointManifestVersion: 0n,
        lastMessageId: payloads.length > 0 ? BigInt(peerNext - 1) : 0n, lastMessageRunningHash: payloads.length > 0 ? hex(peerHash) : ZERO32};
    const proof = (await c.publicClient.readContract({address: d.bundleEncoder, abi: enc.abi as never, functionName: "encode", args: [meta, payloads]})) as Hex;
    await measure(op, d.clprService, svc.abi, "submitBundle", [channelId, proof]);
}
let connectorSeed = 0xc011;
async function send(op: string, data: Hex) {
    const alive = await c.publicClient.readContract({address: d.clprService, abi: svc.abi as never, functionName: "hasConnector", args: [channelId, connectorId]});
    if (!alive) {
        // Without the free-execution fix the connector is banned by the first inbound DATA on Tempo.
        connectorId = await wireConnector(++connectorSeed);
        console.error(`[${label}] connector was banned; registered a fresh one ${connectorId}`);
        op += " [fresh connector]";
    }
    await measure(op, d.application, app.abi, "send", [d.clprService, channelId, connectorId, target, data]);
}
const data16 = ("0x" + "01020304050607080910111213141516") as Hex;
const data512 = ("0x" + Buffer.from(Array.from({length: 512}, (_, i) => (i + 1) & 0xff)).toString("hex")) as Hex;

// ── Measured sequence (mirrors test/gas/TempoStorageWrites.t.sol) ───────────
await send("sendMessage, first on channel, 16B data", data16);           // our slot 1 = DATA
await inbound("submitBundle, 1 inbound DATA 16B (+1 REPLY enqueued)", [await payloadOf(1)], 0); // peer msg 1; our slot 2 = REPLY(1)
await inbound("submitBundle, 1 inbound REPLY (acks our DATA 1)", [await payloadOf(2)], 1);      // peer msg 2 = REPLY for our DATA 1
await inbound("submitBundle, ack-only (acks our REPLY 2)", [], 2);
await send("sendMessage, steady state, 16B data", data16);                // slot 3
await send("sendMessage, steady state, 512B data", data512);              // slot 4
await inbound("submitBundle, 1 inbound DATA 512B (+1 REPLY enqueued)", [await payloadOf(4)], 2); // peer msg 3; our slot 5 = REPLY(3)
await send("sendMessage, steady state, 16B data (again)", data16);        // slot 6
await send("sendMessage, steady state, 512B data (again)", data512);      // slot 7
const ch: any = await c.publicClient.readContract({address: d.clprService, abi: svc.abi as never, functionName: "getChannel", args: [channelId]});
console.error(`[${label}] channel status ${ch.status} next ${ch.nextMessageId} acked ${ch.ackedMessageId} received ${ch.receivedMessageId}`);
if (outJson) writeFileSync(outJson, JSON.stringify({label, chainId, rows}, null, 2));
console.log(JSON.stringify(rows));
