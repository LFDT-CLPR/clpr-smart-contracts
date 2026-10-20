// Full ClprService flow on one chain: deploy, wire a channel + connector + endpoint with real economics,
// then measure sendMessage and submitBundle transactions from their receipts.
// usage: [FEE_TOKEN=<erc20>] [FREE_EXECUTION=1] npx tsx tools/tempo-localnet/measure-submit-bundle.ts <label> <rpcUrl> [outJson]
// Without FEE_TOKEN the service runs on native value: 0.1 ETH connector stake, 1 ETH connector operating
// balance. With FEE_TOKEN (pathUSD 0x20C0000000000000000000000000000000000000 on Tempo, which has no native
// value) it runs in that 6-decimal USD token: 100 USD stake, 10 USD endpoint bond, 1 USD base penalty,
// 10 USD operating balance. FREE_EXECUTION=1 sets messageExecutionCost and every stake and bond to zero.
// The run fails unless every inbound DATA message is delivered (MessageDispatched with SUCCESS) and, when
// execution is charged, paid for (ConnectorCharged).
import {createHash} from "node:crypto";
import {writeFileSync} from "node:fs";
import {decodeEventLog, encodeFunctionData, encodePacked, keccak256, parseAbi, parseEther, type Hex} from "viem";
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

// ── Deploy + configure ──────────────────────────────────────────────────────
const FEE_TOKEN = process.env.FEE_TOKEN as Hex | undefined;
const erc20 = parseAbi([
    "function approve(address spender, uint256 amount) returns (bool)",
    "function transfer(address to, uint256 amount) returns (bool)",
    "function balanceOf(address account) view returns (uint256)"
]);
// The connector callback stipend is raised for Tempo, where a new slot costs 250,000 gas.
const FREE_EXECUTION = process.env.FREE_EXECUTION === "1";
const econ = FREE_EXECUTION
    ? {...defaultEconomicConfig, messageExecutionCost: 0n, minLockedStake: 0n, minEndpointBond: 0n, connectorInboundGasStipend: 3_000_000n}
    : FEE_TOKEN
      ? {...defaultEconomicConfig, minLockedStake: 100_000_000n, minEndpointBond: 10_000_000n, basePenalty: 1_000_000n, connectorInboundGasStipend: 3_000_000n}
      : {...defaultEconomicConfig, connectorInboundGasStipend: 3_000_000n};
const CONNECTOR_FUND = FREE_EXECUTION ? 0n : FEE_TOKEN ? 10_000_000n : parseEther("1");
const params = {
    initialOwner: c.account.address, protocolVersion: 1, chainId: `eip155:${chainId}`, serviceAddress: "0x" as Hex,
    // Per-message gas limits raised for Tempo: a 250,000-gas slot makes Ethereum-sized limits fail inside the app.
    throttles: {...defaultThrottles, maxGasPerMessage: 8_000_000n}, trustAnchor: "0x" as Hex, trustAnchorId: "0x" as Hex,
    econ,
    feeToken: FEE_TOKEN // ClprService constructor argument, fixed for the life of the service
};
async function feeAssetBalance(account: Hex): Promise<bigint> {
    if (!FEE_TOKEN) return c.publicClient.getBalance({address: account});
    return (await c.publicClient.readContract({address: FEE_TOKEN, abi: erc20, functionName: "balanceOf", args: [account]})) as bigint;
}
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
if (FEE_TOKEN) await write(FEE_TOKEN, erc20, "approve", [d.clprService, econ.minEndpointBond]);
await write(d.clprService, svc.abi, "registerEndpoint", [{ipAddress: "10.0.0.1", port: 50211, tlsCertificate: "0x", accountId: "0x"}], FEE_TOKEN ? 0n : econ.minEndpointBond);
async function wireConnector(seed: number): Promise<Hex> {
    const pk = ("0x" + seed.toString(16).padStart(64, "0")) as Hex;
    const acct = privateKeyToAccount(pk);
    const pub = uncompressedPubKey64(acct.publicKey);
    const id = deriveConnectorId({channelId, pubKey: pub, salt: ZERO32});
    await write(d.clprService, svc.abi, "registerConnector", [connectorCommitment(id, pub)]);
    const sig = await acct.signMessage({message: {raw: digestForConnectorReveal(id, d.clprService)}});
    if (FEE_TOKEN) await write(FEE_TOKEN, erc20, "approve", [d.clprService, econ.minLockedStake]);
    await write(d.clprService, svc.abi, "completeConnector", [id, pub, sig, ZERO32, channelId, d.connectorContract, c.account.address], FEE_TOKEN ? 0n : econ.minLockedStake);
    return id;
}
let connectorId = await wireConnector(0xc011);
// Operating balance the mock connector pays payForExecution from, in the fee asset.
if (FREE_EXECUTION) {
    // Nothing to pay from: free execution never calls payForExecution.
} else if (FEE_TOKEN) {
    await write(FEE_TOKEN, erc20, "transfer", [d.connectorContract, CONNECTOR_FUND]);
    await write(d.connectorContract, loadArtifact("MockClprConnector").abi, "setPayToken", [FEE_TOKEN]);
} else {
    const h = await c.walletClient.sendTransaction({account: c.account, chain: c.chain, to: d.connectorContract, value: CONNECTOR_FUND});
    await c.publicClient.waitForTransactionReceipt({hash: h});
}
const feeTokenOnChain = await c.publicClient.readContract({address: d.clprService, abi: svc.abi as never, functionName: "getFeeToken"});
console.error(`[${label}] service ${d.clprService} channel ${channelId} connector ${connectorId} feeToken ${feeTokenOnChain}`);

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
    if (op.includes("inbound DATA")) {
        const ev = rows[rows.length - 1].events;
        if (!ev.includes("MessageDispatched(status=0)")) throw new Error(`${op}: not delivered (${ev.join(", ")})`);
        if (!FREE_EXECUTION && !ev.includes("ConnectorCharged")) throw new Error(`${op}: delivered but not charged`);
    }
}
async function send(op: string, data: Hex) {
    const alive = await c.publicClient.readContract({address: d.clprService, abi: svc.abi as never, functionName: "hasConnector", args: [channelId, connectorId]});
    if (!alive) throw new Error(`${op}: the connector was slashed out`);
    await measure(op, d.application, app.abi, "send", [d.clprService, channelId, connectorId, target, data]);
}
const data16 = ("0x" + "01020304050607080910111213141516") as Hex;
const data512 = ("0x" + Buffer.from(Array.from({length: 512}, (_, i) => (i + 1) & 0xff)).toString("hex")) as Hex;

// ── Measured sequence (mirrors test/gas/TempoStorageWrites.t.sol) ───────────
const connectorFundBefore = await feeAssetBalance(d.connectorContract);
const serviceHeldBefore = await feeAssetBalance(d.clprService);
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
const charged = connectorFundBefore - (await feeAssetBalance(d.connectorContract));
const serviceHeld = await feeAssetBalance(d.clprService);
console.error(`[${label}] execution charges paid by the connector: ${charged} (fee-asset units); service holds ${serviceHeld} (before the sequence: ${serviceHeldBefore})`);
if (FREE_EXECUTION ? charged !== 0n : charged <= 0n) throw new Error(`unexpected execution charge: ${charged}`);
if (serviceHeld !== serviceHeldBefore) throw new Error("charges must pass through the service to the submitter");
if (outJson) writeFileSync(outJson, JSON.stringify({label, chainId, rows}, null, 2));
console.log(JSON.stringify(rows));
