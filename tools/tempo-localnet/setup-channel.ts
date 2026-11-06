// Initialize the ClprService on the local Tempo network and complete one channel on it.
//
//   PRIVATE_KEY=<owner key> CLPR_SERVICE=<address> npx tsx tools/tempo-localnet/setup-channel.ts [rpcUrl]
//
// Prints FIXTURE_OUT::CHANNEL_ID. Set SKIP_INIT=1 when the service is already initialized.
import {secp256k1} from "@noble/curves/secp256k1";
import {encodePacked, keccak256, type Hex} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {makeDeployClients} from "../../script/deploy/client.js";
import {loadDeployParams} from "../../script/deploy/config.js";
import {applyInitialConfig} from "../../script/deploy/applyConfig.js";
import {deployArtifact} from "../../script/deploy/deployCore.js";
import {loadArtifact} from "../../script/deploy/artifacts.js";

const rpcUrl = process.argv[2] ?? "http://127.0.0.1:18545";
const privateKey = process.env.PRIVATE_KEY as Hex | undefined;
const service = process.env.CLPR_SERVICE as Hex | undefined;
if (!privateKey || !service) throw new Error("PRIVATE_KEY and CLPR_SERVICE are required");

const PEER_CHAIN_ID = "eip155:31337";
const PEER_SIGNER_PK = ("0x" + (0xc0de).toString(16).padStart(64, "0")) as Hex;

const clients = await makeDeployClients({rpcUrl, privateKey});
const params = loadDeployParams(privateKey);
const svc = loadArtifact("ClprService");
const write = async (address: Hex, abi: unknown, functionName: string, args: unknown[]) => {
    const hash = await clients.walletClient.writeContract({
        address, abi: abi as never, functionName, args, chain: clients.chain, account: clients.account
    });
    const receipt = await clients.publicClient.waitForTransactionReceipt({hash});
    if (receipt.status !== "success") throw new Error(`${functionName} reverted in ${hash}`);
    return receipt;
};

if (!process.env.SKIP_INIT) {
    await applyInitialConfig(clients, service, params, {autoEnable: true});
    console.error("[Setup] ClprService initialized and enabled");
}

const verifier = await deployArtifact(clients, "E2EVerifier");
const e2e = loadArtifact("E2EVerifier");
await write(verifier, e2e.abi, "configure", [
    PEER_CHAIN_ID,
    "0x000000000000000000000000000000000000beef",
    0n,
    params.throttles,
    "0x01",
    "0x01",
    []
]);
console.error(`[Setup] E2EVerifier configured at ${verifier}`);

const peer = privateKeyToAccount(PEER_SIGNER_PK);
const peerPubKey = ("0x" + Buffer.from(secp256k1.getPublicKey(PEER_SIGNER_PK.slice(2), false).slice(1)).toString("hex")) as Hex;
const channelId = (await clients.publicClient.readContract({
    address: service, abi: svc.abi as never, functionName: "deriveChannelId", args: [PEER_CHAIN_ID, peerPubKey, "0x" + "00".repeat(32)]
})) as Hex;
await write(service, svc.abi, "registerChannel", [channelId, keccak256(encodePacked(["bytes32", "bytes"], [channelId, peerPubKey]))]);
const msgHash = keccak256(encodePacked(["bytes32", "address"], [channelId, service]));
const sig = await peer.signMessage({message: {raw: msgHash}});
await write(service, svc.abi, "completeChannel", [channelId, peerPubKey, sig, "0x" + "00".repeat(32), verifier, "0x", "0x"]);
const channel = (await clients.publicClient.readContract({address: service, abi: svc.abi as never, functionName: "getChannel", args: [channelId]})) as {status: number; nextMessageId: bigint};
console.error(`[Setup] channel ${channelId} status ${channel.status} nextMessageId ${channel.nextMessageId}`);
console.log(`FIXTURE_OUT::CHANNEL_ID ${channelId}`);
console.log(`FIXTURE_OUT::E2E_VERIFIER ${verifier}`);
