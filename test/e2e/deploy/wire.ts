import {parseEther} from "viem";
import {loadArtifact} from "../../../script/deploy/artifacts.js";
import type {ChainClients} from "../lib/clients.js";
import {isSoloBackend} from "../backend/solo/solo.js";
import type {DeployedAddresses} from "./deploy.js";
import {DEFAULT_ECON, DEFAULT_PEER_THROTTLES, SOLO_PEER_THROTTLES} from "./constants";

/// Push ledger + economic config to a freshly-deployed ClprService.
///
/// Called from the *owner* account (= deployer). Endpoints are not part of the
/// ledger configuration; they are admitted to the on-ledger manifest via
/// registerEndpoint/addEndpoint.
/// Pass `soloRelay: true` when the clients connect to a Hiero JSON-RPC relay
/// so Solo-specific throttles and economic constraints are applied.
export async function wireConfig(opts: {
    clients: ChainClients;
    addrs: DeployedAddresses;
    serviceAddressBytes?: `0x${string}`;
    soloRelay?: boolean;
}): Promise<void> {
    const {clients, addrs} = opts;
    const service = loadArtifact("ClprService");

    // Per-side Solo detection: use the explicit flag when provided, otherwise
    // fall back to the global isSoloBackend() for symmetric-backend compatibility.
    const isSolo = opts.soloRelay ?? isSoloBackend();

    const serviceAddressBytes = opts.serviceAddressBytes ?? ("0x" as `0x${string}`);
    const econ = isSolo
        ? {...DEFAULT_ECON, minEndpointBond: 0n, minLockedStake: 0n}
        : DEFAULT_ECON;
    const throttles = isSolo ? SOLO_PEER_THROTTLES : DEFAULT_PEER_THROTTLES;

    const initTx = await clients.walletClient.writeContract({
        address: addrs.clprService,
        abi: service.abi as never,
        functionName: "initialize",
        args: [
            serviceAddressBytes,
            {
                maxMessagesPerBundle: throttles.maxMessagesPerBundle,
                maxMessagePayloadBytes: throttles.maxMessagePayloadBytes,
                maxGasPerMessage: throttles.maxGasPerMessage,
                maxQueueDepth: throttles.maxQueueDepth,
                maxSyncBytes: throttles.maxSyncBytes,
                maxLocalEndpoints: throttles.maxLocalEndpoints,
                maxPeerEndpoints: throttles.maxPeerEndpoints
            },
            "0x", // trustAnchor — stub verifier path; left empty
            "0x", // trustAnchorId
            {
                messageExecutionCost: econ.messageExecutionCost,
                endpointMarginPercent: econ.endpointMarginPercent,
                minLockedStake: econ.minLockedStake,
                minEndpointBond: econ.minEndpointBond,
                basePenalty: econ.basePenalty,
                penaltyMultiplier: econ.penaltyMultiplier,
                slashBanThreshold: econ.slashBanThreshold,
                connectorQueueQuotaPct: econ.connectorQueueQuotaPct,
                connectorInboundGasStipend: econ.connectorInboundGasStipend,
                maxChannels: econ.maxChannels,
                maxConnectors: econ.maxConnectors,
                connectorPaymentGasLimit: econ.connectorPaymentGasLimit
            }
        ]
    });
    await clients.publicClient.waitForTransactionReceipt({hash: initTx});

    const enableTx = await clients.walletClient.writeContract({
        address: addrs.clprService,
        abi: service.abi as never,
        functionName: "setClprEnabled",
        args: [true]
    });
    await clients.publicClient.waitForTransactionReceipt({hash: enableTx});
}

/// Register the caller as a bonded endpoint. Registration is permissionless and
/// posts a refundable bond; it no longer carries a signing key and does not gate
/// submitBundle. Pass `soloRelay: true` when the chain is a Hiero relay — sets bond
/// to 0 since the relay does not forward tx.value into delegatecall targets.
export async function registerEndpoint(opts: {
    clients: ChainClients;
    clprService: `0x${string}`;
    bond?: bigint;
    soloRelay?: boolean;
}): Promise<void> {
    const {clients, clprService, bond} = opts;
    const service = loadArtifact("ClprService");

    const isSolo = opts.soloRelay ?? isSoloBackend();
    const value = isSolo ? 0n : (bond ?? parseEther("0.1"));
    // Two-step admission: registerEndpoint now takes ClprEndpoint discovery data and posts the bond as
    // a PENDING entry (submission is permissionless, so this is not required to submit bundles — it
    // exercises the manifest-registration path). Fields are placeholders; the anvil e2e drives sync via
    // the direct-submit ferry, not gRPC discovery.
    const endpoint = {
        ipAddress: "10.0.0.1",
        port: 50211,
        tlsCertificate: "0x" as `0x${string}`,
        accountId: "0x" as `0x${string}`
    };
    const tx = await clients.walletClient.writeContract({
        address: clprService,
        abi: service.abi as never,
        functionName: "registerEndpoint",
        args: [endpoint],
        value
    });
    const receipt = await clients.publicClient.waitForTransactionReceipt({hash: tx});
    if (receipt.status === "reverted") {
        throw new Error(`registerEndpoint reverted (chain ${await clients.publicClient.getChainId()})`);
    }
}
