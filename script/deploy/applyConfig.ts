import {loadArtifact} from "./artifacts.js";
import type {DeployParams} from "./config.js";
import type {DeployClients} from "./client.js";
import { type Address } from "viem";

/// Applies the first ledger + economic configuration on a deployed `ClprService`,
/// via the one-time `initialize()` bootstrap.
///
/// `clprEnabled` defaults to false on deploy — the service
/// is inert until explicitly enabled. `initialize()` is owner-only but NOT gated
/// by `whenEnabled`, so it can (and must) run while still disabled; it reverts
/// with `ClprAlreadyInitialized` if called more than once. `setClprEnabled(true)`
/// itself reverts with `ClprNotInitialized` unless `initialize()` has already run,
/// so there is no ordering ambiguity: initialize first, enable after.
/// Pass `autoEnable: true` to have this function call `setClprEnabled(true)` once
/// `initialize()` has landed. Leave it false for production/testnet deploys where
/// enabling should be a deliberate, separate operator action taken after
/// reviewing the applied config.
export async function applyInitialConfig(
    clients: DeployClients,
    clprService: `0x${string}`,
    params: DeployParams,
    opts: {autoEnable?: boolean} = {}
): Promise<void> {
    const service = loadArtifact("ClprService");

    const feeToken = (await clients.publicClient.readContract({
        address: clprService,
        abi: service.abi as never,
        functionName: "getFeeToken"
    })) as Address;
    const defaulted = params.defaultedEconAmounts ?? [];
    if (BigInt(feeToken) !== 0n && defaulted.length > 0) {
        throw new Error(
            `missing env ${defaulted.join(", ")} (required for a fee-token service: amounts are in the fee token's base units)`
        );
    }

    const initTx = await clients.walletClient.writeContract({
        address: clprService,
        abi: service.abi as never,
        functionName: "initialize",
        chain: clients.chain,
        account: clients.account,
        args: [
            params.serviceAddress,
            {
                maxMessagesPerBundle: params.throttles.maxMessagesPerBundle,
                maxMessagePayloadBytes: params.throttles.maxMessagePayloadBytes,
                maxGasPerMessage: params.throttles.maxGasPerMessage,
                maxQueueDepth: params.throttles.maxQueueDepth,
                maxSyncBytes: params.throttles.maxSyncBytes,
                maxLocalEndpoints: params.throttles.maxLocalEndpoints,
                maxPeerEndpoints: params.throttles.maxPeerEndpoints
            },
            params.trustAnchor,
            params.trustAnchorId,
            {
                messageExecutionCost: params.econ.messageExecutionCost,
                endpointMarginPercent: params.econ.endpointMarginPercent,
                minLockedStake: params.econ.minLockedStake,
                minEndpointBond: params.econ.minEndpointBond,
                basePenalty: params.econ.basePenalty,
                penaltyMultiplier: params.econ.penaltyMultiplier,
                slashBanThreshold: params.econ.slashBanThreshold,
                connectorQueueQuotaPct: params.econ.connectorQueueQuotaPct,
                connectorInboundGasStipend: params.econ.connectorInboundGasStipend,
                maxChannels: params.econ.maxChannels,
                maxConnectors: params.econ.maxConnectors,
                connectorPaymentGasLimit: params.econ.connectorPaymentGasLimit
            }
        ]
    });
    await clients.publicClient.waitForTransactionReceipt({hash: initTx});

    if (opts.autoEnable) {
        const enableTx = await clients.walletClient.writeContract({
            address: clprService,
            abi: service.abi as never,
            functionName: "setClprEnabled",
            chain: clients.chain,
            account: clients.account,
            args: [true]
        });
        await clients.publicClient.waitForTransactionReceipt({hash: enableTx});
    }
}

/**
 * Transfers Ownable ownership of `target` to `newOwner`.
 * Assumes the current wallet account is the present owner.
 */
export async function transferOwnership(
    clients: DeployClients,
    target: Address,
    newOwner: Address
): Promise<void> {
    const artifact = loadArtifact("ClprService"); // has Ownable's transferOwnership in its ABI
    const hash = await clients.walletClient.writeContract({
        address: target,
        abi: artifact.abi as never,
        functionName: "transferOwnership",
        args: [newOwner],
        chain: clients.chain,
        account: clients.account
    });
    await clients.publicClient.waitForTransactionReceipt({ hash });
}