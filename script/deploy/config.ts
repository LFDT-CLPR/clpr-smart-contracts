import {parseEther} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import { envNumber, normalizePrivateKey } from "./shared/helpers";

/// Matches `ClprTypes.Throttles` / `updateLedgerConfiguration` args.
export interface Throttles {
    maxMessagesPerBundle: bigint;
    maxMessagePayloadBytes: bigint;
    maxGasPerMessage: bigint;
    maxQueueDepth: bigint;
    maxSyncBytes: bigint;
    maxLocalEndpoints: bigint;
    maxPeerEndpoints: bigint;
}

/// Matches `ClprTypes.EconomicConfig` / `updateEconomicConfiguration` args.
export interface EconomicConfig {
    messageExecutionCost: bigint;
    endpointMarginPercent: bigint;
    minLockedStake: bigint;
    minEndpointBond: bigint;
    basePenalty: bigint;
    penaltyMultiplier: bigint;
    slashBanThreshold: number;
    connectorQueueQuotaPct: number;
    connectorInboundGasStipend: bigint;
    maxChannels: number;
    maxConnectors: number;
    connectorPaymentGasLimit: bigint;
}

/// Mirrors `script/ClprConfig.sol` defaults.
export const defaultThrottles: Throttles = {
    maxMessagesPerBundle: 100n,
    maxMessagePayloadBytes: 1024n,
    maxGasPerMessage: 1_000_000n,
    maxQueueDepth: 1000n,
    maxSyncBytes: 1_048_576n,
    maxLocalEndpoints: 0n,
    maxPeerEndpoints: 0n
};

export const defaultEconomicConfig: EconomicConfig = {
    messageExecutionCost: parseEther("0.001"),
    endpointMarginPercent: 10n,
    minLockedStake: parseEther("0.1"),
    minEndpointBond: 0n,
    basePenalty: parseEther("0.01"),
    penaltyMultiplier: 2n,
    slashBanThreshold: 5,
    connectorQueueQuotaPct: 50,
    connectorInboundGasStipend: 500_000n,
    maxChannels: 0,
    maxConnectors: 0,
    connectorPaymentGasLimit: 200_000n
};

export interface ClprModules {
    channelLogic: `0x${string}`;
    messagingLogic: `0x${string}`;
    bundleLogic: `0x${string}`;
    connectorLogic: `0x${string}`;
    adminLogic: `0x${string}`;
    bundleDecodeHelper: `0x${string}`;
}

export interface ClprDeployed extends ClprModules {
    clprService: `0x${string}`;
}

export interface E2EDeployed extends ClprDeployed {
    verifier: `0x${string}`;
    application: `0x${string}`;
    connectorContract: `0x${string}`;
    bundleEncoder: `0x${string}`;
}

export interface DeployParams {
    initialOwner: `0x${string}`;
    protocolVersion: number;
    chainId: string;
    serviceAddress: `0x${string}`;
    throttles: Throttles;
    trustAnchor: `0x${string}`;
    trustAnchorId: `0x${string}`;
    econ: EconomicConfig;
}

export function envBigInt(name: string, fallback: bigint): bigint {
    const raw = process.env[name];
    if (raw === undefined || raw === "") return fallback;
    return BigInt(raw);
}

/// Load deploy parameters from env (mirrors `DeployCore._loadParams` + `_loadEconomicConfig`).
export function loadDeployParams(privateKey: string): DeployParams {
    const pk = normalizePrivateKey(privateKey);
    const deployer = privateKeyToAccount(pk).address;
    const initialOwner = (process.env.INITIAL_OWNER as `0x${string}` | undefined) ?? deployer;

    const econ: EconomicConfig = {
        messageExecutionCost: envBigInt(
            "ECON_MESSAGE_EXECUTION_COST",
            defaultEconomicConfig.messageExecutionCost
        ),
        endpointMarginPercent: envBigInt(
            "ECON_ENDPOINT_MARGIN_PERCENT",
            defaultEconomicConfig.endpointMarginPercent
        ),
        minLockedStake: envBigInt("ECON_MIN_LOCKED_STAKE", defaultEconomicConfig.minLockedStake),
        minEndpointBond: envBigInt("ECON_MIN_ENDPOINT_BOND", defaultEconomicConfig.minEndpointBond),
        basePenalty: envBigInt("ECON_BASE_PENALTY", defaultEconomicConfig.basePenalty),
        penaltyMultiplier: envBigInt("ECON_PENALTY_MULTIPLIER", defaultEconomicConfig.penaltyMultiplier),
        slashBanThreshold: envNumber("ECON_SLASH_BAN_THRESHOLD", defaultEconomicConfig.slashBanThreshold),
        connectorQueueQuotaPct: envNumber(
            "ECON_CONNECTOR_QUEUE_QUOTA_PCT",
            defaultEconomicConfig.connectorQueueQuotaPct
        ),
        connectorInboundGasStipend: envBigInt(
            "ECON_CONNECTOR_INBOUND_GAS_STIPEND",
            defaultEconomicConfig.connectorInboundGasStipend
        ),
        maxChannels: envNumber("ECON_MAX_CHANNELS", defaultEconomicConfig.maxChannels),
        maxConnectors: envNumber("ECON_MAX_CONNECTORS", defaultEconomicConfig.maxConnectors),
        connectorPaymentGasLimit: envBigInt(
            "ECON_CONNECTOR_PAYMENT_GAS_LIMIT",
            defaultEconomicConfig.connectorPaymentGasLimit
        )
    };

    const serviceAddressRaw = process.env.SERVICE_ADDRESS ?? "";
    const serviceAddress = (
        serviceAddressRaw === "" ? "0x" : serviceAddressRaw.startsWith("0x") ? serviceAddressRaw : `0x${serviceAddressRaw}`
    ) as `0x${string}`;

    const trustAnchorRaw = process.env.TRUST_ANCHOR ?? "";
    const trustAnchor = (
        trustAnchorRaw === "" ? "0x" : trustAnchorRaw.startsWith("0x") ? trustAnchorRaw : `0x${trustAnchorRaw}`
    ) as `0x${string}`;

    const trustAnchorIdRaw = process.env.TRUST_ANCHOR_ID ?? "";
    const trustAnchorId = (
        trustAnchorIdRaw === ""
            ? "0x"
            : trustAnchorIdRaw.startsWith("0x")
              ? trustAnchorIdRaw
              : `0x${trustAnchorIdRaw}`
    ) as `0x${string}`;

    return {
        initialOwner,
        protocolVersion: envNumber("PROTOCOL_VERSION", 1),
        chainId: process.env.CHAIN_ID ?? "eip155:1",
        serviceAddress,
        throttles: defaultThrottles,
        trustAnchor,
        trustAnchorId,
        econ
    };
}

export function loadModulesFromEnv(): ClprModules {
    const req = (name: string): `0x${string}` => {
        const v = process.env[name];
        if (!v) throw new Error(`missing env ${name} (required for service-only deploy)`);
        return v as `0x${string}`;
    };
    return {
        channelLogic: req("CHANNEL_LOGIC"),
        messagingLogic: req("MESSAGING_LOGIC"),
        bundleLogic: req("BUNDLE_LOGIC"),
        connectorLogic: req("CONNECTOR_LOGIC"),
        adminLogic: req("ADMIN_LOGIC"),
        bundleDecodeHelper: req("BUNDLE_DECODE_HELPER")
    };
}
