import {existsSync} from "node:fs";
import dotenv from "dotenv";

/// Load `KEY=value` lines into `process.env` (does not override existing shell env).
export function loadDotEnv(envFile: string): void {
    if (!existsSync(envFile)) return;
    dotenv.config({ path: envFile, quiet: true });
}

const CORE_MANAGED_KEYS = [
    "CLPR_SERVICE",
    "CHANNEL_LOGIC",
    "MESSAGING_LOGIC",
    "BUNDLE_LOGIC",
    "CONNECTOR_LOGIC",
    "ADMIN_LOGIC",
    "BUNDLE_DECODE_HELPER"
] as const;

const QBFT_MANAGED_KEYS = ["QBFT_VERIFIER"] as const;

const HIERO_MANAGED_KEYS = [
    "POSEIDON_PERMUTE_A",
    "POSEIDON_PERMUTE_B",
    "POSEIDON_BN254",
    "WRAPS_VERIFIER",
    "TSS_VERIFIER",
    "HIERO_VERIFIER"
] as const;

const SEI_MANAGED_KEYS = ["ED25519_VERIFIER", "SEI_VERIFIER"] as const;

const ETH_MAINNET_MANAGED_KEYS = ["ETH_MAINNET_VERIFIER"] as const;

const TEMPO_MANAGED_KEYS = ["TEMPO_VERIFIER"] as const;

const MANAGED_KEYS = [
    ...CORE_MANAGED_KEYS,
    ...QBFT_MANAGED_KEYS,
    ...HIERO_MANAGED_KEYS,
    ...SEI_MANAGED_KEYS,
    ...ETH_MAINNET_MANAGED_KEYS,
    ...TEMPO_MANAGED_KEYS
] as const;

export type ManagedEnvKey = (typeof MANAGED_KEYS)[number];

export function clprDeployedToEnv(
    d: Partial<{
        clprService: string;
        channelLogic: string;
        messagingLogic: string;
        bundleLogic: string;
        connectorLogic: string;
        adminLogic: string;
        bundleDecodeHelper: string;
    }>
): Partial<Record<ManagedEnvKey, string>> {
    const out: Partial<Record<ManagedEnvKey, string>> = {};
    if (d.clprService) out.CLPR_SERVICE = d.clprService;
    if (d.channelLogic) out.CHANNEL_LOGIC = d.channelLogic;
    if (d.messagingLogic) out.MESSAGING_LOGIC = d.messagingLogic;
    if (d.bundleLogic) out.BUNDLE_LOGIC = d.bundleLogic;
    if (d.connectorLogic) out.CONNECTOR_LOGIC = d.connectorLogic;
    if (d.adminLogic) out.ADMIN_LOGIC = d.adminLogic;
    if (d.bundleDecodeHelper) out.BUNDLE_DECODE_HELPER = d.bundleDecodeHelper;
    return out;
}
