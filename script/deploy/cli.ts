#!/usr/bin/env npx tsx
/**
 * CLPR deployment CLI (viem).
 *
 * Usage:
 *   npx tsx script/deploy/cli.ts <mode> --rpc-url <url|alias> [options]
 *
 * Modes:
 *   all                      Deploy modules + ClprService + apply config
 *   modules                  Deploy logic modules only
 *   service                  Deploy ClprService (modules must exist in env)
 *   config                   Apply initial config to an existing ClprService
 *   e2e-with-qbft-verifier   Deploy full E2E stack with QBFTVerifier
 *   e2e-with-hiero-verifier  Deploy full E2E stack with HieroVerifier
 *
 * Output:
 *   Deployed addresses are ALWAYS printed to stdout as a JSON object
 *   (safe to JSON.parse — all human-readable progress logs go to stderr).
 *
 *   --auto-enable            Call setClprEnabled(true) as the last step of config
 *                            application (only takes effect when this run applies
 *                            config, i.e. deployer == owner). Omit for production/
 *                            testnet deploys: clprEnabled defaults to false (spec
 *                            §7), and leaving it off is the deliberate, separate
 *                            "go live" step an operator takes after reviewing the
 *                            applied config. Pass it for e2e/local-dev runs that
 *                            need an immediately-usable service.
 *
 *   --output <fmt>           Output format. Only "json" is supported today;
 *                            the flag exists so other formats can be added
 *                            later. Default: json.
 *   --output-to-file [path]  Also write the output to a file. If a path is
 *                            given it is used; otherwise it defaults to
 *                            clpr-deployed-addresses.json in the cwd. When
 *                            omitted, no file is written. Console output is
 *                            always printed regardless.
 *
 *   The CLI never writes to an env file. Env files are read for input
 *   (PRIVATE_KEY, RPC aliases, ECON_*, ...) but are never modified.
 */
import path from "node:path";
import fs from "node:fs";
import {Address, privateKeyToAccount} from "viem/accounts";
import {applyInitialConfig, transferOwnership} from "./applyConfig.js";
import {REPO_ROOT} from "./artifacts.js";
import {makeDeployClients, type DeployClients} from "./client.js";
import {
    loadDeployParams,
    loadModulesFromEnv,
    type ClprDeployed,
    type ClprModules,
    type DeployParams
} from "./config.js";
import {
    assertModulesDeployed,
    deployClprAll,
    deployClprModules,
    deployClprService,
    deployE2EWithQbftVerifier,
    deployE2EWithHieroVerifier,
    deployHieroVerifierStack,
    deployQbftVerifier,
    deploySeiVerifierStack,
    deployEthMainnetVerifier,
    hieroVerifierStackToEnv,
    seiVerifierStackToEnv,
    loadLedgerIdBytes
} from "./deployCore.js";
import {clprDeployedToEnv, loadDotEnv} from "./envFile.js";
import {resolveRpcUrl} from "./rpc.js";
import { getAddress } from "viem";
import { normalizePk, requireEnv } from "./shared/helpers.js";

type Mode =
    | "all"
    | "modules"
    | "service"
    | "config"
    | "e2e-with-qbft-verifier"
    | "e2e-with-hiero-verifier"
    | "hiero-verifier"
    | "qbft-verifier"
    | "sei-verifier"
    | "eth-mainnet-verifier";

const VALID_MODES: Mode[] = [
    "all",
    "modules",
    "service",
    "config",
    "e2e-with-qbft-verifier",
    "e2e-with-hiero-verifier",
    "hiero-verifier",
    "qbft-verifier",
    "sei-verifier",
    "eth-mainnet-verifier"
];

/** Output formats. Only "json" today; enum-shaped so more can be added later. */
type OutputFormat = "json";
const VALID_OUTPUT_FORMATS: OutputFormat[] = ["json"];
const DEFAULT_OUTPUT_FILE = "clpr-deployed-addresses.json";

function usage(): string {
    return `usage: tsx script/deploy/cli.ts <${VALID_MODES.join("|")}> --rpc-url <url|anvil|besu|hiero> [--env-file <path>] [--ledger-id <0x...>] [--auto-enable] [--transfer-ownership-to-account] [--output <json>] [--output-to-file [path]]`;
}

function validateOutputFormat(fmt: string): OutputFormat {
    if (!VALID_OUTPUT_FORMATS.includes(fmt as OutputFormat)) {
        throw new Error(
            `unsupported --output format "${fmt}" (supported: ${VALID_OUTPUT_FORMATS.join(", ")})`
        );
    }
    return fmt as OutputFormat;
}

function parseArgs(argv: string[]): {
    mode: Mode;
    rpcUrl: string;
    envFile: string;
    autoEnable: boolean;
    ledgerId?: string;
    transferToAddress: boolean;
    outputFormat: OutputFormat;
    outputToFile: string | null;
} {
    const positional = argv.filter((a) => !a.startsWith("-"));
    const mode = positional[0] as Mode | undefined;
    if (!mode || !VALID_MODES.includes(mode)) throw new Error(usage());

    let rpcUrl = "";
    let envFile = path.join(REPO_ROOT, ".env");
    let transferToAddress = false;
    let autoEnable = false;
    let ledgerId: string | undefined;
    let outputFormat: OutputFormat = "json";
    let outputToFile: string | null = null;

    for (let i = 1; i < argv.length; i++) {
        const arg = argv[i];
        if (arg === "--rpc-url" && argv[i + 1]) {
            rpcUrl = resolveRpcUrl(argv[++i]!);
        } else if (arg?.startsWith("--rpc-url=")) {
            rpcUrl = resolveRpcUrl(arg.slice("--rpc-url=".length));
        } else if (arg === "--env-file" && argv[i + 1]) {
            envFile = argv[++i]!;
        } else if (arg?.startsWith("--env-file=")) {
            envFile = arg.slice("--env-file=".length);
        } else if (arg === "--ledger-id" && argv[i + 1]) {
            ledgerId = argv[++i]!;
        } else if (arg?.startsWith("--ledger-id=")) {
            ledgerId = arg.slice("--ledger-id=".length);
        } else if (arg === "--auto-enable") {
            autoEnable = true;
        } else if (arg === "--transfer-ownership-to-account") {
            transferToAddress = true;
        } else if (arg === "--output" && argv[i + 1]) {
            outputFormat = validateOutputFormat(argv[++i]!);
        } else if (arg?.startsWith("--output=")) {
            outputFormat = validateOutputFormat(arg.slice("--output=".length));
        } else if (arg === "--output-to-file") {
            const next = argv[i + 1];
            if (next && !next.startsWith("-")) {
                outputToFile = argv[++i]!;
            } else {
                outputToFile = DEFAULT_OUTPUT_FILE;
            }
        } else if (arg?.startsWith("--output-to-file=")) {
            const val = arg.slice("--output-to-file=".length);
            outputToFile = val !== "" ? val : DEFAULT_OUTPUT_FILE;
        }
    }
    if (!rpcUrl) throw new Error(`${usage()}\nmissing --rpc-url`);
    return {mode, rpcUrl, envFile, ledgerId, transferToAddress, autoEnable, outputFormat, outputToFile};
}

function requireOwnerAccount(envFile: string): Address {
    const raw = process.env.OWNER_ACCOUNT;
    if (!raw) {
        throw new Error(
            `--transfer-ownership-to-account set but OWNER_ACCOUNT is missing (set in ${envFile})`
        );
    }
    try {
        return getAddress(raw); // validates + checksums
    } catch {
        throw new Error(`OWNER_ACCOUNT is not a valid address: "${raw}"`);
    }
}

function logModules(modules: ClprModules): void {
    console.error("Deployed in this run:");
    console.error(`  ChannelLogic → ${modules.channelLogic} (env: CHANNEL_LOGIC)`);
    console.error(`  MessagingLogic → ${modules.messagingLogic} (env: MESSAGING_LOGIC)`);
    console.error(`  BundleLogic → ${modules.bundleLogic} (env: BUNDLE_LOGIC)`);
    console.error(`  ConnectorLogic → ${modules.connectorLogic} (env: CONNECTOR_LOGIC)`);
    console.error(`  AdminLogic → ${modules.adminLogic} (env: ADMIN_LOGIC)`);
    console.error(`  BundleDecodeHelper → ${modules.bundleDecodeHelper} (env: BUNDLE_DECODE_HELPER)`);
}

function logDeployed(run: ClprDeployed): void {
    console.error("Deployed in this run:");
    console.error(`  ClprService → ${run.clprService} (env: CLPR_SERVICE)`);
    console.error(`  ChannelLogic → ${run.channelLogic} (env: CHANNEL_LOGIC)`);
    console.error(`  MessagingLogic → ${run.messagingLogic} (env: MESSAGING_LOGIC)`);
    console.error(`  BundleLogic → ${run.bundleLogic} (env: BUNDLE_LOGIC)`);
    console.error(`  ConnectorLogic → ${run.connectorLogic} (env: CONNECTOR_LOGIC)`);
    console.error(`  AdminLogic → ${run.adminLogic} (env: ADMIN_LOGIC)`);
    console.error(
        `  BundleDecodeHelper → ${run.bundleDecodeHelper} (env: BUNDLE_DECODE_HELPER)`
    );
}

/**
 * Applies initial config (via `initialize()`) when this run's deployer is also
 * the contract owner and `--auto-enable` was passed; otherwise prints the
 * two-step instructions for whoever must apply it themselves (the deployer, if
 * `--auto-enable` was omitted, or the actual owner via multisig). Centralizes
 * the isOwner/autoEnable branching so `all` and the e2e modes don't each carry
 * their own slightly-different copy of the same three messages.
 */
async function applyInitialConfigOrPrintInstructions(
    clients: DeployClients,
    clprService: `0x${string}`,
    params: DeployParams,
    deployer: Address,
    autoEnable: boolean
): Promise<void> {
    const isOwner = params.initialOwner.toLowerCase() === deployer.toLowerCase();

    if (!isOwner) {
        console.error("Deployer != owner — apply via multisig, in this order:");
        console.error(`  1. initialize(...) on ${clprService} — applies config while still disabled`);
        console.error("  2. setClprEnabled(true) — once the applied config has been verified");
        return;
    }

    if (!autoEnable) {
        console.error("Deployer == owner, but --auto-enable was not passed — config was NOT applied.");
        console.error("Service is still disabled. To bring it up yourself, in this order:");
        console.error(`  1. initialize(...) on ${clprService} — applies config while still disabled`);
        console.error("  2. setClprEnabled(true) — once the applied config has been verified");
        console.error("(or re-run this command with --auto-enable to do both automatically)");
        return;
    }

    await applyInitialConfig(clients, clprService, params, {autoEnable});
    console.error("clprEnabled set to true; initial config applied (deployer == owner).");
}

function extractEnvFile(argv: string[]): string {
    for (let i = 0; i < argv.length; i++) {
        if (argv[i] === "--env-file" && argv[i + 1]) return argv[i + 1]!;
        if (argv[i]?.startsWith("--env-file=")) return argv[i]!.slice("--env-file=".length);
    }
    return path.join(REPO_ROOT, ".env");
}

/**
 * Serialize the deployed addresses in the requested format. Only JSON today;
 * a switch on `fmt` is the single place to extend for future formats.
 */
function formatOutput(addresses: Record<string, string>, fmt: OutputFormat): string {
    switch (fmt) {
        case "json":
            return JSON.stringify(addresses, null, 2);
    }
}

/**
 * Always print the serialized output to stdout; additionally write it to a
 * file when `outputToFile` is set. Human logs are on stderr, so stdout stays
 * clean for JSON.parse by programmatic consumers.
 */
function emitOutput(
    addresses: Partial<Record<string, string>>,
    fmt: OutputFormat,
    outputToFile: string | null
): void {
    // Drop undefined values so consumers get a clean object.
    const clean: Record<string, string> = {};
    for (const [k, v] of Object.entries(addresses)) {
        if (v) clean[k] = v;
    }

    const serialized = formatOutput(clean, fmt);
    process.stdout.write(serialized + "\n");

    if (outputToFile) {
        const filePath = path.isAbsolute(outputToFile) ? outputToFile : path.join(process.cwd(), outputToFile);
        fs.writeFileSync(filePath, serialized + "\n", "utf8");
        console.error(`[Deploy] Wrote deployed addresses to ${filePath}`);
    }
}

async function main(): Promise<void> {
    // Load .env before parseArgs so RPC aliases (BESU_RPC etc.) are available.
    const envFile = extractEnvFile(process.argv.slice(2));
    loadDotEnv(envFile);
    const {mode, rpcUrl, ledgerId, autoEnable, transferToAddress, outputFormat, outputToFile} =
        parseArgs(process.argv.slice(2));

    console.error("");
    console.error("[Deploy] Deployment plan:");
    switch (mode) {
        case "all":
            console.error("[Deploy]   1. Deploy logic modules (6 contracts)");
            console.error("[Deploy]   2. Deploy ClprService");
            console.error("[Deploy]   3. Apply initial configuration (deployer == owner && --auto-enable only)");
            break;
        case "modules":
            console.error("[Deploy]   Deploy logic modules (6 contracts)");
            break;
        case "service":
            console.error("[Deploy]   Deploy ClprService using existing module addresses");
            break;
        case "config":
            console.error("[Deploy]   Apply initial configuration to existing ClprService");
            break;
        case "e2e-with-qbft-verifier":
            console.error("[Deploy]   1. Deploy logic modules (6 contracts)");
            console.error("[Deploy]   2. Deploy ClprService");
            console.error("[Deploy]   3. Deploy QBFTVerifier");
            console.error("[Deploy]   4. Deploy E2E helpers (3 contracts)");
            console.error("[Deploy]   5. Apply initial configuration (deployer == owner && --auto-enable only)");
            break;
        case "e2e-with-hiero-verifier":
            console.error("[Deploy]   1. Deploy logic modules (6 contracts)");
            console.error("[Deploy]   2. Deploy ClprService");
            console.error("[Deploy]   3. Deploy Hiero verifier stack (6 contracts)");
            console.error("[Deploy]   4. Deploy E2E helpers (3 contracts)");
            console.error("[Deploy]   5. Apply initial configuration (deployer == owner && --auto-enable only)");
            break;
        case "hiero-verifier":
            console.error("[Deploy]   Deploy Hiero verifier stack (6 contracts) against existing ClprService");
            break;
        case "qbft-verifier":
            console.error("[Deploy]   Deploy QBFT verifier (1 contract) against existing ClprService");
            break;
        case "sei-verifier":
            console.error("[Deploy]   Deploy Sei/CometBFT verifier stack (2 contracts) against existing ClprService");
            break;
        case "eth-mainnet-verifier":
            console.error("[Deploy]   Deploy Ethereum mainnet verifier (1 contract) against existing ClprService");
            break;
    }
    console.error("");

    switch (mode) {
        case "all":
            requireEnv(["PRIVATE_KEY"], envFile);
            break;
        case "modules":
            requireEnv(["PRIVATE_KEY"], envFile);
            break;
        case "service":
            requireEnv(
                [
                    "PRIVATE_KEY",
                    "CHANNEL_LOGIC",
                    "MESSAGING_LOGIC",
                    "BUNDLE_LOGIC",
                    "CONNECTOR_LOGIC",
                    "ADMIN_LOGIC",
                    "BUNDLE_DECODE_HELPER"
                ],
                envFile
            );
            break;
        case "config":
            requireEnv(["PRIVATE_KEY", "CLPR_SERVICE"], envFile);
            break;
        case "e2e-with-qbft-verifier":
            requireEnv(["PRIVATE_KEY"], envFile);
            break;
        case "e2e-with-hiero-verifier":
            requireEnv(["PRIVATE_KEY"], envFile);
            break;
        case "hiero-verifier":
            requireEnv(["PRIVATE_KEY", "CLPR_SERVICE"], envFile);
            break;
        case "qbft-verifier":
            requireEnv(["PRIVATE_KEY", "CLPR_SERVICE"], envFile);
            break;
        case "sei-verifier":
            requireEnv(
                ["PRIVATE_KEY", "CLPR_SERVICE", "ED25519"],
                envFile
            );
            break;
        case "eth-mainnet-verifier":
            requireEnv(["PRIVATE_KEY", "CLPR_SERVICE"], envFile);
            break;
    }

    const pk = normalizePk(envFile);
    const deployer = privateKeyToAccount(pk).address;

    const clients = await makeDeployClients({rpcUrl, privateKey: pk});
    const params = loadDeployParams(pk);
    // `addresses` holds every address this run produced, keyed by env var name.
    // For e2e modes this includes the helper contracts (E2E_APPLICATION,
    // MOCK_CLPR_CONNECTOR, BUNDLE_ENCODER_HELPER) so consumers get the complete
    // set from stdout without scraping stderr logs.
    let addresses: Partial<Record<string, string>> = {};

    switch (mode) {
        case "modules": {
            const modules = await deployClprModules(clients);
            logModules(modules);
            addresses = clprDeployedToEnv(modules);
            break;
        }
        case "service": {
            const modules = loadModulesFromEnv();
            await assertModulesDeployed(clients, modules);
            const clprService = await deployClprService(clients, params, modules);
            const result = {...modules, clprService};
            logDeployed(result);
            addresses = clprDeployedToEnv(result);
            break;
        }
        case "config": {
            const svc = process.env.CLPR_SERVICE as `0x${string}`;
            await applyInitialConfig(clients, svc, params, {autoEnable});
            console.error(`Config applied on ClprService ${svc}`);
            console.error(
                autoEnable
                    ? "  clprEnabled set to true."
                    : "  clprEnabled is still false — run setClprEnabled(true) (or re-run with --auto-enable) when ready to go live."
            );
            break;
        }
        case "all": {
            const result = await deployClprAll(clients, params);
            await applyInitialConfigOrPrintInstructions(clients, result.clprService, params, deployer, autoEnable);
            logDeployed(result);
            addresses = clprDeployedToEnv(result);
            break;
        }
        case "e2e-with-qbft-verifier": {
            const result = await deployE2EWithQbftVerifier(clients, params);
            await applyInitialConfigOrPrintInstructions(clients, result.clprService, params, deployer, autoEnable);
            addresses = {
                ...clprDeployedToEnv(result),
                QBFT_VERIFIER: result.qbftVerifier,
                E2E_APPLICATION: result.application,
                MOCK_CLPR_CONNECTOR: result.connectorContract,
                BUNDLE_ENCODER_HELPER: result.bundleEncoder
            };
            logDeployed(result);
            console.error(`  QBFTVerifier → ${result.qbftVerifier} (env: QBFT_VERIFIER)`);
            console.error(`  E2EApplication → ${result.application} (env: E2E_APPLICATION)`);
            console.error(`  MockClprConnector → ${result.connectorContract} (env: MOCK_CLPR_CONNECTOR)`);
            console.error(`  BundleEncoderHelper → ${result.bundleEncoder} (env: BUNDLE_ENCODER_HELPER)`);
            break;
        }
        case "e2e-with-hiero-verifier": {
            const ledgerId = loadLedgerIdBytes();
            const result = await deployE2EWithHieroVerifier(clients, params, {ledgerId});
            await applyInitialConfigOrPrintInstructions(clients, result.clprService, params, deployer, autoEnable);
            addresses = {
                ...clprDeployedToEnv(result),
                ...hieroVerifierStackToEnv({...result.verifierStack, hieroVerifier: result.verifier}),
                E2E_APPLICATION: result.application,
                MOCK_CLPR_CONNECTOR: result.connectorContract,
                BUNDLE_ENCODER_HELPER: result.bundleEncoder
            };
            logDeployed(result);
            console.error(`  HieroVerifier → ${result.verifier} (env: HIERO_VERIFIER)`);
            console.error(`  E2EApplication → ${result.application} (env: E2E_APPLICATION)`);
            console.error(`  MockClprConnector → ${result.connectorContract} (env: MOCK_CLPR_CONNECTOR)`);
            console.error(`  BundleEncoderHelper → ${result.bundleEncoder} (env: BUNDLE_ENCODER_HELPER)`);
            break;
        }
        case "hiero-verifier": {
            const lid = ledgerId ? (ledgerId.startsWith("0x") ? ledgerId : `0x${ledgerId}`) as `0x${string}` : loadLedgerIdBytes();
            const result = await deployHieroVerifierStack(clients, lid);
            addresses = hieroVerifierStackToEnv({...result, hieroVerifier: result.hieroVerifier});
            console.error("=========================================");
            console.error(`  PoseidonPermute_A → ${result.poseidonPermuteA} (env: POSEIDON_PERMUTE_A)`);
            console.error(`  PoseidonPermute_B → ${result.poseidonPermuteB} (env: POSEIDON_PERMUTE_B)`);
            console.error(`  PoseidonBN254 → ${result.poseidonBN254} (env: POSEIDON_BN254)`);
            console.error(`  WrapsVerifier → ${result.wrapsVerifier} (env: WRAPS_VERIFIER)`);
            console.error(`  TSSVerifier → ${result.tssVerifier} (env: TSS_VERIFIER)`);
            console.error(`  HieroVerifier → ${result.hieroVerifier} (env: HIERO_VERIFIER)`);
            break;
        }
        case "qbft-verifier": {
            const result = await deployQbftVerifier(clients);
            addresses = {QBFT_VERIFIER: result.qbftVerifier};
            console.error("=========================================");
            console.error(`  QBFTVerifier → ${result.qbftVerifier} (env: QBFT_VERIFIER)`);
            break;
        }
        case "sei-verifier": {
            const result = await deploySeiVerifierStack(clients);
            addresses = seiVerifierStackToEnv(result);
            console.error("=========================================");
            console.error(`  Ed25519Verifier → ${result.ed25519Verifier} (env: ED25519_VERIFIER)`);
            console.error(`  SeiCometBftVerifier → ${result.seiVerifier} (env: SEI_VERIFIER)`);
            break;
        }
        case "eth-mainnet-verifier": {
            const result = await deployEthMainnetVerifier(clients);
            addresses = {ETH_MAINNET_VERIFIER: result.ethMainnetVerifier};
            console.error("=========================================");
            console.error(`  EthMainnetVerifier → ${result.ethMainnetVerifier} (env: ETH_MAINNET_VERIFIER)`);
            break;
        }
    }

    if (transferToAddress) {
        // Prefer the freshly-deployed ClprService from this run; only fall back
        // to the env value for config-only mode (no deploy happened this run).
        const svc = (addresses.CLPR_SERVICE ?? process.env.CLPR_SERVICE) as Address | undefined;
        if (!svc) {
            throw new Error(
                "--transfer-ownership-to-account set but no ClprService address available (deploy it first, or use a mode that deploys it)"
            );
        }
        const account = requireOwnerAccount(envFile);
        await transferOwnership(clients, getAddress(svc), account);
        console.error(`Ownership of ClprService ${svc} transferred to Account ${account}`);
    }

    emitOutput(addresses, outputFormat, outputToFile);
}

main().catch((err) => {
    console.error("");
    console.error("[Deploy] =========================================");
    console.error("[Deploy] DEPLOYMENT FAILED");
    console.error("[Deploy] =========================================");
    console.error(`[Deploy] Error: ${err instanceof Error ? err.message : String(err)}`);
    if (err instanceof Error && err.stack) {
        console.error("[Deploy] Stack trace:");
        err.stack.split("\n").slice(1).forEach((line: string) => {
            console.error(`[Deploy] ${line}`);
        });
    }
    console.error("[Deploy] =========================================");
    console.error("");
    process.exit(1);
});