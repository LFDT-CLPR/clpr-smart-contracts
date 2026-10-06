import {existsSync, readFileSync} from "node:fs";
import path from "node:path";
import {REPO_ROOT, loadArtifact} from "./artifacts.js";
import type {ClprDeployed, ClprModules, DeployParams, E2EDeployed} from "./config.js";
import type {DeployClients} from "./client.js";

// Manual gas-limit override for deployment txs, bypassing viem's RPC auto-estimation.
// Historically forced for Hiero (Mirror Node's eth_estimateGas rejected contract
// creation from ECDSA senders with INSUFFICIENT_TX_FEE; fixed in Mirror Node
// v0.159.0, hiero-ledger/hiero-mirror-node#13820). Kept as a general escape hatch.
function getDeployGas(): bigint | undefined {
    const envGas = process.env.DEPLOY_GAS;
    if (envGas) {
        try {
            return BigInt(envGas);
        } catch {
            console.error(`[Deploy] Invalid DEPLOY_GAS: "${envGas}" (expected number)`);
        }
    }
    return undefined;  // Use viem's auto-estimation by default
}

export async function deployArtifact(
    clients: DeployClients,
    name: string,
    args: readonly unknown[] = []
): Promise<`0x${string}`> {
    console.error(`[Deploy] Starting ${name}...`);
    const {abi, bytecode} = loadArtifact(name);
    console.error(`[Deploy] Loaded artifact for ${name} (bytecode: ${bytecode.length} bytes)`);

    try {
        console.error(`[Deploy] Sending deployment tx for ${name}...`);

        const deployGas = getDeployGas();
        const deployParams: Parameters<typeof clients.walletClient.deployContract>[0] = {
            abi: abi as never,
            bytecode,
            args: args as never,
            chain: clients.chain,
            account: clients.account
        };

        // Only use hardcoded gas if DEPLOY_GAS is explicitly set
        if (deployGas) {
            console.error(`[Deploy]   Gas limit: ${deployGas} (from DEPLOY_GAS env var)`);
            deployParams.gas = deployGas;
        }

        const hash = await clients.walletClient.deployContract(deployParams);
        console.error(`[Deploy] ${name} tx hash: ${hash}`);

        console.error(`[Deploy] Waiting for receipt of ${name}...`);
        const receipt = await clients.publicClient.waitForTransactionReceipt({hash});
        const address = receipt.contractAddress;
        if (!address) throw new Error(`${name} deploy returned no contract address (tx ${hash})`);
        console.error(`[Deploy] ✓ ${name} deployed at ${address}`);
        return address;
    } catch (error) {
        console.error(`[Deploy] ✗ FAILED to deploy ${name}`);
        if (error instanceof Error) {
            console.error(`[Deploy] Error: ${error.message}`);
            if (error.cause) {
                console.error(`[Deploy] Cause: ${error.cause}`);
            }
            if ('code' in error && error.code) {
                console.error(`[Deploy] Code: ${error.code}`);
            }
        } else {
            console.error(`[Deploy] Error: ${String(error)}`);
        }
        throw error;
    }
}

// ── Core CLPR stack ───────────────────────────────────────────────────────

export async function deployClprModules(clients: DeployClients): Promise<ClprModules> {
    console.error("[Deploy] ========================================");
    console.error("[Deploy] Deploying CLPR modules (1/5)...");
    console.error("[Deploy] ========================================");
    const channelLogic = await deployArtifact(clients, "ChannelLogic");

    console.error("[Deploy] ========================================");
    console.error("[Deploy] Deploying CLPR modules (2/5)...");
    console.error("[Deploy] ========================================");
    const messagingLogic = await deployArtifact(clients, "MessagingLogic");

    console.error("[Deploy] ========================================");
    console.error("[Deploy] Deploying CLPR modules (3/5)...");
    console.error("[Deploy] ========================================");
    const bundleLogic = await deployArtifact(clients, "BundleLogic");

    console.error("[Deploy] ========================================");
    console.error("[Deploy] Deploying CLPR modules (4/5)...");
    console.error("[Deploy] ========================================");
    const connectorLogic = await deployArtifact(clients, "ConnectorLogic");

    console.error("[Deploy] ========================================");
    console.error("[Deploy] Deploying CLPR modules (5/5)...");
    console.error("[Deploy] ========================================");
    const adminLogic = await deployArtifact(clients, "AdminLogic");

    console.error("[Deploy] ========================================");
    console.error("[Deploy] Deploying helper contract...");
    console.error("[Deploy] ========================================");
    const bundleDecodeHelper = await deployArtifact(clients, "BundleDecodeHelper");

    console.error("[Deploy] ✓ All CLPR modules deployed successfully");
    return {channelLogic, messagingLogic, bundleLogic, connectorLogic, adminLogic, bundleDecodeHelper};
}

/// Deploy `ClprService` wired to existing modules.
export async function deployClprService(
    clients: DeployClients,
    params: DeployParams,
    modules: ClprModules
): Promise<`0x${string}`> {
    console.error("[Deploy] ========================================");
    console.error("[Deploy] Deploying ClprService...");
    console.error("[Deploy] Parameters:");
    console.error(`[Deploy]   initialOwner: ${params.initialOwner}`);
    console.error(`[Deploy]   protocolVersion: ${params.protocolVersion}`);
    console.error(`[Deploy]   chainId: ${params.chainId}`);
    console.error(`[Deploy]   channelLogic: ${modules.channelLogic}`);
    console.error(`[Deploy]   messagingLogic: ${modules.messagingLogic}`);
    console.error(`[Deploy]   bundleLogic: ${modules.bundleLogic}`);
    console.error(`[Deploy]   connectorLogic: ${modules.connectorLogic}`);
    console.error(`[Deploy]   adminLogic: ${modules.adminLogic}`);
    console.error(`[Deploy]   bundleDecodeHelper: ${modules.bundleDecodeHelper}`);
    console.error("[Deploy] ========================================");
    return deployArtifact(clients, "ClprService", [
        params.initialOwner,
        params.protocolVersion,
        params.chainId,
        modules.channelLogic,
        modules.messagingLogic,
        modules.bundleLogic,
        modules.connectorLogic,
        modules.adminLogic,
        modules.bundleDecodeHelper
    ]);
}

/// Modules + service.
export async function deployClprAll(
    clients: DeployClients,
    params: DeployParams
): Promise<ClprDeployed> {
    console.error("[Deploy] =========================================");
    console.error("[Deploy] Starting full CLPR deployment (all)");
    console.error("[Deploy] =========================================");
    const modules = await deployClprModules(clients);
    const clprService = await deployClprService(clients, params, modules);
    console.error("[Deploy] =========================================");
    console.error("[Deploy] ✓ Full CLPR deployment completed");
    console.error("[Deploy] =========================================");
    return {...modules, clprService};
}

export async function assertModulesDeployed(clients: DeployClients, modules: ClprModules): Promise<void> {
    const entries: [string, `0x${string}`][] = [
        ["CHANNEL_LOGIC", modules.channelLogic],
        ["MESSAGING_LOGIC", modules.messagingLogic],
        ["BUNDLE_LOGIC", modules.bundleLogic],
        ["CONNECTOR_LOGIC", modules.connectorLogic],
        ["ADMIN_LOGIC", modules.adminLogic],
        ["BUNDLE_DECODE_HELPER", modules.bundleDecodeHelper]
    ];
    const missing: string[] = [];
    for (const [name, addr] of entries) {
        const code = await clients.publicClient.getCode({address: addr});
        if (!code || code === "0x") missing.push(`${name}=${addr}`);
    }
    if (missing.length > 0) {
        throw new Error(`module addresses have no bytecode:\n  - ${missing.join("\n  - ")}\nDeploy modules first.`);
    }
}

// ── E2E helpers (shared by all verifier modes) ────────────────────────────

async function deployE2EHelpers(
    clients: DeployClients
): Promise<{application: `0x${string}`; connectorContract: `0x${string}`; bundleEncoder: `0x${string}`}> {
    console.error("[Deploy] ========================================");
    console.error("[Deploy] Deploying E2E helper contracts...");
    console.error("[Deploy] ========================================");
    const application = await deployArtifact(clients, "E2EApplication");
    const connectorContract = await deployArtifact(clients, "MockClprConnector");
    const bundleEncoder = await deployArtifact(clients, "BundleEncoderHelper");
    console.error("[Deploy] ✓ E2E helpers deployed successfully");
    return {application, connectorContract, bundleEncoder};
}

async function assertServiceCode(clients: DeployClients, addr: `0x${string}`, tag: string): Promise<void> {
    const code = await clients.publicClient.getCode({address: addr});
    if (!code || code === "0x") throw new Error(`no bytecode at ClprService on chain ${tag} (${addr})`);
}

// ── E2E with stub verifier ────────────────────────────────────────────────

export async function deployE2E(
    clients: DeployClients,
    params: DeployParams,
    label?: string
): Promise<E2EDeployed> {
    const tag = label ?? String(clients.chain.id);
    console.error(`[Deploy] ========================================`);
    console.error(`[Deploy] Starting E2E deployment (chain: ${tag})`);
    console.error(`[Deploy] ========================================`);
    const core = await deployClprAll(clients, params);
    console.error("[Deploy] ========================================");
    console.error("[Deploy] Deploying E2EVerifier...");
    console.error("[Deploy] ========================================");
    const verifier = await deployArtifact(clients, "E2EVerifier");
    const helpers = await deployE2EHelpers(clients);
    await assertServiceCode(clients, core.clprService, tag);
    console.error(`[Deploy] ✓ E2E deployment completed`);
    return {...core, verifier, ...helpers};
}

// ── E2E with QBFT verifier ────────────────────────────────────────────────

export interface E2EWithQbftVerifierDeployed extends ClprDeployed {
    qbftVerifier: `0x${string}`;
    application: `0x${string}`;
    connectorContract: `0x${string}`;
    bundleEncoder: `0x${string}`;
}

export async function deployE2EWithQbftVerifier(
    clients: DeployClients,
    params: DeployParams,
    opts?: {label?: string}
): Promise<E2EWithQbftVerifierDeployed> {
    const tag = opts?.label ?? String(clients.chain.id);
    console.error(`[Deploy] ========================================`);
    console.error(`[Deploy] Starting E2E+QBFT deployment (chain: ${tag})`);
    console.error(`[Deploy] ========================================`);
    const core = await deployClprAll(clients, params);
    console.error("[Deploy] ========================================");
    console.error("[Deploy] Deploying QbftHeaderModeVerifier...");
    console.error("[Deploy] ========================================");
    const qbftVerifier = await deployArtifact(clients, "QbftHeaderModeVerifier", []);
    const helpers = await deployE2EHelpers(clients);
    await assertServiceCode(clients, core.clprService, tag);
    console.error(`[Deploy] ✓ E2E+QBFT deployment completed`);
    return {...core, qbftVerifier, ...helpers};
}

// ── E2E with Hiero verifier ───────────────────────────────────────────────

export interface HieroVerifierStack {
    poseidonPermuteA: `0x${string}`;
    poseidonPermuteB: `0x${string}`;
    poseidonBN254: `0x${string}`;
    wrapsVerifier: `0x${string}`;
    tssVerifier: `0x${string}`;
}

export interface E2EWithHieroVerifierDeployed extends ClprDeployed {
    verifier: `0x${string}`;
    verifierStack: HieroVerifierStack;
    application: `0x${string}`;
    connectorContract: `0x${string}`;
    bundleEncoder: `0x${string}`;
}

function envAddress(name: string): `0x${string}` | undefined {
    const v = process.env[name];
    if (!v) return undefined;
    return (v.startsWith("0x") ? v : `0x${v}`) as `0x${string}`;
}

export function loadLedgerIdBytes(): `0x${string}` {
    const fromEnv = process.env.LEDGER_ID ?? process.env.TRUST_ANCHOR;
    if (fromEnv) return (fromEnv.startsWith("0x") ? fromEnv : `0x${fromEnv}`) as `0x${string}`;
    const file = path.join(REPO_ROOT, "test", "verifiers", "hiero", "fixtures", "trustAnchor.bin");
    if (existsSync(file)) return `0x${readFileSync(file).toString("hex")}` as `0x${string}`;
    throw new Error(
        "ledger id required: set LEDGER_ID or TRUST_ANCHOR in .env, or add test/verifiers/hiero/fixtures/trustAnchor.bin"
    );
}

export async function deployHieroVerifierStack(
    clients: DeployClients,
    ledgerId: `0x${string}`
): Promise<HieroVerifierStack & {hieroVerifier: `0x${string}`}> {
    console.error("[Deploy] =========================================");
    console.error("[Deploy] Deploying Hiero Verifier Stack");
    console.error("[Deploy] =========================================");

    const poseidonPermuteA = envAddress("POSEIDON_PERMUTE_A") ?? (console.error("[Deploy] [1/6] PoseidonPermuteA"), await deployArtifact(clients, "PoseidonPermuteA"));
    const poseidonPermuteB = envAddress("POSEIDON_PERMUTE_B") ?? (console.error("[Deploy] [2/6] PoseidonPermuteB"), await deployArtifact(clients, "PoseidonPermuteB"));
    const poseidonBN254 = envAddress("POSEIDON_BN254") ?? (console.error("[Deploy] [3/6] PoseidonBN254Contract"), await deployArtifact(clients, "PoseidonBN254Contract", [poseidonPermuteA, poseidonPermuteB]));
    const wrapsVerifier = envAddress("WRAPS_VERIFIER") ?? (console.error("[Deploy] [4/6] WRAPSVerifierContract"), await deployArtifact(clients, "WRAPSVerifierContract", [poseidonBN254]));
    const tssVerifier = envAddress("TSS_VERIFIER") ?? (console.error("[Deploy] [5/6] TSSVerifier"), await deployArtifact(clients, "TSSVerifier", [wrapsVerifier]));
    const hieroVerifier = envAddress("HIERO_VERIFIER") ?? (console.error("[Deploy] [6/6] HieroVerifier"), await deployArtifact(clients, "HieroVerifier", [ledgerId, tssVerifier]));

    console.error("[Deploy] ✓ Hiero Verifier Stack deployed successfully");
    return {poseidonPermuteA, poseidonPermuteB, poseidonBN254, wrapsVerifier, tssVerifier, hieroVerifier};
}

export async function deployE2EWithHieroVerifier(
    clients: DeployClients,
    params: DeployParams,
    opts?: {ledgerId?: `0x${string}`; label?: string}
): Promise<E2EWithHieroVerifierDeployed> {
    const tag = opts?.label ?? String(clients.chain.id);
    const ledgerId = opts?.ledgerId ?? loadLedgerIdBytes();
    console.error(`[Deploy] ========================================`);
    console.error(`[Deploy] Starting E2E+Hiero deployment (chain: ${tag})`);
    console.error(`[Deploy] ========================================`);
    const core = await deployClprAll(clients, params);
    const {hieroVerifier, ...verifierStack} = await deployHieroVerifierStack(clients, ledgerId);
    const helpers = await deployE2EHelpers(clients);
    await assertServiceCode(clients, core.clprService, tag);
    console.error(`[Deploy] ✓ E2E+Hiero deployment completed`);
    return {...core, verifier: hieroVerifier, verifierStack, ...helpers};
}

export const HIERO_VERIFIER_ENV_KEYS = [
    "POSEIDON_PERMUTE_A", "POSEIDON_PERMUTE_B", "POSEIDON_BN254",
    "WRAPS_VERIFIER", "TSS_VERIFIER", "HIERO_VERIFIER"
] as const;

export function hieroVerifierStackToEnv(
    stack: HieroVerifierStack & {hieroVerifier: `0x${string}`}
): Record<(typeof HIERO_VERIFIER_ENV_KEYS)[number], string> {
    return {
        POSEIDON_PERMUTE_A: stack.poseidonPermuteA,
        POSEIDON_PERMUTE_B: stack.poseidonPermuteB,
        POSEIDON_BN254: stack.poseidonBN254,
        WRAPS_VERIFIER: stack.wrapsVerifier,
        TSS_VERIFIER: stack.tssVerifier,
        HIERO_VERIFIER: stack.hieroVerifier
    };
}

// ── QBFT Verifier ──────────────────────────────────────────────────────

export interface QbftVerifierDeployed {
    qbftVerifier: `0x${string}`;
}

export async function deployQbftVerifier(clients: DeployClients): Promise<QbftVerifierDeployed> {
    console.error("[Deploy] =========================================");
    console.error("[Deploy] Deploying QBFT Verifier");
    console.error("[Deploy] =========================================");

    // TODO: remove the legacy QBFTVerifier (incorrect implementation)
    //      remove the line below and deploy QbftHeaderModeVerifier with [] instead
    const qbftVerifier = envAddress("QBFT_VERIFIER") ?? (console.error("[Deploy] Deploying QBFTVerifier"), await deployArtifact(clients, "QBFTVerifier", [1]));
    // uncomment this:
    // const qbftVerifier = envAddress("QBFT_VERIFIER") ?? (console.error("[Deploy] Deploying QbftHeaderModeVerifier"), await deployArtifact(clients, "QbftHeaderModeVerifier", []));
    console.error("[Deploy] ✓ QBFT Verifier deployed successfully");
    return {qbftVerifier};
}

// ── Sei/CometBFT Verifier ──────────────────────────────────────────────

export interface SeiVerifierStack {
    ed25519Verifier: `0x${string}`;
    seiVerifier: `0x${string}`;
}

export async function deploySeiVerifierStack(clients: DeployClients): Promise<SeiVerifierStack> {
    console.error("[Deploy] =========================================");
    console.error("[Deploy] Deploying Sei/CometBFT Verifier Stack");
    console.error("[Deploy] =========================================");

    // SeiCometBftVerifier is now multi-service: the peer chain id, service address, and validator
    // set are established per-channel at verifyConfig time (carried in the config proof and the
    // resulting trust anchor), so no genesis chain configuration is needed at deploy time.
    const ed25519Verifier = envAddress("ED25519_VERIFIER") ?? (console.error("[Deploy] [1/2] Ed25519Verifier"), await deployArtifact(clients, "Ed25519Verifier"));
    const seiVerifier = envAddress("SEI_VERIFIER") ?? (console.error("[Deploy] [2/2] SeiCometBftVerifier"), await deployArtifact(clients, "SeiCometBftVerifier", [ed25519Verifier]));

    console.error("[Deploy] ✓ Sei/CometBFT Verifier Stack deployed successfully");
    return {ed25519Verifier, seiVerifier};
}

export const SEI_VERIFIER_ENV_KEYS = ["ED25519_VERIFIER", "SEI_VERIFIER"] as const;

export function seiVerifierStackToEnv(
    stack: SeiVerifierStack
): Record<(typeof SEI_VERIFIER_ENV_KEYS)[number], string> {
    return {
        ED25519_VERIFIER: stack.ed25519Verifier,
        SEI_VERIFIER: stack.seiVerifier
    };
}

export interface TempoVerifierDeployed {
    tempoVerifier: `0x${string}`;
}

export async function deployTempoVerifier(clients: DeployClients): Promise<TempoVerifierDeployed> {
    console.error("[Deploy] =========================================");
    console.error("[Deploy] Deploying Tempo Verifier");
    console.error("[Deploy] =========================================");

    const tempoVerifier = envAddress("TEMPO_VERIFIER") ?? (console.error("[Deploy] Deploying TempoVerifier"), await deployArtifact(clients, "TempoVerifier"));

    console.error("[Deploy] ✓ Tempo Verifier deployed successfully");
    return {tempoVerifier};
}

// ── Ethereum Mainnet Verifier ──────────────────────────────────────────

export interface EthMainnetVerifierDeployed {
    ethMainnetVerifier: `0x${string}`;
}

export async function deployEthMainnetVerifier(clients: DeployClients): Promise<EthMainnetVerifierDeployed> {
    console.error("[Deploy] =========================================");
    console.error("[Deploy] Deploying Ethereum Mainnet Verifier");
    console.error("[Deploy] =========================================");

    // EthMainnetVerifier requires Ethereum beacon chain contract details
    const expectedContractAddress = process.env.ETH_EXPECTED_CONTRACT_ADDRESS;
    const expectedCodeHash = process.env.ETH_EXPECTED_CODE_HASH;

    if (!expectedContractAddress) {
        throw new Error("ETH_EXPECTED_CONTRACT_ADDRESS is required (Ethereum beacon chain contract address, e.g., '0x...')");
    }
    if (!expectedCodeHash) {
        throw new Error("ETH_EXPECTED_CODE_HASH is required (hex-encoded code hash of beacon contract, e.g., '0x...')");
    }

    const ethMainnetVerifier = envAddress("ETH_MAINNET_VERIFIER") ?? (console.error("[Deploy] Deploying EthMainnetVerifier"), await deployArtifact(clients, "EthMainnetVerifier", [expectedContractAddress, expectedCodeHash]));

    console.error("[Deploy] ✓ Ethereum Mainnet Verifier deployed successfully");
    return {ethMainnetVerifier};
}
