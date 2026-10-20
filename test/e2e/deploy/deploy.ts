import type {Hex} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {
    defaultEconomicConfig,
    defaultThrottles,
    deployArtifact,
    deployE2E,
    deployE2EWithHieroVerifier,
    deployE2EWithQbftVerifier,
    type DeployClients,
    type DeployParams,
    type E2EDeployed,
    type E2EWithQbftVerifierDeployed
} from "../../../script/deploy/index.js";
import type {ChainClients} from "../lib/clients.js";
import type {BackendKind} from "../backend/Backend.js";
import {isSoloBackend} from "../backend/solo/solo.js";
import {resolveSoloLedgerId} from "../lib/soloLedger.js";
import {deployFeeToken, feeTokenMode} from "./feeAsset.js";

export type DeployedAddresses = Pick<
    E2EDeployed,
    "clprService" | "verifier" | "application" | "connectorContract" | "bundleEncoder"
>;

export interface QbftDeployedAddresses {
    clprService: Hex;
    qbftVerifier: Hex;
    application: Hex;
    connectorContract: Hex;
    bundleEncoder: Hex;
}

export interface DeployE2EPairResult {
    addrsA: DeployedAddresses;
    addrsB: DeployedAddresses;
}

export type DeployMode = "e2e" | "qbft" | "hiero" | "sei";

export interface ChainDeployConfig {
    clients: ChainClients;
    caipChainId: string;
    mode: DeployMode;
    ledgerId?: `0x${string}`;
}

function toDeployClients(clients: ChainClients): DeployClients {
    return {
        chain: clients.chain,
        account: clients.account,
        publicClient: clients.publicClient,
        walletClient: clients.walletClient
    };
}

function buildDeployParams(opts: {
    privateKey: Hex;
    protocolVersion: number;
    caipChainId: string;
}): DeployParams {
    const pk = opts.privateKey.startsWith("0x") ? opts.privateKey : (`0x${opts.privateKey}` as Hex);
    const initialOwner = privateKeyToAccount(pk).address;
    return {
        initialOwner,
        protocolVersion: opts.protocolVersion,
        chainId: opts.caipChainId,
        serviceAddress: "0x",
        throttles: defaultThrottles,
        trustAnchor: "0x",
        trustAnchorId: "0x",
        econ: defaultEconomicConfig
    };
}

function defaultParallelDeploy(): boolean {
    if (process.env.CLPR_E2E_DEPLOY_PARALLEL === "1") return true;
    if (process.env.CLPR_E2E_DEPLOY_SEQUENTIAL === "1") return false;
    return !isSoloBackend();
}

type DeployAllOpts = {
    clients: ChainClients;
    privateKey: Hex;
    caipChainId: string;
    protocolVersion?: number;
    label?: string;
    ledgerId?: `0x${string}`;
};

/// Deploys the CLPR contract set onto one chain via viem (`script/deploy/`).
/// Initial ledger/economic config is applied separately by `wireConfig`.
/// Pass `mode: "qbft"` or `mode: "hiero"` for real verifiers.
export async function deployAll(opts: DeployAllOpts & {mode?: "e2e"}): Promise<DeployedAddresses>;
export async function deployAll(opts: DeployAllOpts & {mode: "qbft"}): Promise<QbftDeployedAddresses>;
export async function deployAll(opts: DeployAllOpts & {mode: "hiero"}): Promise<DeployedAddresses>;
export async function deployAll(opts: DeployAllOpts & {mode: "sei"}): Promise<DeployedAddresses>;
export async function deployAll(opts: DeployAllOpts & {mode?: DeployMode}): Promise<DeployedAddresses | QbftDeployedAddresses> {
    const label = opts.label ?? String(await opts.clients.publicClient.getChainId());
    const params = buildDeployParams({...opts, protocolVersion: opts.protocolVersion ?? 1});
    // Token mode: the fee token is a ClprService constructor argument, so it exists before the service.
    if (feeTokenMode()) params.feeToken = await deployFeeToken(opts.clients);
    const clients = toDeployClients(opts.clients);

    if (opts.mode === "qbft") {
        const full: E2EWithQbftVerifierDeployed = await deployE2EWithQbftVerifier(clients, params, {label});
        return {
            clprService: full.clprService,
            qbftVerifier: full.qbftVerifier,
            application: full.application,
            connectorContract: full.connectorContract,
            bundleEncoder: full.bundleEncoder
        };
    }

    if (opts.mode === "hiero") {
        const ledgerId = opts.ledgerId ?? resolveSoloLedgerId();
        const full = await deployE2EWithHieroVerifier(clients, params, {ledgerId, label});
        return {
            clprService: full.clprService,
            verifier: full.verifier,
            application: full.application,
            connectorContract: full.connectorContract,
            bundleEncoder: full.bundleEncoder
        };
    }

    if (opts.mode === "sei") {
        const full = await deployE2E(clients, params, label);
        // SeiCometBftVerifier is multi-service: peer chain id / service / validators are
        // established per-channel via verifyConfig, so the constructor takes only the
        // Ed25519 verifier address.
        const ed25519Verifier = await deployArtifact(clients, "Ed25519Verifier", []);
        const seiVerifier = await deployArtifact(clients, "SeiCometBftVerifier", [ed25519Verifier]);
        return {
            clprService: full.clprService,
            verifier: seiVerifier,
            application: full.application,
            connectorContract: full.connectorContract,
            bundleEncoder: full.bundleEncoder
        };
    }

    const full: E2EDeployed = await deployE2E(clients, params, label);
    return {
        clprService: full.clprService,
        verifier: full.verifier,
        application: full.application,
        connectorContract: full.connectorContract,
        bundleEncoder: full.bundleEncoder
    };
}

/// Verifier deploy mode for a chain that receives proofs from `proofProducer`.
export function deployModeFor(proofProducer: BackendKind): DeployMode {
    if (proofProducer === "solo") return "hiero";
    if (proofProducer === "besu") return "qbft";
    if (proofProducer === "sei") return "sei";
    return "e2e";
}

/// Deploy with per-chain verifier mode (cross-verifier pairs).
export async function deployE2EPair(opts: {
    chainA: ChainDeployConfig;
    chainB: ChainDeployConfig;
    privateKey: Hex;
    protocolVersion?: number;
    parallel?: boolean;
}): Promise<DeployE2EPairResult>;
/// Legacy symmetric deploy (same stub verifier on both chains).
export async function deployE2EPair(opts: {
    clientsA: ChainClients;
    clientsB: ChainClients;
    privateKey: Hex;
    protocolVersion?: number;
    caipChainIdA: string;
    caipChainIdB: string;
    parallel?: boolean;
}): Promise<DeployE2EPairResult>;
export async function deployE2EPair(opts: {
    chainA?: ChainDeployConfig;
    chainB?: ChainDeployConfig;
    clientsA?: ChainClients;
    clientsB?: ChainClients;
    privateKey: Hex;
    protocolVersion?: number;
    caipChainIdA?: string;
    caipChainIdB?: string;
    parallel?: boolean;
}): Promise<DeployE2EPairResult> {
    if (opts.chainA && opts.chainB) {
        const parallel = opts.parallel ?? defaultParallelDeploy();
        const protocolVersion = opts.protocolVersion ?? 1;

        const deployChain = async (cfg: ChainDeployConfig, label: string): Promise<DeployedAddresses> => {
            const shared = {
                clients: cfg.clients,
                privateKey: opts.privateKey,
                caipChainId: cfg.caipChainId,
                protocolVersion,
                label,
                ledgerId: cfg.ledgerId
            };
            if (cfg.mode === "qbft") {
                return normalizeAddrs(await deployAll({...shared, mode: "qbft"}));
            }
            if (cfg.mode === "hiero") {
                return normalizeAddrs(await deployAll({...shared, mode: "hiero"}));
            }
            if (cfg.mode === "sei") {
                return normalizeAddrs(await deployAll({...shared, mode: "sei"}));
            }
            return normalizeAddrs(await deployAll({...shared, mode: "e2e"}));
        };

        if (parallel) {
            const [addrsA, addrsB] = await Promise.all([
                deployChain(opts.chainA, "A"),
                deployChain(opts.chainB, "B")
            ]);
            return {addrsA: normalizeAddrs(addrsA), addrsB: normalizeAddrs(addrsB)};
        }

        const addrsA = await deployChain(opts.chainA, "A");
        const addrsB = await deployChain(opts.chainB, "B");
        return {addrsA: normalizeAddrs(addrsA), addrsB: normalizeAddrs(addrsB)};
    }

    if (!opts.clientsA || !opts.clientsB || !opts.caipChainIdA || !opts.caipChainIdB) {
        throw new Error("deployE2EPair: provide chainA/chainB or clientsA/clientsB with caip ids");
    }

    return deployE2EPair({
        chainA: {clients: opts.clientsA, caipChainId: opts.caipChainIdA, mode: "e2e"},
        chainB: {clients: opts.clientsB, caipChainId: opts.caipChainIdB, mode: "e2e"},
        privateKey: opts.privateKey,
        protocolVersion: opts.protocolVersion,
        parallel: opts.parallel
    });
}

function normalizeAddrs(addrs: DeployedAddresses | QbftDeployedAddresses): DeployedAddresses {
    if ("qbftVerifier" in addrs) {
        return {
            clprService: addrs.clprService,
            verifier: addrs.qbftVerifier,
            application: addrs.application,
            connectorContract: addrs.connectorContract,
            bundleEncoder: addrs.bundleEncoder
        };
    }
    return addrs;
}

function verifierAddr(addrs: DeployedAddresses | QbftDeployedAddresses): Hex {
    return "qbftVerifier" in addrs ? addrs.qbftVerifier : addrs.verifier;
}

export {verifierAddr};
