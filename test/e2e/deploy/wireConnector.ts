import {generatePrivateKey, privateKeyToAccount} from "viem/accounts";
import {parseEther, type Hex} from "viem";
import {loadArtifact} from "../../../script/deploy/artifacts.js";
import type {ChainClients} from "../lib/clients.js";
import {isSoloBackend, soloMinConnectorFund} from "../backend/solo/solo.js";
import {
    connectorCommitment,
    deriveConnectorId,
    digestForConnectorReveal,
    uncompressedPubKey64
} from "../lib/ids.js";
import { TOKEN_CONNECTOR_FUND, ZERO_BYTES32 } from "./constants";
import { approveFeeToken, fundConnectorInToken, getEconomicConfig, getFeeToken, isTokenMode } from "./feeAsset.js";

export interface WiredConnector {
    connectorId: Hex;             // bytes32
    connectorPubKey: Hex;         // 64-byte uncompressed
    connectorAddress: Hex;        // checksummed signer address (pubkey-derived)
    salt: Hex;
}

/// Minimal address set that `wireConnector` needs — only the ClprService proxy
/// and the connector contract.  Using a narrow interface allows both
/// `DeployedAddresses` and `QbftDeployedAddresses` to be passed in.
interface ConnectorDeployAddrs {
    clprService: `0x${string}`;
    connectorContract: `0x${string}`;
}

/// Wire a connector pair: register + reveal on both sides, then fund each
/// local MockClprConnector contract so its `payForExecution` callback can
/// settle when inbound DATA messages arrive.
///
/// Each side follows its service's fee asset (`getFeeToken()`). In token mode the
/// stake is `minLockedStake` of the token, approved here and pulled by
/// completeConnector, plus a `topUpConnectorStake` for any `stake` above it;
/// the connector gets a token operating balance and pays `payForExecution` in it.
///
///   1. Fresh connector keypair (deterministic if `connectorKey` supplied).
///   2. Derive `connectorId` in TS — same value on both chains by construction
///      (function of channelId + pubKey + salt only; no per-chain inputs).
///   3. registerConnector(commitment) on chain A; sign keccak(connectorId‖routerA);
///      completeConnector with the `stake`. Same on chain B.
///   4. Give each MockClprConnector a `fundConnector` operating balance for inbound payments.
///
/// Pre-conditions:
///   - wireChannel has run; `channelId` exists on both chains in ACTIVE state.
///   - Both chains have economicConfig.minLockedStake set (wire.ts handles this).
export async function wireConnector(opts: {
    chainA: ChainClients;
    chainB: ChainClients;
    addrsA: ConnectorDeployAddrs;
    addrsB: ConnectorDeployAddrs;
    channelId: Hex;
    /// Bytes32 salt — defaults to bytes32(0). Use a non-zero salt only if you
    /// need multiple connectors on the same channel in one test run.
    salt?: Hex;
    /// Private key for the connector operator. Defaults to a fresh random key.
    connectorKey?: Hex;
    /// Stake to lock on each side, in fee-asset units (must be >= economicConfig.minLockedStake).
    stake?: bigint;
    /// Operating balance for each MockClprConnector, in fee-asset units, for inbound-message execution.
    fundConnector?: bigint;
    /// Admin address authorized to deregister + top up. Defaults to chain's deployer.
    admin?: Hex;
    /// Set per-side to override global isSoloBackend() for mixed-backend runs.
    soloRelayA?: boolean;
    soloRelayB?: boolean;
    /// When true, only register/complete/fund the connector on chain A (chain B is skipped).
    /// Used by tests that need a connector which exists on the source chain but NOT on the
    /// peer, so inbound DATA referencing it triggers a CONNECTOR_NOT_FOUND reply.
    skipChainB?: boolean;
}): Promise<WiredConnector> {
    const { chainA, chainB, addrsA, addrsB, channelId } = opts;
    const salt = opts.salt ?? ZERO_BYTES32;

    const isSoloA = opts.soloRelayA ?? isSoloBackend();
    const isSoloB = opts.soloRelayB ?? isSoloBackend();

    const feeTokenA = await getFeeToken(chainA, addrsA.clprService);
    const feeTokenB = opts.skipChainB ? feeTokenA : await getFeeToken(chainB, addrsB.clprService);
    const tokenA = isTokenMode(feeTokenA);
    const tokenB = isTokenMode(feeTokenB);

    // Native mode on a Solo relay: tx.value is not forwarded into delegatecall targets, so stake is 0.
    const stakeA = tokenA
        ? (opts.stake ?? (await getEconomicConfig(chainA, addrsA.clprService)).minLockedStake)
        : isSoloA ? 0n : (opts.stake ?? parseEther("0.1"));
    const stakeB = tokenB
        ? (opts.stake ?? (await getEconomicConfig(chainB, addrsB.clprService)).minLockedStake)
        : isSoloB ? 0n : (opts.stake ?? parseEther("0.1"));

    // Connector fund: Solo native mode needs gas-price-based sizing per side.
    let fundA = opts.fundConnector ?? (tokenA ? TOKEN_CONNECTOR_FUND : parseEther("1"));
    let fundB = opts.fundConnector ?? (tokenB ? TOKEN_CONNECTOR_FUND : parseEther("1"));
    if (isSoloA && !tokenA) fundA = await soloMinConnectorFund(chainA.publicClient);
    if (isSoloB && !tokenB) fundB = await soloMinConnectorFund(chainB.publicClient);

    // ── 1. Connector operator keypair ──────────────────────────────────────
    const connectorKey = opts.connectorKey ?? generatePrivateKey();
    const connectorAccount = privateKeyToAccount(connectorKey);
    const connectorPubKey = uncompressedPubKey64(connectorAccount.publicKey);

    // ── 2. Derive connectorId (deterministic across chains) ────────────────
    const connectorId = deriveConnectorId({ channelId, pubKey: connectorPubKey, salt });

    // ── 3. Commit-reveal on both sides ─────────────────────────────────────
    const commitment = connectorCommitment(connectorId, connectorPubKey);

    const adminA = opts.admin ?? chainA.account.address;
    const adminB = opts.admin ?? chainB.account.address;

    await registerOn(chainA, addrsA.clprService, commitment);
    const sigA = await connectorAccount.signMessage({
        message: { raw: digestForConnectorReveal(connectorId, addrsA.clprService) }
    });
    await completeOn(chainA, addrsA.clprService, {
        connectorId, pubKey: connectorPubKey, sig: sigA, salt, channelId,
        connectorContract: addrsA.connectorContract, admin: adminA, stake: stakeA, feeToken: feeTokenA
    });

    if (!opts.skipChainB) {
        await registerOn(chainB, addrsB.clprService, commitment);
        const sigB = await connectorAccount.signMessage({
            message: { raw: digestForConnectorReveal(connectorId, addrsB.clprService) }
        });
        await completeOn(chainB, addrsB.clprService, {
            connectorId, pubKey: connectorPubKey, sig: sigB, salt, channelId,
            connectorContract: addrsB.connectorContract, admin: adminB, stake: stakeB, feeToken: feeTokenB
        });
    }

    // ── 4. Fund each MockClprConnector for payForExecution ─────────────────
    await fundConnector(chainA, addrsA.connectorContract, fundA, feeTokenA);
    if (!opts.skipChainB) {
        await fundConnector(chainB, addrsB.connectorContract, fundB, feeTokenB);
    }

    return { connectorId, connectorPubKey, connectorAddress: connectorAccount.address, salt };
}

// ── Helpers ───────────────────────────────────────────────────────────────

async function registerOn(clients: ChainClients, serviceAddr: Hex, commitment: Hex): Promise<void> {
    const service = loadArtifact("ClprService");
    const tx = await clients.walletClient.writeContract({
        address: serviceAddr,
        abi: service.abi as never,
        functionName: "registerConnector",
        args: [commitment]
    });
    await clients.publicClient.waitForTransactionReceipt({ hash: tx });
}

async function completeOn(
    clients: ChainClients,
    serviceAddr: Hex,
    a: {
        connectorId: Hex; pubKey: Hex; sig: Hex; salt: Hex; channelId: Hex;
        connectorContract: Hex; admin: Hex; stake: bigint; feeToken: Hex;
    }
): Promise<void> {
    const service = loadArtifact("ClprService");
    const tokenMode = isTokenMode(a.feeToken);
    // Token mode: completeConnector pulls exactly minLockedStake; the rest is a separate top-up.
    const minStake = tokenMode ? (await getEconomicConfig(clients, serviceAddr)).minLockedStake : 0n;
    if (tokenMode) await approveFeeToken(clients, a.feeToken, serviceAddr, a.stake);
    const tx = await clients.walletClient.writeContract({
        address: serviceAddr,
        abi: service.abi as never,
        functionName: "completeConnector",
        args: [a.connectorId, a.pubKey, a.sig, a.salt, a.channelId, a.connectorContract, a.admin],
        value: tokenMode ? 0n : a.stake
    });
    const receipt = await clients.publicClient.waitForTransactionReceipt({hash: tx});
    if (receipt.status === "reverted") {
        throw new Error(`completeConnector reverted (chain ${await clients.publicClient.getChainId()})`);
    }
    if (tokenMode && a.stake > minStake) {
        const topUpTx = await clients.walletClient.writeContract({
            address: serviceAddr,
            abi: service.abi as never,
            functionName: "topUpConnectorStake",
            args: [a.channelId, a.connectorId, a.stake - minStake]
        });
        const topUp = await clients.publicClient.waitForTransactionReceipt({hash: topUpTx});
        if (topUp.status === "reverted") {
            throw new Error(`topUpConnectorStake reverted (chain ${await clients.publicClient.getChainId()})`);
        }
    }
}

async function fundConnector(clients: ChainClients, target: Hex, value: bigint, feeToken: Hex): Promise<void> {
    if (isTokenMode(feeToken)) {
        await fundConnectorInToken(clients, feeToken, target, value);
        return;
    }
    // MockClprConnector defines `receive() external payable {}` — a plain
    // value transfer lands in its native balance.
    // Explicit gas avoids eth_estimateGas calls on Hedera where the Mirror Node
    // may not be ready yet when this runs (Mirror Node lags consensus nodes).
    const tx = await clients.walletClient.sendTransaction({
        account: clients.account,
        chain: clients.chain,
        to: target,
        value,
        gas: 100_000n
    });
    const receipt = await clients.publicClient.waitForTransactionReceipt({hash: tx});
    if (receipt.status === "reverted") {
        throw new Error(`fundConnector transfer reverted (chain ${await clients.publicClient.getChainId()})`);
    }
}
