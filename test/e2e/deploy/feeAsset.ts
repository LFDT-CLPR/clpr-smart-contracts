import {zeroAddress, type Hex} from "viem";
import {loadArtifact} from "../../../script/deploy/artifacts.js";
import {deployArtifact} from "../../../script/deploy/deployCore.js";
import type {ChainClients} from "../lib/clients.js";
import {DEFAULT_ECON, TOKEN_ECON} from "./constants.js";

/// Token-mode e2e (`CLPR_E2E_FEE_TOKEN=1`): every ClprService holds and pays stakes, bonds, execution
/// charges and slash proceeds in a 6-decimal USD ERC-20 (`MockFeeToken`) instead of native value. `deployAll` deploys the token and passes it to the ClprService constructor; every
/// other helper reads the mode back from the service with `getFeeToken()`.
export function feeTokenMode(): boolean {
    return process.env.CLPR_E2E_FEE_TOKEN === "1";
}

/// The economic config `wireConfig` applies on a non-Solo chain in the current mode.
export function activeEcon(): typeof DEFAULT_ECON | typeof TOKEN_ECON {
    return feeTokenMode() ? TOKEN_ECON : DEFAULT_ECON;
}

async function send(clients: ChainClients, address: Hex, abi: unknown, functionName: string, args: unknown[]) {
    const hash = await clients.walletClient.writeContract({
        address,
        abi: abi as never,
        functionName,
        args,
        chain: clients.chain,
        account: clients.account
    });
    const receipt = await clients.publicClient.waitForTransactionReceipt({hash});
    if (receipt.status === "reverted") {
        throw new Error(`${functionName} reverted (chain ${await clients.publicClient.getChainId()})`);
    }
}

export async function deployFeeToken(clients: ChainClients): Promise<Hex> {
    return deployArtifact(
        {chain: clients.chain, account: clients.account, publicClient: clients.publicClient, walletClient: clients.walletClient},
        "MockFeeToken",
        [6]
    );
}

/// `zeroAddress` when the service runs on native value.
export async function getFeeToken(clients: ChainClients, clprService: Hex): Promise<Hex> {
    return (await clients.publicClient.readContract({
        address: clprService,
        abi: loadArtifact("ClprService").abi as never,
        functionName: "getFeeToken"
    })) as Hex;
}

export function isTokenMode(feeToken: Hex): boolean {
    return feeToken !== zeroAddress;
}

export async function getEconomicConfig(
    clients: ChainClients,
    clprService: Hex
): Promise<{minLockedStake: bigint; minEndpointBond: bigint; basePenalty: bigint}> {
    return (await clients.publicClient.readContract({
        address: clprService,
        abi: loadArtifact("ClprService").abi as never,
        functionName: "getEconomicConfig"
    })) as {minLockedStake: bigint; minEndpointBond: bigint; basePenalty: bigint};
}

/// Balance of `account` in the service's fee asset: native value, or `feeToken`.
export async function feeAssetBalance(clients: ChainClients, feeToken: Hex, account: Hex): Promise<bigint> {
    if (!isTokenMode(feeToken)) return clients.publicClient.getBalance({address: account});
    return (await clients.publicClient.readContract({
        address: feeToken,
        abi: loadArtifact("MockFeeToken").abi as never,
        functionName: "balanceOf",
        args: [account]
    })) as bigint;
}

/// Mint `amount` of the mock token to the caller and let `spender` (the ClprService) pull it.
export async function approveFeeToken(clients: ChainClients, feeToken: Hex, spender: Hex, amount: bigint) {
    const token = loadArtifact("MockFeeToken");
    await send(clients, feeToken, token.abi, "mint", [clients.account.address, amount]);
    await send(clients, feeToken, token.abi, "approve", [spender, amount]);
}

/// Give a MockClprConnector a token operating balance and make its `payForExecution` pay in it.
export async function fundConnectorInToken(clients: ChainClients, feeToken: Hex, connector: Hex, amount: bigint) {
    await send(clients, feeToken, loadArtifact("MockFeeToken").abi, "mint", [connector, amount]);
    await send(clients, connector, loadArtifact("MockClprConnector").abi, "setPayToken", [feeToken]);
}
