import {createPublicClient, createWalletClient, http, type Chain} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {createNonceManager, jsonRpc} from "viem/nonce";

export interface DeployClients {
    chain: Chain;
    account: ReturnType<typeof privateKeyToAccount>;
    publicClient: ReturnType<typeof createPublicClient>;
    walletClient: ReturnType<typeof createWalletClient>;
}

/// Local account with coordinated nonces for parallel contract deploys.
export function makeDeployAccount(privateKey: `0x${string}`) {
    const nonceManager = createNonceManager({source: jsonRpc()});
    return privateKeyToAccount(privateKey, {nonceManager});
}

export async function makeDeployClients(opts: {
    rpcUrl: string;
    privateKey: `0x${string}`;
}): Promise<DeployClients> {
    const account = makeDeployAccount(opts.privateKey);
    const transport = http(opts.rpcUrl);
    const publicClient = createPublicClient({transport});
    const id = Number(await publicClient.getChainId());
    const chain: Chain = {
        id,
        name: `clpr-${id}`,
        nativeCurrency: {name: "Ether", symbol: "ETH", decimals: 18},
        rpcUrls: {default: {http: [opts.rpcUrl]}},
        // viem derives EIP-1559 fees from eth_feeHistory, which some relays (e.g. the Hiero
        // JSON-RPC relay) answer with values far below the network's enforced minimum, so the
        // tx is rejected ("Gas price '130' is below configured minimum gas price"). Floor both
        // fee fields at eth_gasPrice, which such relays report as that minimum.
        fees: {
            async estimateFeesPerGas({type}) {
                const gasPrice = await publicClient.getGasPrice();
                if (type === "legacy") return {gasPrice} as never;
                const est = await publicClient.estimateFeesPerGas().catch(() => undefined);
                const maxPriorityFeePerGas =
                    est && est.maxPriorityFeePerGas > gasPrice ? est.maxPriorityFeePerGas : gasPrice;
                const maxFeePerGas = est && est.maxFeePerGas > gasPrice ? est.maxFeePerGas : gasPrice;
                return {
                    maxFeePerGas: maxFeePerGas > maxPriorityFeePerGas ? maxFeePerGas : maxPriorityFeePerGas,
                    maxPriorityFeePerGas
                } as never;
            }
        }
    };
    const walletClient = createWalletClient({account, chain, transport});
    return {chain, account, publicClient, walletClient};
}
