import {spawn, type ChildProcess} from "node:child_process";
import {createPublicClient, createWalletClient, encodeFunctionData, http, type Hex, type PublicClient, type WalletClient} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {loadArtifact} from "../../../../../script/deploy/artifacts.js";

/// Anvil harness for the BLS-committee live specs: start a Prague anvil (EIP-2537), deploy one
/// contract, call a view function and measure gas/calldata as a top-level transaction.

const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"; // anvil default account 0

export interface Harness {
    anvil: ChildProcess;
    pub: PublicClient;
    wallet: WalletClient;
    address: Hex;
    abi: readonly unknown[];
}

export async function deploy(name: string, args: unknown[], port: number): Promise<Harness> {
    const art = loadArtifact(name);
    const anvil = spawn("anvil", ["--port", String(port), "--silent", "--hardfork", "prague"], {stdio: "ignore"});
    const rpc = `http://127.0.0.1:${port}`;
    const pub = createPublicClient({transport: http(rpc), pollingInterval: 100}) as PublicClient;
    const deadline = Date.now() + 15_000;
    for (;;) {
        try {
            await pub.getChainId();
            break;
        } catch (err) {
            if (Date.now() > deadline) throw err;
            await new Promise((r) => setTimeout(r, 200));
        }
    }
    const wallet = createWalletClient({account: privateKeyToAccount(ANVIL_KEY), transport: http(rpc)});
    const hash = await wallet.deployContract({abi: art.abi as never, bytecode: art.bytecode, args: args as never, account: wallet.account!, chain: null});
    const r = await pub.waitForTransactionReceipt({hash});
    if (!r.contractAddress) throw new Error(`${name} deploy failed`);
    return {anvil, pub, wallet, address: r.contractAddress, abi: art.abi};
}

export function read<T>(h: Harness, functionName: string, args: unknown[]): Promise<T> {
    return h.pub.readContract({address: h.address, abi: h.abi as never, functionName, args} as never) as Promise<T>;
}

/// eth_estimateGas of a top-level call (21k base + calldata + execution) and its calldata size:
/// what a Hedera EthereumTransaction carrying this call would need.
export async function measure(h: Harness, functionName: string, args: unknown[]): Promise<{gas: bigint; calldata: number}> {
    const gas = await h.pub.estimateContractGas({address: h.address, abi: h.abi as never, functionName, args, account: h.wallet.account!} as never);
    const cd = encodeFunctionData({abi: h.abi, functionName, args} as never);
    return {gas, calldata: (cd.length - 2) / 2};
}

export const HEDERA = {gasLimit: 15_000_000n, calldataLimit: 128 * 1024};
