/**
 * anvilHarness.ts — one local anvil, contract deploys from forge artifacts, view calls and gas /
 * calldata measurement against Hedera's limits. Used by the runtimes3 live replay specs
 * (initia-live, fuel-live, waves-live).
 */

import {spawn, type ChildProcess} from "node:child_process";
import {createPublicClient, createWalletClient, encodeFunctionData, http, type Hex, type PublicClient, type WalletClient} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {loadArtifact} from "../../../script/deploy/artifacts.js";

/** anvil's first default account (public test key, local chain only). */
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
export const HEDERA_GAS = 15_000_000n;
export const HEDERA_CALLDATA = 128 * 1024;

export interface Measured {
    gas: bigint;
    calldata: number;
}

export class AnvilHarness {
    private proc?: ChildProcess;
    pub!: PublicClient;
    wallet!: WalletClient;
    readonly addr: Record<string, Hex> = {};

    constructor(private readonly tag: string, private readonly port = Number(process.env.CLPR_ANVIL_PORT_A ?? 8641)) {}

    async start(): Promise<void> {
        this.proc = spawn("anvil", ["--port", String(this.port), "--silent", "--code-size-limit", "24576"], {stdio: "ignore"});
        const rpc = `http://127.0.0.1:${this.port}`;
        this.pub = createPublicClient({transport: http(rpc), pollingInterval: 100}) as PublicClient;
        const deadline = Date.now() + 15_000;
        for (;;) {
            try {
                await this.pub.getChainId();
                break;
            } catch (err) {
                if (Date.now() > deadline) throw err;
                await new Promise((r) => setTimeout(r, 200));
            }
        }
        this.wallet = createWalletClient({account: privateKeyToAccount(ANVIL_KEY), transport: http(rpc)});
    }

    stop(): void {
        this.proc?.kill("SIGTERM");
    }

    async deploy(name: string, args: unknown[] = [], as = name): Promise<Hex> {
        const art = loadArtifact(name);
        const hash = await this.wallet.deployContract({abi: art.abi as never, bytecode: art.bytecode, args: args as never,
            account: this.wallet.account!, chain: null});
        const r = await this.pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error(`deploy ${name}`);
        const code = await this.pub.getCode({address: r.contractAddress});
        console.log(`[${this.tag}] ${name} runtime ${(code!.length - 2) / 2} B`);
        this.addr[as] = r.contractAddress;
        return r.contractAddress;
    }

    async send(name: string, fn: string, args: unknown[], artifact = name): Promise<bigint> {
        const hash = await this.wallet.writeContract({address: this.addr[name], abi: loadArtifact(artifact).abi as never,
            functionName: fn as never, args: args as never, account: this.wallet.account!, chain: null});
        const r = await this.pub.waitForTransactionReceipt({hash});
        if (r.status !== "success") throw new Error(`${name}.${fn} reverted`);
        return r.gasUsed;
    }

    call(name: string, fn: string, args: unknown[], artifact = name): Promise<any> {
        return this.pub.readContract({address: this.addr[name], abi: loadArtifact(artifact).abi as never, functionName: fn,
            args: args as never});
    }

    /** eth_estimateGas and calldata size of a call; both must fit one Hedera transaction. */
    async measure(name: string, fn: string, args: unknown[], label: string, artifact = name): Promise<Measured> {
        const abi = loadArtifact(artifact).abi;
        const gas = await this.pub.estimateContractGas({address: this.addr[name], abi: abi as never, functionName: fn,
            args: args as never, account: this.wallet.account!});
        const calldata = (encodeFunctionData({abi, functionName: fn, args} as never).length - 2) / 2;
        console.log(`[${this.tag}] ${label}: eth_estimateGas ${gas}, calldata ${calldata} B`);
        if (gas >= HEDERA_GAS) throw new Error(`${label}: ${gas} gas exceeds 15M`);
        if (calldata >= HEDERA_CALLDATA) throw new Error(`${label}: ${calldata} B exceeds 128 KB`);
        return {gas, calldata};
    }
}
