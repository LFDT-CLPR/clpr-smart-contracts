import {
    createPublicClient,
    encodeFunctionData,
    http,
    type Chain,
    type Hex,
    type PublicClient
} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {loadArtifact} from "../../../script/deploy/artifacts.js";
import {buildEthLiveProof, loadLiveCapture, type EthLiveProof} from "../relay/buildEthLiveProof.js";

/// Deploy `EthMainnetVerifier` to a Hiero network through its JSON-RPC relay and submit
/// `verifyBundle` for the recorded live Sepolia bundle as a real EthereumTransaction, so the gas
/// is what Hiero consensus charged, not a simulation.
///
/// Hiero specifics this measures:
///   - Standard Hiero transactions are capped at `hedera.transaction.maxBytes` (6144 B). The
///     verifyBundle calldata is ~19 KB and the verifier init code ~19 KB, so both only fit as
///     HIP-1086 jumbo EthereumTransactions (`jumboTransactions.maxTxnSize`, 130 KB), or via the
///     relay's legacy HFS path (FileCreate + FileAppend, calldata referenced by file id).
///   - Hiero charges at least 80% of the gas limit (HIP-185), so the limit is set close to the
///     estimate to keep the charged gas near the gas actually used.

/// Recorded Sepolia bundle size is 19 140 B of calldata; everything below the standard Hiero
/// transaction limit would not need the jumbo path.
export const HIERO_STANDARD_TX_MAX_BYTES = 6144;

export interface MirrorContractResult {
    gas_used?: number;
    gas_limit?: number;
    gas_consumed?: number;
    result?: string;
    status?: string;
    error_message?: string | null;
    timestamp?: string;
    from?: string;
    contract_id?: string;
    address?: string;
}

export interface MirrorTransaction {
    transaction_id: string;
    name: string;
    result: string;
    charged_tx_fee: number;
    consensus_timestamp: string;
}

export interface HieroTxMeasurement {
    hash: Hex;
    /// Gas limit we signed.
    gasLimit: bigint;
    /// `eth_estimateGas` from the relay (Mirror Node web3 simulation).
    estimate?: bigint;
    /// Receipt gasUsed (what Hiero charged for gas: max(used, 80% of limit)).
    receiptGasUsed: bigint;
    /// Mirror `gas_consumed`: gas the EVM actually consumed, when reported.
    gasConsumed?: number;
    /// Weibar per gas, from the receipt.
    effectiveGasPrice: bigint;
    /// Full transaction fee charged to the payer (tinybar), from the mirror node.
    chargedTinybar?: number;
    /// Hiero transaction type recorded by consensus (expected ETHEREUMTRANSACTION).
    hieroTxName?: string;
    hieroTxId?: string;
    /// Signed RLP transaction size and calldata size, in bytes.
    rawTxBytes: number;
    callDataBytes: number;
    /// FileCreate/FileAppend transactions the relay operator paid just before this one (HFS path).
    relayFileTxs: string[];
    status: "success" | "reverted";
    /// Mirror `error_message` for reverted transactions.
    error?: string;
}

export interface EthVerifierOnHieroReport {
    network: string;
    chainId: number;
    relay: string;
    mirror: string;
    verifier: Hex;
    deploy?: HieroTxMeasurement;
    verify: HieroTxMeasurement;
    /// eth_call of verifyBundle succeeded and returned the expected (zeroed) queue metadata.
    ethCallOk: boolean;
    /// EIP-2537 BLS12-381 precompiles answer (probe: G1ADD of two points at infinity at 0x0b).
    /// The sync-committee check needs them; Hiero consensus v0.74 (EVM v0.67) lacks them.
    eip2537: boolean;
    tinybarPerHbar: 100_000_000;
    measuredAt: string;
}

function sleep(ms: number) {
    return new Promise((r) => setTimeout(r, ms));
}

async function mirrorGet<T>(mirror: string, pathAndQuery: string, attempts = 30): Promise<T> {
    const url = `${mirror.replace(/\/$/, "")}${pathAndQuery}`;
    let last = "";
    for (let i = 0; i < attempts; i++) {
        const res = await fetch(url);
        if (res.ok) return (await res.json()) as T;
        last = `${res.status} ${await res.text()}`;
        await sleep(2_000);
    }
    throw new Error(`mirror GET ${url} failed: ${last}`);
}

/// Resolve consensus-side facts for an EVM tx hash from the mirror node.
async function mirrorFacts(mirror: string, hash: Hex): Promise<{
    result: MirrorContractResult;
    tx?: MirrorTransaction;
    relayFileTxs: string[];
}> {
    const result = await mirrorGet<MirrorContractResult>(mirror, `/api/v1/contracts/results/${hash}`);
    let tx: MirrorTransaction | undefined;
    const relayFileTxs: string[] = [];
    if (result.timestamp) {
        const txs = await mirrorGet<{transactions: MirrorTransaction[]}>(
            mirror,
            `/api/v1/transactions?timestamp=${result.timestamp}`
        );
        tx = txs.transactions.find((t) => t.name === "ETHEREUMTRANSACTION") ?? txs.transactions[0];
        if (tx) {
            // Payer of the EthereumTransaction is the relay operator. With HFS the relay first pays a
            // FileCreate (+ FileAppends) holding the calldata; look for those in the 3 minutes before.
            const payer = tx.transaction_id.split("-")[0];
            const [sec] = result.timestamp.split(".");
            const from = `${Number(sec) - 180}.000000000`;
            for (const type of ["FILECREATE", "FILEAPPEND"]) {
                const r = await mirrorGet<{transactions: MirrorTransaction[]}>(
                    mirror,
                    `/api/v1/transactions?account.id=${payer}&transactiontype=${type}` +
                    `&timestamp=gte:${from}&timestamp=lt:${result.timestamp}&limit=25`
                );
                for (const t of r.transactions) relayFileTxs.push(`${t.name} ${t.transaction_id}`);
            }
        }
    }
    return {result, tx, relayFileTxs};
}

export interface HieroTarget {
    network: string;
    rpcUrl: string;
    mirrorUrl: string;
    privateKey: Hex;
}

function makeClients(t: HieroTarget, chainId: number) {
    const chain: Chain = {
        id: chainId,
        name: t.network,
        nativeCurrency: {name: "HBAR", symbol: "HBAR", decimals: 18},
        rpcUrls: {default: {http: [t.rpcUrl]}}
    };
    const account = privateKeyToAccount(t.privateKey);
    const transport = http(t.rpcUrl, {timeout: 120_000});
    const pub = createPublicClient({chain, transport, pollingInterval: 1_000}) as PublicClient;
    return {chain, account, pub};
}

/// Headroom over the relay's estimate. Hiero charges >= 80% of the limit, so keep this small.
const GAS_HEADROOM_PCT = 115n;

async function sendMeasured(opts: {
    t: HieroTarget;
    chainId: number;
    to?: Hex;
    data: Hex;
    gasOverride?: bigint;
    log: (s: string) => void;
}): Promise<HieroTxMeasurement> {
    const {pub, account} = makeClients(opts.t, opts.chainId);
    const gasPrice = await pub.getGasPrice();

    let estimate: bigint | undefined;
    try {
        estimate = await pub.estimateGas({account: account.address, to: opts.to, data: opts.data});
    } catch (err) {
        opts.log(`eth_estimateGas failed: ${String(err instanceof Error ? err.message : err).split("\n")[0]}`);
    }
    const gasLimit = opts.gasOverride ?? (estimate ? (estimate * GAS_HEADROOM_PCT) / 100n : 3_000_000n);
    const nonce = await pub.getTransactionCount({address: account.address, blockTag: "pending"});

    const request = {
        chainId: opts.chainId,
        type: "legacy" as const,
        to: opts.to ?? null,
        data: opts.data,
        gas: gasLimit,
        gasPrice,
        nonce,
        value: 0n
    };
    const signed = await account.signTransaction(request as never);
    const rawTxBytes = (signed.length - 2) / 2;

    opts.log(`sending ${opts.to ? "call" : "create"}: calldata ${(opts.data.length - 2) / 2} B, ` +
        `raw tx ${rawTxBytes} B, gas limit ${gasLimit} (estimate ${estimate ?? "n/a"})`);
    const hash = await pub.sendRawTransaction({serializedTransaction: signed});
    const receipt = await pub.waitForTransactionReceipt({hash, timeout: 300_000});

    const facts = await mirrorFacts(opts.t.mirrorUrl, hash);
    return {
        hash,
        gasLimit,
        estimate,
        receiptGasUsed: receipt.gasUsed,
        gasConsumed: facts.result.gas_consumed,
        effectiveGasPrice: receipt.effectiveGasPrice,
        chargedTinybar: facts.tx?.charged_tx_fee,
        hieroTxName: facts.tx?.name,
        hieroTxId: facts.tx?.transaction_id,
        rawTxBytes,
        callDataBytes: (opts.data.length - 2) / 2,
        relayFileTxs: facts.relayFileTxs,
        status: receipt.status,
        error: facts.result.error_message ?? undefined
    };
}

/// G1ADD(inf, inf) must return 128 zero bytes where EIP-2537 is live; elsewhere the call
/// returns empty data or fails.
export async function probeEip2537(pub: {call: PublicClient["call"]}): Promise<boolean> {
    try {
        const r = await pub.call({
            to: "0x000000000000000000000000000000000000000b",
            data: `0x${"00".repeat(256)}`,
            gas: 1_000_000n
        });
        return (r.data?.length ?? 0) === 2 + 256;
    } catch {
        return false;
    }
}

/// Run the measurement. Pass `verifier` to reuse an existing deployment (no deploy tx).
export async function measureEthVerifierOnHiero(opts: {
    target: HieroTarget;
    verifier?: Hex;
    live?: EthLiveProof;
    log?: (s: string) => void;
}): Promise<EthVerifierOnHieroReport> {
    const log = opts.log ?? ((s: string) => console.log(`[eth-on-hiero:${opts.target.network}] ${s}`));
    const probe = createPublicClient({transport: http(opts.target.rpcUrl, {timeout: 120_000})});
    const chainId = Number(await probe.getChainId());
    const live = opts.live ?? buildEthLiveProof(loadLiveCapture());
    const art = loadArtifact("EthMainnetVerifier");

    let deploy: HieroTxMeasurement | undefined;
    let verifier = opts.verifier;
    if (!verifier) {
        deploy = await sendMeasured({
            t: opts.target,
            chainId,
            data: art.bytecode,
            log
        });
        if (deploy.status !== "success") throw new Error(`EthMainnetVerifier deploy reverted (${deploy.hash})`);
        const r = await probe.getTransactionReceipt({hash: deploy.hash});
        if (!r.contractAddress) throw new Error(`deploy ${deploy.hash} returned no contract address`);
        verifier = r.contractAddress;
        log(`EthMainnetVerifier deployed at ${verifier} (${deploy.hash})`);
    }

    const args = [live.proofBytes, live.trustAnchor, live.channelContext] as const;
    const data = encodeFunctionData({abi: art.abi, functionName: "verifyBundle", args} as never);

    // eth_call first: proves the verifier accepts the real bundle on Hiero's EVM (BLS12-381
    // precompiles, SHA-256, keccak MPT) before we pay for a transaction.
    let ethCallOk = false;
    try {
        const out = (await probe.readContract({
            address: verifier,
            abi: art.abi as never,
            functionName: "verifyBundle",
            args: args as never
        })) as [{nextMessageId: bigint}, Hex[]];
        ethCallOk = out[0].nextMessageId === 0n && out[1].length === 0;
        log(`eth_call verifyBundle ok (nextMessageId=${out[0].nextMessageId}, payloads=${out[1].length})`);
    } catch (err) {
        log(`eth_call verifyBundle FAILED: ${String(err instanceof Error ? err.message : err).split("\n").slice(0, 3).join(" | ")}`);
    }

    const eip2537 = await probeEip2537(probe);
    log(`EIP-2537 BLS12-381 precompiles: ${eip2537 ? "present" : "ABSENT"}`);

    const verify = await sendMeasured({t: opts.target, chainId, to: verifier, data, log});
    return {
        network: opts.target.network,
        chainId,
        relay: opts.target.rpcUrl,
        mirror: opts.target.mirrorUrl,
        verifier,
        deploy,
        verify,
        ethCallOk,
        eip2537,
        tinybarPerHbar: 100_000_000,
        measuredAt: new Date().toISOString()
    };
}

export function formatMeasurement(label: string, m: HieroTxMeasurement): string {
    const hbar = m.chargedTinybar !== undefined ? (m.chargedTinybar / 1e8).toFixed(4) : "?";
    return `${label}: status=${m.status} gasUsed(receipt)=${m.receiptGasUsed} gasConsumed=${m.gasConsumed ?? "?"} ` +
        `limit=${m.gasLimit} estimate=${m.estimate ?? "?"} fee=${hbar} HBAR (${m.chargedTinybar ?? "?"} tinybar) ` +
        `hieroTx=${m.hieroTxName ?? "?"} ${m.hieroTxId ?? ""} calldata=${m.callDataBytes} B raw=${m.rawTxBytes} B ` +
        `hfs=${m.relayFileTxs.length ? m.relayFileTxs.join(",") : "none"}`;
}
