import type {Hex} from "viem";
import {loadArtifact} from "../../../script/deploy/artifacts.js";
import type {ChainClients} from "../lib/clients.js";
import type {BackendKind} from "../backend/Backend.js";
import {encodeBundle, ChannelStatus, type QueueMetadata} from "./encodeBundle.js";
import {buildHieroProof} from "./buildHieroProof.js";
import {buildQbftProof} from "./buildQbftProof.js";

export interface FerryRange {
    fromId: bigint;
    throughId: bigint;
}

export interface FerryResult {
    bundleBytes: Hex;
    submittedTxHash: Hex;
    payloadCount: number;
}

export {ChannelStatus, type QueueMetadata};

/// Shared orchestration: read payloads, build bundle, submit, diagnose reverts.
async function ferryCore(opts: {
    source: ChainClients;
    dest: ChainClients;
    sourceClprService: Hex;
    destClprService: Hex;
    channelId: Hex;
    range: FerryRange;
    buildBundle: (payloads: Hex[]) => Promise<Hex>;
    label: string;
    gas?: bigint;
}): Promise<FerryResult> {
    const {source, dest, channelId, range} = opts;
    const service = loadArtifact("ClprService");

    const payloads: Hex[] = [];
    for (let id = range.fromId; id <= range.throughId; id++) {
        const m = (await source.publicClient.readContract({
            address: opts.sourceClprService,
            abi: service.abi as never,
            functionName: "getMessage",
            args: [channelId, id]
        })) as {payload: Hex};
        if (!m.payload || m.payload === "0x") {
            throw new Error(`${opts.label}: source.getMessage(${channelId}, ${id}) returned empty payload`);
        }
        payloads.push(m.payload);
    }

    const bundleBytes = await opts.buildBundle(payloads);

    const submittedTxHash = await dest.walletClient.writeContract({
        address: opts.destClprService,
        abi: service.abi as never,
        functionName: "submitBundle",
        args: [channelId, bundleBytes],
        gas: opts.gas ?? 5_000_000n
    });
    const receipt = await dest.publicClient.waitForTransactionReceipt({hash: submittedTxHash});
    if (receipt.status !== "success") {
        try {
            await dest.publicClient.simulateContract({
                address: opts.destClprService,
                abi: service.abi as never,
                functionName: "submitBundle",
                args: [channelId, bundleBytes],
                account: dest.account
            });
        } catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            throw new Error(`${opts.label}: submitBundle reverted on dest (tx ${submittedTxHash}).\n${msg}`);
        }
        throw new Error(`${opts.label}: submitBundle reverted on dest (tx ${submittedTxHash}) but simulate did not.`);
    }

    return {bundleBytes, submittedTxHash, payloadCount: payloads.length};
}

/// Route ferry to the proof builder matching the source chain kind.
export async function ferry(opts: {
    source: ChainClients;
    dest: ChainClients;
    sourceAddrs: {clprService: Hex; bundleEncoder: Hex};
    destAddrs: {clprService: Hex};
    channelId: Hex;
    range: FerryRange;
    sourceKind?: BackendKind;
    trustAnchor?: Hex;
}): Promise<FerryResult> {
    const sourceKind = opts.sourceKind ?? "anvil";

    if (sourceKind === "besu") {
        return ferryQbft({
            source: opts.source,
            dest: opts.dest,
            sourceAddrs: opts.sourceAddrs,
            destAddrs: opts.destAddrs,
            channelId: opts.channelId,
            range: opts.range
        });
    }

    if (sourceKind === "solo") {
        if (!opts.trustAnchor) throw new Error("ferry: trustAnchor (ledgerId) required for solo source");
        return ferryHiero({
            source: opts.source,
            dest: opts.dest,
            sourceAddrs: opts.sourceAddrs,
            destAddrs: opts.destAddrs,
            channelId: opts.channelId,
            range: opts.range,
            trustAnchor: opts.trustAnchor
        });
    }
    
    return ferryStub(opts);
}

async function ferryStub(opts: {
    source: ChainClients;
    dest: ChainClients;
    sourceAddrs: {clprService: Hex; bundleEncoder: Hex};
    destAddrs: {clprService: Hex};
    channelId: Hex;
    range: FerryRange;
}): Promise<FerryResult> {
    const {source, sourceAddrs, channelId} = opts;
    const service = loadArtifact("ClprService");

    const conn = (await source.publicClient.readContract({
        address: sourceAddrs.clprService,
        abi: service.abi as never,
        functionName: "getChannel",
        args: [channelId]
    })) as {
        nextMessageId: bigint;
        receivedMessageId: bigint;
        sentRunningHash: Hex;
        receivedRunningHash: Hex;
        status: number;
        endpointManifestVersion: bigint;
    };

    const metadata: QueueMetadata = {
        nextMessageId: conn.nextMessageId,
        sentRunningHash: conn.sentRunningHash,
        receivedMessageId: conn.receivedMessageId,
        receivedRunningHash: conn.receivedRunningHash,
        state: conn.status,
        endpointManifestVersion: conn.endpointManifestVersion
    };

    return ferryCore({
        ...opts,
        sourceClprService: sourceAddrs.clprService,
        destClprService: opts.destAddrs.clprService,
        label: "ferry",
        buildBundle: (payloads) => encodeBundle({
            clients: source,
            bundleEncoderAddr: sourceAddrs.bundleEncoder,
            metadata,
            payloads
        })
    });
}

/// QBFT verifier ferry. Builds a full EVM state proof for QBFTVerifier.verifyBundle.
export async function ferryQbft(opts: {
    source: ChainClients;
    dest: ChainClients;
    sourceAddrs: {clprService: Hex};
    destAddrs: {clprService: Hex};
    channelId: Hex;
    range: FerryRange;
}): Promise<FerryResult> {
    const rpcUrl = opts.source.chain.rpcUrls.default.http[0];
    if (!rpcUrl) throw new Error("ferryQbft: missing source RPC URL");

    const service = loadArtifact("ClprService");
    const conn = (await opts.source.publicClient.readContract({
        address: opts.sourceAddrs.clprService,
        abi: service.abi as never,
        functionName: "getChannel",
        args: [opts.channelId]
    })) as {nextMessageId: bigint};

    return ferryCore({
        ...opts,
        sourceClprService: opts.sourceAddrs.clprService,
        destClprService: opts.destAddrs.clprService,
        label: "ferryQbft",
        buildBundle: (payloads) => buildQbftProof({
            rpcUrl,
            serviceAddr: opts.sourceAddrs.clprService,
            channelId: opts.channelId,
            payloads,
            lastMessageId: conn.nextMessageId - 1n
        }).then((r) => r.proofBytes)
    });
}

/// Hiero verifier ferry. Builds TSS StateProof from Solo EVM storage via block node.
export async function ferryHiero(opts: {
    source: ChainClients;
    dest: ChainClients;
    sourceAddrs: {clprService: Hex};
    destAddrs: {clprService: Hex};
    channelId: Hex;
    range: FerryRange;
    trustAnchor: Hex;
}): Promise<FerryResult> {
    return ferryCore({
        ...opts,
        sourceClprService: opts.sourceAddrs.clprService,
        destClprService: opts.destAddrs.clprService,
        label: "ferryHiero",
        gas: 16_777_216n,
        buildBundle: () => buildHieroProof({
            source: opts.source,
            serviceAddr: opts.sourceAddrs.clprService,
            channelId: opts.channelId,
            range: opts.range,
            trustAnchor: opts.trustAnchor
        }).then((r) => r.proofBytes)
    });
}
