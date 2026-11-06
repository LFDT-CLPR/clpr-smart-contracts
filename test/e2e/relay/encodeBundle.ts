import type {Hex} from "viem";
import {loadArtifact} from "../../../script/deploy/artifacts.js";
import type {ChainClients} from "../lib/clients.js";

/// Mirrors Solidity's ClprTypes.ChannelStatus enum.
export const ChannelStatus = {
    PENDING: 0,
    ACTIVE: 1,
    PAUSED: 2,
    CLOSING: 3,
    DRAINED: 4,
    CLOSED: 5
} as const;

export interface QueueMetadata {
    nextMessageId: bigint;
    sentRunningHash: Hex;        // bytes32
    receivedMessageId: bigint;
    receivedRunningHash: Hex;    // bytes32
    state: number;               // ClprTypes.ChannelStatus
    endpointManifestVersion: bigint; // source Channel.endpointManifestVersion (proto field 7)
    lastMessageId: bigint;       // id of the bundle's last message; 0 when the bundle carries no messages
    lastMessageRunningHash: Hex; // bytes32; sender's running hash after lastMessageId, zero when empty
}

/// Build the bundle protobuf bytes by asking the chain to encode them.
///
/// This sidesteps the need to reimplement Solidity's protobuf encoder in TS —
/// the encoder body already lives on-chain in BundleEncoderHelper (which
/// inlines `ClprProtobuf.encodeBundleContent`). One `eth_call` returns the
/// canonical bytes that StubBundleContentVerifier / E2EVerifier will decode
/// on the receiving side, byte-for-byte the same as if a real prover had
/// emitted them.
export async function encodeBundle(opts: {
    clients: ChainClients;
    bundleEncoderAddr: Hex;
    metadata: QueueMetadata;
    payloads: Hex[];
}): Promise<Hex> {
    const helper = loadArtifact("BundleEncoderHelper");
    return (await opts.clients.publicClient.readContract({
        address: opts.bundleEncoderAddr,
        abi: helper.abi as never,
        functionName: "encode",
        args: [opts.metadata, opts.payloads]
    })) as Hex;
}
