import {type Hex, keccak256, toHex} from "viem";
import {bigintToTrimmedBuf, hexToBuf} from "../lib/rlp.js";
import {pbBytes, pbInt, pbLen, pbStr} from "../lib/proto.js";
import {deriveChannelSlots} from "./buildEthMainnetProof.js";

/// Shared helpers for the signer-replay and Kaia live-fixture builders: JSON-RPC with retries,
/// the CLPR config/channel encodings and the eth_getProof → bundle-item conversion.

export interface RpcProof {
    accountProof: Hex[];
    codeHash: Hex;
    storageHash: Hex;
    storageProof: {key: Hex; value: Hex; proof: Hex[]}[];
}

export async function rpcCall<T>(url: string, method: string, params: unknown[], insecureTls = false): Promise<T> {
    const prev = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    if (insecureTls) process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    try {
        const r = await fetch(url, {
            method: "POST",
            headers: {"content-type": "application/json"},
            body: JSON.stringify({jsonrpc: "2.0", id: 1, method, params}),
            signal: AbortSignal.timeout(30_000)
        });
        const j = (await r.json()) as {result?: T; error?: unknown};
        if (j.error !== undefined || j.result === undefined || j.result === null) {
            throw new Error(`${url} ${method}: ${JSON.stringify(j.error ?? "null result")}`);
        }
        return j.result;
    } finally {
        if (insecureTls) {
            if (prev === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
            else process.env.NODE_TLS_REJECT_UNAUTHORIZED = prev;
        }
    }
}

export async function anyRpc<T>(rpcs: string[], method: string, params: unknown[], insecureTls = false, tries = 3): Promise<T> {
    let last: unknown;
    for (let t = 0; t < tries; t++) {
        for (const u of rpcs) {
            try {
                return await rpcCall<T>(u, method, params, insecureTls);
            } catch (e) {
                last = e;
            }
        }
        await new Promise((r) => setTimeout(r, 1000));
    }
    throw last;
}

export const hexNum = (n: bigint): Hex => `0x${n.toString(16)}` as Hex;

/// `ClprMessagePayload{control{config_update{configuration}}}` as ClprProtobuf.encodeControlMessage.
export function ledgerConfigPayload(chainId: bigint, serviceAddress: Hex): Buffer {
    const throttles = Buffer.concat([pbInt(1, 100n), pbInt(2, 10_000n), pbInt(3, 1_000_000n), pbInt(4, 1000n),
        pbInt(5, 1_000_000n), pbInt(6, 8n), pbInt(7, 8n)]);
    const config = Buffer.concat([
        pbInt(1, 1n), pbStr(2, `eip155:${chainId}`), pbBytes(3, serviceAddress),
        pbLen(4, pbInt(1, 1_760_000_000n)), pbLen(5, throttles)
    ]);
    return pbLen(3, pbLen(1, pbLen(1, config)));
}

/// ClprTypes.encodeChannelContext = abi.encodePacked(channelId, remoteServiceAddress).
export function encodeChannelContext(channelId: Hex, service: Hex): Hex {
    return (channelId + service.slice(2).toLowerCase()) as Hex;
}

export function liveChannelId(tag: string): Hex {
    return keccak256(toHex(`clpr/${tag}/live`));
}

/// The five channelId-derived Channel slots, in the order the verifier proves them.
export function channelSlots(channelId: Hex): Hex[] {
    return deriveChannelSlots(channelId);
}

/// eth_getProof → [accountProofNodes, storageProof entries [slot32, nodes]].
export function proofItems(p: RpcProof, slots: Hex[]): {accountProof: Buffer[]; storageProof: [Buffer, Buffer[]][]} {
    const accountProof = p.accountProof.map(hexToBuf);
    const storageProof = slots.map((slot) => {
        const e = p.storageProof.find((s) => BigInt(s.key) === BigInt(slot));
        if (!e) throw new Error(`eth_getProof is missing slot ${slot}`);
        return [hexToBuf(slot), e.proof.map(hexToBuf)] as [Buffer, Buffer[]];
    });
    return {accountProof, storageProof};
}

export const u64 = (n: bigint): Buffer => bigintToTrimmedBuf(n);
