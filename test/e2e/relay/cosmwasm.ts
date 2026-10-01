/**
 * cosmwasm.ts — CometBFT + wasmd → CosmWasmVerifier proof encoding (src/verifiers/evm/provenance).
 *
 *   CosmWasmProof     { 1 bundle_content, 2 header: HeaderRef, repeated 3 hop: HeaderRef,
 *                       4 multistore CommitmentProof (store "wasm"), 5 entry: StorageProofEntry,
 *                       6 service_entry: StorageProofEntry, 7 manifest_preimage, 8 ledger_configuration }
 *   HeaderRef         { 1 validator_set, 2 signed_header }   inline, checked in the same call
 *                   | { 3 header_hash }                     accumulated earlier in CometBftCommitAccumulator
 *   StorageProofEntry { 1 key, 2 value (empty if absent), 3 IAVL CommitmentProof }
 *
 * Store layout (verified 2026-10-01 against provenance v1.30.0 → provenance-io/wasmd v0.61.10-pio-2
 * x/wasm/types/keys.go and cosmwasm-std 3.0.4 storage_keys/length_prefixed.rs):
 *   contract storage  = store "wasm", key 0x03 ‖ contract canonical address ‖ contract key
 *   cw-storage-plus   Item(ns)    → key ns
 *                     Map(ns)[k]  → key u16be(len ns) ‖ ns ‖ k
 */

import {bech32} from "@scure/base";
import {pbLen} from "../lib/proto.js";
import {encodeValidatorSet, type AbciStoreProof, type LiveValidator} from "./cometbft.js";

export const WASM_STORE = "wasm";
export const CONTRACT_STORE_PREFIX = 0x03;
export const QUEUE_NAMESPACE = "clpr_queue";
export const SERVICE_ITEM = "clpr_service";

/** bech32 contract address (pb1…) → canonical bytes (20 or 32). */
export function canonicalAddress(bech: string): Buffer {
    return Buffer.from(bech32.fromWords(bech32.decode(bech as `${string}1${string}`, 200).words));
}

/** cw-storage-plus Map key: u16be(len(ns)) ‖ ns ‖ key. */
export function mapKey(namespace: string, key: Buffer): Buffer {
    const ns = Buffer.from(namespace, "utf8");
    const len = Buffer.alloc(2);
    len.writeUInt16BE(ns.length);
    return Buffer.concat([len, ns, key]);
}

/** Full wasm-store key of a contract's own storage key. */
export function contractStoreKey(contract: Buffer, key: Buffer): Buffer {
    return Buffer.concat([Buffer.from([CONTRACT_STORE_PREFIX]), contract, key]);
}

export const queueRecordKey = (service: Buffer, channelId: Buffer): Buffer => contractStoreKey(service, mapKey(QUEUE_NAMESPACE, channelId));
export const serviceItemKey = (service: Buffer): Buffer => contractStoreKey(service, Buffer.from(SERVICE_ITEM, "utf8"));

/** 90-byte queue record (README §4): version ‖ status ‖ next ‖ received ‖ manifestVersion ‖ sent ‖ received hash. */
export function encodeQueueRecord(r: {status: number; next: bigint; received: bigint; manifestVersion: bigint; sentHash: Buffer; receivedHash: Buffer}): Buffer {
    const u64 = (v: bigint) => {
        const b = Buffer.alloc(8);
        b.writeBigUInt64BE(v);
        return b;
    };
    return Buffer.concat([Buffer.from([1, r.status]), u64(r.next), u64(r.received), u64(r.manifestVersion), r.sentHash, r.receivedHash]);
}

export function encodeEntry(p: AbciStoreProof): Buffer {
    return Buffer.concat([pbLen(1, p.key), p.value.length ? pbLen(2, p.value) : Buffer.alloc(0), pbLen(3, p.iavlProof)]);
}

export const inlineHeaderRef = (vals: LiveValidator[], signedHeader: Buffer): Buffer =>
    Buffer.concat([pbLen(1, encodeValidatorSet(vals)), pbLen(2, signedHeader)]);
export const hashHeaderRef = (headerHash: Buffer): Buffer => pbLen(3, headerHash);

export interface CosmWasmProofParts {
    bundleContent?: Buffer;
    header: Buffer;
    hops?: Buffer[];
    multistoreProof: Buffer;
    entry: Buffer;
    serviceEntry?: Buffer;
    manifestPreimage?: Buffer;
    ledgerConfiguration?: Buffer;
}

export function encodeCosmWasmProof(p: CosmWasmProofParts): Buffer {
    const opt = (f: number, b?: Buffer) => (b && b.length ? pbLen(f, b) : Buffer.alloc(0));
    return Buffer.concat([
        opt(1, p.bundleContent),
        pbLen(2, p.header),
        ...(p.hops ?? []).map((h) => pbLen(3, h)),
        pbLen(4, p.multistoreProof),
        pbLen(5, p.entry),
        opt(6, p.serviceEntry),
        opt(7, p.manifestPreimage),
        opt(8, p.ledgerConfiguration)
    ]);
}
