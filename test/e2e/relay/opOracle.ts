import {encodeAbiParameters, keccak256, type Hex} from "viem";
import {rlpEncode, hexToBuf, bigintToTrimmedBuf} from "../lib/rlp.js";
import type {EthGetProofResult} from "./buildEthMainnetProof.js";
import {EIP1967_IMPLEMENTATION_SLOT, slotHex} from "./opstack.js";

/// Encoders for the output-oracle verifiers (`OpOutputOracleVerifier` / `OpOutputOracleProposedVerifier`):
/// the oracle proof (`OpOutputOracleProof.verify`) and the bundle. Every slot mirrors how the contract
/// derives it (`OpOutputOracleProof.slotsFor`) — the proof never names its own slots.

/// `OpOutputOracleProof.PeriodSource`.
export const PERIOD_SOURCE = {IMMUTABLE: 0, STORAGE: 1} as const;

/// `OpOutputOracleProof.Profile`.
export interface OracleProfile {
    oracle: Hex;
    oracleImplCodeHash: Hex;
    outputsSlot: bigint;
    periodSource: number;
    finalizationPeriodSeconds: bigint;
    finalizationPeriodSlot: bigint;
    hasOptimisticMode: boolean;
    optimisticModeSlot: bigint;
    optimisticModeOffset: bigint;
}

/// `OpOutputOracleVerifierBase.L2AccountFormat`.
export interface L2AccountFormat {
    fields: bigint;
    storageRootIndex: bigint;
    codeHashIndex: bigint;
}

/// Ethereum's `[nonce, balance, storageRoot, codeHash]`.
export const ETH_ACCOUNT: L2AccountFormat = {fields: 4n, storageRootIndex: 2n, codeHashIndex: 3n};
/// blast-geth `types.StateAccount`: `[nonce, flags, fixed, shares, remainder, storageRoot, codeHash]`.
export const BLAST_ACCOUNT: L2AccountFormat = {fields: 7n, storageRootIndex: 5n, codeHashIndex: 6n};

/// Storage slot of `l2Outputs[index]` (2 slots per `OutputProposal`; +1 holds timestamp | l2BlockNumber).
export function outputElementSlot(outputsSlot: bigint, index: bigint): bigint {
    const base = BigInt(keccak256(encodeAbiParameters([{type: "uint256"}], [outputsSlot])));
    return (base + 2n * index) & ((1n << 256n) - 1n);
}

/// `OpOutputOracleProof.slotsFor`: `[length, implementation, outputRoot, timestamp|l2BlockNumber,
/// (period), (optimisticMode)]`.
export function oracleSlots(p: OracleProfile, index: bigint): Hex[] {
    const e = outputElementSlot(p.outputsSlot, index);
    return [
        slotHex(p.outputsSlot),
        EIP1967_IMPLEMENTATION_SLOT,
        slotHex(e),
        slotHex(e + 1n),
        ...(p.periodSource === PERIOD_SOURCE.STORAGE ? [slotHex(p.finalizationPeriodSlot)] : []),
        ...(p.hasOptimisticMode ? [slotHex(p.optimisticModeSlot)] : [])
    ];
}

export interface OracleProofParts {
    outputIndex: bigint;
    oracleAccountProof: Buffer[];
    oracleStorageProof: unknown[];
    oracleImplAccountProof: Buffer[];
}

/// The oracle-proof RLP item (`OpOutputOracleProof` OP_IDX_* order).
export function oracleProofItem(p: OracleProofParts): unknown[] {
    return [bigintToTrimmedBuf(p.outputIndex), p.oracleAccountProof, p.oracleStorageProof, p.oracleImplAccountProof];
}

export function encodeOracleProof(p: OracleProofParts): Hex {
    return ("0x" + rlpEncode(oracleProofItem(p) as never).toString("hex")) as Hex;
}

export interface OracleBundleParts {
    lightClientProof: Hex;
    oracle: OracleProofParts;
    outputRootPreimage: Hex;
    l2AccountProof: Buffer[];
    l2StorageProof: unknown[];
    bundleContent: Hex;
}

/// Full `verifyBundle` proof (6-item shape).
export function encodeOracleBundle(p: OracleBundleParts): Hex {
    return ("0x" + rlpEncode([
        hexToBuf(p.lightClientProof),
        oracleProofItem(p.oracle) as never,
        hexToBuf(p.outputRootPreimage),
        p.l2AccountProof,
        p.l2StorageProof as never,
        hexToBuf(p.bundleContent)
    ]).toString("hex")) as Hex;
}

/// Items 0–2 only — the `verifyL2StateRoot` input.
export function encodeOracleL2StateRootProof(p: Pick<OracleBundleParts, "lightClientProof" | "oracle" | "outputRootPreimage">): Hex {
    return ("0x" + rlpEncode([
        hexToBuf(p.lightClientProof),
        oracleProofItem(p.oracle) as never,
        hexToBuf(p.outputRootPreimage)
    ]).toString("hex")) as Hex;
}

/// Read a proven slot value out of an `eth_getProof` result.
export function provenSlot(proof: EthGetProofResult, slot: bigint | Hex): bigint {
    const k = BigInt(slot);
    const sp = proof.storageProof.find((s) => BigInt(s.key) === k);
    if (!sp) throw new Error(`slot ${slotHex(k)} not in proof`);
    return BigInt(sp.value);
}
