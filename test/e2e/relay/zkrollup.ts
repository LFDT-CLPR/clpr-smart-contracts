import {encodeAbiParameters, keccak256, type Hex} from "viem";
import {bigintToTrimmedBuf, hexToBuf, rlpEncode} from "../lib/rlp.js";
import type {EthGetProofResult} from "./buildEthMainnetProof.js";

/// Shared encoders for the L1-settled rollup verifiers (`L1RollupMptVerifier`, `LineaRollupVerifier`):
/// the rollup proof (`L1RollupStateRoot.verify`) and the bundle. Every slot mirrors how the contract
/// derives it; the proof never names its own slots.

export const EIP1967_IMPLEMENTATION_SLOT: Hex = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

export type L2Trie = "mpt" | "linea";

/// `L1RollupStateRoot.Profile` plus the off-chain facts the relayer needs.
export interface L1RollupProfile {
    name: string;
    l2ChainId: number;
    trie: L2Trie;
    rollup: Hex;
    stateRootsSlot: bigint;
    implementation: Hex;
    minKey: bigint;
    /// What the mapping key is.
    keyKind: "l2-block" | "batch-index";
}

/// Values read from the verified implementation source (Blockscout) and checked against mainnet storage
/// on 2026-10-01 (see docs/chains/*.md for how each was derived).
export const LINEA_MAINNET: L1RollupProfile = {
    name: "linea",
    l2ChainId: 59144,
    trie: "linea",
    rollup: "0xd19d4B5d358258f05D7B411E21A1460D11B0876F",
    stateRootsSlot: 282n, // ZkEvmV2.stateRootHashes (currentL2BlockNumber is slot 281)
    implementation: "0x052b73d934e9412045bf731574463fd026d74645",
    minKey: 0n,
    keyKind: "l2-block"
};

export const SCROLL_MAINNET: L1RollupProfile = {
    name: "scroll",
    l2ChainId: 534352,
    trie: "mpt",
    rollup: "0xa13BAF47339d63B743e7Da8741db5456DAc1E556",
    stateRootsSlot: 158n, // ScrollChain.finalizedStateRoots
    implementation: "0x0a20703878e68e587c59204cc0ea86098b8c3ba7",
    minKey: 0n,
    keyKind: "batch-index"
};

export const MORPH_MAINNET: L1RollupProfile = {
    name: "morph",
    l2ChainId: 2818,
    trie: "mpt",
    rollup: "0x759894Ced0e6af42c26668076Ffa84d02E3CeF60",
    stateRootsSlot: 160n, // Rollup.finalizedStateRoots (committedStateRoots is slot 171)
    implementation: "0x213ce22b487b71ac68a1b5b12d2b93d1af30ea1d",
    minKey: 0n,
    keyKind: "batch-index"
};

export const PROFILES: Record<string, L1RollupProfile> = {
    linea: LINEA_MAINNET,
    scroll: SCROLL_MAINNET,
    morph: MORPH_MAINNET
};

export function slotHex(n: bigint): Hex {
    return ("0x" + (n & ((1n << 256n) - 1n)).toString(16).padStart(64, "0")) as Hex;
}

/// `mapping(uint256 => bytes32)` slot of `key`.
export function stateRootSlot(stateRootsSlot: bigint, key: bigint): Hex {
    return keccak256(encodeAbiParameters([{type: "uint256"}, {type: "uint256"}], [key, stateRootsSlot]));
}

/// The rollup-contract slots a rollup proof carries: the root of `key`, plus the EIP-1967 slot.
export function rollupSlots(p: L1RollupProfile, key: bigint): Hex[] {
    return [stateRootSlot(p.stateRootsSlot, key), EIP1967_IMPLEMENTATION_SLOT];
}

/// `[[slot32, proofNodes], …]` for the requested keys, from an `eth_getProof` result.
export function storageEntries(proof: EthGetProofResult, keys: Hex[]): unknown[] {
    const byKey = new Map(proof.storageProof.map((sp) => [BigInt(sp.key), sp]));
    return keys.map((k) => {
        const sp = byKey.get(BigInt(k));
        if (!sp) throw new Error(`missing storage proof for slot ${k}`);
        return [hexToBuf(slotHex(BigInt(k))), sp.proof.map(hexToBuf)];
    });
}

/// `L1RollupStateRoot` proof item: `[key, l1AccountProof, l1StorageProof]`.
export function rollupProofItem(key: bigint, rollupProof: EthGetProofResult, slots: Hex[]): unknown[] {
    return [bigintToTrimmedBuf(key), rollupProof.accountProof.map(hexToBuf), storageEntries(rollupProof, slots)];
}

/// `L1RollupStateRoot.Profile` tuple for deployment.
export function profileTuple(p: L1RollupProfile) {
    return {rollup: p.rollup, stateRootsSlot: p.stateRootsSlot, implementation: p.implementation, minKey: p.minKey};
}

export interface L1RollupBundleParts {
    lightClientProof: Hex;
    rollupProof: unknown[];
    /// MPT: list of nodes; Linea: ABI bytes.
    l2AccountProof: unknown;
    /// MPT: `[[slot, nodes], …]`; Linea: ABI bytes.
    l2StorageProof: unknown;
    bundleContent: Hex;
    manifest?: {storageProof: unknown; preimage: Hex};
}

export function encodeL1RollupBundle(p: L1RollupBundleParts): Hex {
    const items: unknown[] = [hexToBuf(p.lightClientProof), p.rollupProof, p.l2AccountProof, p.l2StorageProof,
        hexToBuf(p.bundleContent)];
    if (p.manifest) items.push(p.manifest.storageProof, hexToBuf(p.manifest.preimage));
    return ("0x" + rlpEncode(items as never).toString("hex")) as Hex;
}

/// `verifyL2StateRoot` input: `[lightClientProof, rollupProof]`.
export function encodeL2StateRootProof(lightClientProof: Hex, rollupProof: unknown[]): Hex {
    return ("0x" + rlpEncode([hexToBuf(lightClientProof), rollupProof] as never).toString("hex")) as Hex;
}
