import {encodeAbiParameters, keccak256, type Hex} from "viem";
import {rlpEncode, hexToBuf, bigintToTrimmedBuf} from "../lib/rlp.js";
import type {EthGetProofResult} from "./buildEthMainnetProof.js";

/// Shared encoders for the OP Stack verifier family (`OpStackVerifier` / `OpStackProposedVerifier`):
/// the L1 dispute proof (`OpStackOutputRootProof.verify`), the output-root preimage, and the bundle.
/// Every slot here mirrors how the contract derives it — the proof never names its own slots.

/// Storage layout profile (`OpStackOutputRootProof.Layout`). Values are the OP Stack contracts in use
/// on the Superchain today: AnchorStateRegistry 3.x, DisputeGameFactory 1.x, and the game's slot 0
/// (FaultDisputeGame and Base's AggregateVerifier both pack createdAt | resolvedAt | status there;
/// `wasRespectedGameTypeWhenCreated` sits at offset 18 in AggregateVerifier).
export interface OpStackLayout {
    asrDisputeGameFactorySlot: bigint;
    asrAnchorGameSlot: bigint;
    asrStartingAnchorRootSlot: bigint;
    asrBlacklistSlot: bigint;
    asrRespectedGameTypeSlot: bigint;
    asrRespectedGameTypeOffset: bigint;
    asrRetirementTimestampOffset: bigint;
    dgfGamesSlot: bigint;
    gameStateSlot: bigint;
    gameCreatedAtOffset: bigint;
    gameResolvedAtOffset: bigint;
    gameStatusOffset: bigint;
    gameWasRespectedSlot: bigint;
    gameWasRespectedOffset: bigint;
}

/// ASR 3.7.0 / DGF 1.5.0 / AggregateVerifier 0.2.0 (Base Sepolia, game type 621) — read from the
/// verified sources (Sourcify / Blockscout) and cross-checked against live storage.
export const BASE_SEPOLIA_LAYOUT: OpStackLayout = {
    asrDisputeGameFactorySlot: 1n,
    asrAnchorGameSlot: 2n,
    asrStartingAnchorRootSlot: 3n,
    asrBlacklistSlot: 5n,
    asrRespectedGameTypeSlot: 6n,
    asrRespectedGameTypeOffset: 0n,
    asrRetirementTimestampOffset: 4n,
    dgfGamesSlot: 103n,
    gameStateSlot: 0n,
    gameCreatedAtOffset: 0n,
    gameResolvedAtOffset: 8n,
    gameStatusOffset: 16n,
    gameWasRespectedSlot: 0n,
    gameWasRespectedOffset: 18n
};

/// ASR 3.9.0 / DGF 1.6.1 / SuperFaultDisputeGame (OP Mainnet, game type 9, super roots): same ASR/DGF
/// slots; the game keeps `wasRespectedGameTypeWhenCreated` in its own slot 9.
export const SUPER_FAULT_DISPUTE_GAME_LAYOUT: OpStackLayout = {
    ...BASE_SEPOLIA_LAYOUT,
    gameWasRespectedSlot: 9n,
    gameWasRespectedOffset: 0n
};

/// `OpStackOutputRootProof.RootFormat`.
export const ROOT_FORMAT = {OUTPUT_ROOT: 0, SUPER_ROOT_V1: 1} as const;

export interface OpStackProfile {
    rootFormat: number;
    l2ChainId: bigint;
    anchorStateRegistry: Hex;
    anchorStateRegistryImplCodeHash: Hex;
    disputeGameFinalityDelaySeconds: bigint;
    gameImplementation: Hex;
    layout: OpStackLayout;
}

export const EIP1967_IMPLEMENTATION_SLOT: Hex = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

export const GAME_STATUS = {IN_PROGRESS: 0, CHALLENGER_WINS: 1, DEFENDER_WINS: 2} as const;

// DisputeGameFactory clone (Solady CWIA): PREFIX ‖ uint16(argsLen) ‖ MID ‖ impl ‖ SUFFIX ‖ args.
const CLONE_PREFIX = "36602c57343d527f9e4ac34f21c619cefc926c8bd93b54bf5a39c7ab2127a895af1cc0691d7e3dff593da1005b363d3d373d3d3d3d61";
const CLONE_MID = "806062363936013d73";
const CLONE_SUFFIX = "5af43d3d93803e606057fd5bf3";

export function slotHex(n: bigint): Hex {
    return ("0x" + (n & ((1n << 256n) - 1n)).toString(16).padStart(64, "0")) as Hex;
}

/// `DisputeGameFactory.getGameUUID`: keccak256(abi.encode(gameType, rootClaim, extraData)).
export function gameUuid(gameType: number, rootClaim: Hex, extraData: Hex): Hex {
    return keccak256(encodeAbiParameters(
        [{type: "uint32"}, {type: "bytes32"}, {type: "bytes"}], [gameType, rootClaim, extraData]
    ));
}

/// `_disputeGames[uuid]` storage slot.
export function dgfGameSlot(uuid: Hex, layout: OpStackLayout): Hex {
    return keccak256(encodeAbiParameters([{type: "bytes32"}, {type: "uint256"}], [uuid, layout.dgfGamesSlot]));
}

/// `disputeGameBlacklist[game]` storage slot.
export function blacklistSlot(game: Hex, layout: OpStackLayout): Hex {
    return keccak256(encodeAbiParameters([{type: "address"}, {type: "uint256"}], [game, layout.asrBlacklistSlot]));
}

/// ASR slots a dispute proof may need: always factory / respected type / implementation, plus the
/// anchor game, the starting anchor root and (per game) the blacklist entry.
export function asrSlots(layout: OpStackLayout, games: Hex[] = []): Hex[] {
    return [
        slotHex(layout.asrDisputeGameFactorySlot),
        slotHex(layout.asrRespectedGameTypeSlot),
        EIP1967_IMPLEMENTATION_SLOT,
        slotHex(layout.asrAnchorGameSlot),
        slotHex(layout.asrStartingAnchorRootSlot),
        ...games.map((g) => blacklistSlot(g, layout))
    ];
}

/// Pack a GameId: gameType(32) ‖ timestamp(64) ‖ proxy(160).
export function packGameId(gameType: number, timestamp: bigint, proxy: Hex): Hex {
    return slotHex((BigInt(gameType) << 224n) | (timestamp << 160n) | BigInt(proxy));
}

/// Build a DisputeGameFactory clone runtime for `impl` with CWIA `args`.
export function cloneCode(impl: Hex, args: Hex): Hex {
    const a = args.slice(2);
    const len = (a.length / 2).toString(16).padStart(4, "0");
    return ("0x" + CLONE_PREFIX + len + CLONE_MID + impl.slice(2).toLowerCase() + CLONE_SUFFIX + a) as Hex;
}

/// Output root preimage (version 0) and its hash.
export function outputRootPreimage(stateRoot: Hex, messagePasserStorageRoot: Hex, blockHash: Hex): {
    preimage: Hex;
    outputRoot: Hex;
} {
    const preimage = ("0x" + "00".repeat(32) + stateRoot.slice(2) + messagePasserStorageRoot.slice(2)
        + blockHash.slice(2)) as Hex;
    return {preimage, outputRoot: keccak256(preimage)};
}

/// Interop super root (version 1): `0x01 ‖ timestamp(8) ‖ (chainId(32) ‖ outputRoot(32))*`.
export function superRootPreimage(timestamp: bigint, entries: {chainId: bigint; outputRoot: Hex}[]): {
    preimage: Hex;
    superRoot: Hex;
} {
    const preimage = ("0x01" + timestamp.toString(16).padStart(16, "0") + entries.map((e) =>
        e.chainId.toString(16).padStart(64, "0") + e.outputRoot.slice(2)).join("")) as Hex;
    return {preimage, superRoot: keccak256(preimage)};
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

export function accountNodes(proof: {accountProof: string[]}): Buffer[] {
    return proof.accountProof.map(hexToBuf);
}

export const MODE = {ANCHOR: 0, GAME: 1} as const;

export interface DisputeProofParts {
    mode: number;
    gameType: number;
    extraData: Hex;
    asrAccountProof: Buffer[];
    asrStorageProof: unknown[];
    asrImplAccountProof: Buffer[];
    dgfAccountProof: Buffer[];
    dgfStorageProof: unknown[];
    gameAccountProof: Buffer[];
    gameCode: Hex;
    gameStorageProof: unknown[];
    /// Super-root chains only; "0x" otherwise.
    superRootPreimage?: Hex;
}

/// The dispute-proof RLP item (`OpStackOutputRootProof` DP_IDX_* order).
export function disputeProofItem(p: DisputeProofParts): unknown[] {
    return [
        bigintToTrimmedBuf(BigInt(p.mode)),
        bigintToTrimmedBuf(BigInt(p.gameType)),
        hexToBuf(p.extraData),
        p.asrAccountProof,
        p.asrStorageProof,
        p.asrImplAccountProof,
        p.dgfAccountProof,
        p.dgfStorageProof,
        p.gameAccountProof,
        hexToBuf(p.gameCode),
        p.gameStorageProof,
        hexToBuf(p.superRootPreimage ?? "0x")
    ];
}

export interface OpStackBundleParts {
    lightClientProof: Hex; // RLP of the 7-item light-client list
    dispute: DisputeProofParts;
    outputRootPreimage: Hex;
    l2AccountProof: Buffer[];
    l2StorageProof: unknown[];
    bundleContent: Hex;
}

/// Full `verifyBundle` proof (6-item shape).
export function encodeOpStackBundle(p: OpStackBundleParts): Hex {
    return ("0x" + rlpEncode([
        hexToBuf(p.lightClientProof),
        disputeProofItem(p.dispute) as never,
        hexToBuf(p.outputRootPreimage),
        p.l2AccountProof,
        p.l2StorageProof as never,
        hexToBuf(p.bundleContent)
    ]).toString("hex")) as Hex;
}

/// Items 0–2 only — the `verifyL2StateRoot` input.
export function encodeOpStackL2StateRootProof(p: Omit<OpStackBundleParts, "l2AccountProof" | "l2StorageProof" | "bundleContent">): Hex {
    return ("0x" + rlpEncode([
        hexToBuf(p.lightClientProof),
        disputeProofItem(p.dispute) as never,
        hexToBuf(p.outputRootPreimage)
    ]).toString("hex")) as Hex;
}

/// ABI tuple for the verifier constructors' `Profile` argument.
export function profileTuple(p: OpStackProfile) {
    return {
        rootFormat: p.rootFormat,
        l2ChainId: p.l2ChainId,
        anchorStateRegistry: p.anchorStateRegistry,
        anchorStateRegistryImplCodeHash: p.anchorStateRegistryImplCodeHash,
        disputeGameFinalityDelaySeconds: p.disputeGameFinalityDelaySeconds,
        gameImplementation: p.gameImplementation,
        layout: p.layout
    };
}
