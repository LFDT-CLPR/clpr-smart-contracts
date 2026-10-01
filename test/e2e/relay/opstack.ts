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

/// ASR 3.5.0 / DGF 1.3.0 / OPSuccinctFaultDisputeGame 2.0.0 (OP Succinct Lite, game type 42: X Layer,
/// Celo). Read from the Sourcify storage layouts of X Layer's ASR implementation 0xeb69…cf2e, DGF
/// implementation 0x74fa…7d50 and game implementation 0x8841…e607, and cross-checked against live
/// mainnet storage: same ASR/DGF slots; the game packs createdAt | resolvedAt | status in slot 0 and
/// keeps `wasRespectedGameTypeWhenCreated` at slot 9, offset 0.
export const OP_SUCCINCT_LITE_LAYOUT: OpStackLayout = {
    ...BASE_SEPOLIA_LAYOUT,
    gameWasRespectedSlot: 9n,
    gameWasRespectedOffset: 0n
};

/// ASR 3.9.0 / DGF 1.6.1 / PermissionedDisputeGame 2.4.0 (V2, game type 1: Ronin, BOB). From the Sourcify
/// layout of Ronin's game implementation 0xe1dF…b87e: slot 0 packs createdAt | resolvedAt | status, and
/// `wasRespectedGameTypeWhenCreated` is slot 10, offset 0. Same ASR/DGF slots as above.
export const PERMISSIONED_DISPUTE_GAME_V2_LAYOUT: OpStackLayout = {
    ...BASE_SEPOLIA_LAYOUT,
    gameWasRespectedSlot: 10n,
    gameWasRespectedOffset: 0n
};

/// OptimismPortal2 3.x (before the AnchorStateRegistry) as the registry, DGF 1.0.1, KailuaGame (game type
/// 1337: MegaETH). From the Sourcify layouts of MegaETH's portal implementation 0x5540…9fd9 (3.15.2), DGF
/// implementation 0x4bba…e4a0 and game implementation 0x8c0E…0B84, cross-checked against live storage:
/// the portal keeps disputeGameFactory (56), disputeGameBlacklist (58) and respectedGameType |
/// respectedGameTypeUpdatedAt (59, offsets 0 and 4; the update time plays the retirement timestamp's role).
/// The portal has no anchor root: both anchor slots point at slot 2, the first word of ResourceMetering's
/// `__gap`, which is always zero, so ANCHOR mode always reverts (OutputRootNotAnchor). KailuaGame packs
/// createdAt | resolvedAt | status | wasRespectedGameTypeWhenCreated in slot 10 (offsets 0, 8, 16, 17).
export const PORTAL2_KAILUA_LAYOUT: OpStackLayout = {
    asrDisputeGameFactorySlot: 56n,
    asrAnchorGameSlot: 2n,
    asrStartingAnchorRootSlot: 2n,
    asrBlacklistSlot: 58n,
    asrRespectedGameTypeSlot: 59n,
    asrRespectedGameTypeOffset: 0n,
    asrRetirementTimestampOffset: 4n,
    dgfGamesSlot: 103n,
    gameStateSlot: 10n,
    gameCreatedAtOffset: 0n,
    gameResolvedAtOffset: 8n,
    gameStatusOffset: 16n,
    gameWasRespectedSlot: 10n,
    gameWasRespectedOffset: 17n
};

export const ZERO_HASH: Hex = "0x0000000000000000000000000000000000000000000000000000000000000000";

/// `OpStackOutputRootProof.RootFormat`.
export const ROOT_FORMAT = {OUTPUT_ROOT: 0, SUPER_ROOT_V1: 1} as const;

export interface OpStackProfile {
    rootFormat: number;
    l2ChainId: bigint;
    anchorStateRegistry: Hex;
    anchorStateRegistryImplCodeHash: Hex;
    disputeGameFinalityDelaySeconds: bigint;
    gameImplementation: Hex;
    /// keccak256(DGF.gameArgs(respectedGameType)), or zero when the factory clones without game args.
    gameArgsHash: Hex;
    layout: OpStackLayout;
}

/// X Layer (chain 196) deployment profile, read from Ethereum mainnet on 2026-10-01:
///   OptimismPortal 0x6405…9993 (5.2.0) → ASR 0x0005…149d (proxy, 3.5.0; implementation 0xeb69…cf2e)
///   → DGF 0x9D4c…f675 (1.3.0) → gameImpls[42] = OPSuccinctFaultDisputeGame 2.0.0 0x8841…e607.
/// The finality delay (302,400 s = 3.5 days) is an immutable of the ASR implementation, bound by its
/// code hash. Re-read at deployment; the live builder checks every field against the chain.
export const XLAYER_MAINNET_PROFILE: OpStackProfile = {
    rootFormat: 0, // ROOT_FORMAT.OUTPUT_ROOT
    l2ChainId: 196n,
    anchorStateRegistry: "0x000590BB65ab1864a7AD46d6B957cC9a4F2C149d",
    anchorStateRegistryImplCodeHash: "0x1194081c631cd5141ef68135c5aaaa59b92a7c2df303a713c3cf81c6bab69348",
    disputeGameFinalityDelaySeconds: 302_400n,
    gameImplementation: "0x8841FA06099FEdfE7DB6962926C6A281e9E1e607",
    gameArgsHash: ZERO_HASH,
    layout: OP_SUCCINCT_LITE_LAYOUT
};

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
    // Deduplicated: a portal-registry layout points both anchor slots at the same always-zero slot.
    return [...new Set([
        slotHex(layout.asrDisputeGameFactorySlot),
        slotHex(layout.asrRespectedGameTypeSlot),
        EIP1967_IMPLEMENTATION_SLOT,
        slotHex(layout.asrAnchorGameSlot),
        slotHex(layout.asrStartingAnchorRootSlot),
        ...games.map((g) => blacklistSlot(g, layout))
    ])] as Hex[];
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
        gameArgsHash: p.gameArgsHash,
        layout: p.layout
    };
}
