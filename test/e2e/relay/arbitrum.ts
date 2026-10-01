import {encodeAbiParameters, encodePacked, keccak256, type Hex} from "viem";
import {rlpEncode, hexToBuf, hexToTrimmedBuf} from "../lib/rlp.js";
import type {EthGetProofResult} from "./buildEthMainnetProof.js";

/// Shared encoders for `ArbitrumNitroVerifier` (Arbitrum Nitro / BoLD rollups settling on Ethereum):
/// the assertion preimage, the rollup storage slots, the L2 header RLP, and the bundle. Every slot
/// here mirrors how `ArbitrumAssertionProof` derives it — the proof never names its own slots.

/// `ArbitrumAssertionProof.Layout`. nitro-contracts v3.x (BoLD) RollupCore, behind the RollupProxy:
/// Initializable+ContextUpgradeable+PausableUpgradeable take slots 0–100, then chainId (101) …
/// `validators` AddressSet (114–115), `_latestConfirmed` (116), `_assertions` (117). AssertionNode
/// slot 0 packs firstChildBlock(8) | secondChildBlock(8) | createdAtBlock(8) | isFirstChild(1) |
/// status(1), so `status` is the byte at offset 25. Cross-checked against live Arbitrum Sepolia /
/// Arbitrum One storage (slot 116 == latestConfirmed(), slot 0 of _assertions[latestConfirmed] has
/// status 2).
export interface ArbitrumLayout {
    assertionsSlot: bigint;
    assertionStatusOffset: bigint;
}

export const BOLD_LAYOUT: ArbitrumLayout = {assertionsSlot: 117n, assertionStatusOffset: 25n};
/// Not used by the verifier (it proves `_assertions[h].status`); the builder reads it to pick the newest.
export const LATEST_CONFIRMED_SLOT = 116n;

export interface ArbitrumProfile {
    rollup: Hex;
    rollupAdminLogic: Hex;
    rollupUserLogic: Hex;
    layout: ArbitrumLayout;
}

export const EIP1967_IMPLEMENTATION_SLOT: Hex = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
export const IMPLEMENTATION_SECONDARY_SLOT: Hex = "0x2b1dbce74324248c222f0ec2d5ed7bd323cfc425b336f0253c5ccfda7265546d";

export const ASSERTION_STATUS = {NO_ASSERTION: 0, PENDING: 1, CONFIRMED: 2} as const;
export const MACHINE_STATUS = {RUNNING: 0, FINISHED: 1, ERRORED: 2} as const;

export function slotHex(n: bigint): Hex {
    return ("0x" + (n & ((1n << 256n) - 1n)).toString(16).padStart(64, "0")) as Hex;
}

/// Slot 0 of `_assertions[assertionHash]`.
export function assertionSlot(assertionHash: Hex, layout: ArbitrumLayout = BOLD_LAYOUT): Hex {
    return keccak256(encodeAbiParameters([{type: "bytes32"}, {type: "uint256"}], [assertionHash, layout.assertionsSlot]));
}

/// Decoded AssertionNode slot 0.
export function decodeAssertionNode(word: Hex | bigint, layout: ArbitrumLayout = BOLD_LAYOUT) {
    const w = BigInt(word);
    const m64 = (1n << 64n) - 1n;
    return {
        firstChildBlock: w & m64,
        secondChildBlock: (w >> 64n) & m64,
        createdAtBlock: (w >> 128n) & m64,
        isFirstChild: ((w >> 192n) & 0xffn) !== 0n,
        status: Number((w >> (layout.assertionStatusOffset * 8n)) & 0xffn)
    };
}

/// `AssertionState` as emitted in `AssertionCreated` (nitro-contracts AssertionState.sol / GlobalState.sol).
export interface AssertionStateJson {
    blockHash: Hex;
    sendRoot: Hex;
    inboxPosition: bigint;
    positionInMessage: bigint;
    machineStatus: number;
    endHistoryRoot: Hex;
}

/// `parentAssertionHash ‖ abi.encode(AssertionState) ‖ inboxAcc` (256 bytes) and the assertion hash
/// `keccak256(parent ‖ keccak256(abi.encode(afterState)) ‖ inboxAcc)` (RollupLib.assertionHash).
export function assertionPreimage(parent: Hex, s: AssertionStateJson, inboxAcc: Hex): {preimage: Hex; hash: Hex} {
    const state = encodeAbiParameters(
        [{type: "bytes32"}, {type: "bytes32"}, {type: "uint64"}, {type: "uint64"}, {type: "uint8"}, {type: "bytes32"}],
        [s.blockHash, s.sendRoot, s.inboxPosition, s.positionInMessage, s.machineStatus, s.endHistoryRoot]
    );
    const preimage = ("0x" + parent.slice(2) + state.slice(2) + inboxAcc.slice(2)) as Hex;
    const hash = keccak256(encodePacked(["bytes32", "bytes32", "bytes32"], [parent, keccak256(state), inboxAcc]));
    return {preimage, hash};
}

/// JSON-RPC block header (geth / Nitro naming).
export interface RpcHeader {
    hash: Hex;
    parentHash: Hex;
    sha3Uncles: Hex;
    miner: Hex;
    stateRoot: Hex;
    transactionsRoot: Hex;
    receiptsRoot: Hex;
    logsBloom: Hex;
    difficulty: Hex;
    number: Hex;
    gasLimit: Hex;
    gasUsed: Hex;
    timestamp: Hex;
    extraData: Hex;
    mixHash: Hex;
    nonce: Hex;
    baseFeePerGas?: Hex;
    withdrawalsRoot?: Hex;
    blobGasUsed?: Hex;
    excessBlobGas?: Hex;
    parentBeaconBlockRoot?: Hex;
    requestsHash?: Hex;
}

/// Consensus RLP of a header (go-ethereum `types.Header` field order; optional fields appended while
/// present). Throws unless it hashes to `h.hash`, so a builder never ships a header the chain did not.
export function encodeHeader(h: RpcHeader): Hex {
    const items: Buffer[] = [
        hexToBuf(h.parentHash), hexToBuf(h.sha3Uncles), hexToBuf(h.miner), hexToBuf(h.stateRoot),
        hexToBuf(h.transactionsRoot), hexToBuf(h.receiptsRoot), hexToBuf(h.logsBloom),
        hexToTrimmedBuf(h.difficulty), hexToTrimmedBuf(h.number), hexToTrimmedBuf(h.gasLimit),
        hexToTrimmedBuf(h.gasUsed), hexToTrimmedBuf(h.timestamp), hexToBuf(h.extraData), hexToBuf(h.mixHash),
        hexToBuf(h.nonce)
    ];
    const optional: [keyof RpcHeader, boolean][] = [
        ["baseFeePerGas", true], ["withdrawalsRoot", false], ["blobGasUsed", true], ["excessBlobGas", true],
        ["parentBeaconBlockRoot", false], ["requestsHash", false]
    ];
    for (const [k, numeric] of optional) {
        const v = h[k];
        if (v === undefined || v === null) break;
        items.push(numeric ? hexToTrimmedBuf(v) : hexToBuf(v));
    }
    const rlp = ("0x" + rlpEncode(items).toString("hex")) as Hex;
    if (keccak256(rlp) !== h.hash.toLowerCase()) throw new Error(`header RLP does not hash to ${h.hash}`);
    return rlp;
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

/// The rollup slots one assertion proof needs: both logic slots and `_assertions[h]` slot 0.
export function rollupSlots(assertionHash: Hex, layout: ArbitrumLayout = BOLD_LAYOUT): Hex[] {
    return [EIP1967_IMPLEMENTATION_SLOT, IMPLEMENTATION_SECONDARY_SLOT, assertionSlot(assertionHash, layout)];
}

/// `ArbitrumAssertionProof` assertion-proof item: `[rollupAccountProof, rollupStorageProof]`.
export function assertionProofItem(rollupProof: EthGetProofResult, assertionHash: Hex, layout: ArbitrumLayout = BOLD_LAYOUT): unknown[] {
    return [accountNodes(rollupProof), storageEntries(rollupProof, rollupSlots(assertionHash, layout))];
}

export interface ArbitrumBundleParts {
    lightClientProof: Hex; // RLP of the 7-item light-client list
    assertionProof: unknown[];
    assertionPreimage: Hex;
    l2Header: Hex;
    l2AccountProof: Buffer[];
    l2StorageProof: unknown[];
    bundleContent: Hex;
}

/// Each top-level item RLP-encoded on its own (Solidity tests splice them with `RLP.encode(bytes[])`).
export function bundleItems(p: ArbitrumBundleParts): Hex[] {
    const enc = (x: unknown) => ("0x" + rlpEncode(x as never).toString("hex")) as Hex;
    return [
        enc(hexToBuf(p.lightClientProof)),
        enc(p.assertionProof),
        enc(hexToBuf(p.assertionPreimage)),
        enc(hexToBuf(p.l2Header)),
        enc(p.l2AccountProof),
        enc(p.l2StorageProof),
        enc(hexToBuf(p.bundleContent))
    ];
}

/// Full `verifyBundle` proof (7-item shape).
export function encodeArbitrumBundle(p: ArbitrumBundleParts): Hex {
    return ("0x" + rlpEncode([
        hexToBuf(p.lightClientProof),
        p.assertionProof as never,
        hexToBuf(p.assertionPreimage),
        hexToBuf(p.l2Header),
        p.l2AccountProof,
        p.l2StorageProof as never,
        hexToBuf(p.bundleContent)
    ]).toString("hex")) as Hex;
}

/// Items 0–3 only — the `verifyL2State` input.
export function encodeArbitrumL2StateProof(p: Pick<ArbitrumBundleParts, "lightClientProof" | "assertionProof" | "assertionPreimage" | "l2Header">): Hex {
    return ("0x" + rlpEncode([
        hexToBuf(p.lightClientProof),
        p.assertionProof as never,
        hexToBuf(p.assertionPreimage),
        hexToBuf(p.l2Header)
    ]).toString("hex")) as Hex;
}

/// ABI tuple for the verifier constructor's `Profile` argument.
export function profileTuple(p: ArbitrumProfile) {
    return {rollup: p.rollup, rollupAdminLogic: p.rollupAdminLogic, rollupUserLogic: p.rollupUserLogic, layout: p.layout};
}
