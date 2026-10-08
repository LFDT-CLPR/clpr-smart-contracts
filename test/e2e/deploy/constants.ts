import {parseEther, type Hex} from "viem";
import {SOLO_MAX_GAS_PER_MESSAGE} from "../backend/solo/solo.js";

const DEFAULT_PEER_THROTTLES = {
    maxMessagesPerBundle: 100n,
    maxMessagePayloadBytes: 16_384n,
    // The protocol default. Every callback is guaranteed its budget, less the CALL's own cost, so a
    // bundle needs `budget + budget / 63` of gas left at each one, which `ferryCore`'s 5M submit gas
    // must cover.
    maxGasPerMessage: 1_000_000n,
    maxQueueDepth: 1_024n,
    maxSyncBytes: 1_000_000n,
    maxLocalEndpoints: 0n, // 0 = unlimited
    maxPeerEndpoints: 0n // 0 = unlimited
} as const;

/** Peer throttles applied on Solo JSON-RPC relays (`wireConfig({soloRelay: true})`). */
const SOLO_PEER_THROTTLES = {
    ...DEFAULT_PEER_THROTTLES,
    maxGasPerMessage: SOLO_MAX_GAS_PER_MESSAGE
} as const;

const ZERO_BYTES32: Hex = `0x${"00".repeat(32)}` as Hex;

const DEFAULT_ECON = {
    messageExecutionCost: 0n,
    endpointMarginPercent: 10n,
    minLockedStake: parseEther("0.1"),
    minEndpointBond: parseEther("0.1"),
    basePenalty: parseEther("0.01"),
    penaltyMultiplier: 2n,
    slashBanThreshold: 5,
    connectorQueueQuotaPct: 50,
    connectorInboundGasStipend: 200_000n,
    maxChannels: 0,
    maxConnectors: 0,
    connectorPaymentGasLimit: 200_000n
} as const;

export {DEFAULT_PEER_THROTTLES, SOLO_PEER_THROTTLES, DEFAULT_ECON, ZERO_BYTES32};