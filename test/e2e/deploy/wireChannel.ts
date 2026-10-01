import {generatePrivateKey, privateKeyToAccount} from "viem/accounts";
import {keccak256, parseEther, zeroAddress, type Hex} from "viem";
import {loadArtifact} from "../../../script/deploy/artifacts.js";
import type {ChainClients} from "../lib/clients.js";
import type {BackendKind} from "../backend/Backend.js";
import {
    channelCommitment,
    deriveChannelId,
    digestForChannelReveal,
    uncompressedPubKey64
} from "../lib/ids.js";
import {pbInt, pbLen, pbStr} from "../lib/proto.js";
import {rlpList, rlpBytes, hexToBuf, bigintToTrimmedBuf} from "../lib/rlp.js";
import {rpcCall, QBFT_EPOCH_LENGTH, encodeTrustAnchor} from "../lib/qbft.js";
import type {DeployedAddresses, QbftDeployedAddresses} from "./deploy.js";
import {wireConfig, registerEndpoint} from "./wire.js";
import {DEFAULT_PEER_THROTTLES, SOLO_PEER_THROTTLES, ZERO_BYTES32} from "./constants.js";

export {ZERO_BYTES32};
export {zeroAddress, parseEther};

// ── Result types ──────────────────────────────────────────────────────────

export interface WiredChannel {
    channelId: Hex;
    operatorPubKey: Hex;
    operatorAddress: Hex;
    salt: Hex;
}

export interface QbftWiredChannel extends WiredChannel {
    configProof: Hex;
    trustAnchor: Hex;
}

// ── wireChannel overloads ──────────────────────────────────────────────

type StubWireOpts = {
    chainA: ChainClients;
    chainB: ChainClients;
    caipA: string;
    caipB: string;
    addrsA: DeployedAddresses;
    addrsB: DeployedAddresses;
    salt?: Hex;
    operatorKey?: Hex;
};

type CrossWireOpts = StubWireOpts & {
    peerKindA: BackendKind;
    peerKindB: BackendKind;
    validatorAddr: Hex;
};

/// QBFT mode opts. When chainB/addrsB/caipB are omitted the channel is
/// wired on chain A only (single-chain tests).
type QbftWireOpts = {
    chainA: ChainClients;
    caipA: string;
    addrsA: QbftDeployedAddresses;
    validatorAddr: Hex;
    chainB?: ChainClients;
    caipB?: string;
    addrsB?: QbftDeployedAddresses;
    peerChainId?: string;
    peerClients?: ChainClients;
    peerServiceAddr?: Hex;
    salt?: Hex;
    operatorKey?: Hex;
};

export function wireChannel(opts: CrossWireOpts): Promise<WiredChannel>;
export function wireChannel(opts: StubWireOpts): Promise<WiredChannel>;
export function wireChannel(opts: QbftWireOpts): Promise<QbftWiredChannel>;
export async function wireChannel(
    opts: StubWireOpts | CrossWireOpts | QbftWireOpts
): Promise<WiredChannel | QbftWiredChannel> {
    if ("peerKindA" in opts) return wireCrossVerifier(opts);
    if ("validatorAddr" in opts) return wireChannelQbft(opts);
    return wireChannelStub(opts);
}

function encodePeerThrottlesPb(t: {
    maxMessagesPerBundle: bigint;
    maxMessagePayloadBytes: bigint;
    maxGasPerMessage: bigint;
    maxQueueDepth: bigint;
    maxSyncBytes: bigint;
}): Buffer {
    return Buffer.concat([
        pbInt(1, t.maxMessagesPerBundle),
        pbInt(2, t.maxMessagePayloadBytes),
        pbInt(3, t.maxGasPerMessage),
        pbInt(4, t.maxQueueDepth),
        pbInt(5, t.maxSyncBytes)
    ]);
}

/// Build `configProof` for `HieroVerifier.verifyConfig` when the peer is Hiero (Solo EVM).
export function buildHieroConfigProof(peerChainId: string): Hex {
    const throttles = encodePeerThrottlesPb(SOLO_PEER_THROTTLES);
    const configMsg = Buffer.concat([
        pbInt(1, 1n),
        pbStr(2, peerChainId),
        pbLen(5, throttles)
    ]);
    const payload = pbLen(3, pbLen(1, pbLen(1, configMsg)));
    return ("0x" + payload.toString("hex")) as Hex;
}

// ── Cross-verifier (Besu|Anvil ↔ Solo) ─────────────────────────────────────────

async function wireCrossVerifier(opts: CrossWireOpts): Promise<WiredChannel> {
    const {chainA, chainB, caipA, caipB, addrsA, addrsB, peerKindA, peerKindB} = opts;
    const salt = opts.salt ?? ZERO_BYTES32;

    const operatorKey = opts.operatorKey ?? generatePrivateKey();
    const operatorAccount = privateKeyToAccount(operatorKey);
    const operatorPubKey = uncompressedPubKey64(operatorAccount.publicKey);

    const idFromA = deriveChannelId({localChainId: caipA, peerChainId: caipB, pubKey: operatorPubKey, salt});
    const idFromB = deriveChannelId({localChainId: caipB, peerChainId: caipA, pubKey: operatorPubKey, salt});
    if (idFromA !== idFromB) {
        throw new Error(`channelId mismatch: A=${idFromA}, B=${idFromB}`);
    }
    const channelId = idFromA;

    let configProofA: Hex = "0x";
    if (peerKindA === "solo") {
        configProofA = buildHieroConfigProof(caipB);
    } else if (peerKindA === "besu") {
        const {configProof} = await buildQbftConfigProof({
            clients: chainB,
            peerChainId: caipB,
            serviceAddr: addrsB.clprService,
            validatorAddr: opts.validatorAddr
        });
        configProofA = configProof;
    } else {
        // Peer produces stub proofs: chain A runs `E2EVerifier`, which needs its peer config.
        await configureE2EVerifier({clients: chainA, verifierAddr: addrsA.verifier, peerChainId: caipB});
    }

    const commitment = channelCommitment(channelId, operatorPubKey);
    await registerOn(chainA, addrsA.clprService, channelId, commitment);
    const sigA = await operatorAccount.signMessage({
        message: {raw: digestForChannelReveal(channelId, addrsA.clprService)}
    });
    await completeOn(chainA, addrsA.clprService, {
        channelId, pubKey: operatorPubKey, sig: sigA, salt,
        verifier: addrsA.verifier, configProof: configProofA
    });

    let configProofB: Hex = "0x";
    if (peerKindB === "solo") {
        configProofB = buildHieroConfigProof(caipA);
    } else if (peerKindB === "besu") {
        const {configProof} = await buildQbftConfigProof({
            clients: chainA,
            peerChainId: caipA,
            serviceAddr: addrsA.clprService,
            validatorAddr: opts.validatorAddr
        });
        configProofB = configProof;
    } else {
        await configureE2EVerifier({clients: chainB, verifierAddr: addrsB.verifier, peerChainId: caipA});
    }

    await registerOn(chainB, addrsB.clprService, channelId, commitment);
    const sigB = await operatorAccount.signMessage({
        message: {raw: digestForChannelReveal(channelId, addrsB.clprService)}
    });
    await completeOn(chainB, addrsB.clprService, {
        channelId, pubKey: operatorPubKey, sig: sigB, salt,
        verifier: addrsB.verifier, configProof: configProofB
    });

    return {channelId, operatorPubKey, operatorAddress: operatorAccount.address, salt};
}

// ── Stub implementation ───────────────────────────────────────────────────

async function wireChannelStub(opts: StubWireOpts): Promise<WiredChannel> {
    const {chainA, chainB, caipA, caipB, addrsA, addrsB} = opts;
    const salt = opts.salt ?? ZERO_BYTES32;

    const operatorKey = opts.operatorKey ?? generatePrivateKey();
    const operatorAccount = privateKeyToAccount(operatorKey);
    const operatorPubKey = uncompressedPubKey64(operatorAccount.publicKey);

    const idFromA = deriveChannelId({localChainId: caipA, peerChainId: caipB, pubKey: operatorPubKey, salt});
    const idFromB = deriveChannelId({localChainId: caipB, peerChainId: caipA, pubKey: operatorPubKey, salt});
    if (idFromA !== idFromB) {
        throw new Error(
            `channelId mismatch — A computed ${idFromA}, B computed ${idFromB}. ` +
                `Cross-platform byte-equivalence is broken — check ids.ts vs ChannelLogic._deriveChannelId.`
        );
    }
    const channelId = idFromA;

    await configureE2EVerifier({clients: chainA, verifierAddr: addrsA.verifier, peerChainId: caipB});
    await configureE2EVerifier({clients: chainB, verifierAddr: addrsB.verifier, peerChainId: caipA});

    const commitment = channelCommitment(channelId, operatorPubKey);
    await registerOn(chainA, addrsA.clprService, channelId, commitment);
    const sigA = await operatorAccount.signMessage({message: {raw: digestForChannelReveal(channelId, addrsA.clprService)}});
    await completeOn(chainA, addrsA.clprService, {channelId, pubKey: operatorPubKey, sig: sigA, salt, verifier: addrsA.verifier, configProof: "0x"});

    await registerOn(chainB, addrsB.clprService, channelId, commitment);
    const sigB = await operatorAccount.signMessage({message: {raw: digestForChannelReveal(channelId, addrsB.clprService)}});
    await completeOn(chainB, addrsB.clprService, {channelId, pubKey: operatorPubKey, sig: sigB, salt, verifier: addrsB.verifier, configProof: "0x"});

    return {channelId, operatorPubKey, operatorAddress: operatorAccount.address, salt};
}

// ── QBFT implementation ───────────────────────────────────────────────────

async function wireChannelQbft(opts: QbftWireOpts): Promise<QbftWiredChannel> {
    const {chainA, caipA, addrsA, validatorAddr} = opts;
    const salt = opts.salt ?? ZERO_BYTES32;

    const operatorKey = opts.operatorKey ?? generatePrivateKey();
    const operatorAccount = privateKeyToAccount(operatorKey);
    const operatorPubKey = uncompressedPubKey64(operatorAccount.publicKey);

    const isTwoSided = opts.chainB !== undefined && opts.addrsB !== undefined && opts.caipB !== undefined;
    const caipB = opts.caipB ?? opts.peerChainId ?? "hiero:localnet";

    const channelId = deriveChannelId({localChainId: caipA, peerChainId: caipB, pubKey: operatorPubKey, salt});

    if (isTwoSided) {
        const idFromB = deriveChannelId({localChainId: caipB, peerChainId: caipA, pubKey: operatorPubKey, salt});
        if (channelId !== idFromB) {
            throw new Error(`QBFT channelId mismatch — A: ${channelId}, B: ${idFromB}`);
        }
    }

    const {configProof, trustAnchor} = await wireQbftOneSide({
        clients: chainA,
        addrs: addrsA,
        caipChainId: caipA,
        peerChainId: caipB,
        validatorAddr,
        proofClients: opts.peerClients ?? (isTwoSided ? opts.chainB! : chainA),
        proofServiceAddr: opts.peerServiceAddr ?? (isTwoSided ? opts.addrsB!.clprService : addrsA.clprService),
        channelId,
        operatorPubKey,
        operatorAccount,
        salt
    });

    if (isTwoSided) {
        await wireQbftOneSide({
            clients: opts.chainB!,
            addrs: opts.addrsB!,
            caipChainId: caipB,
            peerChainId: caipA,
            validatorAddr,
            proofClients: chainA,
            proofServiceAddr: addrsA.clprService,
            channelId,
            operatorPubKey,
            operatorAccount,
            salt
        });
    }

    return {channelId, operatorPubKey, operatorAddress: operatorAccount.address, salt, configProof, trustAnchor};
}

async function wireQbftOneSide(opts: {
    clients: ChainClients;
    addrs: QbftDeployedAddresses;
    caipChainId: string;
    peerChainId: string;
    validatorAddr: Hex;
    proofClients: ChainClients;
    proofServiceAddr: Hex;
    channelId: Hex;
    operatorPubKey: Hex;
    operatorAccount: ReturnType<typeof privateKeyToAccount>;
    salt: Hex;
}): Promise<{configProof: Hex; trustAnchor: Hex}> {
    const {clients, addrs, validatorAddr, channelId, operatorPubKey, operatorAccount, salt} = opts;

    await wireConfig({clients, addrs: {...addrs, verifier: addrs.qbftVerifier}});

    const fakeKey = ("0x" + "11".repeat(64)) as Hex;
    await registerEndpoint({clients, clprService: addrs.clprService, bond: parseEther("0.1")});

    const {configProof, trustAnchor} = await buildQbftConfigProof({
        clients: opts.proofClients,
        peerChainId: opts.peerChainId,
        serviceAddr: opts.proofServiceAddr,
        validatorAddr
    });

    const service = loadArtifact("ClprService");
    const commitment = channelCommitment(channelId, operatorPubKey);

    const regTx = await clients.walletClient.writeContract({
        address: addrs.clprService, abi: service.abi as never,
        functionName: "registerChannel", args: [channelId, commitment]
    });
    await clients.publicClient.waitForTransactionReceipt({hash: regTx});

    const sig = await operatorAccount.signMessage({message: {raw: digestForChannelReveal(channelId, addrs.clprService)}});
    const completeTx = await clients.walletClient.writeContract({
        address: addrs.clprService, abi: service.abi as never,
        functionName: "completeChannel",
        args: [channelId, operatorPubKey, sig, salt, addrs.qbftVerifier, configProof, "0x"],
        gas: 3_000_000n
    });
    await clients.publicClient.waitForTransactionReceipt({hash: completeTx});
    return {configProof, trustAnchor};
}

// ── buildQbftConfigProof ──────────────────────────────────────────────────

async function buildQbftConfigProof(opts: {
    clients: ChainClients;
    peerChainId: string;
    serviceAddr: Hex;
    validatorAddr: Hex;
}): Promise<{configProof: Hex; trustAnchor: Hex}> {
    const {clients, peerChainId, serviceAddr, validatorAddr} = opts;

    const bytecode = await clients.publicClient.getCode({address: serviceAddr});
    if (!bytecode || bytecode === "0x") throw new Error(`ClprService at ${serviceAddr} has no code`);
    const codeHash = keccak256(bytecode) as Hex;

    const rpcUrl = clients.chain.rpcUrls.default.http[0];
    if (!rpcUrl) throw new Error("ChainClients.chain.rpcUrls.default.http[0] is missing");

    const blockTag = await rpcCall<string>(rpcUrl, "eth_blockNumber");
    const rawHeaderHex = await rpcCall<string>(rpcUrl, "debug_getRawHeader", [blockTag]);
    const headerRlp = hexToBuf(rawHeaderHex);

    const blockNumber = BigInt(parseInt(blockTag, 16));
    const epochNumber = blockNumber / QBFT_EPOCH_LENGTH;

    const trustAnchor = encodeTrustAnchor(validatorAddr, codeHash, QBFT_EPOCH_LENGTH, epochNumber);

    const trustAnchorInnerRlp = rlpList([
        rlpBytes(hexToBuf(validatorAddr)),
        rlpBytes(hexToBuf(serviceAddr)),
        rlpBytes(hexToBuf(codeHash))
    ]);

    const configProofBuf = rlpList([
        rlpBytes(hexToBuf(validatorAddr)),
        rlpBytes(hexToBuf(serviceAddr)),
        rlpBytes(Buffer.alloc(32, 0)),
        rlpBytes(Buffer.from(peerChainId)),
        rlpBytes(Buffer.alloc(0)),
        rlpList([
            rlpBytes(bigintToTrimmedBuf(DEFAULT_PEER_THROTTLES.maxMessagesPerBundle)),
            rlpBytes(bigintToTrimmedBuf(DEFAULT_PEER_THROTTLES.maxMessagePayloadBytes)),
            rlpBytes(bigintToTrimmedBuf(DEFAULT_PEER_THROTTLES.maxGasPerMessage)),
            rlpBytes(bigintToTrimmedBuf(DEFAULT_PEER_THROTTLES.maxQueueDepth)),
            rlpBytes(bigintToTrimmedBuf(DEFAULT_PEER_THROTTLES.maxSyncBytes))
        ]),
        rlpBytes(trustAnchorInnerRlp),
        rlpBytes(Buffer.alloc(0)),
        headerRlp,
        rlpBytes(bigintToTrimmedBuf(QBFT_EPOCH_LENGTH))
    ]);

    return {configProof: ("0x" + configProofBuf.toString("hex")) as Hex, trustAnchor};
}

// ── Stub helpers ──────────────────────────────────────────────────────────

async function configureE2EVerifier(opts: {clients: ChainClients; verifierAddr: Hex; peerChainId: string}): Promise<void> {
    const verifier = loadArtifact("E2EVerifier");
    const tx = await opts.clients.walletClient.writeContract({
        address: opts.verifierAddr, abi: verifier.abi as never,
        functionName: "configure",
        args: [
            opts.peerChainId, "0x" as Hex, 0n,
            {
                maxMessagesPerBundle: DEFAULT_PEER_THROTTLES.maxMessagesPerBundle,
                maxMessagePayloadBytes: DEFAULT_PEER_THROTTLES.maxMessagePayloadBytes,
                maxGasPerMessage: DEFAULT_PEER_THROTTLES.maxGasPerMessage,
                maxQueueDepth: DEFAULT_PEER_THROTTLES.maxQueueDepth,
                maxSyncBytes: DEFAULT_PEER_THROTTLES.maxSyncBytes,
                maxLocalEndpoints: DEFAULT_PEER_THROTTLES.maxLocalEndpoints,
                maxPeerEndpoints: DEFAULT_PEER_THROTTLES.maxPeerEndpoints
            },
            "0x" as Hex, "0x" as Hex, []
        ]
    });
    await opts.clients.publicClient.waitForTransactionReceipt({hash: tx});
}

async function registerOn(clients: ChainClients, serviceAddr: Hex, channelId: Hex, commitment: Hex): Promise<void> {
    const service = loadArtifact("ClprService");
    const tx = await clients.walletClient.writeContract({
        address: serviceAddr, abi: service.abi as never,
        functionName: "registerChannel", args: [channelId, commitment]
    });
    await clients.publicClient.waitForTransactionReceipt({hash: tx});
}

async function completeOn(clients: ChainClients, serviceAddr: Hex, a: {channelId: Hex; pubKey: Hex; sig: Hex; salt: Hex; verifier: Hex; configProof: Hex}): Promise<void> {
    const service = loadArtifact("ClprService");
    const tx = await clients.walletClient.writeContract({
        address: serviceAddr, abi: service.abi as never,
        functionName: "completeChannel",
        args: [a.channelId, a.pubKey, a.sig, a.salt, a.verifier, a.configProof, "0x"],
        gas: 3_000_000n
    });
    await clients.publicClient.waitForTransactionReceipt({hash: tx});
}
