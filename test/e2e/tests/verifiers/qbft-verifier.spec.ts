import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {decodeAbiParameters} from "viem";
import {loadArtifact} from "../../../../script/deploy/artifacts";
import type {ChainClients} from "../../lib/clients";
import {provisionE2ESuite} from "../../lib/provisionSuite";
import {deployAll, type QbftDeployedAddresses} from "../../deploy/deploy";
import {wireChannel, type QbftWiredChannel} from "../../deploy/wireChannel";
import {wireConnector} from "../../deploy/wireConnector";
import {buildQbftProof} from "../../relay/buildQbftProof";
import {waitForBlock, encodeTrustAnchor} from "../../lib/qbft";
import {type Backend, createBackend, withOverrideEnvs, parseBackendSpec} from "../../backend";

/// End-to-end test for QBFTVerifier.verifyBundle
///
/// Architecture:
///   - Single-node Besu QBFT cluster (1 validator = 1 committed seal per block).
///   - QBFTVerifier deployed via `deployAll({ mode: "qbft" })`.
///   - Channel established via QBFTVerifier.verifyConfig (ABI-encoded configProof),
///     so ClprService stores the real trust anchor from the start.
///   - verifyBundle called directly as a view (eth_call) to validate the proof
///     logic independently of the ClprService.submitBundle routing.
///
/// What is tested:
///   ✓ QBFTVerifier.verifyConfig — ABI-decodes the operator-supplied configProof
///     and returns the peerChainId / throttles / trust anchor used by completeChannel.
///   ✓ QBFTVerifier.verifyBundle — happy path with real on-chain QBFT proof:
///       - debug_getRawHeader → raw header bytes (with committed seal in extraData)
///       - the header's own validator list seals it (quorum) and links to the trusted set
///       - eth_getProof → account proof verifies against stateRoot
///       - storage proof verifies the channel struct slots against storageRoot
///       - codeHash in trust anchor matches ClprService's on-chain bytecode
///       - bundle content protobuf decoded; message payloads returned correctly
///   ✓ Negative cases: wrong trusted set, bad anchor length
///
/// Run:
///   npm run test:e2e:qbft-verifier
///   CLPR_KEEP_NODES=1 npm run test:e2e:qbft-verifier   # leave node up for debugging

// Skip this test suite if not running besu-only backend
const shouldSkip = (() => {
    const {kindA, kindB} = parseBackendSpec();
    return kindA !== "besu" || kindB !== "besu";
})();

describe.skipIf(shouldSkip)("QBFTVerifier — single-node Besu QBFT (verifyConfig + verifyBundle)", () => {
    let backend: Backend;
    let clients: ChainClients;
    let addrs: QbftDeployedAddresses;
    let channel: QbftWiredChannel;

    const TEST_PAYLOAD = "0xdeadbeefcafe" as `0x${string}`;

    beforeAll(async () => {
        // ── 1. Start the single-node QBFT Besu node ────────────────────────
        backend = withOverrideEnvs({CLPR_BACKEND: "besu"}, createBackend);
        await backend.start();

        const suite = await provisionE2ESuite(backend, "qbft-verifier");
        clients = suite.clientsA;

        const rpcUrl = backend.rpcA();

        // ── 2. Deploy ClprService + QBFTVerifier + helpers ─────────────────
        addrs = await deployAll({
            clients,
            privateKey: suite.privateKey,
            caipChainId: backend.caipA(),
            mode: "qbft"
        });

        // ── 3. Wire channel using QBFTVerifier.verifyConfig ─────────────
        //      buildQbftConfigProof fetches ClprService's codeHash on-chain and
        //      embeds it in the trust anchor.  completeChannel stores this
        //      trust anchor in the Channel struct, so verifyBundle can
        //      verify it without any additional setup.
        channel = await wireChannel({
            chainA: clients,
            caipA: backend.caipA(),
            addrsA: addrs
        });

        // ── 4. Wait for a fresh block after completeChannel ─────────────
        //      The proof will be taken from this block (or a later one).
        //      We need at least one block that sees the ACTIVE channel in
        //      its state root, so the account + storage proofs are non-trivial.
        const currentBlock = await clients.publicClient.getBlockNumber();
        await waitForBlock(rpcUrl, Number(currentBlock) + 2, 30_000);
    }, 300_000);

    afterAll(async () => {
        await backend?.stop();
    });

    // ── Happy-path ──────────────────────────────────────────────────────────

    it("verifyBundle returns correct metadata for a fresh channel (no messages sent)", async () => {
        const rpcUrl = backend.rpcA();

        const {proofBytes, trustAnchor} = await buildQbftProof({
            rpcUrl,
            serviceAddr: addrs.clprService,
            channelId: channel.channelId,
            payloads: []
        });

        const channelContext = (channel.channelId + addrs.clprService.slice(2)) as `0x${string}`;
        const qbftVerifier = loadArtifact("QBFTVerifier");
        const result = (await clients.publicClient.readContract({
            address: addrs.qbftVerifier,
            abi: qbftVerifier.abi as never,
            functionName: "verifyBundle",
            args: [proofBytes, trustAnchor, channelContext]
        })) as [
            {
                state: number;
                nextMessageId: bigint;
                receivedMessageId: bigint;
                sentRunningHash: `0x${string}`;
                receivedRunningHash: `0x${string}`;
            },
            `0x${string}`[],
            `0x${string}`
        ];

        const [metadata, messagePayloads] = result;
        const ZERO_HASH = `0x${"00".repeat(32)}`;

        expect(metadata.state).toBe(1);                  // ACTIVE
        expect(metadata.nextMessageId).toBe(1n);         // fresh — no messages sent
        expect(metadata.receivedMessageId).toBe(0n);     // fresh — no messages received
        expect(metadata.sentRunningHash.toLowerCase()).toBe(ZERO_HASH);
        expect(metadata.receivedRunningHash.toLowerCase()).toBe(ZERO_HASH);
        expect(messagePayloads).toHaveLength(0);
    });

    it("verifyBundle succeeds with a real QBFT proof (1 committed seal)", async () => {
        const rpcUrl = backend.rpcA();

        // The verifier rejects a message-bearing bundle unless the proven channel has an unacked
        // message (ackedMessageId + messageCount < nextMessageId), so enqueue one first.
        const connector = await wireConnector({
            chainA: clients,
            chainB: clients,
            addrsA: addrs,
            addrsB: addrs,
            channelId: channel.channelId,
            skipChainB: true
        });
        const sendTx = await clients.walletClient.writeContract({
            address: addrs.clprService,
            abi: loadArtifact("ClprService").abi as never,
            functionName: "sendMessage",
            args: [channel.channelId, connector.connectorId, addrs.application, TEST_PAYLOAD]
        });
        await clients.publicClient.waitForTransactionReceipt({hash: sendTx});
        const sentBlock = await clients.publicClient.getBlockNumber();
        await waitForBlock(rpcUrl, Number(sentBlock) + 2, 30_000);

        const {proofBytes, trustAnchor} = await buildQbftProof({
            rpcUrl,
            serviceAddr: addrs.clprService,
            channelId: channel.channelId,
            payloads: [TEST_PAYLOAD]
        });

        // Use the trust anchor stored by ClprService (the one verifyConfig returned).
        // It must match what verifyBundle expects.
        const channelContext = (channel.channelId + addrs.clprService.slice(2)) as `0x${string}`;
        const qbftVerifier = loadArtifact("QBFTVerifier");
        const result = (await clients.publicClient.readContract({
            address: addrs.qbftVerifier,
            abi: qbftVerifier.abi as never,
            functionName: "verifyBundle",
            args: [proofBytes, trustAnchor, channelContext]
        })) as [
            {
                state: number;
                nextMessageId: bigint;
                receivedMessageId: bigint;
                sentRunningHash: `0x${string}`;
                receivedRunningHash: `0x${string}`;
            },
            `0x${string}`[],
            `0x${string}`
        ];

        const [metadata, messagePayloads] = result;

        expect(metadata.state).toBe(1); // ACTIVE
        expect(messagePayloads).toHaveLength(1);
        expect(messagePayloads[0].toLowerCase()).toBe(TEST_PAYLOAD.toLowerCase());
    });

    // ── Failure cases ───────────────────────────────────────────────────────

    it("verifyBundle reverts when the trust anchor commits to a different validator set", async () => {
        const rpcUrl = backend.rpcA();

        const {proofBytes, trustAnchor} = await buildQbftProof({
            rpcUrl,
            serviceAddr: addrs.clprService,
            channelId: channel.channelId,
            payloads: []
        });

        // Keep the anchor well-formed (128 bytes, correct codeHash / block) but commit to a set that
        // does not match the submitted list, so verifyBundle fails at the commitment check — not at
        // the trust-anchor length guard.
        const [, , codeHash, anchorBlock] = decodeAbiParameters(
            [{type: "uint8"}, {type: "bytes32"}, {type: "bytes32"}, {type: "uint64"}],
            trustAnchor
        );
        const wrongValidator = "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF" as `0x${string}`;
        const wrongAnchor = encodeTrustAnchor([wrongValidator], codeHash, anchorBlock);

        const channelContext = (channel.channelId + addrs.clprService.slice(2)) as `0x${string}`;
        const qbftVerifier = loadArtifact("QBFTVerifier");
        await expect(
            clients.publicClient.readContract({
                address: addrs.qbftVerifier,
                abi: qbftVerifier.abi as never,
                functionName: "verifyBundle",
                args: [proofBytes, wrongAnchor, channelContext]
            })
        ).rejects.toThrow();
    });

    it("verifyBundle reverts with an invalid trust anchor length", async () => {
        const rpcUrl = backend.rpcA();

        const {proofBytes} = await buildQbftProof({
            rpcUrl,
            serviceAddr: addrs.clprService,
            channelId: channel.channelId,
            payloads: []
        });

        const channelContext = (channel.channelId + addrs.clprService.slice(2)) as `0x${string}`;
        const qbftVerifier = loadArtifact("QBFTVerifier");
        await expect(
            clients.publicClient.readContract({
                address: addrs.qbftVerifier,
                abi: qbftVerifier.abi as never,
                functionName: "verifyBundle",
                args: [proofBytes, "0xdeadbeef", channelContext] // anchor too short — not 128 bytes
            })
        ).rejects.toThrow();
    });

    // ── Supporting assertions ───────────────────────────────────────────────

    it("ClprService is deployed at a non-zero address", () => {
        expect(addrs.clprService).toMatch(/^0x[0-9a-fA-F]{40}$/);
        expect(addrs.clprService.toLowerCase()).not.toBe("0x" + "00".repeat(20));
    });

    it("QBFTVerifier is deployed at a non-zero address", () => {
        expect(addrs.qbftVerifier).toMatch(/^0x[0-9a-fA-F]{40}$/);
    });

    it("channel is ACTIVE after completeChannel with QBFTVerifier", async () => {
        const service = loadArtifact("ClprService");
        const conn = (await clients.publicClient.readContract({
            address: addrs.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {status: number; channelId: `0x${string}`; verifier: `0x${string}`};

        expect(conn.status).toBe(1);                                   // ACTIVE
        expect(conn.channelId).toBe(channel.channelId);
        expect(conn.verifier.toLowerCase()).toBe(addrs.qbftVerifier.toLowerCase());
    });

    it("verifyConfig returns correct peerChainId and non-empty trustAnchor", async () => {
        // Call verifyConfig directly to confirm the ABI-decode round-trip.
        const qbftVerifier = loadArtifact("QBFTVerifier");
        const result = (await clients.publicClient.readContract({
            address: addrs.qbftVerifier,
            abi: qbftVerifier.abi as never,
            functionName: "verifyConfig",
            args: [channel.configProof, channel.channelId, ""]
        })) as [`0x${string}`, string, `0x${string}`, bigint, unknown, `0x${string}`, `0x${string}`, unknown[]];

        // verifyConfig return tuple:
        // [0] channelContext, [1] chainId, [2] serviceAddress, [3] peerConfigNanos,
        // [4] throttles, [5] initialTrustAnchor, [6] initialTrustAnchorId, [7] seedEndpoints
        const [, chainId, , , , initialTrustAnchor] = result;
        expect(chainId).toBe("hiero:localnet");
        expect(initialTrustAnchor).toBe(channel.trustAnchor);
        expect(initialTrustAnchor.length).toBe(2 + 256); // "0x" + 128 bytes = 256 chars
    });

    it("Besu is running QBFT (extraData is long — contains seal data)", async () => {
        const block = await clients.publicClient.getBlock({blockTag: "latest"});
        // QBFT blocks have extraData >> 32 bytes (raw header extraData carries
        // the IBFT2/QBFT committed seal RLP).
        expect(block.extraData.length).toBeGreaterThan(2 + 64);
        expect(block.number).toBeGreaterThan(0n);
    });
});
