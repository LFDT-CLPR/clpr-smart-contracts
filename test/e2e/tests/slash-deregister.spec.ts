import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {type Hex} from "viem";
import {createBackend} from "../backend/index.js";
import type {Backend} from "../backend/Backend.js";
import type {ChainClients} from "../lib/clients.js";
import {provisionE2ESuite} from "../lib/provisionSuite.js";
import {isSoloBackend} from "../backend/solo/solo.js";
import {loadArtifact} from "../../../script/deploy/artifacts.js";
import {deployAll, deployE2EPair} from "../deploy/deploy.js";
import {wireConfig, registerEndpoint} from "../deploy/wire.js";
import {wireChannel} from "../deploy/wireChannel.js";
import {wireConnector, type WiredConnector} from "../deploy/wireConnector.js";
import {activeEcon, feeAssetBalance, getFeeToken} from "../deploy/feeAsset.js";
import {ferry, ferryQbft} from "../relay/ferry.js";
import {waitForBlock} from "../lib/qbft.js";

/// Source-side slashing on a failure reply, followed by deregistration.
///
/// Reproduces the exact lifecycle a security report flagged as a hazard: when a
/// failure reply (CONNECTOR_NOT_FOUND / CONNECTOR_UNDERFUNDED) comes back on the
/// source ledger, the reply handler does TWO things to the same connector —
/// decrement its in-flight count AND slash its stake. The concern was that the
/// slash could revert the in-flight decrement, permanently blocking deregistration
/// and stranding the remaining locked stake.
///
/// Flow:
///   1. Register connector D on chain A ONLY (skipChainB), with stake.
///   2. A.sendMessage via D  → A's in-flight count for D becomes 1.
///   3. ferry A→B            → B has no such connector → enqueues a
///                             CONNECTOR_NOT_FOUND reply.
///   4. ferry B→A            → A's reply handler decrements D's in-flight (1→0)
///                             AND slashes D (partial: basePenalty < stake).
///   5. admin removeConnector(D) on A → MUST succeed and return the remaining
///                             (post-slash) stake; nothing stuck on-ledger.
///
/// Skipped on Solo: that backend forces connector stake to 0, so a single slash
/// drives lockedStake to 0 and deletes (bans) the connector, which would make the
/// "partial slash survives + remaining stake returned" assertions meaningless.
describe.skipIf(isSoloBackend())("source slash on failure reply then deregister", () => {
    let backend: Backend;
    let A: ChainClients;
    let B: ChainClients;
    let addrsA: {clprService: Hex; application: Hex; connectorContract: Hex; bundleEncoder?: Hex};
    let addrsB: {clprService: Hex; application: Hex; connectorContract: Hex; bundleEncoder?: Hex};
    let channelId: Hex;
    let connector: WiredConnector;

    // 10 x minLockedStake: 1 ETH in native mode, 1,000 USD in token mode.
    const STAKE = activeEcon().minLockedStake * 10n;
    const EXPECTED_REMAINING = STAKE - activeEcon().basePenalty; // partial slash leaves this on-ledger

    beforeAll(async () => {
        backend = createBackend();
        await backend.start();

        const suite = await provisionE2ESuite(backend, "slash-deregister");
        A = suite.clientsA;
        B = suite.clientsB;

        const isBesu = backend.kindA() === "besu";

        if (isBesu) {
            // ── QBFT path: real EVM state proofs ─────────────────────────────
            const [a, b] = await Promise.all([
                deployAll({clients: A, privateKey: suite.privateKey, caipChainId: backend.caipA(), mode: "qbft"}),
                deployAll({clients: B, privateKey: suite.privateKey, caipChainId: backend.caipB(), mode: "qbft"})
            ]);
            addrsA = a;
            addrsB = b;

            const conn = await wireChannel({
                chainA: A, chainB: B,
                caipA: backend.caipA(), caipB: backend.caipB(),
                addrsA: a, addrsB: b
            });
            channelId = conn.channelId;

            const block = await A.publicClient.getBlockNumber();
            await waitForBlock(backend.rpcA(), Number(block) + 2, 30_000);
        } else {
            // ── Stub path: E2EVerifier + BundleEncoderHelper (anvil / avalanche) ──
            const pair = await deployE2EPair({
                clientsA: A, clientsB: B,
                privateKey: suite.privateKey,
                caipChainIdA: backend.caipA(),
                caipChainIdB: backend.caipB()
            });
            addrsA = pair.addrsA;
            addrsB = pair.addrsB;

            await wireConfig({clients: A, addrs: pair.addrsA, soloRelay: false});
            await wireConfig({clients: B, addrs: pair.addrsB, soloRelay: false});

            await registerEndpoint({clients: A, clprService: pair.addrsA.clprService, soloRelay: false});
            await registerEndpoint({clients: B, clprService: pair.addrsB.clprService, soloRelay: false});

            const conn = await wireChannel({
                chainA: A, chainB: B,
                caipA: backend.caipA(), caipB: backend.caipB(),
                addrsA: pair.addrsA, addrsB: pair.addrsB
            });
            channelId = conn.channelId;
        }

        // Register the connector on chain A ONLY: a DATA message that references it will
        // not resolve on B, so B replies CONNECTOR_NOT_FOUND.
        connector = await wireConnector({
            chainA: A, chainB: B,
            addrsA, addrsB,
            channelId,
            stake: STAKE,
            skipChainB: true
        });

        // ── A→B: send a DATA message through connector D (first outbound → messageId 1).
        const service = loadArtifact("ClprService");
        const sendTx = await A.walletClient.writeContract({
            address: addrsA.clprService, abi: service.abi as never,
            functionName: "sendMessage",
            args: [channelId, connector.connectorId, addrsB.application, "0x48454c4c4f"] // "HELLO"
        });
        await A.publicClient.waitForTransactionReceipt({hash: sendTx});

        if (isBesu) {
            let block = await A.publicClient.getBlockNumber();
            await waitForBlock(backend.rpcA(), Number(block) + 2, 30_000);
            await ferryQbft({
                source: A, dest: B, sourceAddrs: addrsA, destAddrs: addrsB,
                channelId,
                range: {fromId: 1n, throughId: 1n}
            });

            // B enqueued a CONNECTOR_NOT_FOUND reply at its messageId 1 — ferry it back.
            block = await B.publicClient.getBlockNumber();
            await waitForBlock(backend.rpcB(), Number(block) + 2, 30_000);
            await ferryQbft({
                source: B, dest: A, sourceAddrs: addrsB, destAddrs: addrsA,
                channelId,
                range: {fromId: 1n, throughId: 1n}
            });
        } else {
            await ferry({
                source: A, dest: B,
                sourceAddrs: addrsA as {clprService: Hex; bundleEncoder: Hex},
                destAddrs: addrsB,
                channelId,
                range: {fromId: 1n, throughId: 1n}
            });

            // B enqueued a CONNECTOR_NOT_FOUND reply at its messageId 1 — ferry it back.
            await ferry({
                source: B, dest: A,
                sourceAddrs: addrsB as {clprService: Hex; bundleEncoder: Hex},
                destAddrs: addrsA,
                channelId,
                range: {fromId: 1n, throughId: 1n}
            });
        }
    }, 600_000);

    afterAll(async () => {
        await backend?.stop();
    });

    it("the failure reply slashed the source connector (partial, survives)", async () => {
        const service = loadArtifact("ClprService");
        const c = (await A.publicClient.readContract({
            address: addrsA.clprService, abi: service.abi as never,
            functionName: "getConnector",
            args: [channelId, connector.connectorId]
        })) as {lockedStake: bigint; slashCount: number};
        expect(c.slashCount).toBe(1);                 // slash fired exactly once
        expect(c.lockedStake).toBe(EXPECTED_REMAINING); // stake reduced by basePenalty, not wiped
    });

    it("A received the reply: ackedMessageId and receivedMessageId advanced to 1", async () => {
        const service = loadArtifact("ClprService");
        const conn = (await A.publicClient.readContract({
            address: addrsA.clprService, abi: service.abi as never,
            functionName: "getChannel", args: [channelId]
        })) as {ackedMessageId: bigint; receivedMessageId: bigint};
        expect(conn.ackedMessageId).toBe(1n);
        expect(conn.receivedMessageId).toBe(1n);
    });

    it("the slashed connector can still be deregistered, returning the remaining stake", async () => {
        const service = loadArtifact("ClprService");
        const recipient = "0x000000000000000000000000000000000000dEaD" as Hex;
        const feeToken = await getFeeToken(A, addrsA.clprService);
        const balBefore = await feeAssetBalance(A, feeToken, recipient);

        // admin == deployer (wireConnector default). The in-flight count MUST be 0 here,
        // otherwise removeConnector reverts with ClprConnectorHasInflightMessages.
        const tx = await A.walletClient.writeContract({
            address: addrsA.clprService, abi: service.abi as never,
            functionName: "removeConnector",
            args: [channelId, connector.connectorId, recipient]
        });
        const receipt = await A.publicClient.waitForTransactionReceipt({hash: tx});
        expect(receipt.status).toBe("success");

        const exists = await A.publicClient.readContract({
            address: addrsA.clprService, abi: service.abi as never,
            functionName: "hasConnector",
            args: [channelId, connector.connectorId]
        });
        expect(exists).toBe(false);

        const balAfter = await feeAssetBalance(A, feeToken, recipient);
        expect(balAfter - balBefore).toBe(EXPECTED_REMAINING); // remaining stake returned, not stuck
    });
});
