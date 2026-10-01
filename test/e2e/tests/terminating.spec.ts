import {afterAll, beforeAll, describe, expect, it} from "vitest";
import type {Hex} from "viem";
import {createBackend} from "../backend/index.js";
import type {Backend} from "../backend/Backend.js";
import type {ChainClients} from "../lib/clients.js";
import {provisionE2ESuite} from "../lib/provisionSuite.js";
import {loadArtifact} from "../../../script/deploy/artifacts.js";
import {deployE2EPair, type DeployedAddresses} from "../deploy/deploy.js";
import {wireConfig, registerEndpoint} from "../deploy/wire.js";
import {wireChannel, type WiredChannel} from "../deploy/wireChannel.js";
import {wireConnector, type WiredConnector} from "../deploy/wireConnector.js";
import {ferry} from "../relay/ferry.js";

// ── Helper Types ───────────────────────────────────────────────────────

interface ChannelState {
    channelId?: `0x${string}`;
    status: number;
    nextMessageId: bigint;
    ackedMessageId: bigint;
    receivedMessageId: bigint;
    nextExpectedReplyId: bigint;
    sentRunningHash: `0x${string}`;
    receivedRunningHash: `0x${string}`;
    ownershipCommitment?: `0x${string}`;
    verifier?: `0x${string}`;
    chainId?: string;
    peerServiceAddress?: `0x${string}`;
}

interface MessageIds {
    nextMessageId: bigint;
    ackedMessageId: bigint;
    receivedMessageId?: bigint;
    nextExpectedReplyId?: bigint;
}

// ── Helper Functions ───────────────────────────────────────────────────

const ZERO_HASH = "0x0000000000000000000000000000000000000000000000000000000000000000";

const REPLY_DATA = "0x57454c434f4d45" as Hex; // "WELCOME"
const REQUEST1 = "0x48454c4c4f" as Hex; // "HELLO"
const REQUEST2 = "0x574f524c44" as Hex; // "WORLD"

async function getChannelState(
    clients: ChainClients,
    clprService: Hex,
    channelId: Hex
): Promise<ChannelState> {
    const service = loadArtifact("ClprService");
    return (await clients.publicClient.readContract({
        address: clprService,
        abi: service.abi as never,
        functionName: "getChannel",
        args: [channelId]
    })) as ChannelState;
}

function expectMessageIds(conn: ChannelState, expected: MessageIds) {
    expect(conn.nextMessageId).toBe(expected.nextMessageId);
    expect(conn.ackedMessageId).toBe(expected.ackedMessageId);
    if (expected.receivedMessageId !== undefined) {
        expect(conn.receivedMessageId).toBe(expected.receivedMessageId);
    }
    if (expected.nextExpectedReplyId !== undefined) {
        expect(conn.nextExpectedReplyId).toBe(expected.nextExpectedReplyId);
    }
}

function expectRunningHashesZero(conn: ChannelState) {
    expect(conn.sentRunningHash).toBe(ZERO_HASH);
    expect(conn.receivedRunningHash).toBe(ZERO_HASH);
}

function expectRunningHashesNonZero(conn: ChannelState) {
    expect(conn.sentRunningHash).not.toBe(ZERO_HASH);
    expect(conn.receivedRunningHash).not.toBe(ZERO_HASH);
}

function expectEmptyChannel(conn: ChannelState, status: number) {
    expect(conn.status).toBe(status);
    expectMessageIds(conn, {
        nextMessageId: 1n,
        ackedMessageId: 0n,
        receivedMessageId: 0n,
        nextExpectedReplyId: 1n
    });
    expectRunningHashesZero(conn);
}

async function closeChannel(
    clients: ChainClients,
    clprService: Hex,
    channelId: Hex
): Promise<void> {
    const service = loadArtifact("ClprService");
    const closeTx = await clients.walletClient.writeContract({
        address: clprService,
        abi: service.abi as never,
        functionName: "closeChannel",
        args: [channelId]
    });
    await clients.publicClient.waitForTransactionReceipt({hash: closeTx});
}

async function sendDataMessage(
    clients: ChainClients,
    applicationAddr: Hex,
    clprService: Hex,
    channelId: Hex,
    connectorId: Hex,
    targetApp: Hex,
    payload: Hex
): Promise<void> {
    const appAbi = loadArtifact("E2EApplication").abi;
    const sendTx = await clients.walletClient.writeContract({
        address: applicationAddr,
        abi: appAbi as never,
        functionName: "send",
        args: [clprService, channelId, connectorId, targetApp, payload]
    });
    await clients.publicClient.waitForTransactionReceipt({hash: sendTx});
}

async function configureAppResponse(
    clients: ChainClients,
    applicationAddr: Hex,
    replyData: Hex
): Promise<void> {
    const appAbi = loadArtifact("E2EApplication").abi;
    const setResponseTx = await clients.walletClient.writeContract({
        address: applicationAddr,
        abi: appAbi as never,
        functionName: "setResponse",
        args: [replyData]
    });
    await clients.publicClient.waitForTransactionReceipt({hash: setResponseTx});
}

/// E2E tests for closing empty channels (no messages exchanged).
///
/// Tests verify three scenarios:
/// 1. Close initiated by A only
/// 2. Close initiated by B only
/// 3. Close initiated by both A & B
///
/// Each test validates storage slots (status, message IDs, running hashes)
/// throughout the channel close lifecycle.
describe("channel close lifecycle", () => {
    let backend: Backend;
    let A: ChainClients;
    let B: ChainClients;
    let addrsA: DeployedAddresses;
    let addrsB: DeployedAddresses;

    // ChannelStatus enum values
    const ACTIVE = 1;
    const CLOSING = 3;
    const DRAINED = 4;
    const CLOSED = 5;

    beforeAll(async () => {
        backend = createBackend();
        await backend.start();

        const suite = await provisionE2ESuite(backend, "channel-close");
        A = suite.clientsA;
        B = suite.clientsB;

        ({addrsA, addrsB} = await deployE2EPair({
            clientsA: A,
            clientsB: B,
            privateKey: suite.privateKey,
            protocolVersion: 1,
            caipChainIdA: backend.caipA(),
            caipChainIdB: backend.caipB()
        }));

        await wireConfig({clients: A, addrs: addrsA, soloRelay: backend.kindA() === "solo"});
        await wireConfig({clients: B, addrs: addrsB, soloRelay: backend.kindB() === "solo"});

        await registerEndpoint({clients: A, clprService: addrsA.clprService, soloRelay: backend.kindA() === "solo"});
        await registerEndpoint({clients: B, clprService: addrsB.clprService, soloRelay: backend.kindB() === "solo"});
    }, 600_000);

    afterAll(async () => {
        await backend?.stop();
    });

    it("close empty channel (initiated by A)", async () => {
        // Wire a fresh channel for this test
        const channel = await wireChannel({
            chainA: A, chainB: B,
            caipA: backend.caipA(), caipB: backend.caipB(),
            addrsA, addrsB
        });

        // Step 1: Verify both channels start ACTIVE
        const connAInitial = await getChannelState(A, addrsA.clprService, channel.channelId);
        const connBInitial = await getChannelState(B, addrsB.clprService, channel.channelId);
        expectEmptyChannel(connAInitial, ACTIVE);
        expectEmptyChannel(connBInitial, ACTIVE);

        // Step 2: A initiates close → straight to DRAINED (empty channel, no Data
        // Messages outstanding, so CLOSING and DRAINED are reached in the same call)
        await closeChannel(A, addrsA.clprService, channel.channelId);
        const connADrained = await getChannelState(A, addrsA.clprService, channel.channelId);
        expect(connADrained.status).toBe(DRAINED);
        expectMessageIds(connADrained, {nextMessageId: 1n, ackedMessageId: 0n});
        expectRunningHashesZero(connADrained);

        // Step 3: Ferry A→B → B learns A is DRAINED; B (also empty) cascades
        // ACTIVE→CLOSING→DRAINED→CLOSED in this same bundle
        await ferry({
            source: A,
            dest: B,
            sourceAddrs: addrsA,
            destAddrs: addrsB,
            channelId: channel.channelId,
            range: {fromId: 1n, throughId: 0n}
        });
        const connBClosed = await getChannelState(B, addrsB.clprService, channel.channelId);
        expect(connBClosed.status).toBe(CLOSED);
        expectMessageIds(connBClosed, {nextMessageId: 1n, ackedMessageId: 0n});
        expectRunningHashesZero(connBClosed);

        // Step 4: Ferry B→A → A learns B is CLOSED, transitions to CLOSED
        await ferry({
            source: B,
            dest: A,
            sourceAddrs: addrsB,
            destAddrs: addrsA,
            channelId: channel.channelId,
            range: {fromId: 1n, throughId: 0n}
        });
        const connAClosed = await getChannelState(A, addrsA.clprService, channel.channelId);
        expectEmptyChannel(connAClosed, CLOSED);
    }, 120_000);

    it("close empty channel (initiated by B)", async () => {
        // Wire a fresh channel for this test
        const channel = await wireChannel({
            chainA: A, chainB: B,
            caipA: backend.caipA(), caipB: backend.caipB(),
            addrsA, addrsB
        });

        // Step 1: Verify both channels start ACTIVE
        const connAInitial = await getChannelState(A, addrsA.clprService, channel.channelId);
        const connBInitial = await getChannelState(B, addrsB.clprService, channel.channelId);
        expectEmptyChannel(connAInitial, ACTIVE);
        expectEmptyChannel(connBInitial, ACTIVE);

        // Step 2: B initiates close → straight to DRAINED (empty channel, no Data
        // Messages outstanding, so CLOSING and DRAINED are reached in the same call)
        await closeChannel(B, addrsB.clprService, channel.channelId);
        const connBDrained = await getChannelState(B, addrsB.clprService, channel.channelId);
        expect(connBDrained.status).toBe(DRAINED);
        expectMessageIds(connBDrained, {nextMessageId: 1n, ackedMessageId: 0n});
        expectRunningHashesZero(connBDrained);

        // Step 3: Ferry B→A → A learns B is DRAINED; A (also empty) cascades
        // ACTIVE→CLOSING→DRAINED→CLOSED in this same bundle
        await ferry({
            source: B,
            dest: A,
            sourceAddrs: addrsB,
            destAddrs: addrsA,
            channelId: channel.channelId,
            range: {fromId: 1n, throughId: 0n}
        });
        const connAClosed = await getChannelState(A, addrsA.clprService, channel.channelId);
        expect(connAClosed.status).toBe(CLOSED);
        expectMessageIds(connAClosed, {nextMessageId: 1n, ackedMessageId: 0n});
        expectRunningHashesZero(connAClosed);

        // Step 4: Ferry A→B → B learns A is CLOSED, transitions to CLOSED
        await ferry({
            source: A,
            dest: B,
            sourceAddrs: addrsA,
            destAddrs: addrsB,
            channelId: channel.channelId,
            range: {fromId: 1n, throughId: 0n}
        });
        const connBClosed = await getChannelState(B, addrsB.clprService, channel.channelId);
        expectEmptyChannel(connBClosed, CLOSED);
    }, 120_000);

    it("close empty channel (initiated by A & B)", async () => {
        // Wire a fresh channel for this test
        const channel = await wireChannel({
            chainA: A, chainB: B,
            caipA: backend.caipA(), caipB: backend.caipB(),
            addrsA, addrsB
        });

        // Step 1: Verify both channels start ACTIVE with comprehensive storage slot checks
        const connAInitial = await getChannelState(A, addrsA.clprService, channel.channelId);
        const connBInitial = await getChannelState(B, addrsB.clprService, channel.channelId);
        
        expectEmptyChannel(connAInitial, ACTIVE);
        expectEmptyChannel(connBInitial, ACTIVE);
        
        // Validate storage slots: channel metadata is correct
        expect(connAInitial.channelId).toBe(channel.channelId);
        expect(connBInitial.channelId).toBe(channel.channelId);
        expect(connAInitial.verifier?.toLowerCase()).toBe(addrsA.verifier.toLowerCase());
        expect(connBInitial.verifier?.toLowerCase()).toBe(addrsB.verifier.toLowerCase());
        expect(connAInitial.chainId).toBe(backend.caipB()); // A's peer is B
        expect(connBInitial.chainId).toBe(backend.caipA()); // B's peer is A

        // Step 2: A initiates close → straight to DRAINED (empty channel, no Data
        // Messages outstanding, so CLOSING and DRAINED are reached in the same call)
        await closeChannel(A, addrsA.clprService, channel.channelId);
        const connADrained = await getChannelState(A, addrsA.clprService, channel.channelId);
        expectEmptyChannel(connADrained, DRAINED);

        // Step 3: B initiates close → straight to DRAINED, same reasoning
        await closeChannel(B, addrsB.clprService, channel.channelId);
        const connBDrained = await getChannelState(B, addrsB.clprService, channel.channelId);
        expectEmptyChannel(connBDrained, DRAINED);

        // Step 4: Ferry A→B (A DRAINED, B DRAINED) → B transitions to CLOSED
        await ferry({
            source: A,
            dest: B,
            sourceAddrs: addrsA,
            destAddrs: addrsB,
            channelId: channel.channelId,
            range: {fromId: 1n, throughId: 0n}
        });
        const connBClosed = await getChannelState(B, addrsB.clprService, channel.channelId);
        expectEmptyChannel(connBClosed, CLOSED);

        // Step 5: Ferry B→A → A transitions to CLOSED
        await ferry({
            source: B,
            dest: A,
            sourceAddrs: addrsB,
            destAddrs: addrsA,
            channelId: channel.channelId,
            range: {fromId: 1n, throughId: 0n}
        });
        const connAClosed = await getChannelState(A, addrsA.clprService, channel.channelId);
        expectEmptyChannel(connAClosed, CLOSED);

        // Step 6: Final comprehensive verification - channel metadata preserved
        const connAFinal = await getChannelState(A, addrsA.clprService, channel.channelId);
        const connBFinal = await getChannelState(B, addrsB.clprService, channel.channelId);
        expect(connAFinal.channelId).toBe(channel.channelId);
        expect(connBFinal.channelId).toBe(channel.channelId);
        expect(connAFinal.verifier?.toLowerCase()).toBe(addrsA.verifier.toLowerCase());
        expect(connBFinal.verifier?.toLowerCase()).toBe(addrsB.verifier.toLowerCase());
    }, 120_000);

    it("close with pending outbound messages", async () => {
        // Wire a fresh channel and connector for this test
        const channel = await wireChannel({
            chainA: A, chainB: B,
            caipA: backend.caipA(), caipB: backend.caipB(),
            addrsA, addrsB
        });

        const connector = await wireConnector({
            chainA: A, chainB: B,
            addrsA, addrsB,
            channelId: channel.channelId,
            soloRelayA: backend.kindA() === "solo",
            soloRelayB: backend.kindB() === "solo"
        });

        // Configure B's app to send replies
        await configureAppResponse(B, addrsB.application, REPLY_DATA);

        // Step 1: A sends 2 DATA messages to B
        await sendDataMessage(A, addrsA.application, addrsA.clprService, channel.channelId, connector.connectorId, addrsB.application, REQUEST1);
        await sendDataMessage(A, addrsA.application, addrsA.clprService, channel.channelId, connector.connectorId, addrsB.application, REQUEST2);

        // Verify A has 2 pending outbound messages
        const connAAfterSend = await getChannelState(A, addrsA.clprService, channel.channelId);
        expect(connAAfterSend.status).toBe(ACTIVE);
        expectMessageIds(connAAfterSend, {nextMessageId: 3n, ackedMessageId: 0n});
        expect(connAAfterSend.sentRunningHash).not.toBe(ZERO_HASH);

        // Step 2: A initiates close while messages are pending
        await closeChannel(A, addrsA.clprService, channel.channelId);
        const connAClosing = await getChannelState(A, addrsA.clprService, channel.channelId);
        expect(connAClosing.status).toBe(CLOSING);
        expectMessageIds(connAClosing, {nextMessageId: 3n, ackedMessageId: 0n});

        // Step 3: Ferry A→B - B receives both messages and generates replies
        await ferry({
            source: A,
            dest: B,
            sourceAddrs: addrsA,
            destAddrs: addrsB,
            channelId: channel.channelId,
            range: {fromId: 1n, throughId: 2n}
        });
        const connBAfterReceive = await getChannelState(B, addrsB.clprService, channel.channelId);
        // B has no outbound DATA (lastDataMessageId=0), so CLOSING→DRAINED fires immediately.
        expect(connBAfterReceive.status).toBe(DRAINED);
        expect(connBAfterReceive.nextMessageId).toBe(3n);
        expect(connBAfterReceive.receivedMessageId).toBe(2n);

        // Step 4: Ferry B→A - A receives replies and acks; B is DRAINED so A goes CLOSING→DRAINED→CLOSED
        await ferry({
            source: B,
            dest: A,
            sourceAddrs: addrsB,
            destAddrs: addrsA,
            channelId: channel.channelId,
            range: {fromId: 1n, throughId: 2n}
        });
        const connAAfterAcks = await getChannelState(A, addrsA.clprService, channel.channelId);
        // A's DATA#1 and DATA#2 are acked (ackedMessageId=2 >= lastDataMessageId=2) → DRAINED,
        // and peer (B) is already DRAINED with allAcked → CLOSED in the same bundle.
        expect(connAAfterAcks.status).toBe(CLOSED);
        expectMessageIds(connAAfterAcks, {nextMessageId: 3n, ackedMessageId: 2n, receivedMessageId: 2n, nextExpectedReplyId: 3n});

        // Step 5: Ferry A→B - B learns A is CLOSED and transitions to CLOSED
        await ferry({
            source: A,
            dest: B,
            sourceAddrs: addrsA,
            destAddrs: addrsB,
            channelId: channel.channelId,
            range: {fromId: 3n, throughId: 2n}
        });
        const connBClosed = await getChannelState(B, addrsB.clprService, channel.channelId);
        expect(connBClosed.status).toBe(CLOSED);
        expectMessageIds(connBClosed, {nextMessageId: 3n, ackedMessageId: 2n});

        // A is already CLOSED from step 4 (no further ferry needed).
        const connAFinal = await getChannelState(A, addrsA.clprService, channel.channelId);
        expect(connAFinal.status).toBe(CLOSED);
        expectMessageIds(connAFinal, {nextMessageId: 3n, ackedMessageId: 2n, receivedMessageId: 2n, nextExpectedReplyId: 3n});
        expectRunningHashesNonZero(connAFinal);
    }, 120_000);

    it("close with inbound messages during drain", async () => {
        // Wire a fresh channel and connector for this test
        const channel = await wireChannel({
            chainA: A, chainB: B,
            caipA: backend.caipA(), caipB: backend.caipB(),
            addrsA, addrsB
        });

        const connector = await wireConnector({
            chainA: A, chainB: B,
            addrsA, addrsB,
            channelId: channel.channelId,
            soloRelayA: backend.kindA() === "solo",
            soloRelayB: backend.kindB() === "solo"
        });

        const service = loadArtifact("ClprService");
        const appAbi = loadArtifact("E2EApplication").abi;

        // Configure A's app to send replies
        const setResponseTx = await A.walletClient.writeContract({
            address: addrsA.application,
            abi: appAbi as never,
            functionName: "setResponse",
            args: [REPLY_DATA]
        });
        await A.publicClient.waitForTransactionReceipt({hash: setResponseTx});

        // Step 1: A initiates close on empty channel → straight to DRAINED (no Data
        // Messages outstanding, so CLOSING and DRAINED are reached in the same call)
        const closeTxA = await A.walletClient.writeContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "closeChannel",
            args: [channel.channelId]
        });
        await A.publicClient.waitForTransactionReceipt({hash: closeTxA});

        const connADrained = (await A.publicClient.readContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            nextMessageId: bigint;
        };

        expect(connADrained.status).toBe(DRAINED);
        expect(connADrained.nextMessageId).toBe(1n);

        // Step 2: B sends messages to A (while A is DRAINED)
        const sendTx1 = await B.walletClient.writeContract({
            address: addrsB.application,
            abi: appAbi as never,
            functionName: "send",
            args: [
                addrsB.clprService,
                channel.channelId,
                connector.connectorId,
                addrsA.application,
                REQUEST1
            ]
        });
        await B.publicClient.waitForTransactionReceipt({hash: sendTx1});

        const sendTx2 = await B.walletClient.writeContract({
            address: addrsB.application,
            abi: appAbi as never,
            functionName: "send",
            args: [
                addrsB.clprService,
                channel.channelId,
                connector.connectorId,
                addrsA.application,
                REQUEST2
            ]
        });
        await B.publicClient.waitForTransactionReceipt({hash: sendTx2});

        // Verify B has 2 pending outbound messages
        const connBAfterSend = (await B.publicClient.readContract({
            address: addrsB.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            nextMessageId: bigint;
            ackedMessageId: bigint;
        };

        expect(connBAfterSend.status).toBe(ACTIVE);
        expect(connBAfterSend.nextMessageId).toBe(3n); // sent 2 messages
        expect(connBAfterSend.ackedMessageId).toBe(0n);

        // Step 3: Ferry B→A - A receives messages while CLOSING and generates replies
        await ferry({
            source: B, dest: A,
            sourceAddrs: addrsB, destAddrs: addrsA,
            channelId: channel.channelId,
            range: {fromId: 1n, throughId: 2n}
        });

        // A was already DRAINED from the admin close in Step 1 and stays DRAINED: DATA
        // Messages are still dispatched normally while DRAINED, generating replies.
        const connAAfterReceive = (await A.publicClient.readContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            nextMessageId: bigint;
            receivedMessageId: bigint;
            ackedMessageId: bigint;
            sentRunningHash: `0x${string}`;
            receivedRunningHash: `0x${string}`;
        };

        expect(connAAfterReceive.status).toBe(DRAINED);
        expect(connAAfterReceive.receivedMessageId).toBe(2n); // received 2 DATA messages
        expect(connAAfterReceive.nextMessageId).toBe(3n); // sent 2 REPLY messages
        expect(connAAfterReceive.ackedMessageId).toBe(0n); // no outbound DATA to ack
        expect(connAAfterReceive.receivedRunningHash).not.toBe(ZERO_HASH);

        // Step 4: Ferry A→B - B receives replies and acks
        await ferry({
            source: A, dest: B,
            sourceAddrs: addrsA, destAddrs: addrsB,
            channelId: channel.channelId,
            range: {fromId: 1n, throughId: 2n}
        });

        const connBAfterAcks = (await B.publicClient.readContract({
            address: addrsB.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            ackedMessageId: bigint;
            receivedMessageId: bigint;
        };

        // B's DATA#1 and DATA#2 are acked (ackedMessageId=2 >= lastDataMessageId=2) → DRAINED,
        // and peer (A) is already DRAINED with allAcked → CLOSED in the same bundle.
        expect(connBAfterAcks.status).toBe(CLOSED);
        expect(connBAfterAcks.ackedMessageId).toBe(2n); // both DATA messages acked
        expect(connBAfterAcks.receivedMessageId).toBe(2n); // received 2 replies

        // Step 5: Ferry B→A with B now CLOSED - A learns B is CLOSED and transitions to CLOSED
        await ferry({
            source: B, dest: A,
            sourceAddrs: addrsB, destAddrs: addrsA,
            channelId: channel.channelId,
            range: {fromId: 3n, throughId: 2n} // empty bundle
        });

        const connAAfterLearnDrained = (await A.publicClient.readContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            nextMessageId: bigint;
            ackedMessageId: bigint;
        };

        // A transitions directly to CLOSED (was CLOSING, learned peer is DRAINED)
        expect(connAAfterLearnDrained.status).toBe(CLOSED);
        expect(connAAfterLearnDrained.nextMessageId).toBe(3n);
        expect(connAAfterLearnDrained.ackedMessageId).toBe(2n); // A acked 2 REPLY messages from B

        // B is already CLOSED from step 4 (no further ferry needed).
        const connBFinal = (await B.publicClient.readContract({
            address: addrsB.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            nextMessageId: bigint;
            ackedMessageId: bigint;
            receivedMessageId: bigint;
            nextExpectedReplyId: bigint;
            sentRunningHash: `0x${string}`;
            receivedRunningHash: `0x${string}`;
        };

        // Validate storage slots: final state is CLOSED on both sides with inbound messages processed
        expect(connBFinal.status).toBe(CLOSED);
        expect(connBFinal.nextMessageId).toBe(3n);
        expect(connBFinal.ackedMessageId).toBe(2n);
        expect(connBFinal.receivedMessageId).toBe(2n);
        expect(connBFinal.nextExpectedReplyId).toBe(3n); // B sent 2 DATA messages
        expect(connBFinal.sentRunningHash).not.toBe(ZERO_HASH);
        expect(connBFinal.receivedRunningHash).not.toBe(ZERO_HASH);
    }, 120_000);

    it("close with bidirectional message exchange", async () => {
        // Wire a fresh channel and connector for this test
        const channel = await wireChannel({
            chainA: A, chainB: B,
            caipA: backend.caipA(), caipB: backend.caipB(),
            addrsA, addrsB
        });

        const connector = await wireConnector({
            chainA: A, chainB: B,
            addrsA, addrsB,
            channelId: channel.channelId,
            soloRelayA: backend.kindA() === "solo",
            soloRelayB: backend.kindB() === "solo"
        });

        const service = loadArtifact("ClprService");
        const appAbi = loadArtifact("E2EApplication").abi;

        // Configure both apps to send replies
        const setResponseTxA = await A.walletClient.writeContract({
            address: addrsA.application,
            abi: appAbi as never,
            functionName: "setResponse",
            args: [REPLY_DATA]
        });
        await A.publicClient.waitForTransactionReceipt({hash: setResponseTxA});

        const setResponseTxB = await B.walletClient.writeContract({
            address: addrsB.application,
            abi: appAbi as never,
            functionName: "setResponse",
            args: [REPLY_DATA]
        });
        await B.publicClient.waitForTransactionReceipt({hash: setResponseTxB});

        // Step 1: Both A and B send messages
        const sendTxA = await A.walletClient.writeContract({
            address: addrsA.application,
            abi: appAbi as never,
            functionName: "send",
            args: [
                addrsA.clprService,
                channel.channelId,
                connector.connectorId,
                addrsB.application,
                REQUEST1
            ]
        });
        await A.publicClient.waitForTransactionReceipt({hash: sendTxA});

        const sendTxB = await B.walletClient.writeContract({
            address: addrsB.application,
            abi: appAbi as never,
            functionName: "send",
            args: [
                addrsB.clprService,
                channel.channelId,
                connector.connectorId,
                addrsA.application,
                REQUEST2
            ]
        });
        await B.publicClient.waitForTransactionReceipt({hash: sendTxB});

        // Verify both have pending outbound messages
        const connAAfterSend = (await A.publicClient.readContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            nextMessageId: bigint;
            ackedMessageId: bigint;
        };

        const connBAfterSend = (await B.publicClient.readContract({
            address: addrsB.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            nextMessageId: bigint;
            ackedMessageId: bigint;
        };

        expect(connAAfterSend.status).toBe(ACTIVE);
        expect(connAAfterSend.nextMessageId).toBe(2n); // sent 1 message
        expect(connAAfterSend.ackedMessageId).toBe(0n);
        expect(connBAfterSend.status).toBe(ACTIVE);
        expect(connBAfterSend.nextMessageId).toBe(2n); // sent 1 message
        expect(connBAfterSend.ackedMessageId).toBe(0n);

        // Step 2: Both A and B initiate close
        const closeTxA = await A.walletClient.writeContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "closeChannel",
            args: [channel.channelId]
        });
        await A.publicClient.waitForTransactionReceipt({hash: closeTxA});

        const closeTxB = await B.walletClient.writeContract({
            address: addrsB.clprService,
            abi: service.abi as never,
            functionName: "closeChannel",
            args: [channel.channelId]
        });
        await B.publicClient.waitForTransactionReceipt({hash: closeTxB});

        // Verify both are CLOSING
        const connAClosing = (await A.publicClient.readContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {status: number};

        const connBClosing = (await B.publicClient.readContract({
            address: addrsB.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {status: number};

        expect(connAClosing.status).toBe(CLOSING);
        expect(connBClosing.status).toBe(CLOSING);

        // Step 3: Ferry A→B - B receives A's message and generates reply
        await ferry({
            source: A, dest: B,
            sourceAddrs: addrsA, destAddrs: addrsB,
            channelId: channel.channelId,
            range: {fromId: 1n, throughId: 1n}
        });

        const connBAfterReceiveA = (await B.publicClient.readContract({
            address: addrsB.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            receivedMessageId: bigint;
            nextMessageId: bigint;
        };

        // B learned A is CLOSING; B sent 1 DATA (lastDataMessageId=1), ackedMessageId=0 < 1 → stays CLOSING.
        expect(connBAfterReceiveA.status).toBe(CLOSING);
        expect(connBAfterReceiveA.receivedMessageId).toBe(1n);
        expect(connBAfterReceiveA.nextMessageId).toBe(3n); // sent 1 DATA + 1 REPLY

        // Step 4: Ferry B→A - A receives B's message and reply, generates reply
        await ferry({
            source: B, dest: A,
            sourceAddrs: addrsB, destAddrs: addrsA,
            channelId: channel.channelId,
            range: {fromId: 1n, throughId: 2n} // DATA at id=1, REPLY at id=2
        });

        const connAAfterReceiveB = (await A.publicClient.readContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            receivedMessageId: bigint;
            ackedMessageId: bigint;
            nextMessageId: bigint;
        };

        // A's DATA#1 acked (ackedMessageId=1 >= lastDataMessageId=1) → DRAINED.
        expect(connAAfterReceiveB.status).toBe(DRAINED);
        expect(connAAfterReceiveB.receivedMessageId).toBe(2n); // received DATA + REPLY
        expect(connAAfterReceiveB.ackedMessageId).toBe(1n); // A's DATA acked by B
        expect(connAAfterReceiveB.nextMessageId).toBe(3n); // sent 1 DATA + 1 REPLY

        // Step 5: Ferry A→B - B receives A's reply and ack
        await ferry({
            source: A, dest: B,
            sourceAddrs: addrsA, destAddrs: addrsB,
            channelId: channel.channelId,
            range: {fromId: 2n, throughId: 2n} // REPLY at id=2
        });

        const connBAfterAck = (await B.publicClient.readContract({
            address: addrsB.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            ackedMessageId: bigint;
            receivedMessageId: bigint;
        };

        // B's DATA#1 acked (ackedMessageId=2 >= lastDataMessageId=1) → DRAINED,
        // and peer (A) is DRAINED with allAcked → CLOSED in the same bundle.
        expect(connBAfterAck.status).toBe(CLOSED);
        expect(connBAfterAck.ackedMessageId).toBe(2n); // B's DATA + REPLY both acked by A
        expect(connBAfterAck.receivedMessageId).toBe(2n); // received DATA + REPLY

        // Step 6: Ferry B→A - A gets empty bundle and learns B is CLOSED, A transitions to CLOSED
        await ferry({
            source: B, dest: A,
            sourceAddrs: addrsB, destAddrs: addrsA,
            channelId: channel.channelId,
            range: {fromId: 3n, throughId: 2n} // empty bundle
        });

        const connAAfterLearnDrained = (await A.publicClient.readContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            ackedMessageId: bigint;
        };

        // A transitions directly to CLOSED (was CLOSING, learned peer is DRAINED)
        expect(connAAfterLearnDrained.status).toBe(CLOSED);
        expect(connAAfterLearnDrained.ackedMessageId).toBe(2n); // A acked DATA + REPLY from B

        // B is already CLOSED from step 5 (no further ferry needed).
        // Verify B transitioned to CLOSED
        const connBFinal = (await B.publicClient.readContract({
            address: addrsB.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            nextMessageId: bigint;
            ackedMessageId: bigint;
            receivedMessageId: bigint;
            nextExpectedReplyId: bigint;
            sentRunningHash: `0x${string}`;
            receivedRunningHash: `0x${string}`;
        };

        // Validate storage slots: B also reached CLOSED with all messages processed
        expect(connBFinal.status).toBe(CLOSED);
        expect(connBFinal.nextMessageId).toBe(3n);
        expect(connBFinal.ackedMessageId).toBe(2n); // B's DATA + REPLY both acked
        expect(connBFinal.receivedMessageId).toBe(2n); // received DATA + REPLY
        expect(connBFinal.nextExpectedReplyId).toBe(3n); // B sent 1 DATA + 1 REPLY
        expect(connBFinal.sentRunningHash).not.toBe(ZERO_HASH);
        expect(connBFinal.receivedRunningHash).not.toBe(ZERO_HASH);
    }, 120_000);

    it("close with message during drain", async () => {
        // Wire a fresh channel and connector for this test
        const channel = await wireChannel({
            chainA: A, chainB: B,
            caipA: backend.caipA(), caipB: backend.caipB(),
            addrsA, addrsB
        });

        const connector = await wireConnector({
            chainA: A, chainB: B,
            addrsA, addrsB,
            channelId: channel.channelId,
            soloRelayA: backend.kindA() === "solo",
            soloRelayB: backend.kindB() === "solo"
        });

        const service = loadArtifact("ClprService");
        const appAbi = loadArtifact("E2EApplication").abi;

        // Configure B's app to send replies
        const setResponseTx = await B.walletClient.writeContract({
            address: addrsB.application,
            abi: appAbi as never,
            functionName: "setResponse",
            args: [REPLY_DATA]
        });
        await B.publicClient.waitForTransactionReceipt({hash: setResponseTx});

        // Step 1: Verify channel starts ACTIVE with correct storage slots
        const connAInitial = (await A.publicClient.readContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            nextMessageId: bigint;
            ackedMessageId: bigint;
            receivedMessageId: bigint;
            sentRunningHash: `0x${string}`;
            receivedRunningHash: `0x${string}`;
        };

        expect(connAInitial.status).toBe(ACTIVE);
        expect(connAInitial.nextMessageId).toBe(1n);
        expect(connAInitial.ackedMessageId).toBe(0n);
        expect(connAInitial.receivedMessageId).toBe(0n);
        expect(connAInitial.sentRunningHash).toBe(ZERO_HASH);
        expect(connAInitial.receivedRunningHash).toBe(ZERO_HASH);

        // Step 2: A sends a message to B
        const sendTx = await A.walletClient.writeContract({
            address: addrsA.application,
            abi: appAbi as never,
            functionName: "send",
            args: [
                addrsA.clprService,
                channel.channelId,
                connector.connectorId,
                addrsB.application,
                REQUEST1
            ]
        });
        await A.publicClient.waitForTransactionReceipt({hash: sendTx});

        // Verify A has 1 pending outbound message
        const connAAfterSend = (await A.publicClient.readContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            nextMessageId: bigint;
            ackedMessageId: bigint;
            sentRunningHash: `0x${string}`;
        };

        expect(connAAfterSend.status).toBe(ACTIVE);
        expect(connAAfterSend.nextMessageId).toBe(2n);
        expect(connAAfterSend.ackedMessageId).toBe(0n);
        expect(connAAfterSend.sentRunningHash).not.toBe(ZERO_HASH);

        // Step 3: A initiates close while message is pending
        const closeTxA = await A.walletClient.writeContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "closeChannel",
            args: [channel.channelId]
        });
        await A.publicClient.waitForTransactionReceipt({hash: closeTxA});

        const connAClosing = (await A.publicClient.readContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            nextMessageId: bigint;
            ackedMessageId: bigint;
            receivedMessageId: bigint;
            sentRunningHash: `0x${string}`;
            receivedRunningHash: `0x${string}`;
        };

        expect(connAClosing.status).toBe(CLOSING);
        expect(connAClosing.nextMessageId).toBe(2n);
        expect(connAClosing.ackedMessageId).toBe(0n); // No acks yet from B
        expect(connAClosing.receivedMessageId).toBe(0n); // No replies received yet
        expect(connAClosing.sentRunningHash).not.toBe(ZERO_HASH);

        // Step 4: Ferry A→B - B receives message, generates reply, learns A is CLOSING
        await ferry({
            source: A, dest: B,
            sourceAddrs: addrsA, destAddrs: addrsB,
            channelId: channel.channelId,
            range: {fromId: 1n, throughId: 1n}
        });

        const connBAfterReceive = (await B.publicClient.readContract({
            address: addrsB.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            nextMessageId: bigint;
            receivedMessageId: bigint;
            ackedMessageId: bigint;
            sentRunningHash: `0x${string}`;
            receivedRunningHash: `0x${string}`;
        };

        // B learned A is CLOSING; B has no outbound DATA (lastDataMessageId=0) → DRAINED immediately.
        expect(connBAfterReceive.status).toBe(DRAINED);
        expect(connBAfterReceive.receivedMessageId).toBe(1n); // Processed the DATA message
        expect(connBAfterReceive.nextMessageId).toBe(2n); // Sent 1 REPLY message
        expect(connBAfterReceive.receivedRunningHash).not.toBe(ZERO_HASH);
        expect(connBAfterReceive.sentRunningHash).not.toBe(ZERO_HASH);

        // Step 5: Ferry B→A - A receives B's reply and acks A's message
        await ferry({
            source: B, dest: A,
            sourceAddrs: addrsB, destAddrs: addrsA,
            channelId: channel.channelId,
            range: {fromId: 1n, throughId: 1n}
        });

        const connAAfterAcks = (await A.publicClient.readContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            nextMessageId: bigint;
            ackedMessageId: bigint;
            receivedMessageId: bigint;
            nextExpectedReplyId: bigint;
            sentRunningHash: `0x${string}`;
            receivedRunningHash: `0x${string}`;
        };

        // A's DATA#1 acked (ackedMessageId=1 >= lastDataMessageId=1) → DRAINED,
        // and peer (B) is already DRAINED with allAcked → CLOSED in the same bundle.
        expect(connAAfterAcks.status).toBe(CLOSED);
        expect(connAAfterAcks.ackedMessageId).toBe(1n); // B acked A's DATA message
        expect(connAAfterAcks.receivedMessageId).toBe(1n); // A received B's REPLY
        expect(connAAfterAcks.nextExpectedReplyId).toBe(2n);
        expect(connAAfterAcks.receivedRunningHash).not.toBe(ZERO_HASH);

        // Step 6: Ferry A→B - B learns A is CLOSED (via metadata) and transitions to CLOSED
        await ferry({
            source: A, dest: B,
            sourceAddrs: addrsA, destAddrs: addrsB,
            channelId: channel.channelId,
            range: {fromId: 2n, throughId: 1n} // empty bundle
        });

        const connBAfterLearnDrained = (await B.publicClient.readContract({
            address: addrsB.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            nextMessageId: bigint;
            ackedMessageId: bigint;
            receivedMessageId: bigint;
            sentRunningHash: `0x${string}`;
            receivedRunningHash: `0x${string}`;
        };

        // B should transition to CLOSED (was ACTIVE, learned peer is DRAINED, B has no outbound DATA)
        expect(connBAfterLearnDrained.status).toBe(CLOSED);
        expect(connBAfterLearnDrained.nextMessageId).toBe(2n); // Sent 1 REPLY
        expect(connBAfterLearnDrained.ackedMessageId).toBe(1n); // B's REPLY acked by A
        expect(connBAfterLearnDrained.receivedMessageId).toBe(1n); // Received A's DATA
        expect(connBAfterLearnDrained.sentRunningHash).not.toBe(ZERO_HASH);
        expect(connBAfterLearnDrained.receivedRunningHash).not.toBe(ZERO_HASH);

        // A is already CLOSED from step 5 (no further ferry needed).
        const connAFinal = (await A.publicClient.readContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            nextMessageId: bigint;
            ackedMessageId: bigint;
            receivedMessageId: bigint;
            sentRunningHash: `0x${string}`;
            receivedRunningHash: `0x${string}`;
        };

        // Validate storage slots: final state is CLOSED with all messages processed
        expect(connAFinal.status).toBe(CLOSED);
        expect(connAFinal.nextMessageId).toBe(2n);
        expect(connAFinal.ackedMessageId).toBe(1n);
        expect(connAFinal.receivedMessageId).toBe(1n);
        expect(connAFinal.sentRunningHash).not.toBe(ZERO_HASH);
        expect(connAFinal.receivedRunningHash).not.toBe(ZERO_HASH);
    }, 120_000);

    it("complete lifecycle (exchange message, then close)", async () => {
        // Wire a fresh channel and connector for this test
        const channel = await wireChannel({
            chainA: A, chainB: B,
            caipA: backend.caipA(), caipB: backend.caipB(),
            addrsA, addrsB
        });

        const connector = await wireConnector({
            chainA: A, chainB: B,
            addrsA, addrsB,
            channelId: channel.channelId,
            soloRelayA: backend.kindA() === "solo",
            soloRelayB: backend.kindB() === "solo"
        });

        const service = loadArtifact("ClprService");
        const appAbi = loadArtifact("E2EApplication").abi;

        // Configure B's app to send replies
        const setResponseTx = await B.walletClient.writeContract({
            address: addrsB.application,
            abi: appAbi as never,
            functionName: "setResponse",
            args: [REPLY_DATA]
        });
        await B.publicClient.waitForTransactionReceipt({hash: setResponseTx});

        // Step 1: Verify channel starts ACTIVE with correct storage slots
        const connAInitial = (await A.publicClient.readContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            nextMessageId: bigint;
            ackedMessageId: bigint;
            receivedMessageId: bigint;
            sentRunningHash: `0x${string}`;
            receivedRunningHash: `0x${string}`;
        };

        expect(connAInitial.status).toBe(ACTIVE);
        expect(connAInitial.nextMessageId).toBe(1n);
        expect(connAInitial.ackedMessageId).toBe(0n);
        expect(connAInitial.receivedMessageId).toBe(0n);
        expect(connAInitial.sentRunningHash).toBe(ZERO_HASH);
        expect(connAInitial.receivedRunningHash).toBe(ZERO_HASH);

        // Step 2: A sends a message to B
        const REQUEST = "0x48454c4c4f" as Hex; // "HELLO"
        const sendTx = await A.walletClient.writeContract({
            address: addrsA.application,
            abi: appAbi as never,
            functionName: "send",
            args: [
                addrsA.clprService,
                channel.channelId,
                connector.connectorId,
                addrsB.application,
                REQUEST
            ]
        });
        await A.publicClient.waitForTransactionReceipt({hash: sendTx});

        // Verify A has 1 pending outbound message
        const connAAfterSend = (await A.publicClient.readContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            nextMessageId: bigint;
            ackedMessageId: bigint;
            sentRunningHash: `0x${string}`;
        };

        expect(connAAfterSend.status).toBe(ACTIVE);
        expect(connAAfterSend.nextMessageId).toBe(2n);
        expect(connAAfterSend.ackedMessageId).toBe(0n);
        expect(connAAfterSend.sentRunningHash).not.toBe(ZERO_HASH);

        // Step 3: Ferry A→B - B receives message and generates reply (both still ACTIVE)
        await ferry({
            source: A, dest: B,
            sourceAddrs: addrsA, destAddrs: addrsB,
            channelId: channel.channelId,
            range: {fromId: 1n, throughId: 1n}
        });

        const connBAfterReceive = (await B.publicClient.readContract({
            address: addrsB.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            nextMessageId: bigint;
            receivedMessageId: bigint;
            sentRunningHash: `0x${string}`;
            receivedRunningHash: `0x${string}`;
        };

        expect(connBAfterReceive.status).toBe(ACTIVE); // B still ACTIVE (no close initiated)
        expect(connBAfterReceive.receivedMessageId).toBe(1n); // Processed the DATA message
        expect(connBAfterReceive.nextMessageId).toBe(2n); // Sent 1 REPLY message
        expect(connBAfterReceive.receivedRunningHash).not.toBe(ZERO_HASH);
        expect(connBAfterReceive.sentRunningHash).not.toBe(ZERO_HASH);

        // Step 4: Ferry B→A - A receives B's reply and acks (message exchange complete, both ACTIVE)
        await ferry({
            source: B, dest: A,
            sourceAddrs: addrsB, destAddrs: addrsA,
            channelId: channel.channelId,
            range: {fromId: 1n, throughId: 1n}
        });

        const connAAfterReply = (await A.publicClient.readContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            nextMessageId: bigint;
            ackedMessageId: bigint;
            receivedMessageId: bigint;
            nextExpectedReplyId: bigint;
            sentRunningHash: `0x${string}`;
            receivedRunningHash: `0x${string}`;
        };

        // Message exchange completed successfully - both channels still ACTIVE
        expect(connAAfterReply.status).toBe(ACTIVE);
        expect(connAAfterReply.ackedMessageId).toBe(1n); // B acked A's DATA message
        expect(connAAfterReply.receivedMessageId).toBe(1n); // A received B's REPLY
        expect(connAAfterReply.nextExpectedReplyId).toBe(2n);
        expect(connAAfterReply.receivedRunningHash).not.toBe(ZERO_HASH);

        // Step 5: NOW initiate close after successful message exchange. A's one DATA
        // Message is already acked and answered (nextExpectedReplyId=2 above), so this
        // goes straight to DRAINED instead of stopping at CLOSING.
        const closeTxA = await A.walletClient.writeContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "closeChannel",
            args: [channel.channelId]
        });
        await A.publicClient.waitForTransactionReceipt({hash: closeTxA});

        const connADrained = (await A.publicClient.readContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            nextMessageId: bigint;
            ackedMessageId: bigint;
            receivedMessageId: bigint;
            sentRunningHash: `0x${string}`;
            receivedRunningHash: `0x${string}`;
        };

        expect(connADrained.status).toBe(DRAINED);
        expect(connADrained.nextMessageId).toBe(2n); // No new messages after close
        expect(connADrained.ackedMessageId).toBe(1n); // Previous ack preserved
        expect(connADrained.receivedMessageId).toBe(1n); // Previous receive preserved

        // Step 6: Ferry A→B - B learns A is DRAINED and transitions to CLOSED
        await ferry({
            source: A, dest: B,
            sourceAddrs: addrsA, destAddrs: addrsB,
            channelId: channel.channelId,
            range: {fromId: 2n, throughId: 1n} // empty bundle
        });

        const connBClosed = (await B.publicClient.readContract({
            address: addrsB.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            nextMessageId: bigint;
            ackedMessageId: bigint;
            receivedMessageId: bigint;
        };

        expect(connBClosed.status).toBe(CLOSED);
        expect(connBClosed.nextMessageId).toBe(2n);
        expect(connBClosed.ackedMessageId).toBe(1n);
        expect(connBClosed.receivedMessageId).toBe(1n);

        // Step 7: Ferry B→A - A transitions to CLOSED
        await ferry({
            source: B, dest: A,
            sourceAddrs: addrsB, destAddrs: addrsA,
            channelId: channel.channelId,
            range: {fromId: 2n, throughId: 1n} // empty bundle
        });

        const connAFinal = (await A.publicClient.readContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "getChannel",
            args: [channel.channelId]
        })) as {
            status: number;
            nextMessageId: bigint;
            ackedMessageId: bigint;
            receivedMessageId: bigint;
            nextExpectedReplyId: bigint;
            sentRunningHash: `0x${string}`;
            receivedRunningHash: `0x${string}`;
        };

        // Validate storage slots: final state is CLOSED with message exchange preserved
        expect(connAFinal.status).toBe(CLOSED);
        expect(connAFinal.nextMessageId).toBe(2n);
        expect(connAFinal.ackedMessageId).toBe(1n);
        expect(connAFinal.receivedMessageId).toBe(1n);
        expect(connAFinal.nextExpectedReplyId).toBe(2n);
        expect(connAFinal.sentRunningHash).not.toBe(ZERO_HASH);
        expect(connAFinal.receivedRunningHash).not.toBe(ZERO_HASH);
    }, 120_000);
}, 180_000);
