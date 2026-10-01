import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {type Hex} from "viem";
import {createBackend} from "../backend/index.js";
import type {Backend} from "../backend/Backend.js";
import type {ChainClients} from "../lib/clients.js";
import {provisionE2ESuite} from "../lib/provisionSuite.js";
import {loadArtifact} from "../../../script/deploy/artifacts.js";
import {deployAll, deployE2EPair} from "../deploy/deploy.js";
import {wireConfig, registerEndpoint} from "../deploy/wire.js";
import {wireChannel} from "../deploy/wireChannel.js";
import {wireConnector, type WiredConnector} from "../deploy/wireConnector.js";
import {ferry, ferryQbft} from "../relay/ferry.js";
import {waitForBlock} from "../lib/qbft.js";

/// Full A→B→A bidirectional roundtrip.
///
///   1. E2EApplication.A.send("HELLO" → E2EApplication.B)
///   2. relay: ferry messageId=1 from A to B
///   3. B dispatches DATA → E2EApplication.B.onClprMessage records it
///      AND B enqueues a REPLY message at its outbound messageId=1
///   4. relay: ferry messageId=1 from B back to A
///   5. A dispatches REPLY → E2EApplication.A.onClprResponse records it
///      AND A's bookkeeping advances ackedMessageId, decrements inflight
///
/// On a Besu backend, uses QBFTVerifier + real EVM state proofs.
/// On Anvil/Solo, uses E2EVerifier (stub) + BundleEncoderHelper.
///
/// What each step proves:
///   - Step 2 = the source-to-dest wire format works (Phase D, validated).
///   - Step 4 = the dest-to-source REPLY wire format works (Phase E, this).
///   - Step 5 = the application-level callback fires because the sender we
///     stamped on outbound DATA was a CONTRACT (E2EApplication.A), not an EOA.
describe("roundtrip A->B->A (full bidirectional)", () => {
    let backend: Backend;
    let A: ChainClients;
    let B: ChainClients;
    let addrsA: {clprService: Hex; application: Hex; connectorContract: Hex; bundleEncoder?: Hex};
    let addrsB: {clprService: Hex; application: Hex; connectorContract: Hex; bundleEncoder?: Hex};
    let channelId: Hex;
    let connector: WiredConnector;

    const REQUEST    = "0x48454c4c4f"     as Hex;  // "HELLO"
    const REPLY_DATA = "0x57454c434f4d45" as Hex;  // "WELCOME" — pre-configured response on B

    // Besu single-node genesis validator — matches infra/besu-genesis.json.
    const BESU_VALIDATOR = "0xf39Fd6e51aad88F6f4ce6aB8827279cffFb92266" as Hex;

    beforeAll(async () => {
        backend = createBackend();
        await backend.start();

        const suite = await provisionE2ESuite(backend, "roundtrip");
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

            // wireChannel handles both sides; each side's configProof proves the other chain's state.
            const conn = await wireChannel({
                chainA: A, chainB: B,
                caipA: backend.caipA(), caipB: backend.caipB(),
                addrsA: a, addrsB: b,
                validatorAddr: BESU_VALIDATOR
            });
            channelId = conn.channelId;

            // Wait for a block that sees both channels ACTIVE before proving.
            const block = await A.publicClient.getBlockNumber();
            await waitForBlock(backend.rpcA(), Number(block) + 2, 30_000);
        } else {
            // ── Stub path: E2EVerifier + BundleEncoderHelper ──────────────────
            const pair = await deployE2EPair({
                clientsA: A, clientsB: B,
                privateKey: suite.privateKey,
                caipChainIdA: backend.caipA(),
                caipChainIdB: backend.caipB()
            });
            addrsA = pair.addrsA;
            addrsB = pair.addrsB;

            // Per side: in a mixed spec (e.g. anvil:solo) only one side is a Hiero relay, whose
            // msg.value is in tinybars, so bond/stake settings must not leak across sides.
            const soloA = backend.kindA() === "solo";
            const soloB = backend.kindB() === "solo";
            await wireConfig({clients: A, addrs: pair.addrsA, soloRelay: soloA});
            await wireConfig({clients: B, addrs: pair.addrsB, soloRelay: soloB});

            await registerEndpoint({clients: A, clprService: pair.addrsA.clprService, soloRelay: soloA});
            await registerEndpoint({clients: B, clprService: pair.addrsB.clprService, soloRelay: soloB});

            const conn = await wireChannel({
                chainA: A, chainB: B,
                caipA: backend.caipA(), caipB: backend.caipB(),
                addrsA: pair.addrsA, addrsB: pair.addrsB
            });
            channelId = conn.channelId;
        }

        connector = await wireConnector({
            chainA: A, chainB: B,
            addrsA, addrsB,
            channelId,
            soloRelayA: backend.kindA() === "solo",
            soloRelayB: backend.kindB() === "solo"
        });

        // Configure E2EApplication.B to return REPLY_DATA from its onClprMessage.
        const appAbi = loadArtifact("E2EApplication").abi;
        const setResponseTx = await B.walletClient.writeContract({
            address: addrsB.application, abi: appAbi as never,
            functionName: "setResponse", args: [REPLY_DATA]
        });
        await B.publicClient.waitForTransactionReceipt({hash: setResponseTx});

        // ── A→B: E2EApplication.A.send → service.sendMessage ─────────────────
        // Routing through the app contract stamps the sender bytes as the app's
        // address, so when the REPLY comes back, the onClprResponse callback
        // lands on a contract (not on the EOA).
        const sendTx = await A.walletClient.writeContract({
            address: addrsA.application, abi: appAbi as never,
            functionName: "send",
            args: [addrsA.clprService, channelId, connector.connectorId, addrsB.application, REQUEST]
        });
        await A.publicClient.waitForTransactionReceipt({hash: sendTx});

        if (isBesu) {
            // Wait for the send to land in a proven block before building proof.
            const block = await A.publicClient.getBlockNumber();
            await waitForBlock(backend.rpcA(), Number(block) + 2, 30_000);

            // Ferry messageId=1 from A to B.
            await ferryQbft({
                source: A, dest: B, sourceAddrs: addrsA, destAddrs: addrsB,
                channelId, validatorAddr: BESU_VALIDATOR,
                range: {fromId: 1n, throughId: 1n}
            });

            // ── B→A: ferry the REPLY message that B enqueued at its messageId=1 ──
            const blockB = await B.publicClient.getBlockNumber();
            await waitForBlock(backend.rpcB(), Number(blockB) + 2, 30_000);
            await ferryQbft({
                source: B, dest: A, sourceAddrs: addrsB, destAddrs: addrsA,
                channelId, validatorAddr: BESU_VALIDATOR,
                range: {fromId: 1n, throughId: 1n}
            });
        } else {
            // Ferry messageId=1 from A to B.
            await ferry({
                source: A, dest: B,
                sourceAddrs: addrsA as {clprService: Hex; bundleEncoder: Hex},
                destAddrs: addrsB,
                channelId,
                range: {fromId: 1n, throughId: 1n}
            });

            // ── B→A: ferry the REPLY message that B enqueued at its messageId=1 ──
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

    // ── Outbound (A→B) assertions — recap from Phase D ─────────────────────

    it("B's app recorded the inbound 'HELLO'", async () => {
        const app = loadArtifact("E2EApplication");
        const count = (await B.publicClient.readContract({
            address: addrsB.application, abi: app.abi as never,
            functionName: "getMessageCallCount"
        })) as bigint;
        expect(count).toBe(1n);

        const call = (await B.publicClient.readContract({
            address: addrsB.application, abi: app.abi as never,
            functionName: "messageCalls", args: [0n]
        })) as readonly [Hex, Hex, Hex];
        expect(call[2].toLowerCase()).toBe(REQUEST.toLowerCase());
    });

    it("B saw the sender as A's E2EApplication (not the deployer EOA)", async () => {
        const app = loadArtifact("E2EApplication");
        const call = (await B.publicClient.readContract({
            address: addrsB.application, abi: app.abi as never,
            functionName: "messageCalls", args: [0n]
        })) as readonly [Hex, Hex, Hex];
        expect(call[1].toLowerCase()).toBe(addrsA.application.toLowerCase());
    });

    // ── Inbound REPLY (B→A) assertions — Phase E ───────────────────────────

    it("A's app got an onClprResponse callback", async () => {
        const app = loadArtifact("E2EApplication");
        const count = (await A.publicClient.readContract({
            address: addrsA.application, abi: app.abi as never,
            functionName: "getResponseCallCount"
        })) as bigint;
        expect(count).toBe(1n);
    });

    it("the reply data on A equals 'WELCOME'", async () => {
        const app = loadArtifact("E2EApplication");
        const r = (await A.publicClient.readContract({
            address: addrsA.application, abi: app.abi as never,
            functionName: "responseCalls", args: [0n]
        })) as readonly [Hex, bigint, number, Hex];
        // tuple = (channelId, messageId, status, responseData)
        expect(r[1]).toBe(1n);              // refers to A's original outbound messageId=1
        expect(r[2]).toBe(0);               // ReplyStatus.SUCCESS
        expect(r[3].toLowerCase()).toBe(REPLY_DATA.toLowerCase());
    });

    it("A's channel state advanced with correct storage slot values", async () => {
        const service = loadArtifact("ClprService");
        const conn = (await A.publicClient.readContract({
            address: addrsA.clprService, abi: service.abi as never,
            functionName: "getChannel", args: [channelId]
        })) as {
          nextMessageId: bigint;
          ackedMessageId: bigint;
          receivedMessageId: bigint;
          nextExpectedReplyId: bigint;
          sentRunningHash: `0x${string}`;
          receivedRunningHash: `0x${string}`;
        };
        // Validate storage slots: message IDs advanced correctly
        expect(conn.nextMessageId).toBe(2n);        // A sent 1 DATA message
        expect(conn.ackedMessageId).toBe(1n);       // B acked A's outbound DATA #1
        expect(conn.receivedMessageId).toBe(1n);    // A received B's REPLY #1
        expect(conn.nextExpectedReplyId).toBe(2n);  // A expects reply for next DATA message

        // Validate storage slots: running hashes were updated (not initial values)
        expect(conn.sentRunningHash).not.toBe("0x0000000000000000000000000000000000000000000000000000000000000000");
        expect(conn.receivedRunningHash).not.toBe("0x0000000000000000000000000000000000000000000000000000000000000000");
    });

  it("B's channel state updated with correct storage slot values", async () => {
    const service = loadArtifact("ClprService");
    const conn = (await B.publicClient.readContract({
      address: addrsB.clprService, abi: service.abi as never,
      functionName: "getChannel", args: [channelId]
    })) as {
      nextMessageId: bigint;
      ackedMessageId: bigint;
      receivedMessageId: bigint;
      nextExpectedReplyId: bigint;
      sentRunningHash: `0x${string}`;
      receivedRunningHash: `0x${string}`;
    };

    // Validate storage slots: B's message IDs reflect received DATA and sent REPLY
    expect(conn.nextMessageId).toBe(2n);        // B sent 1 REPLY message
    expect(conn.ackedMessageId).toBe(0n);       // B has no outbound DATA to be acked
    expect(conn.receivedMessageId).toBe(1n);    // B received A's DATA #1
    expect(conn.nextExpectedReplyId).toBe(1n);  // B has no outbound DATA expecting replies

    // Validate storage slots: B's running hashes were updated
    expect(conn.sentRunningHash).not.toBe("0x0000000000000000000000000000000000000000000000000000000000000000");
    expect(conn.receivedRunningHash).not.toBe("0x0000000000000000000000000000000000000000000000000000000000000000");
  });


  it("channel stayed ACTIVE on both sides (no PAUSE during roundtrip)", async () => {
        const service = loadArtifact("ClprService");
        const ACTIVE = 1;
        const onA = (await A.publicClient.readContract({
            address: addrsA.clprService, abi: service.abi as never,
            functionName: "getChannel", args: [channelId]
        })) as {status: number};
        const onB = (await B.publicClient.readContract({
            address: addrsB.clprService, abi: service.abi as never,
            functionName: "getChannel", args: [channelId]
        })) as {status: number};
        expect(onA.status).toBe(ACTIVE);
        expect(onB.status).toBe(ACTIVE);
    });
});
