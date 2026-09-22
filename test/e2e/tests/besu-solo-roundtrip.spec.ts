import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {existsSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import type {Hex} from "viem";
import {
    CANONICAL_MIXED_BESU_SOLO,
    createBackend,
    isMixedBesuSolo,
    withOverrideEnvs
} from "../backend/index.js";
import type {Backend} from "../backend/Backend.js";
import type {ChainClients} from "../lib/clients.js";
import {provisionE2ESuite} from "../lib/provisionSuite.js";
import {resolveSoloLedgerId} from "../lib/soloLedger.js";
import {loadArtifact} from "../../../script/deploy/artifacts.js";
import {deployE2EPair, deployModeFor, type DeployedAddresses} from "../deploy/deploy.js";
import {wireConfig, registerEndpoint} from "../deploy/wire.js";
import {wireChannel, type WiredChannel} from "../deploy/wireChannel.js";
import {wireConnector, type WiredConnector} from "../deploy/wireConnector.js";
import {ferry} from "../relay/ferry.js";

const BACKEND_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "../backend");
const REQUEST = "0x48454c4c4f" as Hex;
const REPLY_DATA = "0x57454c434f4d45" as Hex;

function mixedInfraAvailable(): boolean {
    const besuA = existsSync(path.join(BACKEND_DIR, ".besu-state", "rpc-a.url"));
    const soloB = existsSync(path.join(BACKEND_DIR, ".solo-state", "relay-b.url"));
    return besuA && soloB;
}

function shouldRun(): boolean {
    const env = process.env.CLPR_BACKEND;
    if (env && !isMixedBesuSolo(env)) return false;
    return mixedInfraAvailable();
}

describe.runIf(shouldRun())("cross-verifier roundtrip (besu+solo)", () => {
    let backend: Backend;
    let A: ChainClients;
    let B: ChainClients;
    let addrsA: DeployedAddresses;
    let addrsB: DeployedAddresses;
    let channel: WiredChannel;
    let connector: WiredConnector;
    let ledgerId: `0x${string}`;

    beforeAll(async () => {
        backend = withOverrideEnvs({CLPR_BACKEND: CANONICAL_MIXED_BESU_SOLO}, createBackend);
        await backend.start();

        expect(backend.kindA()).toBe("besu");
        expect(backend.kindB()).toBe("solo");

        ledgerId = resolveSoloLedgerId();
        const suite = await provisionE2ESuite(backend, "cross-besu-solo");
        A = suite.clientsA;
        B = suite.clientsB;

        ({addrsA, addrsB} = await deployE2EPair({
            chainA: {
                clients: A,
                caipChainId: backend.caipA(),
                mode: deployModeFor(backend.kindB()),
                ledgerId
            },
            chainB: {
                clients: B,
                caipChainId: backend.caipB(),
                mode: deployModeFor(backend.kindA())
            },
            privateKey: suite.privateKey,
            protocolVersion: 1
        }));

        await wireConfig({clients: A, addrs: addrsA});
        await wireConfig({clients: B, addrs: addrsB, soloRelay: true});

        await registerEndpoint({clients: A, clprService: addrsA.clprService});
        await registerEndpoint({
            clients: B,
            clprService: addrsB.clprService,
            soloRelay: true
        });

        channel = await wireChannel({
            chainA: A,
            chainB: B,
            caipA: backend.caipA(),
            caipB: backend.caipB(),
            addrsA,
            addrsB,
            peerKindA: backend.kindB(),
            peerKindB: backend.kindA()
        });

        connector = await wireConnector({
            chainA: A,
            chainB: B,
            addrsA,
            addrsB,
            channelId: channel.channelId,
            soloRelayB: true
        });

        const appAbi = loadArtifact("E2EApplication").abi;
        const setResponseTx = await B.walletClient.writeContract({
            address: addrsB.application,
            abi: appAbi as never,
            functionName: "setResponse",
            args: [REPLY_DATA]
        });
        await B.publicClient.waitForTransactionReceipt({hash: setResponseTx});

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
    }, 900_000);

    afterAll(async () => {
        await backend?.stop();
    });

    it("ferries Besu → Solo (A→B) with QBFT proof", async () => {
        await ferry({
            source: A,
            dest: B,
            sourceAddrs: addrsA,
            destAddrs: addrsB,
            channelId: channel.channelId,
            range: {fromId: 1n, throughId: 1n},
            sourceKind: backend.kindA(),
            trustAnchor: ledgerId
        });

        const app = loadArtifact("E2EApplication");
        const count = (await B.publicClient.readContract({
            address: addrsB.application,
            abi: app.abi as never,
            functionName: "getMessageCallCount"
        })) as bigint;
        expect(count).toBe(1n);
    });

    it.skip("ferries Solo → Besu (B→A) with Hiero StateProof (blocked: ProofService not in v0.33)", async () => {
        await ferry({
            source: B,
            dest: A,
            sourceAddrs: addrsB,
            destAddrs: addrsA,
            channelId: channel.channelId,
            range: {fromId: 1n, throughId: 1n},
            sourceKind: backend.kindB(),
            trustAnchor: ledgerId
        });
    });
});
