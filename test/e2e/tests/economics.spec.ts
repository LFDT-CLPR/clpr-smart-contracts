import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {zeroAddress, type Hex} from "viem";
import {createBackend} from "../backend/index.js";
import type {Backend} from "../backend/Backend.js";
import type {ChainClients} from "../lib/clients.js";
import {provisionE2ESuite} from "../lib/provisionSuite.js";
import {loadArtifact} from "../../../script/deploy/artifacts.js";
import {deployE2EPair, type DeployedAddresses} from "../deploy/deploy.js";
import {registerEndpoint, wireConfig} from "../deploy/wire.js";
import {wireChannel} from "../deploy/wireChannel.js";
import {wireConnector, type WiredConnector} from "../deploy/wireConnector.js";
import {activeEcon, feeAssetBalance, feeTokenMode, getFeeToken} from "../deploy/feeAsset.js";
import {ferry} from "../relay/ferry.js";

/// Protocol economics end to end, in whichever fee asset the run uses: native value by default,
/// a 6-decimal USD token with `CLPR_E2E_FEE_TOKEN=1`.
///
///   - each ClprService holds exactly the connector stake and the endpoint bond it took;
///   - an inbound DATA message charges the destination connector's operating balance
///     (gasUsed x gasprice x margin, scaled to token units) and the whole charge reaches the
///     bundle submitter, passing through the service.
///
/// Runs on the stub-verifier backends (anvil, avalanche). Besu may run with a zero gas price,
/// which charges nothing, and the Solo relay does not forward `msg.value`.
const backendSpec = process.env.CLPR_BACKEND ?? "anvil";
const stubBackend = !/besu|solo|sei/.test(backendSpec);

describe.skipIf(!stubBackend)("economics: stakes, bonds and execution charges in the fee asset", () => {
    let backend: Backend;
    let A: ChainClients;
    let B: ChainClients;
    let addrsA: DeployedAddresses;
    let addrsB: DeployedAddresses;
    let channelId: Hex;
    let connector: WiredConnector;
    let feeTokenB: Hex;

    const service = loadArtifact("ClprService");

    async function heldByServiceB(): Promise<bigint> {
        return feeAssetBalance(B, feeTokenB, addrsB.clprService);
    }

    beforeAll(async () => {
        backend = createBackend();
        await backend.start();

        const suite = await provisionE2ESuite(backend, "economics");
        A = suite.clientsA;
        B = suite.clientsB;

        ({addrsA, addrsB} = await deployE2EPair({
            clientsA: A,
            clientsB: B,
            privateKey: suite.privateKey,
            caipChainIdA: backend.caipA(),
            caipChainIdB: backend.caipB()
        }));
        await wireConfig({clients: A, addrs: addrsA, soloRelay: false});
        await wireConfig({clients: B, addrs: addrsB, soloRelay: false});
        await registerEndpoint({clients: A, clprService: addrsA.clprService, soloRelay: false});
        await registerEndpoint({clients: B, clprService: addrsB.clprService, soloRelay: false});

        ({channelId} = await wireChannel({
            chainA: A, chainB: B,
            caipA: backend.caipA(), caipB: backend.caipB(),
            addrsA, addrsB
        }));
        connector = await wireConnector({chainA: A, chainB: B, addrsA, addrsB, channelId});
        feeTokenB = await getFeeToken(B, addrsB.clprService);
    }, 600_000);

    afterAll(async () => {
        await backend?.stop();
    });

    it("runs in the configured fee asset", async () => {
        const feeTokenA = await getFeeToken(A, addrsA.clprService);
        if (feeTokenMode()) {
            expect(feeTokenA).not.toBe(zeroAddress);
            expect(feeTokenB).not.toBe(zeroAddress);
        } else {
            expect(feeTokenA).toBe(zeroAddress);
            expect(feeTokenB).toBe(zeroAddress);
        }
        const econ = (await B.publicClient.readContract({
            address: addrsB.clprService, abi: service.abi as never, functionName: "getEconomicConfig"
        })) as {minLockedStake: bigint; minEndpointBond: bigint; messageExecutionCost: bigint};
        expect(econ.minLockedStake).toBe(activeEcon().minLockedStake);
        expect(econ.minEndpointBond).toBe(activeEcon().minEndpointBond);
        expect(econ.messageExecutionCost).toBeGreaterThan(0n); // charging on
    });

    it("holds exactly the connector stake and the endpoint bond", async () => {
        const conn = (await B.publicClient.readContract({
            address: addrsB.clprService, abi: service.abi as never,
            functionName: "getConnector", args: [channelId, connector.connectorId]
        })) as {lockedStake: bigint};
        const entry = (await B.publicClient.readContract({
            address: addrsB.clprService, abi: service.abi as never,
            functionName: "getEndpointEntry", args: [B.account.address]
        })) as {bond: bigint};
        expect(conn.lockedStake).toBe(activeEcon().minLockedStake);
        expect(entry.bond).toBe(activeEcon().minEndpointBond);
        expect(await heldByServiceB()).toBe(conn.lockedStake + entry.bond);
    });

    it("charges the destination connector for inbound DATA and pays the submitter", async () => {
        const app = loadArtifact("E2EApplication");
        const sendTx = await A.walletClient.writeContract({
            address: addrsA.application, abi: app.abi as never,
            functionName: "send",
            args: [addrsA.clprService, channelId, connector.connectorId, addrsB.application, "0x48454c4c4f"]
        });
        expect((await A.publicClient.waitForTransactionReceipt({hash: sendTx})).status).toBe("success");

        const connectorBefore = await feeAssetBalance(B, feeTokenB, addrsB.connectorContract);
        const submitterBefore = await feeAssetBalance(B, feeTokenB, B.account.address);
        const serviceBefore = await heldByServiceB();

        await ferry({
            source: A, dest: B,
            sourceAddrs: addrsA as {clprService: Hex; bundleEncoder: Hex},
            destAddrs: addrsB,
            channelId,
            range: {fromId: 1n, throughId: 1n}
        });

        const channel = (await B.publicClient.readContract({
            address: addrsB.clprService, abi: service.abi as never,
            functionName: "getChannel", args: [channelId]
        })) as {receivedMessageId: bigint};
        expect(channel.receivedMessageId).toBe(1n);

        const charged = connectorBefore - (await feeAssetBalance(B, feeTokenB, addrsB.connectorContract));
        expect(charged).toBeGreaterThan(0n);
        expect(await heldByServiceB()).toBe(serviceBefore); // the charge passes through the service
        if (feeTokenMode()) {
            // Gas is paid in native value on these backends, so the token delta is the charge alone.
            expect((await feeAssetBalance(B, feeTokenB, B.account.address)) - submitterBefore).toBe(charged);
        }
    });
});
