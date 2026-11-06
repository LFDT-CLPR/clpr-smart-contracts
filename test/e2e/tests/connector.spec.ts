import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {parseEther} from "viem";
import {TOKEN_CONNECTOR_FUND} from "../deploy/constants.js";
import {activeEcon, feeAssetBalance, feeTokenMode, getFeeToken} from "../deploy/feeAsset.js";
import {createBackend} from "../backend/index.js";
import type {Backend} from "../backend/Backend.js";
import type {ChainClients} from "../lib/clients.js";
import {provisionE2ESuite} from "../lib/provisionSuite.js";
import {loadArtifact} from "../../../script/deploy/artifacts.js";
import {deployE2EPair, type DeployedAddresses} from "../deploy/deploy.js";
import {wireConfig} from "../deploy/wire.js";
import {wireChannel, type WiredChannel} from "../deploy/wireChannel.js";
import {wireConnector, type WiredConnector} from "../deploy/wireConnector.js";

/// Phase C: register a connector pair on both chains under a shared channelId
/// and fund the local MockClprConnector contracts.
///
/// Validates:
///   - connectorId derives identically across chains (deterministic from
///     channelId + pubKey + salt).
///   - `hasConnector(channelId, connectorId)` returns true on both sides.
///   - Each side's stored Connector has the locked stake recorded.
///   - The MockClprConnector contracts hold the ETH we sent for payForExecution.
describe("connector", () => {
    let backend: Backend;
    let A: ChainClients;
    let B: ChainClients;
    let addrsA: DeployedAddresses;
    let addrsB: DeployedAddresses;
    let channel: WiredChannel;
    let connector: WiredConnector;

    // Per-side effective stake (minLockedStake in token mode; else 0 on Solo relay, 0.1 ETH on dev chains).
    let stakeA: bigint;
    let stakeB: bigint;
    // Per-side effective connector fund (gas-price-based on Solo; fixed on dev chains).
    let expectedFundA: bigint;
    let expectedFundB: bigint;

    const BASE_FUND = parseEther("1");

    beforeAll(async () => {
        backend = createBackend();
        await backend.start();

        const suite = await provisionE2ESuite(backend, "connector");
        A = suite.clientsA;
        B = suite.clientsB;

        const tokenMode = feeTokenMode();
        stakeA = tokenMode ? activeEcon().minLockedStake : backend.kindA() === "solo" ? 0n : parseEther("0.1");
        stakeB = tokenMode ? activeEcon().minLockedStake : backend.kindB() === "solo" ? 0n : parseEther("0.1");
        expectedFundA = tokenMode ? TOKEN_CONNECTOR_FUND : BASE_FUND;
        expectedFundB = tokenMode ? TOKEN_CONNECTOR_FUND : BASE_FUND;

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

        channel = await wireChannel({
            chainA: A, chainB: B,
            caipA: backend.caipA(), caipB: backend.caipB(),
            addrsA, addrsB
        });

        connector = await wireConnector({
            chainA: A, chainB: B,
            addrsA, addrsB,
            channelId: channel.channelId,
            soloRelayA: backend.kindA() === "solo",
            soloRelayB: backend.kindB() === "solo"
        });
    }, 600_000);

    afterAll(async () => {
        await backend?.stop();
    });

    it("derived a non-zero connectorId", () => {
        expect(connector.connectorId).toMatch(/^0x[0-9a-fA-F]{64}$/);
        expect(connector.connectorId).not.toBe(`0x${"00".repeat(32)}`);
    });

    it("hasConnector returns true on both chains", async () => {
        const service = loadArtifact("ClprService");
        const okA = await A.publicClient.readContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "hasConnector",
            args: [channel.channelId, connector.connectorId]
        });
        const okB = await B.publicClient.readContract({
            address: addrsB.clprService,
            abi: service.abi as never,
            functionName: "hasConnector",
            args: [channel.channelId, connector.connectorId]
        });
        expect(okA).toBe(true);
        expect(okB).toBe(true);
    });

    it("getConnector storage slots have correct values after registration", async () => {
        const service = loadArtifact("ClprService");
        const cA = (await A.publicClient.readContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "getConnector",
            args: [channel.channelId, connector.connectorId]
        })) as {
            connectorId: `0x${string}`;
            connectorContract: `0x${string}`;
            admin: `0x${string}`;
            lockedStake: bigint;
            slashCount: number;
        };
        const cB = (await B.publicClient.readContract({
            address: addrsB.clprService,
            abi: service.abi as never,
            functionName: "getConnector",
            args: [channel.channelId, connector.connectorId]
        })) as {
            connectorId: `0x${string}`;
            connectorContract: `0x${string}`;
            admin: `0x${string}`;
            lockedStake: bigint;
            slashCount: number;
        };

        // Validate storage slots: connectorId matches on both sides
        expect(cA.connectorId).toBe(connector.connectorId);
        expect(cB.connectorId).toBe(connector.connectorId);
        
        // Validate storage slots: locked stake reflects deposits
        expect(cA.lockedStake).toBe(stakeA);
        expect(cB.lockedStake).toBe(stakeB);
        
        // Validate storage slots: slashCount initialized to 0
        expect(cA.slashCount).toBe(0);
        expect(cB.slashCount).toBe(0);
        
        // Validate storage slots: connector contract addresses are correct
        expect(cA.connectorContract.toLowerCase()).toBe(addrsA.connectorContract.toLowerCase());
        expect(cB.connectorContract.toLowerCase()).toBe(addrsB.connectorContract.toLowerCase());
        
        // Validate storage slots: admin addresses are set (should be deployer wallets)
        expect(cA.admin).toBeDefined();
        expect(cB.admin).toBeDefined();
        expect(cA.admin).not.toBe("0x0000000000000000000000000000000000000000");
        expect(cB.admin).not.toBe("0x0000000000000000000000000000000000000000");
    });

    it("connectorCount = 1 on both chains", async () => {
        const service = loadArtifact("ClprService");
        const cntA = (await A.publicClient.readContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "connectorCount"
        })) as bigint;
        const cntB = (await B.publicClient.readContract({
            address: addrsB.clprService,
            abi: service.abi as never,
            functionName: "connectorCount"
        })) as bigint;
        expect(cntA).toBe(1n);
        expect(cntB).toBe(1n);
    });

    it("MockClprConnector contracts hold the funded fee asset on both chains", async () => {
        const balA = await feeAssetBalance(A, await getFeeToken(A, addrsA.clprService), addrsA.connectorContract);
        const balB = await feeAssetBalance(B, await getFeeToken(B, addrsB.clprService), addrsB.connectorContract);
        // Solo sides in native mode scale funding with gas price; every other side is funded exactly.
        if (backend.kindA() === "solo" && !feeTokenMode()) {
            expect(balA).toBeGreaterThanOrEqual(expectedFundA);
        } else {
            expect(balA).toBe(expectedFundA);
        }
        if (backend.kindB() === "solo" && !feeTokenMode()) {
            expect(balB).toBeGreaterThanOrEqual(expectedFundB);
        } else {
            expect(balB).toBe(expectedFundB);
        }
    });
});
