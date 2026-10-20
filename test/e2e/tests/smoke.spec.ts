import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {parseEther} from "viem";
import {createBackend} from "../backend/index.js";
import type {Backend} from "../backend/Backend.js";
import type {ChainClients} from "../lib/clients.js";
import {provisionE2ESuite} from "../lib/provisionSuite.js";
import {loadArtifact} from "../../../script/deploy/artifacts.js";
import {deployE2EPair, type DeployedAddresses} from "../deploy/deploy.js";
import {wireConfig, registerEndpoint} from "../deploy/wire.js";
import {isSoloBackend} from "../backend/solo/solo.js";
import {activeEcon, feeTokenMode} from "../deploy/feeAsset.js";

/// Smoke test: validates that the full toolchain works end-to-end —
/// backend starts, contracts deploy, config writes, endpoint registers,
/// and the kill-switch toggles correctly.
describe("smoke", () => {
    let backend: Backend;
    let A: ChainClients;
    let B: ChainClients;
    let addrsA: DeployedAddresses;
    let addrsB: DeployedAddresses;

    beforeAll(async () => {
        backend = createBackend();
        await backend.start();

        const suite = await provisionE2ESuite(backend, "smoke");
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
    }, isSoloBackend() ? 600_000 : 180_000);

    afterAll(async () => {
        await backend?.stop();
    });

    it("deploys ClprService on both chains", () => {
        expect(addrsA.clprService).toMatch(/^0x[0-9a-fA-F]{40}$/);
        expect(addrsB.clprService).toMatch(/^0x[0-9a-fA-F]{40}$/);
        // Note: on same-backend pairs (anvil:anvil, besu:besu) addresses are identical because
        // CREATE addresses are deterministic from (deployer, nonce) and both chains use the
        // same deployer key starting at nonce 0. On mixed backends the deployer nonces can
        // diverge (e.g. Besu persists state across runs), so we only check both are non-zero.
    });

    it("reports correct chainId on each side", async () => {
        // Avalanche uses fixed C-Chain chainId (43112) regardless of network config
        if (backend.kindA() === "avalanche") {
            expect(await A.publicClient.getChainId()).toBe(43112);
        } else {
            expect(await A.publicClient.getChainId()).toBe(1337);
        }

        if (backend.kindB() === "avalanche") {
            expect(await B.publicClient.getChainId()).toBe(43112);
        } else {
            expect(await B.publicClient.getChainId()).toBe(1338);
        }
    });

    it("reads back the ledger configuration we wrote", async () => {
        const service = loadArtifact("ClprService");
        const cfg = (await A.publicClient.readContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "getLedgerConfiguration"
        })) as {protocolVersion: number; chainId: string; throttles: {maxQueueDepth: number}};
        expect(cfg.protocolVersion).toBe(1);
        expect(cfg.chainId).toBe("eip155:1337");
        expect(cfg.throttles.maxQueueDepth).toBe(1024);
    });

    it("registers a bonded endpoint", async () => {
        const service = loadArtifact("ClprService");

        // Placeholder 64-byte uncompressed pubkey. Will be replaced by the real
        // relay key in roundtrip.spec.ts. Structurally valid for registerEndpoint.

        const soloRelay = backend.kindA() === "solo";
        await registerEndpoint({
            clients: A,
            clprService: addrsA.clprService,
            bond: parseEther("0.1"),
            soloRelay
        });

        // Two-step admission: registerEndpoint creates a PENDING entry (not yet in the live manifest).
        const entry = (await A.publicClient.readContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "getEndpointEntry",
            args: [A.account.address]
        })) as {status: number; bond: bigint};
        expect(entry.status).toBe(1); // EndpointStatus.PENDING
        // Token mode pulls exactly minEndpointBond of the fee token.
        const expectedBond = feeTokenMode() ? activeEcon().minEndpointBond : soloRelay ? 0n : parseEther("0.1");
        expect(entry.bond).toBe(expectedBond);

        // Live manifest count is still 0 until the admin admits the endpoint via addEndpoint.
        const count = (await A.publicClient.readContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "endpointCount"
        })) as bigint;
        expect(count).toBe(0n);
    });

    it("kill-switch toggles and blocks mutating ops", async () => {
        const service = loadArtifact("ClprService");

        const txOff = await A.walletClient.writeContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "setClprEnabled",
            args: [false]
        });
        await A.publicClient.waitForTransactionReceipt({hash: txOff});

        // Any mutating op should now revert with ClprDisabled().
        await expect(
            A.publicClient.simulateContract({
                address: addrsA.clprService,
                abi: service.abi as never,
                functionName: "registerEndpoint",
                args: [{ipAddress: "10.0.0.2", port: 50211, tlsCertificate: "0x", accountId: "0x"}],
                // A token-mode service rejects any msg.value, which would mask the ClprDisabled revert.
                value: feeTokenMode() ? 0n : parseEther("0.001"),
                account: A.account
            })
        ).rejects.toThrow();

        // Re-enable so subsequent tests aren't impacted.
        const txOn = await A.walletClient.writeContract({
            address: addrsA.clprService,
            abi: service.abi as never,
            functionName: "setClprEnabled",
            args: [true]
        });
        await A.publicClient.waitForTransactionReceipt({hash: txOn});
    });
});
