import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {loadArtifact} from "../../../../script/deploy/artifacts.js";
import {keccak256, type Hex} from "viem";
import type {ChainClients} from "../../lib/clients.js";
import {deployE2EPair, type DeployedAddresses} from "../../deploy/deploy.js";
import {createBackend, parseBackendSpec, type Backend} from "../../backend/index.js";
import {
    buildEthMainnetProof,
    encodeEthTrustAnchor,
    SLOTS_PER_SYNC_COMMITTEE_PERIOD
} from "../../relay/buildEthMainnetProof.js";
import {deriveCommittee, firstNParticipants, type BlsCommittee} from "../../relay/bls.js";
import {provisionE2ESuite} from "../../lib/provisionSuite.js";
import {wireConfig, registerEndpoint} from "../../deploy/wire.js";
import {wireChannel} from "../../deploy/wireChannel.js";
import {wireConnector} from "../../deploy/wireConnector.js";

/// End-to-end test for EthMainnetVerifier.verifyBundle — real on-chain BLS12-381 sync-committee
/// verification via EIP-2537 precompiles (G1MSM aggregation + hash-to-G2 + pairing), plus everything
/// downstream (SSZ branch, MPT account/storage proofs, rotation, bundle-content decode).
///
///   - a full 512-member committee is generated with @noble/curves (deterministic test keys);
///   - the relay computes the exact SSZ signing root the committee signs and aggregate-signs it under
///     the ETH2 POP ciphersuite;
///   - the points are EIP-2537 uncompressed (the relayer wire format), so the on-chain pairing holds.
///
/// The 2/3 supermajority is real: 342 of 512 participants is the minimum that satisfies
/// 3·participants ≥ 2·512.
///
/// Run: npm run test:e2e   (anvil backend — anvil ≥ 1.x ships the EIP-2537 precompiles by default)

const ARTIFACT = "EthMainnetVerifier";
const SYNC_COMMITTEE_SIZE = 512;
const SUPERMAJORITY = 342; // ceil(2/3 · 512): 3·342 = 1026 ≥ 1024


/// `Channel.trustAnchorId` for a sync-committee period: 8-byte big-endian, lower-case hex.
function periodId(period: bigint): Hex {
    return ("0x" + period.toString(16).padStart(16, "0")) as Hex;
}

export function ethVerifierShouldSkip(): boolean {
    const {kindA, kindB} = parseBackendSpec();
    return kindA !== "anvil" || kindB !== "anvil";
}

export type VerifyBundleResult = [
    {
        state: number;
        nextMessageId: bigint;
        receivedMessageId: bigint;
        sentRunningHash: Hex;
        receivedRunningHash: Hex;
    },
    Hex[],
    Hex,
    Hex,
    Hex
];

export interface EthVerifierStack {
    backend: Backend;
    A: ChainClients;
    addrsA: DeployedAddresses;
    channelId: Hex;
    serviceCodeHash: Hex;
}

/// Start the backend, deploy a CLPR pair on both chains, wire an ACTIVE channel (stub path), and
/// return the chain-A context plus the ClprService code hash. Caller is responsible for `backend.stop()`.
export async function provisionEthVerifierStack(suiteName: string): Promise<EthVerifierStack> {
    const backend = createBackend();
    await backend.start();

    const suite = await provisionE2ESuite(backend, suiteName);
    const A = suite.clientsA;
    const B = suite.clientsB;

    const pair = await deployE2EPair({
        clientsA: A,
        clientsB: B,
        privateKey: suite.privateKey,
        caipChainIdA: backend.caipA(),
        caipChainIdB: backend.caipB()
    });

    await wireConfig({clients: A, addrs: pair.addrsA});
    await wireConfig({clients: B, addrs: pair.addrsB});

    const fakeKey = ("0x" + "11".repeat(64)) as Hex;
    await registerEndpoint({clients: A, clprService: pair.addrsA.clprService, signingKey: fakeKey});
    await registerEndpoint({clients: B, clprService: pair.addrsB.clprService, signingKey: fakeKey});

    const conn = await wireChannel({
        chainA: A,
        chainB: B,
        caipA: backend.caipA(),
        caipB: backend.caipB(),
        addrsA: pair.addrsA,
        addrsB: pair.addrsB
    });

    // The verifier rejects a message-bearing bundle unless the proven channel has an unacked
    // message (ackedMessageId + messageCount < nextMessageId), so enqueue one on chain A.
    const connector = await wireConnector({
        chainA: A,
        chainB: B,
        addrsA: pair.addrsA,
        addrsB: pair.addrsB,
        channelId: conn.channelId,
        skipChainB: true
    });
    const sendTx = await A.walletClient.writeContract({
        address: pair.addrsA.clprService,
        abi: loadArtifact("ClprService").abi as never,
        functionName: "sendMessage",
        args: [conn.channelId, connector.connectorId, pair.addrsB.application, "0xdeadbeefcafe"]
    });
    await A.publicClient.waitForTransactionReceipt({hash: sendTx});

    const code = await A.publicClient.getCode({address: pair.addrsA.clprService});
    if (!code || code === "0x") throw new Error("ClprService has no code on chain A");

    return {
        backend,
        A,
        addrsA: pair.addrsA,
        channelId: conn.channelId,
        serviceCodeHash: keccak256(code)
    };
}

/// Deploy an Ethereum verifier (`artifactName` selects harness vs production-BLS).
export async function deployEthVerifier(
  A: ChainClients,
  artifactName: string
): Promise<Hex> {
    const art = loadArtifact(artifactName);
    const hash = await A.walletClient.deployContract({
        abi: art.abi as never,
        bytecode: art.bytecode,
        args: []
    });
    const receipt = await A.publicClient.waitForTransactionReceipt({hash});
    if (!receipt.contractAddress) throw new Error(`${artifactName} deploy: no contractAddress`);
    return receipt.contractAddress as Hex;
}

/// `verifyBundle` as a view (eth_call). `artifactName` only supplies the ABI (identical shape across
/// the harness and production verifiers).
export function readVerifyBundle(
  A: ChainClients,
  artifactName: string,
  verifier: Hex,
  proofBytes: Hex,
  trustAnchor: Hex,
  channelContext: Hex = "0x"
): Promise<VerifyBundleResult> {
    const art = loadArtifact(artifactName);
    return A.publicClient.readContract({
        address: verifier,
        abi: art.abi as never,
        functionName: "verifyBundle",
        args: [proofBytes, trustAnchor, channelContext]
    }) as Promise<VerifyBundleResult>;
}

/// Total gas `verifyBundle` consumes end-to-end (BLS + SSZ + MPT + decode + calldata), via eth_estimateGas
/// on the view call. This is the verifier's contribution to a submitBundle transaction (subtract the
/// 21000 base tx cost for pure execution).
export async function estimateVerifyBundleGas(
  A: ChainClients,
  artifactName: string,
  verifier: Hex,
  proofBytes: Hex,
  trustAnchor: Hex,
  channelContext: Hex = "0x"
): Promise<bigint> {
    const art = loadArtifact(artifactName);
    return A.publicClient.estimateContractGas({
        address: verifier,
        abi: art.abi as never,
        functionName: "verifyBundle",
        args: [proofBytes, trustAnchor, channelContext],
        account: A.walletClient.account!
    });
}


describe.skipIf(ethVerifierShouldSkip())("EthMainnetVerifier — Anvil (verifyBundle)", () => {
    let backend: Backend;
    let A: ChainClients;
    let addrsA: DeployedAddresses;
    let channelId: Hex;
    let channelContext: Hex; // ClprTypes.encodeChannelContext: channelId(32) ‖ serviceAddr(20)
    let ethVerifier: Hex; // EthMainnetVerifier pinned to chain A's ClprService
    let serviceCodeHash: Hex;
    let prevCommittee: BlsCommittee; // the window's `current` while `committee` is its `next`
    let committee: BlsCommittee;
    let nextCommittee: BlsCommittee; // a distinct committee to rotate into
    /// C[1]…C[6] for the multi-period catch-up: index == the sync-committee period the committee is
    /// current for, so the window at period p is { C[p], C[p+1] }.
    let C: BlsCommittee[];

    const TEST_PAYLOAD = "0xdeadbeefcafe" as Hex;

    beforeAll(async () => {
        ({backend, A, addrsA, channelId, serviceCodeHash} = await provisionEthVerifierStack("eth-verifier"));
        channelContext = (channelId + addrsA.clprService.slice(2)) as Hex;
        ethVerifier = await deployEthVerifier(A, ARTIFACT);

        prevCommittee = deriveCommittee(SYNC_COMMITTEE_SIZE, "eth-verifier-bls-e2e-prev");
        committee = deriveCommittee(SYNC_COMMITTEE_SIZE, "eth-verifier-bls-e2e");
        nextCommittee = deriveCommittee(SYNC_COMMITTEE_SIZE, "eth-verifier-bls-e2e-next");
        C = [];
        for (let p = 0; p <= 6; p++) {
            C[p] = deriveCommittee(SYNC_COMMITTEE_SIZE, `eth-verifier-catchup-${p}`);
        }
    }, 300_000);

    afterAll(async () => {
        await backend?.stop();
    });

    // ── Happy path ────────────────────────────────────────────────────────────

    it("verifyBundle succeeds with a real 342/512 aggregate BLS signature", async () => {
        const {proofBytes, trustAnchor} = await buildEthMainnetProof({
            rpcUrl: backend.rpcA(),
            serviceAddr: addrsA.clprService,
            channelId,
            payloads: [TEST_PAYLOAD],
            bls: {committee, participants: firstNParticipants(SYNC_COMMITTEE_SIZE, SUPERMAJORITY)}
        });

        const [metadata, messagePayloads] = await readVerifyBundle(A, ARTIFACT, ethVerifier, proofBytes, trustAnchor, channelContext);
        expect(metadata.state).toBe(1); // ACTIVE
        expect(messagePayloads).toHaveLength(1);
        expect(messagePayloads[0].toLowerCase()).toBe(TEST_PAYLOAD.toLowerCase());

        const gas = await estimateVerifyBundleGas(A, ARTIFACT, ethVerifier, proofBytes, trustAnchor, channelContext);
        console.log(`[gas] verifyBundle @ 342/512 (no rotation): ${gas}`);
    });

    it("verifyBundle succeeds with full 512/512 participation", async () => {
        const {proofBytes, trustAnchor} = await buildEthMainnetProof({
            rpcUrl: backend.rpcA(),
            serviceAddr: addrsA.clprService,
            channelId,
            payloads: [TEST_PAYLOAD],
            bls: {committee, participants: firstNParticipants(SYNC_COMMITTEE_SIZE, SYNC_COMMITTEE_SIZE)}
        });

        const [metadata] = await readVerifyBundle(A, ARTIFACT, ethVerifier, proofBytes, trustAnchor, channelContext);
        expect(metadata.state).toBe(1);

        const gas = await estimateVerifyBundleGas(A, ARTIFACT, ethVerifier, proofBytes, trustAnchor, channelContext);
        console.log(`[gas] verifyBundle @ 512/512 (no rotation): ${gas}`);
    });

    // ── Negative cases ──────────────────────────────────────────────────────────

    it("verifyBundle reverts below the 2/3 supermajority (341/512)", async () => {
        const {proofBytes, trustAnchor} = await buildEthMainnetProof({
            rpcUrl: backend.rpcA(),
            serviceAddr: addrsA.clprService,
            channelId,
            payloads: [TEST_PAYLOAD],
            bls: {committee, participants: firstNParticipants(SYNC_COMMITTEE_SIZE, SUPERMAJORITY - 1)}
        });

        await expect(readVerifyBundle(A, ARTIFACT, ethVerifier, proofBytes, trustAnchor)).rejects.toThrow();
    });

    it("verifyBundle reverts on a cryptographically invalid signature", async () => {
        // Enough participants to clear the supermajority, but the signature is produced by a DIFFERENT
        // committee than the one in the trust anchor → on-chain pairing fails.
        const wrongCommittee = deriveCommittee(SYNC_COMMITTEE_SIZE, "eth-verifier-bls-WRONG");
        const {proofBytes, trustAnchor} = await buildEthMainnetProof({
            rpcUrl: backend.rpcA(),
            serviceAddr: addrsA.clprService,
            channelId,
            payloads: [TEST_PAYLOAD],
            bls: {
                committee,
                participants: firstNParticipants(SYNC_COMMITTEE_SIZE, SUPERMAJORITY),
                signWith: wrongCommittee
            }
        });

        await expect(readVerifyBundle(A, ARTIFACT, ethVerifier, proofBytes, trustAnchor)).rejects.toThrow();
    });

    // ── Rotation (dual-encoding next committee) ──────────────────────────────────

    /// The window's whole point: the source chain has crossed into period 1 while the anchor still
    /// starts at period 0, and the bundle verifies with no advance submitted at the boundary.
    it("verifyBundle accepts a bundle signed by the window's next member, with no advance", async () => {
        const {proofBytes, trustAnchor} = await buildEthMainnetProof({
            rpcUrl: backend.rpcA(),
            serviceAddr: addrsA.clprService,
            channelId,
            payloads: [TEST_PAYLOAD],
            headerSlot: SLOTS_PER_SYNC_COMMITTEE_PERIOD + 1n, // period 1
            window: {current: prevCommittee, next: committee, period: 0n},
            bls: {committee, participants: firstNParticipants(SYNC_COMMITTEE_SIZE, SUPERMAJORITY)}
        });

        const [metadata, messagePayloads, newTrustAnchor, newTrustAnchorId] = await readVerifyBundle(
            A, ARTIFACT, ethVerifier, proofBytes, trustAnchor, channelContext
        );
        expect(metadata.state).toBe(1);
        expect(messagePayloads).toHaveLength(1);
        // No rotation data ⇒ the window does not move.
        expect(newTrustAnchor).toBe("0x");
        expect(newTrustAnchorId).toBe("0x");
    });

    it("verifyBundle shifts the window: proves the compressed committee and stores it as the new next", async () => {
        const {proofBytes, trustAnchor} = await buildEthMainnetProof({
            rpcUrl: backend.rpcA(),
            serviceAddr: addrsA.clprService,
            channelId,
            payloads: [TEST_PAYLOAD],
            headerSlot: SLOTS_PER_SYNC_COMMITTEE_PERIOD + 1n, // period 1 = anchorPeriod + 1
            window: {current: prevCommittee, next: committee, period: 0n},
            bls: {committee, participants: firstNParticipants(SYNC_COMMITTEE_SIZE, SUPERMAJORITY)},
            rotation: {committee: nextCommittee}
        });

        const [metadata, , newTrustAnchor, newTrustAnchorId] = await readVerifyBundle(
            A, ARTIFACT, ethVerifier, proofBytes, trustAnchor, channelContext
        );
        expect(metadata.state).toBe(1);

        const expectedAnchor = encodeEthTrustAnchor(
            channelId,
            serviceCodeHash,
            {pubkeys: committee.pubkeys, aggregate: committee.aggregate},
            {pubkeys: nextCommittee.pubkeys, aggregate: nextCommittee.aggregate},
            1n
        );
        expect(newTrustAnchor.toLowerCase()).toBe(expectedAnchor.toLowerCase());
        // The id is the window's START period as an 8-byte big-endian value — the period the chain has
        // actually reached, not the period + 1 the point-encoded anchor used to report.
        expect(newTrustAnchorId.toLowerCase()).toBe("0x0000000000000001");

        const gas = await estimateVerifyBundleGas(A, ARTIFACT, ethVerifier, proofBytes, trustAnchor, channelContext);
        console.log(`[gas] verifyBundle @ 342/512 + WINDOW SHIFT: ${gas}`);
    });

    it("verifyBundle reverts when an uncompressed next key does not match its compressed form", async () => {
        const {proofBytes, trustAnchor} = await buildEthMainnetProof({
            rpcUrl: backend.rpcA(),
            serviceAddr: addrsA.clprService,
            channelId,
            payloads: [TEST_PAYLOAD],
            headerSlot: SLOTS_PER_SYNC_COMMITTEE_PERIOD + 1n,
            window: {current: prevCommittee, next: committee, period: 0n},
            bls: {committee, participants: firstNParticipants(SYNC_COMMITTEE_SIZE, SUPERMAJORITY)},
            rotation: {committee: nextCommittee, mismatchUncompressed: true}
        });

        await expect(readVerifyBundle(A, ARTIFACT, ethVerifier, proofBytes, trustAnchor, channelContext)).rejects.toThrow();
    });

    // ── Multi-period catch-up ───────────────────────

    it(
        "verifyBundle walks the window from period 1 to period 5, then accepts a period-5 bundle",
        async () => {
            const participants = firstNParticipants(SYNC_COMMITTEE_SIZE, SUPERMAJORITY);
            // Anchor installed at period 1: the window is { C1, C2 }.
            let anchor = encodeEthTrustAnchor(channelId, serviceCodeHash, C[1], C[2], 1n);

            for (let step = 0; step < 4; step++) {
                const p = BigInt(2 + step); // signature periods 2, 3, 4, 5
                const i = 2 + step;
                const {proofBytes, trustAnchor: built} = await buildEthMainnetProof({
                    rpcUrl: backend.rpcA(),
                    serviceAddr: addrsA.clprService,
                    channelId,
                    payloads: [],
                    headerSlot: p * SLOTS_PER_SYNC_COMMITTEE_PERIOD + 1n,
                    // The anchor is one period behind the bundle, so `next` is the member that verifies it.
                    window: {current: C[i - 1], next: C[i], period: p - 1n},
                    bls: {committee: C[i], participants},
                    rotation: {committee: C[i + 1]}
                });

                expect(built.toLowerCase()).toBe(anchor.toLowerCase());

                const [metadata, , newTrustAnchor, newTrustAnchorId] = await readVerifyBundle(
                    A, ARTIFACT, ethVerifier, proofBytes, anchor, channelContext
                );
                expect(metadata.state).toBe(1);
                expect(newTrustAnchorId.toLowerCase()).toBe(periodId(p));
                anchor = newTrustAnchor; // feed the RETURNED anchor into the next step
            }

            // Four advances land the window on { C5, C6 }.
            expect(anchor.toLowerCase()).toBe(
                encodeEthTrustAnchor(channelId, serviceCodeHash, C[5], C[6], 5n).toLowerCase()
            );

            const {proofBytes} = await buildEthMainnetProof({
                rpcUrl: backend.rpcA(),
                serviceAddr: addrsA.clprService,
                channelId,
                payloads: [TEST_PAYLOAD],
                headerSlot: 5n * SLOTS_PER_SYNC_COMMITTEE_PERIOD + 1n,
                window: {current: C[5], next: C[6], period: 5n},
                bls: {committee: C[5], participants}
            });
            const [metadata, messagePayloads, newTrustAnchor, newTrustAnchorId] = await readVerifyBundle(
                A, ARTIFACT, ethVerifier, proofBytes, anchor, channelContext
            );
            expect(metadata.state).toBe(1);
            expect(messagePayloads).toHaveLength(1);
            expect(messagePayloads[0].toLowerCase()).toBe(TEST_PAYLOAD.toLowerCase());
            expect(newTrustAnchor).toBe("0x"); // no rotation data ⇒ the window does not move
            expect(newTrustAnchorId).toBe("0x");

            const later = await buildEthMainnetProof({
                rpcUrl: backend.rpcA(),
                serviceAddr: addrsA.clprService,
                channelId,
                payloads: [],
                headerSlot: 6n * SLOTS_PER_SYNC_COMMITTEE_PERIOD + 1n,
                window: {current: C[5], next: C[6], period: 5n},
                bls: {committee: C[6], participants}
            });
            const [laterMetadata] = await readVerifyBundle(
                A, ARTIFACT, ethVerifier, later.proofBytes, anchor, channelContext
            );
            expect(laterMetadata.state).toBe(1);
        },
        180_000
    );

    it("verifyBundle reverts when the signature period is outside the window", async () => {
        // Anchor starts at period 0, so the window covers periods 0 and 1.
        const {proofBytes, trustAnchor} = await buildEthMainnetProof({
            rpcUrl: backend.rpcA(),
            serviceAddr: addrsA.clprService,
            channelId,
            payloads: [],
            headerSlot: SLOTS_PER_SYNC_COMMITTEE_PERIOD * 3n + 1n,
            window: {current: prevCommittee, next: committee, period: 0n},
            bls: {committee, participants: firstNParticipants(SYNC_COMMITTEE_SIZE, SUPERMAJORITY)}
        });

        await expect(readVerifyBundle(A, ARTIFACT, ethVerifier, proofBytes, trustAnchor, channelContext)).rejects.toThrow();
    });

    // ── Downstream (post-BLS) guards: codeHash pinning, anchor decode, channel binding ──────────

    it("verifyBundle reverts when the pinned code hash does not match", async () => {
        // Build a proof with real BLS + account proof, but supply a trust anchor carrying a wrong code hash.
        const wrongCodeHash = `0x${"ba".repeat(32)}` as Hex;

        const {proofBytes} = await buildEthMainnetProof({
            rpcUrl: backend.rpcA(),
            serviceAddr: addrsA.clprService,
            channelId,
            payloads: [TEST_PAYLOAD],
            bls: {committee, participants: firstNParticipants(SYNC_COMMITTEE_SIZE, SUPERMAJORITY)}
        });
        const wrongAnchor = encodeEthTrustAnchor(channelId, wrongCodeHash, {
            pubkeys: committee.pubkeys,
            aggregate: committee.aggregate
        });

        await expect(readVerifyBundle(A, ARTIFACT, ethVerifier, proofBytes, wrongAnchor, channelContext)).rejects.toThrow();
    });

    it("verifyBundle reverts on a malformed trust anchor", async () => {
        const {proofBytes} = await buildEthMainnetProof({
            rpcUrl: backend.rpcA(),
            serviceAddr: addrsA.clprService,
            channelId,
            payloads: [TEST_PAYLOAD],
            bls: {committee, participants: firstNParticipants(SYNC_COMMITTEE_SIZE, SUPERMAJORITY)}
        });

        await expect(readVerifyBundle(A, ARTIFACT, ethVerifier, proofBytes, "0xdeadbeef" as Hex)).rejects.toThrow();
    });

    it("verifyBundle reverts when the storage proof is bound to the wrong channelId", async () => {
        const wrongChannelId = keccak256("0xcafe") as Hex;
        const {proofBytes} = await buildEthMainnetProof({
            rpcUrl: backend.rpcA(),
            serviceAddr: addrsA.clprService,
            channelId: wrongChannelId,
            payloads: [TEST_PAYLOAD],
            bls: {committee, participants: firstNParticipants(SYNC_COMMITTEE_SIZE, SUPERMAJORITY)}
        });
        const mismatchedAnchor = encodeEthTrustAnchor(channelId, serviceCodeHash, {
            pubkeys: committee.pubkeys,
            aggregate: committee.aggregate
        });

        await expect(readVerifyBundle(A, ARTIFACT, ethVerifier, proofBytes, mismatchedAnchor, channelContext)).rejects.toThrow();
    });

    // ── Supporting assertion ──────────────────────────────────────────────────────

    it("EthMainnetVerifier is deployed and pinned to ClprService", () => {
        expect(ethVerifier).toMatch(/^0x[0-9a-fA-F]{40}$/);
        expect(serviceCodeHash).toMatch(/^0x[0-9a-fA-F]{64}$/);
    });
});
