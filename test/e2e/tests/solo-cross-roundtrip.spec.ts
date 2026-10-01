import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {existsSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {BaseError, ContractFunctionRevertedError, encodeFunctionData, type Hex} from "viem";
import {createBackend, parseBackendSpec, withOverrideEnvs} from "../backend/index.js";
import type {Backend, BackendKind} from "../backend/Backend.js";
import type {ChainClients} from "../lib/clients.js";
import {provisionE2ESuite} from "../lib/provisionSuite.js";
import {resolveSoloLedgerId} from "../lib/soloLedger.js";
import {resolveSoloBlockNodeGrpc} from "../lib/soloBlockNode.js";
import {resolveSoloMirrorBaseUrl} from "../lib/soloMirror.js";
import {resolveQbftValidator} from "../lib/verifierContext.js";
import {deriveMessageRunningHashSlot} from "../lib/storageSlots.js";
import {getLatestBlock} from "../lib/blockNodeClient.js";
import {loadArtifact} from "../../../script/deploy/artifacts.js";
import {deployArtifact} from "../../../script/deploy/deployCore.js";
import {deployE2EPair, deployModeFor, type DeployedAddresses} from "../deploy/deploy.js";
import {wireConfig, registerEndpoint} from "../deploy/wire.js";
import {wireChannel, type WiredChannel} from "../deploy/wireChannel.js";
import {wireConnector, type WiredConnector} from "../deploy/wireConnector.js";
import {ferry} from "../relay/ferry.js";
import {
    BI,
    blockItemPath,
    blockSignatureOf,
    encodeStateProof,
    findBlockItem,
    itemKind,
    successorAttestedRoot,
    walkPath
} from "../relay/hieroBlockProof.js";

/// Cross-verifier roundtrip with Solo (Hiero) as chain B and an EVM chain as chain A:
///   CLPR_BACKEND=besu:solo  — A→B carries a real QBFT proof (QBFTVerifier on Solo).
///   CLPR_BACKEND=anvil:solo — A→B carries a stub proof (E2EVerifier on Solo).
/// B→A authenticates the Solo reply with Solo's real TSS signature on chain A (see below).

const BACKEND_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "../backend");
const REQUEST = "0x48454c4c4f" as Hex;
const REPLY_DATA = "0x57454c434f4d45" as Hex;
const SUPPORTED_A: readonly BackendKind[] = ["besu", "anvil"];

/// Resolve the A-side kind, or undefined when this spec should not run.
function resolveKindA(): BackendKind | undefined {
    const raw = process.env.CLPR_BACKEND ?? "besu:solo";
    let kinds: {kindA: BackendKind; kindB: BackendKind};
    try {
        kinds = parseBackendSpec(raw);
    } catch {
        return undefined;
    }
    if (kinds.kindB !== "solo" || !SUPPORTED_A.includes(kinds.kindA)) return undefined;
    if (!existsSync(path.join(BACKEND_DIR, ".solo-state", "relay-b.url"))) return undefined;
    if (kinds.kindA === "besu" && !existsSync(path.join(BACKEND_DIR, ".besu-state", "rpc-a.url"))) return undefined;
    return kinds.kindA;
}

const KIND_A = resolveKindA();

function stripLeadingZeros(b: Buffer): Buffer {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    return b.subarray(i);
}

function revertName(err: unknown): string | undefined {
    if (err instanceof BaseError) {
        const revert = err.walk((e) => e instanceof ContractFunctionRevertedError);
        if (revert instanceof ContractFunctionRevertedError) return revert.data?.errorName ?? revert.reason;
    }
    return undefined;
}

async function expectRevert(p: Promise<unknown>): Promise<string | undefined> {
    try {
        await p;
    } catch (err) {
        return revertName(err) ?? String(err);
    }
    throw new Error("expected revert");
}

describe.runIf(KIND_A !== undefined)(`cross-verifier roundtrip (${KIND_A}+solo)`, () => {
    let backend: Backend;
    let A: ChainClients;
    let B: ChainClients;
    let addrsA: DeployedAddresses;
    let addrsB: DeployedAddresses;
    let channel: WiredChannel;
    let connector: WiredConnector;
    let ledgerId: `0x${string}`;
    let ferryAtoBTx: Hex | undefined;

    beforeAll(async () => {
        backend = withOverrideEnvs({CLPR_BACKEND: `${KIND_A}:solo`}, createBackend);
        await backend.start();

        expect(backend.kindA()).toBe(KIND_A);
        expect(backend.kindB()).toBe("solo");

        ledgerId = resolveSoloLedgerId();
        const suite = await provisionE2ESuite(backend, `cross-${KIND_A}-solo`);
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
            peerKindB: backend.kindA(),
            validatorAddr: resolveQbftValidator()
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

    it(`ferries ${KIND_A} → Solo (A→B) with ${KIND_A === "besu" ? "QBFT" : "stub"} proof`, async () => {
        const res = await ferry({
            source: A,
            dest: B,
            sourceAddrs: addrsA,
            destAddrs: addrsB,
            channelId: channel.channelId,
            range: {fromId: 1n, throughId: 1n},
            sourceKind: backend.kindA(),
            validatorAddr: resolveQbftValidator(),
            trustAnchor: ledgerId
        });
        ferryAtoBTx = res.submittedTxHash;

        const app = loadArtifact("E2EApplication");
        const count = (await B.publicClient.readContract({
            address: addrsB.application,
            abi: app.abi as never,
            functionName: "getMessageCallCount"
        })) as bigint;
        expect(count).toBe(1n);
    });

    /// The Solo reply (B's outbound message 1, enqueued by Solo's ClprService while handling
    /// the A→B bundle) is authenticated on chain A against Solo's real TSS signature:
    ///   1. find the Solo block whose `state_changes` item writes the reply's running hash
    ///      into ClprService storage (block node `getBlock`);
    ///   2. recompute that block's root from its items and check it against the successor
    ///      block's `BlockFooter.previous_block_root_hash`;
    ///   3. on chain A, derive the root from a `block_item_leaf` StateProof with the
    ///      production ClprStateProof/ClprMerkleProof code, and run the production
    ///      TSSVerifier on the block's real hinTS signature.
    /// hinTS passes on the real root and fails on a tampered one. TSSVerifier then stops
    /// with `ClprHieroWrapsProofRequired`: Solo's block proofs carry the 192-byte Schnorr
    /// genesis address-book proof, never a WRAPS proof (see the skipped ferry below).
    it("authenticates the Solo reply on chain A with Solo's real TSS block signature", async () => {
        expect(ferryAtoBTx, "A→B ferry must run first").toBeDefined();
        const blockNode = await resolveSoloBlockNodeGrpc("b");
        const mirror = await resolveSoloMirrorBaseUrl("b");
        expect(blockNode, "Solo block node gRPC").toBeTruthy();
        expect(mirror, "Solo mirror REST").toBeTruthy();

        // Reply running hash, as stored in Solo ClprService storage.
        const hashSlot = deriveMessageRunningHashSlot(channel.channelId, 1n);
        const stored = await B.publicClient.getStorageAt({address: addrsB.clprService, slot: hashSlot});
        expect(stored && BigInt(stored)).toBeTruthy();
        const runningHash = stripLeadingZeros(Buffer.from(stored!.slice(2), "hex"));
        const slotKey = stripLeadingZeros(Buffer.from(hashSlot.slice(2), "hex"));

        const contract = (await (await fetch(`${mirror}/api/v1/contracts/${addrsB.clprService}`)).json()) as {
            contract_id: string;
        };
        const contractNum = BigInt(contract.contract_id.split(".")[2]);

        const receipt = await B.publicClient.getTransactionReceipt({hash: ferryAtoBTx!});
        // The block node lags consensus; wait until the tx block and its successor are served.
        let latest = (await getLatestBlock(blockNode!)).blockNumber;
        for (let i = 0; i < 60 && latest < receipt.blockNumber + 3n; i++) {
            await new Promise((r) => setTimeout(r, 1_000));
            latest = (await getLatestBlock(blockNode!)).blockNumber;
        }
        const from = receipt.blockNumber > 5n ? receipt.blockNumber - 5n : 0n;
        const found = await findBlockItem(blockNode!, from, latest - 1n, (item) =>
            itemKind(item) === BI.STATE_CHANGES && item.includes(runningHash) && item.includes(slotKey)
        );
        if (!found) {
            const any = await findBlockItem(blockNode!, from, latest - 1n, (item) => item.includes(runningHash));
            console.error(
                `[solo] tx block ${receipt.blockNumber}; running hash ${runningHash.toString("hex")} ` +
                    (any ? `found in block ${any.block.blockNumber} item kind ${itemKind(any.block.items[any.itemIndex])}` : "not found in any item")
            );
        }
        expect(found, `state_changes item with the reply running hash in blocks ${from}..${latest - 1n}`).toBeDefined();
        const {block, itemIndex} = found!;
        console.log(
            `[solo→${KIND_A}] reply running hash written in Solo block ${block.blockNumber} ` +
                `(item ${itemIndex}/${block.items.length}, contract 0.0.${contractNum})`
        );

        // Off-chain: recomputed root == successor footer's statement of it.
        const {leaf, siblings, root} = blockItemPath(block, itemIndex);
        const attested = await successorAttestedRoot(blockNode!, block.blockNumber);
        expect(walkPath(leaf, siblings).toString("hex")).toBe(root.toString("hex"));
        expect(root.toString("hex")).toBe(attested.toString("hex"));

        const signature = blockSignatureOf(block);
        expect(signature.length).toBe(1096 + 1632 + 192); // hinTS VK + hinTS sig + Schnorr genesis abProof

        // On chain A: production decoder + Merkle walker derive the root from the proof bytes.
        const proofBytes = encodeStateProof({leaf, siblings, blockSignature: signature});
        const probe = await deployArtifact(A, "HieroBlockItemProbe");
        const [chainRoot, chainLeaf, chainSig] = (await A.publicClient.readContract({
            address: probe,
            abi: loadArtifact("HieroBlockItemProbe").abi as never,
            functionName: "blockItemRoot",
            args: [proofBytes]
        })) as [Hex, Hex, Hex];
        expect(chainRoot.slice(2)).toBe(attested.toString("hex"));
        expect(chainLeaf.slice(2)).toBe(leaf.toString("hex"));
        expect(chainSig.slice(2)).toBe(signature.toString("hex"));

        // hinTS aggregate on chain A: real root verifies; one flipped bit fails the BLS pairing.
        const harness = await deployArtifact(A, "TSSVerifierHarness");
        const harnessAbi = loadArtifact("TSSVerifierHarness").abi as never;
        const hintVk = `0x${signature.subarray(0, 1096).toString("hex")}` as Hex;
        const hintSig = `0x${signature.subarray(1096, 2728).toString("hex")}` as Hex;
        const ok = await A.publicClient.readContract({
            address: harness,
            abi: harnessAbi,
            functionName: "verifyHintsAggregate",
            args: [hintVk, hintSig, chainRoot]
        });
        expect(ok).toBe(true);
        const hintsGas = await A.publicClient.estimateGas({
            account: A.account.address,
            to: harness,
            data: encodeFunctionData({
                abi: harnessAbi,
                functionName: "verifyHintsAggregate",
                args: [hintVk, hintSig, chainRoot]
            } as never)
        });
        console.log(`[solo→${KIND_A}] hinTS aggregate over real Solo block root: gas ≈ ${hintsGas}`);

        const tampered = Buffer.from(attested);
        tampered[0] ^= 1;
        const tamperedErr = await expectRevert(
            A.publicClient.readContract({
                address: harness,
                abi: harnessAbi,
                functionName: "verifyHintsAggregate",
                args: [hintVk, hintSig, `0x${tampered.toString("hex")}`]
            })
        );
        expect(tamperedErr).toMatch(/^HieroHints/);

        // Production TSSVerifier behind the deployed HieroVerifier: hinTS passes, WRAPS is required.
        const hieroAbi = loadArtifact("HieroVerifier").abi as never;
        const tss = (await A.publicClient.readContract({
            address: addrsA.verifier,
            abi: hieroAbi,
            functionName: "TSS_VERIFIER"
        })) as Hex;
        const tssAbi = loadArtifact("TSSVerifier").abi as never;
        const tssErr = await expectRevert(
            A.publicClient.readContract({
                address: tss,
                abi: tssAbi,
                functionName: "verifyTss",
                args: [ledgerId, `0x${signature.toString("hex")}`, chainRoot, "0x"]
            })
        );
        expect(tssErr).toBe("ClprHieroWrapsProofRequired");

        // HieroVerifier.verifyBundle needs a `state_item_leaf` (HIP-1081 state proof).
        const bundleErr = await expectRevert(
            A.publicClient.readContract({
                address: addrsA.verifier,
                abi: hieroAbi,
                functionName: "verifyBundle",
                args: [proofBytes, "0x", "0x"]
            })
        );
        expect(bundleErr).toBe("ClprHieroNoStateItemLeaf");
    });

    /// Blocked on Solo, not on the contracts:
    ///   - block node v0.33.x has no HIP-1081 `ProofService.getStateProof`, so no state-item paths;
    ///   - Solo block proofs are Schnorr-genesis (2920 B); TSSVerifier requires WRAPS (3432 B);
    ///   - HieroVerifier decodes native `ClprChannel` / `ClprMessageValue` state items, which an
    ///     EVM-deployed ClprService on Solo does not produce (its state is contract storage slots).
    it.skip("ferries Solo → A (B→A) through HieroVerifier (blocked: ProofService, WRAPS, native CLPR state)", async () => {
        await ferry({
            source: B,
            dest: A,
            sourceAddrs: addrsB,
            destAddrs: addrsA,
            channelId: channel.channelId,
            range: {fromId: 1n, throughId: 1n},
            sourceKind: backend.kindB(),
            validatorAddr: resolveQbftValidator(),
            trustAnchor: ledgerId
        });
    });
});
