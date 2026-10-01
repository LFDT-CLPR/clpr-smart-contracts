import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {readFileSync} from "node:fs";
import path from "node:path";
import {
    BaseError,
    ContractFunctionRevertedError,
    createPublicClient,
    createWalletClient,
    encodeFunctionData,
    http,
    keccak256,
    type Hex,
    type PublicClient,
    type WalletClient
} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {loadArtifact, REPO_ROOT} from "../../../../script/deploy/artifacts.js";
import {FIXTURE_DIR} from "../../relay/buildGrandpaLiveFixture.js";
import {
    accountStorageKey,
    beefyAddresses,
    beefyAnchor,
    blake2_256,
    decodeBeefyJustification,
    decodeBeefySet,
    decodeHeader,
    decodeJustification,
    encodeBeefyBundle,
    encodeGrandpaBundle,
    encodeGrandpaEntryProof,
    encodeGrandpaPalletBundle,
    encodeHeader,
    EVM_PALLET_PREFIX,
    fromHex,
    grandpaAnchor,
    grandpaScheduledChange,
    mmrPath,
    packBeefySignatures,
    packGrandpaAuthorities,
    packGrandpaVotes,
    palletQueueKey,
    palletServiceKey,
    paraHeadKey,
    Scale,
    splitVotes,
    toHex,
    type BeefyCommit,
    type GrandpaStep
} from "../../relay/substrate.js";

/// GrandpaVerifier (Bittensor, Bifrost Network), GrandpaPalletVerifier + GrandpaCommitAccumulator
/// (Chainflip) and BeefyParachainVerifier (Hydration) against LIVE mainnet data,
/// replayed offline from test/e2e/fixtures/grandpa-live/*.json (re-record:
/// `npm run grandpa-live:refresh`). The fixtures hold raw public-RPC responses; every payload below
/// is re-derived from them with relay/substrate.ts and run through the unmodified verifiers:
///   - Bittensor: a real GRANDPA justification (14 of 20 ed25519 precommits through the
///     pure-Solidity Ed25519Verifier), the real set change 5 → 6 (ScheduledChange digest), and
///     real Frontier AccountStorages read proofs (Substrate trie, blake2 via the 0x09 precompile).
///   - Bifrost Network: the same path (13 of 19 precommits; the set id changes every 300-block
///     session with the same keys).
///   - Chainflip: a real commit of 139 authorities (92 precommits) verified in batches by the
///     accumulator, then the bundle; the real set change; pallet-storage keys proven absent (no CLPR
///     pallet exists) and real items (Grandpa::CurrentSetId, a System::Account entry) proven present.
///   - Hydration: a real Polkadot BEEFY commitment (401 of 600 secp256k1 signatures), the MMR leaf,
///     the relay header, Paras::Heads(2034) from relay state, the Hydration header and its
///     AccountStorages proofs; plus a real BEEFY set rotation at a session boundary.
/// No ClprService is deployed on any of these chains, so on the Frontier chains the "service" is a live contract with storage:
/// its channel slots are absent (proven by non-existence → zero metadata), and real non-zero slots
/// of the same contract are proven through the trie harness.
/// Gas and calldata are checked against Hedera's 15M gas / 128 KB calldata limits.
///
/// Run: forge build && npm run test:e2e:grandpa-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8611);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HEDERA_GAS_LIMIT = 15_000_000n;
const HEDERA_CALLDATA_LIMIT = 131_072;
/// Precommits per GrandpaCommitAccumulator transaction (each ed25519 check costs about 585k gas).
const ACC_BATCH = 20;

const load = (name: string): any => JSON.parse(readFileSync(path.join(FIXTURE_DIR, `${name}.json`), "utf8"));
const bytes = (h: Hex) => (h.length - 2) / 2;
const channelContext = (channelId: Hex, service: Hex): Hex => (channelId + service.slice(2).toLowerCase()) as Hex;
const report: Record<string, Record<string, string | number>> = {};

describe("Substrate verifiers on live mainnet data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let ed25519: Hex;
    let harness: Hex;
    const harnessArt = (() => {
        const j = JSON.parse(readFileSync(path.join(REPO_ROOT, "out/SubstrateTrieHarness.sol/SubstrateTrieHarness.json"), "utf8"));
        return {abi: j.abi, bytecode: j.bytecode.object as Hex};
    })();

    async function deploy(abi: readonly unknown[], bytecode: Hex, args: unknown[] = []): Promise<Hex> {
        const hash = await wallet.deployContract({abi: abi as never, bytecode, args: args as never, account: wallet.account!, chain: null});
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error("deploy failed");
        return r.contractAddress;
    }

    /** eth_estimateGas of a transaction calling `fn` (intrinsic + calldata + execution, as Hedera bills it). */
    async function txGas(to: Hex, abi: readonly unknown[], fn: string, args: unknown[]) {
        const data = encodeFunctionData({abi, functionName: fn, args} as any);
        const gas = await pub.estimateGas({account: wallet.account!, to, data});
        return {gas, calldata: bytes(data)};
    }

    async function expectRevert(p: Promise<unknown>, errorName: string) {
        try {
            await p;
        } catch (e) {
            const rev = (e as BaseError).walk((x) => x instanceof ContractFunctionRevertedError) as ContractFunctionRevertedError | null;
            expect(rev?.data?.errorName ?? (e as Error).message).toBe(errorName);
            return;
        }
        throw new Error(`expected revert ${errorName}`);
    }

    function checkHedera(label: string, g: {gas: bigint; calldata: number}, extra: Record<string, string | number> = {}) {
        report[label] = {gas: g.gas.toString(), calldataBytes: g.calldata, ...extra};
        expect(g.gas).toBeLessThan(HEDERA_GAS_LIMIT);
        expect(g.calldata).toBeLessThan(HEDERA_CALLDATA_LIMIT);
    }

    beforeAll(async () => {
        anvil = spawn("anvil", ["--port", String(ANVIL_PORT), "--silent", "--disable-block-gas-limit", "--code-size-limit", "60000"], {stdio: "ignore"});
        const rpc = `http://127.0.0.1:${ANVIL_PORT}`;
        pub = createPublicClient({transport: http(rpc), pollingInterval: 100}) as PublicClient;
        const deadline = Date.now() + 15_000;
        for (;;) {
            try {
                await pub.getChainId();
                break;
            } catch (err) {
                if (Date.now() > deadline) throw err;
                await new Promise((r) => setTimeout(r, 200));
            }
        }
        wallet = createWalletClient({account: privateKeyToAccount(ANVIL_KEY), transport: http(rpc)});
        const ed = loadArtifact("Ed25519Verifier");
        ed25519 = await deploy(ed.abi, ed.bytecode);
        harness = await deploy(harnessArt.abi, harnessArt.bytecode);
    });

    afterAll(() => {
        anvil?.kill("SIGTERM");
        console.log("\nSubstrate verifiers on live data (gas = full transaction; Hedera limit 15,000,000 gas / 131,072 B):");
        console.table(report);
    });

    // ── GRANDPA + Frontier EVM: Bittensor, Bifrost Network ──────────────────

    /// GrandpaVerifier against a live GRANDPA solo chain with Frontier: a rotation (the first block
    /// of the current set, justified by the previous set) and a newer justification of that set.
    function grandpaEvmSuite(name: string, title: string) {
        describe(title, () => {
            const fx = load(name);
            const art = loadArtifact("GrandpaVerifier");
            let verifier: Hex;
            const ctx = channelContext(fx.channelId, fx.contract);
            const authBefore = packGrandpaAuthorities(fx.rotation.authoritiesBefore);
            const authAfter = packGrandpaAuthorities(fx.typical.authorities);
            const rotationNumber = parseInt(fx.rotation.block.header.number, 16);
            const setBefore = BigInt(fx.rotation.setIdBefore), setAfter = BigInt(fx.typical.setId);

            const step = (block: any, authorities: Buffer, opts: {all?: boolean} = {}): GrandpaStep => {
                const j = decodeJustification(fromHex(block.justification));
                const v = packGrandpaVotes(j, authorities, opts);
                return {headers: [encodeHeader(block.header)], round: j.round, votes: v.votes, ancestry: v.ancestry, authorities};
            };
            const typicalProof = (s = step(fx.typical.block, authAfter), stateProof: string[] = fx.typical.stateProof) =>
                encodeGrandpaBundle({steps: [s], stateProof: stateProof.map(fromHex)});
            const typicalAnchor = grandpaAnchor(setAfter, authAfter, rotationNumber + 1);
            const read = (proof: Hex, anchor: Hex) =>
                pub.readContract({address: verifier, abi: art.abi, functionName: "verifyBundle", args: [proof, anchor, ctx]}) as Promise<any>;

            beforeAll(async () => {
                verifier = await deploy(art.abi, art.bytecode, [
                    ed25519, toHex(EVM_PALLET_PREFIX), fx.evmChainId, setBefore, keccak256(toHex(authBefore)), rotationNumber
                ]);
            });

            it("derives the Frontier AccountStorages key on-chain exactly as the chain does", async () => {
                const slot = fx.typical.realSlots[0] as Hex;
                const onChain = await pub.readContract({address: verifier, abi: art.abi, functionName: "accountStorageKey", args: [fx.contract, slot]});
                expect(onChain).toBe(toHex(accountStorageKey(fx.contract, slot)));
            });

            it("verifies a real justification + storage proof (typical bundle)", async () => {
                const [metadata, payloads, newAnchor, newAnchorId] = await read(typicalProof(), typicalAnchor);
                expect(metadata.nextMessageId).toBe(0n);
                expect(metadata.sentRunningHash).toBe("0x" + "00".repeat(32));
                expect(payloads.length).toBe(0);
                expect(newAnchor).toBe("0x");
                expect(newAnchorId).toBe("0x");
                const g = await txGas(verifier, art.abi, "verifyBundle", [typicalProof(), typicalAnchor, ctx]);
                const s = step(fx.typical.block, authAfter);
                checkHedera(`${name} typical`, g, {block: parseInt(fx.typical.block.header.number, 16), signatures: s.votes.length / 102, authorities: authAfter.length / 40});
            });

            it(`follows the real authority-set change and returns the new anchor`, async () => {
                const header = encodeHeader(fx.rotation.block.header);
                const change = grandpaScheduledChange(header)!;
                expect(change.delay).toBe(0);
                // The set announced in the digest is the set whose authorities signed the typical justification.
                expect(change.authorities.equals(authAfter)).toBe(true);
                const proof = encodeGrandpaBundle({steps: [step(fx.rotation.block, authBefore)], stateProof: fx.rotation.stateProof.map(fromHex)});
                const anchor = grandpaAnchor(setBefore, authBefore, rotationNumber);
                const [, , newAnchor, newAnchorId] = await read(proof, anchor);
                expect(newAnchor).toBe(grandpaAnchor(setAfter, authAfter, rotationNumber + 1));
                expect(newAnchorId).toBe("0x" + setAfter.toString(16).padStart(16, "0"));
                checkHedera(`${name} rotation (set ${setBefore}→${setAfter})`, await txGas(verifier, art.abi, "verifyBundle", [proof, anchor, ctx]), {block: rotationNumber});
            });

            it("proves real non-zero EVM storage slots through the trie", async () => {
                const stateRoot = toHex(decodeHeader(encodeHeader(fx.typical.block.header)).stateRoot);
                for (const slot of fx.typical.realSlots as Hex[]) {
                    const [exists, value] = (await pub.readContract({
                        address: harness, abi: harnessArt.abi, functionName: "get",
                        args: [stateRoot, fx.typical.stateProof, toHex(accountStorageKey(fx.contract, slot))]
                    })) as [boolean, Hex];
                    expect(exists).toBe(true);
                    expect(bytes(value)).toBe(32);
                }
            });

            it("rejects a tampered signature", async () => {
                const s = step(fx.typical.block, authAfter);
                s.votes[38 + 5] ^= 1;
                await expectRevert(read(typicalProof(s), typicalAnchor), "InvalidGrandpaSignature");
            });

            it("rejects a commit below threshold", async () => {
                const s = step(fx.typical.block, authAfter);
                s.votes = s.votes.subarray(0, s.votes.length - 102);
                await expectRevert(read(typicalProof(s), typicalAnchor), "GrandpaThresholdNotMet");
            });

            it("rejects the wrong authority set", async () => {
                const wrong = Buffer.from(authAfter);
                wrong[0] ^= 1;
                await expectRevert(read(typicalProof(), grandpaAnchor(setAfter, wrong, rotationNumber + 1)), "AuthoritySetMismatch");
            });

            it("rejects the previous set's anchor", async () => {
                // Different keys: the list no longer matches. Same keys (Bifrost): the signatures bind set_id.
                const expected = authBefore.equals(authAfter) ? "InvalidGrandpaSignature" : "AuthoritySetMismatch";
                await expectRevert(read(typicalProof(), grandpaAnchor(setBefore, authBefore, rotationNumber)), expected);
            });

            it("rejects a replayed set id (signatures bind set_id)", async () => {
                await expectRevert(read(typicalProof(), grandpaAnchor(setAfter + 1n, authAfter, rotationNumber + 1)), "InvalidGrandpaSignature");
            });

            it("rejects a block below the anchor height (stale)", async () => {
                await expectRevert(read(typicalProof(), grandpaAnchor(setAfter, authAfter, parseInt(fx.typical.block.header.number, 16) + 1)), "HeightTooOld");
            });

            it("rejects a storage proof with a node missing", async () => {
                // Drop the trie root node: no slot can be read (present or absent) without it.
                const root = decodeHeader(encodeHeader(fx.typical.block.header)).stateRoot;
                const pruned = (fx.typical.stateProof as string[]).filter((n) => !blake2_256(fromHex(n)).equals(root));
                expect(pruned.length).toBe(fx.typical.stateProof.length - 1);
                await expectRevert(read(typicalProof(undefined, pruned), typicalAnchor), "MissingProofNode");
            });
        });
    }

    grandpaEvmSuite("bittensor", "Bittensor (GRANDPA, ed25519)");
    grandpaEvmSuite("bifrost", "Bifrost Network (GRANDPA, ed25519)");

    // ── Chainflip: GRANDPA with a commit accumulator, native pallet storage ──

    describe("Chainflip (GRANDPA, 139 authorities, accumulated commits, pallet storage)", () => {
        const fx = load("chainflip");
        const art = loadArtifact("GrandpaPalletVerifier");
        const accArt = loadArtifact("GrandpaCommitAccumulator");
        let verifier: Hex;
        let acc: Hex;
        // No CLPR pallet on Chainflip: the service address is a placeholder 32-byte account id.
        const service = ("0x" + "00".repeat(31) + "01") as Hex;
        const ctx = channelContext(fx.channelId, service);
        const pallet = fromHex(fx.pallet);
        const authBefore = packGrandpaAuthorities(fx.rotation.authoritiesBefore);
        const authAfter = packGrandpaAuthorities(fx.typical.authorities);
        const rotationNumber = parseInt(fx.rotation.block.header.number, 16);
        const setBefore = BigInt(fx.rotation.setIdBefore), setAfter = BigInt(fx.typical.setId);
        const typicalNumber = parseInt(fx.typical.block.header.number, 16);
        const typicalAnchor = grandpaAnchor(setAfter, authAfter, rotationNumber + 1);

        const commit = (block: any, authorities: Buffer) => {
            const j = decodeJustification(fromHex(block.justification));
            const v = packGrandpaVotes(j, authorities);
            return {j, ...v, targetHash: toHex(blake2_256(encodeHeader(block.header))), targetNumber: parseInt(block.header.number, 16)};
        };
        /// A step whose votes were accumulated beforehand (empty `votes`).
        const accStep = (block: any, authorities: Buffer, votes = Buffer.alloc(0)): GrandpaStep => {
            const c = commit(block, authorities);
            return {headers: [encodeHeader(block.header)], round: c.j.round, votes, ancestry: votes.length ? c.ancestry : [], authorities};
        };
        const bundle = (s: GrandpaStep, stateProof: string[] = fx.typical.stateProof) =>
            encodeGrandpaPalletBundle({steps: [s], stateProof: stateProof.map(fromHex)});
        const read = (proof: Hex, anchor: Hex) =>
            pub.readContract({address: verifier, abi: art.abi, functionName: "verifyBundle", args: [proof, anchor, ctx]}) as Promise<any>;
        const commitArg = (block: any, authorities: Buffer, setId: bigint, votes: Buffer) => {
            const c = commit(block, authorities);
            return {targetHash: c.targetHash, targetNumber: c.targetNumber, round: c.j.round, setId, votes: toHex(votes), ancestry: c.ancestry.map(toHex)};
        };

        /// Sends the commit's votes to the accumulator in batches; returns per-transaction gas.
        async function accumulate(block: any, authorities: Buffer, setId: bigint, perBatch: number, label: string) {
            const c = commit(block, authorities);
            const gas: bigint[] = [];
            let maxCalldata = 0;
            for (const votes of splitVotes(c.votes, perBatch)) {
                const args = [commitArg(block, authorities, setId, votes), toHex(authorities)];
                const g = await txGas(acc, accArt.abi, "accumulate", args);
                gas.push(g.gas);
                maxCalldata = Math.max(maxCalldata, g.calldata);
                const hash = await wallet.writeContract({address: acc, abi: accArt.abi as never, functionName: "accumulate", args: args as never, account: wallet.account!, chain: null, gas: g.gas});
                expect((await pub.waitForTransactionReceipt({hash})).status).toBe("success");
            }
            const max = gas.reduce((a, b) => (a > b ? a : b), 0n);
            checkHedera(`${label} (largest of ${gas.length} accumulate txs)`, {gas: max, calldata: maxCalldata}, {
                signatures: c.votes.length / 102, perBatch, totalGas: gas.reduce((a, b) => a + b, 0n).toString()
            });
            return {gas, signatures: c.votes.length / 102};
        }

        beforeAll(async () => {
            acc = await deploy(accArt.abi, accArt.bytecode, [ed25519]);
            verifier = await deploy(art.abi, art.bytecode, [
                ed25519, acc, toHex(pallet), fx.chainId, setBefore, keccak256(toHex(authBefore)), rotationNumber
            ]);
        });

        it("derives the pallet queue key on-chain exactly as the relay does", async () => {
            const onChain = await pub.readContract({address: verifier, abi: art.abi, functionName: "queueKey", args: [fx.channelId]});
            expect(onChain).toBe(toHex(palletQueueKey(pallet, fx.channelId)));
        });

        it("a full commit inline does not fit one Hedera transaction", async () => {
            const c = commit(fx.typical.block, authAfter);
            const proof = bundle(accStep(fx.typical.block, authAfter, c.votes));
            const g = await txGas(verifier, art.abi, "verifyBundle", [proof, typicalAnchor, ctx]);
            report["chainflip inline commit (one tx)"] = {gas: g.gas.toString(), calldataBytes: g.calldata, signatures: c.votes.length / 102, fitsHedera: "no"};
            expect(g.gas).toBeGreaterThan(HEDERA_GAS_LIMIT);
        });

        it("rejects a bundle before the accumulated weight reaches the threshold", async () => {
            const c = commit(fx.typical.block, authAfter);
            const first = splitVotes(c.votes, ACC_BATCH)[0];
            const args = [commitArg(fx.typical.block, authAfter, setAfter, first), toHex(authAfter)];
            const g = await txGas(acc, accArt.abi, "accumulate", args);
            checkHedera("chainflip accumulate batch 1", g, {signatures: first.length / 102});
            const hash = await wallet.writeContract({address: acc, abi: accArt.abi as never, functionName: "accumulate", args: args as never, account: wallet.account!, chain: null, gas: g.gas});
            expect((await pub.waitForTransactionReceipt({hash})).status).toBe("success");
            await expectRevert(read(bundle(accStep(fx.typical.block, authAfter)), typicalAnchor), "GrandpaThresholdNotMet");
            // The same batch cannot be counted twice.
            await expectRevert(pub.simulateContract({address: acc, abi: accArt.abi as never, functionName: "accumulate", args: args as never, account: wallet.account!}), "AlreadyCounted");
        });

        it("accumulates the rest of a real commit and verifies the bundle (typical)", async () => {
            const c = commit(fx.typical.block, authAfter);
            const rest = Buffer.concat(splitVotes(c.votes, ACC_BATCH).slice(1));
            const gas: bigint[] = [];
            for (const votes of splitVotes(rest, ACC_BATCH)) {
                const args = [commitArg(fx.typical.block, authAfter, setAfter, votes), toHex(authAfter)];
                const g = await txGas(acc, accArt.abi, "accumulate", args);
                gas.push(g.gas);
                checkHedera(`chainflip accumulate batch ${gas.length + 1}`, g, {signatures: votes.length / 102});
                const hash = await wallet.writeContract({address: acc, abi: accArt.abi as never, functionName: "accumulate", args: args as never, account: wallet.account!, chain: null, gas: g.gas});
                expect((await pub.waitForTransactionReceipt({hash})).status).toBe("success");
            }
            const [metadata, payloads, newAnchor] = await read(bundle(accStep(fx.typical.block, authAfter)), typicalAnchor);
            expect(metadata.nextMessageId).toBe(0n);
            expect(metadata.sentRunningHash).toBe("0x" + "00".repeat(32));
            expect(payloads.length).toBe(0);
            expect(newAnchor).toBe("0x");
            checkHedera("chainflip typical (verifyBundle after accumulation)", await txGas(verifier, art.abi, "verifyBundle", [bundle(accStep(fx.typical.block, authAfter)), typicalAnchor, ctx]), {
                block: typicalNumber, signatures: c.votes.length / 102, authorities: authAfter.length / 40
            });
        });

        it("proves real Chainflip storage items under the same finality (verifyStorageEntry)", async () => {
            const proof = encodeGrandpaEntryProof({steps: [accStep(fx.typical.block, authAfter)], stateProof: fx.typical.stateProof.map(fromHex)});
            for (let i = 0; i < fx.typical.realKeys.length; i++) {
                const [exists, value, number] = (await pub.readContract({
                    address: verifier, abi: art.abi, functionName: "verifyStorageEntry", args: [proof, typicalAnchor, fx.typical.realKeys[i]]
                })) as [boolean, Hex, number];
                expect(exists).toBe(true);
                expect(value).toBe(fx.typical.realValues[i]);
                expect(number).toBe(typicalNumber);
            }
            // Grandpa::CurrentSetId at the justified block is the anchor's set id.
            expect(fromHex(fx.typical.realValues[0]).readBigUInt64LE()).toBe(setAfter);
            const [exists] = (await pub.readContract({
                address: verifier, abi: art.abi, functionName: "verifyStorageEntry", args: [proof, typicalAnchor, toHex(palletServiceKey(pallet))]
            })) as [boolean];
            expect(exists).toBe(false);
        });

        it("follows the real authority-set change with an accumulated commit of the old set", async () => {
            const change = grandpaScheduledChange(encodeHeader(fx.rotation.block.header))!;
            expect(change.delay).toBe(0);
            expect(change.authorities.equals(authAfter)).toBe(true);
            await accumulate(fx.rotation.block, authBefore, setBefore, ACC_BATCH, `chainflip rotation (set ${setBefore}→${setAfter})`);
            const proof = bundle(accStep(fx.rotation.block, authBefore), fx.rotation.stateProof);
            const anchor = grandpaAnchor(setBefore, authBefore, rotationNumber);
            const [metadata, , newAnchor, newAnchorId] = await read(proof, anchor);
            expect(metadata.nextMessageId).toBe(0n);
            expect(newAnchor).toBe(grandpaAnchor(setAfter, authAfter, rotationNumber + 1));
            expect(newAnchorId).toBe("0x" + setAfter.toString(16).padStart(16, "0"));
            checkHedera(`chainflip rotation verifyBundle (set ${setBefore}→${setAfter})`, await txGas(verifier, art.abi, "verifyBundle", [proof, anchor, ctx]), {block: rotationNumber});
        });

        it("rejects a tampered signature in an accumulator batch", async () => {
            const c = commit(fx.typical.block, authAfter);
            const votes = Buffer.from(splitVotes(c.votes, 1)[0]);
            votes[38 + 5] ^= 1;
            const args = [commitArg(fx.typical.block, authAfter, setAfter + 7n, votes), toHex(authAfter)];
            await expectRevert(pub.simulateContract({address: acc, abi: accArt.abi as never, functionName: "accumulate", args: args as never, account: wallet.account!}), "InvalidGrandpaSignature");
        });

        it("rejects the accumulated record under another set id (signatures bind set_id)", async () => {
            await expectRevert(read(bundle(accStep(fx.typical.block, authAfter)), grandpaAnchor(setAfter + 1n, authAfter, rotationNumber + 1)), "GrandpaThresholdNotMet");
        });

        it("rejects the wrong authority set", async () => {
            const wrong = Buffer.from(authAfter);
            wrong[0] ^= 1;
            await expectRevert(read(bundle(accStep(fx.typical.block, authAfter)), grandpaAnchor(setAfter, wrong, rotationNumber + 1)), "AuthoritySetMismatch");
        });

        it("rejects a block below the anchor height (stale)", async () => {
            await expectRevert(read(bundle(accStep(fx.typical.block, authAfter)), grandpaAnchor(setAfter, authAfter, typicalNumber + 1)), "HeightTooOld");
        });

        it("rejects a storage proof with a node missing", async () => {
            const root = decodeHeader(encodeHeader(fx.typical.block.header)).stateRoot;
            const pruned = (fx.typical.stateProof as string[]).filter((n) => !blake2_256(fromHex(n)).equals(root));
            expect(pruned.length).toBe(fx.typical.stateProof.length - 1);
            await expectRevert(read(bundle(accStep(fx.typical.block, authAfter), pruned), typicalAnchor), "MissingProofNode");
        });
    });

    // ── Hydration: Polkadot BEEFY → relay state → parachain state ───────────

    describe("Hydration (Polkadot BEEFY, secp256k1)", () => {
        const fx = load("hydration");
        const art = loadArtifact("BeefyParachainVerifier");
        let verifier: Hex;
        const ctx = channelContext(fx.channelId, fx.contract);

        const commitOf = (rec: any): BeefyCommit => {
            const sc = decodeBeefyJustification(fromHex(rec.justification));
            const m = mmrPath(rec.mmrProof);
            return {commitment: sc.commitment, ...packBeefySignatures(sc), authorities: beefyAddresses(rec.beefyAuthorities), mmrLeaf: m.leaf, mmrPath: m.path, mmrPathSides: m.sides};
        };
        const bundle = (rec: any, c = commitOf(rec), over: Partial<{relayHeader: Buffer; paraStateProof: Buffer[]}> = {}) =>
            encodeBeefyBundle({
                commits: [c],
                relayHeader: over.relayHeader ?? encodeHeader(rec.relayHeader),
                relayStateProof: rec.relayStateProof.map(fromHex),
                paraStateProof: over.paraStateProof ?? rec.paraStateProof.map(fromHex)
            });
        const rotationBlock = fx.rotation.relayBlock as number;
        const typicalAnchor = beefyAnchor(decodeBeefySet(fx.typical.anchor.current), decodeBeefySet(fx.typical.anchor.next), rotationBlock);
        const read = (proof: Hex, anchor: Hex) =>
            pub.readContract({address: verifier, abi: art.abi, functionName: "verifyBundle", args: [proof, anchor, ctx]}) as Promise<any>;

        beforeAll(async () => {
            const cur = decodeBeefySet(fx.rotation.anchorBefore.current), next = decodeBeefySet(fx.rotation.anchorBefore.next);
            const set = (s: typeof cur) => ({id: s.id, len: s.len, root: toHex(s.root)});
            verifier = await deploy(art.abi, art.bytecode, [
                toHex(EVM_PALLET_PREFIX), fx.evmChainId, fx.paraId, toHex(paraHeadKey(fx.paraId)),
                {current: set(cur), next: set(next), minRelayBlock: fx.rotation.anchorBefore.block}
            ]);
        });

        it("verifies a real BEEFY commitment → relay state → Hydration storage (typical bundle)", async () => {
            const [metadata, payloads, newAnchor] = await read(bundle(fx.typical), typicalAnchor);
            expect(metadata.nextMessageId).toBe(0n);
            expect(payloads.length).toBe(0);
            expect(newAnchor).toBe("0x");
            const c = commitOf(fx.typical);
            checkHedera("hydration typical", await txGas(verifier, art.abi, "verifyBundle", [bundle(fx.typical), typicalAnchor, ctx]), {
                relayBlock: fx.typical.relayBlock, paraBlock: fx.typical.paraBlockNumber, signatures: c.signatures.length / 65, authorities: c.authorities.length / 20
            });
        });

        it("rotates the BEEFY set at a real session boundary", async () => {
            const before = fx.rotation.anchorBefore;
            const anchor = beefyAnchor(decodeBeefySet(before.current), decodeBeefySet(before.next), before.block);
            const [, , newAnchor, newAnchorId] = await read(bundle(fx.rotation), anchor);
            const leaf = mmrPath(fx.rotation.mmrProof).leaf;
            const leafNext = {id: leaf.readBigUInt64LE(37), len: leaf.readUInt32LE(45), root: leaf.subarray(49, 81)};
            expect(newAnchor).toBe(beefyAnchor(decodeBeefySet(before.next), leafNext, rotationBlock));
            expect(newAnchorId).toBe("0x" + decodeBeefySet(before.next).id.toString(16).padStart(16, "0"));
            checkHedera("hydration rotation (BEEFY set)", await txGas(verifier, art.abi, "verifyBundle", [bundle(fx.rotation), anchor, ctx]), {relayBlock: rotationBlock});
        });

        it("catches up across a session in one bundle (rotation hop + newer commitment)", async () => {
            const before = fx.rotation.anchorBefore;
            const anchor = beefyAnchor(decodeBeefySet(before.current), decodeBeefySet(before.next), before.block);
            const proof = encodeBeefyBundle({
                commits: [commitOf(fx.rotation), commitOf(fx.typical)],
                relayHeader: encodeHeader(fx.typical.relayHeader),
                relayStateProof: fx.typical.relayStateProof.map(fromHex),
                paraStateProof: fx.typical.paraStateProof.map(fromHex)
            });
            const [metadata, , newAnchor] = await read(proof, anchor);
            expect(metadata.nextMessageId).toBe(0n);
            const leaf = mmrPath(fx.rotation.mmrProof).leaf;
            const leafNext = {id: leaf.readBigUInt64LE(37), len: leaf.readUInt32LE(45), root: leaf.subarray(49, 81)};
            expect(newAnchor).toBe(beefyAnchor(decodeBeefySet(before.next), leafNext, rotationBlock));
            checkHedera("hydration hop + bundle (2 commitments)", await txGas(verifier, art.abi, "verifyBundle", [proof, anchor, ctx]), {relayBlock: fx.typical.relayBlock});
        });

        it("proves real non-zero Hydration EVM slots through the trie", async () => {
            const headData = new Scale(fromHex(await (async () => {
                // Paras::Heads value is inside the relay proof; read it back through the harness.
                const relayRoot = toHex(decodeHeader(encodeHeader(fx.typical.relayHeader)).stateRoot);
                const [exists, v] = (await pub.readContract({address: harness, abi: harnessArt.abi, functionName: "get", args: [relayRoot, fx.typical.relayStateProof, toHex(paraHeadKey(fx.paraId))]})) as [boolean, Hex];
                expect(exists).toBe(true);
                return v;
            })())).vec();
            const paraRoot = toHex(decodeHeader(Buffer.from(headData)).stateRoot);
            for (const slot of fx.typical.realSlots as Hex[]) {
                const [exists, value] = (await pub.readContract({
                    address: harness, abi: harnessArt.abi, functionName: "get",
                    args: [paraRoot, fx.typical.paraStateProof, toHex(accountStorageKey(fx.contract, slot))]
                })) as [boolean, Hex];
                expect(exists).toBe(true);
                expect(bytes(value)).toBe(32);
            }
        });

        it("rejects a tampered signature", async () => {
            const c = commitOf(fx.typical);
            c.signatures[3] ^= 1;
            await expectRevert(read(bundle(fx.typical, c), typicalAnchor), "InvalidBeefySignature");
        });

        it("rejects a commitment below threshold", async () => {
            const sc = decodeBeefyJustification(fromHex(fx.typical.justification));
            const c = {...commitOf(fx.typical), ...packBeefySignatures(sc, 400)};
            await expectRevert(read(bundle(fx.typical, c), typicalAnchor), "BeefyThresholdNotMet");
        });

        it("rejects an unknown validator set (anchor two sessions behind)", async () => {
            const cur = decodeBeefySet(fx.typical.anchor.current);
            const shifted = beefyAnchor({...cur, id: cur.id - 2n}, {...cur, id: cur.id - 1n}, rotationBlock);
            await expectRevert(read(bundle(fx.typical), shifted), "UnknownValidatorSet");
        });

        it("rejects a wrong authority list for the set", async () => {
            const c = commitOf(fx.typical);
            c.authorities = Buffer.from(c.authorities);
            c.authorities[0] ^= 1;
            await expectRevert(read(bundle(fx.typical, c), typicalAnchor), "AuthoritySetMismatch");
        });

        it("rejects a stale commitment (below the anchor's relay block)", async () => {
            const anchor = beefyAnchor(decodeBeefySet(fx.typical.anchor.current), decodeBeefySet(fx.typical.anchor.next), fx.typical.relayBlock + 1);
            await expectRevert(read(bundle(fx.typical), anchor), "HeightTooOld");
        });

        it("rejects a relay header that is not the leaf's parent", async () => {
            await expectRevert(read(bundle(fx.typical, undefined, {relayHeader: encodeHeader(fx.rotation.relayHeader)}), typicalAnchor), "RelayHeaderMismatch");
        });

        it("rejects a parachain proof from a different para block", async () => {
            await expectRevert(read(bundle(fx.typical, undefined, {paraStateProof: fx.rotation.paraStateProof.map(fromHex)}), typicalAnchor), "MissingProofNode");
        });
    });
});
