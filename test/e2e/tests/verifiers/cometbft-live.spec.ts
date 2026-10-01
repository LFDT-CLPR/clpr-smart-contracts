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
    type Hex,
    type PublicClient,
    type WalletClient
} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {loadArtifact, REPO_ROOT} from "../../../../script/deploy/artifacts.js";
import {pbLen} from "../../lib/proto.js";
import {
    decodeAbciProof,
    encodeSignedHeader,
    encodeStateProof,
    encodeValidatorSet,
    evmStorageKey,
    parseRpcValidator,
    toHex,
    validatorSetHash,
    type LiveValidator,
    type RpcSignedHeader
} from "../../relay/cometbft.js";
import {channelSlots, FIXTURE_DIR, verifyArcCertificate} from "../../relay/buildCometBftLiveFixture.js";

/// CometBftVerifier (src/verifiers/evm/cometbft) against LIVE mainnet data, replayed offline from
/// test/e2e/fixtures/cometbft-live/*.json (re-record: `npm run cometbft-live:refresh`).
///
/// The fixtures hold raw public-RPC responses; every proof below is re-derived from them with
/// relay/cometbft.ts. The production verifier runs unmodified:
///   - Cronos and Mezo: full `verifyBundle` — real commit (min-power signer subset, real Ed25519
///     through the pure-Solidity Ed25519Verifier), real ICS-23 multistore + IAVL proofs. No
///     ClprService exists on those chains, so the "service" is a real contract (WCRO on Cronos);
///     its channel slots are absent → genuine IAVL NON-existence proofs → zeroed metadata. A real
///     non-zero slot is checked with an existence proof through the harness.
///   - Heimdall v2 (secp256k1eth), dYdX, Provenance, THORChain: the light-client step alone
///     (`applyHops` = validator set + header + >2/3 commit), which is also what a validator-set
///     rotation costs.
///   - Arc (Malachite): certificate signatures re-verified off-chain (different wire format).
/// Gas and calldata are checked against Hedera's 15M gas / 128 KB calldata limits.
///
/// Run: forge build && npm run test:e2e:cometbft-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8597);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HEDERA_GAS_LIMIT = 15_000_000n;
const HEDERA_CALLDATA_LIMIT = 131_072;
const PAYLOAD: Hex = "0xc1a9c0ffee";

type Fixture = any;
const load = (name: string): Fixture => JSON.parse(readFileSync(path.join(FIXTURE_DIR, `${name}.json`), "utf8"));
const vals = (pages: any[]): LiveValidator[] => pages.flatMap((p) => p.result.validators).map(parseRpcValidator);
const sh = (commitJson: any): RpcSignedHeader => commitJson.result.signed_header;
const anchor = (hash: Buffer, height: bigint): Hex => toHex(Buffer.concat([hash, Buffer.from(height.toString(16).padStart(16, "0"), "hex")]));
const hop = (s: RpcSignedHeader, v: LiveValidator[], opts = {}): Buffer =>
    Buffer.concat([pbLen(1, encodeValidatorSet(v)), pbLen(2, encodeSignedHeader(s, v, opts).signedHeader)]);
const bytes = (h: Hex) => (h.length - 2) / 2;

function channelContext(channelId: Hex, service: Hex): Hex {
    // ClprTypes.encodeChannelContext = abi.encodePacked(channelId, remoteServiceAddress)
    return (channelId + service.slice(2).toLowerCase()) as Hex;
}

const report: Record<string, Record<string, string | number>> = {};

describe("CometBFT verifier family on live mainnet data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let ed25519Verifier: Hex;
    const verifierArt = loadArtifact("CometBftVerifier");
    const harnessArt = (() => {
        const j = JSON.parse(readFileSync(path.join(REPO_ROOT, "out/CometBftVerifierHarness.sol/CometBftVerifierHarness.json"), "utf8"));
        return {abi: j.abi, bytecode: j.bytecode.object as Hex};
    })();

    async function deploy(abi: readonly unknown[], bytecode: Hex, args: unknown[] = []): Promise<Hex> {
        const hash = await wallet.deployContract({abi: abi as never, bytecode, args: args as never, account: wallet.account!, chain: null});
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error("deploy failed");
        return r.contractAddress;
    }

    function profile(chainId: string, scheme: "ed25519" | "secp256k1eth", bootstrap: Buffer, height: bigint, storeKey = "evm", prefix = 2) {
        return {
            chainId,
            storeKey: toHex(Buffer.from(storeKey)),
            evmStateKeyPrefix: prefix,
            keyScheme: scheme === "ed25519" ? 0 : 1,
            ed25519Verifier: scheme === "ed25519" ? ed25519Verifier : "0x0000000000000000000000000000000000000000",
            bootstrapValidatorsHash: toHex(bootstrap),
            bootstrapHeight: height
        };
    }

    /** eth_estimateGas of a transaction calling `fn` (intrinsic + calldata + execution, as Hedera bills it). */
    async function txGas(to: Hex, abi: readonly unknown[], fn: string, args: unknown[]): Promise<{gas: bigint; calldata: number}> {
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
        ed25519Verifier = await deploy(ed.abi, ed.bytecode);
    });

    afterAll(() => {
        anvil?.kill("SIGTERM");
        console.log("\nCometBFT family on live data (gas = full transaction, Hedera limit 15,000,000 gas / 131,072 B):");
        console.table(report);
    });

    // ── EVM-store chains: full verifyBundle ──────────────────────────────────

    for (const name of ["cronos", "mezo"]) {
        describe(name, () => {
            const fx = load(name);
            const s = sh(fx.raw.commit);
            const v = vals(fx.raw.validators);
            const H = BigInt(fx.meta.height);
            const setHash = validatorSetHash(v);
            const proofs = fx.raw.abci.map((r: any, i: number) => {
                const slots = [...channelSlots(fx.channelId), fx.existenceSlot];
                return decodeAbciProof(r, evmStorageKey(fx.evmStateKeyPrefix, fx.target, slots[i]));
            });
            const enc = encodeSignedHeader(s, v);
            const stateProof = encodeStateProof(enc.signedHeader, fx.storeKey, proofs.slice(0, 5));
            const bundleContent = pbLen(2, Buffer.from(PAYLOAD.slice(2), "hex"));
            const base = Buffer.concat([pbLen(1, stateProof), pbLen(2, bundleContent), pbLen(3, encodeValidatorSet(v))]);
            const hopBuf = hop(sh(fx.raw.hopCommit), vals(fx.raw.hopValidators));
            const withHop = Buffer.concat([base, pbLen(6, hopBuf)]);
            const ctx = channelContext(fx.channelId, fx.target);
            const trust = anchor(setHash, H - 10n);
            let verifier: Hex;
            let harness: Hex;

            beforeAll(async () => {
                const p = profile(s.header.chain_id, "ed25519", setHash, H - 10n, fx.storeKey, fx.evmStateKeyPrefix);
                verifier = await deploy(verifierArt.abi, verifierArt.bytecode, [p]);
                harness = await deploy(harnessArt.abi, harnessArt.bytecode, [p]);
            });

            const call = (proof: Buffer | Hex, a: Hex = trust, at?: Hex) =>
                pub.readContract({address: at ?? verifier, abi: verifierArt.abi as never, functionName: "verifyBundle", args: [typeof proof === "string" ? proof : toHex(proof), a, ctx]}) as Promise<any>;

            it("builder: live inputs are self-consistent and minimal", () => {
                expect(s.header.validators_hash.toLowerCase()).toBe(setHash.toString("hex"));
                expect(proofs.slice(0, 5).every((p: any) => p.value.length === 0)).toBe(true); // absent channel slots
                expect(proofs[5].value.length).toBe(32); // the real non-zero slot
                expect(proofs.every((p: any) => p.height === H - 1n)).toBe(true);
                expect(enc.signedPower * 3n).toBeGreaterThan(enc.totalPower * 2n);
            });

            it("verifyBundle: real commit + IAVL non-existence proofs → zeroed metadata, payload out", async () => {
                const [metadata, payloads, newAnchor, newAnchorId] = await call(base);
                expect(metadata.nextMessageId).toBe(0n);
                expect(metadata.receivedMessageId).toBe(0n);
                expect(payloads).toEqual([PAYLOAD]);
                const rotated = s.header.next_validators_hash !== s.header.validators_hash;
                expect(newAnchor).toBe(rotated ? anchor(Buffer.from(s.header.next_validators_hash, "hex"), H + 1n) : "0x");
                expect(newAnchorId).toBe(newAnchor);

                const g = await txGas(verifier, verifierArt.abi, "verifyBundle", [toHex(base), trust, ctx]);
                const gh = await txGas(verifier, verifierArt.abi, "verifyBundle", [toHex(withHop), trust, ctx]);
                expect(g.gas).toBeLessThan(HEDERA_GAS_LIMIT);
                expect(g.calldata).toBeLessThan(HEDERA_CALLDATA_LIMIT);
                report[name] = {
                    validators: v.length, signatures: enc.signerIndices.length,
                    bundleGas: Number(g.gas), bundleCalldata: g.calldata,
                    "bundle+hop gas": Number(gh.gas), "bundle+hop calldata": gh.calldata,
                    fits: gh.gas < HEDERA_GAS_LIMIT ? "yes" : "NO"
                };
            });

            it("verifyBundle with a real hop (catch-up path) moves through header H-5", async () => {
                const [, payloads] = await call(withHop);
                expect(payloads).toEqual([PAYLOAD]);
            });

            it("existence proof of a real non-zero slot (harness, same production code path)", async () => {
                const sp = encodeStateProof(enc.signedHeader, fx.storeKey, [proofs[5]]);
                const [height, numbers, values] = (await pub.readContract({
                    address: harness, abi: harnessArt.abi, functionName: "verifyStorage",
                    args: [toHex(sp), toHex(encodeValidatorSet(v)), toHex(setHash), H - 10n, fx.target]
                })) as [bigint, Hex[], Hex[]];
                expect(height).toBe(H);
                expect(numbers[0]).toBe(("0x" + fx.existenceSlot.slice(2).padStart(64, "0")) as Hex);
                expect(values[0]).toBe(toHex(proofs[5].value));
                if (name === "cronos") expect(Buffer.from(values[0].slice(2, 24), "hex").toString()).toBe("Wrapped CRO");
            });

            it("rejects: flipped signature byte", async () => {
                const sig = Buffer.from(s.commit.signatures[enc.signerIndices[0]].signature!, "base64");
                const at = enc.signedHeader.indexOf(sig);
                const bad = Buffer.from(enc.signedHeader);
                bad[at + 5] ^= 0x01;
                const p = Buffer.concat([pbLen(1, encodeStateProof(bad, fx.storeKey, proofs.slice(0, 5))), pbLen(2, bundleContent), pbLen(3, encodeValidatorSet(v))]);
                await expectRevert(call(p), "InvalidSignature");
            });

            it("rejects: below threshold (the minimal subset minus one signer)", async () => {
                const short = encodeSignedHeader(s, v, {only: enc.signerIndices.slice(0, -1)});
                expect(short.signedPower * 3n).toBeLessThanOrEqual(short.totalPower * 2n);
                const p = Buffer.concat([pbLen(1, encodeStateProof(short.signedHeader, fx.storeKey, proofs.slice(0, 5))), pbLen(2, bundleContent), pbLen(3, encodeValidatorSet(v))]);
                await expectRevert(call(p), "QuorumNotMet");
            });

            it("rejects: stale data (anchor height above the header)", async () => {
                await expectRevert(call(base, anchor(setHash, H + 1n)), "HeightTooOld");
            });

            it("rejects: wrong validator set (anchor for another set)", async () => {
                await expectRevert(call(base, anchor(Buffer.alloc(32, 7), H - 10n)), "ValidatorSetHashMismatch");
            });

            it("rejects: tampered IAVL proof", async () => {
                const forged = proofs.slice(0, 5).map((p: any) => ({...p}));
                const iavl = Buffer.from(forged[2].iavlProof);
                iavl[iavl.length - 3] ^= 0x01;
                forged[2].iavlProof = iavl;
                const p = Buffer.concat([pbLen(1, encodeStateProof(enc.signedHeader, fx.storeKey, forged)), pbLen(2, bundleContent), pbLen(3, encodeValidatorSet(v))]);
                await expect(call(p)).rejects.toThrow();
            });

            it("rejects: another chain's verifier (chain id is pinned by the profile)", async () => {
                const other = name === "cronos" ? "mezo_31612-1" : "cronosmainnet_25-1";
                const p = profile(other, "ed25519", setHash, H - 10n, fx.storeKey, fx.evmStateKeyPrefix);
                const otherVerifier = await deploy(verifierArt.abi, verifierArt.bytecode, [p]);
                await expectRevert(call(base, trust, otherVerifier), "ChainIdMismatch");
            });
        });
    }

    // ── Light-client step on chains without an EVM store ────────────────────

    for (const name of ["heimdall", "dydx", "provenance", "thorchain"]) {
        it(`${name}: live commit verifies through applyHops (= rotation cost), gas per signature`, async () => {
            const fx = load(name);
            const s = sh(fx.raw.commit);
            const v = vals(fx.raw.validators);
            const H = BigInt(fx.meta.height);
            const setHash = validatorSetHash(v);
            const p = profile(s.header.chain_id, v[0].scheme, setHash, H);
            const harness = await deploy(harnessArt.abi, harnessArt.bytecode, [p]);

            const min = hop(s, v);
            const [next, nextHeight] = (await pub.readContract({
                address: harness, abi: harnessArt.abi, functionName: "applyHops", args: [[toHex(min)], toHex(setHash), H]
            })) as [Hex, bigint];
            expect(next).toBe(("0x" + s.header.next_validators_hash.toLowerCase()) as Hex);
            expect(nextHeight).toBe(H + 1n);

            const g = await txGas(harness, harnessArt.abi, "applyHops", [[toHex(min)], toHex(setHash), H]);
            const g1 = await txGas(harness, harnessArt.abi, "applyHops", [[toHex(hop(s, v, {extra: 1}))], toHex(setHash), H]);
            // `extra` signatures are past the quorum point: the verifier stops before them, so the
            // marginal signature cost is measured by moving the quorum point instead (drop the
            // top-power signer so one more is needed).
            const drop = JSON.parse(JSON.stringify(s));
            drop.commit.signatures[encodeSignedHeader(s, v).signerIndices[0]].block_id_flag = 1;
            let perSig = "n/a";
            try {
                const e2 = encodeSignedHeader(drop, v);
                const g2 = await txGas(harness, harnessArt.abi, "applyHops", [[toHex(hop(drop, v))], toHex(setHash), H]);
                const sigDelta = e2.signerIndices.length - encodeSignedHeader(s, v).signerIndices.length;
                if (sigDelta > 0) perSig = String((g2.gas - g.gas) / BigInt(sigDelta));
            } catch {
                /* dropping the top signer can make 2/3 unreachable on small sets */
            }
            const enc = encodeSignedHeader(s, v);
            report[name] = {
                validators: v.length, signatures: enc.signerIndices.length, scheme: v[0].scheme,
                "commit (hop) gas": Number(g.gas), calldata: g.calldata, "gas/extra sig": perSig,
                "unused sig overhead": Number(g1.gas - g.gas),
                fits: g.gas < HEDERA_GAS_LIMIT ? "yes" : "NO"
            };
            if (name === "thorchain") expect(g.gas).toBeGreaterThan(HEDERA_GAS_LIMIT); // 67 equal-power Ed25519 sigs
            else expect(g.gas).toBeLessThan(HEDERA_GAS_LIMIT);
        });
    }

    it("arc (Malachite): live certificate re-verified off-chain against ValidatorRegistry", () => {
        const fx = load("arc");
        const r = verifyArcCertificate(fx.raw.certificate, fx.raw.validators);
        expect(r.quorum).toBe(true);
        expect(r.verified).toBe(fx.raw.certificate.signatures.length);
        expect(fx.raw.certificate.block_hash).toBe(fx.raw.block.hash);
        report.arc = {validators: fx.raw.validators.length, signatures: r.verified, scheme: "ed25519 (SSZ vote)", note: "off-chain only"};
    });
});
