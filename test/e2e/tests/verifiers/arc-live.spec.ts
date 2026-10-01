import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {readFileSync} from "node:fs";
import path from "node:path";
import {BaseError, ContractFunctionRevertedError, createPublicClient, createWalletClient, encodeFunctionData, http, keccak256, toRlp, type Hex, type PublicClient, type WalletClient} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {loadArtifact, REPO_ROOT} from "../../../../script/deploy/artifacts.js";
import {pbLen} from "../../lib/proto.js";
import {encodeHeader, storageEntries, type ProofJson} from "../../relay/evmHeader.js";
import {arcAnchor, arcSetHash, encodeArcBundle, registryMultiProof, selectSignatures, validatorsFromProof, type ArcStep} from "../../relay/arc.js";
import {ARC_FIXTURE_DIR} from "../../relay/buildArcLiveFixture.js";
import {channelSlots} from "../../relay/buildCometBftLiveFixture.js";

/// ArcMalachiteVerifier (src/verifiers/evm/arc) against LIVE Arc testnet data, replayed offline from
/// test/e2e/fixtures/arc-live/testnet.json (re-record: `npm run arc-live:refresh`).
///
/// The fixture holds raw public-RPC responses (block, arc_getCertificate, eth_getProof); every proof
/// is re-encoded here with relay/arc.ts. The production verifier runs unmodified with the real
/// pure-Solidity Ed25519Verifier. No ClprService exists on Arc, so the "service" is the 0x3600…0001
/// system proxy: its channel slots are absent → MPT exclusion proofs → zeroed metadata.
///
/// Run: forge build && npm run test:e2e:arc-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8598);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HEDERA_GAS_LIMIT = 15_000_000n;
const HEDERA_CALLDATA_LIMIT = 131_072;
const PAYLOAD: Hex = "0xc1a9c0ffee";
const BOGUS_ROOT: Hex = `0x${"11".repeat(32)}`;

const fx = JSON.parse(readFileSync(path.join(ARC_FIXTURE_DIR, "testnet.json"), "utf8"));
const bytes = (h: Hex) => (h.length - 2) / 2;
const report: Record<string, Record<string, string | number>> = {};

describe("ArcMalachiteVerifier on live Arc testnet data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let verifier: Hex;
    const art = loadArtifact("ArcMalachiteVerifier");

    const [s1, s2] = fx.snapshots;
    const H1 = BigInt(s1.height);
    const H2 = BigInt(s2.height);
    const ctx = (fx.channelId + fx.target.slice(2).toLowerCase()) as Hex;
    const bundleContent = toHex(pbLen(2, Buffer.from(PAYLOAD.slice(2), "hex")));

    let vals: Awaited<ReturnType<typeof validatorsFromProof>>["validators"];
    let regRoot: Hex;
    let setHash: Hex;
    const steps: Record<string, ArcStep> = {};

    function toHex(b: Buffer): Hex {
        return `0x${b.toString("hex")}`;
    }

    async function step(s: any, withRotation: boolean, all = false): Promise<ArcStep> {
        const {slots, validators} = await validatorsFromProof(s.registryProof as ProofJson);
        const sel = selectSignatures(s.certificate, validators, all);
        return {
            header: encodeHeader(s.block),
            parentHeader: encodeHeader(s.parentBlock),
            round: s.certificate.round,
            sigs: sel.sigs,
            validators,
            parentRegistryAccountProof: s.parentRegistryProof.accountProof,
            rotation: withRotation ? {registryAccountProof: s.registryProof.accountProof, registrySetProof: registryMultiProof(s.registryProof, slots)} : undefined
        };
    }

    function bundle(st: ArcStep, hops: ArcStep[] = [], svc: any = s2.serviceProof): Hex {
        return encodeArcBundle({
            step: st, hops,
            serviceAccountProof: svc.accountProof,
            storageEntries: storageEntries(svc.storageProof.slice(0, 5)),
            bundleContent
        });
    }

    const call = (proof: Hex, anchor: Hex) =>
        pub.readContract({address: verifier, abi: art.abi as never, functionName: "verifyBundle", args: [proof, anchor, ctx]}) as Promise<any>;

    async function txGas(proof: Hex, anchor: Hex) {
        const data = encodeFunctionData({abi: art.abi as never, functionName: "verifyBundle", args: [proof, anchor, ctx]} as any);
        return {gas: await pub.estimateGas({account: wallet.account!, to: verifier, data}), calldata: bytes(data)};
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

    async function deploy(abi: readonly unknown[], bytecode: Hex, args: unknown[] = []): Promise<Hex> {
        const hash = await wallet.deployContract({abi: abi as never, bytecode, args: args as never, account: wallet.account!, chain: null});
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error("deploy failed");
        return r.contractAddress;
    }

    beforeAll(async () => {
        anvil = spawn("anvil", ["--port", String(ANVIL_PORT), "--silent", "--disable-block-gas-limit", "--code-size-limit", "60000"], {stdio: "ignore"});
        const rpcUrl = `http://127.0.0.1:${ANVIL_PORT}`;
        pub = createPublicClient({transport: http(rpcUrl), pollingInterval: 100}) as PublicClient;
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
        wallet = createWalletClient({account: privateKeyToAccount(ANVIL_KEY), transport: http(rpcUrl)});
        const ed = loadArtifact("Ed25519Verifier");
        const ed25519 = await deploy(ed.abi, ed.bytecode);

        vals = (await validatorsFromProof(s2.registryProof)).validators;
        setHash = arcSetHash(vals);
        regRoot = s2.parentRegistryProof.storageHash;
        verifier = await deploy(art.abi, art.bytecode, [{
            chainId: String(fx.chainId), ed25519Verifier: ed25519, registry: fx.registry,
            bootstrapSetHash: setHash, bootstrapRegistryRoot: regRoot, bootstrapHeight: H1
        }]);
        steps.h1 = await step(s1, false);
        steps.h1rot = await step(s1, true);
        steps.h2 = await step(s2, false);
        steps.h2rot = await step(s2, true);
    });

    afterAll(() => {
        anvil?.kill("SIGTERM");
        console.log("\nArc (Malachite) on live testnet data (gas = full transaction; Hedera limit 15,000,000 gas / 131,072 B):");
        console.table(report);
    });

    it("fixture: header, certificate and registry proofs are self-consistent", () => {
        for (const s of fx.snapshots) {
            expect(keccak256(encodeHeader(s.block))).toBe(s.certificate.block_hash);
            expect(keccak256(s.registryProof.accountProof[0])).toBe(s.block.stateRoot);
            expect(keccak256(s.serviceProof.accountProof[0])).toBe(s.block.stateRoot);
            expect(keccak256(encodeHeader(s.parentBlock))).toBe(s.block.parentHash);
            expect(keccak256(s.parentRegistryProof.accountProof[0])).toBe(s.parentBlock.stateRoot);
            expect(s.checks.setFromParentProof).toBe(s.checks.setFromCallAtParent); // registry at H-1 == the set Arc used for H
        }
        expect(s1.parentRegistryProof.storageHash).toBe(s2.parentRegistryProof.storageHash);
        expect(s2.serviceProof.storageProof.slice(0, 5).map((p: any) => p.key)).toEqual(channelSlots(fx.channelId));
        expect(s2.serviceProof.storageProof.slice(0, 5).every((p: any) => BigInt(p.value) === 0n)).toBe(true);
        expect(BigInt(s2.serviceProof.storageProof[5].value)).not.toBe(0n); // the real non-zero slot
    });

    it("verifyBundle: real certificate + registry unchanged → zeroed metadata, payload, no rotation", async () => {
        const proof = bundle(steps.h2);
        const anchor = arcAnchor(setHash, regRoot, H1);
        const [metadata, payloads, newAnchor, newAnchorId] = await call(proof, anchor);
        expect(metadata.nextMessageId).toBe(0n);
        expect(payloads).toEqual([PAYLOAD]);
        expect(newAnchor).toBe("0x");
        expect(newAnchorId).toBe("0x");
        const g = await txGas(proof, anchor);
        expect(g.gas).toBeLessThan(HEDERA_GAS_LIMIT);
        report["bundle"] = {height: Number(H2), signatures: steps.h2.sigs.length, validators: vals.length, gas: Number(g.gas), calldata: g.calldata, fits: "yes"};
    });

    it("rotation step: registry at state H + live storage multiproof → set for H+1 → new anchor", async () => {
        const proof = bundle(steps.h2rot);
        const anchor = arcAnchor(setHash, regRoot, H1);
        const [, payloads, newAnchor, newAnchorId] = await call(proof, anchor);
        expect(payloads).toEqual([PAYLOAD]);
        expect(newAnchor).toBe(arcAnchor(setHash, regRoot, H2 + 1n));
        expect(newAnchorId).toBe(newAnchor);
        const g = await txGas(proof, anchor);
        expect(g.gas).toBeLessThan(HEDERA_GAS_LIMIT);
        expect(g.calldata).toBeLessThan(HEDERA_CALLDATA_LIMIT);
        const [nodes, paths] = steps.h2rot.rotation!.registrySetProof;
        report["bundle + rotation"] = {
            height: Number(H2), signatures: steps.h2rot.sigs.length, validators: vals.length, gas: Number(g.gas), calldata: g.calldata,
            "set proof": `${nodes.length} nodes, ${bytes(toRlp([nodes, paths]))} B`, fits: g.gas < HEDERA_GAS_LIMIT ? "yes" : "NO"
        };
    });

    it("registry derivation alone (harness): live multiproof → the set Arc uses", async () => {
        const h = JSON.parse(readFileSync(path.join(REPO_ROOT, "out/ArcMalachiteVerifierHarness.sol/ArcMalachiteVerifierHarness.json"), "utf8"));
        const harness = await deploy(h.abi, h.bytecode.object, [{
            chainId: String(fx.chainId), ed25519Verifier: fx.registry, registry: fx.registry,
            bootstrapSetHash: setHash, bootstrapRegistryRoot: regRoot, bootstrapHeight: H1
        }, false]);
        const item = toRlp(steps.h2rot.rotation!.registrySetProof);
        expect(await pub.readContract({address: harness, abi: h.abi, functionName: "deriveSetHash", args: [item, regRoot]})).toBe(setHash);
        const data = encodeFunctionData({abi: h.abi, functionName: "deriveSetHash", args: [item, regRoot]});
        const gas = await pub.estimateGas({account: wallet.account!, to: harness, data});
        report["set derivation only"] = {validators: vals.length, gas: Number(gas), calldata: bytes(data)};
    });

    it("hop: rotation step at H1, then the bundle at H2", async () => {
        const proof = bundle(steps.h2, [steps.h1rot]);
        const anchor = arcAnchor(setHash, regRoot, H1);
        const [, payloads, newAnchor] = await call(proof, anchor);
        expect(payloads).toEqual([PAYLOAD]);
        expect(newAnchor).toBe(arcAnchor(setHash, regRoot, H1 + 1n));
        const g = await txGas(proof, anchor);
        report["hop + bundle"] = {height: Number(H2), signatures: steps.h1rot.sigs.length + steps.h2.sigs.length, validators: vals.length, gas: Number(g.gas), calldata: g.calldata, fits: g.gas < HEDERA_GAS_LIMIT ? "yes" : "NO"};
    });

    it("rejects: flipped signature byte", async () => {
        const st = {...steps.h2, sigs: steps.h2.sigs.map((x, i) => (i === 0 ? {...x, signature: (x.signature.slice(0, 10) + (x.signature[10] === "0" ? "1" : "0") + x.signature.slice(11)) as Hex} : x))};
        await expectRevert(call(bundle(st), arcAnchor(setHash, regRoot, H1)), "InvalidSignature");
    });

    it("rejects: below threshold (minimal subset minus the last signer)", async () => {
        const st = {...steps.h2, sigs: steps.h2.sigs.slice(0, -1)};
        await expectRevert(call(bundle(st), arcAnchor(setHash, regRoot, H1)), "QuorumNotMet");
    });

    it("rejects: signer listed twice", async () => {
        const st = {...steps.h2, sigs: [steps.h2.sigs[0], ...steps.h2.sigs]};
        await expectRevert(call(bundle(st), arcAnchor(setHash, regRoot, H1)), "SignerIndexNotIncreasing");
    });

    it("rejects: wrong validator set (anchor for another set)", async () => {
        await expectRevert(call(bundle(steps.h2), arcAnchor(`0x${"07".repeat(32)}`, regRoot, H1)), "ValidatorSetHashMismatch");
    });

    it("rejects: stale data (anchor height above the header)", async () => {
        await expectRevert(call(bundle(steps.h1), arcAnchor(setHash, regRoot, H1 + 1n)), "HeightTooOld");
    });

    it("rejects: certificate replayed onto another header (H1 signatures, H2 header)", async () => {
        const st = {...steps.h2, sigs: steps.h1.sigs, round: steps.h1.round};
        await expectRevert(call(bundle(st), arcAnchor(setHash, regRoot, H1)), "InvalidSignature");
    });

    it("rejects: anchor registry root is not the registry at H-1 (signing set not pinned)", async () => {
        await expectRevert(call(bundle(steps.h2), arcAnchor(setHash, BOGUS_ROOT, H1)), "RegistryRootMismatch");
    });

    it("rejects: parent header of another block", async () => {
        await expectRevert(call(bundle({...steps.h2, parentHeader: steps.h1.parentHeader}), arcAnchor(setHash, regRoot, H1)), "ParentHeaderMismatch");
    });

    it("rejects: tampered registry multiproof node", async () => {
        const [nodes, paths] = steps.h2rot.rotation!.registrySetProof;
        const bad = [...nodes];
        bad[bad.length - 1] = (bad[bad.length - 1].slice(0, -2) + (bad[bad.length - 1].endsWith("00") ? "01" : "00")) as Hex;
        await expect(call(bundle({...steps.h2rot, rotation: {...steps.h2rot.rotation!, registrySetProof: [bad, paths]}}), arcAnchor(setHash, regRoot, H1))).rejects.toThrow();
    });

    it("rejects: ClprService storage proof from another block (H1 proof, H2 header)", async () => {
        await expect(call(bundle(steps.h2, [], s1.serviceProof), arcAnchor(setHash, regRoot, H1))).rejects.toThrow();
    });
});
