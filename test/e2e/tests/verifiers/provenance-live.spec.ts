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
import {loadArtifact} from "../../../../script/deploy/artifacts.js";
import {pbLen} from "../../lib/proto.js";
import {decodeAbciProof, encodeSignedHeader, encodeValidatorSet, parseRpcValidator, toHex, validatorSetHash, type LiveValidator, type RpcSignedHeader} from "../../relay/cometbft.js";
import {canonicalAddress, encodeCosmWasmProof, encodeEntry, hashHeaderRef, inlineHeaderRef} from "../../relay/cosmwasm.js";
import {FIXTURE_DIR} from "../../relay/buildProvenanceLiveFixture.js";
import {FIXTURE_DIR as COMETBFT_FIXTURE_DIR} from "../../relay/buildCometBftLiveFixture.js";

/// CosmWasmVerifier + CometBftCommitAccumulator (src/verifiers/evm/provenance, src/verifiers/evm/cometbft)
/// against LIVE Provenance mainnet data, replayed offline from test/e2e/fixtures/provenance-live/provenance.json
/// (re-record: `npm run provenance-live:refresh`).
///
/// The fixture holds raw public-RPC responses around a real validator-set rotation R (signed by the
/// old set) and a header B = R+2 (signed by the new set). Every proof is re-derived here; the
/// production contracts run unmodified, with real Ed25519 through the pure-Solidity Ed25519Verifier
/// and real ICS-23 multistore + IAVL proofs from Provenance's `wasm` store:
///   - one-transaction bundle at R (commit + state proof together) → rotation anchor out;
///   - a real CosmWasm contract's storage (Figure's "Crypto-Backed Loan" pool): its cw2
///     `contract_info` Item and a cw-storage-plus Map entry, by existence proof; the CLPR queue
///     record key, absent on that contract, by non-existence proof;
///   - catch-up across the rotation (two commits): too big for one transaction, so it is split
///     across transactions with the accumulator;
///   - THORChain's 67-signature commit (cometbft-live fixture) accumulated over 4 transactions.
/// Gas is eth_estimateGas of the whole transaction, checked against Hedera's 15M gas / 128 KB.
///
/// Run: forge build && npm run test:e2e:provenance-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8598);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HEDERA_GAS_LIMIT = 15_000_000n;
const HEDERA_CALLDATA_LIMIT = 131_072;
const PAYLOAD: Hex = "0xc1a9c0ffee";

const fx = JSON.parse(readFileSync(path.join(FIXTURE_DIR, "provenance.json"), "utf8"));
const vals = (pages: any[]): LiveValidator[] => pages.flatMap((p) => p.result.validators).map(parseRpcValidator);
const sh = (commitJson: any): RpcSignedHeader => commitJson.result.signed_header;
const anchor = (hash: Buffer, height: bigint): Hex => toHex(Buffer.concat([hash, Buffer.from(height.toString(16).padStart(16, "0"), "hex")]));
const bytes = (h: Hex) => (h.length - 2) / 2;
const hexBuf = (h: string) => Buffer.from(h.replace(/^0x/, ""), "hex");

const report: Record<string, Record<string, string | number>> = {};

describe("Provenance (CosmWasm) on live mainnet data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let ed25519: Hex;
    let accumulator: Hex;
    let verifier: Hex;
    const accArt = loadArtifact("CometBftCommitAccumulator");
    const verArt = loadArtifact("CosmWasmVerifier");
    // The verifier bubbles the accumulator's reverts, so decode with both ABIs.
    const abi = [...verArt.abi, ...accArt.abi.filter((x: any) => x.type === "error")] as readonly unknown[];

    const contract = canonicalAddress(fx.contract);
    const channelId = hexBuf(fx.channelId);
    const ctx = toHex(Buffer.concat([channelId, contract]));

    const R = BigInt(fx.meta.rotationHeight);
    const B = BigInt(fx.meta.bundleHeight);
    const shR = sh(fx.raw.rotation.commit);
    const shB = sh(fx.raw.bundle.commit);
    const valsR = vals(fx.raw.rotation.validators);
    const valsB = vals(fx.raw.bundle.validators);
    const oldSet = validatorSetHash(valsR);
    const newSet = validatorSetHash(valsB);
    const encR = encodeSignedHeader(shR, valsR);
    const encB = encodeSignedHeader(shB, valsB);
    const keyOf = (name: string) => hexBuf(fx.keys.find((k: any) => k.name === name).key);
    const proofsAt = (part: "rotation" | "bundle") =>
        Object.fromEntries(fx.keys.map((k: any, i: number) => [k.name, decodeAbciProof(fx.raw[part].abci[i], keyOf(k.name))]));
    const pR = proofsAt("rotation");
    const pB = proofsAt("bundle");
    const content = pbLen(2, hexBuf(PAYLOAD));
    const trustOld = anchor(oldSet, R - 10n);

    const bundleAtR = (header = inlineHeaderRef(valsR, encR.signedHeader), entry = encodeEntry(pR.queue)) =>
        toHex(encodeCosmWasmProof({bundleContent: content, header, multistoreProof: pR.queue.multistoreProof, entry}));

    async function deploy(a: readonly unknown[], bytecode: Hex, args: unknown[] = []): Promise<Hex> {
        const hash = await wallet.deployContract({abi: a as never, bytecode, args: args as never, account: wallet.account!, chain: null});
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error("deploy failed");
        return r.contractAddress;
    }

    async function txGas(to: Hex, a: readonly unknown[], fn: string, args: unknown[]): Promise<{gas: bigint; calldata: number}> {
        const data = encodeFunctionData({abi: a, functionName: fn, args} as any);
        return {gas: await pub.estimateGas({account: wallet.account!, to, data}), calldata: bytes(data)};
    }

    /** Send accumulate(validatorSet, signedHeader) as a real transaction; returns its gas used. */
    async function accumulate(at: Hex, v: LiveValidator[], signedHeader: Buffer): Promise<{gas: bigint; calldata: number}> {
        const args = [toHex(encodeValidatorSet(v)), toHex(signedHeader)];
        const est = await txGas(at, accArt.abi, "accumulate", args);
        const hash = await wallet.writeContract({address: at, abi: accArt.abi as never, functionName: "accumulate" as never, args: args as never, account: wallet.account!, chain: null, gas: est.gas + 100_000n});
        const r = await pub.waitForTransactionReceipt({hash});
        expect(r.status).toBe("success");
        return {gas: r.gasUsed, calldata: est.calldata};
    }

    const verifyBundle = (proof: Hex, a: Hex = trustOld, at: Hex = verifier) =>
        pub.readContract({address: at, abi: abi as never, functionName: "verifyBundle", args: [proof, a, ctx]}) as Promise<any>;

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
        ed25519 = await deploy(ed.abi, ed.bytecode);
        accumulator = await deploy(accArt.abi, accArt.bytecode, [fx.chainId, 0, ed25519]);
        verifier = await deploy(verArt.abi, verArt.bytecode, [{accumulator, storeKey: toHex(Buffer.from("wasm")), bootstrapValidatorsHash: toHex(oldSet), bootstrapHeight: R - 10n}]);
    }, 60_000);

    afterAll(() => {
        anvil?.kill("SIGTERM");
        console.log("\nProvenance on live data (gas = full transaction, Hedera limit 15,000,000 gas / 131,072 B):");
        console.table(report);
    });

    it("builder: live inputs are self-consistent", () => {
        expect(fx.chainId).toBe("pio-mainnet-1");
        expect(shR.header.validators_hash.toLowerCase()).toBe(oldSet.toString("hex"));
        expect(shR.header.next_validators_hash.toLowerCase()).toBe(newSet.toString("hex")); // a real rotation
        expect(shB.header.validators_hash).toBe(shR.header.next_validators_hash);
        expect(contract.length).toBe(32);
        expect(pR.queue.value.length).toBe(0); // no CLPR Service here: the queue record is absent
        expect(pR.cw2.value.toString()).toBe('{"contract":"democratized_prime_pool_v2","version":"1.0.0"}');
        expect(pR.map.value.length).toBeGreaterThan(0);
        for (const p of Object.values(pR) as any[]) expect(p.height).toBe(R - 1n);
        for (const p of Object.values(pB) as any[]) expect(p.height).toBe(B - 1n);
        expect(encR.signedPower * 3n).toBeGreaterThan(encR.totalPower * 2n);
    });

    // ── One transaction: commit + state proof ───────────────────────────────

    it("verifyBundle at the rotation header in ONE transaction: commit + IAVL non-existence → new anchor", async () => {
        const proof = bundleAtR();
        const [metadata, payloads, newAnchor, newAnchorId, manifest] = await verifyBundle(proof);
        expect(metadata.nextMessageId).toBe(0n);
        expect(metadata.sentRunningHash).toBe(toHex(Buffer.alloc(32)));
        expect(payloads).toEqual([PAYLOAD]);
        expect(newAnchor).toBe(anchor(newSet, R + 1n));
        expect(newAnchorId).toBe(newAnchor);
        expect(manifest.version).toBe(0n);

        const g = await txGas(verifier, verArt.abi, "verifyBundle", [proof, trustOld, ctx]);
        expect(g.gas).toBeLessThan(HEDERA_GAS_LIMIT);
        expect(g.calldata).toBeLessThan(HEDERA_CALLDATA_LIMIT);
        report["bundle at R (1 tx, rotation)"] = {signatures: encR.signerIndices.length, gas: Number(g.gas), calldata: g.calldata, fits: "yes"};
    });

    it("verifyBundle at B, signed by the new set, from the anchor the rotation bundle returned", async () => {
        const proof = toHex(encodeCosmWasmProof({bundleContent: content, header: inlineHeaderRef(valsB, encB.signedHeader), multistoreProof: pB.queue.multistoreProof, entry: encodeEntry(pB.queue)}));
        const [, payloads, newAnchor] = await verifyBundle(proof, anchor(newSet, R + 1n));
        expect(payloads).toEqual([PAYLOAD]);
        expect(newAnchor).toBe(shB.header.next_validators_hash === shB.header.validators_hash ? "0x" : anchor(hexBuf(shB.header.next_validators_hash), B + 1n));
        const g = await txGas(verifier, verArt.abi, "verifyBundle", [proof, anchor(newSet, R + 1n), ctx]);
        expect(g.gas).toBeLessThan(HEDERA_GAS_LIMIT);
        report["bundle at B (1 tx)"] = {signatures: encB.signerIndices.length, gas: Number(g.gas), calldata: g.calldata, fits: "yes"};
    });

    it("verifyContractEntry: a real contract's cw2 Item and cw-storage-plus Map entry, by existence proof", async () => {
        for (const [name, key, entry] of [
            ["cw2 contract_info", Buffer.from("contract_info"), pR.cw2],
            ["Map sb1[owner]", Buffer.concat([Buffer.from([0, 3]), Buffer.from(fx.mapNamespace), Buffer.from(fx.mapKey)]), pR.map]
        ] as const) {
            const proof = toHex(encodeCosmWasmProof({header: inlineHeaderRef(valsR, encR.signedHeader), multistoreProof: entry.multistoreProof, entry: encodeEntry(entry)}));
            const args = [proof, trustOld, toHex(contract), toHex(key)];
            const [exists, value, height] = (await pub.readContract({address: verifier, abi: abi as never, functionName: "verifyContractEntry", args: args as never})) as [boolean, Hex, bigint];
            expect(exists).toBe(true);
            expect(value).toBe(toHex(entry.value));
            expect(height).toBe(R);
            const g = await txGas(verifier, verArt.abi, "verifyContractEntry", args);
            expect(g.gas).toBeLessThan(HEDERA_GAS_LIMIT);
            report[`entry: ${name}`] = {signatures: encR.signerIndices.length, gas: Number(g.gas), calldata: g.calldata, fits: "yes"};
        }
    });

    // ── Two commits: the catch-up across the rotation ───────────────────────

    it("catch-up across the rotation inline (hop R + header B) does NOT fit one transaction", async () => {
        const proof = toHex(encodeCosmWasmProof({
            bundleContent: content, header: inlineHeaderRef(valsB, encB.signedHeader), hops: [inlineHeaderRef(valsR, encR.signedHeader)],
            multistoreProof: pB.queue.multistoreProof, entry: encodeEntry(pB.queue)
        }));
        const [, payloads] = await verifyBundle(proof); // correct, just too big
        expect(payloads).toEqual([PAYLOAD]);
        const g = await txGas(verifier, verArt.abi, "verifyBundle", [proof, trustOld, ctx]);
        expect(g.gas).toBeGreaterThan(HEDERA_GAS_LIMIT);
        report["bundle at B + inline hop R (1 tx)"] = {signatures: encR.signerIndices.length + encB.signerIndices.length, gas: Number(g.gas), calldata: g.calldata, fits: "NO"};
    });

    it("split: R's commit over 2 txs, B's commit in 1 tx, then the bundle by header hash", async () => {
        const half = Math.ceil(encR.signerIndices.length / 2);
        const r1 = encodeSignedHeader(shR, valsR, {only: encR.signerIndices.slice(0, half)});
        const r2 = encodeSignedHeader(shR, valsR, {only: encR.signerIndices.slice(half)});
        const a1 = await accumulate(accumulator, valsR, r1.signedHeader);
        await expectRevert(
            pub.readContract({address: verifier, abi: abi as never, functionName: "verifyBundle", args: [bundleAtR(hashHeaderRef(encR.headerHash)), trustOld, ctx]}),
            "NotFinalized"
        );
        const a2 = await accumulate(accumulator, valsR, r2.signedHeader);
        const a3 = await accumulate(accumulator, valsB, encB.signedHeader);

        // Bundle at R by reference: the state proof gets the whole transaction.
        const atR = bundleAtR(hashHeaderRef(encR.headerHash));
        const [, , naR] = await verifyBundle(atR);
        expect(naR).toBe(anchor(newSet, R + 1n));
        const gR = await txGas(verifier, verArt.abi, "verifyBundle", [atR, trustOld, ctx]);

        // Catch-up bundle at B: hop R and header B, both by reference.
        const atB = toHex(encodeCosmWasmProof({
            bundleContent: content, header: hashHeaderRef(encB.headerHash), hops: [hashHeaderRef(encR.headerHash)],
            multistoreProof: pB.queue.multistoreProof, entry: encodeEntry(pB.queue)
        }));
        const [, payloads] = await verifyBundle(atB);
        expect(payloads).toEqual([PAYLOAD]);
        const gB = await txGas(verifier, verArt.abi, "verifyBundle", [atB, trustOld, ctx]);
        for (const g of [a1, a2, a3, gR, gB]) expect(g.gas).toBeLessThan(HEDERA_GAS_LIMIT);
        report["split: accumulate R 1/2"] = {signatures: r1.signerIndices.length, gas: Number(a1.gas), calldata: a1.calldata, fits: "yes"};
        report["split: accumulate R 2/2"] = {signatures: r2.signerIndices.length, gas: Number(a2.gas), calldata: a2.calldata, fits: "yes"};
        report["split: accumulate B"] = {signatures: encB.signerIndices.length, gas: Number(a3.gas), calldata: a3.calldata, fits: "yes"};
        report["split: bundle at R by hash"] = {signatures: 0, gas: Number(gR.gas), calldata: gR.calldata, fits: "yes"};
        report["split: bundle at B, hop R, by hash"] = {signatures: 0, gas: Number(gB.gas), calldata: gB.calldata, fits: "yes"};
    }, 120_000);

    // ── Negative cases on live data ─────────────────────────────────────────

    it("rejects: flipped signature byte", async () => {
        const sig = Buffer.from(shR.commit.signatures[encR.signerIndices[0]].signature!, "base64");
        const bad = Buffer.from(encR.signedHeader);
        bad[bad.indexOf(sig) + 5] ^= 0x01;
        await expectRevert(verifyBundle(bundleAtR(inlineHeaderRef(valsR, bad))), "InvalidSignature");
    });

    it("rejects: below threshold (minimal subset minus one signer)", async () => {
        const short = encodeSignedHeader(shR, valsR, {only: encR.signerIndices.slice(0, -1)});
        expect(short.signedPower * 3n).toBeLessThanOrEqual(short.totalPower * 2n);
        await expectRevert(verifyBundle(bundleAtR(inlineHeaderRef(valsR, short.signedHeader))), "QuorumNotMet");
    });

    it("rejects: wrong validator set (the new set's anchor for an old-set header)", async () => {
        await expectRevert(verifyBundle(bundleAtR(), anchor(newSet, R - 10n)), "ValidatorSetHashMismatch");
    });

    it("rejects: stale or replayed header (anchor already past R)", async () => {
        await expectRevert(verifyBundle(bundleAtR(), anchor(oldSet, R + 1n)), "HeightTooOld");
    });

    it("rejects: tampered IAVL proof and another channel's key", async () => {
        const forged = {...pR.queue, iavlProof: Buffer.from(pR.queue.iavlProof)};
        forged.iavlProof[forged.iavlProof.length - 3] ^= 0x01;
        await expect(verifyBundle(bundleAtR(undefined, encodeEntry(forged)))).rejects.toThrow();
        const otherCtx = toHex(Buffer.concat([Buffer.alloc(32, 9), contract]));
        await expectRevert(
            pub.readContract({address: verifier, abi: abi as never, functionName: "verifyBundle", args: [bundleAtR(), trustOld, otherCtx]}),
            "StorageKeyMismatch"
        );
    });

    it("rejects: a commit for another chain id (accumulator pinned to pio-mainnet-1)", async () => {
        const other = await deploy(accArt.abi, accArt.bytecode, ["pio-testnet-1", 0, ed25519]);
        await expectRevert(
            pub.readContract({address: other, abi: accArt.abi as never, functionName: "checkHeader", args: [toHex(encodeValidatorSet(valsR)), toHex(encR.signedHeader), toHex(oldSet), R]}),
            "ChainIdMismatch"
        );
    });

    // ── THORChain: 67 equal-power signatures over 4 transactions ────────────

    it("THORChain (cometbft-live fixture): the 43.6M-gas commit accumulates in 4 transactions", async () => {
        const th = JSON.parse(readFileSync(path.join(COMETBFT_FIXTURE_DIR, "thorchain.json"), "utf8"));
        const s = sh(th.raw.commit);
        const v = vals(th.raw.validators);
        const enc = encodeSignedHeader(s, v);
        const acc = await deploy(accArt.abi, accArt.bytecode, [s.header.chain_id, 0, ed25519]);
        const per = Math.ceil(enc.signerIndices.length / 4);
        const gases: bigint[] = [];
        for (let i = 0; i < enc.signerIndices.length; i += per) {
            gases.push((await accumulate(acc, v, encodeSignedHeader(s, v, {only: enc.signerIndices.slice(i, i + per)}).signedHeader)).gas);
        }
        const h = (await pub.readContract({address: acc, abi: accArt.abi as never, functionName: "finalizedHeader", args: [toHex(enc.headerHash)]})) as any;
        expect(h.appHash).toBe(("0x" + s.header.app_hash.toLowerCase()) as Hex);
        for (const g of gases) expect(g).toBeLessThan(HEDERA_GAS_LIMIT);
        report["THORChain accumulate (4 txs)"] = {signatures: enc.signerIndices.length, gas: gases.map(Number).join(" + "), calldata: "-", fits: "yes"};
    }, 120_000);
});
