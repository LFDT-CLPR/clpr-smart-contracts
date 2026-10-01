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
import {decodeAbciProof, encodeSignedHeader, encodeValidatorSet, parseRpcValidator, toHex, validatorSetHash, type EncodedCommit, type LiveValidator, type RpcSignedHeader} from "../../relay/cometbft.js";
import {canonicalAddress, encodeCosmWasmProof, encodeEntry, hashHeaderRef, inlineHeaderRef, mapKey} from "../../relay/cosmwasm.js";
import {FIXTURE_DIR} from "../../relay/buildThorchainLiveFixture.js";

/// THORChain (thorchain-1) full bundle: CometBftCommitAccumulator + CosmWasmVerifier against LIVE
/// mainnet data, replayed offline from test/e2e/fixtures/thorchain-live/thorchain.json
/// (re-record: `npm run thorchain-live:refresh`).
///
/// THORChain's validators all have power 100, so no power ordering helps: >2/3 is 64 of 95 (at the
/// churn R) or 67 of 99 (now) Ed25519 signatures, ~41-43M gas. Every commit is therefore split over
/// 4 `accumulate` transactions (≤ 15M each), and the bundle references the header by hash. The state
/// proof is a real ICS-23 multistore + IAVL proof from THORChain's `wasm` store (App Layer) for the
/// Rujira swap router: its cw2 Item and a cw-storage-plus Map entry by existence, and the CLPR queue
/// record key (absent there) by non-existence.
///
/// Run: forge build && npm run test:e2e:thorchain-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8601);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HEDERA_GAS_LIMIT = 15_000_000n;
const HEDERA_CALLDATA_LIMIT = 131_072;
const PAYLOAD: Hex = "0xc1a9c0ffee";
const BATCHES = 4;

const fx = JSON.parse(readFileSync(path.join(FIXTURE_DIR, "thorchain.json"), "utf8"));
const vals = (pages: any[]): LiveValidator[] => pages.flatMap((p) => p.result.validators).map(parseRpcValidator);
const sh = (commitJson: any): RpcSignedHeader => commitJson.result.signed_header;
const anchor = (hash: Buffer, height: bigint): Hex => toHex(Buffer.concat([hash, Buffer.from(height.toString(16).padStart(16, "0"), "hex")]));
const hexBuf = (h: string) => Buffer.from(h.replace(/^0x/, ""), "hex");

const report: Record<string, Record<string, string | number>> = {};

describe("THORChain (CosmWasm App Layer) on live mainnet data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let ed25519: Hex;
    let accumulator: Hex;
    let verifier: Hex;
    const accArt = loadArtifact("CometBftCommitAccumulator");
    const verArt = loadArtifact("CosmWasmVerifier");
    const abi = [...verArt.abi, ...accArt.abi.filter((x: any) => x.type === "error")] as readonly unknown[];

    const contract = canonicalAddress(fx.contract);
    const ctx = toHex(Buffer.concat([hexBuf(fx.channelId), contract]));
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
    const trustNew = anchor(newSet, R + 1n);

    const bundle = (header: Buffer, p: any, hops: Buffer[] = [], entry = encodeEntry(p)) =>
        toHex(encodeCosmWasmProof({bundleContent: content, header, hops, multistoreProof: p.multistoreProof, entry}));

    async function deploy(a: readonly unknown[], bytecode: Hex, args: unknown[] = []): Promise<Hex> {
        const hash = await wallet.deployContract({abi: a as never, bytecode, args: args as never, account: wallet.account!, chain: null});
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error("deploy failed");
        return r.contractAddress;
    }

    async function txGas(to: Hex, a: readonly unknown[], fn: string, args: unknown[]): Promise<{gas: bigint; calldata: number}> {
        const data = encodeFunctionData({abi: a, functionName: fn, args} as any);
        return {gas: await pub.estimateGas({account: wallet.account!, to, data}), calldata: (data.length - 2) / 2};
    }

    async function accumulate(at: Hex, v: LiveValidator[], signedHeader: Buffer): Promise<{gas: bigint; calldata: number}> {
        const args = [toHex(encodeValidatorSet(v)), toHex(signedHeader)];
        const est = await txGas(at, accArt.abi, "accumulate", args);
        const hash = await wallet.writeContract({address: at, abi: accArt.abi as never, functionName: "accumulate" as never, args: args as never, account: wallet.account!, chain: null, gas: est.gas + 100_000n});
        const r = await pub.waitForTransactionReceipt({hash});
        expect(r.status).toBe("success");
        return {gas: r.gasUsed, calldata: est.calldata};
    }

    /** The minimal signer subset of `enc`, cut into BATCHES signed headers. */
    const batches = (s: RpcSignedHeader, v: LiveValidator[], enc: EncodedCommit): EncodedCommit[] => {
        const per = Math.ceil(enc.signerIndices.length / BATCHES);
        const out: EncodedCommit[] = [];
        for (let i = 0; i < enc.signerIndices.length; i += per) out.push(encodeSignedHeader(s, v, {only: enc.signerIndices.slice(i, i + per)}));
        return out;
    };

    const verifyBundle = (proof: Hex, a: Hex, c: Hex = ctx) =>
        pub.readContract({address: verifier, abi: abi as never, functionName: "verifyBundle", args: [proof, a, c]}) as Promise<any>;

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
        pub = createPublicClient({transport: http(rpc, {timeout: 120_000}), pollingInterval: 100}) as PublicClient;
        const deadline = Date.now() + 30_000;
        for (;;) {
            try {
                await pub.getChainId();
                break;
            } catch (err) {
                if (Date.now() > deadline) throw err;
                await new Promise((r) => setTimeout(r, 200));
            }
        }
        wallet = createWalletClient({account: privateKeyToAccount(ANVIL_KEY), transport: http(rpc, {timeout: 120_000})});
        const ed = loadArtifact("Ed25519Verifier");
        ed25519 = await deploy(ed.abi, ed.bytecode);
        accumulator = await deploy(accArt.abi, accArt.bytecode, [fx.chainId, 0, ed25519]);
        verifier = await deploy(verArt.abi, verArt.bytecode, [{accumulator, storeKey: toHex(Buffer.from("wasm")), bootstrapValidatorsHash: toHex(oldSet), bootstrapHeight: R - 10n}]);
    }, 120_000);

    afterAll(() => {
        anvil?.kill("SIGTERM");
        console.log("\nTHORChain on live data (gas = full transaction, Hedera limit 15,000,000 gas / 131,072 B):");
        console.table(report);
    });

    it("builder: live inputs are self-consistent", () => {
        expect(fx.chainId).toBe("thorchain-1");
        expect(shR.header.validators_hash.toLowerCase()).toBe(oldSet.toString("hex"));
        expect(shR.header.next_validators_hash.toLowerCase()).toBe(newSet.toString("hex")); // a real churn
        expect(new Set(valsB.map((v) => v.power))).toEqual(new Set([100n])); // equal power
        expect(encR.signerIndices.length * 3).toBeGreaterThan(valsR.length * 2);
        expect(encB.signerIndices.length * 3).toBeGreaterThan(valsB.length * 2);
        expect(contract.length).toBe(32);
        expect(pB.queue.value.length).toBe(0); // no CLPR Service: the queue record is absent
        expect(JSON.parse(pB.cw2.value.toString()).contract).toBe("rujira-thorchain-swap");
        expect(pB.map.value.toString()).toMatch(/^"thor1/);
        for (const p of Object.values(pR) as any[]) expect(p.height).toBe(R - 1n);
        for (const p of Object.values(pB) as any[]) expect(p.height).toBe(B - 1n);
    });

    it("one transaction does not fit: inline commit + state proof", async () => {
        const proof = bundle(inlineHeaderRef(valsB, encB.signedHeader), pB.queue);
        const [, payloads] = await verifyBundle(proof, trustNew); // correct, just too big
        expect(payloads).toEqual([PAYLOAD]);
        const g = await txGas(verifier, verArt.abi, "verifyBundle", [proof, trustNew, ctx]);
        expect(g.gas).toBeGreaterThan(HEDERA_GAS_LIMIT);
        report["bundle at B, inline commit (1 tx)"] = {signatures: encB.signerIndices.length, gas: Number(g.gas), calldata: g.calldata, fits: "NO"};
    }, 300_000);

    it("rotation: R's commit (64 sigs) over 4 txs, then the bundle at R by hash → new anchor", async () => {
        const bs = batches(shR, valsR, encR);
        expect(bs.length).toBe(BATCHES);
        const gas: bigint[] = [];
        for (const [i, b] of bs.entries()) {
            if (i === BATCHES - 1) {
                await expectRevert(verifyBundle(bundle(hashHeaderRef(encR.headerHash), pR.queue), trustOld), "NotFinalized");
            }
            const a = await accumulate(accumulator, valsR, b.signedHeader);
            gas.push(a.gas);
            report[`accumulate R ${i + 1}/${BATCHES}`] = {signatures: b.signerIndices.length, gas: Number(a.gas), calldata: a.calldata, fits: a.gas < HEDERA_GAS_LIMIT ? "yes" : "NO"};
        }
        for (const g of gas) expect(g).toBeLessThan(HEDERA_GAS_LIMIT);

        const proof = bundle(hashHeaderRef(encR.headerHash), pR.queue);
        const [metadata, payloads, newAnchor, newAnchorId] = await verifyBundle(proof, trustOld);
        expect(metadata.nextMessageId).toBe(0n);
        expect(payloads).toEqual([PAYLOAD]);
        expect(newAnchor).toBe(trustNew);
        expect(newAnchorId).toBe(newAnchor);
        const g = await txGas(verifier, verArt.abi, "verifyBundle", [proof, trustOld, ctx]);
        expect(g.gas).toBeLessThan(HEDERA_GAS_LIMIT);
        expect(g.calldata).toBeLessThan(HEDERA_CALLDATA_LIMIT);
        report["bundle at R by hash (rotation)"] = {signatures: 0, gas: Number(g.gas), calldata: g.calldata, fits: "yes"};
    }, 600_000);

    it("typical: B's commit (67 sigs) over 4 txs, then the bundle at B by hash from the anchor R returned", async () => {
        const bs = batches(shB, valsB, encB);
        for (const [i, b] of bs.entries()) {
            const a = await accumulate(accumulator, valsB, b.signedHeader);
            expect(a.gas).toBeLessThan(HEDERA_GAS_LIMIT);
            report[`accumulate B ${i + 1}/${BATCHES}`] = {signatures: b.signerIndices.length, gas: Number(a.gas), calldata: a.calldata, fits: "yes"};
        }
        const proof = bundle(hashHeaderRef(encB.headerHash), pB.queue);
        const [metadata, payloads, newAnchor] = await verifyBundle(proof, trustNew);
        expect(metadata.nextMessageId).toBe(0n);
        expect(payloads).toEqual([PAYLOAD]);
        expect(newAnchor).toBe(shB.header.next_validators_hash === shB.header.validators_hash ? "0x" : anchor(hexBuf(shB.header.next_validators_hash), B + 1n));
        const g = await txGas(verifier, verArt.abi, "verifyBundle", [proof, trustNew, ctx]);
        expect(g.gas).toBeLessThan(HEDERA_GAS_LIMIT);
        report["bundle at B by hash"] = {signatures: 0, gas: Number(g.gas), calldata: g.calldata, fits: "yes"};

        // Catch-up: a relay that still holds the pre-churn anchor crosses R as a hop, both by hash.
        const catchUp = bundle(hashHeaderRef(encB.headerHash), pB.queue, [hashHeaderRef(encR.headerHash)]);
        const [, p2] = await verifyBundle(catchUp, trustOld);
        expect(p2).toEqual([PAYLOAD]);
        const g2 = await txGas(verifier, verArt.abi, "verifyBundle", [catchUp, trustOld, ctx]);
        report["bundle at B, hop R, by hash"] = {signatures: 0, gas: Number(g2.gas), calldata: g2.calldata, fits: "yes"};
    }, 600_000);

    it("verifyContractEntry: the live Rujira contract's cw2 Item and Map vaults[avax-avax], by existence proof", async () => {
        for (const [name, key, entry] of [
            ["cw2 contract_info", Buffer.from("contract_info"), pB.cw2],
            ["Map vaults[avax-avax]", mapKey(fx.mapNamespace, Buffer.from(fx.mapKey)), pB.map]
        ] as const) {
            const proof = toHex(encodeCosmWasmProof({header: hashHeaderRef(encB.headerHash), multistoreProof: entry.multistoreProof, entry: encodeEntry(entry)}));
            const args = [proof, trustNew, toHex(contract), toHex(key)];
            const [exists, value, height] = (await pub.readContract({address: verifier, abi: abi as never, functionName: "verifyContractEntry", args: args as never})) as [boolean, Hex, bigint];
            expect(exists).toBe(true);
            expect(value).toBe(toHex(entry.value));
            expect(height).toBe(B);
            const g = await txGas(verifier, verArt.abi, "verifyContractEntry", args);
            expect(g.gas).toBeLessThan(HEDERA_GAS_LIMIT);
            report[`entry: ${name}`] = {signatures: 0, gas: Number(g.gas), calldata: g.calldata, fits: "yes"};
        }
    });

    // ── Negative cases on live data ─────────────────────────────────────────

    it("rejects: a replayed batch (no new signatures) and a flipped signature byte", async () => {
        await expect(accumulate(accumulator, valsB, batches(shB, valsB, encB)[0].signedHeader)).rejects.toThrow(/NoNewSignatures|revert/);
        const fresh = await deploy(accArt.abi, accArt.bytecode, [fx.chainId, 0, ed25519]);
        const one = encodeSignedHeader(shB, valsB, {only: encB.signerIndices.slice(0, 1)}).signedHeader;
        const sig = Buffer.from(shB.commit.signatures[encB.signerIndices[0]].signature!, "base64");
        const bad = Buffer.from(one);
        bad[bad.indexOf(sig) + 5] ^= 0x01;
        await expectRevert(
            pub.simulateContract({address: fresh, abi: accArt.abi as never, functionName: "accumulate" as never, args: [toHex(encodeValidatorSet(valsB)), toHex(bad)] as never, account: wallet.account!}),
            "InvalidSignature"
        );
    }, 120_000);

    it("rejects: wrong validator set, stale anchor, another channel, tampered IAVL proof", async () => {
        const atB = bundle(hashHeaderRef(encB.headerHash), pB.queue);
        await expectRevert(verifyBundle(atB, anchor(oldSet, R + 1n)), "ValidatorSetHashMismatch");
        await expectRevert(verifyBundle(atB, anchor(newSet, B + 1n)), "HeightTooOld");
        await expectRevert(verifyBundle(atB, trustNew, toHex(Buffer.concat([Buffer.alloc(32, 9), contract]))), "StorageKeyMismatch");
        const forged = {...pB.queue, iavlProof: Buffer.from(pB.queue.iavlProof)};
        forged.iavlProof[forged.iavlProof.length - 3] ^= 0x01;
        await expect(verifyBundle(bundle(hashHeaderRef(encB.headerHash), pB.queue, [], encodeEntry(forged)), trustNew)).rejects.toThrow();
    });
});
