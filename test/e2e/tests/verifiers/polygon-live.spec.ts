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
import {loadArtifact} from "../../../../script/deploy/artifacts.js";
import {pbLen} from "../../lib/proto.js";
import {decodeAbciProof, encodeSignedHeader, parseRpcValidator, toHex, validatorSetHash, type LiveValidator, type RpcSignedHeader} from "../../relay/cometbft.js";
import {encodeEntry, inlineHeaderRef} from "../../relay/cosmwasm.js";
import {decodeCount, decodeMilestone, encodeAccountProof, encodeBorHeader, encodePolygonProof, encodeStorageProof, MILESTONE_COUNT_KEY, milestoneKey, storageValue, type EthProof} from "../../relay/polygon.js";
import {deriveChannelSlots} from "../../relay/buildEthMainnetProof.js";
import {FIXTURE_DIR} from "../../relay/buildPolygonLiveFixture.js";

/// PolygonPosVerifier (src/verifiers/evm/polygon) against LIVE Polygon PoS mainnet data, replayed
/// offline from test/e2e/fixtures/polygon-live/polygon.json (re-record: `npm run polygon-live:refresh`).
///
/// The whole chain is real: a Heimdall v2 commit (secp256k1eth, 10 of ~104 validators clear 2/3 by
/// power) → ICS-23 multistore proof of store `milestone` → IAVL existence proof of the latest
/// milestone (0x81 ‖ count) → the Bor header whose keccak256 is milestone.hash → Bor stateRoot →
/// MPT account proof of WPOL → MPT storage proofs. No ClprService exists on Polygon yet, so the
/// channel's five slots are real MPT exclusion proofs (zero metadata); `verifyContractSlots` proves
/// WPOL's non-zero slots 0-2 (name, symbol, decimals) through the same path.
///
/// Run: forge build && npm run test:e2e:polygon-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8602);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HEDERA_GAS_LIMIT = 15_000_000n;
const HEDERA_CALLDATA_LIMIT = 131_072;
const PAYLOAD: Hex = "0xc1a9c0ffee";
const SECP256K1_ETH = 1;

const fx = JSON.parse(readFileSync(path.join(FIXTURE_DIR, "polygon.json"), "utf8"));
const hexBuf = (h: string) => Buffer.from(h.replace(/^0x/, ""), "hex");
const anchor = (hash: Buffer, height: bigint): Hex => toHex(Buffer.concat([hash, Buffer.from(height.toString(16).padStart(16, "0"), "hex")]));
const report: Record<string, Record<string, string | number>> = {};

interface Capture {
    height: bigint;
    sh: RpcSignedHeader;
    vals: LiveValidator[];
    setHash: Buffer;
    enc: ReturnType<typeof encodeSignedHeader>;
    milestone: ReturnType<typeof decodeAbciProof>;
    borHeader: Buffer;
    borProof: EthProof;
}

function load(c: any): Capture {
    const sh = c.raw.commit.result.signed_header as RpcSignedHeader;
    const vals = (c.raw.validators as any[]).flatMap((p) => p.result.validators).map(parseRpcValidator);
    const count = decodeCount(decodeAbciProof(c.raw.abci.count, MILESTONE_COUNT_KEY).value);
    return {
        height: BigInt(c.height), sh, vals, setHash: validatorSetHash(vals), enc: encodeSignedHeader(sh, vals),
        milestone: decodeAbciProof(c.raw.abci.milestone, milestoneKey(count)),
        borHeader: encodeBorHeader(c.raw.borBlock), borProof: c.raw.borProof
    };
}

describe("Polygon PoS (Heimdall milestone → Bor MPT) on live mainnet data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let verifier: Hex;
    const accArt = loadArtifact("CometBftCommitAccumulator");
    const verArt = loadArtifact("PolygonPosVerifier");
    const abi = [...verArt.abi, ...accArt.abi.filter((x: any) => x.type === "error")] as readonly unknown[];

    const T = load(fx.typical);
    const R = fx.rotation ? load(fx.rotation) : undefined;
    const B = fx.afterRotation ? load(fx.afterRotation) : undefined;
    const bootstrapSet = R ? R.setHash : T.setHash;
    const bootstrapHeight = (R ?? T).height - 10n;
    const channelSlots = deriveChannelSlots(fx.channelId);
    const ctx = toHex(Buffer.concat([hexBuf(fx.channelId), hexBuf(fx.service)]));
    const content = pbLen(2, hexBuf(PAYLOAD));

    const parts = (c: Capture, over: Partial<Parameters<typeof encodePolygonProof>[0]> = {}) => ({
        bundleContent: content,
        header: inlineHeaderRef(c.vals, c.enc.signedHeader),
        multistoreProof: c.milestone.multistoreProof,
        milestoneEntry: encodeEntry(c.milestone),
        borHeader: c.borHeader,
        accountProof: encodeAccountProof(c.borProof),
        storageProof: encodeStorageProof(c.borProof, channelSlots),
        ...over
    });
    const bundle = (c: Capture, over = {}) => toHex(encodePolygonProof(parts(c, over)));

    async function deploy(a: readonly unknown[], bytecode: Hex, args: unknown[] = []): Promise<Hex> {
        const hash = await wallet.deployContract({abi: a as never, bytecode, args: args as never, account: wallet.account!, chain: null});
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error("deploy failed");
        return r.contractAddress;
    }

    async function txGas(fn: string, args: unknown[]): Promise<{gas: bigint; calldata: number}> {
        const data = encodeFunctionData({abi: verArt.abi, functionName: fn, args} as any);
        return {gas: await pub.estimateGas({account: wallet.account!, to: verifier, data}), calldata: (data.length - 2) / 2};
    }

    const verifyBundle = (proof: Hex, a: Hex, c: Hex = ctx) =>
        pub.readContract({address: verifier, abi: abi as never, functionName: "verifyBundle", args: [proof, a, c]}) as Promise<any>;

    async function expectRevert(p: Promise<unknown>, errorName?: string) {
        try {
            await p;
        } catch (e) {
            if (!errorName) return;
            const rev = (e as BaseError).walk((x) => x instanceof ContractFunctionRevertedError) as ContractFunctionRevertedError | null;
            expect(rev?.data?.errorName ?? (e as Error).message).toBe(errorName);
            return;
        }
        throw new Error(`expected revert ${errorName ?? ""}`);
    }

    function record(name: string, sigs: number, g: {gas: bigint; calldata: number}) {
        expect(g.gas).toBeLessThan(HEDERA_GAS_LIMIT);
        expect(g.calldata).toBeLessThan(HEDERA_CALLDATA_LIMIT);
        report[name] = {signatures: sigs, gas: Number(g.gas), calldata: g.calldata, fits: "yes"};
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
        const accumulator = await deploy(accArt.abi, accArt.bytecode, [fx.chainId, SECP256K1_ETH, "0x0000000000000000000000000000000000000000"]);
        verifier = await deploy(verArt.abi, verArt.bytecode, [{
            accumulator, storeKey: toHex(Buffer.from("milestone")), borChainId: fx.borChainId,
            bootstrapValidatorsHash: toHex(bootstrapSet), bootstrapHeight
        }]);
    }, 120_000);

    afterAll(() => {
        anvil?.kill("SIGTERM");
        console.log("\nPolygon PoS on live data (gas = full transaction, Hedera limit 15,000,000 gas / 131,072 B):");
        console.table(report);
    });

    it("builder: live inputs are self-consistent", () => {
        expect(fx.chainId).toBe("heimdallv2-137");
        for (const c of [T, R, B].filter(Boolean) as Capture[]) {
            const m = decodeMilestone(c.milestone.value);
            expect(m.borChainId).toBe("137");
            expect(toHex(m.hash)).toBe(keccak256(c.borHeader));
            expect(c.milestone.height).toBe(c.height - 1n);
            expect(c.enc.signedPower * 3n).toBeGreaterThan(c.enc.totalPower * 2n);
            for (const s of channelSlots) expect(storageValue(c.borProof, s)).toBe(0n); // no ClprService
        }
        if (R && B) {
            expect(R.sh.header.next_validators_hash).not.toBe(R.sh.header.validators_hash); // a real rotation
            expect(B.sh.header.validators_hash).toBe(R.sh.header.next_validators_hash);
        }
    });

    it("verifyBundle: Heimdall commit → milestone → Bor header → WPOL storage, in one transaction", async () => {
        const a = anchor(T.setHash, T.height - 10n);
        const proof = bundle(T);
        const [metadata, payloads, newAnchor] = await verifyBundle(proof, a);
        expect(metadata.nextMessageId).toBe(0n);
        expect(metadata.sentRunningHash).toBe(toHex(Buffer.alloc(32)));
        expect(payloads).toEqual([PAYLOAD]);
        expect(newAnchor).toBe(T.sh.header.next_validators_hash === T.sh.header.validators_hash ? "0x" : anchor(hexBuf(T.sh.header.next_validators_hash), T.height + 1n));
        record("typical bundle (1 tx)", T.enc.signerIndices.length, await txGas("verifyBundle", [proof, a, ctx]));
        report["typical bundle (1 tx)"].heimdall = Number(T.height);
        report["typical bundle (1 tx)"].bor = fx.typical.borBlock;
    });

    it("verifyContractSlots: WPOL's real slots 0-2 (name, symbol, decimals) at the milestone block", async () => {
        const c = R ?? T;
        const slots = fx.slots.slice(5) as Hex[];
        const proof = toHex(encodePolygonProof({...parts(c), bundleContent: undefined, storageProof: encodeStorageProof(c.borProof, slots)}));
        const a = anchor(c.setHash, bootstrapHeight);
        const args = [proof, a, fx.service, slots.map((s) => toHex(Buffer.from(BigInt(s).toString(16).padStart(64, "0"), "hex")))];
        const [values, borBlock, heimdall] = (await pub.readContract({address: verifier, abi: abi as never, functionName: "verifyContractSlots", args: args as never})) as [Hex[], bigint, bigint];
        values.forEach((v, i) => expect(BigInt(v)).toBe(storageValue(c.borProof, slots[i])));
        expect(BigInt(values[2])).toBe(18n); // decimals
        expect(BigInt(values[0])).not.toBe(0n);
        expect(borBlock).toBe(BigInt(R ? fx.rotation.borBlock : fx.typical.borBlock));
        expect(heimdall).toBe(c.height);
        record("verifyContractSlots (3 slots)", c.enc.signerIndices.length, await txGas("verifyContractSlots", args));
    });

    it.runIf(R && B)("rotation: bundle at R (signed by the old set) returns the new anchor; B verifies from it", async () => {
        const trustOld = anchor(R!.setHash, bootstrapHeight);
        const atR = bundle(R!);
        const [, , naR] = await verifyBundle(atR, trustOld);
        const trustNew = anchor(B!.setHash, R!.height + 1n);
        expect(naR).toBe(trustNew);
        record("rotation bundle at R (1 tx)", R!.enc.signerIndices.length, await txGas("verifyBundle", [atR, trustOld, ctx]));

        const atB = bundle(B!);
        const [, payloads] = await verifyBundle(atB, trustNew);
        expect(payloads).toEqual([PAYLOAD]);
        record("bundle at B from the new anchor", B!.enc.signerIndices.length, await txGas("verifyBundle", [atB, trustNew, ctx]));

        const catchUp = bundle(B!, {hops: [inlineHeaderRef(R!.vals, R!.enc.signedHeader)]});
        const [, p2] = await verifyBundle(catchUp, trustOld);
        expect(p2).toEqual([PAYLOAD]);
        record("catch-up: hop R inline + bundle at B", R!.enc.signerIndices.length + B!.enc.signerIndices.length, await txGas("verifyBundle", [catchUp, trustOld, ctx]));
    });

    // ── Negative cases on live data ─────────────────────────────────────────

    const C = R ?? T;
    const trust = anchor(C.setHash, bootstrapHeight);

    it("rejects: flipped signature byte", async () => {
        const sig = Buffer.from(C.sh.commit.signatures[C.enc.signerIndices[0]].signature!, "base64");
        const bad = Buffer.from(C.enc.signedHeader);
        bad[bad.indexOf(sig) + 5] ^= 0x01;
        await expectRevert(verifyBundle(bundle(C, {header: inlineHeaderRef(C.vals, bad)}), trust), "InvalidSignature");
    });

    it("rejects: below threshold (minimal subset minus one signer)", async () => {
        const short = encodeSignedHeader(C.sh, C.vals, {only: C.enc.signerIndices.slice(0, -1)});
        await expectRevert(verifyBundle(bundle(C, {header: inlineHeaderRef(C.vals, short.signedHeader)}), trust), "QuorumNotMet");
    });

    it("rejects: wrong validator set and stale anchor", async () => {
        await expectRevert(verifyBundle(bundle(C), anchor(Buffer.alloc(32, 7), bootstrapHeight)), "ValidatorSetHashMismatch");
        await expectRevert(verifyBundle(bundle(C), anchor(C.setHash, C.height + 1n)), "HeightTooOld");
    });

    it("rejects: a Bor header that is not the milestone's, and tampered milestone proof", async () => {
        const other = C === T ? (B ?? R) : T;
        if (other) await expectRevert(verifyBundle(bundle(C, {borHeader: other.borHeader}), trust), "BorHeaderHashMismatch");
        const forged = {...C.milestone, iavlProof: Buffer.from(C.milestone.iavlProof)};
        forged.iavlProof[forged.iavlProof.length - 3] ^= 0x01;
        await expectRevert(verifyBundle(bundle(C, {milestoneEntry: encodeEntry(forged)}), trust));
    });

    it("rejects: another service's account and another channel's slots", async () => {
        const otherSvc = toHex(Buffer.concat([hexBuf(fx.channelId), Buffer.alloc(20, 0x11)]));
        await expectRevert(verifyBundle(bundle(C), trust, otherSvc));
        const otherChan = toHex(Buffer.concat([Buffer.alloc(32, 9), hexBuf(fx.service)]));
        await expectRevert(verifyBundle(bundle(C), trust, otherChan), "SlotNotProven");
    });
});

