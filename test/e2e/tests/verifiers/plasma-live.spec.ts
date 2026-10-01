import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {readFileSync} from "node:fs";
import path from "node:path";
import {BaseError, ContractFunctionRevertedError, createPublicClient, createWalletClient, encodeFunctionData, http, keccak256, type Hex, type PublicClient, type WalletClient} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {loadArtifact} from "../../../../script/deploy/artifacts.js";
import {pbLen} from "../../lib/proto.js";
import {encodeHeader, storageEntries} from "../../relay/evmHeader.js";
import {committeeRoot, decodeBlockV1, decodeGossip, encodePlasmaBundle, finalityItem, hx, plasmaAnchor, qcRoot, sortKeys, toHex, verifyQc} from "../../relay/plasma.js";
import {PLASMA_FIXTURE_DIR} from "../../relay/buildPlasmaLiveFixture.js";
import {channelSlots} from "../../relay/buildCometBftLiveFixture.js";

/// PlasmaBftVerifier (src/verifiers/evm/plasma) against LIVE Plasma mainnet data, replayed offline from
/// test/e2e/fixtures/plasma-live/mainnet.json (re-record: `npm run plasma-live:refresh`).
///
/// The fixture holds the raw gossip bytes of consensus blocks B, B+1, B+2 and raw public-RPC JSON
/// (block, eth_getProof); every proof is re-derived here with relay/plasma.ts. The production verifier
/// runs unmodified (EIP-2537 pairing on anvil). No ClprService exists on Plasma, so the "service" is
/// the validator-set proxy: its channel slots are absent → MPT exclusion proofs → zeroed metadata.
///
/// Run: forge build && npm run test:e2e:plasma-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8598);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HEDERA_GAS_LIMIT = 15_000_000n;
const HEDERA_CALLDATA_LIMIT = 131_072;
const PAYLOAD: Hex = "0xc1a9c0ffee";

const fx = JSON.parse(readFileSync(path.join(PLASMA_FIXTURE_DIR, "mainnet.json"), "utf8"));
const bytes = (h: Hex) => (h.length - 2) / 2;
const report: Record<string, Record<string, string | number>> = {};

describe("PlasmaBftVerifier on live Plasma mainnet data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let verifier: Hex;
    const art = loadArtifact("PlasmaBftVerifier");

    const N = BigInt(fx.height);
    const keys = sortKeys(fx.committee.map(hx));
    const [b0, b1, b2] = fx.gossip.map((g: string) => decodeBlockV1(decodeGossip(hx(g)).block));
    const ctx = (fx.channelId + fx.target.slice(2).toLowerCase()) as Hex;
    const bundleContent = toHex(pbLen(2, Buffer.from(PAYLOAD.slice(2), "hex")));
    const anchor = plasmaAnchor(fx.committeeRoot, N);

    const bundle = (finality: any[] = finalityItem(keys, b0, b1, b2)) =>
        encodePlasmaBundle({
            finality,
            serviceAccountProof: fx.serviceProof.accountProof,
            storageEntries: storageEntries(fx.serviceProof.storageProof.slice(0, 5)),
            bundleContent
        });

    const call = (proof: Hex, a: Hex = anchor) =>
        pub.readContract({address: verifier, abi: art.abi as never, functionName: "verifyBundle", args: [proof, a, ctx]}) as Promise<any>;

    async function txGas(proof: Hex) {
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

    beforeAll(async () => {
        anvil = spawn("anvil", ["--port", String(ANVIL_PORT), "--silent", "--hardfork", "prague", "--disable-block-gas-limit"], {stdio: "ignore"});
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
        const hash = await wallet.deployContract({
            abi: art.abi as never, bytecode: art.bytecode, account: wallet.account!, chain: null,
            args: [{chainId: String(fx.chainId), bootstrapCommitteeRoot: fx.committeeRoot, bootstrapHeight: N}] as never
        });
        const r = await pub.waitForTransactionReceipt({hash});
        verifier = r.contractAddress!;
    });

    afterAll(() => {
        anvil?.kill("SIGTERM");
        console.log("\nPlasma (PlasmaBFT) on live mainnet data (gas = full transaction; Hedera limit 15,000,000 gas / 131,072 B):");
        console.table(report);
    });

    it("fixture: gossip blocks, QCs, committee and proofs are self-consistent", () => {
        for (const g of fx.gossip) expect(toHex(decodeBlockV1(decodeGossip(hx(g)).block).hash)).toBe(toHex(decodeGossip(hx(g)).blockHash));
        expect(b0.evm.number).toBe(N);
        expect(toHex(b0.evm.stateRoot)).toBe(fx.evmBlock.stateRoot);
        expect(toHex(b0.evm.blockHash)).toBe(fx.evmBlock.hash);
        expect(keccak256(encodeHeader(fx.evmBlock))).toBe(fx.evmBlock.hash);
        expect(keccak256(fx.serviceProof.accountProof[0])).toBe(fx.evmBlock.stateRoot);
        expect(toHex(committeeRoot(keys))).toBe(fx.committeeRoot);
        expect(toHex(b1.leaves[6])).toBe(toHex(qcRoot(b1.qc)));
        expect(toHex(b1.qc.blockHash)).toBe(toHex(b0.hash));
        expect(toHex(b2.qc.blockHash)).toBe(toHex(b1.hash));
        expect(verifyQc(b1.qc, keys) && verifyQc(b2.qc, keys)).toBe(true);
        expect(fx.serviceProof.storageProof.slice(0, 5).map((p: any) => p.key)).toEqual(channelSlots(fx.channelId));
        expect(fx.serviceProof.storageProof.slice(0, 5).every((p: any) => BigInt(p.value) === 0n)).toBe(true);
        expect(BigInt(fx.serviceProof.storageProof[5].value)).not.toBe(0n); // the real non-zero slot (ERC-1967 impl)
    });

    it("verifyBundle: two real QCs over B and B+1 → zeroed metadata, payload, anchor unchanged", async () => {
        const proof = bundle();
        const [metadata, payloads, newAnchor, newAnchorId] = await call(proof);
        expect(metadata.nextMessageId).toBe(0n);
        expect(payloads).toEqual([PAYLOAD]);
        expect(newAnchor).toBe("0x");
        expect(newAnchorId).toBe("0x");
        const g = await txGas(proof);
        expect(g.gas).toBeLessThan(HEDERA_GAS_LIMIT);
        expect(g.calldata).toBeLessThan(HEDERA_CALLDATA_LIMIT);
        report["bundle"] = {height: Number(N), committee: keys.length, "QC1 votes": b1.qc.votes.length, "QC2 votes": b2.qc.votes.length, gas: Number(g.gas), calldata: g.calldata, fits: "yes"};
    });

    it("rejects: QC2 signature taken from QC1", async () => {
        const f = finalityItem(keys, b0, b1, b2);
        f[5] = [...f[5]];
        [f[5][3], f[5][4]] = [f[4][3], f[4][4]];
        await expectRevert(call(bundle(f)), "BlsSignatureInvalid");
    });

    it("rejects: below quorum (QC2 minus one voter)", async () => {
        const f = finalityItem(keys, b0, b1, b2);
        f[5] = [...f[5]];
        f[5][2] = f[5][2].slice(1);
        await expectRevert(call(bundle(f)), "QuorumNotMet");
    });

    it("rejects: wrong committee (anchor for another committee)", async () => {
        await expectRevert(call(bundle(), plasmaAnchor(`0x${"07".repeat(32)}`, N)), "CommitteeRootMismatch");
    });

    it("rejects: stale data (anchor height above B)", async () => {
        await expectRevert(call(bundle(), plasmaAnchor(fx.committeeRoot, N + 1n)), "HeightTooOld");
    });

    it("rejects: B+2 offered as the child of B", async () => {
        const f = finalityItem(keys, b0, b1, b2);
        f[3] = toHex(Uint8Array.from(Buffer.concat(b2.leaves.map((x: Uint8Array) => Buffer.from(x)))));
        await expectRevert(call(bundle(f)), "NotChildOfCertifiedBlock");
    });

    it("rejects: ClprService storage proof for another channel", async () => {
        const other = (`0x${"ab".repeat(32)}` + fx.target.slice(2).toLowerCase()) as Hex;
        await expect(pub.readContract({address: verifier, abi: art.abi as never, functionName: "verifyBundle", args: [bundle(), anchor, other]})).rejects.toThrow();
    });
});
