import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {createHash} from "node:crypto";
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
import {decodeAbciProof, encodeSignedHeader, parseRpcValidator, toHex, validatorSetHash, type AbciStoreProof, type LiveValidator} from "../../relay/cometbft.js";
import {encodeCosmWasmProof, encodeEntry, inlineHeaderRef} from "../../relay/cosmwasm.js";
import {FIXTURE_DIR} from "../../relay/buildDydxClprFixture.js";

/// CosmosModuleVerifier (src/verifiers/evm/dydx) end to end against a REAL x/clpr chain.
///
/// localnet.json was recorded from modules/x-clpr's one-validator chain (dYdX v9.7.1's cosmos-sdk,
/// store, IAVL and CometBFT forks) after scripts/send-demo.sh opened a channel, enqueued three
/// Data Messages and set the endpoint manifest. Every proof is re-derived from the raw RPC JSON;
/// the contracts run unmodified with real Ed25519 (pure-Solidity Ed25519Verifier) and real ICS-23
/// multistore + IAVL proofs of the module's "clpr" store.
///
/// mainnet.json is live dYdX (dydx-mainnet-1): a 10-of-21 Ed25519 commit and an ICS-23 proof of
/// bank supply, verified through the same contract with storeKey "bank". It shows that dYdX's own
/// multistore and IAVL proofs pass the pipeline the module relies on.
///
/// Run: forge build && npm run test:e2e:dydx-xclpr     (re-record: npm run dydx-xclpr:refresh)

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8601);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HEDERA_GAS_LIMIT = 15_000_000n;
const HEDERA_CALLDATA_LIMIT = 131_072;

const load = (n: string) => JSON.parse(readFileSync(path.join(FIXTURE_DIR, n), "utf8"));
const lx = load("localnet.json");
const mx = load("mainnet.json");
const vals = (pages: any[]): LiveValidator[] => pages.flatMap((p) => p.result.validators).map(parseRpcValidator);
const anchor = (hash: Buffer, height: bigint): Hex => toHex(Buffer.concat([hash, Buffer.from(height.toString(16).padStart(16, "0"), "hex")]));
const hexBuf = (h: string) => Buffer.from(h.replace(/^0x/, ""), "hex");
const sha256 = (b: Buffer) => createHash("sha256").update(b).digest();
const proofs = (fx: any): Record<string, AbciStoreProof> =>
    Object.fromEntries(fx.keys.map((k: any, i: number) => [k.name, decodeAbciProof(fx.raw.abci[i], hexBuf(k.key))]));

/** ClprMessageValue{1 payload, 2 running_hash_after_processing}. */
function parseMessageValue(v: Buffer): {payload: Buffer; runningHash: Buffer} {
    const out: Record<number, Buffer> = {};
    let o = 0;
    const varint = () => {
        let r = 0, s = 0;
        for (;;) {
            const b = v[o++];
            r |= (b & 0x7f) << s;
            if (!(b & 0x80)) return r;
            s += 7;
        }
    };
    while (o < v.length) {
        const tag = varint();
        const len = varint();
        out[tag >> 3] = v.subarray(o, o + len);
        o += len;
    }
    return {payload: out[1], runningHash: out[2]};
}

const report: Record<string, Record<string, string | number>> = {};

describe("x/clpr (native Cosmos SDK module) → Hiero: CosmosModuleVerifier", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let ed25519: Hex;
    let verifier: Hex;
    const accArt = loadArtifact("CometBftCommitAccumulator");
    const verArt = loadArtifact("CosmosModuleVerifier");
    const abi = [...verArt.abi, ...accArt.abi.filter((x: any) => x.type === "error")] as readonly unknown[];

    // ── localnet ──
    const H = BigInt(lx.meta.height);
    const sh = lx.raw.commit.result.signed_header;
    const v = vals(lx.raw.validators);
    const setHash = validatorSetHash(v);
    const enc = encodeSignedHeader(sh, v);
    const p = proofs(lx);
    const channelId = hexBuf(lx.channelId);
    const moduleAddr = sha256(Buffer.from("clpr")).subarray(0, 20);
    const ctx = toHex(Buffer.concat([channelId, moduleAddr]));
    const trust = anchor(setHash, H - 10n);
    const header = () => inlineHeaderRef(v, enc.signedHeader);
    const msgs = ["msg1", "msg2", "msg3"].map((n) => parseMessageValue(p[n].value));
    const content = Buffer.concat(msgs.map((m) => pbLen(2, m.payload)));
    const manifest = hexBuf(lx.manifest);

    const bundle = (o: {entry?: Buffer; withManifest?: boolean; hdr?: Buffer} = {}) =>
        toHex(encodeCosmWasmProof({
            bundleContent: content, header: o.hdr ?? header(), multistoreProof: p.queue.multistoreProof,
            entry: o.entry ?? encodeEntry(p.queue),
            ...(o.withManifest === false ? {} : {serviceEntry: encodeEntry(p.service), manifestPreimage: manifest})
        }));
    const entryProof = (name: string) => toHex(encodeCosmWasmProof({header: header(), multistoreProof: p[name].multistoreProof, entry: encodeEntry(p[name])}));

    async function deploy(a: readonly unknown[], bytecode: Hex, args: unknown[] = []): Promise<Hex> {
        const hash = await wallet.deployContract({abi: a as never, bytecode, args: args as never, account: wallet.account!, chain: null});
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error("deploy failed");
        return r.contractAddress;
    }
    const deployVerifier = async (chainId: string, storeKey: string, boot: Buffer, bootHeight: bigint) => {
        const acc = await deploy(accArt.abi, accArt.bytecode, [chainId, 0, ed25519]);
        return deploy(verArt.abi, verArt.bytecode, [{accumulator: acc, storeKey: toHex(Buffer.from(storeKey)), bootstrapValidatorsHash: toHex(boot), bootstrapHeight: bootHeight}]);
    };
    async function txGas(to: Hex, fn: string, args: unknown[]): Promise<{gas: bigint; calldata: number}> {
        const data = encodeFunctionData({abi: verArt.abi, functionName: fn, args} as any);
        return {gas: await pub.estimateGas({account: wallet.account!, to, data}), calldata: (data.length - 2) / 2};
    }
    const read = (fn: string, args: unknown[], at: Hex = verifier) =>
        pub.readContract({address: at, abi: abi as never, functionName: fn, args: args as never}) as Promise<any>;
    async function expectRevert(pr: Promise<unknown>, errorName: string) {
        try {
            await pr;
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
        verifier = await deployVerifier(lx.chainId, "clpr", setHash, H - 10n);
    }, 60_000);

    afterAll(() => {
        anvil?.kill("SIGTERM");
        console.log("\nx/clpr → Hiero (gas = full transaction, Hedera limit 15,000,000 gas / 131,072 B):");
        console.table(report);
    });

    it("builder: the recorded x/clpr state is what the module should have written", () => {
        expect(lx.chainId).toBe("dydx-clpr-local-1");
        expect(sh.header.validators_hash.toLowerCase()).toBe(setHash.toString("hex"));
        for (const e of Object.values(p)) expect(e.height).toBe(H - 1n);
        // Running hash chain, BundleLib form: h' = sha256(h ‖ sha256(payload)).
        let h = Buffer.alloc(32);
        for (const m of msgs) {
            h = sha256(Buffer.concat([h, sha256(m.payload)]));
            expect(m.runningHash.equals(h)).toBe(true);
        }
        // Queue record: format 1, ACTIVE, next 4, received 0, manifest v1, sent hash = h.
        const r = p.queue.value;
        expect(r.length).toBe(90);
        expect([r[0], r[1]]).toEqual([1, 1]);
        expect(r.readBigUInt64BE(2)).toBe(4n);
        expect(r.readBigUInt64BE(18)).toBe(1n);
        expect(r.subarray(26, 58).equals(h)).toBe(true);
        // Service item: module address ‖ keccak256(manifest).
        expect(p.service.value.equals(Buffer.concat([moduleAddr, hexBuf(keccak256(manifest))]))).toBe(true);
        expect(p.msg4.value.length).toBe(0);
    });

    it("verifyBundle: real commit + clpr store proof → queue metadata, payloads and manifest", async () => {
        const proof = bundle();
        const [metadata, payloads, newAnchor, , m] = await read("verifyBundle", [proof, trust, ctx]);
        expect(metadata.nextMessageId).toBe(4n);
        expect(metadata.receivedMessageId).toBe(0n);
        expect(metadata.state).toBe(1); // ACTIVE
        expect(metadata.endpointManifestVersion).toBe(1n);
        expect(metadata.sentRunningHash).toBe(toHex(msgs[2].runningHash));
        expect(payloads).toEqual(msgs.map((x) => toHex(x.payload)));
        expect(newAnchor).toBe("0x"); // single validator, no rotation
        expect(m.version).toBe(1n);
        expect(m.serviceAddress).toBe(toHex(moduleAddr));
        // What ClprService (BundleLib Step 5) then checks: the payloads reproduce the proven hash.
        let h = Buffer.alloc(32);
        for (const x of payloads as Hex[]) h = sha256(Buffer.concat([h, sha256(hexBuf(x))]));
        expect(toHex(h)).toBe(metadata.sentRunningHash);

        const g = await txGas(verifier, "verifyBundle", [proof, trust, ctx]);
        expect(g.gas).toBeLessThan(HEDERA_GAS_LIMIT);
        expect(g.calldata).toBeLessThan(HEDERA_CALLDATA_LIMIT);
        report["localnet bundle (3 msgs + manifest)"] = {signatures: enc.signerIndices.length, gas: Number(g.gas), calldata: g.calldata};
    });

    it("verifyQueueMessage: each queued entry 0x02 ‖ channel ‖ id, by existence proof", async () => {
        for (let i = 0; i < 3; i++) {
            const args = [entryProof(`msg${i + 1}`), trust, toHex(channelId), BigInt(i + 1)];
            const [payload, rh, height] = await read("verifyQueueMessage", args);
            expect(payload).toBe(toHex(msgs[i].payload));
            expect(rh).toBe(toHex(msgs[i].runningHash));
            expect(height).toBe(H);
            if (i === 0) {
                const g = await txGas(verifier, "verifyQueueMessage", args);
                expect(g.gas).toBeLessThan(HEDERA_GAS_LIMIT);
                report["localnet queue entry"] = {signatures: enc.signerIndices.length, gas: Number(g.gas), calldata: g.calldata};
            }
        }
        // Message 4 was never sent: non-existence proof.
        await expectRevert(read("verifyQueueMessage", [entryProof("msg4"), trust, toHex(channelId), 4n]), "EntryNotFound");
        const [exists, value] = await read("verifyModuleEntry", [entryProof("msg4"), trust, toHex(p.msg4.key)]);
        expect(exists).toBe(false);
        expect(value).toBe("0x");
    });

    it("verifyConfig: from the bootstrap checkpoint, binds the module address and manifest", async () => {
        const ledgerConfig = pbLen(2, moduleAddr);
        const proof = toHex(encodeCosmWasmProof({header: header(), multistoreProof: p.service.multistoreProof, entry: encodeEntry(p.service), ledgerConfiguration: ledgerConfig}));
        const r = await read("verifyConfig", [proof, toHex(channelId), toHex(manifest)]);
        expect(r[0]).toBe(ctx);
        expect(r[1]).toBe("dydx-clpr-local-1");
        expect(r[2]).toBe(toHex(moduleAddr));
        expect(r[5]).toBe(anchor(setHash, H + 1n));
        expect(r[7].version).toBe(1n);
        const bad = toHex(encodeCosmWasmProof({header: header(), multistoreProof: p.service.multistoreProof, entry: encodeEntry(p.service), ledgerConfiguration: pbLen(2, Buffer.alloc(20, 7))}));
        await expectRevert(read("verifyConfig", [bad, toHex(channelId), "0x"]), "InvalidServiceEntry");
    });

    it("rejects: another channel, tampered record, tampered IAVL proof, wrong manifest", async () => {
        await expectRevert(read("verifyBundle", [bundle(), trust, toHex(Buffer.concat([Buffer.alloc(32, 9), moduleAddr]))]), "StorageKeyMismatch");
        const forgedValue = {...p.queue, value: Buffer.from(p.queue.value)};
        forgedValue.value[9] ^= 0x01; // next_message_id
        await expect(read("verifyBundle", [bundle({entry: encodeEntry(forgedValue)}), trust, ctx])).rejects.toThrow();
        const forgedProof = {...p.queue, iavlProof: Buffer.from(p.queue.iavlProof)};
        forgedProof.iavlProof[forgedProof.iavlProof.length - 3] ^= 0x01;
        await expect(read("verifyBundle", [bundle({entry: encodeEntry(forgedProof)}), trust, ctx])).rejects.toThrow();
        const wrongManifest = toHex(encodeCosmWasmProof({bundleContent: content, header: header(), multistoreProof: p.queue.multistoreProof, entry: encodeEntry(p.queue), serviceEntry: encodeEntry(p.service), manifestPreimage: Buffer.from("0802", "hex")}));
        await expectRevert(read("verifyBundle", [wrongManifest, trust, ctx]), "ManifestCommitmentMismatch");
        // A 32-byte (CosmWasm-style) service address is not a module account.
        await expectRevert(read("verifyBundle", [bundle(), trust, toHex(Buffer.concat([channelId, Buffer.alloc(32, 1)]))]), "InvalidServiceAddressLength");
    });

    it("rejects: bad signature, wrong validator set, stale header, wrong store key", async () => {
        const badSig = Buffer.from(enc.signedHeader);
        badSig[badSig.length - 5] ^= 0x01; // inside the last signature
        await expect(read("verifyBundle", [bundle({hdr: inlineHeaderRef(v, badSig)}), trust, ctx])).rejects.toThrow();
        await expect(read("verifyBundle", [bundle(), anchor(Buffer.alloc(32, 3), H - 10n), ctx])).rejects.toThrow();
        await expect(read("verifyBundle", [bundle(), anchor(setHash, H + 1n), ctx])).rejects.toThrow(); // header below anchor height
        const bankVerifier = await deployVerifier(lx.chainId, "bank", setHash, H - 10n);
        await expectRevert(read("verifyBundle", [bundle(), trust, ctx], bankVerifier), "InvalidStoreKey");
    });

    it("live dYdX mainnet: 10-of-21 Ed25519 commit + ICS-23 proof of bank supply, same pipeline", async () => {
        const msh = mx.raw.commit.result.signed_header;
        const mv = vals(mx.raw.validators);
        const mset = validatorSetHash(mv);
        const menc = encodeSignedHeader(msh, mv);
        const mp = proofs(mx).supply_adydx;
        const MH = BigInt(mx.meta.height);
        expect(mx.chainId).toBe("dydx-mainnet-1");
        expect(menc.signedPower * 3n).toBeGreaterThan(menc.totalPower * 2n);
        const dydx = await deployVerifier("dydx-mainnet-1", "bank", mset, MH - 10n);
        const proof = toHex(encodeCosmWasmProof({header: inlineHeaderRef(mv, menc.signedHeader), multistoreProof: mp.multistoreProof, entry: encodeEntry(mp)}));
        const args = [proof, anchor(mset, MH - 10n), toHex(mp.key)];
        const [exists, value, height] = await read("verifyModuleEntry", args, dydx);
        expect(exists).toBe(true);
        expect(Buffer.from(hexBuf(value)).toString()).toBe(mp.value.toString());
        expect(height).toBe(MH);
        const g = await txGas(dydx, "verifyModuleEntry", args);
        expect(g.gas).toBeLessThan(HEDERA_GAS_LIMIT);
        expect(g.calldata).toBeLessThan(HEDERA_CALLDATA_LIMIT);
        report["dYdX mainnet entry (bank supply)"] = {signatures: menc.signerIndices.length, gas: Number(g.gas), calldata: g.calldata};
    }, 60_000);
});
