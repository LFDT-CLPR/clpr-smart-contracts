import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {readFileSync} from "node:fs";
import path from "node:path";
import {createPublicClient, createWalletClient, encodeAbiParameters, encodeFunctionData, http, keccak256, type Hex, type PublicClient, type WalletClient} from "viem";
import {privateKeyToAccount, sign} from "viem/accounts";
import {loadArtifact, REPO_ROOT} from "../../../../script/deploy/artifacts.js";
import {loadHyperEvmFixture, receiptProof} from "../../relay/buildHyperEvmLiveProof.js";
import {rlpEncode} from "../../lib/rlp.js";

/// HyperEvmVerifier on a REAL HyperEVM mainnet block (chain 999), replayed on anvil
/// (re-capture: `npm run hyperevm-live:refresh`). The header is re-encoded and must hash to the real
/// block hash; the receipts trie is rebuilt from every receipt of the block and must match the
/// header's receiptsRoot (HyperEVM's stateRoot is 0x0); one real log is proven out of it.
///
/// TRUST LABEL: the block attestation is signed by TEST attestor keys. HyperEVM finality is attested
/// by a CLPR attestor set (K-of-N), not by Hyperliquid validators; no such set exists yet.

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8619);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const BLOCK_DOMAIN = keccak256(new TextEncoder().encode("CLPR_HYPEREVM_BLOCK_ATTESTATION_V1"));
const ROTATE_DOMAIN = keccak256(new TextEncoder().encode("CLPR_HYPEREVM_ATTESTOR_ROTATION_V1"));
const hb = (h: string) => Buffer.from(h.replace(/^0x/, ""), "hex");
const big = (n: bigint | number) => {
    let h = BigInt(n).toString(16);
    if (h === "0") return Buffer.alloc(0);
    if (h.length % 2) h = "0" + h;
    return hb(h);
};

type Att = {key: Hex; address: Hex};
function attestors(seed: string, n: number): Att[] {
    return Array.from({length: n}, (_, i) => {
        const key = keccak256(new TextEncoder().encode(`${seed}-${i}`));
        return {key, address: privateKeyToAccount(key).address.toLowerCase() as Hex};
    }).sort((a, b) => (BigInt(a.address) < BigInt(b.address) ? -1 : 1));
}
const setRlp = (k: number, as: Att[]) => [big(k), as.map((a) => hb(a.address))];
const setHash = (k: number, as: Att[]) => keccak256(encodeAbiParameters([{type: "uint256"}, {type: "address[]"}], [BigInt(k), as.map((a) => a.address)]));
async function sigs(as: Att[], digest: Hex) {
    const out: Buffer[] = [];
    for (const a of as) {
        const s = await sign({hash: digest, privateKey: a.key});
        out.push(Buffer.concat([hb(s.r), hb(s.s), Buffer.from([Number(s.v)])]));
    }
    return out;
}

describe("HyperEvmVerifier on a live HyperEVM block (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let harness: Hex;
    let verifier: Hex;
    const f = loadHyperEvmFixture();
    const vArt = loadArtifact("HyperEvmVerifier");
    const hArt = JSON.parse(readFileSync(path.join(REPO_ROOT, "out", "HyperEvmLiveHarness.sol", "HyperEvmLiveHarness.json"), "utf8"));
    const gas: Record<string, {gas: number; calldata: number}> = {};

    async function deploy(abi: unknown, bytecode: Hex, args: unknown[] = []) {
        const hash = await wallet.deployContract({abi: abi as never, bytecode, args: args as never, account: wallet.account!, chain: null});
        return (await pub.waitForTransactionReceipt({hash})).contractAddress!;
    }

    beforeAll(async () => {
        anvil = spawn("anvil", ["--port", String(ANVIL_PORT), "--silent"], {stdio: "ignore"});
        const rpc = `http://127.0.0.1:${ANVIL_PORT}`;
        pub = createPublicClient({transport: http(rpc), pollingInterval: 100}) as PublicClient;
        for (const deadline = Date.now() + 15_000; ; ) {
            try {
                await pub.getChainId();
                break;
            } catch (e) {
                if (Date.now() > deadline) throw e;
                await new Promise((r) => setTimeout(r, 200));
            }
        }
        wallet = createWalletClient({account: privateKeyToAccount(ANVIL_KEY), transport: http(rpc)});
        harness = await deploy(hArt.abi, hArt.bytecode.object);
        verifier = await deploy(vArt.abi, vArt.bytecode, ["eip155:999", 999n]);
    }, 60_000);

    afterAll(() => {
        anvil?.kill("SIGTERM");
        console.table(gas);
    });

    async function proof(setK: number, set: Att[], signers: Att[], rotations: Buffer[][] | unknown[] = []) {
        const digest = keccak256(
            encodeAbiParameters([{type: "bytes32"}, {type: "uint256"}, {type: "uint256"}, {type: "bytes32"}], [BLOCK_DOMAIN, 999n, BigInt(f.block.number), f.block.hash])
        );
        const {root, nodes} = receiptProof(f.receipts.map(hb), f.pick.transactionIndex);
        expect(`0x${root.toString("hex")}`).toBe(f.block.receiptsRoot);
        return `0x${rlpEncode([setRlp(setK, set), rotations as never, hb(f.block.header), await sigs(signers, digest), [big(f.pick.transactionIndex), nodes], big(f.pick.logIndex), Buffer.alloc(0)]).toString("hex")}` as Hex;
    }

    it("re-encoded header hashes to the real block; stateRoot is zero", () => {
        expect(keccak256(f.block.header)).toBe(f.block.hash);
        expect(BigInt(f.block.stateRoot)).toBe(0n);
    });

    it("proves the real log out of the attested block (3-of-5 test attestors)", async () => {
        const set = attestors("hl-attestor", 5);
        const p = await proof(3, set, set.slice(0, 3));
        const anchor = encodeAbiParameters([{type: "bytes32"}, {type: "uint256"}, {type: "uint256"}, {type: "address"}], [setHash(3, set), 0n, 0n, f.pick.log.address]);
        const [number, emitter, topics, data] = (await pub.readContract({address: harness, abi: hArt.abi, functionName: "provenLog", args: [p, anchor]})) as any;
        expect(number).toBe(BigInt(f.block.number));
        expect(emitter.toLowerCase()).toBe(f.pick.log.address.toLowerCase());
        expect(topics).toEqual(f.pick.log.topics);
        expect(data).toBe(f.pick.log.data);
        const data_ = encodeFunctionData({abi: hArt.abi, functionName: "provenLog", args: [p, anchor]});
        gas["live block + receipt, 3-of-5"] = {gas: Number(await pub.estimateGas({to: harness, data: data_})), calldata: (data_.length - 2) / 2};
        // verifyBundle runs the same steps and stops where the real log is not a ClprQueueRecord
        const ctx = `0x${"11".repeat(32)}${"22".repeat(20)}` as Hex;
        await expect(pub.readContract({address: verifier, abi: vArt.abi, functionName: "verifyBundle", args: [p, anchor, ctx]})).rejects.toThrow(/WrongEvent|WrongService/);
    });

    it("13-of-19 attestors, and a rotation to a new set", async () => {
        const set = attestors("hl-attestor-19", 19);
        const p = await proof(13, set, set.slice(0, 13));
        const anchor = encodeAbiParameters([{type: "bytes32"}, {type: "uint256"}, {type: "uint256"}, {type: "address"}], [setHash(13, set), 0n, 0n, f.pick.log.address]);
        const d = encodeFunctionData({abi: hArt.abi, functionName: "provenLog", args: [p, anchor]});
        gas["live block + receipt, 13-of-19"] = {gas: Number(await pub.estimateGas({to: harness, data: d})), calldata: (d.length - 2) / 2};

        const next = attestors("hl-attestor-19-next", 19);
        const rotDigest = keccak256(encodeAbiParameters([{type: "bytes32"}, {type: "uint256"}, {type: "uint256"}, {type: "bytes32"}], [ROTATE_DOMAIN, 999n, 1n, setHash(13, next)]));
        const rot = [[setRlp(13, next), await sigs(set.slice(0, 13), rotDigest)]];
        const p2 = await proof(13, set, next.slice(0, 13), rot);
        const [, , , , epoch] = (await pub.readContract({address: harness, abi: hArt.abi, functionName: "provenLog", args: [p2, anchor]})) as any;
        expect(epoch).toBe(1n);
        const d2 = encodeFunctionData({abi: hArt.abi, functionName: "provenLog", args: [p2, anchor]});
        gas["live block + receipt + rotation, 13-of-19"] = {gas: Number(await pub.estimateGas({to: harness, data: d2})), calldata: (d2.length - 2) / 2};
        // below threshold
        const p3 = await proof(13, set, set.slice(0, 12));
        await expect(pub.readContract({address: harness, abi: hArt.abi, functionName: "provenLog", args: [p3, anchor]})).rejects.toThrow(/AttestorQuorumNotReached/);
    });
});
