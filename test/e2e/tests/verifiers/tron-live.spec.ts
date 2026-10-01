import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {readFileSync} from "node:fs";
import path from "node:path";
import {
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
import {
    buildTronLiveProof,
    loadTronCapture,
    reencodeBundle,
    SR_COUNT,
    THRESHOLD,
    type TronCapture,
    type TronLiveProof
} from "../../relay/buildTronLiveProof.js";
import {hexToBuf} from "../../lib/rlp.js";

/// TronVerifier against REAL TRON data (Nile testnet and mainnet), replayed offline from
/// test/e2e/fixtures/tron-live/<network>.json (re-capture: `npm run tron-live:refresh`).
///
/// Per network the fixture holds: the 27 SRs of maintenance period p-1 (config), the real
/// maintenance block opening period p with a window naming all 27 SRs of p and 19 old-set
/// signatures after it (SR-set rotation), and a real successful TriggerSmartContract with 19 SR
/// confirmations. Every header is re-encoded and its signature replayed by the production code.
///
/// There is no ClprService on TRON, so the real contract call stands in for `attestQueue`: the full
/// `verifyBundle` passes config, set hash, rotation, confirmations, Merkle inclusion, contractRet and
/// the attestor address, and then stops at the selector check (WrongAttestationCall). The harness
/// runs the same production code up to that check and returns what it proved.
///
/// Run: forge build && npm run test:e2e:tron-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8597);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

function loadHarness(): {abi: readonly unknown[]; bytecode: Hex} {
    const file = path.join(REPO_ROOT, "out", "TronVerifierHarness.sol", "TronVerifierHarness.json");
    const j = JSON.parse(readFileSync(file, "utf8")) as {abi: readonly unknown[]; bytecode: {object: Hex}};
    return {abi: j.abi, bytecode: j.bytecode.object};
}

const byteLen = (h: Hex) => (h.length - 2) / 2;
const calldataGas = (data: Hex) => hexToBuf(data).reduce((a, b) => a + (b === 0 ? 4 : 16), 0);

describe("TronVerifier on live TRON data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    const verifierArt = loadArtifact("TronVerifier");
    const harnessArt = loadHarness();

    async function deploy(abi: readonly unknown[], bytecode: Hex, args: unknown[]): Promise<Hex> {
        const hash = await wallet.deployContract({abi: abi as never, bytecode, args: args as never, account: wallet.account!, chain: null});
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error("deploy failed");
        return r.contractAddress;
    }

    beforeAll(async () => {
        anvil = spawn("anvil", ["--port", String(ANVIL_PORT), "--silent"], {stdio: "ignore"});
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
    });

    afterAll(() => {
        anvil?.kill("SIGTERM");
    });

    for (const network of ["nile", "mainnet"]) {
        describe(network, () => {
            let capture: TronCapture;
            let live: TronLiveProof;
            let verifier: Hex;
            let harness: Hex;

            const call = (fn: string, args: unknown[], at = verifier, abi = verifierArt.abi) =>
                pub.readContract({address: at, abi: abi as never, functionName: fn, args: args as never}) as Promise<unknown>;

            beforeAll(async () => {
                capture = loadTronCapture(network);
                live = await buildTronLiveProof(capture);
                const ctor = [BigInt(SR_COUNT), BigInt(THRESHOLD), BigInt(capture.intervalMs), BigInt(capture.offsetMs), capture.caip2];
                verifier = await deploy(verifierArt.abi, verifierArt.bytecode, ctor);
                harness = await deploy(harnessArt.abi, harnessArt.bytecode, ctor);
            });

            it("re-encoded real headers parse on-chain to the node's block ids and signers", async () => {
                const sample = [...capture.config.headers.slice(0, 3), capture.rotation.headers[0], capture.attestation.headers[0]];
                for (const h of sample) {
                    const [number, , , id] = (await call("header", [h.raw, h.sig], harness, harnessArt.abi)) as [bigint, bigint, Hex, Hex, Hex];
                    expect(number).toBe(BigInt(h.number));
                    expect(id).toBe(h.blockId);
                }
            });

            it("verifyConfig accepts the real SR set of period p-1", async () => {
                const out = (await call("verifyConfig", [live.configProof, live.channelId, "0x"])) as unknown[];
                expect(out[1]).toBe(capture.caip2);
                expect(out[5]).toBe(live.configAnchor);
                const gas = await pub.estimateContractGas({
                    address: verifier, abi: verifierArt.abi as never, functionName: "verifyConfig",
                    args: [live.configProof, live.channelId, "0x"] as never, account: wallet.account!
                });
                console.log(`[tron-live:${network}] verifyConfig gas ${gas} | configProof ${byteLen(live.configProof)} B | ` +
                    `${live.meta.configHeaders} headers, PQ SRs ${live.meta.pqWitnesses.length}, permission-key SRs ${live.meta.permissionKeyWitnesses.length}`);
            });

            it("rotates to period p over the real maintenance boundary and confirms a real contract call", async () => {
                const args = [live.bundleProof, live.configAnchor] as const;
                const [period, setHash, txBlock, target, , contractRet] =
                    (await call("liveBundle", [...args], harness, harnessArt.abi)) as [bigint, Hex, bigint, Hex, Hex, bigint];
                expect(period).toBe(live.rotatedPeriod);
                expect(period).toBe(live.configPeriod + 1n);
                expect(setHash).toBe(live.rotatedSetHash);
                expect(txBlock).toBe(BigInt(live.meta.txBlock));
                expect(target.toLowerCase()).toBe(live.attestor);
                expect(contractRet).toBe(1n);

                const gas = await pub.estimateContractGas({
                    address: harness, abi: harnessArt.abi as never, functionName: "liveBundle", args: args as never,
                    account: wallet.account!
                });
                const data = encodeFunctionData({abi: verifierArt.abi, functionName: "verifyBundle",
                    args: [live.bundleProof, live.configAnchor, live.channelContext]} as never);
                console.log(`[tron-live:${network}] rotation p${live.configPeriod}->p${period} (+${live.meta.joined.length}/-${live.meta.left.length} SRs) ` +
                    `+ tx in block ${txBlock} (${live.meta.txCount} txs, depth ${live.meta.merkleDepth}): eth_estimateGas ${gas} ` +
                    `(calldata ${byteLen(data)} B ≈ ${calldataGas(data)} gas) | rotation ${live.meta.rotationHeaders} headers, attestation ${live.meta.attestationHeaders}`);
            });

            it("steady state: a bundle without rotation against the rotated anchor", async () => {
                const args = [live.steadyBundleProof, live.rotatedAnchor] as const;
                const [period, setHash, , , , contractRet] =
                    (await call("liveBundle", [...args], harness, harnessArt.abi)) as [bigint, Hex, bigint, Hex, Hex, bigint];
                expect(period).toBe(live.rotatedPeriod);
                expect(setHash).toBe(live.rotatedSetHash);
                expect(contractRet).toBe(1n);
                const gas = await pub.estimateContractGas({
                    address: harness, abi: harnessArt.abi as never, functionName: "liveBundle", args: args as never,
                    account: wallet.account!
                });
                const data = encodeFunctionData({abi: verifierArt.abi, functionName: "verifyBundle",
                    args: [live.steadyBundleProof, live.rotatedAnchor, live.channelContext]} as never);
                console.log(`[tron-live:${network}] steady bundle (${live.meta.attestationHeaders} headers, ${live.meta.txCount} txs in block): ` +
                    `eth_estimateGas ${gas} (calldata ${byteLen(data)} B ≈ ${calldataGas(data)} gas)`);
                await expect(call("verifyBundle", [live.steadyBundleProof, live.rotatedAnchor, live.channelContext]))
                    .rejects.toThrow(/WrongAttestationCall/);
            });

            it("full verifyBundle passes every proof step and stops only at the attestQueue selector", async () => {
                await expect(call("verifyBundle", [live.bundleProof, live.configAnchor, live.channelContext]))
                    .rejects.toThrow(/WrongAttestationCall/);
            });

            it("rejects a corrupted signature in the rotation window", async () => {
                const rot = live.parts.rotation as [Buffer[][], Buffer];
                const headers = rot[0].map((h) => [Buffer.from(h[0]), Buffer.from(h[1])]);
                const i = headers.findIndex((h, k) => k > 0 && h[1].length === 65);
                headers[i][1][40] ^= 0xff; // in s: recovers some other valid key (an invalid r would read as "no signature")
                const proof = reencodeBundle(live.parts, {rotation: [headers, rot[1]]});
                await expect(call("verifyBundle", [proof, live.configAnchor, live.channelContext]))
                    .rejects.toThrow(/UnauthenticatedSignerKey|InsufficientConfirmations/);
            });

            it("rejects a rotation endorsed by fewer than 19 old-set SRs", async () => {
                const rot = live.parts.rotation as [Buffer[][], Buffer];
                const proof = reencodeBundle(live.parts, {rotation: [rot[0].slice(0, -1), rot[1]]});
                await expect(call("verifyBundle", [proof, live.configAnchor, live.channelContext]))
                    .rejects.toThrow(/InsufficientConfirmations/);
            });

            it("rejects a tampered transaction under the real Merkle proof", async () => {
                const att = [...(live.parts.attestation as Buffer[])];
                const tx = Buffer.from(att[1] as Buffer);
                tx[tx.length - 1] ^= 1;
                att[1] = tx;
                const proof = reencodeBundle(live.parts, {attestation: att});
                await expect(call("verifyBundle", [proof, live.configAnchor, live.channelContext]))
                    .rejects.toThrow(/TxRootMismatch/);
            });

            it("rejects the real chain under a different trusted set", async () => {
                const anchor = hexToBuf(live.configAnchor);
                anchor[40] ^= 1; // setHash word
                await expect(call("verifyBundle", [live.bundleProof, ("0x" + anchor.toString("hex")) as Hex, live.channelContext]))
                    .rejects.toThrow(/SrSetHashMismatch/);
            });
        });
    }
});
