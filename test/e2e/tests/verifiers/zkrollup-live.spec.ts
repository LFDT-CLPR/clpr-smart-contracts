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
    buildZkRollupLiveProof,
    loadZkRollupLiveCapture,
    type ZkRollupLiveProof
} from "../../relay/buildZkRollupLiveProof.js";
import {encodeL2StateRootProof, profileTuple} from "../../relay/zkrollup.js";
import {hexToBuf} from "../../lib/rlp.js";

/// L1RollupMptVerifier (Scroll, Morph) and LineaRollupVerifier (Linea) against REAL Ethereum-mainnet
/// data, replayed offline on anvil from test/e2e/fixtures/<chain>-live/capture.json
/// (re-capture: `npm run zkrollup-live:refresh:<chain>`).
///
/// Every link is live data: the mainnet sync committee's signature over the header (with its real
/// non-signers), the execution state_root branch, eth_getProof at that L1 block of the rollup proxy
/// (finalized-root mapping slot + EIP-1967 implementation slot), and the L2 proof at the finalized root
/// (eth_getProof on Scroll/Morph, linea_getProof on Linea) of a stand-in account with the
/// channelId-derived slots (absent there: genuine exclusion proofs). Verifiers are deployed with the
/// pinned profiles of test/e2e/relay/zkrollup.ts (same values as ZkRollupProfiles.sol).
///
/// Run: forge build && npm run test:e2e:zkrollup-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8615);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HEDERA_GAS_LIMIT = 15_000_000n;
const HEDERA_TX_BYTES = 128 * 1024;

const byteLen = (h: Hex) => (h.length - 2) / 2;
const calldataGas = (data: Hex) => hexToBuf(data).reduce((acc, b) => acc + (b === 0 ? 4 : 16), 0);

/// LineaPoseidon2 creation code, from the generated LineaPoseidon2Code.sol (no ABI artifact of its own).
function poseidon2Creation(): Hex {
    const src = readFileSync(path.join(REPO_ROOT, "src/libraries/proof/linea/LineaPoseidon2Code.sol"), "utf8");
    const m = /hex"([0-9a-f]+)"/.exec(src);
    if (!m) throw new Error("no creation code in LineaPoseidon2Code.sol");
    return ("0x" + m[1]) as Hex;
}

describe("L1-settled rollup verifiers on live Ethereum mainnet data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    let l1Verifier: Hex;
    let lineaTrie: Hex;
    const l1Art = loadArtifact("EthL1StateVerifier");
    const mptArt = loadArtifact("L1RollupMptVerifier");
    const lineaArt = loadArtifact("LineaRollupVerifier");
    const trieArt = loadArtifact("LineaStateTrieVerifier");
    const errors = [l1Art, trieArt].flatMap((a) => (a.abi as {type: string}[]).filter((e) => e.type === "error"));
    const abi = [...mptArt.abi, ...errors] as readonly unknown[];
    const l1Abi = l1Art.abi;
    const gasReport: string[] = [];
    const live: Record<string, ZkRollupLiveProof> = {};
    const verifiers: Record<string, Hex> = {};

    async function deployRaw(data: Hex): Promise<Hex> {
        const hash = await wallet.sendTransaction({data, account: wallet.account!, chain: null});
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error("deploy failed");
        return r.contractAddress;
    }

    async function deploy(art: {abi: readonly unknown[]; bytecode: Hex}, args: unknown[]): Promise<Hex> {
        const hash = await wallet.deployContract({
            abi: art.abi as never, bytecode: art.bytecode, args: args as never, account: wallet.account!, chain: null
        });
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error("deploy failed");
        return r.contractAddress;
    }

    function read<T>(address: Hex, functionName: string, args: unknown[], useAbi = abi): Promise<T> {
        return pub.readContract({address, abi: useAbi as never, functionName, args}) as Promise<T>;
    }

    async function measure(label: string, address: Hex, functionName: string, args: unknown[], useAbi = abi): Promise<bigint> {
        const gas = await pub.estimateContractGas({address, abi: useAbi as never, functionName, args, account: wallet.account!});
        const data = encodeFunctionData({abi: useAbi, functionName, args} as never);
        const cd = calldataGas(data);
        gasReport.push(`${label}: eth_estimateGas ${gas} (= 21000 + ${cd} calldata + ~${gas - 21000n - BigInt(cd)} execution), ` +
            `calldata ${byteLen(data)} B`);
        expect(gas).toBeLessThan(HEDERA_GAS_LIMIT);
        expect(byteLen(data)).toBeLessThan(HEDERA_TX_BYTES);
        return gas;
    }

    beforeAll(async () => {
        for (const chain of ["linea", "scroll", "morph"]) live[chain] = buildZkRollupLiveProof(loadZkRollupLiveCapture(chain));

        anvil = spawn("anvil", ["--port", String(ANVIL_PORT), "--silent", "--gas-limit", "100000000"], {stdio: "ignore"});
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
        // Electra/Fulu beacon layout: execution state_root gindex 802 (depth 9), next_sync_committee 87 (depth 6).
        l1Verifier = await deploy(l1Art, [802n, 9n, 87n, 6n, 8192n]);
        const poseidon2 = await deployRaw(poseidon2Creation());
        lineaTrie = await deploy(trieArt, [poseidon2]);
        verifiers.linea = await deploy(lineaArt, [l1Verifier, profileTuple(live.linea.profile), lineaTrie]);
        verifiers.scroll = await deploy(mptArt, [l1Verifier, profileTuple(live.scroll.profile)]);
        verifiers.morph = await deploy(mptArt, [l1Verifier, profileTuple(live.morph.profile)]);
    }, 60_000);

    afterAll(() => {
        anvil?.kill("SIGTERM");
        if (gasReport.length) console.log(["[zkrollup-live] gas (Hedera: ≤ 15M gas, ≤ 128 KB tx)", ...gasReport].join("\n  "));
    });

    for (const chain of ["linea", "scroll", "morph"]) {
        describe(chain, () => {
            it("the sync committee authenticates the L1 state root, and the rollup's finalized root follows", async () => {
                const p = live[chain];
                const [key, root, na] = await read<[bigint, Hex, Hex, Hex]>(verifiers[chain], "verifyL2StateRoot",
                    [p.l2StateRootProof, p.trustAnchor]);
                expect(key).toBe(p.key);
                expect(root.toLowerCase()).toBe(p.l2StateRoot.toLowerCase());
                expect(na).toBe("0x");
                await measure(`${chain} verifyL2StateRoot`, verifiers[chain], "verifyL2StateRoot", [p.l2StateRootProof, p.trustAnchor]);
            });

            it("full verifyBundle down to the stand-in's channel slots (exclusion proofs → zero metadata)", async () => {
                const p = live[chain];
                const [metadata, msgs, na, , manifest] = await read<[{nextMessageId: bigint; receivedMessageId: bigint;
                    sentRunningHash: Hex}, Hex[], Hex, Hex, {version: bigint}]>(verifiers[chain], "verifyBundle",
                    [p.bundle, p.trustAnchor, p.channelContext]);
                expect(metadata.nextMessageId).toBe(0n);
                expect(metadata.receivedMessageId).toBe(0n);
                expect(msgs).toEqual([]);
                expect(na).toBe("0x");
                expect(manifest.version).toBe(0n);
                await measure(`${chain} verifyBundle (bundle ${byteLen(p.bundle)} B)`, verifiers[chain], "verifyBundle",
                    [p.bundle, p.trustAnchor, p.channelContext]);
            });

            it("rejects a key whose root is not finalized at that L1 block", async () => {
                const p = live[chain];
                await expect(read(verifiers[chain], "verifyL2StateRoot",
                    [encodeL2StateRootProof(p.lightClient.lightClientProof, p.rollupProofNext), p.trustAnchor]))
                    .rejects.toThrow(/StateRootNotFinalized/);
            });

            it("rejects the bundle under another channel's code-hash pin", async () => {
                const p = live[chain];
                const bad = (p.trustAnchor.slice(0, -2) + (p.trustAnchor.endsWith("00") ? "01" : "00")) as Hex;
                await expect(read(verifiers[chain], "verifyBundle", [p.bundle, bad, p.channelContext]))
                    .rejects.toThrow(/CodeHashMismatch/);
            });

            it("a real sync-committee rotation (L1 half) and its cost", async () => {
                const p = live[chain];
                if (!p.rotation) return;
                const [, , na, naId] = await read<[Hex, bigint, Hex, Hex]>(l1Verifier, "verifyL1State",
                    [p.rotation.lightClientProof, p.trustAnchor], l1Abi);
                expect(byteLen(na)).toBe(260);
                expect(BigInt(naId)).toBe(p.rotation.nextPeriod);
                if (chain === "linea") {
                    await measure("L1 light client only (verifyL1State)", l1Verifier, "verifyL1State",
                        [p.lightClient.lightClientProof, p.trustAnchor], l1Abi);
                    await measure("L1 light client with rotation (verifyL1State)", l1Verifier, "verifyL1State",
                        [p.rotation.lightClientProof, p.trustAnchor], l1Abi);
                }
            });
        });
    }
});
