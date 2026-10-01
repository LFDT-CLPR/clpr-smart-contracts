import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {spawn, type ChildProcess} from "node:child_process";
import {readFileSync} from "node:fs";
import path from "node:path";
import {
    createPublicClient,
    createWalletClient,
    decodeAbiParameters,
    encodeFunctionData,
    http,
    type Hex,
    type PublicClient,
    type WalletClient
} from "viem";
import {privateKeyToAccount} from "viem/accounts";
import {REPO_ROOT} from "../../../../script/deploy/artifacts.js";
import {
    buildStellarLiveProof,
    CHANNEL_ID,
    loadStellarCapture,
    type StellarCapture,
    type StellarLiveProof
} from "../../relay/buildStellarLiveProof.js";
import {encodeAnchor, encodeBundle, hex, unhex, type ScpProof} from "../../relay/stellar.js";

/// StellarScpVerifier against REAL Stellar data (testnet and pubnet), replayed offline from
/// test/e2e/fixtures/stellar-live/<network>.json (re-capture: `npm run stellar-live:refresh`).
///
/// Per network the fixture holds a real EXTERNALIZE quorum of the network's tier-1 quorum set for a
/// slot S (signatures from SDF's history archive), the tx set of S, headers S-1..N and a real
/// successful Soroban transaction in ledger N with its result set and success preimage. Pubnet also
/// holds the real September 2026 tier-1 expansion (5 of 7 organizations → 7 of 10).
///
/// There is no CLPR service on Stellar, so the real event (testnet `new_block_event`, pubnet RedStone
/// `REDSTONE` update) stands in for `clpr_queue`: verifyBundle passes finality, checkpoint, header walk, result set,
/// transaction hash, success preimage and emitter, and stops at the topic check
/// (WrongAttestationEvent). The harness runs the same production code and returns what it proved.
///
/// Run: forge build && npm run test:e2e:stellar-live

const ANVIL_PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8598);
const ANVIL_KEY: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HEDERA_GAS = 15_000_000n;
const HEDERA_CALLDATA = 131_072;

function artifact(file: string, name: string): {abi: readonly unknown[]; bytecode: Hex} {
    const j = JSON.parse(readFileSync(path.join(REPO_ROOT, "out", file, `${name}.json`), "utf8")) as {
        abi: readonly unknown[];
        bytecode: {object: Hex};
    };
    return {abi: j.abi, bytecode: j.bytecode.object};
}

const byteLen = (h: Hex) => (h.length - 2) / 2;

describe("StellarScpVerifier on live Stellar data (fixture replay)", () => {
    let anvil: ChildProcess;
    let pub: PublicClient;
    let wallet: WalletClient;
    const edArt = artifact("Ed25519Verifier.sol", "Ed25519Verifier");
    const verifierArt = artifact("StellarScpVerifier.sol", "StellarScpVerifier");
    const harnessArt = artifact("StellarScpVerifierHarness.sol", "StellarScpVerifierHarness");
    let ed: Hex;

    async function deploy(abi: readonly unknown[], bytecode: Hex, args: unknown[]): Promise<Hex> {
        const hash = await wallet.deployContract({abi: abi as never, bytecode, args: args as never, account: wallet.account!, chain: null});
        const r = await pub.waitForTransactionReceipt({hash});
        if (!r.contractAddress) throw new Error("deploy failed");
        return r.contractAddress;
    }

    beforeAll(async () => {
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
        ed = await deploy(edArt.abi, edArt.bytecode, []);
    });

    afterAll(() => {
        anvil?.kill("SIGTERM");
    });

    for (const network of ["testnet", "pubnet"]) {
        describe(network, () => {
            let c: StellarCapture;
            let live: StellarLiveProof;
            let verifier: Hex;
            let harness: Hex;

            const call = (fn: string, args: unknown[], at = verifier, abi = verifierArt.abi) =>
                pub.readContract({address: at, abi: abi as never, functionName: fn, args: args as never}) as Promise<unknown>;
            const estimate = (fn: string, args: unknown[], at = verifier, abi = verifierArt.abi) =>
                pub.estimateContractGas({address: at, abi: abi as never, functionName: fn, args: args as never, account: wallet.account!});
            const calldata = (args: unknown[]) =>
                byteLen(encodeFunctionData({abi: verifierArt.abi, functionName: "verifyBundle", args} as never));
            const log = (s: string) => console.log(`[stellar-live:${network}] ${s}`);

            const scp = (): ScpProof => ({
                envelopes: c.finality.envelopes.map((e) => ({statement: unhex(e.statement), signature: unhex(e.signature)})),
                txSet: unhex(c.finality.txSet)
            });

            beforeAll(async () => {
                c = loadStellarCapture(network);
                const ctor = [ed, c.networkId, c.caip2];
                verifier = await deploy(verifierArt.abi, verifierArt.bytecode, ctor);
                harness = await deploy(harnessArt.abi, harnessArt.bytecode, ctor);
                const cm = (await call("controlMessage", [c.caip2, c.attestation.contractId], harness, harnessArt.abi)) as Hex;
                live = buildStellarLiveProof(c, unhex(cm));
            });

            it("verifyConfig accepts the real tier-1 quorum set with a real EXTERNALIZE quorum", async () => {
                const out = (await call("verifyConfig", [live.configProof, hex(CHANNEL_ID), "0x"])) as unknown[];
                expect(out[1]).toBe(c.caip2);
                expect(out[2]).toBe(c.attestation.contractId);
                expect(out[5]).toBe(live.anchor1);
                const gas = await estimate("verifyConfig", [live.configProof, hex(CHANNEL_ID), "0x"]);
                log(`verifyConfig: ${c.qsetSummary}, ${c.finality.envelopes.length} signatures: gas ${gas}, proof ${byteLen(live.configProof)} B`);
                expect(gas).toBeLessThan(HEDERA_GAS);
            });

            it("step 1: SCP finality of slot S checkpoints ledger S-1 (a complete verifyBundle)", async () => {
                const args = [live.step1, live.anchor0, live.channelContext];
                const [meta, payloads, newAnchor] = (await call("verifyBundle", args)) as [
                    {nextMessageId: bigint; state: number},
                    Hex[],
                    Hex
                ];
                expect(newAnchor).toBe(live.anchor1);
                expect(meta.nextMessageId).toBe(1n);
                expect(meta.state).toBe(0);
                expect(payloads.length).toBe(0);
                const gas = await estimate("verifyBundle", args);
                const cd = calldata(args);
                const perSig = c.finality.envelopes.length;
                log(`step 1 (slot ${c.finality.slot}, ${perSig} of ${c.finality.envelopesAvailable} envelopes, tx set ${byteLen(c.finality.txSet)} B): ` +
                    `eth_estimateGas ${gas}, calldata ${cd} B`);
                expect(gas).toBeLessThan(HEDERA_GAS);
                expect(cd).toBeLessThan(HEDERA_CALLDATA);
            });

            it("step 2: headers back to the event's ledger and a real Soroban event", async () => {
                const args = [live.step2, live.anchor1, c.attestation.contractId];
                const p = (await call("proveEvent", args, harness, harnessArt.abi)) as {
                    checkpointSeq: number;
                    ledgerSeq: number;
                    emitter: Hex;
                    eventCount: bigint;
                };
                expect(p.checkpointSeq).toBe(c.finality.slot - 1);
                expect(p.ledgerSeq).toBe(c.attestation.ledger);
                expect(p.emitter).toBe(c.attestation.contractId);
                expect(p.eventCount).toBe(BigInt(c.attestation.eventCount));
                const gas = await estimate("proveEvent", args, harness, harnessArt.abi);
                const cd = calldata([live.step2, live.anchor1, live.channelContext]);
                log(`step 2 (${c.headers.length} headers, result set of ${c.attestation.resultSetTxCount} txs = ${byteLen(c.attestation.resultSet)} B): ` +
                    `eth_estimateGas ${gas} (harness), calldata ${cd} B`);
                expect(gas).toBeLessThan(HEDERA_GAS);
                expect(cd).toBeLessThan(HEDERA_CALLDATA);
                await expect(call("verifyBundle", [live.step2, live.anchor1, live.channelContext])).rejects.toThrow(
                    /WrongAttestationEvent/
                );
            });

            it("single-transaction bundle (SCP + tx set + headers + event)", async () => {
                const cd = calldata([live.full, live.anchor0, live.channelContext]);
                const p = (await call("proveEvent", [live.full, live.anchor0, c.attestation.contractId], harness, harnessArt.abi)) as {
                    slot: bigint;
                    ledgerSeq: number;
                };
                expect(p.slot).toBe(BigInt(c.finality.slot));
                expect(p.ledgerSeq).toBe(c.attestation.ledger);
                await expect(call("verifyBundle", [live.full, live.anchor0, live.channelContext])).rejects.toThrow(
                    /WrongAttestationEvent/
                );
                const gas = await estimate("proveEvent", [live.full, live.anchor0, c.attestation.contractId], harness, harnessArt.abi);
                log(`single bundle: eth_estimateGas ${gas} (harness), calldata ${cd} B` +
                    (cd < HEDERA_CALLDATA ? "" : " (over Hedera's 128 KB: use the two-step form)"));
                if (network === "testnet") expect(cd).toBeLessThan(HEDERA_CALLDATA);
            });

            if (network === "pubnet") {
                it("rotates over the real September 2026 tier-1 expansion", async () => {
                    const r = c.rotation!;
                    const args = [live.rotation!.bundle, live.rotation!.anchor, live.channelContext];
                    const out = (await call("verifyBundle", args)) as [unknown, unknown, Hex];
                    const [qsetHash, lastSlot] = decodeAbiParameters(
                        [{type: "bytes32"}, {type: "uint64"}, {type: "uint32"}, {type: "bytes32"}, {type: "bytes32"}],
                        out[2]
                    );
                    expect(qsetHash).toBe(r.newQsetHash);
                    expect(lastSlot).toBe(BigInt(r.slot));
                    const gas = await estimate("verifyBundle", args);
                    const cd = calldata(args);
                    log(`rotation at slot ${r.slot}: ${r.oldSummary} -> ${r.newSummary}; ${r.envelopes.length} old-set endorsers ` +
                        `(of ${r.endorsersAvailable}), tx set ${byteLen(r.txSet)} B: eth_estimateGas ${gas}, calldata ${cd} B`);
                    expect(gas).toBeLessThan(HEDERA_GAS);
                    expect(cd).toBeLessThan(HEDERA_CALLDATA);
                    log(`current tier-1 set ${r.newQsetHash === c.qsetHash ? "is" : "is NOT"} the rotated set`);
                });
            }

            // ── Negative cases on real data ──────────────────────────────────────

            it("rejects a corrupted signature", async () => {
                const s = scp();
                s.envelopes[1].signature = Buffer.from(s.envelopes[1].signature);
                s.envelopes[1].signature[5] ^= 1;
                const proof = hex(encodeBundle({qset: unhex(c.qset), scp: s, headers: []}));
                await expect(call("verifyBundle", [proof, live.anchor0, live.channelContext])).rejects.toThrow(/BadSignature/);
            });

            it("rejects a quorum one signature short", async () => {
                const s = scp();
                s.envelopes = s.envelopes.slice(1);
                const proof = hex(encodeBundle({qset: unhex(c.qset), scp: s, headers: []}));
                await expect(call("verifyBundle", [proof, live.anchor0, live.channelContext])).rejects.toThrow(/QuorumNotSatisfied/);
            });

            it("rejects another ledger's tx set", async () => {
                const s = scp();
                s.txSet = Buffer.from(s.txSet);
                s.txSet[40] ^= 1;
                const proof = hex(encodeBundle({qset: unhex(c.qset), scp: s, headers: []}));
                await expect(call("verifyBundle", [proof, live.anchor0, live.channelContext])).rejects.toThrow(/TxSetMismatch/);
            });

            it("rejects a different trusted quorum set", async () => {
                const anchor = unhex(live.anchor0);
                anchor[0] ^= 1;
                await expect(call("verifyBundle", [live.step1, hex(anchor), live.channelContext])).rejects.toThrow(/QuorumSetMismatch/);
            });

            it("rejects a stale (already proven) slot", async () => {
                await expect(call("verifyBundle", [live.step1, live.anchor1, live.channelContext])).rejects.toThrow(/StaleSlot/);
            });

            it("rejects a tampered result set", async () => {
                const rs = unhex(c.attestation.resultSet);
                rs[rs.length - 1] ^= 1;
                const proof = hex(
                    encodeBundle({
                        qset: unhex(c.qset),
                        headers: c.headers.map(unhex),
                        attestation: {
                            txPayload: unhex(c.attestation.txPayload),
                            resultSet: rs,
                            offset: c.attestation.offset,
                            preimage: unhex(c.attestation.preimage)
                        }
                    })
                );
                await expect(call("verifyBundle", [proof, live.anchor1, live.channelContext])).rejects.toThrow(/ResultSetMismatch/);
            });

            it("rejects the event for a channel whose service is another contract", async () => {
                const other = encodeAnchor({
                    qsetHash: unhex(c.qsetHash),
                    lastSlot: c.finality.slot,
                    checkpointSeq: c.finality.slot - 1,
                    checkpointHash: unhex(c.finality.previousLedgerHash),
                    lastMetadataHash: Buffer.alloc(32)
                });
                const ctx = hex(Buffer.concat([CHANNEL_ID, Buffer.alloc(32, 7)]));
                await expect(call("verifyBundle", [live.step2, hex(other), ctx])).rejects.toThrow(/WrongEmitter/);
            });
        });
    }
});
