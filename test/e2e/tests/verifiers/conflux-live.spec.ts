import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {encodeAbiParameters, type Hex} from "viem";
import {buildConfluxVectors, loadConfluxVectors, type ConfluxVectors} from "../../relay/buildConfluxLiveProof.js";
import {readFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {deploy, HEDERA, measure, read, type Harness} from "./blscommittees/anvil.js";

/// ConfluxPosLightClient against REAL Conflux mainnet data, replayed offline on anvil from
/// test/e2e/fixtures/conflux-live/vectors.json (re-capture: `npm run conflux-live:refresh`).
///
/// Real inputs: the PoS committee of epoch E-1, the last ledger info of E-1 (aggregated BLS
/// signature, carries the E committee), an epoch-E ledger info with a pivot decision, and the
/// pivot block header whose deferred state root equals the eSpace stateRoot of that height.
///
/// Run: forge build && npm run test:e2e:conflux-live

const PORT = Number(process.env.CLPR_ANVIL_PORT_A ?? 8671);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

type Result = {epoch: bigint; round: bigint; pivotHeight: bigint; pivotBlockHash: Hex; deferredStateRoot: Hex};

describe("ConfluxPosLightClient on live Conflux mainnet data (fixture replay)", () => {
    let v: ConfluxVectors;
    let h: Harness;
    const anchor = (hash: Hex, epoch: string, pivot = 0n): Hex =>
        encodeAbiParameters([{type: "bytes32"}, {type: "uint64"}, {type: "uint64"}], [hash, BigInt(epoch), pivot]);

    beforeAll(async () => {
        v = loadConfluxVectors();
        h = await deploy("ConfluxPosLightClient", [v.bootstrap.hash, BigInt(v.bootstrap.epoch)], PORT);
    });

    afterAll(() => {
        h?.anvil.kill("SIGTERM");
    });

    it("the offline builder reproduces vectors.json from capture.json (BLS, header hash, eSpace root cross-checks)", () => {
        const cap = JSON.parse(readFileSync(path.resolve(__dirname, "../../fixtures/conflux-live/capture.json"), "utf8"));
        expect(buildConfluxVectors(cap)).toEqual(v);
    });

    it("bundle with a real committee rotation: E-1 anchor → epoch E pivot state root", async () => {
        const args = [v.proofs.bundleWithRotation, anchor(v.bootstrap.hash, v.bootstrap.epoch)];
        const [r, na] = await read<[Result, Hex]>(h, "verifyPivotStateRoot", args);
        expect(r.deferredStateRoot).toBe(v.bundle.deferredStateRoot);
        expect(r.deferredStateRoot).toBe(v.bundle.espaceStateRoot);
        expect(r.pivotBlockHash).toBe(v.bundle.pivotHash);
        expect(na).toBe(anchor(v.next.hash, v.next.epoch, BigInt(v.bundle.pivotHeight)));
        const g = await measure(h, "verifyPivotStateRoot", args);
        console.log(`[conflux-live] bundle + rotation (epoch ${v.bootstrap.epoch}→${v.next.epoch}, pivot ${v.bundle.pivotHeight}): eth_estimateGas ${g.gas}, calldata ${g.calldata} B`);
        expect(g.gas).toBeLessThan(HEDERA.gasLimit);
        expect(g.calldata).toBeLessThan(HEDERA.calldataLimit);
    });

    it("bundle in the current epoch (no rotation)", async () => {
        const args = [v.proofs.bundle, anchor(v.next.hash, v.next.epoch)];
        const [r] = await read<[Result, Hex]>(h, "verifyPivotStateRoot", args);
        expect(r.deferredStateRoot).toBe(v.bundle.deferredStateRoot);
        const g = await measure(h, "verifyPivotStateRoot", args);
        console.log(`[conflux-live] bundle (${v.bundle.signers} signers): eth_estimateGas ${g.gas}, calldata ${g.calldata} B`);
        expect(g.gas).toBeLessThan(HEDERA.gasLimit);
    });

    it("rotation only (catch-up)", async () => {
        const args = [v.proofs.catchUp, anchor(v.bootstrap.hash, v.bootstrap.epoch)];
        const na = await read<Hex>(h, "verifyEpochChanges", args);
        expect(na).toBe(anchor(v.next.hash, v.next.epoch));
        const g = await measure(h, "verifyEpochChanges", args);
        console.log(`[conflux-live] rotation (${v.next.addresses.length} validators): eth_estimateGas ${g.gas}, calldata ${g.calldata} B`);
        expect(g.gas).toBeLessThan(HEDERA.gasLimit);
    });

    it("rejects the rotation proof under an anchor that already moved past it", async () => {
        await expect(read(h, "verifyEpochChanges", [v.proofs.catchUp, anchor(v.next.hash, v.next.epoch)])).rejects.toThrow(/CommitteeMismatch/);
    });

    it("rejects a replayed pivot", async () => {
        await expect(read(h, "verifyPivotStateRoot", [v.proofs.bundle, anchor(v.next.hash, v.next.epoch, BigInt(v.bundle.pivotHeight))]))
            .rejects.toThrow(/PivotNotNewer/);
    });

    it("rejects a tampered pivot header", async () => {
        const p = v.proofs.bundle;
        const tampered = (p.slice(0, -2) + (p.slice(-2) === "00" ? "01" : "00")) as Hex;
        await expect(read(h, "verifyPivotStateRoot", [tampered, anchor(v.next.hash, v.next.epoch)])).rejects.toThrow(/PivotHeaderMismatch/);
    });
});
