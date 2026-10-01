import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {readFileSync} from "node:fs";
import path from "node:path";
import {bls12_381} from "@noble/curves/bls12-381";
import type {Hex} from "viem";
import {g1ToUncompressed, g2ToUncompressed} from "../../relay/bls.js";
import {AnvilHarness} from "../../relay/anvilHarness.js";
import {FIXTURE_DIR, b58, headerProtobuf} from "../../relay/buildWavesLiveFixture.js";

/// WavesFinalityVerifier against a REAL Waves testnet finalization, replayed offline on anvil from
/// test/e2e/fixtures/waves-live/waves.json (re-capture with `npm run waves-live:refresh`).
///
/// Proven on-chain: block P's id = BLAKE2b-256 of its header protobuf; the aggregated BLS
/// endorsement (min-pk, DST ..._NUL_) of the generators in the next block's finalizationVoting
/// verifies over F.id ‖ BE32(F.height) ‖ P.id; those endorsers hold ≥ 2/3 of the period's balance.
/// The generator set itself (keys, balances) is trusted input, see the contract.
///
/// Run: forge build && npm run test:e2e:waves-live

const fixture = JSON.parse(readFileSync(path.join(FIXTURE_DIR, "waves.json"), "utf8"));
const hex = (b: Buffer): Hex => ("0x" + b.toString("hex")) as Hex;

function u32(n: number): Buffer {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n);
    return b;
}

function u64(n: bigint): Buffer {
    const b = Buffer.alloc(8);
    b.writeBigUInt64BE(n);
    return b;
}

describe("WavesFinalityVerifier on live Waves testnet data (fixture replay)", () => {
    const h = new AnvilHarness("waves-live");
    const raw = fixture.raw;
    const gens = raw.finality.currentGenerators as any[];
    const keys = raw.commits.map((c: any) => g1ToUncompressed(bls12_381.G1.ProjectivePoint.fromHex(b58(c.endorserPublicKey))));
    const set = (balances = gens.map((g) => BigInt(g.balance))) => Buffer.concat([
        u32(raw.finality.currentGenerationPeriod.start), u32(raw.finality.currentGenerationPeriod.end),
        ...keys.map((k: Buffer, i: number) => Buffer.concat([k, u64(balances[i])]))
    ]);
    const fv = raw.voting.finalizationVoting;
    const header = headerProtobuf(raw.endorsed);
    const sig = g2ToUncompressed(bls12_381.G2.ProjectivePoint.fromHex(b58(fv.aggregatedEndorsementSignature)));
    const endorsement = (over: Partial<{finalizedHeight: number; endorserIndexes: number[]; signature: Buffer}> = {}) => ({
        finalizedId: hex(b58(raw.finalized.id)),
        finalizedHeight: over.finalizedHeight ?? fv.finalizedHeight,
        endorserIndexes: over.endorserIndexes ?? fv.endorserIndexes,
        signature: hex(over.signature ?? sig)
    });
    let setHash: Hex;

    beforeAll(async () => {
        await h.start();
        await h.deploy("WavesFinalityVerifier");
        setHash = await h.call("WavesFinalityVerifier", "generatorSetHash", [hex(set())]);
    });

    afterAll(() => h.stop());

    it("recomputes the live block id from the header protobuf with BLAKE2b on EIP-152", async () => {
        expect(await h.call("WavesFinalityVerifier", "blockId", [hex(header)])).toBe(hex(b58(raw.endorsed.id)));
    });

    it("proves the live block final: BLS endorsers hold ≥ 2/3 of the generating balance", async () => {
        const b = await h.call("WavesFinalityVerifier", "verifyFinalized", [hex(header), endorsement(), hex(set()), setHash]);
        expect(b.id).toBe(hex(b58(raw.endorsed.id)));
        expect(b.parentId).toBe(hex(b58(raw.endorsed.reference)));
        expect(b.stateHash).toBe(hex(b58(raw.endorsed.stateHash)));
        expect(b.transactionsRoot).toBe(hex(b58(raw.endorsed.transactionsRoot)));
        expect(b.endorsedBalance * 3n >= b.totalBalance * 2n).toBe(true);
        console.log(`[waves-live] block ${raw.endorsed.height} final: endorsers ${fv.endorserIndexes} hold ${b.endorsedBalance}/${b.totalBalance}`);
        await h.measure("WavesFinalityVerifier", "verifyFinalized", [hex(header), endorsement(), hex(set()), setHash], `finality of block ${raw.endorsed.height} (${gens.length} generators)`);
    });

    it("rejects a tampered header, a wrong finalized height, too few endorsers, unordered indexes and another set", async () => {
        const bad = Buffer.from(header);
        bad[bad.length - 1] ^= 1;
        await expect(h.call("WavesFinalityVerifier", "verifyFinalized", [hex(bad), endorsement(), hex(set()), setHash])).rejects.toThrow();
        await expect(h.call("WavesFinalityVerifier", "verifyFinalized", [hex(header), endorsement({finalizedHeight: fv.finalizedHeight - 1}), hex(set()), setHash])).rejects.toThrow();
        await expect(h.call("WavesFinalityVerifier", "verifyFinalized", [hex(header), endorsement({endorserIndexes: [fv.endorserIndexes[0]]}), hex(set()), setHash])).rejects.toThrow(/BelowTwoThirds|reverted/);
        if (fv.endorserIndexes.length > 1) {
            await expect(h.call("WavesFinalityVerifier", "verifyFinalized", [hex(header), endorsement({endorserIndexes: [...fv.endorserIndexes].reverse()}), hex(set()), setHash])).rejects.toThrow();
        }
        const inflated = set(gens.map((g, i) => (fv.endorserIndexes.includes(i) ? BigInt(g.balance) * 10n : BigInt(g.balance))));
        await expect(h.call("WavesFinalityVerifier", "verifyFinalized", [hex(header), endorsement(), hex(inflated), setHash])).rejects.toThrow();
    });
});
