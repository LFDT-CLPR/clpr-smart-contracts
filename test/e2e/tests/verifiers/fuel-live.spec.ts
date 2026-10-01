import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {readFileSync} from "node:fs";
import path from "node:path";
import type {Hex} from "viem";
import {buildEthLiveProof, buildExecutionStateRootBranch} from "../../relay/buildEthLiveProof.js";
import {bigintToTrimmedBuf, hexToBuf, rlpDecode, rlpEncode} from "../../lib/rlp.js";
import {AnvilHarness} from "../../relay/anvilHarness.js";
import {CHAIN_STATE, FIXTURE_DIR, MAINNET_GENESIS_TIME, SECONDS_PER_SLOT, consensusHeader, fullHeader} from "../../relay/buildFuelLiveFixture.js";

/// FuelVerifier against REAL Fuel Ignition + Ethereum mainnet data, replayed offline on anvil from
/// test/e2e/fixtures/fuel-live/fuel.json (re-capture with `npm run fuel-live:refresh`).
///
/// Proven on-chain, all with production contracts (EthL1StateVerifier + FuelVerifier):
///   Ethereum sync committee (BLS aggregate, non-signers authenticated) signs the header →
///   execution state_root → FuelChainState account (code hash) → storage: the commit's block id
///   and timestamp, _paused = 0, ERC-1967 implementation → commit timestamp + 1 day ≤ slot time →
///   Fuel commit header id = committed id → message block in prevRoot → message in outbox.
/// The message is a real one from Fuel's bridge (no CLPR Service is deployed on Fuel), so the
/// generic `verifyFuelMessage` entry is used; `verifyBundle` adds the record checks (Foundry tests).
///
/// Run: forge build && npm run test:e2e:fuel-live

const fixture = JSON.parse(readFileSync(path.join(FIXTURE_DIR, "fuel.json"), "utf8"));
const RECIPIENT = ("0x" + "00".repeat(31) + "01") as Hex;

const hex = (b: Buffer): Hex => ("0x" + b.toString("hex")) as Hex;

describe("FuelVerifier on live Fuel Ignition + Ethereum mainnet data (fixture replay)", () => {
    const h = new AnvilHarness("fuel-live");
    const eth = buildEthLiveProof(fixture.l1);
    const mp = fixture.fuel.messageProof;
    const cs = fixture.l1ChainState;
    const implementation = ("0x" + BigInt(cs.storageProof[3].value).toString(16).padStart(40, "0")) as Hex;

    const lightClientProof = (): Buffer => {
        const p = eth.parts;
        return rlpEncode([p.attestedHeader, p.syncAggregate, p.executionStateRoot, p.executionBranch, Buffer.alloc(0), [], p.nonSignerEntries]);
    };
    const merkle = (m: {proofIndex: string; proofSet: string[]}) => [bigintToTrimmedBuf(BigInt(m.proofIndex)), m.proofSet.map(hexToBuf)];

    function proof(over: {message?: any; blockProof?: any; commitHeader?: Buffer} = {}): Hex {
        return hex(rlpEncode([
            lightClientProof(),
            cs.accountProof.map(hexToBuf),
            cs.storageProof.map((s: any) => [hexToBuf("0x" + BigInt(s.key).toString(16).padStart(64, "0")), s.proof.map(hexToBuf)]),
            over.commitHeader ?? consensusHeader(mp.commitBlockHeader),
            fullHeader(mp.messageBlockHeader),
            over.blockProof ?? merkle(mp.blockProof),
            merkle(mp.messageProof),
            over.message ?? [hexToBuf(mp.sender), hexToBuf(mp.recipient), hexToBuf(mp.nonce), bigintToTrimmedBuf(BigInt(mp.amount)), hexToBuf(mp.data)]
        ]));
    }

    function profile(timeToFinalize: bigint, impl: Hex = implementation) {
        return {
            l1StateVerifier: h.addr.EthL1StateVerifier,
            l1GenesisTime: MAINNET_GENESIS_TIME,
            l1SecondsPerSlot: SECONDS_PER_SLOT,
            chainState: CHAIN_STATE.address,
            chainStateCodeHash: cs.codeHash,
            chainStateImplementation: impl,
            commitSlotsBase: CHAIN_STATE.commitSlotsBase,
            pausedSlot: CHAIN_STATE.pausedSlot,
            numCommitSlots: CHAIN_STATE.numCommitSlots,
            blocksPerCommitInterval: CHAIN_STATE.blocksPerCommitInterval,
            timeToFinalize,
            messageRecipient: RECIPIENT
        };
    }

    beforeAll(async () => {
        await h.start();
        // Electra/Fulu mainnet beacon layout: execution state_root gindex 802 (depth 9),
        // next_sync_committee gindex 87 (depth 6), 8192 slots per sync-committee period.
        await h.deploy("EthL1StateVerifier", [802n, 9n, 87n, 6n, 8192n]);
        await h.deploy("FuelVerifier", [profile(CHAIN_STATE.timeToFinalize)]);
        await h.deploy("FuelVerifier", [profile(30n * 86400n)], "FuelVerifierLongDelay");
        await h.deploy("FuelVerifier", [profile(CHAIN_STATE.timeToFinalize, "0x000000000000000000000000000000000000dEaD")], "FuelVerifierOtherImpl");
    });

    afterAll(() => h.stop());

    it("proves a live Fuel message from the Ethereum sync committee down to the Fuel outbox", async () => {
        const [m] = await h.call("FuelVerifier", "verifyFuelMessage", [proof(), eth.trustAnchor]);
        expect(m.sender).toBe(mp.sender);
        expect(m.recipient).toBe(mp.recipient);
        expect(m.nonce).toBe(mp.nonce);
        expect(m.data).toBe(mp.data);
        expect(BigInt(m.blockHeight)).toBe(BigInt(fixture.meta.messageBlockHeight));
        expect(BigInt(m.commitHeight)).toBe(BigInt(fixture.meta.commitHeight));
        expect(BigInt(m.commitTimestamp)).toBe(BigInt(fixture.meta.commitTimestamp));
        console.log(`[fuel-live] sync committee ${eth.meta.participants}/512, slot ${eth.meta.attestedSlot}; Fuel commit ${fixture.meta.commitHeight}, message block ${fixture.meta.messageBlockHeight}`);
        await h.measure("FuelVerifier", "verifyFuelMessage", [proof(), eth.trustAnchor], "full message proof (L1 + FuelChainState + Fuel)");
    });

    it("rejects a tampered message, a wrong history proof and a wrong commit header", async () => {
        const msg = [hexToBuf(mp.sender), hexToBuf(mp.recipient), hexToBuf(mp.nonce), bigintToTrimmedBuf(BigInt(mp.amount)), Buffer.concat([hexToBuf(mp.data), Buffer.from([0])])];
        await expect(h.call("FuelVerifier", "verifyFuelMessage", [proof({message: msg}), eth.trustAnchor])).rejects.toThrow(/MessageNotInBlock|reverted/);
        const bp = merkle(mp.blockProof) as [Buffer, Buffer[]];
        const badBp = [bp[0], bp[1].map((s, i) => (i === 0 ? Buffer.alloc(32, 7) : s))];
        await expect(h.call("FuelVerifier", "verifyFuelMessage", [proof({blockProof: badBp}), eth.trustAnchor])).rejects.toThrow();
        const ch = Buffer.from(consensusHeader(mp.commitBlockHeader));
        ch[75] ^= 1;
        await expect(h.call("FuelVerifier", "verifyFuelMessage", [proof({commitHeader: ch}), eth.trustAnchor])).rejects.toThrow();
    });

    it("enforces the finalization delay and the pinned implementation", async () => {
        await expect(h.call("FuelVerifierLongDelay", "verifyFuelMessage", [proof(), eth.trustAnchor], "FuelVerifier")).rejects.toThrow();
        await expect(h.call("FuelVerifierOtherImpl", "verifyFuelMessage", [proof(), eth.trustAnchor], "FuelVerifier")).rejects.toThrow();
    });

    it("measures the L1 half alone, with and without a sync-committee rotation", async () => {
        const plain = await h.measure("EthL1StateVerifier", "verifyL1State", [hex(lightClientProof()), eth.trustAnchor], "L1 half only (verifyL1State)");
        const r = eth.rotation;
        if (!r) return;
        const u = fixture.l1.rotationUpdate.data;
        const b = u.attested_header.beacon;
        const exec = buildExecutionStateRootBranch(u.attested_header);
        const [nextCommittee, nextBranch] = rlpDecode(hexToBuf(r.rotationRlp)) as any[];
        const [nonSigners] = rlpDecode(hexToBuf(r.nonSignerWrapperRlp)) as any[];
        const lc = rlpEncode([
            [bigintToTrimmedBuf(BigInt(b.slot)), bigintToTrimmedBuf(BigInt(b.proposer_index)), hexToBuf(b.parent_root), hexToBuf(b.state_root), hexToBuf(b.body_root)],
            [hexToBuf(r.bits), hexToBuf(r.signature)], exec.stateRoot, exec.branch, nextCommittee, nextBranch, nonSigners
        ]);
        const [, , newAnchor] = await h.call("EthL1StateVerifier", "verifyL1State", [hex(lc), eth.trustAnchor]);
        expect((newAnchor.length - 2) / 2).toBe(260);
        const rot = await h.measure("EthL1StateVerifier", "verifyL1State", [hex(lc), eth.trustAnchor], "L1 half with a sync-committee rotation");
        console.log(`[fuel-live] rotation adds ${rot.gas - plain.gas} gas and ${rot.calldata - plain.calldata} B to the L1 half`);
    });

    it("rejects a trust anchor with another sync committee", async () => {
        const bad = Buffer.from(hexToBuf(eth.trustAnchor));
        bad[200] ^= 1; // committee Merkle root
        await expect(h.call("FuelVerifier", "verifyFuelMessage", [proof(), hex(bad)])).rejects.toThrow();
    });
});
