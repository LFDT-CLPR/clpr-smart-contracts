import {afterAll, beforeAll, describe, expect, it} from "vitest";
import {readFileSync} from "node:fs";
import path from "node:path";
import type {Hex} from "viem";
import {decodeAbciProof, encodeSignedHeader, encodeValidatorSet, parseRpcValidator, toHex} from "../../relay/cometbft.js";
import {pbLen} from "../../lib/proto.js";
import {rlpEncode} from "../../lib/rlp.js";
import {AnvilHarness} from "../../relay/anvilHarness.js";
import {FIXTURE_DIR, resourceKey, tableEntryKey} from "../../relay/buildInitiaLiveFixture.js";

/// InitiaMoveVerifier against REAL Initia mainnet (interwoven-1) data, replayed offline on anvil from
/// test/e2e/fixtures/initia-live/initia.json (re-capture with `npm run initia-live:refresh`).
///
/// Proven on-chain: header H (hash recomputed from its fields, validators_hash = anchor set) →
/// app_hash → `move` store root (ICS-23 Tendermint) → (1) the `0x1::dex::ModuleStore` resource and
/// (2) the first entry of its `pairs` table (ICS-23 IAVL), with both keys derived on-chain by
/// InitiaMoveVerifier.resourceKey / tableEntryKey and the table handle read from the proven resource.
/// That is the CLPR path: `Service` resource → table handle → `channels[channelId]`.
///
/// Commit signatures: checked OFF-chain here (cometbft.ts encodeSignedHeader verifies every chosen
/// Ed25519 signature and the >2/3 power). On-chain, they are checked by the CometBFT family's
/// `CometBftCommitAccumulator` (PR #6), which this branch does not contain; the spec uses
/// MockCometBftHeaderSource, which recomputes the header hash but skips signatures.
///
/// Run: forge build && npm run test:e2e:initia-live

const fixture = JSON.parse(readFileSync(path.join(FIXTURE_DIR, "initia.json"), "utf8"));
const STD = ("0x" + "00".repeat(31) + "01") as Hex;

describe("InitiaMoveVerifier on live Initia mainnet data (fixture replay)", () => {
    const h = new AnvilHarness("initia-live");
    const vals = fixture.raw.validators.flatMap((p: any) => p.result.validators).map(parseRpcValidator);
    const sh = fixture.raw.commit.result.signed_header;
    const enc = encodeSignedHeader(sh, vals);
    const headerRef = Buffer.concat([pbLen(1, encodeValidatorSet(vals)), pbLen(2, enc.signedHeader)]);
    const setHash = ("0x" + sh.header.validators_hash.toLowerCase()) as Hex;
    const height = BigInt(sh.header.height);
    const anchor = (setHash + height.toString(16).padStart(16, "0")) as Hex;

    const resKey = resourceKey(Buffer.from(STD.slice(2), "hex"), "dex", "ModuleStore");
    const res = decodeAbciProof(fixture.raw.resource, resKey);
    const handle = res.value.subarray(0, 32);
    const entKey = tableEntryKey(handle, Buffer.from(fixture.meta.tableKeyBytes.slice(2), "hex"));
    const ent = decodeAbciProof(fixture.raw.entry, entKey);

    const valueProof = (p: {multistoreProof: Buffer; iavlProof: Buffer; value: Buffer}, value = p.value) =>
        toHex(rlpEncode([[], headerRef, p.multistoreProof, p.iavlProof, value]));

    beforeAll(async () => {
        await h.start();
        await h.deploy("MockCometBftHeaderSource");
        await h.deploy("InitiaMoveVerifier", [h.addr.MockCometBftHeaderSource, setHash, 0n]);
    });

    afterAll(() => h.stop());

    it("the fixture's commit is real: header hash = block id, more than 2/3 of the power signed (off-chain check)", () => {
        expect(toHex(enc.headerHash)).toBe(fixture.meta.headerHash);
        expect(toHex(enc.headerHash)).toBe(("0x" + fixture.raw.commit.result.signed_header.commit.block_id.hash.toLowerCase()) as Hex);
        expect(enc.signedPower * 3n > enc.totalPower * 2n).toBe(true);
        console.log(`[initia-live] height ${height}, ${vals.length} validators, ${enc.signerIndices.length} signatures carry ${enc.signedPower}/${enc.totalPower}`);
    });

    it("derives the Move keys on-chain exactly as initia x/move does", async () => {
        expect(await h.call("InitiaMoveVerifier", "resourceKey", [("0x" + "00".repeat(31) + "01"), toHex(Buffer.from("dex")), toHex(Buffer.from("ModuleStore"))]))
            .toBe(toHex(resKey));
        expect(await h.call("InitiaMoveVerifier", "tableEntryKey", [toHex(handle), fixture.meta.tableKeyBytes])).toBe(toHex(entKey));
    });

    it("proves the live 0x1::dex::ModuleStore resource under the header's app_hash", async () => {
        const [hdr, value] = await h.call("InitiaMoveVerifier", "verifyMoveValue", [valueProof(res), anchor, toHex(resKey)]);
        expect(hdr.appHash).toBe(fixture.meta.appHash);
        expect(hdr.height).toBe(height);
        expect(value).toBe(toHex(res.value));
        expect(toHex(handle)).toBe(fixture.meta.tableHandle);
        await h.measure("InitiaMoveVerifier", "verifyMoveValue", [valueProof(res), anchor, toHex(resKey)], "resource proof (inline header)");
    });

    it("proves the live table entry under the handle read from that resource", async () => {
        const [, value] = await h.call("InitiaMoveVerifier", "verifyMoveValue", [valueProof(ent), anchor, toHex(entKey)]);
        expect(value).toBe(toHex(ent.value));
        await h.measure("InitiaMoveVerifier", "verifyMoveValue", [valueProof(ent), anchor, toHex(entKey)], "table-entry proof (inline header)");
    });

    it("rejects a tampered value, another key, a wrong validator set and a stale anchor", async () => {
        const bad = Buffer.from(ent.value);
        bad[bad.length - 1] ^= 1;
        await expect(h.call("InitiaMoveVerifier", "verifyMoveValue", [valueProof(ent, bad), anchor, toHex(entKey)])).rejects.toThrow();
        await expect(h.call("InitiaMoveVerifier", "verifyMoveValue", [valueProof(ent), anchor, toHex(resKey)])).rejects.toThrow();
        const wrongSet = ("0x" + "11".repeat(32) + height.toString(16).padStart(16, "0")) as Hex;
        await expect(h.call("InitiaMoveVerifier", "verifyMoveValue", [valueProof(ent), wrongSet, toHex(entKey)])).rejects.toThrow();
        const stale = (setHash + (height + 1n).toString(16).padStart(16, "0")) as Hex;
        await expect(h.call("InitiaMoveVerifier", "verifyMoveValue", [valueProof(ent), stale, toHex(entKey)])).rejects.toThrow();
    });
});
