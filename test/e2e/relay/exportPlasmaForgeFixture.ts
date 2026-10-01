/**
 * exportPlasmaForgeFixture.ts — flatten the live Plasma fixture into the pieces the Foundry tests
 * (test/verifiers/evm/plasma/PlasmaBftVerifier.t.sol) reassemble and mutate.
 *
 *   npx tsx test/e2e/relay/exportPlasmaForgeFixture.ts   (run after `npm run plasma-live:refresh`)
 */
import {readFileSync, writeFileSync, mkdirSync} from "node:fs";
import path from "node:path";
import {toRlp} from "viem";
import {storageEntries} from "./evmHeader.js";
import {decodeBlockV1, decodeGossip, g1Uncompressed, g2Uncompressed, hx, toHex, type Qc} from "./plasma.js";
import {PLASMA_FIXTURE_DIR} from "./buildPlasmaLiveFixture.js";

const OUT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../../verifiers/evm/plasma/fixtures/plasma-mainnet.json");
const fx = JSON.parse(readFileSync(path.join(PLASMA_FIXTURE_DIR, "mainnet.json"), "utf8"));
const [b0, b1, b2] = fx.gossip.map((g: string) => decodeBlockV1(decodeGossip(hx(g)).block));
const cat = (xs: Uint8Array[]) => toHex(Uint8Array.from(Buffer.concat(xs.map((x) => Buffer.from(x)))));
const qc = (q: Qc) => ({proposer: Number(q.proposer), height: Number(q.height), view: Number(q.view), votes: q.votes, sig96: toHex(q.sig), sig256: toHex(g2Uncompressed(q.sig))});

const out = {
    chainId: String(fx.chainId),
    target: fx.target,
    channelId: fx.channelId,
    committeeRoot: fx.committeeRoot,
    height: Number(fx.height),
    stateRoot: fx.evmBlock.stateRoot,
    committee: cat(fx.committee.map((k: string) => g1Uncompressed(hx(k)))),
    headerB: cat(b0.leaves),
    stateBranch: cat(b0.stateBranch),
    headerB1: cat(b1.leaves),
    headerB2: cat(b2.leaves),
    qc1: qc(b1.qc),
    qc2: qc(b2.qc),
    serviceAccountProof: toRlp(fx.serviceProof.accountProof),
    storageProof: toRlp(storageEntries(fx.serviceProof.storageProof.slice(0, 5)) as any),
    configSlotProof: toRlp(storageEntries(fx.serviceProof.storageProof.slice(6, 7)) as any)
};
mkdirSync(path.dirname(OUT), {recursive: true});
writeFileSync(OUT, JSON.stringify(out, null, 1) + "\n");
console.log(`wrote ${OUT}`);
