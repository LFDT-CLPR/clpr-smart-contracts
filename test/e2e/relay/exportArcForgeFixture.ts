/**
 * exportArcForgeFixture.ts — flatten the live Arc fixture into RLP pieces for the Foundry tests
 * (test/verifiers/evm/arc/ArcMalachiteVerifier.t.sol), which reassemble and mutate them.
 *
 *   npx tsx test/e2e/relay/exportArcForgeFixture.ts   (run after `npm run arc-live:refresh`)
 */
import {readFileSync, writeFileSync, mkdirSync} from "node:fs";
import path from "node:path";
import {toRlp, type Hex} from "viem";
import {encodeHeader, storageEntries} from "./evmHeader.js";
import {arcSetHash, registryMultiProof, selectSignatures, validatorsFromProof} from "./arc.js";
import {ARC_FIXTURE_DIR} from "./buildArcLiveFixture.js";

const OUT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../../verifiers/evm/arc/fixtures/arc-testnet.json");
const fx = JSON.parse(readFileSync(path.join(ARC_FIXTURE_DIR, "testnet.json"), "utf8"));

async function snap(s: any) {
    const {slots} = await validatorsFromProof(s.registryProof);
    const {validators} = await validatorsFromProof(s.parentRegistryProof.storageProof.length ? s.parentRegistryProof : s.registryProof);
    const sel = selectSignatures(s.certificate, validators);
    return {
        height: Number(s.height),
        round: s.certificate.round,
        blockHash: s.block.hash,
        stateRoot: s.block.stateRoot,
        header: encodeHeader(s.block),
        parentHeader: encodeHeader(s.parentBlock),
        parentRegistryAccountProof: toRlp(s.parentRegistryProof.accountProof),
        sigIndices: sel.sigs.map((x) => x.index),
        sigs: sel.sigs.map((x) => x.signature),
        registryAccountProof: toRlp(s.registryProof.accountProof),
        registrySetProof: toRlp(registryMultiProof(s.registryProof, slots)),
        serviceAccountProof: toRlp(s.serviceProof.accountProof),
        storageProof: toRlp(storageEntries(s.serviceProof.storageProof.slice(0, 5)) as any),
        configSlotProof: toRlp(storageEntries(s.serviceProof.storageProof.slice(6, 7)) as any)
    };
}

const {validators} = await validatorsFromProof(fx.snapshots[1].registryProof);
const out = {
    chainId: String(fx.chainId),
    registry: fx.registry,
    target: fx.target,
    channelId: fx.channelId,
    registryRoot: fx.snapshots[1].parentRegistryProof.storageHash,
    setHash: arcSetHash(validators),
    pubkeys: validators.map((v) => v.publicKey),
    powers: validators.map((v) => Number(v.votingPower)),
    h1: await snap(fx.snapshots[0]),
    h2: await snap(fx.snapshots[1])
};
mkdirSync(path.dirname(OUT), {recursive: true});
writeFileSync(OUT, JSON.stringify(out, null, 1) + "\n");
console.log(`wrote ${OUT}`);
