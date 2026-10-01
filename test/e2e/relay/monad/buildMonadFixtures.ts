/// Generates the synthetic MonadVerifier fixture (test/verifiers/evm/monad/fixtures/synthetic.json):
/// a mainnet-sized (196-validator) MonadBFT chain with real BLS QCs, BLAKE3 block ids, delayed eth
/// headers, MIP-8 page-storage tries for the ClprService and the staking precompile, a full
/// validator-set rotation, and the negative cases. Live-data replay is separate (refreshMonadLive.ts).
///
/// Run: npx tsx test/e2e/relay/monad/buildMonadFixtures.ts
import {writeFileSync, mkdirSync, rmSync} from "node:fs";
import path from "node:path";
import {type Input} from "@ethereumjs/rlp";
import {
    type Validator, type Anchor, type ChannelState, PagedStorage, StateTrie, makeValidator, sortValidators, valsetBlob,
    finalityChain, ethHeader, encodeAnchor, rlp, int, word, keccak, cat, toHex, hex, be, bundleContent, channelContext,
    channelSlots, channelStorage, stakingStorage, chunkSlots, finalizeItem, rotationAcc, SLOT_VALSET_CONSENSUS, STAKING,
    signQc, blockId, startSlots, idsBlob, chunkItem, registryBlob
} from "./monad.js";

const OUT_DIR = path.join(process.cwd(), "test/verifiers/evm/monad/fixtures/synthetic");
export const N = 196;
export const CHUNK = Number(process.env.MONAD_CHUNK ?? 66); // warm rotation (keys from the registry)
export const COLD_CHUNK = Number(process.env.MONAD_COLD_CHUNK ?? 28); // first rotation (all keys proven)
const EPOCH = 2190n;
const SERVICE = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
const CODE_HASH = keccak(new TextEncoder().encode("ClprService runtime code"));
const CHANNEL_ID = keccak(new TextEncoder().encode("monad-hiero-channel-1"));

function stakeOf(i: number): bigint {
    // Uneven, mainnet-like stakes (~1e24..2e27 wei).
    return (BigInt((i * 7919) % 997) + 3n) * 10n ** 24n + BigInt(i) * 10n ** 21n;
}

/// Signer set covering at least `frac` of total stake (by index order).
function signersFor(sorted: Validator[], frac: number): Set<number> {
    const total = sorted.reduce((a, v) => a + v.stake, 0n);
    const s = new Set<number>();
    let acc = 0n;
    const target = (total * BigInt(Math.round(frac * 10000))) / 10000n;
    for (let i = 0; i < sorted.length && acc <= target; i++) {
        if (i % 9 === 4) continue; // leave holes so the bitmap is non-trivial
        s.add(i);
        acc += sorted[i].stake;
    }
    return s;
}

function stakeSum(sorted: Validator[], s: Set<number>) {
    let x = 0n;
    for (const i of s) x += sorted[i].stake;
    return x;
}

function manifestProto(version: bigint, service: Uint8Array): Uint8Array {
    return cat(new Uint8Array([0x08]), varint(version), new Uint8Array([0x12, service.length]), service);
}
function varint(v: bigint): Uint8Array {
    const out: number[] = [];
    do { let b = Number(v & 0x7fn); v >>= 7n; if (v) b |= 0x80; out.push(b); } while (v);
    return Uint8Array.from(out);
}

export function build() {
    // ── validator sets ──
    const current: Validator[] = Array.from({length: N}, (_, i) => ({...makeValidator(i, stakeOf(i)), id: BigInt(i + 1)}));
    // Next epoch: 3 validators replaced, stakes changed (array order = staking's stake-descending order).
    const nextRaw: Validator[] = current.map((v, i) => ({...v, stake: v.stake + BigInt(i % 5) * 10n ** 23n}));
    for (const k of [10, 77, 150]) nextRaw[k] = {...makeValidator(1000 + k, stakeOf(k) + 1n), id: BigInt(1000 + k)};
    const next = [...nextRaw].sort((a, b) => (a.stake === b.stake ? Number(a.id! - b.id!) : a.stake > b.stake ? -1 : 1));
    const curSorted = sortValidators(current);
    const nextSorted = sortValidators(next);
    const curBlob = valsetBlob(curSorted);
    const nextBlob = valsetBlob(nextSorted);
    const signers = signersFor(curSorted, 0.72);
    const nextSigners = signersFor(nextSorted, 0.8);

    // ── state at the finalized block (in epoch EPOCH's delay period) ──
    const svc = hex(SERVICE);
    const channel: ChannelState = {
        status: 1, nextMessageId: 4n, ackedMessageId: 1n, receivedMessageId: 2n,
        sentRunningHash: BigInt(toHex(keccak(new TextEncoder().encode("sent")))),
        receivedRunningHash: BigInt(toHex(keccak(new TextEncoder().encode("recv")))),
        endpointManifestVersion: 1n, verifier: 0xabcdefn
    };
    const manifest = manifestProto(2n, svc);
    const svcSlots = channelStorage(CHANNEL_ID, channel);
    svcSlots.set(18n, BigInt(toHex(keccak(manifest))));
    svcSlots.set(17n, 2n);
    for (let j = 0; j < 30; j++) svcSlots.set(BigInt(toHex(keccak(be(BigInt(j), 32)))), BigInt(j + 1)); // other state
    const svcStorage = new PagedStorage(svcSlots);
    const stakingSt = new PagedStorage(stakingStorage(EPOCH, next));
    const accounts = new Map([
        [SERVICE, {nonce: 1n, balance: 0n, storage: svcStorage, codeHash: CODE_HASH}],
        ["0x0000000000000000000000000000000000001000", {nonce: 0n, balance: 10n ** 27n, storage: stakingSt, codeHash: keccak(new Uint8Array(0))}]
    ]);
    const state = new StateTrie(accounts, 200);
    const BLOCK = 109_600_000n;
    const eth = ethHeader(state.root, BLOCK);

    const fin = finalityChain({sorted: curSorted, signers, epoch: EPOCH, seqP: BLOCK + 3n, roundP: 109_623_310n, ethHeaderRlp: eth});

    const anchor0: Anchor = {epoch: EPOCH, valsetHash: keccak(curBlob), codeHash: CODE_HASH, keysHash: keccak(registryBlob(current))};
    const messages = [new TextEncoder().encode("monad message 3"), new TextEncoder().encode("monad message 4")];
    const content = bundleContent(messages);
    const chPages = svcStorage.pagesFor(channelSlots(CHANNEL_ID));
    const svcAcct = state.accountProof(SERVICE);
    const stakingAcct = state.accountProof("0x0000000000000000000000000000000000001000");
    const rotStart: Input = [stakingAcct, stakingSt.pagesFor(startSlots(N))];

    const kind0 = (o: {finality?: Input; valset?: Uint8Array; acct?: Input; pages?: Input; rot?: Input; manifest?: boolean}) => {
        const items: Input[] = [int(0), o.finality ?? fin.finalityItem, o.valset ?? curBlob, o.acct ?? svcAcct, o.pages ?? chPages, content, o.rot ?? []];
        if (o.manifest) items.push(svcStorage.pagesFor([18n]), manifest);
        return toHex(rlp(items));
    };

    const cases: Record<string, {proof: string; anchor: string; expect?: string; note?: string}> = {};
    const A0 = toHex(encodeAnchor(anchor0));
    cases.bundle_ok = {proof: kind0({}), anchor: A0};
    cases.bundle_manifest = {proof: kind0({manifest: true}), anchor: A0};

    // ── negatives (finality / QC) ──
    {
        const bad = structuredClone(fin.finalityItem) as Uint8Array[];
        const otherSig = signQc({...fin.qcOnB.vote, round: fin.qcOnB.vote.round + 5n}, curSorted, signers);
        // keep the QC (vote, bitmap, compressed sig) but swap in a signature over another vote — compressed binding fails
        cases.bad_signature_encoding = {proof: kind0({finality: [bad[0], bad[1], fin.qcOnB.qcItem, otherSig.sigUncompressed]}), anchor: A0, expect: "BlsSignatureEncoding"};
        // a QC whose compressed + uncompressed signature agree but sign another vote
        const forged: Input = [(fin.qcOnB.qcItem as Input[])[0], (otherSig.qcItem as Input[])[1]];
        cases.bad_signature = {proof: kind0({finality: [bad[0], bad[1], forged, otherSig.sigUncompressed]}), anchor: A0, expect: "BlsSignatureInvalid"};
    }
    {
        // Below threshold: a valid aggregate signature by validators holding < 2/3 stake.
        const total = curSorted.reduce((a, v) => a + v.stake, 0n);
        const few = new Set<number>();
        let acc = 0n;
        for (let i = 0; i < N && acc * 3n < total * 2n - 3n * 10n ** 24n; i++) { few.add(i); acc += curSorted[i].stake; }
        while (stakeSum(curSorted, few) >= (total * 2n) / 3n + 1n) few.delete(Math.max(...few));
        const q = signQc(fin.qcOnB.vote, curSorted, few);
        cases.below_threshold = {proof: kind0({finality: [fin.headerP, fin.headerB, q.qcItem, q.sigUncompressed]}), anchor: A0, expect: "InsufficientStake"};
    }
    {
        // Wrong validator set: the next epoch's set presented under the current anchor.
        cases.wrong_validator_set = {proof: kind0({valset: nextBlob}), anchor: A0, expect: "ValidatorSetMismatch"};
        // Anchor commits to another set (signature by the right keys no longer covers the committed set).
        const wrongAnchor = toHex(encodeAnchor({...anchor0, valsetHash: keccak(nextBlob)}));
        cases.wrong_anchor_set = {proof: kind0({}), anchor: wrongAnchor, expect: "ValidatorSetMismatch"};
    }
    {
        // Not committed: QC on B two rounds after P's QC (a timeout in between) — 2-chain rule fails.
        const gap = finalityChain({sorted: curSorted, signers, epoch: EPOCH, seqP: BLOCK + 3n, roundP: 109_623_310n, ethHeaderRlp: eth, roundGap: 2n});
        cases.not_committed = {proof: kind0({finality: gap.finalityItem}), anchor: A0, expect: "NotCommitted"};
        // Delayed result for the wrong block (seq - 2 instead of seq - 3).
        const off = finalityChain({sorted: curSorted, signers, epoch: EPOCH, seqP: BLOCK + 2n, roundP: 109_623_310n, ethHeaderRlp: eth});
        cases.delayed_mismatch = {proof: kind0({finality: off.finalityItem}), anchor: A0, expect: "DelayedResultMismatch"};
        // B does not extend P (headers from two different chains).
        const other = finalityChain({sorted: curSorted, signers, epoch: EPOCH, seqP: BLOCK + 3n, roundP: 109_623_400n, ethHeaderRlp: eth});
        cases.block_id_mismatch = {proof: kind0({finality: [fin.headerP, other.headerB, other.qcOnB.qcItem, other.qcOnB.sigUncompressed]}), anchor: A0, expect: "BlockIdMismatch"};
        // Stale epoch: anchor already at EPOCH+1, QC from EPOCH.
        cases.stale_epoch = {proof: kind0({}), anchor: toHex(encodeAnchor({...anchor0, epoch: EPOCH + 1n})), expect: "EpochMismatch"};
    }
    {
        // Wrong storage proofs.
        const pages = structuredClone(chPages) as [Uint8Array[], Input[][]];
        const vals = pages[1][0][3] as Uint8Array[];
        vals[0] = word(BigInt(toHex(vals[0])) + 1n);
        cases.wrong_storage_value = {proof: kind0({pages}), anchor: A0, expect: "PageCommitmentMismatch"};
        const pages2 = structuredClone(chPages) as [Uint8Array[], Input[][]];
        const nodes = pages2[0];
        nodes[nodes.length - 1] = cat(nodes[nodes.length - 1].slice(0, -1), new Uint8Array([nodes[nodes.length - 1].at(-1)! ^ 1]));
        cases.wrong_storage_node = {proof: kind0({pages: pages2}), anchor: A0, expect: "MptHashMismatch"};
        const pages3 = structuredClone(chPages) as [Uint8Array[], Input[][]];
        pages3[1] = pages3[1].slice(1); // drop the first page
        cases.missing_page = {proof: kind0({pages: pages3}), anchor: A0, expect: "PageNotProven"};
        const acct = structuredClone(svcAcct) as Uint8Array[];
        cases.wrong_code_hash = {proof: kind0({}), anchor: toHex(encodeAnchor({...anchor0, codeHash: keccak(new Uint8Array([1]))})), expect: "CodeHashMismatch"};
        void acct;
    }

    // ── rotation ──
    const startProof = kind0({rot: rotStart});
    const pendingBase: Anchor = {...anchor0, pendingEpoch: EPOCH + 1n, pendingBlock: BLOCK, stakingRoot: stakingSt.root,
        serviceRoot: svcStorage.root, pendingLength: BigInt(N), pendingProven: 0n, pendingAcc: new Uint8Array(32), pendingIds: keccak(idsBlob(next))};
    cases.rotation_start = {proof: startProof, anchor: A0, note: toHex(encodeAnchor(pendingBase))};
    {
        // Not in the delay period → rejected.
        const st2 = new PagedStorage(stakingStorage(EPOCH, next, false));
        const accounts2 = new Map(accounts);
        accounts2.set("0x0000000000000000000000000000000000001000", {nonce: 0n, balance: 10n ** 27n, storage: st2, codeHash: keccak(new Uint8Array(0))});
        const state2 = new StateTrie(accounts2, 200);
        const fin2 = finalityChain({sorted: curSorted, signers, epoch: EPOCH, seqP: BLOCK + 3n, roundP: 109_623_310n, ethHeaderRlp: ethHeader(state2.root, BLOCK)});
        const p = toHex(rlp([int(0), fin2.finalityItem, curBlob, state2.accountProof(SERVICE), svcStorage.pagesFor(channelSlots(CHANNEL_ID)), content,
            [state2.accountProof("0x0000000000000000000000000000000000001000"), st2.pagesFor(startSlots(N))]]));
        cases.rotation_not_in_delay = {proof: p, anchor: A0, expect: "RotationStateInvalid"};
        // Restart with an older (or equal) block than the pending one → stale.
        cases.rotation_restart_stale = {proof: startProof, anchor: toHex(encodeAnchor(pendingBase)), expect: "RotationStale"};
    }
    const A1obj: Anchor = {epoch: EPOCH + 1n, valsetHash: keccak(nextBlob), codeHash: CODE_HASH, keysHash: keccak(registryBlob(next))};
    const rotationSteps = (base: Anchor, prev: Validator[] | null, size: number) => {
        const out: Array<{proof: string; anchorAfter: string}> = [];
        let proven = 0;
        while (proven < N) {
            const count = Math.min(size, N - proven);
            const item = chunkItem(next, prev, stakingSt, proven, count);
            proven += count;
            const last = proven === N;
            const proof = toHex(rlp([int(1), chPages, content, item, last ? finalizeItem(next) : []]));
            const after: Anchor = last ? A1obj : {...base, pendingProven: BigInt(proven), pendingAcc: rotationAcc(next, proven)};
            out.push({proof, anchorAfter: toHex(encodeAnchor(after))});
        }
        return out;
    };
    // Warm: the current set's key registry is in the anchor; only the 3 new validators' keys are proven.
    const steps = rotationSteps(pendingBase, current, CHUNK);
    {
        // Restart from a later delay-period block after one chunk: progress is kept, roots/block refreshed.
        const later = finalityChain({sorted: curSorted, signers, epoch: EPOCH, seqP: BLOCK + 8n, roundP: 109_623_330n, ethHeaderRlp: ethHeader(state.root, BLOCK + 5n)});
        const afterChunk0 = JSON.parse(JSON.stringify(steps[0]));
        cases.rotation_restart_keeps_progress = {proof: kind0({finality: later.finalityItem, rot: rotStart}), anchor: afterChunk0.anchorAfter,
            note: toHex(encodeAnchor({...pendingBase, pendingBlock: BLOCK + 5n, pendingProven: BigInt(CHUNK), pendingAcc: rotationAcc(next, CHUNK)}))};
    }
    // Cold: first rotation after bootstrap (no registry) — every validator's keys are proven.
    const coldBase: Anchor = {...pendingBase, keysHash: new Uint8Array(32)};
    const coldSteps = rotationSteps(coldBase, null, COLD_CHUNK);
    {
        // finalize separately (no chunk) with a wrong permutation / before completion
        const full: Anchor = {...pendingBase, pendingProven: BigInt(N), pendingAcc: rotationAcc(next)};
        const [blob, perm, ids] = finalizeItem(next) as Uint8Array[];
        const badPerm = Uint8Array.from(perm);
        [badPerm[0], badPerm[1], badPerm[2], badPerm[3]] = [badPerm[2], badPerm[3], badPerm[0], badPerm[1]];
        cases.finalize_bad_permutation = {proof: toHex(rlp([int(1), chPages, content, [], [blob, badPerm, ids]])), anchor: toHex(encodeAnchor(full)), expect: "RotationAccumulatorMismatch"};
        // Entries out of secp order (swap sorted entries 0 and 1 together with their indices).
        const swapped = cat(blob.slice(193, 386), blob.slice(0, 193), blob.slice(386));
        cases.finalize_unsorted = {proof: toHex(rlp([int(1), chPages, content, [], [swapped, badPerm, ids]])), anchor: toHex(encodeAnchor(full)), expect: "ValidatorOrder"};
        const dupPerm = Uint8Array.from(perm);
        dupPerm[2] = dupPerm[0]; dupPerm[3] = dupPerm[1];
        cases.finalize_dup_index = {proof: toHex(rlp([int(1), chPages, content, [], [blob, dupPerm, ids]])), anchor: toHex(encodeAnchor(full)), expect: "InvalidPermutation"};
        const badStake = Uint8Array.from(blob);
        badStake[193 - 1] ^= 1; // stake of the first sorted validator
        cases.finalize_wrong_stake = {proof: toHex(rlp([int(1), chPages, content, [], [badStake, perm, ids]])), anchor: toHex(encodeAnchor(full)), expect: "RotationAccumulatorMismatch"};
        cases.finalize_incomplete = {proof: toHex(rlp([int(1), chPages, content, [], [blob, perm, ids]])), anchor: toHex(encodeAnchor({...full, pendingProven: BigInt(N - 1)})), expect: "RotationIncomplete"};
        cases.finalize_ok_separate = {proof: toHex(rlp([int(1), chPages, content, [], [blob, perm, ids]])), anchor: toHex(encodeAnchor(full)),
            note: toHex(encodeAnchor(A1obj))};
        // chunk proving a tampered key page
        const cold2 = chunkItem(next, null, stakingSt, 0, 2) as Input[];
        const pages = structuredClone(cold2[3]) as [Uint8Array[], Input[][]];
        const v = pages[1][pages[1].length - 1][3] as Uint8Array[];
        v[3] = word(BigInt(toHex(v[3])) ^ 1n);
        cases.chunk_tampered_keys = {proof: toHex(rlp([int(1), chPages, content, [cold2[0], cold2[1], cold2[2], pages, cold2[4]], []])), anchor: toHex(encodeAnchor(coldBase)), expect: "PageCommitmentMismatch"};
        cases.chunk_overflow = {proof: toHex(rlp([int(1), chPages, content, cold2, []])), anchor: toHex(encodeAnchor({...coldBase, pendingProven: BigInt(N - 1)})), expect: "RotationOverflow"};
        const badIds = idsBlob(next); badIds[7] ^= 1;
        cases.chunk_wrong_ids = {proof: toHex(rlp([int(1), chPages, content, [badIds, cold2[1], cold2[2], cold2[3], cold2[4]], []])), anchor: toHex(encodeAnchor(coldBase)), expect: "RotationStateInvalid"};
        // Registry that does not match the anchor's keysHash.
        const warm2 = chunkItem(next, current, stakingSt, 0, 2) as Input[];
        const badReg = registryBlob(current); badReg[20] ^= 1;
        cases.chunk_wrong_registry = {proof: toHex(rlp([int(1), chPages, content, [warm2[0], badReg, warm2[2], warm2[3], warm2[4]], []])), anchor: toHex(encodeAnchor(pendingBase)), expect: "RotationStateInvalid"};
        // A hint pointing at another validator's registry entry.
        const badHints = Uint8Array.from(warm2[2] as Uint8Array); badHints[1] ^= 1;
        cases.chunk_wrong_hint = {proof: toHex(rlp([int(1), chPages, content, [warm2[0], warm2[1], badHints, warm2[3], warm2[4]], []])), anchor: toHex(encodeAnchor(pendingBase)), expect: "InvalidValidatorEntry"};
        cases.rotation_without_pending = {proof: steps[0].proof, anchor: A0, expect: "RotationNotPending"};
    }

    // ── epoch EPOCH+1 bundle (after rotation) and the old epoch's QC replayed against it ──
    const BLOCK2 = BLOCK + 60_000n;
    const fin3 = finalityChain({sorted: nextSorted, signers: nextSigners, epoch: EPOCH + 1n, seqP: BLOCK2 + 3n, roundP: 109_700_000n, ethHeaderRlp: ethHeader(state.root, BLOCK2)});
    const A1 = toHex(encodeAnchor(A1obj));
    cases.bundle_next_epoch = {proof: kind0({finality: fin3.finalityItem, valset: nextBlob}), anchor: A1};
    cases.replay_old_epoch_after_rotation = {proof: kind0({}), anchor: A1, expect: "ValidatorSetMismatch"};
    cases.next_epoch_qc_before_rotation = {proof: kind0({finality: fin3.finalityItem}), anchor: A0, expect: "EpochMismatch"};

    // ── config ──
    const throttles: Input = [int(50), int(16384), int(2_000_000), int(1000), int(131072), int(8), int(8)];
    const config = toHex(rlp([new TextEncoder().encode("eip155:143"), svc, CODE_HASH, int(1_760_000_000_000_000_000n), throttles, int(EPOCH), curBlob, fin.finalityItem, registryBlob(current)]));
    const manifestProof = toHex(rlp([fin.finalityItem, svcAcct, svcStorage.pagesFor([18n]), manifest]));

    const out = {
        meta: {
            validators: N, epoch: Number(EPOCH), chunk: CHUNK, signers: signers.size, block: Number(BLOCK),
            service: SERVICE, codeHash: toHex(CODE_HASH), channelId: toHex(CHANNEL_ID),
            blockIdP: toHex(blockId(fin.headerP)), blockIdB: toHex(blockId(fin.headerB)), stateRoot: toHex(state.root),
            ethBlockHash: toHex(keccak(eth)), headerPBytes: fin.headerP.length, headerBBytes: fin.headerB.length,
            channel: {nextMessageId: Number(channel.nextMessageId), receivedMessageId: Number(channel.receivedMessageId),
                sentRunningHash: toHex(word(channel.sentRunningHash)), receivedRunningHash: toHex(word(channel.receivedRunningHash))}
        },
        channelContext: toHex(channelContext(CHANNEL_ID, svc)),
        channelId: toHex(CHANNEL_ID),
        anchor0: A0,
        anchor1: A1,
        config, manifestProof,
        messages: messages.map(toHex),
        cases,
        rotationSteps: steps,
        rotationColdSteps: coldSteps,
        coldStart: toHex(encodeAnchor(coldBase))
    };
    return out;
}

if (import.meta.url === `file://${process.argv[1]}`) {
    const out = build();
    rmSync(OUT_DIR, {recursive: true, force: true});
    mkdirSync(OUT_DIR, {recursive: true});
    // One small file per case: forge copies a whole JSON document into EVM memory on every parse.
    const {cases, rotationSteps, rotationColdSteps, ...rest} = out;
    writeFileSync(path.join(OUT_DIR, "meta.json"),
        JSON.stringify({...rest, rotationSteps: rotationSteps.length, rotationColdSteps: rotationColdSteps.length}, null, 1));
    rotationColdSteps.forEach((st, i) => writeFileSync(path.join(OUT_DIR, `rotation_cold_step_${i}.json`), JSON.stringify(st)));
    for (const [k, v] of Object.entries(cases)) writeFileSync(path.join(OUT_DIR, `${k}.json`), JSON.stringify(v));
    rotationSteps.forEach((st, i) => writeFileSync(path.join(OUT_DIR, `rotation_step_${i}.json`), JSON.stringify(st)));
    const sizes = Object.fromEntries(Object.entries(cases).map(([k, v]) => [k, (v.proof.length - 2) / 2]));
    console.log("wrote", OUT_DIR, {bundle_ok: sizes.bundle_ok, rotation_start: sizes.rotation_start,
        steps: rotationSteps.map((st) => (st.proof.length - 2) / 2), cold: rotationColdSteps.map((st) => (st.proof.length - 2) / 2)});
}
