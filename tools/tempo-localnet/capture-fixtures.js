// Capture TempoVerifier fixtures from the local Tempo network. See README.md.
//
//   node tools/tempo-localnet/capture-fixtures.js <clprService> <channelId> <rotationEpoch>
//
// Writes test/verifiers/tempo/fixtures/localnet.json: a config block under the old key, the
// boundary block that names the new key, and a current block with the channel's eth_getProof.
import { bls12_381 as bls } from '@noble/curves/bls12-381';
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { keccak_256 } from '@noble/hashes/sha3';

const [service, channelId, rotationEpochArg] = process.argv.slice(2);
if (!service || !channelId || !rotationEpochArg) { console.error('usage: capture-fixtures.js <clprService> <channelId> <rotationEpoch>'); process.exit(2); }
const RPC = process.env.TEMPO_RPC ?? 'http://127.0.0.1:18545';
const L = Number(process.env.TEMPO_EPOCH_LENGTH ?? 100);
const rotationEpoch = Number(rotationEpochArg); // first epoch signed by the NEW key
const OUT = resolve(dirname(fileURLToPath(import.meta.url)), '../../test/verifiers/tempo/fixtures/localnet.json');

const hex = s => Uint8Array.from(Buffer.from(s.replace(/^0x/, ''), 'hex'));
const toHex = b => '0x' + Buffer.from(b).toString('hex');
const pad64 = n => n.toString(16).padStart(128, '0');
const g1Unc = P => { const a = P.toAffine(); return '0x' + pad64(a.x) + pad64(a.y); };
const g2Unc = P => { const a = P.toAffine(); return '0x' + pad64(a.x.c0) + pad64(a.x.c1) + pad64(a.y.c0) + pad64(a.y.c1); };
async function rpc(method, params) {
  const r = await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  const j = await r.json(); if (j.error) throw new Error(method + ': ' + JSON.stringify(j.error)); return j.result;
}
// minimal RLP
const encB = b => (b.length === 1 && b[0] < 0x80) ? Buffer.from(b) : Buffer.concat([encL(b.length, 0x80), Buffer.from(b)]);
const encL = (n, off) => { if (n < 56) return Buffer.from([off + n]); const l = []; while (n > 0) { l.unshift(n & 0xff); n = Math.floor(n / 256); } return Buffer.from([off + 55 + l.length, ...l]); };
const encList = items => { const body = Buffer.concat(items); return Buffer.concat([encL(body.length, 0xc0), body]); };
const qty = v => { const n = typeof v === 'number' ? BigInt(v) : BigInt(v); if (n === 0n) return encB(Buffer.alloc(0)); let h = n.toString(16); if (h.length % 2) h = '0' + h; return encB(Buffer.from(h, 'hex')); };
const data = h => encB(Buffer.from(h.slice(2), 'hex'));
function headerRlp(h) {
  const inner = [data(h.parentHash), data(h.sha3Uncles), data(h.miner), data(h.stateRoot), data(h.transactionsRoot), data(h.receiptsRoot), data(h.logsBloom), qty(h.difficulty), qty(h.number), qty(h.gasLimit), qty(h.gasUsed), qty(h.timestamp), data(h.extraData), data(h.mixHash), data(h.nonce)];
  for (const k of ['baseFeePerGas', 'withdrawalsRoot', 'blobGasUsed', 'excessBlobGas', 'parentBeaconBlockRoot', 'requestsHash']) { if (h[k] == null) break; inner.push(['baseFeePerGas', 'blobGasUsed', 'excessBlobGas'].includes(k) ? qty(h[k]) : data(h[k])); }
  const outer = [qty(h.mainBlockGeneralGasLimit), qty(h.sharedGasLimit), qty(h.timestampMillisPart), encList(inner)];
  if (h.consensusContext) { const c = h.consensusContext; outer.push(encList([qty(c.epoch), qty(c.view), qty(c.parentView), data(c.proposer)])); }
  return encList(outer);
}
function varint(b, o) { let v = 0n, s = 0n; for (;;) { const x = b[o++]; v |= BigInt(x & 0x7f) << s; if (x < 0x80) return [v, o]; s += 7n; } }
function outcomeKey(extra) { let [ep, o] = varint(extra, 0); o += 37; let [, o2] = varint(extra, o); return { epoch: Number(ep), key: toHex(extra.slice(o2, o2 + 96)) }; }
async function certified(height) {
  const c = await rpc('consensus_getFinalization', [{ height }]);
  const blk = await rpc('eth_getBlockByNumber', ['0x' + height.toString(16), false]);
  const rlp = headerRlp(blk);
  if (toHex(keccak_256(rlp)) !== blk.hash || c.digest !== blk.hash) throw new Error(`header hash mismatch at ${height}`);
  const b = hex(c.certificate); const p = b.length - 96;
  const sigC = b.slice(p, p + 48);
  return { number: height, epoch: c.epoch, hash: blk.hash, extraData: blk.extraData, headerRlp: toHex(rlp), proposal: toHex(b.slice(0, p)), sigCompressed: toHex(sigC), sigUncompressed: g1Unc(bls.G1.ProjectivePoint.fromHex(sigC)) };
}
const keyBoth = c => ({ keyCompressed: c, keyUncompressed: g2Unc(bls.G2.ProjectivePoint.fromHex(c.slice(2))) });

// channel slots, as ClprEvmBundleVerifier derives them
const abiWord = v => Buffer.from(BigInt(v).toString(16).padStart(64, '0'), 'hex');
const keccakHex = bufs => toHex(keccak_256(Buffer.concat(bufs)));
const cBase = BigInt(keccakHex([Buffer.from(channelId.slice(2), 'hex'), abiWord(15)]));
const slots = [1n, 2n, 4n, 5n, 16n].map(o => '0x' + (cBase + o).toString(16).padStart(64, '0'));

// reth answers eth_getProof only near the head. Take the proof at the head, then wait for its certificate.
async function proofAtHead(keys) {
  for (let attempt = 0; attempt < 30; attempt++) {
    const n = parseInt(await rpc('eth_blockNumber', []), 16);
    try { return { number: n, proof: await rpc('eth_getProof', [service, keys, '0x' + n.toString(16)]) }; }
    catch (e) { if (!String(e).includes('proof window')) throw e; }
  }
  throw new Error('could not fetch eth_getProof at the head block');
}
async function waitForCertificate(height) {
  for (let i = 0; i < 60; i++) { try { await rpc('consensus_getFinalization', [{ height }]); return; } catch { await new Promise(r => setTimeout(r, 1000)); } }
  throw new Error(`no certificate for ${height} after 60s`);
}
const head = parseInt(await rpc('eth_blockNumber', []), 16);
if (Math.floor(head / L) < rotationEpoch) throw new Error(`chain is in epoch ${Math.floor(head / L)}, rotation epoch ${rotationEpoch} not reached`);
const boundaryHeight = rotationEpoch * L - 1;               // last block of the previous epoch: names the new key
const configHeight = boundaryHeight - Math.floor(L / 2);     // well inside the previous epoch: old key
const prevBoundary = (rotationEpoch - 1) * L - 1;            // outcome for the previous epoch: old key
const genesis = await rpc('eth_getBlockByNumber', ['0x0', false]);
const oldKey = prevBoundary >= 0 ? outcomeKey(hex((await rpc('eth_getBlockByNumber', ['0x' + prevBoundary.toString(16), false])).extraData)).key : outcomeKey(hex(genesis.extraData)).key;
const rotationBlock = await certified(boundaryHeight);
const newKey = outcomeKey(hex(rotationBlock.extraData));
if (newKey.epoch !== rotationEpoch) throw new Error(`boundary ${boundaryHeight} names epoch ${newKey.epoch}, expected ${rotationEpoch}`);
if (newKey.key === oldKey) throw new Error('no key change at the requested boundary');

// channel slots, plus the message slot when nextMessageId > 1
const probe = await proofAtHead(slots);
const nextMessageId = (BigInt(probe.proof.storageProof[0].value) >> 168n) & ((1n << 64n) - 1n);
let keys = slots;
if (nextMessageId > 1n) {
  const qBase = keccakHex([Buffer.from(channelId.slice(2), 'hex'), abiWord(1)]);
  const msgBase = BigInt(keccakHex([abiWord(nextMessageId - 1n), Buffer.from(qBase.slice(2), 'hex')]));
  keys = [...slots, '0x' + (msgBase + 1n).toString(16).padStart(64, '0')];
}
const { number: current, proof } = await proofAtHead(keys);
await waitForCertificate(current);
const currentBlock = await certified(current);
const steadyAnchor = await certified(current - 1);
const configBlock = await certified(configHeight);

const out = {
  service, channelId, epochLength: L, rotationEpoch, codeHash: proof.codeHash, storageHash: proof.storageHash, nextMessageId: nextMessageId.toString(),
  oldKey: keyBoth(oldKey), newKey: keyBoth(newKey.key),
  config: configBlock, rotation: rotationBlock, current: currentBlock, steadyAnchor,
  accountProof: proof.accountProof,
  storageProof: proof.storageProof.map(sp => ({ key: sp.key, value: sp.value, proof: sp.proof })),
};
writeFileSync(OUT, JSON.stringify(out, null, 1) + '\n');
console.log(`wrote ${OUT}`);
console.log(`config ${configBlock.number} (epoch ${configBlock.epoch}, old key) | rotation ${rotationBlock.number} -> epoch ${newKey.epoch} new key | current ${current} (epoch ${currentBlock.epoch}) | nextMessageId ${nextMessageId} | ${proof.storageProof.length} slots`);
