/**
 * Records a live MultiversX mainnet fixture for MvxMetachainVerifier / MvxBls:
 *
 *   - the latest metachain block: raw protobuf header (gateway `/internal/4294967295/raw/block/by-nonce`),
 *     its equivalent proof (aggregated signature + signer bitmap) and the ordered eligible list the
 *     public API reports for it (`/blocks/<hash>` → `validators`)
 *   - the same block's leader signature over the previous random seed (`randSeed`), a single signature
 *   - the latest shard-0 block's proof, signed by the shard's eligible list
 *
 * Keys and signatures arrive in mcl's compressed format and are written uncompressed (EIP-2537);
 * every signature is checked off-chain first.
 *
 * Usage: npx tsx test/e2e/relay/buildMvxLiveFixture.ts [--out test/e2e/fixtures/mvx-live/mainnet.json]
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { keccak256, type Hex } from 'viem';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { blake2b } from '@noble/hashes/blake2.js';
import * as mvx from './mvx.ts';

const API = process.env.MVX_API ?? 'https://api.multiversx.com';
const GATEWAY = process.env.MVX_GATEWAY ?? 'https://gateway.multiversx.com';
const META = 4294967295;

async function get(url: string): Promise<any> {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return r.json();
}

const hexb = (s: string) => Buffer.from(s, 'hex');
const b64 = (s: string) => Buffer.from(s, 'base64');

async function blockCase(shard: number) {
  const [latest] = await get(`${API}/blocks?size=1&shard=${shard}`);
  const d = await get(`${API}/blocks/${latest.hash}`);
  const raw = b64((await get(`${GATEWAY}/internal/${shard}/raw/block/by-nonce/${d.nonce}`)).data.block);
  const json = (await get(`${GATEWAY}/internal/${shard}/json/block/by-nonce/${d.nonce}`)).data.block;
  if (Buffer.from(blake2b(raw, { dkLen: 32 })).toString('hex') !== d.hash) throw new Error('blake2b(raw) != hash');
  if (d.proof.headerHash !== d.hash) throw new Error('proof is for another header');

  const keys = (d.validators as string[]).map((k) => mvx.g2FromMcl(hexb(k)));
  const bitmap = hexb(d.proof.pubKeysBitmap);
  let agg = bls.G2.ProjectivePoint.ZERO;
  let signers = 0;
  keys.forEach((k, i) => {
    if (bitmap[i >> 3] & (1 << (i & 7))) {
      agg = agg.add(k);
      signers++;
    }
  });
  const sig = mvx.g1FromMcl(hexb(d.proof.aggregatedSignature));
  if (!mvx.verify(sig, hexb(d.hash), agg)) throw new Error(`shard ${shard}: aggregated signature does not verify`);

  const leaderKey = mvx.g2FromMcl(hexb(d.proposer));
  const randSeed = mvx.g1FromMcl(b64(json.randSeed));
  if (!mvx.verify(randSeed, b64(json.prevRandSeed), leaderKey)) throw new Error('rand seed does not verify');

  const keysEnc = keys.map(mvx.encG2) as Hex[];
  const keysConcat = ('0x' + keysEnc.map((k) => k.slice(2)).join('')) as Hex;
  return {
    shard,
    epoch: d.epoch,
    nonce: d.nonce,
    round: d.round,
    headerHash: '0x' + d.hash,
    rawHeader: '0x' + raw.toString('hex'),
    bitmap: '0x' + d.proof.pubKeysBitmap,
    signers,
    eligible: keys.length,
    signature: mvx.encG1(sig),
    signatureMcl: '0x' + d.proof.aggregatedSignature,
    keys: keysEnc,
    keysHash: keccak256(keysConcat),
    keysMcl: (d.validators as string[]).map((k) => '0x' + k),
    leader: {
      key: mvx.encG2(leaderKey),
      keyMcl: '0x' + d.proposer,
      message: '0x' + b64(json.prevRandSeed).toString('hex'),
      signature: mvx.encG1(randSeed),
    },
  };
}

async function main(): Promise<void> {
  const outIdx = process.argv.indexOf('--out');
  const out = outIdx > 0 ? process.argv[outIdx + 1] : 'test/e2e/fixtures/mvx-live/mainnet.json';
  const config = (await get(`${GATEWAY}/network/config`)).data.config;
  const fixture = {
    network: 'mvx-mainnet',
    chainId: `mvx:${config.erd_chain_id}`,
    recordedAt: new Date().toISOString(),
    api: API,
    gateway: GATEWAY,
    metaConsensusGroupSize: config.erd_meta_consensus_group_size,
    shardConsensusGroupSize: config.erd_shard_consensus_group_size,
    meta: await blockCase(META),
    shard0: await blockCase(0),
  };
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, JSON.stringify(fixture, null, 2) + '\n');
  console.log(
    `wrote ${out}: meta nonce ${fixture.meta.nonce} (${fixture.meta.signers}/${fixture.meta.eligible}), ` +
      `shard 0 nonce ${fixture.shard0.nonce} (${fixture.shard0.signers}/${fixture.shard0.eligible})`,
  );
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
