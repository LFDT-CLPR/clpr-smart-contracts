/**
 * Records a live Internet Computer mainnet fixture for IcpVerifier:
 *
 *   1. `icrc3_get_tip_certificate` on the ckBTC ledger (a data certificate, delegated from the NNS
 *      root key to the ckBTC ledger's subnet, with the legacy `/subnet/<id>/canister_ranges` scope)
 *      and the ledger's witness tree whose root is the ledger's `certified_data`.
 *   2. `read_state` (v3) of the ckBTC ledger's `module_hash` (delegated, scoped by a
 *      `/canister_ranges/<id>/<start>` shard).
 *   3. `read_state` (v2) of the ICP ledger's `module_hash` on the NNS subnet (no delegation: signed by
 *      the root key itself).
 *
 * Every certificate is checked off-chain with @noble/curves before it is written.
 *
 * Usage: npx tsx test/e2e/relay/buildIcpLiveFixture.ts [--out test/e2e/fixtures/icp-live/mainnet.json]
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import * as icp from './icp.ts';

/** NNS root public key (DER), as pinned by the IC agents (agent-js `IC_ROOT_KEY`). */
export const IC_ROOT_KEY_DER =
  '308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100814c0e6ec71fab583b08bd81373c255c3c371b2e84863c98a4f1e08b74235d14fb5d9c0cd546d9685f913a0c0b2cc5341583bf4b4392e467db96d65b9bb4cb717112f8472e0d5a4d14505ffd7484b01291091c5f87b98883463f98091a0baaae';
const DST = 'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_';
const CKBTC_LEDGER = 'mxzaz-hqaaa-aaaar-qaada-cai';
const ICP_LEDGER = 'ryjl3-tyaaa-aaaaa-aaaba-cai';

const p64 = (x: bigint) => x.toString(16).padStart(128, '0');

export function g1Uncompressed(compressed: Uint8Array): string {
  const a = bls.G1.ProjectivePoint.fromHex(compressed).toAffine();
  return '0x' + p64(a.x) + p64(a.y);
}

export function g2Uncompressed(compressed: Uint8Array): string {
  const a = bls.G2.ProjectivePoint.fromHex(compressed).toAffine();
  return '0x' + p64(a.x.c0) + p64(a.x.c1) + p64(a.y.c0) + p64(a.y.c1);
}

const ds = (s: string) => icp.concat(Uint8Array.of(s.length), new TextEncoder().encode(s));

function checkSig(tree: icp.HashTree, sig: Uint8Array, derKey: Uint8Array): void {
  const msg = icp.concat(ds('ic-state-root'), icp.reconstruct(tree));
  if (!bls.verifyShortSignature(sig, msg, derKey.slice(37), { DST })) throw new Error('BLS check failed');
}

const ROOT = icp.unhex(IC_ROOT_KEY_DER);

/** Solidity `IcpCertificate.Certificate` as JSON (hex strings). */
export type CertJson = {
  tree: string;
  signature: string;
  subnetId: string;
  delegationTree: string;
  delegationSignature: string;
  subnetKey: string;
  rangesShard: string;
};

/** Verify a certificate off-chain and convert it for the verifier. */
export function certToJson(bytes: Uint8Array, canisterId: Uint8Array): { cert: CertJson; time: bigint } {
  const c = icp.parseCertificate(bytes);
  const out: CertJson = {
    tree: icp.hex(icp.cborEncode(c.tree as unknown as icp.Cbor)),
    signature: g1Uncompressed(c.signature),
    subnetId: '0x',
    delegationTree: '0x',
    delegationSignature: '0x',
    subnetKey: '0x',
    rangesShard: '0x',
  };
  if (c.delegation) {
    const d = icp.parseCertificate(c.delegation.certificate);
    if (d.delegation) throw new Error('nested delegation');
    checkSig(d.tree, d.signature, ROOT);
    const sid = c.delegation.subnetId;
    const der = icp.lookup(d.tree, ['subnet', sid, 'public_key'])!;
    checkSig(c.tree, c.signature, der);
    out.subnetId = icp.hex(sid);
    out.delegationTree = icp.hex(icp.cborEncode(d.tree as unknown as icp.Cbor));
    out.delegationSignature = g1Uncompressed(d.signature);
    out.subnetKey = g2Uncompressed(der.slice(37));
    if (!icp.lookup(d.tree, ['subnet', sid, 'canister_ranges'])) {
      // sharded form: pick the shard whose start is the greatest label <= canisterId
      const shards = icp.children(d.tree, ['canister_ranges', sid]).map(([l]) => l);
      const cmp = (a: Uint8Array, b: Uint8Array) => Buffer.compare(Buffer.from(a), Buffer.from(b));
      const le = shards.filter((l) => cmp(l, canisterId) <= 0).sort(cmp);
      if (le.length === 0) throw new Error('no canister_ranges shard for canister');
      out.rangesShard = icp.hex(le[le.length - 1]);
    }
  } else {
    checkSig(c.tree, c.signature, ROOT);
  }
  const time = icp.decodeLeb128(icp.lookup(c.tree, ['time'])!);
  return { cert: out, time };
}

async function main(): Promise<void> {
  const outIdx = process.argv.indexOf('--out');
  const out = outIdx > 0 ? process.argv[outIdx + 1] : 'test/e2e/fixtures/icp-live/mainnet.json';

  // 1. data certificate + witness (ckBTC ledger, ICRC-3)
  const ckbtc = icp.principalFromText(CKBTC_LEDGER);
  const reply = icp.decodeTipCertificate(
    await icp.query(CKBTC_LEDGER, 'icrc3_get_tip_certificate', icp.CANDID_EMPTY_ARGS),
  );
  if (!reply) throw new Error('ledger returned no tip certificate');
  const dataCert = certToJson(reply.certificate, ckbtc);
  const witness = icp.asTree(icp.cborDecode(reply.hashTree));
  const certified = icp.lookup(icp.parseCertificate(reply.certificate).tree, ['canister', ckbtc, 'certified_data'])!;
  if (!icp.eq(certified, icp.reconstruct(witness))) throw new Error('witness root != certified_data');
  const lastBlockHash = icp.lookup(witness, ['last_block_hash'])!;
  const lastBlockIndex = icp.lookup(witness, ['last_block_index'])!;

  // 2. read_state v3, delegated, sharded canister ranges
  const v3Path = ['canister', ckbtc, 'module_hash'];
  const v3 = certToJson(await icp.readState(CKBTC_LEDGER, [v3Path], 'v3'), ckbtc);
  const v3Value = icp.lookup(icp.asTree(icp.cborDecode(icp.unhex(v3.cert.tree))), v3Path)!;

  // 3. read_state v2 on the NNS subnet, signed by the root key
  const icpLedger = icp.principalFromText(ICP_LEDGER);
  const rootPath = ['canister', icpLedger, 'module_hash'];
  const nns = certToJson(await icp.readState(ICP_LEDGER, [rootPath], 'v2'), icpLedger);
  const nnsValue = icp.lookup(icp.asTree(icp.cborDecode(icp.unhex(nns.cert.tree))), rootPath)!;

  const enc = (p: (string | Uint8Array)[]) => p.map((l) => icp.hex(typeof l === 'string' ? new TextEncoder().encode(l) : l));
  const fixture = {
    network: 'icp-mainnet',
    recordedAt: new Date().toISOString(),
    api: icp.IC_API,
    rootKeyDer: '0x' + IC_ROOT_KEY_DER,
    rootKeyUncompressed: g2Uncompressed(ROOT.slice(37)),
    dataCertificate: {
      canister: CKBTC_LEDGER,
      canisterId: icp.hex(ckbtc),
      method: 'icrc3_get_tip_certificate',
      certificate: dataCert.cert,
      certificateBytes: reply.certificate.length,
      time: dataCert.time.toString(),
      witness: icp.hex(icp.cborEncode(witness as unknown as icp.Cbor)),
      path: enc(['last_block_hash']),
      value: icp.hex(lastBlockHash),
      lastBlockIndex: icp.decodeLeb128(lastBlockIndex).toString(),
    },
    readStateDelegatedSharded: {
      canister: CKBTC_LEDGER,
      canisterId: icp.hex(ckbtc),
      endpoint: '/api/v3/canister/<id>/read_state',
      certificate: v3.cert,
      time: v3.time.toString(),
      path: enc(v3Path),
      value: icp.hex(v3Value),
    },
    readStateRootSubnet: {
      canister: ICP_LEDGER,
      canisterId: icp.hex(icpLedger),
      endpoint: '/api/v2/canister/<id>/read_state',
      certificate: nns.cert,
      time: nns.time.toString(),
      path: enc(rootPath),
      value: icp.hex(nnsValue),
    },
  };
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, JSON.stringify(fixture, null, 2) + '\n');
  console.log(`wrote ${out}: ckBTC tip index ${fixture.dataCertificate.lastBlockIndex}, shard ${v3.cert.rangesShard}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
