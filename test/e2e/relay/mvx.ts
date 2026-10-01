/**
 * MultiversX BLS off-chain: herumi `bls-go-binary` v1.37.0 without BLS_ETH, as mx-chain-crypto-go uses
 * it. Everything here mirrors mcl's source (MCL_MAP_TO_MODE_ORIGINAL, `MapTo::calcBN`,
 * `Fp::setHashOf`, mcl compressed serialization) and is checked against live mainnet signatures by
 * buildMvxLiveFixture.ts before a fixture is written.
 */
import { createHash } from 'node:crypto';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';

const Fp2 = bls.fields.Fp2;
export const P = bls.fields.Fp.ORDER;
const mod = (a: bigint) => ((a % P) + P) % P;
const pow = (a: bigint, e: bigint) => {
  let r = 1n;
  a = mod(a);
  while (e > 0n) {
    if (e & 1n) r = (r * a) % P;
    a = (a * a) % P;
    e >>= 1n;
  }
  return r;
};
const sqrt = (a: bigint): bigint | undefined => {
  const r = pow(a, (P + 1n) / 4n);
  return mod(r * r) === mod(a) ? r : undefined;
};
const le = (b: Uint8Array) => BigInt('0x' + (Buffer.from(b).reverse().toString('hex') || '0'));

/** mcl MapTo::initBLS12 constants for BLS12_381. */
const C1 = BigInt('0xbe32ce5fbeed9ca374d38c0ed41eefd5bb675277cdf12d11bc2fb026c41400045c03fffffffdfffd');
const C2 = BigInt('0x5f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe');
const COFACTOR = BigInt('0x396c8c005555e1568c00aaab0000aaab');

/** mcl Fp::setHashOf (SHA-512 for a 384-bit field). */
export function hashToField(msg: Uint8Array): bigint {
  const h = createHash('sha512').update(msg).digest().subarray(0, 48);
  let t = le(h) & ((1n << 381n) - 1n);
  if (t >= P) t &= (1n << 380n) - 1n;
  return t;
}

/** mcl MapTo::calcBN on G1 then G1 cofactor (original mode). */
export function hashToG1(msg: Uint8Array) {
  const t = hashToField(msg);
  if (t === 0n) throw new Error('t = 0');
  const negative = sqrt(t) === undefined;
  let w = pow(mod(t * t + 5n), P - 2n);
  w = mod(mod(w * C1) * t);
  let x = 0n;
  for (let i = 0; i < 3; i++) {
    if (i === 0) x = mod(C2 - t * w);
    if (i === 1) x = mod(-x - 1n);
    if (i === 2) x = mod(pow(mod(w * w), P - 2n) + 1n);
    let y = sqrt(mod(x * x * x + 4n));
    if (y !== undefined) {
      if (negative) y = mod(-y);
      return bls.G1.ProjectivePoint.fromAffine({ x, y }).multiplyUnsafe(COFACTOR);
    }
  }
  throw new Error('map failed');
}

/** herumi's G2 generator in this mode: mapToG2(1) with the original map, cofactor cleared. */
export function generatorQ() {
  const B2 = Fp2.fromBigTuple([4n, 4n]);
  const t = Fp2.fromBigTuple([1n, 0n]);
  let w = Fp2.add(Fp2.add(Fp2.sqr(t), B2), Fp2.ONE);
  w = Fp2.mul(Fp2.mul(Fp2.inv(w), C1), t);
  let x = Fp2.ZERO;
  for (let i = 0; i < 3; i++) {
    if (i === 0) x = Fp2.add(Fp2.neg(Fp2.mul(t, w)), Fp2.fromBigTuple([C2, 0n]));
    if (i === 1) x = Fp2.sub(Fp2.neg(x), Fp2.ONE);
    if (i === 2) x = Fp2.add(Fp2.inv(Fp2.sqr(w)), Fp2.ONE);
    const y2 = Fp2.add(Fp2.mul(Fp2.sqr(x), x), B2);
    let y;
    try {
      y = Fp2.sqrt(y2);
    } catch {
      y = undefined;
    }
    if (y && Fp2.eql(Fp2.sqr(y), y2)) return bls.G2.ProjectivePoint.fromAffine({ x, y }).clearCofactor();
  }
  throw new Error('no generator');
}

/** mcl compressed G1 (48 bytes): x little-endian, top bit of the last byte = y is odd. */
export function g1FromMcl(b: Uint8Array) {
  const flag = (b[47] & 0x80) !== 0;
  const xb = Uint8Array.from(b);
  xb[47] &= 0x7f;
  const x = le(xb);
  let y = sqrt(mod(x * x * x + 4n));
  if (y === undefined) throw new Error('G1 x not on curve');
  if (((y & 1n) === 1n) !== flag) y = mod(-y);
  const p = bls.G1.ProjectivePoint.fromAffine({ x, y });
  p.assertValidity();
  return p;
}

/** mcl compressed G2 (96 bytes): x = (a, b) little-endian, top bit of the last byte = y.a is odd. */
export function g2FromMcl(b: Uint8Array) {
  const flag = (b[95] & 0x80) !== 0;
  const xb = Uint8Array.from(b);
  xb[95] &= 0x7f;
  const x = Fp2.fromBigTuple([le(xb.subarray(0, 48)), le(xb.subarray(48, 96))]);
  let y = Fp2.sqrt(Fp2.add(Fp2.mul(Fp2.sqr(x), x), Fp2.fromBigTuple([4n, 4n])));
  if (((y.c0 & 1n) === 1n) !== flag) y = Fp2.neg(y);
  const p = bls.G2.ProjectivePoint.fromAffine({ x, y });
  p.assertValidity();
  return p;
}

const p64 = (x: bigint) => x.toString(16).padStart(128, '0');
type G1 = ReturnType<typeof g1FromMcl>;
type G2 = ReturnType<typeof g2FromMcl>;
export const encG1 = (p: G1) => {
  const a = p.toAffine();
  return '0x' + p64(a.x) + p64(a.y);
};
export const encG2 = (p: G2) => {
  const a = p.toAffine();
  return '0x' + p64(a.x.c0) + p64(a.x.c1) + p64(a.y.c0) + p64(a.y.c1);
};

/** e(sig, Q) == e(H(m), pk) */
export function verify(sig: G1, msg: Uint8Array, pk: G2): boolean {
  return bls.fields.Fp12.eql(bls.pairing(sig, generatorQ()), bls.pairing(hashToG1(msg), pk));
}
