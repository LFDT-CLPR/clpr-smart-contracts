/**
 * Minimal Internet Computer client for the ICP → Hiero verifier fixtures: CBOR, principals,
 * hash trees (IC interface spec, "Certification"), anonymous query and read_state calls, and the
 * small Candid decoding needed for `icrc3_get_tip_certificate`.
 *
 * Only public boundary-node endpoints are used. No keys are needed: query and read_state accept
 * unsigned envelopes from the anonymous principal.
 */
import { createHash } from 'node:crypto';

// ── CBOR (RFC 8949), the subset the IC uses ─────────────────────────────────

export type Cbor = number | bigint | string | Uint8Array | Cbor[] | Map<string, Cbor> | { tag: number; value: Cbor };

function head(major: number, n: number | bigint): Uint8Array {
  const v = BigInt(n);
  const m = major << 5;
  if (v < 24n) return Uint8Array.of(m | Number(v));
  if (v < 0x100n) return Uint8Array.of(m | 24, Number(v));
  if (v < 0x10000n) return Uint8Array.of(m | 25, Number(v >> 8n), Number(v & 0xffn));
  if (v < 0x100000000n) {
    const b = new Uint8Array(5);
    b[0] = m | 26;
    new DataView(b.buffer).setUint32(1, Number(v));
    return b;
  }
  const b = new Uint8Array(9);
  b[0] = m | 27;
  new DataView(b.buffer).setBigUint64(1, v);
  return b;
}

export function cborEncode(x: Cbor): Uint8Array {
  if (typeof x === 'number' || typeof x === 'bigint') return head(0, x);
  if (typeof x === 'string') {
    const s = new TextEncoder().encode(x);
    return concat(head(3, s.length), s);
  }
  if (x instanceof Uint8Array) return concat(head(2, x.length), x);
  if (Array.isArray(x)) return concat(head(4, x.length), ...x.map(cborEncode));
  if (x instanceof Map) {
    const parts: Uint8Array[] = [head(5, x.size)];
    for (const [k, v] of x) parts.push(cborEncode(k), cborEncode(v));
    return concat(...parts);
  }
  return concat(head(6, x.tag), cborEncode(x.value));
}

export function cborDecode(buf: Uint8Array): Cbor {
  let p = 0;
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const arg = (info: number): bigint => {
    if (info < 24) return BigInt(info);
    if (info === 24) return BigInt(buf[p++]);
    if (info === 25) { const v = dv.getUint16(p); p += 2; return BigInt(v); }
    if (info === 26) { const v = dv.getUint32(p); p += 4; return BigInt(v); }
    if (info === 27) { const v = dv.getBigUint64(p); p += 8; return v; }
    throw new Error(`cbor: unsupported additional info ${info}`);
  };
  const item = (): Cbor => {
    const ib = buf[p++];
    const major = ib >> 5;
    const info = ib & 31;
    if (major === 7) {
      if (info === 20) return 0; // false
      if (info === 21) return 1; // true
      if (info === 22) return 0; // null
      throw new Error(`cbor: unsupported simple ${info}`);
    }
    if (info === 31) {
      // indefinite length: arrays, maps and chunked strings end with the 0xff break byte
      if (major === 4) { const a: Cbor[] = []; while (buf[p] !== 0xff) a.push(item()); p++; return a; }
      if (major === 5) {
        const m = new Map<string, Cbor>();
        while (buf[p] !== 0xff) { const k = item(); m.set(String(k), item()); }
        p++;
        return m;
      }
      if (major === 2 || major === 3) {
        const chunks: Uint8Array[] = [];
        while (buf[p] !== 0xff) {
          const c = item();
          chunks.push(typeof c === 'string' ? new TextEncoder().encode(c) : (c as Uint8Array));
        }
        p++;
        const all = concat(...chunks);
        return major === 2 ? all : new TextDecoder().decode(all);
      }
      throw new Error(`cbor: unsupported indefinite major ${major}`);
    }
    const n = arg(info);
    switch (major) {
      case 0: return n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : n;
      case 2: { const v = buf.slice(p, p + Number(n)); p += Number(n); return v; }
      case 3: { const v = new TextDecoder().decode(buf.slice(p, p + Number(n))); p += Number(n); return v; }
      case 4: { const a: Cbor[] = []; for (let i = 0; i < Number(n); i++) a.push(item()); return a; }
      case 5: {
        const m = new Map<string, Cbor>();
        for (let i = 0; i < Number(n); i++) { const k = item(); m.set(String(k), item()); }
        return m;
      }
      case 6: return { tag: Number(n), value: item() };
      default: throw new Error(`cbor: unsupported major ${major}`);
    }
  };
  const v = item();
  if (p !== buf.length) throw new Error('cbor: trailing bytes');
  return v;
}

/** Strip the self-describe tag 55799 if present. */
export function untag(x: Cbor): Cbor {
  while (typeof x === 'object' && !(x instanceof Uint8Array) && !Array.isArray(x) && !(x instanceof Map)) {
    x = x.value;
  }
  return x;
}

// ── principals ──────────────────────────────────────────────────────────────

const B32 = 'abcdefghijklmnopqrstuvwxyz234567';

export function principalFromText(text: string): Uint8Array {
  const s = text.replace(/-/g, '');
  let bits = 0;
  let acc = 0;
  const out: number[] = [];
  for (const c of s) {
    acc = (acc << 5) | B32.indexOf(c);
    bits += 5;
    if (bits >= 8) { out.push((acc >> (bits - 8)) & 0xff); bits -= 8; }
  }
  const raw = Uint8Array.from(out);
  return raw.slice(4); // drop the CRC32 checksum
}

// ── hash trees ──────────────────────────────────────────────────────────────

export type HashTree =
  | [0]
  | [1, HashTree, HashTree]
  | [2, Uint8Array, HashTree]
  | [3, Uint8Array]
  | [4, Uint8Array];

const sha256 = (...parts: Uint8Array[]) => new Uint8Array(createHash('sha256').update(concat(...parts)).digest());
const ds = (s: string) => concat(Uint8Array.of(s.length), new TextEncoder().encode(s));

export function reconstruct(t: HashTree): Uint8Array {
  switch (t[0]) {
    case 0: return sha256(ds('ic-hashtree-empty'));
    case 1: return sha256(ds('ic-hashtree-fork'), reconstruct(t[1]), reconstruct(t[2]));
    case 2: return sha256(ds('ic-hashtree-labeled'), t[1], reconstruct(t[2]));
    case 3: return sha256(ds('ic-hashtree-leaf'), t[1]);
    case 4: return t[1];
  }
}

function flatten(t: HashTree): HashTree[] {
  if (t[0] === 0) return [];
  if (t[0] === 1) return [...flatten(t[1]), ...flatten(t[2])];
  return [t];
}

export function lookup(t: HashTree, path: (Uint8Array | string)[]): Uint8Array | undefined {
  if (path.length === 0) return t[0] === 3 ? t[1] : undefined;
  const want = typeof path[0] === 'string' ? new TextEncoder().encode(path[0]) : path[0];
  for (const s of flatten(t)) {
    if (s[0] === 2 && eq(s[1], want)) return lookup(s[2], path.slice(1));
  }
  return undefined;
}

/** All labeled children directly under `path`. */
export function children(t: HashTree, path: (Uint8Array | string)[]): [Uint8Array, HashTree][] {
  let cur: HashTree = t;
  for (const l of path) {
    const want = typeof l === 'string' ? new TextEncoder().encode(l) : l;
    const hit = flatten(cur).find((s) => s[0] === 2 && eq(s[1], want)) as [2, Uint8Array, HashTree] | undefined;
    if (!hit) return [];
    cur = hit[2];
  }
  return flatten(cur).filter((s) => s[0] === 2).map((s) => [s[1] as Uint8Array, (s as [2, Uint8Array, HashTree])[2]]);
}

export function asTree(x: Cbor): HashTree {
  return untag(x) as unknown as HashTree;
}

export type Certificate = {
  tree: HashTree;
  signature: Uint8Array;
  delegation?: { subnetId: Uint8Array; certificate: Uint8Array };
};

export function parseCertificate(bytes: Uint8Array): Certificate {
  const m = untag(cborDecode(bytes)) as Map<string, Cbor>;
  const out: Certificate = { tree: asTree(m.get('tree')!), signature: m.get('signature') as Uint8Array };
  const d = m.get('delegation') as Map<string, Cbor> | undefined;
  if (d) out.delegation = { subnetId: d.get('subnet_id') as Uint8Array, certificate: d.get('certificate') as Uint8Array };
  return out;
}

// ── HTTP: anonymous query and read_state ────────────────────────────────────

export const IC_API = process.env.ICP_API ?? 'https://icp-api.io';
const ANONYMOUS = Uint8Array.of(4);

function expiry(): bigint {
  return BigInt(Date.now() + 120_000) * 1_000_000n;
}

async function post(url: string, body: Uint8Array): Promise<Cbor> {
  const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/cbor' }, body });
  const buf = new Uint8Array(await res.arrayBuffer());
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status} ${new TextDecoder().decode(buf).slice(0, 300)}`);
  return untag(cborDecode(buf));
}

export async function query(canister: string, method: string, arg: Uint8Array): Promise<Uint8Array> {
  const cid = principalFromText(canister);
  const content = new Map<string, Cbor>([
    ['request_type', 'query'],
    ['canister_id', cid],
    ['method_name', method],
    ['arg', arg],
    ['sender', ANONYMOUS],
    ['ingress_expiry', expiry()],
  ]);
  const env = cborEncode({ tag: 55799, value: new Map<string, Cbor>([['content', content]]) });
  const r = (await post(`${IC_API}/api/v2/canister/${canister}/query`, env)) as Map<string, Cbor>;
  if (r.get('status') !== 'replied') throw new Error(`query rejected: ${r.get('reject_message')}`);
  return (r.get('reply') as Map<string, Cbor>).get('arg') as Uint8Array;
}

export async function readState(
  canister: string,
  paths: (Uint8Array | string)[][],
  version: 'v2' | 'v3' = 'v3',
): Promise<Uint8Array> {
  const enc = (l: Uint8Array | string) => (typeof l === 'string' ? new TextEncoder().encode(l) : l);
  const content = new Map<string, Cbor>([
    ['request_type', 'read_state'],
    ['paths', paths.map((p) => p.map(enc))],
    ['sender', ANONYMOUS],
    ['ingress_expiry', expiry()],
  ]);
  const env = cborEncode({ tag: 55799, value: new Map<string, Cbor>([['content', content]]) });
  const r = (await post(`${IC_API}/api/${version}/canister/${canister}/read_state`, env)) as Map<string, Cbor>;
  return r.get('certificate') as Uint8Array;
}

// ── Candid: just enough for `opt record { certificate : blob; hash_tree : blob }` ──

export const CANDID_EMPTY_ARGS = new Uint8Array([0x44, 0x49, 0x44, 0x4c, 0x00, 0x00]);

function leb(buf: Uint8Array, p: { i: number }): bigint {
  let r = 0n;
  let s = 0n;
  for (;;) {
    const b = buf[p.i++];
    r |= BigInt(b & 0x7f) << s;
    s += 7n;
    if ((b & 0x80) === 0) return r;
  }
}

function sleb(buf: Uint8Array, p: { i: number }): bigint {
  let r = 0n;
  let s = 0n;
  let b = 0;
  do {
    b = buf[p.i++];
    r |= BigInt(b & 0x7f) << s;
    s += 7n;
  } while (b & 0x80);
  if (b & 0x40) r -= 1n << s;
  return r;
}

/** Decode the reply of `icrc3_get_tip_certificate`. Returns undefined for `null`. */
export function decodeTipCertificate(arg: Uint8Array): { certificate: Uint8Array; hashTree: Uint8Array } | undefined {
  const p = { i: 4 };
  if (new TextDecoder().decode(arg.slice(0, 4)) !== 'DIDL') throw new Error('candid: bad magic');
  const ntypes = Number(leb(arg, p));
  for (let t = 0; t < ntypes; t++) {
    const op = sleb(arg, p);
    if (op === -18n || op === -19n) sleb(arg, p); // opt / vec: inner type
    else if (op === -20n || op === -21n) {
      // record / variant: n fields of (id, type)
      const n = Number(leb(arg, p));
      for (let f = 0; f < n; f++) { leb(arg, p); sleb(arg, p); }
    } else throw new Error(`candid: unsupported type op ${op}`);
  }
  const nargs = Number(leb(arg, p));
  if (nargs !== 1) throw new Error('candid: expected one value');
  sleb(arg, p); // the arg type index
  if (arg[p.i++] === 0) return undefined;
  // record fields are serialised in field-id order: certificate (hash 0x0e5bf3ce...) and hash_tree.
  // Both are blobs; read the two length-prefixed values and tell them apart by content.
  const read = () => { const n = Number(leb(arg, p)); const v = arg.slice(p.i, p.i + n); p.i += n; return v; };
  const a = read();
  const b = read();
  const isCert = (x: Uint8Array) => {
    const m = untag(cborDecode(x));
    return m instanceof Map && m.has('signature');
  };
  return isCert(a) ? { certificate: a, hashTree: b } : { certificate: b, hashTree: a };
}

// ── bytes ──────────────────────────────────────────────────────────────────

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of parts) { out.set(x, o); o += x.length; }
  return out;
}

export function eq(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

export const hex = (b: Uint8Array) => '0x' + Buffer.from(b).toString('hex');
export const unhex = (s: string) => new Uint8Array(Buffer.from(s.replace(/^0x/, ''), 'hex'));

export function decodeLeb128(b: Uint8Array): bigint {
  return leb(b, { i: 0 });
}
