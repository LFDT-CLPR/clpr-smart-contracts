/**
 * arc.ts — relay encoding for ArcMalachiteVerifier (src/verifiers/evm/arc).
 *
 * Everything is derived from public RPC JSON:
 *   - `arc_getCertificate(H)` → {height, round, block_hash, signatures[{address, signature(base64)}]}
 *   - `eth_getBlockByNumber(H)` → the RLP header (keccak == block_hash)
 *   - `eth_getProof(ValidatorRegistry, registrySlots, H)` → registry account proof and the storage
 *     multiproof the verifier walks to derive the validator set.
 */

import {encodeAbiParameters, keccak256, toRlp, type Hex} from "viem";
import {ed25519} from "@noble/curves/ed25519";
import {encodeMultiProof, rlpInt, slotKey, type ProofJson} from "./evmHeader.js";

export const ARC_REGISTRY: Hex = "0x3600000000000000000000000000000000000002";
/** ERC-7201 base of ValidatorRegistryStorage ("arc.storage.ValidatorRegistry"). */
export const REGISTRY_STORAGE = 0xb58da0dce03316992faea3e12c60705b8ac05a309e27e3bc8421e5b271c9d200n;
const STATUS_ACTIVE = 2n;

export interface ArcValidator {
    publicKey: Hex; // 32 bytes
    votingPower: bigint;
}

const u256 = (n: bigint): Hex => slotKey(n);
const word = (v: Hex | undefined) => BigInt(v ?? "0x0");

export function arcAddress(publicKey: Hex): Hex {
    return keccak256(publicKey).slice(0, 42) as Hex;
}

/** setHash = keccak256(‖ pubkey(32) ‖ power(8 BE)) over the effective set, in registry order. */
export function arcSetHash(vals: ArcValidator[]): Hex {
    const parts = vals.map((v) => Buffer.concat([Buffer.from(v.publicKey.slice(2), "hex"), Buffer.from(v.votingPower.toString(16).padStart(16, "0"), "hex")]));
    return keccak256(Buffer.concat(parts));
}

/** SSZ(Vote{Precommit, height, Some(round), Some(blockHash), address}) — 75 bytes. */
export function arcPrecommitSignBytes(height: bigint, round: number, blockHash: Hex, address: Hex): Buffer {
    const le = (n: bigint, len: number) => {
        const b = Buffer.alloc(len);
        for (let i = 0; i < len; i++) b[i] = Number((n >> BigInt(8 * i)) & 0xffn);
        return b;
    };
    return Buffer.concat([
        Buffer.from([1]), le(height, 8), le(37n, 4), le(42n, 4), Buffer.from(address.slice(2), "hex"),
        Buffer.from([1]), le(BigInt(round), 4), Buffer.from([1]), Buffer.from(blockHash.slice(2), "hex")
    ]);
}

// ── Registry storage layout ─────────────────────────────────────────────────

export const registryLenSlot = (): bigint => REGISTRY_STORAGE + 1n;
export const registryValuesSlot = (i: bigint): bigint => BigInt(keccak256(u256(registryLenSlot()))) + i;
export const registryStructSlot = (id: bigint): bigint =>
    BigInt(keccak256(encodeAbiParameters([{type: "uint256"}, {type: "uint256"}], [id, REGISTRY_STORAGE])));
export const registryKeySlot = (sb: bigint): bigint => BigInt(keccak256(u256(sb + 1n)));

/**
 * Walk the registry exactly as the verifier's `_deriveSetHash` does, reading words through `read`
 * (getStorageAt, or a proof's values). Returns the slots in lookup order and the effective set.
 */
export async function walkRegistry(read: (slot: bigint) => Promise<bigint>): Promise<{slots: bigint[]; validators: ArcValidator[]}> {
    const slots: bigint[] = [];
    const get = async (s: bigint) => {
        slots.push(s);
        return read(s);
    };
    const n = await get(registryLenSlot());
    const validators: ArcValidator[] = [];
    for (let i = 0n; i < n; i++) {
        const id = await get(registryValuesSlot(i));
        const sb = registryStructSlot(id);
        const status = (await get(sb)) & 0xffn;
        const power = (await get(sb + 2n)) & ((1n << 64n) - 1n);
        const lenWord = await get(sb + 1n);
        if (status !== STATUS_ACTIVE || power === 0n || lenWord !== 65n) continue;
        const pk = await get(registryKeySlot(sb));
        validators.push({publicKey: u256(pk), votingPower: power});
    }
    return {slots, validators};
}

/** Registry multiproof (RLP item for the step) from one eth_getProof over `slots` (lookup order). */
export function registryMultiProof(proof: ProofJson, slots: bigint[]): [Hex[], Hex] {
    const byKey = new Map(proof.storageProof.map((s) => [BigInt(s.key), s.proof]));
    return encodeMultiProof(slots.map((s) => {
        const p = byKey.get(s);
        if (!p) throw new Error(`registry slot ${u256(s)} missing from proof`);
        return p;
    }));
}

/** Re-walk the registry from proof values only (the verifier's view). */
export async function validatorsFromProof(proof: ProofJson): Promise<{slots: bigint[]; validators: ArcValidator[]}> {
    const byKey = new Map(proof.storageProof.map((s) => [BigInt(s.key), word(s.value)]));
    return walkRegistry(async (s) => {
        const v = byKey.get(s);
        if (v === undefined) throw new Error(`slot ${u256(s)} not in proof`);
        return v;
    });
}

// ── Certificate ──────────────────────────────────────────────────────────────

export interface ArcCertificate {
    height: number | string;
    round: number;
    block_hash: Hex;
    signatures: {address: Hex; signature: string}[];
}

export interface SelectedSigs {
    sigs: {index: number; signature: Hex}[];
    signedPower: bigint;
    totalPower: bigint;
    verified: number;
}

/**
 * Verify every certificate signature off-chain, then pick the smallest power-ordered subset that
 * clears 2/3 (sorted back to index order for the verifier). `all` keeps every valid signature.
 */
export function selectSignatures(cert: ArcCertificate, vals: ArcValidator[], all = false): SelectedSigs {
    const idx = new Map(vals.map((v, i) => [arcAddress(v.publicKey).toLowerCase(), i]));
    const totalPower = vals.reduce((a, v) => a + v.votingPower, 0n);
    const valid: {index: number; signature: Hex}[] = [];
    for (const s of cert.signatures) {
        const i = idx.get(s.address.toLowerCase());
        if (i === undefined) throw new Error(`certificate signer ${s.address} not in the set`);
        const sig = Buffer.from(s.signature, "base64");
        const msg = arcPrecommitSignBytes(BigInt(cert.height), cert.round, cert.block_hash, s.address);
        if (!ed25519.verify(sig, msg, Buffer.from(vals[i].publicKey.slice(2), "hex"))) throw new Error(`bad signature from ${s.address}`);
        valid.push({index: i, signature: `0x${sig.toString("hex")}`});
    }
    const ordered = all ? valid : [...valid].sort((a, b) => (vals[b.index].votingPower > vals[a.index].votingPower ? 1 : vals[b.index].votingPower < vals[a.index].votingPower ? -1 : a.index - b.index));
    const chosen: typeof valid = [];
    let signed = 0n;
    for (const s of ordered) {
        if (!all && signed * 3n > totalPower * 2n) break;
        chosen.push(s);
        signed += vals[s.index].votingPower;
    }
    if (signed * 3n <= totalPower * 2n) throw new Error("certificate below 2/3");
    chosen.sort((a, b) => a.index - b.index);
    return {sigs: chosen, signedPower: signed, totalPower, verified: valid.length};
}

// ── Payload encoding ─────────────────────────────────────────────────────────

export interface ArcStep {
    header: Hex;
    parentHeader: Hex;
    round: number;
    sigs: {index: number; signature: Hex}[];
    validators: ArcValidator[];
    /** Registry account proof at stateRoot(H-1): pins the signing set. */
    parentRegistryAccountProof: Hex[];
    /** Optional: registry account proof at stateRoot(H) + storage multiproof → set for H+1. */
    rotation?: {registryAccountProof: Hex[]; registrySetProof: [Hex[], Hex]};
}

export function stepItem(s: ArcStep): any[] {
    return [
        s.header,
        s.parentHeader,
        rlpInt(s.round),
        s.sigs.map((x) => [rlpInt(x.index), x.signature]),
        s.validators.map((v) => [v.publicKey, rlpInt(v.votingPower)]),
        s.parentRegistryAccountProof,
        s.rotation ? [s.rotation.registryAccountProof, s.rotation.registrySetProof] : []
    ];
}

export function encodeArcBundle(p: {
    step: ArcStep;
    hops?: ArcStep[];
    serviceAccountProof: Hex[];
    storageEntries: [Hex, Hex[]][];
    bundleContent: Hex;
    manifest?: {storageEntries: [Hex, Hex[]][]; preimage: Hex};
}): Hex {
    const items: any[] = [stepItem(p.step), (p.hops ?? []).map(stepItem), p.serviceAccountProof, p.storageEntries, p.bundleContent];
    if (p.manifest) items.push(p.manifest.storageEntries, p.manifest.preimage);
    return toRlp(items);
}

export function encodeArcConfig(p: {step: ArcStep; hops?: ArcStep[]; serviceAccountProof: Hex[]; slotEntries: [Hex, Hex[]][]; ledgerConfig: Hex}): Hex {
    return toRlp([stepItem(p.step), (p.hops ?? []).map(stepItem), p.serviceAccountProof, p.slotEntries, p.ledgerConfig]);
}

export function arcAnchor(setHash: Hex, registryRoot: Hex, height: bigint): Hex {
    return `0x${setHash.slice(2)}${registryRoot.slice(2)}${height.toString(16).padStart(16, "0")}`;
}
