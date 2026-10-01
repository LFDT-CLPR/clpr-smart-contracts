import {createHash} from "node:crypto";

/// Minimal SSZ (consensus-specs/ssz/simple-serialize.md) over serialized bytes: deserialization
/// boundaries + hash_tree_root + single-field Merkle branches for containers. No value objects —
/// every type hashes straight from its byte span. Just enough to rebuild light-client proofs from a
/// beacon node that serves `debug/beacon/states` and `beacon/blocks` as SSZ but has no light-client
/// API (PulseChain's Lighthouse-Pulse). Correctness is checked at the call sites: every computed
/// root must equal the root the beacon header commits to.

export function sha256(...parts: Buffer[]): Buffer {
    const h = createHash("sha256");
    for (const p of parts) h.update(p);
    return h.digest();
}

const ZERO_HASHES: Buffer[] = [Buffer.alloc(32)];
for (let i = 1; i < 64; i++) ZERO_HASHES.push(sha256(ZERO_HASHES[i - 1], ZERO_HASHES[i - 1]));

function ceilLog2(n: bigint): number {
    let d = 0;
    while (1n << BigInt(d) < n) d++;
    return d;
}

/// merkleize(chunks, limit): binary tree of depth ceil(log2(limit)) with virtual zero padding.
export function merkleize(chunks: Buffer[], limit?: bigint): Buffer {
    const lim = limit ?? BigInt(Math.max(chunks.length, 1));
    if (BigInt(chunks.length) > lim) throw new Error("ssz: more chunks than limit");
    const depth = ceilLog2(lim);
    if (chunks.length === 0) return ZERO_HASHES[depth];
    let layer = chunks;
    for (let d = 0; d < depth; d++) {
        const next: Buffer[] = [];
        for (let i = 0; i < layer.length; i += 2) {
            next.push(sha256(layer[i], i + 1 < layer.length ? layer[i + 1] : ZERO_HASHES[d]));
        }
        layer = next;
    }
    return layer[0];
}

/// Branch (leaf → root siblings) for leaf `index` in a tree over `leaves` padded to a power of two.
export function merkleBranch(leaves: Buffer[], index: number): Buffer[] {
    let width = 1;
    while (width < leaves.length) width <<= 1;
    let layer = [...leaves];
    while (layer.length < width) layer.push(Buffer.alloc(32));
    const out: Buffer[] = [];
    let idx = index;
    while (layer.length > 1) {
        out.push(layer[idx ^ 1]);
        const next: Buffer[] = [];
        for (let i = 0; i < layer.length; i += 2) next.push(sha256(layer[i], layer[i + 1]));
        layer = next;
        idx >>= 1;
    }
    return out;
}

function mixInLength(root: Buffer, len: number | bigint): Buffer {
    const b = Buffer.alloc(32);
    b.writeBigUInt64LE(BigInt(len), 0);
    return sha256(root, b);
}

function pack(bytes: Buffer): Buffer[] {
    const chunks: Buffer[] = [];
    for (let i = 0; i < bytes.length; i += 32) {
        const c = Buffer.alloc(32);
        bytes.copy(c, 0, i, Math.min(i + 32, bytes.length));
        chunks.push(c);
    }
    return chunks;
}

export interface SszType {
    /// Serialized size if fixed, else null.
    fixed: number | null;
    root(b: Buffer): Buffer;
}

export const uint = (n: number): SszType & {basic: true} => ({
    fixed: n,
    basic: true,
    root: (b) => {
        if (b.length !== n) throw new Error(`ssz: uint${n * 8} length ${b.length}`);
        const c = Buffer.alloc(32);
        b.copy(c);
        return c;
    }
});
export const uint8 = uint(1);
export const uint64 = uint(8);
export const uint256 = uint(32);
export const boolean = uint8;

export const bytesN = (n: number): SszType => ({
    fixed: n,
    root: (b) => {
        if (b.length !== n) throw new Error(`ssz: Bytes${n} length ${b.length}`);
        return merkleize(pack(b), BigInt(Math.ceil(n / 32)));
    }
});
export const bytes32 = bytesN(32);

export const byteList = (max: number): SszType => ({
    fixed: null,
    root: (b) => {
        if (b.length > max) throw new Error("ssz: ByteList over limit");
        return mixInLength(merkleize(pack(b), BigInt(Math.ceil(max / 32))), b.length);
    }
});

export const bitvector = (n: number): SszType => ({
    fixed: Math.ceil(n / 8),
    root: (b) => merkleize(pack(b), BigInt(Math.ceil(n / 256)))
});

export const bitlist = (max: number): SszType => ({
    fixed: null,
    root: (b) => {
        if (b.length === 0) throw new Error("ssz: empty Bitlist");
        const last = b[b.length - 1];
        if (last === 0) throw new Error("ssz: Bitlist without delimiter");
        const msb = 31 - Math.clz32(last);
        const bitLen = (b.length - 1) * 8 + msb;
        if (bitLen > max) throw new Error("ssz: Bitlist over limit");
        const data = Buffer.from(b);
        data[data.length - 1] = last ^ (1 << msb);
        const trimmed = data.subarray(0, Math.ceil(bitLen / 8));
        return mixInLength(merkleize(pack(trimmed), BigInt(Math.ceil(max / 256))), bitLen);
    }
});

function isBasic(t: SszType): boolean {
    return (t as {basic?: boolean}).basic === true;
}

/// Split a sequence of `count` (or offset-derived) elements of type `elem`.
function splitElements(elem: SszType, b: Buffer): Buffer[] {
    if (elem.fixed !== null) {
        if (b.length % elem.fixed !== 0) throw new Error("ssz: ragged fixed-size sequence");
        const out: Buffer[] = [];
        for (let i = 0; i < b.length; i += elem.fixed) out.push(b.subarray(i, i + elem.fixed));
        return out;
    }
    if (b.length === 0) return [];
    const first = b.readUInt32LE(0);
    if (first % 4 !== 0 || first > b.length) throw new Error("ssz: bad first offset");
    const n = first / 4;
    const offs: number[] = [];
    for (let i = 0; i < n; i++) offs.push(b.readUInt32LE(i * 4));
    offs.push(b.length);
    const out: Buffer[] = [];
    for (let i = 0; i < n; i++) {
        if (offs[i + 1] < offs[i]) throw new Error("ssz: decreasing offsets");
        out.push(b.subarray(offs[i], offs[i + 1]));
    }
    return out;
}

export const vector = (elem: SszType, n: number): SszType => ({
    fixed: elem.fixed === null ? null : elem.fixed * n,
    root: (b) => {
        const els = splitElements(elem, b);
        if (els.length !== n) throw new Error(`ssz: Vector length ${els.length} != ${n}`);
        if (isBasic(elem)) return merkleize(pack(b), BigInt(Math.ceil((n * elem.fixed!) / 32)));
        return merkleize(els.map((e) => elem.root(e)), BigInt(n));
    }
});

export const list = (elem: SszType, max: bigint | number): SszType => ({
    fixed: null,
    root: (b) => {
        const els = splitElements(elem, b);
        if (BigInt(els.length) > BigInt(max)) throw new Error("ssz: List over limit");
        if (isBasic(elem)) {
            const limit = (BigInt(max) * BigInt(elem.fixed!) + 31n) / 32n;
            return mixInLength(merkleize(pack(b), limit), els.length);
        }
        return mixInLength(merkleize(els.map((e) => elem.root(e)), BigInt(max)), els.length);
    }
});

export interface ContainerType extends SszType {
    names: string[];
    fields: SszType[];
    /// Byte spans of each field in a serialized value.
    split(b: Buffer): Buffer[];
    fieldRoots(b: Buffer): Buffer[];
}

export const container = (spec: [string, SszType][]): ContainerType => {
    const names = spec.map(([n]) => n);
    const fields = spec.map(([, t]) => t);
    const allFixed = fields.every((f) => f.fixed !== null);
    const fixedPart = fields.reduce((a, f) => a + (f.fixed ?? 4), 0);
    const split = (b: Buffer): Buffer[] => {
        const spans: (Buffer | number)[] = [];
        let pos = 0;
        for (const f of fields) {
            if (f.fixed !== null) {
                spans.push(b.subarray(pos, pos + f.fixed));
                pos += f.fixed;
            } else {
                spans.push(b.readUInt32LE(pos));
                pos += 4;
            }
        }
        const varIdx = spans.map((s, i) => (typeof s === "number" ? i : -1)).filter((i) => i >= 0);
        if (varIdx.length && spans[varIdx[0]] !== fixedPart) throw new Error("ssz: first offset != fixed part");
        if (!varIdx.length && b.length !== fixedPart) throw new Error("ssz: container length mismatch");
        varIdx.forEach((fi, k) => {
            const start = spans[fi] as number;
            const end = k + 1 < varIdx.length ? (spans[varIdx[k + 1]] as number) : b.length;
            if (end < start || end > b.length) throw new Error("ssz: bad container offsets");
            spans[fi] = b.subarray(start, end);
        });
        return spans as Buffer[];
    };
    const fieldRoots = (b: Buffer) => split(b).map((s, i) => fields[i].root(s));
    return {
        fixed: allFixed ? fixedPart : null,
        names,
        fields,
        split,
        fieldRoots,
        root: (b) => merkleize(fieldRoots(b))
    };
};

/// Field index + Merkle branch for `name` in container `t` serialized as `b`.
export function containerFieldProof(t: ContainerType, b: Buffer, name: string): {
    index: number;
    leaf: Buffer;
    branch: Buffer[];
    root: Buffer;
    gindex: bigint;
} {
    const index = t.names.indexOf(name);
    if (index < 0) throw new Error(`ssz: no field ${name}`);
    const roots = t.fieldRoots(b);
    const branch = merkleBranch(roots, index);
    return {index, leaf: roots[index], branch, root: merkleize(roots), gindex: (1n << BigInt(branch.length)) + BigInt(index)};
}

// ── Capella consensus types, parameterized by the chain preset (`/eth/v1/config/spec`) ──────
export function capellaTypes(spec: Record<string, string>) {
    const n = (k: string) => {
        const v = spec[k];
        if (v === undefined || v === null) throw new Error(`spec missing ${k}`);
        return Number(v);
    };
    const big = (k: string) => BigInt(spec[k]);
    const checkpoint = container([["epoch", uint64], ["root", bytes32]]);
    const beaconBlockHeader = container([
        ["slot", uint64], ["proposer_index", uint64], ["parent_root", bytes32], ["state_root", bytes32],
        ["body_root", bytes32]
    ]);
    const signedHeader = container([["message", beaconBlockHeader], ["signature", bytesN(96)]]);
    const eth1Data = container([["deposit_root", bytes32], ["deposit_count", uint64], ["block_hash", bytes32]]);
    const attestationData = container([
        ["slot", uint64], ["index", uint64], ["beacon_block_root", bytes32], ["source", checkpoint],
        ["target", checkpoint]
    ]);
    const indexedAttestation = container([
        ["attesting_indices", list(uint64, n("MAX_VALIDATORS_PER_COMMITTEE"))], ["data", attestationData],
        ["signature", bytesN(96)]
    ]);
    const attestation = container([
        ["aggregation_bits", bitlist(n("MAX_VALIDATORS_PER_COMMITTEE"))], ["data", attestationData],
        ["signature", bytesN(96)]
    ]);
    const depositData = container([
        ["pubkey", bytesN(48)], ["withdrawal_credentials", bytes32], ["amount", uint64], ["signature", bytesN(96)]
    ]);
    const deposit = container([["proof", vector(bytes32, 33)], ["data", depositData]]);
    const signedVoluntaryExit = container([
        ["message", container([["epoch", uint64], ["validator_index", uint64]])], ["signature", bytesN(96)]
    ]);
    const syncAggregate = container([
        ["sync_committee_bits", bitvector(n("SYNC_COMMITTEE_SIZE"))], ["sync_committee_signature", bytesN(96)]
    ]);
    const withdrawal = container([
        ["index", uint64], ["validator_index", uint64], ["address", bytesN(20)], ["amount", uint64]
    ]);
    const payloadCommon: [string, SszType][] = [
        ["parent_hash", bytes32], ["fee_recipient", bytesN(20)], ["state_root", bytes32], ["receipts_root", bytes32],
        ["logs_bloom", bytesN(n("BYTES_PER_LOGS_BLOOM"))], ["prev_randao", bytes32], ["block_number", uint64],
        ["gas_limit", uint64], ["gas_used", uint64], ["timestamp", uint64],
        ["extra_data", byteList(n("MAX_EXTRA_DATA_BYTES"))], ["base_fee_per_gas", uint256], ["block_hash", bytes32]
    ];
    const executionPayload = container([
        ...payloadCommon,
        ["transactions", list(byteList(n("MAX_BYTES_PER_TRANSACTION")), n("MAX_TRANSACTIONS_PER_PAYLOAD"))],
        ["withdrawals", list(withdrawal, n("MAX_WITHDRAWALS_PER_PAYLOAD"))]
    ]);
    const executionPayloadHeader = container([
        ...payloadCommon, ["transactions_root", bytes32], ["withdrawals_root", bytes32]
    ]);
    const signedBlsChange = container([
        ["message", container([
            ["validator_index", uint64], ["from_bls_pubkey", bytesN(48)], ["to_execution_address", bytesN(20)]
        ])],
        ["signature", bytesN(96)]
    ]);
    const beaconBlockBody = container([
        ["randao_reveal", bytesN(96)], ["eth1_data", eth1Data], ["graffiti", bytes32],
        ["proposer_slashings", list(container([["signed_header_1", signedHeader], ["signed_header_2", signedHeader]]), n("MAX_PROPOSER_SLASHINGS"))],
        ["attester_slashings", list(container([["attestation_1", indexedAttestation], ["attestation_2", indexedAttestation]]), n("MAX_ATTESTER_SLASHINGS"))],
        ["attestations", list(attestation, n("MAX_ATTESTATIONS"))],
        ["deposits", list(deposit, n("MAX_DEPOSITS"))],
        ["voluntary_exits", list(signedVoluntaryExit, n("MAX_VOLUNTARY_EXITS"))],
        ["sync_aggregate", syncAggregate],
        ["execution_payload", executionPayload],
        ["bls_to_execution_changes", list(signedBlsChange, n("MAX_BLS_TO_EXECUTION_CHANGES"))]
    ]);
    const beaconBlock = container([
        ["slot", uint64], ["proposer_index", uint64], ["parent_root", bytes32], ["state_root", bytes32],
        ["body", beaconBlockBody]
    ]);
    const signedBeaconBlock = container([["message", beaconBlock], ["signature", bytesN(96)]]);
    const syncCommittee = container([
        ["pubkeys", vector(bytesN(48), n("SYNC_COMMITTEE_SIZE"))], ["aggregate_pubkey", bytesN(48)]
    ]);
    const validator = container([
        ["pubkey", bytesN(48)], ["withdrawal_credentials", bytes32], ["effective_balance", uint64], ["slashed", boolean],
        ["activation_eligibility_epoch", uint64], ["activation_epoch", uint64], ["exit_epoch", uint64],
        ["withdrawable_epoch", uint64]
    ]);
    const vrl = big("VALIDATOR_REGISTRY_LIMIT");
    const beaconState = container([
        ["genesis_time", uint64], ["genesis_validators_root", bytes32], ["slot", uint64],
        ["fork", container([["previous_version", bytesN(4)], ["current_version", bytesN(4)], ["epoch", uint64]])],
        ["latest_block_header", beaconBlockHeader],
        ["block_roots", vector(bytes32, n("SLOTS_PER_HISTORICAL_ROOT"))],
        ["state_roots", vector(bytes32, n("SLOTS_PER_HISTORICAL_ROOT"))],
        ["historical_roots", list(bytes32, big("HISTORICAL_ROOTS_LIMIT"))],
        ["eth1_data", eth1Data],
        ["eth1_data_votes", list(eth1Data, n("EPOCHS_PER_ETH1_VOTING_PERIOD") * n("SLOTS_PER_EPOCH"))],
        ["eth1_deposit_index", uint64],
        ["validators", list(validator, vrl)],
        ["balances", list(uint64, vrl)],
        ["randao_mixes", vector(bytes32, n("EPOCHS_PER_HISTORICAL_VECTOR"))],
        ["slashings", vector(uint64, n("EPOCHS_PER_SLASHINGS_VECTOR"))],
        ["previous_epoch_participation", list(uint8, vrl)],
        ["current_epoch_participation", list(uint8, vrl)],
        ["justification_bits", bitvector(4)],
        ["previous_justified_checkpoint", checkpoint],
        ["current_justified_checkpoint", checkpoint],
        ["finalized_checkpoint", checkpoint],
        ["inactivity_scores", list(uint64, vrl)],
        ["current_sync_committee", syncCommittee],
        ["next_sync_committee", syncCommittee],
        ["latest_execution_payload_header", executionPayloadHeader],
        ["next_withdrawal_index", uint64],
        ["next_withdrawal_validator_index", uint64],
        ["historical_summaries", list(container([["block_summary_root", bytes32], ["state_summary_root", bytes32]]), big("HISTORICAL_ROOTS_LIMIT"))]
    ]);
    return {
        beaconBlockHeader, beaconBlockBody, beaconBlock, signedBeaconBlock, executionPayload,
        executionPayloadHeader, syncCommittee, syncAggregate, beaconState
    };
}
