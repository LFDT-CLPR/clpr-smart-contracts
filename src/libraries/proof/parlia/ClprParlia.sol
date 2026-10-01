// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprBeaconBls} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconBls.sol";
import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title ClprParlia
/// @notice Parlia (BNB Smart Chain) light-client primitives: header decoding and hashing, the
///         chain-id-bound ECDSA seal, epoch-block validator parsing and BEP-126 fast-finality vote
///         attestations (BLS12-381, EIP-2537).
///
/// Every rule mirrors bnb-chain/bsc `consensus/parlia` (checked against commit c5533ab, Aug 2026):
///   - Header seal: `types.SealHash(header, chainId)` = keccak256(RLP([chainId, parentHash … time,
///     extra[:len-65], mixDigest, nonce] ++ (if parentBeaconRoot present: baseFee, withdrawalsHash,
///     blobGasUsed, excessBlobGas, parentBeaconRoot) ++ (if requestsHash present: requestsHash))).
///     Fields after requestsHash (balHash, slotNumber) are NOT sealed. Signature = extra[len-65:],
///     `r ‖ s ‖ v` with v ∈ {0, 1}.
///   - Epoch extra (post-Bohr): `vanity32 ‖ n(1) ‖ n × (address20 ‖ blsPubkey48) ‖ turnLength(1) ‖
///     [voteAttestation] ‖ seal65`, validators sorted ascending by address (`prepareValidators`).
///   - Vote attestation (`verifyVoteAttestation`): the bitset indexes the validator set sorted
///     ascending; quorum is `popcount ≥ ceil(2n/3)`; signature is a FastAggregateVerify of
///     `keccak256(RLP([srcNum, srcHash, tgtNum, tgtHash]))` under DST
///     `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` (prysm v5.3.2 / blst, the same ciphersuite as
///     the Ethereum beacon chain — so {ClprBeaconBls} is reused verbatim).
///   - Finality (`Snapshot.updateAttestation` + `GetFinalizedHeader`): an attestation whose target
///     is the direct child of its source finalizes the source.
library ClprParlia {
    // ── extraData layout ─────────────────────────────────────────────────────
    uint256 internal constant EXTRA_VANITY = 32;
    uint256 internal constant EXTRA_SEAL = 65;
    uint256 internal constant VALIDATOR_NUMBER_SIZE = 1;
    uint256 internal constant TURN_LENGTH_SIZE = 1;
    uint256 internal constant ADDRESS_LENGTH = 20;
    uint256 internal constant BLS_PUBKEY_COMPRESSED_LENGTH = 48;
    /// @dev `address20 ‖ blsPubkey48` per validator in an epoch block's extraData.
    uint256 internal constant VALIDATOR_BYTES_LENGTH = ADDRESS_LENGTH + BLS_PUBKEY_COMPRESSED_LENGTH;
    /// @dev `types.ValidatorsBitSet` is a uint64, so a vote attestation can address at most 64 validators.
    uint256 internal constant MAX_VALIDATORS = 64;

    // ── EIP-2537 encodings ────────────────────────────────────────────────────
    uint256 internal constant BLS_PUBKEY_LENGTH = 128; // uncompressed G1
    uint256 internal constant BLS_SIGNATURE_LENGTH = 256; // uncompressed G2
    /// @dev `address20 ‖ uncompressedKey128`, the unit of the anchor's `keysHash` commitment.
    uint256 internal constant ENTRY_LENGTH = ADDRESS_LENGTH + BLS_PUBKEY_LENGTH;

    // ── Header field indices (core/types.Header RLP order) ───────────────────
    uint256 internal constant MIN_HEADER_FIELDS = 15;
    uint256 internal constant MAX_HEADER_FIELDS = 23; // … requestsHash(20), balHash(21), slotNumber(22)
    uint256 internal constant IDX_PARENT_HASH = 0;
    uint256 internal constant IDX_STATE_ROOT = 3;
    uint256 internal constant IDX_NUMBER = 8;
    uint256 internal constant IDX_TIME = 11;
    uint256 internal constant IDX_EXTRA = 12;
    uint256 internal constant IDX_MIX_DIGEST = 13;
    uint256 internal constant IDX_NONCE = 14;
    uint256 internal constant IDX_BASE_FEE = 15;
    uint256 internal constant IDX_PARENT_BEACON_ROOT = 19;
    uint256 internal constant IDX_REQUESTS_HASH = 20;

    // ── Attestation RLP: [voteAddressSet, signature256, srcNum, srcHash, tgtNum, tgtHash] ─────────
    uint256 internal constant ATTESTATION_FIELDS = 6;

    address internal constant BLS12_G1ADD = address(0x0b);

    error InvalidHeader();
    error InvalidExtraData();
    error InvalidEpochValidators();
    error ValidatorsNotSorted();
    error InvalidTurnLength();
    error InvalidAttestation();
    error AttestationNotFinalizing();
    error AttestationSourceMismatch();
    error HeaderChainBroken(uint256 index);
    error InsufficientVotes(uint256 votes, uint256 validators);
    error VoteBitOutOfRange();
    error SealRecoverFailed();
    error UnauthorizedSealer(address signer);
    error InvalidValidatorKey(uint256 index);
    error BlsPrecompileCallFailed();

    struct Header {
        bytes32 hash;
        bytes32 parentHash;
        bytes32 stateRoot;
        uint64 number;
        bytes extra;
        Memory.Slice[] fields;
    }

    struct Attestation {
        uint64 voteAddressSet;
        bytes signature;
        uint64 sourceNumber;
        bytes32 sourceHash;
        uint64 targetNumber;
        bytes32 targetHash;
    }

    /// @dev Validator set in the order the attestation bitset indexes it (ascending address).
    struct ValidatorSet {
        address[] addrs;
        bytes keys; // n × 128-byte EIP-2537 uncompressed G1 public keys, concatenated
    }

    /// @dev Parsed epoch-block validator section.
    struct EpochInfo {
        address[] addrs;
        bytes32 validatorsHash; // keccak256 of the raw `n × (address20 ‖ blsPubkey48)` section
        uint256 validatorsOffset; // offset of that section inside `extra`
        uint8 turnLength;
    }

    // ── Headers ───────────────────────────────────────────────────────────────

    /// @dev Decode a raw RLP header. `hash` is keccak256 of the exact encoded bytes (the block hash).
    function decodeHeader(Memory.Slice item) internal pure returns (Header memory h) {
        h.fields = RLP.readList(item);
        uint256 n = h.fields.length;
        if (n < MIN_HEADER_FIELDS || n > MAX_HEADER_FIELDS) revert InvalidHeader();
        h.hash = keccak256(Memory.toBytes(item));
        h.parentHash = RLP.readBytes32(h.fields[IDX_PARENT_HASH]);
        h.stateRoot = RLP.readBytes32(h.fields[IDX_STATE_ROOT]);
        uint256 number = RLP.readUint256(h.fields[IDX_NUMBER]);
        if (number > type(uint64).max) revert InvalidHeader();
        // forge-lint: disable-next-line(unsafe-typecast)
        h.number = uint64(number);
        h.extra = RLP.readBytes(h.fields[IDX_EXTRA]);
        if (h.extra.length < EXTRA_VANITY + EXTRA_SEAL) revert InvalidExtraData();
    }

    /// @dev Decode a header chain `[h_0, …, h_m]` (ascending, each the parent of the next) and check
    ///      the parent-hash and number links. Returns the first (oldest) and last (newest) header.
    function decodeHeaderChain(Memory.Slice chainItem) internal pure returns (Header memory first, Header memory last) {
        Memory.Slice[] memory items = RLP.readList(chainItem);
        if (items.length == 0) revert InvalidHeader();
        first = decodeHeader(items[0]);
        last = first;
        for (uint256 i = 1; i < items.length; i++) {
            Header memory next = decodeHeader(items[i]);
            if (next.parentHash != last.hash || next.number <= last.number || next.number - last.number != 1) {
                revert HeaderChainBroken(i);
            }
            last = next;
        }
    }

    /// @dev Recover the block producer from the Parlia seal (`types.SealHash` with `chainId`).
    function sealSigner(Header memory h, uint256 chainId) internal pure returns (address signer) {
        Memory.Slice[] memory f = h.fields;
        uint256 n = f.length;
        // [chainId, 12 leading fields, extra-without-seal, mixDigest, nonce, (5 Cancun fields), (requestsHash)]
        uint256 parts = 16;
        if (n > IDX_PARENT_BEACON_ROOT) parts += 5;
        if (n > IDX_REQUESTS_HASH) parts += 1;
        bytes[] memory enc = new bytes[](parts);
        enc[0] = RLP.encode(chainId);
        for (uint256 i = 0; i < IDX_EXTRA; i++) {
            enc[i + 1] = Memory.toBytes(f[i]);
        }
        bytes memory extra = h.extra;
        uint256 unsealedLength = extra.length - EXTRA_SEAL;
        bytes memory unsealed = new bytes(unsealedLength);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            mcopy(add(unsealed, 0x20), add(extra, 0x20), unsealedLength)
            let sig := add(add(extra, 0x20), unsealedLength)
            r := mload(sig)
            s := mload(add(sig, 0x20))
            v := byte(0, mload(add(sig, 0x40)))
        }
        enc[13] = RLP.encode(unsealed);
        enc[14] = Memory.toBytes(f[IDX_MIX_DIGEST]);
        enc[15] = Memory.toBytes(f[IDX_NONCE]);
        if (n > IDX_PARENT_BEACON_ROOT) {
            for (uint256 i = 0; i < 5; i++) {
                enc[16 + i] = Memory.toBytes(f[IDX_BASE_FEE + i]);
            }
            if (n > IDX_REQUESTS_HASH) enc[21] = Memory.toBytes(f[IDX_REQUESTS_HASH]);
        }
        if (v > 1) revert SealRecoverFailed();
        signer = ecrecover(keccak256(RLP.encode(enc)), v + 27, r, s);
        if (signer == address(0)) revert SealRecoverFailed();
    }

    /// @dev Require the header's sealer to be a member of `addrs`.
    function requireSealedBy(Header memory h, uint256 chainId, address[] memory addrs) internal pure {
        address signer = sealSigner(h, chainId);
        for (uint256 i = 0; i < addrs.length; i++) {
            if (addrs[i] == signer) return;
        }
        revert UnauthorizedSealer(signer);
    }

    // ── Epoch blocks ──────────────────────────────────────────────────────────

    /// @dev Parse the validator section and turn length of an epoch block's extraData (post-Luban,
    ///      post-Bohr layout). Enforces the canonical ascending address order (the order the vote
    ///      bitset indexes) and 1 ≤ n ≤ 64.
    function parseEpoch(bytes memory extra) internal pure returns (EpochInfo memory info) {
        uint256 n = uint8(extra[EXTRA_VANITY]);
        if (n == 0 || n > MAX_VALIDATORS) revert InvalidEpochValidators();
        uint256 start = EXTRA_VANITY + VALIDATOR_NUMBER_SIZE;
        uint256 end = start + n * VALIDATOR_BYTES_LENGTH;
        if (extra.length < end + TURN_LENGTH_SIZE + EXTRA_SEAL) revert InvalidEpochValidators();
        info.turnLength = uint8(extra[end]);
        if (info.turnLength == 0) revert InvalidTurnLength();
        info.validatorsOffset = start;
        info.addrs = new address[](n);
        bytes32 h;
        assembly ("memory-safe") {
            h := keccak256(add(add(extra, 0x20), start), sub(end, start))
        }
        info.validatorsHash = h;
        for (uint256 i = 0; i < n; i++) {
            address a;
            uint256 off = start + i * VALIDATOR_BYTES_LENGTH;
            assembly ("memory-safe") {
                a := shr(96, mload(add(add(extra, 0x20), off)))
            }
            if (i > 0 && uint160(a) <= uint160(info.addrs[i - 1])) revert ValidatorsNotSorted();
            info.addrs[i] = a;
        }
    }

    /// @dev Bind relayer-supplied uncompressed keys to the epoch block's compressed keys: each key
    ///      must compress (the cheap direction, {ClprBls12381.compressG1}) to the 48 bytes the block
    ///      commits to. `packedKeys` is `n × uncompressedKey128` in header order.
    ///      Returns the validator set and keccak256(concat(address20 ‖ uncompressedKey128)).
    function bindEpochKeys(bytes memory extra, EpochInfo memory info, bytes memory packedKeys)
        internal
        pure
        returns (ValidatorSet memory set, bytes32 keysHash)
    {
        uint256 n = info.addrs.length;
        set.addrs = info.addrs;
        set.keys = packedKeys;
        if (set.keys.length != n * BLS_PUBKEY_LENGTH) revert InvalidEpochValidators();
        bytes memory key = new bytes(BLS_PUBKEY_LENGTH);
        bytes memory entries = new bytes(n * ENTRY_LENGTH);
        bytes memory keys = set.keys;
        for (uint256 i = 0; i < n; i++) {
            address a = set.addrs[i];
            assembly ("memory-safe") {
                let src := add(add(keys, 0x20), mul(i, 128))
                mcopy(add(key, 0x20), src, 128)
                let dst := add(add(entries, 0x20), mul(i, 148))
                mstore(dst, shl(96, a))
                mcopy(add(dst, 20), src, 128)
            }
            bytes memory compressed = ClprBls12381.compressG1(key);
            uint256 off = info.validatorsOffset + i * VALIDATOR_BYTES_LENGTH + ADDRESS_LENGTH;
            bool same;
            assembly ("memory-safe") {
                let x := add(add(extra, 0x20), off)
                let y := add(compressed, 0x20)
                same := and(eq(mload(x), mload(y)), eq(shr(128, mload(add(x, 0x20))), shr(128, mload(add(y, 0x20)))))
            }
            // The point at infinity (0xc0…) never reaches here as a valid vote key: BSC's StakeHub
            // requires a BLS proof of possession and every node's blst KeyValidate rejects it.
            if (!same || uint8(compressed[0]) & ClprBls12381.FLAG_INFINITY != 0) revert InvalidValidatorKey(i);
        }
        keysHash = keccak256(entries);
    }

    /// @dev Decode the anchor set supplied with a bundle: ONE byte string of `n × (address20 ‖
    ///      uncompressedKey128)` entries. Returns the set and keccak256 of that string, which the
    ///      caller compares with the anchor's `keysHash`.
    function decodeValidatorEntries(Memory.Slice item)
        internal
        pure
        returns (ValidatorSet memory set, bytes32 keysHash)
    {
        bytes memory e = RLP.readBytes(item);
        if (e.length == 0 || e.length % ENTRY_LENGTH != 0) revert InvalidEpochValidators();
        uint256 n = e.length / ENTRY_LENGTH;
        keysHash = keccak256(e);
        set.addrs = new address[](n);
        set.keys = new bytes(n * BLS_PUBKEY_LENGTH);
        bytes memory keys = set.keys;
        for (uint256 i = 0; i < n; i++) {
            address a;
            assembly ("memory-safe") {
                let src := add(add(e, 0x20), mul(i, 148))
                a := shr(96, mload(src))
                mcopy(add(add(keys, 0x20), mul(i, 128)), add(src, 20), 128)
            }
            set.addrs[i] = a;
        }
    }

    // ── Vote attestations ─────────────────────────────────────────────────────

    function decodeAttestation(Memory.Slice item) internal pure returns (Attestation memory a) {
        Memory.Slice[] memory f = RLP.readList(item);
        if (f.length != ATTESTATION_FIELDS) revert InvalidAttestation();
        uint256 bits = RLP.readUint256(f[0]);
        uint256 src = RLP.readUint256(f[2]);
        uint256 tgt = RLP.readUint256(f[4]);
        if (bits > type(uint64).max || src > type(uint64).max || tgt > type(uint64).max) revert InvalidAttestation();
        // forge-lint: disable-next-line(unsafe-typecast)
        a.voteAddressSet = uint64(bits);
        a.signature = RLP.readBytes(f[1]);
        if (a.signature.length != BLS_SIGNATURE_LENGTH) revert InvalidAttestation();
        // forge-lint: disable-next-line(unsafe-typecast)
        a.sourceNumber = uint64(src);
        a.sourceHash = RLP.readBytes32(f[3]);
        // forge-lint: disable-next-line(unsafe-typecast)
        a.targetNumber = uint64(tgt);
        a.targetHash = RLP.readBytes32(f[5]);
    }

    /// @dev `types.VoteData.Hash()` = keccak256(RLP([SourceNumber, SourceHash, TargetNumber, TargetHash])),
    ///      re-encoded canonically here so the signed message never depends on relayer encoding.
    function voteDataHash(Attestation memory a) internal pure returns (bytes32) {
        bytes[] memory enc = new bytes[](4);
        enc[0] = RLP.encode(uint256(a.sourceNumber));
        enc[1] = RLP.encode(a.sourceHash);
        enc[2] = RLP.encode(uint256(a.targetNumber));
        enc[3] = RLP.encode(a.targetHash);
        return keccak256(RLP.encode(enc));
    }

    /// @dev Verify a finalizing attestation for header `last`: target is the direct child of the
    ///      source (BSC's finality rule), the source is `last`, the quorum holds and the aggregate BLS
    ///      signature verifies under `set`.
    function verifyFinalizing(Attestation memory a, Header memory last, ValidatorSet memory set) internal view {
        if (a.targetNumber <= a.sourceNumber || a.targetNumber - a.sourceNumber != 1) {
            revert AttestationNotFinalizing();
        }
        if (a.sourceHash != last.hash || a.sourceNumber != last.number) revert AttestationSourceMismatch();
        verifyVotes(a, set);
    }

    /// @dev Quorum (`popcount ≥ ceil(2n/3)`, no bit beyond the set) + FastAggregateVerify. The voter
    ///      aggregate is a running `BLS12_G1ADD` sum (375 gas each; on-curve checked by the precompile);
    ///      `BLS12_PAIRING_CHECK` then subgroup-checks that aggregate inside {ClprBeaconBls}.
    function verifyVotes(Attestation memory a, ValidatorSet memory set) internal view {
        uint256 n = set.addrs.length;
        uint256 bits = a.voteAddressSet;
        if (n < MAX_VALIDATORS && bits >> n != 0) revert VoteBitOutOfRange();
        // buf = [running aggregate (128) ‖ next key (128)]; G1ADD writes the sum back over the aggregate.
        bytes memory buf = new bytes(256);
        bytes memory keys = set.keys;
        uint256 votes;
        bool ok = true;
        for (uint256 i = 0; i < n; i++) {
            if ((bits >> i) & 1 == 0) continue;
            assembly ("memory-safe") {
                let dst := add(buf, 0x20)
                let src := add(add(keys, 0x20), mul(i, 128))
                switch votes
                case 0 { mcopy(dst, src, 128) }
                default {
                    mcopy(add(dst, 128), src, 128)
                    let r := staticcall(gas(), 0x0b, dst, 256, dst, 128)
                    ok := and(ok, and(r, eq(returndatasize(), 128)))
                }
            }
            votes++;
        }
        if (!ok) revert BlsPrecompileCallFailed();
        if (votes * 3 < 2 * n || votes == 0) revert InsufficientVotes(votes, n);
        bytes memory agg = new bytes(128);
        assembly ("memory-safe") {
            mcopy(add(agg, 0x20), add(buf, 0x20), 128)
        }
        ClprBeaconBls.aggregateVerifyComplement(agg, new bytes[](0), a.signature, voteDataHash(a));
    }

    // ── Validator-set tenure ──────────────────────────────────────────────────

    /// @dev `Snapshot.minerHistoryCheckLen()` = (n/2 + 1) · turnLength − 1. The set published in epoch
    ///      block E is switched in after block `E + checkLen` (with checkLen taken from the set it
    ///      replaces), so it produces — and its votes target — blocks from `E + checkLen + 1`.
    function checkLen(uint256 validatorCount, uint256 turnLength) internal pure returns (uint64) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64((validatorCount / 2 + 1) * turnLength - 1);
    }
}
