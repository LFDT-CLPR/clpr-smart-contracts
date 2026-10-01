// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprBeaconSsz} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconSsz.sol";
import {ClprBeaconBls} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconBls.sol";
import {ClprCommitteeMerkle} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprCommitteeMerkle.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title EthBeaconLightClient
/// @notice The Ethereum consensus-layer light-client steps shared by every CLPR verifier that trusts
///         Ethereum L1 through its sync committee: {EthMainnetVerifier} (Ethereum itself) and the OP
///         Stack verifier family (L2 output roots settled on Ethereum, via {EthL1StateVerifier}).
///
///         Chain of trust implemented here:
///           trust anchor (committee Merkle root + aggregate) → 2/3 sync-committee BLS signature over
///           the attested beacon header → SSZ branch proving the execution `state_root` in the header's
///           `body_root` → (optional) SSZ branch proving `next_sync_committee` in the header's
///           `state_root` → successor trust anchor.
///
/// @dev Layout parameters that a consensus fork can move (the generalized indices and branch depths)
///      are taken as arguments, never read from constants inside this library, so a caller can later
///      source them from a fork profile (clpr-spec ADR 2026-10-01 "Fork-Aware Verifiers", §3.3/B.2).
/// @dev Trust anchor: FLAT packed 260 bytes (fixed offsets, no RLP):
///      `gvr32 ‖ forkVersion4 ‖ channelId32 ‖ aggregatePubkey128 ‖ committeeMerkleRoot32 ‖ codeHash32`.
///      The 512 committee keys are NOT stored — the anchor commits to them with a keccak Merkle root
///      ({ClprCommitteeMerkle}); per proof the relay supplies only the NON-signers' keys.
library EthBeaconLightClient {
    // ── Trust anchor layout ──────────────────────────────────────────────────
    uint256 internal constant ANCHOR_OFF_GVR = 0;
    uint256 internal constant ANCHOR_OFF_FORK_VERSION = 32;
    uint256 internal constant ANCHOR_OFF_CHANNEL_ID = 36;
    uint256 internal constant ANCHOR_OFF_AGGREGATE = 68;
    uint256 internal constant ANCHOR_OFF_COMMITTEE_ROOT = 196;
    uint256 internal constant ANCHOR_OFF_CODE_HASH = 228;
    uint256 internal constant TRUST_ANCHOR_LENGTH = ANCHOR_OFF_CODE_HASH + 32; // 260

    // ── Sizes ────────────────────────────────────────────────────────────────
    uint256 internal constant SYNC_COMMITTEE_SIZE = ClprBeaconSsz.SYNC_COMMITTEE_SIZE;
    uint256 internal constant BLS_PUBKEY_LENGTH = 128; // uncompressed G1 (pad16||x||pad16||y)
    uint256 internal constant BLS_SIGNATURE_LENGTH = 256; // uncompressed G2
    uint256 internal constant SYNC_BITS_LENGTH = 64; // Bitvector[512] / 8
    uint256 internal constant FORK_VERSION_LENGTH = 4;
    uint256 internal constant HEADER_FIELDS = 5;
    uint256 internal constant SYNC_AGGREGATE_FIELDS = 2;
    uint256 internal constant COMMITTEE_FIELDS = 2;

    // RLP prefix bytes used to detect the optional rotation pair.
    uint8 internal constant RLP_EMPTY_STRING = 0x80;
    uint8 internal constant RLP_EMPTY_LIST = 0xc0;

    // Canonical RLP envelope of one non-signer entry: a 416-byte string is always prefixed
    // `0xb9 0x01a0` (long string, two length bytes). Checked in place so the payload can be
    // read as a slice — no per-entry RLP.readBytes copy.
    bytes3 internal constant ENTRY_RLP_PREFIX = 0xb901a0;
    uint256 internal constant ENTRY_RLP_PREFIX_LENGTH = 3;
    uint256 internal constant ENTRY_RLP_LENGTH = ENTRY_RLP_PREFIX_LENGTH + ClprCommitteeMerkle.ENTRY_LENGTH; // 419

    // ── Errors ───────────────────────────────────────────────────────────────
    error InvalidBeaconHeader();
    error InvalidSyncAggregate();
    error InvalidCommittee();
    error InvalidBranch();
    error ExecutionBranchInvalid();
    error NextCommitteeBranchInvalid();
    error RotationPairMismatch();
    /// @dev Participation is below the 2/3 supermajority required to trust the attested header.
    error InsufficientParticipation(uint256 participants, uint256 committeeSize);
    /// @dev The non-signer item must carry exactly one entry per clear participation bit.
    error NonSignerProofCountMismatch(uint256 expected, uint256 got);
    /// @dev A non-signer entry failed Merkle authentication against the anchor's committee root.
    ///      MANDATORY security check: without it a relay could pass a forged point as a
    ///      "non-signer" and steer the complement aggregation to any key it controls.
    error NonSignerProofInvalid(uint256 index);

    struct BeaconHeader {
        uint64 slot;
        uint64 proposerIndex;
        bytes32 parentRoot;
        bytes32 stateRoot;
        bytes32 bodyRoot;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Attested header + sync aggregate
    // ─────────────────────────────────────────────────────────────────────────

    function decodeBeaconHeader(Memory.Slice headerItem) internal pure returns (BeaconHeader memory header) {
        Memory.Slice[] memory fields = RLP.readList(headerItem);
        if (fields.length != HEADER_FIELDS) revert InvalidBeaconHeader();
        // forge-lint: disable-next-line(unsafe-typecast)
        header.slot = uint64(RLP.readUint256(fields[0]));
        // forge-lint: disable-next-line(unsafe-typecast)
        header.proposerIndex = uint64(RLP.readUint256(fields[1]));
        header.parentRoot = RLP.readBytes32(fields[2]);
        header.stateRoot = RLP.readBytes32(fields[3]);
        header.bodyRoot = RLP.readBytes32(fields[4]);
    }

    /// @dev SSZ `hash_tree_root(BeaconBlockHeader)`.
    function headerRoot(BeaconHeader memory h) internal pure returns (bytes32) {
        return ClprBeaconSsz.beaconBlockHeaderRoot(h.slot, h.proposerIndex, h.parentRoot, h.stateRoot, h.bodyRoot);
    }

    /// @dev Decode `[bits(64), signature(256)]`, enforcing both lengths.
    function decodeSyncAggregate(Memory.Slice aggregateItem)
        internal
        pure
        returns (bytes memory bits, bytes memory signature)
    {
        Memory.Slice[] memory agg = RLP.readList(aggregateItem);
        if (agg.length != SYNC_AGGREGATE_FIELDS) revert InvalidSyncAggregate();
        bits = RLP.readBytes(agg[0]);
        signature = RLP.readBytes(agg[1]);
        if (bits.length != SYNC_BITS_LENGTH || signature.length != BLS_SIGNATURE_LENGTH) revert InvalidSyncAggregate();
    }

    /// @dev Sync-committee BLS verification against an explicit (committeeRoot, aggregatePubkey).
    ///      Enforces the 2/3 supermajority on the bitvector (cheap failures stay cheap), collects the
    ///      NON-signers' keys from `nonSignerItem` authenticating each against `committeeRoot`, derives
    ///      the sync-committee signing root, and runs the on-chain BLS12-381 verification
    ///      (`ClprBeaconBls.aggregateVerifyComplement`: EIP-2537 G1MSM complement aggregation +
    ///      RFC-9380 hash-to-G2 + pairing). All points are EIP-2537 uncompressed.
    /// @param nonSignerItem one `key ‖ proof` entry per clear bit, ascending order. With full
    ///        participation the item is an empty RLP list and no key material is needed.
    /// @param bits the 64-byte participation bitvector (length pre-checked by the caller).
    function verifySyncCommitteeSignature(
        bytes32 committeeRoot,
        bytes memory aggregatePubkey,
        Memory.Slice nonSignerItem,
        bytes memory signature,
        bytes memory bits,
        bytes32 beaconBlockRoot,
        bytes memory forkVersion,
        bytes32 genesisValidatorsRoot
    ) internal view {
        // 2/3 supermajority on the participant count, decided by the bitvector before touching any
        // key material (the bits are covered by the signature check that follows: flipping a bit
        // changes the participant set and the pairing fails).
        // bits.length == 64 (pre-checked by the caller), so the vector is exactly two words.
        uint256 w0;
        uint256 w1;
        assembly ("memory-safe") {
            w0 := mload(add(bits, 32))
            w1 := mload(add(bits, 64))
        }
        uint256 participantCount = _popcount(w0) + _popcount(w1);
        uint256 nonSignerCount = SYNC_COMMITTEE_SIZE - participantCount;
        if (3 * participantCount < 2 * SYNC_COMMITTEE_SIZE) {
            revert InsufficientParticipation(participantCount, SYNC_COMMITTEE_SIZE);
        }

        bytes[] memory nonParticipants = _collectNonSigners(nonSignerItem, bits, nonSignerCount, committeeRoot);

        bytes32 domain = ClprBeaconSsz.computeSyncCommitteeDomain(_toBytes4(forkVersion), genesisValidatorsRoot);
        bytes32 signingRoot = ClprBeaconSsz.computeSigningRoot(beaconBlockRoot, domain);
        // Participant aggregate = committee aggregate − Σ(non-participants); at the 2/3 supermajority that
        // subtracts ≤ 1/3 of the committee instead of aggregating the ≥ 2/3 that signed.
        ClprBeaconBls.aggregateVerifyComplement(aggregatePubkey, nonParticipants, signature, signingRoot);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Execution state root
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Prove the execution-layer `state_root` (payload item `stateRootItem`) into the attested
    ///      header's `bodyRoot` along `branchItem` at `gindex` (`depth` siblings).
    function verifyExecutionStateRoot(
        Memory.Slice stateRootItem,
        Memory.Slice branchItem,
        bytes32 bodyRoot,
        uint256 gindex,
        uint256 depth
    ) internal pure returns (bytes32 executionStateRoot) {
        executionStateRoot = RLP.readBytes32(stateRootItem);
        if (!ClprBeaconSsz.verifyProof(executionStateRoot, decodeBranch(branchItem, depth), bodyRoot, gindex)) {
            revert ExecutionBranchInvalid();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Rotation
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Verifies the optional next-sync-committee rotation. The pair is both-present or
    ///      both-absent: an absent committee is an empty RLP string, an absent branch an empty RLP
    ///      list (matching the reference encoder).
    ///
    ///      The beacon `SyncCommittee` (and therefore the `next_sync_committee` Merkle proof) commits to
    ///      *compressed* 48-byte pubkeys, but on-chain BLS verification wants *uncompressed* keys and
    ///      on-chain decompression is gas-infeasible. So the relayer ships only the UNCOMPRESSED next
    ///      committee `[pubkeys[512], aggregate]` and:
    ///        1. the SSZ committee root is reconstructed from the derived compressed keys (each
    ///           `compressG1(uncompressed[i])` — the cheap on-chain direction) and proven against the
    ///           attested header stateRoot. This authenticates the uncompressed keys in one pass:
    ///           `compressG1` is injective on valid points, so only the real committee can reproduce the
    ///           beacon-committed root (fail-closed — a wrong key just fails the branch check);
    ///        2. the successor anchor stores the keccak Merkle root over those uncompressed keys, so
    ///           future proofs verify BLS with no decompression;
    ///        3. all of the pubkeys & the aggregate are on the curve.
    /// @return newTrustAnchor the successor anchor, or empty bytes when no rotation is carried.
    function verifyRotation(
        Memory.Slice nextCommitteeItem,
        Memory.Slice nextBranchItem,
        bytes32 stateRoot,
        bytes32 gvr,
        bytes memory forkVersion,
        bytes32 channelId,
        bytes32 codeHash,
        uint256 gindex,
        uint256 depth
    ) internal view returns (bytes memory newTrustAnchor) {
        bool committeeAbsent = _firstByte(nextCommitteeItem) == RLP_EMPTY_STRING;
        bool branchAbsent = _firstByte(nextBranchItem) == RLP_EMPTY_LIST;
        if (committeeAbsent != branchAbsent) revert RotationPairMismatch();
        if (committeeAbsent) return new bytes(0);

        (bytes[] memory nextPubkeys, bytes memory nextAggregate) = decodeCommittee(nextCommitteeItem, BLS_PUBKEY_LENGTH);

        ClprBeaconBls.requireOnCurveG1(nextPubkeys, nextAggregate);

        // Reconstruct the beacon-committed SSZ root from the uncompressed keys (compressing each on the
        // fly) and prove it against the attested state — this authenticates the uncompressed keys.
        bytes32 committeeRoot = ClprBeaconSsz.syncCommitteeRootFromUncompressed(nextPubkeys, nextAggregate);
        if (!ClprBeaconSsz.verifyProof(committeeRoot, decodeBranch(nextBranchItem, depth), stateRoot, gindex)) {
            revert NextCommitteeBranchInvalid();
        }
        newTrustAnchor = encodeTrustAnchor(nextPubkeys, nextAggregate, gvr, forkVersion, channelId, codeHash);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Decoders / encoders
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Decode an `[pubkeys[512], aggregate]` committee enforcing a fixed per-key byte length
    ///      (128 uncompressed, or 48 compressed for the beacon-native rotation committee).
    function decodeCommittee(Memory.Slice committeeItem, uint256 pubkeyLen)
        internal
        pure
        returns (bytes[] memory pubkeys, bytes memory aggregatePubkey)
    {
        Memory.Slice[] memory committee = RLP.readList(committeeItem);
        if (committee.length != COMMITTEE_FIELDS) revert InvalidCommittee();

        Memory.Slice[] memory pubkeyItems = RLP.readList(committee[0]);
        if (pubkeyItems.length != SYNC_COMMITTEE_SIZE) revert InvalidCommittee();
        pubkeys = new bytes[](SYNC_COMMITTEE_SIZE);
        for (uint256 i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
            pubkeys[i] = RLP.readBytes(pubkeyItems[i]);
            if (pubkeys[i].length != pubkeyLen) revert InvalidCommittee();
        }
        aggregatePubkey = RLP.readBytes(committee[1]);
        if (aggregatePubkey.length != pubkeyLen) revert InvalidCommittee();
    }

    function decodeBranch(Memory.Slice branchItem, uint256 expectedDepth)
        internal
        pure
        returns (bytes32[] memory branch)
    {
        Memory.Slice[] memory items = RLP.readList(branchItem);
        if (items.length != expectedDepth) revert InvalidBranch();
        branch = new bytes32[](expectedDepth);
        for (uint256 i = 0; i < expectedDepth; i++) {
            branch[i] = RLP.readBytes32(items[i]);
        }
    }

    /// @dev Build the flat packed trust anchor:
    ///      `gvr ‖ forkVersion ‖ channelId ‖ aggregate ‖ committeeMerkleRoot ‖ codeHash` — 260 bytes.
    ///      The keys are committed via `ClprCommitteeMerkle.root` (1,023 keccaks, once per
    ///      rotation/genesis), never stored. The Java implementation mirrors this byte-for-byte.
    /// @dev Lengths are enforced upstream ({decodeCommittee} / config decoding): 512 keys × 128 bytes,
    ///      128-byte aggregate, 4-byte forkVersion.
    function encodeTrustAnchor(
        bytes[] memory pubkeys,
        bytes memory aggregatePubkey,
        bytes32 gvr,
        bytes memory forkVersion,
        bytes32 channelId,
        bytes32 codeHash
    ) internal pure returns (bytes memory anchor) {
        bytes32 committeeRoot = ClprCommitteeMerkle.root(pubkeys);
        anchor = new bytes(TRUST_ANCHOR_LENGTH);
        uint256 keyLen = BLS_PUBKEY_LENGTH; // inline assembly only accepts direct number constants
        assembly ("memory-safe") {
            let dst := add(anchor, 32)
            mstore(add(dst, ANCHOR_OFF_GVR), gvr)
            mcopy(add(dst, ANCHOR_OFF_FORK_VERSION), add(forkVersion, 32), FORK_VERSION_LENGTH)
            mstore(add(dst, ANCHOR_OFF_CHANNEL_ID), channelId)
            mcopy(add(dst, ANCHOR_OFF_AGGREGATE), add(aggregatePubkey, 32), keyLen)
            mstore(add(dst, ANCHOR_OFF_COMMITTEE_ROOT), committeeRoot)
            mstore(add(dst, ANCHOR_OFF_CODE_HASH), codeHash)
        }
    }

    /// @dev Encode a sync-committee period as the trust-anchor identifier (`Channel.trustAnchorId`):
    ///      the protocol-native, monotonic handle for "which committee", rather than an opaque hash of
    ///      the anchor. 8-byte big-endian; never empty for a real period, so the interface invariant
    ///      "id non-empty iff anchor non-empty" holds at every call site.
    function periodId(uint64 period) internal pure returns (bytes memory) {
        return abi.encodePacked(period);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Private helpers
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Collect the NON-signers' uncompressed keys. The i-th entry is bound to the i-th CLEAR bit
    ///      of the `Bitvector[512]` (bit `i` is bit `i % 8` of byte `i / 8`, LSB-first): its Merkle fold
    ///      runs along that committee index, so only the key the beacon committed at that exact
    ///      position can reproduce `committeeRoot`. This authentication is load-bearing — see
    ///      {NonSignerProofInvalid}.
    function _collectNonSigners(
        Memory.Slice nonSignerItem,
        bytes memory bits,
        uint256 nonSignerCount,
        bytes32 committeeRoot
    ) private pure returns (bytes[] memory nonParticipants) {
        Memory.Slice[] memory entries = RLP.readList(nonSignerItem);
        if (entries.length != nonSignerCount) revert NonSignerProofCountMismatch(nonSignerCount, entries.length);

        nonParticipants = new bytes[](nonSignerCount);
        uint256 j;
        for (uint256 byteIdx = 0; byteIdx < SYNC_BITS_LENGTH && j < nonSignerCount; byteIdx++) {
            uint256 b = uint8(bits[byteIdx]);
            if (b == 0xFF) continue; // all eight participants signed
            for (uint256 bit = 0; bit < 8; bit++) {
                if ((b >> bit) & 1 == 0) {
                    uint256 index = (byteIdx << 3) | bit;
                    Memory.Slice item = entries[j];
                    if (Memory.length(item) != ENTRY_RLP_LENGTH || bytes3(Memory.load(item, 0)) != ENTRY_RLP_PREFIX) {
                        revert NonSignerProofInvalid(index);
                    }
                    (bool ok, bytes memory key) = ClprCommitteeMerkle.verifyAndExtractKey(
                        Memory.slice(item, ENTRY_RLP_PREFIX_LENGTH), index, committeeRoot
                    );
                    if (!ok) revert NonSignerProofInvalid(index);
                    nonParticipants[j++] = key;
                }
            }
        }
    }

    /// @dev Number of set bits in a 256-bit word (SWAR fold).
    function _popcount(uint256 x) private pure returns (uint256) {
        unchecked {
            x -= (x >> 1) & 0x5555555555555555555555555555555555555555555555555555555555555555;
            x = (x & 0x3333333333333333333333333333333333333333333333333333333333333333)
                + ((x >> 2) & 0x3333333333333333333333333333333333333333333333333333333333333333);
            x = (x + (x >> 4)) & 0x0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F;
            // Fold bytes into 16-bit lanes (each ≤ 16) so the lane-sum below (≤ 256) cannot carry.
            x = (x + (x >> 8)) & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF;
            return (x * 0x0001000100010001000100010001000100010001000100010001000100010001) >> 240;
        }
    }

    /// @dev First RLP prefix byte of an item — distinguishes an empty string (0x80) from an empty
    ///      list (0xc0) for the optional rotation pair.
    function _firstByte(Memory.Slice item) private pure returns (uint8) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint8(bytes1(Memory.load(item, 0)));
    }

    /// @dev First 4 bytes of a (length-4) `bytes` as `bytes4`. Trailing memory is zero-padded.
    function _toBytes4(bytes memory b) private pure returns (bytes4 out) {
        assembly ("memory-safe") {
            out := mload(add(b, 0x20))
        }
    }
}
