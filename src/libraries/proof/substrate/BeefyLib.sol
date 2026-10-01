// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ScaleCodec} from "@hiero-ledger/clpr/libraries/proof/substrate/ScaleCodec.sol";

/// @title BeefyLib
/// @notice BEEFY (Polkadot relay chain) finality: signed commitments, authority-set commitments,
///         MMR leaves and MMR inclusion paths. Every format below was checked against polkadot-sdk
///         (sp-consensus-beefy, pallet-beefy-mmr, binary-merkle-tree, pallet-mmr) and live Polkadot.
///
/// Commitment (sp_consensus_beefy::Commitment<u32>), SCALE:
///   payload: Vec<([u8;2] id, Vec<u8>)> ‖ block_number: u32 LE ‖ validator_set_id: u64 LE
///   The MMR root is the 32-byte payload entry with id "mh" (known_payloads::MMR_ROOT_ID).
///   Each authority signs keccak256(SCALE(commitment)) with secp256k1 (65-byte r‖s‖v, v ∈ {0,1},
///   low-s enforced by `ecdsa_crypto::AuthorityId::verify`). Threshold: n − (n − 1) / 3.
///
/// Authority set (pallet_beefy_mmr::compute_authority_set): BeefyAuthoritySet{id: u64, len: u32,
///   keyset_commitment} where keyset_commitment = binary_merkle_tree::merkle_root::<Keccak256>
///   over the authorities' 20-byte Ethereum addresses: leaves are keccak256(address); each row
///   pairs keccak256(left ‖ right); an odd last node is promoted unchanged.
///
/// MMR leaf (sp_consensus_beefy::mmr::MmrLeaf), SCALE, 113 bytes on Polkadot:
///   version: u8 ‖ parent_number: u32 LE ‖ parent_hash: H256 ‖
///   beefy_next_authority_set{id: u64 LE, len: u32 LE, root: H256} ‖ leaf_extra: H256
///   Leaf hash = keccak256(SCALE(leaf)); pallet-mmr merges keccak256(left ‖ right) inside a
///   mountain and bags peaks right-to-left as keccak256(right ‖ left).
library BeefyLib {
    uint256 internal constant SIGNATURE_LENGTH = 65;
    uint256 internal constant MMR_LEAF_LENGTH = 113;
    bytes2 internal constant MMR_ROOT_ID = "mh";

    struct AuthoritySet {
        uint64 id;
        uint32 len;
        bytes32 root;
    }

    struct Commitment {
        bytes32 mmrRoot;
        uint32 blockNumber;
        uint64 validatorSetId;
    }

    struct MmrLeaf {
        uint8 version;
        uint32 parentNumber;
        bytes32 parentHash;
        AuthoritySet nextAuthoritySet;
        bytes32 leafExtra;
    }

    error InvalidCommitment();
    error MissingMmrRoot();
    error InvalidAuthorityList();
    error AuthoritySetMismatch();
    error InvalidSignersBitfield();
    error InvalidSignaturesLength();
    error InvalidBeefySignature(uint256 authorityIndex);
    error BeefyThresholdNotMet(uint256 signed, uint256 threshold);
    error InvalidMmrLeaf();
    error MmrProofMismatch();
    error MmrPathTooLong();

    /// @notice Decodes a SCALE commitment; requires exactly one 32-byte "mh" payload entry.
    function decodeCommitment(bytes memory c) internal pure returns (Commitment memory r) {
        (uint256 n, uint256 off) = ScaleCodec.readCompact(c, 0);
        bool found;
        for (uint256 i; i < n; ++i) {
            bytes2 id = bytes2(ScaleCodec.readFixed(c, off, 2));
            uint256 len;
            (len, off) = ScaleCodec.readCompact(c, off + 2);
            if (id == MMR_ROOT_ID) {
                if (found || len != 32) revert InvalidCommitment();
                r.mmrRoot = ScaleCodec.readBytes32(c, off);
                found = true;
            }
            off += len;
        }
        if (!found) revert MissingMmrRoot();
        r.blockNumber = ScaleCodec.readU32(c, off);
        r.validatorSetId = ScaleCodec.readU64(c, off + 4);
        if (off + 12 != c.length) revert InvalidCommitment();
    }

    /// @notice keyset_commitment of a packed list of 20-byte authority addresses.
    function keysetRoot(bytes memory addresses) internal pure returns (bytes32) {
        if (addresses.length == 0 || addresses.length % 20 != 0) revert InvalidAuthorityList();
        uint256 n = addresses.length / 20;
        bytes32[] memory row = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            row[i] = ScaleCodec.keccakRange(addresses, i * 20, 20);
        }
        while (n > 1) {
            uint256 m = (n + 1) / 2;
            for (uint256 i; i < n / 2; ++i) {
                row[i] = _hashPair(row[2 * i], row[2 * i + 1]);
            }
            if (n % 2 == 1) row[m - 1] = row[n - 1];
            n = m;
        }
        return row[0];
    }

    /// @notice Verifies that authorities of `set` (given as `addresses`, which must commit to
    ///         `set.root` and number `set.len`) signed `commitmentBytes` past the BEEFY threshold.
    /// @param signers    Bitfield over the authority list, MSB-first per byte (index 0 = 0x80 of
    ///                   byte 0, as in sp-consensus-beefy CompactSignedCommitment); exactly
    ///                   ceil(len / 8) bytes with no bit set past `len`.
    /// @param signatures 65-byte signatures, one per set bit, in index order.
    function verifySignatures(
        bytes memory commitmentBytes,
        AuthoritySet memory set,
        bytes memory addresses,
        bytes memory signers,
        bytes memory signatures
    ) internal pure {
        uint256 n = set.len;
        if (addresses.length != n * 20) revert AuthoritySetMismatch();
        if (keysetRoot(addresses) != set.root) revert AuthoritySetMismatch();
        if (signers.length != (n + 7) / 8) revert InvalidSignersBitfield();
        for (uint256 i = n; i < signers.length * 8; ++i) {
            if (_bit(signers, i)) revert InvalidSignersBitfield();
        }
        if (signatures.length % SIGNATURE_LENGTH != 0) revert InvalidSignaturesLength();

        bytes32 digest = keccak256(commitmentBytes);
        uint256 s;
        for (uint256 i; i < n; ++i) {
            if (!_bit(signers, i)) continue;
            uint256 off = s * SIGNATURE_LENGTH;
            if (off + SIGNATURE_LENGTH > signatures.length) revert InvalidSignaturesLength();
            bytes32 r = ScaleCodec.readBytes32(signatures, off);
            bytes32 sv = ScaleCodec.readBytes32(signatures, off + 32);
            uint8 v = uint8(signatures[off + 64]);
            if (v < 27) v += 27;
            (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, v, r, sv);
            address expected = ScaleCodec.readAddress(addresses, i * 20);
            if (err != ECDSA.RecoverError.NoError || rec != expected) revert InvalidBeefySignature(i);
            ++s;
        }
        if (s * SIGNATURE_LENGTH != signatures.length) revert InvalidSignaturesLength();
        uint256 need = n - (n - 1) / 3;
        if (s < need) revert BeefyThresholdNotMet(s, need);
    }

    /// @notice Decodes a 113-byte SCALE `MmrLeaf` with an H256 `leaf_extra`.
    function decodeLeaf(bytes memory leaf) internal pure returns (MmrLeaf memory l) {
        if (leaf.length != MMR_LEAF_LENGTH) revert InvalidMmrLeaf();
        l.version = uint8(leaf[0]);
        l.parentNumber = ScaleCodec.readU32(leaf, 1);
        l.parentHash = ScaleCodec.readBytes32(leaf, 5);
        l.nextAuthoritySet = AuthoritySet({
            id: ScaleCodec.readU64(leaf, 37), len: ScaleCodec.readU32(leaf, 45), root: ScaleCodec.readBytes32(leaf, 49)
        });
        l.leafExtra = ScaleCodec.readBytes32(leaf, 81);
    }

    /// @notice Verifies `leaf` is a leaf of the MMR whose (bagged) root is `root`.
    /// @param path  The leaf's inclusion path: mountain siblings bottom-up, then the bagged right
    ///              peaks (if any), then each left peak from nearest to farthest. The relay derives
    ///              it from `mmr_generateProof` (README §4).
    /// @param sides Bit i set ⇒ path[i] is hashed on the left: keccak256(path[i] ‖ acc);
    ///              otherwise keccak256(acc ‖ path[i]).
    /// @dev Sound because every step is a keccak256 of 64 bytes while a leaf is hashed from its
    ///      113-byte encoding, so no inner node can pass as a leaf.
    function verifyMmrLeaf(bytes32 root, bytes memory leaf, bytes32[] memory path, uint256 sides) internal pure {
        if (path.length > 256) revert MmrPathTooLong();
        if (leaf.length != MMR_LEAF_LENGTH) revert InvalidMmrLeaf();
        bytes32 acc = keccak256(leaf);
        for (uint256 i; i < path.length; ++i) {
            acc = (sides >> i) & 1 == 1 ? _hashPair(path[i], acc) : _hashPair(acc, path[i]);
        }
        if (acc != root) revert MmrProofMismatch();
    }

    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32 h) {
        assembly ("memory-safe") {
            mstore(0, a)
            mstore(32, b)
            h := keccak256(0, 64)
        }
    }

    function _bit(bytes memory bits, uint256 i) private pure returns (bool) {
        return (uint8(bits[i / 8]) >> (7 - (i % 8))) & 1 == 1;
    }
}
