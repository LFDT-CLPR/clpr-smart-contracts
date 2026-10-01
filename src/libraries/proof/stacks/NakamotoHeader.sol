// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Sha512t256Call} from "@hiero-ledger/clpr/libraries/crypto/ClprSha512t256Hasher.sol";

/// @title NakamotoHeader
/// @notice Stacks Nakamoto block headers (stacks-core `NakamotoBlockHeader`) and their signer signatures.
///
/// The verifier never sees the signer-signature vector inside the header: the relayer passes the
/// header WITHOUT it, which is exactly the preimage of `signer_signature_hash` (= the block hash):
///
///   version u8 | chain_length u64 | burn_spent u64 | consensus_hash [20] | parent_block_id [32] |
///   tx_merkle_root [32] | state_index_root [32] | timestamp u64 | miner_signature [65] |
///   pox_treatment (u16 bits, u32 len, bytes) | problematic_txs (version ≥ 1 only)
///
/// All integers are big-endian. The fixed 206-byte prefix is read at fixed offsets; the variable tail
/// is only hashed. `block_id` (the index block hash, which parent links and MARF back-pointers use)
/// is SHA-512/256(block_hash ‖ consensus_hash).
library NakamotoHeader {
    /// @dev Bytes before `pox_treatment`.
    uint256 internal constant PREFIX = 206;
    /// @dev Header versions whose prefix layout this library reads: 0 (Nakamoto, epochs 3.x) and
    ///      1 (epoch 4.0, adds `problematic_txs` to the tail). A new version is rejected until reviewed.
    uint256 internal constant MAX_VERSION = 1;
    /// @dev Bytes per relayer-supplied signature: signer index (u16) ‖ recovery id ‖ r ‖ s.
    uint256 internal constant SIG_LEN = 67;

    struct Header {
        uint8 version;
        uint64 chainLength;
        bytes20 consensusHash;
        bytes32 parentBlockId;
        bytes32 stateIndexRoot;
        uint64 timestamp;
        bytes32 blockHash; // = signer_signature_hash, what the signers sign
        bytes32 blockId; // index block hash
    }

    error HeaderTooShort();
    error HeaderVersionUnsupported(uint8 version);
    error SignaturesMalformed();
    error SignerIndexNotAscending();
    error SignerIndexOutOfRange();
    error BadRecoveryId();
    error SignerMismatch(uint256 index);
    error EmptySignerSet();
    error BelowThreshold(uint256 signedWeight, uint256 totalWeight);

    /// @notice Hash and decode a header preimage (the header without its signer signatures).
    function parse(address hasher, bytes memory pre) internal view returns (Header memory h) {
        if (pre.length <= PREFIX) revert HeaderTooShort();
        uint8 version = uint8(pre[0]);
        if (version > MAX_VERSION) revert HeaderVersionUnsupported(version);
        h.version = version;
        uint256 w;
        assembly ("memory-safe") {
            let d := add(pre, 0x20)
            w := shr(192, mload(add(d, 1)))
            mstore(add(h, 0x20), w) // chainLength
            mstore(add(h, 0x40), shl(96, shr(96, mload(add(d, 17))))) // consensusHash (bytes20, left-aligned)
            mstore(add(h, 0x60), mload(add(d, 37))) // parentBlockId
            mstore(add(h, 0x80), mload(add(d, 101))) // stateIndexRoot
            mstore(add(h, 0xa0), shr(192, mload(add(d, 133)))) // timestamp
        }
        h.blockHash = Sha512t256Call.hash(hasher, pre);
        h.blockId = Sha512t256Call.hash(hasher, abi.encodePacked(h.blockHash, h.consensusHash));
    }

    /// @notice Check signer signatures over `blockHash` against a weighted signer set and require at
    ///         least 70% of the total weight (stacks-core `compute_voting_weight_threshold`:
    ///         signed ≥ ⌈7·total/10⌉ ⇔ 10·signed ≥ 7·total).
    /// @param signers the set's signer addresses (keccak of the uncompressed key), in reward-set order
    /// @param weights the matching signer weights
    /// @param sigs packed `index(2) ‖ recid(1) ‖ r(32) ‖ s(32)`, strictly ascending signer index
    /// @return signed the weight that signed
    function verifySigners(bytes32 blockHash, address[] memory signers, uint64[] memory weights, bytes memory sigs)
        internal
        pure
        returns (uint256 signed)
    {
        uint256 n = signers.length;
        if (n == 0 || weights.length != n) revert EmptySignerSet();
        if (sigs.length % SIG_LEN != 0) revert SignaturesMalformed();
        uint256 count = sigs.length / SIG_LEN;
        uint256 next; // smallest index the next signature may use
        for (uint256 i = 0; i < count; ++i) {
            uint256 idx;
            uint256 v;
            bytes32 r;
            bytes32 s;
            assembly ("memory-safe") {
                let p := add(add(sigs, 0x20), mul(i, 67))
                idx := shr(240, mload(p))
                v := byte(0, mload(add(p, 2)))
                r := mload(add(p, 3))
                s := mload(add(p, 35))
            }
            if (idx < next) revert SignerIndexNotAscending();
            if (idx >= n) revert SignerIndexOutOfRange();
            // Stacks recovery ids 2/3 (r ≥ n) never occur in practice and ecrecover cannot take them.
            if (v > 1) revert BadRecoveryId();
            // casting to 'uint8' is safe because v ≤ 1
            // forge-lint: disable-next-line(unsafe-typecast)
            address a = ecrecover(blockHash, uint8(v + 27), r, s);
            if (a == address(0) || a != signers[idx]) revert SignerMismatch(idx);
            signed += weights[idx];
            next = idx + 1;
        }
        uint256 total;
        for (uint256 i = 0; i < n; ++i) {
            total += weights[i];
        }
        if (total == 0) revert EmptySignerSet();
        if (signed * 10 < total * 7) revert BelowThreshold(signed, total);
    }
}
