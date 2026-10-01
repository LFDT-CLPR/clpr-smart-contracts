// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title ClprMithrilMessage
/// @notice Rebuilds a Mithril `ProtocolMessage` (legacy hash scheme) from typed parts and returns the
///         message the STM signs. mithril-common `ProtocolMessage::compute_hash`:
///         `hex(SHA-256(key_1 ‖ value_1 ‖ key_2 ‖ value_2 ‖ …))`, keys in `ProtocolMessagePartKey`
///         declaration order, every key and value a UTF-8 string.
///
///         The relayer supplies each part as `(keyId, typed value)`; this library renders the exact
///         string Mithril hashed (lower-case hex, decimal, the hex-of-JSON aggregate key), so every
///         field the verifier later relies on is bound to the signature by construction:
///
///   id key                                               typed value          rendered
///    0 snapshot_digest                                    32 bytes             hex
///    1 cardano_transactions_merkle_root                   32 bytes             hex
///    2 cardano_blocks_transactions_merkle_root            32 bytes             hex
///    3 next_aggregate_verification_key                    root32‖nrLeaves8‖total8  hex(JSON)
///    4 next_protocol_parameters                           k8‖m8‖phiU8F24 4     hex(SHA-256(k‖m‖φ))
///                                                         or the 32-byte hash  hex (opaque; no rotation)
///    5 current_epoch                                      u64 BE               decimal
///    6 latest_block_number                                u64 BE               decimal
///    7 cardano_blocks_transactions_block_number_offset    u64 BE               decimal
///    8 cardano_stake_distribution_epoch                   u64 BE               decimal
///    9 cardano_stake_distribution_merkle_root             32 bytes             hex
///   10 cardano_database_merkle_root                       32 bytes             hex
///   11 next_aggregate_verification_key_snark              lower-case hex text  verbatim
///
/// @dev Keys must strictly increase. Because every rendered value is hex or decimal (alphabets that
///      contain none of the key strings' `_`/letters past `f`), the concatenated preimage parses one
///      way only. The "rigid" hash scheme (SNARK aggregates only) is not supported: such a message
///      would not hash to the signed value and verification fails closed.
library ClprMithrilMessage {
    uint8 internal constant SNAPSHOT_DIGEST = 0;
    uint8 internal constant TX_ROOT = 1;
    uint8 internal constant BLOCKS_TX_ROOT = 2;
    uint8 internal constant NEXT_AVK = 3;
    uint8 internal constant NEXT_PARAMS = 4;
    uint8 internal constant CURRENT_EPOCH = 5;
    uint8 internal constant LATEST_BLOCK = 6;
    uint8 internal constant BLOCKS_TX_OFFSET = 7;
    uint8 internal constant STAKE_EPOCH = 8;
    uint8 internal constant STAKE_ROOT = 9;
    uint8 internal constant DATABASE_ROOT = 10;
    uint8 internal constant NEXT_AVK_SNARK = 11;

    struct Parsed {
        bytes message; // the 64 ASCII hex characters the STM signs
        bool hasEpoch;
        uint64 epoch;
        bool hasNextAvk;
        bytes32 nextAvkRoot;
        uint64 nextAvkLeaves;
        uint64 nextAvkTotal;
        bool hasNextParams;
        uint64 nextK;
        uint64 nextM;
        uint32 nextPhi;
        bool hasBlocksTxRoot;
        bytes32 blocksTxRoot;
        bool hasTxRoot;
        bytes32 txRoot;
        bool hasLatestBlock;
        uint64 latestBlock;
    }

    error PartKeyOrder(uint256 keyId);
    error PartValueLength(uint256 keyId);
    error PartValueNotHex(uint256 keyId);

    /// @param keyIds  part keys, strictly increasing
    /// @param values  typed values (see table)
    function build(uint256[] memory keyIds, bytes[] memory values) internal pure returns (Parsed memory r) {
        if (keyIds.length != values.length) revert PartValueLength(type(uint256).max);
        bytes memory pre;
        for (uint256 i = 0; i < keyIds.length; i++) {
            uint256 id = keyIds[i];
            if (id > NEXT_AVK_SNARK || (i > 0 && id <= keyIds[i - 1])) revert PartKeyOrder(id);
            bytes memory v = values[i];
            bytes memory rendered;
            if (
                id == TX_ROOT || id == BLOCKS_TX_ROOT || id == SNAPSHOT_DIGEST || id == STAKE_ROOT
                    || id == DATABASE_ROOT
            ) {
                if (v.length != 32) revert PartValueLength(id);
                rendered = toHex(v);
                if (id == TX_ROOT) {
                    r.hasTxRoot = true;
                    r.txRoot = bytes32(v);
                } else if (id == BLOCKS_TX_ROOT) {
                    r.hasBlocksTxRoot = true;
                    r.blocksTxRoot = bytes32(v);
                }
            } else if (id == NEXT_AVK) {
                if (v.length != 48) revert PartValueLength(id);
                bytes32 root = bytes32(v);
                uint64 leaves = uint64(_be(v, 32, 8));
                uint64 total = uint64(_be(v, 40, 8));
                rendered = toHex(avkJson(root, leaves, total));
                (r.hasNextAvk, r.nextAvkRoot, r.nextAvkLeaves, r.nextAvkTotal) = (true, root, leaves, total);
            } else if (id == NEXT_PARAMS) {
                if (v.length == 32) {
                    // opaque hash: the next parameters are not needed (no rotation through this cert)
                    rendered = toHex(v);
                } else {
                    if (v.length != 20) revert PartValueLength(id);
                    rendered = toHex(abi.encodePacked(sha256(v)));
                    r.hasNextParams = true;
                    r.nextK = uint64(_be(v, 0, 8));
                    r.nextM = uint64(_be(v, 8, 8));
                    r.nextPhi = uint32(_be(v, 16, 4));
                }
            } else if (id == NEXT_AVK_SNARK) {
                if (v.length == 0) revert PartValueLength(id);
                for (uint256 j = 0; j < v.length; j++) {
                    uint8 c = uint8(v[j]);
                    if (!((c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66))) revert PartValueNotHex(id);
                }
                rendered = v;
            } else {
                // decimal u64 parts
                if (v.length != 8) revert PartValueLength(id);
                uint64 x = uint64(_be(v, 0, 8));
                rendered = bytes(_dec(x));
                if (id == CURRENT_EPOCH) (r.hasEpoch, r.epoch) = (true, x);
                else if (id == LATEST_BLOCK) (r.hasLatestBlock, r.latestBlock) = (true, x);
            }
            pre = bytes.concat(pre, keyString(id), rendered);
        }
        r.message = toHex(abi.encodePacked(sha256(pre)));
    }

    function keyString(uint256 id) internal pure returns (bytes memory) {
        if (id == 0) return "snapshot_digest";
        if (id == 1) return "cardano_transactions_merkle_root";
        if (id == 2) return "cardano_blocks_transactions_merkle_root";
        if (id == 3) return "next_aggregate_verification_key";
        if (id == 4) return "next_protocol_parameters";
        if (id == 5) return "current_epoch";
        if (id == 6) return "latest_block_number";
        if (id == 7) return "cardano_blocks_transactions_block_number_offset";
        if (id == 8) return "cardano_stake_distribution_epoch";
        if (id == 9) return "cardano_stake_distribution_merkle_root";
        if (id == 10) return "cardano_database_merkle_root";
        return "next_aggregate_verification_key_snark";
    }

    /// @notice serde_json of mithril `AggregateVerificationKeyForConcatenation`:
    ///         `{"mt_commitment":{"root":[b0,…,b31],"nr_leaves":N,"hasher":null},"total_stake":T}`.
    function avkJson(bytes32 root, uint64 nrLeaves, uint64 totalStake) internal pure returns (bytes memory j) {
        j = bytes('{"mt_commitment":{"root":[');
        for (uint256 i = 0; i < 32; i++) {
            j = bytes.concat(j, bytes(_dec(uint8(root[i]))), i == 31 ? bytes("") : bytes(","));
        }
        j = bytes.concat(
            j, '],"nr_leaves":', bytes(_dec(nrLeaves)), ',"hasher":null},"total_stake":', bytes(_dec(totalStake)), "}"
        );
    }

    /// @notice Lower-case hex of `b`.
    function toHex(bytes memory b) internal pure returns (bytes memory out) {
        out = new bytes(b.length * 2);
        bytes16 digits = "0123456789abcdef";
        for (uint256 i = 0; i < b.length; i++) {
            uint8 x = uint8(b[i]);
            out[2 * i] = digits[x >> 4];
            out[2 * i + 1] = digits[x & 0xf];
        }
    }

    function _dec(uint256 x) private pure returns (string memory) {
        if (x == 0) return "0";
        uint256 len;
        for (uint256 t = x; t != 0; t /= 10) {
            len++;
        }
        bytes memory s = new bytes(len);
        while (x != 0) {
            // forge-lint: disable-next-line(unsafe-typecast)
            s[--len] = bytes1(uint8(48 + (x % 10)));
            x /= 10;
        }
        return string(s);
    }

    function _be(bytes memory b, uint256 off, uint256 n) private pure returns (uint256 v) {
        for (uint256 i = 0; i < n; i++) {
            v = (v << 8) | uint8(b[off + i]);
        }
    }
}
