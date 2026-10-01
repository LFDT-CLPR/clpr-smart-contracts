// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title ClprConfluxPos
/// @notice Decoders for the Conflux PoS chain (a Diem fork in conflux-rust `crates/pos`): the BCS
///         encoding of `LedgerInfo` (`types/src/ledger_info.rs`, `block_info.rs`) and of
///         `EpochState` (`epoch_state.rs`, `validator_verifier.rs`).
///
/// @dev BCS: integers little-endian; `Vec<u8>`/`HashValue` as ULEB128 length + bytes; `Option` as
///      0x00 | 0x01 ‖ value; `BTreeMap` as ULEB128 count + entries in key order. `PivotBlockDecision
///      .block_hash` is an `ethereum_types::H256`, which serde writes as the string "0x" + 64 lowercase
///      hex digits, so in BCS it is ULEB128(66) + 66 ASCII bytes.
library ClprConfluxPos {
    /// @dev SHA3-256("DIEM::LedgerInfo"): the Diem `CryptoHasher` seed prefixed to the BCS bytes
    ///      of a `LedgerInfo` to form the BLS signing message (`crypto/src/hash.rs`).
    bytes32 internal constant LEDGER_INFO_SEED = 0xcd510d1ab583c33b54fa949014601df0664857c18c4cfb228c862dd869df1b62;

    uint256 internal constant COMPRESSED_G1_LEN = 48;

    error BcsTruncated();
    error BcsTrailingBytes();
    error BcsBadLength();
    error BcsBadOption();
    error BcsBadHex();

    struct Validator {
        bytes32 account;
        bytes publicKey; // 48-byte compressed G1
        uint64 votingPower;
    }

    struct EpochState {
        uint64 epoch;
        Validator[] validators; // BTreeMap order (ascending account address)
        uint64 quorumVotingPower;
        uint64 totalVotingPower;
    }

    struct LedgerInfo {
        uint64 epoch;
        uint64 round;
        uint64 version;
        uint64 timestampUsecs;
        bool hasNextEpochState;
        EpochState nextEpochState;
        bool hasPivot;
        uint64 pivotHeight;
        bytes32 pivotBlockHash;
    }

    /// @notice Decode a BCS `LedgerInfo`. Reverts unless every byte is consumed.
    function decodeLedgerInfo(bytes memory b) internal pure returns (LedgerInfo memory li) {
        uint256 p = 0;
        (li.epoch, p) = _u64(b, p);
        (li.round, p) = _u64(b, p);
        p = _skipHash(b, p); // id
        p = _skipHash(b, p); // executed_state_id
        (li.version, p) = _u64(b, p);
        (li.timestampUsecs, p) = _u64(b, p);
        (li.hasNextEpochState, p) = _option(b, p);
        if (li.hasNextEpochState) (li.nextEpochState, p) = _epochState(b, p);
        (li.hasPivot, p) = _option(b, p);
        if (li.hasPivot) {
            (li.pivotHeight, p) = _u64(b, p);
            uint256 n;
            (n, p) = _uleb(b, p);
            if (n != 66) revert BcsBadLength();
            li.pivotBlockHash = _hexH256(b, p);
            p += 66;
        }
        p = _skipHash(b, p); // consensus_data_hash
        if (p != b.length) revert BcsTrailingBytes();
    }

    function _epochState(bytes memory b, uint256 p) private pure returns (EpochState memory es, uint256) {
        (es.epoch, p) = _u64(b, p);
        uint256 n;
        (n, p) = _uleb(b, p);
        es.validators = new Validator[](n);
        for (uint256 i = 0; i < n; i++) {
            Validator memory v = es.validators[i];
            if (p + 32 > b.length) revert BcsTruncated();
            assembly ("memory-safe") {
                mstore(v, mload(add(add(b, 0x20), p)))
            }
            p += 32;
            uint256 len;
            (len, p) = _uleb(b, p);
            if (len != COMPRESSED_G1_LEN) revert BcsBadLength();
            v.publicKey = _slice(b, p, len);
            p += len;
            bool hasVrf;
            (hasVrf, p) = _option(b, p);
            if (hasVrf) {
                (len, p) = _uleb(b, p);
                p += len;
            }
            (v.votingPower, p) = _u64(b, p);
        }
        (es.quorumVotingPower, p) = _u64(b, p);
        (es.totalVotingPower, p) = _u64(b, p);
        uint256 seedLen;
        (seedLen, p) = _uleb(b, p); // vrf_seed
        p += seedLen;
        if (p > b.length) revert BcsTruncated();
        return (es, p);
    }

    // ── primitives ─────────────────────────────────────────────────────────────────────────

    function _u64(bytes memory b, uint256 p) private pure returns (uint64 v, uint256) {
        if (p + 8 > b.length) revert BcsTruncated();
        for (uint256 i = 0; i < 8; i++) {
            // casting is safe: i < 8, so 8 * i < 64
            // forge-lint: disable-next-line(unsafe-typecast)
            v |= uint64(uint8(b[p + i])) << uint64(8 * i);
        }
        return (v, p + 8);
    }

    function _uleb(bytes memory b, uint256 p) private pure returns (uint256 v, uint256) {
        for (uint256 shift = 0; shift < 35; shift += 7) {
            if (p >= b.length) revert BcsTruncated();
            uint8 c = uint8(b[p++]);
            v |= uint256(c & 0x7f) << shift;
            if (c & 0x80 == 0) return (v, p);
        }
        revert BcsBadLength();
    }

    function _option(bytes memory b, uint256 p) private pure returns (bool some, uint256) {
        if (p >= b.length) revert BcsTruncated();
        uint8 tag = uint8(b[p]);
        if (tag > 1) revert BcsBadOption();
        return (tag == 1, p + 1);
    }

    /// @dev `HashValue` is serialized as bytes: ULEB128(32) + 32 bytes.
    function _skipHash(bytes memory b, uint256 p) private pure returns (uint256) {
        if (p >= b.length || uint8(b[p]) != 32) revert BcsBadLength();
        p += 33;
        if (p > b.length) revert BcsTruncated();
        return p;
    }

    /// @dev Parse "0x" + 64 lowercase hex digits at `b[p..p+66)`.
    function _hexH256(bytes memory b, uint256 p) private pure returns (bytes32 out) {
        if (p + 66 > b.length) revert BcsTruncated();
        if (b[p] != "0" || b[p + 1] != "x") revert BcsBadHex();
        uint256 v;
        for (uint256 i = 0; i < 64; i++) {
            uint8 c = uint8(b[p + 2 + i]);
            uint256 d;
            if (c >= 0x30 && c <= 0x39) d = c - 0x30;
            else if (c >= 0x61 && c <= 0x66) d = c - 0x61 + 10;
            else revert BcsBadHex();
            v = (v << 4) | d;
        }
        out = bytes32(v);
    }

    function _slice(bytes memory b, uint256 p, uint256 len) private pure returns (bytes memory out) {
        if (p + len > b.length) revert BcsTruncated();
        out = new bytes(len);
        assembly ("memory-safe") {
            mcopy(add(out, 0x20), add(add(b, 0x20), p), len)
        }
    }
}
