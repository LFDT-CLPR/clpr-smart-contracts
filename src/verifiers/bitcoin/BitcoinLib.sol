// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title BitcoinLib
/// @notice Pure/view helpers for verifying Bitcoin L1 data on an EVM: 80-byte block headers,
///         compact difficulty ("nBits") encoding, the mainnet 2016-block retarget rule, the Bitcoin
///         Cash ASERT rule, chainwork,
///         transaction Merkle branches, and transaction parsing (legacy and BIP-144 segwit).
///
/// @dev Byte-order convention: every 32-byte hash handled here is in Bitcoin's INTERNAL byte order
///      — the order in which it appears inside serialized headers/transactions and in which
///      double-SHA256 produces it. The human-facing "display" order (block explorers, RPC) is the
///      byte-reverse. Proof-of-work compares the hash as a LITTLE-endian 256-bit integer, which is
///      why {reverse256} exists.
///
///      All parsing is bounds-checked and reverts with a custom error, never a Panic, so arbitrary
///      relay-supplied bytes can only produce a clean rejection.
library BitcoinLib {
    // ── Constants ─────────────────────────────────────────────────────────────

    uint256 internal constant HEADER_LENGTH = 80;
    /// @dev Blocks per difficulty period.
    uint256 internal constant RETARGET_INTERVAL = 2016;
    /// @dev Target timespan of a period (two weeks, in seconds).
    uint256 internal constant TARGET_TIMESPAN = 14 days;
    /// @dev Target block spacing; the min-difficulty rule kicks in after 2x this gap.
    uint256 internal constant TARGET_SPACING = 10 minutes;

    // ── Errors ────────────────────────────────────────────────────────────────

    error BtcOutOfBounds();
    error BtcNegativeTarget();
    error BtcZeroTarget();
    error BtcTargetOverflow();
    error BtcBadMerkleIndex();
    error BtcTxMalformed();
    error BtcTxNoInputs();
    error BtcTxTooFewOutputs();
    error BtcTxTrailingBytes();
    error BtcTx64Bytes();

    // ── Hashing ───────────────────────────────────────────────────────────────

    /// @dev SHA256(SHA256(data)) via the SHA-256 precompile (0x02).
    function hash256(bytes memory data) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(sha256(data)));
    }

    /// @dev hash256 of the 64-byte concatenation `a ‖ b` (Merkle interior node).
    function hash256Pair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(sha256(abi.encodePacked(a, b))));
    }

    /// @dev Reverse the byte order of a 256-bit word (internal ↔ display order; LE ↔ BE integer).
    function reverse256(uint256 v) internal pure returns (uint256) {
        v = ((v & 0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >> 8)
            | ((v & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) << 8);
        v = ((v & 0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >> 16)
            | ((v & 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) << 16);
        v = ((v & 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >> 32)
            | ((v & 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) << 32);
        v = ((v & 0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >> 64)
            | ((v & 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) << 64);
        return (v >> 128) | (v << 128);
    }

    // ── Raw memory readers (bounds-checked) ──────────────────────────────────

    function _check(bytes memory b, uint256 off, uint256 len) private pure {
        if (off + len > b.length) revert BtcOutOfBounds();
    }

    function readBytes32(bytes memory b, uint256 off) internal pure returns (bytes32 out) {
        _check(b, off, 32);
        assembly ("memory-safe") {
            out := mload(add(add(b, 0x20), off))
        }
    }

    /// @dev Little-endian unsigned integer of `len` (≤ 8) bytes at `off`.
    function readLE(bytes memory b, uint256 off, uint256 len) internal pure returns (uint64 v) {
        _check(b, off, len);
        for (uint256 i = 0; i < len; ++i) {
            v |= uint64(uint8(b[off + i])) << uint64(8 * i);
        }
    }

    /// @dev Bitcoin CompactSize ("varint"). Returns the value and the offset after it.
    function readVarInt(bytes memory b, uint256 off) internal pure returns (uint256 v, uint256 next) {
        _check(b, off, 1);
        uint8 first = uint8(b[off]);
        if (first < 0xfd) return (first, off + 1);
        if (first == 0xfd) return (readLE(b, off + 1, 2), off + 3);
        if (first == 0xfe) return (readLE(b, off + 1, 4), off + 5);
        return (readLE(b, off + 1, 8), off + 9);
    }

    /// @dev Copy `len` bytes starting at `off` into a new array.
    function slice(bytes memory b, uint256 off, uint256 len) internal pure returns (bytes memory out) {
        _check(b, off, len);
        out = new bytes(len);
        assembly ("memory-safe") {
            let src := add(add(b, 0x20), off)
            let dst := add(out, 0x20)
            mcopy(dst, src, len)
        }
    }

    // ── Headers ───────────────────────────────────────────────────────────────

    /// @dev Header `i` of a concatenation of 80-byte headers, copied to its own array.
    function headerAt(bytes memory headers, uint256 i) internal pure returns (bytes memory) {
        return slice(headers, i * HEADER_LENGTH, HEADER_LENGTH);
    }

    function prevHash(bytes memory header) internal pure returns (bytes32) {
        return readBytes32(header, 4);
    }

    function merkleRoot(bytes memory header) internal pure returns (bytes32) {
        return readBytes32(header, 36);
    }

    function timestamp(bytes memory header) internal pure returns (uint32) {
        return uint32(readLE(header, 68, 4));
    }

    function nBits(bytes memory header) internal pure returns (uint32) {
        return uint32(readLE(header, 72, 4));
    }

    // ── Compact target ("nBits") ──────────────────────────────────────────────

    /// @dev Decode a compact target (Bitcoin Core `arith_uint256::SetCompact`), rejecting the
    ///      negative, zero and overflow cases that `DeriveTarget` rejects.
    function bitsToTarget(uint32 bits) internal pure returns (uint256 target) {
        uint256 size = bits >> 24;
        uint256 word = bits & 0x007fffff;
        if (word != 0 && (bits & 0x00800000) != 0) revert BtcNegativeTarget();
        if (word != 0 && (size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32))) {
            revert BtcTargetOverflow();
        }
        if (size <= 3) {
            target = word >> (8 * (3 - size));
        } else {
            target = word << (8 * (size - 3));
        }
        if (target == 0) revert BtcZeroTarget();
    }

    /// @dev Encode a target in compact form (Bitcoin Core `arith_uint256::GetCompact`).
    function targetToBits(uint256 target) internal pure returns (uint32) {
        uint256 size = 0;
        for (uint256 t = target; t != 0; t >>= 8) {
            ++size;
        }
        uint256 compact;
        if (size <= 3) {
            compact = target << (8 * (3 - size));
        } else {
            compact = target >> (8 * (size - 3));
        }
        // The 0x00800000 bit is the sign bit; if set, shift the mantissa and bump the exponent.
        if (compact & 0x00800000 != 0) {
            compact >>= 8;
            ++size;
        }
        // casting to 'uint32' is safe: size ≤ 33 and compact ≤ 0x7fffff.
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint32(compact | (size << 24));
    }

    /// @dev Mainnet retarget (Bitcoin Core `CalculateNextWorkRequired`): scale the previous target by
    ///      the actual timespan of the period, clamped to [timespan/4, timespan*4], capped at powLimit.
    /// @param lastBits nBits of the last block of the ending period (height boundary-1).
    /// @param periodStartTime Timestamp of the first block of the ending period (height boundary-2016).
    /// @param lastTime Timestamp of the last block of the ending period.
    function retarget(uint32 lastBits, uint32 periodStartTime, uint32 lastTime, uint256 powLimit)
        internal
        pure
        returns (uint32)
    {
        // Signed: a period can (rarely, legally) end with a timestamp before its first block's.
        int256 span = int256(uint256(lastTime)) - int256(uint256(periodStartTime));
        if (span < int256(TARGET_TIMESPAN / 4)) span = int256(TARGET_TIMESPAN / 4);
        if (span > int256(TARGET_TIMESPAN * 4)) span = int256(TARGET_TIMESPAN * 4);

        uint256 target = bitsToTarget(lastBits);
        // Core computes this in 256 bits; with a sane powLimit (< 2^250) this cannot overflow.
        uint256 next;
        unchecked {
            uint256 prod = target * uint256(span);
            next = prod / uint256(span) == target ? prod / TARGET_TIMESPAN : powLimit;
        }
        if (next > powLimit) next = powLimit;
        return targetToBits(next);
    }

    /// @dev Expected work of a block at `target` (Bitcoin Core `GetBlockProof`): 2^256 / (target+1).
    function work(uint256 target) internal pure returns (uint256) {
        return (~target / (target + 1)) + 1;
    }

    // ── ASERT (Bitcoin Cash aserti3-2d) ───────────────────────────────────────

    /// @dev Bitcoin Cash ASERT target (Bitcoin Cash Node `pow.cpp` `CalculateASERT`):
    ///      `refTarget * 2^((timeDiff - spacing * (heightDiff + 1)) / halfLife)` in 16.16 fixed point,
    ///      with the cubic approximation of 2^x, clamped to [1, powLimit].
    /// @param refTarget Target of the ASERT anchor block (0 < refTarget ≤ powLimit < 2^224).
    /// @param timeDiff Parent block's time minus the time of the anchor block's parent, in seconds.
    /// @param heightDiff Parent block's height minus the anchor block's height.
    /// @param halfLife Seconds ahead of (behind) schedule that double (halve) the target.
    function asertTarget(uint256 refTarget, int256 timeDiff, uint256 heightDiff, uint256 powLimit, uint256 halfLife)
        internal
        pure
        returns (uint256 next)
    {
        // C++ integer division truncates toward zero, as Solidity's signed division does.
        // forge-lint: disable-next-line(unsafe-typecast)
        int256 exponent = ((timeDiff - int256(TARGET_SPACING * (heightDiff + 1))) * 65536) / int256(halfLife);
        // Arithmetic shift: floor, as in the reference.
        int256 shifts = exponent >> 16;
        // casting to 'uint256' is safe: exponent - shifts * 65536 is in [0, 65535].
        // forge-lint: disable-next-line(unsafe-typecast)
        uint256 frac = uint256(exponent - shifts * 65536);
        // The reference computes this sum in uint64; its maximum (frac = 65535) is below 2^64.
        uint256 factor =
            65536 + ((195766423245049 * frac + 971821376 * frac * frac + 5127 * frac * frac * frac + (1 << 47)) >> 48);
        next = refTarget * factor; // < 2^241 since refTarget < 2^224
        shifts -= 16;
        if (shifts <= 0) {
            // casting to 'uint256' is safe: -shifts ≥ 0.
            // forge-lint: disable-next-line(unsafe-typecast)
            next >>= uint256(-shifts);
        } else {
            // casting to 'uint256' is safe: shifts > 0.
            // forge-lint: disable-next-line(unsafe-typecast)
            uint256 l = uint256(shifts);
            uint256 shifted = next << l;
            // Bits shifted out: the real value is ≥ 2^256, which clamps to powLimit anyway.
            next = (shifted >> l) != next ? powLimit : shifted;
        }
        if (next == 0) next = 1;
        else if (next > powLimit) next = powLimit;
    }

    /// @dev Compact nBits a Bitcoin Cash block must carry (BCHN `GetNextASERTWorkRequired`).
    /// @param anchorBits nBits of the ASERT anchor block.
    /// @param anchorParentTime Timestamp of the anchor block's parent.
    /// @param anchorHeight Height of the anchor block.
    /// @param parentHeight Height of the new block's parent (≥ anchorHeight).
    /// @param parentTime Timestamp of the new block's parent.
    function asertBits(
        uint32 anchorBits,
        uint32 anchorParentTime,
        uint32 anchorHeight,
        uint256 parentHeight,
        uint32 parentTime,
        uint256 powLimit,
        uint256 halfLife
    ) internal pure returns (uint32) {
        int256 timeDiff = int256(uint256(parentTime)) - int256(uint256(anchorParentTime));
        return
            targetToBits(
                asertTarget(bitsToTarget(anchorBits), timeDiff, parentHeight - anchorHeight, powLimit, halfLife)
            );
    }

    // ── Merkle ────────────────────────────────────────────────────────────────

    /// @dev Fold a Merkle branch from leaf `txid` at position `index`. Siblings are in internal
    ///      byte order, leaf-first. `index` must fit in `branch.length` bits (no silent truncation).
    function computeMerkleRoot(bytes32 txid, uint256 index, bytes32[] memory branch) internal pure returns (bytes32 h) {
        if (branch.length < 256 && (index >> branch.length) != 0) revert BtcBadMerkleIndex();
        h = txid;
        for (uint256 i = 0; i < branch.length; ++i) {
            h = (index & 1) == 1 ? hash256Pair(branch[i], h) : hash256Pair(h, branch[i]);
            index >>= 1;
        }
    }

    // ── Transactions ──────────────────────────────────────────────────────────

    /// @dev The fields of a transaction the CLPR verifier needs. Scripts are copied out.
    struct Tx {
        bytes32 txid;
        bytes32 in0PrevTxid;
        uint32 in0PrevVout;
        uint256 outputCount;
        bytes out0Script;
        bytes out1Script;
    }

    /// @dev Parse a serialized transaction — legacy, or BIP-144 segwit (`marker 0x00, flag 0x01`,
    ///      witnesses after the outputs) — and compute its txid over the NON-witness serialization
    ///      `version ‖ inputs ‖ outputs ‖ locktime`. The whole buffer must be consumed exactly.
    ///      Requires ≥ 1 input and ≥ 2 outputs (the CLPR message shape). Rejects 64-byte
    ///      non-witness serializations, which are ambiguous with Merkle interior nodes.
    function parseTx(bytes memory raw) internal pure returns (Tx memory t) {
        if (raw.length < 10) revert BtcTxMalformed();
        uint256 pos = 4; // version
        bool segwit = false;
        if (raw[4] == 0x00) {
            // A zero input count is only legal as the segwit marker, which must be followed by flag 0x01.
            if (raw[5] != 0x01) revert BtcTxNoInputs();
            segwit = true;
            pos = 6;
        }
        uint256 ioStart = pos;

        uint256 nIn;
        (nIn, pos) = readVarInt(raw, pos);
        if (nIn == 0) revert BtcTxNoInputs();
        // Each input is ≥ 41 bytes; reject absurd counts before looping.
        if (nIn > raw.length / 41) revert BtcTxMalformed();
        for (uint256 i = 0; i < nIn; ++i) {
            if (i == 0) {
                t.in0PrevTxid = readBytes32(raw, pos);
                t.in0PrevVout = uint32(readLE(raw, pos + 32, 4));
            }
            uint256 scriptLen;
            (scriptLen, pos) = readVarInt(raw, pos + 36);
            pos += scriptLen + 4; // scriptSig + sequence
            if (pos > raw.length) revert BtcOutOfBounds();
        }

        uint256 nOut;
        (nOut, pos) = readVarInt(raw, pos);
        if (nOut < 2) revert BtcTxTooFewOutputs();
        if (nOut > raw.length / 9) revert BtcTxMalformed();
        t.outputCount = nOut;
        for (uint256 i = 0; i < nOut; ++i) {
            uint256 scriptLen;
            (scriptLen, pos) = readVarInt(raw, pos + 8); // skip 8-byte value
            if (i == 0) t.out0Script = slice(raw, pos, scriptLen);
            else if (i == 1) t.out1Script = slice(raw, pos, scriptLen);
            pos += scriptLen;
            if (pos > raw.length) revert BtcOutOfBounds();
        }
        uint256 ioEnd = pos;

        if (segwit) {
            // One witness stack per input: count, then (len, bytes) items.
            for (uint256 i = 0; i < nIn; ++i) {
                uint256 items;
                (items, pos) = readVarInt(raw, pos);
                if (items > raw.length) revert BtcTxMalformed();
                for (uint256 j = 0; j < items; ++j) {
                    uint256 itemLen;
                    (itemLen, pos) = readVarInt(raw, pos);
                    pos += itemLen;
                    if (pos > raw.length) revert BtcOutOfBounds();
                }
            }
        }
        // Exactly the 4-byte locktime must remain.
        if (pos + 4 != raw.length) revert BtcTxTrailingBytes();

        bytes memory stripped;
        if (segwit) {
            stripped = abi.encodePacked(slice(raw, 0, 4), slice(raw, ioStart, ioEnd - ioStart), slice(raw, pos, 4));
        } else {
            stripped = raw;
        }
        if (stripped.length == 64) revert BtcTx64Bytes();
        t.txid = hash256(stripped);
    }
}
