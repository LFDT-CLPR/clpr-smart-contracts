// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title ClprCbor
/// @notice Strict, offset-based CBOR (RFC 8949) reader over `bytes memory` — just enough to walk
///         Cardano block headers, transaction bodies and Plutus data. Every read is bounds-checked;
///         reserved additional-info values, nesting deeper than {MAX_DEPTH} and half-read items
///         revert. Lengths and integers above 2^64 are rejected (Cardano never produces them in the
///         structures read here).
library ClprCbor {
    uint8 internal constant MAJOR_UINT = 0;
    uint8 internal constant MAJOR_NINT = 1;
    uint8 internal constant MAJOR_BYTES = 2;
    uint8 internal constant MAJOR_TEXT = 3;
    uint8 internal constant MAJOR_ARRAY = 4;
    uint8 internal constant MAJOR_MAP = 5;
    uint8 internal constant MAJOR_TAG = 6;
    uint8 internal constant MAJOR_SIMPLE = 7;

    /// @dev `arg` value reported for an indefinite-length head.
    uint256 internal constant INDEFINITE = type(uint256).max;
    uint256 internal constant MAX_DEPTH = 32;

    error CborOutOfBounds();
    error CborMalformed();
    error CborUnexpectedType(uint8 major);

    /// @notice Read an item head at `off`: major type, argument (length / value / tag;
    ///         {INDEFINITE} for an indefinite-length string, array or map) and the offset after it.
    function head(bytes memory b, uint256 off) internal pure returns (uint8 major, uint256 arg, uint256 next) {
        if (off >= b.length) revert CborOutOfBounds();
        uint8 ib = uint8(b[off]);
        major = ib >> 5;
        uint8 ai = ib & 0x1f;
        next = off + 1;
        if (ai < 24) {
            arg = ai;
        } else if (ai <= 27) {
            uint256 n = uint256(1) << (ai - 24); // 1, 2, 4, 8
            if (next + n > b.length) revert CborOutOfBounds();
            for (uint256 i = 0; i < n; i++) {
                arg = (arg << 8) | uint8(b[next + i]);
            }
            next += n;
        } else if (
            ai == 31 && (major == MAJOR_BYTES || major == MAJOR_TEXT || major == MAJOR_ARRAY || major == MAJOR_MAP)
        ) {
            arg = INDEFINITE;
        } else if (ai == 31 && major == MAJOR_SIMPLE) {
            revert CborMalformed(); // a stray "break"
        } else {
            revert CborMalformed();
        }
    }

    /// @notice Offset just past the item starting at `off`.
    function skip(bytes memory b, uint256 off) internal pure returns (uint256) {
        return _skip(b, off, 0);
    }

    function _skip(bytes memory b, uint256 off, uint256 depth) private pure returns (uint256 next) {
        if (depth > MAX_DEPTH) revert CborMalformed();
        uint8 major;
        uint256 arg;
        (major, arg, next) = head(b, off);
        if (major == MAJOR_BYTES || major == MAJOR_TEXT) {
            if (arg == INDEFINITE) {
                while (true) {
                    if (next >= b.length) revert CborOutOfBounds();
                    if (uint8(b[next]) == 0xff) return next + 1;
                    (uint8 cm, uint256 clen, uint256 cnext) = head(b, next);
                    if (cm != major || clen == INDEFINITE) revert CborMalformed();
                    next = cnext + clen;
                }
            }
            next += arg;
            if (next > b.length) revert CborOutOfBounds();
        } else if (major == MAJOR_ARRAY || major == MAJOR_MAP) {
            uint256 per = major == MAJOR_MAP ? 2 : 1;
            if (arg == INDEFINITE) {
                while (true) {
                    if (next >= b.length) revert CborOutOfBounds();
                    if (uint8(b[next]) == 0xff) return next + 1;
                    for (uint256 j = 0; j < per; j++) {
                        next = _skip(b, next, depth + 1);
                    }
                }
            }
            if (arg > b.length) revert CborOutOfBounds(); // cheap sanity bound
            for (uint256 i = 0; i < arg * per; i++) {
                next = _skip(b, next, depth + 1);
            }
        } else if (major == MAJOR_TAG) {
            next = _skip(b, next, depth + 1);
        }
        // uint / nint / simple: head only
    }

    /// @notice Unsigned integer at `off`.
    function readUint(bytes memory b, uint256 off) internal pure returns (uint256 v, uint256 next) {
        uint8 major;
        (major, v, next) = head(b, off);
        if (major != MAJOR_UINT) revert CborUnexpectedType(major);
    }

    /// @notice Definite-length byte string at `off`: (content offset, length, next).
    function readBytesRef(bytes memory b, uint256 off)
        internal
        pure
        returns (uint256 start, uint256 len, uint256 next)
    {
        uint8 major;
        (major, len, start) = head(b, off);
        if (major != MAJOR_BYTES) revert CborUnexpectedType(major);
        if (len == INDEFINITE) revert CborMalformed();
        next = start + len;
        if (next > b.length) revert CborOutOfBounds();
    }

    /// @notice Definite-length byte string at `off`, copied.
    function readBytes(bytes memory b, uint256 off) internal pure returns (bytes memory out, uint256 next) {
        uint256 start;
        uint256 len;
        (start, len, next) = readBytesRef(b, off);
        out = slice(b, start, len);
    }

    /// @notice Head of an array (or map) at `off`; returns the element count (or {INDEFINITE}).
    function readArray(bytes memory b, uint256 off) internal pure returns (uint256 count, uint256 next) {
        uint8 major;
        (major, count, next) = head(b, off);
        if (major != MAJOR_ARRAY) revert CborUnexpectedType(major);
    }

    function readMap(bytes memory b, uint256 off) internal pure returns (uint256 count, uint256 next) {
        uint8 major;
        (major, count, next) = head(b, off);
        if (major != MAJOR_MAP) revert CborUnexpectedType(major);
    }

    /// @notice True if the byte at `off` is the indefinite-length "break" (0xff).
    function isBreak(bytes memory b, uint256 off) internal pure returns (bool) {
        if (off >= b.length) revert CborOutOfBounds();
        return uint8(b[off]) == 0xff;
    }

    function slice(bytes memory b, uint256 start, uint256 len) internal pure returns (bytes memory out) {
        if (start + len > b.length) revert CborOutOfBounds();
        out = new bytes(len);
        assembly ("memory-safe") {
            mcopy(add(out, 0x20), add(add(b, 0x20), start), len)
        }
    }

    /// @notice 32 bytes at `start` (caller checked the length).
    function word(bytes memory b, uint256 start) internal pure returns (bytes32 w) {
        if (start + 32 > b.length) revert CborOutOfBounds();
        assembly ("memory-safe") {
            w := mload(add(add(b, 0x20), start))
        }
    }
}
