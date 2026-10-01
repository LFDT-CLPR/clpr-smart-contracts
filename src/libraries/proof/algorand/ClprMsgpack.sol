// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title ClprMsgpack
/// @notice Bounds-checked MessagePack reader for go-algorand's canonical encoding (msgp: maps with
///         sorted string keys, minimal integers, `bin` for byte slices, `str` for strings and logs).
///         Every read checks the input length and reverts with {MsgpackMalformed} instead of indexing
///         out of range, because the bytes come from a permissionless relayer.
library ClprMsgpack {
    uint8 internal constant T_UINT = 0;
    uint8 internal constant T_NEG = 1;
    uint8 internal constant T_BIN = 2;
    uint8 internal constant T_STR = 3;
    uint8 internal constant T_ARR = 4;
    uint8 internal constant T_MAP = 5;
    uint8 internal constant T_NIL = 6;
    uint8 internal constant T_BOOL = 7;
    uint8 internal constant T_FLOAT = 8;

    uint256 internal constant MAX_DEPTH = 32;

    error MsgpackMalformed(uint256 offset);

    /// @notice Decode the item header at `p`. For bin/str: `v` = length, `body` = first payload byte.
    ///         For arrays and maps: `v` = element (pair) count, `body` = first element. For integers and
    ///         booleans: `v` = value, `body` = next item. For floats: `body` = next item.
    function header(bytes memory d, uint256 p) internal pure returns (uint8 t, uint256 v, uint256 body) {
        if (p >= d.length) revert MsgpackMalformed(p);
        uint8 b = uint8(d[p]);
        if (b <= 0x7f) return (T_UINT, b, p + 1);
        if (b >= 0xe0) return (T_NEG, 0, p + 1);
        if (b >= 0x80 && b <= 0x8f) return (T_MAP, b & 0x0f, p + 1);
        if (b >= 0x90 && b <= 0x9f) return (T_ARR, b & 0x0f, p + 1);
        if (b >= 0xa0 && b <= 0xbf) return _sized(d, T_STR, b & 0x1f, p + 1);
        if (b == 0xc0) return (T_NIL, 0, p + 1);
        if (b == 0xc2 || b == 0xc3) return (T_BOOL, b - 0xc2, p + 1);
        if (b == 0xc4) return _sized(d, T_BIN, _be(d, p + 1, 1), p + 2);
        if (b == 0xc5) return _sized(d, T_BIN, _be(d, p + 1, 2), p + 3);
        if (b == 0xc6) return _sized(d, T_BIN, _be(d, p + 1, 4), p + 5);
        if (b == 0xca) return (T_FLOAT, 0, _within(d, p + 5));
        if (b == 0xcb) return (T_FLOAT, 0, _within(d, p + 9));
        if (b == 0xcc) return (T_UINT, _be(d, p + 1, 1), p + 2);
        if (b == 0xcd) return (T_UINT, _be(d, p + 1, 2), p + 3);
        if (b == 0xce) return (T_UINT, _be(d, p + 1, 4), p + 5);
        if (b == 0xcf) return (T_UINT, _be(d, p + 1, 8), p + 9);
        if (b == 0xd0) return (T_NEG, 0, _within(d, p + 2));
        if (b == 0xd1) return (T_NEG, 0, _within(d, p + 3));
        if (b == 0xd2) return (T_NEG, 0, _within(d, p + 5));
        if (b == 0xd3) return (T_NEG, 0, _within(d, p + 9));
        if (b == 0xd9) return _sized(d, T_STR, _be(d, p + 1, 1), p + 2);
        if (b == 0xda) return _sized(d, T_STR, _be(d, p + 1, 2), p + 3);
        if (b == 0xdb) return _sized(d, T_STR, _be(d, p + 1, 4), p + 5);
        if (b == 0xdc) return (T_ARR, _be(d, p + 1, 2), p + 3);
        if (b == 0xdd) return (T_ARR, _be(d, p + 1, 4), p + 5);
        if (b == 0xde) return (T_MAP, _be(d, p + 1, 2), p + 3);
        if (b == 0xdf) return (T_MAP, _be(d, p + 1, 4), p + 5);
        revert MsgpackMalformed(p); // ext types and reserved bytes do not occur in go-algorand encodings
    }

    /// @notice Offset just past the item at `p`.
    function skip(bytes memory d, uint256 p) internal pure returns (uint256) {
        return _skip(d, p, 0);
    }

    /// @notice Find `key` in the map at `p`; returns the value offset, or 0 when absent (offset 0 is
    ///         never a value position). Reverts if the item at `p` is not a map.
    function lookup(bytes memory d, uint256 p, bytes memory key) internal pure returns (uint256) {
        (uint8 t, uint256 n, uint256 q) = header(d, p);
        if (t != T_MAP) revert MsgpackMalformed(p);
        bytes32 kh = keccak256(key);
        for (uint256 i = 0; i < n; i++) {
            (uint8 kt, uint256 klen, uint256 kb) = header(d, q);
            if (kt != T_STR) revert MsgpackMalformed(q);
            uint256 v = kb + klen;
            if (klen == key.length && _hashAt(d, kb, klen) == kh) return v;
            q = _skip(d, v, 1);
        }
        return 0;
    }

    /// @notice Unsigned integer at `p`.
    function readUint(bytes memory d, uint256 p) internal pure returns (uint256 v) {
        uint8 t;
        (t, v,) = header(d, p);
        if (t != T_UINT) revert MsgpackMalformed(p);
    }

    /// @notice (offset, length) of the str or bin payload at `p`; `t` must be T_STR or T_BIN.
    function readBytesRef(bytes memory d, uint256 p, uint8 want) internal pure returns (uint256 start, uint256 len) {
        uint8 t;
        (t, len, start) = header(d, p);
        if (t != want) revert MsgpackMalformed(p);
    }

    function _skip(bytes memory d, uint256 p, uint256 depth) private pure returns (uint256) {
        if (depth > MAX_DEPTH) revert MsgpackMalformed(p);
        (uint8 t, uint256 v, uint256 q) = header(d, p);
        if (t == T_BIN || t == T_STR) return q + v;
        if (t == T_ARR) {
            for (uint256 i = 0; i < v; i++) {
                q = _skip(d, q, depth + 1);
            }
            return q;
        }
        if (t == T_MAP) {
            for (uint256 i = 0; i < v; i++) {
                q = _skip(d, q, depth + 1);
                q = _skip(d, q, depth + 1);
            }
            return q;
        }
        return q;
    }

    function _sized(bytes memory d, uint8 t, uint256 len, uint256 body) private pure returns (uint8, uint256, uint256) {
        if (body > d.length || len > d.length - body) revert MsgpackMalformed(body);
        return (t, len, body);
    }

    function _within(bytes memory d, uint256 end) private pure returns (uint256) {
        if (end > d.length) revert MsgpackMalformed(end);
        return end;
    }

    function _be(bytes memory d, uint256 p, uint256 n) private pure returns (uint256 v) {
        if (p > d.length || n > d.length - p) revert MsgpackMalformed(p);
        for (uint256 i = 0; i < n; i++) {
            v = (v << 8) | uint8(d[p + i]);
        }
    }

    function _hashAt(bytes memory d, uint256 p, uint256 n) private pure returns (bytes32 h) {
        assembly ("memory-safe") {
            h := keccak256(add(add(d, 0x20), p), n)
        }
    }
}
