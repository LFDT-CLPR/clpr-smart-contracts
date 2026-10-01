// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title ScaleCodec
/// @notice The few SCALE (parity-scale-codec) primitives the Substrate verifiers need: compact
///         integers, little-endian fixed-width integers and in-memory slicing.
library ScaleCodec {
    /// @dev A read ran past the end of the buffer.
    error ScaleOutOfBounds();
    /// @dev Compact "big-integer" mode (prefix 0b11) is not used for any value decoded here.
    error ScaleCompactTooLarge();
    /// @dev A compact integer was not in its shortest (canonical) form.
    error ScaleCompactNonCanonical();

    /// @notice Decodes a SCALE compact integer at `off`. Modes 0b00 (6-bit), 0b01 (14-bit) and
    ///         0b10 (30-bit) are supported, which covers every length, count and block number a
    ///         header, trie node or authority list can contain. Non-canonical encodings revert.
    function readCompact(bytes memory b, uint256 off) internal pure returns (uint256 value, uint256 next) {
        if (off >= b.length) revert ScaleOutOfBounds();
        uint256 b0 = uint8(b[off]);
        uint256 mode = b0 & 3;
        if (mode == 0) return (b0 >> 2, off + 1);
        if (mode == 1) {
            if (off + 2 > b.length) revert ScaleOutOfBounds();
            value = (b0 | (uint256(uint8(b[off + 1])) << 8)) >> 2;
            if (value < 64) revert ScaleCompactNonCanonical();
            return (value, off + 2);
        }
        if (mode == 2) {
            if (off + 4 > b.length) revert ScaleOutOfBounds();
            value =
                (b0
                        | (uint256(uint8(b[off + 1])) << 8)
                        | (uint256(uint8(b[off + 2])) << 16)
                        | (uint256(uint8(b[off + 3])) << 24)) >> 2;
            if (value < 16384) revert ScaleCompactNonCanonical();
            return (value, off + 4);
        }
        revert ScaleCompactTooLarge();
    }

    /// @notice SCALE compact encoding of `v` (v < 2^30).
    function encodeCompact(uint256 v) internal pure returns (bytes memory) {
        uint256 n;
        uint256 x;
        if (v < 64) (n, x) = (1, v << 2);
        else if (v < 16384) (n, x) = (2, (v << 2) | 1);
        else if (v < (1 << 30)) (n, x) = (4, (v << 2) | 2);
        else revert ScaleCompactTooLarge();
        bytes memory out = new bytes(n);
        assembly ("memory-safe") {
            // Little-endian: byte i of the encoding is bits [8i, 8i + 8) of x.
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                mstore8(add(add(out, 32), i), and(shr(mul(8, i), x), 0xff))
            }
        }
        return out;
    }

    /// @notice Little-endian u32 at `off`.
    function readU32(bytes memory b, uint256 off) internal pure returns (uint32 v) {
        if (off + 4 > b.length) revert ScaleOutOfBounds();
        for (uint256 i; i < 4; ++i) {
            v |= uint32(uint8(b[off + i])) << (8 * i);
        }
    }

    /// @notice Little-endian u64 at `off`.
    function readU64(bytes memory b, uint256 off) internal pure returns (uint64 v) {
        if (off + 8 > b.length) revert ScaleOutOfBounds();
        for (uint256 i; i < 8; ++i) {
            v |= uint64(uint8(b[off + i])) << (8 * i);
        }
    }

    /// @notice 32 bytes at `off`.
    function readBytes32(bytes memory b, uint256 off) internal pure returns (bytes32 v) {
        if (off + 32 > b.length) revert ScaleOutOfBounds();
        assembly ("memory-safe") {
            v := mload(add(add(b, 32), off))
        }
    }

    /// @notice The `n` (≤ 32) bytes at `off`, left-aligned and zero-padded.
    function readFixed(bytes memory b, uint256 off, uint256 n) internal pure returns (bytes32 v) {
        if (n > 32 || off + n > b.length) revert ScaleOutOfBounds();
        assembly ("memory-safe") {
            v := mload(add(add(b, 32), off))
        }
        if (n < 32) v &= bytes32(~(type(uint256).max >> (8 * n)));
    }

    /// @notice The 20 bytes at `off` as an address.
    function readAddress(bytes memory b, uint256 off) internal pure returns (address a) {
        if (off + 20 > b.length) revert ScaleOutOfBounds();
        assembly ("memory-safe") {
            a := shr(96, mload(add(add(b, 32), off)))
        }
    }

    /// @notice Copy of `b[off : off + len]`.
    function slice(bytes memory b, uint256 off, uint256 len) internal pure returns (bytes memory out) {
        if (off + len > b.length) revert ScaleOutOfBounds();
        out = new bytes(len);
        assembly ("memory-safe") {
            mcopy(add(out, 32), add(add(b, 32), off), len)
        }
    }

    /// @notice keccak256 of `b[off : off + len]` without copying.
    function keccakRange(bytes memory b, uint256 off, uint256 len) internal pure returns (bytes32 h) {
        if (off + len > b.length) revert ScaleOutOfBounds();
        assembly ("memory-safe") {
            h := keccak256(add(add(b, 32), off), len)
        }
    }

    /// @notice Little-endian bytes of a u32.
    function le32(uint32 v) internal pure returns (bytes4) {
        return bytes4(uint32((v >> 24) | ((v >> 8) & 0xff00) | ((v << 8) & 0xff0000) | (v << 24)));
    }

    /// @notice Little-endian bytes of a u64.
    function le64(uint64 v) internal pure returns (bytes8) {
        v = ((v & 0xFF00FF00FF00FF00) >> 8) | ((v & 0x00FF00FF00FF00FF) << 8);
        v = ((v & 0xFFFF0000FFFF0000) >> 16) | ((v & 0x0000FFFF0000FFFF) << 16);
        v = (v >> 32) | (v << 32);
        return bytes8(v);
    }
}
