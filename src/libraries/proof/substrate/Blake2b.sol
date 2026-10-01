// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title Blake2b
/// @notice BLAKE2b-256 and BLAKE2b-128 (RFC 7693, unkeyed) built on the EIP-152 `BLAKE2F`
///         compression precompile at address 0x09. Substrate hashes block headers and trie nodes
///         with BLAKE2b-256 (`BlakeTwo256`) and uses BLAKE2b-128 in `Blake2_128Concat` storage keys.
/// @dev Hedera's EVM registers the full Prague precompile set (Besu
///      `MainnetPrecompiledContracts.populateForPrague`, hiero-consensus-node V070Module), which
///      includes BLAKE2F. One compression costs 12 gas (12 rounds) plus the call overhead.
///
///      Precompile input (213 bytes): rounds(4, BE) ‖ h(64, 8×u64 LE) ‖ m(128) ‖ t(16, 2×u64 LE) ‖ f(1).
///      The output is the new h (64 bytes); the digest is its first `outLen` bytes.
library Blake2b {
    /// @dev The BLAKE2F precompile call failed (precompile missing or out of gas).
    error Blake2fFailed();

    /// @dev h0..h7 for an unkeyed 32-byte digest: IV with h[0] ^= 0x01010000 ^ 32, as LE bytes.
    bytes32 private constant H32_LO = 0x28c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5;
    /// @dev h0..h7 for an unkeyed 16-byte digest: IV with h[0] ^= 0x01010000 ^ 16, as LE bytes.
    bytes32 private constant H16_LO = 0x18c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5;
    /// @dev h4..h7 (unchanged IV words), shared by both digest sizes.
    bytes32 private constant H_HI = 0xd182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b;

    /// @notice BLAKE2b-256 of `data` (Substrate `BlakeTwo256` / `blake2_256`).
    function hash256(bytes memory data) internal view returns (bytes32 out) {
        (out,) = _compress(data, H32_LO);
    }

    /// @notice BLAKE2b-128 of `data` (Substrate `blake2_128`), left-aligned in a bytes16.
    function hash128(bytes memory data) internal view returns (bytes16 out) {
        (bytes32 lo,) = _compress(data, H16_LO);
        // casting to 'bytes16' is safe: the 16-byte digest is, by definition, the first 16 bytes of h.
        // forge-lint: disable-next-line(unsafe-typecast)
        out = bytes16(lo);
    }

    /// @notice BLAKE2b-128 of a 20-byte value (an EVM address), without allocating.
    function hash128Address(address a) internal view returns (bytes16) {
        return hash128(abi.encodePacked(a));
    }

    /// @notice BLAKE2b-128 of a 32-byte word.
    function hash128Word(bytes32 w) internal view returns (bytes16) {
        return hash128(abi.encodePacked(w));
    }

    /// @dev Runs every 128-byte block of `data` through BLAKE2F and returns the final state h.
    function _compress(bytes memory data, bytes32 hLo) private view returns (bytes32 o0, bytes32 o1) {
        bool ok = true;
        assembly ("memory-safe") {
            // Byte-reverse a u64 (big-endian word value → little-endian byte order).
            function le64(x) -> y {
                x := or(shr(8, and(x, 0xFF00FF00FF00FF00)), shl(8, and(x, 0x00FF00FF00FF00FF)))
                x := or(shr(16, and(x, 0xFFFF0000FFFF0000)), shl(16, and(x, 0x0000FFFF0000FFFF)))
                y := or(shr(32, x), shl(32, and(x, 0xFFFFFFFF)))
            }

            // Scratch beyond the free-memory pointer (not allocated; nothing else runs meanwhile).
            let ptr := mload(0x40)
            mstore(ptr, shl(224, 12)) // rounds = 12 (BLAKE2b)
            mstore(add(ptr, 4), hLo)
            mstore(add(ptr, 36), H_HI)

            let len := mload(data)
            let src := add(data, 32)
            let off := 0
            for {} 1 {} {
                let remaining := sub(len, off)
                let last := iszero(gt(remaining, 128))
                let n := 128
                if last { n := remaining }

                let m := add(ptr, 68)
                mstore(m, 0)
                mstore(add(m, 32), 0)
                mstore(add(m, 64), 0)
                mstore(add(m, 96), 0)
                mcopy(m, add(src, off), n)

                off := add(off, n)
                // t = bytes consumed so far (t1 = 0: inputs are far below 2^64 bytes), then f.
                mstore(add(ptr, 196), shl(192, le64(off)))
                mstore(add(ptr, 204), 0)
                mstore8(add(ptr, 212), last)

                // A chain without BLAKE2F would "succeed" with empty return data: reject that too.
                // (Yul evaluates arguments right to left, so the call is made first, on its own.)
                let success := staticcall(gas(), 0x09, ptr, 213, add(ptr, 4), 64)
                if or(iszero(success), iszero(eq(returndatasize(), 64))) {
                    ok := 0
                    break
                }
                if last { break }
            }
            o0 := mload(add(ptr, 4))
            o1 := mload(add(ptr, 36))
        }
        if (!ok) revert Blake2fFailed();
    }
}
