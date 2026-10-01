// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title TezosBlake2b
/// @notice BLAKE2b (RFC 7693) over the EIP-152 `BLAKE2F` compression precompile at `0x09`, the hash
///         Tezos uses for block, operation, payload and context (Irmin) hashes.
/// @dev The precompile input is `rounds(4, BE) ‖ h(64) ‖ m(128) ‖ t(16, LE) ‖ f(1)`; the state words
///      and the message block are little-endian, so raw message bytes are copied in unchanged and the
///      digest is the first `outLen` bytes of the final state. Only unkeyed BLAKE2b with a 32- or
///      20-byte digest is needed (parameter block `0x0101 00 outLen`).
library TezosBlake2b {
    /// @dev Initial state for a 32-byte digest: IV with h0 ^= 0x01010020, as little-endian words.
    bytes32 internal constant H0_32 = 0x28c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5;
    /// @dev Initial state for a 20-byte digest: IV with h0 ^= 0x01010014.
    bytes32 internal constant H0_20 = 0x1cc9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5;
    /// @dev Second half of the initial state (IV[4..8], little-endian), shared by both digest sizes.
    bytes32 internal constant H1 = 0xd182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b;

    error Blake2fFailed();

    /// @notice BLAKE2b-256 of `data`.
    function hash256(bytes memory data) internal view returns (bytes32 out) {
        uint256 src;
        assembly ("memory-safe") {
            src := add(data, 0x20)
        }
        return hashAt(src, data.length, H0_32);
    }

    /// @notice BLAKE2b-160 of `data` (Tezos public-key hashes), left-aligned.
    function hash160(bytes memory data) internal view returns (bytes20 out) {
        uint256 src;
        assembly ("memory-safe") {
            src := add(data, 0x20)
        }
        return bytes20(hashAt(src, data.length, H0_20));
    }

    /// @notice BLAKE2b of `len` bytes at memory address `src`; `h0` selects the digest size
    ///         ({H0_32} or {H0_20}). Returns the first 32 bytes of the final state.
    function hashAt(uint256 src, uint256 len, bytes32 h0) internal view returns (bytes32 out) {
        bool ok = true;
        assembly ("memory-safe") {
            // Scratch space past the free-memory pointer (not allocated: nothing persists).
            let buf := mload(0x40)
            mstore(buf, shl(224, 12)) // rounds = 12
            mstore(add(buf, 4), h0)
            mstore(add(buf, 36), H1)
            let m := add(buf, 68)
            let off := 0
            for {} 1 {} {
                let remaining := sub(len, off)
                let last := iszero(gt(remaining, 128))
                let n := 128
                if last { n := remaining }
                mstore(m, 0)
                mstore(add(m, 32), 0)
                mstore(add(m, 64), 0)
                mstore(add(m, 96), 0)
                mcopy(m, add(src, off), n)
                off := add(off, n)
                // t (16 bytes, little-endian) and f
                mstore(add(buf, 196), 0)
                mstore8(add(buf, 196), and(off, 0xff))
                mstore8(add(buf, 197), and(shr(8, off), 0xff))
                mstore8(add(buf, 198), and(shr(16, off), 0xff))
                mstore8(add(buf, 199), and(shr(24, off), 0xff))
                mstore8(add(buf, 212), last)
                ok := and(ok, staticcall(gas(), 0x09, buf, 213, add(buf, 4), 64))
                if last { break }
            }
            out := mload(add(buf, 4))
        }
        if (!ok) revert Blake2fFailed();
    }
}
