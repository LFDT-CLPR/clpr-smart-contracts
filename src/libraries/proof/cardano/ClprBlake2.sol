// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title ClprBlake2
/// @notice BLAKE2b (RFC 7693, unkeyed, any digest length 1..64) on the EIP-152 BLAKE2F precompile
///         (0x09).
///
///         Cardano and Mithril use three of them:
///           - BLAKE2b-256: block-header hash, block-body hash, transaction id, Mithril STM Merkle tree
///           - BLAKE2b-512 / BLAKE2b-128: Mithril lottery evaluation and BLS aggregation scalars
///           - BLAKE2s-256: Mithril's Merkle-mountain-range trees (CardanoTransactions,
///             CardanoBlocksTransactions)
///         BLAKE2s-256 has no precompile and runs in the stand-alone {ClprBlake2sHasher}.
///         BLAKE2F is live on Hedera mainnet and testnet (checked with `eth_call` against the
///         EIP-152 test vector).
library ClprBlake2 {
    error Blake2fFailed();
    error BadDigestLength();

    /// @dev BLAKE2b IV as eight little-endian 64-bit words (the precompile's `h` layout), with the
    ///      parameter block for digest length 0 and key length 0 already XORed in (fanout 1, depth 1).
    ///      The digest length goes into byte 0 (see {_iv}).
    bytes32 private constant IV_LO = 0x08c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5;
    bytes32 private constant IV_HI = 0xd182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b;

    /// @notice BLAKE2b-256 of `data`.
    function b2b256(bytes memory data) internal view returns (bytes32 out) {
        (out,) = b2b(data, 32);
    }

    /// @notice BLAKE2b with a `outLen`-byte digest (1..64), returned left-aligned in `(lo, hi)`
    ///         (bytes 0..31 in `lo`, 32..63 in `hi`; bytes past `outLen` are zero).
    function b2b(bytes memory data, uint256 outLen) internal view returns (bytes32 lo, bytes32 hi) {
        if (outLen == 0 || outLen > 64) revert BadDigestLength();
        bool ok = true;
        assembly ("memory-safe") {
            let b := mload(0x40) // temporary frame past the free pointer (not allocated)
            mstore(b, shl(224, 12))
            mstore(add(b, 4), xor(IV_LO, shl(248, outLen)))
            mstore(add(b, 36), IV_HI)
            let len := mload(data)
            let blocks := div(add(len, 127), 128)
            if iszero(blocks) { blocks := 1 }
            for { let i := 0 } lt(i, blocks) { i := add(i, 1) } {
                let off := mul(i, 128)
                let last := eq(i, sub(blocks, 1))
                let n := 128
                if last { n := sub(len, off) }
                mstore(add(b, 68), 0)
                mstore(add(b, 100), 0)
                mstore(add(b, 132), 0)
                mstore(add(b, 164), 0)
                mcopy(add(b, 68), add(add(data, 0x20), off), n)
                let t := add(off, n)
                mstore(add(b, 196), shl(248, and(t, 0xff)))
                mstore8(add(b, 197), and(shr(8, t), 0xff))
                mstore8(add(b, 198), and(shr(16, t), 0xff))
                mstore8(add(b, 199), and(shr(24, t), 0xff))
                mstore(add(b, 200), 0)
                mstore8(add(b, 212), last)
                if iszero(staticcall(gas(), 0x09, b, 213, add(b, 4), 64)) { ok := 0 }
            }
            lo := mload(add(b, 4))
            hi := mload(add(b, 36))
        }
        if (!ok) revert Blake2fFailed();
        // Clear bytes beyond outLen.
        if (outLen < 32) {
            lo &= bytes32(~(type(uint256).max >> (outLen * 8)));
            hi = 0;
        } else if (outLen < 64) {
            hi &= bytes32(~(type(uint256).max >> ((outLen - 32) * 8)));
        }
    }
}
