// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title MvxBlake2b
/// @notice BLAKE2b-256 (RFC 7693, unkeyed, 32-byte digest) on the EIP-152 BLAKE2 F precompile (0x09).
///         MultiversX hashes headers (and trie nodes) with BLAKE2b-256.
library MvxBlake2b {
    address internal constant BLAKE2F = address(0x09);

    /// @dev IV with h[0] ^= 0x01010000 ^ (keyLength << 8) ^ digestLength (0, 32), little-endian words.
    bytes internal constant H0 =
        hex"28c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b";

    error Blake2fFailed();

    /// @notice BLAKE2b-256 of `data`.
    function hash256(bytes memory data) internal view returns (bytes32 digest) {
        bytes memory h = H0;
        uint256 len = data.length;
        uint256 blocks = len == 0 ? 1 : (len + 127) / 128;
        for (uint256 i = 0; i < blocks; i++) {
            bytes memory m = new bytes(128);
            uint256 off = i * 128;
            uint256 n = len - off < 128 ? len - off : 128;
            if (len == 0) n = 0;
            assembly ("memory-safe") {
                mcopy(add(m, 0x20), add(add(data, 0x20), off), n)
            }
            bool last = i == blocks - 1;
            uint64 counter = uint64(last ? len : off + 128);
            bytes memory input =
                abi.encodePacked(uint32(12), h, m, _le64(counter), uint64(0), last ? bytes1(0x01) : bytes1(0x00));
            (bool ok, bytes memory out) = BLAKE2F.staticcall(input);
            if (!ok || out.length != 64) revert Blake2fFailed();
            h = out;
        }
        assembly ("memory-safe") {
            digest := mload(add(h, 0x20))
        }
    }

    function _le64(uint64 v) private pure returns (bytes8 r) {
        uint64 x;
        for (uint256 i = 0; i < 8; i++) {
            x = (x << 8) | ((v >> (8 * i)) & 0xff);
        }
        return bytes8(x);
    }
}
