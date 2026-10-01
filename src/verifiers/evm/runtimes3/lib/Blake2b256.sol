// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title Blake2b256
/// @notice BLAKE2b with a 32-byte digest and no key (RFC 7693), Waves' `fastHash`, on the EIP-152
///         BLAKE2 F precompile (address 0x09, 12 rounds per 128-byte block).
library Blake2b256 {
    address internal constant BLAKE2F = address(0x09);

    error Blake2fFailed();

    /// @dev Initial state words h[0..7] as little-endian bytes: IV with h[0] ^= 0x01010020
    ///      (digest length 32, key length 0, fanout 1, depth 1).
    bytes internal constant H0 =
        hex"28c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b";

    function hash(bytes memory data) internal view returns (bytes32 digest) {
        bytes memory h = H0;
        uint256 n = data.length;
        uint256 blocks = n == 0 ? 1 : (n + 127) / 128;
        for (uint256 i = 0; i < blocks; i++) {
            bytes memory m = new bytes(128);
            uint256 off = i * 128;
            uint256 take = n - off < 128 ? n - off : 128;
            if (n == 0) take = 0;
            assembly ("memory-safe") {
                mcopy(add(m, 0x20), add(add(data, 0x20), off), take)
            }
            bool last = i + 1 == blocks;
            uint64 t = uint64(last ? n : off + 128);
            bytes memory input = abi.encodePacked(uint32(12), h, m, _le64(t), uint64(0), last ? uint8(1) : uint8(0));
            (bool ok, bytes memory out) = BLAKE2F.staticcall(input);
            if (!ok || out.length != 64) revert Blake2fFailed();
            h = out;
        }
        assembly ("memory-safe") {
            digest := mload(add(h, 0x20))
        }
    }

    function _le64(uint64 v) private pure returns (bytes8 out) {
        uint64 r;
        for (uint256 i = 0; i < 8; i++) {
            r = (r << 8) | ((v >> (8 * i)) & 0xff);
        }
        out = bytes8(r);
    }
}
