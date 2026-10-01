// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title MvxSha512
/// @notice SHA-512 (FIPS 180-4) in Solidity. The EVM has no SHA-512 precompile; MultiversX's BLS
///         hash-to-G1 (herumi/mcl, original map) starts from SHA-512 of the message.
library MvxSha512 {
    function _k(uint256 i) private pure returns (uint64) {
        bytes memory k = hex"428a2f98d728ae227137449123ef65cdb5c0fbcfec4d3b2fe9b5dba58189dbbc3956c25bf348b53859f111f1b605d019"
            hex"923f82a4af194f9bab1c5ed5da6d8118d807aa98a303024212835b0145706fbe243185be4ee4b28c550c7dc3d5ffb4e2"
            hex"72be5d74f27b896f80deb1fe3b1696b19bdc06a725c71235c19bf174cf692694e49b69c19ef14ad2efbe4786384f25e3"
            hex"0fc19dc68b8cd5b5240ca1cc77ac9c652de92c6f592b02754a7484aa6ea6e4835cb0a9dcbd41fbd476f988da831153b5"
            hex"983e5152ee66dfaba831c66d2db43210b00327c898fb213fbf597fc7beef0ee4c6e00bf33da88fc2d5a79147930aa725"
            hex"06ca6351e003826f142929670a0e6e7027b70a8546d22ffc2e1b21385c26c9264d2c6dfc5ac42aed53380d139d95b3df"
            hex"650a73548baf63de766a0abb3c77b2a881c2c92e47edaee692722c851482353ba2bfe8a14cf10364a81a664bbc423001"
            hex"c24b8b70d0f89791c76c51a30654be30d192e819d6ef5218d69906245565a910f40e35855771202a106aa07032bbd1b8"
            hex"19a4c116b8d2d0c81e376c085141ab532748774cdf8eeb9934b0bcb5e19b48a8391c0cb3c5c95a634ed8aa4ae3418acb"
            hex"5b9cca4f7763e373682e6ff3d6b2b8a3748f82ee5defb2fc78a5636f43172f6084c87814a1f0ab728cc702081a6439ec"
            hex"90befffa23631e28a4506cebde82bde9bef9a3f7b2c67915c67178f2e372532bca273eceea26619cd186b8c721c0c207"
            hex"eada7dd6cde0eb1ef57d4f7fee6ed17806f067aa72176fba0a637dc5a2c898a6113f9804bef90dae1b710b35131c471b"
            hex"28db77f523047d8432caab7b40c724933c9ebe0a15c9bebc431d67c49c100d4c4cc5d4becb3e42b6597f299cfc657e2a"
            hex"5fcb6fab3ad6faec6c44198c4a475817";
        uint64 v;
        assembly ("memory-safe") {
            v := shr(192, mload(add(add(k, 0x20), mul(i, 8))))
        }
        return v;
    }

    function _rotr(uint64 x, uint64 n) private pure returns (uint64) {
        return (x >> n) | (x << (64 - n));
    }

    /// @notice SHA-512 of `data`.
    function hash(bytes memory data) internal pure returns (bytes memory out) {
        uint64[8] memory h = [
            uint64(0x6a09e667f3bcc908),
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179
        ];
        // padding: data ‖ 0x80 ‖ zeros ‖ 128-bit big-endian bit length, to a multiple of 128 bytes
        uint256 len = data.length;
        // forge-lint: disable-next-line(divide-before-multiply)
        uint256 padded = ((len + 17 + 127) / 128) * 128; // rounds up to whole blocks
        bytes memory m = new bytes(padded);
        assembly ("memory-safe") {
            mcopy(add(m, 0x20), add(data, 0x20), len)
        }
        m[len] = 0x80;
        uint256 bits = len * 8;
        for (uint256 i = 0; i < 16; i++) {
            // casting to 'uint8' is safe because it keeps the intended low byte of the shifted length.
            // forge-lint: disable-next-line(unsafe-typecast)
            m[padded - 1 - i] = bytes1(uint8(bits >> (8 * i)));
        }
        uint64[80] memory w;
        unchecked {
            for (uint256 off = 0; off < padded; off += 128) {
                for (uint256 t = 0; t < 16; t++) {
                    uint64 word;
                    assembly ("memory-safe") {
                        word := shr(192, mload(add(add(m, 0x20), add(off, mul(t, 8)))))
                    }
                    w[t] = word;
                }
                for (uint256 t = 16; t < 80; t++) {
                    uint64 s0 = _rotr(w[t - 15], 1) ^ _rotr(w[t - 15], 8) ^ (w[t - 15] >> 7);
                    uint64 s1 = _rotr(w[t - 2], 19) ^ _rotr(w[t - 2], 61) ^ (w[t - 2] >> 6);
                    w[t] = w[t - 16] + s0 + w[t - 7] + s1;
                }
                uint64[8] memory v = [h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]];
                for (uint256 t = 0; t < 80; t++) {
                    uint64 s1 = _rotr(v[4], 14) ^ _rotr(v[4], 18) ^ _rotr(v[4], 41);
                    uint64 ch = (v[4] & v[5]) ^ (~v[4] & v[6]);
                    uint64 t1 = v[7] + s1 + ch + _k(t) + w[t];
                    uint64 s0 = _rotr(v[0], 28) ^ _rotr(v[0], 34) ^ _rotr(v[0], 39);
                    uint64 maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
                    uint64 t2 = s0 + maj;
                    v[7] = v[6];
                    v[6] = v[5];
                    v[5] = v[4];
                    v[4] = v[3] + t1;
                    v[3] = v[2];
                    v[2] = v[1];
                    v[1] = v[0];
                    v[0] = t1 + t2;
                }
                for (uint256 i = 0; i < 8; i++) {
                    h[i] += v[i];
                }
            }
        }
        out = abi.encodePacked(h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
    }
}
