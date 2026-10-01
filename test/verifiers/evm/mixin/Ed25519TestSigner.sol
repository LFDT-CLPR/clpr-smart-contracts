// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @dev Test-only ed25519 arithmetic and Schnorr signing (RFC 8032 verification equation), so tests
///      can produce Mixin kernel CoSi signatures: one signature by the summed private scalars under
///      the summed public keys. Points use extended coordinates with the complete a = -1 addition
///      (add-2008-hwcd-3; d is a non-square, so it also doubles). Not constant time; never deploy.
library Ed25519TestSigner {
    uint256 internal constant P = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
    uint256 internal constant L = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed;
    uint256 internal constant D2 = 0x2406d9dc56dffce7198e80f2eef3d13000e0149a8283b156ebd69b9426b2f159;
    uint256 internal constant BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202;
    uint256 internal constant BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960;

    struct Pt {
        uint256 x;
        uint256 y;
        uint256 z;
        uint256 t;
    }

    function add(Pt memory a, Pt memory b) internal pure returns (Pt memory r) {
        uint256 A = mulmod(addmod(a.y, P - a.x, P), addmod(b.y, P - b.x, P), P);
        uint256 B = mulmod(addmod(a.y, a.x, P), addmod(b.y, b.x, P), P);
        uint256 C = mulmod(mulmod(a.t, D2, P), b.t, P);
        uint256 Dd = mulmod(addmod(a.z, a.z, P), b.z, P);
        uint256 E = addmod(B, P - A, P);
        uint256 F = addmod(Dd, P - C, P);
        uint256 G = addmod(Dd, C, P);
        uint256 H = addmod(B, A, P);
        r = Pt(mulmod(E, F, P), mulmod(G, H, P), mulmod(F, G, P), mulmod(E, H, P));
    }

    function mulBase(uint256 k) internal pure returns (Pt memory r) {
        r = Pt(0, 1, 1, 0);
        Pt memory b = Pt(BX, BY, 1, mulmod(BX, BY, P));
        while (k > 0) {
            if (k & 1 == 1) r = add(r, b);
            b = add(b, b);
            k >>= 1;
        }
    }

    function inv(uint256 a) internal pure returns (uint256 r) {
        r = 1;
        uint256 e = P - 2;
        while (e > 0) {
            if (e & 1 == 1) r = mulmod(r, a, P);
            a = mulmod(a, a, P);
            e >>= 1;
        }
    }

    function affine(Pt memory p) internal pure returns (uint256 x, uint256 y) {
        uint256 zi = inv(p.z);
        x = mulmod(p.x, zi, P);
        y = mulmod(p.y, zi, P);
    }

    function le(uint256 v) internal pure returns (bytes32 b) {
        uint256 out;
        for (uint256 i = 0; i < 32; ++i) {
            out |= ((v >> (8 * i)) & 0xff) << (8 * (31 - i));
        }
        b = bytes32(out);
    }

    function compress(Pt memory p) internal pure returns (bytes32) {
        (uint256 x, uint256 y) = affine(p);
        return le(y | ((x & 1) << 255));
    }

    /// @dev Schnorr: R = rB, k = SHA-512(R ‖ A ‖ M) mod L (digest little-endian), S = r + k·a.
    ///      `sha512` returns the 64-byte digest (the test passes the hasher contract's).
    function sign(uint256 a, uint256 r, bytes memory message, function(bytes memory) view returns (bytes memory) sha512)
        internal
        view
        returns (bytes memory sig)
    {
        bytes32 A = compress(mulBase(a));
        bytes32 R = compress(mulBase(r));
        bytes memory h = sha512(abi.encodePacked(R, A, message));
        uint256 lo;
        uint256 hi;
        for (uint256 i = 0; i < 32; ++i) {
            lo |= uint256(uint8(h[i])) << (8 * i);
            hi |= uint256(uint8(h[32 + i])) << (8 * i);
        }
        uint256 two256 = addmod(type(uint256).max % L, 1, L);
        uint256 k = addmod(lo % L, mulmod(hi % L, two256, L), L);
        uint256 s = addmod(r % L, mulmod(k, a % L, L), L);
        sig = abi.encodePacked(R, le(s));
    }
}
