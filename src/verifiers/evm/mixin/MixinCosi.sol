// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title MixinCosi
/// @notice The aggregate public key of a Mixin kernel CoSi signature: the plain sum of the signers'
///         ed25519 public spend keys, selected by the signature mask (mixin crypto/cosi.go
///         `FullVerify` → crypto/aggregation.go `aggregatePublicKey`: P = Σ points, no coefficients).
///         The collective signature is then one standard ed25519 signature under that key.
/// @dev Keys arrive compressed (32 bytes, little-endian y, sign of x in the top bit). Decompressing
///      each needs a square root (~255 field squarings), so the proof supplies every signer's x and
///      this library checks it instead: x < p, the sign bit, and -x² + y² = 1 + d·x²·y². Points are
///      summed in extended coordinates (add-2008-hwcd-3, a = -1) and normalized with one inversion.
library MixinCosi {
    uint256 internal constant P = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
    uint256 internal constant D = 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3;
    uint256 internal constant D2 = 0x2406d9dc56dffce7198e80f2eef3d13000e0149a8283b156ebd69b9426b2f159; // 2d mod p

    error BadPoint(uint256 index);
    error EmptyAggregate();

    /// @dev Little-endian 32 bytes → integer.
    function le(bytes32 b) internal pure returns (uint256 v) {
        uint256 x = uint256(b);
        for (uint256 i = 0; i < 32; ++i) {
            v |= ((x >> (8 * (31 - i))) & 0xff) << (8 * i);
        }
    }

    function toLe(uint256 v) internal pure returns (bytes32 b) {
        uint256 out;
        for (uint256 i = 0; i < 32; ++i) {
            out |= ((v >> (8 * i)) & 0xff) << (8 * (31 - i));
        }
        b = bytes32(out);
    }

    /// @notice Sum the keys `keys[i]` for set bits i of `mask`, given each one's affine x in order.
    /// @return agg the compressed sum
    /// @return count the number of keys summed
    function aggregate(bytes32[] memory keys, uint256[] memory xs, uint64 mask)
        internal
        view
        returns (bytes32 agg, uint256 count)
    {
        uint256 X;
        uint256 Y;
        uint256 Z;
        uint256 T;
        for (uint256 i = 0; i < 64; ++i) {
            if ((mask >> i) & 1 == 0) continue;
            if (i >= keys.length || count >= xs.length) revert BadPoint(i);
            (uint256 x, uint256 y) = _checked(keys[i], xs[count], i);
            if (count == 0) {
                (X, Y, Z, T) = (x, y, 1, mulmod(x, y, P));
            } else {
                (X, Y, Z, T) = _addAffine(X, Y, Z, T, x, y);
            }
            ++count;
        }
        if (count == 0 || count != xs.length) revert EmptyAggregate();
        uint256 zi = _inv(Z);
        uint256 ax = mulmod(X, zi, P);
        uint256 ay = mulmod(Y, zi, P);
        agg = toLe(ay | ((ax & 1) << 255));
    }

    function _checked(bytes32 key, uint256 x, uint256 index) private pure returns (uint256, uint256) {
        uint256 enc = le(key);
        uint256 y = enc & ((1 << 255) - 1);
        if (y >= P || x >= P || (x & 1) != (enc >> 255)) revert BadPoint(index);
        uint256 x2 = mulmod(x, x, P);
        uint256 y2 = mulmod(y, y, P);
        // -x² + y² == 1 + d x² y²
        if (addmod(P - x2, y2, P) != addmod(1, mulmod(D, mulmod(x2, y2, P), P), P)) revert BadPoint(index);
        return (x, y);
    }

    /// @dev (X1:Y1:Z1:T1) + (x2, y2, 1, x2·y2).
    function _addAffine(uint256 X1, uint256 Y1, uint256 Z1, uint256 T1, uint256 x2, uint256 y2)
        private
        pure
        returns (uint256, uint256, uint256, uint256)
    {
        uint256 a = mulmod(addmod(Y1, P - X1, P), addmod(y2, P - x2, P), P);
        uint256 b = mulmod(addmod(Y1, X1, P), addmod(y2, x2, P), P);
        uint256 c = mulmod(mulmod(T1, D2, P), mulmod(x2, y2, P), P);
        uint256 d = addmod(Z1, Z1, P);
        uint256 e = addmod(b, P - a, P);
        uint256 f = addmod(d, P - c, P);
        uint256 g = addmod(d, c, P);
        uint256 h = addmod(b, a, P);
        return (mulmod(e, f, P), mulmod(g, h, P), mulmod(f, g, P), mulmod(e, h, P));
    }

    function _inv(uint256 z) private view returns (uint256 r) {
        bool ok;
        assembly ("memory-safe") {
            let p := mload(0x40)
            mstore(p, 0x20)
            mstore(add(p, 0x20), 0x20)
            mstore(add(p, 0x40), 0x20)
            mstore(add(p, 0x60), z)
            mstore(add(p, 0x80), sub(P, 2))
            mstore(add(p, 0xa0), P)
            ok := staticcall(gas(), 0x05, p, 0xc0, p, 0x20)
            r := mload(p)
        }
        if (!ok || r == 0) revert EmptyAggregate();
    }
}
