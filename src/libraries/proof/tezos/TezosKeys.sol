// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";

/// @title TezosKeys
/// @notice Signature checks for Tezos tz2 (secp256k1) and tz3 (P-256) consensus keys over a
///         BLAKE2b-256 digest, with the compressed key from the Tezos context and the affine `y`
///         coordinate supplied by the relayer.
///
/// Tezos signs `BLAKE2b-256(watermark ‖ bytes)` with ECDSA for both curves (octez
/// src/lib_crypto/secp256k1.ml, p256.ml); signatures are `r ‖ s` (64 bytes). A compressed key is
/// `0x02|0x03 ‖ x`; the supplied `y` is accepted only if it is on the curve and has the parity the
/// prefix names, so it is the unique point the context key encodes.
library TezosKeys {
    uint256 internal constant SECP_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f;
    uint256 internal constant P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;

    error BadKeyEncoding();

    function _prefixAndX(uint256 keyAt) private pure returns (uint256 prefix, uint256 x) {
        assembly ("memory-safe") {
            prefix := byte(0, mload(keyAt))
            x := mload(add(keyAt, 1))
        }
        if (prefix != 2 && prefix != 3) revert BadKeyEncoding();
    }

    /// @notice tz2: ECDSA/secp256k1 over `digest`, via `ecrecover` (both recovery ids are tried).
    function verifySecp256k1(uint256 keyAt, bytes32 y, bytes32 digest, bytes memory sig) internal pure returns (bool) {
        if (sig.length != 64) return false;
        (uint256 prefix, uint256 x) = _prefixAndX(keyAt);
        uint256 yy = uint256(y);
        if (yy >= SECP_P || (yy & 1) != prefix - 2) return false;
        // y² = x³ + 7
        if (mulmod(yy, yy, SECP_P) != addmod(mulmod(mulmod(x, x, SECP_P), x, SECP_P), 7, SECP_P)) return false;
        address expected = address(uint160(uint256(keccak256(abi.encodePacked(x, yy)))));
        bytes32 r;
        bytes32 s;
        assembly ("memory-safe") {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
        }
        for (uint8 v = 27; v <= 28; v++) {
            address a = ecrecover(digest, v, r, s);
            if (a != address(0) && a == expected) return true;
        }
        return false;
    }

    /// @notice tz3: ECDSA/P-256 over `digest`, in Solidity (no P-256 precompile is assumed). A
    ///         high-`s` signature is checked as `(r, N − s)`, which verifies iff `(r, s)` does.
    function verifyP256(uint256 keyAt, bytes32 y, bytes32 digest, bytes memory sig) internal view returns (bool) {
        if (sig.length != 64) return false;
        (uint256 prefix, uint256 x) = _prefixAndX(keyAt);
        if ((uint256(y) & 1) != prefix - 2) return false;
        bytes32 r;
        uint256 s;
        assembly ("memory-safe") {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
        }
        if (s == 0 || s >= P256_N) return false;
        if (s > P256_N / 2) s = P256_N - s;
        return P256.verifySolidity(digest, r, bytes32(s), bytes32(x), y);
    }
}
