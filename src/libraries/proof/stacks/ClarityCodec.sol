// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Sha512t256Call} from "@hiero-ledger/clpr/libraries/crypto/ClprSha512t256Hasher.sol";

/// @title ClarityCodec
/// @notice The pieces of Clarity's storage encoding a Stacks state proof needs.
///
/// A Clarity data-map entry lives in the MARF under the key string
///   `vm::<contract principal>::0::<map name>::<hex(serialize(key))>`      (StoreType::DataMap = 0)
/// and the trie path is SHA-512/256 of that string. The leaf value is SHA-512/256 of the lowercase
/// hex of `serialize(some(value))` (clarity_db.rs `make_key_for_quad`, `put_value_with_size`;
/// index/mod.rs `MARFValue::from_value`). Values use Clarity's consensus serialization
/// (clarity-types serialization.rs): uint = 0x01 ‖ u128, buff = 0x02 ‖ u32 len ‖ bytes,
/// some = 0x0a ‖ v, list = 0x0b ‖ u32 n ‖ items, tuple = 0x0c ‖ u32 n ‖ (u8 len ‖ name ‖ v)…
/// with tuple fields in byte order of their names, standard principal = 0x05 ‖ version ‖ hash160.
library ClarityCodec {
    error SignerListMalformed();
    error UnexpectedPrincipalVersion(uint8 version);
    error WeightTooLarge();

    bytes16 private constant HEX = "0123456789abcdef";

    /// @notice Lowercase hex (no 0x) of `b`.
    function toHex(bytes memory b) internal pure returns (bytes memory out) {
        uint256 n = b.length;
        out = new bytes(2 * n);
        assembly ("memory-safe") {
            let src := add(b, 0x20)
            let dst := add(out, 0x20)
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let c := byte(0, mload(add(src, i)))
                mstore8(add(dst, mul(i, 2)), byte(shr(4, c), HEX))
                mstore8(add(dst, add(mul(i, 2), 1)), byte(and(c, 0x0f), HEX))
            }
        }
    }

    /// @notice MARF leaf value hash of a stored Clarity value: H(hex(serialized)).
    function valueHash(address hasher, bytes memory serialized) internal view returns (bytes32) {
        return Sha512t256Call.hash(hasher, toHex(serialized));
    }

    /// @notice MARF path of a data-map entry.
    function mapEntryPath(
        address hasher,
        bytes memory contractPrincipal,
        bytes memory mapName,
        bytes memory keySerialized
    ) internal view returns (bytes32) {
        return Sha512t256Call.hash(
            hasher, bytes.concat("vm::", contractPrincipal, "::0::", mapName, "::", toHex(keySerialized))
        );
    }

    /// @notice Serialized Clarity `uint`.
    function uintValue(uint128 v) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0x01), v);
    }

    /// @notice Serialized Clarity `(buff 32)`.
    function buff32(bytes32 v) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0x02), uint32(32), v);
    }

    /// @notice Parse `some(list {signer: principal, weight: uint})`, the value of `.signers`
    ///         `cycle-signer-set` (signers.clar), in reward-set order.
    /// @param principalVersion the p2pkh address version every signer must use (22 mainnet, 26 testnet)
    function parseSignerList(bytes memory v, uint8 principalVersion)
        internal
        pure
        returns (bytes20[] memory keyHashes, uint64[] memory weights)
    {
        // 0x0a 0x0b u32 n, then n × [0x0c 00000002 06"signer" 05 ver h160(20) 06"weight" 01 u128] = 58 bytes
        if (v.length < 6 || v[0] != 0x0a || v[1] != 0x0b) revert SignerListMalformed();
        uint256 n;
        assembly ("memory-safe") {
            n := shr(224, mload(add(v, 0x22))) // u32 list length at offset 2
        }
        if (v.length != 6 + 58 * n) revert SignerListMalformed();
        keyHashes = new bytes20[](n);
        weights = new uint64[](n);
        // fixed bytes of an entry: 13 before the version byte, 8 between the hash160 and the u128
        uint256 head =
            uint256(bytes32(abi.encodePacked(uint8(0x0c), uint32(2), uint8(6), "signer", uint8(0x05)))) >> 152;
        uint256 mid = uint256(bytes32(abi.encodePacked(uint8(6), "weight", uint8(0x01)))) >> 192;
        for (uint256 i = 0; i < n; ++i) {
            uint256 a;
            uint256 ver;
            bytes20 h;
            uint256 b;
            uint256 w;
            assembly ("memory-safe") {
                let p := add(add(v, 0x26), mul(i, 58))
                a := shr(152, mload(p)) // bytes 0..12
                ver := byte(13, mload(p))
                h := and(mload(add(p, 14)), not(sub(shl(96, 1), 1))) // bytes 14..33
                b := shr(192, mload(add(p, 34))) // bytes 34..41
                w := shr(128, mload(add(p, 42))) // bytes 42..57, u128
            }
            if (a != head || b != mid) revert SignerListMalformed();
            // casting to 'uint8' is safe because `ver` is a single byte
            // forge-lint: disable-next-line(unsafe-typecast)
            if (ver != principalVersion) revert UnexpectedPrincipalVersion(uint8(ver));
            if (w > type(uint64).max) revert WeightTooLarge();
            keyHashes[i] = h;
            // casting to 'uint64' is safe because of the bound checked above
            // forge-lint: disable-next-line(unsafe-typecast)
            weights[i] = uint64(w);
        }
    }
}
