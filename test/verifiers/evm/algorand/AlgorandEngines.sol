// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprShake256Engine} from "@hiero-ledger/clpr/libraries/proof/algorand/ClprShake256Engine.sol";
import {ClprSumHash512Engine} from "@hiero-ledger/clpr/libraries/proof/algorand/ClprSumHash512Engine.sol";
import {ClprSumHashTableChunk} from "@hiero-ledger/clpr/libraries/proof/algorand/ClprSumHashTableChunk.sol";

/// @notice Deploys the Algorand hash engines for tests. The SumHash512 nibble table is derived ON CHAIN
///         from the SHAKE256 engine (matrix = SHAKE256(u16 64 ‖ u16 8 ‖ u16 1024 ‖ "Algorand"), 64 KiB),
///         so the engine constructor's pinned chunk code hashes are checked against an independent
///         derivation (the code hashes themselves come from the TypeScript generator).
library AlgorandEngines {
    function deploy() internal returns (address shake, address sumhash) {
        shake = address(new ClprShake256Engine());
        bytes memory table = nibbleTable(shake);
        address[16] memory chunks;
        for (uint256 i = 0; i < 16; i++) {
            bytes memory code = new bytes(16385);
            assembly ("memory-safe") {
                mcopy(add(code, 0x21), add(add(table, 0x20), shl(14, i)), 16384)
            }
            chunks[i] = address(new ClprSumHashTableChunk(code));
        }
        sumhash = address(new ClprSumHash512Engine(chunks));
    }

    function nibbleTable(address shake) internal view returns (bytes memory table) {
        (bool ok, bytes memory m) =
            shake.staticcall(abi.encodePacked(uint8(1), uint32(65536), hex"400008000004", "Algorand"));
        require(ok && m.length == 65536, "matrix");
        // A[i][j] (little-endian u64 at 8·(1024 i + j)) → uint64 array
        uint256[] memory a = new uint256[](8192);
        assembly ("memory-safe") {
            let src := add(m, 0x20)
            let dst := add(a, 0x20)
            for { let k := 0 } lt(k, 8192) { k := add(k, 1) } {
                let w := shr(192, mload(add(src, shl(3, k))))
                let v := 0
                for { let b := 0 } lt(b, 8) { b := add(b, 1) } { v := or(shl(8, v), and(shr(shl(3, b), w), 0xff)) }
                mstore(add(dst, shl(5, k)), v)
            }
        }
        table = new bytes(262144);
        assembly ("memory-safe") {
            let A := add(a, 0x20)
            let T := add(table, 0x20)
            let M := 0xffffffffffffffff
            for { let p := 0 } lt(p, 256) { p := add(p, 1) } {
                for { let v := 1 } lt(v, 16) { v := add(v, 1) } {
                    let w0 := 0
                    let w1 := 0
                    for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                        let s := 0
                        for { let b := 0 } lt(b, 4) { b := add(b, 1) } {
                            if and(shr(b, v), 1) {
                                s := and(add(s, mload(add(A, shl(5, add(shl(10, i), add(shl(2, p), b)))))), M)
                            }
                        }
                        switch lt(i, 4)
                        case 1 { w0 := or(w0, shl(shl(6, i), s)) }
                        default { w1 := or(w1, shl(shl(6, sub(i, 4)), s)) }
                    }
                    let e := add(T, shl(6, add(shl(4, p), v)))
                    mstore(e, w0)
                    mstore(add(e, 32), w1)
                }
            }
        }
    }
}
