// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {StarkTables} from "@hiero-ledger/clpr/libraries/proof/starknet/StarkTables.sol";

/// @title StarkPoseidon
/// @notice Starknet's Poseidon over the STARK field, as cairo-lang `poseidon_utils.py` /
///         `poseidon_hash.py` define it: the Hades permutation on 3 elements (8 full rounds split 4/4
///         around 83 partial rounds, S-box x³, MDS [[3,1,1],[1,-1,1],[1,1,-2]], round constants
///         sha256("Hades" ‖ i) mod p) and the sponge `poseidon_hash_many` (rate 2, capacity 1, input
///         padded with 1 then zeros to an even length).
/// @dev About 20k gas per permutation. Starknet uses it for the class trie and the global state root.
library StarkPoseidon {
    uint256 internal constant P = 0x0800000000000011000000000000000000000000000000000000000000000001;

    error FeltOutOfRange();

    /// @notice poseidon_hash_many(xs). Reverts unless every x < p.
    function hashMany(uint256[] memory xs) internal pure returns (uint256) {
        bytes memory rc = StarkTables.POSEIDON_RC;
        uint256 n = xs.length;
        uint256 s0;
        uint256 s1;
        uint256 s2;
        // Blocks of two; the final block carries the padding 1 (then 0 when n is even).
        for (uint256 i = 0; i <= n; i += 2) {
            uint256 a = i < n ? xs[i] : 1;
            uint256 b = i + 1 < n ? xs[i + 1] : (i + 1 == n ? 1 : 0);
            if (a >= P || b >= P) revert FeltOutOfRange();
            (s0, s1, s2) = hades(rc, addmod(s0, a, P), addmod(s1, b, P), s2);
        }
        return s0;
    }

    /// @notice The Hades permutation; `rc` is {StarkTables.POSEIDON_RC} in memory.
    function hades(bytes memory rc, uint256 s0, uint256 s1, uint256 s2)
        internal
        pure
        returns (uint256, uint256, uint256)
    {
        assembly ("memory-safe") {
            // Opaque p (the free-memory pointer is < 2^255): DUPed, not rebuilt at every use.
            let p := or(0x0800000000000011000000000000000000000000000000000000000000000001, shr(255, mload(0x40)))
            let c := add(rc, 0x20)
            for { let r := 0 } lt(r, 91) { r := add(r, 1) } {
                s0 := addmod(s0, mload(c), p)
                s1 := addmod(s1, mload(add(c, 0x20)), p)
                s2 := addmod(s2, mload(add(c, 0x40)), p)
                c := add(c, 0x60)
                // Full rounds: 0..3 and 87..90.
                if or(lt(r, 4), gt(r, 86)) {
                    s0 := mulmod(mulmod(s0, s0, p), s0, p)
                    s1 := mulmod(mulmod(s1, s1, p), s1, p)
                }
                s2 := mulmod(mulmod(s2, s2, p), s2, p)
                // MDS: t = s0+s1+s2 → (t + 2·s0, t − 2·s1, t − 3·s2).
                let t := addmod(addmod(s0, s1, p), s2, p)
                let n0 := addmod(t, addmod(s0, s0, p), p)
                let n1 := addmod(t, sub(p, addmod(s1, s1, p)), p)
                s2 := addmod(t, sub(p, mulmod(s2, 3, p)), p)
                s0 := n0
                s1 := n1
            }
        }
        return (s0, s1, s2);
    }
}
