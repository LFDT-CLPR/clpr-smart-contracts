// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

struct ValidatorSet {
    address[] members;
}

enum QbftValidatorMode {
    Header,
    Contract
}

/// @title QbftValidators
/// @notice Shared helpers for a QBFT validator set: the quorum size and a commitment.
library QbftValidators {
    /// @notice The seals a header needs for finality over `n` validators.
    /// @dev (2 * n + 2) / 3 is equivalent to ceil(2n / 3).
    function quorum(uint256 n) internal pure returns (uint256) {
        return (2 * n + 2) / 3;
    }

    function commit(ValidatorSet memory s) internal pure returns (bytes32) {
        return keccak256(abi.encode(s.members));
    }

    function sortedDedup(address[] memory input) internal pure returns (address[] memory out) {
        uint256 n = input.length;
        for (uint256 i = 1; i < n;) {
            address key = input[i];
            uint256 j = i;
            while (j > 0 && uint160(input[j - 1]) > uint160(key)) {
                input[j] = input[j - 1];
                unchecked {
                    j--;
                }
            }
            input[j] = key;
            unchecked {
                i++;
            }
        }
        uint256 unique;
        for (uint256 i = 0; i < n;) {
            if (i == 0 || input[i] != input[i - 1]) {
                input[unique] = input[i];
                unchecked {
                    unique++;
                }
            }
            unchecked {
                i++;
            }
        }
        out = new address[](unique);
        for (uint256 i = 0; i < unique;) {
            out[i] = input[i];
            unchecked {
                i++;
            }
        }
    }

    /// @notice Sort `members` ascending IN PLACE and return the number of distinct members.
    /// @dev For callers that reject duplicates anyway ({QbftContractValidatorSource-resolveSet}) this
    ///      replaces {sortedDedup}: no compaction pass and no copy into a fresh array. Insertion sort
    ///      in assembly; every caller caps the list at `ClprQbftQuorum.MAX_VALIDATORS` first.
    function sortInPlace(address[] memory members) internal pure returns (uint256 distinct) {
        assembly ("memory-safe") {
            let n := mload(members)
            let base := add(members, 0x20)
            let end := add(base, shl(5, n))
            for { let p := add(base, 0x20) } lt(p, end) { p := add(p, 0x20) } {
                let v := mload(p)
                let q := p
                for {} gt(q, base) {} {
                    let prev := mload(sub(q, 0x20))
                    if iszero(gt(prev, v)) { break }
                    mstore(q, prev)
                    q := sub(q, 0x20)
                }
                mstore(q, v)
            }
            if n {
                distinct := 1
                for { let p := add(base, 0x20) } lt(p, end) { p := add(p, 0x20) } {
                    distinct := add(distinct, iszero(eq(mload(p), mload(sub(p, 0x20)))))
                }
            }
        }
    }

    /// @notice True when two sorted, deduped member lists are equal.
    function equals(address[] memory a, address[] memory b) internal pure returns (bool) {
        if (a.length != b.length) return false;
        for (uint256 i = 0; i < a.length;) {
            if (a[i] != b[i]) return false;
            unchecked {
                i++;
            }
        }
        return true;
    }
}
