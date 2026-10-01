// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {StarkPedersen} from "@hiero-ledger/clpr/libraries/proof/starknet/StarkPedersen.sol";

/// @title StarknetPatricia
/// @notice Proofs against Starknet's binary Merkle-Patricia tries (contract trie, per-contract storage
///         tries; height 251, Pedersen), matching the Starknet docs ("State" → Merkle-Patricia trie) and
///         the `starknet_getStorageProof` node format:
///           binary node  hash = H(left, right)
///           edge node    hash = H(child, path) + length     (path = `length` bits, 1 ≤ length ≤ 251)
///         A leaf (depth 251) is the stored value itself. The empty trie has root 0.
///
/// @dev A proof is a SET of nodes, flattened to 3 words each — binary `[left, right, 0]`, edge
///      `[child, path, length]` — exactly the node set the RPC returns for a batch of keys. Every node is
///      hashed once ({hashNodes}); walks then look nodes up by hash, so nodes shared by several keys
///      cost one Pedersen. A walk returns 0 for a proven absence: the key leaves the trie at an edge
///      whose path disagrees with it (or the root is 0).
library StarknetPatricia {
    uint256 internal constant HEIGHT = 251;
    uint256 internal constant P = 0x0800000000000011000000000000000000000000000000000000000000000001;

    error InvalidTrieNode(uint256 index);
    error MissingTrieNode(uint256 hash, uint256 depth);
    error KeyOutOfRange(uint256 key);

    /// @notice Hash every node of a flattened node set; reverts on a malformed node.
    /// @param tables {StarkPedersen.loadTables} pointer.
    function hashNodes(uint256 tables, uint256[] memory nodes) internal view returns (uint256[] memory hashes) {
        if (nodes.length % 3 != 0) revert InvalidTrieNode(nodes.length);
        uint256 n = nodes.length / 3;
        hashes = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            uint256 a = nodes[3 * i];
            uint256 b = nodes[3 * i + 1];
            uint256 len = nodes[3 * i + 2];
            if (len == 0) {
                hashes[i] = StarkPedersen.hash(tables, a, b);
            } else {
                if (len > HEIGHT || b >> len != 0) revert InvalidTrieNode(i);
                hashes[i] = addmod(StarkPedersen.hash(tables, a, b), len, P);
            }
        }
    }

    /// @notice The value at `key` in the trie with root `root`, given the hashed node set.
    function get(uint256[] memory nodes, uint256[] memory hashes, uint256 root, uint256 key)
        internal
        pure
        returns (uint256 cur)
    {
        if (key >> HEIGHT != 0) revert KeyOutOfRange(key);
        cur = root;
        uint256 depth = 0;
        while (depth < HEIGHT) {
            if (cur == 0) return 0;
            uint256 i = _find(hashes, cur);
            if (i == type(uint256).max) revert MissingTrieNode(cur, depth);
            uint256 len = nodes[3 * i + 2];
            if (len == 0) {
                cur = (key >> (HEIGHT - 1 - depth)) & 1 == 1 ? nodes[3 * i + 1] : nodes[3 * i];
                depth += 1;
            } else {
                if (depth + len > HEIGHT) revert InvalidTrieNode(i);
                uint256 want = (key >> (HEIGHT - depth - len)) & ((1 << len) - 1);
                if (want != nodes[3 * i + 1]) return 0;
                cur = nodes[3 * i];
                depth += len;
            }
        }
    }

    function _find(uint256[] memory hashes, uint256 h) private pure returns (uint256) {
        for (uint256 i = 0; i < hashes.length; i++) {
            if (hashes[i] == h) return i;
        }
        return type(uint256).max;
    }
}
