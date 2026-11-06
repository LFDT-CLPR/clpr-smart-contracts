// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @title MptWire
/// @notice The one place the MPT proof wire shape (and the synthetic single-leaf node) is built
///         in tests.
library MptWire {
    /// @dev Raw node bytes → `RLP([RLP(node0), RLP(node1), ...])`, the proof item the walker consumes.
    function wrap(bytes[] memory nodes) internal pure returns (bytes memory) {
        bytes[] memory wrapped = new bytes[](nodes.length);
        for (uint256 i = 0; i < nodes.length; i++) {
            wrapped[i] = RLP.encode(nodes[i]);
        }
        return RLP.encode(wrapped);
    }

    /// @dev {wrap} for a one-node proof.
    function wrapOne(bytes memory node) internal pure returns (bytes memory) {
        bytes[] memory nodes = new bytes[](1);
        nodes[0] = node;
        return wrap(nodes);
    }

    /// @dev A leaf node covering the full 64-nibble `keyHash` path (compact prefix 0x20 = leaf,
    ///      even) whose value item is `valueItem` — already RLP-encoded, so tests can plant a list
    ///      or malformed item where a byte string belongs.
    function leaf(bytes32 keyHash, bytes memory valueItem) internal pure returns (bytes memory) {
        bytes memory path = new bytes(33);
        path[0] = 0x20;
        for (uint256 i = 0; i < 32; i++) {
            path[i + 1] = keyHash[i];
        }
        bytes[] memory items = new bytes[](2);
        items[0] = RLP.encode(path);
        items[1] = valueItem;
        return RLP.encode(items);
    }

    /// @dev A leaf node hanging directly off a root branch: covers the 63 nibbles of `keyHash`
    ///      after the first, which the branch consumed (compact prefix 0x3 = leaf, odd).
    function leafAfterBranch(bytes32 keyHash, bytes memory valueItem) internal pure returns (bytes memory) {
        bytes memory path = new bytes(32);
        path[0] = bytes1(0x30 | (uint8(keyHash[0]) & 0x0f));
        for (uint256 i = 1; i < 32; i++) {
            path[i] = keyHash[i];
        }
        bytes[] memory items = new bytes[](2);
        items[0] = RLP.encode(path);
        items[1] = valueItem;
        return RLP.encode(items);
    }

    /// @dev A 17-item branch node whose child at nibble `i` is `children[i]` by hash, or empty
    ///      when `children[i]` is zero; the terminal value is empty.
    function branch(bytes32[16] memory children) internal pure returns (bytes memory) {
        bytes[] memory items = new bytes[](17);
        for (uint256 i = 0; i < 16; i++) {
            items[i] = children[i] == bytes32(0) ? RLP.encode(new bytes(0)) : RLP.encode(children[i]);
        }
        items[16] = RLP.encode(new bytes(0));
        return RLP.encode(items);
    }
}
