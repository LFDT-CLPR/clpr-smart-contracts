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
}
