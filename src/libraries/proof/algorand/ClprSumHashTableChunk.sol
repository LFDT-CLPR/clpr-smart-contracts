// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title ClprSumHashTableChunk
/// @notice A data contract: its runtime code is the constructor argument (`0x00 ‖ data`; the leading STOP
///         makes a call a no-op). Holds one 16 KiB chunk of the SumHash512 nibble table, or the chunk
///         index of {ClprSumHash512Engine}.
contract ClprSumHashTableChunk {
    constructor(bytes memory code) {
        assembly {
            return(add(code, 0x20), mload(code))
        }
    }
}
