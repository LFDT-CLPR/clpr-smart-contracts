// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";
import {MerklePatriciaProof} from "@hiero-ledger/clpr/libraries/proof/evm/MerklePatriciaProof.sol";
import {RlpCursor} from "@hiero-ledger/clpr/libraries/proof/evm/RlpCursor.sol";

/// @title MptWalk
/// @notice Test-side conveniences over the production range walk: copy the proven value out of the
///         proof buffer as `bytes`. Production never copies (see `ClprEvmStateProof`), so these
///         wrappers live in `test/` — they exist only so assertions can compare byte strings.
library MptWalk {
    /// @dev Strict walk; returns the RLP-encoded leaf value copied out of the proof.
    function verifyInclusion(bytes32 root, bytes32 keyHash, Memory.Slice proofItem)
        internal
        pure
        returns (bytes memory)
    {
        (uint256 valuePtr, uint256 valueLen) = MerklePatriciaProof.requireValueRange(root, keyHash, proofItem);
        return _copyOut(proofItem, valuePtr, valueLen);
    }

    /// @dev Lenient walk; empty bytes when the key is absent.
    function getOrEmpty(bytes32 root, bytes32 keyHash, Memory.Slice proofItem) internal pure returns (bytes memory) {
        (uint256 valuePtr, uint256 valueLen) = MerklePatriciaProof.valueRangeOrZero(root, keyHash, proofItem);
        return valuePtr == 0 ? bytes("") : _copyOut(proofItem, valuePtr, valueLen);
    }

    /// @dev The range `[valuePtr, valuePtr + valueLen)` — inside `proofItem` by construction as
    ///      fresh `bytes`, through OZ's bounds-checked `Memory.slice` + `Memory.toBytes`.
    function _copyOut(Memory.Slice proofItem, uint256 valuePtr, uint256 valueLen) private pure returns (bytes memory) {
        (uint256 ptr,) = RlpCursor.bounds(proofItem);
        return Memory.toBytes(Memory.slice(proofItem, valuePtr - ptr, valueLen));
    }
}
