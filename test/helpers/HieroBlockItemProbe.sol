// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprStateProof} from "@hiero-ledger/clpr/libraries/proof/hiero/ClprStateProof.sol";
import {ClprMerkleProof} from "@hiero-ledger/clpr/libraries/proof/hiero/ClprMerkleProof.sol";

/// @dev Test-only probe: runs the production `ClprStateProof.decode` and
///      `ClprMerkleProof.computeChainedRoot` over a Hiero `StateProof` whose leaf is a
///      `block_item_leaf`, returning the derived block root and the TSS signature so an
///      e2e test can hand them to the production `TSSVerifier`. Adds no verification logic.
contract HieroBlockItemProbe {
    error NoBlockItemLeaf();

    function blockItemRoot(bytes calldata proofBytes)
        external
        pure
        returns (bytes memory blockRoot, bytes memory blockItem, bytes memory signature)
    {
        ClprStateProof.StateProofDecoded memory sp = ClprStateProof.decode(proofBytes);
        uint256 idx = ClprMerkleProof.findFirstPath(sp.paths, ClprMerkleProof.LeafKind.BlockItemLeaf);
        if (idx == type(uint256).max) revert NoBlockItemLeaf();
        blockRoot = ClprMerkleProof.computeChainedRoot(sp.paths, idx);
        blockItem = sp.paths[idx].blockItemLeaf;
        signature = sp.signature;
    }
}
