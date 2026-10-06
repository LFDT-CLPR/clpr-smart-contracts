// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprStateProof} from "@hiero-ledger/clpr/libraries/proof/hiero/ClprStateProof.sol";
import {ClprMerkleProof} from "@hiero-ledger/clpr/libraries/proof/hiero/ClprMerkleProof.sol";

interface IHintsHarness {
    function verifyHintsAggregate(bytes calldata vk, bytes calldata sig, bytes calldata root) external view;
}

interface IWrapsHarness {
    function verify(bytes calldata abProof, bytes calldata hintsVk, bytes calldata ledgerId, address poseidon)
        external
        view;
}

/// @dev On-chain twin of test/verifiers/hiero/GasUsage.t.sol: measures each verifier step with gasleft()
///      so the same breakdown can be read from any live chain through eth_call.
contract HieroGasStepsHarness {
    struct In {
        bytes rawProof;
        bytes ledgerId;
        bytes hintsVk;
        bytes abProof;
        bytes hintsVkN8;
        bytes hintsSigN8;
        bytes blockRootN8;
        address hints;
        address wraps;
        address poseidon;
    }

    /// @return g [decode, merkle1, merkle2, hints, wraps, total]
    function breakdown(In calldata i) external view returns (uint256[6] memory g) {
        uint256 g0 = gasleft();
        ClprStateProof.StateProofDecoded memory sp = ClprStateProof.decode(i.rawProof);
        g[0] = g0 - gasleft();

        g0 = gasleft();
        uint256 baseIdx = ClprMerkleProof.findFirstPath(sp.paths, ClprMerkleProof.LeafKind.StateItemLeaf);
        ClprMerkleProof.computeChainedRoot(sp.paths, baseIdx);
        g[1] = g0 - gasleft();

        g0 = gasleft();
        for (uint256 k = 0; k < sp.paths.length; k++) {
            if (sp.paths[k].stateItemLeaf.length == 0 || baseIdx == k) continue;
            ClprMerkleProof.computeChainedRoot(sp.paths, k);
        }
        g[2] = g0 - gasleft();

        g0 = gasleft();
        IHintsHarness(i.hints).verifyHintsAggregate(i.hintsVkN8, i.hintsSigN8, i.blockRootN8);
        g[3] = g0 - gasleft();

        g0 = gasleft();
        IWrapsHarness(i.wraps).verify(i.abProof, i.hintsVk, i.ledgerId, i.poseidon);
        g[4] = g0 - gasleft();

        g[5] = g[0] + g[1] + g[2] + g[3] + g[4];
    }
}
