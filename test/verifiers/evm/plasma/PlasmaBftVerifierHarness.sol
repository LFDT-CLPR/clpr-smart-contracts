// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {PlasmaBftVerifier} from "@hiero-ledger/clpr/verifiers/evm/plasma/PlasmaBftVerifier.sol";
import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";

/// @dev Exposes the production verifier's SSZ helpers so synthetic tests can build consensus
///      blocks and QCs. The live-data suite checks the same formulas against real Plasma blocks.
contract PlasmaBftVerifierHarness is PlasmaBftVerifier {
    constructor(Profile memory p) PlasmaBftVerifier(p) {}

    /// @dev SSZ List[Bytes48, 1024] root of `keys` (EIP-2537 uncompressed G1, already sorted).
    function committeeRoot(bytes calldata keys) external pure returns (bytes32) {
        uint256 n = keys.length / 128;
        bytes32[] memory layer = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            bytes memory c = ClprBls12381.compressG1(keys[i * 128:(i + 1) * 128]);
            layer[i] = sha256(abi.encodePacked(c, bytes16(0)));
        }
        return _mixLength(_merkleizeLimit(layer, COMMITTEE_LIST_DEPTH), n);
    }

    function blockHash(bytes32[] calldata leaves) external pure returns (bytes32) {
        return _blockHash(leaves);
    }

    function qcRoot(
        uint64 proposer,
        uint64 height,
        uint64[] calldata votes,
        bytes calldata sig96,
        uint64 view_,
        bytes32 hash
    ) external pure returns (bytes32) {
        Qc memory q;
        (q.proposer, q.height, q.votes, q.sig96) = (proposer, height, votes, sig96);
        return _qcRoot(q, view_, hash);
    }

    function compressG1(bytes calldata u) external pure returns (bytes memory) {
        return ClprBls12381.compressG1(u);
    }
}
