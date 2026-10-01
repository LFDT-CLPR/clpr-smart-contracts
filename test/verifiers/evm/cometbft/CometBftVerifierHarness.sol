// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {CometBftVerifier} from "@hiero-ledger/clpr/verifiers/evm/cometbft/CometBftVerifier.sol";
import {CometBftLib} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftLib.sol";

/// @dev Exposes two production steps of {CometBftVerifier} for live-data replay
///      (test/e2e/tests/verifiers/cometbft-live.spec.ts):
///      - `applyHops`: the light-client step alone (validator set + header + >2/3 commit). It is
///        what a validator-set rotation costs, and it needs no EVM store, so it also measures
///        commits from chains whose app state is not an EVM store (Heimdall, dYdX, Provenance,
///        THORChain).
///      - `verifyStorage`: the full state-proof path (commit → app_hash → store root → IAVL) for
///        arbitrary slots, so a real non-zero slot can be checked with an existence proof.
contract CometBftVerifierHarness is CometBftVerifier {
    constructor(Profile memory p) CometBftVerifier(p) {}

    function applyHops(bytes[] calldata hops, bytes32 setHash, uint64 minHeight)
        external
        view
        returns (bytes32, uint64)
    {
        return _applyHops(hops, setHash, minHeight);
    }

    function verifyStorage(
        bytes calldata stateProof,
        bytes calldata validatorSet,
        bytes32 setHash,
        uint64 minHeight,
        bytes20 serviceAddr
    ) external view returns (int64 height, bytes32[] memory slotNumbers, bytes32[] memory slotValues) {
        Validator[] memory vals = _parseValidatorSet(validatorSet, setHash);
        CometBftLib.SeiHeader memory header;
        (header, slotValues, slotNumbers,) = _verifyStateProof(stateProof, vals, setHash, minHeight, serviceAddr);
        height = header.height;
    }
}
