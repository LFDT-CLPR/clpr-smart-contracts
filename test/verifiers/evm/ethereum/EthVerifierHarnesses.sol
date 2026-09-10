// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {EthMainnetVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/EthMainnetVerifier.sol";
import {ClprBeaconSsz} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconSsz.sol";
import {ClprCommitteeMerkle} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprCommitteeMerkle.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @dev Exposes the verifier internals (new sync-committee model) for unit testing.
contract EthMainnetVerifierTestHarness is EthMainnetVerifier {
    constructor() {}

    function decodeTrustAnchor(bytes calldata ta) external pure returns (AnchorScalars memory) {
        return _decodeAnchorScalars(ta);
    }

    /// @dev Committee `i` of the window: its stored aggregate and keccak Merkle root.
    function decodeCommitteeSlot(bytes calldata ta, uint256 i)
        external
        pure
        returns (bytes memory aggregatePubkey, bytes32 committeeRoot)
    {
        if (ta.length != TRUST_ANCHOR_LENGTH) revert InvalidTrustAnchor();
        uint256 off = ANCHOR_OFF_COMMITTEES + i * COMMITTEE_STRIDE;
        aggregatePubkey = ta[off:off + BLS_PUBKEY_LENGTH];
        committeeRoot = bytes32(ta[off + COMMITTEE_OFF_ROOT:off + COMMITTEE_OFF_ROOT + 32]);
    }

    function encodeTrustAnchor(
        AnchorScalars memory scalars,
        bytes[] memory pubkeys,
        bytes memory aggregatePubkey,
        bytes[] memory nextPubkeys,
        bytes memory nextAggregatePubkey
    ) external pure returns (bytes memory) {
        return _encodeTrustAnchor(
            scalars,
            aggregatePubkey,
            ClprCommitteeMerkle.root(pubkeys),
            nextAggregatePubkey,
            ClprCommitteeMerkle.root(nextPubkeys)
        );
    }

    function decodeBundleContent(bytes memory data) external pure returns (bytes[] memory messages) {
        return _decodeBundleContent(data);
    }

    // External wrappers so vm.expectRevert can catch reverts from the internal library functions.
    function merkleizeExt(bytes32[] memory chunks) external pure returns (bytes32) {
        return ClprBeaconSsz.merkleize(chunks);
    }
}

/// @dev Exposes the internal BLS + rotation paths
contract EthMainnetVerifierProofHarness is EthMainnetVerifier {
    constructor() {}

    /// `nonSignerWrapperRlp` is `RLP[nonSignerProofs]` (a single-item outer list), so this mirrors
    /// how `verifyBundle` slices payload item 10 before calling `_verifyBls`.
    function verifyBlsExt(
        bytes calldata trustAnchor,
        bytes memory nonSignerWrapperRlp,
        bytes memory signature,
        bytes memory bits,
        bytes32 beaconBlockRoot,
        bytes memory forkVersion,
        bytes32 gvr
    ) external view {
        Memory.Slice[] memory items = RLP.decodeList(nonSignerWrapperRlp);
        _verifyBls(trustAnchor, COMMITTEE_CURRENT, items[0], signature, bits, beaconBlockRoot, forkVersion, gvr);
    }

    /// `rotationRlp` is `RLP[nextCommittee, nextCommitteeBranch]` (the two bundle items), so this
    /// mirrors how `verifyBundle` slices the payload before calling `_verifyRotation`.
    function verifyRotationExt(
        bytes memory rotationRlp,
        bytes32 stateRoot,
        bytes calldata trustAnchor,
        uint64 signaturePeriod,
        uint64 attestedPeriod,
        uint256 committeeIndex
    ) external view returns (bytes memory) {
        Memory.Slice[] memory items = RLP.decodeList(rotationRlp);
        return
            _verifyRotation(items[0], items[1], stateRoot, trustAnchor, signaturePeriod, attestedPeriod, committeeIndex);
    }

    function verifyProofOrRevertExt(bytes32 leaf, bytes32[] memory proof, bytes32 root, uint256 gindex) external pure {
        ClprBeaconSsz.verifyProofOrRevert(leaf, proof, root, gindex);
    }
}
