// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {TempoSyntheticProofs} from "@test/helpers/TempoSyntheticProofs.sol";
import {ClprTempoCertificate} from "@hiero-ledger/clpr/libraries/proof/tempo/ClprTempoCertificate.sol";

/// @dev Wrapper so reverts surface through an external call.
contract TempoCertificateHarness {
    function parseProposal(bytes memory data) external pure returns (ClprTempoCertificate.Proposal memory) {
        return ClprTempoCertificate.parseProposal(data);
    }

    function dkgOutcomeKey(bytes memory extraData) external pure returns (uint64, bytes memory) {
        return ClprTempoCertificate.dkgOutcomeKey(extraData);
    }
}

/// @title ClprTempoCertificateTest
/// @notice Proposal, varint, and DKG-outcome readers on mainnet bytes and edge cases.
contract ClprTempoCertificateTest is TempoSyntheticProofs {
    TempoCertificateHarness internal h;

    function setUp() public {
        h = new TempoCertificateHarness();
    }

    function test_parseProposal_mainnetTip() public view {
        TempoFixture memory f = _loadTempoFixture("presto-tip");
        ClprTempoCertificate.Proposal memory p = h.parseProposal(f.proposal);
        assertEq(p.epoch, f.epoch, "epoch");
        assertEq(p.payload, f.digest, "payload is the block hash");
        assertEq(p.payload, keccak256(f.headerRlp), "block hash is keccak of the outer Tempo header");
        assertEq(p.epoch, f.blockNumber / 21600, "epoch = height / epochLength on mainnet");
        assertEq(p.parentView + 1, p.viewNumber, "consecutive views in steady state");
    }

    function test_finalizeMessage_prefixesLengthAndNamespace() public pure {
        bytes memory m = ClprTempoCertificate.finalizeMessage(hex"aa");
        assertEq(m, abi.encodePacked(bytes1(0x0e), "TEMPO_FINALIZE", hex"aa"));
    }

    function test_dkgOutcomeKey_mainnetBoundaryBlock() public view {
        TempoFixture memory f = _loadTempoFixture("presto-boundary");
        // extraData is inner header field 12.
        bytes memory extraData = _extraDataOf(f.headerRlp);
        (uint64 epoch, bytes memory key) = h.dkgOutcomeKey(extraData);
        assertEq(epoch, f.epoch + 1, "the last block of epoch e carries the outcome for e+1");
        assertEq(key, _loadTempoNextKey("presto-boundary"), "constant term of the public polynomial is the group key");
    }

    // ── proposal / outcome shape ────────────────────────────────────────────

    function test_parseProposal_rejectsWrongPayloadLength() public {
        vm.expectRevert(ClprTempoCertificate.InvalidProposal.selector);
        h.parseProposal(abi.encodePacked(_varint(1), _varint(2), _varint(1), bytes31(0)));
        vm.expectRevert(ClprTempoCertificate.InvalidProposal.selector);
        h.parseProposal(abi.encodePacked(_varint(1), _varint(2), _varint(1), bytes32(0), bytes1(0)));
    }

    function test_dkgOutcomeKey_rejectsShortAndEmptyOutcomes() public {
        vm.expectRevert(ClprTempoCertificate.InvalidDkgOutcome.selector);
        h.dkgOutcomeKey(abi.encodePacked(_varint(7), bytes32(0))); // ends inside the fixed fields
        vm.expectRevert(ClprTempoCertificate.InvalidDkgOutcome.selector);
        h.dkgOutcomeKey(abi.encodePacked(_varint(7), bytes32(0), bytes1(0), bytes4(0), _varint(0))); // no coefficients
        vm.expectRevert(ClprTempoCertificate.InvalidDkgOutcome.selector);
        h.dkgOutcomeKey(abi.encodePacked(_varint(7), bytes32(0), bytes1(0), bytes4(0), _varint(1), new bytes(95)));
    }

    function test_dkgOutcomeKey_syntheticOutcome() public view {
        bytes memory key = new bytes(96);
        key[0] = 0xaa;
        key[95] = 0xbb;
        (uint64 epoch, bytes memory got) = h.dkgOutcomeKey(_dkgOutcome(1234, key));
        assertEq(epoch, 1234);
        assertEq(got, key);
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    function _extraDataOf(bytes memory tempoHeader) internal pure returns (bytes memory) {
        return _innerField(tempoHeader, 12);
    }
}
