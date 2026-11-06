// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {EthMainnetVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/EthMainnetVerifier.sol";
import {EthCommitteeFixtures} from "@test/verifiers/evm/ethereum/EthCommitteeFixtures.sol";
import {
    EthMainnetVerifierTestHarness,
    EthMainnetVerifierProofHarness
} from "@test/verifiers/evm/ethereum/EthVerifierHarnesses.sol";
import {ClprBeaconBls} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconBls.sol";
import {ClprBeaconSsz} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconSsz.sol";
import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";
import {ClprCommitteeMerkle} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprCommitteeMerkle.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @notice Window-encoding behaviour of {EthMainnetVerifier}: which window member verifies a bundle,
///         when the window advances, and what it advances to.
contract EthMainnetWindowTest is EthCommitteeFixtures {
    EthMainnetVerifierTestHarness internal exposed; // anchor codec
    EthMainnetVerifierProofHarness internal harness; // verifyBundle + _verifyRotation, real BLS

    function setUp() public override {
        super.setUp();
        exposed = new EthMainnetVerifierTestHarness();
        harness = new EthMainnetVerifierProofHarness();
    }

    // ── Committee selection ───────────────────────────────────────────────────
    //
    // A 2×2: {signature in the anchor's period, one period ahead} × {signed by current, by next}.
    // Reaching `InvalidBranch` means the BLS pairing SUCCEEDED; `BlsSignatureInvalid` means it failed.

    function test_window_signatureInAnchorPeriod_verifiesAgainstCurrent() public {
        bytes memory anchor = _windowAnchor(exposed, 4, 1); // { C1, C2 }, window covers periods 4 and 5
        bytes memory payload = _bundle(_slotIn(4), _slotIn(4) + 1, 1); // signed in period 4 by C1 = current
        vm.expectRevert(EthMainnetVerifier.InvalidBranch.selector);
        harness.verifyBundle(payload, anchor, "");
    }

    function test_window_signatureOnePeriodAhead_verifiesAgainstNext() public {
        bytes memory anchor = _windowAnchor(exposed, 4, 1); // { C1, C2 }
        bytes memory payload = _bundle(_slotIn(5), _slotIn(5) + 1, 2); // signed in period 5 by C2 = next
        // The whole point of the feature: the chain crossed a boundary and the endpoint submitted
        // nothing at that instant, yet the bundle still verifies.
        vm.expectRevert(EthMainnetVerifier.InvalidBranch.selector);
        harness.verifyBundle(payload, anchor, "");
    }

    function test_window_wrongCommitteeForAnchorPeriod_reverts() public {
        bytes memory anchor = _windowAnchor(exposed, 4, 1);
        bytes memory payload = _bundle(_slotIn(4), _slotIn(4) + 1, 2); // period 4, but signed by C2
        vm.expectRevert(ClprBeaconBls.BlsSignatureInvalid.selector);
        harness.verifyBundle(payload, anchor, "");
    }

    function test_window_wrongCommitteeForNextPeriod_reverts() public {
        bytes memory anchor = _windowAnchor(exposed, 4, 1);
        bytes memory payload = _bundle(_slotIn(5), _slotIn(5) + 1, 1); // period 5, but signed by C1
        vm.expectRevert(ClprBeaconBls.BlsSignatureInvalid.selector);
        harness.verifyBundle(payload, anchor, "");
    }

    // ── Window bounds ─────────────────────────────────────────────────────────

    function test_window_signatureBehindWindow_reverts() public {
        bytes memory anchor = _windowAnchor(exposed, 4, 1);
        bytes memory payload = _bundle(_slotIn(3), _slotIn(3) + 1, 1);
        // The window widens forward only: a retired committee is never retained.
        vm.expectRevert(
            abi.encodeWithSelector(EthMainnetVerifier.SignaturePeriodOutOfWindow.selector, uint64(3), uint64(4))
        );
        harness.verifyBundle(payload, anchor, "");
    }

    function test_window_signatureAheadOfWindow_reverts() public {
        bytes memory anchor = _windowAnchor(exposed, 4, 1);
        bytes memory payload = _bundle(_slotIn(6), _slotIn(6) + 1, 3);
        // A gap: C3 has never been proven to this verifier. §3.2's reactive trigger — the endpoint
        // must advance the window before this bundle can be accepted.
        vm.expectRevert(
            abi.encodeWithSelector(EthMainnetVerifier.SignaturePeriodOutOfWindow.selector, uint64(6), uint64(4))
        );
        harness.verifyBundle(payload, anchor, "");
    }

    // ── signatureSlot bounds ──────────────────────────────────────────────────

    function test_signatureSlot_notAfterAttestedHeader_reverts() public {
        bytes memory anchor = _windowAnchor(exposed, 4, 1);
        bytes memory payload = _bundle(_slotIn(4) + 10, _slotIn(4) + 10, 1); // equal, not strictly after
        vm.expectRevert(
            abi.encodeWithSelector(EthMainnetVerifier.InvalidSignatureSlot.selector, _slotIn(4) + 10, _slotIn(4) + 10)
        );
        harness.verifyBundle(payload, anchor, "");
    }

    function test_signatureSlot_morePeriodsAheadThanAttested_reverts() public {
        // An unbounded signatureSlot is a free committee selector: a submitter could attest an old
        // header and name a slot in whichever period picks the window member it can sign for.
        bytes memory anchor = _windowAnchor(exposed, 4, 1);
        bytes memory payload = _bundle(_slotIn(3), _slotIn(5) + 1, 2);
        vm.expectRevert(
            abi.encodeWithSelector(EthMainnetVerifier.InvalidSignatureSlot.selector, _slotIn(5) + 1, _slotIn(3))
        );
        harness.verifyBundle(payload, anchor, "");
    }

    // ── Advance: widen (in the anchor's own period — the window does not move) ────

    function test_advance_widenInAnchorPeriod_returnsEmptyAnchor() public view {
        // Signed inside the window's own period, proving C2 — which the anchor already holds as
        // `next`. Nothing to advance, so no anchor comes back: returning bytes here would satisfy
        // BundleLib's trust-anchor progress condition for free, forever.
        (bytes memory rotationRlp, bytes32 stateRoot) = _rotationPair(2, "");
        bytes memory anchor = _windowAnchor(exposed, 4, 1);
        bytes memory result = harness.verifyRotationExt(rotationRlp, stateRoot, anchor, 4, 4, 0);
        assertEq(result.length, 0, "widen must return an empty anchor");
    }

    function test_advance_widenWithDifferentCommittee_reverts() public {
        // Two distinct state-proven successors to one period: a corrupted anchor or a chain fork.
        (bytes memory rotationRlp, bytes32 stateRoot) = _rotationPair(3, ""); // proves C3, but `next` is C2
        bytes memory anchor = _windowAnchor(exposed, 4, 1);
        vm.expectRevert(EthMainnetVerifier.WindowNextCommitteeMismatch.selector);
        harness.verifyRotationExt(rotationRlp, stateRoot, anchor, 4, 4, 0);
    }

    // ── Advance: shift ────────────────────────────────────────────────────────

    function test_advance_onePeriodAhead_shiftsWindow() public view {
        (bytes memory rotationRlp, bytes32 stateRoot) = _rotationPair(3, ""); // proves C3
        bytes memory anchor = _windowAnchor(exposed, 4, 1); // { C1, C2 } @ 4
        bytes memory shifted = harness.verifyRotationExt(rotationRlp, stateRoot, anchor, 5, 5, 1);

        assertEq(shifted.length, 428, "window anchor stays 428 bytes");

        EthMainnetVerifier.AnchorScalars memory before = exposed.decodeTrustAnchor(anchor);
        EthMainnetVerifier.AnchorScalars memory got = exposed.decodeTrustAnchor(shifted);
        assertEq(got.period, 5, "window start advances to the signature period");
        assertEq(got.gvr, before.gvr, "gvr survives the advance");
        assertEq(keccak256(got.forkVersion), keccak256(before.forkVersion), "forkVersion survives");
        assertEq(got.channelId, before.channelId, "channelId survives");
        assertEq(got.codeHash, before.codeHash, "codeHash survives");

        (bytes memory oldNextAgg, bytes32 oldNextRoot) = exposed.decodeCommitteeSlot(anchor, 1);
        (bytes memory newCurAgg, bytes32 newCurRoot) = exposed.decodeCommitteeSlot(shifted, 0);
        assertEq(keccak256(newCurAgg), keccak256(oldNextAgg), "current <- old next (aggregate)");
        assertEq(newCurRoot, oldNextRoot, "current <- old next (committee root)");

        (bytes memory newNextAgg, bytes32 newNextRoot) = exposed.decodeCommitteeSlot(shifted, 1);
        assertEq(keccak256(newNextAgg), keccak256(_committeeAggregate(3)), "next <- the freshly proven committee");
        assertEq(newNextRoot, ClprCommitteeMerkle.root(_uncompressedKeys(SYNC_COMMITTEE_SIZE, 3)), "next root");
        assertTrue(keccak256(newCurAgg) != keccak256(newNextAgg), "window members stay distinct");
    }

    function test_advance_straddlingPeriodBoundary_reverts() public {
        // Attested in period 4, signed in period 5: selection would key off C2 while the branch proves
        // the successor of period 4. Application bundles may straddle; advances may not.
        (bytes memory rotationRlp, bytes32 stateRoot) = _rotationPair(3, "");
        bytes memory anchor = _windowAnchor(exposed, 4, 1);
        vm.expectRevert(
            abi.encodeWithSelector(EthMainnetVerifier.RotationPeriodStraddle.selector, uint64(5), uint64(4))
        );
        harness.verifyRotationExt(rotationRlp, stateRoot, anchor, 5, 4, 1);
    }

    // ── Catch-up: period 1 → period 5 (the scenario in the issue) ─────────────

    /// @dev The anchor is installed at period 1 and the source chain is at period 5. The endpoint
    ///      submits one window-advance per period; each is verified under the authority installed by
    ///      its predecessor, so committee history cannot be skipped. After the fourth, the window is
    ///      { C5, C6 } and an application bundle signed in period 5 verifies.
    function test_catchUp_period1ToPeriod5_thenBundleVerifies() public {
        bytes memory anchor = _windowAnchor(exposed, 1, 1); // { C1, C2 } @ period 1

        for (uint64 step = 0; step < 4; step++) {
            uint64 signaturePeriod = 2 + step; // 2, 3, 4, 5
            uint256 provenSk = uint256(signaturePeriod) + 1; // C3, C4, C5, C6
            (bytes memory rotationRlp, bytes32 stateRoot) = _rotationPair(provenSk, "");
            anchor = harness.verifyRotationExt(rotationRlp, stateRoot, anchor, signaturePeriod, signaturePeriod, 1);

            assertEq(exposed.decodeTrustAnchor(anchor).period, signaturePeriod, "window start per step");
            (bytes memory curAgg,) = exposed.decodeCommitteeSlot(anchor, 0);
            (bytes memory nextAgg,) = exposed.decodeCommitteeSlot(anchor, 1);
            assertEq(keccak256(curAgg), keccak256(_committeeAggregate(uint256(signaturePeriod))), "current per step");
            assertEq(keccak256(nextAgg), keccak256(_committeeAggregate(provenSk)), "next per step");
        }

        assertEq(exposed.decodeTrustAnchor(anchor).period, 5, "window ends at period 5");

        bytes memory payload = _bundle(_slotIn(5), _slotIn(5) + 1, 5);
        vm.expectRevert(EthMainnetVerifier.InvalidBranch.selector);
        harness.verifyBundle(payload, anchor, "");

        bytes memory alsoValid = _bundle(_slotIn(6), _slotIn(6) + 1, 6);
        vm.expectRevert(EthMainnetVerifier.InvalidBranch.selector);
        harness.verifyBundle(alsoValid, anchor, "");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// An 11-item bundle payload with a REAL full-participation sync aggregate by committee `sk` over
    /// the attested header. Everything after the BLS step is a placeholder: the execution branch is an
    /// empty list, so a bundle whose signature verifies reverts with `InvalidBranch`.
    function _bundle(uint64 attestedSlot, uint64 signatureSlot, uint256 sk) internal view returns (bytes memory) {
        bytes32 beaconBlockRoot =
            ClprBeaconSsz.beaconBlockHeaderRoot(attestedSlot, 0, bytes32(0), bytes32(0), bytes32(0));
        bytes32 domain = ClprBeaconSsz.computeSyncCommitteeDomain(FORK_VERSION, GVR);
        bytes32 signingRoot = ClprBeaconSsz.computeSigningRoot(beaconBlockRoot, domain);

        bytes[] memory header = new bytes[](5);
        header[0] = RLP.encode(uint256(attestedSlot));
        header[1] = RLP.encode(uint256(0));
        header[2] = RLP.encode(bytes32(0));
        header[3] = RLP.encode(bytes32(0));
        header[4] = RLP.encode(bytes32(0));

        bytes[] memory agg = new bytes[](2);
        agg[0] = RLP.encode(_allOneBits());
        agg[1] = RLP.encode(_aggSig(signingRoot, SYNC_COMMITTEE_SIZE, sk));

        bytes[] memory top = new bytes[](11);
        top[0] = RLP.encode(header);
        top[1] = RLP.encode(uint256(signatureSlot));
        top[2] = RLP.encode(agg);
        top[3] = RLP.encode(bytes32(uint256(0xEE))); // executionStateRoot
        top[4] = hex"c0"; // executionBranch: empty ⇒ InvalidBranch once BLS has passed
        top[5] = hex"80"; // nextCommittee absent
        top[6] = hex"c0"; // nextCommitteeBranch absent
        top[7] = hex"c0"; // accountProof
        top[8] = hex"c0"; // storageProof
        top[9] = RLP.encode(new bytes(0)); // bundleContent
        top[10] = hex"c0"; // nonSignerProofs: empty at full participation
        return RLP.encode(top);
    }
}
