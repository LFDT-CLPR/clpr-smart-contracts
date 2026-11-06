// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {EthMainnetVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/EthMainnetVerifier.sol";
import {EthCommitteeFixtures} from "@test/verifiers/evm/ethereum/EthCommitteeFixtures.sol";
import {
    EthMainnetVerifierTestHarness,
    EthMainnetVerifierProofHarness
} from "@test/verifiers/evm/ethereum/EthVerifierHarnesses.sol";
import {ClprBeaconSsz} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconSsz.sol";
import {ClprCommitteeMerkle} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprCommitteeMerkle.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {ClprBeaconBls} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconBls.sol";
import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";

/// @dev Unit tests for the sync-committee EthMainnetVerifier: the SSZ primitives, the RLP
///      trust-anchor round-trip, the decoders, verifyConfig, payload-shape and supermajority guards.
///      Full real-BLS verifyBundle (committee + signature + MPT/SSZ proofs) is covered end-to-end in
///      test/e2e/tests/verifiers/eth-verifier.spec.ts.
contract EthMainnetVerifierTest is EthCommitteeFixtures {
    address internal constant SERVICE_ADDR = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;

    bytes32 internal constant BEACON_BLOCK_ROOT = bytes32(uint256(0x1234));
    uint64 internal constant ANCHOR_PERIOD = 4; // window { C4, C5 } for the shape/guard tests

    EthMainnetVerifierTestHarness internal exposed; // BLS-bypass harness + exposed internals
    EthMainnetVerifierProofHarness internal harness; // Exposing bls (not bypassed)

    function setUp() public override {
        super.setUp();
        exposed = new EthMainnetVerifierTestHarness();
        harness = new EthMainnetVerifierProofHarness();
    }

    // ── Constant lockstep (committee size ↔ tree depth) ──────────────────────

    function test_committeeMerkle_constantsConsistent() public pure {
        assertEq(ClprCommitteeMerkle.COMMITTEE_SIZE, ClprBeaconSsz.SYNC_COMMITTEE_SIZE, "size mirrors SSZ constant");
        assertEq(uint256(1) << ClprCommitteeMerkle.DEPTH, ClprCommitteeMerkle.COMMITTEE_SIZE, "DEPTH = log2(size)");
    }

    // ── SSZ: beacon header root ───────────────────────────────────────────────

    function test_beaconBlockHeaderRoot_deterministic_nonZero() public pure {
        bytes32 r1 = ClprBeaconSsz.beaconBlockHeaderRoot(
            1000, 42, bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3))
        );
        bytes32 r2 = ClprBeaconSsz.beaconBlockHeaderRoot(
            1000, 42, bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3))
        );
        assertEq(r1, r2);
        assertTrue(r1 != bytes32(0));
    }

    // ── SSZ: Merkle branch ────────────────────────────────────────────────────

    function test_verifyProof_twoLeafTree() public pure {
        bytes32 left = keccak256("left");
        bytes32 right = keccak256("right");
        bytes32 root = sha256(abi.encodePacked(left, right));

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = right;
        assertTrue(ClprBeaconSsz.verifyProof(left, proof, root, 2)); // left child, gindex 2
        proof[0] = left;
        assertTrue(ClprBeaconSsz.verifyProof(right, proof, root, 3)); // right child, gindex 3
        // wrong root → false
        proof[0] = right;
        assertFalse(ClprBeaconSsz.verifyProof(left, proof, bytes32(uint256(1)), 2));
    }

    // ── SSZ: merkleize ────────────────────────────────────────────────────────

    function test_merkleize_matchesManualFold() public pure {
        bytes32[] memory leaves = new bytes32[](4);
        leaves[0] = keccak256("a");
        leaves[1] = keccak256("b");
        leaves[2] = keccak256("c");
        leaves[3] = keccak256("d");
        bytes32 expected = sha256(
            abi.encodePacked(
                sha256(abi.encodePacked(keccak256("a"), keccak256("b"))),
                sha256(abi.encodePacked(keccak256("c"), keccak256("d")))
            )
        );
        assertEq(ClprBeaconSsz.merkleize(leaves), expected);
    }

    function test_merkleize_revertsOnNonPowerOfTwo() public {
        bytes32[] memory leaves = new bytes32[](3);
        vm.expectRevert(ClprBeaconSsz.ChunksNotPowerOfTwo.selector);
        exposed.merkleizeExt(leaves);
    }

    // ── SSZ: sync-committee domain + root ─────────────────────────────────────

    function test_computeSyncCommitteeDomain_prefixAndDeterminism() public pure {
        bytes32 d1 = ClprBeaconSsz.computeSyncCommitteeDomain(FORK_VERSION, GVR);
        bytes32 d2 = ClprBeaconSsz.computeSyncCommitteeDomain(FORK_VERSION, GVR);
        assertEq(d1, d2);

        // casting to 'bytes4' is safe because we know what value is here (test data):
        // Top 4 bytes are DOMAIN_SYNC_COMMITTEE = 0x07000000.
        // forge-lint: disable-next-line(unsafe-typecast)
        assertEq(bytes4(d1), bytes4(0x07000000));
        // Different fork/gvr ⇒ different domain.
        assertTrue(ClprBeaconSsz.computeSyncCommitteeDomain(0x05000000, GVR) != d1);
    }

    // ── Trust anchor round-trip ───────────────────────────────────────────────

    function test_trustAnchor_encodeDecode_roundtrip() public view {
        bytes[] memory pubkeys = _pubkeys(0x33);
        bytes memory agg = _pubkey(0x44);
        bytes[] memory nextPubkeys = _pubkeys(0x55);
        bytes memory nextAgg = _pubkey(0x66);
        EthMainnetVerifier.AnchorScalars memory scalars = _scalars(ANCHOR_PERIOD);
        bytes memory anchor = exposed.encodeTrustAnchor(scalars, pubkeys, agg, nextPubkeys, nextAgg);
        assertEq(anchor.length, 428, "window anchor is 428 bytes");

        EthMainnetVerifier.AnchorScalars memory got = exposed.decodeTrustAnchor(anchor);
        assertEq(got.gvr, GVR);
        assertEq(keccak256(got.forkVersion), keccak256(scalars.forkVersion));
        assertEq(got.channelId, CHANNEL_ID);
        assertEq(got.codeHash, SERVICE_CODE_HASH, "code hash committed");
        assertEq(got.period, ANCHOR_PERIOD, "window start period committed");

        (bytes memory gotAgg, bytes32 gotRoot) = exposed.decodeCommitteeSlot(anchor, 0);
        assertEq(keccak256(gotAgg), keccak256(agg), "current aggregate");
        assertEq(gotRoot, ClprCommitteeMerkle.root(pubkeys), "current committee Merkle root");

        (bytes memory gotNextAgg, bytes32 gotNextRoot) = exposed.decodeCommitteeSlot(anchor, 1);
        assertEq(keccak256(gotNextAgg), keccak256(nextAgg), "next aggregate");
        assertEq(gotNextRoot, ClprCommitteeMerkle.root(nextPubkeys), "next committee Merkle root");

        // The two members must be independently addressable — a stride bug would alias them.
        assertTrue(keccak256(gotAgg) != keccak256(gotNextAgg), "window members are distinct");
    }

    function test_decodeTrustAnchor_revertsOnWrongLength() public {
        // Flat anchor is fixed-length; anything else is rejected up front.
        vm.expectRevert(EthMainnetVerifier.InvalidTrustAnchor.selector);
        exposed.decodeTrustAnchor(hex"deadbeef");
    }

    // ── verifyConfig (empty bootstrap) ────────────────────────────────────────

    function test_verifyConfig_emptyInput_reverts() public {
        vm.expectRevert(EthMainnetVerifier.InvalidPayloadShape.selector);
        exposed.verifyConfig("", bytes32(0), "");
    }

    // ── verifyBundle shape + supermajority ────────────────────────────────────

    function test_verifyBundle_revertsOnWrongPayloadShape() public {
        bytes[] memory items = new bytes[](3);
        items[0] = RLP.encode(uint256(0));
        items[1] = RLP.encode(uint256(0));
        items[2] = RLP.encode(uint256(0));
        bytes memory payload = RLP.encode(items);
        bytes memory anchor = _anchor(); // precompute (external call) before arming expectRevert
        vm.expectRevert(EthMainnetVerifier.InvalidPayloadShape.selector);
        exposed.verifyBundle(payload, anchor, "");
    }

    /// @dev The sync aggregate carries an all-zero participation bitvector ⇒ zero participants ⇒ below
    ///      the 2/3 supermajority, so `_verifyBls` reverts at the supermajority gate (before any
    ///      EIP-2537 precompile call), which is why this runs without a real committee/signature.
    function test_verifyBundle_revertsOnInsufficientParticipation() public {
        bytes memory payload = _payloadReachingBls();
        bytes memory anchor = _anchor();
        vm.expectRevert(
            abi.encodeWithSelector(EthMainnetVerifier.InsufficientParticipation.selector, uint256(0), uint256(512))
        );
        exposed.verifyBundle(payload, anchor, "");
    }

    // ── Bundle content decode ─────────────────────────────────────────────────

    function test_decodeBundleContent_collectsField2() public view {
        bytes memory data = abi.encodePacked(PB.encodeBytesField(2, hex"deadbeef"), PB.encodeBytesField(2, hex"cafe"));
        bytes[] memory msgs = exposed.decodeBundleContent(data);
        assertEq(msgs.length, 2);
        assertEq(keccak256(msgs[0]), keccak256(hex"deadbeef"));
        assertEq(keccak256(msgs[1]), keccak256(hex"cafe"));
    }

    function test_verifyBls_succeeds_atSupermajority() public view {
        bytes[] memory pubkeys = _uncompressedKeys(SYNC_COMMITTEE_SIZE);
        bytes memory aggregate = _committeeAggregate(); // 512·gen
        bytes memory bits = _bits(SUPERMAJORITY);

        bytes32 domain = ClprBeaconSsz.computeSyncCommitteeDomain(FORK_VERSION, GVR);
        bytes32 signingRoot = ClprBeaconSsz.computeSigningRoot(BEACON_BLOCK_ROOT, domain);
        bytes memory sig = _aggSig(signingRoot, SUPERMAJORITY);

        // Succeeds → exercises _verifyBls, _collectNonSigners (170 Merkle-authenticated entries),
        // _toBytes4 and the complement BLS path (aggregate − 170 non-participants = 342 participants,
        // matching the 342·H signature).
        bytes memory anchor = exposed.encodeTrustAnchor(
            _scalars(ANCHOR_PERIOD),
            pubkeys,
            aggregate,
            _pubkeys(0x55), // `next` is filler: these exercise committee 0 only
            _pubkey(0x66)
        );
        bytes memory wrapper = _nonSignerWrapper(genUncompressed, SYNC_COMMITTEE_SIZE - SUPERMAJORITY);
        harness.verifyBlsExt(anchor, wrapper, sig, bits, BEACON_BLOCK_ROOT, abi.encodePacked(FORK_VERSION), GVR);
    }

    /// @dev Guards the fixture generalisation the window tests rest on: two committees at different
    ///      secret keys must differ in BOTH the stored aggregate and the committee Merkle root, and a
    ///      signature by one must fail against the other.
    function test_fixtures_distinctSecretKeys_produceDistinctCommittees() public view {
        bytes[] memory keys1 = _uncompressedKeys(SYNC_COMMITTEE_SIZE, 1);
        bytes[] memory keys2 = _uncompressedKeys(SYNC_COMMITTEE_SIZE, 2);
        bytes memory agg1 = _committeeAggregate(1);
        bytes memory agg2 = _committeeAggregate(2);

        assertTrue(keccak256(keys1[0]) != keccak256(keys2[0]), "member keys must differ");
        assertTrue(keccak256(agg1) != keccak256(agg2), "aggregates must differ");
        assertTrue(
            ClprCommitteeMerkle.root(keys1) != ClprCommitteeMerkle.root(keys2), "committee Merkle roots must differ"
        );
        assertTrue(
            ClprBeaconSsz.syncCommitteeRootFromUncompressed(keys1, agg1)
                != ClprBeaconSsz.syncCommitteeRootFromUncompressed(keys2, agg2),
            "SSZ committee roots must differ"
        );
    }

    /// @dev The other half of the guard: committee 2's signature must not verify under committee 1.
    function test_fixtures_signatureFromOtherCommittee_reverts() public {
        bytes[] memory pubkeys = _uncompressedKeys(SYNC_COMMITTEE_SIZE, 1);
        bytes memory aggregate = _committeeAggregate(1);
        bytes memory bits = _bits(SYNC_COMMITTEE_SIZE);

        bytes32 domain = ClprBeaconSsz.computeSyncCommitteeDomain(FORK_VERSION, GVR);
        bytes32 signingRoot = ClprBeaconSsz.computeSigningRoot(BEACON_BLOCK_ROOT, domain);
        bytes memory wrongSig = _aggSig(signingRoot, SYNC_COMMITTEE_SIZE, 2); // signed by committee 2

        bytes memory anchor = exposed.encodeTrustAnchor(
            _scalars(ANCHOR_PERIOD),
            pubkeys,
            aggregate,
            _pubkeys(0x55), // `next` is filler: these exercise committee 0 only
            _pubkey(0x66)
        );
        bytes memory wrapper = _nonSignerWrapper(genUncompressed, 0);
        vm.expectRevert();
        harness.verifyBlsExt(anchor, wrapper, wrongSig, bits, BEACON_BLOCK_ROOT, abi.encodePacked(FORK_VERSION), GVR);
    }

    function test_verifyBls_revertsBelowSupermajority() public {
        bytes[] memory pubkeys = _uncompressedKeys(SYNC_COMMITTEE_SIZE);
        bytes memory aggregate = _committeeAggregate();
        bytes memory bits = _bits(SUPERMAJORITY - 1);
        bytes32 domain = ClprBeaconSsz.computeSyncCommitteeDomain(FORK_VERSION, GVR);
        bytes32 signingRoot = ClprBeaconSsz.computeSigningRoot(BEACON_BLOCK_ROOT, domain);
        bytes memory sig = _aggSig(signingRoot, SUPERMAJORITY - 1);

        bytes memory anchor = exposed.encodeTrustAnchor(
            _scalars(ANCHOR_PERIOD),
            pubkeys,
            aggregate,
            _pubkeys(0x55), // `next` is filler: these exercise committee 0 only
            _pubkey(0x66)
        );
        // Supermajority is decided from the bits BEFORE any proof material is touched, so an empty
        // non-signer item is fine here.
        bytes memory wrapper = _nonSignerWrapper(genUncompressed, 0);
        vm.expectRevert(
            abi.encodeWithSelector(
                EthMainnetVerifier.InsufficientParticipation.selector, SUPERMAJORITY - 1, SYNC_COMMITTEE_SIZE
            )
        );
        harness.verifyBlsExt(anchor, wrapper, sig, bits, BEACON_BLOCK_ROOT, abi.encodePacked(FORK_VERSION), GVR);
    }

    /// @dev THE attack the Merkle authentication exists to stop: a relay passing an arbitrary point
    ///      as a "non-signer" (steering the complement aggregate to a key it controls). The forged
    ///      entry is internally consistent (its proof folds correctly for its own key) but cannot
    ///      reproduce the anchor's committee root → NonSignerProofInvalid at the first clear bit.
    function test_verifyBls_revertsOnForgedNonSignerKey() public {
        bytes[] memory pubkeys = _uncompressedKeys(SYNC_COMMITTEE_SIZE);
        bytes memory aggregate = _committeeAggregate();
        bytes memory bits = _bits(SUPERMAJORITY);
        bytes32 domain = ClprBeaconSsz.computeSyncCommitteeDomain(FORK_VERSION, GVR);
        bytes32 signingRoot = ClprBeaconSsz.computeSigningRoot(BEACON_BLOCK_ROOT, domain);
        bytes memory sig = _aggSig(signingRoot, SUPERMAJORITY);

        bytes memory anchor = exposed.encodeTrustAnchor(
            _scalars(ANCHOR_PERIOD),
            pubkeys,
            aggregate,
            _pubkeys(0x55), // `next` is filler: these exercise committee 0 only
            _pubkey(0x66)
        );
        // Entries built from a DIFFERENT key than the committee's → root mismatch.
        bytes memory wrapper = _nonSignerWrapper(_pubkey(0x77), SYNC_COMMITTEE_SIZE - SUPERMAJORITY);
        vm.expectRevert(
            abi.encodeWithSelector(EthMainnetVerifier.NonSignerProofInvalid.selector, uint256(SUPERMAJORITY))
        );
        harness.verifyBlsExt(anchor, wrapper, sig, bits, BEACON_BLOCK_ROOT, abi.encodePacked(FORK_VERSION), GVR);
    }

    function test_verifyBls_revertsOnNonSignerCountMismatch() public {
        bytes[] memory pubkeys = _uncompressedKeys(SYNC_COMMITTEE_SIZE);
        bytes memory aggregate = _committeeAggregate();
        bytes memory bits = _bits(SUPERMAJORITY); // 170 clear bits…
        bytes32 domain = ClprBeaconSsz.computeSyncCommitteeDomain(FORK_VERSION, GVR);
        bytes32 signingRoot = ClprBeaconSsz.computeSigningRoot(BEACON_BLOCK_ROOT, domain);
        bytes memory sig = _aggSig(signingRoot, SUPERMAJORITY);

        bytes memory anchor = exposed.encodeTrustAnchor(
            _scalars(ANCHOR_PERIOD),
            pubkeys,
            aggregate,
            _pubkeys(0x55), // `next` is filler: these exercise committee 0 only
            _pubkey(0x66)
        );
        bytes memory wrapper = _nonSignerWrapper(genUncompressed, 0); // …but zero entries supplied
        vm.expectRevert(
            abi.encodeWithSelector(
                EthMainnetVerifier.NonSignerProofCountMismatch.selector, SYNC_COMMITTEE_SIZE - SUPERMAJORITY, uint256(0)
            )
        );
        harness.verifyBlsExt(anchor, wrapper, sig, bits, BEACON_BLOCK_ROOT, abi.encodePacked(FORK_VERSION), GVR);
    }

    /// @dev Wrapper RLP `[ nonSignerProofs ]` for a committee whose 512 keys are ALL `key`: every
    ///      tree level then has a single repeated node value, so one shared 288-byte proof
    ///      (level hashes h0..h8) is valid for every index. Entries are `key ‖ proof` (416 B).
    function _nonSignerWrapper(bytes memory key, uint256 nonSignerCount) internal pure returns (bytes memory) {
        bytes32 h = keccak256(key);
        bytes memory proof;
        for (uint256 j = 0; j < ClprCommitteeMerkle.DEPTH; j++) {
            proof = abi.encodePacked(proof, h);
            h = keccak256(abi.encodePacked(h, h));
        }
        bytes memory encodedEntry = RLP.encode(abi.encodePacked(key, proof));
        bytes[] memory entries = new bytes[](nonSignerCount);
        for (uint256 i = 0; i < nonSignerCount; i++) {
            entries[i] = encodedEntry;
        }
        bytes[] memory outer = new bytes[](1);
        outer[0] = RLP.encode(entries);
        return RLP.encode(outer);
    }

    // ── _verifyRotation (uncompressed committee → derive compressed → SSZ root → successor anchor) ─

    function test_verifyRotation_succeeds_returnsUncompressedAnchor() public view {
        // Signed one period ahead of the anchor (verified by `next`), proving committee 2 → the window
        // shifts and a successor anchor comes back.
        (bytes memory rotationRlp, bytes32 stateRoot) = _rotationPair(2, "");
        bytes memory anchor = _windowAnchor(exposed, ANCHOR_PERIOD, 1);

        bytes memory newAnchor =
            harness.verifyRotationExt(rotationRlp, stateRoot, anchor, ANCHOR_PERIOD + 1, ANCHOR_PERIOD + 1, 1);
        assertTrue(newAnchor.length > 0, "successor anchor non-empty");
    }

    function test_verifyRotation_absent_returnsEmpty() public view {
        bytes[] memory pair = new bytes[](2);
        pair[0] = RLP.encode(new bytes(0)); // nextCommittee absent → empty RLP string (0x80)
        pair[1] = RLP.encode(new bytes[](0)); // nextCommitteeBranch absent → empty RLP list (0xc0)
        bytes memory rotationRlp = RLP.encode(pair);

        bytes memory newAnchor =
            harness.verifyRotationExt(rotationRlp, bytes32(0), _anchor(), ANCHOR_PERIOD, ANCHOR_PERIOD, 0);
        assertEq(newAnchor.length, 0, "no rotation -> empty anchor");
    }

    function test_verifyRotation_revertsOnCorruptedKey() public {
        // Corrupt one uncompressed key with an ON-CURVE point that isn't the committed one (the
        // negated generator): it passes the G1ADD on-curve gate, but its sign flag flips the
        // compressed leaf, so the reconstructed root fails the branch → NextCommitteeBranchInvalid.
        (bytes memory rotationRlp, bytes32 stateRoot) =
            _rotationPair(1, abi.encodePacked(bytes16(0), G1_GEN_X, bytes16(0), G1_GEN_Y_NEG));
        // External call precomputed: an armed expectRevert would consume it.
        bytes memory anchor = _windowAnchor(exposed, ANCHOR_PERIOD, 1);
        vm.expectRevert(EthMainnetVerifier.NextCommitteeBranchInvalid.selector);
        harness.verifyRotationExt(rotationRlp, stateRoot, anchor, ANCHOR_PERIOD + 1, ANCHOR_PERIOD + 1, 1);
    }

    function test_verifyRotation_revertsOnOffCurveKey() public {
        // The anchor-poisoning vector: same x, same-SIGN garbage y (y_gen + 1, still ≤ (p−1)/2).
        // compressG1 of it is byte-identical to the committed leaf, so the SSZ root check alone
        // would accept it = only the fail-fast G1ADD on-curve gate rejects it → BlsPointNotOnCurveG1.
        bytes memory garbageY = G1_GEN_Y;
        garbageY[47] = bytes1(uint8(garbageY[47]) + 1);
        (bytes memory rotationRlp, bytes32 stateRoot) =
            _rotationPair(1, abi.encodePacked(bytes16(0), G1_GEN_X, bytes16(0), garbageY));
        // External call precomputed: an armed expectRevert would consume it.
        bytes memory anchor = _windowAnchor(exposed, ANCHOR_PERIOD, 1);
        vm.expectRevert(ClprBeaconBls.BlsPointNotOnCurveG1.selector);
        harness.verifyRotationExt(rotationRlp, stateRoot, anchor, ANCHOR_PERIOD + 1, ANCHOR_PERIOD + 1, 1);
    }

    // ── verifyConfig (non-empty bootstrap) ────────────────────────────────────

    function test_verifyConfig_nonEmpty_returnsAnchorAndPeriodId() public view {
        uint256 slot = uint256(SLOTS_PER_SYNC_COMMITTEE_PERIOD) * 5 + 17; // period 5
        bytes memory configRlp = _configPayload(slot);

        (,,,,, bytes memory anchor, bytes memory anchorId,) = harness.verifyConfig(configRlp, CHANNEL_ID, "");
        assertTrue(anchor.length > 0, "initial anchor non-empty");
        // anchorId = period(slot) as 8-byte big-endian (period 5).
        assertEq(anchorId, abi.encodePacked(uint64(5)));
    }

    /// @notice The endpoint-limit throttles (maxLocalEndpoints/maxPeerEndpoints) embedded in the
    ///         config proof's ledger configuration round-trip through verifyConfig — not dropped.
    function test_verifyConfig_nonEmpty_carriesEndpointLimits() public view {
        uint256 slot = uint256(SLOTS_PER_SYNC_COMMITTEE_PERIOD) * 5 + 17; // period 5
        bytes[] memory pubkeys = _uncompressedKeys(SYNC_COMMITTEE_SIZE);
        ClprTypes.LedgerConfiguration memory lc;
        lc.throttles.maxLocalEndpoints = 7;
        lc.throttles.maxPeerEndpoints = 13;
        bytes[] memory cfg = new bytes[](7);
        cfg[0] = RLP.encode(slot);
        cfg[1] = _encodeCommittee(pubkeys, genUncompressed);
        cfg[2] = _encodeCommittee(_uncompressedKeys(SYNC_COMMITTEE_SIZE, 2), _memberKey(2));
        cfg[3] = RLP.encode(abi.encodePacked(GVR));
        cfg[4] = RLP.encode(abi.encodePacked(FORK_VERSION));
        cfg[5] = RLP.encode(ClprProtobuf.encodeControlMessage(lc));
        cfg[6] = RLP.encode(abi.encodePacked(bytes32(uint256(0xC0DE)))); // expected code hash

        (,,,, ClprTypes.Throttles memory throttles,,,) = harness.verifyConfig(RLP.encode(cfg), CHANNEL_ID, "");
        assertEq(throttles.maxLocalEndpoints, 7, "maxLocalEndpoints must survive the config proof");
        assertEq(throttles.maxPeerEndpoints, 13, "maxPeerEndpoints must survive the config proof");
    }

    function test_verifyConfig_revertsOnWrongFieldCount() public {
        bytes[] memory items = new bytes[](4); // CONFIG_FIELDS is 7
        for (uint256 i = 0; i < 4; i++) {
            items[i] = RLP.encode(uint256(0));
        }
        vm.expectRevert(EthMainnetVerifier.InvalidConfigPayload.selector);
        harness.verifyConfig(RLP.encode(items), CHANNEL_ID, "");
    }

    /// @dev A non-empty endpoint-manifest proof with the wrong field count reverts: the config-time
    ///      manifest path now verifies the proof (8-field beacon+MPT shape) instead of ignoring it.
    ///      (Full happy-path — real BLS + MPT — is covered by the eth-pos e2e, like verifyBundle.)
    function test_verifyConfig_revertsOnMalformedManifestProof() public {
        bytes memory configRlp = _configPayload(uint256(SLOTS_PER_SYNC_COMMITTEE_PERIOD) * 5 + 17);
        bytes[] memory badManifestProof = new bytes[](3); // must be CONFIG_MANIFEST_PROOF_FIELDS (8)
        for (uint256 i = 0; i < 3; i++) {
            badManifestProof[i] = RLP.encode(uint256(0));
        }
        vm.expectRevert(EthMainnetVerifier.InvalidConfigPayload.selector);
        harness.verifyConfig(configRlp, CHANNEL_ID, RLP.encode(badManifestProof));
    }

    /// @dev The config-time manifest proof is verified against the window's CURRENT member, so its
    ///      attested header must sit inside the config slot's period.
    function test_verifyConfig_revertsOnManifestProofOutsideConfigPeriod() public {
        uint64 configPeriod = 5;
        bytes memory configRlp = _configPayload(uint256(configPeriod) * SLOTS_PER_SYNC_COMMITTEE_PERIOD + 17);

        bytes[] memory header = new bytes[](5);
        header[0] = RLP.encode(uint256(17)); // slot 17 → period 0, not the config's period 5
        header[1] = RLP.encode(uint256(0));
        header[2] = RLP.encode(bytes32(0));
        header[3] = RLP.encode(bytes32(0));
        header[4] = RLP.encode(bytes32(0));

        bytes[] memory manifestProof = new bytes[](8);
        manifestProof[0] = RLP.encode(header);
        for (uint256 i = 1; i < 8; i++) {
            manifestProof[i] = RLP.encode(uint256(0));
        }

        vm.expectRevert(
            abi.encodeWithSelector(EthMainnetVerifier.ConfigManifestPeriodMismatch.selector, uint64(0), configPeriod)
        );
        harness.verifyConfig(configRlp, CHANNEL_ID, RLP.encode(manifestProof));
    }

    function test_verifyConfig_revertsWhenBothWindowMembersAreTheSameCommittee() public {
        bytes[] memory cfg = new bytes[](7);
        cfg[0] = RLP.encode(uint256(SLOTS_PER_SYNC_COMMITTEE_PERIOD) * 5 + 17);
        cfg[1] = _encodeCommittee(_uncompressedKeys(SYNC_COMMITTEE_SIZE, 1), genUncompressed);
        cfg[2] = _encodeCommittee(_uncompressedKeys(SYNC_COMMITTEE_SIZE, 1), genUncompressed); // same again
        cfg[3] = RLP.encode(abi.encodePacked(GVR));
        cfg[4] = RLP.encode(abi.encodePacked(FORK_VERSION));
        ClprTypes.LedgerConfiguration memory lc;
        cfg[5] = RLP.encode(ClprProtobuf.encodeControlMessage(lc));
        cfg[6] = RLP.encode(abi.encodePacked(SERVICE_CODE_HASH));

        bytes memory configRlp = RLP.encode(cfg);
        vm.expectRevert(EthMainnetVerifier.ConfigWindowNotDistinct.selector);
        harness.verifyConfig(configRlp, CHANNEL_ID, "");
    }

    function test_verifyConfig_revertsOnBadForkVersionLength() public {
        bytes memory configRlp = _configPayload(SLOTS_PER_SYNC_COMMITTEE_PERIOD, abi.encodePacked(bytes3(0x040000))); // 3 bytes, not 4
        vm.expectRevert(EthMainnetVerifier.InvalidConfigPayload.selector);
        harness.verifyConfig(configRlp, CHANNEL_ID, "");
    }

    // ── Rotation decode/shape guards ──────────────────────────────────────────

    function test_verifyRotation_revertsOnPairMismatch() public {
        // committee present (a non-empty-string item) but branch absent (empty RLP list).
        bytes[] memory pair = new bytes[](2);
        pair[0] = RLP.encode(uint256(1)); // present (first byte != 0x80)
        pair[1] = RLP.encode(new bytes[](0)); // absent branch (0xc0)
        bytes memory rotationRlp = RLP.encode(pair);
        // External call precomputed: an armed expectRevert would consume it.
        bytes memory anchor = _windowAnchor(exposed, ANCHOR_PERIOD, 1);
        vm.expectRevert(EthMainnetVerifier.RotationPairMismatch.selector);
        harness.verifyRotationExt(rotationRlp, bytes32(0), anchor, ANCHOR_PERIOD, ANCHOR_PERIOD, 0);
    }

    function test_verifyRotation_revertsOnInvalidCommitteeShape() public {
        // A present committee + branch, but an uncompressed pubkey of the wrong length → InvalidCommittee
        // during decode.
        bytes[] memory uncompressed = _uncompressedKeys(SYNC_COMMITTEE_SIZE);
        uncompressed[0] = hex"1234"; // wrong length (not 128)
        bytes memory nextCommittee = _encodeCommittee(uncompressed, genUncompressed);
        bytes32[] memory branch = new bytes32[](6);
        bytes[] memory pair = new bytes[](2);
        pair[0] = nextCommittee;
        pair[1] = _encodeBranch(branch);
        bytes memory rotationRlp = RLP.encode(pair);

        // External call precomputed: an armed expectRevert would consume it.
        bytes memory anchor = _windowAnchor(exposed, ANCHOR_PERIOD, 1);
        vm.expectRevert(EthMainnetVerifier.InvalidCommittee.selector);
        harness.verifyRotationExt(rotationRlp, bytes32(0), anchor, ANCHOR_PERIOD, ANCHOR_PERIOD, 0);
    }

    function test_verifyRotation_revertsOnBadBranchDepth() public {
        // Valid (generator) committee so decode + root reconstruction pass, but a branch of the wrong
        // depth → _decodeBranch reverts InvalidBranch.
        bytes[] memory uncompressed = _uncompressedKeys(SYNC_COMMITTEE_SIZE);
        bytes memory nextCommittee = _encodeCommittee(uncompressed, genUncompressed);
        bytes32[] memory branch = new bytes32[](5); // NEXT_COMMITTEE_BRANCH_DEPTH is 6
        bytes[] memory pair = new bytes[](2);
        pair[0] = nextCommittee;
        pair[1] = _encodeBranch(branch);
        bytes memory rotationRlp = RLP.encode(pair);

        // External call precomputed: an armed expectRevert would consume it.
        bytes memory anchor = _windowAnchor(exposed, ANCHOR_PERIOD, 1);
        vm.expectRevert(EthMainnetVerifier.InvalidBranch.selector);
        harness.verifyRotationExt(rotationRlp, bytes32(0), anchor, ANCHOR_PERIOD, ANCHOR_PERIOD, 0);
    }

    function test_verifyRotation_revertsOnWrongCommitteeShape() public {
        // nextCommittee present but not a [pubkeys, aggregate] 2-list → InvalidCommittee.
        bytes[] memory one = new bytes[](1);
        one[0] = RLP.encode(uint256(1));
        bytes32[] memory branch = new bytes32[](6);
        bytes[] memory pair = new bytes[](2);
        pair[0] = RLP.encode(one); // 1-element list, not 2
        pair[1] = _encodeBranch(branch);
        bytes memory rotationRlp = RLP.encode(pair);

        // External call precomputed: an armed expectRevert would consume it.
        bytes memory anchor = _windowAnchor(exposed, ANCHOR_PERIOD, 1);
        vm.expectRevert(EthMainnetVerifier.InvalidCommittee.selector);
        harness.verifyRotationExt(rotationRlp, bytes32(0), anchor, ANCHOR_PERIOD, ANCHOR_PERIOD, 0);
    }

    // ── ClprBeaconSsz.verifyProofOrRevert convenience wrapper ─────────────────

    function test_verifyProofOrRevert() public {
        bytes32 left = keccak256("l");
        bytes32 right = keccak256("r");
        bytes32 root = sha256(abi.encodePacked(left, right));
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = right;
        harness.verifyProofOrRevertExt(left, proof, root, 2); // left child, gindex 2 -> ok
        vm.expectRevert(ClprBeaconSsz.SszProofInvalid.selector);
        harness.verifyProofOrRevertExt(left, proof, bytes32(uint256(1)), 2); // wrong root -> revert
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// 64-byte Bitvector[512] with the first `n` bits set (LSB-first within each byte).
    function _bits(uint256 n) internal pure returns (bytes memory bits) {
        bits = new bytes(64);
        for (uint256 i = 0; i < n; i++) {
            // 2**(i&7) is the LSB-first bit mask within the byte (avoids the literal-shift lint).
            bits[i >> 3] = bytes1(uint8(bits[i >> 3]) | uint8(2 ** (i & 7)));
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    function _pubkey(uint8 fill) internal pure returns (bytes memory b) {
        // 128-byte uncompressed EIP-2537 G1 (pad16||x||pad16||y), matching BLS_PUBKEY_LENGTH.
        b = new bytes(128);
        for (uint256 i = 0; i < 128; i++) {
            b[i] = bytes1(fill);
        }
    }

    function _pubkeys(uint8 base) internal pure returns (bytes[] memory keys) {
        keys = new bytes[](512);
        for (uint256 i = 0; i < 512; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            keys[i] = _pubkey(uint8(base + (i % 200)));
        }
    }

    /// A window anchor over two placeholder committees, current period `ANCHOR_PERIOD`.
    function _anchor() internal view returns (bytes memory) {
        return _anchor(ANCHOR_PERIOD);
    }

    function _anchor(uint64 period) internal view returns (bytes memory) {
        return exposed.encodeTrustAnchor(_scalars(period), _pubkeys(0x33), _pubkey(0x44), _pubkeys(0x55), _pubkey(0x66));
    }

    function _scalars(uint64 period) internal pure returns (EthMainnetVerifier.AnchorScalars memory) {
        return EthMainnetVerifier.AnchorScalars({
            gvr: GVR,
            forkVersion: abi.encodePacked(FORK_VERSION),
            channelId: CHANNEL_ID,
            codeHash: SERVICE_CODE_HASH,
            period: period
        });
    }

    /// @dev An 11-item bundle whose header + sync aggregate are well-formed (so verifyBundle reaches
    ///      `_verifyBls`); the bits are all-zero ⇒ zero participants ⇒ the supermajority gate reverts
    ///      (before the non-signer item is touched). The remaining items are placeholders.
    function _payloadReachingBls() internal pure returns (bytes memory) {
        bytes[] memory header = new bytes[](5);
        header[0] = RLP.encode(uint256(ANCHOR_PERIOD) * SLOTS_PER_SYNC_COMMITTEE_PERIOD); // slot, inside the anchor period
        header[1] = RLP.encode(uint256(7)); // proposerIndex
        header[2] = RLP.encode(bytes32(uint256(1))); // parentRoot
        header[3] = RLP.encode(bytes32(uint256(2))); // stateRoot
        header[4] = RLP.encode(bytes32(uint256(3))); // bodyRoot

        bytes[] memory agg = new bytes[](2);
        agg[0] = RLP.encode(new bytes(64)); // bits
        agg[1] = RLP.encode(new bytes(256)); // signature (256-byte uncompressed G2)

        bytes[] memory top = new bytes[](11);
        top[0] = RLP.encode(header);
        // signatureSlot: one slot after the attested header, so the same period selects `current`.
        top[1] = RLP.encode(uint256(ANCHOR_PERIOD) * SLOTS_PER_SYNC_COMMITTEE_PERIOD + 1);
        top[2] = RLP.encode(agg);
        top[3] = RLP.encode(bytes32(uint256(0xEE))); // executionStateRoot
        top[4] = hex"c0"; // executionBranch: empty list ⇒ depth mismatch (InvalidBranch)
        top[5] = hex"80"; // nextCommittee absent
        top[6] = hex"c0"; // nextCommitteeBranch absent
        top[7] = hex"c0"; // accountProof
        top[8] = hex"c0"; // storageProof
        top[9] = RLP.encode(new bytes(0)); // bundleContent
        top[10] = hex"c0"; // nonSignerProofs: empty list
        return RLP.encode(top);
    }

    function _configPayload(uint256 slot) internal view returns (bytes memory) {
        return _configPayload(slot, abi.encodePacked(FORK_VERSION));
    }

    function _configPayload(uint256 slot, bytes memory forkVersion) internal view returns (bytes memory) {
        bytes[] memory cfg = new bytes[](7);
        cfg[0] = RLP.encode(slot);
        cfg[1] = _encodeCommittee(_uncompressedKeys(SYNC_COMMITTEE_SIZE, 1), genUncompressed);
        cfg[2] = _encodeCommittee(_uncompressedKeys(SYNC_COMMITTEE_SIZE, 2), _memberKey(2));
        cfg[3] = RLP.encode(abi.encodePacked(GVR));
        cfg[4] = RLP.encode(forkVersion);
        // A valid (default) ControlMessage so decodeControlMessage round-trips.
        ClprTypes.LedgerConfiguration memory lc;
        cfg[5] = RLP.encode(ClprProtobuf.encodeControlMessage(lc));
        cfg[6] = RLP.encode(abi.encodePacked(SERVICE_CODE_HASH));
        return RLP.encode(cfg);
    }
}
