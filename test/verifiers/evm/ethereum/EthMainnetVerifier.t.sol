// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {EthMainnetVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/EthMainnetVerifier.sol";
import {EthBeaconLightClient} from "@hiero-ledger/clpr/libraries/proof/beacon/EthBeaconLightClient.sol";
import {EthCommitteeFixtures} from "@test/verifiers/evm/ethereum/EthCommitteeFixtures.sol";
import {ClprBeaconSsz} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconSsz.sol";
import {ClprCommitteeMerkle} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprCommitteeMerkle.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {ClprBeaconBls} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconBls.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @dev Exposes the verifier internals (new sync-committee model) for unit testing.
contract EthMainnetVerifierTestHarness is EthMainnetVerifier {
    constructor() {}

    function decodeTrustAnchor(bytes calldata ta)
        external
        pure
        returns (
            bytes32 committeeRoot,
            bytes memory aggregatePubkey,
            bytes32 gvr,
            bytes memory forkVersion,
            bytes32 channelId,
            bytes32 codeHash
        )
    {
        // Mirror verifyBundle's flat-anchor reads (fixed offsets).
        if (ta.length != TRUST_ANCHOR_LENGTH) revert InvalidTrustAnchor();
        gvr = bytes32(ta[ANCHOR_OFF_GVR:ANCHOR_OFF_GVR + 32]);
        forkVersion = ta[ANCHOR_OFF_FORK_VERSION:ANCHOR_OFF_FORK_VERSION + FORK_VERSION_LENGTH];
        channelId = bytes32(ta[ANCHOR_OFF_CHANNEL_ID:ANCHOR_OFF_CHANNEL_ID + 32]);
        aggregatePubkey = ta[ANCHOR_OFF_AGGREGATE:ANCHOR_OFF_AGGREGATE + BLS_PUBKEY_LENGTH];
        committeeRoot = bytes32(ta[ANCHOR_OFF_COMMITTEE_ROOT:ANCHOR_OFF_COMMITTEE_ROOT + 32]);
        codeHash = bytes32(ta[ANCHOR_OFF_CODE_HASH:ANCHOR_OFF_CODE_HASH + 32]);
    }

    function encodeTrustAnchor(
        bytes[] memory pubkeys,
        bytes memory aggregatePubkey,
        bytes32 gvr,
        bytes memory forkVersion,
        bytes32 channelId,
        bytes32 codeHash
    ) external pure returns (bytes memory) {
        return _encodeTrustAnchor(pubkeys, aggregatePubkey, gvr, forkVersion, channelId, codeHash);
    }

    function decodeBundleContent(bytes memory data) external pure returns (bytes[] memory messages) {
        return _decodeBundleContent(data);
    }

    // External wrappers so vm.expectRevert can catch reverts from the internal library functions.
    function merkleizeExt(bytes32[] memory chunks) external pure returns (bytes32) {
        return ClprBeaconSsz.merkleize(chunks);
    }
}

/// @dev Exposes the internal BLS + rotation paths so they can be exercised directly with a
///      SELF-CONSISTENT instance (every committee member is the G1 generator, secret key 1), without a
///      full MPT/SSZ bundle or a live chain. The aggregate of N members is N·G1 and the matching
///      signature is N·H(signingRoot), so `aggregateVerifyComplement` succeeds; the rotation committees are
///      the (compressed, uncompressed) generator so the compress-and-bind check passes and the SSZ
///      committee root is provable. (forge coverage only sees Foundry tests, so these paths — covered
///      end-to-end by the e2e spec — also need a Foundry exercise.)
contract EthMainnetVerifierProofHarness is EthMainnetVerifier {
    constructor() {}

    /// `nonSignerWrapperRlp` is `RLP[nonSignerProofs]` (a single-item outer list), so this mirrors
    /// how `verifyBundle` slices payload item 9 before calling `_verifyBls`.
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
        _verifyBls(trustAnchor, items[0], signature, bits, beaconBlockRoot, forkVersion, gvr);
    }

    /// `rotationRlp` is `RLP[nextCommittee, nextCommitteeBranch]` (the two bundle items), so this
    /// mirrors how `verifyBundle` slices the payload before calling `_verifyRotation`.
    function verifyRotationExt(
        bytes memory rotationRlp,
        bytes32 stateRoot,
        bytes32 gvr,
        bytes memory forkVersion,
        bytes32 channelId,
        bytes32 codeHash
    ) external view returns (bytes memory) {
        Memory.Slice[] memory items = RLP.decodeList(rotationRlp);
        return _verifyRotation(items[0], items[1], stateRoot, gvr, forkVersion, channelId, codeHash);
    }

    function verifyProofOrRevertExt(bytes32 leaf, bytes32[] memory proof, bytes32 root, uint256 gindex) external pure {
        ClprBeaconSsz.verifyProofOrRevert(leaf, proof, root, gindex);
    }
}

/// @dev Unit tests for the sync-committee EthMainnetVerifier: the SSZ primitives, the RLP
///      trust-anchor round-trip, the decoders, verifyConfig, payload-shape and supermajority guards.
///      Full real-BLS verifyBundle (committee + signature + MPT/SSZ proofs) is covered end-to-end in
///      test/e2e/tests/verifiers/eth-verifier.spec.ts.
contract EthMainnetVerifierTest is EthCommitteeFixtures {
    address internal constant SERVICE_ADDR = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;
    bytes32 internal constant SERVICE_CODE_HASH = bytes32(uint256(0xC0DE));
    bytes4 internal constant FORK_VERSION = 0x04000000; // Deneb mainnet
    bytes32 internal constant GVR = bytes32(uint256(0x9999));

    uint256 internal constant GINDEX_NEXT_SYNC_COMMITTEE_IN_STATE = 87;
    bytes32 internal constant BEACON_BLOCK_ROOT = bytes32(uint256(0x1234));
    bytes32 internal constant CHANNEL_ID = bytes32(uint256(0xC04EC));

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
        bytes memory forkVersion = abi.encodePacked(FORK_VERSION);
        bytes32 channelId = bytes32(uint256(0xC04EC));

        bytes memory anchor = exposed.encodeTrustAnchor(pubkeys, agg, GVR, forkVersion, channelId, SERVICE_CODE_HASH);
        assertEq(anchor.length, 260, "flat anchor is 260 bytes");
        (
            bytes32 gotRoot,
            bytes memory gotAgg,
            bytes32 gotGvr,
            bytes memory gotFork,
            bytes32 gotChannelId,
            bytes32 gotCodeHash
        ) = exposed.decodeTrustAnchor(anchor);

        assertEq(gotRoot, ClprCommitteeMerkle.root(pubkeys), "committee Merkle root committed");
        assertEq(keccak256(gotAgg), keccak256(agg));
        assertEq(gotGvr, GVR);
        assertEq(keccak256(gotFork), keccak256(forkVersion));
        assertEq(gotChannelId, channelId);
        assertEq(gotCodeHash, SERVICE_CODE_HASH, "code hash committed");
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
            abi.encodeWithSelector(EthBeaconLightClient.InsufficientParticipation.selector, uint256(0), uint256(512))
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
            pubkeys, aggregate, GVR, abi.encodePacked(FORK_VERSION), CHANNEL_ID, SERVICE_CODE_HASH
        );
        bytes memory wrapper = _nonSignerWrapper(genUncompressed, SYNC_COMMITTEE_SIZE - SUPERMAJORITY);
        harness.verifyBlsExt(anchor, wrapper, sig, bits, BEACON_BLOCK_ROOT, abi.encodePacked(FORK_VERSION), GVR);
    }

    function test_verifyBls_revertsBelowSupermajority() public {
        bytes[] memory pubkeys = _uncompressedKeys(SYNC_COMMITTEE_SIZE);
        bytes memory aggregate = _committeeAggregate();
        bytes memory bits = _bits(SUPERMAJORITY - 1);
        bytes32 domain = ClprBeaconSsz.computeSyncCommitteeDomain(FORK_VERSION, GVR);
        bytes32 signingRoot = ClprBeaconSsz.computeSigningRoot(BEACON_BLOCK_ROOT, domain);
        bytes memory sig = _aggSig(signingRoot, SUPERMAJORITY - 1);

        bytes memory anchor = exposed.encodeTrustAnchor(
            pubkeys, aggregate, GVR, abi.encodePacked(FORK_VERSION), CHANNEL_ID, SERVICE_CODE_HASH
        );
        // Supermajority is decided from the bits BEFORE any proof material is touched, so an empty
        // non-signer item is fine here.
        bytes memory wrapper = _nonSignerWrapper(genUncompressed, 0);
        vm.expectRevert(
            abi.encodeWithSelector(
                EthBeaconLightClient.InsufficientParticipation.selector, SUPERMAJORITY - 1, SYNC_COMMITTEE_SIZE
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
            pubkeys, aggregate, GVR, abi.encodePacked(FORK_VERSION), CHANNEL_ID, SERVICE_CODE_HASH
        );
        // Entries built from a DIFFERENT key than the committee's → root mismatch.
        bytes memory wrapper = _nonSignerWrapper(_pubkey(0x77), SYNC_COMMITTEE_SIZE - SUPERMAJORITY);
        vm.expectRevert(
            abi.encodeWithSelector(EthBeaconLightClient.NonSignerProofInvalid.selector, uint256(SUPERMAJORITY))
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
            pubkeys, aggregate, GVR, abi.encodePacked(FORK_VERSION), CHANNEL_ID, SERVICE_CODE_HASH
        );
        bytes memory wrapper = _nonSignerWrapper(genUncompressed, 0); // …but zero entries supplied
        vm.expectRevert(
            abi.encodeWithSelector(
                EthBeaconLightClient.NonSignerProofCountMismatch.selector,
                SYNC_COMMITTEE_SIZE - SUPERMAJORITY,
                uint256(0)
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
        (bytes memory rotationRlp, bytes32 stateRoot) = _rotationWithStateRoot(new bytes(0));

        bytes memory newAnchor = harness.verifyRotationExt(
            rotationRlp, stateRoot, GVR, abi.encodePacked(FORK_VERSION), CHANNEL_ID, SERVICE_CODE_HASH
        );
        assertTrue(newAnchor.length > 0, "successor anchor non-empty");
    }

    function test_verifyRotation_absent_returnsEmpty() public view {
        bytes[] memory pair = new bytes[](2);
        pair[0] = RLP.encode(new bytes(0)); // nextCommittee absent → empty RLP string (0x80)
        pair[1] = RLP.encode(new bytes[](0)); // nextCommitteeBranch absent → empty RLP list (0xc0)
        bytes memory rotationRlp = RLP.encode(pair);

        bytes memory newAnchor = harness.verifyRotationExt(
            rotationRlp, bytes32(0), GVR, abi.encodePacked(FORK_VERSION), CHANNEL_ID, SERVICE_CODE_HASH
        );
        assertEq(newAnchor.length, 0, "no rotation -> empty anchor");
    }

    function test_verifyRotation_revertsOnCorruptedKey() public {
        // Corrupt one uncompressed key with an ON-CURVE point that isn't the committed one (the
        // negated generator): it passes the G1ADD on-curve gate, but its sign flag flips the
        // compressed leaf, so the reconstructed root fails the branch → NextCommitteeBranchInvalid.
        (bytes memory rotationRlp, bytes32 stateRoot) =
            _rotationWithStateRoot(abi.encodePacked(bytes16(0), G1_GEN_X, bytes16(0), G1_GEN_Y_NEG));
        vm.expectRevert(EthBeaconLightClient.NextCommitteeBranchInvalid.selector);
        harness.verifyRotationExt(
            rotationRlp, stateRoot, GVR, abi.encodePacked(FORK_VERSION), CHANNEL_ID, SERVICE_CODE_HASH
        );
    }

    function test_verifyRotation_revertsOnOffCurveKey() public {
        // The anchor-poisoning vector: same x, same-SIGN garbage y (y_gen + 1, still ≤ (p−1)/2).
        // compressG1 of it is byte-identical to the committed leaf, so the SSZ root check alone
        // would accept it = only the fail-fast G1ADD on-curve gate rejects it → BlsPointNotOnCurveG1.
        bytes memory garbageY = G1_GEN_Y;
        garbageY[47] = bytes1(uint8(garbageY[47]) + 1);
        (bytes memory rotationRlp, bytes32 stateRoot) =
            _rotationWithStateRoot(abi.encodePacked(bytes16(0), G1_GEN_X, bytes16(0), garbageY));
        vm.expectRevert(ClprBeaconBls.BlsPointNotOnCurveG1.selector);
        harness.verifyRotationExt(
            rotationRlp, stateRoot, GVR, abi.encodePacked(FORK_VERSION), CHANNEL_ID, SERVICE_CODE_HASH
        );
    }

    // ── verifyConfig (non-empty bootstrap) ────────────────────────────────────

    function test_verifyConfig_nonEmpty_returnsAnchorAndPeriodId() public view {
        uint256 slot = 8192 * 5 + 17; // period 5
        bytes memory configRlp = _configPayload(slot);

        (,,,,, bytes memory anchor, bytes memory anchorId,) = harness.verifyConfig(configRlp, CHANNEL_ID, "");
        assertTrue(anchor.length > 0, "initial anchor non-empty");
        // anchorId = period(slot) as 8-byte big-endian (period 5).
        assertEq(anchorId, abi.encodePacked(uint64(5)));
    }

    /// @notice The endpoint-limit throttles (maxLocalEndpoints/maxPeerEndpoints) embedded in the
    ///         config proof's ledger configuration round-trip through verifyConfig — not dropped.
    function test_verifyConfig_nonEmpty_carriesEndpointLimits() public view {
        uint256 slot = 8192 * 5 + 17; // period 5
        bytes[] memory pubkeys = _uncompressedKeys(SYNC_COMMITTEE_SIZE);
        ClprTypes.LedgerConfiguration memory lc;
        lc.throttles.maxLocalEndpoints = 7;
        lc.throttles.maxPeerEndpoints = 13;
        bytes[] memory cfg = new bytes[](6);
        cfg[0] = RLP.encode(slot);
        cfg[1] = _encodeCommittee(pubkeys, genUncompressed);
        cfg[2] = RLP.encode(abi.encodePacked(GVR));
        cfg[3] = RLP.encode(abi.encodePacked(FORK_VERSION));
        cfg[4] = RLP.encode(ClprProtobuf.encodeControlMessage(lc));
        cfg[5] = RLP.encode(abi.encodePacked(bytes32(uint256(0xC0DE)))); // expected code hash

        (,,,, ClprTypes.Throttles memory throttles,,,) = harness.verifyConfig(RLP.encode(cfg), CHANNEL_ID, "");
        assertEq(throttles.maxLocalEndpoints, 7, "maxLocalEndpoints must survive the config proof");
        assertEq(throttles.maxPeerEndpoints, 13, "maxPeerEndpoints must survive the config proof");
    }

    function test_verifyConfig_revertsOnWrongFieldCount() public {
        bytes[] memory items = new bytes[](4); // CONFIG_FIELDS is 6
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
        bytes memory configRlp = _configPayload(8192 * 5 + 17);
        bytes[] memory badManifestProof = new bytes[](3); // must be CONFIG_MANIFEST_PROOF_FIELDS (8)
        for (uint256 i = 0; i < 3; i++) {
            badManifestProof[i] = RLP.encode(uint256(0));
        }
        vm.expectRevert(EthMainnetVerifier.InvalidConfigPayload.selector);
        harness.verifyConfig(configRlp, CHANNEL_ID, RLP.encode(badManifestProof));
    }

    function test_verifyConfig_revertsOnBadForkVersionLength() public {
        bytes memory configRlp = _configPayload(8192, abi.encodePacked(bytes3(0x040000))); // 3 bytes, not 4
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
        vm.expectRevert(EthBeaconLightClient.RotationPairMismatch.selector);
        harness.verifyRotationExt(
            rotationRlp, bytes32(0), GVR, abi.encodePacked(FORK_VERSION), CHANNEL_ID, SERVICE_CODE_HASH
        );
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

        vm.expectRevert(EthBeaconLightClient.InvalidCommittee.selector);
        harness.verifyRotationExt(
            rotationRlp, bytes32(0), GVR, abi.encodePacked(FORK_VERSION), CHANNEL_ID, SERVICE_CODE_HASH
        );
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

        vm.expectRevert(EthBeaconLightClient.InvalidBranch.selector);
        harness.verifyRotationExt(
            rotationRlp, bytes32(0), GVR, abi.encodePacked(FORK_VERSION), CHANNEL_ID, SERVICE_CODE_HASH
        );
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

        vm.expectRevert(EthBeaconLightClient.InvalidCommittee.selector);
        harness.verifyRotationExt(
            rotationRlp, bytes32(0), GVR, abi.encodePacked(FORK_VERSION), CHANNEL_ID, SERVICE_CODE_HASH
        );
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

    /// RLP `[nextCommittee, nextCommitteeBranch]` for a generator committee, plus the matching stateRoot
    /// (the committee root folded up the branch at gindex 87). `mismatch` swaps an uncompressed key.
    function _rotationWithStateRoot(bytes memory key0Override)
        internal
        pure
        returns (bytes memory rotationRlp, bytes32 stateRoot)
    {
        bytes[] memory uncompressed = new bytes[](SYNC_COMMITTEE_SIZE);
        bytes memory gen = abi.encodePacked(bytes16(0), G1_GEN_X, bytes16(0), G1_GEN_Y);
        for (uint256 i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
            uncompressed[i] = gen;
        }
        bytes memory uncompressedAgg = gen;

        // Expected SSZ committee root computed INDEPENDENTLY from the compressed keys (test-side
        // reference), then folded up a synthetic 6-sibling branch — cross-checks the contract's
        // uncompressed-input reconstruction against the beacon-native encoding.
        bytes32 committeeRoot = _committeeRootFromCompressed(_compressedKeys(SYNC_COMMITTEE_SIZE), G1_GEN_COMPRESSED);
        bytes32[] memory branch = new bytes32[](6);
        for (uint256 i = 0; i < 6; i++) {
            branch[i] = keccak256(abi.encodePacked("next-committee-branch", i));
        }
        stateRoot = _fold(committeeRoot, branch, GINDEX_NEXT_SYNC_COMMITTEE_IN_STATE);

        if (key0Override.length != 0) {
            uncompressed[0] = key0Override;
        }

        // Uncompressed-only nextCommittee `[pubkeys512, aggregate]`; the contract derives the compressed
        // form on-chain to reconstruct the committee root.
        bytes memory nextCommittee = _encodeCommittee(uncompressed, uncompressedAgg);
        bytes memory branchRlp = _encodeBranch(branch);

        bytes[] memory pair = new bytes[](2);
        pair[0] = nextCommittee;
        pair[1] = branchRlp;
        rotationRlp = RLP.encode(pair);
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

    function _anchor() internal view returns (bytes memory) {
        return exposed.encodeTrustAnchor(
            _pubkeys(0x33),
            _pubkey(0x44),
            GVR,
            abi.encodePacked(FORK_VERSION),
            bytes32(uint256(0xC04EC)),
            SERVICE_CODE_HASH
        );
    }

    /// @dev A 10-item bundle whose header + sync aggregate are well-formed (so verifyBundle reaches
    ///      `_verifyBls`); the bits are all-zero ⇒ zero participants ⇒ the supermajority gate reverts
    ///      (before the non-signer item is touched). The remaining items are placeholders.
    function _payloadReachingBls() internal pure returns (bytes memory) {
        bytes[] memory header = new bytes[](5);
        header[0] = RLP.encode(uint256(100)); // slot
        header[1] = RLP.encode(uint256(7)); // proposerIndex
        header[2] = RLP.encode(bytes32(uint256(1))); // parentRoot
        header[3] = RLP.encode(bytes32(uint256(2))); // stateRoot
        header[4] = RLP.encode(bytes32(uint256(3))); // bodyRoot

        bytes[] memory agg = new bytes[](2);
        agg[0] = RLP.encode(new bytes(64)); // bits
        agg[1] = RLP.encode(new bytes(256)); // signature (256-byte uncompressed G2)

        bytes[] memory top = new bytes[](10);
        top[0] = RLP.encode(header);
        top[1] = RLP.encode(agg);
        top[2] = RLP.encode(bytes32(uint256(0xEE))); // executionStateRoot
        top[3] = hex"c0"; // executionBranch: empty list ⇒ depth mismatch (InvalidBranch)
        top[4] = hex"80"; // nextCommittee absent
        top[5] = hex"c0"; // nextCommitteeBranch absent
        top[6] = hex"c0"; // accountProof
        top[7] = hex"c0"; // storageProof
        top[8] = RLP.encode(new bytes(0)); // bundleContent
        top[9] = hex"c0"; // nonSignerProofs: empty list
        return RLP.encode(top);
    }

    /// Config payload RLP `[slot, syncCommittee, gvr, forkVersion, ledgerConfiguration]`. The committee
    /// is the (uncompressed) generator (verifyConfig does not BLS-verify); the ledger is empty bytes so
    /// `decodeControlMessage` returns defaults.
    function _configPayload(uint256 slot) internal view returns (bytes memory) {
        return _configPayload(slot, abi.encodePacked(FORK_VERSION));
    }

    function _configPayload(uint256 slot, bytes memory forkVersion) internal view returns (bytes memory) {
        bytes[] memory pubkeys = _uncompressedKeys(SYNC_COMMITTEE_SIZE);
        bytes[] memory cfg = new bytes[](6);
        cfg[0] = RLP.encode(slot);
        cfg[1] = _encodeCommittee(pubkeys, genUncompressed);
        cfg[2] = RLP.encode(abi.encodePacked(GVR));
        cfg[3] = RLP.encode(forkVersion);
        // A valid (default) ControlMessage so decodeControlMessage round-trips.
        ClprTypes.LedgerConfiguration memory lc;
        cfg[4] = RLP.encode(ClprProtobuf.encodeControlMessage(lc));
        cfg[5] = RLP.encode(abi.encodePacked(SERVICE_CODE_HASH));
        return RLP.encode(cfg);
    }

    function _encodeBranch(bytes32[] memory branch) internal pure returns (bytes memory) {
        bytes[] memory enc = new bytes[](branch.length);
        for (uint256 i = 0; i < branch.length; i++) {
            enc[i] = RLP.encode(abi.encodePacked(branch[i]));
        }
        return RLP.encode(enc);
    }

    /// Fold a leaf up to its SSZ root using the same rule as ClprBeaconSsz.verifyProof.
    function _fold(bytes32 leaf, bytes32[] memory branch, uint256 gindex) internal pure returns (bytes32) {
        bytes32 computed = leaf;
        uint256 idx = gindex;
        for (uint256 i = 0; i < branch.length; i++) {
            if (idx & 1 == 1) {
                computed = sha256(abi.encodePacked(branch[i], computed));
            } else {
                computed = sha256(abi.encodePacked(computed, branch[i]));
            }
            idx >>= 1;
        }
        return computed;
    }
}
