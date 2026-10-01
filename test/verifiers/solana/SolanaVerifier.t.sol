// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {console} from "forge-std/console.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {AlpenglowCert} from "@hiero-ledger/clpr/verifiers/solana/AlpenglowCert.sol";
import {AlpenglowFinalityVerifier} from "@hiero-ledger/clpr/verifiers/solana/AlpenglowFinalityVerifier.sol";
import {SolanaCommittee} from "@hiero-ledger/clpr/verifiers/solana/SolanaCommittee.sol";
import {SolanaVerifier} from "@hiero-ledger/clpr/verifiers/solana/SolanaVerifier.sol";
import {SolanaTestKit} from "./SolanaTestKit.sol";

contract SolanaVerifierTest is SolanaTestKit {
    string internal constant CHAIN = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"; // devnet genesis hash prefix
    bytes32 internal constant PROGRAM = keccak256("clpr-solana-program");
    bytes32 internal constant CHANNEL = keccak256("channel-1");

    AlpenglowFinalityVerifier internal ag;
    SolanaVerifier internal v;
    SolanaCommittee.Committee internal c0;
    uint256[] internal k0;

    function setUp() public {
        (SolanaCommittee.Committee memory c, uint256[] memory keys) = _committee(5, 3, 0, 1);
        c0 = c;
        k0 = keys;
        ag = new AlpenglowFinalityVerifier();
        v = new SolanaVerifier(CHAIN, SolanaCommittee.hash(c), ag);
    }

    // ── builders ──────────────────────────────────────────────────────────────

    function _ctx() internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: CHANNEL, remoteServiceAddress: abi.encodePacked(PROGRAM)})
        );
    }

    function _anchor(uint8 mode, bytes32 committeeHash, uint64 nonce, bytes32 setHash, uint64 epoch)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(SolanaVerifier.Anchor(mode, committeeHash, nonce, bytes32(0), setHash, epoch));
    }

    function _att(uint64 slot, bytes32 blockRef) internal pure returns (SolanaVerifier.QueueAttestation memory a) {
        a.programId = PROGRAM;
        a.channelId = CHANNEL;
        a.slot = slot;
        a.blockRef = blockRef;
        a.status = uint8(ClprTypes.ChannelStatus.ACTIVE);
        a.nextMessageId = 3;
        a.sentRunningHash = keccak256("srh");
        a.receivedMessageId = 1;
        a.receivedRunningHash = keccak256("rrh");
        a.endpointManifestVersion = 1;
    }

    function _content() internal pure returns (bytes memory) {
        // ClprBundleContent { repeated bytes field 2 } with two payloads
        return abi.encodePacked(hex"1203", "abc", hex"1202", "de");
    }

    function _bundle(SolanaVerifier.QueueAttestation memory a, uint256[] memory signers)
        internal
        view
        returns (SolanaVerifier.BundleProof memory p)
    {
        p.committee = c0;
        p.attestation = a;
        p.sigs = _sign(k0, signers, v.queueDigest(SolanaCommittee.hash(c0), a));
        p.bundleContent = _content();
    }

    function _verify(SolanaVerifier.BundleProof memory p, bytes memory anchor)
        internal
        view
        returns (
            ClprTypes.QueueMetadata memory m,
            bytes[] memory payloads,
            bytes memory newAnchor,
            bytes memory newAnchorId
        )
    {
        (m, payloads, newAnchor, newAnchorId,) = v.verifyBundle(abi.encode(p), anchor, _ctx());
    }

    function _attestedAnchor() internal view returns (bytes memory) {
        return _anchor(1, SolanaCommittee.hash(c0), 0, bytes32(0), 0);
    }

    // ── ATTESTED mode ─────────────────────────────────────────────────────────

    function test_attested_typical_bundle() public view {
        SolanaVerifier.BundleProof memory p = _bundle(_att(452_171_492, keccak256("bh")), _range(0, 3));
        bytes memory data = abi.encode(p);
        uint256 g = gasleft();
        (ClprTypes.QueueMetadata memory m, bytes[] memory payloads, bytes memory na, bytes memory naId) =
            _verify(p, _attestedAnchor());
        g -= gasleft();
        console.log("attested bundle 3-of-5: gas %d, proof bytes %d", g, data.length);
        assertEq(m.nextMessageId, 3);
        assertEq(m.sentRunningHash, keccak256("srh"));
        assertEq(uint8(m.state), uint8(ClprTypes.ChannelStatus.ACTIVE));
        assertEq(payloads.length, 2);
        assertEq(payloads[0], bytes("abc"));
        assertEq(na.length, 0);
        assertEq(naId.length, 0);
    }

    function test_attested_13_of_19_gas() public {
        (SolanaCommittee.Committee memory c, uint256[] memory keys) = _committee(19, 13, 0, 5);
        SolanaVerifier v2 = new SolanaVerifier(CHAIN, SolanaCommittee.hash(c), ag);
        SolanaVerifier.BundleProof memory p;
        p.committee = c;
        p.attestation = _att(1, 0);
        p.sigs = _sign(keys, _range(0, 13), v2.queueDigest(SolanaCommittee.hash(c), p.attestation));
        p.bundleContent = _content();
        bytes memory data = abi.encode(p);
        bytes memory anchor = _anchor(1, SolanaCommittee.hash(c), 0, bytes32(0), 0);
        uint256 g = gasleft();
        v2.verifyBundle(data, anchor, _ctx());
        g -= gasleft();
        console.log("attested bundle 13-of-19: gas %d, proof bytes %d", g, data.length);
    }

    function test_attested_rejects_below_threshold() public {
        SolanaVerifier.BundleProof memory p = _bundle(_att(1, 0), _range(0, 2));
        vm.expectRevert(abi.encodeWithSelector(SolanaCommittee.BelowThreshold.selector, 2, 3));
        _verify(p, _attestedAnchor());
    }

    function test_attested_rejects_non_member_signature() public {
        SolanaVerifier.BundleProof memory p = _bundle(_att(1, 0), _range(0, 3));
        (, uint256[] memory outsiders) = _committee(5, 3, 0, 99);
        uint256[] memory one = new uint256[](1);
        one[0] = 2;
        SolanaCommittee.Signatures memory bad =
            _sign(outsiders, one, v.queueDigest(SolanaCommittee.hash(c0), p.attestation));
        p.sigs.sigs[2] = bad.sigs[0];
        vm.expectRevert(abi.encodeWithSelector(SolanaCommittee.BadSignature.selector, 2));
        _verify(p, _attestedAnchor());
    }

    function test_attested_rejects_duplicate_signer() public {
        SolanaVerifier.BundleProof memory p = _bundle(_att(1, 0), _range(0, 3));
        p.sigs.memberIndex[2] = p.sigs.memberIndex[1];
        p.sigs.sigs[2] = p.sigs.sigs[1];
        vm.expectRevert(SolanaCommittee.SignerIndexNotIncreasing.selector);
        _verify(p, _attestedAnchor());
    }

    function test_attested_rejects_tampered_queue_state() public {
        SolanaVerifier.BundleProof memory p = _bundle(_att(1, 0), _range(1, 4));
        p.attestation.nextMessageId = 4;
        vm.expectPartialRevert(SolanaCommittee.BadSignature.selector);
        _verify(p, _attestedAnchor());
    }

    function test_attested_rejects_wrong_committee() public {
        SolanaVerifier.BundleProof memory p = _bundle(_att(1, 0), _range(0, 3));
        bytes memory anchor = _anchor(1, keccak256("other"), 0, bytes32(0), 0);
        vm.expectPartialRevert(SolanaCommittee.CommitteeHashMismatch.selector);
        _verify(p, anchor);
    }

    function test_attested_rejects_other_program_or_channel() public {
        SolanaVerifier.QueueAttestation memory a = _att(1, 0);
        a.programId = keccak256("evil");
        SolanaVerifier.BundleProof memory p = _bundle(a, _range(0, 3));
        vm.expectRevert(SolanaVerifier.ProgramIdMismatch.selector);
        _verify(p, _attestedAnchor());
        a = _att(1, 0);
        a.channelId = keccak256("channel-2");
        p = _bundle(a, _range(0, 3));
        vm.expectRevert(SolanaVerifier.ChannelIdMismatch.selector);
        _verify(p, _attestedAnchor());
    }

    function test_attested_rejects_cross_chain_replay() public {
        SolanaVerifier other =
            new SolanaVerifier("solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z", SolanaCommittee.hash(c0), ag);
        SolanaVerifier.BundleProof memory p = _bundle(_att(1, 0), _range(0, 3));
        vm.expectPartialRevert(SolanaCommittee.BadSignature.selector);
        other.verifyBundle(abi.encode(p), _attestedAnchor(), _ctx());
    }

    function test_attested_rejects_finality_proof_and_set_updates() public {
        SolanaVerifier.BundleProof memory p = _bundle(_att(1, 0), _range(0, 3));
        p.finality = hex"00";
        vm.expectRevert(SolanaVerifier.UnexpectedFinalityProof.selector);
        _verify(p, _attestedAnchor());
        p.finality = "";
        p.setUpdates = new SolanaVerifier.EpochSetUpdate[](1);
        vm.expectRevert(SolanaVerifier.SetUpdatesNotAllowed.selector);
        _verify(p, _attestedAnchor());
    }

    function test_attested_rejects_bad_status() public {
        SolanaVerifier.QueueAttestation memory a = _att(1, 0);
        a.status = 6;
        SolanaVerifier.BundleProof memory p = _bundle(a, _range(0, 3));
        vm.expectRevert(abi.encodeWithSelector(SolanaVerifier.InvalidStatus.selector, 6));
        _verify(p, _attestedAnchor());
    }

    function test_attested_manifest_binding() public {
        ClprTypes.ClprEndpointManifest memory mf;
        mf.version = 2;
        mf.serviceAddress = abi.encodePacked(PROGRAM);
        mf.endpoints = new ClprTypes.Endpoint[](0);
        bytes memory pre = ClprProtobuf.encodeEndpointManifest(mf);
        SolanaVerifier.QueueAttestation memory a = _att(1, 0);
        a.manifestCommitment = keccak256(pre);
        SolanaVerifier.BundleProof memory p = _bundle(a, _range(0, 3));
        p.manifestPreimage = pre;
        (,,,, ClprTypes.ClprEndpointManifest memory got) = v.verifyBundle(abi.encode(p), _attestedAnchor(), _ctx());
        assertEq(got.version, 2);
        p.manifestPreimage = abi.encodePacked(pre, hex"00");
        vm.expectRevert(ClprEvmBundleVerifier.ManifestCommitmentMismatch.selector);
        _verify(p, _attestedAnchor());
    }

    // ── Committee rotation ────────────────────────────────────────────────────

    function _rotation(uint64 nonce, uint256 seed, SolanaCommittee.Committee memory from, uint256[] memory fromKeys)
        internal
        view
        returns (SolanaCommittee.Rotation memory r, uint256[] memory keys)
    {
        (r.next, keys) = _committee(7, 5, nonce, seed);
        r.sigs = _sign(
            fromKeys,
            _range(0, from.threshold),
            v.rotationDigest(SolanaCommittee.hash(from), SolanaCommittee.hash(r.next))
        );
    }

    function test_rotation_then_new_committee_signs() public view {
        (SolanaCommittee.Rotation memory r, uint256[] memory k1) = _rotation(1, 2, c0, k0);
        SolanaVerifier.BundleProof memory p;
        p.committee = c0;
        p.rotations = new SolanaCommittee.Rotation[](1);
        p.rotations[0] = r;
        p.attestation = _att(1, 0);
        p.sigs = _sign(k1, _range(0, 5), v.queueDigest(SolanaCommittee.hash(r.next), p.attestation));
        uint256 g = gasleft();
        (,, bytes memory na, bytes memory naId) = _verify(p, _attestedAnchor());
        g -= gasleft();
        console.log("attested bundle + rotation 5->7: gas %d, proof bytes %d", g, abi.encode(p).length);
        SolanaVerifier.Anchor memory an = abi.decode(na, (SolanaVerifier.Anchor));
        assertEq(an.committeeHash, SolanaCommittee.hash(r.next));
        assertEq(an.committeeNonce, 1);
        assertEq(naId, abi.encodePacked(uint64(1), uint64(0)));
    }

    function test_rotation_old_committee_cannot_sign_after_rotation() public {
        (SolanaCommittee.Rotation memory r,) = _rotation(1, 2, c0, k0);
        SolanaVerifier.BundleProof memory p;
        p.committee = c0;
        p.rotations = new SolanaCommittee.Rotation[](1);
        p.rotations[0] = r;
        p.attestation = _att(1, 0);
        p.sigs = _sign(k0, _range(0, 5), v.queueDigest(SolanaCommittee.hash(r.next), p.attestation));
        vm.expectPartialRevert(SolanaCommittee.BadSignature.selector);
        _verify(p, _attestedAnchor());
    }

    function test_rotation_rejects_minority_and_bad_nonce() public {
        (SolanaCommittee.Rotation memory r, uint256[] memory k1) = _rotation(1, 2, c0, k0);
        SolanaVerifier.BundleProof memory p;
        p.committee = c0;
        p.rotations = new SolanaCommittee.Rotation[](1);
        r.sigs = _sign(k0, _range(0, 2), v.rotationDigest(SolanaCommittee.hash(c0), SolanaCommittee.hash(r.next)));
        p.rotations[0] = r;
        p.attestation = _att(1, 0);
        p.sigs = _sign(k1, _range(0, 5), v.queueDigest(SolanaCommittee.hash(r.next), p.attestation));
        vm.expectRevert(abi.encodeWithSelector(SolanaCommittee.BelowThreshold.selector, 2, 3));
        _verify(p, _attestedAnchor());

        (r,) = _rotation(5, 2, c0, k0);
        p.rotations[0] = r;
        vm.expectRevert(abi.encodeWithSelector(SolanaCommittee.RotationNonceNotNext.selector, 5, 1));
        _verify(p, _attestedAnchor());
    }

    // ── ALPENGLOW mode on the live devnet genesis certificate ─────────────────

    function _live() internal view returns (AlpenglowCert.FinalityProof memory p, AlpenglowCert.EpochSet memory s) {
        string memory h = vm.readFile("test/e2e/fixtures/solana-live/devnet-genesis.proof.hex");
        (p, s) =
            abi.decode(vm.parseBytes(vm.replace(h, "\n", "")), (AlpenglowCert.FinalityProof, AlpenglowCert.EpochSet));
    }

    function _agBundle() internal view returns (SolanaVerifier.BundleProof memory p, bytes memory anchor) {
        (AlpenglowCert.FinalityProof memory fp, AlpenglowCert.EpochSet memory s) = _live();
        p = _bundle(_att(fp.slot, fp.blockId), _range(0, 3));
        p.finality = abi.encode(fp, s);
        anchor = _anchor(2, SolanaCommittee.hash(c0), 0, AlpenglowCert.setHash(s), s.epoch);
    }

    function test_alpenglow_live_devnet_bundle() public view {
        (SolanaVerifier.BundleProof memory p, bytes memory anchor) = _agBundle();
        uint256 g = gasleft();
        (ClprTypes.QueueMetadata memory m,,,) = _verify(p, anchor);
        g -= gasleft();
        console.log("alpenglow bundle (live devnet genesis cert): gas %d, proof bytes %d", g, abi.encode(p).length);
        assertEq(m.nextMessageId, 3);
    }

    function test_alpenglow_rejects_attestation_for_other_block() public {
        (SolanaVerifier.BundleProof memory p, bytes memory anchor) = _agBundle();
        p.attestation.blockRef = keccak256("fork");
        p.sigs = _sign(k0, _range(0, 3), v.queueDigest(SolanaCommittee.hash(c0), p.attestation));
        vm.expectRevert(SolanaVerifier.FinalityTargetMismatch.selector);
        _verify(p, anchor);
    }

    function test_alpenglow_rejects_unanchored_set() public {
        (SolanaVerifier.BundleProof memory p,) = _agBundle();
        bytes memory anchor = _anchor(2, SolanaCommittee.hash(c0), 0, keccak256("other set"), 1167);
        vm.expectPartialRevert(SolanaVerifier.UnknownEpochSet.selector);
        _verify(p, anchor);
    }

    function test_alpenglow_epoch_set_updates() public {
        (SolanaVerifier.BundleProof memory p, bytes memory anchor) = _agBundle();
        (, AlpenglowCert.EpochSet memory live) = _live();
        // Two later epochs signed by the committee: the live set (epoch 1167) falls out of the anchor.
        p.setUpdates = new SolanaVerifier.EpochSetUpdate[](2);
        for (uint256 i = 0; i < 2; i++) {
            AlpenglowCert.EpochSet memory s = _live2(live, uint64(1168 + i));
            p.setUpdates[i].set = s;
            p.setUpdates[i].sigs = _sign(k0, _range(0, 3), v.epochSetDigest(SolanaCommittee.hash(c0), s));
        }
        vm.expectPartialRevert(SolanaVerifier.UnknownEpochSet.selector);
        _verify(p, anchor);

        // One update keeps the live set as `prev`: still verifies, and the anchor advances.
        SolanaVerifier.EpochSetUpdate[] memory one = new SolanaVerifier.EpochSetUpdate[](1);
        one[0] = p.setUpdates[0];
        p.setUpdates = one;
        (,, bytes memory na,) = _verify(p, anchor);
        SolanaVerifier.Anchor memory an = abi.decode(na, (SolanaVerifier.Anchor));
        assertEq(an.curEpoch, 1168);
        assertEq(an.prevSetHash, AlpenglowCert.setHash(live));

        // Stale (non-increasing) epoch is refused.
        p.setUpdates[0].set = _live2(live, 1167);
        p.setUpdates[0].sigs = _sign(k0, _range(0, 3), v.epochSetDigest(SolanaCommittee.hash(c0), p.setUpdates[0].set));
        vm.expectRevert(abi.encodeWithSelector(SolanaVerifier.EpochNotIncreasing.selector, 1167, 1167));
        _verify(p, anchor);

        // An update signed by a minority is refused.
        p.setUpdates[0].set = _live2(live, 1170);
        p.setUpdates[0].sigs = _sign(k0, _range(0, 2), v.epochSetDigest(SolanaCommittee.hash(c0), p.setUpdates[0].set));
        vm.expectRevert(abi.encodeWithSelector(SolanaCommittee.BelowThreshold.selector, 2, 3));
        _verify(p, anchor);
    }

    function _live2(AlpenglowCert.EpochSet memory s, uint64 epoch)
        internal
        pure
        returns (AlpenglowCert.EpochSet memory o)
    {
        o = AlpenglowCert.EpochSet(
            epoch,
            epoch * 432_000,
            epoch * 432_000 + 431_999,
            s.shredVersion,
            s.size,
            s.depth,
            s.totalStake,
            s.root,
            s.aggregatePubkey
        );
    }

    // ── verifyConfig ──────────────────────────────────────────────────────────

    function _config(uint8 mode) internal view returns (SolanaVerifier.ConfigProof memory p) {
        p.committee = c0;
        p.attestation.programId = PROGRAM;
        p.attestation.slot = 1;
        p.attestation.peerConfigNanos = 123;
        p.attestation.throttles = ClprTypes.Throttles(10, 4096, 1_000_000, 100, 1 << 20, 4, 4);
        p.sigs = _sign(k0, _range(0, 3), v.configDigest(SolanaCommittee.hash(c0), p.attestation));
        p.mode = mode;
        if (mode == 2) {
            (, AlpenglowCert.EpochSet memory s) = _live();
            p.initialSet = new AlpenglowCert.EpochSet[](1);
            p.initialSet[0] = s;
            p.setSigs = _sign(k0, _range(0, 3), v.epochSetDigest(SolanaCommittee.hash(c0), s));
        }
    }

    function test_config_both_modes() public view {
        for (uint8 mode = 1; mode <= 2; mode++) {
            (bytes memory ctx, string memory cid, bytes memory svc, uint96 nanos,, bytes memory anchor,,) =
                v.verifyConfig(abi.encode(_config(mode)), CHANNEL, "");
            assertEq(cid, CHAIN);
            assertEq(svc, abi.encodePacked(PROGRAM));
            assertEq(ctx, _ctx());
            assertEq(nanos, 123);
            assertEq(abi.decode(anchor, (SolanaVerifier.Anchor)).mode, mode);
        }
    }

    function test_config_rejects_unpinned_committee_and_forged_config() public {
        SolanaVerifier.ConfigProof memory p = _config(1);
        (SolanaCommittee.Committee memory other, uint256[] memory ko) = _committee(5, 3, 0, 7);
        p.committee = other;
        p.sigs = _sign(ko, _range(0, 3), v.configDigest(SolanaCommittee.hash(other), p.attestation));
        vm.expectPartialRevert(SolanaCommittee.CommitteeHashMismatch.selector);
        v.verifyConfig(abi.encode(p), CHANNEL, "");

        p = _config(1);
        p.attestation.peerConfigNanos = 124;
        vm.expectPartialRevert(SolanaCommittee.BadSignature.selector);
        v.verifyConfig(abi.encode(p), CHANNEL, "");
    }

    function test_attested_only_deployment_refuses_alpenglow() public {
        SolanaVerifier attestedOnly =
            new SolanaVerifier(CHAIN, SolanaCommittee.hash(c0), AlpenglowFinalityVerifier(address(0)));
        bytes memory cfg = abi.encode(_config(2));
        vm.expectRevert(SolanaVerifier.AlpenglowUnavailable.selector);
        attestedOnly.verifyConfig(cfg, CHANNEL, "");
    }
}
