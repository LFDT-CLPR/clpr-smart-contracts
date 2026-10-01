// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {CantonAttestedProofs} from "@test/helpers/CantonAttestedProofs.sol";
import {CantonAttestedVerifier} from "@hiero-ledger/clpr/verifiers/canton/CantonAttestedVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";

contract CantonAttestedVerifierTest is CantonAttestedProofs {
    uint256 internal constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    CantonAttestedVerifier internal v;
    OperatorSet internal ops; // 3-of-4, epoch 0
    CantonAttestedVerifier.Rotation[] internal noRotations;

    function setUp() public {
        ops = _operators(1, 4, 3);
        v = _deploy(ops);
    }

    function _anchorBytes(OperatorSet memory s, uint64 epoch) internal pure returns (bytes memory) {
        return abi.encode(_anchor(s, epoch));
    }

    function _validProof(bytes[] memory payloads) internal view returns (bytes memory) {
        return
            _bundle(
                v, ops, 0, noRotations, _head(uint64(payloads.length), _chain(0, payloads)), payloads, "", _firstN(3)
            );
    }

    function _verify(bytes memory proof, bytes memory anchor)
        internal
        view
        returns (
            ClprTypes.QueueMetadata memory m,
            bytes[] memory p,
            bytes memory na,
            bytes memory nid,
            ClprTypes.ClprEndpointManifest memory man
        )
    {
        return v.verifyBundle(proof, anchor, _channelContext());
    }

    // ── Happy paths ──────────────────────────────────────────────────────────

    function test_trustModelLabel() public view {
        assertEq(v.TRUST_MODEL(), "t-of-n CLPR operators");
    }

    function test_bundle_happyPath() public view {
        bytes[] memory payloads = _samplePayloads(3);
        (
            ClprTypes.QueueMetadata memory m,
            bytes[] memory p,
            bytes memory na,
            bytes memory nid,
            ClprTypes.ClprEndpointManifest memory man
        ) = _verify(_validProof(payloads), _anchorBytes(ops, 0));
        assertEq(m.nextMessageId, 4);
        assertEq(m.sentRunningHash, _chain(0, payloads));
        assertEq(uint8(m.state), uint8(ClprTypes.ChannelStatus.ACTIVE));
        assertEq(m.endpointManifestVersion, 1);
        assertEq(p.length, 3);
        assertEq(p[2], payloads[2]);
        assertEq(na.length, 0);
        assertEq(nid.length, 0);
        assertEq(man.version, 0);
    }

    function test_bundle_allFourSignersAlsoAccepted() public view {
        bytes[] memory payloads = _samplePayloads(1);
        bytes memory proof = _bundle(v, ops, 0, noRotations, _head(1, _chain(0, payloads)), payloads, "", _firstN(4));
        _verify(proof, _anchorBytes(ops, 0));
    }

    function test_bundle_nonContiguousSignerSubset() public view {
        bytes[] memory payloads = _samplePayloads(1);
        uint256[] memory idx = new uint256[](3);
        (idx[0], idx[1], idx[2]) = (0, 2, 3);
        _verify(_bundle(v, ops, 0, noRotations, _head(1, _chain(0, payloads)), payloads, "", idx), _anchorBytes(ops, 0));
    }

    function test_bundle_ackOnlyEmptyPayloads() public view {
        bytes[] memory none = new bytes[](0);
        CantonAttestedVerifier.QueueHead memory h = _head(0, bytes32(0));
        h.receivedMessageId = 7;
        h.receivedRunningHash = keccak256("rx");
        (ClprTypes.QueueMetadata memory m, bytes[] memory p,,,) =
            _verify(_bundle(v, ops, 0, noRotations, h, none, "", _firstN(3)), _anchorBytes(ops, 0));
        assertEq(m.nextMessageId, 1);
        assertEq(m.receivedMessageId, 7);
        assertEq(m.receivedRunningHash, keccak256("rx"));
        assertEq(p.length, 0);
    }

    function test_bundle_withManifest() public view {
        bytes[] memory payloads = _samplePayloads(1);
        ClprTypes.ClprEndpointManifest memory mf;
        mf.version = 3;
        mf.serviceAddress = _serviceAddress();
        mf.endpoints = new ClprTypes.Endpoint[](0);
        bytes memory mb = ClprProtobuf.encodeEndpointManifest(mf);
        (,,,, ClprTypes.ClprEndpointManifest memory out) = _verify(
            _bundle(v, ops, 0, noRotations, _head(1, _chain(0, payloads)), payloads, mb, _firstN(3)),
            _anchorBytes(ops, 0)
        );
        assertEq(out.version, 3);
        assertEq(out.serviceAddress, _serviceAddress());
    }

    // ── Signature negatives ──────────────────────────────────────────────────

    function test_bundle_belowThreshold_reverts() public {
        bytes[] memory payloads = _samplePayloads(1);
        bytes memory proof = _bundle(v, ops, 0, noRotations, _head(1, _chain(0, payloads)), payloads, "", _firstN(2));
        bytes memory anchor = _anchorBytes(ops, 0);
        vm.expectRevert(abi.encodeWithSelector(CantonAttestedVerifier.BelowThreshold.selector, 2, 3));
        this.callVerify(proof, anchor);
    }

    function test_bundle_badSignature_reverts() public {
        bytes[] memory payloads = _samplePayloads(1);
        CantonAttestedVerifier.QueueHead memory h = _head(1, _chain(0, payloads));
        bytes32 digest = v.queueHeadDigest(_anchor(ops, 0), h, payloads, "");
        bytes memory sigs = _sign(digest, ops, _firstN(3));
        sigs[66 + 10] = bytes1(uint8(sigs[66 + 10]) ^ 1); // corrupt operator 1's r
        bytes memory proof = abi.encode(CantonAttestedVerifier.BundleProof(1, noRotations, h, payloads, "", sigs));
        bytes memory anchor = _anchorBytes(ops, 0);
        vm.expectRevert(abi.encodeWithSelector(CantonAttestedVerifier.BadSignature.selector, 1));
        this.callVerify(proof, anchor);
    }

    function test_bundle_wrongOperatorSet_reverts() public {
        // Signed by four strangers that are not the anchored set.
        OperatorSet memory strangers = _operators(100, 4, 3);
        bytes[] memory payloads = _samplePayloads(1);
        bytes memory proof =
            _bundle(v, strangers, 0, noRotations, _head(1, _chain(0, payloads)), payloads, "", _firstN(3));
        bytes memory anchor = _anchorBytes(ops, 0);
        vm.expectRevert(abi.encodeWithSelector(CantonAttestedVerifier.BadSignature.selector, 0));
        this.callVerify(proof, anchor);
    }

    function test_bundle_duplicateSigner_reverts() public {
        bytes[] memory payloads = _samplePayloads(1);
        uint256[] memory idx = new uint256[](3);
        (idx[0], idx[1], idx[2]) = (0, 1, 1);
        bytes memory proof = _bundle(v, ops, 0, noRotations, _head(1, _chain(0, payloads)), payloads, "", idx);
        bytes memory anchor = _anchorBytes(ops, 0);
        vm.expectRevert(CantonAttestedVerifier.SignersNotAscending.selector);
        this.callVerify(proof, anchor);
    }

    function test_bundle_unknownOperatorIndex_reverts() public {
        bytes[] memory payloads = _samplePayloads(1);
        CantonAttestedVerifier.QueueHead memory h = _head(1, _chain(0, payloads));
        bytes32 digest = v.queueHeadDigest(_anchor(ops, 0), h, payloads, "");
        bytes memory sigs = bytes.concat(_sign(digest, ops, _firstN(3)), abi.encodePacked(uint8(9), new bytes(65)));
        bytes memory proof = abi.encode(CantonAttestedVerifier.BundleProof(1, noRotations, h, payloads, "", sigs));
        bytes memory anchor = _anchorBytes(ops, 0);
        vm.expectRevert(abi.encodeWithSelector(CantonAttestedVerifier.UnknownOperator.selector, 9));
        this.callVerify(proof, anchor);
    }

    function test_bundle_highS_malleatedSignature_reverts() public {
        bytes[] memory payloads = _samplePayloads(1);
        CantonAttestedVerifier.QueueHead memory h = _head(1, _chain(0, payloads));
        bytes32 digest = v.queueHeadDigest(_anchor(ops, 0), h, payloads, "");
        (uint8 vv, bytes32 r, bytes32 s) = vm.sign(ops.keys[0], digest);
        bytes32 highS = bytes32(SECP256K1_N - uint256(s));
        uint8 flippedV = vv == 27 ? 28 : 27;
        bytes memory sigs =
            bytes.concat(abi.encodePacked(uint8(0), r, highS, flippedV), _sign(digest, ops, _range(1, 3)));
        bytes memory proof = abi.encode(CantonAttestedVerifier.BundleProof(1, noRotations, h, payloads, "", sigs));
        bytes memory anchor = _anchorBytes(ops, 0);
        vm.expectRevert(abi.encodeWithSelector(CantonAttestedVerifier.BadSignature.selector, 0));
        this.callVerify(proof, anchor);
    }

    function test_bundle_malformedSignatureLength_reverts() public {
        bytes[] memory payloads = _samplePayloads(1);
        CantonAttestedVerifier.QueueHead memory h = _head(1, _chain(0, payloads));
        bytes memory proof =
            abi.encode(CantonAttestedVerifier.BundleProof(1, noRotations, h, payloads, "", new bytes(65)));
        bytes memory anchor = _anchorBytes(ops, 0);
        vm.expectRevert(CantonAttestedVerifier.MalformedSignatures.selector);
        this.callVerify(proof, anchor);
    }

    // ── Content binding negatives ────────────────────────────────────────────

    function test_bundle_tamperedPayload_reverts() public {
        bytes[] memory payloads = _samplePayloads(2);
        bytes memory proof = _validProof(payloads);
        CantonAttestedVerifier.BundleProof memory p = abi.decode(proof, (CantonAttestedVerifier.BundleProof));
        p.payloads[1] = hex"0a03220178";
        bytes memory anchor = _anchorBytes(ops, 0);
        vm.expectRevert();
        this.callVerify(abi.encode(p), anchor);
    }

    function test_bundle_tamperedRunningHash_reverts() public {
        bytes[] memory payloads = _samplePayloads(2);
        CantonAttestedVerifier.BundleProof memory p =
            abi.decode(_validProof(payloads), (CantonAttestedVerifier.BundleProof));
        p.head.runningHash = bytes32(uint256(p.head.runningHash) ^ 1);
        bytes memory anchor = _anchorBytes(ops, 0);
        vm.expectRevert();
        this.callVerify(abi.encode(p), anchor);
    }

    function test_bundle_tamperedMessageId_reverts() public {
        bytes[] memory payloads = _samplePayloads(2);
        CantonAttestedVerifier.BundleProof memory p =
            abi.decode(_validProof(payloads), (CantonAttestedVerifier.BundleProof));
        p.head.messageId = 3;
        bytes memory anchor = _anchorBytes(ops, 0);
        vm.expectRevert();
        this.callVerify(abi.encode(p), anchor);
    }

    function test_bundle_otherChannel_reverts() public {
        bytes[] memory payloads = _samplePayloads(1);
        bytes memory proof = _validProof(payloads);
        bytes memory otherCtx = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: bytes32(uint256(0xBAD)), remoteServiceAddress: _serviceAddress()})
        );
        bytes memory anchor = _anchorBytes(ops, 0);
        vm.expectRevert(CantonAttestedVerifier.ChannelMismatch.selector);
        v.verifyBundle(proof, anchor, otherCtx);
    }

    function test_bundle_otherServiceAddress_reverts() public {
        bytes[] memory payloads = _samplePayloads(1);
        bytes memory proof = _validProof(payloads);
        bytes memory otherCtx = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: CHANNEL_ID, remoteServiceAddress: bytes("clpr::other")})
        );
        bytes memory anchor = _anchorBytes(ops, 0);
        vm.expectRevert(CantonAttestedVerifier.ServiceAddressMismatch.selector);
        v.verifyBundle(proof, anchor, otherCtx);
    }

    function test_bundle_otherCantonPartyAnchor_reverts() public {
        CantonAttestedVerifier.TrustAnchor memory a = _anchor(ops, 0);
        a.cantonParty = keccak256("clpr::other");
        bytes memory proof = _validProof(_samplePayloads(1));
        vm.expectRevert(CantonAttestedVerifier.WrongCantonParty.selector);
        this.callVerify(proof, abi.encode(a));
    }

    function test_bundle_signaturesFromOtherVerifierDeployment_reverts() public {
        // Same operators, same anchor, different verifyingContract in the EIP-712 domain.
        CantonAttestedVerifier other = _deploy(ops);
        bytes[] memory payloads = _samplePayloads(1);
        bytes memory proof =
            _bundle(other, ops, 0, noRotations, _head(1, _chain(0, payloads)), payloads, "", _firstN(3));
        bytes memory anchor = _anchorBytes(ops, 0);
        vm.expectRevert();
        this.callVerify(proof, anchor);
    }

    function test_bundle_statusOutOfRange_reverts() public {
        bytes[] memory payloads = _samplePayloads(1);
        CantonAttestedVerifier.QueueHead memory h = _head(1, _chain(0, payloads));
        h.status = 6;
        bytes memory proof = _bundle(v, ops, 0, noRotations, h, payloads, "", _firstN(3));
        bytes memory anchor = _anchorBytes(ops, 0);
        vm.expectRevert(CantonAttestedVerifier.InvalidQueueHead.selector);
        this.callVerify(proof, anchor);
    }

    function test_bundle_morePayloadsThanMessageId_reverts() public {
        bytes[] memory payloads = _samplePayloads(3);
        bytes memory proof = _bundle(v, ops, 0, noRotations, _head(2, _chain(0, payloads)), payloads, "", _firstN(3));
        bytes memory anchor = _anchorBytes(ops, 0);
        vm.expectRevert(CantonAttestedVerifier.InvalidQueueHead.selector);
        this.callVerify(proof, anchor);
    }

    function test_bundle_nonCanonicalEncoding_reverts() public {
        bytes memory proof = _validProof(_samplePayloads(1));
        // Dirty the padding after the last byte: the decoder ignores it, the canonical check does not.
        proof[proof.length - 1] = 0x01;
        bytes memory anchor = _anchorBytes(ops, 0);
        vm.expectRevert(CantonAttestedVerifier.NonCanonicalProof.selector);
        this.callVerify(proof, anchor);
    }

    function test_bundle_wrongVersion_reverts() public {
        CantonAttestedVerifier.BundleProof memory p =
            abi.decode(_validProof(_samplePayloads(1)), (CantonAttestedVerifier.BundleProof));
        p.version = 2;
        bytes memory anchor = _anchorBytes(ops, 0);
        vm.expectRevert(abi.encodeWithSelector(CantonAttestedVerifier.UnsupportedProofVersion.selector, 2));
        this.callVerify(abi.encode(p), anchor);
    }

    function test_bundle_manifestServiceAddressMismatch_reverts() public {
        bytes[] memory payloads = _samplePayloads(1);
        ClprTypes.ClprEndpointManifest memory mf;
        mf.version = 2;
        mf.serviceAddress = bytes("clpr::other");
        mf.endpoints = new ClprTypes.Endpoint[](0);
        bytes memory proof = _bundle(
            v,
            ops,
            0,
            noRotations,
            _head(1, _chain(0, payloads)),
            payloads,
            ClprProtobuf.encodeEndpointManifest(mf),
            _firstN(3)
        );
        bytes memory anchor = _anchorBytes(ops, 0);
        vm.expectRevert(CantonAttestedVerifier.ManifestServiceAddressMismatch.selector);
        this.callVerify(proof, anchor);
    }

    // ── Rotation and replay ──────────────────────────────────────────────────

    function test_rotation_happyPath_andNewAnchorReturned() public view {
        OperatorSet memory next = _operators(50, 5, 3);
        CantonAttestedVerifier.Rotation[] memory rots = new CantonAttestedVerifier.Rotation[](1);
        rots[0] = _rotation(v, ops, 0, next, _firstN(3));
        bytes[] memory payloads = _samplePayloads(1);
        bytes memory proof = _bundle(v, next, 1, rots, _head(1, _chain(0, payloads)), payloads, "", _firstN(3));
        (,, bytes memory na, bytes memory nid,) = _verify(proof, _anchorBytes(ops, 0));
        assertEq(na, _anchorBytes(next, 1));
        assertEq(nid, abi.encodePacked(uint64(1)));
    }

    function test_rotation_chainOfTwo() public view {
        OperatorSet memory s1 = _operators(50, 5, 3);
        OperatorSet memory s2 = _operators(70, 3, 2);
        CantonAttestedVerifier.Rotation[] memory rots = new CantonAttestedVerifier.Rotation[](2);
        rots[0] = _rotation(v, ops, 0, s1, _firstN(3));
        rots[1] = _rotation(v, s1, 1, s2, _firstN(3));
        bytes[] memory payloads = _samplePayloads(1);
        (,, bytes memory na,,) = _verify(
            _bundle(v, s2, 2, rots, _head(1, _chain(0, payloads)), payloads, "", _firstN(2)), _anchorBytes(ops, 0)
        );
        assertEq(na, _anchorBytes(s2, 2));
    }

    function test_rotation_belowThreshold_reverts() public {
        OperatorSet memory next = _operators(50, 5, 3);
        CantonAttestedVerifier.Rotation[] memory rots = new CantonAttestedVerifier.Rotation[](1);
        rots[0] = _rotation(v, ops, 0, next, _firstN(2));
        bytes[] memory payloads = _samplePayloads(1);
        bytes memory proof = _bundle(v, next, 1, rots, _head(1, _chain(0, payloads)), payloads, "", _firstN(3));
        bytes memory anchor = _anchorBytes(ops, 0);
        vm.expectRevert(abi.encodeWithSelector(CantonAttestedVerifier.BelowThreshold.selector, 2, 3));
        this.callVerify(proof, anchor);
    }

    function test_rotation_signedByNewSetOnly_reverts() public {
        // The incoming set cannot authorize itself.
        OperatorSet memory next = _operators(50, 5, 3);
        CantonAttestedVerifier.Rotation[] memory rots = new CantonAttestedVerifier.Rotation[](1);
        bytes32 digest = v.rotationDigest(_anchor(ops, 0), next.threshold, next.addrs);
        rots[0] = CantonAttestedVerifier.Rotation(next.threshold, next.addrs, _sign(digest, next, _firstN(3)));
        bytes[] memory payloads = _samplePayloads(1);
        bytes memory proof = _bundle(v, next, 1, rots, _head(1, _chain(0, payloads)), payloads, "", _firstN(3));
        bytes memory anchor = _anchorBytes(ops, 0);
        vm.expectRevert();
        this.callVerify(proof, anchor);
    }

    function test_rotation_minorityThreshold_reverts() public {
        // 2-of-4 is not a strict majority.
        OperatorSet memory weak = _operators(50, 4, 2);
        CantonAttestedVerifier.Rotation[] memory rots = new CantonAttestedVerifier.Rotation[](1);
        rots[0] = _rotation(v, ops, 0, weak, _firstN(3));
        bytes[] memory payloads = _samplePayloads(1);
        bytes memory proof = _bundle(v, weak, 1, rots, _head(1, _chain(0, payloads)), payloads, "", _firstN(2));
        bytes memory anchor = _anchorBytes(ops, 0);
        vm.expectRevert(CantonAttestedVerifier.InvalidOperatorSet.selector);
        this.callVerify(proof, anchor);
    }

    function test_rotation_unsortedOperators_reverts() public {
        OperatorSet memory next = _operators(50, 3, 2);
        (next.addrs[0], next.addrs[1]) = (next.addrs[1], next.addrs[0]);
        CantonAttestedVerifier.Rotation[] memory rots = new CantonAttestedVerifier.Rotation[](1);
        rots[0] = _rotation(v, ops, 0, next, _firstN(3));
        bytes[] memory payloads = _samplePayloads(1);
        bytes memory proof = _bundle(v, ops, 0, noRotations, _head(1, _chain(0, payloads)), payloads, "", _firstN(3));
        CantonAttestedVerifier.BundleProof memory p = abi.decode(proof, (CantonAttestedVerifier.BundleProof));
        p.rotations = rots;
        bytes memory anchor = _anchorBytes(ops, 0);
        vm.expectRevert(CantonAttestedVerifier.InvalidOperatorSet.selector);
        this.callVerify(abi.encode(p), anchor);
    }

    function test_replay_oldEpochHeadAfterRotation_reverts() public {
        // A head attested by the epoch-0 set is not accepted against the epoch-1 anchor, even when
        // the epoch-0 operators are still members of the epoch-1 set.
        OperatorSet memory same = ops;
        bytes[] memory payloads = _samplePayloads(1);
        bytes memory oldProof = _bundle(v, ops, 0, noRotations, _head(1, _chain(0, payloads)), payloads, "", _firstN(3));
        bytes memory epoch1Anchor = _anchorBytes(same, 1);
        vm.expectRevert();
        this.callVerify(oldProof, epoch1Anchor);
    }

    function test_replay_rotationCannotBeReappliedFromNewEpoch() public {
        // The epoch-0 -> 1 rotation signatures do not authorize 1 -> 2.
        OperatorSet memory next = _operators(50, 5, 3);
        CantonAttestedVerifier.Rotation[] memory rots = new CantonAttestedVerifier.Rotation[](1);
        rots[0] = _rotation(v, ops, 0, next, _firstN(3));
        bytes[] memory payloads = _samplePayloads(1);
        bytes memory proof = _bundle(v, next, 2, rots, _head(1, _chain(0, payloads)), payloads, "", _firstN(3));
        bytes memory anchor = _anchorBytes(ops, 1);
        vm.expectRevert();
        this.callVerify(proof, anchor);
    }

    function test_constructor_rejectsMinorityThreshold() public {
        OperatorSet memory weak = _operators(1, 4, 2);
        vm.expectRevert(CantonAttestedVerifier.InvalidOperatorSet.selector);
        new CantonAttestedVerifier(_anchor(weak, 0), CANTON_CHAIN_ID);
    }

    // ── verifyConfig ─────────────────────────────────────────────────────────

    function test_config_happyPath_withRotationAndManifest() public view {
        OperatorSet memory next = _operators(50, 5, 3);
        CantonAttestedVerifier.Rotation[] memory rots = new CantonAttestedVerifier.Rotation[](1);
        rots[0] = _rotation(v, ops, 0, next, _firstN(3));
        bytes memory cfg = _configProof(v, ops, rots, next, 1, CHANNEL_ID, CANTON_CHAIN_ID, _serviceAddress());
        ClprTypes.ClprEndpointManifest memory mf;
        mf.version = 1;
        mf.serviceAddress = _serviceAddress();
        mf.endpoints = new ClprTypes.Endpoint[](0);
        bytes memory mp = _manifestProof(v, next, 1, CHANNEL_ID, ClprProtobuf.encodeEndpointManifest(mf));
        (
            bytes memory ctx,
            string memory chainId,
            bytes memory svc,
            uint96 nanos,
            ClprTypes.Throttles memory t,
            bytes memory anchor,
            bytes memory anchorId,
            ClprTypes.ClprEndpointManifest memory outMf
        ) = v.verifyConfig(cfg, CHANNEL_ID, mp);
        assertEq(ctx, _channelContext());
        assertEq(chainId, CANTON_CHAIN_ID);
        assertEq(svc, _serviceAddress());
        assertEq(nanos, 1_700_000_000_000_000_000);
        assertEq(t.maxMessagesPerBundle, 50);
        assertEq(anchor, _anchorBytes(next, 1));
        assertEq(anchorId, abi.encodePacked(uint64(1)));
        assertEq(outMf.version, 1);
    }

    function test_config_genesisMismatch_reverts() public {
        OperatorSet memory other = _operators(200, 4, 3);
        bytes memory cfg = _configProof(v, other, noRotations, other, 0, CHANNEL_ID, CANTON_CHAIN_ID, _serviceAddress());
        vm.expectRevert(CantonAttestedVerifier.GenesisMismatch.selector);
        v.verifyConfig(cfg, CHANNEL_ID, "");
    }

    function test_config_otherChannelId_reverts() public {
        bytes memory cfg = _configProof(v, ops, noRotations, ops, 0, CHANNEL_ID, CANTON_CHAIN_ID, _serviceAddress());
        vm.expectRevert();
        v.verifyConfig(cfg, bytes32(uint256(0xBAD)), "");
    }

    function test_config_manifestSignedByStaleSet_reverts() public {
        OperatorSet memory next = _operators(50, 5, 3);
        CantonAttestedVerifier.Rotation[] memory rots = new CantonAttestedVerifier.Rotation[](1);
        rots[0] = _rotation(v, ops, 0, next, _firstN(3));
        bytes memory cfg = _configProof(v, ops, rots, next, 1, CHANNEL_ID, CANTON_CHAIN_ID, _serviceAddress());
        ClprTypes.ClprEndpointManifest memory mf;
        mf.version = 1;
        mf.serviceAddress = _serviceAddress();
        mf.endpoints = new ClprTypes.Endpoint[](0);
        bytes memory mp = _manifestProof(v, ops, 0, CHANNEL_ID, ClprProtobuf.encodeEndpointManifest(mf));
        vm.expectRevert();
        v.verifyConfig(cfg, CHANNEL_ID, mp);
    }

    // ── Gas and calldata (Hedera: 15M gas, 128 KB calldata) ─────────────────

    function test_gas_typicalBundle_7of10_10x256B() public {
        _measureBundle(10, 7, 10, 256, "bundle n=10 t=7, 10 payloads x 256 B");
    }

    function test_gas_bundle_11of16_50x1KB() public {
        _measureBundle(16, 11, 50, 1024, "bundle n=16 t=11, 50 payloads x 1 KB");
    }

    function test_gas_bundle_43of64_1x256B() public {
        _measureBundle(64, 43, 1, 256, "bundle n=64 t=43, 1 payload x 256 B");
    }

    function test_gas_rotation_7of10_to_7of10() public {
        OperatorSet memory a = _operators(1000, 10, 7);
        OperatorSet memory b = _operators(2000, 10, 7);
        CantonAttestedVerifier w = _deploy(a);
        CantonAttestedVerifier.Rotation[] memory rots = new CantonAttestedVerifier.Rotation[](1);
        rots[0] = _rotation(w, a, 0, b, _firstN(7));
        bytes[] memory none = new bytes[](0);
        bytes memory proof = _bundle(w, b, 1, rots, _head(0, bytes32(0)), none, "", _firstN(7));
        bytes memory anchor = abi.encode(_anchor(a, 0));
        bytes memory ctx = _channelContext();
        uint256 g = gasleft();
        w.verifyBundle(proof, anchor, ctx);
        uint256 used = g - gasleft();
        emit log_named_uint("rotation-only bundle n=10 t=7: gas", used);
        emit log_named_uint("rotation-only bundle n=10 t=7: proof bytes", proof.length);
        assertLt(used, 1_000_000);
    }

    function _measureBundle(uint256 n, uint16 t, uint256 k, uint256 size, string memory label) internal {
        OperatorSet memory s = _operators(500, n, t);
        CantonAttestedVerifier w = _deploy(s);
        bytes[] memory payloads = new bytes[](k);
        for (uint256 i = 0; i < k; ++i) {
            payloads[i] = abi.encodePacked(uint8(0x0a), _blob(size, i));
        }
        bytes memory proof =
            _bundle(w, s, 0, noRotations, _head(uint64(k), _chain(0, payloads)), payloads, "", _firstN(t));
        bytes memory anchor = abi.encode(_anchor(s, 0));
        bytes memory ctx = _channelContext();
        uint256 g = gasleft();
        w.verifyBundle(proof, anchor, ctx);
        uint256 used = g - gasleft();
        emit log_named_uint(string.concat(label, ": gas"), used);
        emit log_named_uint(string.concat(label, ": proof bytes"), proof.length);
        assertLt(used, 15_000_000);
        assertLt(proof.length + anchor.length, 128 * 1024);
    }

    function _blob(uint256 size, uint256 salt) internal pure returns (bytes memory b) {
        b = new bytes(size);
        for (uint256 i = 0; i < size; i += 32) {
            bytes32 w = keccak256(abi.encode(salt, i));
            for (uint256 j = 0; j < 32 && i + j < size; ++j) {
                b[i + j] = w[j];
            }
        }
    }

    function _range(uint256 from, uint256 to) internal pure returns (uint256[] memory idx) {
        idx = new uint256[](to - from + 1);
        for (uint256 i = from; i <= to; ++i) {
            idx[i - from] = i;
        }
    }

    /// @dev External hop so `vm.expectRevert` sees the verifier call at the right depth.
    function callVerify(bytes memory proof, bytes memory anchor) external view {
        v.verifyBundle(proof, anchor, _channelContext());
    }
}
