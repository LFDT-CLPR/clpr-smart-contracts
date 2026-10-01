// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {CantonAttestedVerifier} from "@hiero-ledger/clpr/verifiers/canton/CantonAttestedVerifier.sol";
import {IntegrationTestBase} from "@test/integration/IntegrationTestBase.sol";
import {CantonAttestedProofs} from "@test/helpers/CantonAttestedProofs.sol";

/// @dev Full ClprService lifecycle (completeChannel -> sendMessage -> submitBundle -> close) with
///      CantonAttestedVerifier as the channel's verifier, mirroring IntegrationMock.
contract IntegrationCantonTest is IntegrationTestBase, CantonAttestedProofs {
    CantonAttestedVerifier internal canton;
    OperatorSet internal ops;
    CantonAttestedVerifier.Rotation[] internal noRotations;

    function setUp() public override {
        ops = _operators(1, 4, 3);
        canton = _deploy(ops);
        _deployServiceAndConnect(address(canton));
    }

    function _deployAndConnectVerifier(address verifier_) internal override {
        bytes memory pubKey = _signerPubKey();
        channelId = service.deriveChannelId(CANTON_CHAIN_ID, pubKey, bytes32(0));
        service.registerChannel(channelId, keccak256(abi.encodePacked(channelId, pubKey)));
        bytes32 msgHash = keccak256(abi.encodePacked(channelId, address(service)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, _ethSignedHash(msgHash));
        bytes memory configProof =
            _configProof(canton, ops, noRotations, ops, 0, channelId, CANTON_CHAIN_ID, _serviceAddress());
        service.completeChannel(channelId, pubKey, abi.encodePacked(r, s, v), bytes32(0), verifier_, configProof, "");
    }

    function _headFor(uint64 messageId, bytes32 runningHash, uint64 receivedMessageId)
        internal
        view
        returns (CantonAttestedVerifier.QueueHead memory h)
    {
        h = _head(messageId, runningHash);
        h.channelId = channelId;
        h.receivedMessageId = receivedMessageId;
    }

    function _dataPayload() internal view returns (bytes memory) {
        return
            ClprProtobuf.encodeDataMessage(
                connectorAddr, abi.encodePacked(address(app)), hex"BEEF0102", hex"48454C4C4F"
            );
    }

    function _replyPayload() internal pure returns (bytes memory) {
        return ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"504F4E47524550");
    }

    function test_fullLifecycle_cantonAttestedBundle() public {
        assertEq(_registerConnectorAndSend(), 1);
        bytes[] memory payloads = new bytes[](2);
        payloads[0] = _dataPayload();
        payloads[1] = _replyPayload();
        // The reference ClprService folds sha256(payload) into the chain (pre-ADR 2026-08-01 rule);
        // the Daml app's PayloadDigest scheme produces the same value.
        bytes memory proof =
            _bundle(canton, ops, 0, noRotations, _headFor(2, _chain(0, payloads), 1), payloads, "", _firstN(3));

        service.submitBundle(channelId, proof);

        _verifyPostBundle(1, 3, hex"48454C4C4F", 2, 2, 1, ClprTypes.ChannelStatus.ACTIVE);
        _closeChannel();
    }

    function test_rotationAdvancesStoredTrustAnchor() public {
        _registerConnectorAndSend();
        OperatorSet memory next = _operators(50, 5, 3);
        CantonAttestedVerifier.Rotation[] memory rots = new CantonAttestedVerifier.Rotation[](1);
        rots[0] = _rotation(canton, ops, 0, next, _firstN(3));
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = _dataPayload();
        service.submitBundle(
            channelId, _bundle(canton, next, 1, rots, _headFor(1, _chain(0, payloads), 0), payloads, "", _firstN(3))
        );
        ClprTypes.Channel memory ch = service.getChannel(channelId);
        assertEq(ch.trustAnchor, abi.encode(_anchor(next, 1)));
        assertEq(ch.receivedMessageId, 1);

        // The old set can no longer attest this channel.
        bytes[] memory none = new bytes[](0);
        bytes memory stale =
            _bundle(canton, ops, 0, noRotations, _headFor(1, _chain(0, payloads), 1), none, "", _firstN(3));
        vm.expectRevert();
        service.submitBundle(channelId, stale);
    }

    function test_replayedBundleRejectedByService() public {
        _registerConnectorAndSend();
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = _dataPayload();
        bytes memory proof =
            _bundle(canton, ops, 0, noRotations, _headFor(1, _chain(0, payloads), 0), payloads, "", _firstN(3));
        service.submitBundle(channelId, proof);
        vm.expectRevert();
        service.submitBundle(channelId, proof);
    }

    /// @dev Documents the open spec/implementation gap: a queue hashed with the spec §4.1 rule
    ///      (sha256(prev || payload), ADR 2026-08-01) is rejected by today's reference ClprService.
    function test_specDirectRunningHash_rejectedByReferenceService() public {
        _registerConnectorAndSend();
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = _dataPayload();
        bytes32 specHash = sha256(abi.encodePacked(bytes32(0), payloads[0]));
        bytes memory proof = _bundle(canton, ops, 0, noRotations, _headFor(1, specHash, 0), payloads, "", _firstN(3));
        vm.expectRevert(ClprTypes.ClprRunningHashMismatch.selector);
        service.submitBundle(channelId, proof);
    }

    /// @dev A head attested for another channel is rejected for this one.
    function test_rejectBundle_storageProofForWrongChannel() public override {
        _registerConnectorAndSend();
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = _dataPayload();
        CantonAttestedVerifier.QueueHead memory h = _headFor(1, _chain(0, payloads), 0);
        h.channelId = bytes32(uint256(channelId) ^ 1);
        bytes memory proof = _bundle(canton, ops, 0, noRotations, h, payloads, "", _firstN(3));
        vm.expectRevert(CantonAttestedVerifier.ChannelMismatch.selector);
        service.submitBundle(channelId, proof);
    }
}
