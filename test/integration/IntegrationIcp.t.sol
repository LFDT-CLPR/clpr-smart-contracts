// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {IcpHashTree} from "@hiero-ledger/clpr/libraries/proof/icp/IcpHashTree.sol";
import {IcpVerifier} from "@hiero-ledger/clpr/verifiers/icpmvx/IcpVerifier.sol";
import {IntegrationTestBase} from "@test/integration/IntegrationTestBase.sol";
import {IcpTestKit} from "@test/verifiers/icpmvx/IcpTestKit.sol";
import {ClprTestBase} from "@test/helpers/ClprTestBase.sol";

/// @dev Full CLPR lifecycle on an unmodified ClprService with IcpVerifier and the synthetic Internet
///      Computer of {IcpTestKit}: delegated BLS certificates and a CLPR canister witness.
contract IntegrationIcpTest is IntegrationTestBase, IcpTestKit {
    function setUp() public override(ClprTestBase, IcpTestKit) {
        IcpTestKit.setUp();
        control = _control(PEER_CHAIN_ID, CANISTER);
        v = new IcpVerifier(PEER_CHAIN_ID, rootDer, rootKey, 0);
        _setUp();
        _deployServiceAndConnect(address(v));
    }

    function _configProof() internal view returns (bytes memory) {
        IcpVerifier.ConfigProof memory p;
        p.witness = _witnessFor(channelId, record);
        p.cert = _cert(CANISTER, IcpHashTree.reconstruct(p.witness));
        p.controlMessage = control;
        return abi.encode(p);
    }

    function _deployAndConnectVerifier(address verifier_) internal override {
        bytes memory pubKey = _signerPubKey();
        channelId = _deriveTestChannelId(pubKey, bytes32(0));
        service.registerChannel(channelId, keccak256(abi.encodePacked(channelId, pubKey)));
        bytes32 msgHash = keccak256(abi.encodePacked(channelId, address(service)));
        (uint8 sv, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, _ethSignedHash(msgHash));
        service.completeChannel(
            channelId, pubKey, abi.encodePacked(r, s, sv), bytes32(0), verifier_, _configProof(), ""
        );
    }

    function _inbound() internal view returns (ClprTypes.QueueMetadata memory meta, bytes[] memory msgs) {
        msgs = _buildInboundBundles(1);
        bytes32 hash1 = sha256(abi.encodePacked(bytes32(0), sha256(msgs[0])));
        bytes32 hash2 = sha256(abi.encodePacked(hash1, sha256(msgs[1])));
        meta = ClprTypes.QueueMetadata({
            nextMessageId: 3,
            sentRunningHash: hash2,
            receivedMessageId: 1,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0
        });
    }

    function _proofFor(bytes32 channel, ClprTypes.QueueMetadata memory m, bytes memory content)
        internal
        view
        returns (bytes memory)
    {
        bytes memory rec = _record(
            uint8(m.state),
            m.nextMessageId,
            m.receivedMessageId,
            m.sentRunningHash,
            m.receivedRunningHash,
            m.endpointManifestVersion
        );
        IcpVerifier.BundleProof memory p;
        p.witness = _witnessFor(channel, rec);
        p.cert = _cert(CANISTER, IcpHashTree.reconstruct(p.witness));
        p.bundleContent = content;
        return abi.encode(p);
    }

    function test_completeChannel_setsRootKeyAnchor() public {
        ClprTypes.Channel memory c = service.getChannel(channelId);
        assertEq(c.verifier, address(v));
        assertEq(c.trustAnchor, _anchor());
        assertEq(c.peerServiceAddress, CANISTER);
    }

    function test_fullLifecycle() public {
        assertEq(_registerConnectorAndSend(), 1, "first outbound message");
        (ClprTypes.QueueMetadata memory meta, bytes[] memory msgs) = _inbound();
        bytes memory proof = _proofFor(channelId, meta, ClprProtobuf.encodeBundleContent(meta, msgs));

        uint256 g = gasleft();
        service.submitBundle(channelId, proof);
        g -= gasleft();
        console.log("submitBundle via IcpVerifier gas:", g, "proof bytes:", proof.length);

        _verifyPostBundle(1, 3, hex"48454C4C4F", 2, 2, 1, ClprTypes.ChannelStatus.ACTIVE);
        assertEq(service.getChannel(channelId).trustAnchor, _anchor(), "the anchor never rotates");

        // the same certified state again makes no progress
        bytes memory again = _proofFor(channelId, meta, "");
        vm.expectRevert(bytes4(keccak256("NoProgress()")));
        service.submitBundle(channelId, again);

        // an older certified state (nothing sent yet) is rejected: it makes no progress
        ClprTypes.QueueMetadata memory old = meta;
        old.nextMessageId = 1;
        old.sentRunningHash = bytes32(0);
        old.receivedMessageId = 0;
        bytes memory stale = _proofFor(channelId, old, "");
        vm.expectRevert(bytes4(keccak256("NoProgress()")));
        service.submitBundle(channelId, stale);
        _closeChannel();
    }

    function test_rejectBundle_storageProofForWrongChannel() public override {
        _registerConnectorAndSend();
        (ClprTypes.QueueMetadata memory meta, bytes[] memory msgs) = _inbound();
        bytes memory proof = _proofFor(keccak256("other channel"), meta, ClprProtobuf.encodeBundleContent(meta, msgs));
        vm.expectRevert(IcpHashTree.PathNotFound.selector);
        service.submitBundle(channelId, proof);
    }
}
