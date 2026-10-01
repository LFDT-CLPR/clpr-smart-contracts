// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {Ed25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/Ed25519Verifier.sol";
import {StellarScpVerifier} from "@hiero-ledger/clpr/verifiers/evm/stellar/StellarScpVerifier.sol";
import {IntegrationTestBase} from "@test/integration/IntegrationTestBase.sol";
import {StellarTestBuilder} from "@test/verifiers/evm/stellar/StellarTestBuilder.sol";

/// @dev Full CLPR lifecycle on an unmodified ClprService with StellarScpVerifier and the synthetic
///      Stellar chain (real Ed25519 SCP signatures, real XDR). The fixture's `clpr_queue` event carries
///      the metadata of IntegrationTestBase's inbound DATA + REPLY, so this suite pins the deployment
///      order the fixture generator assumed (Ed25519Verifier, then the verifier, then the service).
contract IntegrationStellarTest is IntegrationTestBase, StellarTestBuilder {
    StellarScpVerifier internal stellarVerifier;

    function setUp() public override {
        _setUp();
        _loadFixture();
        Ed25519Verifier ed = new Ed25519Verifier();
        stellarVerifier = new StellarScpVerifier(ed, NETWORK_ID, PEER_CHAIN_ID);
        _deployServiceAndConnect(address(stellarVerifier));
    }

    function _configProof() internal view returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory lc;
        lc.protocolVersion = 1;
        lc.chainId = PEER_CHAIN_ID; // _deriveTestChannelId's peer chain
        lc.serviceAddress = abi.encodePacked(SERVICE);
        lc.nanosSinceEpoch = PEER_CONFIG_NANOS;
        lc.throttles = ClprTypes.Throttles(10, 4096, 500_000, 100, 131_072, 4, 4);
        bytes[] memory items = new bytes[](3);
        items[0] = _str(Q1);
        items[1] = _scpStd(101);
        items[2] = _str(ClprProtobuf.encodeControlMessage(lc));
        return _list(items);
    }

    function _deployAndConnectVerifier(address verifier_) internal override {
        bytes memory pubKey = _signerPubKey();
        channelId = _deriveTestChannelId(pubKey, bytes32(0));
        service.registerChannel(channelId, keccak256(abi.encodePacked(channelId, pubKey)));
        bytes32 msgHash = keccak256(abi.encodePacked(channelId, address(service)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, _ethSignedHash(msgHash));
        service.completeChannel(channelId, pubKey, abi.encodePacked(r, s, v), bytes32(0), verifier_, _configProof(), "");
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

    function _content(ClprTypes.QueueMetadata memory meta, bytes[] memory msgs) internal pure returns (bytes memory) {
        return ClprProtobuf.encodeBundleContent(meta, msgs);
    }

    function test_fixtureMatchesIntegrationBase() public {
        _registerConnectorAndSend();
        (ClprTypes.QueueMetadata memory meta,) = _inbound();
        assertEq(channelId, CHANNEL, "fixture channel id drifted: rerun npm run stellar-synthetic:refresh");
        assertEq(
            keccak256(abi.encode(meta)),
            keccak256(abi.encode(_fixtureMeta())),
            "fixture metadata drifted: rerun npm run stellar-synthetic:refresh"
        );
    }

    function test_completeChannel_setsStellarAnchor() public {
        ClprTypes.Channel memory c = service.getChannel(channelId);
        assertEq(c.verifier, address(stellarVerifier));
        assertEq(c.trustAnchor, _anchor(Q1_HASH, 101, 100, _headerHash(100), bytes32(0)));
        assertEq(c.peerServiceAddress, abi.encodePacked(SERVICE));
    }

    function test_fullLifecycle() public {
        assertEq(_registerConnectorAndSend(), 1, "first outbound message");
        (ClprTypes.QueueMetadata memory meta, bytes[] memory msgs) = _inbound();
        bytes memory proof =
            _bundle(Q1, _scpStd(105), _headers(104, 103), _attItem(_att("queue")), "", _content(meta, msgs), "");

        uint256 g = gasleft();
        service.submitBundle(channelId, proof);
        g -= gasleft();
        console.log("submitBundle via StellarScpVerifier gas:", g, "calldata bytes:", proof.length);

        _verifyPostBundle(1, 3, hex"48454C4C4F", 2, 2, 1, ClprTypes.ChannelStatus.ACTIVE);
        assertEq(
            service.getChannel(channelId).trustAnchor,
            _anchor(Q1_HASH, 105, 104, _headerHash(104), keccak256(abi.encode(meta)))
        );

        vm.expectRevert();
        service.submitBundle(channelId, proof);
        _closeChannel();
    }

    /// The pubnet shape through an unmodified service: a checkpoint-only bundle (before any
    /// attestation it returns the empty PENDING queue), then headers + event + messages from that
    /// checkpoint. Re-submitting the same state is NoProgress; an older state is a replay.
    function test_twoStepBundles() public {
        _registerConnectorAndSend();
        (ClprTypes.QueueMetadata memory meta, bytes[] memory msgs) = _inbound();

        bytes memory step1 = _bundle(Q1, _scpStd(105), _emptyList(), _emptyList(), "", "", "");
        service.submitBundle(channelId, step1);
        assertEq(service.getChannel(channelId).trustAnchor, _anchor(Q1_HASH, 105, 104, _headerHash(104), bytes32(0)));
        assertEq(service.getChannel(channelId).receivedMessageId, 0);

        bytes memory step2 =
            _bundle(Q1, _emptyList(), _headers(104, 103), _attItem(_att("queue")), "", _content(meta, msgs), "");
        service.submitBundle(channelId, step2);
        _verifyPostBundle(1, 3, hex"48454C4C4F", 2, 2, 1, ClprTypes.ChannelStatus.ACTIVE);
        assertEq(
            service.getChannel(channelId).trustAnchor,
            _anchor(Q1_HASH, 105, 104, _headerHash(104), keccak256(abi.encode(meta)))
        );

        // Same state again: the verifier returns no new anchor and the service sees no progress.
        bytes memory again = _bundle(Q1, _emptyList(), _headers(104, 103), _attItem(_att("queue")), "", "", "");
        vm.expectRevert(bytes4(keccak256("NoProgress()")));
        service.submitBundle(channelId, again);

        // A later checkpoint re-returns the proven metadata.
        service.submitBundle(channelId, _bundle(Q1, _scpStd(112), _emptyList(), _emptyList(), abi.encode(meta), "", ""));

        // An older queue state (nextMessageId 1) proven from it is a replay.
        bytes memory stale = _bundle(Q1, _emptyList(), _headers(111, 110), _attItem(_att("queueStale")), "", "", "");
        vm.expectRevert(ClprTypes.ClprReplayDetected.selector);
        service.submitBundle(channelId, stale);
    }

    function test_rejectBundle_storageProofForWrongChannel() public override {
        _registerConnectorAndSend();
        (ClprTypes.QueueMetadata memory meta, bytes[] memory msgs) = _inbound();
        bytes memory proof =
            _bundle(Q1, _scpStd(105), _headers(104, 103), _attItem(_att("wrongChannel")), "", _content(meta, msgs), "");
        vm.expectRevert(StellarScpVerifier.WrongAttestationEvent.selector);
        service.submitBundle(channelId, proof);
    }
}
