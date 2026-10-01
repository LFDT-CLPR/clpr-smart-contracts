// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {TronVerifier} from "@hiero-ledger/clpr/verifiers/evm/tron/TronVerifier.sol";
import {ClprTronAttestor, IClprTronAttestor} from "@hiero-ledger/clpr/verifiers/evm/tron/ClprTronAttestor.sol";
import {IntegrationTestBase} from "@test/integration/IntegrationTestBase.sol";
import {TronTestBuilder} from "@test/verifiers/evm/tron/TronTestBuilder.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @dev Full CLPR lifecycle on an unmodified ClprService with TronVerifier: a channel is completed
///      from a TRON config proof, then an inbound bundle proven by a synthetic SR-signed TRON chain
///      (attestQueue transaction + 19 SR confirmations) delivers DATA and a REPLY.
///      Also exercises ClprTronAttestor against a real ClprService (standing in for the TRON side).
contract IntegrationTronTest is IntegrationTestBase, TronTestBuilder {
    TronVerifier internal tronVerifier;

    address internal constant TRON_SERVICE = address(0x7E0A5E2F);
    address internal constant ATTESTOR = address(0xA77E5700);
    uint64 internal constant PERIOD = 994_901;
    uint64 internal constant T0 = OFFSET + PERIOD * INTERVAL + 60_000;
    uint64 internal constant N0 = 71_431_000;

    function setUp() public override {
        _setUp();
        _initSrs();
        tronVerifier = new TronVerifier(N, T, INTERVAL, OFFSET, PEER_CHAIN_ID);
        _deployServiceAndConnect(address(tronVerifier));
    }

    function _ledgerConfig() internal pure returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory lc;
        lc.protocolVersion = 1;
        lc.chainId = PEER_CHAIN_ID; // _deriveTestChannelId's peer chain
        lc.serviceAddress = abi.encodePacked(TRON_SERVICE);
        lc.nanosSinceEpoch = PEER_CONFIG_NANOS;
        lc.throttles = ClprTypes.Throttles(10, 4096, 500_000, 100, 65_536, 4, 4);
        return ClprProtobuf.encodeControlMessage(lc);
    }

    function _deployAndConnectVerifier(address verifier_) internal override {
        bytes memory pubKey = _signerPubKey();
        channelId = _deriveTestChannelId(pubKey, bytes32(0));
        service.registerChannel(channelId, keccak256(abi.encodePacked(channelId, pubKey)));
        bytes32 msgHash = keccak256(abi.encodePacked(channelId, address(service)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, _ethSignedHash(msgHash));

        Hdr memory first =
            Hdr({number: N0, timestamp: T0, parentHash: keccak256("g"), txTrieRoot: 0, witness: address(0)});
        (bytes memory headers,) = _chain(first, _firstN(T), _noModes());
        bytes[] memory cfg = new bytes[](4);
        cfg[0] = _setRlp(_set());
        cfg[1] = RLP.encode(abi.encodePacked(ATTESTOR));
        cfg[2] = headers;
        cfg[3] = RLP.encode(_ledgerConfig());
        service.completeChannel(channelId, pubKey, abi.encodePacked(r, s, v), bytes32(0), verifier_, _rlpList(cfg), "");
    }

    function _bundle(ClprTypes.QueueMetadata memory meta, bytes[] memory msgs, bytes32 attestedChannel, uint64 blockNum)
        internal
        view
        returns (bytes memory)
    {
        bytes memory data = abi.encodeCall(
            IClprTronAttestor.attestQueue,
            (
                TRON_SERVICE,
                attestedChannel,
                uint8(meta.state),
                meta.nextMessageId,
                meta.sentRunningHash,
                meta.receivedMessageId,
                meta.receivedRunningHash,
                meta.endpointManifestVersion,
                bytes32(0)
            )
        );
        bytes[] memory items = new bytes[](6);
        items[0] = _setRlp(_set());
        items[1] = _rlpEmptyList();
        items[2] = _rlpEmptyList();
        items[3] =
            _txProof(_triggerTx(address(0x0123), ATTESTOR, data, 1), blockNum, T0 + 600_000, _firstN(T), _noModes());
        items[4] = RLP.encode(ClprProtobuf.encodeBundleContent(meta, msgs));
        items[5] = RLP.encode(bytes(""));
        return _rlpList(items);
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

    function test_completeChannel_setsTronAnchor() public {
        ClprTypes.Channel memory c = service.getChannel(channelId);
        assertEq(c.verifier, address(tronVerifier));
        assertEq(c.trustAnchor, abi.encode(PERIOD, _setHash(_set()), ATTESTOR, N0 + T - 1));
        assertEq(c.trustAnchorId, abi.encodePacked(PERIOD));
        assertEq(c.peerServiceAddress, abi.encodePacked(TRON_SERVICE));
    }

    function test_fullLifecycle() public {
        assertEq(_registerConnectorAndSend(), 1, "first outbound message");
        (ClprTypes.QueueMetadata memory meta, bytes[] memory msgs) = _inbound();
        bytes memory proof = _bundle(meta, msgs, channelId, N0 + 300);

        uint256 g = gasleft();
        service.submitBundle(channelId, proof);
        g -= gasleft();
        console.log("submitBundle via TronVerifier gas:", g, "calldata bytes:", proof.length);

        _verifyPostBundle(1, 3, hex"48454C4C4F", 2, 2, 1, ClprTypes.ChannelStatus.ACTIVE);

        // Replaying the same proven state is rejected by the service.
        vm.expectRevert();
        service.submitBundle(channelId, proof);
        _closeChannel();
    }

    function test_rejectBundle_storageProofForWrongChannel() public override {
        _registerConnectorAndSend();
        (ClprTypes.QueueMetadata memory meta, bytes[] memory msgs) = _inbound();
        bytes memory proof = _bundle(meta, msgs, bytes32(uint256(0xBADC0DE)), N0 + 300);
        vm.expectRevert(TronVerifier.AttestedChannelMismatch.selector);
        service.submitBundle(channelId, proof);
    }

    // ── ClprTronAttestor against a real ClprService ───────────────────────────

    function test_attestor_matchesLiveChannelState() public {
        _registerConnectorAndSend();
        ClprTronAttestor att = new ClprTronAttestor(IClprService(address(service)));
        ClprTypes.Channel memory c = service.getChannel(channelId);
        bytes32 commitment = keccak256(ClprProtobuf.encodeEndpointManifest(service.getEndpointManifest()));

        att.attestQueue(
            address(service),
            channelId,
            uint8(c.status),
            c.nextMessageId,
            c.sentRunningHash,
            c.receivedMessageId,
            c.receivedRunningHash,
            c.endpointManifestVersion,
            commitment
        );
        att.attestManifest(address(service), commitment);

        vm.expectRevert(ClprTronAttestor.QueueMismatch.selector);
        att.attestQueue(
            address(service),
            channelId,
            uint8(c.status),
            c.nextMessageId + 1,
            c.sentRunningHash,
            c.receivedMessageId,
            c.receivedRunningHash,
            c.endpointManifestVersion,
            commitment
        );
        vm.expectRevert(ClprTronAttestor.ManifestMismatch.selector);
        att.attestManifest(address(service), keccak256("x"));
        vm.expectRevert(ClprTronAttestor.WrongService.selector);
        att.attestManifest(address(0xdead), commitment);
        // getChannel itself rejects an unknown channel; the attestor's own check is a backstop.
        vm.expectRevert(ClprTypes.ClprChannelNotFound.selector);
        att.attestQueue(address(service), keccak256("nope"), 0, 0, 0, 0, 0, 0, commitment);
    }
}
