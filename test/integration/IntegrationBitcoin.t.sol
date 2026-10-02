// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {BitcoinVerifier} from "@hiero-ledger/clpr/verifiers/bitcoin/BitcoinVerifier.sol";
import {IntegrationTestBase} from "@test/integration/IntegrationTestBase.sol";
import {ConnectorRegistrar} from "@test/helpers/ConnectorRegistrar.sol";
import {BitcoinTestBuilder} from "@test/verifiers/bitcoin/BitcoinTestBuilder.sol";

/// @dev The real ClprService consuming BitcoinVerifier output: completeChannel with a Bitcoin
///      config proof, then submitBundle with three Bitcoin messages. Proves the verifier's
///      synthesized queue metadata (nextMessageId, BundleLib running hash, receivedMessageId = 0)
///      is accepted by the unmodified service — and shows the receive-only gap: every inbound DATA
///      enqueues a REPLY toward Bitcoin that can never be acknowledged.
contract IntegrationBitcoinTest is IntegrationTestBase, BitcoinTestBuilder {
    uint8 internal constant K = 6;
    BitcoinVerifier internal btc;
    bytes internal senderScript = abi.encodePacked(hex"0014", bytes20(keccak256("bitcoin sender")));
    bytes32 internal genesisTxid;

    function setUp() public override {
        _initChain();
        btc = _deployRegtestVerifier(K);
        _deployServiceAndConnect(address(btc));
    }

    function _deployAndConnectVerifier(address verifier_) internal override {
        bytes memory pubKey = _signerPubKey();
        channelId = service.deriveChannelId(REGTEST_CHAIN_ID, pubKey, bytes32(0));
        service.registerChannel(channelId, keccak256(abi.encodePacked(channelId, pubKey)));

        // Genesis cursor tx on "Bitcoin", buried k deep.
        bytes memory genesis =
            _clprTx(keccak256("funding"), 0, _commitment(bytes8(channelId), bytes32(0), 0), senderScript, true);
        genesisTxid = _txid(genesis);
        bytes[] memory txs = new bytes[](1);
        txs[0] = genesis;
        uint32 h = _mine(txs);
        _mineEmpty(K - 1);
        BitcoinVerifier.ConfigProof memory p;
        p.startHeight = cpHeight + 1;
        p.headers = _headers(cpHeight + 1, _tipHeight());
        p.genesis = _txProof(h, p.startHeight, 1, genesis, "");

        bytes32 msgHash = keccak256(abi.encodePacked(channelId, address(service)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, _ethSignedHash(msgHash));
        service.completeChannel(channelId, pubKey, abi.encodePacked(r, s, v), bytes32(0), verifier_, abi.encode(p), "");
    }

    function test_channelCompletedWithBitcoinPeer() public {
        ClprTypes.Channel memory c = service.getChannel(channelId);
        assertEq(c.chainId, REGTEST_CHAIN_ID);
        assertEq(c.peerServiceAddress, senderScript);
        assertEq(uint8(c.status), uint8(ClprTypes.ChannelStatus.ACTIVE));
        assertEq(c.verifier, address(btc));
    }

    function test_threeBitcoinMessagesDeliveredByService() public {
        connectorAddr = ConnectorRegistrar.register(
            IClprService(address(service)), channelId, bytes32("btc-connector"), address(connector), owner, 1 ether
        );
        (bool ok,) = address(connector).call{value: 9 ether}("");
        require(ok, "fund connector failed");

        uint32 anchorHeight =
            abi.decode(service.getChannel(channelId).trustAnchor, (BitcoinVerifier.TrustAnchor)).checkpoint.height;

        // Three chained message txs in one block, then k-1 blocks on top.
        bytes[] memory txs = new bytes[](3);
        bytes[] memory payloads = new bytes[](3);
        bytes32 prev = genesisTxid;
        for (uint256 i = 0; i < 3; ++i) {
            payloads[i] = ClprProtobuf.encodeDataMessage(
                connectorAddr, abi.encodePacked(address(app)), senderScript, abi.encodePacked("btc msg ", i + 1)
            );
            // forge-lint: disable-next-line(unsafe-typecast)
            txs[i] = _clprTx(
                prev, 1, _commitment(bytes8(channelId), sha256(payloads[i]), uint64(i + 1)), senderScript, true
            );
            prev = _txid(txs[i]);
        }
        uint32 h = _mine(txs);
        _mineEmpty(K - 1);

        BitcoinVerifier.BundleProof memory p;
        p.startHeight = anchorHeight + 1;
        p.headers = _headers(p.startHeight, _tipHeight());
        p.messages = new BitcoinVerifier.TxProof[](3);
        for (uint256 i = 0; i < 3; ++i) {
            p.messages[i] = _txProof(h, p.startHeight, i + 1, txs[i], payloads[i]);
        }
        bytes memory proof = abi.encode(p);

        service.submitBundle(channelId, proof);

        // All three delivered, in order, to the application.
        assertEq(app.getMessageCallCount(), 3);
        for (uint256 i = 0; i < 3; ++i) {
            (bytes32 cid, bytes memory sender, bytes memory data) = app.messageCalls(i);
            assertEq(cid, channelId);
            assertEq(sender, senderScript, "sender = channel's Bitcoin script");
            assertEq(data, abi.encodePacked("btc msg ", i + 1));
        }
        ClprTypes.Channel memory c = service.getChannel(channelId);
        assertEq(c.receivedMessageId, 3);
        BitcoinVerifier.TrustAnchor memory a = abi.decode(c.trustAnchor, (BitcoinVerifier.TrustAnchor));
        assertEq(c.receivedRunningHash, a.runningHash, "service and verifier agree on the running hash");
        assertEq(a.lastMessageId, 3);
        assertEq(a.checkpoint.height, h);

        // Receive-only gap: the service queued three REPLYs toward Bitcoin, which can never ack them.
        assertEq(c.nextMessageId, 4, "3 undeliverable replies queued");
        assertEq(c.ackedMessageId, 0);

        // Outbound DATA toward Bitcoin is refused: the verifier's placeholder peer throttles
        // (maxSyncBytes = 1) make every sendMessage fail the peer-size check.
        vm.prank(address(app));
        vm.expectRevert(ClprTypes.ClprPayloadTooLarge.selector);
        service.sendMessage(channelId, connectorAddr, abi.encodePacked(address(app)), hex"01");

        // Replaying the same bundle fails (the anchor's cursor moved on).
        vm.expectRevert(BitcoinVerifier.NotACursorSpend.selector);
        service.submitBundle(channelId, proof);
    }
}
