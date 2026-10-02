// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {BitcoinTestBuilder} from "./BitcoinTestBuilder.sol";
import {BitcoinVerifier} from "@hiero-ledger/clpr/verifiers/bitcoin/BitcoinVerifier.sol";
import {BitcoinLib} from "@hiero-ledger/clpr/verifiers/bitcoin/BitcoinLib.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";

/// @notice BitcoinVerifier message/queue tests on a deterministic regtest chain built in Solidity
///         (real headers + regtest PoW, real tx serializations, real Merkle trees).
contract BitcoinVerifierRegtestTest is BitcoinTestBuilder {
    BitcoinVerifier internal v;
    uint8 internal constant K = 6;

    bytes32 internal constant CHANNEL_ID = keccak256("bitcoin->hiero test channel");
    bytes internal senderScript = abi.encodePacked(hex"0014", bytes20(keccak256("sender key")));
    bytes internal channelContext;

    // Config outputs
    bytes internal anchor0;
    bytes32 internal genesisTxid;
    uint32 internal genesisHeight;

    // Three queued messages
    bytes[] internal payloads;
    bytes[] internal msgTxs;
    uint32[] internal msgHeights;
    uint256[] internal msgPos;

    function setUp() public {
        _initChain();
        v = _deployRegtestVerifier(K);
        channelContext = abi.encodePacked(CHANNEL_ID, senderScript);
    }

    // ── Scenario helpers ─────────────────────────────────────────────────────

    function _genesisTx(bytes memory script) internal pure returns (bytes memory) {
        return _clprTx(keccak256("funding"), 0, _commitment(bytes8(CHANNEL_ID), bytes32(0), 0), script, true);
    }

    /// @dev Mine the genesis cursor tx (block 101) plus k-1 blocks and run verifyConfig.
    function _configure() internal returns (bytes memory anchor) {
        bytes[] memory txs = new bytes[](1);
        txs[0] = _genesisTx(senderScript);
        genesisTxid = _txid(txs[0]);
        genesisHeight = _mine(txs);
        _mineEmpty(K - 1);

        BitcoinVerifier.ConfigProof memory p;
        p.startHeight = cpHeight + 1;
        p.headers = _headers(cpHeight + 1, _tipHeight());
        p.genesis = _txProof(genesisHeight, p.startHeight, 1, txs[0], "");
        (,,,,, anchor,,) = v.verifyConfig(abi.encode(p), CHANNEL_ID, "");
    }

    function _payload(uint256 i) internal view returns (bytes memory) {
        return ClprProtobuf.encodeDataMessage(
            keccak256("connector"), abi.encodePacked(address(0xA11CE)), senderScript, abi.encodePacked("hello #", i)
        );
    }

    /// @dev Queue 3 messages: #1 in its own block, #2 and #3 chained inside the next block.
    function _queueThree() internal {
        bytes32 prev = genesisTxid;
        for (uint256 i = 1; i <= 3; ++i) {
            bytes memory pl = _payload(i);
            // forge-lint: disable-next-line(unsafe-typecast)
            bytes memory raw =
                _clprTx(prev, 1, _commitment(bytes8(CHANNEL_ID), sha256(pl), uint64(i)), senderScript, i != 2);
            payloads.push(pl);
            msgTxs.push(raw);
            prev = _txid(raw);
        }
        bytes[] memory b1 = new bytes[](1);
        b1[0] = msgTxs[0];
        uint32 h1 = _mine(b1);
        bytes[] memory b2 = new bytes[](2);
        b2[0] = msgTxs[1];
        b2[1] = msgTxs[2];
        uint32 h2 = _mine(b2);
        msgHeights.push(h1);
        msgHeights.push(h2);
        msgHeights.push(h2);
        msgPos.push(1);
        msgPos.push(1);
        msgPos.push(2);
    }

    function _bundle(uint32 startHeight, uint32 tip, uint256 nMsgs) internal view returns (bytes memory) {
        BitcoinVerifier.BundleProof memory p;
        p.startHeight = startHeight;
        p.headers = _headers(startHeight, tip);
        p.messages = new BitcoinVerifier.TxProof[](nMsgs);
        for (uint256 i = 0; i < nMsgs; ++i) {
            p.messages[i] = _txProof(msgHeights[i], startHeight, msgPos[i], msgTxs[i], payloads[i]);
        }
        return abi.encode(p);
    }

    function _decode(bytes memory a) internal pure returns (BitcoinVerifier.TrustAnchor memory) {
        return abi.decode(a, (BitcoinVerifier.TrustAnchor));
    }

    function _happySetup() internal returns (uint32 startHeight) {
        anchor0 = _configure();
        _queueThree();
        _mineEmpty(K - 1); // last message block gets exactly k confirmations
        startHeight = _decode(anchor0).checkpoint.height + 1;
    }

    // ── verifyConfig ─────────────────────────────────────────────────────────

    function test_config_happyPath() public {
        bytes[] memory txs = new bytes[](1);
        txs[0] = _genesisTx(senderScript);
        uint32 h = _mine(txs);
        _mineEmpty(K - 1);
        BitcoinVerifier.ConfigProof memory p;
        p.startHeight = cpHeight + 1;
        p.headers = _headers(cpHeight + 1, _tipHeight());
        p.genesis = _txProof(h, p.startHeight, 1, txs[0], "");

        (
            bytes memory ctx,
            string memory cid,
            bytes memory svc,
            uint96 nanos,
            ClprTypes.Throttles memory t,
            bytes memory anchor,
            bytes memory anchorId,
            ClprTypes.ClprEndpointManifest memory m
        ) = v.verifyConfig(abi.encode(p), CHANNEL_ID, "");

        assertEq(ctx, channelContext, "context = channelId || sender script");
        assertEq(cid, REGTEST_CHAIN_ID);
        assertEq(svc, senderScript, "service address = sender script");
        assertEq(nanos, uint96(cpTime + 600) * 1e9);
        ClprTypes.validateThrottles(t);
        assertEq(m.version, 0);
        assertEq(m.serviceAddress, senderScript);
        assertGt(anchorId.length, 0);

        BitcoinVerifier.TrustAnchor memory a = _decode(anchor);
        assertEq(a.checkpoint.height, h, "checkpoint = genesis block (exactly k confirmations)");
        assertEq(a.checkpoint.blockHash, BitcoinLib.hash256(_headerAt(h)));
        assertEq(a.cursorTxid, _txid(txs[0]));
        assertEq(a.cursorVout, 1);
        assertEq(a.lastMessageId, 0);
        assertEq(a.runningHash, bytes32(0));
        assertEq(a.confirmations, K);
        assertEq(a.checkpoint.chainWork, BitcoinLib.work(REGTEST_POW_LIMIT), "one block of regtest work");
    }

    function test_config_rejectsWrongChannelTag() public {
        bytes[] memory txs = new bytes[](1);
        txs[0] = _genesisTx(senderScript);
        uint32 h = _mine(txs);
        _mineEmpty(K - 1);
        BitcoinVerifier.ConfigProof memory p;
        p.startHeight = cpHeight + 1;
        p.headers = _headers(cpHeight + 1, _tipHeight());
        p.genesis = _txProof(h, p.startHeight, 1, txs[0], "");
        vm.expectRevert(BitcoinVerifier.WrongChannelTag.selector);
        v.verifyConfig(abi.encode(p), keccak256("another channel"), "");
    }

    function test_config_rejectsInsufficientConfirmations() public {
        bytes[] memory txs = new bytes[](1);
        txs[0] = _genesisTx(senderScript);
        uint32 h = _mine(txs);
        _mineEmpty(K - 2); // one short
        BitcoinVerifier.ConfigProof memory p;
        p.startHeight = cpHeight + 1;
        p.headers = _headers(cpHeight + 1, _tipHeight());
        p.genesis = _txProof(h, p.startHeight, 1, txs[0], "");
        vm.expectRevert(abi.encodeWithSelector(BitcoinVerifier.InsufficientConfirmations.selector, h, cpHeight));
        v.verifyConfig(abi.encode(p), CHANNEL_ID, "");
    }

    function test_config_rejectsManifestProof() public {
        vm.expectRevert(BitcoinVerifier.ManifestProofUnsupported.selector);
        v.verifyConfig(hex"00", CHANNEL_ID, hex"01");
    }

    function test_config_rejectsEmptyProof() public {
        vm.expectRevert();
        v.verifyConfig("", CHANNEL_ID, "");
    }

    // ── verifyBundle: happy path ─────────────────────────────────────────────

    function test_bundle_threeMessages() public {
        uint32 start = _happySetup();
        bytes memory proof = _bundle(start, _tipHeight(), 3);

        (
            ClprTypes.QueueMetadata memory meta,
            bytes[] memory out,
            bytes memory newAnchor,
            bytes memory newId,
            ClprTypes.ClprEndpointManifest memory m
        ) = v.verifyBundle(proof, anchor0, channelContext);

        assertEq(out.length, 3);
        bytes32 rh;
        for (uint256 i = 0; i < 3; ++i) {
            assertEq(out[i], payloads[i], "payload delivered verbatim");
            rh = sha256(abi.encodePacked(rh, sha256(payloads[i])));
        }
        // Metadata in exactly the shape BundleLib checks (Step 4 + Step 5).
        assertEq(meta.nextMessageId, 4);
        assertEq(meta.sentRunningHash, rh, "BundleLib running hash");
        assertEq(meta.receivedMessageId, 0, "Bitcoin never receives");
        assertEq(uint8(meta.state), uint8(ClprTypes.ChannelStatus.ACTIVE));
        assertEq(m.version, 0, "no manifest update");

        BitcoinVerifier.TrustAnchor memory a = _decode(newAnchor);
        assertEq(a.checkpoint.height, msgHeights[2], "anchor advanced to tip-k+1");
        assertEq(a.checkpoint.blockHash, BitcoinLib.hash256(_headerAt(msgHeights[2])));
        assertEq(a.cursorTxid, _txid(msgTxs[2]));
        assertEq(a.lastMessageId, 3);
        assertEq(a.runningHash, rh);
        assertEq(newId, abi.encodePacked(a.checkpoint.blockHash, uint64(3)));

        // Chainwork grows by exactly one regtest block per new header.
        BitcoinVerifier.TrustAnchor memory a0 = _decode(anchor0);
        assertEq(
            a.checkpoint.chainWork - a0.checkpoint.chainWork,
            uint256(a.checkpoint.height - a0.checkpoint.height) * BitcoinLib.work(REGTEST_POW_LIMIT)
        );
    }

    function test_bundle_incrementalDeliveryContinuesRunningHash() public {
        uint32 start = _happySetup();
        // Bundle 1: only message #1.
        (ClprTypes.QueueMetadata memory m1,, bytes memory a1,,) =
            v.verifyBundle(_bundle(start, _tipHeight(), 1), anchor0, channelContext);
        assertEq(m1.nextMessageId, 2);
        // Bundle 2: messages #2, #3 from the new anchor. Their block is at/below the new
        // checkpoint, so the proof starts at or below it (historical inclusion via linkage).
        BitcoinVerifier.TrustAnchor memory d1 = _decode(a1);
        assertEq(d1.checkpoint.height, msgHeights[2]);
        BitcoinVerifier.BundleProof memory p;
        p.startHeight = msgHeights[1];
        p.headers = _headers(p.startHeight, _tipHeight());
        p.messages = new BitcoinVerifier.TxProof[](2);
        p.messages[0] = _txProof(msgHeights[1], p.startHeight, msgPos[1], msgTxs[1], payloads[1]);
        p.messages[1] = _txProof(msgHeights[2], p.startHeight, msgPos[2], msgTxs[2], payloads[2]);
        (ClprTypes.QueueMetadata memory m2, bytes[] memory out2, bytes memory a2,,) =
            v.verifyBundle(abi.encode(p), a1, channelContext);
        assertEq(out2.length, 2);
        assertEq(m2.nextMessageId, 4);
        bytes32 rh;
        for (uint256 i = 0; i < 3; ++i) {
            rh = sha256(abi.encodePacked(rh, sha256(payloads[i])));
        }
        assertEq(m2.sentRunningHash, rh);
        assertEq(_decode(a2).lastMessageId, 3);
    }

    /// @dev The anchor may advance past a block that holds undelivered messages; they stay
    ///      provable by supplying headers from below the checkpoint (bound by hash linkage).
    function test_bundle_messagesBelowCheckpointStillProvable() public {
        uint32 start = _happySetup();
        _mineEmpty(20);
        // Advance the anchor without delivering anything.
        (,, bytes memory a1,,) = v.verifyBundle(_bundle(start, _tipHeight(), 0), anchor0, channelContext);
        BitcoinVerifier.TrustAnchor memory d1 = _decode(a1);
        assertGt(d1.checkpoint.height, msgHeights[2] + 10);
        assertEq(d1.lastMessageId, 0);
        // Deliver all three from below the checkpoint with no new headers above it.
        BitcoinVerifier.BundleProof memory p;
        p.startHeight = msgHeights[0];
        p.headers = _headers(p.startHeight, d1.checkpoint.height);
        p.messages = new BitcoinVerifier.TxProof[](3);
        for (uint256 i = 0; i < 3; ++i) {
            p.messages[i] = _txProof(msgHeights[i], p.startHeight, msgPos[i], msgTxs[i], payloads[i]);
        }
        (ClprTypes.QueueMetadata memory meta,, bytes memory a2,,) = v.verifyBundle(abi.encode(p), a1, channelContext);
        assertEq(meta.nextMessageId, 4);
        assertEq(_decode(a2).checkpoint.height, d1.checkpoint.height, "checkpoint unchanged");
    }

    function test_bundle_headersOnlyAdvancesAnchor() public {
        uint32 start = _happySetup();
        (ClprTypes.QueueMetadata memory meta, bytes[] memory out, bytes memory a1,,) =
            v.verifyBundle(_bundle(start, _tipHeight(), 0), anchor0, channelContext);
        assertEq(out.length, 0);
        assertEq(meta.nextMessageId, 1);
        assertEq(meta.sentRunningHash, bytes32(0));
        assertEq(_decode(a1).checkpoint.height, _tipHeight() - K + 1);
    }

    function test_bundle_noProgressReturnsEmptyAnchor() public {
        _happySetup();
        BitcoinVerifier.TrustAnchor memory a0 = _decode(anchor0);
        // Only k-1 new headers: nothing becomes final, nothing delivered.
        (,, bytes memory a1, bytes memory id1,) =
            v.verifyBundle(_bundle(a0.checkpoint.height + 1, a0.checkpoint.height + K - 1, 0), anchor0, channelContext);
        assertEq(a1.length, 0);
        assertEq(id1.length, 0);
    }

    // ── verifyBundle: negative ───────────────────────────────────────────────

    function test_bundle_rejectsInsufficientConfirmations() public {
        anchor0 = _configure();
        _queueThree();
        _mineEmpty(K - 2); // last message block has k-1 confirmations
        uint32 start = _decode(anchor0).checkpoint.height + 1;
        bytes memory proof = _bundle(start, _tipHeight(), 3);
        vm.expectRevert(
            abi.encodeWithSelector(BitcoinVerifier.InsufficientConfirmations.selector, msgHeights[1], msgHeights[0])
        );
        v.verifyBundle(proof, anchor0, channelContext);
    }

    function test_bundle_rejectsWrongMerkleProof() public {
        uint32 start = _happySetup();
        BitcoinVerifier.BundleProof memory p =
            abi.decode(_bundle(start, _tipHeight(), 3), (BitcoinVerifier.BundleProof));
        p.messages[1].merkleBranch[0] = bytes32(uint256(p.messages[1].merkleBranch[0]) ^ 1);
        vm.expectRevert(BitcoinVerifier.MerkleProofInvalid.selector);
        v.verifyBundle(abi.encode(p), anchor0, channelContext);
    }

    function test_bundle_rejectsWrongMerkleIndex() public {
        uint32 start = _happySetup();
        BitcoinVerifier.BundleProof memory p =
            abi.decode(_bundle(start, _tipHeight(), 3), (BitcoinVerifier.BundleProof));
        p.messages[2].txIndex = 1; // proof for position 2 presented as position 1
        vm.expectRevert(BitcoinVerifier.MerkleProofInvalid.selector);
        v.verifyBundle(abi.encode(p), anchor0, channelContext);
    }

    function test_bundle_rejectsTxNotSpendingCursor() public {
        anchor0 = _configure();
        bytes memory pl = _payload(1);
        // Correct commitment, but input 0 spends some other outpoint.
        bytes memory raw =
            _clprTx(keccak256("elsewhere"), 1, _commitment(bytes8(CHANNEL_ID), sha256(pl), 1), senderScript, true);
        bytes[] memory txs = new bytes[](1);
        txs[0] = raw;
        uint32 h = _mine(txs);
        _mineEmpty(K - 1);
        uint32 start = _decode(anchor0).checkpoint.height + 1;
        BitcoinVerifier.BundleProof memory p;
        p.startHeight = start;
        p.headers = _headers(start, _tipHeight());
        p.messages = new BitcoinVerifier.TxProof[](1);
        p.messages[0] = _txProof(h, start, 1, raw, pl);
        vm.expectRevert(BitcoinVerifier.NotACursorSpend.selector);
        v.verifyBundle(abi.encode(p), anchor0, channelContext);
    }

    function test_bundle_rejectsWrongCursorVout() public {
        anchor0 = _configure();
        bytes memory pl = _payload(1);
        bytes memory raw = _clprTx(genesisTxid, 2, _commitment(bytes8(CHANNEL_ID), sha256(pl), 1), senderScript, true);
        bytes[] memory txs = new bytes[](1);
        txs[0] = raw;
        uint32 h = _mine(txs);
        _mineEmpty(K - 1);
        uint32 start = _decode(anchor0).checkpoint.height + 1;
        BitcoinVerifier.BundleProof memory p;
        p.startHeight = start;
        p.headers = _headers(start, _tipHeight());
        p.messages = new BitcoinVerifier.TxProof[](1);
        p.messages[0] = _txProof(h, start, 1, raw, pl);
        vm.expectRevert(BitcoinVerifier.NotACursorSpend.selector);
        v.verifyBundle(abi.encode(p), anchor0, channelContext);
    }

    function test_bundle_rejectsOutOfOrderMessages() public {
        uint32 start = _happySetup();
        BitcoinVerifier.BundleProof memory p =
            abi.decode(_bundle(start, _tipHeight(), 3), (BitcoinVerifier.BundleProof));
        (p.messages[0], p.messages[1]) = (p.messages[1], p.messages[0]);
        vm.expectRevert(BitcoinVerifier.NotACursorSpend.selector);
        v.verifyBundle(abi.encode(p), anchor0, channelContext);
    }

    function test_bundle_rejectsReplayOfDeliveredMessage() public {
        uint32 start = _happySetup();
        (,, bytes memory a1,,) = v.verifyBundle(_bundle(start, _tipHeight(), 1), anchor0, channelContext);
        BitcoinVerifier.BundleProof memory p;
        p.startHeight = msgHeights[0];
        p.headers = _headers(p.startHeight, _tipHeight());
        p.messages = new BitcoinVerifier.TxProof[](1);
        p.messages[0] = _txProof(msgHeights[0], p.startHeight, msgPos[0], msgTxs[0], payloads[0]);
        vm.expectRevert(BitcoinVerifier.NotACursorSpend.selector);
        v.verifyBundle(abi.encode(p), a1, channelContext);
    }

    function test_bundle_rejectsPayloadHashMismatch() public {
        uint32 start = _happySetup();
        BitcoinVerifier.BundleProof memory p =
            abi.decode(_bundle(start, _tipHeight(), 3), (BitcoinVerifier.BundleProof));
        p.messages[1].payload = _payload(99);
        vm.expectRevert(BitcoinVerifier.PayloadHashMismatch.selector);
        v.verifyBundle(abi.encode(p), anchor0, channelContext);
    }

    function test_bundle_rejectsCursorMovedToOtherScript() public {
        anchor0 = _configure();
        bytes memory pl = _payload(1);
        bytes memory other = abi.encodePacked(hex"0014", bytes20(keccak256("thief")));
        bytes memory raw = _clprTx(genesisTxid, 1, _commitment(bytes8(CHANNEL_ID), sha256(pl), 1), other, true);
        bytes[] memory txs = new bytes[](1);
        txs[0] = raw;
        uint32 h = _mine(txs);
        _mineEmpty(K - 1);
        uint32 start = _decode(anchor0).checkpoint.height + 1;
        BitcoinVerifier.BundleProof memory p;
        p.startHeight = start;
        p.headers = _headers(start, _tipHeight());
        p.messages = new BitcoinVerifier.TxProof[](1);
        p.messages[0] = _txProof(h, start, 1, raw, pl);
        vm.expectRevert(BitcoinVerifier.CursorNotHeldBySender.selector);
        v.verifyBundle(abi.encode(p), anchor0, channelContext);
    }

    function test_bundle_rejectsWrongMessageId() public {
        anchor0 = _configure();
        bytes memory pl = _payload(1);
        bytes memory raw = _clprTx(genesisTxid, 1, _commitment(bytes8(CHANNEL_ID), sha256(pl), 7), senderScript, true);
        bytes[] memory txs = new bytes[](1);
        txs[0] = raw;
        uint32 h = _mine(txs);
        _mineEmpty(K - 1);
        uint32 start = _decode(anchor0).checkpoint.height + 1;
        BitcoinVerifier.BundleProof memory p;
        p.startHeight = start;
        p.headers = _headers(start, _tipHeight());
        p.messages = new BitcoinVerifier.TxProof[](1);
        p.messages[0] = _txProof(h, start, 1, raw, pl);
        vm.expectRevert(abi.encodeWithSelector(BitcoinVerifier.UnexpectedMessageId.selector, 1, 7));
        v.verifyBundle(abi.encode(p), anchor0, channelContext);
    }

    function test_bundle_rejectsOtherChannelsMessage() public {
        uint32 start = _happySetup();
        bytes memory otherCtx = abi.encodePacked(keccak256("other channel"), senderScript);
        bytes memory proof = _bundle(start, _tipHeight(), 3);
        vm.expectRevert(BitcoinVerifier.WrongChannelTag.selector);
        v.verifyBundle(proof, anchor0, otherCtx);
    }

    function test_bundle_rejectsBrokenLinkage() public {
        uint32 start = _happySetup();
        BitcoinVerifier.BundleProof memory p =
            abi.decode(_bundle(start, _tipHeight(), 0), (BitcoinVerifier.BundleProof));
        // Drop the second header: header[2] no longer links to header[1].
        p.headers = abi.encodePacked(_headerAt(start), _headers(start + 2, _tipHeight()));
        vm.expectRevert(abi.encodeWithSelector(BitcoinVerifier.BrokenLinkage.selector, 1));
        v.verifyBundle(abi.encode(p), anchor0, channelContext);
    }

    function test_bundle_rejectsHeadersNotConnectingToAnchor() public {
        uint32 start = _happySetup();
        vm.expectRevert(abi.encodeWithSelector(BitcoinVerifier.BrokenLinkage.selector, 0));
        // Right height, but the anchor names a different checkpoint hash.
        BitcoinVerifier.TrustAnchor memory a = _decode(anchor0);
        a.checkpoint.blockHash = keccak256("fork");
        v.verifyBundle(_bundle(start, _tipHeight(), 0), abi.encode(a), channelContext);
    }

    function test_bundle_rejectsGapAboveAnchor() public {
        uint32 start = _happySetup();
        BitcoinVerifier.BundleProof memory p =
            abi.decode(_bundle(start, _tipHeight(), 0), (BitcoinVerifier.BundleProof));
        p.startHeight = start + 1;
        vm.expectRevert(BitcoinVerifier.HeadersDoNotConnect.selector);
        v.verifyBundle(abi.encode(p), anchor0, channelContext);
    }

    function test_bundle_rejectsForgedAncestor() public {
        uint32 start = _happySetup();
        // Present a fake header "below" the checkpoint: its hash won't match the checkpoint.
        BitcoinVerifier.BundleProof memory p;
        p.startHeight = start - 1;
        p.headers = abi.encodePacked(
            _grind(keccak256("x"), keccak256("y"), cpTime, REGTEST_BITS), _headers(start, _tipHeight())
        );
        vm.expectRevert(BitcoinVerifier.CheckpointMismatch.selector);
        v.verifyBundle(abi.encode(p), anchor0, channelContext);
    }

    function test_bundle_rejectsBadProofOfWork() public {
        uint32 start = _happySetup();
        // A header with a valid link but a nonce that misses the regtest target.
        bytes memory h;
        for (uint32 nonce = 0;; ++nonce) {
            h = abi.encodePacked(
                _le32(0x20000000),
                _decode(anchor0).checkpoint.blockHash,
                bytes32(0),
                _le32(cpTime),
                _le32(REGTEST_BITS),
                _le32(nonce)
            );
            if (BitcoinLib.reverse256(uint256(BitcoinLib.hash256(h))) > REGTEST_POW_LIMIT) break;
        }
        BitcoinVerifier.BundleProof memory p;
        p.startHeight = start;
        p.headers = h;
        vm.expectRevert(abi.encodeWithSelector(BitcoinVerifier.InsufficientProofOfWork.selector, start));
        v.verifyBundle(abi.encode(p), anchor0, channelContext);
    }

    function test_bundle_rejectsWrongBitsOnRegtest() public {
        uint32 start = _happySetup();
        bytes memory h = _grind(_decode(anchor0).checkpoint.blockHash, bytes32(0), cpTime, 0x2000ffff);
        BitcoinVerifier.BundleProof memory p;
        p.startHeight = start;
        p.headers = h;
        vm.expectRevert(
            abi.encodeWithSelector(
                BitcoinVerifier.WrongDifficultyBits.selector, start, REGTEST_BITS, uint32(0x2000ffff)
            )
        );
        v.verifyBundle(abi.encode(p), anchor0, channelContext);
    }

    function test_bundle_rejectsMalformedAnchorAndProofs() public {
        uint32 start = _happySetup();
        bytes memory good = _bundle(start, _tipHeight(), 3);
        vm.expectRevert(BitcoinVerifier.InvalidTrustAnchor.selector);
        v.verifyBundle(good, hex"01", channelContext);
        vm.expectRevert(BitcoinVerifier.InvalidHeadersLength.selector);
        v.verifyBundle("", anchor0, channelContext);
        // Truncated ABI never panics.
        bytes memory bad = BitcoinLib.slice(good, 0, good.length / 2);
        (bool ok, bytes memory ret) =
            address(v).staticcall(abi.encodeCall(v.verifyBundle, (bad, anchor0, channelContext)));
        assertFalse(ok);
        assertTrue(ret.length < 4 || bytes4(ret) != bytes4(0x4e487b71), "no Panic");
    }

    // ── Redaction of undeliverable (but committed) payloads ──────────────────

    function _singleMessage(bytes memory pl) internal returns (bytes memory proof) {
        anchor0 = _configure();
        bytes memory raw = _clprTx(genesisTxid, 1, _commitment(bytes8(CHANNEL_ID), sha256(pl), 1), senderScript, true);
        bytes[] memory txs = new bytes[](1);
        txs[0] = raw;
        uint32 h = _mine(txs);
        _mineEmpty(K - 1);
        uint32 start = _decode(anchor0).checkpoint.height + 1;
        BitcoinVerifier.BundleProof memory p;
        p.startHeight = start;
        p.headers = _headers(start, _tipHeight());
        p.messages = new BitcoinVerifier.TxProof[](1);
        p.messages[0] = _txProof(h, start, 1, raw, pl);
        return abi.encode(p);
    }

    function test_bundle_spoofedSenderIsRedacted() public {
        bytes memory pl = ClprProtobuf.encodeDataMessage(
            keccak256("connector"), abi.encodePacked(address(0xA11CE)), hex"deadbeef", "spoof"
        );
        (ClprTypes.QueueMetadata memory meta, bytes[] memory out,,,) =
            v.verifyBundle(_singleMessage(pl), anchor0, channelContext);
        bytes memory redacted = ClprProtobuf.encodeRedactedMessage(sha256(pl));
        assertEq(out[0], redacted);
        assertEq(uint8(ClprProtobuf.getMessageType(out[0])), uint8(ClprTypes.MessageType.REDACTED));
        assertEq(meta.sentRunningHash, sha256(abi.encodePacked(bytes32(0), sha256(redacted))));
    }

    function test_bundle_replyMessageIsRedacted() public {
        bytes memory pl = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, "fake ack");
        (, bytes[] memory out,,,) = v.verifyBundle(_singleMessage(pl), anchor0, channelContext);
        assertEq(out[0], ClprProtobuf.encodeRedactedMessage(sha256(pl)));
    }

    function test_bundle_garbagePayloadIsRedacted() public {
        bytes memory pl = hex"ffffffff";
        (, bytes[] memory out,,,) = v.verifyBundle(_singleMessage(pl), anchor0, channelContext);
        assertEq(out[0], ClprProtobuf.encodeRedactedMessage(sha256(pl)));
    }

    function test_bundle_oversizedPayloadIsRedacted() public {
        bytes memory pl = ClprProtobuf.encodeDataMessage(
            keccak256("connector"), abi.encodePacked(address(0xA11CE)), senderScript, new bytes(5000)
        );
        (, bytes[] memory out,,,) = v.verifyBundle(_singleMessage(pl), anchor0, channelContext);
        assertEq(out[0], ClprProtobuf.encodeRedactedMessage(sha256(pl)));
    }

    // ── Gas ──────────────────────────────────────────────────────────────────

    /// @dev Steady state: the anchor checkpoint is the block right before the messages' block, and
    ///      the bundle carries exactly `nHeaders` headers. All 3 messages sit in the first new block
    ///      (chained within it), which is final once `nHeaders ≥ k`.
    function _gasScenario(uint256 nHeaders) internal returns (uint256 gasUsed, uint256 calldataBytes) {
        BitcoinVerifier.TrustAnchor memory a = _decode(_configure());
        a.checkpoint = BitcoinVerifier.Checkpoint({
            blockHash: tipHash,
            height: _tipHeight(),
            chainWork: a.checkpoint.chainWork + 5 * BitcoinLib.work(REGTEST_POW_LIMIT),
            bits: REGTEST_BITS,
            time: tipTime,
            periodStartTime: cpTime
        });
        anchor0 = abi.encode(a);

        bytes[] memory txs = new bytes[](3);
        bytes32 prev = genesisTxid;
        for (uint256 i = 1; i <= 3; ++i) {
            bytes memory pl = _payload(i);
            // forge-lint: disable-next-line(unsafe-typecast)
            txs[i - 1] = _clprTx(prev, 1, _commitment(bytes8(CHANNEL_ID), sha256(pl), uint64(i)), senderScript, true);
            prev = _txid(txs[i - 1]);
            payloads.push(pl);
            msgTxs.push(txs[i - 1]);
            msgPos.push(i);
        }
        uint32 h = _mine(txs);
        for (uint256 i = 0; i < 3; ++i) {
            msgHeights.push(h);
        }
        _mineEmpty(nHeaders - 1);

        bytes memory proof = _bundle(h, _tipHeight(), 3);
        bytes memory cd = abi.encodeCall(v.verifyBundle, (proof, anchor0, channelContext));
        uint256 g = gasleft();
        (bool ok, bytes memory ret) = address(v).staticcall(cd);
        gasUsed = g - gasleft();
        assertTrue(ok, "verifyBundle failed");
        (ClprTypes.QueueMetadata memory meta,,,,) =
            abi.decode(ret, (ClprTypes.QueueMetadata, bytes[], bytes, bytes, ClprTypes.ClprEndpointManifest));
        assertEq(meta.nextMessageId, 4);
        calldataBytes = cd.length;
    }

    function test_gas_verifyBundle_6headers_3messages() public {
        (uint256 g, uint256 cd) = _gasScenario(6);
        emit log_named_uint("verifyBundle gas (6 headers, 3 msgs)", g);
        emit log_named_uint("verifyBundle calldata bytes (6 headers, 3 msgs)", cd);
        assertLt(g, 15_000_000);
        assertLt(cd, 128 * 1024);
    }

    function test_gas_verifyBundle_12headers_3messages() public {
        (uint256 g, uint256 cd) = _gasScenario(12);
        emit log_named_uint("verifyBundle gas (12 headers, 3 msgs)", g);
        emit log_named_uint("verifyBundle calldata bytes (12 headers, 3 msgs)", cd);
        assertLt(g, 15_000_000);
        assertLt(cd, 128 * 1024);
    }

    /// @dev Upper bound on how far behind the checkpoint a message can still be proven within the
    ///      128 KB calldata budget (80 bytes per ancestor header).
    function test_gas_verifyBundle_1000headers() public {
        (uint256 g, uint256 cd) = _gasScenario(1000);
        emit log_named_uint("verifyBundle gas (1000 headers, 3 msgs)", g);
        emit log_named_uint("verifyBundle calldata bytes (1000 headers, 3 msgs)", cd);
        assertLt(g, 15_000_000);
        assertLt(cd, 128 * 1024);
    }
}
