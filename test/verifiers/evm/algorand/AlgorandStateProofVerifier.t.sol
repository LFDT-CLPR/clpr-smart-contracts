// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprMsgpack} from "@hiero-ledger/clpr/libraries/proof/algorand/ClprMsgpack.sol";
import {
    AlgorandStateProofVerifier as V
} from "@hiero-ledger/clpr/verifiers/evm/algorand/AlgorandStateProofVerifier.sol";
import {AlgorandTestKit} from "@test/verifiers/evm/algorand/AlgorandTestKit.sol";

/// @notice AlgorandStateProofVerifier on synthetic worlds (real Algorand encodings, bootstrapped interval).
contract AlgorandStateProofVerifierTest is Test, AlgorandTestKit {
    function setUp() public {
        _initKit();
    }

    function _bundle(World memory w) internal returns (bytes memory proof, bytes memory anchor) {
        bytes32 r = _install(w);
        return (_encode(w), anchorOf(r));
    }

    function test_bundle_happyPath() public {
        World memory w = _world(defaultQueue());
        (bytes memory proof, bytes memory anchor) = _bundle(w);
        uint256 g = gasleft();
        (
            ClprTypes.QueueMetadata memory m,
            bytes[] memory payloads,
            bytes memory na,
            bytes memory naId,
            ClprTypes.ClprEndpointManifest memory em
        ) = av.verifyBundle(proof, anchor, ctx());
        emit log_named_uint("synthetic bundle gas", g - gasleft());
        emit log_named_uint("synthetic bundle calldata", proof.length);
        assertEq(m.nextMessageId, 3);
        assertEq(m.receivedMessageId, 1);
        assertEq(m.sentRunningHash, keccak256("sent"));
        assertEq(m.receivedRunningHash, keccak256("received"));
        assertEq(uint8(m.state), uint8(ClprTypes.ChannelStatus.ACTIVE));
        assertEq(m.endpointManifestVersion, 4);
        assertEq(payloads.length, 1);
        assertEq(payloads[0], "hello algorand");
        assertEq(na.length, 0);
        assertEq(naId.length, 0);
        assertEq(em.version, 0);
    }

    function test_bundle_withManifest() public {
        Queue memory q = defaultQueue();
        bytes memory mf = manifest(abi.encodePacked(APP_ID), 4);
        q.manifestCommitment = keccak256(mf);
        World memory w = _world(q);
        w.withManifest = true;
        w.manifest = mf;
        (bytes memory proof, bytes memory anchor) = _bundle(w);
        (,,,, ClprTypes.ClprEndpointManifest memory em) = av.verifyBundle(proof, anchor, ctx());
        assertEq(em.version, 4);
        assertEq(em.serviceAddress, abi.encodePacked(APP_ID));
    }

    function test_bundle_queueLogAfterOtherLog() public {
        World memory w = _world(defaultQueue());
        w.extraLogBefore = "some other event";
        (bytes memory proof, bytes memory anchor) = _bundle(w);
        (ClprTypes.QueueMetadata memory m,,,,) = av.verifyBundle(proof, anchor, ctx());
        assertEq(m.nextMessageId, 3);
    }

    function test_rejects_wrongLogIndex() public {
        World memory w = _world(defaultQueue());
        w.extraLogBefore = "some other event";
        w.logIndex = 0; // _seal moves it to 1; force 0 after sealing
        bytes32 r = _install(w);
        w.logIndex = 0;
        vm.expectRevert(V.InvalidQueueRecord.selector);
        av.verifyBundle(_encode(w), anchorOf(r), ctx());
        w.logIndex = 2;
        vm.expectRevert(abi.encodeWithSelector(V.LogMissing.selector, 2));
        av.verifyBundle(_encode(w), anchorOf(r), ctx());
    }

    function test_rejects_otherChannel() public {
        World memory w = _world(defaultQueue());
        w.channelId = keccak256("other-channel");
        (bytes memory proof, bytes memory anchor) = _bundle(w);
        vm.expectRevert(V.ChannelMismatch.selector);
        av.verifyBundle(proof, anchor, ctx());
    }

    function test_rejects_otherApplication() public {
        World memory w = _world(defaultQueue());
        w.appId = APP_ID + 1;
        (bytes memory proof, bytes memory anchor) = _bundle(w);
        vm.expectRevert(abi.encodeWithSelector(V.WrongApplication.selector, APP_ID + 1));
        av.verifyBundle(proof, anchor, ctx());
    }

    function test_rejects_notApplicationCall() public {
        World memory w = _world(defaultQueue());
        w.stib = stib(APP_ID, "pay", _logs(w));
        (bytes memory proof, bytes memory anchor) = _bundle(w);
        vm.expectRevert(V.NotAnApplicationCall.selector);
        av.verifyBundle(proof, anchor, ctx());
    }

    function test_rejects_noLogs() public {
        World memory w = _world(defaultQueue());
        w.stib = stib(APP_ID, "appl", new bytes[](0));
        (bytes memory proof, bytes memory anchor) = _bundle(w);
        vm.expectRevert(abi.encodeWithSelector(V.LogMissing.selector, 0));
        av.verifyBundle(proof, anchor, ctx());
    }

    function test_rejects_badStatus() public {
        Queue memory q = defaultQueue();
        q.status = 9;
        (bytes memory proof, bytes memory anchor) = _bundle(_world(q));
        vm.expectRevert(V.InvalidQueueRecord.selector);
        av.verifyBundle(proof, anchor, ctx());
    }

    function test_rejects_tamperedLogAfterCommitment() public {
        World memory w = _world(defaultQueue());
        bytes32 r = _install(w);
        // flip nextMessageId inside the committed stib
        bytes memory ev = queueEvent(CHANNEL_ID, w.q);
        bytes memory s = w.stib;
        uint256 at = _indexOf(s, ev);
        s[at + 44] ^= 0x01;
        vm.expectRevert(V.TransactionProofInvalid.selector);
        av.verifyBundle(_encode(w), anchorOf(r), ctx());
    }

    function test_rejects_wrongTxIndexOrPath() public {
        World memory w = _world(defaultQueue());
        bytes32 r = _install(w);
        w.txIndex = 3;
        vm.expectRevert(V.TransactionProofInvalid.selector);
        av.verifyBundle(_encode(w), anchorOf(r), ctx());
        w.txIndex = 4; // ≥ 2^depth
        vm.expectRevert(V.TransactionProofInvalid.selector);
        av.verifyBundle(_encode(w), anchorOf(r), ctx());
    }

    function test_rejects_wrongHeaderPath() public {
        World memory w = _world(defaultQueue());
        bytes32 r = _install(w);
        w.headerPath[5] ^= 0x01;
        vm.expectRevert(V.HeaderProofInvalid.selector);
        av.verifyBundle(_encode(w), anchorOf(r), ctx());
    }

    function test_rejects_wrongTxnCommitmentInHeader() public {
        World memory w = _world(defaultQueue());
        bytes32 r = _install(w);
        w.txnCommitment = keccak256("other block");
        vm.expectRevert(V.HeaderProofInvalid.selector);
        av.verifyBundle(_encode(w), anchorOf(r), ctx());
    }

    function test_rejects_otherNetworkGenesis() public {
        World memory w = _world(defaultQueue());
        bytes32 r = _install(w);
        vm.expectRevert(V.HeaderProofInvalid.selector);
        av.verifyBundle(_encode(w), abi.encodePacked(r, keccak256("testnet")), ctx());
    }

    function test_rejects_unknownLineage() public {
        World memory w = _world(defaultQueue());
        _install(w);
        vm.expectRevert(abi.encodeWithSelector(V.IntervalNotAccumulated.selector, LAST));
        av.verifyBundle(_encode(w), anchorOf(keccak256("other root")), ctx());
    }

    function test_rejects_roundOutsideInterval() public {
        World memory w = _world(defaultQueue());
        bytes32 r = _install(w);
        bytes memory p = _encode(w);
        V.BundleProof memory bp = abi.decode(p, (V.BundleProof));
        bp.txn.round = LAST + 1;
        vm.expectRevert(V.RoundOutsideInterval.selector);
        av.verifyBundle(abi.encode(bp), anchorOf(r), ctx());
    }

    function test_rejects_badAnchorOrContext() public {
        World memory w = _world(defaultQueue());
        (bytes memory proof, bytes memory anchor) = _bundle(w);
        vm.expectRevert(V.InvalidTrustAnchor.selector);
        av.verifyBundle(proof, abi.encodePacked(bytes32(0), GENESIS), ctx());
        vm.expectRevert(V.InvalidServiceAddress.selector);
        av.verifyBundle(proof, anchor, abi.encodePacked(CHANNEL_ID, uint32(7)));
    }

    function test_rejects_manifestMismatch() public {
        Queue memory q = defaultQueue();
        q.manifestCommitment = keccak256("committed");
        World memory w = _world(q);
        w.withManifest = true;
        w.manifest = manifest(abi.encodePacked(APP_ID), 4);
        (bytes memory proof, bytes memory anchor) = _bundle(w);
        vm.expectRevert();
        av.verifyBundle(proof, anchor, ctx());
    }

    function test_rejects_malformedMsgpack() public {
        World memory w = _world(defaultQueue());
        w.stib = hex"83a26474c4"; // map header then a truncated bin8
        (bytes memory proof, bytes memory anchor) = _bundle(w);
        vm.expectRevert(abi.encodeWithSelector(ClprMsgpack.MsgpackMalformed.selector, 5));
        av.verifyBundle(proof, anchor, ctx());
    }

    function test_config_happyPath() public {
        World memory w = _world(defaultQueue());
        bytes memory cfg = _config(w, "algorand:wGHE2Pwdvd7S12BL5FaOP20EGYesN73k");
        (bytes memory c, string memory chainId, bytes memory sa,,, bytes memory anchor, bytes memory anchorId,) =
            av.verifyConfig(cfg, CHANNEL_ID, "");
        assertEq(chainId, "algorand:wGHE2Pwdvd7S12BL5FaOP20EGYesN73k");
        assertEq(sa, abi.encodePacked(APP_ID));
        assertEq(c, ctx());
        assertEq(anchor.length, 64);
        assertEq(anchorId, abi.encodePacked(bytes32(anchor)));
        // the anchor proves the world's bundle
        (ClprTypes.QueueMetadata memory m,,,,) = av.verifyBundle(_encode(w), anchor, ctx());
        assertEq(m.nextMessageId, 3);
    }

    function test_config_rejectsUnknownBootstrapAndNamespace() public {
        World memory w = _world(defaultQueue());
        bytes memory cfg = _config(w, "eip155:1");
        vm.expectRevert(V.WrongChainNamespace.selector);
        av.verifyConfig(cfg, CHANNEL_ID, "");
        // another Algorand network's CAIP-2 id (testnet) for the mainnet genesis hash
        cfg = _config(w, "algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDe");
        vm.expectRevert(V.WrongChainNamespace.selector);
        av.verifyConfig(cfg, CHANNEL_ID, "");
        V.ConfigProof memory c = abi.decode(_config(w, "algorand:x"), (V.ConfigProof));
        c.bootstrap.lnProvenWeight += 1;
        vm.expectRevert(V.BootstrapUnknown.selector);
        av.verifyConfig(abi.encode(c), CHANNEL_ID, "");
    }

    function test_caip2_matchesNamespaceSpec() public view {
        assertEq(av.caip2(GENESIS), "algorand:wGHE2Pwdvd7S12BL5FaOP20EGYesN73k"); // mainnet
        // testnet genesis SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=
        assertEq(
            av.caip2(0x4863b518a4b3c84ec810f22d4f1081cb0f71f059a7ac20dec62f7f70e5093a22),
            "algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDe"
        );
    }

    function _indexOf(bytes memory hay, bytes memory needle) internal pure returns (uint256) {
        for (uint256 i = 0; i + needle.length <= hay.length; i++) {
            bool ok = true;
            for (uint256 j = 0; j < needle.length && ok; j++) {
                ok = hay[i + j] == needle[j];
            }
            if (ok) return i;
        }
        revert("not found");
    }
}
