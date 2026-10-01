// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {PolygonPosVerifier} from "@hiero-ledger/clpr/verifiers/evm/polygon/PolygonPosVerifier.sol";
import {CometBftCommitAccumulator} from "@hiero-ledger/clpr/verifiers/evm/cometbft/CometBftCommitAccumulator.sol";
import {CometBftLightClient} from "@hiero-ledger/clpr/verifiers/evm/cometbft/CometBftLightClient.sol";
import {CometBftStoreProofBase} from "@hiero-ledger/clpr/verifiers/evm/cometbft/CometBftStoreProofBase.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {PolygonSyntheticChain} from "@test/helpers/PolygonSyntheticChain.sol";

/// @notice PolygonPosVerifier on a synthetic Heimdall + Bor chain (test/helpers/PolygonSyntheticChain.sol):
///         real secp256k1eth commits, a real IAVL `milestone` store, a real RLP Bor header and real
///         Merkle-Patricia tries. Live Heimdall + Bor data: test/e2e/tests/verifiers/polygon-live.spec.ts.
contract PolygonPosVerifierTest is PolygonSyntheticChain {
    CometBftCommitAccumulator internal acc;
    PolygonPosVerifier internal verifier;

    function setUp() public {
        _initSets();
        acc = new CometBftCommitAccumulator(CHAIN, CometBftLightClient.KeyScheme.SECP256K1_ETH, address(0));
        verifier = new PolygonPosVerifier(
            PolygonPosVerifier.Profile({
                accumulator: acc,
                storeKey: bytes("milestone"),
                borChainId: BOR_CHAIN,
                bootstrapValidatorsHash: hashA,
                bootstrapHeight: ANCHOR_HEIGHT
            })
        );
    }

    function _verify(bytes memory proof, bytes memory anchor)
        internal
        view
        returns (ClprTypes.QueueMetadata memory m, bytes memory na, ClprTypes.ClprEndpointManifest memory man)
    {
        bytes[] memory payloads;
        (m, payloads, na,, man) = verifier.verifyBundle(proof, anchor, _ctxPoly());
        assertEq(payloads.length, 1);
        assertEq(payloads[0], PAYLOAD);
    }

    // ═════════════════════════════════════════════════════════════════════════
    //   Happy paths
    // ═════════════════════════════════════════════════════════════════════════

    function test_bundle_milestoneToBorStorage_decodes() public view {
        (ClprTypes.QueueMetadata memory m, bytes memory na, ClprTypes.ClprEndpointManifest memory man) =
            _verify(_enc(_q(_defaultWorld(), hashA)), _anchor(hashA, ANCHOR_HEIGHT));
        assertEq(uint8(m.state), 1);
        assertEq(m.nextMessageId, 3);
        assertEq(m.receivedMessageId, 0);
        assertEq(m.sentRunningHash, bytes32(0));
        assertEq(na.length, 0, "no rotation");
        assertEq(man.version, 0, "no manifest update");
    }

    function test_bundle_rotation_returnsNewAnchor() public view {
        (, bytes memory na,) = _verify(_enc(_q(_defaultWorld(), hashB)), _anchor(hashA, ANCHOR_HEIGHT));
        assertEq(na, _anchor(hashB, 121));
    }

    function test_bundle_manifest_boundToProvenCommitment() public view {
        bytes memory man = _manifestPoly(4);
        World memory w = _world(uint256(1) << 160, bytes32(uint256(18)), uint256(keccak256(man)));
        Q memory q = _q(w, hashA);
        q.manifestStorageProof = w.extraProof;
        q.manifestPreimage = man;
        (,, ClprTypes.ClprEndpointManifest memory m) = _verify(_enc(q), _anchor(hashA, ANCHOR_HEIGHT));
        assertEq(m.version, 4);
        assertEq(m.serviceAddress, abi.encodePacked(SVC));
    }

    function test_bundle_headerByHash_afterTwoAccumulateBatches() public {
        World memory w = _defaultWorld();
        (bytes memory sh0,) = _heimdall(w, 120, setA, hashA, _idx(0));
        (bytes memory sh1, bytes memory ms) = _heimdall(w, 120, setA, hashA, _idx(1));
        (bytes32 hh, bool fin) = acc.accumulate(_encodeSet(setA), sh0);
        assertFalse(fin);
        Q memory q = _q(w, hashA);
        q.headerRef = _hashRef(hh);
        q.multistore = ms;
        vm.expectRevert(CometBftCommitAccumulator.NotFinalized.selector);
        verifier.verifyBundle(_enc(q), _anchor(hashA, ANCHOR_HEIGHT), _ctxPoly());
        (, fin) = acc.accumulate(_encodeSet(setA), sh1);
        assertTrue(fin);
        (ClprTypes.QueueMetadata memory m,,) = _verify(_enc(q), _anchor(hashA, ANCHOR_HEIGHT));
        assertEq(m.nextMessageId, 3);
    }

    function test_bundle_inlineHop_thenHeaderFromNewSet() public view {
        World memory w = _defaultWorld();
        (bytes memory hop,) = _heimdall(w, 110, setA, hashB, _idx(0, 1));
        (bytes memory sh, bytes memory ms) = _heimdall(w, 120, setB, hashB, _idx(0, 1));
        Q memory q = _q(w, hashB);
        q.hops = new bytes[](1);
        q.hops[0] = _inlineRef(setA, hop);
        q.headerRef = _inlineRef(setB, sh);
        q.multistore = ms;
        (, bytes memory na,) = _verify(_enc(q), _anchor(hashA, ANCHOR_HEIGHT));
        assertEq(na, _anchor(hashB, 121));
    }

    function test_verifyConfig_fromBootstrap_provesServiceSlot() public view {
        (
            bytes memory ctx,
            string memory chainId,
            bytes memory service,
            uint96 nanos,
            ClprTypes.Throttles memory th,
            bytes memory anchor,,
            ClprTypes.ClprEndpointManifest memory m
        ) = verifier.verifyConfig(_configProof(_configWorld(SVC)), CHANNEL, "");
        assertEq(ctx, _ctxPoly());
        assertEq(chainId, CHAIN);
        assertEq(service, abi.encodePacked(SVC));
        assertEq(nanos, 1_700_000_000_000_000_000);
        assertEq(th.maxMessagesPerBundle, 10);
        assertEq(anchor, _anchor(hashB, 121));
        assertEq(m.version, 0);
    }

    function test_verifyContractSlots_readsProvenValues() public view {
        World memory w = _defaultWorld();
        bytes32[] memory slots = new bytes32[](2);
        slots[0] = _channelSlots()[0];
        slots[1] = _channelSlots()[1];
        Q memory q = _q(w, hashA);
        q.content = false;
        q.storageProof = _entries(w.st, slots);
        (bytes32[] memory v, uint64 borBlock, uint64 hh) =
            verifier.verifyContractSlots(_enc(q), _anchor(hashA, ANCHOR_HEIGHT), SVC, slots);
        assertEq(uint256(v[0]), (uint256(1) << 160) | (uint256(3) << 168));
        assertEq(v[1], bytes32(0));
        assertEq(borBlock, BOR_NUMBER);
        assertEq(hh, 120);
    }

    // ═════════════════════════════════════════════════════════════════════════
    //   Negative cases
    // ═════════════════════════════════════════════════════════════════════════

    function _expectBundleRevert(Q memory q, bytes memory anchor, bytes4 sel) internal {
        vm.expectRevert(sel);
        verifier.verifyBundle(_enc(q), anchor, _ctxPoly());
    }

    function test_reverts_badSignature() public {
        World memory w = _defaultWorld();
        bytes32 appHash;
        bytes memory ms;
        (ms, appHash) = _storeProof(bytes("milestone"), w.tree.root);
        Block memory b = _block(120, hashA, hashA, appHash);
        bytes[] memory over = new bytes[](2);
        over[1] = _sign(setA[2], _signBytes(b, b.header.timeSeconds + 1)); // validator 2 signs for 1
        Q memory q = _q(w, hashA);
        q.headerRef = _inlineRef(setA, _signedHeader(b, setA, _idx(0, 1), over));
        _expectBundleRevert(q, _anchor(hashA, ANCHOR_HEIGHT), CometBftLightClient.InvalidSignature.selector);
    }

    function test_reverts_belowThreshold() public {
        World memory w = _defaultWorld();
        (bytes memory sh,) = _heimdall(w, 120, setA, hashA, _idx(0, 2)); // 40 + 20 = 60%
        Q memory q = _q(w, hashA);
        q.headerRef = _inlineRef(setA, sh);
        _expectBundleRevert(q, _anchor(hashA, ANCHOR_HEIGHT), CometBftLightClient.QuorumNotMet.selector);
    }

    function test_reverts_wrongValidatorSet() public {
        _expectBundleRevert(
            _q(_defaultWorld(), hashA),
            _anchor(hashB, ANCHOR_HEIGHT),
            CometBftLightClient.ValidatorSetHashMismatch.selector
        );
    }

    function test_reverts_staleHeader() public {
        _expectBundleRevert(_q(_defaultWorld(), hashA), _anchor(hashA, 121), CometBftLightClient.HeightTooOld.selector);
    }

    function test_reverts_wrongStoreKey() public {
        World memory w = _defaultWorld();
        (bytes memory ms, bytes32 appHash) = _storeProof(bytes("checkpoint"), w.tree.root);
        Block memory b = _block(120, hashA, hashA, appHash);
        Q memory q = _q(w, hashA);
        q.headerRef = _inlineRef(setA, _signedHeader(b, setA, _idx(0, 1)));
        q.multistore = ms;
        _expectBundleRevert(q, _anchor(hashA, ANCHOR_HEIGHT), CometBftStoreProofBase.InvalidStoreKey.selector);
    }

    function test_reverts_milestoneKeyNotInMilestoneMap() public {
        World memory w = _defaultWorld();
        Q memory q = _q(w, hashA);
        q.milestoneEntry = w.tree.entryR; // the count item (0x83), a real entry of the same store
        _expectBundleRevert(q, _anchor(hashA, ANCHOR_HEIGHT), PolygonPosVerifier.InvalidMilestoneKey.selector);
    }

    function test_reverts_absentMilestone() public {
        World memory w = _defaultWorld();
        Q memory q = _q(w, hashA);
        q.milestoneEntry = _absent(w.tree, _msKey(COUNT + 1)); // 0x81‖6 sorts between 0x81‖5 and 0x83
        _expectBundleRevert(q, _anchor(hashA, ANCHOR_HEIGHT), PolygonPosVerifier.MilestoneNotFound.selector);
    }

    function test_reverts_tamperedMilestoneValue() public {
        World memory w = _defaultWorld();
        World memory other = _world(uint256(7) << 168, bytes32(uint256(18)), 0);
        Q memory q = _q(w, hashA);
        // The other world's milestone entry is not in this store.
        q.milestoneEntry = other.tree.entryL;
        vm.expectRevert();
        verifier.verifyBundle(_enc(q), _anchor(hashA, ANCHOR_HEIGHT), _ctxPoly());
    }

    function test_reverts_otherBorChain() public {
        World memory w = _defaultWorld();
        w.milestone = _milestone(BOR_NUMBER, keccak256(w.borHeader), "80002");
        w.tree = _milestoneTree(w.milestone);
        _expectBundleRevert(_q(w, hashA), _anchor(hashA, ANCHOR_HEIGHT), PolygonPosVerifier.BorChainIdMismatch.selector);
    }

    function test_reverts_borHeaderNotTheMilestoneHash() public {
        World memory w = _defaultWorld();
        Q memory q = _q(w, hashA);
        q.borHeader = _borHeader(keccak256("forged state"), BOR_NUMBER);
        _expectBundleRevert(q, _anchor(hashA, ANCHOR_HEIGHT), PolygonPosVerifier.BorHeaderHashMismatch.selector);
    }

    function test_reverts_borNumberNotMilestoneEndBlock() public {
        World memory w = _defaultWorld();
        w.milestone = _milestone(BOR_NUMBER + 1, keccak256(w.borHeader), BOR_CHAIN);
        w.tree = _milestoneTree(w.milestone);
        _expectBundleRevert(
            _q(w, hashA), _anchor(hashA, ANCHOR_HEIGHT), PolygonPosVerifier.BorBlockNumberMismatch.selector
        );
    }

    function test_reverts_accountProofForAnotherService() public {
        Q memory q = _q(_defaultWorld(), hashA);
        bytes memory ctx = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: CHANNEL, remoteServiceAddress: abi.encodePacked(address(0xBEEF))})
        );
        vm.expectRevert();
        verifier.verifyBundle(_enc(q), _anchor(hashA, ANCHOR_HEIGHT), ctx);
    }

    function test_reverts_anotherChannelsSlots() public {
        Q memory q = _q(_defaultWorld(), hashA);
        bytes memory ctx = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: keccak256("other"), remoteServiceAddress: abi.encodePacked(SVC)})
        );
        vm.expectRevert();
        verifier.verifyBundle(_enc(q), _anchor(hashA, ANCHOR_HEIGHT), ctx);
    }

    function test_reverts_tamperedStorageProof() public {
        World memory w = _defaultWorld();
        Q memory q = _q(w, hashA);
        World memory other = _world(uint256(9) << 168, bytes32(uint256(18)), 0);
        q.storageProof = other.storageProof; // valid shape, another storage root
        vm.expectRevert();
        verifier.verifyBundle(_enc(q), _anchor(hashA, ANCHOR_HEIGHT), _ctxPoly());
    }

    function test_reverts_notFinalizedHeaderByHash() public {
        Q memory q = _q(_defaultWorld(), hashA);
        q.headerRef = _hashRef(keccak256("never accumulated"));
        _expectBundleRevert(q, _anchor(hashA, ANCHOR_HEIGHT), CometBftCommitAccumulator.NotFinalized.selector);
    }

    function test_reverts_manifestWithoutProof() public {
        Q memory q = _q(_defaultWorld(), hashA);
        q.manifestPreimage = _manifestPoly(1);
        _expectBundleRevert(q, _anchor(hashA, ANCHOR_HEIGHT), PolygonPosVerifier.ManifestProofPairMismatch.selector);
    }

    function test_reverts_manifestNotTheCommitment() public {
        World memory w = _world(uint256(1) << 160, bytes32(uint256(18)), uint256(keccak256("other")));
        Q memory q = _q(w, hashA);
        q.manifestStorageProof = w.extraProof;
        q.manifestPreimage = _manifestPoly(1);
        _expectBundleRevert(q, _anchor(hashA, ANCHOR_HEIGHT), ClprEvmBundleVerifier.ManifestCommitmentMismatch.selector);
    }

    function test_reverts_missingBorProof() public {
        Q memory q = _q(_defaultWorld(), hashA);
        q.borHeader = "";
        _expectBundleRevert(q, _anchor(hashA, ANCHOR_HEIGHT), PolygonPosVerifier.MissingBorProof.selector);
    }

    function test_reverts_badAnchor() public {
        _expectBundleRevert(_q(_defaultWorld(), hashA), hex"01", CometBftStoreProofBase.InvalidTrustAnchor.selector);
    }

    function test_reverts_verifyConfig_serviceSlotMismatch() public {
        bytes memory proof = _configProof(_configWorld(address(0xBEEF)));
        vm.expectRevert(PolygonPosVerifier.ServiceAddressSlotMismatch.selector);
        verifier.verifyConfig(proof, CHANNEL, "");
    }

    function test_reverts_verifyConfig_notFromBootstrap() public {
        World memory w = _configWorld(SVC);
        (bytes memory sh, bytes memory ms) = _heimdall(w, 120, setB, hashB, _idx(0, 1));
        Q memory q = _q(w, hashB);
        q.content = false;
        q.headerRef = _inlineRef(setB, sh);
        q.multistore = ms;
        q.storageProof = w.extraProof;
        q.ledgerConfig = _ledgerConfig(SVC);
        vm.expectRevert(CometBftLightClient.ValidatorSetHashMismatch.selector);
        verifier.verifyConfig(_enc(q), CHANNEL, "");
    }

    function test_reverts_profile() public {
        vm.expectRevert(CometBftStoreProofBase.InvalidProfile.selector);
        new PolygonPosVerifier(
            PolygonPosVerifier.Profile({
                accumulator: acc,
                storeKey: bytes("milestone"),
                borChainId: "",
                bootstrapValidatorsHash: hashA,
                bootstrapHeight: 1
            })
        );
    }
}
