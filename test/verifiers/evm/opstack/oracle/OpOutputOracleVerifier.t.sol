// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {OpOutputOracleVerifier} from "@hiero-ledger/clpr/verifiers/evm/opstack/oracle/OpOutputOracleVerifier.sol";
import {
    OpOutputOracleProposedVerifier
} from "@hiero-ledger/clpr/verifiers/evm/opstack/oracle/OpOutputOracleProposedVerifier.sol";
import {
    OpOutputOracleVerifierBase
} from "@hiero-ledger/clpr/verifiers/evm/opstack/oracle/OpOutputOracleVerifierBase.sol";
import {OpStackBundleVerifierBase} from "@hiero-ledger/clpr/verifiers/evm/opstack/OpStackBundleVerifierBase.sol";
import {EthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/EthL1StateVerifier.sol";
import {IEthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/lib/IEthL1StateVerifier.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {OpOutputOracleProof as OO} from "@hiero-ledger/clpr/libraries/proof/opstack/OpOutputOracleProof.sol";
import {EthBeaconLightClient} from "@hiero-ledger/clpr/libraries/proof/beacon/EthBeaconLightClient.sol";
import {ClprBeaconSsz} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconSsz.sol";
import {ClprBeaconBls} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconBls.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {EthCommitteeFixtures} from "@test/verifiers/evm/ethereum/EthCommitteeFixtures.sol";
import {MockEthL1StateVerifier} from "@test/verifiers/evm/opstack/OpStackVerifier.t.sol";

/// @dev Shared helpers: profile and bundle encoding.
abstract contract OracleTestBase is EthCommitteeFixtures {
    uint8 internal constant IMMUTABLE = uint8(OO.PeriodSource.IMMUTABLE);
    uint8 internal constant STORAGE = uint8(OO.PeriodSource.STORAGE);

    function _ethAccount() internal pure returns (OpOutputOracleVerifierBase.L2AccountFormat memory) {
        return OpOutputOracleVerifierBase.L2AccountFormat({fields: 4, storageRootIndex: 2, codeHashIndex: 3});
    }

    function _blastAccount() internal pure returns (OpOutputOracleVerifierBase.L2AccountFormat memory) {
        return OpOutputOracleVerifierBase.L2AccountFormat({fields: 7, storageRootIndex: 5, codeHashIndex: 6});
    }

    function _bundle(
        bytes memory lightClientProof,
        bytes memory oracleProof,
        bytes memory preimage,
        bytes memory accountProof,
        bytes memory storageProof
    ) internal pure returns (bytes memory) {
        bytes[] memory items = new bytes[](6);
        items[0] = RLP.encode(lightClientProof);
        items[1] = oracleProof;
        items[2] = RLP.encode(preimage);
        items[3] = accountProof;
        items[4] = storageProof;
        items[5] = RLP.encode(bytes(""));
        return RLP.encode(items);
    }

    function _channelContext(bytes32 cid, address service) internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: cid, remoteServiceAddress: abi.encodePacked(service)})
        );
    }

    /// Flat 260-byte anchor carrying `channelId` and the pinned L2 code hash (the committee fields only
    /// matter to the real light client).
    function _flatAnchor(bytes32 cid, bytes32 codeHash) internal pure returns (bytes memory a) {
        a = new bytes(EthBeaconLightClient.TRUST_ANCHOR_LENGTH);
        assembly {
            let d := add(a, 32)
            mstore(add(d, 36), cid)
            mstore(add(d, 228), codeHash)
        }
    }

    function _replaceOracleProofIndex(bytes memory oracleProof, uint256 index) internal pure returns (bytes memory) {
        bytes[] memory items = new bytes[](4);
        items[0] = RLP.encode(index);
        // Re-encode the other three items verbatim.
        (uint256[] memory offs, uint256[] memory lens) = _itemSpans(oracleProof);
        for (uint256 i = 1; i < 4; i++) {
            bytes memory it = new bytes(lens[i]);
            for (uint256 j = 0; j < lens[i]; j++) {
                it[j] = oracleProof[offs[i] + j];
            }
            items[i] = it;
        }
        return RLP.encode(items);
    }

    /// Spans of the (raw, header-included) items of an RLP list.
    function _itemSpans(bytes memory list) internal pure returns (uint256[] memory offs, uint256[] memory lens) {
        uint256 p = _payloadStart(list, 0);
        offs = new uint256[](8);
        lens = new uint256[](8);
        uint256 n;
        while (p < list.length) {
            uint256 l = _itemLength(list, p);
            offs[n] = p;
            lens[n] = l;
            n++;
            p += l;
        }
    }

    function _payloadStart(bytes memory b, uint256 p) private pure returns (uint256) {
        uint8 h = uint8(b[p]);
        if (h < 0xf8) return p + 1;
        return p + 1 + (h - 0xf7);
    }

    function _itemLength(bytes memory b, uint256 p) private pure returns (uint256) {
        uint8 h = uint8(b[p]);
        if (h < 0x80) return 1;
        if (h < 0xb8) return 1 + (h - 0x80);
        if (h < 0xc0) return 1 + (h - 0xb7) + _be(b, p + 1, h - 0xb7);
        if (h < 0xf8) return 1 + (h - 0xc0);
        return 1 + (h - 0xf7) + _be(b, p + 1, h - 0xf7);
    }

    function _be(bytes memory b, uint256 p, uint256 n) private pure returns (uint256 v) {
        for (uint256 i = 0; i < n; i++) {
            v = (v << 8) | uint8(b[p + i]);
        }
    }
}

/// @notice The acceptance matrix on synthetic L1 state (`buildOpOracleSyntheticFixture.ts`: anvil,
///         real MPT proofs), covering the states the live chains do not show on demand: a deleted output
///         still in storage past `length`, optimistic mode, a packed flag with a non-zero neighbour, and a
///         ClprService with a populated channel.
contract OpOutputOracleSyntheticTest is OracleTestBase {
    string internal json;
    bytes32 internal l1StateRoot;
    uint64 internal l1Slot;
    uint64 internal l1Time;
    uint256 internal period;
    bytes32 internal implCodeHash;
    address internal oracle;
    address internal oracleOptimistic;
    address internal oracleKatana;
    bytes32 internal outputRoot;
    bytes32 internal otherRoot;

    address internal service;
    bytes32 internal serviceCodeHash;
    bytes32 internal channelId;
    bytes internal preimage;
    bytes internal accountProof;
    bytes internal storageProof;

    MockEthL1StateVerifier internal l1;
    OpOutputOracleVerifier internal finalized;
    OpOutputOracleProposedVerifier internal proposed;
    OpOutputOracleVerifier internal katana;

    function setUp() public override {
        super.setUp();
        json =
            vm.readFile(string.concat(vm.projectRoot(), "/test/verifiers/evm/opstack/oracle/fixtures/synthetic.json"));
        l1StateRoot = vm.parseJsonBytes32(json, ".l1.stateRoot");
        l1Slot = uint64(vm.parseJsonUint(json, ".l1.slot"));
        l1Time = uint64(vm.parseJsonUint(json, ".l1.time"));
        period = vm.parseJsonUint(json, ".l1.period");
        implCodeHash = vm.parseJsonBytes32(json, ".implCodeHash");
        oracle = vm.parseJsonAddress(json, ".oracle");
        oracleOptimistic = vm.parseJsonAddress(json, ".oracleOptimistic");
        oracleKatana = vm.parseJsonAddress(json, ".oracleKatana");
        outputRoot = vm.parseJsonBytes32(json, ".outputRoot");
        otherRoot = vm.parseJsonBytes32(json, ".otherRoot");
        service = vm.parseJsonAddress(json, ".l2.service");
        serviceCodeHash = vm.parseJsonBytes32(json, ".l2.serviceCodeHash");
        channelId = vm.parseJsonBytes32(json, ".l2.channelId");
        preimage = vm.parseJsonBytes(json, ".l2.preimage");
        accountProof = vm.parseJsonBytes(json, ".l2.accountProof");
        storageProof = vm.parseJsonBytes(json, ".l2.storageProof");

        l1 = new MockEthL1StateVerifier(l1StateRoot, l1Slot);
        finalized = new OpOutputOracleVerifier(l1, 0, 12, _mantleLike(oracle), _ethAccount());
        proposed = new OpOutputOracleProposedVerifier(l1, 0, 12, _mantleLike(oracle), _ethAccount());
        katana = new OpOutputOracleVerifier(l1, 0, 12, _katanaLike(oracleKatana), _ethAccount());
    }

    function _mantleLike(address o) internal view returns (OO.Profile memory) {
        return OO.Profile({
            oracle: o,
            oracleImplCodeHash: implCodeHash,
            outputsSlot: 3,
            periodSource: OO.PeriodSource.STORAGE,
            finalizationPeriodSeconds: 0,
            finalizationPeriodSlot: 8,
            hasOptimisticMode: true,
            optimisticModeSlot: 16,
            optimisticModeOffset: 0
        });
    }

    function _katanaLike(address o) internal view returns (OO.Profile memory) {
        return OO.Profile({
            oracle: o,
            oracleImplCodeHash: implCodeHash,
            outputsSlot: 116,
            periodSource: OO.PeriodSource.IMMUTABLE,
            finalizationPeriodSeconds: 0,
            finalizationPeriodSlot: 0,
            hasOptimisticMode: true,
            optimisticModeSlot: 124,
            optimisticModeOffset: 0
        });
    }

    function _proof(string memory key) internal view returns (bytes memory) {
        return vm.parseJsonBytes(json, string.concat(".proofs.", key));
    }

    function _ts(uint256 i) internal view returns (uint256) {
        return vm.parseJsonUintArray(json, ".outputTimestamps")[i];
    }

    // ── verifyOutput: the settlement rule alone ─────────────────────────────

    function test_finalized_acceptsOutputPastThePeriod() public view {
        OO.Output memory o = finalized.verifyOutput(_proof("oracle.i1"), l1StateRoot, l1Time, outputRoot);
        assertEq(o.index, 1);
        assertEq(o.l1Timestamp, _ts(1));
        assertEq(o.l2BlockNumber, 200);
    }

    function test_finalized_rejectsOutputInsideThePeriod_proposedAccepts() public {
        bytes memory p = _proof("oracle.i2");
        vm.expectRevert(abi.encodeWithSelector(OO.OutputNotFinalized.selector, 2, _ts(2), l1Time, period));
        finalized.verifyOutput(p, l1StateRoot, l1Time, outputRoot);
        assertEq(proposed.verifyOutput(p, l1StateRoot, l1Time, outputRoot).index, 2);
    }

    /// OptimismPortal._isFinalizationPeriodElapsed: `block.timestamp > timestamp + period`.
    function test_finalizationPeriod_boundary() public {
        bytes memory p = _proof("oracle.i2");
        uint64 edge = uint64(_ts(2) + period);
        vm.expectPartialRevert(OO.OutputNotFinalized.selector);
        finalized.verifyOutput(p, l1StateRoot, edge, outputRoot);
        finalized.verifyOutput(p, l1StateRoot, edge + 1, outputRoot);
    }

    function test_period_isReadFromStorage_notTheProfile() public {
        // A STORAGE profile ignores its own finalizationPeriodSeconds: a 0 there must not shorten the 1 h.
        OO.Profile memory prof = _mantleLike(oracle);
        prof.finalizationPeriodSeconds = 0;
        OpOutputOracleVerifier v = new OpOutputOracleVerifier(l1, 0, 12, prof, _ethAccount());
        vm.expectPartialRevert(OO.OutputNotFinalized.selector);
        v.verifyOutput(_proof("oracle.i2"), l1StateRoot, l1Time, outputRoot);
    }

    function test_rejectsDeletedOutputStillInStorage_bothTiers() public {
        // Element #3 still holds our root (deleteL2Outputs only truncates the length) but length is 3.
        bytes memory p = _proof("oracle.i3");
        vm.expectRevert(abi.encodeWithSelector(OO.OutputNotPosted.selector, 3, 3));
        finalized.verifyOutput(p, l1StateRoot, l1Time, outputRoot);
        vm.expectRevert(abi.encodeWithSelector(OO.OutputNotPosted.selector, 3, 3));
        proposed.verifyOutput(p, l1StateRoot, l1Time, outputRoot);
    }

    function test_rejectsOutputRootThatIsNotAtTheIndex() public {
        vm.expectRevert(abi.encodeWithSelector(OO.OutputRootMismatch.selector, 0, otherRoot, outputRoot));
        proposed.verifyOutput(_proof("oracle.i0"), l1StateRoot, l1Time, outputRoot);
        // The other root at #0 is itself accepted.
        finalized.verifyOutput(_proof("oracle.i0"), l1StateRoot, l1Time, otherRoot);
    }

    function test_rejectsOptimisticMode_bothTiers() public {
        OpOutputOracleVerifier f = new OpOutputOracleVerifier(l1, 0, 12, _mantleLike(oracleOptimistic), _ethAccount());
        OpOutputOracleProposedVerifier pr =
            new OpOutputOracleProposedVerifier(l1, 0, 12, _mantleLike(oracleOptimistic), _ethAccount());
        bytes memory p = _proof("optimistic.i1");
        vm.expectRevert(OO.OptimisticModeEnabled.selector);
        f.verifyOutput(p, l1StateRoot, l1Time, outputRoot);
        vm.expectRevert(OO.OptimisticModeEnabled.selector);
        pr.verifyOutput(p, l1StateRoot, l1Time, outputRoot);
    }

    function test_optimisticFlagOffset_ignoresPackedNeighbour() public view {
        // Katana layout: optimisticModeManager is packed at offset 1 of the flag's slot (non-zero).
        assertEq(katana.verifyOutput(_proof("katana.i1"), l1StateRoot, l1Time, outputRoot).index, 1);
    }

    function test_katanaLike_periodZero_finalOncePosted() public view {
        // #2 is 30 min old: inside a 1 h period, but AggchainFEP outputs are final when appended.
        assertEq(katana.verifyOutput(_proof("katana.i2"), l1StateRoot, l1Time, outputRoot).index, 2);
    }

    function test_rejectsUnpinnedImplementation() public {
        OO.Profile memory prof = _mantleLike(oracle);
        prof.oracleImplCodeHash = keccak256("other implementation");
        OpOutputOracleVerifier v = new OpOutputOracleVerifier(l1, 0, 12, prof, _ethAccount());
        vm.expectPartialRevert(OO.OracleImplMismatch.selector);
        v.verifyOutput(_proof("oracle.i1"), l1StateRoot, l1Time, outputRoot);
    }

    function test_rejectsProofOfAnotherOracle() public {
        // Pinned oracle = the optimistic one; the proof is the other oracle's account → MPT mismatch.
        OpOutputOracleVerifier v = new OpOutputOracleVerifier(l1, 0, 12, _mantleLike(oracleOptimistic), _ethAccount());
        vm.expectRevert();
        v.verifyOutput(_proof("oracle.i1"), l1StateRoot, l1Time, outputRoot);
    }

    function test_rejectsProofWithoutThePeriodSlot() public {
        vm.expectPartialRevert(ClprEvmStateProof.SlotNotProven.selector);
        finalized.verifyOutput(_proof("oracle.i1NoPeriod"), l1StateRoot, l1Time, outputRoot);
    }

    function test_rejectsIndexMismatchedWithItsSlots() public {
        // The proof carries #1's element slots; claiming index 2 derives #2's slots, which are absent.
        bytes memory p = _replaceOracleProofIndex(_proof("oracle.i1"), 2);
        vm.expectPartialRevert(ClprEvmStateProof.SlotNotProven.selector);
        proposed.verifyOutput(p, l1StateRoot, l1Time, outputRoot);
    }

    function test_rejectsBadShapes() public {
        bytes[] memory three = new bytes[](3);
        three[0] = RLP.encode(uint256(1));
        three[1] = RLP.encode(new bytes[](0));
        three[2] = RLP.encode(new bytes[](0));
        vm.expectRevert(OO.InvalidOracleProof.selector);
        finalized.verifyOutput(RLP.encode(three), l1StateRoot, l1Time, outputRoot);

        bytes memory huge = _replaceOracleProofIndex(_proof("oracle.i1"), uint256(type(uint64).max) + 1);
        vm.expectRevert(OO.InvalidOracleProof.selector);
        finalized.verifyOutput(huge, l1StateRoot, l1Time, outputRoot);
    }

    // ── verifyBundle: the whole path (L1 light client mocked) ──────────────

    function test_bundle_finalized_populatedChannel() public view {
        bytes memory b = _bundle("", _proof("oracle.i1"), preimage, accountProof, storageProof);
        uint256 g = gasleft();
        (ClprTypes.QueueMetadata memory m,,,,) =
            finalized.verifyBundle(b, _flatAnchor(channelId, serviceCodeHash), _channelContext(channelId, service));
        console.log("OpOutputOracleVerifier.verifyBundle (mock L1) gas:", g - gasleft());
        assertEq(m.nextMessageId, 3);
        assertEq(m.receivedMessageId, 2);
        assertEq(m.sentRunningHash, keccak256("sent"));
        assertEq(m.receivedRunningHash, keccak256("received"));
        assertEq(uint8(m.state), 1);
        assertEq(m.endpointManifestVersion, 1);
    }

    function test_bundle_proposedAcceptsWhatFinalizedRejects() public {
        bytes memory b = _bundle("", _proof("oracle.i2"), preimage, accountProof, storageProof);
        bytes memory a = _flatAnchor(channelId, serviceCodeHash);
        bytes memory ctx = _channelContext(channelId, service);
        (ClprTypes.QueueMetadata memory m,,,,) = proposed.verifyBundle(b, a, ctx);
        assertEq(m.nextMessageId, 3);
        vm.expectPartialRevert(OO.OutputNotFinalized.selector);
        finalized.verifyBundle(b, a, ctx);
    }

    function test_bundle_rejectsWrongPinnedCodeHash() public {
        bytes memory b = _bundle("", _proof("oracle.i1"), preimage, accountProof, storageProof);
        vm.expectRevert(ClprEvmBundleVerifier.CodeHashMismatch.selector);
        finalized.verifyBundle(b, _flatAnchor(channelId, keccak256("x")), _channelContext(channelId, service));
    }

    function test_bundle_rejectsStorageProofOfAnotherChannel() public {
        bytes32 other = keccak256("another channel");
        bytes memory b = _bundle("", _proof("oracle.i1"), preimage, accountProof, storageProof);
        vm.expectPartialRevert(ClprEvmStateProof.SlotNotProven.selector);
        finalized.verifyBundle(b, _flatAnchor(other, serviceCodeHash), _channelContext(other, service));
    }

    function test_bundle_rejectsPreimageOfAnotherOutput() public {
        bytes memory wrong = preimage;
        wrong[127] ^= 0x01; // another block hash → another output root
        bytes memory b = _bundle("", _proof("oracle.i1"), wrong, accountProof, storageProof);
        vm.expectPartialRevert(OO.OutputRootMismatch.selector);
        proposed.verifyBundle(b, _flatAnchor(channelId, serviceCodeHash), _channelContext(channelId, service));
    }

    function test_bundle_rejectsWrongAccountFormat() public {
        // An Ethereum 4-field account leaf under a Blast-format deployment.
        OpOutputOracleVerifier v = new OpOutputOracleVerifier(l1, 0, 12, _mantleLike(oracle), _blastAccount());
        bytes memory b = _bundle("", _proof("oracle.i1"), preimage, accountProof, storageProof);
        vm.expectRevert(OpOutputOracleVerifierBase.InvalidL2Account.selector);
        v.verifyBundle(b, _flatAnchor(channelId, serviceCodeHash), _channelContext(channelId, service));
    }

    function test_bundle_rejectsBadShapes() public {
        bytes memory a = _flatAnchor(channelId, serviceCodeHash);
        vm.expectRevert(OpStackBundleVerifierBase.InvalidTrustAnchor.selector);
        finalized.verifyBundle(RLP.encode(new bytes[](6)), new bytes(259), _channelContext(channelId, service));
        vm.expectRevert(OpStackBundleVerifierBase.InvalidPayloadShape.selector);
        finalized.verifyBundle(RLP.encode(new bytes[](5)), a, _channelContext(channelId, service));
    }

    // ── deployment ──────────────────────────────────────────────────────────

    function test_constructor_rejectsIncompleteProfile() public {
        OO.Profile memory prof = _mantleLike(oracle);
        prof.oracle = address(0);
        vm.expectRevert(OpStackBundleVerifierBase.InvalidDeployment.selector);
        new OpOutputOracleVerifier(l1, 0, 12, prof, _ethAccount());

        prof = _mantleLike(oracle);
        prof.oracleImplCodeHash = bytes32(0);
        vm.expectRevert(OpStackBundleVerifierBase.InvalidDeployment.selector);
        new OpOutputOracleVerifier(l1, 0, 12, prof, _ethAccount());

        prof = _mantleLike(oracle);
        prof.optimisticModeOffset = 32;
        vm.expectRevert(OpStackBundleVerifierBase.InvalidDeployment.selector);
        new OpOutputOracleVerifier(l1, 0, 12, prof, _ethAccount());

        OpOutputOracleVerifierBase.L2AccountFormat memory bad =
            OpOutputOracleVerifierBase.L2AccountFormat({fields: 4, storageRootIndex: 4, codeHashIndex: 3});
        vm.expectRevert(OpStackBundleVerifierBase.InvalidDeployment.selector);
        new OpOutputOracleVerifier(l1, 0, 12, _mantleLike(oracle), bad);

        bad = OpOutputOracleVerifierBase.L2AccountFormat({fields: 4, storageRootIndex: 3, codeHashIndex: 3});
        vm.expectRevert(OpStackBundleVerifierBase.InvalidDeployment.selector);
        new OpOutputOracleVerifier(l1, 0, 12, _mantleLike(oracle), bad);

        vm.expectRevert(OpStackBundleVerifierBase.InvalidDeployment.selector);
        new OpOutputOracleVerifier(IEthL1StateVerifier(address(0)), 0, 12, _mantleLike(oracle), _ethAccount());
        vm.expectRevert(OpStackBundleVerifierBase.InvalidDeployment.selector);
        new OpOutputOracleVerifier(l1, 0, 0, _mantleLike(oracle), _ethAccount());
    }

    function test_profile_roundTripsAndTier() public view {
        OO.Profile memory p = finalized.profile();
        assertEq(p.oracle, oracle);
        assertEq(p.oracleImplCodeHash, implCodeHash);
        assertEq(p.outputsSlot, 3);
        assertEq(uint8(p.periodSource), STORAGE);
        assertEq(p.finalizationPeriodSlot, 8);
        assertTrue(p.hasOptimisticMode);
        assertEq(p.optimisticModeSlot, 16);
        assertEq(uint8(finalized.FINALITY()), uint8(OpStackBundleVerifierBase.Finality.FINALIZED));
        assertEq(uint8(proposed.FINALITY()), uint8(OpStackBundleVerifierBase.Finality.PROPOSED));
        assertEq(finalized.L2_ACCOUNT_FIELDS(), 4);
    }
}

/// @notice REAL mainnet data from Blast, Mantle and Katana (`buildOpOracleLiveProof.ts`), replayed
///         through the REAL {EthL1StateVerifier}: a generator sync committee signs a beacon header whose
///         body commits the captured mainnet execution `state_root` at the captured slot (the real
///         committee's signature is replayed in the vitest spec), and every oracle and L2 proof is the
///         live `eth_getProof` data.
contract OpOutputOracleLiveTest is OracleTestBase {
    bytes4 internal constant FORK_VERSION = 0x06000000;
    bytes32 internal constant GVR = bytes32(uint256(0x6a1));

    string internal json;
    bytes32 internal l1StateRoot;
    uint64 internal l1Slot;
    uint64 internal l1Time;
    uint64 internal genesisTime;
    address internal l2Account;
    EthL1StateVerifier internal l1;

    function setUp() public override {
        super.setUp();
        json = vm.readFile(string.concat(vm.projectRoot(), "/test/verifiers/evm/opstack/oracle/fixtures/live.json"));
        l1StateRoot = vm.parseJsonBytes32(json, ".l1.stateRoot");
        l1Slot = uint64(vm.parseJsonUint(json, ".l1.slot"));
        l1Time = uint64(vm.parseJsonUint(json, ".l1.time"));
        genesisTime = uint64(vm.parseJsonUint(json, ".l1.genesisTime"));
        l2Account = vm.parseJsonAddress(json, ".l2Account");
        l1 = new EthL1StateVerifier(
            ClprBeaconSsz.GINDEX_EXECUTION_STATE_ROOT_IN_BODY,
            9,
            ClprBeaconSsz.GINDEX_NEXT_SYNC_COMMITTEE_IN_STATE,
            6,
            8192
        );
    }

    // ── fixture plumbing ────────────────────────────────────────────────────

    function _s(string memory chain, string memory key) internal pure returns (string memory) {
        return string.concat(".chains.", chain, ".", key);
    }

    function _profile(string memory chain) internal view returns (OO.Profile memory) {
        return OO.Profile({
            oracle: vm.parseJsonAddress(json, _s(chain, "oracle")),
            oracleImplCodeHash: vm.parseJsonBytes32(json, _s(chain, "oracleImplCodeHash")),
            outputsSlot: vm.parseJsonUint(json, _s(chain, "outputsSlot")),
            periodSource: OO.PeriodSource(vm.parseJsonUint(json, _s(chain, "periodSource"))),
            // Only IMMUTABLE profiles carry the value (STORAGE reads it from the oracle).
            finalizationPeriodSeconds: vm.parseJsonUint(json, _s(chain, "periodSource")) == IMMUTABLE
                ? vm.parseJsonUint(json, _s(chain, "finalizationPeriodSeconds"))
                : 0,
            finalizationPeriodSlot: vm.parseJsonUint(json, _s(chain, "finalizationPeriodSlot")),
            hasOptimisticMode: vm.parseJsonBool(json, _s(chain, "hasOptimisticMode")),
            optimisticModeSlot: vm.parseJsonUint(json, _s(chain, "optimisticModeSlot")),
            optimisticModeOffset: vm.parseJsonUint(json, _s(chain, "optimisticModeOffset"))
        });
    }

    function _format(string memory chain) internal view returns (OpOutputOracleVerifierBase.L2AccountFormat memory) {
        return OpOutputOracleVerifierBase.L2AccountFormat({
            fields: vm.parseJsonUint(json, _s(chain, "accountFields")),
            storageRootIndex: vm.parseJsonUint(json, _s(chain, "accountStorageRootIndex")),
            codeHashIndex: vm.parseJsonUint(json, _s(chain, "accountCodeHashIndex"))
        });
    }

    function _finalized(string memory chain) internal returns (OpOutputOracleVerifier) {
        return new OpOutputOracleVerifier(l1, genesisTime, 12, _profile(chain), _format(chain));
    }

    function _proposed(string memory chain) internal returns (OpOutputOracleProposedVerifier) {
        return new OpOutputOracleProposedVerifier(l1, genesisTime, 12, _profile(chain), _format(chain));
    }

    function _channelId(string memory chain) internal view returns (bytes32) {
        return vm.parseJsonBytes32(json, _s(chain, "channelId"));
    }

    function _ctx(string memory chain) internal view returns (bytes memory) {
        return _channelContext(_channelId(chain), l2Account);
    }

    /// Generator-committee anchor binding the chain's channel and the pinned L2 code hash.
    function _anchor(string memory chain) internal view returns (bytes memory) {
        return EthBeaconLightClient.encodeTrustAnchor(
            _uncompressedKeys(SYNC_COMMITTEE_SIZE),
            _committeeAggregate(),
            GVR,
            abi.encodePacked(FORK_VERSION),
            _channelId(chain),
            vm.parseJsonBytes32(json, _s(chain, "l2CodeHash"))
        );
    }

    /// Light-client proof: `signers` generator keys sign a header at the captured slot whose body
    /// commits the captured mainnet `state_root` (gindex 802, zero siblings).
    function _lightClient(uint256 signers, bool corruptSignature) internal view returns (bytes memory) {
        bytes32[] memory branch = new bytes32[](9);
        bytes32 bodyRoot = l1StateRoot;
        uint256 idx = ClprBeaconSsz.GINDEX_EXECUTION_STATE_ROOT_IN_BODY;
        for (uint256 i = 0; i < 9; i++) {
            bodyRoot = idx & 1 == 1
                ? sha256(abi.encodePacked(branch[i], bodyRoot))
                : sha256(abi.encodePacked(bodyRoot, branch[i]));
            idx >>= 1;
        }
        bytes32 headerRoot =
            ClprBeaconSsz.beaconBlockHeaderRoot(l1Slot, 7, bytes32(uint256(1)), bytes32(uint256(2)), bodyRoot);
        bytes32 signingRoot =
            ClprBeaconSsz.computeSigningRoot(headerRoot, ClprBeaconSsz.computeSyncCommitteeDomain(FORK_VERSION, GVR));
        bytes[] memory header = new bytes[](5);
        header[0] = RLP.encode(uint256(l1Slot));
        header[1] = RLP.encode(uint256(7));
        header[2] = RLP.encode(bytes32(uint256(1)));
        header[3] = RLP.encode(bytes32(uint256(2)));
        header[4] = RLP.encode(bodyRoot);
        bytes memory bits = new bytes(64);
        for (uint256 i = 0; i < signers; i++) {
            bits[i / 8] |= bytes1(uint8(1) << uint8(i % 8));
        }
        bytes memory sig = _aggSig(corruptSignature ? keccak256(abi.encode(signingRoot)) : signingRoot, signers);
        bytes[] memory agg = new bytes[](2);
        agg[0] = RLP.encode(bits);
        agg[1] = RLP.encode(sig);
        bytes[] memory br = new bytes[](9);
        for (uint256 i = 0; i < 9; i++) {
            br[i] = RLP.encode(branch[i]);
        }
        bytes[] memory lc = new bytes[](7);
        lc[0] = RLP.encode(header);
        lc[1] = RLP.encode(agg);
        lc[2] = RLP.encode(l1StateRoot);
        lc[3] = RLP.encode(br);
        lc[4] = RLP.encode(bytes(""));
        lc[5] = RLP.encode(new bytes[](0));
        lc[6] = RLP.encode(new bytes[](0)); // full participation only (no non-signer proofs)
        return RLP.encode(lc);
    }

    function _liveBundle(string memory chain, string memory which) internal view returns (bytes memory) {
        string memory c = string.concat(chain, ".", which);
        return _bundle(
            _lightClient(SYNC_COMMITTEE_SIZE, false),
            vm.parseJsonBytes(json, _s(c, "oracleProof")),
            vm.parseJsonBytes(json, _s(c, "preimage")),
            vm.parseJsonBytes(json, _s(c, "l2AccountProof")),
            vm.parseJsonBytes(json, _s(c, "l2StorageProof"))
        );
    }

    function _run(OpOutputOracleVerifierBase v, string memory chain, string memory which, string memory label)
        internal
        view
    {
        bytes memory proof = _liveBundle(chain, which);
        bytes memory anchor = _anchor(chain);
        bytes memory ctx = _ctx(chain);
        uint256 g = gasleft();
        (ClprTypes.QueueMetadata memory m, bytes[] memory payloads, bytes memory na,,) =
            v.verifyBundle(proof, anchor, ctx);
        console.log(label, g - gasleft(), proof.length);
        // No ClprService on these chains: the L2ToL1MessagePasser stands in, the channel slots are
        // absent → genuine exclusion proofs → zeroed metadata.
        assertEq(m.nextMessageId, 0);
        assertEq(m.sentRunningHash, bytes32(0));
        assertEq(payloads.length, 0);
        assertEq(na.length, 0);
    }

    // ── live, full verifyBundle ─────────────────────────────────────────────

    function test_live_mantle_finalized_fullBundle() public {
        _run(_finalized("mantle"), "mantle", "finalized", "mantle FINALIZED verifyBundle gas / proof bytes:");
    }

    function test_live_katana_finalized_fullBundle() public {
        _run(_finalized("katana"), "katana", "finalized", "katana FINALIZED verifyBundle gas / proof bytes:");
    }

    function test_live_blast_proposed_fullBundle_sevenFieldAccount() public {
        _run(_proposed("blast"), "blast", "newest", "blast PROPOSED verifyBundle gas / proof bytes:");
    }

    function test_live_mantle_proposed_fullBundle() public {
        _run(_proposed("mantle"), "mantle", "newest", "mantle PROPOSED verifyBundle gas / proof bytes:");
    }

    function test_live_blast_finalized_output() public {
        // Blast's finalized output is 7 days old: its L2 proofs are past the public RPC's window, so the
        // L1 half is checked alone (the vitest spec runs a full bundle from a staged refresh).
        OpOutputOracleVerifier v = _finalized("blast");
        OO.Output memory o = v.verifyOutput(
            vm.parseJsonBytes(json, _s("blast", "finalized.oracleProof")),
            l1StateRoot,
            l1Time,
            vm.parseJsonBytes32(json, _s("blast", "finalized.outputRoot"))
        );
        assertEq(o.index, vm.parseJsonUint(json, _s("blast", "finalized.index")));
        assertGt(uint256(l1Time), uint256(o.l1Timestamp) + 7 days);
    }

    // ── live, tier and settlement rejections ────────────────────────────────

    function test_live_finalizedRejectsNewestOutputs_blastAndMantle() public {
        OpOutputOracleVerifier b = _finalized("blast");
        bytes memory bb = _liveBundle("blast", "newest");
        bytes memory ba = _anchor("blast");
        bytes memory bc = _ctx("blast");
        vm.expectPartialRevert(OO.OutputNotFinalized.selector);
        b.verifyBundle(bb, ba, bc);

        OpOutputOracleVerifier m = _finalized("mantle");
        bytes memory mb = _liveBundle("mantle", "newest");
        bytes memory ma = _anchor("mantle");
        bytes memory mc = _ctx("mantle");
        vm.expectPartialRevert(OO.OutputNotFinalized.selector);
        m.verifyBundle(mb, ma, mc);
    }

    function test_live_rejectsUnpostedIndex_allChains() public {
        string[3] memory chains = ["blast", "mantle", "katana"];
        for (uint256 i = 0; i < 3; i++) {
            OpOutputOracleProposedVerifier v = _proposed(chains[i]);
            uint256 len = vm.parseJsonUint(json, _s(chains[i], "length"));
            bytes memory p = vm.parseJsonBytes(json, _s(chains[i], "unpostedOracleProof"));
            bytes32 r = vm.parseJsonBytes32(json, _s(chains[i], "newest.outputRoot"));
            vm.expectRevert(abi.encodeWithSelector(OO.OutputNotPosted.selector, len, len));
            v.verifyOutput(p, l1StateRoot, l1Time, r);
        }
    }

    function test_live_rejectsOutputOfAnotherChain() public {
        // Mantle's oracle proof with Katana's output-root preimage.
        OpOutputOracleVerifier v = _finalized("mantle");
        bytes memory proof = _bundle(
            _lightClient(SYNC_COMMITTEE_SIZE, false),
            vm.parseJsonBytes(json, _s("mantle", "finalized.oracleProof")),
            vm.parseJsonBytes(json, _s("katana", "finalized.preimage")),
            vm.parseJsonBytes(json, _s("katana", "finalized.l2AccountProof")),
            vm.parseJsonBytes(json, _s("katana", "finalized.l2StorageProof"))
        );
        bytes memory a = _anchor("mantle");
        bytes memory c = _ctx("mantle");
        vm.expectPartialRevert(OO.OutputRootMismatch.selector);
        v.verifyBundle(proof, a, c);
    }

    function test_live_rejectsUnpinnedImplementation() public {
        OO.Profile memory p = _profile("katana");
        p.oracleImplCodeHash = keccak256("AggchainFEP v4");
        OpOutputOracleVerifier v = new OpOutputOracleVerifier(l1, genesisTime, 12, p, _format("katana"));
        bytes memory b = _liveBundle("katana", "finalized");
        bytes memory a = _anchor("katana");
        bytes memory c = _ctx("katana");
        vm.expectPartialRevert(OO.OracleImplMismatch.selector);
        v.verifyBundle(b, a, c);
    }

    function test_live_accountFormat_isPerChain() public {
        // Blast's 7-field leaf under an Ethereum-format deployment, and the reverse.
        OpOutputOracleProposedVerifier b =
            new OpOutputOracleProposedVerifier(l1, genesisTime, 12, _profile("blast"), _ethAccount());
        bytes memory bb = _liveBundle("blast", "newest");
        bytes memory ba = _anchor("blast");
        bytes memory bc = _ctx("blast");
        vm.expectRevert(OpOutputOracleVerifierBase.InvalidL2Account.selector);
        b.verifyBundle(bb, ba, bc);

        OpOutputOracleVerifier m = new OpOutputOracleVerifier(l1, genesisTime, 12, _profile("mantle"), _blastAccount());
        bytes memory mb = _liveBundle("mantle", "finalized");
        bytes memory ma = _anchor("mantle");
        bytes memory mc = _ctx("mantle");
        vm.expectRevert(OpOutputOracleVerifierBase.InvalidL2Account.selector);
        m.verifyBundle(mb, ma, mc);
    }

    function test_live_rejectsWrongPinnedL2CodeHash() public {
        OpOutputOracleVerifier v = _finalized("katana");
        bytes memory b = _liveBundle("katana", "finalized");
        bytes memory a = EthBeaconLightClient.encodeTrustAnchor(
            _uncompressedKeys(SYNC_COMMITTEE_SIZE),
            _committeeAggregate(),
            GVR,
            abi.encodePacked(FORK_VERSION),
            _channelId("katana"),
            keccak256("ClprService runtime")
        );
        bytes memory c = _ctx("katana");
        vm.expectRevert(ClprEvmBundleVerifier.CodeHashMismatch.selector);
        v.verifyBundle(b, a, c);
    }

    // ── live, L1 light-client rejections ────────────────────────────────────

    function test_live_rejectsBadSignature() public {
        OpOutputOracleVerifier v = _finalized("mantle");
        string memory c = "mantle.finalized";
        bytes memory proof = _bundle(
            _lightClient(SYNC_COMMITTEE_SIZE, true),
            vm.parseJsonBytes(json, _s(c, "oracleProof")),
            vm.parseJsonBytes(json, _s(c, "preimage")),
            vm.parseJsonBytes(json, _s(c, "l2AccountProof")),
            vm.parseJsonBytes(json, _s(c, "l2StorageProof"))
        );
        bytes memory a = _anchor("mantle");
        bytes memory ctx = _ctx("mantle");
        vm.expectRevert(ClprBeaconBls.BlsSignatureInvalid.selector);
        v.verifyBundle(proof, a, ctx);
    }

    function test_live_rejectsBelowTwoThirds() public {
        OpOutputOracleVerifier v = _finalized("mantle");
        string memory c = "mantle.finalized";
        bytes memory proof = _bundle(
            _lightClient(SUPERMAJORITY - 1, false),
            vm.parseJsonBytes(json, _s(c, "oracleProof")),
            vm.parseJsonBytes(json, _s(c, "preimage")),
            vm.parseJsonBytes(json, _s(c, "l2AccountProof")),
            vm.parseJsonBytes(json, _s(c, "l2StorageProof"))
        );
        bytes memory a = _anchor("mantle");
        bytes memory ctx = _ctx("mantle");
        vm.expectRevert(
            abi.encodeWithSelector(
                EthBeaconLightClient.InsufficientParticipation.selector, SUPERMAJORITY - 1, SYNC_COMMITTEE_SIZE
            )
        );
        v.verifyBundle(proof, a, ctx);
    }

    function test_live_rejectsWrongValidatorSet() public {
        // The anchor names another committee: its aggregate key is 511·G instead of 512·G, so the real
        // signature of the 512 generator keys does not verify under it.
        OpOutputOracleVerifier v = _finalized("katana");
        bytes memory b = _liveBundle("katana", "finalized");
        (bool ok, bytes memory other) =
            BLS12_G1MSM.staticcall(abi.encodePacked(genUncompressed, bytes32(SYNC_COMMITTEE_SIZE - 1)));
        assertTrue(ok);
        bytes memory a = EthBeaconLightClient.encodeTrustAnchor(
            _uncompressedKeys(SYNC_COMMITTEE_SIZE),
            other,
            GVR,
            abi.encodePacked(FORK_VERSION),
            _channelId("katana"),
            vm.parseJsonBytes32(json, _s("katana", "l2CodeHash"))
        );
        bytes memory c = _ctx("katana");
        vm.expectRevert(ClprBeaconBls.BlsSignatureInvalid.selector);
        v.verifyBundle(b, a, c);
    }

    function test_live_rejectsOtherForkVersion() public {
        OpOutputOracleVerifier v = _finalized("katana");
        bytes memory b = _liveBundle("katana", "finalized");
        bytes memory a = _anchor("katana");
        a[EthBeaconLightClient.ANCHOR_OFF_FORK_VERSION + 3] = 0x01;
        bytes memory c = _ctx("katana");
        vm.expectRevert(ClprBeaconBls.BlsSignatureInvalid.selector);
        v.verifyBundle(b, a, c);
    }

    function test_live_l1Clock_isTheBeaconSlot() public view {
        assertEq(uint256(genesisTime) + uint256(l1Slot) * 12, uint256(l1Time));
    }
}
