// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {FuelSyntheticChain} from "./FuelSyntheticChain.sol";
import {MockEthL1StateVerifier} from "./MockEthL1StateVerifier.sol";
import {FuelVerifier} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/FuelVerifier.sol";
import {FuelBlockProof} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/lib/FuelBlockProof.sol";
import {ClprQueueRecordVerifier} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/ClprQueueRecordVerifier.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {IEthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/lib/IEthL1StateVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @dev FuelVerifier against a synthetic Fuel chain (two blocks below the commit), synthetic
///      FuelChainState storage (a real MPT branch with four leaves) and a mock L1 light client.
///      The real Ethereum light client and real Fuel data run in fuel-live.spec.ts.
contract FuelVerifierTest is FuelSyntheticChain {
    function setUp() public {
        _deployFuel();
    }

    // ── Happy paths ──────────────────────────────────────────────────────────

    function test_verifyBundle_provesRecordMessage() public {
        bytes memory proof = _default();
        (
            ClprTypes.QueueMetadata memory m,
            bytes[] memory payloads,
            bytes memory newAnchor,,
            ClprTypes.ClprEndpointManifest memory man
        ) = fuel.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
        _assertDefaultMetadata(m);
        assertEq(payloads.length, 2);
        assertEq(newAnchor.length, 0);
        assertEq(man.version, 0);
    }

    function test_verifyBundle_passesRotationThrough() public {
        bytes memory proof = _default();
        l1.set(l1.stateRoot(), FINAL_SLOT, hex"aabb");
        (,, bytes memory newAnchor, bytes memory newId,) = fuel.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
        assertEq(newAnchor, hex"aabb");
        assertEq(newId, abi.encodePacked(uint64(7)));
    }

    function test_verifyBundle_withManifest() public {
        bytes memory manifest = _manifest(abi.encodePacked(SERVICE));
        FuelChain memory c = _chain(_msg(_record(1, 7, 3, 2, keccak256(manifest))));
        (,,,, ClprTypes.ClprEndpointManifest memory man) =
            fuel.verifyBundle(_bundle(c, _l1(c), FINAL_SLOT, manifest), _anchor(CHANNEL_ID), _ctx());
        assertEq(man.version, 3);
    }

    function test_verifyFuelMessage_returnsMessage() public {
        FuelChain memory c = _chain(_msg(_defaultRecord()));
        bytes[] memory items = new bytes[](8);
        items[0] = RLP.encode(bytes("lc"));
        bytes32[] memory slots = fuel.chainStateSlots(2);
        bytes32[] memory values = new bytes32[](4);
        values[0] = c.commitId;
        values[1] = bytes32(uint256(COMMIT_TS));
        values[3] = bytes32(uint256(uint160(IMPL)));
        (bytes32 storageRoot, bytes memory storageProof) = _storage(slots, values);
        (bytes32 stateRoot, bytes memory accountProof) = _account(storageRoot, CODE_HASH);
        l1.set(stateRoot, FINAL_SLOT, "");
        items[1] = accountProof;
        items[2] = storageProof;
        items[3] = RLP.encode(c.commitHeader);
        items[4] = RLP.encode(c.messageHeader);
        items[5] = c.blockProof;
        items[6] = c.messageProof;
        items[7] = c.message;
        (FuelVerifier.FuelMessage memory m,,) = fuel.verifyFuelMessage(RLP.encode(items), _anchor(CHANNEL_ID));
        assertEq(m.sender, SERVICE);
        assertEq(m.blockHeight, 1);
        assertEq(m.commitHeight, 2);
        assertEq(m.commitTimestamp, COMMIT_TS);
    }

    // ── Negative cases ───────────────────────────────────────────────────────

    function test_revert_otherChannelAnchor() public {
        bytes memory proof = _default();
        vm.expectRevert(FuelVerifier.ChannelMismatch.selector);
        fuel.verifyBundle(proof, _anchor(keccak256("other")), _ctx());
    }

    function test_revert_commitNotFinal() public {
        FuelChain memory c = _chain(_msg(_defaultRecord()));
        bytes memory proof = _bundle(c, _l1(c), (COMMIT_TS + TTF) / 12 - 1, "");
        vm.expectRevert(FuelVerifier.CommitNotFinal.selector);
        fuel.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
    }

    function test_revert_commitMismatch() public {
        FuelChain memory c = _chain(_msg(_defaultRecord()));
        L1Opts memory o = _l1(c);
        o.committedId = keccak256("another committed block");
        bytes memory proof = _bundle(c, o, FINAL_SLOT, "");
        vm.expectRevert(FuelVerifier.CommitMismatch.selector);
        fuel.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
    }

    function test_revert_paused() public {
        FuelChain memory c = _chain(_msg(_defaultRecord()));
        L1Opts memory o = _l1(c);
        o.paused = true;
        bytes memory proof = _bundle(c, o, FINAL_SLOT, "");
        vm.expectRevert(FuelVerifier.ChainStatePaused.selector);
        fuel.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
    }

    function test_revert_upgradedImplementation() public {
        FuelChain memory c = _chain(_msg(_defaultRecord()));
        L1Opts memory o = _l1(c);
        o.impl = address(0x2222);
        bytes memory proof = _bundle(c, o, FINAL_SLOT, "");
        vm.expectRevert(FuelVerifier.ImplementationMismatch.selector);
        fuel.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
    }

    function test_revert_wrongCodeHash() public {
        FuelChain memory c = _chain(_msg(_defaultRecord()));
        L1Opts memory o = _l1(c);
        o.codeHash = keccak256("other code");
        bytes memory proof = _bundle(c, o, FINAL_SLOT, "");
        vm.expectRevert(ClprEvmBundleVerifier.CodeHashMismatch.selector);
        fuel.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
    }

    function test_revert_blockNotInHistory() public {
        FuelChain memory c = _chain(_msg(_defaultRecord()));
        c.blockProof = _merkle(0, new bytes32[](1));
        bytes memory proof = _bundle(c, _l1(c), FINAL_SLOT, "");
        vm.expectRevert(FuelVerifier.BlockNotInHistory.selector);
        fuel.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
    }

    function test_revert_tamperedMessageData() public {
        FuelChain memory c = _chain(_msg(_defaultRecord()));
        FuelChain memory forged = _chain(_msg(_record(1, 99, 3, 2, bytes32(0))));
        c.message = forged.message; // same outbox root, other data
        bytes memory proof = _bundle(c, _l1(c), FINAL_SLOT, "");
        vm.expectRevert(FuelVerifier.MessageNotInBlock.selector);
        fuel.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
    }

    function test_revert_wrongSender() public {
        Msg memory m = _msg(_defaultRecord());
        m.sender = keccak256("another contract");
        FuelChain memory c = _chain(m);
        bytes memory proof = _bundle(c, _l1(c), FINAL_SLOT, "");
        vm.expectRevert(FuelVerifier.InvalidMessage.selector);
        fuel.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
    }

    function test_revert_wrongRecipient() public {
        Msg memory m = _msg(_defaultRecord());
        m.recipient = bytes32(uint256(0xBAD));
        FuelChain memory c = _chain(m);
        bytes memory proof = _bundle(c, _l1(c), FINAL_SLOT, "");
        vm.expectRevert(FuelVerifier.InvalidMessage.selector);
        fuel.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
    }

    function test_revert_nonZeroAmount() public {
        Msg memory m = _msg(_defaultRecord());
        m.amount = 1;
        FuelChain memory c = _chain(m);
        bytes memory proof = _bundle(c, _l1(c), FINAL_SLOT, "");
        vm.expectRevert(FuelVerifier.InvalidMessage.selector);
        fuel.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
    }

    function test_revert_recordForOtherChannel() public {
        Msg memory m = _msg(_defaultRecord());
        m.data = abi.encodePacked(keccak256("other channel"), _defaultRecord());
        FuelChain memory c = _chain(m);
        bytes memory proof = _bundle(c, _l1(c), FINAL_SLOT, "");
        vm.expectRevert(FuelVerifier.InvalidMessage.selector);
        fuel.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
    }

    function test_revert_badRecord() public {
        FuelChain memory c = _chain(_msg(_record(9, 7, 3, 2, bytes32(0))));
        bytes memory proof = _bundle(c, _l1(c), FINAL_SLOT, "");
        vm.expectRevert(ClprQueueRecordVerifier.InvalidQueueRecord.selector);
        fuel.verifyBundle(proof, _anchor(CHANNEL_ID), _ctx());
    }

    // ── verifyConfig ─────────────────────────────────────────────────────────

    function test_verifyConfig() public view {
        bytes memory cfg = abi.encode(
            _anchor(CHANNEL_ID), abi.encodePacked(uint64(5)), _controlMessage("fuel:9889", abi.encodePacked(SERVICE))
        );
        (bytes memory ctx, string memory chainId,,,, bytes memory anchor,, ClprTypes.ClprEndpointManifest memory man) =
            fuel.verifyConfig(cfg, CHANNEL_ID, "");
        assertEq(ctx, _ctx());
        assertEq(chainId, "fuel:9889");
        assertEq(anchor, _anchor(CHANNEL_ID));
        assertEq(man.version, 0);
    }

    function test_revert_config_wrongCodeHash() public {
        bytes memory badAnchor = _anchor(CHANNEL_ID);
        badAnchor[259] = 0x00;
        bytes memory cfg = abi.encode(badAnchor, hex"05", _controlMessage("fuel:9889", abi.encodePacked(SERVICE)));
        vm.expectRevert(FuelVerifier.InvalidTrustAnchor.selector);
        fuel.verifyConfig(cfg, CHANNEL_ID, "");
    }

    function test_revert_config_malformedManifestProof() public {
        bytes memory cfg =
            abi.encode(_anchor(CHANNEL_ID), hex"05", _controlMessage("fuel:9889", abi.encodePacked(SERVICE)));
        vm.expectRevert();
        fuel.verifyConfig(cfg, CHANNEL_ID, hex"01");
    }

    function test_revert_config_namespace() public {
        bytes memory cfg =
            abi.encode(_anchor(CHANNEL_ID), hex"05", _controlMessage("eip155:1", abi.encodePacked(SERVICE)));
        vm.expectRevert(ClprQueueRecordVerifier.WrongChainNamespace.selector);
        fuel.verifyConfig(cfg, CHANNEL_ID, "");
    }

    // ── FuelBlockProof ───────────────────────────────────────────────────────

    function _root(bytes32[] memory leaves, uint256 from, uint256 n) internal pure returns (bytes32) {
        if (n == 1) return FuelBlockProof.leafDigest(leaves[from]);
        uint256 k = 1;
        while (k * 2 < n) k *= 2;
        return FuelBlockProof.nodeDigest(_root(leaves, from, k), _root(leaves, from + k, n - k));
    }

    function _path(bytes32[] memory leaves, uint256 from, uint256 n, uint256 idx, bytes32[] memory acc, uint256 depth)
        internal
        pure
        returns (uint256)
    {
        if (n == 1) return depth;
        uint256 k = 1;
        while (k * 2 < n) k *= 2;
        uint256 d;
        if (idx < k) {
            d = _path(leaves, from, k, idx, acc, depth);
            acc[d] = _root(leaves, from + k, n - k);
        } else {
            d = _path(leaves, from + k, n - k, idx - k, acc, depth);
            acc[d] = _root(leaves, from, k);
        }
        return d + 1;
    }

    function test_binaryMerkle_everyIndexOfOddTrees() public pure {
        for (uint256 n = 1; n <= 9; n++) {
            bytes32[] memory leaves = new bytes32[](n);
            for (uint256 i; i < n; ++i) {
                leaves[i] = keccak256(abi.encode(n, i));
            }
            bytes32 root = _root(leaves, 0, n);
            for (uint256 i; i < n; ++i) {
                bytes32[] memory acc = new bytes32[](8);
                uint256 len = _path(leaves, 0, n, i, acc, 0);
                bytes32[] memory proof = new bytes32[](len);
                for (uint256 j; j < len; ++j) {
                    proof[j] = acc[j];
                }
                assertTrue(FuelBlockProof.verifyInclusion(root, leaves[i], i, n, proof));
                if (n > 1) assertFalse(FuelBlockProof.verifyInclusion(root, leaves[(i + 1) % n], i, n, proof));
            }
        }
    }
}
