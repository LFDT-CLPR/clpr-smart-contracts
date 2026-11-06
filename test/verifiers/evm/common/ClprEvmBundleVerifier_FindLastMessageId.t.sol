// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {SeiCometBftVerifierHarness} from "@test/helpers/SeiCometBftVerifierHarness.sol";

/// @notice `_findLastMessageId` over the sender's unacked window [acked + count, next - 1].
contract ClprEvmBundleVerifier_FindLastMessageIdTest is Test {
    bytes32 internal constant CID = bytes32(uint256(0xC1));
    SeiCometBftVerifierHarness internal harness;

    function setUp() public {
        harness = new SeiCometBftVerifierHarness(true);
    }

    function _slot(uint64 id) internal view returns (bytes32) {
        return harness.lastMessageRunningHashSlot(CID, id);
    }

    /// @dev A bundle starting at acked + 1 ends at acked + count: the first probe.
    function test_bundleFromAcked_hitsFirstProbe() public view {
        assertEq(harness.findLastMessageId(CID, _slot(8), 5, 20, 3), 8);
    }

    /// @dev A bundle starting past acked + 1 (the receiver has received more than the sender has
    ///      seen acked) ends further into the window.
    function test_bundlePastAcked_found() public view {
        assertEq(harness.findLastMessageId(CID, _slot(14), 5, 20, 3), 14);
    }

    function test_latestMessage_found() public view {
        assertEq(harness.findLastMessageId(CID, _slot(19), 5, 20, 3), 19);
    }

    function test_bundleStartingAtAcked_reverts() public {
        bytes32 slot = _slot(7);
        vm.expectRevert(ClprEvmBundleVerifier.LastMessageSlotNotFound.selector);
        harness.findLastMessageId(CID, slot, 5, 20, 3);
    }

    function test_slotAtNext_reverts() public {
        bytes32 slot = _slot(20);
        vm.expectRevert(ClprEvmBundleVerifier.LastMessageSlotNotFound.selector);
        harness.findLastMessageId(CID, slot, 5, 20, 3);
    }

    function test_otherChannelSlot_reverts() public {
        bytes32 foreign = harness.lastMessageRunningHashSlot(bytes32(uint256(0xC2)), 8);
        vm.expectRevert(ClprEvmBundleVerifier.LastMessageSlotNotFound.selector);
        harness.findLastMessageId(CID, foreign, 5, 20, 3);
    }
}
