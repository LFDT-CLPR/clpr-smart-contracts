// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {OpStackVerifier} from "@hiero-ledger/clpr/verifiers/evm/opstack/OpStackVerifier.sol";
import {OpStackProposedVerifier} from "@hiero-ledger/clpr/verifiers/evm/opstack/OpStackProposedVerifier.sol";
import {XLayerProfile} from "@hiero-ledger/clpr/verifiers/evm/opstack/profiles/XLayerProfile.sol";
import {EthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/EthL1StateVerifier.sol";
import {ClprBeaconSsz} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconSsz.sol";
import {OpStackOutputRootProof as OP} from "@hiero-ledger/clpr/libraries/proof/opstack/OpStackOutputRootProof.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";

/// @notice The X Layer profile against REAL Ethereum-mainnet data: the mainnet sync committee's signature,
///         X Layer's AnchorStateRegistry / DisputeGameFactory / OP Succinct Lite games at the attested L1
///         block, and the X Layer headers the games claim. Inputs: `fixtures/xlayer-live.json`, written by
///         `npm run opstack-live:refresh:xlayer` from test/e2e/fixtures/xlayer-live/capture.json (the
///         vitest spec opstack-live-xlayer.spec.ts replays the same capture on anvil).
contract OpStackXLayerLiveTest is Test {
    string internal json;
    EthL1StateVerifier internal l1;
    OpStackVerifier internal finalized;
    OpStackProposedVerifier internal proposed;
    bytes internal anchor;
    uint64 internal genesisTime;

    function setUp() public {
        json = vm.readFile(string.concat(vm.projectRoot(), "/test/verifiers/evm/opstack/fixtures/xlayer-live.json"));
        l1 = new EthL1StateVerifier(
            ClprBeaconSsz.GINDEX_EXECUTION_STATE_ROOT_IN_BODY,
            9,
            ClprBeaconSsz.GINDEX_NEXT_SYNC_COMMITTEE_IN_STATE,
            6,
            8192
        );
        genesisTime = uint64(vm.parseJsonUint(json, ".l1GenesisTime"));
        // Deployed from the PINNED profile, never from captured values.
        finalized = new OpStackVerifier(l1, genesisTime, 12, XLayerProfile.profile());
        proposed = new OpStackProposedVerifier(l1, genesisTime, 12, XLayerProfile.profile());
        anchor = vm.parseJsonBytes(json, ".trustAnchor");
    }

    function _proof(string memory key) internal view returns (bytes memory) {
        return vm.parseJsonBytes(json, string.concat(".", key, ".proof"));
    }

    function _root(string memory key) internal view returns (bytes32) {
        return vm.parseJsonBytes32(json, string.concat(".", key, ".l2StateRoot"));
    }

    function test_profileMatchesLiveChain() public view {
        OP.Profile memory p = XLayerProfile.profile();
        assertEq(p.l2ChainId, vm.parseJsonUint(json, ".profile.l2ChainId"));
        assertEq(p.anchorStateRegistry, vm.parseJsonAddress(json, ".profile.anchorStateRegistry"));
        assertEq(
            p.anchorStateRegistryImplCodeHash, vm.parseJsonBytes32(json, ".profile.anchorStateRegistryImplCodeHash")
        );
        assertEq(p.disputeGameFinalityDelaySeconds, vm.parseJsonUint(json, ".profile.disputeGameFinalityDelaySeconds"));
        assertEq(p.gameImplementation, vm.parseJsonAddress(json, ".profile.gameImplementation"));
        assertEq(uint256(XLayerProfile.GAME_TYPE), vm.parseJsonUint(json, ".profile.respectedGameType"));
        assertEq(uint8(finalized.FINALITY()), 0);
        assertEq(finalized.L2_CHAIN_ID(), 196);
    }

    function test_finalized_anchorMode() public {
        (bytes32 root,,) = finalized.verifyL2StateRoot(_proof("anchorMode"), anchor);
        assertEq(root, _root("anchorMode"));
    }

    function test_finalized_gameMode() public {
        (bytes32 root,,) = finalized.verifyL2StateRoot(_proof("anchorGame"), anchor);
        assertEq(root, _root("anchorGame"));
    }

    function test_finalized_rejectsResolvedInsideDelay() public {
        bytes memory proof = _proof("resolved");
        vm.expectRevert(
            abi.encodeWithSelector(
                OP.GameNotFinalized.selector,
                vm.parseJsonAddress(json, ".resolved.game"),
                uint64(vm.parseJsonUint(json, ".resolved.resolvedAt")),
                uint64(vm.parseJsonUint(json, ".l1Time")),
                uint256(302_400)
            )
        );
        finalized.verifyL2StateRoot(proof, anchor);
        (bytes32 root,,) = proposed.verifyL2StateRoot(proof, anchor);
        assertEq(root, _root("resolved"));
    }

    function test_finalized_rejectsInProgress() public {
        bytes memory proof = _proof("newest");
        vm.expectRevert(
            abi.encodeWithSelector(OP.GameNotResolved.selector, vm.parseJsonAddress(json, ".newest.game"), uint8(0))
        );
        finalized.verifyL2StateRoot(proof, anchor);
        (bytes32 root,,) = proposed.verifyL2StateRoot(proof, anchor);
        assertEq(root, _root("newest"));
    }

    function test_proposed_fullBundle() public {
        bytes memory bundle = vm.parseJsonBytes(json, ".proposedBundle");
        vm.skip(bundle.length == 0); // needs an L2 proof staged with `npm run opstack-live:stage:xlayer`
        bytes memory ctx = vm.parseJsonBytes(json, ".channelContext");
        (ClprTypes.QueueMetadata memory m,,,,) = proposed.verifyBundle(bundle, anchor, ctx);
        assertEq(m.nextMessageId, 0);
        vm.expectRevert();
        finalized.verifyBundle(bundle, anchor, ctx);
    }

    function test_finalized_fullBundle() public {
        bytes memory bundle = vm.parseJsonBytes(json, ".finalizedBundle");
        vm.skip(bundle.length == 0); // needs a staged game that has finalized (≥ 3.6 days later)
        (ClprTypes.QueueMetadata memory m,,,,) =
            finalized.verifyBundle(bundle, anchor, vm.parseJsonBytes(json, ".channelContext"));
        assertEq(m.nextMessageId, 0);
    }

    function test_rejectsTamperedSignature() public {
        bytes memory proof = _proof("anchorGame");
        bytes memory bad = bytes.concat(anchor);
        bad[32] = 0x05; // Electra fork version: the real signature no longer verifies
        vm.expectRevert();
        finalized.verifyL2StateRoot(proof, bad);
    }
}
