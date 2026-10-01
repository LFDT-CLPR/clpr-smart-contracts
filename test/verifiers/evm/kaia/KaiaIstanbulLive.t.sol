// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {KaiaIstanbulVerifier} from "@hiero-ledger/clpr/verifiers/evm/kaia/KaiaIstanbulVerifier.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";

/// @dev KaiaIstanbulVerifier on REAL chain data recorded by
///      `npx tsx test/e2e/relay/buildKaiaLiveProof.ts --refresh` into test/e2e/fixtures/kaia-live/.
///      Kaia mainnet: verifyConfig on the last header before a real qualified-set change (30 → 31
///      validators), a bundle on the first header of the new set (rotation, vouched by the old set's
///      committed seals) and a recent header under the rotated anchor. Kairos: verifyConfig ~10 000
///      blocks back and a recent header (same 4-validator set). The bundles prove the AddressBook
///      system contract (0x…0400) with its code hash pinned; the channelId-derived slots are empty,
///      so the storage step checks real exclusion proofs.
contract KaiaIstanbulLiveTest is Test {
    struct Vectors {
        uint64 chainId;
        bytes configProof;
        bytes trustAnchor;
        bytes rotatedAnchor;
        bytes rotationProof;
        bytes plainAnchor;
        bytes plainProof;
        bytes channelContext;
        bytes32 channelId;
        uint64 rotationBlock;
    }

    function _load(string memory network) internal view returns (Vectors memory v) {
        string memory json = vm.readFile(string.concat("test/e2e/fixtures/kaia-live/", network, "-vectors.json"));
        v.chainId = uint64(vm.parseJsonUint(json, ".chainId"));
        v.configProof = vm.parseJsonBytes(json, ".configProof");
        v.trustAnchor = vm.parseJsonBytes(json, ".trustAnchor");
        v.rotatedAnchor = vm.parseJsonBytes(json, ".rotatedAnchor");
        v.rotationProof = vm.parseJsonBytes(json, ".rotationProof");
        v.plainAnchor = vm.parseJsonBytes(json, ".plainAnchor");
        v.plainProof = vm.parseJsonBytes(json, ".plainProof");
        v.channelContext = vm.parseJsonBytes(json, ".channelContext");
        v.channelId = vm.parseJsonBytes32(json, ".channelId");
        v.rotationBlock = uint64(vm.parseJsonUint(json, ".rotationBlock"));
    }

    function _config(KaiaIstanbulVerifier verifier, Vectors memory v, string memory caip2) internal view {
        (bytes memory ctx, string memory chainId,,,, bytes memory anchor,,) =
            verifier.verifyConfig(v.configProof, v.channelId, "");
        assertEq(chainId, caip2);
        assertEq(anchor, v.trustAnchor, "verifyConfig anchor");
        assertEq(ctx, v.channelContext);
    }

    function test_live_kaiaMainnet_rotationAndState() public {
        Vectors memory v = _load("kaia-mainnet");
        KaiaIstanbulVerifier verifier = new KaiaIstanbulVerifier(8217);
        _config(verifier, v, "eip155:8217");

        uint256 g = gasleft();
        (ClprTypes.QueueMetadata memory m, bytes[] memory msgs, bytes memory newAnchor, bytes memory newId,) =
            verifier.verifyBundle(v.rotationProof, v.trustAnchor, v.channelContext);
        uint256 rotGas = g - gasleft();
        assertEq(newAnchor, v.rotatedAnchor, "rotated anchor");
        assertEq(newId, abi.encodePacked(v.rotationBlock));
        assertEq(m.nextMessageId, 0);
        assertEq(msgs.length, 0);

        g = gasleft();
        (,, newAnchor,,) = verifier.verifyBundle(v.plainProof, v.plainAnchor, v.channelContext);
        uint256 plainGas = g - gasleft();
        assertEq(newAnchor.length, 0);

        console.log("[kaia-live] mainnet verifyBundle with rotation (execution gas):", rotGas);
        console.log("[kaia-live] mainnet verifyBundle without rotation (execution gas):", plainGas);
        console.log("[kaia-live] mainnet proof bytes (rotation / plain):", v.rotationProof.length, v.plainProof.length);
    }

    function test_live_kairos() public {
        Vectors memory v = _load("kairos");
        KaiaIstanbulVerifier verifier = new KaiaIstanbulVerifier(1001);
        _config(verifier, v, "eip155:1001");
        assertEq(v.plainAnchor, v.trustAnchor, "no set change on Kairos in the window");
        uint256 g = gasleft();
        (,, bytes memory newAnchor,,) = verifier.verifyBundle(v.plainProof, v.plainAnchor, v.channelContext);
        console.log("[kaia-live] kairos verifyBundle (execution gas):", g - gasleft());
        assertEq(newAnchor.length, 0);
    }

    // ── Negative cases on real data ───────────────────────────────────────────

    function test_live_revertWhen_stateUnderPreRotationAnchor() public {
        // The recent header's set is the rotated-in one: under the old anchor it must be vouched for
        // by f+1 old members, which the anchor's validator bytes (old set) do not match.
        Vectors memory v = _load("kaia-mainnet");
        KaiaIstanbulVerifier verifier = new KaiaIstanbulVerifier(8217);
        vm.expectRevert(KaiaIstanbulVerifier.ValidatorSetMismatch.selector);
        verifier.verifyBundle(v.plainProof, v.trustAnchor, v.channelContext);
    }

    function test_live_revertWhen_rotationReplayedAfterNewerAnchor() public {
        Vectors memory v = _load("kaia-mainnet");
        KaiaIstanbulVerifier verifier = new KaiaIstanbulVerifier(8217);
        vm.expectRevert(KaiaIstanbulVerifier.ValidatorSetMismatch.selector);
        verifier.verifyBundle(v.rotationProof, v.rotatedAnchor, v.channelContext);
    }

    function test_live_revertWhen_headerOlderThanAnchor() public {
        Vectors memory v = _load("kairos");
        KaiaIstanbulVerifier verifier = new KaiaIstanbulVerifier(1001);
        bytes memory anchor = v.plainAnchor;
        anchor[64] = 0x7f; // setBlock far in the future
        vm.expectPartialRevert(KaiaIstanbulVerifier.HeaderOutOfOrder.selector);
        verifier.verifyBundle(v.plainProof, anchor, v.channelContext);
    }

    function test_live_revertWhen_codeHashNotPinned() public {
        Vectors memory v = _load("kaia-mainnet");
        KaiaIstanbulVerifier verifier = new KaiaIstanbulVerifier(8217);
        bytes memory anchor = v.plainAnchor;
        anchor[31] ^= 0x01;
        vm.expectRevert(ClprEvmBundleVerifier.CodeHashMismatch.selector);
        verifier.verifyBundle(v.plainProof, anchor, v.channelContext);
    }

    function test_live_revertWhen_kairosProofUnderMainnetAnchor() public {
        Vectors memory k = _load("kairos");
        Vectors memory m = _load("kaia-mainnet");
        KaiaIstanbulVerifier verifier = new KaiaIstanbulVerifier(8217);
        vm.expectRevert(KaiaIstanbulVerifier.ValidatorSetMismatch.selector);
        verifier.verifyBundle(k.plainProof, m.plainAnchor, k.channelContext);
    }

    function test_live_revertWhen_configOnOtherNetworkVerifier() public {
        Vectors memory v = _load("kairos");
        KaiaIstanbulVerifier verifier = new KaiaIstanbulVerifier(8217);
        vm.expectRevert(KaiaIstanbulVerifier.ChainIdMismatch.selector);
        verifier.verifyConfig(v.configProof, v.channelId, "");
    }
}
