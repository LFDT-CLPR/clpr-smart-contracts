// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {AvalancheWarpVerifier} from "@hiero-ledger/clpr/verifiers/evm/avalanche/AvalancheWarpVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @dev Real Fuji vectors (test/e2e/fixtures/avalanche-live/vectors.json, written by
///      `npm run avalanche-live:refresh`): a C-Chain header, the Primary Network canonical set at two
///      P-Chain heights (a real set change), the validators' Warp signature over the block hash and
///      WAVAX's account + channel-slot exclusion proofs. verifyConfig bootstraps from the live set;
///      verifyBundle and a real rotation then run unmodified.
contract AvalancheWarpLiveTest is Test {
    AvalancheWarpVerifier internal verifier;
    string internal j;

    function setUp() public {
        verifier = new AvalancheWarpVerifier();
        j = vm.readFile(_vectorsPath());
    }

    /// Overridden by the Flare / Coston2 replays (FlareWarpLive.t.sol), which run every test below.
    function _vectorsPath() internal pure virtual returns (string memory) {
        return "test/e2e/fixtures/avalanche-live/vectors.json";
    }

    function _b(string memory key) internal view returns (bytes memory) {
        return vm.parseJsonBytes(j, key);
    }

    function _u(string memory key) internal view returns (uint256) {
        return vm.parseUint(vm.parseJsonString(j, key));
    }

    function _ledger(bytes memory serviceAddress) internal view returns (bytes memory) {
        return ClprProtobuf.encodeControlMessage(
            ClprTypes.LedgerConfiguration({
                protocolVersion: 1,
                chainId: string.concat("eip155:", vm.toString(vm.parseJsonUint(j, ".evmChainId"))),
                serviceAddress: serviceAddress,
                nanosSinceEpoch: 1_790_000_000 * 1e9,
                throttles: ClprTypes.Throttles({
                    maxMessagesPerBundle: 100,
                    maxMessagePayloadBytes: 10_000,
                    maxGasPerMessage: 1_000_000,
                    maxQueueDepth: 1000,
                    maxSyncBytes: 1_000_000,
                    maxLocalEndpoints: 8,
                    maxPeerEndpoints: 8
                }),
                trustAnchor: "",
                trustAnchorId: ""
            })
        );
    }

    function _config(bool previous) internal view returns (bytes memory) {
        address[] memory att = vm.parseJsonAddressArray(j, ".attestors");
        bytes[] memory a = new bytes[](att.length);
        for (uint256 i = 0; i < att.length; i++) {
            a[i] = RLP.encode(att[i]);
        }
        bytes[] memory c = new bytes[](12);
        c[0] = RLP.encode(_ledger(_b(".serviceAddress")));
        c[1] = RLP.encode(vm.parseJsonUint(j, ".evmChainId"));
        c[2] = RLP.encode(vm.parseJsonUint(j, ".networkId"));
        c[3] = RLP.encode(vm.parseJsonBytes32(j, ".sourceChainId"));
        c[4] = RLP.encode(_u(previous ? ".previousPChainHeight" : ".pChainHeight"));
        c[5] = RLP.encode(_u(previous ? ".previousPChainTimestamp" : ".pChainTimestamp"));
        c[6] = RLP.encode(_b(previous ? ".previousValidatorSet" : ".validatorSet"));
        c[7] = RLP.encode(_u(previous ? ".previousTotalWeight" : ".totalWeight"));
        c[8] = RLP.encode(_u(".maxSetAge"));
        c[9] = RLP.encode(_u(".attestorThreshold"));
        c[10] = RLP.encode(a);
        c[11] = RLP.encode(vm.parseJsonBytes32(j, ".codeHash"));
        return RLP.encode(c);
    }

    /// verifyConfig over the live P-Chain set yields exactly the anchor the relay builder computed.
    function test_live_verifyConfig_bootstrapsFromLiveSet() public view {
        bytes32 channelId = vm.parseJsonBytes32(j, ".channelId");
        (bytes memory ctx,,,,, bytes memory anchor, bytes memory id,) =
            verifier.verifyConfig(_config(false), channelId, "");
        assertEq(anchor, _b(".trustAnchor"));
        assertEq(ctx, _b(".channelContext"));
        assertEq(id, abi.encodePacked(uint64(_u(".pChainHeight"))));
        (,,,,, anchor,,) = verifier.verifyConfig(_config(true), channelId, "");
        assertEq(anchor, _b(".previousTrustAnchor"));
    }

    /// Execution gas of the verifier call alone (calldata pre-built, so the test's own memory is not counted).
    function _gas(bytes memory proof, bytes memory anchor) internal view returns (uint256 used, bytes memory ret) {
        bytes memory data = abi.encodeCall(AvalancheWarpVerifier.verifyBundle, (proof, anchor, _b(".channelContext")));
        address target = address(verifier);
        uint256 g = gasleft();
        bool ok;
        (ok, ret) = target.staticcall(data);
        used = g - gasleft();
        require(ok, "verifyBundle reverted");
    }

    function test_live_verifyBundle() public view {
        bytes memory proof = _b(".proofBytes");
        (ClprTypes.QueueMetadata memory m,, bytes memory a,,) =
            verifier.verifyBundle(proof, _b(".trustAnchor"), _b(".channelContext"));
        assertEq(m.nextMessageId, 0);
        assertEq(a.length, 0);
        (uint256 used,) = _gas(proof, _b(".trustAnchor"));
        console.log(string.concat("live ", vm.parseJsonString(j, ".network"), " verifyBundle execution gas"), used);
        console.log("  proofBytes", proof.length);
    }

    function test_live_rotation() public view {
        bytes memory proof = _b(".rotationProofBytes");
        (,, bytes memory a, bytes memory id,) =
            verifier.verifyBundle(proof, _b(".previousTrustAnchor"), _b(".channelContext"));
        assertEq(a, _b(".trustAnchor"));
        assertEq(id, abi.encodePacked(uint64(_u(".pChainHeight"))));
        (uint256 used,) = _gas(proof, _b(".previousTrustAnchor"));
        console.log(string.concat("live ", vm.parseJsonString(j, ".network"), " rotation bundle execution gas"), used);
        console.log("  proofBytes", proof.length);
    }

    /// The live aggregate signature is checked bit-exactly: one flipped bit fails the pairing.
    function test_live_rejectsFlippedSignatureBit() public {
        bytes memory proof = _b(".proofBytes");
        bytes memory sig = _b(".signature");
        // Locate the 256-byte signature inside the bundle and flip its last byte.
        uint256 at = _find(proof, sig);
        proof[at + 255] = bytes1(uint8(proof[at + 255]) ^ 1);
        bytes memory anchor = _b(".trustAnchor");
        bytes memory ctx = _b(".channelContext");
        vm.expectRevert();
        verifier.verifyBundle(proof, anchor, ctx);
    }

    function test_live_rejectsSignatureUnderPreviousSet() public {
        // Rebuild the no-rotation bundle carrying the previous set against the previous anchor
        // (maxSetAge widened so only the signature check can fail).
        bytes memory proof = _b(".proofBytes");
        bytes memory cur = _b(".validatorSet");
        bytes memory prev = _b(".previousValidatorSet");
        bytes memory swapped = _replace(proof, cur, prev);
        bytes memory anchor = _b(".previousTrustAnchor");
        for (uint256 i = 180; i < 188; i++) {
            anchor[i] = 0xff;
        }
        anchor[180] = 0x00; // maxSetAge ≈ 2^56 s, no overflow when added to the timestamp
        bytes memory ctx = _b(".channelContext");
        if (_sameKeys(cur, prev)) {
            // Weight-only change (Flare's set changes with every delegation): the bit set still names
            // the same keys, so the real signature stays valid under the previous weights as long as
            // the signers held ≥67% there too. Accepting it is correct, and the check below proves it.
            verifier.verifyBundle(swapped, anchor, ctx);
            return;
        }
        vm.expectRevert();
        verifier.verifyBundle(swapped, anchor, ctx);
    }

    /// Same keys in the same order (only weights differ). Entries are x48 ‖ y48 ‖ weight8.
    function _sameKeys(bytes memory a, bytes memory b) internal pure returns (bool) {
        if (a.length != b.length) return false;
        for (uint256 i = 0; i < a.length; i++) {
            if (i % 104 < 96 && a[i] != b[i]) return false;
        }
        return true;
    }

    function _find(bytes memory hay, bytes memory needle) internal pure returns (uint256) {
        bytes32 h = keccak256(needle);
        for (uint256 i = 0; i + needle.length <= hay.length; i++) {
            if (hay[i] != needle[0]) continue;
            bytes memory w = new bytes(needle.length);
            for (uint256 k = 0; k < needle.length; k++) {
                w[k] = hay[i + k];
            }
            if (keccak256(w) == h) return i;
        }
        revert("needle not found");
    }

    /// Swap the validator-set item (index 2, currently `a`) of an RLP bundle for `b`.
    function _replace(bytes memory proof, bytes memory a, bytes memory b) internal pure returns (bytes memory) {
        bytes[] memory items = LiveRlp.split(proof);
        require(keccak256(_inner(items[2])) == keccak256(a), "item 2 is not the validator set");
        items[2] = RLP.encode(b);
        return RLP.encode(items);
    }

    function _inner(bytes memory item) internal pure returns (bytes memory) {
        return RLP.decodeBytes(item);
    }
}

library LiveRlp {
    function split(bytes memory list) internal pure returns (bytes[] memory items) {
        Memory.Slice[] memory s = RLP.decodeList(list);
        items = new bytes[](s.length);
        for (uint256 i = 0; i < s.length; i++) {
            items[i] = Memory.toBytes(s[i]);
        }
    }
}
