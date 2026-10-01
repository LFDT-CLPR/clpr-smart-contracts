// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Ed25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/Ed25519Verifier.sol";
import {ClprEd25519SignatureCache} from "@hiero-ledger/clpr/verifiers/evm/neartons/ClprEd25519SignatureCache.sol";
import {ClprEd25519Check} from "@hiero-ledger/clpr/verifiers/evm/neartons/ClprEd25519Check.sol";
import {NearVerifier} from "@hiero-ledger/clpr/verifiers/evm/neartons/NearVerifier.sol";
import {NearLightClient} from "@hiero-ledger/clpr/libraries/proof/near/NearLightClient.sol";

/// @notice NearVerifier against real NEAR mainnet and testnet data
///         (test/e2e/fixtures/near-live, re-record with `npm run neartons-live:refresh`).
contract NearLiveTest is Test {
    Ed25519Verifier internal ed;
    ClprEd25519SignatureCache internal cache;

    function setUp() public {
        ed = new Ed25519Verifier();
        cache = new ClprEd25519SignatureCache(ed);
    }

    function _load(string memory net) internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/e2e/fixtures/near-live/", net, ".json"));
    }

    function _verifier(string memory j) internal returns (NearVerifier) {
        bytes32[] memory cp = vm.parseJsonBytes32Array(j, ".derived.checkpointPrev");
        return new NearVerifier(
            vm.parseJsonString(j, ".derived.chainId"), NearLightClient.EpochState(cp[0], cp[1], cp[2], cp[3]), ed, cache
        );
    }

    function _record(string memory j) internal {
        bytes memory message = vm.parseJsonBytes(j, ".derived.message");
        bytes32[] memory keys = vm.parseJsonBytes32Array(j, ".derived.signerKeys");
        bytes[] memory sigs = vm.parseJsonBytesArray(j, ".derived.signerSignatures");
        // ~20 signatures per Hedera transaction
        for (uint256 start = 0; start < keys.length; start += 20) {
            uint256 n = keys.length - start < 20 ? keys.length - start : 20;
            bytes32[] memory k = new bytes32[](n);
            bytes memory s;
            for (uint256 i = 0; i < n; i++) {
                k[i] = keys[start + i];
                s = bytes.concat(s, sigs[start + i]);
            }
            uint256 g = gasleft();
            cache.record(message, k, s);
            emit log_named_uint("cache.record gas", g - gasleft());
        }
    }

    function _checkNet(string memory net, bool inlineSigs) internal {
        string memory j = _load(net);
        NearVerifier v = _verifier(j);
        bytes memory anchorPrev = vm.parseJsonBytes(j, ".derived.anchorPrev");
        bytes memory anchorCur = vm.parseJsonBytes(j, ".derived.anchorCur");
        bytes memory proof;
        if (inlineSigs) {
            proof = vm.parseJsonBytes(j, ".derived.stateProof");
        } else {
            _record(j);
            proof = vm.parseJsonBytes(j, ".derived.stateProofCached");
        }

        uint256 g = gasleft();
        (bytes memory value, bytes32 h,, bytes memory na) = v.verifyStateValue(proof, anchorCur);
        emit log_named_uint(string.concat(net, " verifyStateValue gas"), g - gasleft());
        assertEq(value, vm.parseJsonBytes(j, ".derived.value"));
        assertEq(h, vm.parseJsonBytes32(j, ".derived.lcHash"));
        assertEq(na.length, 0);

        g = gasleft();
        (,,, na) = v.verifyStateValue(proof, anchorPrev);
        emit log_named_uint(string.concat(net, " verifyStateValue + epoch rotation gas"), g - gasleft());
        assertEq(na, anchorCur);
    }

    function test_testnet_inline() public {
        _checkNet("testnet", true);
    }

    function test_mainnet_cached() public {
        _checkNet("mainnet", false);
    }

    function test_mainnet_inline_measure() public {
        _checkNet("mainnet", true);
    }

    function test_rejects_uncached_empty_signature() public {
        string memory j = _load("mainnet");
        NearVerifier v = _verifier(j);
        bytes memory proof = vm.parseJsonBytes(j, ".derived.stateProofCached");
        bytes memory anchorCur = vm.parseJsonBytes(j, ".derived.anchorCur");
        vm.expectPartialRevert(ClprEd25519Check.SignatureNotCached.selector);
        v.verifyStateValue(proof, anchorCur);
    }
}
