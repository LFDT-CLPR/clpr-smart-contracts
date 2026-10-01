// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Ed25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/Ed25519Verifier.sol";
import {ClprEd25519SignatureCache} from "@hiero-ledger/clpr/verifiers/evm/neartons/ClprEd25519SignatureCache.sol";
import {ClprEd25519Check} from "@hiero-ledger/clpr/verifiers/evm/neartons/ClprEd25519Check.sol";
import {TonVerifier} from "@hiero-ledger/clpr/verifiers/evm/neartons/TonVerifier.sol";

/// @notice TonVerifier against real TON mainnet and testnet data (Simplex finalize certificates,
///         a real key-block rotation, a basechain account proof). Fixtures: test/e2e/fixtures/ton-live.
contract TonLiveTest is Test {
    Ed25519Verifier internal ed;
    ClprEd25519SignatureCache internal cache;

    struct Batch {
        bytes32[] keys;
        bytes message;
        bytes[] sigs;
    }

    function setUp() public {
        ed = new Ed25519Verifier();
        cache = new ClprEd25519SignatureCache(ed);
    }

    function _load(string memory net) internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/e2e/fixtures/ton-live/", net, ".json"));
    }

    function _verifier(string memory j) internal returns (TonVerifier) {
        bytes memory a = vm.parseJsonBytes(j, ".derived.anchorPrev");
        return new TonVerifier(vm.parseJsonString(j, ".derived.chainId"), uint32(bytes4(a)), bytes32(0), ed, cache);
    }

    function _record(string memory j) internal {
        uint256 n =
            vm.parseJsonUint(j, ".derived.meta.signersK") / 20 + vm.parseJsonUint(j, ".derived.meta.signersL") / 20 + 2;
        for (uint256 i = 0; i < n; i++) {
            string memory k = string.concat(".derived.cacheBatches[", vm.toString(i), "]");
            if (!vm.keyExistsJson(j, k)) break;
            bytes32[] memory keys = vm.parseJsonBytes32Array(j, string.concat(k, ".keys"));
            bytes[] memory sigs = vm.parseJsonBytesArray(j, string.concat(k, ".sigs"));
            bytes memory s;
            for (uint256 x = 0; x < sigs.length; x++) {
                s = bytes.concat(s, sigs[x]);
            }
            uint256 g = gasleft();
            cache.record(vm.parseJsonBytes(j, string.concat(k, ".message")), keys, s);
            emit log_named_uint("cache.record gas", g - gasleft());
        }
    }

    function _run(string memory net, bool inlineSigs) internal {
        string memory j = _load(net);
        TonVerifier v = _verifier(j);
        if (!inlineSigs) _record(j);
        string memory sfx = inlineSigs ? "" : "Cached";
        bytes memory kb = vm.parseJsonBytes(j, string.concat(".derived.keyBlocks", sfx));
        bytes memory blk = vm.parseJsonBytes(j, string.concat(".derived.block", sfx));
        bytes memory st = vm.parseJsonBytes(j, ".derived.stateChain");
        bytes memory svc = vm.parseJsonBytes(j, ".derived.serviceAddress");

        uint256 g = gasleft();
        (bytes32 dh, uint32 seq, bytes memory na) = v.verifyAccountData(
            vm.parseJsonBytes(j, ".derived.validatorsCur"), "", blk, st, svc, vm.parseJsonBytes(j, ".derived.anchorCur")
        );
        emit log_named_uint(string.concat(net, " block + account proof gas"), g - gasleft());
        assertEq(dh, vm.parseJsonBytes32(j, ".derived.dataHash"));
        assertEq(seq, vm.parseJsonUint(j, ".derived.seqno"));
        assertEq(na.length, 0);

        g = gasleft();
        (dh,, na) = v.verifyAccountData(
            vm.parseJsonBytes(j, ".derived.validatorsPrev"),
            kb,
            blk,
            st,
            svc,
            vm.parseJsonBytes(j, ".derived.anchorPrev")
        );
        emit log_named_uint(string.concat(net, " key-block rotation + block + account proof gas"), g - gasleft());
        assertEq(na, vm.parseJsonBytes(j, ".derived.anchorCur"));
        assertEq(dh, vm.parseJsonBytes32(j, ".derived.dataHash"));
    }

    function test_testnet_inline() public {
        _run("testnet", true);
    }

    function test_mainnet_cached() public {
        _run("mainnet", false);
    }

    function test_mainnet_uncached_reverts() public {
        string memory j = _load("mainnet");
        TonVerifier v = _verifier(j);
        vm.expectPartialRevert(ClprEd25519Check.SignatureNotCached.selector);
        v.verifyAccountData(
            vm.parseJsonBytes(j, ".derived.validatorsCur"),
            "",
            vm.parseJsonBytes(j, ".derived.blockCached"),
            vm.parseJsonBytes(j, ".derived.stateChain"),
            vm.parseJsonBytes(j, ".derived.serviceAddress"),
            vm.parseJsonBytes(j, ".derived.anchorCur")
        );
    }
}
