// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Ed25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/Ed25519Verifier.sol";
import {ClprEd25519SignatureCache} from "@hiero-ledger/clpr/verifiers/evm/neartons/ClprEd25519SignatureCache.sol";
import {AuroraVerifier} from "@hiero-ledger/clpr/verifiers/evm/neartons/AuroraVerifier.sol";
import {NearLightClient} from "@hiero-ledger/clpr/libraries/proof/near/NearLightClient.sol";

/// @notice AuroraVerifier against real data: a NEAR mainnet light-client block and the EVM storage of
///         an ERC-20 inside the Aurora Cloud silo engine `0x4e45415c.c.aurora` (EIP-155 1313161564)
///         (test/e2e/fixtures/aurora-live, re-record with `npm run neartons-live:refresh`).
contract AuroraLiveTest is Test {
    Ed25519Verifier internal ed;
    ClprEd25519SignatureCache internal cache;
    string internal j;
    AuroraVerifier internal v;

    function setUp() public {
        ed = new Ed25519Verifier();
        cache = new ClprEd25519SignatureCache(ed);
        j = vm.readFile(string.concat(vm.projectRoot(), "/test/e2e/fixtures/aurora-live/mainnet.json"));
        bytes32[] memory cp = vm.parseJsonBytes32Array(j, ".derived.checkpointPrev");
        v = new AuroraVerifier(
            vm.parseJsonString(j, ".derived.chainId"),
            NearLightClient.EpochState(cp[0], cp[1], cp[2], cp[3]),
            ed,
            cache,
            bytes(vm.parseJsonString(j, ".derived.engineAccount")),
            vm.parseUint(vm.parseJsonString(j, ".derived.evmChainId"))
        );
    }

    function _record() internal {
        bytes memory message = vm.parseJsonBytes(j, ".derived.message");
        bytes32[] memory keys = vm.parseJsonBytes32Array(j, ".derived.signerKeys");
        bytes[] memory sigs = vm.parseJsonBytesArray(j, ".derived.signerSignatures");
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

    function test_mainnet_cached() public {
        _record();
        bytes memory anchorCur = vm.parseJsonBytes(j, ".derived.anchorCur");
        bytes memory proof = vm.parseJsonBytes(j, ".derived.storageProofCached");
        uint256 g = gasleft();
        (bytes32[] memory values, uint32 gen, bytes32 h,, bytes memory na) = v.verifyEvmStorage(proof, anchorCur);
        emit log_named_uint("verifyEvmStorage (6 slots) gas", g - gasleft());
        bytes32[] memory expected = vm.parseJsonBytes32Array(j, ".derived.tokenValues");
        assertEq(values.length, expected.length);
        for (uint256 i = 0; i < values.length; i++) {
            assertEq(values[i], expected[i]);
        }
        assertEq(values[4], bytes32(0)); // never-written slots: exclusion proofs
        assertEq(values[5], bytes32(0));
        assertEq(gen, vm.parseJsonUint(j, ".derived.tokenGeneration"));
        assertEq(h, vm.parseJsonBytes32(j, ".derived.lcHash"));
        assertEq(na.length, 0);

        // the same block from the previous epoch's anchor rotates it
        bytes memory anchorPrev = vm.parseJsonBytes(j, ".derived.anchorPrev");
        g = gasleft();
        (,,,, na) = v.verifyEvmStorage(proof, anchorPrev);
        emit log_named_uint("verifyEvmStorage + epoch rotation gas", g - gasleft());
        assertEq(na, anchorCur);

        // an EOA: generation 0 (absent) and an absent slot under the 54-byte key form
        (values, gen,,,) = v.verifyEvmStorage(vm.parseJsonBytes(j, ".derived.eoaProofCached"), anchorCur);
        assertEq(gen, 0);
        assertEq(values[0], bytes32(0));
    }

    function test_mainnet_inline_measure() public {
        bytes memory proof = vm.parseJsonBytes(j, ".derived.storageProof");
        bytes memory anchorCur = vm.parseJsonBytes(j, ".derived.anchorCur");
        uint256 g = gasleft();
        v.verifyEvmStorage(proof, anchorCur);
        emit log_named_uint("verifyEvmStorage, inline approvals gas", g - gasleft());
    }

    function test_rejects_forgedSlotValue() public {
        _record();
        // AuroraVerifier.StorageProof: decode, change the first proven value, re-encode
        bytes memory proof = vm.parseJsonBytes(j, ".derived.storageProofCached");
        AuroraVerifier.StorageProof memory p = abi.decode(proof, (AuroraVerifier.StorageProof));
        p.proofs[0].value = bytes32(uint256(p.proofs[0].value) + 1);
        bytes memory bad = abi.encode(p);
        bytes memory anchorCur = vm.parseJsonBytes(j, ".derived.anchorCur");
        vm.expectRevert(NearLightClient.TrieValueMismatch.selector);
        v.verifyEvmStorage(bad, anchorCur);
    }

    function test_rejects_absentSlotClaimedSet() public {
        _record();
        AuroraVerifier.StorageProof memory p =
            abi.decode(vm.parseJsonBytes(j, ".derived.storageProofCached"), (AuroraVerifier.StorageProof));
        p.proofs[4].value = bytes32(uint256(1));
        bytes memory bad = abi.encode(p);
        bytes memory anchorCur = vm.parseJsonBytes(j, ".derived.anchorCur");
        vm.expectRevert(NearLightClient.TrieKeyNotFound.selector);
        v.verifyEvmStorage(bad, anchorCur);
    }

    function test_rejects_hiddenGeneration() public {
        _record();
        AuroraVerifier.StorageProof memory p =
            abi.decode(vm.parseJsonBytes(j, ".derived.storageProofCached"), (AuroraVerifier.StorageProof));
        p.engine.generation = 0;
        bytes memory bad = abi.encode(p);
        bytes memory anchorCur = vm.parseJsonBytes(j, ".derived.anchorCur");
        vm.expectRevert(NearLightClient.TrieKeyPresent.selector);
        v.verifyEvmStorage(bad, anchorCur);
    }
}
