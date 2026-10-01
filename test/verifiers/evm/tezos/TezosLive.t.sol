// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Ed25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/Ed25519Verifier.sol";
import {TezosSignatureCache} from "@hiero-ledger/clpr/verifiers/evm/tezos/TezosSignatureCache.sol";
import {TezosLightClient} from "@hiero-ledger/clpr/verifiers/evm/tezos/TezosLightClient.sol";
import {TezosContextVerifier} from "@hiero-ledger/clpr/verifiers/evm/tezos/TezosContextVerifier.sol";
import {TezosVerifier} from "@hiero-ledger/clpr/verifiers/evm/tezos/TezosVerifier.sol";
import {TezosContextProof} from "@hiero-ledger/clpr/libraries/proof/tezos/TezosContextProof.sol";
import {TezosLibHarness} from "./TezosVerifier.t.sol";
import {EtherlinkCementedState} from "@hiero-ledger/clpr/verifiers/evm/tezos/EtherlinkCementedState.sol";

/// @notice TezosVerifier against real Tezos mainnet data (test/e2e/fixtures/tezos-live, re-record
///         with `npm run tezos-live:refresh`): a real Tenderbake attestation quorum (tz1 Ed25519,
///         tz2 secp256k1, tz3 P-256 and the tz4 BLS aggregate), rights re-drawn from the real delegate
///         sampler, and real context proofs (tzBTC ledger big_map entry, Etherlink's last cemented
///         commitment) under the state root the quorum finalizes.
contract TezosLiveTest is Test {
    string internal j;
    Ed25519Verifier internal ed;
    TezosSignatureCache internal cache;
    TezosVerifier internal v;
    TezosContextVerifier internal ctxv;

    function setUp() public {
        j = vm.readFile(string.concat(vm.projectRoot(), "/test/e2e/fixtures/tezos-live/mainnet.json"));
        ed = new Ed25519Verifier();
        cache = new TezosSignatureCache(ed);
        ctxv = new TezosContextVerifier();
        v = new TezosVerifier(
            _profile(),
            ed,
            cache,
            ctxv,
            vm.parseJsonString(j, ".derived.caip2"),
            hex"01e0d2b0c72e6767ff58e09b4ceb6b77b8ad6e922d00", // any KT1; the generic entry point ignores it
            31,
            uint32(vm.parseJsonUint(j, ".derived.anchorLevel")),
            vm.parseJsonBytes32(j, ".derived.anchorRoot")
        );
    }

    function _profile() internal view returns (TezosLightClient.Profile memory p) {
        p.chainId = bytes4(vm.parseJsonBytes(j, ".derived.chainIdBytes"));
        p.protocolLevel = uint8(vm.parseJsonUint(j, ".derived.protocolLevel"));
        p.eraFirstLevel = uint32(vm.parseJsonUint(j, ".derived.profile.eraFirstLevel"));
        p.eraFirstCycle = uint32(vm.parseJsonUint(j, ".derived.profile.eraFirstCycle"));
        p.blocksPerCycle = uint32(vm.parseJsonUint(j, ".derived.profile.blocksPerCycle"));
        p.committeeSize = uint16(vm.parseJsonUint(j, ".derived.profile.committeeSize"));
        p.threshold = uint16(vm.parseJsonUint(j, ".derived.profile.threshold"));
    }

    function _finality(string memory key) internal view returns (TezosLightClient.FinalityProof memory) {
        return abi.decode(vm.parseJsonBytes(j, key), (TezosLightClient.FinalityProof));
    }

    function _steps(string memory key) internal view returns (bytes[] memory steps) {
        string[] memory s = vm.parseJsonStringArray(j, key);
        steps = new bytes[](s.length);
        for (uint256 i = 0; i < s.length; i++) {
            steps[i] = bytes(s[i]);
        }
    }

    /// @dev Verify the tzBTC entry under the finalized root; returns the gas of the verifier call alone.
    function _check(TezosLightClient.FinalityProof memory f) internal view returns (uint256 used) {
        bytes memory anchor = vm.parseJsonBytes(j, ".derived.anchor");
        bytes[] memory steps = _steps(".derived.tzbtc.steps");
        bytes memory proof = vm.parseJsonBytes(j, ".derived.tzbtc.proof");
        uint256 g = gasleft();
        (bytes memory value, bytes memory na) = v.verifyContextValue(f, anchor, steps, proof);
        used = g - gasleft();
        assertEq(value, vm.parseJsonBytes(j, ".derived.tzbtc.value"));
        assertEq(na, vm.parseJsonBytes(j, ".derived.newAnchor"));
    }

    function _recordAll() internal {
        string[] memory groups = new string[](2);
        groups[0] = ".derived.cacheEd25519";
        groups[1] = ".derived.cacheP256";
        for (uint256 k = 0; k < 2; k++) {
            bytes[] memory batches = vm.parseJsonBytesArray(j, groups[k]);
            for (uint256 i = 0; i < batches.length; i++) {
                TezosSignatureCache.Entry[] memory es = abi.decode(batches[i], (TezosSignatureCache.Entry[]));
                uint256 g = gasleft();
                cache.record(es);
                emit log_named_uint(string.concat(groups[k], " record batch gas"), g - gasleft());
            }
        }
    }

    function test_live_inlineSignatures() public {
        TezosLightClient.FinalityProof memory f = _finality(".derived.finalityInline");
        emit log_named_uint("verifyContextValue (inline signatures) gas", _check(f));
    }

    function test_live_cachedSignatures() public {
        _recordAll();
        TezosLightClient.FinalityProof memory f = _finality(".derived.finalityCached");
        emit log_named_uint("verifyContextValue (cached tz1/tz3) gas", _check(f));
    }

    /// @dev From an anchor one cycle earlier: the bundle carries the trust anchor across a cycle
    ///      boundary (Tezos's per-cycle rights change).
    function test_live_rotation() public {
        bytes memory anchor = vm.parseJsonBytes(j, ".derived.prevAnchor");
        assertLt(vm.parseJsonUint(j, ".derived.prevAnchorCycle"), vm.parseJsonUint(j, ".derived.cycle"));
        bytes[] memory steps = _steps(".derived.tzbtc.steps");
        bytes memory proof = vm.parseJsonBytes(j, ".derived.tzbtc.proof");
        TezosLightClient.FinalityProof memory f = _finality(".derived.finalityRotationInline");
        uint256 g = gasleft();
        (bytes memory value, bytes memory na) = v.verifyContextValue(f, anchor, steps, proof);
        emit log_named_uint("rotation (inline signatures) gas", g - gasleft());
        assertEq(value, vm.parseJsonBytes(j, ".derived.tzbtc.value"));
        assertEq(na, vm.parseJsonBytes(j, ".derived.newAnchor"));
        _recordAll();
        f = _finality(".derived.finalityRotationCached");
        g = gasleft();
        (value,) = v.verifyContextValue(f, anchor, steps, proof);
        emit log_named_uint("rotation (cached tz1/tz3) gas", g - gasleft());
        assertEq(value, vm.parseJsonBytes(j, ".derived.tzbtc.value"));
    }

    /// @dev The cost of re-drawing the attestation rights: the live sampler (196 delegates), the
    ///      level's real signers, counting until the 4,667-slot threshold.
    function test_live_slotDrawCost() public {
        TezosLibHarness lib = new TezosLibHarness();
        uint256[] memory signers = vm.parseJsonUintArray(j, ".derived.signerSupport");
        (uint256 counted, uint256 used) = lib.countSigned(
            vm.parseJsonBytes(j, ".derived.samplerValue"),
            vm.parseJsonBytes32(j, ".derived.seed"),
            vm.parseJsonUint(j, ".derived.cyclePosition"),
            signers,
            7000,
            4667
        );
        emit log_named_uint("slot re-draw until 4,667 signer slots (gas)", used);
        assertEq(counted, 4667);
    }

    function test_live_etherlinkCementedState() public {
        EtherlinkCementedState e = new EtherlinkCementedState(
            _profile(), ed, cache, ctxv, bytes20(vm.parseJsonBytes(j, ".derived.etherlink.rollupHex"))
        );
        TezosLightClient.FinalityProof memory f = _finality(".derived.finalityInline");
        bytes memory anchor = vm.parseJsonBytes(j, ".derived.anchor");
        bytes memory lccProof = vm.parseJsonBytes(j, ".derived.etherlink.lccProof");
        bytes memory cProof = vm.parseJsonBytes(j, ".derived.etherlink.commitmentProof");
        uint256 g = gasleft();
        (bytes32 stateHash, uint32 inboxLevel, bytes32 lcc, bytes memory na) =
            e.verifyCementedState(f, anchor, lccProof, cProof);
        emit log_named_uint("Etherlink verifyCementedState (inline signatures) gas", g - gasleft());
        assertEq(stateHash, vm.parseJsonBytes32(j, ".derived.etherlink.compressedState"));
        assertEq(inboxLevel, vm.parseJsonUint(j, ".derived.etherlink.inboxLevel"));
        assertEq(lcc, vm.parseJsonBytes32(j, ".derived.etherlink.lcc"));
        assertEq(na, vm.parseJsonBytes(j, ".derived.newAnchor"));
    }

    function test_live_rejects_belowThreshold() public {
        TezosLightClient.FinalityProof memory f = _finality(".derived.finalityInline");
        delete f.aggregates; // drop the tz4 aggregate (about a third of the slots)
        bytes memory anchor = vm.parseJsonBytes(j, ".derived.anchor");
        bytes[] memory steps = _steps(".derived.tzbtc.steps");
        bytes memory proof = vm.parseJsonBytes(j, ".derived.tzbtc.proof");
        vm.expectPartialRevert(TezosLightClient.QuorumNotReached.selector);
        v.verifyContextValue(f, anchor, steps, proof);
    }

    function test_live_rejects_tamperedSignature() public {
        TezosLightClient.FinalityProof memory f = _finality(".derived.finalityInline");
        f.attestations[0].signature[5] ^= 0x01;
        bytes memory anchor = vm.parseJsonBytes(j, ".derived.anchor");
        bytes[] memory steps = _steps(".derived.tzbtc.steps");
        bytes memory proof = vm.parseJsonBytes(j, ".derived.tzbtc.proof");
        vm.expectRevert(abi.encodeWithSelector(TezosLightClient.BadAttestationSignature.selector, 0));
        v.verifyContextValue(f, anchor, steps, proof);
    }

    function test_live_rejects_otherAnchor() public {
        TezosLightClient.FinalityProof memory f = _finality(".derived.finalityInline");
        bytes memory anchor = abi.encode(uint32(vm.parseJsonUint(j, ".derived.anchorLevel")), bytes32(uint256(1)));
        bytes[] memory steps = _steps(".derived.tzbtc.steps");
        bytes memory proof = vm.parseJsonBytes(j, ".derived.tzbtc.proof");
        vm.expectRevert(abi.encodeWithSelector(TezosContextProof.ProofHashMismatch.selector, 0));
        v.verifyContextValue(f, anchor, steps, proof);
    }

    function test_live_contractStorage() public view {
        TezosLightClient.FinalityProof memory f = _finality(".derived.finalityInline");
        (bytes memory s,) = v.verifyContextValue(
            f,
            vm.parseJsonBytes(j, ".derived.anchor"),
            _steps(".derived.tzbtcStorage.steps"),
            vm.parseJsonBytes(j, ".derived.tzbtcStorage.proof")
        );
        assertEq(s, vm.parseJsonBytes(j, ".derived.tzbtcStorage.value"));
    }
}
