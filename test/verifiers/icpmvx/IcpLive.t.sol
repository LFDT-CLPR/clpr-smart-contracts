// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IcpVerifier} from "@hiero-ledger/clpr/verifiers/icpmvx/IcpVerifier.sol";
import {IcpCertificate} from "@hiero-ledger/clpr/libraries/proof/icp/IcpCertificate.sol";
import {IcpBls} from "@hiero-ledger/clpr/libraries/proof/icp/IcpBls.sol";

/// @notice IcpVerifier against real Internet Computer mainnet certificates
///         (test/e2e/fixtures/icp-live/mainnet.json, re-record with `npm run icp-live:refresh`).
contract IcpLiveTest is Test {
    string internal j;
    IcpVerifier internal v;

    function setUp() public {
        j = vm.readFile(string.concat(vm.projectRoot(), "/test/e2e/fixtures/icp-live/mainnet.json"));
        v = new IcpVerifier(
            "icp:mainnet", vm.parseJsonBytes(j, ".rootKeyDer"), vm.parseJsonBytes(j, ".rootKeyUncompressed"), 0
        );
    }

    function _cert(string memory k) internal view returns (IcpCertificate.Certificate memory c) {
        string memory p = string.concat(".", k, ".certificate");
        c.tree = vm.parseJsonBytes(j, string.concat(p, ".tree"));
        c.signature = vm.parseJsonBytes(j, string.concat(p, ".signature"));
        c.subnetId = vm.parseJsonBytes(j, string.concat(p, ".subnetId"));
        c.delegationTree = vm.parseJsonBytes(j, string.concat(p, ".delegationTree"));
        c.delegationSignature = vm.parseJsonBytes(j, string.concat(p, ".delegationSignature"));
        c.subnetKey = vm.parseJsonBytes(j, string.concat(p, ".subnetKey"));
        c.rangesShard = vm.parseJsonBytes(j, string.concat(p, ".rangesShard"));
    }

    function _field(string memory k, string memory f) internal view returns (bytes memory) {
        return vm.parseJsonBytes(j, string.concat(".", k, ".", f));
    }

    function _time(string memory k) internal view returns (uint64) {
        return uint64(vm.parseUint(vm.parseJsonString(j, string.concat(".", k, ".time"))));
    }

    /// @dev ckBTC ledger data certificate (delegated, legacy canister ranges) and the ledger's witness.
    function test_live_dataCertificate_ckbtcTip() public {
        IcpCertificate.Certificate memory c = _cert("dataCertificate");
        bytes[] memory path = vm.parseJsonBytesArray(j, ".dataCertificate.path");
        bytes memory id = _field("dataCertificate", "canisterId");
        bytes memory witness = _field("dataCertificate", "witness");
        uint256 g = gasleft();
        (bytes memory value, uint64 time) = v.verifyCertifiedValue(c, id, witness, path);
        emit log_named_uint("ckBTC data certificate + witness gas", g - gasleft());
        emit log_named_uint(
            "calldata bytes", abi.encodeCall(IcpVerifier.verifyCertifiedValue, (c, id, witness, path)).length
        );
        assertEq(value, _field("dataCertificate", "value"));
        assertEq(time, _time("dataCertificate"));
    }

    /// @dev read_state v3 certificate (delegated, canister ranges in a /canister_ranges shard).
    function test_live_readState_delegatedShardedRanges() public {
        IcpCertificate.Certificate memory c = _cert("readStateDelegatedSharded");
        assertGt(c.rangesShard.length, 0);
        bytes[] memory path = vm.parseJsonBytesArray(j, ".readStateDelegatedSharded.path");
        uint256 g = gasleft();
        (bytes memory value, uint64 time) =
            v.verifyStateValue(c, _field("readStateDelegatedSharded", "canisterId"), path);
        emit log_named_uint("read_state v3 (sharded ranges) gas", g - gasleft());
        assertEq(value, _field("readStateDelegatedSharded", "value"));
        assertEq(time, _time("readStateDelegatedSharded"));
    }

    /// @dev read_state certificate of the NNS subnet, signed by the root key (no delegation).
    function test_live_readState_rootSubnet() public {
        IcpCertificate.Certificate memory c = _cert("readStateRootSubnet");
        assertEq(c.subnetId.length, 0);
        bytes[] memory path = vm.parseJsonBytesArray(j, ".readStateRootSubnet.path");
        uint256 g = gasleft();
        (bytes memory value,) = v.verifyStateValue(c, _field("readStateRootSubnet", "canisterId"), path);
        emit log_named_uint("read_state root subnet gas", g - gasleft());
        assertEq(value, _field("readStateRootSubnet", "value"));
    }

    // ── negative cases on live data ─────────────────────────────────────────

    function test_live_rejectsTamperedWitness() public {
        IcpCertificate.Certificate memory c = _cert("dataCertificate");
        bytes memory witness = _field("dataCertificate", "witness");
        witness[witness.length - 1] ^= 0x01;
        bytes[] memory path = vm.parseJsonBytesArray(j, ".dataCertificate.path");
        bytes memory id = _field("dataCertificate", "canisterId");
        vm.expectRevert(IcpVerifier.CertifiedDataMismatch.selector);
        v.verifyCertifiedValue(c, id, witness, path);
    }

    function test_live_rejectsSignatureFromOtherCertificate() public {
        IcpCertificate.Certificate memory c = _cert("dataCertificate");
        c.signature = _cert("readStateDelegatedSharded").signature;
        bytes[] memory path = vm.parseJsonBytesArray(j, ".dataCertificate.path");
        bytes memory id = _field("dataCertificate", "canisterId");
        bytes memory witness = _field("dataCertificate", "witness");
        vm.expectRevert(IcpBls.BadSignature.selector);
        v.verifyCertifiedValue(c, id, witness, path);
    }

    function test_live_rejectsCanisterOutsideSubnetRanges() public {
        // the ckBTC subnet's delegation does not cover the ICP ledger (NNS subnet)
        IcpCertificate.Certificate memory c = _cert("readStateDelegatedSharded");
        bytes[] memory path = vm.parseJsonBytesArray(j, ".readStateDelegatedSharded.path");
        bytes memory nnsLedger = _field("readStateRootSubnet", "canisterId");
        vm.expectRevert(IcpCertificate.CanisterNotInRanges.selector);
        v.verifyStateValue(c, nnsLedger, path);
    }

    function test_live_rejectsSubnetKeyFromOtherSubnet() public {
        IcpCertificate.Certificate memory c = _cert("dataCertificate");
        c.subnetKey = vm.parseJsonBytes(j, ".rootKeyUncompressed");
        bytes[] memory path = vm.parseJsonBytesArray(j, ".dataCertificate.path");
        bytes memory id = _field("dataCertificate", "canisterId");
        bytes memory witness = _field("dataCertificate", "witness");
        vm.expectRevert(IcpBls.KeyEncodingMismatch.selector);
        v.verifyCertifiedValue(c, id, witness, path);
    }

    function test_live_rejectsDelegationSignedByOtherKey() public {
        IcpCertificate.Certificate memory c = _cert("dataCertificate");
        c.delegationSignature = _cert("readStateRootSubnet").signature;
        bytes[] memory path = vm.parseJsonBytesArray(j, ".dataCertificate.path");
        bytes memory id = _field("dataCertificate", "canisterId");
        bytes memory witness = _field("dataCertificate", "witness");
        vm.expectRevert(IcpBls.BadSignature.selector);
        v.verifyCertifiedValue(c, id, witness, path);
    }

    function test_live_maxDelegationAge() public {
        bytes memory der = vm.parseJsonBytes(j, ".rootKeyDer");
        bytes memory unc = vm.parseJsonBytes(j, ".rootKeyUncompressed");
        IcpVerifier strict = new IcpVerifier("icp:mainnet", der, unc, 1); // 1 ns
        IcpCertificate.Certificate memory c = _cert("dataCertificate");
        bytes[] memory path = vm.parseJsonBytesArray(j, ".dataCertificate.path");
        bytes memory id = _field("dataCertificate", "canisterId");
        bytes memory witness = _field("dataCertificate", "witness");
        vm.expectRevert(IcpCertificate.DelegationTooOld.selector);
        strict.verifyCertifiedValue(c, id, witness, path);
        IcpVerifier day = new IcpVerifier("icp:mainnet", der, unc, 1 days * 1e9);
        day.verifyCertifiedValue(c, id, witness, path);
    }
}
