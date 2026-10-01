// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {OpOutputOracleVerifier} from "@hiero-ledger/clpr/verifiers/evm/opstack/oracle/OpOutputOracleVerifier.sol";
import {
    OpOutputOracleProposedVerifier
} from "@hiero-ledger/clpr/verifiers/evm/opstack/oracle/OpOutputOracleProposedVerifier.sol";
import {
    OpOutputOracleVerifierBase
} from "@hiero-ledger/clpr/verifiers/evm/opstack/oracle/OpOutputOracleVerifierBase.sol";
import {FraxtalProfile} from "@hiero-ledger/clpr/verifiers/evm/opstack/oracle/profiles/FraxtalProfile.sol";
import {EthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/EthL1StateVerifier.sol";
import {ClprBeaconSsz} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconSsz.sol";
import {OpOutputOracleProof as OO} from "@hiero-ledger/clpr/libraries/proof/opstack/OpOutputOracleProof.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";

/// @notice Fraxtal (chain 252) against REAL Ethereum-mainnet data: the mainnet sync committee's signature,
///         Fraxtal's L2OutputOracle at the signed L1 block, and Fraxtal L2 proofs of the
///         L2ToL1MessagePasser (ClprService stand-in, channel slots absent). Input:
///         `fixtures/fraxtal-live.json`, written by
///         `npx tsx test/e2e/relay/buildOpOracleLiveProof.ts --set fraxtal --refresh`. The verifiers are
///         deployed from the PINNED profile library, never from captured values.
contract OpOutputOracleFraxtalLiveTest is Test {
    string internal json;
    EthL1StateVerifier internal l1;
    OpOutputOracleVerifier internal finalized;
    OpOutputOracleProposedVerifier internal proposed;
    bytes internal anchor;
    bytes internal ctx;
    uint64 internal genesisTime;
    uint64 internal l1Time;
    bytes32 internal l1StateRoot;

    string internal constant C = ".chains.fraxtal.";

    function setUp() public {
        json = vm.readFile(
            string.concat(vm.projectRoot(), "/test/verifiers/evm/opstack/oracle/fixtures/fraxtal-live.json")
        );
        l1 = new EthL1StateVerifier(
            ClprBeaconSsz.GINDEX_EXECUTION_STATE_ROOT_IN_BODY,
            9,
            ClprBeaconSsz.GINDEX_NEXT_SYNC_COMMITTEE_IN_STATE,
            6,
            8192
        );
        genesisTime = uint64(vm.parseJsonUint(json, ".l1.genesisTime"));
        l1Time = uint64(vm.parseJsonUint(json, ".l1.time"));
        l1StateRoot = vm.parseJsonBytes32(json, ".l1.stateRoot");
        finalized =
            new OpOutputOracleVerifier(l1, genesisTime, 12, FraxtalProfile.profile(), FraxtalProfile.accountFormat());
        proposed = new OpOutputOracleProposedVerifier(
            l1, genesisTime, 12, FraxtalProfile.profile(), FraxtalProfile.accountFormat()
        );
        anchor = vm.parseJsonBytes(json, string.concat(C, "trustAnchor"));
        ctx = vm.parseJsonBytes(json, string.concat(C, "channelContext"));
    }

    function _b(string memory key) internal view returns (bytes memory) {
        return vm.parseJsonBytes(json, string.concat(C, key));
    }

    function _u(string memory key) internal view returns (uint256) {
        return vm.parseJsonUint(json, string.concat(C, key));
    }

    function _logBundleGas(string memory label, bytes memory bundle, uint256 execution) internal view {
        bytes memory data = abi.encodeCall(finalized.verifyBundle, (bundle, anchor, ctx));
        uint256 gas = 21_000 + execution;
        for (uint256 i; i < data.length; ++i) {
            gas += data[i] == 0 ? 4 : 16;
        }
        console.log(string.concat("fraxtal ", label, ": gas ~"), gas, "calldata B", data.length);
    }

    function test_profileMatchesLiveChain() public view {
        OO.Profile memory p = FraxtalProfile.profile();
        assertEq(p.oracle, vm.parseJsonAddress(json, string.concat(C, "oracle")), "oracle");
        assertEq(p.oracleImplCodeHash, vm.parseJsonBytes32(json, string.concat(C, "oracleImplCodeHash")), "impl");
        assertEq(_u("finalizationPeriodSeconds"), 604_800, "period (read from slot 8)");
        assertEq(uint8(finalized.FINALITY()), 0);
        assertEq(uint8(proposed.FINALITY()), 1);
    }

    /// FINALIZED: full `verifyBundle` on the newest output past the 7-day period, down to Fraxtal storage.
    function test_finalized_fullBundle() public {
        assertTrue(vm.parseJsonBool(json, string.concat(C, "finalized.finalizedAtL1")));
        bytes memory bundle = _b("finalized.bundle");
        uint256 g = gasleft();
        (ClprTypes.QueueMetadata memory m, bytes[] memory payloads,,,) = finalized.verifyBundle(bundle, anchor, ctx);
        g -= gasleft();
        assertEq(m.nextMessageId, 0);
        assertEq(payloads.length, 0);
        _logBundleGas("FINALIZED verifyBundle", bundle, g);
        (bytes32 root,,) = finalized.verifyL2StateRoot(_b("finalized.l2StateRootProof"), anchor);
        assertEq(root, vm.parseJsonBytes32(json, string.concat(C, "finalized.l2StateRoot")));
    }

    /// PROPOSED accepts the newest output; FINALIZED rejects it inside the 7-day period.
    function test_newestOutput_proposedOnly() public {
        bytes memory bundle = _b("newest.bundle");
        uint256 g = gasleft();
        (ClprTypes.QueueMetadata memory m,,,,) = proposed.verifyBundle(bundle, anchor, ctx);
        g -= gasleft();
        assertEq(m.nextMessageId, 0);
        _logBundleGas("PROPOSED verifyBundle", bundle, g);
        vm.expectRevert(
            abi.encodeWithSelector(
                OO.OutputNotFinalized.selector,
                _u("newest.index"),
                _u("newest.l1Timestamp"),
                uint256(l1Time),
                uint256(604_800)
            )
        );
        finalized.verifyBundle(bundle, anchor, ctx);
    }

    /// `verifyOutput` on the light-client-proven L1 state root.
    function test_verifyOutput() public view {
        OO.Output memory o = finalized.verifyOutput(
            _b("finalized.oracleProof"),
            l1StateRoot,
            l1Time,
            vm.parseJsonBytes32(json, string.concat(C, "finalized.outputRoot"))
        );
        assertEq(o.index, _u("finalized.index"));
        assertEq(o.l2BlockNumber, _u("finalized.l2BlockNumber"));
    }

    /// The index `length` was never posted at the captured block (or was deleted): both tiers reject it.
    function test_rejectsUnpostedIndex() public {
        vm.expectRevert(abi.encodeWithSelector(OO.OutputNotPosted.selector, _u("length"), _u("length")));
        proposed.verifyOutput(_b("unpostedOracleProof"), l1StateRoot, l1Time, bytes32(uint256(1)));
    }

    /// Another output's root at this index.
    function test_rejectsOutputRootNotAtIndex() public {
        vm.expectPartialRevert(OO.OutputRootMismatch.selector);
        finalized.verifyOutput(
            _b("finalized.oracleProof"),
            l1StateRoot,
            l1Time,
            vm.parseJsonBytes32(json, string.concat(C, "newest.outputRoot"))
        );
    }

    /// A profile pinning another oracle implementation (e.g. after an upgrade) rejects the live proof.
    function test_rejectsOtherOracleImplementation() public {
        OO.Profile memory p = FraxtalProfile.profile();
        p.oracleImplCodeHash = keccak256("other");
        OpOutputOracleVerifier other =
            new OpOutputOracleVerifier(l1, genesisTime, 12, p, FraxtalProfile.accountFormat());
        vm.expectPartialRevert(OO.OracleImplMismatch.selector);
        other.verifyBundle(_b("finalized.bundle"), anchor, ctx);
    }

    /// Blast's 7-field account leaf does not decode Fraxtal's 4-field accounts.
    function test_rejectsWrongAccountFormat() public {
        OpOutputOracleVerifier other = new OpOutputOracleVerifier(
            l1,
            genesisTime,
            12,
            FraxtalProfile.profile(),
            OpOutputOracleVerifierBase.L2AccountFormat({fields: 7, storageRootIndex: 5, codeHashIndex: 6})
        );
        vm.expectRevert();
        other.verifyBundle(_b("finalized.bundle"), anchor, ctx);
    }

    /// A trust anchor pinning another L2 code hash fails at the account binding.
    function test_rejectsWrongPinnedL2CodeHash() public {
        bytes memory bad = bytes.concat(anchor);
        bytes32 other = keccak256("some ClprService runtime");
        for (uint256 i; i < 32; ++i) {
            bad[228 + i] = other[i];
        }
        vm.expectRevert();
        finalized.verifyBundle(_b("finalized.bundle"), bad, ctx);
    }

    /// The real signature no longer verifies under another fork version.
    function test_rejectsTamperedSignature() public {
        bytes memory bad = bytes.concat(anchor);
        bad[32] = 0x05; // Electra fork version
        vm.expectRevert();
        finalized.verifyBundle(_b("finalized.bundle"), bad, ctx);
    }
}
