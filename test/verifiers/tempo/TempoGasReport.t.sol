// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {console2} from "forge-std/console2.sol";
import {TempoGasUsageTest} from "@test/verifiers/tempo/TempoGasUsage.t.sol";
import {TempoVerifier} from "@hiero-ledger/clpr/verifiers/evm/tempo/TempoVerifier.sol";
import {ClprTempoBls} from "@hiero-ledger/clpr/libraries/proof/tempo/ClprTempoBls.sol";
import {ClprTempoCertificate} from "@hiero-ledger/clpr/libraries/proof/tempo/ClprTempoCertificate.sol";
import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";
import {CalldataGas} from "@test/helpers/CalldataGas.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @dev Each step runs as its own call frame, so `vm.lastCallGas()` measures it like a real call.
contract TempoGasHarness is TempoVerifier {
    function hashToG1(bytes memory message) external view returns (bytes memory) {
        return ClprBls12381.hashToG1(message, ClprTempoBls.DST);
    }

    function verifyMinSig(bytes memory sig, bytes memory message, bytes memory key) external view {
        ClprTempoBls.verifyMinSig(sig, message, key);
    }

    function compressG2(bytes memory key) external pure returns (bytes memory) {
        return ClprBls12381.compressG2(key);
    }

    function compressG1(bytes memory sig) external pure returns (bytes memory) {
        return ClprBls12381.compressG1(sig);
    }

    function parseProposal(bytes memory proposal) external pure returns (ClprTempoCertificate.Proposal memory) {
        return ClprTempoCertificate.parseProposal(proposal);
    }

    function dkgOutcomeKey(bytes memory extraData) external pure returns (uint64, bytes memory) {
        return ClprTempoCertificate.dkgOutcomeKey(extraData);
    }

    /// @dev Header decode + proposal parse + signature binding + BLS check, as the verifier does per block.
    function certify(bytes memory header, CertificateBytesIn memory c, bytes memory key, uint64 epochLength)
        external
        view
        returns (uint64)
    {
        bytes[] memory items = new bytes[](4);
        items[0] = header;
        items[1] = RLP.encode(c.proposal);
        items[2] = RLP.encode(c.sigCompressed);
        items[3] = RLP.encode(c.sigUncompressed);
        Memory.Slice[] memory s = RLP.decodeList(RLP.encode(items));
        return _verifyCertifiedHeader(
            s[0], Certificate({proposal: s[1], sigCompressed: s[2], sigUncompressed: s[3]}), key, epochLength
        )
        .number;
    }

    struct CertificateBytesIn {
        bytes proposal;
        bytes sigCompressed;
        bytes sigUncompressed;
    }
}

/// @title TempoGasReportTest
/// @notice The measurements behind `src/verifiers/evm/tempo/GAS_REPORT.md`. Reproduce with
///         `FOUNDRY_PROFILE=test forge test --match-path test/verifiers/tempo/TempoGasReport.t.sol -vv`.
contract TempoGasReportTest is TempoGasUsageTest {
    TempoGasHarness internal h;

    function setUp() public override {
        super.setUp();
        h = new TempoGasHarness();
    }

    /// @dev The BLS primitives on the real mainnet certificate.
    function test_report_primitives() public view {
        TempoFixture memory f = _loadTempoFixture("presto-tip");
        bytes memory message = ClprTempoCertificate.finalizeMessage(f.proposal);

        h.parseProposal(f.proposal);
        console2.log("parseProposal:", vm.lastCallGas().gasTotalUsed);
        h.compressG1(f.sigUncompressed);
        console2.log("compressG1 (signature binding):", vm.lastCallGas().gasTotalUsed);
        h.compressG2(f.keyUncompressed);
        console2.log("compressG2 (key binding):", vm.lastCallGas().gasTotalUsed);
        h.hashToG1(message);
        console2.log("hashToG1:", vm.lastCallGas().gasTotalUsed);
        h.verifyMinSig(f.sigUncompressed, message, f.keyUncompressed);
        console2.log("verifyMinSig (hashToG1 + pairing):", vm.lastCallGas().gasTotalUsed);

        TempoGasHarness.CertificateBytesIn memory c = TempoGasHarness.CertificateBytesIn({
            proposal: f.proposal, sigCompressed: f.sigCompressed, sigUncompressed: f.sigUncompressed
        });
        h.certify(f.headerRlp, c, f.keyUncompressed, 21600);
        console2.log("certified header, mainnet tip:", vm.lastCallGas().gasTotalUsed);

        TempoFixture memory b = _loadTempoFixture("presto-boundary");
        h.dkgOutcomeKey(_innerField(b.headerRlp, 12));
        console2.log("dkgOutcomeKey, mainnet boundary:", vm.lastCallGas().gasTotalUsed);
    }

    /// @dev Full verifier calls on the synthetic scenarios shared with the baselines.
    function test_report_verifier() public view {
        (bytes memory proof, bytes memory anchor) = _steady();
        _measure("verifyBundle steady state", proof, anchor);

        (proof, anchor) = _rotation();
        _measure("verifyBundle, 1 rotation", proof, anchor);

        uint256 sk3 = _testKey("tempo-gas-3");
        bytes[] memory rotations = new bytes[](2);
        rotations[0] = _boundaryRotation(sk1, 3, pk2);
        rotations[1] = _boundaryRotation(sk2, 4, _blsPublicKey(sk3));
        proof = _bundleAt(sk3, 5 * L + 1, rotations);
        _measure("verifyBundle, 2 rotations", proof, _tempoAnchor(CODE_HASH, L, 3 * L, pk1));

        bytes memory config = _config();
        verifier.verifyConfig(config, CHANNEL_ID, "");
        console2.log("verifyConfig:", vm.lastCallGas().gasTotalUsed);
        console2.log("verifyConfig proof bytes:", config.length);
        console2.log("verifyConfig calldata gas:", CalldataGas.eip2028(config));
    }

    function _measure(string memory label, bytes memory proof, bytes memory anchor) internal view {
        bytes memory ctx = _ctx();
        verifier.verifyBundle(proof, anchor, ctx);
        console2.log(string.concat(label, ":"), vm.lastCallGas().gasTotalUsed);
        console2.log(string.concat(label, " proof bytes:"), proof.length + anchor.length + ctx.length);
        console2.log(
            string.concat(label, " calldata gas:"),
            CalldataGas.eip2028(proof) + CalldataGas.eip2028(anchor) + CalldataGas.eip2028(ctx)
        );
    }
}
