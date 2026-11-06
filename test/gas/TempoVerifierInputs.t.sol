// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {console2} from "forge-std/console2.sol";
import {Test} from "forge-std/Test.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {Ed25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/Ed25519Verifier.sol";
import {CometBftLib} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftLib.sol";
import {QbftHeaderModeProofBuilders} from "@test/verifiers/evm/qbft/QbftHeaderModeProofBuilders.sol";
import {QbftContractModeProofBuilders} from "@test/verifiers/evm/qbft/QbftContractModeProofBuilders.sol";
import {EthBundleProofFactory} from "@test/verifiers/evm/ethereum/EthBundleProofFactory.sol";
import {TempoGasUsageTest} from "@test/verifiers/tempo/TempoGasUsage.t.sol";
import {TempoGasHarness} from "@test/verifiers/tempo/TempoGasReport.t.sol";
import {SeiRealBundleFixtures} from "@test/verifiers/evm/sei/SeiRealBundleFixtures.sol";
import {SeiGasHarness} from "@test/verifiers/evm/sei/GasUsage.t.sol";
import {Harness as SeiParseHarness} from "@test/verifiers/evm/sei/SeiRealBundle.t.sol";

/// @notice Prints the calldata of the verifier gas scenarios, built by the same helpers as the gas
///         baselines, so `tools/tempo-localnet/measure-verifier-gas.ts` can replay them as real
///         transactions on a live chain. Each line is `DUMP <target contract> <scenario> <calldata>`.
///         Does nothing unless `CLPR_DUMP_VERIFIER_INPUTS=1`:
///         `CLPR_DUMP_VERIFIER_INPUTS=1 FOUNDRY_PROFILE=test forge test --match-path test/gas/TempoVerifierInputs.t.sol -vv`
abstract contract VerifierInputsDump is Test {
    function _enabled() internal view returns (bool) {
        return vm.envOr("CLPR_DUMP_VERIFIER_INPUTS", false);
    }

    function _dump(string memory target, string memory id, bytes memory data) internal pure {
        console2.log(string.concat("DUMP ", target, " ", id, " ", vm.toString(data)));
    }

    function _bundle(string memory target, string memory id, bytes memory proof, bytes memory anchor, bytes memory ctx)
        internal
        pure
    {
        _dump(target, id, abi.encodeCall(IClprVerifier.verifyBundle, (proof, anchor, ctx)));
    }
}

contract QbftHeaderModeInputsDump is QbftHeaderModeProofBuilders, VerifierInputsDump {
    string internal constant T = "QbftHeaderModeVerifier";

    function test_dump() public view {
        if (!_enabled()) return;
        (bytes memory proof, bytes memory anchor) = _steadyScenario("gas-h", 1);
        _bundle(T, "steady-1", proof, anchor, _syntheticChannelContext());
        (proof, anchor) = _rotationScenario("gas-rot", 10);
        _bundle(T, "rotation-10-11", proof, anchor, _syntheticChannelContext());
        (proof, anchor) = _rotationScenario("gas-rot", 51);
        _bundle(T, "rotation-51-52", proof, anchor, _syntheticChannelContext());
        _dump(
            T,
            "config",
            abi.encodeCall(IClprVerifier.verifyConfig, (_configScenario("gas-hc"), SYNTHETIC_CHANNEL_ID, ""))
        );
    }
}

contract QbftContractModeInputsDump is QbftContractModeProofBuilders, VerifierInputsDump {
    string internal constant T = "QbftContractModeVerifier";

    function test_dump() public view {
        if (!_enabled()) return;
        (bytes memory proof, bytes memory anchor) = _steadyScenario("gas-s", 3);
        _bundle(T, "steady-3", proof, anchor, _syntheticChannelContext());
        (proof, anchor) = _rotationScenario("gas-rot", 10);
        _bundle(T, "rotation-10-11", proof, anchor, _syntheticChannelContext());
        (proof, anchor) = _rotationScenario("gas-rot", 51);
        _bundle(T, "rotation-51-52", proof, anchor, _syntheticChannelContext());
        _dump(
            T,
            "config",
            abi.encodeCall(IClprVerifier.verifyConfig, (_configScenario("gas-c"), SYNTHETIC_CHANNEL_ID, ""))
        );
    }
}

/// @dev The shape `EthGasReport.t.sol` measures: 8-node account proof, 4-node storage proofs, dense branches.
contract EthMainnetInputsDump is EthBundleProofFactory, VerifierInputsDump {
    string internal constant T = "EthMainnetVerifier";

    function _spec(uint256 n, uint256 signers, Rotation rotation) internal pure returns (BundleSpec memory) {
        return BundleSpec({
            messageCount: n,
            signers: signers,
            accountDepth: 7,
            storageDepth: 3,
            denseBranches: true,
            rotation: rotation,
            manifest: false,
            ackedByPeer: 0,
            channelId: bytes32(uint256(0xC0FFEE)),
            peerService: address(0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C),
            codeHash: bytes32(uint256(0xC0DE)),
            connectorId: bytes32(uint256(0xC0)),
            targetApp: address(0xA99)
        });
    }

    function _eth(string memory id, BundleSpec memory s) internal {
        BuiltBundle memory b = _buildBundle(s);
        _bundle(T, id, b.proof, b.trustAnchor, b.channelContext);
    }

    function test_dump() public {
        if (!_enabled()) return;
        _eth("n1-512", _spec(1, SYNC_COMMITTEE_SIZE, Rotation.None));
        _eth("n1-342", _spec(1, SUPERMAJORITY, Rotation.None));
        _eth("n10-512", _spec(10, SYNC_COMMITTEE_SIZE, Rotation.None));
        _eth("n1-512-widen", _spec(1, SYNC_COMMITTEE_SIZE, Rotation.Widen));
        _eth("n1-512-shift", _spec(1, SYNC_COMMITTEE_SIZE, Rotation.Shift));
        BundleSpec memory s = _spec(1, SYNC_COMMITTEE_SIZE, Rotation.None);
        _dump(T, "config", abi.encodeCall(IClprVerifier.verifyConfig, (_configProof(s, "eip155:1"), s.channelId, "")));
    }
}

contract TempoInputsDump is TempoGasUsageTest, VerifierInputsDump {
    string internal constant T = "TempoVerifier";

    function test_dump() public view {
        if (!_enabled()) return;
        (bytes memory proof, bytes memory anchor) = _steady();
        _bundle(T, "steady", proof, anchor, _ctx());
        (proof, anchor) = _rotation();
        _bundle(T, "rotation-1", proof, anchor, _ctx());
        uint256 sk3 = _testKey("tempo-gas-3");
        bytes[] memory rotations = new bytes[](2);
        rotations[0] = _boundaryRotation(sk1, 3, pk2);
        rotations[1] = _boundaryRotation(sk2, 4, _blsPublicKey(sk3));
        _bundle(T, "rotation-2", _bundleAt(sk3, 5 * L + 1, rotations), _tempoAnchor(CODE_HASH, L, 3 * L, pk1), _ctx());
        _dump(T, "config", abi.encodeCall(IClprVerifier.verifyConfig, (_config(), CHANNEL_ID, "")));

        TempoFixture memory f = _loadTempoFixture("presto-tip");
        TempoGasHarness.CertificateBytesIn memory c = TempoGasHarness.CertificateBytesIn({
            proposal: f.proposal, sigCompressed: f.sigCompressed, sigUncompressed: f.sigUncompressed
        });
        _dump(
            "TempoGasHarness",
            "certify-mainnet-tip",
            abi.encodeCall(TempoGasHarness.certify, (f.headerRlp, c, f.keyUncompressed, 21600))
        );
    }
}

/// @dev Sei has no full-bundle builder with real signatures, so its steps are measured on the real
///      relay data, as `test/verifiers/evm/sei/GasUsage.t.sol` does, plus one direct Ed25519 check.
contract SeiInputsDump is SeiRealBundleFixtures, VerifierInputsDump {
    function test_dump() public {
        if (!_enabled()) return;
        _dump(
            "SeiGasHarness",
            "signed-header",
            abi.encodeCall(SeiGasHarness.measureSignedHeader, (SIGNED_HEADER, PUBKEY, POWER, SIG))
        );
        _dump("SeiGasHarness", "iavl-slot", abi.encodeCall(SeiGasHarness.measureIavlProof, (IAVL_PROOF, ABSENT_KEY)));

        SeiParseHarness h = new SeiParseHarness(address(new Ed25519Verifier()));
        (CometBftLib.SeiHeader memory hdr, CometBftLib.SeiCommit memory cm) = h.parseSignedHeader(SIGNED_HEADER);
        bytes memory signBytes = h.precommitSignBytes(
            hdr.chainId,
            hdr.height,
            cm.round,
            h.headerHash(hdr),
            cm.partSetTotal,
            cm.partSetHash,
            cm.signatures[0].timestampSeconds,
            cm.signatures[0].timestampNanos
        );
        _dump("Ed25519Verifier", "verify-1-sig", abi.encodeCall(Ed25519Verifier.verify, (PUBKEY, signBytes, SIG)));
    }
}
