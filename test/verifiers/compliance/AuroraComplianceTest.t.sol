// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprVerifierComplianceTest} from "@test/verifiers/compliance/ClprVerifierComplianceTest.sol";
import {AuroraVerifierFixture} from "@test/verifiers/evm/neartons/AuroraVerifier.t.sol";
import {NearTonFixtures} from "@test/verifiers/evm/neartons/NearTonTestKit.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {AuroraVerifier} from "@hiero-ledger/clpr/verifiers/evm/neartons/AuroraVerifier.sol";
import {NearLightClient} from "@hiero-ledger/clpr/libraries/proof/near/NearLightClient.sol";

/// @title AuroraComplianceTest
/// @notice Compliance adapter binding `AuroraVerifier` to the shared verifier compliance suite, on the
///         synthetic world of {AuroraVerifierFixture} (NEAR light-client block, aurora-engine trie
///         with the ClprService slots under storage generation 1). Only Ed25519 is replaced by a
///         message-binding stub; real NEAR and aurora-engine data are covered by AuroraLive.t.sol.
contract AuroraComplianceTest is ClprVerifierComplianceTest, AuroraVerifierFixture {
    function setUp() public override(ClprVerifierComplianceTest, AuroraVerifierFixture) {
        AuroraVerifierFixture.setUp();
        verifier = _deployVerifier();
    }

    function _deployVerifier() internal view override returns (IClprVerifier) {
        return IClprVerifier(address(v));
    }

    function _configProof(World memory w, bytes memory controlMessage) internal view returns (bytes memory) {
        AuroraVerifier.ConfigProof memory p;
        p.blocks = new NearLightClient.Block[](1);
        p.blocks[0] = _block(E1, E2, sha256(prodB), prodA, keysA, _merkle(w.root), _signers(2, 3));
        p.shards = _shards(w.root);
        p.engine = _engine(w);
        p.controlMessage = controlMessage;
        return abi.encode(p);
    }

    function _validConfig() internal view override returns (ConfigVector memory) {
        return ConfigVector(_configProof(_world(1), control), CHANNEL, CHAIN, abi.encodePacked(SERVICE));
    }

    function _validBundle() internal view override returns (BundleVector memory) {
        return BundleVector(abi.encode(_bundle(_world(1), true, false)), _anchor(E1), _ctx(), NEXT_ID, 2);
    }

    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        manifest = committedPreimage; // slot 18 holds keccak256 of this preimage
        World memory w = _world(1);
        configProof = _configProof(w, control);
        channelId = CHANNEL;
        manifestProof = abi.encode(
            AuroraVerifier.ManifestProof(
                _slotProof(w, bytes32(uint256(18)), keccak256(committedPreimage)), carriedPreimage
            )
        );
    }

    function _runningHashVector() internal override returns (RunningHashVector memory) {
        bytes32 h = sha256(abi.encodePacked(bytes32(0), sha256(hex"0a0101")));
        sentHash = sha256(abi.encodePacked(h, sha256(hex"0a0102"))); // NearTonFixtures.bundleContent payloads
        return RunningHashVector(abi.encode(_bundle(_world(1), true, false)), _anchor(E1), _ctx(), bytes32(0));
    }

    function _wrongChainConfigVector() internal view override returns (bytes memory, bytes32) {
        return (_configProof(_world(1), NearTonFixtures.controlMessage("eip155:1", abi.encodePacked(SERVICE))), CHANNEL);
    }
}
