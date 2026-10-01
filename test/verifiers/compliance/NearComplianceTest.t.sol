// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprVerifierComplianceTest} from "@test/verifiers/compliance/ClprVerifierComplianceTest.sol";
import {NearVerifierFixture} from "@test/verifiers/evm/neartons/NearVerifier.t.sol";
import {NearTonFixtures} from "@test/verifiers/evm/neartons/NearTonTestKit.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {NearVerifier} from "@hiero-ledger/clpr/verifiers/evm/neartons/NearVerifier.sol";
import {NearLightClient} from "@hiero-ledger/clpr/libraries/proof/near/NearLightClient.sol";

/// @title NearComplianceTest
/// @notice Compliance adapter binding `NearVerifier` to the shared verifier compliance suite, on the
///         synthetic NEAR world of {NearVerifierFixture} (light-client block, shard roots, state trie).
///         Only Ed25519 is replaced by a message-binding stub; the real curve and the real NEAR
///         formats are covered by NearLive.t.sol.
contract NearComplianceTest is ClprVerifierComplianceTest, NearVerifierFixture {
    function setUp() public override(ClprVerifierComplianceTest, NearVerifierFixture) {
        NearVerifierFixture.setUp();
        verifier = _deployVerifier();
    }

    function _deployVerifier() internal view override returns (IClprVerifier) {
        return IClprVerifier(address(v));
    }

    function _configProof(bytes memory controlMessage) internal view returns (bytes memory) {
        NearVerifier.ConfigProof memory p;
        (bytes32 root, bytes[] memory cpath) = _trie(record, 2);
        p.blocks = new NearLightClient.Block[](1);
        p.blocks[0] = _block(E1, E2, sha256(prodB), prodA, keysA, _merkle(root), _signers(2, 3));
        p.shards = _shards(root);
        p.configNodes = cpath;
        p.controlMessage = controlMessage;
        return abi.encode(p);
    }

    function _validConfig() internal view override returns (ConfigVector memory) {
        return ConfigVector(_configProof(control), CHANNEL, CHAIN, SERVICE);
    }

    function _validBundle() internal view override returns (BundleVector memory) {
        return BundleVector(abi.encode(_bundle(false)), _anchor(E1), _ctx(), 7, 2);
    }

    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        manifest = committedPreimage; // the trie's "m" entry commits to this preimage
        configProof = _configProof(control);
        channelId = CHANNEL;
        (, bytes[] memory mpath) = _trie(record, 1);
        manifestProof = abi.encode(NearVerifier.ManifestProof(mpath, carriedPreimage));
    }

    function _runningHashVector() internal override returns (RunningHashVector memory) {
        bytes32 h = sha256(abi.encodePacked(bytes32(0), sha256(hex"0a0101")));
        h = sha256(abi.encodePacked(h, sha256(hex"0a0102"))); // NearTonFixtures.bundleContent payloads
        record = abi.encodePacked(uint8(1), _le64(7), _le64(5), h, keccak256("recv"), _le64(3));
        return RunningHashVector(abi.encode(_bundle(false)), _anchor(E1), _ctx(), bytes32(0));
    }

    function _wrongChainConfigVector() internal view override returns (bytes memory, bytes32) {
        return (_configProof(NearTonFixtures.controlMessage("near:mainnet", SERVICE)), CHANNEL);
    }
}
