// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprVerifierComplianceTest} from "@test/verifiers/compliance/ClprVerifierComplianceTest.sol";
import {TonVerifierFixture} from "@test/verifiers/evm/neartons/TonVerifier.t.sol";
import {NearTonFixtures} from "@test/verifiers/evm/neartons/NearTonTestKit.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {TonVerifier} from "@hiero-ledger/clpr/verifiers/evm/neartons/TonVerifier.sol";

/// @title TonComplianceTest
/// @notice Compliance adapter binding `TonVerifier` to the shared verifier compliance suite, on the
///         synthetic TON world of {TonVerifierFixture} (Simplex-signed masterchain block, state and
///         account BoCs). Only Ed25519 is replaced by a message-binding stub; the real curve and the
///         real TON formats are covered by TonLive.t.sol.
contract TonComplianceTest is ClprVerifierComplianceTest, TonVerifierFixture {
    function setUp() public override(ClprVerifierComplianceTest, TonVerifierFixture) {
        TonVerifierFixture.setUp();
        verifier = _deployVerifier();
    }

    function _deployVerifier() internal view override returns (IClprVerifier) {
        return IClprVerifier(address(v));
    }

    function _configProof(bytes memory controlMessage) internal view returns (bytes memory) {
        TonVerifier.ConfigProof memory p;
        p.validators = valsA;
        p.keyBlocks = new TonVerifier.McBlock[](0);
        (p.block, p.state) = _chain(7, KEY0, keysA, 1);
        p.controlMessage = controlMessage;
        return abi.encode(p);
    }

    function _validConfig() internal view override returns (ConfigVector memory) {
        return ConfigVector(_configProof(control), CHANNEL, CHAIN, _svc());
    }

    function _validBundle() internal view override returns (BundleVector memory) {
        return BundleVector(abi.encode(_bundle(1)), _anchor(KEY0, valsA), _ctx(), 7, 2);
    }

    /// @dev TonVerifier's manifest proof is the preimage itself: the commitment it must match is
    ///      `manifest_commitment` of the same proven account data as the configuration.
    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        manifest = committedPreimage;
        configProof = _configProof(control);
        channelId = CHANNEL;
        manifestProof = carriedPreimage;
    }

    function _runningHashVector() internal override returns (RunningHashVector memory) {
        bytes32 h = sha256(abi.encodePacked(bytes32(0), sha256(hex"0a0101")));
        sentHash = sha256(abi.encodePacked(h, sha256(hex"0a0102"))); // NearTonFixtures.bundleContent payloads
        return RunningHashVector(abi.encode(_bundle(1)), _anchor(KEY0, valsA), _ctx(), bytes32(0));
    }

    function _wrongChainConfigVector() internal view override returns (bytes memory, bytes32) {
        return (_configProof(NearTonFixtures.controlMessage("ton:mainnet", _svc())), CHANNEL);
    }
}
