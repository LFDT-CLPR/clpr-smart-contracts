// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprVerifierComplianceTest} from "@test/verifiers/compliance/ClprVerifierComplianceTest.sol";
import {MixinTestBuilder} from "@test/verifiers/evm/mixin/MixinTestBuilder.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";

/// @title MixinComplianceTest
/// @dev IClprVerifier compliance for MixinKernelVerifier over synthetic CoSi-signed kernel snapshots
///      and record threads (the encodings of the live fixture; see test/verifiers/evm/mixin).
contract MixinComplianceTest is ClprVerifierComplianceTest, MixinTestBuilder {
    function _deployVerifier() internal override returns (IClprVerifier) {
        return IClprVerifier(address(_deployMixin()));
    }

    function _validConfig() internal view override returns (ConfigVector memory) {
        return ConfigVector({
            configProof: _configProof("mixin:mainnet", ""),
            channelId: CHANNEL,
            expectedChainId: "mixin:mainnet",
            expectedServiceAddress: abi.encodePacked(APP)
        });
    }

    function _wrongChainConfigVector() internal view override returns (bytes memory, bytes32) {
        return (_configProof("mixin:testnet", ""), CHANNEL);
    }

    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        view
        override
        returns (bytes memory, bytes32, bytes memory)
    {
        return (_configProof("mixin:mainnet", committedPreimage), CHANNEL, carriedPreimage);
    }

    function _validBundle() internal view override returns (BundleVector memory) {
        (bytes memory content, bytes32 running) = _content(2);
        (bytes memory proof,) = _bundleProof(_defaults(content, running, 3));
        return BundleVector({
            proofBytes: proof,
            trustAnchor: _anchor(),
            channelContext: _context(),
            expectedNextMessageId: 3,
            expectedPayloadCount: 2
        });
    }

    function _runningHashVector() internal view override returns (RunningHashVector memory) {
        (bytes memory content, bytes32 running) = _content(3);
        (bytes memory proof,) = _bundleProof(_defaults(content, running, 4));
        return RunningHashVector({
            proofBytes: proof, trustAnchor: _anchor(), channelContext: _context(), previousRunningHash: bytes32(0)
        });
    }
}
