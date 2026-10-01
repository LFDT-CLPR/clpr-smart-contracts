// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprVerifierComplianceTest} from "@test/verifiers/compliance/ClprVerifierComplianceTest.sol";
import {HyperEvmTestBuilder} from "@test/verifiers/evm/hyperliquid/HyperEvmTestBuilder.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {HyperEvmVerifier} from "@hiero-ledger/clpr/verifiers/evm/hyperliquid/HyperEvmVerifier.sol";

/// @title HyperEvmComplianceTest
/// @dev IClprVerifier compliance for HyperEvmVerifier over synthetic attested HyperEVM blocks whose
///      receipts carry the ClprHyperEvmBeacon record (the encodings of the live fixture).
contract HyperEvmComplianceTest is ClprVerifierComplianceTest, HyperEvmTestBuilder {
    function _deployVerifier() internal override returns (IClprVerifier) {
        return IClprVerifier(address(_deployHyper()));
    }

    function _validConfig() internal view override returns (ConfigVector memory) {
        return ConfigVector({
            configProof: _configProof("eip155:999", ""),
            channelId: CHANNEL,
            expectedChainId: "eip155:999",
            expectedServiceAddress: abi.encodePacked(SERVICE)
        });
    }

    function _wrongChainConfigVector() internal view override returns (bytes memory, bytes32) {
        return (_configProof("eip155:998", ""), CHANNEL);
    }

    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        view
        override
        returns (bytes memory, bytes32, bytes memory)
    {
        return (_configProof("eip155:999", committedPreimage), CHANNEL, carriedPreimage);
    }

    function _validBundle() internal view override returns (BundleVector memory) {
        (bytes memory content, bytes32 running) = _content(2);
        return BundleVector({
            proofBytes: _bundleProof(_defaultBundle(content, running, 3)),
            trustAnchor: _anchor(),
            channelContext: _context(),
            expectedNextMessageId: 3,
            expectedPayloadCount: 2
        });
    }

    function _runningHashVector() internal view override returns (RunningHashVector memory) {
        (bytes memory content, bytes32 running) = _content(3);
        return RunningHashVector({
            proofBytes: _bundleProof(_defaultBundle(content, running, 4)),
            trustAnchor: _anchor(),
            channelContext: _context(),
            previousRunningHash: bytes32(0)
        });
    }
}
