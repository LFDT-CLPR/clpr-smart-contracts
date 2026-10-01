// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprVerifierComplianceTest} from "@test/verifiers/compliance/ClprVerifierComplianceTest.sol";
import {CantonAttestedProofs} from "@test/helpers/CantonAttestedProofs.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {CantonAttestedVerifier} from "@hiero-ledger/clpr/verifiers/canton/CantonAttestedVerifier.sol";

/// @title CantonComplianceTest
/// @notice Runs the shared IClprVerifier compliance suite against CantonAttestedVerifier
///         (trust model: t-of-n CLPR operators).
contract CantonComplianceTest is ClprVerifierComplianceTest, CantonAttestedProofs {
    OperatorSet internal ops;
    CantonAttestedVerifier internal canton;
    CantonAttestedVerifier.Rotation[] internal noRotations;

    function setUp() public override {
        ops = _operators(1, 4, 3);
        super.setUp();
    }

    function _deployVerifier() internal override returns (IClprVerifier) {
        canton = _deploy(ops);
        return IClprVerifier(address(canton));
    }

    function _validConfig() internal view override returns (ConfigVector memory) {
        return ConfigVector({
            configProof: _configProof(canton, ops, noRotations, ops, 0, CHANNEL_ID, CANTON_CHAIN_ID, _serviceAddress()),
            channelId: CHANNEL_ID,
            expectedChainId: CANTON_CHAIN_ID,
            expectedServiceAddress: _serviceAddress()
        });
    }

    function _validBundle() internal view override returns (BundleVector memory) {
        bytes[] memory payloads = _samplePayloads(2);
        return BundleVector({
            proofBytes: _bundle(canton, ops, 0, noRotations, _head(2, _chain(0, payloads)), payloads, "", _firstN(3)),
            trustAnchor: abi.encode(_anchor(ops, 0)),
            channelContext: _channelContext(),
            expectedNextMessageId: 3,
            expectedPayloadCount: 2
        });
    }

    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        view
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        configProof = _validConfig().configProof;
        channelId = CHANNEL_ID;
        // Operators sign the committed bytes; the proof carries possibly different bytes.
        bytes32 digest = _manifestDigest(address(canton), 0, CHANNEL_ID, committedPreimage);
        manifestProof = abi.encode(
            CantonAttestedVerifier.ManifestProof({
                manifest: carriedPreimage, signatures: _sign(digest, ops, _firstN(3))
            })
        );
    }

    function _runningHashVector() internal view override returns (RunningHashVector memory) {
        bytes[] memory payloads = _samplePayloads(3);
        return RunningHashVector({
            proofBytes: _bundle(canton, ops, 0, noRotations, _head(3, _chain(0, payloads)), payloads, "", _firstN(3)),
            trustAnchor: abi.encode(_anchor(ops, 0)),
            channelContext: _channelContext(),
            previousRunningHash: bytes32(0)
        });
    }

    /// @dev A correctly signed config for a different Canton network id.
    function _wrongChainConfigVector() internal view override returns (bytes memory configProof, bytes32 channelId) {
        return
            (
                _configProof(canton, ops, noRotations, ops, 0, CHANNEL_ID, "canton:mainnet", _serviceAddress()),
                CHANNEL_ID
            );
    }
}
