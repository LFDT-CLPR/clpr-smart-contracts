// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprVerifierComplianceTest} from "@test/verifiers/compliance/ClprVerifierComplianceTest.sol";
import {CardanoTestKit} from "@test/verifiers/evm/cardano/CardanoTestKit.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";

/// @title CardanoComplianceTest
/// @dev Shared IClprVerifier compliance suite against CardanoMithrilVerifier with synthetic but
///      cryptographically real Mithril certificates, MKMap proofs and Cardano encodings.
contract CardanoComplianceTest is ClprVerifierComplianceTest, CardanoTestKit {
    Network internal netA;
    Network internal netB;

    function setUp() public override {
        _initKit();
        netA = _network(100, 1, 4, 10);
        netB = _network(101, 2, 5, 10);
        ClprVerifierComplianceTest.setUp();
    }

    function _deployVerifier() internal view override returns (IClprVerifier) {
        return IClprVerifier(address(cv));
    }

    function _validConfig() internal view override returns (ConfigVector memory) {
        return ConfigVector({
            configProof: _config(netA, "cip34:0-1"),
            channelId: CHANNEL_ID,
            expectedChainId: "cip34:0-1",
            expectedServiceAddress: abi.encodePacked(SCRIPT)
        });
    }

    function _validBundle() internal view override returns (BundleVector memory) {
        Queue memory q = defaultQueue();
        return BundleVector({
            proofBytes: _encode(_world(netA, netB, q)),
            trustAnchor: _anchor(netA),
            channelContext: ctx(),
            expectedNextMessageId: q.nextMessageId,
            expectedPayloadCount: 1
        });
    }

    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        view
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        Queue memory q = defaultQueue();
        q.manifestCommitment = keccak256(committedPreimage);
        World memory w = _world(netA, netB, q);
        w.content = "";
        w.withManifest = true;
        w.manifest = carriedPreimage;
        return (_config(netA, "cip34:0-1"), CHANNEL_ID, _encode(w));
    }

    function _runningHashVector() internal view override returns (RunningHashVector memory) {
        Queue memory q = defaultQueue();
        q.sentRunningHash = sha256(abi.encodePacked(bytes32(0), sha256("hello cardano")));
        return RunningHashVector({
            proofBytes: _encode(_world(netA, netB, q)),
            trustAnchor: _anchor(netA),
            channelContext: ctx(),
            previousRunningHash: bytes32(0)
        });
    }

    function _wrongChainConfigVector() internal view override returns (bytes memory, bytes32) {
        return (_config(netA, "eip155:1"), CHANNEL_ID);
    }
}
