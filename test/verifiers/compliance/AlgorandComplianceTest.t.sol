// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprVerifierComplianceTest} from "@test/verifiers/compliance/ClprVerifierComplianceTest.sol";
import {AlgorandTestKit} from "@test/verifiers/evm/algorand/AlgorandTestKit.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";

/// @title AlgorandComplianceTest
/// @dev Shared IClprVerifier compliance suite against AlgorandStateProofVerifier with synthetic worlds
///      (real Algorand encodings; the interval is bootstrapped, so no state-proof signatures).
contract AlgorandComplianceTest is ClprVerifierComplianceTest, AlgorandTestKit {
    string internal constant CHAIN = "algorand:wGHE2Pwdvd7S12BL5FaOP20EGYesN73k";

    function setUp() public override {
        _initKit();
        root = _install(_world(defaultQueue()));
        ClprVerifierComplianceTest.setUp();
    }

    function _deployVerifier() internal view override returns (IClprVerifier) {
        return IClprVerifier(address(av));
    }

    function _validConfig() internal override returns (ConfigVector memory) {
        return ConfigVector({
            configProof: _config(_world(defaultQueue()), CHAIN),
            channelId: CHANNEL_ID,
            expectedChainId: CHAIN,
            expectedServiceAddress: abi.encodePacked(APP_ID)
        });
    }

    function _validBundle() internal override returns (BundleVector memory) {
        World memory w = _world(defaultQueue());
        bytes32 r = _install(w);
        return BundleVector({
            proofBytes: _encode(w),
            trustAnchor: anchorOf(r),
            channelContext: ctx(),
            expectedNextMessageId: w.q.nextMessageId,
            expectedPayloadCount: 1
        });
    }

    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        Queue memory q = defaultQueue();
        q.manifestCommitment = keccak256(committedPreimage);
        World memory w = _world(q);
        w.content = "";
        w.withManifest = true;
        w.manifest = carriedPreimage;
        configProof = _config(w, CHAIN);
        return (configProof, CHANNEL_ID, _encode(w));
    }

    function _runningHashVector() internal override returns (RunningHashVector memory) {
        Queue memory q = defaultQueue();
        q.sentRunningHash = sha256(abi.encodePacked(bytes32(0), sha256("hello algorand")));
        World memory w = _world(q);
        bytes32 r = _install(w);
        return RunningHashVector({
            proofBytes: _encode(w), trustAnchor: anchorOf(r), channelContext: ctx(), previousRunningHash: bytes32(0)
        });
    }

    function _wrongChainConfigVector() internal override returns (bytes memory, bytes32) {
        return (_config(_world(defaultQueue()), "eip155:1"), CHANNEL_ID);
    }
}
