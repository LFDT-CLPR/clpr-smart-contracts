// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprVerifierComplianceTest} from "@test/verifiers/compliance/ClprVerifierComplianceTest.sol";
import {IcpTestKit} from "@test/verifiers/icpmvx/IcpTestKit.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {IcpVerifier} from "@hiero-ledger/clpr/verifiers/icpmvx/IcpVerifier.sol";

/// @title IcpComplianceTest
/// @notice Compliance adapter binding `IcpVerifier` to the shared verifier suite on the synthetic
///         Internet Computer of {IcpTestKit}: real BLS12-381 signatures (EIP-2537), real CBOR hash
///         trees, a delegated certificate and a CLPR canister witness.
contract IcpComplianceTest is ClprVerifierComplianceTest, IcpTestKit {
    function setUp() public override(ClprVerifierComplianceTest, IcpTestKit) {
        IcpTestKit.setUp();
        verifier = _deployVerifier();
    }

    function _deployVerifier() internal view override returns (IClprVerifier) {
        return IClprVerifier(address(v));
    }

    function _validConfig() internal view override returns (ConfigVector memory) {
        return ConfigVector(abi.encode(_configProofStruct()), CHANNEL, CHAIN, CANISTER);
    }

    function _validBundle() internal view override returns (BundleVector memory) {
        return BundleVector(abi.encode(_bundle(false)), _anchor(), _ctx(), 7, 2);
    }

    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        manifest = committedPreimage; // the witness's clpr/manifest leaf commits to this preimage
        configProof = abi.encode(_configProofStruct());
        channelId = CHANNEL;
        manifestProof = abi.encode(IcpVerifier.ManifestProof(carriedPreimage));
    }

    function _runningHashVector() internal view override returns (RunningHashVector memory) {
        // IcpTestKit's record carries sha256-chain(0, [0a0101, 0a0102]), the payloads of _bundleContent
        return RunningHashVector(abi.encode(_bundle(false)), _anchor(), _ctx(), bytes32(0));
    }

    function _wrongChainConfigVector() internal override returns (bytes memory, bytes32) {
        control = _control("icp:other", CANISTER);
        return (abi.encode(_configProofStruct()), CHANNEL);
    }
}
