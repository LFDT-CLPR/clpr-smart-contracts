// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {EvmCertifiedStateCompliance} from "@test/verifiers/compliance/EvmCertifiedStateCompliance.sol";
import {ArcMalachiteVerifierHarness} from "@test/verifiers/evm/arc/ArcMalachiteVerifierHarness.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ArcMalachiteVerifier} from "@hiero-ledger/clpr/verifiers/evm/arc/ArcMalachiteVerifier.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @title ArcComplianceTest
/// @dev ClprVerifierComplianceTest adapter (via ClprEvmStorageComplianceTest) for ArcMalachiteVerifier.
///      Each vector certifies a synthetic Arc block H whose parent H-1 holds the ValidatorRegistry
///      account with the anchored storage root, signed by a one-validator set. The production code
///      path runs unchanged except the Ed25519 check, which the harness stubs (pure-Solidity Ed25519
///      signing is not available in Foundry); the live-data suite covers real Ed25519.
contract ArcComplianceTest is EvmCertifiedStateCompliance {
    address internal constant REGISTRY = 0x3600000000000000000000000000000000000002;
    bytes32 internal constant REGISTRY_ROOT = bytes32(uint256(0x5e75e7));
    bytes32 internal constant VALIDATOR_KEY = keccak256("arc-compliance-validator");
    uint64 internal constant BOOTSTRAP_HEIGHT = 1;

    ArcMalachiteVerifierHarness internal arc;

    function _setHash() internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(VALIDATOR_KEY, uint64(1)));
    }

    function _deployVerifier() internal override returns (IClprVerifier) {
        arc = new ArcMalachiteVerifierHarness(
            ArcMalachiteVerifier.Profile({
                chainId: _chainId(),
                ed25519Verifier: address(0xed),
                registry: REGISTRY,
                bootstrapSetHash: _setHash(),
                bootstrapRegistryRoot: REGISTRY_ROOT,
                bootstrapHeight: BOOTSTRAP_HEIGHT
            }),
            true
        );
        return IClprVerifier(address(arc));
    }

    function _chainId() internal pure override returns (string memory) {
        return "5042002";
    }

    function _otherChainId() internal pure override returns (string memory) {
        return "5042003";
    }

    function _anchor() internal pure override returns (bytes memory) {
        return abi.encodePacked(_setHash(), REGISTRY_ROOT, BOOTSTRAP_HEIGHT);
    }

    function _header(bytes32 parentHash, bytes32 stateRoot, uint256 number) internal pure returns (bytes memory) {
        bytes[] memory h = new bytes[](15);
        h[0] = RLP.encode(parentHash);
        h[1] = RLP.encode(bytes32(0));
        h[2] = RLP.encode(address(0));
        h[3] = RLP.encode(stateRoot);
        h[4] = RLP.encode(bytes32(0));
        h[5] = RLP.encode(bytes32(0));
        h[6] = RLP.encode(new bytes(256));
        h[7] = RLP.encode(uint256(0));
        h[8] = RLP.encode(number);
        h[9] = RLP.encode(uint256(0));
        h[10] = RLP.encode(uint256(0));
        h[11] = RLP.encode(uint256(0));
        h[12] = RLP.encode(new bytes(0));
        h[13] = RLP.encode(bytes32(0));
        h[14] = RLP.encode(new bytes(8));
        return RLP.encode(h);
    }

    /// @dev step = [header H, parent H-1, round, sigs, validators, parentRegistryAccountProof, rotation=[]].
    function _finality(bytes32 stateRoot) internal view override returns (bytes[] memory f) {
        (bytes32 parentState, bytes memory registryProof) =
            _buildSyntheticAccountProof(REGISTRY, REGISTRY_ROOT, bytes32(uint256(0xC0DE2)));
        bytes memory parent = _header(bytes32(0), parentState, 1);
        bytes memory header = _header(keccak256(parent), stateRoot, 2);
        bytes memory m =
            arc.precommitSignBytes(2, 0, keccak256(header), bytes20(keccak256(abi.encodePacked(VALIDATOR_KEY))));
        bytes memory sig = abi.encodePacked(
            keccak256(abi.encodePacked(VALIDATOR_KEY, m)), keccak256(abi.encodePacked(m, VALIDATOR_KEY))
        );

        bytes[] memory pair = new bytes[](2);
        pair[0] = RLP.encode(uint256(0));
        pair[1] = RLP.encode(sig);
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = RLP.encode(pair);
        bytes[] memory val = new bytes[](2);
        val[0] = RLP.encode(abi.encodePacked(VALIDATOR_KEY));
        val[1] = RLP.encode(uint256(1));
        bytes[] memory vals = new bytes[](1);
        vals[0] = RLP.encode(val);

        bytes[] memory step = new bytes[](7);
        step[0] = RLP.encode(header);
        step[1] = RLP.encode(parent);
        step[2] = RLP.encode(uint256(0));
        step[3] = RLP.encode(sigs);
        step[4] = RLP.encode(vals);
        step[5] = registryProof;
        step[6] = RLP.encode(new bytes[](0));

        f = new bytes[](2);
        f[0] = RLP.encode(step);
        f[1] = RLP.encode(new bytes[](0)); // no hops
    }
}
