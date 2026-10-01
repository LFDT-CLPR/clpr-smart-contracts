// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {SubstrateEvmComplianceBase} from "@test/verifiers/compliance/SubstrateEvmComplianceBase.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {Blake2b} from "@hiero-ledger/clpr/libraries/proof/substrate/Blake2b.sol";
import {ScaleCodec} from "@hiero-ledger/clpr/libraries/proof/substrate/ScaleCodec.sol";
import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {GrandpaLightClient} from "@hiero-ledger/clpr/verifiers/evm/grandpa/GrandpaLightClient.sol";
import {GrandpaVerifier} from "@hiero-ledger/clpr/verifiers/evm/grandpa/GrandpaVerifier.sol";

/// @dev Message-binding stand-in for the Ed25519 curve operation (forge 1.5 has no ed25519 signing
///      cheatcode, and the vectors are built on the fly). A "signature" is sha256(key ‖ message) ‖
///      sha256(message ‖ key), so any change to a signed byte, the key or the authority index still
///      fails. The real curve is exercised by GrandpaVerifier.t.sol (synthetic ed25519 signatures)
///      and by the live Bittensor spec (test/e2e/tests/verifiers/grandpa-live.spec.ts).
contract BindingEd25519Stub is IEd25519Verifier {
    function verify(bytes32 pubKey, bytes calldata message, bytes calldata signature) external pure returns (bool) {
        return keccak256(signature)
            == keccak256(
            abi.encodePacked(sha256(abi.encodePacked(pubKey, message)), sha256(abi.encodePacked(message, pubKey)))
        );
    }
}

/// @title GrandpaComplianceTest
/// @notice ClprVerifierComplianceTest adapter (via ClprEvmStorageComplianceTest and
///         SubstrateEvmComplianceBase) for GrandpaVerifier. Every bundle carries a real GRANDPA
///         commit: a header over the synthetic Frontier state, precommitted by a one-authority set
///         through the full GrandpaLib path (header hash, set binding, threshold, message layout),
///         with the curve operation replaced by {BindingEd25519Stub}.
contract GrandpaComplianceTest is SubstrateEvmComplianceBase {
    string internal constant CHAIN_ID = "eip155:964";
    uint32 internal constant BLOCK = 10;
    uint64 internal constant ROUND = 1;

    bytes32 internal constant AUTHORITY_KEY = keccak256("grandpa-compliance-authority");
    bytes internal authorities;

    function _deployVerifier() internal override returns (IClprVerifier) {
        authorities = abi.encodePacked(AUTHORITY_KEY, hex"0100000000000000"); // weight 1 (u64 LE)
        BindingEd25519Stub ed = new BindingEd25519Stub();
        return
            IClprVerifier(address(new GrandpaVerifier(address(ed), EVM_PALLET, CHAIN_ID, 0, keccak256(authorities), 1)));
    }

    function _chainId() internal pure override returns (string memory) {
        return CHAIN_ID;
    }

    function _anchor() internal view override returns (bytes memory) {
        return abi.encodePacked(uint64(0), keccak256(authorities), uint32(1));
    }

    function _steps(bytes32 stateRoot) internal view returns (GrandpaLightClient.Step[] memory steps) {
        bytes memory header = _header(keccak256("parent"), BLOCK, stateRoot);
        bytes32 h = Blake2b.hash256(header);
        bytes memory message =
            abi.encodePacked(uint8(1), h, ScaleCodec.le32(BLOCK), ScaleCodec.le64(ROUND), ScaleCodec.le64(0));
        bytes memory sig = abi.encodePacked(
            sha256(abi.encodePacked(AUTHORITY_KEY, message)), sha256(abi.encodePacked(message, AUTHORITY_KEY))
        );
        steps = new GrandpaLightClient.Step[](1);
        steps[0].headers = new bytes[](1);
        steps[0].headers[0] = header;
        steps[0].round = ROUND;
        steps[0].votes = abi.encodePacked(uint16(0), h, uint32(BLOCK), sig);
        steps[0].ancestry = new bytes[](0);
        steps[0].authorities = authorities;
    }

    function _bundleProof(bytes32 stateRoot, bytes[] memory nodes, bytes memory content)
        internal
        view
        override
        returns (bytes memory)
    {
        return abi.encode(GrandpaVerifier.BundleProof(_steps(stateRoot), nodes, false, content, ""));
    }

    function _configProof(bytes32 stateRoot, bytes[] memory nodes, bytes memory ledgerConfig)
        internal
        view
        override
        returns (bytes memory)
    {
        return abi.encode(GrandpaVerifier.ConfigProof(_steps(stateRoot), nodes, ledgerConfig));
    }
}
