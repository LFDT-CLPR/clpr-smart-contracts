// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ArcMalachiteVerifier} from "@hiero-ledger/clpr/verifiers/evm/arc/ArcMalachiteVerifier.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @dev Exposes internals of the production verifier; `stubEd25519` replaces only the external
///      Ed25519 call (synthetic tests), everything else is the production code path.
contract ArcMalachiteVerifierHarness is ArcMalachiteVerifier {
    bool public immutable STUB_ED25519;

    constructor(Profile memory p, bool stubEd25519) ArcMalachiteVerifier(p) {
        STUB_ED25519 = stubEd25519;
    }

    /// @dev Registry storage multiproof (RLP([nodes, paths])) → set hash.
    function deriveSetHash(bytes calldata proofItem, bytes32 registryRoot) external pure returns (bytes32) {
        bytes memory m = proofItem;
        return _deriveSetHash(Memory.asSlice(m), registryRoot);
    }

    /// @dev One light-client step from `anchor`; returns the next anchor and the state root.
    function step(bytes calldata stepRlp, bytes calldata anchor) external view returns (bytes memory, bytes32) {
        bytes memory m = stepRlp;
        (Anchor memory next, bytes32 stateRoot) = _step(_decodeAnchor(anchor), Memory.asSlice(m));
        return (_encodeAnchor(next), stateRoot);
    }

    function _verifyEd25519(bytes32 key, bytes memory message, bytes memory sig) internal view override returns (bool) {
        if (!STUB_ED25519) return super._verifyEd25519(key, message, sig);
        // Stub: a signature is "valid" iff it equals keccak(key ‖ message) ‖ keccak(message ‖ key).
        return keccak256(sig)
            == keccak256(
            abi.encodePacked(keccak256(abi.encodePacked(key, message)), keccak256(abi.encodePacked(message, key)))
        );
    }
}
