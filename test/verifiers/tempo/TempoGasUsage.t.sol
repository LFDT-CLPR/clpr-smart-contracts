// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {TempoSyntheticProofs} from "@test/helpers/TempoSyntheticProofs.sol";
import {TempoVerifier} from "@hiero-ledger/clpr/verifiers/evm/tempo/TempoVerifier.sol";
import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";

/// @notice Gas baselines for TempoVerifier (`script/gas/baselines.yml`). Each test makes one
///         success-path call. The baselines read the gas report columns: `min` is the steady
///         state, `max` is a single rotation.
contract TempoGasUsageTest is TempoSyntheticProofs {
    uint64 internal constant L = 100;
    address internal constant SERVICE = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;
    bytes32 internal constant CODE_HASH = bytes32(uint256(0xC0DE));
    bytes32 internal constant CHANNEL_ID = bytes32(uint256(0xC0FFEE));

    TempoVerifier internal verifier;
    uint256 internal sk1;
    uint256 internal sk2;
    bytes internal pk1;
    bytes internal pk2;

    function setUp() public virtual {
        verifier = new TempoVerifier();
        sk1 = _testKey("tempo-gas-1");
        sk2 = _testKey("tempo-gas-2");
        pk1 = _blsPublicKey(sk1);
        pk2 = _blsPublicKey(sk2);
    }

    /// @dev Steady state: one certificate, 5 channel slots, no rotations.
    function test_gas_verifyBundle_success() public view {
        (bytes memory proof, bytes memory anchor) = _steady();
        verifier.verifyBundle(proof, anchor, _ctx());
    }

    /// @dev One rotation: the boundary block of epoch 3 names key 2, the current block is in epoch 4.
    function test_gas_verifyBundle_rotation() public view {
        (bytes memory proof, bytes memory anchor) = _rotation();
        verifier.verifyBundle(proof, anchor, _ctx());
    }

    function test_gas_verifyConfig_success() public view {
        verifier.verifyConfig(_config(), CHANNEL_ID, "");
    }

    // ── scenarios ────────────────────────────────────────────────────────────

    function _steady() internal view returns (bytes memory proof, bytes memory anchor) {
        proof = _bundleAt(sk1, 250, new bytes[](0));
        anchor = _tempoAnchor(CODE_HASH, L, 249, pk1);
    }

    function _rotation() internal view returns (bytes memory proof, bytes memory anchor) {
        bytes[] memory rotations = new bytes[](1);
        rotations[0] = _boundaryRotation(sk1, 3, pk2);
        proof = _bundleAt(sk2, 4 * L + 1, rotations);
        anchor = _tempoAnchor(CODE_HASH, L, 3 * L, pk1);
    }

    function _config() internal view returns (bytes memory) {
        bytes memory header = _tempoHeader(5, bytes32(0), "", true);
        ConfigParts memory parts;
        parts.service = SERVICE;
        parts.chainId = "eip155:4217";
        parts.codeHash = CODE_HASH;
        parts.epochLength = L;
        parts.keyCompressed = ClprBls12381.compressG2(pk1);
        parts.keyUncompressed = pk1;
        parts.header = header;
        parts.cert = _certify(sk1, L, header, 5, 9);
        parts.throttles = _defaultThrottles();
        return _encodeConfigProof(parts);
    }

    function _bundleAt(uint256 sk, uint64 number, bytes[] memory rotations) internal view returns (bytes memory) {
        BundleParts memory parts;
        bytes32 storageRoot;
        (storageRoot, parts.storageProof) = _buildChannelStorageProof(CHANNEL_ID);
        bytes32 stateRoot;
        (stateRoot, parts.accountProof) = _buildSyntheticAccountProof(SERVICE, storageRoot, CODE_HASH);
        parts.header = _tempoHeader(number, stateRoot, "", true);
        parts.cert = _certify(sk, L, parts.header, number, 42);
        parts.rotations = rotations;
        parts.content = "";
        return _encodeBundle(parts);
    }

    function _boundaryRotation(uint256 sk, uint64 e, bytes memory nextKey) internal view returns (bytes memory) {
        uint64 number = (e + 1) * L - 1;
        bytes memory header =
            _tempoHeader(number, bytes32(0), _dkgOutcome(e + 1, ClprBls12381.compressG2(nextKey)), true);
        return _encodeRotation(header, _certify(sk, L, header, number, 10), nextKey);
    }

    function _ctx() internal pure returns (bytes memory) {
        return _tempoChannelContext(CHANNEL_ID, SERVICE);
    }
}
