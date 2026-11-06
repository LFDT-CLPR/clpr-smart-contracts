// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {TempoSyntheticProofs} from "@test/helpers/TempoSyntheticProofs.sol";
import {TempoVerifier} from "@hiero-ledger/clpr/verifiers/evm/tempo/TempoVerifier.sol";
import {ClprTempoBls} from "@hiero-ledger/clpr/libraries/proof/tempo/ClprTempoBls.sol";
import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @title TempoLocalnetTest
/// @notice Real data from the tools/tempo-localnet network: a real channel, real `eth_getProof`
///         output, real certificates, and a real key rotation. Fixture: fixtures/localnet.json.
contract TempoLocalnetTest is TempoSyntheticProofs {
    string internal constant FIXTURE = "test/verifiers/tempo/fixtures/localnet.json";

    struct Certified {
        uint64 number;
        uint64 epoch;
        bytes headerRlp;
        CertificateBytes cert;
    }

    struct Key {
        bytes compressed;
        bytes uncompressed;
    }

    string internal json;
    TempoVerifier internal v;
    address internal service;
    bytes32 internal channelId;
    uint64 internal L;
    bytes32 internal codeHash;
    Key internal oldKey;
    Key internal newKey;
    Certified internal config;
    Certified internal rotation;
    Certified internal current;
    Certified internal steadyAnchor;
    bytes internal accountProof;
    bytes internal storageProof;

    function setUp() public {
        v = new TempoVerifier();
        json = vm.readFile(FIXTURE);
        service = vm.parseJsonAddress(json, ".service");
        channelId = vm.parseJsonBytes32(json, ".channelId");
        L = uint64(vm.parseJsonUint(json, ".epochLength"));
        codeHash = vm.parseJsonBytes32(json, ".codeHash");
        oldKey = _key(".oldKey");
        newKey = _key(".newKey");
        config = _certified(".config");
        rotation = _certified(".rotation");
        current = _certified(".current");
        steadyAnchor = _certified(".steadyAnchor");
        accountProof = _accountProofRlp();
        storageProof = _storageProofRlp();
    }

    // ── The real rotation, end to end ───────────────────────────────────────

    function test_localnet_configUnderOldKey() public view {
        (,,,,, bytes memory anchor, bytes memory anchorId,) = v.verifyConfig(_configProof(), channelId, "");
        (bytes32 ch, uint64 epochLength, uint64 anchorBlock, bytes memory identity) =
            abi.decode(anchor, (bytes32, uint64, uint64, bytes));
        assertEq(ch, codeHash);
        assertEq(epochLength, L);
        assertEq(anchorBlock, config.number);
        assertEq(identity, oldKey.uncompressed, "anchor holds the pre-rotation key");
        assertEq(anchorId, abi.encodePacked(config.number));
        assertLt(config.epoch, rotation.epoch + 1, "config block precedes the rotation");
    }

    function test_localnet_bundleAcrossRotation() public view {
        assertEq(rotation.number + 1, rotation.epoch * L + L, "rotation is the last block of its epoch");
        assertGt(current.number, rotation.number, "current block is after the boundary");
        // Later epochs ran reshares, which keep the key. One rotation is enough.
        assertGt(current.epoch, rotation.epoch, "current block is in an epoch under the new key");

        bytes[] memory rotations = new bytes[](1);
        rotations[0] = _encodeRotation(rotation.headerRlp, rotation.cert, newKey.uncompressed);
        (
            ClprTypes.QueueMetadata memory metadata,
            bytes[] memory payloads,
            bytes memory newAnchor,
            bytes memory newAnchorId,
        ) = v.verifyBundle(_bundle(current, rotations), _anchor(config.number, oldKey.uncompressed), _ctx());

        // Real channel state: active, nothing sent.
        assertEq(uint8(metadata.state), uint8(ClprTypes.ChannelStatus.ACTIVE));
        assertEq(metadata.nextMessageId, 1);
        assertEq(metadata.receivedMessageId, 0);
        assertEq(payloads.length, 0);

        (,, uint64 anchorBlock, bytes memory identity) = abi.decode(newAnchor, (bytes32, uint64, uint64, bytes));
        assertEq(identity, newKey.uncompressed, "anchor rotated to the post-DKG key");
        assertEq(anchorBlock, current.number);
        assertEq(newAnchorId, abi.encodePacked(current.number));
    }

    function test_localnet_steadyStateUnderNewKey() public view {
        (ClprTypes.QueueMetadata memory metadata,, bytes memory newAnchor,,) =
            v.verifyBundle(_bundle(current, new bytes[](0)), _anchor(steadyAnchor.number, newKey.uncompressed), _ctx());
        assertEq(metadata.nextMessageId, 1);
        assertEq(newAnchor.length, 0, "no rotation crossed");
    }

    function test_localnet_missingRotationIsRejected() public {
        bytes memory bundle = _bundle(current, new bytes[](0));
        bytes memory anchor = _anchor(config.number, oldKey.uncompressed);
        vm.expectRevert(ClprTempoBls.BlsSignatureInvalid.selector);
        v.verifyBundle(bundle, anchor, _ctx());
    }

    function test_localnet_oldKeyCannotSignNewEpoch() public {
        bytes memory bundle = _bundle(current, new bytes[](0));
        bytes memory anchor = _anchor(steadyAnchor.number, oldKey.uncompressed);
        vm.expectRevert(ClprTempoBls.BlsSignatureInvalid.selector);
        v.verifyBundle(bundle, anchor, _ctx());
    }

    function test_localnet_boundaryCertifiedByOldKeyOnly() public view {
        // The keys differ, and both compress to the committed bytes.
        assertTrue(keccak256(oldKey.compressed) != keccak256(newKey.compressed), "full DKG changed the key");
        assertEq(ClprBls12381.compressG2(newKey.uncompressed), newKey.compressed);
        assertEq(ClprBls12381.compressG2(oldKey.uncompressed), oldKey.compressed);
    }

    // ── fixture decoding ────────────────────────────────────────────────────

    function _key(string memory path) internal view returns (Key memory k) {
        k.compressed = vm.parseJsonBytes(json, string.concat(path, ".keyCompressed"));
        k.uncompressed = vm.parseJsonBytes(json, string.concat(path, ".keyUncompressed"));
    }

    function _certified(string memory path) internal view returns (Certified memory c) {
        c.number = uint64(vm.parseJsonUint(json, string.concat(path, ".number")));
        c.epoch = uint64(vm.parseJsonUint(json, string.concat(path, ".epoch")));
        c.headerRlp = vm.parseJsonBytes(json, string.concat(path, ".headerRlp"));
        c.cert.proposal = vm.parseJsonBytes(json, string.concat(path, ".proposal"));
        c.cert.sigCompressed = vm.parseJsonBytes(json, string.concat(path, ".sigCompressed"));
        c.cert.sigUncompressed = vm.parseJsonBytes(json, string.concat(path, ".sigUncompressed"));
    }

    /// @dev Account proof nodes as an RLP list.
    function _accountProofRlp() internal view returns (bytes memory) {
        bytes[] memory nodes = vm.parseJsonBytesArray(json, ".accountProof");
        bytes[] memory items = new bytes[](nodes.length);
        for (uint256 i = 0; i < nodes.length; i++) {
            items[i] = RLP.encode(nodes[i]);
        }
        return RLP.encode(items);
    }

    /// @dev Storage proof entries as RLP([[slotKey, [nodes]], ...]).
    function _storageProofRlp() internal view returns (bytes memory) {
        uint256 n;
        while (vm.keyExistsJson(json, string.concat(".storageProof[", vm.toString(n), "].key"))) {
            n++;
        }
        bytes[] memory entries = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            string memory base = string.concat(".storageProof[", vm.toString(i), "]");
            bytes[] memory nodes = vm.parseJsonBytesArray(json, string.concat(base, ".proof"));
            bytes[] memory nodeItems = new bytes[](nodes.length);
            for (uint256 j = 0; j < nodes.length; j++) {
                nodeItems[j] = RLP.encode(nodes[j]);
            }
            bytes[] memory entry = new bytes[](2);
            entry[0] = RLP.encode(abi.encodePacked(vm.parseJsonBytes32(json, string.concat(base, ".key"))));
            entry[1] = RLP.encode(nodeItems);
            entries[i] = RLP.encode(entry);
        }
        return RLP.encode(entries);
    }

    // ── proof assembly ──────────────────────────────────────────────────────

    function _configProof() internal view returns (bytes memory) {
        ConfigParts memory parts;
        parts.service = service;
        parts.chainId = "eip155:1337";
        parts.codeHash = codeHash;
        parts.epochLength = L;
        parts.keyCompressed = oldKey.compressed;
        parts.keyUncompressed = oldKey.uncompressed;
        parts.header = config.headerRlp;
        parts.cert = config.cert;
        parts.throttles = _defaultThrottles();
        return _encodeConfigProof(parts);
    }

    function _bundle(Certified memory block_, bytes[] memory rotations) internal view returns (bytes memory) {
        BundleParts memory parts;
        parts.header = block_.headerRlp;
        parts.cert = block_.cert;
        parts.rotations = rotations;
        parts.accountProof = accountProof;
        parts.storageProof = storageProof;
        parts.content = "";
        return _encodeBundle(parts);
    }

    function _anchor(uint64 anchorBlock, bytes memory key) internal view returns (bytes memory) {
        return _tempoAnchor(codeHash, L, anchorBlock, key);
    }

    function _ctx() internal view returns (bytes memory) {
        return _tempoChannelContext(channelId, service);
    }
}
