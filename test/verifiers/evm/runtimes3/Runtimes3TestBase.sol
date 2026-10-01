// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";

/// @dev Shared builders for the runtimes3 verifier tests: the BCS `ChannelQueue` record, bundle
///      content, a ledger configuration, an endpoint manifest, and synthetic ICS-23 proofs.
abstract contract Runtimes3TestBase is Test {
    bytes32 internal constant CHANNEL_ID = keccak256("clpr-runtimes3-channel");
    bytes32 internal constant SENT_HASH = keccak256("sent");
    bytes32 internal constant RECV_HASH = keccak256("received");

    // ── Queue record ──────────────────────────────────────────────────────────

    function _le64(uint64 v) internal pure returns (bytes memory out) {
        out = new bytes(8);
        for (uint256 i = 0; i < 8; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            out[i] = bytes1(uint8(v >> (8 * i)));
        }
    }

    function _record(uint8 status, uint64 nextId, uint64 recvId, uint64 manifestVersion, bytes32 commitment)
        internal
        pure
        returns (bytes memory)
    {
        return _recordWithSent(status, nextId, recvId, manifestVersion, commitment, SENT_HASH);
    }

    function _recordWithSent(
        uint8 status,
        uint64 nextId,
        uint64 recvId,
        uint64 manifestVersion,
        bytes32 commitment,
        bytes32 sentHash
    ) internal pure returns (bytes memory) {
        bytes memory head = abi.encodePacked(
            status, _le64(nextId), _le64(recvId), uint8(32), sentHash, uint8(32), RECV_HASH, _le64(manifestVersion)
        );
        return
            commitment == bytes32(0) ? abi.encodePacked(head, uint8(0)) : abi.encodePacked(head, uint8(32), commitment);
    }

    function _defaultRecord() internal pure returns (bytes memory) {
        return _record(1, 7, 3, 2, bytes32(0));
    }

    function _payloads() internal pure returns (bytes[] memory msgs) {
        msgs = new bytes[](2);
        msgs[0] = hex"0a03010203";
        msgs[1] = hex"0a020405";
    }

    function _bundleContent() internal pure returns (bytes memory) {
        ClprTypes.QueueMetadata memory m;
        return ClprProtobuf.encodeBundleContent(m, _payloads());
    }

    /// @dev sha256 running hash over `_payloads()` from `previous`.
    function _chainedSentHash(bytes32 previous) internal pure returns (bytes32 h) {
        h = previous;
        bytes[] memory p = _payloads();
        for (uint256 i; i < p.length; ++i) {
            h = sha256(abi.encodePacked(h, sha256(p[i])));
        }
    }

    function _manifest(bytes memory service) internal pure returns (bytes memory) {
        ClprTypes.ClprEndpointManifest memory m;
        m.version = 3;
        m.serviceAddress = service;
        m.endpoints = new ClprTypes.Endpoint[](1);
        m.endpoints[0] =
            ClprTypes.Endpoint({ipAddress: "10.0.0.1", port: 50211, tlsCertificate: hex"01", accountId: hex"02"});
        return ClprProtobuf.encodeEndpointManifest(m);
    }

    function _controlMessage(string memory chainId, bytes memory service) internal pure returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory lc;
        lc.protocolVersion = 1;
        lc.chainId = chainId;
        lc.serviceAddress = service;
        lc.nanosSinceEpoch = 1_790_000_000_000_000_000;
        lc.throttles = ClprTypes.Throttles({
            maxMessagesPerBundle: 10,
            maxMessagePayloadBytes: 4096,
            maxGasPerMessage: 1_000_000,
            maxQueueDepth: 100,
            maxSyncBytes: 65536,
            maxLocalEndpoints: 4,
            maxPeerEndpoints: 4
        });
        return ClprProtobuf.encodeControlMessage(lc);
    }

    function _assertDefaultMetadata(ClprTypes.QueueMetadata memory m) internal pure {
        assertEq(uint8(m.state), 1);
        assertEq(m.nextMessageId, 7);
        assertEq(m.receivedMessageId, 3);
        assertEq(m.sentRunningHash, SENT_HASH);
        assertEq(m.receivedRunningHash, RECV_HASH);
        assertEq(m.endpointManifestVersion, 2);
    }

    // ── Synthetic ICS-23 proofs ───────────────────────────────────────────────

    struct Ics23Proof {
        bytes encoded; // CommitmentProof{1: ExistenceProof}
        bytes32 root;
    }

    function _leafOp(bytes memory prefix) internal pure returns (bytes memory) {
        return abi.encodePacked(
            PB.encodeVarintField(1, uint8(1)),
            PB.encodeVarintField(3, uint8(1)),
            PB.encodeVarintField(4, uint8(1)),
            PB.encodeBytesField(5, prefix)
        );
    }

    function _innerOp(bytes memory prefix, bytes memory suffix) internal pure returns (bytes memory) {
        return abi.encodePacked(
            PB.encodeVarintField(1, uint8(1)), PB.encodeBytesField(2, prefix), PB.encodeBytesField(3, suffix)
        );
    }

    function _leafHash(bytes memory leafPrefix, bytes memory key, bytes memory value) internal pure returns (bytes32) {
        return sha256(
            abi.encodePacked(
                leafPrefix, PB.encodeVarint(uint64(key.length)), key, PB.encodeVarint(uint64(32)), sha256(value)
            )
        );
    }

    /// @dev A two-leaf IAVL tree: (key, value) is the left child, `sibling` the right child's hash.
    function _iavlProof(bytes memory key, bytes memory value, bytes32 sibling)
        internal
        pure
        returns (Ics23Proof memory p)
    {
        bytes memory leafPrefix = hex"00020202";
        bytes32 leaf = _leafHash(leafPrefix, key, value);
        bytes memory innerPrefix = hex"02040220";
        bytes memory innerSuffix = abi.encodePacked(uint8(0x20), sibling);
        p.root = sha256(abi.encodePacked(innerPrefix, leaf, innerSuffix));
        bytes memory ep = abi.encodePacked(
            PB.encodeBytesField(1, key),
            PB.encodeBytesField(2, value),
            PB.encodeBytesField(3, _leafOp(leafPrefix)),
            PB.encodeBytesField(4, _innerOp(innerPrefix, innerSuffix))
        );
        p.encoded = PB.encodeBytesField(1, ep);
    }

    /// @dev A two-store multistore (Tendermint spec): `storeName → storeRoot` is the right child.
    function _multistoreProof(bytes memory storeName, bytes32 storeRoot, bytes32 leftSibling)
        internal
        pure
        returns (Ics23Proof memory p)
    {
        bytes memory value = abi.encodePacked(storeRoot);
        bytes32 leaf = _leafHash(hex"00", storeName, value);
        bytes memory innerPrefix = abi.encodePacked(uint8(1), leftSibling);
        p.root = sha256(abi.encodePacked(innerPrefix, leaf));
        bytes memory ep = abi.encodePacked(
            PB.encodeBytesField(1, storeName),
            PB.encodeBytesField(2, value),
            PB.encodeBytesField(3, _leafOp(hex"00")),
            PB.encodeBytesField(4, _innerOp(innerPrefix, ""))
        );
        p.encoded = PB.encodeBytesField(1, ep);
    }
}
