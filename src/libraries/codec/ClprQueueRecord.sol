// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";

/// @title ClprQueueRecord
/// @notice A fixed 190-byte snapshot of one channel's queue state, published by a CLPR endpoint on a
///         ledger that cannot expose EVM storage proofs: in an XRPL transaction memo, a Mixin
///         transaction `extra` (256-byte limit) or a HyperEVM event. The ledger's consensus proves
///         the publication; the record says what was published.
/// @dev Layout (big-endian, packed):
///        0  "CLPR"                     4
///        4  version = 1                1
///        5  channelId                  32  (zero: a service-level record, valid only at config)
///       37  state (ChannelStatus)      1
///       38  nextMessageId              8
///       46  receivedMessageId          8
///       54  sentRunningHash            32
///       86  receivedRunningHash        32
///      118  endpointManifestVersion    8   (the peer manifest version the endpoint has cached)
///      126  manifestCommitment         32  (keccak256 of the endpoint's own encoded manifest, or 0)
///      158  configHash                 32  (keccak256 of its encoded LedgerConfiguration control message)
///      190
library ClprQueueRecord {
    uint256 internal constant LENGTH = 190;
    bytes4 internal constant MAGIC = "CLPR";
    uint8 internal constant VERSION = 1;

    struct Record {
        bytes32 channelId;
        uint8 state;
        uint64 nextMessageId;
        uint64 receivedMessageId;
        bytes32 sentRunningHash;
        bytes32 receivedRunningHash;
        uint64 endpointManifestVersion;
        bytes32 manifestCommitment;
        bytes32 configHash;
    }

    error RecordTooShort(uint256 length);
    error RecordBadMagic();
    error RecordBadVersion(uint8 version);
    error RecordBadState(uint8 state);

    /// @notice Decode the record starting at byte `off` of `b`.
    function decode(bytes memory b, uint256 off) internal pure returns (Record memory r) {
        if (b.length < off + LENGTH) revert RecordTooShort(b.length);
        bytes32 w0;
        bytes32 w1;
        bytes32 w2;
        bytes32 w3;
        bytes32 w4;
        bytes32 w5;
        assembly ("memory-safe") {
            let p := add(add(b, 0x20), off)
            w0 := mload(p) // magic(4) version(1) channelId[0..27)
            w1 := mload(add(p, 37)) // state nextId receivedId ... (first 17 bytes)
            w2 := mload(add(p, 54))
            w3 := mload(add(p, 86))
            w4 := mload(add(p, 126))
            w5 := mload(add(p, 158))
        }
        if (bytes4(w0) != MAGIC) revert RecordBadMagic();
        uint8 version = uint8(uint256(w0) >> 216);
        if (version != VERSION) revert RecordBadVersion(version);
        bytes32 ch;
        uint64 mv;
        assembly ("memory-safe") {
            let p := add(add(b, 0x20), off)
            ch := mload(add(p, 5))
            mv := shr(192, mload(add(p, 118)))
        }
        r.channelId = ch;
        r.state = uint8(uint256(w1) >> 248);
        if (r.state > uint8(type(ClprTypes.ChannelStatus).max)) revert RecordBadState(r.state);
        r.nextMessageId = uint64(uint256(w1) >> 184);
        r.receivedMessageId = uint64(uint256(w1) >> 120);
        r.sentRunningHash = w2;
        r.receivedRunningHash = w3;
        r.endpointManifestVersion = mv;
        r.manifestCommitment = w4;
        r.configHash = w5;
    }

    function encode(Record memory r) internal pure returns (bytes memory) {
        return abi.encodePacked(
            MAGIC,
            VERSION,
            r.channelId,
            r.state,
            r.nextMessageId,
            r.receivedMessageId,
            r.sentRunningHash,
            r.receivedRunningHash,
            r.endpointManifestVersion,
            r.manifestCommitment,
            r.configHash
        );
    }

    function toMetadata(Record memory r) internal pure returns (ClprTypes.QueueMetadata memory m) {
        m.state = ClprTypes.ChannelStatus(r.state);
        m.nextMessageId = r.nextMessageId;
        m.receivedMessageId = r.receivedMessageId;
        m.sentRunningHash = r.sentRunningHash;
        m.receivedRunningHash = r.receivedRunningHash;
        m.endpointManifestVersion = r.endpointManifestVersion;
    }
}
