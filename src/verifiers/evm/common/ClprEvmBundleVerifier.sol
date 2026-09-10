// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title ClprEvmBundleVerifier
/// @notice Shared base for CLPR verifiers whose peer ledger exposes EVM-style (Merkle-Patricia)
///         state. The downstream half of bundle verification — the MPT account proof, the channel
///         storage-slot derivation, the queue-metadata slot decode, and the `ClprBundleContent`
///         protobuf decode — is identical regardless of how the block/state root itself is
///         authenticated (QBFT committed seals, beacon sync-committee BLS, …). Concrete verifiers
///         authenticate a `stateRoot` their own way and then reuse the helpers below for everything
///         that follows, so this logic lives in one place instead of being copied per chain.
///
/// @dev The storage-layout base slots match the CLPR service contract's `storage-layout.json`.
abstract contract ClprEvmBundleVerifier is IClprVerifier {
    /// @dev `_channels` mapping base slot (CLPR service storage-layout.json).
    uint256 internal constant CHANNELS_BASE_SLOT = 15;
    /// @dev `_messageQueues` mapping base slot.
    uint256 internal constant MESSAGE_QUEUES_BASE_SLOT = 1;
    /// @dev Storage slot of `EndpointManifestState.commitment` — `_endpointManifest` base (17) +
    ///      the `commitment` member (1). Holds `keccak256(ClprProtobuf.encodeEndpointManifest(manifest))`
    ///      of the current live manifest (see {ManifestLib}). A single-slot proof of this commitment
    ///      binds a supplied manifest preimage to the peer's on-ledger state.
    uint256 internal constant ENDPOINT_MANIFEST_COMMITMENT_SLOT = 18;

    /// @dev The account proof authenticated a codeHash that does not match the pinned expected hash.
    error CodeHashMismatch();
    /// @dev The storage proof did not carry the expected number of entries (5 for ACK-only bundles,
    ///      6 when the bundle also carries outbound messages).
    error InvalidStorageProofShape();
    /// @dev The supplied manifest preimage does not hash to the proven on-ledger commitment.
    error ManifestCommitmentMismatch();
    /// @dev The proven manifest's service_address does not match the Channel's peer service address.
    error ManifestServiceAddressMismatch();
    /// @dev The proven manifest version is 0 (never a valid manifest; MUST be >= 1).
    error ManifestVersionZero();
    /// @dev A 5-entry (message-bearing) storage proof was supplied for a channel whose proven
    ///      nextMessageId is 0. Per the CLPR spec a channel's nextMessageId starts at 1 and only
    ///      increments, so 0 means no message was ever sent and no last-message running-hash slot
    ///      exists — the 5th entry cannot correspond to a real slot.
    error InvalidNextMessageId();
    /// @dev Address is the wrong length.
    error InvalidServiceAddressLength();

    // ── Account proof ─────────────────────────────────────────────────────────

    /// @dev Verify the MPT account proof for `service` against `stateRoot`, enforce the pinned code
    ///      hash (skipped when `expectedCodeHash` is zero — i.e. bytecode pinning disabled), and
    ///      return the account's storage root for the subsequent storage-slot proofs.
    function _verifyServiceStorageRoot(
        Memory.Slice accountProofItem,
        bytes32 stateRoot,
        address service,
        bytes32 expectedCodeHash
    ) internal pure returns (bytes32 storageRoot) {
        bytes32 codeHash;
        (storageRoot, codeHash) = ClprEvmStateProof.verifyAccountFields(accountProofItem, stateRoot, service);
        if (expectedCodeHash != bytes32(0) && codeHash != expectedCodeHash) revert CodeHashMismatch();
    }

    // ── Channel storage-slot derivation ────────────────────────────────────

    /// @dev The five `Channel` metadata slots for `channelId`, derived from the CLPR storage
    ///      layout (never taken from the proof) so the proven values are bound to this channel:
    ///        +1  verifier|status|nextMessageId
    ///        +2  ackedMessageId|receivedMessageId|nextExpectedReplyId
    ///        +4  sentRunningHash
    ///        +5  receivedRunningHash
    ///        +16 endpointManifestVersion (QueueMetadata proto field 7 — the source's cached peer
    ///            manifest version, surfaced so the receiver can detect manifest staleness)
    function _channelMetadataSlots(bytes32 channelId) internal pure returns (bytes32[] memory slots) {
        bytes32 cBase = keccak256(abi.encode(channelId, CHANNELS_BASE_SLOT));
        slots = new bytes32[](5);
        slots[0] = bytes32(uint256(cBase) + 1); // verifier|status|nextMessageId
        slots[1] = bytes32(uint256(cBase) + 2); // ackedMessageId|receivedMessageId|nextExpectedReplyId
        slots[2] = bytes32(uint256(cBase) + 4); // sentRunningHash
        slots[3] = bytes32(uint256(cBase) + 5); // receivedRunningHash
        slots[4] = bytes32(uint256(cBase) + 16); // endpointManifestVersion
    }

    /// @dev `_messageQueues[channelId][messageId].runningHashAfterProcessing` slot (struct base +1),
    ///      bound to `channelId` and `messageId`.
    function _lastMessageRunningHashSlot(bytes32 channelId, uint64 messageId) internal pure returns (bytes32) {
        bytes32 qBase = keccak256(abi.encode(channelId, MESSAGE_QUEUES_BASE_SLOT));
        bytes32 msgBase = keccak256(abi.encode(messageId, qBase));
        return bytes32(uint256(msgBase) + 1); // MessageValue.runningHashAfterProcessing (+1)
    }

    // ── Channel storage proof ──────────────────────────────────────────────

    /// @dev Prove the channel's queue-metadata storage slots against `storageRoot` and decode them
    ///      into queue metadata. The expected slots are derived from `channelId` via the CLPR
    ///      storage layout (never read from the proof), so every proven value is cryptographically
    ///      bound to *this* channel — a relay cannot substitute another channel's slot, nor
    ///      reorder the values, because each entry must prove the exact slot the verifier asks for.
    ///      The proof carries the five `Channel` slots (the fifth being endpointManifestVersion),
    ///      plus the last-message running-hash slot only when the bundle carries outbound messages
    ///      (6 entries); ACK-only bundles carry 5.
    function _verifyChannelStorage(Memory.Slice storageProofItem, bytes32 storageRoot, bytes32 channelId)
        internal
        pure
        returns (ClprTypes.QueueMetadata memory metadata)
    {
        (bytes32[] memory labels, Memory.Slice[] memory proofs) = ClprEvmStateProof.indexEntries(storageProofItem);
        if (labels.length != 5 && labels.length != 6) revert InvalidStorageProofShape();

        bytes32[] memory connValues =
            ClprEvmStateProof.verifyIndexedSlots(labels, proofs, storageRoot, _channelMetadataSlots(channelId));
        metadata = _buildQueueMetadata(connValues);

        if (labels.length == 6) {
            // A 6th entry proves the last sent message's running hash, which only exists once
            // nextMessageId > 0. Guard explicitly so `nextMessageId - 1` cannot underflow into an
            // opaque arithmetic panic; the proof is invalid either way.
            if (metadata.nextMessageId == 0) revert InvalidNextMessageId();
            bytes32[] memory msgSlots = new bytes32[](1);
            msgSlots[0] = _lastMessageRunningHashSlot(channelId, uint64(metadata.nextMessageId - 1));

            // Validate that the message slot is proven in the storage proof. The return value (the
            // proven hash) is not needed — only that the proof holds.
            // slither-disable=unused-return
            ClprEvmStateProof.verifyIndexedSlots(labels, proofs, storageRoot, msgSlots);
        }
    }

    // ── Queue metadata decode ─────────────────────────────────────────────────

    /// @dev Decode the five proven `Channel` slot values into queue metadata. Solidity packs
    ///      primitive struct fields from the LSB, so on a big-endian word the first-declared field
    ///      sits at the right:
    ///        slots[0] = verifier(20)|status(1)|nextMessageId(8)
    ///        slots[1] = ackedMessageId(8)|receivedMessageId(8)|nextExpectedReplyId(8)
    ///        slots[2] = sentRunningHash, slots[3] = receivedRunningHash
    ///        slots[4] = endpointManifestVersion (uint64 at offset 0).
    function _buildQueueMetadata(bytes32[] memory slots)
        internal
        pure
        returns (ClprTypes.QueueMetadata memory metadata)
    {
        uint256 slot1 = uint256(slots[0]);
        uint256 slot2 = uint256(slots[1]);
        metadata = ClprTypes.QueueMetadata({
            // casting is safe: Channel struct slot+1/+2 pack status and message IDs per storage-layout.json.
            // forge-lint: disable-next-line(unsafe-typecast)
            state: ClprTypes.ChannelStatus(uint8(slot1 >> 160)),
            // forge-lint: disable-next-line(unsafe-typecast)
            nextMessageId: uint64(slot1 >> 168),
            // forge-lint: disable-next-line(unsafe-typecast)
            receivedMessageId: uint64(slot2 >> 64),
            sentRunningHash: slots[2],
            receivedRunningHash: slots[3],
            // Proven Channel.endpointManifestVersion (member slot +16, uint64 at offset 0):
            // the source's cached peer-manifest version, per QueueMetadata proto field 7.
            // forge-lint: disable-next-line(unsafe-typecast)
            endpointManifestVersion: uint64(uint256(slots[4]))
        });
    }

    /// @dev The UNINITIALIZED manifest (version 0). Returned by `verifyConfig` for bring-up when no
    ///      manifest proof is supplied: the Channel then stores endpointManifestVersion = 0, so the
    ///      first proven manifest — whatever its version >= 1, including a peer's genuine version-1
    ///      manifest — strictly exceeds it and applies via BundleLib Step 1b. (Fabricating a version-1
    ///      manifest here instead would collide with a real remote manifest still at version 1 and
    ///      silently suppress its first propagation.)
    function _uninitializedEndpointManifest(bytes memory serviceAddress)
        internal
        pure
        returns (ClprTypes.ClprEndpointManifest memory m)
    {
        m.serviceAddress = serviceAddress;
        m.endpoints = new ClprTypes.Endpoint[](0);
    }

    /// @dev An absent manifest sentinel (version 0). Returned by `verifyBundle` when the bundle carries
    ///      no manifest proof — the CLPR Service treats version 0 as "no update" (Finding 35).
    function _absentEndpointManifest() internal pure returns (ClprTypes.ClprEndpointManifest memory m) {
        m.endpoints = new ClprTypes.Endpoint[](0);
    }

    // ── Endpoint manifest storage proof ────────────────────────────────────────

    /// @dev Verify a single-slot storage proof of the peer service's endpoint-manifest commitment
    ///      (slot {ENDPOINT_MANIFEST_COMMITMENT_SLOT}) against `storageRoot`, then bind the supplied
    ///      `manifestProtobuf` preimage to it: its keccak256 MUST equal the proven commitment. Decodes
    ///      and returns the manifest. Reverts unless the preimage matches, `service_address` matches
    ///      `expectedServiceAddress`, and version >= 1.
    /// @param manifestStorageProofItem RLP list with a single storage-proof entry for the commitment slot.
    /// @param storageRoot The peer service account's storage root (from the authenticated account proof).
    /// @param manifestProtobuf `ClprProtobuf.encodeEndpointManifest(manifest)` preimage (the committed bytes).
    /// @param expectedServiceAddress The Channel's peer service address (ctx.remoteServiceAddress).
    function _verifyEndpointManifest(
        Memory.Slice manifestStorageProofItem,
        bytes32 storageRoot,
        bytes memory manifestProtobuf,
        bytes memory expectedServiceAddress
    ) internal pure returns (ClprTypes.ClprEndpointManifest memory manifest) {
        bytes32[] memory slots = new bytes32[](1);
        slots[0] = bytes32(ENDPOINT_MANIFEST_COMMITMENT_SLOT);
        bytes32[] memory proven = ClprEvmStateProof.verifyProvenSlots(manifestStorageProofItem, storageRoot, slots);

        if (keccak256(manifestProtobuf) != proven[0]) revert ManifestCommitmentMismatch();

        manifest = ClprProtobuf.decodeEndpointManifest(manifestProtobuf);
        if (manifest.version == 0) revert ManifestVersionZero();
        if (
            expectedServiceAddress.length > 0 && keccak256(manifest.serviceAddress) != keccak256(expectedServiceAddress)
        ) {
            revert ManifestServiceAddressMismatch();
        }
    }

    // ── Bundle content protobuf ───────────────────────────────────────────────

    /// @dev `ClprBundleContent` proto: field 2 (LEN, repeated) carries the message payloads we
    ///      return. Field 1 (queue metadata) is ignored — metadata is taken from the verified
    ///      storage proof, not from this untrusted attached field.
    function _decodeBundleContent(bytes memory data) internal pure returns (bytes[] memory messages) {
        // Pass 1: count field-2 occurrences.
        uint256 msgCount = 0;
        uint256 off = 0;
        while (off < data.length) {
            uint64 fieldNumber;
            uint8 wireType;
            (fieldNumber, wireType, off) = PB.decodeFieldKey(data, off);
            if (fieldNumber == 2 && wireType == 2) {
                unchecked {
                    ++msgCount;
                }
            }
            off = PB.skipField(data, off, wireType);
        }
        messages = new bytes[](msgCount);

        // Pass 2: collect payloads.
        uint256 idx = 0;
        uint256 cursor = 0;
        while (cursor < data.length) {
            uint64 fieldNumber;
            uint8 wireType;
            (fieldNumber, wireType, cursor) = PB.decodeFieldKey(data, cursor);
            if (fieldNumber == 2 && wireType == 2) {
                (messages[idx], cursor) = PB.decodeLengthDelimited(data, cursor);
                unchecked {
                    ++idx;
                }
            } else {
                cursor = PB.skipField(data, cursor, wireType);
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────

    /// @dev Converts an opaque service-address byte string (from ChannelContext) to an address.
    function _toAddress(bytes memory b) internal pure returns (address addr) {
        if (b.length != 20) revert InvalidServiceAddressLength();
        assembly {
            addr := mload(add(b, 20))
        }
    }

    /// @dev First 4 bytes of a (length-4) `bytes` as `bytes4`. Trailing memory is zero-padded.
    function _toBytes4(bytes memory b) internal pure returns (bytes4 out) {
        assembly ("memory-safe") {
            out := mload(add(b, 0x20))
        }
    }
}
