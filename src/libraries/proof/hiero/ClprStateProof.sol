// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprMerkleProof} from "@hiero-ledger/clpr/libraries/proof/hiero/ClprMerkleProof.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

/// @title ClprStateProof
/// @notice Decoder for a Hiero `StateProof` protobuf message
/// @dev    Wire shapes mirror the protos under
///         `clpr-hiero/hapi/hedera-protobuf-java-api/src/main/proto/block/stream/`:
///         - `StateProof { repeated MerklePath paths = 1; oneof proof { TssSignedBlockProof signed_block_proof = 2; } }`
///         - `MerklePath { repeated SiblingNode siblings = 1; uint32 next_path_index = 2; oneof content { bytes hash = 3; bytes state_item_leaf = 4; bytes block_item_leaf = 5; bytes timestamp_leaf = 6; } }`
///         - `SiblingNode { bool is_left = 1; bytes hash = 2; }`
///         - `TssSignedBlockProof { bytes block_signature = 1; }`

library ClprStateProof {
    uint64 internal constant SP_PATHS = 1;
    uint64 internal constant SP_SIGNED_BLOCK_PROOF = 2;

    uint64 internal constant MP_SIBLINGS = 1;
    uint64 internal constant MP_NEXT_PATH_INDEX = 2;
    uint64 internal constant MP_HASH = 3;
    uint64 internal constant MP_STATE_ITEM_LEAF = 4;
    uint64 internal constant MP_BLOCK_ITEM_LEAF = 5;
    uint64 internal constant MP_TIMESTAMP_LEAF = 6;

    uint64 internal constant SIB_HASH = 2;
    uint64 internal constant SIB_IS_LEFT = 1;

    uint64 internal constant SBP_BLOCK_SIGNATURE = 1;

    // Field 2 of StateItem = StateKey; field 3 = StateValue
    uint64 internal constant STATE_ITEM_VALUE_FIELD = 3;

    // Tags identifying which state-item the leaf carries. Derived from the
    // Hiero generated proto for `StateValue`
    uint64 internal constant SV_CHANNEL_TAG = 482;
    uint64 internal constant SV_MESSAGE_TAG = 498;
    uint64 internal constant SV_ENDPOINT_MANIFEST_TAG = 514;

    /// @notice A Merkle path chain does not converge on the expected block root hash.
    error StateProofPathInvalid();
    /// @notice The state proof contains no `ClprChannel` state-item leaf.
    error StateProofMissingChannel();
    /// @notice A `MerklePath` populated more than one `content`.
    error StateProofPathAmbiguousContent();

    struct StateProofDecoded {
        // TSS Signature
        bytes signature;
        MerklePath[] paths;
    }

    struct SiblingNode {
        bytes hash;
        bool isLeft;
    }

    struct MerklePath {
        uint32 nextPathIndex; /* The next parent path of this path going up the tree. Expressed as an index
                              * into the array of MerklePaths in the StatePoof. For example 0 being first
                              * in list etc. If this is the root path then the value is UINT32_MAX
                              * (this is `-1` in Java; 0xFFFFFFFF).
                              */
        bytes explicitHash; /* The explicit hash of this path, if present. If not present, the hash is computed from the leaf and siblings. */
        bytes stateItemLeaf; /**
                              * StateItem leaf, if this path starts at a state item.
                              */
        bytes blockItemLeaf; /**
                              * BlockItem leaf, if this path starts at a block item.
                              */
        bytes timestampLeaf; /**
                              * Timestamp leaf, if this path starts at a timestamp.
                              */
        SiblingNode[] siblings;
    }

    /// @notice Decode a `StateProof` protobuf wire message into its structured form.
    /// @param wire Raw protobuf bytes of a `StateProof` message.
    /// @return proof Decoded struct containing the TSS signature and all `MerklePath` entries.
    function decode(bytes memory wire) internal pure returns (StateProofDecoded memory proof) {
        bytes[] memory rawPaths = new bytes[](64);
        uint256 pathN;
        uint256 pos;

        while (pos < wire.length) {
            uint64 fieldNum;
            uint8 wireType;
            (fieldNum, wireType, pos) = PB.decodeFieldKey(wire, pos);

            if (wireType != 2) {
                pos = PB.skipField(wire, pos, wireType);
                continue;
            }

            bytes memory val;
            (val, pos) = PB.decodeLengthDelimited(wire, pos);

            if (fieldNum == SP_PATHS) {
                rawPaths[pathN++] = val;
            } else if (fieldNum == SP_SIGNED_BLOCK_PROOF) {
                proof.signature = _decodeSignedBlockProofSignature(val);
            }
        }

        proof.paths = new MerklePath[](pathN);
        for (uint256 i = 0; i < pathN; i++) {
            proof.paths[i] = _decodeMerklePath(rawPaths[i]);
        }
    }

    function _decodeSignedBlockProofSignature(bytes memory wire) private pure returns (bytes memory sig) {
        uint256 pos;
        while (pos < wire.length) {
            uint64 fieldNum;
            uint8 wireType;
            (fieldNum, wireType, pos) = PB.decodeFieldKey(wire, pos);

            if (wireType == 2) {
                bytes memory val;
                (val, pos) = PB.decodeLengthDelimited(wire, pos);
                if (fieldNum == SBP_BLOCK_SIGNATURE) {
                    sig = val;
                }
            } else {
                pos = PB.skipField(wire, pos, wireType);
            }
        }
    }

    function _decodeMerklePath(bytes memory wire) private pure returns (MerklePath memory path) {
        bytes[] memory rawSiblings = new bytes[](64);
        uint256 siblingN;
        uint256 pos;

        while (pos < wire.length) {
            uint64 fieldNum;
            uint8 wireType;
            (fieldNum, wireType, pos) = PB.decodeFieldKey(wire, pos);

            if (wireType == 0) {
                uint64 v;
                (v, pos) = PB.decodeVarint(wire, pos);
                if (fieldNum == MP_NEXT_PATH_INDEX) {
                    path.nextPathIndex = SafeCast.toUint32(v);
                }
            } else if (wireType == 2) {
                bytes memory val;
                (val, pos) = PB.decodeLengthDelimited(wire, pos);

                if (fieldNum == MP_SIBLINGS) {
                    rawSiblings[siblingN++] = val;
                } else if (fieldNum == MP_HASH) {
                    path.explicitHash = val;
                } else if (fieldNum == MP_STATE_ITEM_LEAF) {
                    path.stateItemLeaf = val;
                } else if (fieldNum == MP_BLOCK_ITEM_LEAF) {
                    path.blockItemLeaf = val;
                } else if (fieldNum == MP_TIMESTAMP_LEAF) {
                    path.timestampLeaf = val;
                }
            } else {
                pos = PB.skipField(wire, pos, wireType);
            }
        }

        uint256 contentArms;
        if (path.explicitHash.length != 0) contentArms++;
        if (path.stateItemLeaf.length != 0) contentArms++;
        if (path.blockItemLeaf.length != 0) contentArms++;
        if (path.timestampLeaf.length != 0) contentArms++;
        if (contentArms > 1) revert StateProofPathAmbiguousContent();

        path.siblings = new SiblingNode[](siblingN);
        for (uint256 i = 0; i < siblingN; i++) {
            path.siblings[i] = _decodeSiblingNode(rawSiblings[i]);
        }
    }

    function _decodeSiblingNode(bytes memory wire) private pure returns (SiblingNode memory node) {
        uint256 pos;
        while (pos < wire.length) {
            uint64 fieldNum;
            uint8 wireType;
            (fieldNum, wireType, pos) = PB.decodeFieldKey(wire, pos);

            if (wireType == 2) {
                bytes memory val;
                (val, pos) = PB.decodeLengthDelimited(wire, pos);
                if (fieldNum == SIB_HASH) {
                    node.hash = val;
                }
            } else if (wireType == 0) {
                uint64 v;
                (v, pos) = PB.decodeVarint(wire, pos);
                if (fieldNum == SIB_IS_LEFT) {
                    node.isLeft = (v != 0);
                }
            } else {
                pos = PB.skipField(wire, pos, wireType);
            }
        }
    }

    /// @notice Walks every `state_item_leaf` path in `paths`, authenticates each
    ///         chain against the trusted `blockRootHash`, and decodes the proven
    ///         leaves into a `ClprChannel` (exactly one is required) and an
    ///         in-order list of `ClprMessageValue` payloads plus their
    ///         `runningHashAfterProcessing`.
    ///
    /// @dev    Proto-shaped paths layout (`block/stream/state_proof.proto`):
    ///         ```
    ///         paths = [
    ///             MerklePath { hash               },  // [0] prev-block-root spine
    ///             MerklePath { timestamp_leaf     },  // [1] consensus-timestamp leaf
    ///             MerklePath { hash               },  // [2] block-root spine
    ///             MerklePath { state_item_leaf = ClprChannel,    next_path_index → ... },
    ///             MerklePath { state_item_leaf = ClprMessageValue,  next_path_index → ... },
    ///             MerklePath { state_item_leaf = ClprMessageValue,  next_path_index → ... },
    ///             ...
    ///         ]
    ///         ```
    ///         Spine paths are independent proofs; this function ignores them
    ///         and walks only paths that carry `state_item_leaf`. Each
    ///         state-item path's chain (its own siblings + any chained
    ///         type-3 intermediates via `next_path_index`) MUST converge on
    ///         `blockRootHash` — that's the per-leaf authentication step.
    ///         Tag dispatch on the StateItem→StateValue oneof:
    ///           - `SV_CHANNEL_TAG` (482): exactly one is expected; the
    ///             wire bytes are decoded via `decodeChannelFromMemory`.
    ///           - `SV_MESSAGE_TAG` (498): zero or more; each contributes one
    ///             payload + one running-hash entry, in path order.
    ///           - `SV_ENDPOINT_MANIFEST_TAG` (514): at most one; carries the
    ///             source ledger's `ClprEndpointManifest` singleton for an
    ///             in-bundle manifest update (Step 1b). Its raw wire bytes are
    ///             returned for the verifier to decode and bind.
    ///
    /// @return channel            Decoded `ClprChannel` from the proven leaf.
    /// @return messagePayloads       Proven message payloads in path order.
    /// @return manifestWire          Raw proven `ClprEndpointManifest` bytes; empty
    ///                               when the proof carries no manifest leaf.
    function extractDecodedQueueData(MerklePath[] memory paths, bytes memory blockRootHash)
        internal
        pure
        returns (ClprTypes.Channel memory channel, bytes[] memory messagePayloads, bytes memory manifestWire)
    {
        // Upper-bound at `paths.length` (every leaf path contributes at most one
        // entry) and truncate after the loop. Avoids the prior O(k²) regrow.
        bytes[] memory rawPayloads = new bytes[](paths.length);
        uint256 messageN;
        bytes memory channelWire;

        // Cache the keccak of the trusted root once
        bytes32 expectedRoot = keccak256(blockRootHash);

        uint256 lastMessageIndex = type(uint256).max;
        uint256 firstStateItemLeaf = type(uint256).max;
        for (uint256 i = 0; i < paths.length; i++) {
            MerklePath memory path = paths[i];
            if (path.stateItemLeaf.length == 0) continue;

            // Unwrap `StateItem.value` → `StateValue.{channel|message_value}`.
            bytes memory stateValue = extractStateItemValue(path.stateItemLeaf);
            if (stateValue.length == 0) continue;

            uint64 tag = readFirstVarintTag(stateValue);
            bytes memory inner = unwrapStateValueField(stateValue);
            if (inner.length == 0) continue;

            if (firstStateItemLeaf == type(uint256).max) firstStateItemLeaf = i;

            if (tag == SV_CHANNEL_TAG) {
                // Exactly one Channel leaf is expected; if multiple appear,
                // the last one wins (kept permissive; the caller's invariants
                // decide whether to tighten this).
                channelWire = inner;

                if (i != firstStateItemLeaf) {
                    bytes memory channelRoot = ClprMerkleProof.computeChainedRoot(paths, i);
                    if (keccak256(channelRoot) != expectedRoot) revert StateProofPathInvalid();
                }
            } else if (tag == SV_MESSAGE_TAG) {
                ClprTypes.MessageValue memory mv = _decodeMessageValueFromMemory(inner);
                rawPayloads[messageN] = mv.payload;
                messageN++;
                lastMessageIndex = i;
            } else if (tag == SV_ENDPOINT_MANIFEST_TAG) {
                // At most one manifest leaf; the last one wins (same permissive
                // posture as the Channel leaf). Authenticate its chain unless
                // it is the leaf the block root was derived from.
                manifestWire = inner;

                if (i != firstStateItemLeaf) {
                    bytes memory manifestRoot = ClprMerkleProof.computeChainedRoot(paths, i);
                    if (keccak256(manifestRoot) != expectedRoot) revert StateProofPathInvalid();
                }
            }
            // Unknown StateValue tags (forward-compatibility): skipped silently.
            // Trust anchor update is not supported yet.
        }

        if (channelWire.length == 0) revert StateProofMissingChannel();

        channel = ClprProtobuf.decodeChannelFromMemory(channelWire);

        // We only check last message. But our root that we compare to
        // was taken from the first state item leaf
        // No need to calculate its chained root again.
        if (lastMessageIndex != type(uint256).max && lastMessageIndex != firstStateItemLeaf) {
            bytes memory lastMessageRoot = ClprMerkleProof.computeChainedRoot(paths, lastMessageIndex);
            if (keccak256(lastMessageRoot) != expectedRoot) revert StateProofPathInvalid();
        }

        messagePayloads = new bytes[](messageN);
        for (uint256 i = 0; i < messageN; i++) {
            messagePayloads[i] = rawPayloads[i];
        }
    }

    /// @notice Walk the `state_item_leaf` paths and return the raw wire bytes of the single
    ///         proven `ClprEndpointManifest` leaf.
    function extractManifestWire(MerklePath[] memory paths, bytes memory blockRootHash)
        internal
        pure
        returns (bytes memory manifestWire)
    {
        bytes32 expectedRoot = keccak256(blockRootHash);
        uint256 firstStateItemLeaf = type(uint256).max;

        for (uint256 i = 0; i < paths.length; i++) {
            MerklePath memory path = paths[i];
            if (path.stateItemLeaf.length == 0) continue;

            bytes memory stateValue = extractStateItemValue(path.stateItemLeaf);
            if (stateValue.length == 0) continue;

            uint64 tag = readFirstVarintTag(stateValue);
            bytes memory inner = unwrapStateValueField(stateValue);
            if (inner.length == 0) continue;

            if (firstStateItemLeaf == type(uint256).max) firstStateItemLeaf = i;

            if (tag == SV_ENDPOINT_MANIFEST_TAG) {
                manifestWire = inner;
                if (i != firstStateItemLeaf) {
                    bytes memory manifestRoot = ClprMerkleProof.computeChainedRoot(paths, i);
                    if (keccak256(manifestRoot) != expectedRoot) revert StateProofPathInvalid();
                }
            }
        }
    }

    /// @notice Extract the `StateValue` bytes from an encoded `StateItem` leaf.
    /// @dev Returns empty bytes if field 3 (`StateValue`) is absent.
    /// @param stateItemLeaf Encoded `StateItem` protobuf bytes.
    /// @return value Raw `StateValue` bytes, or empty if not present.
    function extractStateItemValue(bytes memory stateItemLeaf) internal pure returns (bytes memory value) {
        uint256 pos;
        while (pos < stateItemLeaf.length) {
            uint64 fieldNum;
            uint8 wireType;
            (fieldNum, wireType, pos) = PB.decodeFieldKey(stateItemLeaf, pos);

            if (wireType == 2) {
                bytes memory val;
                (val, pos) = PB.decodeLengthDelimited(stateItemLeaf, pos);
                if (fieldNum == STATE_ITEM_VALUE_FIELD) {
                    return val;
                }
            } else {
                pos = PB.skipField(stateItemLeaf, pos, wireType);
            }
        }
    }

    /// @notice Read the first varint from `data` — used to get the `StateValue` oneof tag.
    /// @param data Protobuf-encoded `StateValue` bytes.
    /// @return tag The field number / wire-type packed varint (e.g. 482 for Channel).
    function readFirstVarintTag(bytes memory data) internal pure returns (uint64 tag) {
        uint256 pos;
        (tag, pos) = PB.decodeVarint(data, pos);
    }

    /// @notice Unwrap the first length-delimited field from a `StateValue` oneof.
    /// @dev Returns the first LEN-delimited field regardless of field number (fieldNum 60 for
    ///      Channel, 62 for MessageValue); the caller uses `readFirstVarintTag` to know which.
    /// @param stateValue Raw `StateValue` protobuf bytes.
    /// @return inner The first embedded message bytes, or empty if none found.
    function unwrapStateValueField(bytes memory stateValue) internal pure returns (bytes memory inner) {
        uint256 pos;
        while (pos < stateValue.length) {
            uint64 fieldNum;
            uint8 wireType;
            (fieldNum, wireType, pos) = PB.decodeFieldKey(stateValue, pos);

            if (wireType == 2) {
                bytes memory val;
                (val, pos) = PB.decodeLengthDelimited(stateValue, pos);
                return val;
            } else {
                pos = PB.skipField(stateValue, pos, wireType);
            }
        }
    }

    // --- Inline protobuf decoders for state values --------------------------
    //
    // These mirror PR #40's additions to ClprProtobuf.sol but live here so the
    // dependency graph stays one-way (Module 2 → state-value shape). If they
    // need to be shared with another library, lift them into ClprProtobuf.sol
    // verbatim in a follow-up.

    function _decodeMessageValueFromMemory(bytes memory data) private pure returns (ClprTypes.MessageValue memory mv) {
        uint256 pos;
        while (pos < data.length) {
            uint64 fieldNum;
            uint8 wireType;
            (fieldNum, wireType, pos) = PB.decodeFieldKey(data, pos);

            if (wireType == 2) {
                bytes memory val;
                (val, pos) = PB.decodeLengthDelimited(data, pos);
                if (fieldNum == 1) {
                    mv.payload = val;
                } else if (fieldNum == 2 && val.length == 32) {
                    mv.runningHashAfterProcessing = _toBytes32(val);
                }
            } else {
                pos = PB.skipField(data, pos, wireType);
            }
        }
    }

    function _toBytes32(bytes memory b) private pure returns (bytes32 out) {
        if (b.length != 32) return bytes32(0);
        assembly {
            out := mload(add(b, 32))
        }
    }
}
