// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprProtobufHelpers} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";

/// @title ClprTempoCertificate
/// @notice Readers for the parts of a Tempo finalization certificate.
/// @dev Commonware encodings. Integers are protobuf varints.
///      Proposal: varint(epoch) ‖ varint(view) ‖ varint(parentView) ‖ blockHash(32).
///      Finalize message: varint(14) ‖ "TEMPO_FINALIZE" ‖ Proposal.
///      DKG outcome: varint(epoch) ‖ summary(32) ‖ mode(1) ‖ total(4) ‖ varint(n) ‖ key(96) ‖ ...
library ClprTempoCertificate {
    /// @dev The payload is the block hash.
    uint256 internal constant PAYLOAD_LENGTH = 32;
    /// @dev summary(32) ‖ mode(1) ‖ total(4), between the two varints of the outcome.
    uint256 internal constant OUTCOME_FIXED_FIELDS_LENGTH = 37;
    uint256 internal constant COMPRESSED_G2_LENGTH = 96;

    /// @dev Chain namespace plus the Simplex finalize suffix.
    bytes internal constant FINALIZE_NAMESPACE = "TEMPO_FINALIZE";

    error InvalidProposal();
    error InvalidDkgOutcome();

    struct Proposal {
        uint64 epoch;
        uint64 viewNumber;
        uint64 parentView;
        bytes32 payload;
    }

    /// @notice Decode a proposal. Exactly 32 bytes must follow the three varints.
    function parseProposal(bytes memory data) internal pure returns (Proposal memory p) {
        uint256 off;
        (p.epoch, off) = ClprProtobufHelpers.decodeVarint(data, off);
        (p.viewNumber, off) = ClprProtobufHelpers.decodeVarint(data, off);
        (p.parentView, off) = ClprProtobufHelpers.decodeVarint(data, off);
        if (data.length != off + PAYLOAD_LENGTH) revert InvalidProposal();
        bytes32 payload;
        assembly ("memory-safe") {
            payload := mload(add(add(data, 0x20), off))
        }
        p.payload = payload;
    }

    /// @notice The bytes a finalize vote signs: namespace length, namespace, proposal.
    function finalizeMessage(bytes memory proposal) internal pure returns (bytes memory) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return abi.encodePacked(bytes1(uint8(FINALIZE_NAMESPACE.length)), FINALIZE_NAMESPACE, proposal);
    }

    /// @notice Read the epoch and the compressed group key from a boundary block's `extraData`.
    /// @dev Only the leading fields are read.
    function dkgOutcomeKey(bytes memory extraData) internal pure returns (uint64 epoch, bytes memory key) {
        uint256 off;
        (epoch, off) = ClprProtobufHelpers.decodeVarint(extraData, off);
        off += OUTCOME_FIXED_FIELDS_LENGTH;
        if (off > extraData.length) revert InvalidDkgOutcome();
        uint64 coefficients;
        (coefficients, off) = ClprProtobufHelpers.decodeVarint(extraData, off);
        if (coefficients == 0 || extraData.length < off + COMPRESSED_G2_LENGTH) revert InvalidDkgOutcome();
        key = new bytes(COMPRESSED_G2_LENGTH);
        assembly ("memory-safe") {
            mcopy(add(key, 0x20), add(add(extraData, 0x20), off), 96)
        }
    }
}
