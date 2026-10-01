// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title FuelBlockProof
/// @notice Fuel block headers, block-history and message-outbox proofs, as fuel-core builds them
///         (FuelLabs/fuel-core `crates/types/src/blockchain/header{,/v1}.rs`) and as Fuel's own
///         Ethereum message portal checks them (FuelLabs/fuel-bridge `FuelMessagePortalV3`).
///
/// ## Header (BlockHeaderV1, the version Fuel Ignition and Fuel testnet produce)
/// ```
/// consensus  prevRoot(32) ‖ height(u32) ‖ time(u64, TAI64) ‖ applicationHash(32)       76 bytes
/// application daHeight(u64) ‖ consensusParametersVersion(u32) ‖ stateTransitionBytecodeVersion(u32)
///            ‖ transactionsCount(u16) ‖ messageReceiptCount(u32) ‖ transactionsRoot(32)
///            ‖ messageOutboxRoot(32) ‖ eventInboxRoot(32)                             118 bytes
/// block id = sha256(consensus), applicationHash = sha256(application)   (all integers big-endian)
/// ```
/// A "full" header in this library is `consensus[0:44] ‖ application` (162 bytes): the
/// applicationHash is recomputed, never taken from the proof.
///
/// ## Merkle trees (fuel-merkle `binary`, RFC 6962 shape)
/// leaf = sha256(0x00 ‖ data), node = sha256(0x01 ‖ left ‖ right); the left subtree of n leaves holds
/// the largest power of two below n. `prevRoot` of block H is the root over the ids of blocks
/// 0 … H−1; `messageOutboxRoot` is the root over the block's message ids in receipt order.
/// Proof siblings are ordered leaf to root.
library FuelBlockProof {
    uint256 internal constant CONSENSUS_HEADER_LENGTH = 76;
    uint256 internal constant FULL_HEADER_LENGTH = 162;

    error InvalidFuelHeader();

    struct FullHeader {
        bytes32 id;
        bytes32 prevRoot;
        uint32 height;
        uint32 messageReceiptCount;
        bytes32 messageOutboxRoot;
    }

    /// @dev Block id and fields of a 76-byte consensus header.
    function consensusHeader(bytes memory h)
        internal
        pure
        returns (bytes32 id, bytes32 prevRoot, uint32 height, uint64 time)
    {
        if (h.length != CONSENSUS_HEADER_LENGTH) revert InvalidFuelHeader();
        id = sha256(h);
        assembly ("memory-safe") {
            let p := add(h, 0x20)
            prevRoot := mload(p)
            height := shr(224, mload(add(p, 32)))
            time := shr(192, mload(add(p, 36)))
        }
    }

    /// @dev Block id and fields of a 162-byte full header (applicationHash recomputed).
    function fullHeader(bytes memory h) internal pure returns (FullHeader memory f) {
        if (h.length != FULL_HEADER_LENGTH) revert InvalidFuelHeader();
        bytes memory application = new bytes(FULL_HEADER_LENGTH - 44);
        bytes memory consensus = new bytes(CONSENSUS_HEADER_LENGTH);
        assembly ("memory-safe") {
            let p := add(h, 0x20)
            mcopy(add(application, 0x20), add(p, 44), 118)
            mcopy(add(consensus, 0x20), p, 44)
        }
        bytes32 appHash = sha256(application);
        assembly ("memory-safe") {
            mstore(add(consensus, 76), appHash) // consensus[44:76] = applicationHash
        }
        f.id = sha256(consensus);
        assembly ("memory-safe") {
            let p := add(h, 0x20)
            mstore(add(f, 0x20), mload(p))
            mstore(add(f, 0x40), shr(224, mload(add(p, 32))))
            mstore(add(f, 0x60), shr(224, mload(add(p, 62))))
            mstore(add(f, 0x80), mload(add(p, 98)))
        }
    }

    /// @dev Fuel message id: sha256(sender ‖ recipient ‖ nonce ‖ amount(u64) ‖ data).
    function messageId(bytes32 sender, bytes32 recipient, bytes32 nonce, uint64 amount, bytes memory data)
        internal
        pure
        returns (bytes32)
    {
        return sha256(abi.encodePacked(sender, recipient, nonce, amount, data));
    }

    function leafDigest(bytes32 data) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(bytes1(0x00), data));
    }

    function nodeDigest(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(bytes1(0x01), left, right));
    }

    /// @dev Inclusion of the 32-byte leaf `data` at `index` in a tree of `size` leaves with root
    ///      `root` (RFC 9162 §2.1.3.2 audit-path check; siblings leaf to root).
    function verifyInclusion(bytes32 root, bytes32 data, uint256 index, uint256 size, bytes32[] memory proof)
        internal
        pure
        returns (bool)
    {
        if (index >= size) return false;
        uint256 fn = index;
        uint256 sn = size - 1;
        bytes32 r = leafDigest(data);
        for (uint256 i = 0; i < proof.length; i++) {
            if (sn == 0) return false;
            if (fn & 1 == 1 || fn == sn) {
                r = nodeDigest(proof[i], r);
                while (fn & 1 == 0 && fn != 0) {
                    fn >>= 1;
                    sn >>= 1;
                }
            } else {
                r = nodeDigest(r, proof[i]);
            }
            fn >>= 1;
            sn >>= 1;
        }
        return sn == 0 && r == root;
    }
}
