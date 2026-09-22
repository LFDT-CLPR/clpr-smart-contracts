// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {MptWire} from "@test/helpers/MptWire.sol";

/// @dev Shared proof-building utilities for QBFT synthetic tests.
///      Produces fully valid QBFT block headers, MPT account/storage proofs, and
///      config proofs without external fixtures, using known validator keys.
abstract contract QbftSyntheticProofs is Test {
    // ── Block header ───────────────────────────────────────────────────────────

    function _buildHeaderAtNumber(uint256 blockNumber, bytes32 stateRoot, bytes memory extraDataInner)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory h = new bytes[](15);
        h[0] = RLP.encode(bytes32(0));
        h[1] = RLP.encode(bytes32(0));
        h[2] = RLP.encode(address(0));
        h[3] = RLP.encode(stateRoot);
        h[4] = RLP.encode(bytes32(0));
        h[5] = RLP.encode(bytes32(0));
        h[6] = RLP.encode(new bytes(256)); // bloom
        h[7] = RLP.encode(uint256(0));
        h[8] = RLP.encode(blockNumber);
        h[9] = RLP.encode(uint256(0));
        h[10] = RLP.encode(uint256(0));
        h[11] = RLP.encode(uint256(0));
        h[12] = RLP.encode(extraDataInner);
        h[13] = RLP.encode(bytes32(0));
        h[14] = RLP.encode(new bytes(8)); // nonce
        return RLP.encode(h);
    }

    function _buildHeader(bytes32 stateRoot, bytes memory extraDataInner) internal pure returns (bytes memory) {
        return _buildHeaderAtNumber(1, stateRoot, extraDataInner);
    }

    function _emptyHeader(uint256 nFields) internal pure returns (bytes memory) {
        bytes[] memory h = new bytes[](nFields);
        for (uint256 i = 0; i < nFields; i++) {
            h[i] = hex"80";
        }
        return RLP.encode(h);
    }

    function _buildExtraData(bytes[] memory seals, uint256 round) internal pure returns (bytes memory) {
        return _buildExtraDataListing(new address[](0), seals, round);
    }

    function _buildExtraDataListing(address[] memory listed, bytes[] memory seals, uint256 round)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory vItems = new bytes[](listed.length);
        for (uint256 i = 0; i < listed.length; i++) {
            vItems[i] = RLP.encode(listed[i]);
        }
        bytes[] memory extra = new bytes[](5);
        extra[0] = RLP.encode(new bytes(32)); // vanity
        extra[1] = RLP.encode(vItems); // validators
        extra[2] = RLP.encode(new bytes(0)); // vote
        extra[3] = RLP.encode(round);
        bytes[] memory wrappedSeals = new bytes[](seals.length);
        for (uint256 i = 0; i < seals.length; i++) {
            wrappedSeals[i] = RLP.encode(seals[i]);
        }
        extra[4] = RLP.encode(wrappedSeals);
        return RLP.encode(extra);
    }

    function _buildSealedCurrentHeader(uint256 blockNumber, bytes32 stateRoot, uint256 pk)
        internal
        pure
        returns (bytes memory)
    {
        address[] memory listed = new address[](1);
        listed[0] = vm.addr(pk);
        bytes memory sealingExtra = _buildExtraDataListing(listed, new bytes[](0), 0);
        bytes memory sealingHeader = _buildHeaderAtNumber(blockNumber, stateRoot, sealingExtra);
        bytes32 sealHash = keccak256(sealingHeader);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, sealHash);
        bytes[] memory seals = new bytes[](1);
        seals[0] = abi.encodePacked(r, s, uint8(v - 27));
        return _buildHeaderAtNumber(blockNumber, stateRoot, _buildExtraDataListing(listed, seals, 0));
    }

    function _buildMultiSealedHeaderAtBlock(
        uint256 blockNumber,
        bytes32 stateRoot,
        uint256 round,
        uint256 extraPk1,
        uint256 extraPk2
    ) internal pure returns (bytes memory) {
        bytes memory sealingExtra = _buildExtraData(new bytes[](0), round);
        bytes memory sealingHeader = _buildHeaderAtNumber(blockNumber, stateRoot, sealingExtra);
        bytes32 sealHash = keccak256(sealingHeader);
        uint256 total = (extraPk1 != 0 ? 1 : 0) + (extraPk2 != 0 ? 1 : 0);
        bytes[] memory seals = new bytes[](total);
        uint256 idx;
        if (extraPk1 != 0) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(extraPk1, sealHash);
            seals[idx++] = abi.encodePacked(r, s, uint8(v - 27));
        }
        if (extraPk2 != 0) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(extraPk2, sealHash);
            seals[idx++] = abi.encodePacked(r, s, uint8(v - 27));
        }
        return _buildHeaderAtNumber(blockNumber, stateRoot, _buildExtraData(seals, round));
    }

    // ── MPT helpers ────────────────────────────────────────────────────────────

    function _buildSyntheticMPTProof(bytes32 keyHash, bytes memory leafValue)
        internal
        pure
        returns (bytes32 root, bytes memory proofRlp)
    {
        bytes memory leafNode = MptWire.leaf(keyHash, RLP.encode(leafValue));
        root = keccak256(leafNode);
        proofRlp = MptWire.wrapOne(leafNode);
    }

    function _buildAccountRlp(bytes32 storageRoot, bytes32 codeHash) internal pure returns (bytes memory) {
        bytes[] memory fields = new bytes[](4);
        fields[0] = RLP.encode(uint256(0)); // nonce
        fields[1] = RLP.encode(uint256(0)); // balance
        fields[2] = RLP.encode(storageRoot);
        fields[3] = RLP.encode(codeHash);
        return RLP.encode(fields);
    }

    function _buildSyntheticAccountProof(address service, bytes32 storageRoot, bytes32 codeHash)
        internal
        pure
        returns (bytes32 stateRoot, bytes memory accountProofRlp)
    {
        bytes32 keyHash = keccak256(abi.encodePacked(service));
        return _buildSyntheticMPTProof(keyHash, _buildAccountRlp(storageRoot, codeHash));
    }

    /// @dev All slots are proven absent (return zero) via a dummy leaf keyed by 0xFF..FF.
    function _buildZeroStorageProof(uint256 count)
        internal
        pure
        returns (bytes32 storageRoot, bytes memory storageProofRlp)
    {
        bytes memory dummyLeafNode = MptWire.leaf(bytes32(type(uint256).max), RLP.encode(new bytes(0)));
        storageRoot = keccak256(dummyLeafNode);
        bytes memory nodeListRlp = MptWire.wrapOne(dummyLeafNode);
        bytes[] memory entries = new bytes[](count);
        for (uint256 i = 0; i < count; i++) {
            bytes[] memory entry = new bytes[](2);
            entry[0] = RLP.encode(abi.encodePacked(bytes32(uint256(i))));
            entry[1] = nodeListRlp;
            entries[i] = RLP.encode(entry);
        }
        storageProofRlp = RLP.encode(entries);
    }

    /// @dev Build a 5-entry storage proof for `channelId`'s channel slots (+1, +2, +4, +5, +16),
    ///      all proven as zero. The trie root is anchored to slot+1's leaf; the other paths diverge
    ///      so getOrEmpty returns empty → zero value.
    function _buildChannelStorageProof(bytes32 channelId)
        internal
        pure
        returns (bytes32 storageRoot, bytes memory storageProofRlp)
    {
        bytes32 cBase = keccak256(abi.encode(channelId, uint256(15)));
        bytes memory proofNodesRlp;
        (storageRoot, proofNodesRlp) =
            _buildSyntheticMPTProof(keccak256(abi.encodePacked(bytes32(uint256(cBase) + 1))), RLP.encode(uint256(0)));
        uint8[5] memory offsets = [1, 2, 4, 5, 16];
        bytes[] memory entries = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            bytes32 slotKey = bytes32(uint256(cBase) + offsets[i]);
            bytes[] memory entry = new bytes[](2);
            entry[0] = RLP.encode(abi.encodePacked(slotKey));
            entry[1] = proofNodesRlp;
            entries[i] = RLP.encode(entry);
        }
        storageProofRlp = RLP.encode(entries);
    }

    /// @dev Like {_buildChannelStorageProof}, but the trie anchors the +16 slot
    ///      (Channel.endpointManifestVersion) with `manifestVersion` while the other slots
    ///      prove zero — exercises the QueueMetadata.endpointManifestVersion decode path.
    function _buildChannelStorageProofWithManifestVersion(bytes32 channelId, uint64 manifestVersion)
        internal
        pure
        returns (bytes32 storageRoot, bytes memory storageProofRlp)
    {
        bytes32 cBase = keccak256(abi.encode(channelId, uint256(15)));
        bytes memory proofNodesRlp;
        (storageRoot, proofNodesRlp) = _buildSyntheticMPTProof(
            keccak256(abi.encodePacked(bytes32(uint256(cBase) + 16))), RLP.encode(uint256(manifestVersion))
        );
        uint8[5] memory offsets = [1, 2, 4, 5, 16];
        bytes[] memory entries = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            bytes32 slotKey = bytes32(uint256(cBase) + offsets[i]);
            bytes[] memory entry = new bytes[](2);
            entry[0] = RLP.encode(abi.encodePacked(slotKey));
            entry[1] = proofNodesRlp;
            entries[i] = RLP.encode(entry);
        }
        storageProofRlp = RLP.encode(entries);
    }

    /// @dev Build a bundle-scoped 6-entry storage proof with ackedMessageId=3 (non-zero, distinct
    ///      from nextExpectedReplyId=0) to catch wrong-field reads. ackedMessageId lives at offset 0
    ///      (bits 0-63) in Channel slot+2; nextExpectedReplyId lives at offset 16 (bits 128-191).
    ///      A verifier that reads slot+2 >> 128 instead of slot+2 >> 0 would derive
    ///      bundleLastMessageId = 0+1 = 1 instead of 3+1 = 4, look for the wrong message-slot key,
    ///      and hit SlotNotProven — making this a regression test for that exact bug.
    function _buildChannelStorageProof6(bytes32 channelId)
        internal
        pure
        returns (bytes32 storageRoot, bytes memory storageProofRlp)
    {
        bytes32 cBase = keccak256(abi.encode(channelId, uint256(15)));
        bytes memory proofNodesRlp;
        // slot+1 value: nextMessageId=1 packed at bits [168..231]
        (storageRoot, proofNodesRlp) = _buildSyntheticMPTProof(
            keccak256(abi.encodePacked(bytes32(uint256(cBase) + 1))), RLP.encode(uint256(1) << 168)
        );
        // 5th slot: _messageQueues[channelId][nextMessageId-1=0].runningHashAfterProcessing (+1)
        bytes32 qBase = keccak256(abi.encode(channelId, uint256(1)));
        bytes32 msgBase = keccak256(abi.encode(uint64(0), qBase));
        bytes32 msgSlot = bytes32(uint256(msgBase) + 1);

        uint8[5] memory offsets = [1, 2, 4, 5, 16];
        bytes[] memory entries = new bytes[](6);
        for (uint256 i = 0; i < 5; i++) {
            bytes32 slotKey = bytes32(uint256(cBase) + offsets[i]);
            bytes[] memory entry = new bytes[](2);
            entry[0] = RLP.encode(abi.encodePacked(slotKey));
            entry[1] = proofNodesRlp;
            entries[i] = RLP.encode(entry);
        }
        bytes[] memory entry6 = new bytes[](2);
        entry6[0] = RLP.encode(abi.encodePacked(msgSlot));
        entry6[1] = proofNodesRlp;
        entries[5] = RLP.encode(entry6);
        storageProofRlp = RLP.encode(entries);
    }

    /// @dev Same shape as {_buildChannelStorageProof6} but with nextMessageId=0 (slot+1 encodes 0
    ///      at bits 168-231). Per the CLPR spec nextMessageId starts at 1, so 0 means no message was
    ///      ever sent and no last-message running-hash slot exists. A 6-entry proof in this state is
    ///      malformed — exercises the InvalidNextMessageId guard. (The bundle-scoped payloadCount
    ///      form this helper previously tested was reverted on main by #379.)
    function _buildChannelStorageProof6ZeroNextMessageId(bytes32 channelId)
        internal
        pure
        returns (bytes32 storageRoot, bytes memory storageProofRlp)
    {
        bytes32 cBase = keccak256(abi.encode(channelId, uint256(15)));
        bytes memory proofNodesRlp;
        // slot+1 value with nextMessageId=0 (i.e. untouched/default)
        (storageRoot, proofNodesRlp) =
            _buildSyntheticMPTProof(keccak256(abi.encodePacked(bytes32(uint256(cBase) + 1))), RLP.encode(uint256(0)));
        // The message-slot key is irrelevant here: `nextMessageId - 1` would underflow before this
        // entry is ever looked up, so any key reproduces the malformed case.
        bytes32 qBase = keccak256(abi.encode(channelId, uint256(1)));
        bytes32 msgBase = keccak256(abi.encode(uint64(0), qBase));
        bytes32 msgSlot = bytes32(uint256(msgBase) + 1);

        uint8[5] memory offsets = [1, 2, 4, 5, 16];
        bytes[] memory entries = new bytes[](6);
        for (uint256 i = 0; i < 5; i++) {
            bytes32 slotKey = bytes32(uint256(cBase) + offsets[i]);
            bytes[] memory entry = new bytes[](2);
            entry[0] = RLP.encode(abi.encodePacked(slotKey));
            entry[1] = proofNodesRlp;
            entries[i] = RLP.encode(entry);
        }
        bytes[] memory entry6 = new bytes[](2);
        entry6[0] = RLP.encode(abi.encodePacked(msgSlot));
        entry6[1] = proofNodesRlp;
        entries[5] = RLP.encode(entry6);
        storageProofRlp = RLP.encode(entries);
    }

    // ── Config proof ───────────────────────────────────────────────────────────

    /// @dev A header-mode config proof: RLP([serviceAddr, chainId, peerConfigNanos, throttles(5),
    ///      descriptor, blockHeader]) with the descriptor [mode = 0, codeHash]. The header (block 0)
    ///      lists the single validator `vm.addr(validatorPk)` and is sealed by it.
    function _buildSyntheticConfigProof(
        uint256 validatorPk,
        address peerService,
        bytes32 codeHash,
        string memory chainId
    ) internal pure returns (bytes memory) {
        bytes memory header = _buildSealedCurrentHeader(0, bytes32(0), validatorPk);
        return _buildHeaderModeConfigProof(header, peerService, codeHash, chainId);
    }

    function _buildHeaderModeConfigProof(
        bytes memory header,
        address peerService,
        bytes32 codeHash,
        string memory chainId
    ) internal pure returns (bytes memory) {
        bytes[] memory throttleItems = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            throttleItems[i] = RLP.encode(uint256(0));
        }
        bytes[] memory taItems = new bytes[](2);
        taItems[0] = RLP.encode(uint256(0)); // mode: header
        taItems[1] = RLP.encode(codeHash);

        bytes[] memory items = new bytes[](6);
        items[0] = RLP.encode(abi.encodePacked(peerService));
        items[1] = RLP.encode(bytes(chainId));
        items[2] = RLP.encode(uint256(0)); // peerConfigNanos
        items[3] = RLP.encode(throttleItems);
        items[4] = RLP.encode(RLP.encode(taItems));
        items[5] = header;
        return RLP.encode(items);
    }
}
