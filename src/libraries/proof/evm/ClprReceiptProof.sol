// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title ClprReceiptProof
/// @notice Inclusion of one transaction receipt in a block's receipts trie (Yellow Paper §4.3.2: key =
///         RLP(transactionIndex), value = the receipt, typed receipts prefixed by their type byte),
///         and extraction of one log from it. Unlike {MerklePatriciaProof} the trie key is not a
///         32-byte hash, so the walk follows the key's own nibbles.
library ClprReceiptProof {
    error ReceiptProofHash(uint256 node);
    error ReceiptProofNode(uint256 node);
    error ReceiptProofKey();
    error ReceiptProofInline();
    error ReceiptFailed();
    error LogIndexOutOfRange(uint256 index, uint256 count);

    struct Log {
        address emitter;
        bytes32[] topics;
        bytes data;
    }

    /// @notice The receipt for transaction `index` under `receiptsRoot`, proven by `proof` (nodes root
    ///         first).
    function verifyReceipt(bytes32 receiptsRoot, uint256 index, bytes[] memory proof)
        internal
        pure
        returns (bytes memory receipt)
    {
        bytes memory key = RLP.encode(index);
        uint256 nibbles = key.length * 2;
        uint256 at; // nibble cursor
        bytes32 expect = receiptsRoot;
        for (uint256 i = 0; i < proof.length; ++i) {
            bytes memory node = proof[i];
            if (keccak256(node) != expect) revert ReceiptProofHash(i);
            Memory.Slice[] memory items = RLP.decodeList(node);
            if (items.length == 17) {
                if (at == nibbles) return RLP.readBytes(items[16]);
                bytes memory child = RLP.readBytes(items[_nib(key, at)]);
                if (child.length != 32) revert ReceiptProofInline();
                expect = bytes32(child);
                ++at;
            } else if (items.length == 2) {
                bytes memory path = RLP.readBytes(items[0]);
                if (path.length == 0) revert ReceiptProofNode(i);
                uint8 flag = uint8(path[0]) >> 4;
                if (flag > 3) revert ReceiptProofNode(i);
                uint256 plen = path.length * 2 - (flag & 1 == 1 ? 1 : 2);
                uint256 pstart = flag & 1 == 1 ? 1 : 2;
                for (uint256 k = 0; k < plen; ++k) {
                    if (at + k >= nibbles || _nib(path, pstart + k) != _nib(key, at + k)) revert ReceiptProofKey();
                }
                at += plen;
                if (flag >= 2) {
                    if (at != nibbles || i + 1 != proof.length) revert ReceiptProofKey();
                    return RLP.readBytes(items[1]);
                }
                bytes memory child = RLP.readBytes(items[1]);
                if (child.length != 32) revert ReceiptProofInline();
                expect = bytes32(child);
            } else {
                revert ReceiptProofNode(i);
            }
        }
        revert ReceiptProofKey();
    }

    /// @notice Log `logIndex` of a successful receipt (EIP-2718 typed or legacy; status must be 1).
    function successfulLog(bytes memory receipt, uint256 logIndex) internal pure returns (Log memory log) {
        if (receipt.length == 0) revert ReceiptFailed();
        bytes memory body = receipt;
        if (uint8(receipt[0]) < 0x80) {
            body = new bytes(receipt.length - 1);
            for (uint256 i = 0; i < body.length; ++i) {
                body[i] = receipt[i + 1];
            }
        }
        Memory.Slice[] memory r = RLP.decodeList(body);
        if (r.length != 4 || RLP.readUint256(r[0]) != 1) revert ReceiptFailed();
        Memory.Slice[] memory logs = RLP.readList(r[3]);
        if (logIndex >= logs.length) revert LogIndexOutOfRange(logIndex, logs.length);
        Memory.Slice[] memory l = RLP.readList(logs[logIndex]);
        if (l.length != 3) revert ReceiptProofNode(type(uint256).max);
        log.emitter = RLP.readAddress(l[0]);
        Memory.Slice[] memory ts = RLP.readList(l[1]);
        log.topics = new bytes32[](ts.length);
        for (uint256 i = 0; i < ts.length; ++i) {
            log.topics[i] = RLP.readBytes32(ts[i]);
        }
        log.data = RLP.readBytes(l[2]);
    }

    function _nib(bytes memory b, uint256 i) private pure returns (uint256) {
        uint8 x = uint8(b[i / 2]);
        return i % 2 == 0 ? x >> 4 : x & 15;
    }
}
