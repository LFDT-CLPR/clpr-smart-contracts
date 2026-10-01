// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title MixinLib
/// @notice Mixin kernel binary formats (MixinNetwork/mixin @ 1cd2882, common/encoding.go):
///         - Snapshot payload (`EncodeSnapshotPayload`, version 2): 0x7777 ‖ 0x00 ‖ 0x02 ‖ nodeId(32)
///           ‖ round(u64) ‖ references (u16 0, or u16 2 ‖ self(32) ‖ external(32)) ‖ u16 n ‖ n sorted
///           transaction hashes(32) ‖ timestamp(u64) ‖ an absent CoSi signature (u64 0). Its BLAKE3
///           is the snapshot hash the kernel nodes sign (`Snapshot.PayloadHash`).
///         - Transaction (`EncodeTransaction`, version 5): 0x7777 ‖ 0x00 ‖ 0x05 ‖ asset(32) ‖ inputs ‖
///           outputs ‖ references ‖ u32 extraLength ‖ extra ‖ signatures. The transaction hash is
///           BLAKE3 of the payload: the same encoding with an empty signature map (u16 0) at the end.
///         All integers are big-endian.
library MixinLib {
    error BadSnapshot(uint256 offset);
    error BadTransaction(uint256 offset);

    struct Snapshot {
        bytes32 nodeId;
        uint64 round;
        uint64 timestamp;
        bytes32[] transactions;
    }

    function _u16(bytes memory b, uint256 at) private pure returns (uint256 v) {
        if (at + 2 > b.length) revert BadTransaction(at);
        assembly ("memory-safe") {
            v := shr(240, mload(add(add(b, 0x20), at)))
        }
    }

    function _u64(bytes memory b, uint256 at) private pure returns (uint64 v) {
        assembly ("memory-safe") {
            v := shr(192, mload(add(add(b, 0x20), at)))
        }
    }

    function _b32(bytes memory b, uint256 at) private pure returns (bytes32 v) {
        assembly ("memory-safe") {
            v := mload(add(add(b, 0x20), at))
        }
    }

    /// @notice Parse a version-2 snapshot payload (the hashed form: no signature, no topology).
    function parseSnapshot(bytes memory p) internal pure returns (Snapshot memory s) {
        // fixed head: magic(2) version(2) nodeId(32) round(8) refCount(2)
        if (p.length < 46 + 2 + 32 + 8 + 8) revert BadSnapshot(0);
        if (uint8(p[0]) != 0x77 || uint8(p[1]) != 0x77 || uint8(p[2]) != 0 || uint8(p[3]) != 2) revert BadSnapshot(0);
        s.nodeId = _b32(p, 4);
        s.round = _u64(p, 36);
        uint256 at = 44;
        uint256 refs = _u16(p, at);
        at += 2;
        if (refs != 0 && refs != 2) revert BadSnapshot(at);
        at += refs * 32;
        uint256 n = _u16(p, at);
        at += 2;
        if (n == 0 || n > 255) revert BadSnapshot(at);
        if (p.length != at + n * 32 + 16) revert BadSnapshot(at);
        s.transactions = new bytes32[](n);
        for (uint256 i = 0; i < n; ++i) {
            s.transactions[i] = _b32(p, at + 32 * i);
        }
        at += n * 32;
        s.timestamp = _u64(p, at);
        if (_u64(p, at + 8) != 0) revert BadSnapshot(at + 8); // the hashed payload has no signature
    }

    struct Transaction {
        bytes32 asset;
        uint256 inputCount;
        bytes32 input0Hash;
        uint256 input0Index;
        uint256 outputCount;
        uint8 output0Type;
        bytes extra;
        uint256 payloadLength; // bytes up to and including the u16 0 signature count
    }

    /// @notice Parse a version-5 transaction payload; it must end right after an empty signature map.
    function parseTransaction(bytes memory t) internal pure returns (Transaction memory out) {
        if (t.length < 38 || uint8(t[0]) != 0x77 || uint8(t[1]) != 0x77 || uint8(t[2]) != 0 || uint8(t[3]) != 5) {
            revert BadTransaction(0);
        }
        out.asset = _b32(t, 4);
        uint256 at = 36; // after asset
        uint256 n = _u16(t, at);
        at += 2;
        if (n == 0) revert BadTransaction(at);
        out.inputCount = n;
        for (uint256 i = 0; i < n; ++i) {
            if (i == 0) {
                out.input0Hash = _b32(t, at);
                out.input0Index = _u16(t, at + 32);
            }
            at = _skipInput(t, at);
        }
        n = _u16(t, at);
        at += 2;
        out.outputCount = n;
        if (n > 0) {
            if (at + 2 > t.length) revert BadTransaction(at);
            out.output0Type = uint8(t[at + 1]);
        }
        for (uint256 i = 0; i < n; ++i) {
            at = _skipOutput(t, at);
        }
        n = _u16(t, at); // references
        at += 2 + n * 32;
        if (at + 4 > t.length) revert BadTransaction(at);
        uint256 el;
        assembly ("memory-safe") {
            el := shr(224, mload(add(add(t, 0x20), at)))
        }
        at += 4;
        if (at + el + 2 != t.length) revert BadTransaction(at);
        bytes memory extra = new bytes(el);
        assembly ("memory-safe") {
            mcopy(add(extra, 0x20), add(add(t, 0x20), at), el)
        }
        out.extra = extra;
        at += el;
        if (_u16(t, at) != 0) revert BadTransaction(at); // payload form: empty signature map
        out.payloadLength = t.length;
    }

    function _skipInput(bytes memory t, uint256 at) private pure returns (uint256) {
        at += 34; // hash + index
        at += 2 + _u16(t, at); // genesis
        if (_present(t, at)) {
            at += 2 + 32; // magic + chain
            at += 2 + _u16(t, at); // asset key
            at += 2 + _u16(t, at); // transaction
            at += 8; // index
            at += 2 + _u16(t, at); // amount
        } else {
            at += 2;
        }
        if (_present(t, at)) {
            at += 2;
            at += 2 + _u16(t, at); // group
            at += 8; // batch
            at += 2 + _u16(t, at); // amount
        } else {
            at += 2;
        }
        return at;
    }

    function _skipOutput(bytes memory t, uint256 at) private pure returns (uint256) {
        at += 2; // 0x00 ‖ type
        at += 2 + _u16(t, at); // amount
        at += 2 + 32 * _u16(t, at); // keys
        at += 32; // mask
        at += 2 + _u16(t, at); // script
        if (_present(t, at)) {
            at += 2;
            at += 2 + _u16(t, at); // address
            at += 2 + _u16(t, at); // tag
        } else {
            at += 2;
        }
        return at;
    }

    /// @dev 0x7777 = present, 0x0000 = absent (`magic` / `null` in encoding.go); anything else is invalid.
    function _present(bytes memory t, uint256 at) private pure returns (bool) {
        uint256 v = _u16(t, at);
        if (v == 0x7777) return true;
        if (v == 0) return false;
        revert BadTransaction(at);
    }
}
