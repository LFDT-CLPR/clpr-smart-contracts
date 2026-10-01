// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @dev Builds java-tron-encoded headers, transactions and Merkle proofs for synthetic chains, with
///      the exact encodings the live fixtures use (field order of the generated protobuf code).
abstract contract TronTestBuilder is Test {
    uint256 internal constant N = 27;
    uint256 internal constant T = 19;
    uint64 internal constant INTERVAL = 1_800_000; // Nile maintenance interval
    uint64 internal constant OFFSET = 600_000; // Nile grid offset
    uint64 internal constant SLOT = 3000;
    string internal constant NILE = "tron:0xcd8690dc";

    /// @dev One synthetic Super Representative.
    struct Sr {
        address witness;
        uint256 pk; // private key of its signing key
        address key;
    }

    struct Hdr {
        uint64 number;
        uint64 timestamp;
        bytes32 parentHash;
        bytes32 txTrieRoot;
        address witness;
    }

    // ── Protobuf encoders ────────────────────────────────────────────────────

    function _tronAddr(address a) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0x41), a);
    }

    function _lenField(uint64 f, bytes memory v) internal pure returns (bytes memory) {
        return abi.encodePacked(PB.encodeFieldKey(f, 2), PB.encodeLengthDelimited(v));
    }

    function _headerRaw(Hdr memory h) internal pure returns (bytes memory) {
        return abi.encodePacked(
            PB.encodeVarintField(1, h.timestamp),
            _lenField(2, abi.encodePacked(h.txTrieRoot)),
            _lenField(3, abi.encodePacked(h.parentHash)),
            PB.encodeVarintField(7, h.number),
            _lenField(9, _tronAddr(h.witness)),
            PB.encodeVarintField(10, 38)
        );
    }

    function _blockId(Hdr memory h) internal pure returns (bytes32) {
        bytes32 hash = sha256(_headerRaw(h));
        return bytes32((uint256(h.number) << 192) | (uint256(hash) & ((1 << 192) - 1)));
    }

    function _sign(uint256 pk, bytes memory raw) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, sha256(raw));
        return abi.encodePacked(r, s, uint8(v - 27)); // java-tron writes v as 0/1
    }

    function _triggerTx(address owner, address target, bytes memory data, uint64 contractRet)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory trigger =
            abi.encodePacked(_lenField(1, _tronAddr(owner)), _lenField(2, _tronAddr(target)), _lenField(4, data));
        return _wrapTx(31, "type.googleapis.com/protocol.TriggerSmartContract", trigger, contractRet);
    }

    function _permissionUpdateTx(address owner, address witnessKey) internal pure returns (bytes memory) {
        bytes memory key = abi.encodePacked(_lenField(1, _tronAddr(witnessKey)), PB.encodeVarintField(2, 1));
        bytes memory witnessPerm = abi.encodePacked(
            PB.encodeVarintField(1, 1), // type Witness
            PB.encodeVarintField(2, 1), // id 1
            _lenField(3, bytes("witness")),
            PB.encodeVarintField(4, 1), // threshold
            _lenField(7, key)
        );
        bytes memory ownerKey = abi.encodePacked(_lenField(1, _tronAddr(owner)), PB.encodeVarintField(2, 1));
        bytes memory ownerPerm =
            abi.encodePacked(_lenField(3, bytes("owner")), PB.encodeVarintField(4, 1), _lenField(7, ownerKey));
        bytes memory update =
            abi.encodePacked(_lenField(1, _tronAddr(owner)), _lenField(2, ownerPerm), _lenField(3, witnessPerm));
        return _wrapTx(46, "type.googleapis.com/protocol.AccountPermissionUpdateContract", update, 0);
    }

    function _wrapTx(uint64 ctype, string memory url, bytes memory value, uint64 contractRet)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory any = abi.encodePacked(_lenField(1, bytes(url)), _lenField(2, value));
        bytes memory contractMsg = abi.encodePacked(PB.encodeVarintField(1, ctype), _lenField(2, any));
        bytes memory raw = abi.encodePacked(
            _lenField(1, hex"f58d"),
            _lenField(4, hex"d8375a8a47dbfb92"),
            PB.encodeVarintField(8, 1790822544733),
            _lenField(11, contractMsg),
            PB.encodeVarintField(14, 1790822244425),
            PB.encodeVarintField(18, 100_000_000)
        );
        bytes memory sig = new bytes(65);
        sig[0] = 0x11;
        bytes memory out = abi.encodePacked(_lenField(1, raw), _lenField(2, sig));
        if (contractRet != 0) out = abi.encodePacked(out, _lenField(5, PB.encodeVarintField(3, contractRet)));
        return out;
    }

    // ── Merkle ────────────────────────────────────────────────────────────────

    function _merkleRoot(bytes32[] memory leaves) internal pure returns (bytes32) {
        if (leaves.length == 0) return bytes32(0);
        bytes32[] memory level = leaves;
        while (level.length > 1) {
            bytes32[] memory nextLevel = new bytes32[]((level.length + 1) / 2);
            for (uint256 i = 0; i < level.length; i += 2) {
                nextLevel[i / 2] = i + 1 < level.length ? sha256(abi.encodePacked(level[i], level[i + 1])) : level[i];
            }
            level = nextLevel;
        }
        return level[0];
    }

    function _merkleProof(bytes32[] memory leaves, uint256 index) internal pure returns (bytes32[] memory proof) {
        bytes32[] memory tmp = new bytes32[](64);
        uint256 k;
        bytes32[] memory level = leaves;
        while (level.length > 1) {
            if (!(index == level.length - 1 && level.length % 2 == 1)) {
                tmp[k++] = level[index ^ 1];
            }
            bytes32[] memory nextLevel = new bytes32[]((level.length + 1) / 2);
            for (uint256 i = 0; i < level.length; i += 2) {
                nextLevel[i / 2] = i + 1 < level.length ? sha256(abi.encodePacked(level[i], level[i + 1])) : level[i];
            }
            level = nextLevel;
            index >>= 1;
        }
        proof = new bytes32[](k);
        for (uint256 i = 0; i < k; ++i) {
            proof[i] = tmp[i];
        }
    }

    Sr[] internal srs; // the trusted set, sorted by witness
    Sr internal newcomer; // an SR outside the set (self-keyed)

    function _initSrs() internal {
        Sr[] memory tmp = new Sr[](N);
        for (uint256 i = 0; i < N; ++i) {
            uint256 pk = 0xA11CE + i;
            address key = vm.addr(pk);
            // The last 7 SRs sign with a witness-permission key, as 6 of 27 mainnet SRs did in Oct 2026.
            address witness = i < 20 ? key : vm.addr(pk + 0x10000);
            tmp[i] = Sr({witness: witness, pk: pk, key: key});
        }
        _sort(tmp);
        for (uint256 i = 0; i < N; ++i) {
            srs.push(tmp[i]);
        }
        uint256 npk = 0xBEEF;
        newcomer = Sr({witness: vm.addr(npk), pk: npk, key: vm.addr(npk)});
    }

    // ── Set / anchor helpers ──────────────────────────────────────────────────

    function _sort(Sr[] memory a) internal pure {
        for (uint256 i = 1; i < a.length; ++i) {
            Sr memory x = a[i];
            uint256 j = i;
            while (j > 0 && a[j - 1].witness > x.witness) {
                a[j] = a[j - 1];
                --j;
            }
            a[j] = x;
        }
    }

    function _set() internal view returns (Sr[] memory s) {
        s = new Sr[](N);
        for (uint256 i = 0; i < N; ++i) {
            s[i] = srs[i];
        }
    }

    function _setRlp(Sr[] memory s) internal pure returns (bytes memory) {
        bytes[] memory items = new bytes[](s.length);
        for (uint256 i = 0; i < s.length; ++i) {
            bytes[] memory pair = new bytes[](2);
            pair[0] = RLP.encode(abi.encodePacked(s[i].witness));
            pair[1] = RLP.encode(abi.encodePacked(s[i].key));
            items[i] = RLP.encode(pair);
        }
        return RLP.encode(items);
    }

    function _setHash(Sr[] memory s) internal pure returns (bytes32) {
        bytes memory packed;
        for (uint256 i = 0; i < s.length; ++i) {
            packed = abi.encodePacked(packed, s[i].witness, s[i].key);
        }
        return keccak256(packed);
    }

    // ── Chain helpers ─────────────────────────────────────────────────────────

    /// @dev sigMode per header: 0 = signed by the producer's key, 1 = no signature (FN-DSA block),
    ///      2 = signed by a wrong key.
    function _chain(Hdr memory first, Sr[] memory producers, uint8[] memory sigMode)
        internal
        pure
        returns (bytes memory rlp, Hdr memory last)
    {
        bytes[] memory items = new bytes[](producers.length);
        Hdr memory h = first;
        for (uint256 i = 0; i < producers.length; ++i) {
            if (i > 0) {
                h = Hdr({
                    number: last.number + 1,
                    timestamp: last.timestamp + SLOT,
                    parentHash: _blockId(last),
                    txTrieRoot: bytes32(0),
                    witness: producers[i].witness
                });
            } else {
                h.witness = producers[0].witness;
            }
            bytes memory raw = _headerRaw(h);
            uint8 mode = sigMode.length > i ? sigMode[i] : 0;
            bytes memory sig = mode == 0 ? _sign(producers[i].pk, raw) : mode == 2 ? _sign(0xDEAD, raw) : bytes("");
            items[i] = _rlpHeader(raw, sig);
            last = h;
        }
        rlp = _rlpList(items);
    }

    function _firstN(uint256 count) internal view returns (Sr[] memory p) {
        p = new Sr[](count);
        for (uint256 i = 0; i < count; ++i) {
            p[i] = srs[i];
        }
    }

    function _noModes() internal pure returns (uint8[] memory) {
        return new uint8[](0);
    }

    /// @dev TxProof for `txBytes` placed at index 1 of a 3-tx block at (number, ts), confirmed by
    ///      `producers` (producers[0] produces the block itself).
    function _txProof(bytes memory txBytes, uint64 number, uint64 ts, Sr[] memory producers, uint8[] memory modes)
        internal
        pure
        returns (bytes memory)
    {
        bytes32[] memory leaves = new bytes32[](3);
        leaves[0] = sha256("other tx 0");
        leaves[1] = sha256(txBytes);
        leaves[2] = sha256("other tx 2");
        Hdr memory first = Hdr({
            number: number,
            timestamp: ts,
            parentHash: bytes32(uint256(number - 1) << 192),
            txTrieRoot: _merkleRoot(leaves),
            witness: address(0)
        });
        (bytes memory headers,) = _chain(first, producers, modes);
        return _rlpTxProof(headers, txBytes, 1, 3, _merkleProof(leaves, 1));
    }

    // ── RLP helpers ───────────────────────────────────────────────────────────

    function _rlpList(bytes[] memory items) internal pure returns (bytes memory) {
        return RLP.encode(items);
    }

    function _rlpEmptyList() internal pure returns (bytes memory) {
        return RLP.encode(new bytes[](0));
    }

    function _rlpHeader(bytes memory raw, bytes memory sig) internal pure returns (bytes memory) {
        bytes[] memory pair = new bytes[](2);
        pair[0] = RLP.encode(raw);
        pair[1] = RLP.encode(sig);
        return RLP.encode(pair);
    }

    function _rlpSiblings(bytes32[] memory s) internal pure returns (bytes memory) {
        bytes[] memory items = new bytes[](s.length);
        for (uint256 i = 0; i < s.length; ++i) {
            items[i] = RLP.encode(abi.encodePacked(s[i]));
        }
        return RLP.encode(items);
    }

    function _rlpTxProof(bytes memory headers, bytes memory txBytes, uint256 index, uint256 count, bytes32[] memory sib)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory items = new bytes[](5);
        items[0] = headers;
        items[1] = RLP.encode(txBytes);
        items[2] = RLP.encode(index);
        items[3] = RLP.encode(count);
        items[4] = _rlpSiblings(sib);
        return RLP.encode(items);
    }
}
