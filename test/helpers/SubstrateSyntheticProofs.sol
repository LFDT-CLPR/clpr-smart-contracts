// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Blake2b} from "@hiero-ledger/clpr/libraries/proof/substrate/Blake2b.sol";
import {ScaleCodec} from "@hiero-ledger/clpr/libraries/proof/substrate/ScaleCodec.sol";

/// @title SubstrateSyntheticProofs
/// @notice Builds Substrate state (LayoutV1 trie), headers and Frontier storage keys on the fly, so
///         tests can commit arbitrary values (e.g. any endpoint-manifest preimage) and still present
///         a valid proof. `_buildTrie` returns only the nodes on the paths of entries marked `prove`
///         (plus their hashed value nodes): exactly what `state_getReadProof` returns, which lets a
///         test omit a slot that IS in the trie and get a deterministic `MissingProofNode`.
abstract contract SubstrateSyntheticProofs is Test {
    bytes16 internal constant EVM_PALLET = 0x1da53b775b270400e7e61ed5cbc5a146; // twox128("EVM")
    bytes16 internal constant ACCOUNT_STORAGES = 0xab1160471b1418779239ba8e2b847e42; // twox128("AccountStorages")
    /// @dev Polkadot Paras::Heads(2034): twox128("Paras") ‖ twox128("Heads") ‖ twox64(2034 LE) ‖ 2034 LE.
    bytes internal constant PARA_HEAD_KEY_2034 =
        hex"cd710b30bd2eab0352ddcc26417aa1941b3c252fcb29d88eff4f3de5de4476c3c77a93d174890f1ff2070000";

    struct Entry {
        bytes key;
        bytes value;
        bool prove;
    }

    bytes[] private _proofNodes;

    // ── Frontier keys ────────────────────────────────────────────────────────

    function _evmKey(address account, bytes32 slot) internal view returns (bytes memory) {
        return abi.encodePacked(
            EVM_PALLET,
            ACCOUNT_STORAGES,
            Blake2b.hash128(abi.encodePacked(account)),
            account,
            Blake2b.hash128(abi.encodePacked(slot)),
            slot
        );
    }

    function _evmEntry(address account, bytes32 slot, bytes32 value, bool prove) internal view returns (Entry memory) {
        return Entry(_evmKey(account, slot), abi.encodePacked(value), prove);
    }

    // ── Headers ──────────────────────────────────────────────────────────────

    /// @dev SCALE header with the given digest items (each already SCALE-encoded).
    function _header(bytes32 parent, uint32 number, bytes32 stateRoot, bytes[] memory digest)
        internal
        pure
        returns (bytes memory h)
    {
        h = abi.encodePacked(
            parent,
            ScaleCodec.encodeCompact(number),
            stateRoot,
            keccak256(abi.encode(number)),
            ScaleCodec.encodeCompact(digest.length)
        );
        for (uint256 i; i < digest.length; ++i) {
            h = abi.encodePacked(h, digest[i]);
        }
    }

    function _header(bytes32 parent, uint32 number, bytes32 stateRoot) internal pure returns (bytes memory) {
        return _header(parent, number, stateRoot, new bytes[](0));
    }

    // ── Trie (LayoutV1) ──────────────────────────────────────────────────────

    /// @return root  blake2_256 of the root node.
    /// @return proof Nodes on the paths of entries with `prove` set (root always included).
    function _buildTrie(Entry[] memory entries) internal returns (bytes32 root, bytes[] memory proof) {
        delete _proofNodes;
        // Sort by key (insertion sort; tests use a handful of entries).
        for (uint256 i = 1; i < entries.length; ++i) {
            Entry memory e = entries[i];
            uint256 j = i;
            while (j > 0 && _less(e.key, entries[j - 1].key)) {
                entries[j] = entries[j - 1];
                --j;
            }
            entries[j] = e;
        }
        bytes[] memory nibs = new bytes[](entries.length);
        for (uint256 i; i < entries.length; ++i) {
            nibs[i] = _nibbles(entries[i].key);
        }
        bytes memory rootNode = entries.length == 0 ? bytes(hex"00") : _node(entries, nibs, 0, entries.length, 0);
        _proofNodes.push(rootNode);
        root = Blake2b.hash256(rootNode);
        proof = _proofNodes;
    }

    function _node(Entry[] memory es, bytes[] memory nibs, uint256 from, uint256 to, uint256 depth)
        private
        returns (bytes memory)
    {
        if (to - from == 1) {
            bytes memory p = _sliceNibbles(nibs[from], depth, nibs[from].length);
            (bool leafHashed, bytes memory leafVal) = _valueEnc(es[from]);
            return abi.encodePacked(
                _nodeHeader(leafHashed ? 0x20 : 0x40, leafHashed ? 3 : 2, p.length), _packNibbles(p), leafVal
            );
        }
        uint256 cp;
        while (true) {
            bool same = true;
            for (uint256 i = from; i < to; ++i) {
                if (nibs[i].length <= depth + cp || nibs[i][depth + cp] != nibs[from][depth + cp]) {
                    same = false;
                    break;
                }
            }
            if (!same) break;
            ++cp;
        }
        uint256 at = depth + cp;
        uint256 start = from;
        bool hashedValue;
        bytes memory val;
        bytes memory head = _nodeHeader(0x80, 2, cp);
        if (nibs[from].length == at) {
            (hashedValue, val) = _valueEnc(es[from]);
            head = hashedValue ? _nodeHeader(0x10, 4, cp) : _nodeHeader(0xc0, 2, cp);
            ++start;
        }
        (bytes memory children, uint16 bitmap) = _children(es, nibs, start, to, at);
        return abi.encodePacked(
            head,
            _packNibbles(_sliceNibbles(nibs[from], depth, at)),
            uint8(bitmap & 0xff),
            uint8(bitmap >> 8),
            val,
            children
        );
    }

    function _children(Entry[] memory es, bytes[] memory nibs, uint256 i, uint256 to, uint256 at)
        private
        returns (bytes memory children, uint16 bitmap)
    {
        while (i < to) {
            uint8 c = uint8(nibs[i][at]);
            uint256 j = i;
            bool proveChild;
            while (j < to && uint8(nibs[j][at]) == c) {
                proveChild = proveChild || es[j].prove;
                ++j;
            }
            children = abi.encodePacked(children, _ref(_node(es, nibs, i, j, at + 1), proveChild));
            bitmap |= uint16(1) << c;
            i = j;
        }
    }

    function _ref(bytes memory child, bool prove) private returns (bytes memory) {
        if (child.length >= 32) {
            if (prove) _proofNodes.push(child);
            return abi.encodePacked(ScaleCodec.encodeCompact(32), Blake2b.hash256(child));
        }
        return abi.encodePacked(ScaleCodec.encodeCompact(child.length), child);
    }

    function _valueEnc(Entry memory e) private returns (bool hashed, bytes memory enc) {
        if (e.value.length >= 33) {
            if (e.prove) _proofNodes.push(e.value);
            return (true, abi.encodePacked(Blake2b.hash256(e.value)));
        }
        return (false, abi.encodePacked(ScaleCodec.encodeCompact(e.value.length), e.value));
    }

    function _nodeHeader(uint8 prefix, uint256 maskBits, uint256 count) private pure returns (bytes memory out) {
        uint256 max = 255 >> maskBits;
        if (count < max) return abi.encodePacked(uint8(prefix + count));
        out = abi.encodePacked(uint8(prefix + max));
        uint256 rem = count - (max - 1);
        while (rem >= 256) {
            out = abi.encodePacked(out, uint8(255));
            rem -= 255;
        }
        out = abi.encodePacked(out, uint8(rem - 1));
    }

    function _nibbles(bytes memory k) private pure returns (bytes memory n) {
        n = new bytes(k.length * 2);
        for (uint256 i; i < k.length; ++i) {
            n[2 * i] = bytes1(uint8(k[i]) >> 4);
            n[2 * i + 1] = bytes1(uint8(k[i]) & 0x0f);
        }
    }

    function _sliceNibbles(bytes memory n, uint256 from, uint256 to) private pure returns (bytes memory out) {
        out = new bytes(to - from);
        for (uint256 i; i < out.length; ++i) {
            out[i] = n[from + i];
        }
    }

    function _packNibbles(bytes memory n) private pure returns (bytes memory out) {
        out = new bytes((n.length + 1) / 2);
        uint256 i;
        uint256 o;
        if (n.length % 2 == 1) {
            out[o++] = n[i++];
        }
        for (; i < n.length; i += 2) {
            out[o++] = bytes1((uint8(n[i]) << 4) | uint8(n[i + 1]));
        }
    }

    function _less(bytes memory a, bytes memory b) private pure returns (bool) {
        uint256 n = a.length < b.length ? a.length : b.length;
        for (uint256 i; i < n; ++i) {
            if (a[i] != b[i]) return uint8(a[i]) < uint8(b[i]);
        }
        return a.length < b.length;
    }
}
