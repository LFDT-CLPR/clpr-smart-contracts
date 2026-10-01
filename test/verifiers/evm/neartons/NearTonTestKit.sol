// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";

/// @notice Deterministic stand-in for Ed25519 in the synthetic suites: a "signature" is
///         keccak(pk, msg) ‖ keccak(msg, pk). Real Ed25519 (and the exact signed bytes of each chain)
///         is covered by the live-fixture suites, which replay genuine NEAR and TON signatures through
///         the pure-Solidity Ed25519Verifier.
contract MockEd25519 is IEd25519Verifier {
    function verify(bytes32 pubKey, bytes calldata message, bytes calldata signature) external pure returns (bool) {
        return keccak256(signature) == keccak256(sign(pubKey, message));
    }

    function sign(bytes32 pubKey, bytes memory message) public pure returns (bytes memory) {
        return abi.encodePacked(keccak256(abi.encode(pubKey, message)), keccak256(abi.encode(message, pubKey)));
    }
}

library NearTonFixtures {
    function manifest(bytes memory serviceAddress, uint64 version) internal pure returns (bytes memory) {
        ClprTypes.ClprEndpointManifest memory m;
        m.version = version;
        m.serviceAddress = serviceAddress;
        m.endpoints = new ClprTypes.Endpoint[](1);
        m.endpoints[0] =
            ClprTypes.Endpoint({ipAddress: "10.0.0.1", port: 50211, tlsCertificate: hex"01", accountId: hex"02"});
        return ClprProtobuf.encodeEndpointManifest(m);
    }

    function controlMessage(string memory chainId, bytes memory serviceAddress) internal pure returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory c;
        c.protocolVersion = 1;
        c.chainId = chainId;
        c.serviceAddress = serviceAddress;
        c.nanosSinceEpoch = 1_790_000_000_000_000_123;
        c.throttles = ClprTypes.Throttles({
            maxMessagesPerBundle: 10,
            maxMessagePayloadBytes: 4096,
            maxGasPerMessage: 500_000,
            maxQueueDepth: 100,
            maxSyncBytes: 65536,
            maxLocalEndpoints: 0,
            maxPeerEndpoints: 0
        });
        return ClprProtobuf.encodeControlMessage(c);
    }

    function bundleContent() internal pure returns (bytes memory) {
        ClprTypes.QueueMetadata memory meta;
        bytes[] memory payloads = new bytes[](2);
        payloads[0] = hex"0a0101";
        payloads[1] = hex"0a0102";
        return ClprProtobuf.encodeBundleContent(meta, payloads);
    }
}

/// @notice Builds NEAR state tries (RawTrieNodeWithSize, nibble-path encoding) for the synthetic
///         suites, and the path of nodes to one key.
library NearTrieBuilder {
    struct Entry {
        bytes nibbles;
        bytes value;
    }

    function nibblesOf(bytes memory key) internal pure returns (bytes memory n) {
        n = new bytes(key.length * 2);
        for (uint256 i = 0; i < key.length; i++) {
            n[2 * i] = bytes1(uint8(key[i]) >> 4);
            n[2 * i + 1] = bytes1(uint8(key[i]) & 0x0f);
        }
    }

    /// @return root the trie root; @return path nodes from the root to `target` (index into entries)
    function build(Entry[] memory entries, uint256 target) internal pure returns (bytes32 root, bytes[] memory path) {
        bytes[] memory acc = new bytes[](64);
        uint256 len;
        bytes memory node;
        (node, len) = _node(entries, _all(entries.length), 0, target, acc, 0);
        root = sha256(node);
        path = new bytes[](len);
        for (uint256 i = 0; i < len; i++) {
            path[i] = acc[i];
        }
    }

    uint256 internal constant ALL = type(uint256).max;

    /// @return root the trie root; @return nodes every node of the trie (for {pathTo})
    function buildAll(Entry[] memory entries) internal pure returns (bytes32 root, bytes[] memory nodes) {
        bytes[] memory acc = new bytes[](512);
        uint256 len;
        bytes memory node;
        (node, len) = _node(entries, _all(entries.length), 0, ALL, acc, 0);
        root = sha256(node);
        nodes = new bytes[](len);
        for (uint256 i = 0; i < len; i++) {
            nodes[i] = acc[i];
        }
    }

    /// @notice The nodes on `key`'s path, root first, ending at its value or where the key leaves the
    ///         trie (an exclusion proof).
    function pathTo(bytes32 root, bytes memory key, bytes[] memory all) internal pure returns (bytes[] memory path) {
        bytes memory nib = nibblesOf(key);
        bytes[] memory acc = new bytes[](128);
        uint256 n;
        uint256 pos;
        bytes32 h = root;
        for (;;) {
            bytes memory node = _byHash(all, h);
            acc[n++] = node;
            uint8 tag = uint8(node[0]);
            if (tag == 0 || tag == 3) {
                uint256 len = uint256(uint8(node[1])) | uint256(uint8(node[2])) << 8;
                uint8 first = uint8(node[5]);
                bool ok = true;
                uint256 p = pos;
                if (first & 0x10 != 0) {
                    ok = p < nib.length && uint8(nib[p]) == first & 0x0f;
                    p++;
                }
                for (uint256 j = 1; ok && j < len; j++) {
                    uint8 bt = uint8(node[5 + j]);
                    ok = p + 1 < nib.length && uint8(nib[p]) == bt >> 4 && uint8(nib[p + 1]) == bt & 0x0f;
                    p += 2;
                }
                if (!ok || tag == 0) break;
                pos = p;
                h = _at(node, 5 + len);
            } else {
                uint256 off = tag == 2 ? 37 : 1;
                uint256 bitmap = uint256(uint8(node[off])) | uint256(uint8(node[off + 1])) << 8;
                if (pos == nib.length) break;
                uint256 c = uint8(nib[pos]);
                if (bitmap & (1 << c) == 0) break;
                uint256 k;
                for (uint256 j = 0; j < c; j++) {
                    if (bitmap & (1 << j) != 0) k++;
                }
                h = _at(node, off + 2 + 32 * k);
                pos++;
            }
        }
        path = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            path[i] = acc[i];
        }
    }

    function _byHash(bytes[] memory all, bytes32 h) private pure returns (bytes memory) {
        for (uint256 i = 0; i < all.length; i++) {
            if (sha256(all[i]) == h) return all[i];
        }
        revert("trie: node not found");
    }

    function _at(bytes memory b, uint256 off) private pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 0x20), off))
        }
    }

    function _all(uint256 n) private pure returns (uint256[] memory idx) {
        idx = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            idx[i] = i;
        }
    }

    function _contains(uint256[] memory idx, uint256 t) private pure returns (bool) {
        for (uint256 i = 0; i < idx.length; i++) {
            if (idx[i] == t) return true;
        }
        return false;
    }

    function _encodePath(bytes memory nib, uint256 from, uint256 to, bool leaf) private pure returns (bytes memory e) {
        uint256 l = to - from;
        uint256 i = from;
        uint8 first = leaf ? 0x20 : 0;
        if (l % 2 == 1) {
            first += 0x10 + uint8(nib[from]);
            i++;
        }
        e = abi.encodePacked(first);
        for (; i < to; i += 2) {
            e = abi.encodePacked(e, bytes1(uint8(nib[i]) * 16 + uint8(nib[i + 1])));
        }
    }

    function _le32(uint256 v) private pure returns (bytes4) {
        return bytes4(uint32((v & 0xff) << 24 | ((v >> 8) & 0xff) << 16 | ((v >> 16) & 0xff) << 8 | (v >> 24)));
    }

    function _valueRef(bytes memory v) private pure returns (bytes memory) {
        return abi.encodePacked(_le32(v.length), sha256(v));
    }

    function _node(
        Entry[] memory e,
        uint256[] memory idx,
        uint256 depth,
        uint256 target,
        bytes[] memory acc,
        uint256 len
    ) private pure returns (bytes memory node, uint256 newLen) {
        bool onPath = target == ALL || _contains(idx, target);
        uint256 slot = len;
        if (onPath) len++;
        bytes8 mem = bytes8(0);
        if (idx.length == 1) {
            Entry memory x = e[idx[0]];
            bytes memory p = _encodePath(x.nibbles, depth, x.nibbles.length, true);
            node = abi.encodePacked(uint8(0), _le32(p.length), p, _valueRef(x.value), mem);
        } else {
            // common prefix beyond depth
            uint256 cp = 0;
            for (;;) {
                bool same = true;
                uint256 d = depth + cp;
                for (uint256 i = 0; i < idx.length; i++) {
                    if (e[idx[i]].nibbles.length <= d || e[idx[i]].nibbles[d] != e[idx[0]].nibbles[d]) {
                        same = false;
                        break;
                    }
                }
                if (!same) break;
                cp++;
            }
            if (cp > 0) {
                bytes memory child;
                (child, len) = _node(e, idx, depth + cp, target, acc, len);
                bytes memory p = _encodePath(e[idx[0]].nibbles, depth, depth + cp, false);
                node = abi.encodePacked(uint8(3), _le32(p.length), p, sha256(child), mem);
            } else {
                bytes memory valueRef;
                uint16 bitmap;
                bytes memory children;
                for (uint256 c = 0; c < 16; c++) {
                    uint256 cnt;
                    for (uint256 i = 0; i < idx.length; i++) {
                        if (e[idx[i]].nibbles.length > depth && uint8(e[idx[i]].nibbles[depth]) == c) cnt++;
                    }
                    if (cnt == 0) continue;
                    uint256[] memory sub = new uint256[](cnt);
                    uint256 k;
                    for (uint256 i = 0; i < idx.length; i++) {
                        if (e[idx[i]].nibbles.length > depth && uint8(e[idx[i]].nibbles[depth]) == c) {
                            sub[k++] = idx[i];
                        }
                    }
                    bytes memory child;
                    (child, len) = _node(e, sub, depth + 1, target, acc, len);
                    bitmap |= uint16(1 << c);
                    children = abi.encodePacked(children, sha256(child));
                }
                for (uint256 i = 0; i < idx.length; i++) {
                    if (e[idx[i]].nibbles.length == depth) valueRef = _valueRef(e[idx[i]].value);
                }
                bytes2 bm = bytes2(uint16((bitmap & 0xff) << 8 | (bitmap >> 8)));
                node = valueRef.length == 0
                    ? abi.encodePacked(uint8(1), bm, children, mem)
                    : abi.encodePacked(uint8(2), valueRef, bm, children, mem);
            }
        }
        if (onPath) acc[slot] = node;
        newLen = len;
    }
}
