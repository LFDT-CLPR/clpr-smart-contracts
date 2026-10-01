// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {CosmWasmSyntheticChain} from "@test/helpers/CosmWasmSyntheticChain.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @dev Synthetic Polygon PoS for PolygonPosVerifier tests: a Heimdall chain with real secp256k1eth
///      signatures ({CometBftSyntheticChain}), a real two-leaf IAVL `milestone` store (milestone
///      0x81‖count and the count item 0x83), a real RLP Bor header whose keccak is the milestone
///      hash, and real (small) Merkle-Patricia tries for the Bor state and ClprService storage.
abstract contract PolygonSyntheticChain is CosmWasmSyntheticChain {
    address internal constant SVC = 0x1111111111111111111111111111111111111111;
    uint64 internal constant COUNT = 5;
    uint64 internal constant BOR_NUMBER = 94_745_706;
    string internal constant BOR_CHAIN = "137";

    Val[] internal setA; // powers 40/30/20/10 → validators 0+1 clear 2/3
    Val[] internal setB;
    bytes32 internal hashA;
    bytes32 internal hashB;

    /// @dev One synthetic chain state, bottom-up.
    struct World {
        Trie2 st;
        bytes storageProof; // 5 channel slots
        bytes extraProof; // slot `extraSlot` (manifest commitment or config service address)
        bytes accountProof;
        bytes32 stateRoot;
        bytes borHeader;
        bytes milestone;
        Tree tree; // milestone store
    }

    function _initSets() internal {
        setA.push(_secpVal("a0", 40));
        setA.push(_secpVal("a1", 30));
        setA.push(_secpVal("a2", 20));
        setA.push(_secpVal("a3", 10));
        setB.push(_secpVal("b0", 50));
        setB.push(_secpVal("b1", 25));
        setB.push(_secpVal("b2", 25));
        hashA = _setHash(setA);
        hashB = _setHash(setB);
    }

    // ═════════════════════════════════════════════════════════════════════════
    //   Merkle-Patricia helpers (leaves are always ≥ 32 B, so hash-referenced)
    // ═════════════════════════════════════════════════════════════════════════

    function _leaf(bytes32 keyHash, bytes memory value, bool afterBranch) internal pure returns (bytes memory) {
        bytes memory path;
        if (afterBranch) {
            path = new bytes(32);
            path[0] = bytes1(0x30 | (uint8(keyHash[0]) & 0x0f)); // odd leaf, 63 nibbles
            for (uint256 i = 1; i < 32; ++i) {
                path[i] = keyHash[i];
            }
        } else {
            path = new bytes(33);
            path[0] = 0x20; // even leaf, 64 nibbles
            for (uint256 i; i < 32; ++i) {
                path[i + 1] = keyHash[i];
            }
        }
        bytes[] memory items = new bytes[](2);
        items[0] = RLP.encode(path);
        items[1] = RLP.encode(value);
        return RLP.encode(items);
    }

    function _proof(bytes memory n0) internal pure returns (bytes memory) {
        bytes[] memory nodes = new bytes[](1);
        nodes[0] = RLP.encode(n0);
        return RLP.encode(nodes);
    }

    function _proof(bytes memory n0, bytes memory n1) internal pure returns (bytes memory) {
        bytes[] memory nodes = new bytes[](2);
        nodes[0] = RLP.encode(n0);
        nodes[1] = RLP.encode(n1);
        return RLP.encode(nodes);
    }

    /// @dev A trie with one leaf.
    function _mpt1(bytes32 k, bytes memory v) internal pure returns (bytes32 root, bytes memory proof) {
        bytes memory l = _leaf(k, v, false);
        return (keccak256(l), _proof(l));
    }

    /// @dev A trie with two leaves under one branch; the keys' first nibbles must differ.
    struct Trie2 {
        bytes32 root;
        bytes branch;
        bytes l1;
        bytes l2;
        uint8 n1;
        uint8 n2;
    }

    function _mpt2(bytes32 k1, bytes memory v1, bytes32 k2, bytes memory v2) internal pure returns (Trie2 memory t) {
        t.n1 = uint8(k1[0]) >> 4;
        t.n2 = uint8(k2[0]) >> 4;
        require(t.n1 != t.n2, "first nibbles collide");
        t.l1 = _leaf(k1, v1, true);
        t.l2 = _leaf(k2, v2, true);
        bytes[] memory items = new bytes[](17);
        for (uint256 i; i < 17; ++i) {
            items[i] = hex"80";
        }
        items[t.n1] = RLP.encode(keccak256(t.l1));
        items[t.n2] = RLP.encode(keccak256(t.l2));
        t.branch = RLP.encode(items);
        t.root = keccak256(t.branch);
    }

    /// @dev The proof nodes for `slot`: down to its leaf, or just the branch when its child is empty.
    function _proofFor(Trie2 memory t, bytes32 slot) internal pure returns (bytes memory) {
        uint8 n = uint8(_slotHash(slot)[0]) >> 4;
        if (n == t.n1) return _proof(t.branch, t.l1);
        if (n == t.n2) return _proof(t.branch, t.l2);
        return _proof(t.branch);
    }

    function _entries(Trie2 memory t, bytes32[] memory slots) internal pure returns (bytes memory) {
        bytes[] memory es = new bytes[](slots.length);
        for (uint256 i; i < slots.length; ++i) {
            bytes[] memory e = new bytes[](2);
            e[0] = RLP.encode(slots[i]);
            e[1] = _proofFor(t, slots[i]);
            es[i] = RLP.encode(e);
        }
        return RLP.encode(es);
    }

    function _slotHash(bytes32 slot) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(slot));
    }

    function _channelSlots() internal pure returns (bytes32[] memory s) {
        bytes32 cBase = keccak256(abi.encode(CHANNEL, uint256(15)));
        uint8[5] memory offsets = [1, 2, 4, 5, 16];
        s = new bytes32[](5);
        for (uint256 i; i < 5; ++i) {
            s[i] = bytes32(uint256(cBase) + offsets[i]);
        }
    }

    function _one(bytes32 x) internal pure returns (bytes32[] memory s) {
        s = new bytes32[](1);
        s[0] = x;
    }

    // ═════════════════════════════════════════════════════════════════════════
    //   Chain builders
    // ═════════════════════════════════════════════════════════════════════════

    function _borHeader(bytes32 stateRoot, uint64 number) internal pure returns (bytes memory) {
        bytes[] memory f = new bytes[](16);
        f[0] = RLP.encode(keccak256("parent"));
        f[1] = RLP.encode(keccak256(hex"c0"));
        f[2] = RLP.encode(address(0));
        f[3] = RLP.encode(stateRoot);
        f[4] = RLP.encode(keccak256("txs"));
        f[5] = RLP.encode(keccak256("receipts"));
        f[6] = RLP.encode(new bytes(256));
        f[7] = RLP.encode(uint256(1));
        f[8] = RLP.encode(uint256(number));
        f[9] = RLP.encode(uint256(160_000_000));
        f[10] = RLP.encode(uint256(20_000_000));
        f[11] = RLP.encode(uint256(1_790_830_379));
        f[12] = RLP.encode(bytes(hex"d78301100883626f72"));
        f[13] = RLP.encode(bytes32(0));
        f[14] = RLP.encode(new bytes(8));
        f[15] = RLP.encode(uint256(30 gwei));
        return RLP.encode(f);
    }

    function _milestone(uint64 endBlock, bytes32 hash, string memory borChainId) internal pure returns (bytes memory) {
        return abi.encodePacked(
            PB.encodeBytesField(1, bytes("0xeedba2484aaf940f37cd3cd21a5d7c4a7dafbfc0")),
            PB.encodeVarintField(2, endBlock - 1),
            PB.encodeVarintField(3, endBlock),
            PB.encodeBytesField(4, abi.encodePacked(hash)),
            PB.encodeBytesField(5, bytes(borChainId)),
            PB.encodeBytesField(6, bytes("bc405c45")),
            PB.encodeVarintField(7, 1_790_830_379),
            PB.encodeVarintField(8, 1_511_337_053)
        );
    }

    function _msKey(uint64 count) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0x81), count);
    }

    /// @dev Milestone store: the milestone (left) and the count item 0x83 (right).
    function _milestoneTree(bytes memory milestone) internal pure returns (Tree memory) {
        return _tree(_msKey(COUNT), milestone, hex"83", abi.encodePacked(COUNT));
    }

    function _storeProof(bytes memory storeKey, bytes32 storeRoot)
        internal
        pure
        returns (bytes memory proof, bytes32 appHash)
    {
        bytes memory v = abi.encodePacked(storeRoot);
        appHash = _leafHash(storeKey, v);
        bytes memory leafOp = abi.encodePacked(
            PB.encodeVarintField(1, uint8(1)),
            PB.encodeVarintField(2, uint8(0)),
            PB.encodeVarintField(3, uint8(1)),
            PB.encodeVarintField(4, uint8(1)),
            PB.encodeBytesField(5, hex"00")
        );
        proof = PB.encodeBytesField(
            1,
            abi.encodePacked(
                PB.encodeBytesField(1, storeKey), PB.encodeBytesField(2, v), PB.encodeBytesField(3, leafOp)
            )
        );
    }

    /// @dev Channel slot +1 holds `slot1`; `extraSlot` holds `extraValue`; everything else is absent.
    function _world(uint256 slot1, bytes32 extraSlot, uint256 extraValue) internal pure returns (World memory w) {
        return _world2(_channelSlots()[0], slot1, extraSlot, extraValue);
    }

    /// @dev Storage holds exactly `slotA` and `slotB`. `storageProof` covers the 5 channel slots,
    ///      `extraProof` covers `slotB`.
    function _world2(bytes32 slotA, uint256 valueA, bytes32 extraSlot, uint256 extraValue)
        internal
        pure
        returns (World memory w)
    {
        bytes32[] memory cs = _channelSlots();
        Trie2 memory st = _mpt2(_slotHash(slotA), RLP.encode(valueA), _slotHash(extraSlot), RLP.encode(extraValue));
        bytes32 storageRoot = st.root;
        w.st = st;
        w.storageProof = _entries(st, cs);
        w.extraProof = _entries(st, _one(extraSlot));
        bytes[] memory account = new bytes[](4);
        account[0] = RLP.encode(uint256(1));
        account[1] = RLP.encode(uint256(0));
        account[2] = RLP.encode(storageRoot);
        account[3] = RLP.encode(keccak256("code"));
        (w.stateRoot, w.accountProof) = _mpt1(keccak256(abi.encodePacked(SVC)), RLP.encode(account));
        w.borHeader = _borHeader(w.stateRoot, BOR_NUMBER);
        w.milestone = _milestone(BOR_NUMBER, keccak256(w.borHeader), BOR_CHAIN);
        w.tree = _milestoneTree(w.milestone);
    }

    function _defaultWorld() internal pure returns (World memory) {
        // status ACTIVE (1) at bit 160, nextMessageId 3 at bit 168.
        return _world((uint256(1) << 160) | (uint256(3) << 168), bytes32(uint256(18)), 0);
    }

    /// @dev Heimdall block at `height` committing the milestone store of `w`.
    function _heimdall(World memory w, int64 height, Val[] memory vals, bytes32 nextHash, uint256[] memory signers)
        internal
        pure
        returns (bytes memory signedHeader, bytes memory multistore)
    {
        bytes32 appHash;
        (multistore, appHash) = _storeProof(bytes("milestone"), w.tree.root);
        Block memory b = _block(height, _setHash(vals), nextHash, appHash);
        signedHeader = _signedHeader(b, vals, signers);
    }

    struct Q {
        bytes headerRef;
        bytes[] hops;
        bytes multistore;
        bytes milestoneEntry;
        bytes borHeader;
        bytes accountProof;
        bytes storageProof;
        bytes manifestStorageProof;
        bytes manifestPreimage;
        bytes ledgerConfig;
        bool content;
    }

    function _enc(Q memory q) internal pure returns (bytes memory out) {
        if (q.content) out = PB.encodeBytesField(1, PB.encodeBytesField(2, PAYLOAD));
        out = abi.encodePacked(out, PB.encodeBytesField(2, q.headerRef));
        for (uint256 i; i < q.hops.length; ++i) {
            out = abi.encodePacked(out, PB.encodeBytesField(3, q.hops[i]));
        }
        out = abi.encodePacked(
            out,
            PB.encodeBytesField(4, q.multistore),
            PB.encodeBytesField(5, q.milestoneEntry),
            PB.encodeBytesField(6, q.borHeader),
            PB.encodeBytesField(7, q.accountProof),
            PB.encodeBytesField(8, q.storageProof)
        );
        out = abi.encodePacked(
            out,
            PB.encodeBytesField(9, q.manifestStorageProof),
            PB.encodeBytesField(10, q.manifestPreimage),
            PB.encodeBytesField(11, q.ledgerConfig)
        );
    }

    /// @dev A bundle proof over `w` at Heimdall height 120, signed inline by setA validators 0+1.
    function _q(World memory w, bytes32 nextHash) internal view returns (Q memory q) {
        (bytes memory sh, bytes memory ms) = _heimdall(w, 120, setA, nextHash, _idx(0, 1));
        q.headerRef = _inlineRef(setA, sh);
        q.multistore = ms;
        q.milestoneEntry = w.tree.entryL;
        q.borHeader = w.borHeader;
        q.accountProof = w.accountProof;
        q.storageProof = w.storageProof;
        q.content = true;
    }

    function _ctxPoly() internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: CHANNEL, remoteServiceAddress: abi.encodePacked(SVC)})
        );
    }

    function _manifestPoly(uint64 version) internal pure returns (bytes memory) {
        ClprTypes.ClprEndpointManifest memory m;
        m.version = version;
        m.serviceAddress = abi.encodePacked(SVC);
        m.endpoints = new ClprTypes.Endpoint[](0);
        return ClprProtobuf.encodeEndpointManifest(m);
    }

    function _ledgerConfig(address service) internal pure returns (bytes memory) {
        return abi.encodePacked(
            PB.encodeBytesField(1, bytes("137")),
            PB.encodeBytesField(2, abi.encodePacked(service)),
            PB.encodeVarintField(3, uint64(1_700_000_000_000_000_000)),
            PB.encodeBytesField(
                4, abi.encodePacked(PB.encodeVarintField(1, uint64(10)), PB.encodeVarintField(5, uint64(20_000)))
            )
        );
    }

    function _serviceSlotValue(address a) internal pure returns (uint256) {
        return uint256(bytes32(bytes20(a))) | 0x28;
    }

    function _configWorld(address stored) internal pure returns (World memory) {
        return _world(0, bytes32(uint256(25)), _serviceSlotValue(stored));
    }

    function _configProof(World memory w) internal view returns (bytes memory) {
        Q memory q = _q(w, hashB);
        q.content = false;
        q.storageProof = w.extraProof;
        q.ledgerConfig = _ledgerConfig(SVC);
        return _enc(q);
    }
}
