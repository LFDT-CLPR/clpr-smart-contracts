// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {Ics23Lib} from "@hiero-ledger/clpr/libraries/proof/cometbft/Ics23Lib.sol";
import {CometBftSyntheticChain} from "@test/helpers/CometBftSyntheticChain.sol";

/// @dev Synthetic wasmd state for CosmWasmVerifier tests: a real two-leaf IAVL-shaped tree in store
///      `wasm`, the CLPR queue-record / service-item keys (src/verifiers/evm/provenance/README.md §4),
///      and CosmWasmProof encoders. Headers are signed with real secp256k1eth keys by
///      {CometBftSyntheticChain}.
abstract contract CosmWasmSyntheticChain is CometBftSyntheticChain {
    bytes internal constant SERVICE = hex"dc184aa5ecc3765b1aa6a6be3b530bfcee73f507adaa8442c4709cc4aa62fed6";
    bytes32 internal constant CHANNEL = keccak256("channel-1");
    uint64 internal constant ANCHOR_HEIGHT = 100;
    bytes internal constant PAYLOAD = hex"deadbeef";

    // ── wasm store: a two-leaf IAVL-shaped tree ───────────────────────────────

    struct Tree {
        bytes32 root;
        bytes entryL; // existence proof of the left leaf
        bytes entryR; // existence proof of the right leaf
        bytes keyL;
        bytes valueL;
        bytes keyR;
        bytes valueR;
    }

    bytes internal constant NODE_HEADER = hex"020402"; // never 0x00-led (leaf prefix)

    /// @dev root = sha256(H ‖ 0x20 ‖ leafL ‖ 0x20 ‖ leafR); kL < kR. The left op is prefix 4 B +
    ///      suffix 33 B and the right op prefix 37 B + empty suffix, the IAVL inner-op shapes.
    function _tree(bytes memory kL, bytes memory vL, bytes memory kR, bytes memory vR)
        internal
        pure
        returns (Tree memory t)
    {
        require(Ics23Lib.bytesLt(kL, kR), "keys unsorted");
        bytes32 hL = _leafHash(kL, vL);
        bytes32 hR = _leafHash(kR, vR);
        t.root = sha256(abi.encodePacked(NODE_HEADER, bytes1(0x20), hL, bytes1(0x20), hR));
        Ics23Lib.InnerOp[] memory pl = new Ics23Lib.InnerOp[](1);
        pl[0] = Ics23Lib.InnerOp({
            hashOp: 1, prefix: abi.encodePacked(NODE_HEADER, bytes1(0x20)), suffix: abi.encodePacked(bytes1(0x20), hR)
        });
        Ics23Lib.InnerOp[] memory pr = new Ics23Lib.InnerOp[](1);
        pr[0] = Ics23Lib.InnerOp({
            hashOp: 1, prefix: abi.encodePacked(NODE_HEADER, bytes1(0x20), hL, bytes1(0x20)), suffix: ""
        });
        t.entryL = _encodeExistenceEntryWithPath(kL, vL, pl);
        t.entryR = _encodeExistenceEntryWithPath(kR, vR, pr);
        (t.keyL, t.valueL, t.keyR, t.valueR) = (kL, vL, kR, vR);
    }

    /// @dev StorageProofEntry for an absent `key` with kL < key < kR (NonExistenceProof{1 key,
    ///      2 left, 3 right} inside CommitmentProof field 2).
    function _absent(Tree memory t, bytes memory key) internal pure returns (bytes memory) {
        bytes memory nep = abi.encodePacked(
            PB.encodeBytesField(1, key),
            PB.encodeBytesField(2, _innerEp(t.entryL)),
            PB.encodeBytesField(3, _innerEp(t.entryR))
        );
        return abi.encodePacked(PB.encodeBytesField(1, key), PB.encodeBytesField(3, PB.encodeBytesField(2, nep)));
    }

    /// @dev The ExistenceProof bytes inside a StorageProofEntry built by _encodeExistenceEntryWithPath.
    function _innerEp(bytes memory entry) internal pure returns (bytes memory ep) {
        (bytes memory proof, uint256 off) = (bytes(""), 0);
        while (off < entry.length) {
            (uint64 fn_, uint8 wt, uint256 o2) = PB.decodeFieldKey(entry, off);
            if (fn_ == 3) (proof, off) = PB.decodeLengthDelimited(entry, o2);
            else off = PB.skipField(entry, o2, wt);
        }
        (, uint256 o3) = _skipKey(proof);
        (ep,) = PB.decodeLengthDelimited(proof, o3);
    }

    function _skipKey(bytes memory b) internal pure returns (uint64 fn_, uint256 off) {
        (fn_,, off) = PB.decodeFieldKey(b, 0);
    }

    /// @dev Name of the IAVL store the synthetic multistore holds.
    function _storeName() internal pure virtual returns (bytes memory) {
        return bytes("wasm");
    }

    /// @dev Multistore proof for store `_storeName()` (single-store Tendermint tree: app_hash = leaf).
    function _multistore(bytes32 storeRoot) internal pure returns (bytes memory proof, bytes32 appHash) {
        bytes memory k = _storeName();
        bytes memory v = abi.encodePacked(storeRoot);
        appHash = _leafHash(k, v);
        bytes memory leafOp = abi.encodePacked(
            PB.encodeVarintField(1, uint8(1)),
            PB.encodeVarintField(2, uint8(0)),
            PB.encodeVarintField(3, uint8(1)),
            PB.encodeVarintField(4, uint8(1)),
            PB.encodeBytesField(5, hex"00")
        );
        proof = PB.encodeBytesField(
            1, abi.encodePacked(PB.encodeBytesField(1, k), PB.encodeBytesField(2, v), PB.encodeBytesField(3, leafOp))
        );
    }

    // ── CLPR layout ───────────────────────────────────────────────────────────

    function _queueKey(bytes memory service, bytes32 channelId) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0x03), service, hex"000a", "clpr_queue", channelId);
    }

    function _serviceKey(bytes memory service) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0x03), service, "clpr_service");
    }

    function _record(uint8 status, uint64 next, uint64 received, uint64 manifestVersion)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            uint8(1), status, next, received, manifestVersion, keccak256("sent"), keccak256("received")
        );
    }

    function _manifest(uint64 version) internal pure returns (bytes memory) {
        ClprTypes.ClprEndpointManifest memory m;
        m.version = version;
        m.serviceAddress = SERVICE;
        m.endpoints = new ClprTypes.Endpoint[](0);
        return ClprProtobuf.encodeEndpointManifest(m);
    }

    /// @dev Standard state: the channel's queue record (left) and the service item (right).
    ///      ("…clpr_queue…" sorts before "…clpr_service": byte 0x00 < 'c'.)
    function _state(bytes memory record, bytes32 commitment) internal pure returns (Tree memory) {
        return _tree(_queueKey(SERVICE, CHANNEL), record, _serviceKey(SERVICE), abi.encodePacked(SERVICE, commitment));
    }

    // ── Payloads ──────────────────────────────────────────────────────────────

    function _inlineRef(Val[] memory vals, bytes memory signedHeader) internal pure returns (bytes memory) {
        return abi.encodePacked(PB.encodeBytesField(1, _encodeSet(vals)), PB.encodeBytesField(2, signedHeader));
    }

    function _hashRef(bytes32 h) internal pure returns (bytes memory) {
        return PB.encodeBytesField(3, abi.encodePacked(h));
    }

    struct P {
        bytes headerRef;
        bytes[] hops;
        bytes multistore;
        bytes entry;
        bytes serviceEntry;
        bytes preimage;
        bytes ledgerConfig;
        bool content;
    }

    function _encode(P memory p) internal pure returns (bytes memory out) {
        if (p.content) out = PB.encodeBytesField(1, PB.encodeBytesField(2, PAYLOAD));
        out = abi.encodePacked(out, PB.encodeBytesField(2, p.headerRef));
        for (uint256 i; i < p.hops.length; ++i) {
            out = abi.encodePacked(out, PB.encodeBytesField(3, p.hops[i]));
        }
        out = abi.encodePacked(
            out,
            PB.encodeBytesField(4, p.multistore),
            PB.encodeBytesField(5, p.entry),
            PB.encodeBytesField(6, p.serviceEntry),
            PB.encodeBytesField(7, p.preimage),
            PB.encodeBytesField(8, p.ledgerConfig)
        );
    }

    /// @dev A block at `height` over state `t`, signed by `signers` of `vals`.
    function _signed(Tree memory t, int64 height, Val[] memory vals, bytes32 nextHash, uint256[] memory signers)
        internal
        pure
        returns (bytes memory signedHeader, bytes memory multistore, Block memory b)
    {
        bytes32 appHash;
        (multistore, appHash) = _multistore(t.root);
        b = _block(height, _setHash(vals), nextHash, appHash);
        signedHeader = _signedHeader(b, vals, signers);
    }

    function _bundle(Tree memory t, int64 height, Val[] memory vals, bytes32 nextHash, bytes memory entry)
        internal
        pure
        returns (bytes memory)
    {
        (bytes memory sh, bytes memory ms,) = _signed(t, height, vals, nextHash, _idx(0, 1));
        P memory p;
        p.headerRef = _inlineRef(vals, sh);
        p.multistore = ms;
        p.entry = entry;
        p.content = true;
        return _encode(p);
    }

    function _ctx() internal pure returns (bytes memory) {
        return
            ClprTypes.encodeChannelContext(
                ClprTypes.ChannelContext({channelId: CHANNEL, remoteServiceAddress: SERVICE})
            );
    }
}
