// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {XrplLightClient} from "@hiero-ledger/clpr/verifiers/evm/xrpl/XrplLightClient.sol";
import {XrplUnlKeys} from "@hiero-ledger/clpr/verifiers/evm/xrpl/XrplUnlKeys.sol";
import {XrplVerifier} from "@hiero-ledger/clpr/verifiers/evm/xrpl/XrplVerifier.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @dev Synthetic XRPL ledgers in the exact rippled encodings the live fixtures use: secp256k1 test
///      validators signing STValidations (DER), a 118-byte header, one-transaction tx trees and
///      one-entry state trees, clpr/v1 AccountSet messages and AccountRoot entries.
abstract contract XrplTestBuilder is Test {
    uint256 internal constant N_VALIDATORS = 5; // quorum ceil(0.8 * 5) = 4
    uint256 internal constant QUORUM = 4;
    bytes20 internal constant OUTBOX = bytes20(hex"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    bytes32 internal constant CHANNEL = bytes32(uint256(0xC1A2));
    uint32 internal constant SEQ_BASE = 21_187_269;
    uint32 internal constant LEDGER = 21_187_300;

    uint256[] internal valKeys;
    bytes[] internal masters;
    XrplLightClient internal lightClient;
    XrplUnlKeys internal unlKeys;
    address internal hasher;
    /// @dev When set, used as bundle fields [0] (UNL) and [1] (manifests) instead of the defaults.
    bytes internal unlOverride;
    bytes internal manifestsOverride;
    /// @dev When set, one byte of every tx-tree inner node is flipped (a wrong inclusion proof).
    bool internal corruptInner;

    function _half(bytes memory data) internal view returns (bytes32 h) {
        (bool ok, bytes memory out) = hasher.staticcall(data);
        require(ok && out.length == 64, "hasher");
        h = bytes32(out);
    }

    struct Msg {
        uint32 sequence;
        uint64 received;
        uint64 status;
        uint64 next;
        bytes payload;
        bytes32 channel;
    }

    function _deployXrpl(string memory caip2) internal returns (XrplVerifier v) {
        for (uint256 i = 0; i < N_VALIDATORS; ++i) {
            valKeys.push(uint256(keccak256(abi.encode("xrpl-validator", i))));
            masters.push(abi.encodePacked(bytes1(0xED), keccak256(abi.encode("master", i))));
        }
        hasher = deployCode("ClprSha512Hasher.sol:ClprSha512Hasher");
        address ed = deployCode("Ed25519Verifier.sol:Ed25519Verifier");
        unlKeys = new XrplUnlKeys(IEd25519Verifier(ed), hasher);
        lightClient = new XrplLightClient(unlKeys);
        v = new XrplVerifier(caip2, lightClient);
    }

    // ── keys and signatures ──────────────────────────────────────────────────

    function _compressed(uint256 pk) internal returns (bytes memory) {
        Vm.Wallet memory w = vm.createWallet(pk);
        return abi.encodePacked(bytes1(w.publicKeyY & 1 == 0 ? 0x02 : 0x03), bytes32(w.publicKeyX));
    }

    function _der(bytes32 r, bytes32 s) internal pure returns (bytes memory) {
        bytes memory ri = _derInt(r);
        bytes memory si = _derInt(s);
        return abi.encodePacked(bytes1(0x30), uint8(ri.length + si.length), ri, si);
    }

    function _derInt(bytes32 x) internal pure returns (bytes memory out) {
        bytes memory b = abi.encodePacked(x);
        uint256 i;
        while (i < 31 && b[i] == 0 && uint8(b[i + 1]) < 0x80) ++i;
        bytes memory v = new bytes(32 - i);
        for (uint256 k = 0; k < v.length; ++k) {
            v[k] = b[i + k];
        }
        if (uint8(v[0]) >= 0x80) v = abi.encodePacked(bytes1(0), v);
        out = abi.encodePacked(bytes1(0x02), uint8(v.length), v);
    }

    function _signDer(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return _der(r, s);
    }

    function _vl(bytes memory b) internal pure returns (bytes memory) {
        require(b.length <= 192, "vl");
        return abi.encodePacked(uint8(b.length), b);
    }

    // ── UNL ──────────────────────────────────────────────────────────────────

    function _unlAnchorList() internal returns (bytes memory) {
        bytes[] memory es = new bytes[](N_VALIDATORS);
        for (uint256 i = 0; i < N_VALIDATORS; ++i) {
            bytes[] memory e = new bytes[](3);
            e[0] = RLP.encode(masters[i]);
            e[1] = RLP.encode(vm.addr(valKeys[i]));
            e[2] = RLP.encode(uint256(1));
            es[i] = RLP.encode(e);
        }
        return RLP.encode(es);
    }

    function _unlConfigList() internal returns (bytes memory) {
        bytes[] memory es = new bytes[](N_VALIDATORS);
        for (uint256 i = 0; i < N_VALIDATORS; ++i) {
            bytes[] memory e = new bytes[](3);
            e[0] = RLP.encode(masters[i]);
            e[1] = RLP.encode(_compressed(valKeys[i]));
            e[2] = RLP.encode(uint256(1));
            es[i] = RLP.encode(e);
        }
        return RLP.encode(es);
    }

    function _unlHash() internal returns (bytes32) {
        bytes memory acc;
        for (uint256 i = 0; i < N_VALIDATORS; ++i) {
            acc = abi.encodePacked(acc, masters[i], vm.addr(valKeys[i]), uint32(1));
        }
        return keccak256(acc);
    }

    // ── ledger ───────────────────────────────────────────────────────────────

    function _header(uint32 seq, bytes32 parent, bytes32 txHash, bytes32 accountHash)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            seq,
            uint64(99_999_888_634_780_896),
            parent,
            txHash,
            accountHash,
            uint32(844_146_811),
            uint32(844_146_812),
            uint8(10),
            uint8(0)
        );
    }

    function _ledgerHash(bytes memory header) internal view returns (bytes32) {
        return _half(abi.encodePacked(bytes4("LWR\x00"), header));
    }

    /// @dev Full validations of `header` by validators [0, count), RLP [[index, STValidation], ...].
    function _validations(bytes memory header, uint256 count) internal returns (bytes memory) {
        bytes32 lh = _ledgerHash(header);
        uint32 seq;
        assembly {
            seq := shr(224, mload(add(header, 0x20)))
        }
        bytes[] memory out = new bytes[](count);
        for (uint256 i = 0; i < count; ++i) {
            bytes memory unsigned = abi.encodePacked(
                hex"2280000001",
                hex"26",
                seq,
                hex"29",
                uint32(844_146_813),
                hex"51",
                lh,
                hex"73",
                _vl(_compressed(valKeys[i]))
            );
            bytes32 digest = _half(abi.encodePacked(bytes4("VAL\x00"), unsigned));
            bytes memory val = abi.encodePacked(unsigned, hex"76", _vl(_signDer(valKeys[i], digest)));
            bytes[] memory e = new bytes[](2);
            e[0] = RLP.encode(i);
            e[1] = RLP.encode(val);
            out[i] = RLP.encode(e);
        }
        return RLP.encode(out);
    }

    /// @dev A one-leaf SHAMap: the root inner node holds `leafHash` at nibble 0 of `key`.
    function _oneLeafTree(bytes32 key, bytes32 leafHash) internal view returns (bytes32 root, bytes memory inner) {
        bytes32[16] memory kids;
        kids[uint256(key) >> 252] = leafHash;
        inner = abi.encodePacked(kids);
        root = _half(abi.encodePacked(bytes4("MIN\x00"), inner));
    }

    function _vlLen(uint256 n) internal pure returns (bytes memory) {
        if (n <= 192) return abi.encodePacked(uint8(n));
        n -= 193;
        return abi.encodePacked(uint8(193 + (n >> 8)), uint8(n));
    }

    function _txLeaf(bytes memory txb, bytes memory meta) internal view returns (bytes32 id, bytes32 leaf) {
        id = _half(abi.encodePacked(bytes4("TXN\x00"), txb));
        leaf = _half(abi.encodePacked(bytes4("SND\x00"), _vlLen(txb.length), txb, _vlLen(meta.length), meta, id));
    }

    // ── CLPR messages ────────────────────────────────────────────────────────

    function _memo(Msg memory m) internal pure returns (bytes memory) {
        bytes memory sync =
            abi.encodePacked(hex"08", uint8(m.received), hex"10", uint8(m.status), hex"18", uint8(m.next));
        return abi.encodePacked(
            hex"0a20", m.channel, hex"12", uint8(sync.length), sync, hex"1a", _vlProto(m.payload), m.payload
        );
    }

    function _vlProto(bytes memory p) internal pure returns (bytes memory) {
        require(p.length < 128, "proto len");
        return abi.encodePacked(uint8(p.length));
    }

    /// @dev AccountSet, no flags, one clpr/v1 memo. `extra` is inserted as additional top-level
    ///      field bytes (for negative cases); `flags` / `ticket` / `memoFormat` likewise.
    function _clprTx(Msg memory m, bytes20 account, bytes memory extra, uint32 flags, bool memoFormat)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory memoData = _memo(m);
        bytes memory memoObj = abi.encodePacked(
            hex"ea",
            hex"7c",
            _vl("clpr/v1"),
            hex"7d",
            _vlLen(memoData.length),
            memoData,
            memoFormat ? bytes(hex"7e0474657874") : bytes(""),
            hex"e1"
        );
        return abi.encodePacked(
            hex"120003",
            hex"22",
            flags,
            hex"24",
            m.sequence,
            extra,
            hex"68400000000000001e",
            hex"7300",
            hex"8114",
            account,
            hex"f9",
            memoObj,
            hex"f1"
        );
    }

    function _clprTx(Msg memory m) internal pure returns (bytes memory) {
        return _clprTx(m, OUTBOX, "", 0, false);
    }

    bytes internal constant META_OK = hex"201c00000000031000"; // TransactionIndex 0, tesSUCCESS
    bytes internal constant META_TEC = hex"201c0000000003108c"; // tecDST_TAG_NEEDED-style failure

    function _msg(uint32 id) internal pure returns (Msg memory m) {
        m.sequence = SEQ_BASE + id - 1;
        m.received = 2;
        m.status = 1;
        m.next = id + 1;
        m.payload = abi.encodePacked(hex"0a0412020801", uint8(id)); // a small ClprMessagePayload stand-in
        m.channel = CHANNEL;
    }

    // ── bundles ──────────────────────────────────────────────────────────────

    /// @dev Bundle proof with each transaction in its own ledger: the newest is the validated one and
    ///      older ones are parent-linked ancestors. `txs[0]` is the oldest.
    function _bundle(bytes[] memory txs, bytes[] memory metas, uint256 validators, bytes32 prevRunning)
        internal
        returns (bytes memory proof)
    {
        uint256 n = txs.length;
        bytes[] memory headers = new bytes[](n);
        bytes[] memory inners = new bytes[](n);
        bytes32 parent = keccak256("genesis");
        for (uint256 k = 0; k < n; ++k) {
            (bytes32 id, bytes32 leaf) = _txLeaf(txs[k], metas[k]);
            (bytes32 root, bytes memory inner) = _oneLeafTree(id, leaf);
            // casting to 'uint32' is safe: test ledgers are a handful of sequences
            // forge-lint: disable-next-line(unsafe-typecast)
            headers[k] = _header(LEDGER - uint32(n - 1 - k), parent, root, keccak256(abi.encode("state", k)));
            if (corruptInner) inner[511] = bytes1(uint8(inner[511]) ^ 1);
            inners[k] = inner;
            parent = _ledgerHash(headers[k]);
        }
        bytes[] memory ancestors = new bytes[](n - 1);
        for (uint256 j = 0; j < n - 1; ++j) {
            bytes[] memory a = new bytes[](1);
            a[0] = RLP.encode(headers[n - 2 - j]);
            ancestors[j] = RLP.encode(a);
        }
        bytes[] memory entries = new bytes[](n);
        for (uint256 k = 0; k < n; ++k) {
            bytes[] memory e = new bytes[](4);
            e[0] = RLP.encode(n - 1 - k); // ledgerRef: 0 = validated (newest)
            e[1] = RLP.encode(txs[k]);
            e[2] = RLP.encode(metas[k]);
            bytes[] memory il = new bytes[](1);
            il[0] = RLP.encode(inners[k]);
            e[3] = RLP.encode(il);
            entries[k] = RLP.encode(e);
        }
        bytes[] memory p = new bytes[](7);
        p[0] = unlOverride.length > 0 ? unlOverride : _unlAnchorList();
        p[1] = manifestsOverride.length > 0 ? manifestsOverride : RLP.encode(new bytes[](0));
        p[2] = RLP.encode(headers[n - 1]);
        p[3] = _validations(headers[n - 1], validators);
        p[4] = RLP.encode(ancestors);
        p[5] = RLP.encode(entries);
        p[6] = RLP.encode(abi.encodePacked(prevRunning));
        proof = RLP.encode(p);
    }

    function _messages(uint32 count)
        internal
        pure
        returns (bytes[] memory txs, bytes[] memory metas, bytes[] memory payloads)
    {
        txs = new bytes[](count);
        metas = new bytes[](count);
        payloads = new bytes[](count);
        for (uint32 i = 0; i < count; ++i) {
            Msg memory m = _msg(i + 1);
            txs[i] = _clprTx(m);
            metas[i] = META_OK;
            payloads[i] = m.payload;
        }
    }

    function _anchor() internal returns (bytes memory) {
        return abi.encode(_unlHash(), N_VALIDATORS, uint256(SEQ_BASE), uint256(0));
    }

    function _context() internal pure returns (bytes memory) {
        return abi.encodePacked(CHANNEL, OUTBOX);
    }

    // ── config ───────────────────────────────────────────────────────────────

    function _accountRoot(bytes20 account, uint32 flags) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"110061", hex"22", flags, hex"2401434ac5", hex"8114", account);
    }

    function _controlMessage(string memory chainId) internal pure returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory lc;
        lc.protocolVersion = 1;
        lc.chainId = chainId;
        lc.serviceAddress = abi.encodePacked(OUTBOX);
        lc.nanosSinceEpoch = 1_790_822_400 * 1e9;
        lc.throttles = ClprTypes.Throttles(10, 800, 500_000, 100, 65_536, 4, 4);
        return ClprProtobuf.encodeControlMessage(lc);
    }

    function _config(string memory chainId, uint32 rootFlags, bytes memory manifestCommitment)
        internal
        returns (bytes memory)
    {
        bytes memory root = _accountRoot(OUTBOX, rootFlags);
        bytes32 key = _half(abi.encodePacked(uint16(0x0061), OUTBOX));
        bytes32 leaf = _half(abi.encodePacked(bytes4("MLN\x00"), root, key));
        (bytes32 accountHash, bytes memory inner) = _oneLeafTree(key, leaf);
        bytes memory header = _header(LEDGER, keccak256("parent"), keccak256("txs"), accountHash);
        bytes[] memory inners = new bytes[](1);
        inners[0] = RLP.encode(inner);
        bytes[] memory p = new bytes[](8);
        p[0] = _unlConfigList();
        p[1] = RLP.encode(header);
        p[2] = _validations(header, QUORUM);
        p[3] = RLP.encode(inners);
        p[4] = RLP.encode(root);
        p[5] = RLP.encode(uint256(SEQ_BASE));
        p[6] = RLP.encode(_controlMessage(chainId));
        p[7] = RLP.encode(manifestCommitment);
        return RLP.encode(p);
    }
}
