// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprQueueRecord} from "@hiero-ledger/clpr/libraries/codec/ClprQueueRecord.sol";
import {ClprBlake3} from "@hiero-ledger/clpr/libraries/crypto/ClprBlake3.sol";
import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {MixinKernelVerifier} from "@hiero-ledger/clpr/verifiers/evm/mixin/MixinKernelVerifier.sol";
import {Ed25519TestSigner as Ed} from "@test/verifiers/evm/mixin/Ed25519TestSigner.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @dev Synthetic Mixin kernel data in the kernel's encodings: an 8-node ready set (threshold
///      8*2/3+1 = 6) plus one pledging node (index 8), real ed25519 keys, version-2 snapshot payloads
///      signed with CoSi (one Schnorr signature by the summed scalars), version-5 record-thread
///      transactions, and NodeAccept / NodeRemove XIN transactions.
abstract contract MixinTestBuilder is Test {
    uint256 internal constant NODES = 8;
    uint256 internal constant ALL = 9; // NODES + the pledging node
    uint256 internal constant NEW_NODE = 8;
    uint256 internal constant THRESHOLD = 6;
    bytes32 internal constant CHANNEL = bytes32(uint256(0xC0FFEE));
    bytes32 internal constant APP = keccak256("mtg-app-id"); // the opaque service address
    bytes32 internal constant TIP = keccak256("thread tip");
    bytes32 internal constant XIN = 0xa99c2e0e2b1da4d648755ef19bd95139acbbe6564cfb06dec7cd34931ca72cdc;
    uint64 internal constant T0 = 1_790_828_733_912_240_416;
    uint64 internal constant HOUR = 3600 * 1e9;
    uint8 internal constant ACCEPT = 0xa4;
    uint8 internal constant REMOVE = 0xa6;

    MixinKernelVerifier internal mv;
    address internal hasher;
    uint256[] internal scalars;
    bytes32[] internal pubs;
    uint256[] internal xsOf;

    function _sha512(bytes memory d) internal view returns (bytes memory out) {
        bool ok;
        (ok, out) = hasher.staticcall(d);
        require(ok, "hasher");
    }

    function _deployMixin() internal returns (MixinKernelVerifier) {
        hasher = deployCode("ClprSha512Hasher.sol:ClprSha512Hasher");
        address ed = deployCode("Ed25519Verifier.sol:Ed25519Verifier");
        for (uint256 i = 0; i < ALL; ++i) {
            uint256 a = uint256(keccak256(abi.encode("mixin node", i))) % Ed.L;
            Ed.Pt memory pt = Ed.mulBase(a);
            (uint256 x,) = Ed.affine(pt);
            scalars.push(a);
            pubs.push(Ed.compress(pt));
            xsOf.push(x);
        }
        mv = new MixinKernelVerifier("mixin:mainnet", IEd25519Verifier(ed));
        return mv;
    }

    /// @dev The initial ready list: nodes 0..7.
    function _list() internal pure returns (uint256[] memory l) {
        l = new uint256[](NODES);
        for (uint256 i = 0; i < NODES; ++i) {
            l[i] = i;
        }
    }

    function _keys(uint256[] memory list) internal view returns (bytes32[] memory k) {
        k = new bytes32[](list.length);
        for (uint256 i = 0; i < list.length; ++i) {
            k[i] = pubs[list[i]];
        }
    }

    function _hashOf(uint256[] memory list) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(_keys(list)));
    }

    function _nodesHash() internal view returns (bytes32) {
        return _hashOf(_list());
    }

    function _keysRlp(uint256[] memory list) internal view returns (bytes memory) {
        bytes[] memory k = new bytes[](list.length);
        for (uint256 i = 0; i < list.length; ++i) {
            k[i] = RLP.encode(abi.encodePacked(pubs[list[i]]));
        }
        return RLP.encode(k);
    }

    function _without(uint256[] memory list, uint256 node) internal pure returns (uint256[] memory out) {
        out = new uint256[](list.length - 1);
        uint256 j;
        for (uint256 i = 0; i < list.length; ++i) {
            if (list[i] != node) out[j++] = list[i];
        }
    }

    function _with(uint256[] memory list, uint256 node) internal pure returns (uint256[] memory out) {
        out = new uint256[](list.length + 1);
        for (uint256 i = 0; i < list.length; ++i) {
            out[i] = list[i];
        }
        out[list.length] = node;
    }

    function _lowMask(uint256 n) internal pure returns (uint64) {
        return uint64((1 << n) - 1);
    }

    // ── transactions and snapshots ───────────────────────────────────────────

    /// @dev Version-5 payload: one input (`spends`, 0), one output of `outType`, no references, `extra`.
    function _txOf(bytes32 asset, bytes32 spends, uint8 outType, bytes memory extra)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory input = abi.encodePacked(spends, uint16(0), uint16(0), uint16(0), uint16(0));
        bytes memory output = abi.encodePacked(
            uint8(0),
            outType,
            uint16(4),
            uint32(100_000_000), // amount
            uint16(1),
            keccak256("one-time key"),
            keccak256("mask"),
            uint16(3),
            hex"fffe01", // script
            uint16(0) // no withdrawal
        );
        return abi.encodePacked(
            hex"77770005", asset, uint16(1), input, uint16(1), output, uint16(0), uint32(extra.length), extra, uint16(0)
        );
    }

    function _tx(bytes32 spends, uint256, bytes memory extra) internal pure returns (bytes memory) {
        return _txOf(keccak256("XIN asset"), spends, 0, extra);
    }

    /// @dev A NodeAccept / NodeRemove transaction for `node`: extra = signer ‖ payee.
    function _nodeTx(uint8 outType, uint256 node) internal view returns (bytes memory) {
        return _txOf(
            XIN,
            keccak256(abi.encode("pledge or accept", node)),
            outType,
            abi.encodePacked(pubs[node], keccak256("payee"))
        );
    }

    function _snapshotPayload(bytes32 txHash, uint64 timestamp) internal pure returns (bytes memory) {
        return _snapshotPayloadR(txHash, timestamp, 50_288);
    }

    function _snapshotPayloadR(bytes32 txHash, uint64 timestamp, uint64 round) internal pure returns (bytes memory) {
        if (round == 0) {
            return abi.encodePacked(
                hex"77770002", keccak256("node id"), round, uint16(0), uint16(1), txHash, timestamp, uint64(0)
            );
        }
        return abi.encodePacked(
            hex"77770002",
            keccak256("node id"),
            round,
            uint16(2),
            keccak256("self"),
            keccak256("external"),
            uint16(1),
            txHash,
            timestamp,
            uint64(0)
        );
    }

    struct Snap {
        bytes payload;
        bytes sig;
        uint64 mask;
        bytes xs;
    }

    /// @dev CoSi over `payload` by the positions in `mask` of the signer list `list`.
    function _cosiOn(bytes memory payload, uint256[] memory list, uint64 mask) internal view returns (Snap memory s) {
        uint256 a;
        uint256 count;
        for (uint256 i = 0; i < list.length; ++i) {
            if ((mask >> i) & 1 == 1) {
                a = addmod(a, scalars[list[i]], Ed.L);
                ++count;
            }
        }
        bytes[] memory xs = new bytes[](count);
        uint256 j;
        for (uint256 i = 0; i < list.length; ++i) {
            if ((mask >> i) & 1 == 1) xs[j++] = RLP.encode(abi.encodePacked(xsOf[list[i]]));
        }
        bytes32 h = ClprBlake3.hash(payload);
        s.payload = payload;
        s.sig = Ed.sign(a, uint256(keccak256(abi.encode("nonce", h))) % Ed.L, abi.encodePacked(h), _sha512);
        s.mask = mask;
        s.xs = RLP.encode(xs);
    }

    function _cosi(bytes memory payload, uint64 mask) internal view returns (Snap memory) {
        return _cosiOn(payload, _list(), mask);
    }

    function _finRlp(Snap memory s) internal pure returns (bytes memory) {
        bytes[] memory f = new bytes[](4);
        f[0] = s.xs;
        f[1] = RLP.encode(s.payload);
        f[2] = RLP.encode(s.sig);
        f[3] = RLP.encode(uint256(s.mask));
        return RLP.encode(f);
    }

    /// @dev A node change: `txp` final in a snapshot at `ts` (`round`) signed under `signers` by `mask`.
    function _change(bytes memory txp, uint256[] memory signers, uint64 mask, uint64 ts, uint64 round)
        internal
        view
        returns (bytes memory)
    {
        Snap memory s = _cosiOn(_snapshotPayloadR(ClprBlake3.hash(txp), ts, round), signers, mask);
        bytes[] memory c = new bytes[](5);
        c[0] = s.xs;
        c[1] = RLP.encode(s.payload);
        c[2] = RLP.encode(s.sig);
        c[3] = RLP.encode(uint256(s.mask));
        c[4] = RLP.encode(txp);
        return RLP.encode(c);
    }

    /// @dev The accept of NEW_NODE at `ts`: round 0, signed by `list` ++ [NEW_NODE].
    function _acceptChange(uint256[] memory list, uint64 ts) internal view returns (bytes memory) {
        return _change(_nodeTx(ACCEPT, NEW_NODE), _with(list, NEW_NODE), _lowMask(list.length + 1), ts, 0);
    }

    function _removeChange(uint256[] memory list, uint256 node, uint64 ts) internal view returns (bytes memory) {
        return _change(_nodeTx(REMOVE, node), list, _lowMask(list.length), ts, 77);
    }

    // ── records ──────────────────────────────────────────────────────────────

    function _control(string memory chainId) internal pure returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory lc;
        lc.protocolVersion = 1;
        lc.chainId = chainId;
        lc.serviceAddress = abi.encodePacked(APP);
        lc.nanosSinceEpoch = 1_790_822_400 * 1e9;
        lc.throttles = ClprTypes.Throttles(10, 4096, 500_000, 100, 65_536, 4, 4);
        return ClprProtobuf.encodeControlMessage(lc);
    }

    function _record(bytes32 channelId, uint64 next, bytes32 sent, bytes memory manifest, bytes memory control)
        internal
        pure
        returns (bytes memory)
    {
        ClprQueueRecord.Record memory r;
        r.channelId = channelId;
        r.state = uint8(ClprTypes.ChannelStatus.ACTIVE);
        r.nextMessageId = next;
        r.receivedMessageId = 1;
        r.sentRunningHash = sent;
        r.manifestCommitment = manifest.length > 0 ? keccak256(manifest) : bytes32(0);
        r.configHash = keccak256(control);
        return ClprQueueRecord.encode(r);
    }

    // ── proofs ───────────────────────────────────────────────────────────────

    struct B {
        bytes32 tip; // what the first thread tx spends
        uint256 threadLength; // records before the final one (intermediate links)
        uint64 mask;
        bytes record;
        bytes content;
        bool checkpoint;
        bool txOutsideSnapshot;
        bool flipSig;
        uint256[] anchorList; // field [0]
        uint256[] signers; // the record snapshot's signer list
        uint64 ts; // the record snapshot's timestamp
        bytes[] changes;
        bytes tipTx; // when set, the thread is only this tip transaction (no record snapshot)
    }

    function _defaults(bytes memory content, bytes32 sent, uint64 next) internal pure returns (B memory b) {
        b.tip = TIP;
        b.threadLength = 1;
        b.mask = 0x3f; // nodes 0..5
        b.record = _record(CHANNEL, next, sent, "", _control("mixin:mainnet"));
        b.content = content;
        b.anchorList = _list();
        b.signers = _list();
        b.ts = T0;
    }

    function _bundleProof(B memory b) internal view returns (bytes memory proof, bytes32 lastTx) {
        bytes[] memory t;
        bytes memory fin;
        if (b.tipTx.length > 0) {
            t = new bytes[](1);
            t[0] = RLP.encode(b.tipTx);
            lastTx = ClprBlake3.hash(b.tipTx);
            fin = RLP.encode(new bytes[](0));
        } else {
            bytes[] memory thread = new bytes[](b.threadLength + 1);
            bytes32 prev = b.tip;
            for (uint256 i = 0; i < b.threadLength; ++i) {
                thread[i] = _tx(prev, 0, _record(bytes32(uint256(0xAAAA)), 1, 0, "", "")); // another channel's record
                prev = ClprBlake3.hash(thread[i]);
            }
            thread[b.threadLength] = _tx(prev, 0, b.record);
            lastTx = ClprBlake3.hash(thread[b.threadLength]);
            Snap memory s = _cosiOn(
                _snapshotPayload(b.txOutsideSnapshot ? keccak256("other tx") : lastTx, b.ts), b.signers, b.mask
            );
            if (b.flipSig) s.sig[40] = bytes1(uint8(s.sig[40]) ^ 1);
            t = new bytes[](thread.length);
            for (uint256 i = 0; i < thread.length; ++i) {
                t[i] = RLP.encode(thread[i]);
            }
            fin = _finRlp(s);
        }
        bytes[] memory p = new bytes[](6);
        p[0] = _keysRlp(b.anchorList);
        p[1] = RLP.encode(b.changes);
        p[2] = fin;
        p[3] = RLP.encode(t);
        p[4] = RLP.encode(b.checkpoint ? uint256(1) : 0);
        p[5] = RLP.encode(b.content);
        proof = RLP.encode(p);
    }

    function _anchorOf(uint256[] memory list, bytes32 tip, bytes32 pendingKey, uint64 pendingAt, uint64 changedAt)
        internal
        view
        returns (bytes memory)
    {
        return abi.encode(_hashOf(list), tip, pendingKey, pendingAt, changedAt);
    }

    function _anchor() internal view returns (bytes memory) {
        return _anchorOf(_list(), TIP, 0, 0, T0 - 24 * HOUR);
    }

    function _context() internal pure returns (bytes memory) {
        return abi.encodePacked(CHANNEL, APP);
    }

    function _configProof(string memory chainId, bytes memory manifest) internal view returns (bytes memory) {
        bytes memory control = _control(chainId);
        bytes memory txp = _tx(keccak256("mtg genesis"), 0, _record(bytes32(0), 0, 0, manifest, control));
        Snap memory s = _cosi(_snapshotPayload(ClprBlake3.hash(txp), T0), 0x3f);
        bytes[] memory c = new bytes[](5);
        c[0] = _keysRlp(_list());
        c[1] = RLP.encode(new bytes[](0));
        c[2] = _finRlp(s);
        c[3] = RLP.encode(txp);
        c[4] = RLP.encode(control);
        return RLP.encode(c);
    }

    function _content(uint256 n) internal pure returns (bytes memory content, bytes32 running) {
        for (uint256 i = 0; i < n; ++i) {
            bytes memory payload = abi.encodePacked(hex"0a0412020801", uint8(i + 1));
            content = abi.encodePacked(content, hex"12", uint8(payload.length), payload);
            running = sha256(abi.encodePacked(running, sha256(payload)));
        }
    }
}
