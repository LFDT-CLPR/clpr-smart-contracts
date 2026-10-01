// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprQueueRecord} from "@hiero-ledger/clpr/libraries/codec/ClprQueueRecord.sol";
import {HyperEvmVerifier} from "@hiero-ledger/clpr/verifiers/evm/hyperliquid/HyperEvmVerifier.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @dev Synthetic HyperEVM blocks: a Cancun header (20 fields, stateRoot 0 as on HyperEVM) whose
///      receipts trie holds one receipt (key RLP(0) = 0x80, a single leaf) carrying the beacon's
///      ClprQueueRecord log, and K-of-N attestor signatures from test keys.
abstract contract HyperEvmTestBuilder is Test {
    address internal constant SERVICE = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;
    address internal constant BEACON = address(0xBEAC0);
    bytes32 internal constant CHANNEL = bytes32(uint256(0xC0FFEE));
    uint256 internal constant BLOCK = 47_353_393;
    uint256 internal constant N = 5;
    uint256 internal constant K = 3;

    HyperEvmVerifier internal hv;
    uint256[] internal keys; // sorted by address
    address[] internal addrs;

    function _setupAttestors(string memory seed) internal returns (uint256[] memory ks, address[] memory as_) {
        ks = new uint256[](N);
        as_ = new address[](N);
        for (uint256 i = 0; i < N; ++i) {
            ks[i] = uint256(keccak256(abi.encode(seed, i)));
            as_[i] = vm.addr(ks[i]);
        }
        // insertion sort by address
        for (uint256 i = 1; i < N; ++i) {
            for (uint256 j = i; j > 0 && as_[j] < as_[j - 1]; --j) {
                (as_[j], as_[j - 1]) = (as_[j - 1], as_[j]);
                (ks[j], ks[j - 1]) = (ks[j - 1], ks[j]);
            }
        }
    }

    function _deployHyper() internal returns (HyperEvmVerifier) {
        (uint256[] memory ks, address[] memory as_) = _setupAttestors("attestor");
        keys = ks;
        addrs = as_;
        hv = new HyperEvmVerifier("eip155:999", 999);
        return hv;
    }

    function _setRlp(uint256 threshold, address[] memory as_) internal pure returns (bytes memory) {
        bytes[] memory l = new bytes[](as_.length);
        for (uint256 i = 0; i < as_.length; ++i) {
            l[i] = RLP.encode(as_[i]);
        }
        bytes[] memory s = new bytes[](2);
        s[0] = RLP.encode(threshold);
        s[1] = RLP.encode(l);
        return RLP.encode(s);
    }

    function _setHash(uint256 threshold, address[] memory as_) internal pure returns (bytes32) {
        return keccak256(abi.encode(threshold, as_));
    }

    function _sigs(uint256[] memory ks, uint256[] memory which, bytes32 digest) internal pure returns (bytes memory) {
        bytes[] memory out = new bytes[](which.length);
        for (uint256 i = 0; i < which.length; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ks[which[i]], digest);
            out[i] = RLP.encode(abi.encodePacked(r, s, v));
        }
        return RLP.encode(out);
    }

    function _first(uint256 n) internal pure returns (uint256[] memory w) {
        w = new uint256[](n);
        for (uint256 i = 0; i < n; ++i) {
            w[i] = i;
        }
    }

    function _record(
        bytes32 channelId,
        uint64 next,
        bytes32 sentHash,
        bytes memory manifestPreimage,
        bytes memory control
    ) internal pure returns (bytes memory) {
        ClprQueueRecord.Record memory r;
        r.channelId = channelId;
        r.state = uint8(ClprTypes.ChannelStatus.ACTIVE);
        r.nextMessageId = next;
        r.receivedMessageId = 1;
        r.sentRunningHash = sentHash;
        r.manifestCommitment = manifestPreimage.length > 0 ? keccak256(manifestPreimage) : bytes32(0);
        r.configHash = keccak256(control);
        return ClprQueueRecord.encode(r);
    }

    function _receipt(
        address emitter,
        bytes32 topic0,
        address service,
        bytes32 channelId,
        bytes memory record,
        uint256 status
    ) internal pure returns (bytes memory) {
        bytes[] memory topics = new bytes[](3);
        topics[0] = RLP.encode(abi.encodePacked(topic0));
        topics[1] = RLP.encode(abi.encodePacked(bytes32(uint256(uint160(service)))));
        topics[2] = RLP.encode(abi.encodePacked(channelId));
        bytes[] memory log = new bytes[](3);
        log[0] = RLP.encode(emitter);
        log[1] = RLP.encode(topics);
        log[2] = RLP.encode(abi.encode(record));
        bytes[] memory logs = new bytes[](1);
        logs[0] = RLP.encode(log);
        bytes[] memory r = new bytes[](4);
        r[0] = RLP.encode(status);
        r[1] = RLP.encode(uint256(50_000));
        r[2] = RLP.encode(new bytes(256));
        r[3] = RLP.encode(logs);
        return abi.encodePacked(bytes1(0x02), RLP.encode(r)); // EIP-1559 typed receipt
    }

    /// @dev Header with a one-leaf receipts trie; returns (header, leafNode).
    function _block(bytes memory receipt) internal pure returns (bytes memory header, bytes memory leaf) {
        bytes[] memory l = new bytes[](2);
        l[0] = RLP.encode(bytes(hex"2080")); // leaf, even path [8, 0] = RLP(0)
        l[1] = RLP.encode(receipt);
        leaf = RLP.encode(l);
        bytes[] memory h = new bytes[](20);
        h[0] = RLP.encode(abi.encodePacked(keccak256("parent")));
        h[1] = RLP.encode(abi.encodePacked(keccak256(hex"c0")));
        h[2] = RLP.encode(address(0));
        h[3] = RLP.encode(abi.encodePacked(bytes32(0))); // HyperEVM: no state root
        h[4] = RLP.encode(abi.encodePacked(keccak256("txs")));
        h[5] = RLP.encode(abi.encodePacked(keccak256(leaf)));
        h[6] = RLP.encode(new bytes(256));
        h[7] = RLP.encode(uint256(0));
        h[8] = RLP.encode(BLOCK);
        h[9] = RLP.encode(uint256(3_000_000));
        h[10] = RLP.encode(uint256(50_000));
        h[11] = RLP.encode(uint256(1_790_000_000));
        h[12] = RLP.encode(bytes(""));
        h[13] = RLP.encode(abi.encodePacked(bytes32(0)));
        h[14] = RLP.encode(abi.encodePacked(bytes8(0)));
        h[15] = RLP.encode(uint256(100_000_000));
        h[16] = RLP.encode(abi.encodePacked(keccak256("withdrawals")));
        h[17] = RLP.encode(uint256(0));
        h[18] = RLP.encode(uint256(0));
        h[19] = RLP.encode(abi.encodePacked(bytes32(0)));
        header = RLP.encode(h);
    }

    function _control(string memory chainId) internal pure returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory lc;
        lc.protocolVersion = 1;
        lc.chainId = chainId;
        lc.serviceAddress = abi.encodePacked(SERVICE);
        lc.nanosSinceEpoch = 1_790_822_400 * 1e9;
        lc.throttles = ClprTypes.Throttles(10, 4096, 500_000, 100, 65_536, 4, 4);
        return ClprProtobuf.encodeControlMessage(lc);
    }

    struct Bundle {
        bytes record;
        address emitter;
        bytes32 topic0;
        uint256 status;
        uint256 signers;
        bytes rotations;
        bytes content;
        bytes manifest;
        uint256[] signerKeys; // override signing keys (else `keys`)
        bool corruptReceiptNode; // prove a different receipt node than the one the header commits to
    }

    function _defaultBundle(bytes memory content, bytes32 sentHash, uint64 next)
        internal
        pure
        returns (Bundle memory b)
    {
        b.record = _record(CHANNEL, next, sentHash, "", _control("eip155:999"));
        b.emitter = BEACON;
        b.topic0 = keccak256("ClprQueueRecord(address,bytes32,bytes)");
        b.status = 1;
        b.signers = K;
        b.rotations = RLP.encode(new bytes[](0));
        b.content = content;
    }

    function _bundleProof(Bundle memory b) internal view returns (bytes memory) {
        (bytes memory header, bytes memory leaf) =
            _block(_receipt(b.emitter, b.topic0, SERVICE, CHANNEL, b.record, b.status));
        uint256[] memory ks = b.signerKeys.length > 0 ? b.signerKeys : keys;
        if (b.corruptReceiptNode) {
            (, leaf) = _block(_receipt(b.emitter, b.topic0, SERVICE, CHANNEL, b.record, 1 - b.status));
        }
        bytes[] memory nodes = new bytes[](1);
        nodes[0] = RLP.encode(leaf);
        bytes[] memory rc = new bytes[](2);
        rc[0] = RLP.encode(uint256(0));
        rc[1] = RLP.encode(nodes);
        bytes[] memory p = new bytes[](b.manifest.length > 0 ? 8 : 7);
        p[0] = _setRlp(K, addrs);
        p[1] = b.rotations;
        p[2] = RLP.encode(header);
        p[3] = _sigs(ks, _first(b.signers), hv.blockDigest(BLOCK, keccak256(header)));
        p[4] = RLP.encode(rc);
        p[5] = RLP.encode(uint256(0));
        p[6] = RLP.encode(b.content);
        if (b.manifest.length > 0) p[7] = RLP.encode(b.manifest);
        return RLP.encode(p);
    }

    function _anchor() internal view returns (bytes memory) {
        return abi.encode(_setHash(K, addrs), uint256(0), uint256(0), BEACON);
    }

    function _context() internal pure returns (bytes memory) {
        return abi.encodePacked(CHANNEL, SERVICE);
    }

    function _configProof(string memory chainId, bytes memory manifestPreimage) internal view returns (bytes memory) {
        bytes memory control = _control(chainId);
        bytes memory record = _record(bytes32(0), 0, 0, manifestPreimage, control);
        (bytes memory header, bytes memory leaf) =
            _block(_receipt(BEACON, keccak256("ClprQueueRecord(address,bytes32,bytes)"), SERVICE, 0, record, 1));
        bytes[] memory nodes = new bytes[](1);
        nodes[0] = RLP.encode(leaf);
        bytes[] memory rc = new bytes[](2);
        rc[0] = RLP.encode(uint256(0));
        rc[1] = RLP.encode(nodes);
        bytes[] memory p = new bytes[](7);
        p[0] = _setRlp(K, addrs);
        p[1] = RLP.encode(header);
        p[2] = _sigs(keys, _first(K), hv.blockDigest(BLOCK, keccak256(header)));
        p[3] = RLP.encode(rc);
        p[4] = RLP.encode(uint256(0));
        p[5] = RLP.encode(control);
        p[6] = RLP.encode(BEACON);
        return RLP.encode(p);
    }

    /// @dev ClprBundleContent with `n` payloads (field 2) and the running hash over them from 0.
    function _content(uint256 n) internal pure returns (bytes memory content, bytes32 running) {
        for (uint256 i = 0; i < n; ++i) {
            bytes memory payload = abi.encodePacked(hex"0a0412020801", uint8(i + 1));
            content = abi.encodePacked(content, hex"12", uint8(payload.length), payload);
            running = sha256(abi.encodePacked(running, sha256(payload)));
        }
    }
}
