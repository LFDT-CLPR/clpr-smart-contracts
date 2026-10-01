// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprAlgorandStateProof as SP} from "@hiero-ledger/clpr/libraries/proof/algorand/ClprAlgorandStateProof.sol";
import {ClprFalconDet1024Engine} from "@hiero-ledger/clpr/libraries/proof/algorand/ClprFalconDet1024Engine.sol";
import {
    AlgorandStateProofAccumulator as Acc
} from "@hiero-ledger/clpr/verifiers/evm/algorand/AlgorandStateProofAccumulator.sol";
import {
    AlgorandStateProofVerifier as V
} from "@hiero-ledger/clpr/verifiers/evm/algorand/AlgorandStateProofVerifier.sol";

/// @notice Synthetic Algorand worlds for the bundle verifier: a bootstrapped interval whose
///         BlockHeadersCommitment covers a light header, whose Sha256TxnCommitment covers a CLPR
///         application call with an ARC-28 `ClprQueue` log. All hashes are the real Algorand encodings
///         (SHA-256 vector commitments, canonical msgpack); only the state-proof signatures are skipped,
///         because the interval is bootstrapped (the live tests cover signatures).
abstract contract AlgorandTestKit {
    bytes32 internal constant CHANNEL_ID = keccak256("algorand-channel");
    uint64 internal constant APP_ID = 3_141_592_653;
    bytes32 internal constant GENESIS = 0xc061c4d8fc1dbdded2d7604be4568e3f6d041987ac37bde4b620b5ab39248adf;
    uint64 internal constant FIRST = 64_999_937;
    uint64 internal constant LAST = 65_000_192;
    uint64 internal constant ROUND = 65_000_100;

    Acc internal acc;
    V internal av;
    bytes32 internal root;

    struct Queue {
        uint8 status;
        uint64 nextMessageId;
        uint64 receivedMessageId;
        bytes32 sentRunningHash;
        bytes32 receivedRunningHash;
        uint64 manifestVersion;
        bytes32 manifestCommitment;
    }

    struct World {
        Queue q;
        bytes32 channelId;
        uint64 appId;
        bytes32 genesisHash;
        bytes extraLogBefore; // a non-CLPR log emitted before the queue event (logIndex shifts)
        bytes stib;
        uint64 txIndex;
        bytes txPath;
        bytes32 txid;
        bytes32 blockHash;
        bytes32 txnCommitment;
        bytes headerPath;
        bytes content;
        bool withManifest;
        bytes manifest;
        uint256 logIndex;
    }

    function _initKit() internal {
        acc = new Acc(address(0x5b), address(0x5a), ClprFalconDet1024Engine(address(0xfa)));
        av = new V(acc);
    }

    function defaultQueue() internal pure returns (Queue memory q) {
        q.status = uint8(ClprTypes.ChannelStatus.ACTIVE);
        q.nextMessageId = 3;
        q.receivedMessageId = 1;
        q.sentRunningHash = keccak256("sent");
        q.receivedRunningHash = keccak256("received");
        q.manifestVersion = 4;
    }

    function queueEvent(bytes32 channelId, Queue memory q) internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes4(0x27fe15da),
            channelId,
            q.status,
            q.nextMessageId,
            q.receivedMessageId,
            q.sentRunningHash,
            q.receivedRunningHash,
            q.manifestVersion,
            q.manifestCommitment
        );
    }

    // ── msgpack ──────────────────────────────────────────────────────────────

    function _str(bytes memory s) internal pure returns (bytes memory) {
        if (s.length < 32) return abi.encodePacked(uint8(0xa0 | s.length), s);
        if (s.length < 256) return abi.encodePacked(uint8(0xd9), uint8(s.length), s);
        return abi.encodePacked(uint8(0xda), uint16(s.length), s);
    }

    /// @dev SignedTxnInBlock {dt: {lg: logs}, sig, txn: {apid, fee, snd, type}} with sorted keys.
    function stib(uint64 appId, string memory txType, bytes[] memory logs) internal pure returns (bytes memory) {
        bytes memory lg = abi.encodePacked(uint8(0x90 | logs.length));
        for (uint256 i = 0; i < logs.length; i++) {
            lg = abi.encodePacked(lg, _str(logs[i]));
        }
        bytes memory txn = abi.encodePacked(
            uint8(0x84),
            _str("apid"),
            SP.encodeUint(appId),
            _str("fee"),
            SP.encodeUint(1000),
            _str("snd"),
            uint8(0xc4),
            uint8(32),
            keccak256("sender"),
            _str("type"),
            _str(bytes(txType))
        );
        return abi.encodePacked(
            uint8(0x83),
            _str("dt"),
            uint8(0x81),
            _str("lg"),
            lg,
            _str("sig"),
            uint8(0xc4),
            uint8(64),
            keccak256("sig-a"),
            keccak256("sig-b"),
            _str("txn"),
            txn
        );
    }

    // ── world ────────────────────────────────────────────────────────────────

    function _world(Queue memory q) internal pure returns (World memory w) {
        w.q = q;
        w.channelId = CHANNEL_ID;
        w.appId = APP_ID;
        w.genesisHash = GENESIS;
        w.txIndex = 2;
        w.txPath = abi.encodePacked(keccak256("tx-sib-0"), keccak256("tx-sib-1"));
        w.txid = keccak256("txid");
        w.blockHash = keccak256("block");
        w.headerPath = abi.encodePacked(
            keccak256("h0"),
            keccak256("h1"),
            keccak256("h2"),
            keccak256("h3"),
            keccak256("h4"),
            keccak256("h5"),
            keccak256("h6"),
            keccak256("h7")
        );
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = "hello algorand";
        w.content = bytes.concat(hex"12", abi.encodePacked(uint8(payloads[0].length)), payloads[0]);
    }

    function _logs(World memory w) internal pure returns (bytes[] memory logs) {
        bytes memory ev = queueEvent(w.channelId, w.q);
        if (w.extraLogBefore.length == 0) {
            logs = new bytes[](1);
            logs[0] = ev;
        } else {
            logs = new bytes[](2);
            logs[0] = w.extraLogBefore;
            logs[1] = ev;
        }
    }

    /// @dev Fill stib, txn commitment and return the BlockHeadersCommitment the world needs.
    function _seal(World memory w) internal pure returns (bytes32 headersRoot) {
        if (w.stib.length == 0) w.stib = stib(w.appId, "appl", _logs(w));
        if (w.extraLogBefore.length != 0 && w.logIndex == 0) w.logIndex = 1;
        w.txnCommitment = SP.sha256Root(SP.txnLeaf(w.txid, w.stib), w.txIndex, w.txPath);
        headersRoot = SP.sha256Root(
            SP.lightHeaderLeaf(w.blockHash, w.genesisHash, ROUND, w.txnCommitment), ROUND - FIRST, w.headerPath
        );
    }

    function bootstrapMessage(bytes32 headersRoot) internal pure returns (SP.Message memory m) {
        m.blockHeadersCommitment = headersRoot;
        m.votersCommitment = abi.encodePacked(keccak256("voters-hi"), keccak256("voters-lo"));
        m.lnProvenWeight = 2_230_000;
        m.firstAttestedRound = FIRST;
        m.lastAttestedRound = LAST;
    }

    /// @dev Seal the world, bootstrap its interval in the accumulator (idempotent) and return the root.
    function _install(World memory w) internal returns (bytes32 r) {
        SP.Message memory m = bootstrapMessage(_seal(w));
        r = SP.messageHash(m);
        if (acc.interval(r, LAST).lastAttestedRound == 0) acc.bootstrap(m);
    }

    function _encode(World memory w) internal pure returns (bytes memory) {
        V.TxProof memory t = V.TxProof({
            intervalLastRound: LAST,
            blockHash: w.blockHash,
            round: ROUND,
            txnCommitment: w.txnCommitment,
            headerPath: w.headerPath,
            txIndex: w.txIndex,
            txPath: w.txPath,
            txid: w.txid,
            stib: w.stib
        });
        return abi.encode(
            V.BundleProof({
                txn: t,
                logIndex: w.logIndex,
                bundleContent: w.content,
                hasManifest: w.withManifest,
                manifest: w.manifest
            })
        );
    }

    function anchorOf(bytes32 r) internal pure returns (bytes memory) {
        return abi.encodePacked(r, GENESIS);
    }

    function ctx() internal pure returns (bytes memory) {
        return abi.encodePacked(CHANNEL_ID, APP_ID);
    }

    function manifest(bytes memory serviceAddress, uint64 version) internal pure returns (bytes memory) {
        ClprTypes.ClprEndpointManifest memory m;
        m.version = version;
        m.serviceAddress = serviceAddress;
        m.endpoints = new ClprTypes.Endpoint[](0);
        return ClprProtobuf.encodeEndpointManifest(m);
    }

    function ledgerConfig(string memory chainId) internal pure returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory lc;
        lc.protocolVersion = 1;
        lc.chainId = chainId;
        lc.serviceAddress = abi.encodePacked(APP_ID);
        lc.nanosSinceEpoch = 1_760_000_000 * 1e9;
        lc.throttles.maxMessagesPerBundle = 100;
        lc.throttles.maxMessagePayloadBytes = 10_000;
        lc.throttles.maxSyncBytes = 1_000_000;
        lc.throttles.maxQueueDepth = 1000;
        lc.throttles.maxGasPerMessage = 1_000_000;
        return ClprProtobuf.encodeControlMessage(lc);
    }

    function _config(World memory w, string memory chainId) internal returns (bytes memory) {
        SP.Message memory m = bootstrapMessage(_seal(w));
        if (acc.interval(SP.messageHash(m), LAST).lastAttestedRound == 0) acc.bootstrap(m);
        return
            abi.encode(V.ConfigProof({bootstrap: m, genesisHash: GENESIS, ledgerConfiguration: ledgerConfig(chainId)}));
    }
}
