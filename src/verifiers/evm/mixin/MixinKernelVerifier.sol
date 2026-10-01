// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprRecordVerifierBase} from "@hiero-ledger/clpr/verifiers/evm/common/ClprRecordVerifierBase.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprQueueRecord} from "@hiero-ledger/clpr/libraries/codec/ClprQueueRecord.sol";
import {ClprBlake3} from "@hiero-ledger/clpr/libraries/crypto/ClprBlake3.sol";
import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {MixinCosi} from "@hiero-ledger/clpr/verifiers/evm/mixin/MixinCosi.sol";
import {MixinLib} from "@hiero-ledger/clpr/verifiers/evm/mixin/MixinLib.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title MixinKernelVerifier
/// @notice Mixin kernel → Hiero `IClprVerifier`, checking the kernel's collective signature on-chain.
///
///         Finality. A snapshot is final when it carries a CoSi signature from at least the kernel
///         threshold of consensus nodes (mixin kernel/graph.go `verifyFinalization` →
///         crypto/cosi.go `FullVerify`). The CoSi signature is ONE standard ed25519 signature over
///         the snapshot hash (BLAKE3 of the snapshot payload), under the plain sum of the signers'
///         public spend keys, selected by a 64-bit mask over the ordered signer list
///         (kernel/graph.go `ConsensusKeys`). The verifier recomputes the snapshot hash with BLAKE3,
///         sums the masked keys ({MixinCosi}), and checks the signature with an {IEd25519Verifier}.
///
///         Node set. The signer list at time t is every node ACCEPTED before t whose acceptance is
///         older than 12 hours (`ConsensusReady`), in (accept time, id) order. The anchor holds the
///         ready list and at most one node accepted less than 12 hours before the anchor's last
///         change (the pending node). A bundle may carry kernel node changes, each a NodeAccept
///         (output type 0xa4) or NodeRemove (0xa6) XIN transaction in a snapshot that the current
///         list finalizes. An accept makes its signer key pending; a pending node joins the end of
///         the list for snapshots more than 12 hours after its accept snapshot. A remove drops the
///         key named in its extra. The kernel validates both transaction types before it finalizes
///         them (common/node.go), so a final accept or remove is a real node-set change.
///
///         Authorization. Mixin has no contracts (MVM is retired), so the CLPR endpoint is a Mixin
///         MTG app (a k-of-n group) that publishes a {ClprQueueRecord} in a transaction's `extra`
///         (256-byte limit; the record is 190 bytes). The records form a THREAD: each record
///         transaction spends output 0 of the previous one. The kernel only finalizes a transaction
///         whose inputs are unspent and signed by their owners, so a final transaction that extends
///         the thread was authorized by whoever holds the thread output (the MTG). Each output can be
///         spent once, so the thread cannot fork. The anchor pins the thread tip. A bundle carries the
///         record transactions from the tip to the newest one, and only the newest needs a snapshot:
///         its finality implies its inputs were final. The thread may start with the tip itself
///         (already verified); a thread that is only the tip re-reads its record without a snapshot,
///         which lets a bundle carry node changes and no new record.
///
/// @dev Bundle proof, RLP:
///        [0] ready node keys [key(32), ...] in kernel order (must hash to the anchor)
///        [1] node changes [[signerXs, snapshotPayload, signature(64), mask, txPayload], ...]
///        [2] record finality [signerXs, snapshotPayload, signature(64), mask], or [] when the
///            thread is only the tip
///        [3] thread [txPayload, ...]: optionally the tip first; each next spends (prev, 0)
///        [4] checkpoint (0 or 1): 1 returns a new anchor whose tip is the last transaction
///        [5] ClprBundleContent protobuf (messages, bound by the record's sentRunningHash)
///        [6] optional endpoint manifest preimage
///      signerXs: the affine x of every masked signer key, in mask order.
///      Trust anchor: abi.encode(bytes32 nodesHash, bytes32 tip, bytes32 pendingKey, uint64 pendingAt,
///      uint64 changedAt), nodesHash = keccak256(key ‖ key ‖ ...); pendingKey = 0 when no node is
///      pending; changedAt = the timestamp of the last applied change (changes must be newer).
contract MixinKernelVerifier is ClprRecordVerifierBase {
    IEd25519Verifier public immutable ED25519;

    /// @dev mixin config/reader.go: KernelNodeAcceptPeriodMinimum (12 h), KernelMinimumNodesCount,
    ///      SnapshotReferenceThreshold × SnapshotRoundGap (10 × 3 s), and the XIN asset id.
    uint64 internal constant ACCEPT_PERIOD = 12 hours * 1e9;
    uint64 internal constant REFERENCE_GAP = 30 * 1e9;
    uint256 internal constant MIN_NODES = 7;
    uint256 internal constant MAX_NODES = 64;
    bytes32 internal constant XIN = 0xa99c2e0e2b1da4d648755ef19bd95139acbbe6564cfb06dec7cd34931ca72cdc;
    uint8 internal constant OUTPUT_NODE_ACCEPT = 0xa4;
    uint8 internal constant OUTPUT_NODE_REMOVE = 0xa6;

    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error NodeSetMismatch();
    error BelowThreshold(uint256 signers, uint256 threshold);
    error BadCosiSignature();
    error TransactionNotInSnapshot(bytes32 txHash);
    error ThreadBroken(uint256 index);
    error EmptyThread();
    error ZeroEd25519Verifier();
    error NotANodeChange(uint256 index);
    error NodeAlreadyPending(uint256 index);
    error UnknownNode(uint256 index);
    error NodeCountOutOfRange(uint256 nodes);
    error StaleNodeChange(uint256 index);

    /// @dev The verifier's view of the kernel node set.
    struct NodeSet {
        bytes32[] ready;
        bytes32 pendingKey;
        uint64 pendingAt;
        uint64 changedAt;
    }

    struct Anchor {
        bytes32 nodesHash;
        bytes32 tip;
        bytes32 pendingKey;
        uint64 pendingAt;
        uint64 changedAt;
    }

    constructor(string memory caip2, IEd25519Verifier ed25519) ClprRecordVerifierBase(caip2) {
        if (address(ed25519) == address(0)) revert ZeroEd25519Verifier();
        ED25519 = ed25519;
    }

    /// @inheritdoc IClprVerifier
    function verifyBundle(bytes calldata proofBytes, bytes calldata trustAnchor, bytes calldata channelContext)
        external
        view
        override
        returns (
            ClprTypes.QueueMetadata memory metadata,
            bytes[] memory messagePayloads,
            bytes memory newTrustAnchor,
            bytes memory newTrustAnchorId,
            ClprTypes.ClprEndpointManifest memory newEndpointManifest
        )
    {
        Anchor memory a = _decodeAnchor(trustAnchor);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        Memory.Slice[] memory p = RLP.decodeList(proofBytes);
        if (p.length != 6 && p.length != 7) revert InvalidPayloadShape();

        NodeSet memory ns =
            NodeSet({ready: _words(p[0]), pendingKey: a.pendingKey, pendingAt: a.pendingAt, changedAt: a.changedAt});
        if (keccak256(abi.encodePacked(ns.ready)) != a.nodesHash) revert NodeSetMismatch();
        bool changed = _applyChanges(ns, RLP.readList(p[1]));

        (bytes32 lastTx, bytes memory extra, bool onlyTip) = _thread(RLP.readList(p[3]), a.tip);
        Memory.Slice[] memory fin = RLP.readList(p[2]);
        if (onlyTip) {
            if (fin.length != 0) revert InvalidPayloadShape();
        } else {
            if (fin.length != 4) revert InvalidPayloadShape();
            MixinLib.Snapshot memory s = _finalSnapshot(ns, fin, bytes32(0));
            _requireTx(s, lastTx);
            changed = _promote(ns, s.timestamp) || changed;
        }

        ClprQueueRecord.Record memory r = ClprQueueRecord.decode(extra, 0);
        _requireChannel(r, ctx.channelId);
        metadata = ClprQueueRecord.toMetadata(r);
        messagePayloads = _decodeBundleContent(RLP.readBytes(p[5]));
        newEndpointManifest = p.length == 7
            ? _recordManifest(r, RLP.readBytes(p[6]), ctx.remoteServiceAddress)
            : _absentEndpointManifest();
        bool checkpoint = RLP.readUint256(p[4]) == 1;
        if (checkpoint || changed) {
            bytes32 tip = checkpoint ? lastTx : a.tip;
            newTrustAnchor = _encodeAnchor(ns, tip);
            newTrustAnchorId = abi.encodePacked(tip);
        }
    }

    /// @dev Apply node changes in order; each must be final under the set as it stands before it.
    function _applyChanges(NodeSet memory ns, Memory.Slice[] memory changes) internal view returns (bool changed) {
        for (uint256 i = 0; i < changes.length; ++i) {
            Memory.Slice[] memory c = RLP.readList(changes[i]);
            if (c.length != 5) revert InvalidPayloadShape();
            bytes memory txPayload = RLP.readBytes(c[4]);
            MixinLib.Transaction memory t = MixinLib.parseTransaction(txPayload);
            if (
                t.asset != XIN || t.inputCount != 1 || t.outputCount != 1 || t.extra.length != 64
                    || (t.output0Type != OUTPUT_NODE_ACCEPT && t.output0Type != OUTPUT_NODE_REMOVE)
            ) revert NotANodeChange(i);
            bytes32 key;
            {
                bytes memory e = t.extra;
                assembly ("memory-safe") {
                    key := mload(add(e, 0x20))
                }
            }
            bool accept = t.output0Type == OUTPUT_NODE_ACCEPT;
            Memory.Slice[] memory fin = new Memory.Slice[](4);
            (fin[0], fin[1], fin[2], fin[3]) = (c[0], c[1], c[2], c[3]);
            // the accept is the pledging node's round 0, which its own key co-signs (ConsensusKeys)
            MixinLib.Snapshot memory s = _finalSnapshot(ns, fin, accept ? key : bytes32(0));
            _requireTx(s, ClprBlake3.hash(txPayload));
            // changes apply in kernel order, once each: an old change cannot be replayed
            if (s.timestamp <= ns.changedAt) revert StaleNodeChange(i);
            ns.changedAt = s.timestamp;
            _promote(ns, s.timestamp);
            if (accept) {
                if (s.round != 0) revert NotANodeChange(i);
                if (ns.pendingKey != bytes32(0)) revert NodeAlreadyPending(i);
                for (uint256 k = 0; k < ns.ready.length; ++k) {
                    if (ns.ready[k] == key) revert NodeAlreadyPending(i);
                }
                ns.pendingKey = key;
                ns.pendingAt = s.timestamp;
            } else {
                _remove(ns, key, i);
            }
        }
        return changes.length != 0;
    }

    /// @dev Move the pending node into the ready list once it is ConsensusReady at `timestamp`.
    function _promote(NodeSet memory ns, uint64 timestamp) internal pure returns (bool) {
        if (ns.pendingKey == bytes32(0) || ns.pendingAt + ACCEPT_PERIOD >= timestamp) return false;
        uint256 n = ns.ready.length;
        if (n + 1 > MAX_NODES) revert NodeCountOutOfRange(n + 1);
        bytes32[] memory next = new bytes32[](n + 1);
        for (uint256 i = 0; i < n; ++i) {
            next[i] = ns.ready[i];
        }
        next[n] = ns.pendingKey;
        ns.ready = next;
        ns.pendingKey = bytes32(0);
        ns.pendingAt = 0;
        return true;
    }

    function _remove(NodeSet memory ns, bytes32 key, uint256 index) internal pure {
        uint256 n = ns.ready.length;
        bytes32[] memory next = new bytes32[](n - 1);
        uint256 j;
        bool found;
        for (uint256 i = 0; i < n; ++i) {
            if (!found && ns.ready[i] == key) {
                found = true;
                continue;
            }
            if (j == n - 1) revert UnknownNode(index);
            next[j++] = ns.ready[i];
        }
        if (!found) revert UnknownNode(index);
        ns.ready = next;
    }

    /// @dev Verify a snapshot's CoSi under the signer list at its timestamp (+ `extraKey` last, for
    ///      a pledging node's round 0). Threshold: the kernel's base × 2 / 3 + 1, where base counts
    ///      the ready nodes and a pending node accepted more than 30 s before the snapshot
    ///      (kernel/node.go `ConsensusThreshold` with final = true).
    function _finalSnapshot(NodeSet memory ns, Memory.Slice[] memory f, bytes32 extraKey)
        internal
        view
        returns (MixinLib.Snapshot memory s)
    {
        bytes memory payload = RLP.readBytes(f[1]);
        s = MixinLib.parseSnapshot(payload);
        bool pendingReady = ns.pendingKey != bytes32(0) && ns.pendingAt + ACCEPT_PERIOD < s.timestamp;
        uint256 n = ns.ready.length;
        uint256 total = n + (pendingReady ? 1 : 0) + (extraKey != bytes32(0) ? 1 : 0);
        if (total > MAX_NODES) revert NodeCountOutOfRange(total);
        bytes32[] memory keys = new bytes32[](total);
        for (uint256 i = 0; i < n; ++i) {
            keys[i] = ns.ready[i];
        }
        if (pendingReady) keys[n++] = ns.pendingKey;
        if (extraKey != bytes32(0)) keys[n] = extraKey;

        uint256 base = ns.ready.length;
        if (ns.pendingKey != bytes32(0) && ns.pendingAt + REFERENCE_GAP < s.timestamp) ++base;
        if (base < MIN_NODES) revert NodeCountOutOfRange(base);
        uint256 threshold = base * 2 / 3 + 1;

        uint256[] memory xs;
        {
            bytes32[] memory xw = _words(f[0]);
            assembly ("memory-safe") {
                xs := xw
            }
        }
        uint256 mask = RLP.readUint256(f[3]);
        if (mask > type(uint64).max) revert InvalidPayloadShape();
        // casting to 'uint64' is safe: larger masks are rejected above
        // forge-lint: disable-next-line(unsafe-typecast)
        (bytes32 aggregate, uint256 count) = MixinCosi.aggregate(keys, xs, uint64(mask));
        if (count < threshold) revert BelowThreshold(count, threshold);
        bytes32 snapshotHash = ClprBlake3.hash(payload);
        if (!ED25519.verify(aggregate, abi.encodePacked(snapshotHash), RLP.readBytes(f[2]))) {
            revert BadCosiSignature();
        }
    }

    function _requireTx(MixinLib.Snapshot memory s, bytes32 txHash) internal pure {
        for (uint256 i = 0; i < s.transactions.length; ++i) {
            if (s.transactions[i] == txHash) return;
        }
        revert TransactionNotInSnapshot(txHash);
    }

    /// @dev Walk the record thread from `tip`: tx 0 is the tip itself or spends (tip, 0); each next
    ///      tx spends output 0 of the previous one.
    function _thread(Memory.Slice[] memory txs, bytes32 tip)
        internal
        pure
        returns (bytes32 h, bytes memory extra, bool onlyTip)
    {
        if (txs.length == 0) revert EmptyThread();
        h = tip;
        for (uint256 i = 0; i < txs.length; ++i) {
            bytes memory payload = RLP.readBytes(txs[i]);
            MixinLib.Transaction memory t = MixinLib.parseTransaction(payload);
            bytes32 th = ClprBlake3.hash(payload);
            if (i == 0 && th == tip) {
                extra = t.extra;
                continue;
            }
            if (t.input0Hash != h || t.input0Index != 0) revert ThreadBroken(i);
            h = th;
            extra = t.extra;
        }
        onlyTip = h == tip;
    }

    /// @inheritdoc IClprVerifier
    /// @dev Config proof, RLP: [readyKeys, pending ([] or [key, acceptTimestamp]),
    ///      [signerXs, snapshotPayload, signature, mask], configTxPayload, controlMessage]. The config
    ///      transaction must be final under that node set; its record (channel 0 or this channel)
    ///      commits to the control message, and it becomes the thread tip. Which transaction heads
    ///      the MTG's thread, and the node set, are chosen by whoever opens the channel.
    function verifyConfig(bytes calldata configProofBytes, bytes32 channelId, bytes calldata endpointManifestProofBytes)
        external
        view
        override
        returns (
            bytes memory channelContext,
            string memory chainId,
            bytes memory serviceAddress,
            uint96 peerConfigNanos,
            ClprTypes.Throttles memory throttles,
            bytes memory initialTrustAnchor,
            bytes memory initialTrustAnchorId,
            ClprTypes.ClprEndpointManifest memory endpointManifest
        )
    {
        if (configProofBytes.length == 0) revert InvalidPayloadShape();
        Memory.Slice[] memory c = RLP.decodeList(configProofBytes);
        if (c.length != 5) revert InvalidPayloadShape();
        NodeSet memory ns;
        ns.ready = _words(c[0]);
        {
            Memory.Slice[] memory pend = RLP.readList(c[1]);
            if (pend.length == 2) {
                ns.pendingKey = bytes32(RLP.readBytes(pend[0]));
                uint256 at = RLP.readUint256(pend[1]);
                if (ns.pendingKey == bytes32(0) || at == 0 || at > type(uint64).max) revert InvalidPayloadShape();
                // casting to 'uint64' is safe: the range is checked above
                // forge-lint: disable-next-line(unsafe-typecast)
                ns.pendingAt = uint64(at);
            } else if (pend.length != 0) {
                revert InvalidPayloadShape();
            }
        }
        Memory.Slice[] memory fin = RLP.readList(c[2]);
        if (fin.length != 4) revert InvalidPayloadShape();

        bytes memory txPayload = RLP.readBytes(c[3]);
        bytes32 tip = ClprBlake3.hash(txPayload);
        {
            MixinLib.Snapshot memory s = _finalSnapshot(ns, fin, bytes32(0));
            _requireTx(s, tip);
            _promote(ns, s.timestamp);
            ns.changedAt = s.timestamp;
        }
        ClprQueueRecord.Record memory r = ClprQueueRecord.decode(MixinLib.parseTransaction(txPayload).extra, 0);
        ClprTypes.LedgerConfiguration memory lc = _verifiedConfig(r, channelId, RLP.readBytes(c[4]));

        serviceAddress = lc.serviceAddress;
        initialTrustAnchor = _encodeAnchor(ns, tip);
        initialTrustAnchorId = abi.encodePacked(tip);
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        endpointManifest = _configManifest(r, endpointManifestProofBytes, serviceAddress);
        chainId = lc.chainId;
        peerConfigNanos = lc.nanosSinceEpoch;
        throttles = lc.throttles;
    }

    function _words(Memory.Slice item) internal pure returns (bytes32[] memory out) {
        Memory.Slice[] memory l = RLP.readList(item);
        out = new bytes32[](l.length);
        for (uint256 i = 0; i < l.length; ++i) {
            bytes memory w = RLP.readBytes(l[i]);
            if (w.length != 32) revert InvalidPayloadShape();
            out[i] = bytes32(w);
        }
    }

    function _encodeAnchor(NodeSet memory ns, bytes32 tip) internal pure returns (bytes memory) {
        return abi.encode(keccak256(abi.encodePacked(ns.ready)), tip, ns.pendingKey, ns.pendingAt, ns.changedAt);
    }

    function _decodeAnchor(bytes calldata trustAnchor) internal pure returns (Anchor memory a) {
        if (trustAnchor.length != 160) revert InvalidTrustAnchor();
        (a.nodesHash, a.tip, a.pendingKey, a.pendingAt, a.changedAt) =
            abi.decode(trustAnchor, (bytes32, bytes32, bytes32, uint64, uint64));
        if (a.nodesHash == bytes32(0) || a.tip == bytes32(0)) revert InvalidTrustAnchor();
        if ((a.pendingKey == bytes32(0)) != (a.pendingAt == 0)) revert InvalidTrustAnchor();
    }
}
