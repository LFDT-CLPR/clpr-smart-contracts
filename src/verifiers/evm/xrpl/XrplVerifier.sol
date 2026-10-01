// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {XrplLib} from "@hiero-ledger/clpr/verifiers/evm/xrpl/XrplLib.sol";
import {XrplLightClient} from "@hiero-ledger/clpr/verifiers/evm/xrpl/XrplLightClient.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title XrplVerifier
/// @notice XRP Ledger → Hiero `IClprVerifier`. {XrplLightClient} checks the UNL validations, the
///         ledger headers and the transaction-tree inclusion of each transaction with its metadata
///         (tesSUCCESS). This contract applies the XRPL CLPR outbox rules (README.md, "Outbox rules"):
///
///         - XRPL has no CLPR Service (XLS-101 is a draft). Each channel has an outbox account: a
///           k-of-n multisig with its master key disabled and no regular key.
///         - Each CLPR message is one AccountSet from the outbox with no flags and no other fields,
///           carrying exactly one Memo: MemoType "clpr/v1", no MemoFormat, MemoData = protobuf
///           `ClprXrplMemo { bytes channel_id = 1; ChannelSyncData sync_data = 2;
///           ClprMessagePayload payload = 3; }`. Serialized Memos are at most 1024 bytes.
///         - message_id = Sequence - seq_base + 1. Sequences are unique and consecutive per account,
///           which gives order and exactly-once. Tickets (Sequence 0), Batch inner transactions
///           (tfInnerBatchTxn), Delegate-signed and any other transaction shape are rejected.
///
/// @dev Bundle proof, RLP: the light client's ledger prefix [0..4] (UNL, manifests, header,
///      validations, ancestors), then
///        [5] transactions: [[ledgerRef, tx, meta, [inner(512), ...]], ...], consecutive Sequences
///        [6] the running hash before the first transaction (32 bytes, untrusted; see below)
///      The payloads come from the memos, so a bundle carries no separate content. The proof fixes
///      every payload and its message id; sentRunningHash is derived from them, starting at [6].
///      [6] needs no authentication: BundleLib recomputes the chain from the channel's own
///      receivedRunningHash over the new payloads and reverts unless it equals sentRunningHash, so
///      a wrong starting hash only makes the bundle fail.
///      Trust anchor: abi.encode(bytes32 unlHash, uint256 unlCount, uint256 seqBase, uint256 minLedgerSeq).
///      A manifest rotation returns a new anchor (new unlHash, minLedgerSeq = this ledger).
contract XrplVerifier is ClprEvmBundleVerifier {
    bytes32 internal constant MEMO_TYPE_HASH = keccak256("clpr/v1");
    uint16 internal constant TT_ACCOUNT_SET = 3;
    uint256 internal constant MAX_MEMOS_BYTES = 1024; // rippled STTx.cpp isMemoOkay
    uint256 internal constant TX_FIELD = 5;
    uint32 internal constant LSF_DISABLE_MASTER = 0x00100000;
    uint16 internal constant LT_ACCOUNT_ROOT = 0x0061;

    XrplLightClient public immutable LIGHT_CLIENT;
    bytes32 internal immutable CHAIN_ID_HASH;

    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error ZeroLightClient();
    error WrongSender();
    error NotClprMessage(uint256 offset);
    error SequenceGap(uint256 expected, uint256 actual);
    error BadMemo();
    error ChannelMismatch();
    error NextMessageIdMismatch(uint256 expected, uint256 actual);
    error NoTransactions();
    error WrongChain(string chainId);
    error OutboxNotLocked();
    error ManifestNotCommitted();

    struct Anchor {
        bytes32 unlHash;
        uint256 unlCount;
        uint256 seqBase;
        uint256 minLedgerSeq;
    }

    struct Memo {
        bytes32 channelId;
        uint64 receivedMessageId;
        uint64 status;
        uint64 nextMessageId;
        bytes payload;
    }

    constructor(string memory caip2, XrplLightClient lightClient) {
        if (address(lightClient) == address(0)) revert ZeroLightClient();
        LIGHT_CLIENT = lightClient;
        CHAIN_ID_HASH = keccak256(bytes(caip2));
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
        if (ctx.remoteServiceAddress.length != 20) revert InvalidServiceAddressLength();
        Memory.Slice[] memory p = RLP.decodeList(proofBytes);
        if (p.length != 7) revert InvalidPayloadShape();
        bytes32 running = RLP.readBytes32(p[6]);

        (XrplLightClient.Ledger memory lg, XrplLightClient.ProvenTx[] memory txs) =
            LIGHT_CLIENT.proveTransactions(proofBytes, a.unlHash, a.unlCount, a.minLedgerSeq, TX_FIELD);
        if (txs.length == 0) revert NoTransactions();

        bytes20 outbox = bytes20(ctx.remoteServiceAddress);
        messagePayloads = new bytes[](txs.length);
        Memo memory m;
        uint256 id;
        for (uint256 k = 0; k < txs.length; ++k) {
            (bytes20 account, uint256 seq, bytes memory memoData) = _clprMessage(txs[k].tx);
            if (account != outbox) revert WrongSender();
            uint256 expected = k == 0 ? seq : id + a.seqBase; // Sequence of the next message
            if (seq < a.seqBase || seq != expected) revert SequenceGap(expected, seq);
            id = seq - a.seqBase + 1;
            m = _decodeMemo(memoData);
            if (m.channelId != ctx.channelId) revert ChannelMismatch();
            if (m.nextMessageId != id + 1) revert NextMessageIdMismatch(id + 1, m.nextMessageId);
            messagePayloads[k] = m.payload;
            running = sha256(abi.encodePacked(running, sha256(m.payload)));
        }
        if (m.status > uint64(type(ClprTypes.ChannelStatus).max)) revert BadMemo();
        metadata.nextMessageId = uint64(id + 1);
        metadata.sentRunningHash = running;
        metadata.receivedMessageId = m.receivedMessageId;
        metadata.state = ClprTypes.ChannelStatus(m.status);
        // receivedRunningHash and endpointManifestVersion are not published on XRPL (zero).
        newEndpointManifest = _absentEndpointManifest();

        if (lg.newUnlHash != bytes32(0)) {
            newTrustAnchor = abi.encode(lg.newUnlHash, a.unlCount, a.seqBase, uint256(lg.seq));
            newTrustAnchorId = abi.encodePacked(lg.newUnlHash);
        }
    }

    // ── transaction shape ─────────────────────────────────────────────────────

    /// @dev Enforce the CLPR message shape and return the MemoData. Allowed top-level fields:
    ///      TransactionType (= AccountSet), Flags (= 0), Sequence (non-zero), NetworkID,
    ///      LastLedgerSequence, Fee, SigningPubKey, TxnSignature, Account, Signers, Memos. Anything
    ///      else (TicketSequence, SetFlag, Domain, Delegate, ...) is rejected. Memos must hold exactly
    ///      one Memo with MemoType "clpr/v1" and MemoData only, serialized within 1024 bytes.
    ///      Returns the sender (top-level sfAccount, never a Signer's), the Sequence and the MemoData.
    function _clprMessage(bytes memory tx)
        internal
        pure
        returns (bytes20 account, uint256 sequence, bytes memory memoData)
    {
        uint256 i;
        uint256 depth;
        uint256 memosStart;
        uint256 memoCount;
        bool inMemos;
        bool typeOk;
        while (i < tx.length) {
            (uint256 t, uint256 f, uint256 vs, uint256 ve, uint256 nx) = XrplLib.nextField(tx, i);
            if (t == XrplLib.STI_OBJECT || t == XrplLib.STI_ARRAY) {
                if (f == 1) {
                    if (depth == 0) revert NotClprMessage(i);
                    --depth;
                    if (depth == 0 && inMemos) {
                        if (i - memosStart > MAX_MEMOS_BYTES) revert BadMemo();
                        inMemos = false;
                    }
                } else {
                    if (depth == 0) {
                        if (t == XrplLib.STI_ARRAY && f == 9) {
                            inMemos = true; // sfMemos
                            memosStart = nx;
                        } else if (!(t == XrplLib.STI_ARRAY && f == 3)) {
                            revert NotClprMessage(i); // only Memos and Signers
                        }
                    } else if (depth == 1 && inMemos) {
                        if (t != XrplLib.STI_OBJECT || f != 10 || ++memoCount > 1) revert BadMemo();
                    }
                    ++depth;
                }
            } else if (depth == 0) {
                _checkTopField(tx, t, f, vs, i);
                if (t == 2 && f == 4) sequence = XrplLib.readU32(tx, vs);
                if (t == 8 && f == 1) {
                    if (ve - vs != 20) revert NotClprMessage(i);
                    account = bytes20(XrplLib.readB32(tx, vs));
                }
            } else if (inMemos) {
                if (depth != 2 || t != XrplLib.STI_VL) revert BadMemo();
                if (f == 12) {
                    typeOk = keccak256(XrplLib.slice(tx, vs, ve)) == MEMO_TYPE_HASH;
                } else if (f == 13) {
                    memoData = XrplLib.slice(tx, vs, ve);
                } else {
                    revert BadMemo(); // MemoFormat or anything else
                }
            }
            i = nx;
        }
        if (memoCount != 1 || !typeOk || memoData.length == 0) revert BadMemo();
        if (sequence == 0 || account == bytes20(0)) revert NotClprMessage(tx.length);
    }

    function _checkTopField(bytes memory tx, uint256 t, uint256 f, uint256 vs, uint256 at) internal pure {
        if (t == 1 && f == 2) {
            if (uint8(tx[vs]) != 0 || uint8(tx[vs + 1]) != TT_ACCOUNT_SET) revert NotClprMessage(at);
        } else if (t == 2 && f == 2) {
            if (XrplLib.readU32(tx, vs) != 0) revert NotClprMessage(at); // no flags (no tfInnerBatchTxn)
        } else if (t == 2 && f == 4) {
            if (XrplLib.readU32(tx, vs) == 0) revert NotClprMessage(at); // a Ticket
        } else if (
            !(t == 2 && (f == 1 || f == 27)) // NetworkID, LastLedgerSequence
                && !(t == 6 && f == 8) // Fee
                && !(t == 7 && (f == 3 || f == 4)) // SigningPubKey, TxnSignature
                && !(t == 8 && f == 1) // Account
        ) {
            revert NotClprMessage(at);
        }
    }

    /// @dev Strict ClprXrplMemo decode: fields 1 (32 bytes), 2 (ChannelSyncData), 3 (payload), each
    ///      at most once; field 3 required. ChannelSyncData: received_message_id = 1, status = 2,
    ///      next_message_id = 3 (clpr-service-spec ChannelSyncData; status uses ClprChannelStatus).
    function _decodeMemo(bytes memory d) internal pure returns (Memo memory m) {
        uint256 off;
        uint256 seen;
        while (off < d.length) {
            uint64 fn;
            uint8 wt;
            (fn, wt, off) = PB.decodeFieldKey(d, off);
            if (wt != 2 || fn == 0 || fn > 3 || seen & (1 << fn) != 0) revert BadMemo();
            seen |= 1 << fn;
            bytes memory v;
            (v, off) = PB.decodeLengthDelimited(d, off);
            if (fn == 1) {
                if (v.length != 32) revert BadMemo();
                m.channelId = bytes32(v);
            } else if (fn == 2) {
                _decodeSync(v, m);
            } else {
                m.payload = v;
            }
        }
        if (seen & 8 == 0 || m.payload.length == 0) revert BadMemo();
    }

    function _decodeSync(bytes memory s, Memo memory m) internal pure {
        uint256 off;
        while (off < s.length) {
            uint64 fn;
            uint8 wt;
            (fn, wt, off) = PB.decodeFieldKey(s, off);
            if (wt != 0 || fn == 0 || fn > 3) revert BadMemo();
            uint64 v;
            (v, off) = PB.decodeVarint(s, off);
            if (fn == 1) m.receivedMessageId = v;
            else if (fn == 2) m.status = v;
            else m.nextMessageId = v;
        }
    }

    // ── verifyConfig ──────────────────────────────────────────────────────────

    /// @inheritdoc IClprVerifier
    /// @dev Config proof, RLP: [UNL [[masterKey, compressedSigningKey(33), manifestSeq], ...],
    ///      header, validations, [inner(512), ...], outbox AccountRoot data, seqBase, controlMessage,
    ///      manifestCommitment (32 bytes, or empty)]. The light client proves the outbox AccountRoot
    ///      in a UNL-validated ledger; it must have lsfDisableMaster and no RegularKey, so only its
    ///      signer list can send. seq_base, the LedgerConfiguration and the manifest commitment are
    ///      not on XRPL: they are supplied by whoever opens the channel, as the design specifies.
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
        Memory.Slice[] memory p = RLP.decodeList(configProofBytes);
        if (p.length != 8) revert InvalidPayloadShape();
        ClprTypes.LedgerConfiguration memory lc = ClprProtobuf.decodeControlMessage(RLP.readBytes(p[6])).config;
        if (keccak256(bytes(lc.chainId)) != CHAIN_ID_HASH) revert WrongChain(lc.chainId);
        serviceAddress = lc.serviceAddress;
        if (serviceAddress.length != 20) revert InvalidServiceAddressLength();
        uint256 seqBase = RLP.readUint256(p[5]);
        if (seqBase == 0 || seqBase > type(uint32).max) revert InvalidPayloadShape();

        (uint32 ledgerSeq, bytes32 unlHash, uint256 unlCount, bytes memory root) =
            LIGHT_CLIENT.proveConfigAccount(configProofBytes, bytes20(serviceAddress));
        _checkOutbox(root, bytes20(serviceAddress));

        initialTrustAnchor = abi.encode(unlHash, unlCount, seqBase, uint256(ledgerSeq));
        initialTrustAnchorId = abi.encodePacked(unlHash);
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        endpointManifest = _configManifest(RLP.readBytes(p[7]), endpointManifestProofBytes, serviceAddress);
        chainId = lc.chainId;
        peerConfigNanos = lc.nanosSinceEpoch;
        throttles = lc.throttles;
    }

    /// @dev AccountRoot of the outbox: lsfDisableMaster set, no sfRegularKey.
    function _checkOutbox(bytes memory root, bytes20 outbox) internal pure {
        uint256 i;
        bool typeOk;
        bool locked;
        bool accountOk;
        while (i < root.length) {
            (uint256 t, uint256 f, uint256 vs, uint256 ve, uint256 nx) = XrplLib.nextField(root, i);
            if (t == 1 && f == 1) {
                typeOk = uint16(uint8(root[vs])) << 8 | uint8(root[vs + 1]) == LT_ACCOUNT_ROOT;
            } else if (t == 2 && f == 2) {
                locked = XrplLib.readU32(root, vs) & LSF_DISABLE_MASTER != 0;
            } else if (t == 8 && f == 1) {
                accountOk = ve - vs == 20 && bytes20(XrplLib.readB32(root, vs)) == outbox;
            } else if (t == 8 && f == 8) {
                revert OutboxNotLocked(); // sfRegularKey
            }
            i = nx;
        }
        if (!typeOk || !accountOk) revert WrongSender();
        if (!locked) revert OutboxNotLocked();
    }

    function _configManifest(bytes memory commitment, bytes calldata preimage, bytes memory serviceAddress)
        internal
        pure
        returns (ClprTypes.ClprEndpointManifest memory m)
    {
        if (preimage.length == 0) return _uninitializedEndpointManifest(serviceAddress);
        if (commitment.length != 32) revert ManifestNotCommitted();
        if (keccak256(preimage) != bytes32(commitment)) revert ManifestCommitmentMismatch();
        m = ClprProtobuf.decodeEndpointManifest(preimage);
        if (m.version == 0) revert ManifestVersionZero();
        if (keccak256(m.serviceAddress) != keccak256(serviceAddress)) revert ManifestServiceAddressMismatch();
    }

    function _decodeAnchor(bytes calldata trustAnchor) internal pure returns (Anchor memory a) {
        if (trustAnchor.length != 128) revert InvalidTrustAnchor();
        (a.unlHash, a.unlCount, a.seqBase, a.minLedgerSeq) =
            abi.decode(trustAnchor, (bytes32, uint256, uint256, uint256));
        if (a.unlCount == 0 || a.unlHash == bytes32(0) || a.seqBase == 0 || a.seqBase > type(uint32).max) {
            revert InvalidTrustAnchor();
        }
    }
}
