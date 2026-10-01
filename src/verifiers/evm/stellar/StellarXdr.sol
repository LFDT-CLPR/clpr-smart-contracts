// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title StellarXdr
/// @notice Strict decoders for the few Stellar XDR structures the Stellar → Hiero verifier reads.
///         Definitions follow stellar/stellar-xdr (Stellar-SCP.x, Stellar-ledger.x,
///         Stellar-transaction.x, Stellar-contract.x). Every decoder checks bounds and fails closed on
///         an unknown union arm, so a future protocol change halts verification instead of being
///         misread.
/// @dev All integers are big-endian; variable-length opaque data is a 4-byte length followed by the
///      bytes padded to a multiple of 4. Content is always authenticated by a SHA-256 over the exact
///      bytes, so the decoders only need to locate fields the way stellar-core does.
library StellarXdr {
    // ── Constants (stellar-xdr) ──────────────────────────────────────────────

    /// @dev EnvelopeType.ENVELOPE_TYPE_SCP (Stellar-ledger-entries.x).
    uint32 internal constant ENVELOPE_TYPE_SCP = 1;
    /// @dev EnvelopeType.ENVELOPE_TYPE_TX: prefix of a v1 transaction's signature payload.
    uint32 internal constant ENVELOPE_TYPE_TX = 2;
    /// @dev SCPStatementType.SCP_ST_EXTERNALIZE (Stellar-SCP.x).
    uint32 internal constant SCP_ST_EXTERNALIZE = 2;
    /// @dev PublicKeyType.PUBLIC_KEY_TYPE_ED25519.
    uint32 internal constant PUBLIC_KEY_TYPE_ED25519 = 0;
    /// @dev StellarValueType arms (Stellar-ledger.x).
    uint32 internal constant STELLAR_VALUE_BASIC = 0;
    uint32 internal constant STELLAR_VALUE_SIGNED = 1;
    uint32 internal constant STELLAR_VALUE_EMPTY_TX_SET = 2;
    /// @dev TransactionResultCode.txSUCCESS, OperationResultCode.opINNER,
    ///      OperationType.INVOKE_HOST_FUNCTION, InvokeHostFunctionResultCode.SUCCESS.
    uint32 internal constant TX_SUCCESS = 0;
    uint32 internal constant OP_INNER = 0;
    uint32 internal constant INVOKE_HOST_FUNCTION = 24;
    uint32 internal constant INVOKE_HOST_FUNCTION_SUCCESS = 0;
    /// @dev SCValType arms used by the CLPR attestation event.
    uint32 internal constant SCV_VOID = 1;
    uint32 internal constant SCV_BYTES = 13;
    uint32 internal constant SCV_SYMBOL = 15;
    /// @dev ContractEventType.CONTRACT.
    uint32 internal constant CONTRACT_EVENT = 1;
    /// @dev stellar-core QuorumSetUtils.cpp: MAXIMUM_QUORUM_NESTING_LEVEL.
    uint256 internal constant MAX_QSET_DEPTH = 4;
    /// @dev Total validators accepted in a quorum set. stellar-core allows 1000; at ~0.64M gas per
    ///      Ed25519 signature on Hedera, more than this could never be checked in one transaction.
    uint256 internal constant MAX_QSET_VALIDATORS = 64;
    /// @dev Upper bound of LedgerHeader.scpValue.upgrades (UpgradeType upgrades<6>) and of one
    ///      UpgradeType (opaque<128>).
    uint256 internal constant MAX_UPGRADES = 6;
    uint256 internal constant MAX_UPGRADE_BYTES = 128;

    error XdrOutOfBounds();
    error XdrTrailingBytes();
    error XdrBadLength();
    error XdrUnsupportedArm(uint32 arm);
    error NotExternalize(uint32 statementType);
    error UnsupportedKeyType(uint32 keyType);
    error QuorumSetInsane();

    // ── Types ────────────────────────────────────────────────────────────────

    /// @notice The LedgerHeader fields the verifier uses. `hash` = SHA-256(XDR(LedgerHeader)), the
    ///         ledger hash (stellar-core LedgerManagerImpl: `lcl.hash = xdrSha256(header)`).
    struct Header {
        bytes32 hash;
        uint32 ledgerVersion;
        bytes32 previousLedgerHash;
        bytes32 txSetHash;
        bytes32 txSetResultHash;
        bytes32 bucketListHash;
        uint32 ledgerSeq;
    }

    /// @notice An SCPStatement with the EXTERNALIZE pledge.
    struct Externalize {
        bytes32 nodeId;
        uint64 slotIndex;
        uint32 counter;
        bytes value; // StellarValue XDR (SCPBallot.value)
        uint32 nH;
        bytes32 commitQuorumSetHash; // D: the signer's own quorum set hash
    }

    /// @notice SCPQuorumSet, decoded. Validators are ed25519 node ids.
    struct QuorumSet {
        uint32 threshold;
        bytes32[] validators;
        QuorumSet[] innerSets;
    }

    // ── Primitive readers ────────────────────────────────────────────────────

    function u32(bytes memory b, uint256 o) internal pure returns (uint32 v) {
        if (o + 4 > b.length) revert XdrOutOfBounds();
        assembly ("memory-safe") {
            v := shr(224, mload(add(add(b, 0x20), o)))
        }
    }

    function u64(bytes memory b, uint256 o) internal pure returns (uint64 v) {
        if (o + 8 > b.length) revert XdrOutOfBounds();
        assembly ("memory-safe") {
            v := shr(192, mload(add(add(b, 0x20), o)))
        }
    }

    function b32(bytes memory b, uint256 o) internal pure returns (bytes32 v) {
        if (o + 32 > b.length) revert XdrOutOfBounds();
        assembly ("memory-safe") {
            v := mload(add(add(b, 0x20), o))
        }
    }

    /// @dev Skip `opaque<max>` at `o`; returns the data start, its length and the offset after padding.
    function opaque(bytes memory b, uint256 o, uint256 max)
        internal
        pure
        returns (uint256 start, uint256 len, uint256 end)
    {
        len = u32(b, o);
        if (len > max) revert XdrBadLength();
        start = o + 4;
        end = start + ((len + 3) & ~uint256(3));
        if (end > b.length) revert XdrOutOfBounds();
    }

    /// @dev Copy `b[start:start+len]`.
    function slice(bytes memory b, uint256 start, uint256 len) internal pure returns (bytes memory out) {
        if (start + len > b.length) revert XdrOutOfBounds();
        out = new bytes(len);
        assembly ("memory-safe") {
            mcopy(add(out, 0x20), add(add(b, 0x20), start), len)
        }
    }

    /// @dev SHA-256 of `b[start:start+len]` without copying (precompile 0x02).
    function sha256Range(bytes memory b, uint256 start, uint256 len) internal view returns (bytes32 h) {
        if (start + len > b.length) revert XdrOutOfBounds();
        bool ok;
        assembly ("memory-safe") {
            ok := staticcall(gas(), 0x02, add(add(b, 0x20), start), len, 0x00, 0x20)
            h := mload(0x00)
        }
        require(ok);
    }

    /// @dev NodeID / AccountID = PublicKey union; only ed25519 exists.
    function nodeId(bytes memory b, uint256 o) internal pure returns (bytes32 key, uint256 end) {
        uint32 t = u32(b, o);
        if (t != PUBLIC_KEY_TYPE_ED25519) revert UnsupportedKeyType(t);
        key = b32(b, o + 4);
        end = o + 36;
    }

    // ── StellarValue and LedgerHeader ────────────────────────────────────────

    /// @dev End offset of a StellarValue starting at `o`. Accepts BASIC, SIGNED and EMPTY_TX_SET;
    ///      fails closed on any other arm (e.g. the MS_CLOSE_TIME arms still behind an #ifdef).
    function stellarValueEnd(bytes memory b, uint256 o) internal pure returns (uint256 end, uint32 extArm) {
        // txSetHash (32) + closeTime (8)
        end = o + 40;
        uint256 n = u32(b, end);
        if (n > MAX_UPGRADES) revert XdrBadLength();
        end += 4;
        for (uint256 i = 0; i < n; ++i) {
            (,, end) = opaque(b, end, MAX_UPGRADE_BYTES);
        }
        extArm = u32(b, end);
        end += 4;
        if (extArm == STELLAR_VALUE_BASIC) {
            // void
        } else if (extArm == STELLAR_VALUE_SIGNED) {
            end = _closeValueSignatureEnd(b, end);
        } else if (extArm == STELLAR_VALUE_EMPTY_TX_SET) {
            // txSetHash, previousLedgerHash, previousLedgerVersion, LedgerCloseValueSignature
            end = _closeValueSignatureEnd(b, end + 68);
        } else {
            revert XdrUnsupportedArm(extArm);
        }
        if (end > b.length) revert XdrOutOfBounds();
    }

    /// @dev LedgerCloseValueSignature { NodeID nodeID; Signature signature (opaque<64>); }.
    function _closeValueSignatureEnd(bytes memory b, uint256 o) private pure returns (uint256 end) {
        (, end) = nodeId(b, o);
        (,, end) = opaque(b, end, 64);
    }

    /// @notice Decode a LedgerHeader (XDR) and hash it. The whole input must be one header.
    function parseHeader(bytes memory h) internal pure returns (Header memory hdr) {
        hdr.ledgerVersion = u32(h, 0);
        hdr.previousLedgerHash = b32(h, 4);
        hdr.txSetHash = b32(h, 36);
        (uint256 o,) = stellarValueEnd(h, 36);
        hdr.txSetResultHash = b32(h, o);
        hdr.bucketListHash = b32(h, o + 32);
        hdr.ledgerSeq = u32(h, o + 64);
        // totalCoins 8, feePool 8, inflationSeq 4, idPool 8, baseFee 4, baseReserve 4,
        // maxTxSetSize 4, skipList 4 x 32
        o += 68 + 40 + 128;
        uint32 ext = u32(h, o);
        o += 4;
        if (ext == 1) {
            // LedgerHeaderExtensionV1 { uint32 flags; union switch (int v) { case 0: void; } ext; }
            uint32 inner = u32(h, o + 4);
            if (inner != 0) revert XdrUnsupportedArm(inner);
            o += 8;
        } else if (ext != 0) {
            revert XdrUnsupportedArm(ext);
        }
        if (o != h.length) revert XdrTrailingBytes();
        hdr.hash = sha256(h);
    }

    // ── SCP ──────────────────────────────────────────────────────────────────

    /// @notice Decode an SCPStatement (XDR) that must carry the EXTERNALIZE pledge.
    function parseExternalize(bytes memory s) internal pure returns (Externalize memory e) {
        uint256 o;
        (e.nodeId, o) = nodeId(s, 0);
        e.slotIndex = u64(s, o);
        uint32 t = u32(s, o + 8);
        if (t != SCP_ST_EXTERNALIZE) revert NotExternalize(t);
        e.counter = u32(s, o + 12);
        (uint256 vs, uint256 vl, uint256 end) = opaque(s, o + 16, type(uint32).max);
        e.value = slice(s, vs, vl);
        e.nH = u32(s, end);
        e.commitQuorumSetHash = b32(s, end + 4);
        if (end + 36 != s.length) revert XdrTrailingBytes();
    }

    /// @notice The bytes an SCP envelope signature covers (stellar-core HerderImpl::signEnvelope):
    ///         xdr(networkID) || xdr(ENVELOPE_TYPE_SCP) || xdr(statement). Ed25519 signs them raw.
    function scpSignedMessage(bytes32 networkId, bytes memory statement) internal pure returns (bytes memory) {
        return abi.encodePacked(networkId, ENVELOPE_TYPE_SCP, statement);
    }

    /// @notice Decode an SCPQuorumSet and check stellar-core's sanity rules (QuorumSetUtils.cpp):
    ///         nesting depth <= 4, 1 <= threshold <= entries, no duplicate validator, at least one
    ///         validator. With `strict`, also its "extra checks": threshold >= the v-blocking size
    ///         (a 51 % majority at every level), which stellar-core applies to a node's own config.
    function parseQuorumSet(bytes memory b, bool strict) internal pure returns (QuorumSet memory q) {
        bytes32[] memory seen = new bytes32[](MAX_QSET_VALIDATORS);
        uint256 count;
        uint256 end;
        (q, end, count) = _qset(b, 0, 0, seen, 0, strict);
        if (end != b.length) revert XdrTrailingBytes();
        if (count == 0) revert QuorumSetInsane();
    }

    function _qset(bytes memory b, uint256 o, uint256 depth, bytes32[] memory seen, uint256 count, bool strict)
        private
        pure
        returns (QuorumSet memory q, uint256 end, uint256 newCount)
    {
        if (depth > MAX_QSET_DEPTH) revert QuorumSetInsane();
        q.threshold = u32(b, o);
        uint256 nv = u32(b, o + 4);
        end = o + 8;
        if (count + nv > MAX_QSET_VALIDATORS) revert QuorumSetInsane();
        q.validators = new bytes32[](nv);
        for (uint256 i = 0; i < nv; ++i) {
            bytes32 k;
            (k, end) = nodeId(b, end);
            for (uint256 j = 0; j < count; ++j) {
                if (seen[j] == k) revert QuorumSetInsane();
            }
            seen[count++] = k;
            q.validators[i] = k;
        }
        uint256 ni = u32(b, end);
        end += 4;
        if (ni > MAX_QSET_VALIDATORS) revert QuorumSetInsane();
        uint256 entries = nv + ni;
        if (q.threshold == 0 || q.threshold > entries) revert QuorumSetInsane();
        // v-blocking size = entries - threshold + 1; strict requires threshold >= it.
        if (strict && 2 * uint256(q.threshold) < entries + 1) revert QuorumSetInsane();
        q.innerSets = new QuorumSet[](ni);
        for (uint256 i = 0; i < ni; ++i) {
            (q.innerSets[i], end, count) = _qset(b, end, depth + 1, seen, count, strict);
        }
        newCount = count;
    }

    /// @notice True iff `signers` (sorted ascending, distinct) contain a slice of `q`, i.e. stellar-core's
    ///         LocalNode::isQuorumSlice: at least `threshold` of the entries are satisfied, a validator
    ///         entry being satisfied when it signed and an inner set when it is itself satisfied.
    function isSatisfied(QuorumSet memory q, bytes32[] memory signers) internal pure returns (bool) {
        uint256 have;
        uint256 need = q.threshold;
        for (uint256 i = 0; i < q.validators.length; ++i) {
            if (contains(signers, q.validators[i]) && ++have >= need) return true;
        }
        for (uint256 i = 0; i < q.innerSets.length; ++i) {
            if (isSatisfied(q.innerSets[i], signers) && ++have >= need) return true;
        }
        return false;
    }

    /// @notice True iff `k` is a validator anywhere in `q`.
    function isMember(QuorumSet memory q, bytes32 k) internal pure returns (bool) {
        for (uint256 i = 0; i < q.validators.length; ++i) {
            if (q.validators[i] == k) return true;
        }
        for (uint256 i = 0; i < q.innerSets.length; ++i) {
            if (isMember(q.innerSets[i], k)) return true;
        }
        return false;
    }

    function contains(bytes32[] memory sorted, bytes32 k) internal pure returns (bool) {
        uint256 lo;
        uint256 hi = sorted.length;
        while (lo < hi) {
            uint256 mid = (lo + hi) >> 1;
            bytes32 v = sorted[mid];
            if (v == k) return true;
            if (v < k) lo = mid + 1;
            else hi = mid;
        }
        return false;
    }

    // ── Transaction results and Soroban events ───────────────────────────────

    /// @notice Read the InvokeHostFunction success hash of the transaction result that starts at
    ///         `o` inside a TransactionResultSet (right after the 32-byte transaction hash). The
    ///         result must be txSUCCESS with exactly one opINNER / INVOKE_HOST_FUNCTION / SUCCESS
    ///         operation result, which is the shape of every successful Soroban transaction.
    ///         The same layout holds for an InnerTransactionResult inside a fee-bump pair.
    /// @return successHash sha256(InvokeHostFunctionSuccessPreImage), stellar-core
    ///         InvokeHostFunctionOpFrame::finalizeSuccess.
    function invokeSuccessHash(bytes memory rs, uint256 o) internal pure returns (bytes32 successHash) {
        // feeCharged int64 at o
        uint32 code = u32(rs, o + 8);
        if (code != TX_SUCCESS) revert XdrUnsupportedArm(code);
        if (u32(rs, o + 12) != 1) revert XdrBadLength();
        uint32 opCode = u32(rs, o + 16);
        if (opCode != OP_INNER) revert XdrUnsupportedArm(opCode);
        uint32 opType = u32(rs, o + 20);
        if (opType != INVOKE_HOST_FUNCTION) revert XdrUnsupportedArm(opType);
        uint32 r = u32(rs, o + 24);
        if (r != INVOKE_HOST_FUNCTION_SUCCESS) revert XdrUnsupportedArm(r);
        successHash = b32(rs, o + 28);
    }

    /// @notice Locate the first contract event in an InvokeHostFunctionSuccessPreImage
    ///         `{ SCVal returnValue; ContractEvent events<>; }` whose return value is SCV_VOID.
    /// @return contractId the emitting contract (set by the host, so it cannot be spoofed)
    /// @return topicsStart offset of the event's `SCVal topics<>` vector (its count word)
    /// @return eventCount number of events in the preimage
    function firstContractEvent(bytes memory p)
        internal
        pure
        returns (bytes32 contractId, uint256 topicsStart, uint256 eventCount)
    {
        uint32 rv = u32(p, 0);
        if (rv != SCV_VOID) revert XdrUnsupportedArm(rv);
        eventCount = u32(p, 4);
        if (eventCount == 0) revert XdrBadLength();
        // ContractEvent: ExtensionPoint ext (v 0), ContractID* contractID, type, body (v 0)
        uint32 ext = u32(p, 8);
        if (ext != 0) revert XdrUnsupportedArm(ext);
        if (u32(p, 12) != 1) revert XdrUnsupportedArm(0); // contractID must be present
        contractId = b32(p, 16);
        uint32 t = u32(p, 48);
        if (t != CONTRACT_EVENT) revert XdrUnsupportedArm(t);
        uint32 body = u32(p, 52);
        if (body != 0) revert XdrUnsupportedArm(body);
        topicsStart = 56;
    }
}
