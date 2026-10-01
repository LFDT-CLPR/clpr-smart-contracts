// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title XrplLib
/// @notice XRP Ledger binary formats and hashes, as rippled defines them (XRPLF/rippled @ ddbc5f1):
///         - STObject serialization (`STObject::add`): fields sorted by (type, field code); a field id
///           is 1-3 bytes; VL lengths are 1-3 bytes (`Serializer::addEncoded`); nested OBJECT/ARRAY
///           end with 0xE1/0xF1.
///         - Ledger hash: sha512Half("LWR\0" ‖ seq ‖ drops ‖ parent ‖ txHash ‖ accountHash ‖
///           parentCloseTime ‖ closeTime ‖ closeTimeResolution ‖ closeFlags) (LedgerHeader.cpp).
///         - SHAMap: inner = sha512Half("MIN\0" ‖ 16 child hashes, zero if empty); account-state leaf
///           = sha512Half("MLN\0" ‖ data ‖ key); tx+meta leaf = sha512Half("SND\0" ‖ VL(tx) ‖ VL(meta)
///           ‖ txid), with txid = sha512Half("TXN\0" ‖ tx). Branch at depth d is nibble d of the key,
///           high nibble first (`selectBranch`).
///         - Validations and manifests are signed over sha512Half(prefix ‖ object without its
///           non-signing fields) (`STObject::getSigningHash`, `Manifest::verify`).
library XrplLib {
    // HashPrefix values (HashPrefix.h): three ASCII letters and a zero byte.
    bytes4 internal constant PREFIX_LEDGER = "LWR\x00";
    bytes4 internal constant PREFIX_INNER = "MIN\x00";
    bytes4 internal constant PREFIX_STATE_LEAF = "MLN\x00";
    bytes4 internal constant PREFIX_TX_LEAF = "SND\x00";
    bytes4 internal constant PREFIX_TX_ID = "TXN\x00";
    bytes4 internal constant PREFIX_VALIDATION = "VAL\x00";
    bytes4 internal constant PREFIX_MANIFEST = "MAN\x00";

    uint256 internal constant HEADER_LENGTH = 118;
    uint32 internal constant VF_FULL_VALIDATION = 0x00000001;

    // Serialized type codes (SField.h).
    uint256 internal constant STI_UINT16 = 1;
    uint256 internal constant STI_UINT32 = 2;
    uint256 internal constant STI_UINT256 = 5;
    uint256 internal constant STI_AMOUNT = 6;
    uint256 internal constant STI_VL = 7;
    uint256 internal constant STI_ACCOUNT = 8;
    uint256 internal constant STI_OBJECT = 14;
    uint256 internal constant STI_ARRAY = 15;
    uint256 internal constant STI_VECTOR256 = 19;

    error MalformedField(uint256 offset);
    error UnsupportedFieldType(uint256 sType);
    error BadHeaderLength(uint256 length);
    error BadDerSignature();
    error MissingField(uint256 sType, uint256 field);
    error SHAMapPathTooLong();
    error SHAMapHashMismatch(uint256 depth);
    error BadPublicKey();

    // ── STObject walker ───────────────────────────────────────────────────────

    /// @notice Read the field starting at `i`. For OBJECT/ARRAY starts and ends there is no value
    ///         (`vs == ve == next`); an end marker is reported as field 1 of its type.
    function nextField(bytes memory b, uint256 i)
        internal
        pure
        returns (uint256 t, uint256 f, uint256 vs, uint256 ve, uint256 next)
    {
        uint256 n = b.length;
        if (i >= n) revert MalformedField(i);
        uint256 h = uint8(b[i++]);
        t = h >> 4;
        f = h & 15;
        if (t == 0) {
            if (i >= n) revert MalformedField(i);
            t = uint8(b[i++]);
            if (t < 16) revert MalformedField(i);
        }
        if (f == 0) {
            if (i >= n) revert MalformedField(i);
            f = uint8(b[i++]);
            if (f < 16) revert MalformedField(i);
        }
        vs = i;
        if (t == STI_OBJECT || t == STI_ARRAY) {
            return (t, f, i, i, i);
        }
        uint256 len;
        if (t == STI_VL || t == STI_ACCOUNT || t == STI_VECTOR256) {
            if (i >= n) revert MalformedField(i);
            uint256 b1 = uint8(b[i++]);
            if (b1 <= 192) {
                len = b1;
            } else if (b1 <= 240) {
                if (i >= n) revert MalformedField(i);
                len = 193 + (b1 - 193) * 256 + uint8(b[i++]);
            } else if (b1 <= 254) {
                if (i + 1 >= n) revert MalformedField(i);
                len = 12481 + (b1 - 241) * 65536 + uint256(uint8(b[i])) * 256 + uint8(b[i + 1]);
                i += 2;
            } else {
                revert MalformedField(i);
            }
            vs = i;
        } else if (t == STI_AMOUNT) {
            if (i >= n) revert MalformedField(i);
            uint256 a = uint8(b[i]);
            len = a & 0x80 != 0 ? 48 : (a & 0x20 != 0 ? 33 : 8); // IOU | MPT | XRP (STAmount::add)
        } else {
            len = _fixedLength(t);
        }
        ve = vs + len;
        if (ve > n) revert MalformedField(i);
        next = ve;
    }

    function _fixedLength(uint256 t) private pure returns (uint256) {
        if (t == 1) return 2; // UINT16
        if (t == 2) return 4; // UINT32
        if (t == 3) return 8; // UINT64
        if (t == 4) return 16; // UINT128
        if (t == 5) return 32; // UINT256
        if (t == 9) return 12; // NUMBER
        if (t == 10) return 4; // INT32
        if (t == 11) return 8; // INT64
        if (t == 16) return 1; // UINT8
        if (t == 17) return 20; // UINT160
        if (t == 20) return 12; // UINT96
        if (t == 21) return 24; // UINT192
        if (t == 22) return 48; // UINT384
        if (t == 23) return 64; // UINT512
        if (t == 26) return 20; // CURRENCY
        // PATHSET, ISSUE, XCHAIN_BRIDGE and anything newer: fail closed.
        revert UnsupportedFieldType(t);
    }

    function readU32(bytes memory b, uint256 at) internal pure returns (uint32 v) {
        assembly ("memory-safe") {
            v := shr(224, mload(add(add(b, 0x20), at)))
        }
    }

    function readB32(bytes memory b, uint256 at) internal pure returns (bytes32 v) {
        assembly ("memory-safe") {
            v := mload(add(add(b, 0x20), at))
        }
    }

    function slice(bytes memory b, uint256 from, uint256 to) internal pure returns (bytes memory out) {
        out = new bytes(to - from);
        assembly ("memory-safe") {
            mcopy(add(out, 0x20), add(add(b, 0x20), from), sub(to, from))
        }
    }

    // ── SHA-512Half ───────────────────────────────────────────────────────────

    error HasherFailed();

    /// @notice sha512Half via the {ClprSha512Hasher} contract at `hasher` (raw calldata in, 64-byte
    ///         digest out). One deployed hasher keeps the XRPL contracts small and is about twice
    ///         as fast as the via-IR library inside them.
    function half(address hasher, bytes memory data) internal view returns (bytes32 h) {
        assembly ("memory-safe") {
            let ok := staticcall(gas(), hasher, add(data, 0x20), mload(data), 0x00, 0x40)
            if iszero(and(ok, eq(returndatasize(), 0x40))) {
                mstore(0x00, 0x6da4348c) // HasherFailed()
                revert(0x1c, 0x04)
            }
            h := mload(0x00)
        }
    }

    // ── Ledger header ─────────────────────────────────────────────────────────

    struct Header {
        uint32 seq;
        bytes32 parentHash;
        bytes32 txHash;
        bytes32 accountHash;
        bytes32 hash;
    }

    function parseHeader(bytes memory h, address hasher) internal view returns (Header memory hd) {
        if (h.length != HEADER_LENGTH) revert BadHeaderLength(h.length);
        hd.seq = readU32(h, 0);
        hd.parentHash = readB32(h, 12);
        hd.txHash = readB32(h, 44);
        hd.accountHash = readB32(h, 76);
        hd.hash = half(hasher, abi.encodePacked(PREFIX_LEDGER, h));
    }

    // ── Validations ───────────────────────────────────────────────────────────

    /// @notice Check a serialized STValidation is a full validation of (ledgerHash, seq) and return
    ///         its signing digest and (r, s). The signer is checked by the caller with ecrecover.
    function validationDigest(bytes memory v, bytes32 ledgerHash, uint32 seq, address hasher)
        internal
        view
        returns (bytes32 digest, bytes32 r, bytes32 s)
    {
        uint256 i;
        uint256 sigStart;
        uint256 sigEnd;
        uint256 sigVs;
        bool hasFlags;
        bool hasHash;
        bool hasSeq;
        while (i < v.length) {
            (uint256 t, uint256 f, uint256 vs, uint256 ve, uint256 nx) = nextField(v, i);
            if (t == STI_OBJECT || t == STI_ARRAY) revert MalformedField(i); // validations are flat
            if (t == STI_UINT32 && f == 2) {
                if (readU32(v, vs) & VF_FULL_VALIDATION == 0) revert MissingField(t, f);
                hasFlags = true;
            } else if (t == STI_UINT32 && f == 6) {
                if (readU32(v, vs) != seq) revert MissingField(t, f);
                hasSeq = true;
            } else if (t == STI_UINT256 && f == 1) {
                if (readB32(v, vs) != ledgerHash) revert MissingField(t, f);
                hasHash = true;
            } else if (t == STI_VL && f == 6) {
                sigStart = i;
                sigEnd = nx;
                sigVs = vs;
                (r, s) = parseDer(v, vs, ve);
            }
            i = nx;
        }
        if (!hasFlags || !hasHash || !hasSeq || sigEnd == 0) revert MissingField(0, 0);
        // signing data = prefix ‖ fields without sfSignature (the only non-signing validation field)
        bytes memory pre = new bytes(4 + v.length - (sigEnd - sigStart));
        assembly ("memory-safe") {
            let d := add(pre, 0x20)
            mstore(d, PREFIX_VALIDATION)
            let src := add(v, 0x20)
            mcopy(add(d, 4), src, sigStart)
            mcopy(add(add(d, 4), sigStart), add(src, sigEnd), sub(mload(v), sigEnd))
        }
        digest = half(hasher, pre);
    }

    /// @notice Strict DER ECDSA (r, s) for secp256k1 as rippled emits it (`ecdsaCanonicality`):
    ///         SEQUENCE { INTEGER r, INTEGER s }, minimal encodings, 0 < r, s < n.
    function parseDer(bytes memory b, uint256 from, uint256 to) internal pure returns (bytes32 r, bytes32 s) {
        if (to - from < 8 || to - from > 72) revert BadDerSignature();
        if (uint8(b[from]) != 0x30 || uint8(b[from + 1]) != to - from - 2) revert BadDerSignature();
        uint256 p = from + 2;
        uint256 next;
        (r, next) = _derInt(b, p, to);
        (s, next) = _derInt(b, next, to);
        if (next != to) revert BadDerSignature();
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        if (r == 0 || s == 0 || uint256(r) >= n || uint256(s) >= n) revert BadDerSignature();
    }

    function _derInt(bytes memory b, uint256 p, uint256 to) private pure returns (bytes32 v, uint256 next) {
        if (p + 2 > to || uint8(b[p]) != 0x02) revert BadDerSignature();
        uint256 len = uint8(b[p + 1]);
        p += 2;
        if (len == 0 || len > 33 || p + len > to) revert BadDerSignature();
        if (uint8(b[p]) & 0x80 != 0) revert BadDerSignature(); // negative
        if (len > 1 && uint8(b[p]) == 0 && uint8(b[p + 1]) & 0x80 == 0) revert BadDerSignature(); // non-minimal
        if (len == 33) {
            p += 1;
            len = 32;
        }
        uint256 x;
        for (uint256 k = 0; k < len; ++k) {
            x = (x << 8) | uint8(b[p + k]);
        }
        return (bytes32(x), p + len);
    }

    /// @notice True iff (r, s) over `digest` was made by `signer` (either recovery id).
    function signedBy(bytes32 digest, bytes32 r, bytes32 s, address signer) internal pure returns (bool) {
        if (signer == address(0)) return false;
        return ecrecover(digest, 27, r, s) == signer || ecrecover(digest, 28, r, s) == signer;
    }

    // ── secp256k1 keys ────────────────────────────────────────────────────────

    /// @notice Ethereum-style address of a 33-byte compressed secp256k1 public key.
    function secpAddress(bytes memory pk) internal view returns (address) {
        if (pk.length != 33) revert BadPublicKey();
        uint8 pre = uint8(pk[0]);
        if (pre != 2 && pre != 3) revert BadPublicKey();
        uint256 x = uint256(readB32(pk, 1));
        uint256 P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
        if (x >= P) revert BadPublicKey();
        uint256 rhs = addmod(mulmod(mulmod(x, x, P), x, P), 7, P);
        uint256 y = _modexp(rhs, (P + 1) / 4, P);
        if (mulmod(y, y, P) != rhs) revert BadPublicKey();
        if (y & 1 != pre & 1) y = P - y;
        return address(uint160(uint256(keccak256(abi.encodePacked(x, y)))));
    }

    function _modexp(uint256 b, uint256 e, uint256 m) private view returns (uint256 r) {
        bool ok;
        assembly ("memory-safe") {
            let p := mload(0x40)
            mstore(p, 0x20)
            mstore(add(p, 0x20), 0x20)
            mstore(add(p, 0x40), 0x20)
            mstore(add(p, 0x60), b)
            mstore(add(p, 0x80), e)
            mstore(add(p, 0xa0), m)
            ok := staticcall(gas(), 0x05, p, 0xc0, p, 0x20)
            r := mload(p)
        }
        if (!ok) revert BadPublicKey();
    }

    // ── SHAMap ────────────────────────────────────────────────────────────────

    /// @notice Walk `inners` (each the 16 child hashes of one inner node, root first) from `root`
    ///         along `key` and require the reached child to be `leafHash`. The key is bound by the
    ///         leaf hash itself (both leaf kinds hash their key), so a leaf at any depth is sound.
    function verifyPath(bytes32 root, bytes32 key, bytes[] memory inners, bytes32 leafHash, address hasher)
        internal
        view
    {
        uint256 depth = inners.length;
        if (depth == 0 || depth > 64) revert SHAMapPathTooLong();
        bytes32 expect = root;
        for (uint256 d = 0; d < depth; ++d) {
            expect = _innerStep(inners[d], expect, key, d, hasher);
        }
        if (expect != leafHash) revert SHAMapHashMismatch(depth);
    }

    /// @dev Check one inner node against its expected hash and return the child on `key`'s path.
    function _innerStep(bytes memory node, bytes32 expect, bytes32 key, uint256 d, address hasher)
        private
        view
        returns (bytes32)
    {
        if (node.length != 512) revert SHAMapHashMismatch(d);
        if (half(hasher, abi.encodePacked(PREFIX_INNER, node)) != expect) revert SHAMapHashMismatch(d);
        return readB32(node, ((uint256(key) >> (252 - 4 * d)) & 15) * 32);
    }

    /// @notice Hash of ledger `seq` from a serialized LedgerHashes entry (sfLastLedgerSequence =
    ///         the newest listed ledger, sfHashes = consecutive ledger hashes ending at it).
    function skipListHash(bytes memory entry, uint32 seq) internal pure returns (bytes32) {
        (uint256 last, uint256 hs, uint256 n) = _skipFields(entry);
        if (n == 0 || seq > last || last - seq >= n) revert MissingField(STI_VECTOR256, 2);
        return readB32(entry, hs + 32 * (n - 1 - (last - seq)));
    }

    function _skipFields(bytes memory entry) private pure returns (uint256 last, uint256 hs, uint256 n) {
        uint256 i;
        bool hasLast;
        while (i < entry.length) {
            (uint256 t, uint256 f, uint256 vs, uint256 ve, uint256 nx) = nextField(entry, i);
            if (t == STI_UINT16 && f == 1 && (uint8(entry[vs]) != 0 || uint8(entry[vs + 1]) != 0x68)) {
                revert MalformedField(i); // ltLEDGER_HASHES
            }
            if (t == STI_UINT32 && f == 27) (last, hasLast) = (readU32(entry, vs), true);
            if (t == STI_VECTOR256 && f == 2) (hs, n) = (vs, (ve - vs) / 32);
            i = nx;
        }
        if (!hasLast) revert MissingField(STI_UINT32, 27);
    }

    function txId(bytes memory tx, address hasher) internal view returns (bytes32) {
        return half(hasher, abi.encodePacked(PREFIX_TX_ID, tx));
    }

    function txLeafHash(bytes memory tx, bytes memory meta, bytes32 id, address hasher)
        internal
        view
        returns (bytes32)
    {
        return half(hasher, abi.encodePacked(PREFIX_TX_LEAF, encodeVL(tx.length), tx, encodeVL(meta.length), meta, id));
    }

    function stateLeafHash(bytes memory data, bytes32 key, address hasher) internal view returns (bytes32) {
        return half(hasher, abi.encodePacked(PREFIX_STATE_LEAF, data, key));
    }

    function encodeVL(uint256 n) internal pure returns (bytes memory) {
        if (n <= 192) return abi.encodePacked(uint8(n));
        if (n <= 12480) {
            n -= 193;
            return abi.encodePacked(uint8(193 + (n >> 8)), uint8(n));
        }
        n -= 12481;
        return abi.encodePacked(uint8(241 + (n >> 16)), uint8(n >> 8), uint8(n));
    }

    // ── Transactions ──────────────────────────────────────────────────────────

    struct Tx {
        uint16 txType;
        bytes20 account;
        uint32 sequence;
        bool ticketed;
        bytes memo; // MemoData of the first Memo whose MemoType equals the requested type
        bool hasMemo;
    }

    /// @notice Top-level fields of a serialized transaction, plus the first memo of `memoType`.
    ///         Nested objects (Memos, Signers) are entered only to find the memo; a top-level
    ///         sfAccount is never confused with a Signer's.
    struct TxWalk {
        uint256 i;
        uint256 depth;
        bool inMemos;
        bool typeMatch;
        bool hasData;
        bool hasAccount;
        bool hasType;
        uint256 dataVs;
        uint256 dataVe;
        bytes32 wantType;
    }

    function parseTx(bytes memory tx, bytes memory memoType) internal pure returns (Tx memory out) {
        TxWalk memory w;
        w.wantType = keccak256(memoType);
        while (w.i < tx.length) {
            (uint256 t, uint256 f, uint256 vs, uint256 ve, uint256 nx) = nextField(tx, w.i);
            if (t == STI_OBJECT || t == STI_ARRAY) {
                _txContainer(w, out, tx, t, f);
            } else if (w.depth == 0) {
                _txTopField(w, out, tx, t, f, vs, ve);
            } else if (w.inMemos && w.depth == 2 && t == STI_VL) {
                if (f == 12) {
                    w.typeMatch = keccak256(slice(tx, vs, ve)) == w.wantType; // sfMemoType
                } else if (f == 13) {
                    (w.dataVs, w.dataVe, w.hasData) = (vs, ve, true); // sfMemoData
                }
            }
            w.i = nx;
        }
        if (w.depth != 0 || !w.hasAccount || !w.hasType) revert MalformedField(tx.length);
    }

    function _txContainer(TxWalk memory w, Tx memory out, bytes memory tx, uint256 t, uint256 f) private pure {
        if (f == 1) {
            if (w.depth == 0) revert MalformedField(w.i);
            --w.depth;
            if (w.depth == 1 && w.inMemos && t == STI_OBJECT) {
                // end of one Memo object
                if (w.typeMatch && w.hasData && !out.hasMemo) {
                    out.memo = slice(tx, w.dataVs, w.dataVe);
                    out.hasMemo = true;
                }
                w.typeMatch = false;
                w.hasData = false;
            }
            if (w.depth == 0) w.inMemos = false;
        } else {
            if (w.depth == 0 && t == STI_ARRAY && f == 9) w.inMemos = true; // sfMemos
            ++w.depth;
        }
    }

    function _txTopField(TxWalk memory w, Tx memory out, bytes memory tx, uint256 t, uint256 f, uint256 vs, uint256 ve)
        private
        pure
    {
        if (t == STI_UINT16 && f == 2) {
            out.txType = uint16(uint8(tx[vs])) << 8 | uint8(tx[vs + 1]);
            w.hasType = true;
        } else if (t == STI_UINT32 && f == 4) {
            out.sequence = readU32(tx, vs);
        } else if (t == STI_UINT32 && f == 41) {
            out.ticketed = true; // sfTicketSequence
        } else if (t == STI_ACCOUNT && f == 1) {
            if (ve - vs != 20) revert MalformedField(w.i);
            out.account = bytes20(readB32(tx, vs));
            w.hasAccount = true;
        }
    }

    /// @notice tesSUCCESS check. sfTransactionResult (UINT8, field 3; id bytes 0x03 0x10) has the
    ///         highest (type, field) of the metadata template (TxMeta.cpp: TransactionIndex,
    ///         ParentBatchID, DeliveredAmount, AffectedNodes, TransactionResult), and STObject::add
    ///         sorts fields, so it is always the last three bytes of the serialized metadata.
    function metaSucceeded(bytes memory meta) internal pure returns (bool) {
        uint256 n = meta.length;
        return n >= 3 && uint8(meta[n - 3]) == 0x03 && uint8(meta[n - 2]) == 0x10 && uint8(meta[n - 1]) == 0x00;
    }

    // ── Manifests ─────────────────────────────────────────────────────────────

    struct Manifest {
        bytes master; // 33 bytes: 0xED ‖ ed25519 key, or compressed secp256k1
        bytes signingKey;
        uint32 sequence;
        bytes masterSignature;
        bytes signature;
        bytes signingData; // "MAN\0" ‖ fields without sfSignature / sfMasterSignature
    }

    function parseManifest(bytes memory m) internal pure returns (Manifest memory out) {
        uint256 i;
        bytes memory keep = new bytes(m.length + 4);
        uint256 kl = 4;
        assembly ("memory-safe") {
            mstore(add(keep, 0x20), PREFIX_MANIFEST)
        }
        bool hasSeq;
        while (i < m.length) {
            (uint256 t, uint256 f, uint256 vs, uint256 ve, uint256 nx) = nextField(m, i);
            if (t == STI_OBJECT || t == STI_ARRAY) revert MalformedField(i);
            bool signingField = true;
            if (t == STI_VL && f == 1) {
                out.master = slice(m, vs, ve);
            } else if (t == STI_VL && f == 3) {
                out.signingKey = slice(m, vs, ve);
            } else if (t == STI_UINT32 && f == 4) {
                out.sequence = readU32(m, vs);
                hasSeq = true;
            } else if (t == STI_VL && f == 18) {
                out.masterSignature = slice(m, vs, ve);
                signingField = false;
            } else if (t == STI_VL && f == 6) {
                out.signature = slice(m, vs, ve);
                signingField = false;
            } else if (t == STI_UINT16 && f == 16) {
                if (uint8(m[vs]) != 0 || uint8(m[vs + 1]) != 0) revert MalformedField(i); // version 0 only
            }
            if (signingField) {
                assembly ("memory-safe") {
                    mcopy(add(add(keep, 0x20), kl), add(add(m, 0x20), i), sub(nx, i))
                }
                kl += nx - i;
            }
            i = nx;
        }
        if (out.master.length != 33 || !hasSeq || out.masterSignature.length == 0) revert MissingField(0, 0);
        assembly ("memory-safe") {
            mstore(keep, kl)
        }
        out.signingData = keep;
    }
}
