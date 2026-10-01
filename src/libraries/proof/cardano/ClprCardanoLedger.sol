// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprCbor} from "./ClprCbor.sol";
import {ClprBlake2} from "./ClprBlake2.sol";

/// @title ClprCardanoLedger
/// @notice Cardano (Babbage/Conway) ledger encodings the verifier reads, checked against
///         cardano-ledger CDDL (`babbage.cddl`, `conway.cddl`) and a live preprod block:
///
///   block        = [header, transaction_bodies, transaction_witness_sets, auxiliary_data_set,
///                   invalid_transactions]               (the relay wraps it as [era, block])
///   header       = [header_body, body_signature]; block hash = Blake2b-256(header)
///   header_body  = [block_number, slot, prev_hash, issuer_vkey, vrf_vkey, vrf_result,
///                   block_body_size, block_body_hash, operational_cert, protocol_version]
///   block_body_hash = Blake2b-256(H(transaction_bodies) ‖ H(witness_sets) ‖ H(auxiliary_data_set)
///                                 ‖ H(invalid_transactions)), H = Blake2b-256 of the exact CBOR
///                   (Alonzo `hashTxSeq`; unchanged in Babbage and Conway)
///   transaction id = Blake2b-256(transaction_body CBOR as it appears in the block)
///   transaction_output (post-Alonzo map) = {0: address, 1: value, ? 2: datum_option, ? 3: script_ref}
///   value        = coin / [coin, {policy_id => {asset_name => uint}}]
///   datum_option = [0, hash32] / [1, #6.24(bytes .cbor plutus_data)]
///   address      = header byte (type ‖ network) ‖ payment credential (28) ‖ …; payment is a script
///                  for types 1, 3, 5, 7
library ClprCardanoLedger {
    using ClprCbor for bytes;

    error HeaderMalformed();
    error HeaderMismatch();
    error BlockBodyHashMismatch();
    error TransactionInvalid(uint256 index);
    error TransactionNotInBlock();
    error OutputMalformed();
    error OutputIndexOutOfRange();
    error NotScriptAddress();
    error ScriptCredentialMismatch();
    error ThreadTokenMissing();
    error NoInlineDatum();

    struct Header {
        uint64 blockNumber;
        uint64 slot;
        bytes32 bodyHash;
    }

    /// @notice Block number, slot and body hash from a header (`[header_body, body_signature]`).
    function parseHeader(bytes memory h) internal pure returns (Header memory r) {
        (uint256 n, uint256 off) = h.readArray(0);
        if (n != 2) revert HeaderMalformed();
        (uint256 nb, uint256 p) = h.readArray(off);
        if (nb != 10) revert HeaderMalformed();
        uint256 v;
        (v, p) = h.readUint(p);
        r.blockNumber = uint64(v);
        (v, p) = h.readUint(p);
        r.slot = uint64(v);
        for (uint256 i = 2; i < 7; i++) {
            p = h.skip(p);
        }
        (uint256 s, uint256 len,) = h.readBytesRef(p);
        if (len != 32) revert HeaderMalformed();
        r.bodyHash = h.word(s);
        if (h.skip(0) != h.length) revert HeaderMalformed();
    }

    /// @notice Check that the transaction with body `txBody` is phase-2 VALID in the block whose
    ///         header commits to `bodyHash`.
    /// @param bodies   either the 32-byte hash of `transaction_bodies` (allowed only when
    ///                 `invalidTxs` is the empty array 0x80) or the full `transaction_bodies` CBOR
    /// @param txIndex  position of the transaction in the block (used only with full bodies)
    /// @dev With an empty `invalid_transactions` every transaction of the block is valid, so the block
    ///      membership Mithril certifies suffices. Otherwise the body array is opened to locate the
    ///      transaction and its index must not be listed.
    function checkValidInBlock(
        bytes32 bodyHash,
        bytes memory bodies,
        bytes32 witsHash,
        bytes32 auxHash,
        bytes memory invalidTxs,
        bytes memory txBody,
        uint256 txIndex
    ) internal view {
        bytes32 bodiesHash;
        bool emptyInvalid = invalidTxs.length == 1 && uint8(invalidTxs[0]) == 0x80;
        if (emptyInvalid && bodies.length == 32) {
            bodiesHash = bytes32(bodies);
        } else {
            bodiesHash = ClprBlake2.b2b256(bodies);
            // locate the transaction body at txIndex
            (uint256 cnt, uint256 p) = bodies.readArray(0);
            if (cnt == ClprCbor.INDEFINITE || txIndex >= cnt) revert TransactionNotInBlock();
            for (uint256 i = 0; i < txIndex; i++) {
                p = bodies.skip(p);
            }
            uint256 e = bodies.skip(p);
            if (e - p != txBody.length || keccak256(bodies.slice(p, e - p)) != keccak256(txBody)) {
                revert TransactionNotInBlock();
            }
            if (bodies.skip(0) != bodies.length) revert TransactionNotInBlock();
            // txIndex must not be listed as invalid
            (uint256 ni, uint256 q) = invalidTxs.readArray(0);
            if (ni == ClprCbor.INDEFINITE) revert TransactionNotInBlock();
            for (uint256 i = 0; i < ni; i++) {
                uint256 ix;
                (ix, q) = invalidTxs.readUint(q);
                if (ix == txIndex) revert TransactionInvalid(txIndex);
            }
            if (q != invalidTxs.length) revert TransactionNotInBlock();
        }
        bytes32 computed =
            ClprBlake2.b2b256(abi.encodePacked(bodiesHash, witsHash, auxHash, ClprBlake2.b2b256(invalidTxs)));
        if (computed != bodyHash) revert BlockBodyHashMismatch();
    }

    /// @notice Raw CBOR of output `index` of a transaction body (key 1 of the body map).
    function outputAt(bytes memory txBody, uint256 index) internal pure returns (uint256 start, uint256 end) {
        (uint256 n, uint256 p) = txBody.readMap(0);
        if (n == ClprCbor.INDEFINITE) revert OutputMalformed();
        for (uint256 i = 0; i < n; i++) {
            uint256 key;
            (key, p) = txBody.readUint(p);
            if (key == 1) {
                (uint256 cnt, uint256 q) = txBody.readArray(p);
                if (cnt == ClprCbor.INDEFINITE) revert OutputMalformed();
                if (index >= cnt) revert OutputIndexOutOfRange();
                for (uint256 j = 0; j < index; j++) {
                    q = txBody.skip(q);
                }
                return (q, txBody.skip(q));
            }
            p = txBody.skip(p);
        }
        revert OutputMalformed();
    }

    /// @notice From a post-Alonzo map-form output: require its payment credential to be script
    ///         `scriptHash`, that it holds exactly one `scriptHash`.`assetName` token, and return the
    ///         inline datum's Plutus-data bytes.
    function scriptOutputDatum(bytes memory txBody, uint256 start, bytes28 scriptHash, bytes memory assetName)
        internal
        pure
        returns (bytes memory datum)
    {
        (uint256 n, uint256 p) = txBody.readMap(start);
        if (n == ClprCbor.INDEFINITE) revert OutputMalformed();
        bool addrOk;
        bool tokenOk;
        for (uint256 i = 0; i < n; i++) {
            uint256 key;
            (key, p) = txBody.readUint(p);
            if (key == 0) {
                (uint256 s, uint256 len, uint256 nx) = txBody.readBytesRef(p);
                if (len < 29) revert NotScriptAddress();
                uint8 kind = uint8(txBody[s]) >> 4;
                if (kind != 1 && kind != 3 && kind != 5 && kind != 7) revert NotScriptAddress();
                if (bytes28(txBody.word(s + 1)) != scriptHash) revert ScriptCredentialMismatch();
                addrOk = true;
                p = nx;
            } else if (key == 1) {
                tokenOk = _holdsToken(txBody, p, scriptHash, assetName);
                p = txBody.skip(p);
            } else if (key == 2) {
                (uint256 cnt, uint256 q) = txBody.readArray(p);
                if (cnt != 2) revert NoInlineDatum();
                uint256 tag;
                (tag, q) = txBody.readUint(q);
                if (tag != 1) revert NoInlineDatum();
                (uint8 major, uint256 tg, uint256 q2) = txBody.head(q);
                if (major != ClprCbor.MAJOR_TAG || tg != 24) revert NoInlineDatum();
                (datum, p) = txBody.readBytes(q2);
            } else {
                p = txBody.skip(p);
            }
        }
        if (!addrOk) revert NotScriptAddress();
        if (!tokenOk) revert ThreadTokenMissing();
        if (datum.length == 0) revert NoInlineDatum();
    }

    function _holdsToken(bytes memory b, uint256 p, bytes28 policy, bytes memory assetName)
        private
        pure
        returns (bool)
    {
        (uint8 major,,) = b.head(p);
        if (major == ClprCbor.MAJOR_UINT) return false; // coin only
        (uint256 cnt, uint256 q) = b.readArray(p);
        if (cnt != 2) revert OutputMalformed();
        q = b.skip(q); // coin
        (uint256 np, uint256 r) = b.readMap(q);
        if (np == ClprCbor.INDEFINITE) revert OutputMalformed();
        for (uint256 i = 0; i < np; i++) {
            (uint256 ps, uint256 plen, uint256 r2) = b.readBytesRef(r);
            bool match_ = plen == 28 && bytes28(b.word(ps)) == policy;
            (uint256 na, uint256 r3) = b.readMap(r2);
            if (na == ClprCbor.INDEFINITE) revert OutputMalformed();
            for (uint256 j = 0; j < na; j++) {
                (uint256 as_, uint256 alen, uint256 r4) = b.readBytesRef(r3);
                uint256 qty;
                (qty, r3) = b.readUint(r4);
                if (
                    match_ && alen == assetName.length && keccak256(b.slice(as_, alen)) == keccak256(assetName)
                        && qty == 1
                ) {
                    return true;
                }
            }
            r = r3;
        }
        return false;
    }
}
