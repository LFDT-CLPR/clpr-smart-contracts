// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";

/// @title TronLib
/// @notice Parsing and hashing primitives for TRON (java-tron) block headers and transactions.
/// @dev Every rule here mirrors java-tron (develop @ b33eed8, Sep 2026):
///      - `BlockHeader.raw` (core/Tron.proto): timestamp=1, txTrieRoot=2, parentHash=3, number=7,
///        witness_id=8, witness_address=9, version=10, accountStateRoot=11.
///      - Block hash  = SHA-256(raw bytes)                         (BlockCapsule.getRawHash)
///      - Block id    = uint64 BE number || hash[8..32]             (BlockCapsule.BlockId)
///      - Signature   = secp256k1 over the block hash, 65 bytes r||s||v with v in {0,1}
///                      (BlockCapsule.sign / validateSignature).
///      - txTrieRoot  = binary SHA-256 tree over SHA-256(Transaction bytes); an odd node is
///                      promoted unchanged; an empty block has the all-zero root
///                      (BlockCapsule.calcMerkleRoot, capsule/utils/MerkleTree.java).
///      The parsers are fail-closed: an unknown or duplicated header field reverts, so any future
///      header extension is reviewed before the verifier accepts it.
library TronLib {
    /// @dev 21-byte TRON addresses carry this prefix byte before the 20-byte account id.
    uint8 internal constant ADDRESS_PREFIX = 0x41;

    /// @dev `Transaction.Contract.ContractType` values used by the verifier.
    uint64 internal constant TRIGGER_SMART_CONTRACT = 31;
    uint64 internal constant ACCOUNT_PERMISSION_UPDATE_CONTRACT = 46;

    /// @dev `Transaction.Result.contractResult.SUCCESS`.
    uint64 internal constant CONTRACT_RESULT_SUCCESS = 1;

    /// @dev `Permission.PermissionType.Witness`.
    uint64 internal constant PERMISSION_TYPE_WITNESS = 1;

    error TronHeaderUnknownField(uint64 field);
    error TronHeaderDuplicateField(uint64 field);
    error TronHeaderBadField(uint64 field);
    error TronBadAddress();
    error TronBadWireType();
    error TronTxMalformed();
    error TronTxContractCount(uint256 count);
    error TronTxTypeUrlMismatch();
    error TronMerkleBadIndex();
    error TronMerkleBadProofLength();
    error TronTxLength64();
    error TronWitnessPermissionMalformed();

    /// @notice Parsed `BlockHeader.raw`.
    struct Header {
        uint64 number;
        uint64 timestamp;
        bytes32 parentHash;
        bytes32 txTrieRoot;
        address witness;
        /// @dev SHA-256 of the raw bytes: the signed digest.
        bytes32 rawHash;
    }

    // ── Header ────────────────────────────────────────────────────────────────

    /// @notice Parse a `BlockHeader.raw` protobuf and compute its SHA-256.
    function parseHeader(bytes memory raw) internal pure returns (Header memory h) {
        h.rawHash = sha256(raw);
        uint256 seen; // bitmap of field numbers already seen
        uint256 off;
        while (off < raw.length) {
            (uint64 field, uint8 wt, uint256 next) = PB.decodeFieldKey(raw, off);
            if (field > 255) revert TronHeaderUnknownField(field);
            // forge-lint: disable-next-line(incorrect-shift)
            uint256 bit = 1 << field; // bit `field` of the seen-bitmap; field <= 255
            if (seen & bit != 0) revert TronHeaderDuplicateField(field);
            seen |= bit;
            if (field == 1 || field == 7 || field == 8 || field == 10) {
                if (wt != 0) revert TronHeaderBadField(field);
                uint64 v;
                (v, off) = PB.decodeVarint(raw, next);
                if (field == 1) h.timestamp = v;
                else if (field == 7) h.number = v;
                // witness_id (8) and version (10) are not used by the verifier.
            } else if (field == 2 || field == 3 || field == 9 || field == 11) {
                if (wt != 2) revert TronHeaderBadField(field);
                (uint256 start, uint256 len, uint256 end) = _lenField(raw, next);
                if (field == 2 || field == 3) {
                    if (len != 32) revert TronHeaderBadField(field);
                    bytes32 v = _load32(raw, start);
                    if (field == 2) h.txTrieRoot = v;
                    else h.parentHash = v;
                } else if (field == 9) {
                    h.witness = _tronAddressAt(raw, start, len);
                }
                // accountStateRoot (11): never populated on mainnet/Nile (ALLOW_ACCOUNT_STATE_ROOT=0)
                // and, even when enabled, it commits only to AccountStore, never to contract storage.
                off = end;
            } else {
                revert TronHeaderUnknownField(field);
            }
        }
        // number (7), timestamp (1) and witness_address (9) are mandatory for a produced block.
        if (seen & (1 << 1) == 0 || seen & (1 << 7) == 0 || seen & (1 << 9) == 0) revert TronHeaderBadField(0);
    }

    /// @notice java-tron BlockId: 8-byte big-endian block number followed by hash[8..32].
    function blockId(Header memory h) internal pure returns (bytes32) {
        return bytes32((uint256(h.number) << 192) | (uint256(h.rawHash) & ((1 << 192) - 1)));
    }

    /// @notice Recover the ECDSA signer of a block hash. Returns address(0) for an empty or invalid
    ///         signature (a block signed with FN-DSA-512 per TIP-899 carries no ECDSA signature).
    function recoverSigner(bytes32 digest, bytes memory sig) internal pure returns (address signer) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        signer = ecrecover(digest, v, r, s);
    }

    // ── Transaction Merkle tree ─────────────────────────────────────────────────

    /// @notice Root of java-tron's transaction tree for a leaf at `index` among `count` leaves.
    /// @dev `siblings` lists the sibling hashes bottom-up; levels where the node is the promoted odd
    ///      last node consume no sibling. All siblings must be consumed.
    function txMerkleRoot(bytes32 leaf, uint256 index, uint256 count, bytes32[] memory siblings)
        internal
        pure
        returns (bytes32 node)
    {
        if (count == 0 || index >= count) revert TronMerkleBadIndex();
        node = leaf;
        uint256 k;
        while (count > 1) {
            if (!(index == count - 1 && count % 2 == 1)) {
                if (k >= siblings.length) revert TronMerkleBadProofLength();
                bytes32 sib = siblings[k++];
                node = index % 2 == 0 ? sha256(abi.encodePacked(node, sib)) : sha256(abi.encodePacked(sib, node));
            }
            index >>= 1;
            count = (count + 1) >> 1;
        }
        if (k != siblings.length) revert TronMerkleBadProofLength();
    }

    /// @notice Merkle leaf of a full `Transaction` encoding.
    /// @dev Leaves and inner nodes are both plain SHA-256 (no domain separation in java-tron), so a
    ///      64-byte "transaction" could be an inner node's preimage. Real transactions are never
    ///      64 bytes (raw_data alone carries ref-block, expiry and a typed contract), so reject it.
    function txLeaf(bytes memory txBytes) internal pure returns (bytes32) {
        if (txBytes.length == 64) revert TronTxLength64();
        return sha256(txBytes);
    }

    // ── Transaction ──────────────────────────────────────────────────────────

    /// @notice Decode a full `Transaction` (raw_data=1, signature=2, ret=5, pq_auth_sig=6).
    /// @return contractType  `raw_data.contract[0].type`
    /// @return parameter     `raw_data.contract[0].parameter.value` (the typed contract bytes)
    /// @return contractRet   `ret[0].contractRet` (0 when `ret` is absent)
    /// @dev Exactly one contract is required (java-tron rejects any other count). The Any type_url
    ///      must name the type that `type` declares, as java-tron's Any.unpack enforces.
    function parseTransaction(bytes memory txBytes)
        internal
        pure
        returns (uint64 contractType, bytes memory parameter, uint64 contractRet)
    {
        bytes memory raw;
        bool haveRaw;
        bool haveRet;
        uint256 off;
        while (off < txBytes.length) {
            (uint64 field, uint8 wt, uint256 next) = PB.decodeFieldKey(txBytes, off);
            if (field == 1) {
                if (wt != 2 || haveRaw) revert TronTxMalformed();
                (raw, off) = PB.decodeLengthDelimited(txBytes, next);
                haveRaw = true;
            } else if (field == 5 && !haveRet) {
                if (wt != 2) revert TronTxMalformed();
                bytes memory result;
                (result, off) = PB.decodeLengthDelimited(txBytes, next);
                contractRet = _resultContractRet(result);
                haveRet = true;
            } else {
                off = _skip(txBytes, next, wt);
            }
        }
        if (!haveRaw) revert TronTxMalformed();
        (contractType, parameter) = _rawSingleContract(raw);
    }

    /// @notice Decode `TriggerSmartContract` (owner=1, contract_address=2, call_value=3, data=4,
    ///         call_token_value=5, token_id=6).
    function parseTrigger(bytes memory p) internal pure returns (address contractAddress, bytes memory data) {
        bool haveAddr;
        bool haveData;
        uint256 off;
        while (off < p.length) {
            (uint64 field, uint8 wt, uint256 next) = PB.decodeFieldKey(p, off);
            if (field == 2) {
                if (wt != 2 || haveAddr) revert TronTxMalformed();
                (uint256 start, uint256 len, uint256 end) = _lenField(p, next);
                contractAddress = _tronAddressAt(p, start, len);
                haveAddr = true;
                off = end;
            } else if (field == 4) {
                if (wt != 2 || haveData) revert TronTxMalformed();
                (data, off) = PB.decodeLengthDelimited(p, next);
                haveData = true;
            } else {
                off = _skip(p, next, wt);
            }
        }
        if (!haveAddr) revert TronTxMalformed();
    }

    /// @notice Decode `AccountPermissionUpdateContract` (owner_address=1, owner=2, witness=3,
    ///         actives=4) and return the owner and its single witness-permission key.
    /// @dev java-tron (AccountPermissionUpdateActuator) requires a witness account to set a witness
    ///      permission with exactly one key; that key's address is the block-signing address
    ///      (AccountCapsule.getWitnessPermissionAddress).
    function parsePermissionUpdate(bytes memory p) internal pure returns (address owner, address witnessKey) {
        bytes memory witnessPerm;
        bool haveOwner;
        bool haveWitness;
        uint256 off;
        while (off < p.length) {
            (uint64 field, uint8 wt, uint256 next) = PB.decodeFieldKey(p, off);
            if (field == 1) {
                if (wt != 2 || haveOwner) revert TronTxMalformed();
                (uint256 start, uint256 len, uint256 end) = _lenField(p, next);
                owner = _tronAddressAt(p, start, len);
                haveOwner = true;
                off = end;
            } else if (field == 3) {
                if (wt != 2 || haveWitness) revert TronTxMalformed();
                (witnessPerm, off) = PB.decodeLengthDelimited(p, next);
                haveWitness = true;
            } else {
                off = _skip(p, next, wt);
            }
        }
        if (!haveOwner || !haveWitness) revert TronWitnessPermissionMalformed();
        witnessKey = _witnessPermissionKey(witnessPerm);
    }

    // ── Internals ─────────────────────────────────────────────────────────────

    /// @dev `Permission` (type=1, id=2, permission_name=3, threshold=4, parent_id=5, operations=6,
    ///      keys=7 repeated Key{address=1, weight=2}). Requires type Witness and exactly one key.
    function _witnessPermissionKey(bytes memory perm) private pure returns (address key) {
        uint64 ptype;
        uint256 keyCount;
        uint256 off;
        while (off < perm.length) {
            (uint64 field, uint8 wt, uint256 next) = PB.decodeFieldKey(perm, off);
            if (field == 1) {
                if (wt != 0) revert TronWitnessPermissionMalformed();
                (ptype, off) = PB.decodeVarint(perm, next);
            } else if (field == 7) {
                if (wt != 2) revert TronWitnessPermissionMalformed();
                bytes memory k;
                (k, off) = PB.decodeLengthDelimited(perm, next);
                key = _keyAddress(k);
                ++keyCount;
            } else {
                off = _skip(perm, next, wt);
            }
        }
        if (ptype != PERMISSION_TYPE_WITNESS || keyCount != 1) revert TronWitnessPermissionMalformed();
    }

    function _keyAddress(bytes memory k) private pure returns (address a) {
        bool have;
        uint256 off;
        while (off < k.length) {
            (uint64 field, uint8 wt, uint256 next) = PB.decodeFieldKey(k, off);
            if (field == 1) {
                if (wt != 2 || have) revert TronWitnessPermissionMalformed();
                (uint256 start, uint256 len, uint256 end) = _lenField(k, next);
                a = _tronAddressAt(k, start, len);
                have = true;
                off = end;
            } else {
                off = _skip(k, next, wt);
            }
        }
        if (!have) revert TronWitnessPermissionMalformed();
    }

    /// @dev `Transaction.Result`: contractRet is field 3 (varint).
    function _resultContractRet(bytes memory r) private pure returns (uint64 ret) {
        uint256 off;
        while (off < r.length) {
            (uint64 field, uint8 wt, uint256 next) = PB.decodeFieldKey(r, off);
            if (field == 3) {
                if (wt != 0) revert TronTxMalformed();
                (ret, off) = PB.decodeVarint(r, next);
            } else {
                off = _skip(r, next, wt);
            }
        }
    }

    /// @dev `Transaction.raw`: contract=11 (repeated, exactly one). `Contract`: type=1,
    ///      parameter=2 (google.protobuf.Any{type_url=1, value=2}).
    function _rawSingleContract(bytes memory raw) private pure returns (uint64 ctype, bytes memory value) {
        bytes memory contractMsg;
        uint256 count;
        uint256 off;
        while (off < raw.length) {
            (uint64 field, uint8 wt, uint256 next) = PB.decodeFieldKey(raw, off);
            if (field == 11) {
                if (wt != 2) revert TronTxMalformed();
                (contractMsg, off) = PB.decodeLengthDelimited(raw, next);
                ++count;
            } else {
                off = _skip(raw, next, wt);
            }
        }
        if (count != 1) revert TronTxContractCount(count);

        bytes memory any;
        bool haveType;
        bool haveParam;
        off = 0;
        while (off < contractMsg.length) {
            (uint64 field, uint8 wt, uint256 next) = PB.decodeFieldKey(contractMsg, off);
            if (field == 1) {
                if (wt != 0 || haveType) revert TronTxMalformed();
                (ctype, off) = PB.decodeVarint(contractMsg, next);
                haveType = true;
            } else if (field == 2) {
                if (wt != 2 || haveParam) revert TronTxMalformed();
                (any, off) = PB.decodeLengthDelimited(contractMsg, next);
                haveParam = true;
            } else {
                off = _skip(contractMsg, next, wt);
            }
        }
        if (!haveParam) revert TronTxMalformed();

        bytes memory typeUrl;
        bool haveUrl;
        bool haveValue;
        off = 0;
        while (off < any.length) {
            (uint64 field, uint8 wt, uint256 next) = PB.decodeFieldKey(any, off);
            if (field == 1) {
                if (wt != 2 || haveUrl) revert TronTxMalformed();
                (typeUrl, off) = PB.decodeLengthDelimited(any, next);
                haveUrl = true;
            } else if (field == 2) {
                if (wt != 2 || haveValue) revert TronTxMalformed();
                (value, off) = PB.decodeLengthDelimited(any, next);
                haveValue = true;
            } else {
                off = _skip(any, next, wt);
            }
        }
        bytes32 urlHash = keccak256(typeUrl);
        if (ctype == TRIGGER_SMART_CONTRACT) {
            if (urlHash != keccak256("type.googleapis.com/protocol.TriggerSmartContract")) {
                revert TronTxTypeUrlMismatch();
            }
        } else if (ctype == ACCOUNT_PERMISSION_UPDATE_CONTRACT) {
            if (urlHash != keccak256("type.googleapis.com/protocol.AccountPermissionUpdateContract")) {
                revert TronTxTypeUrlMismatch();
            }
        }
    }

    /// @dev Length-delimited field at `off` (positioned after the key): returns the payload start,
    ///      its length and the offset after it, without copying.
    function _lenField(bytes memory data, uint256 off) private pure returns (uint256 start, uint256 len, uint256 end) {
        uint64 l;
        (l, start) = PB.decodeVarint(data, off);
        if (l > data.length - start) revert PB.TruncatedInput();
        len = l;
        end = start + len;
    }

    function _skip(bytes memory data, uint256 off, uint8 wt) private pure returns (uint256) {
        if (wt != 0 && wt != 2) revert TronBadWireType();
        return PB.skipField(data, off, wt);
    }

    function _load32(bytes memory data, uint256 start) private pure returns (bytes32 v) {
        assembly ("memory-safe") {
            v := mload(add(add(data, 0x20), start))
        }
    }

    /// @dev A 21-byte TRON address (0x41 || 20-byte id) at `data[start..start+len]` → EVM address.
    function _tronAddressAt(bytes memory data, uint256 start, uint256 len) private pure returns (address a) {
        if (len != 21 || uint8(data[start]) != ADDRESS_PREFIX) revert TronBadAddress();
        bytes32 w = _load32(data, start + 1);
        // casting to 'bytes20' is safe because it keeps the 20 address bytes that follow the prefix
        // forge-lint: disable-next-line(unsafe-typecast)
        a = address(bytes20(w));
    }
}
