// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {CometBftLib} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftLib.sol";
import {Ics23Lib} from "@hiero-ledger/clpr/libraries/proof/cometbft/Ics23Lib.sol";

/// @title CometBftProofCodec
/// @notice Protobuf decoders shared by the CometBFT verifier family (SeiCometBftVerifier,
///         CometBftVerifier): the relay's state proof, signed header (header + commit), ICS-23
///         CommitmentProofs and the CLPR LedgerConfiguration. Layouts are documented in
///         src/verifiers/evm/cometbft/README.md §4. All functions are internal and pure.
/// @dev Moved verbatim from SeiCometBftVerifier (behaviour unchanged); the error names match the
///      ones the verifiers declare, so revert selectors are the same as before the move.
library CometBftProofCodec {
    error InvalidProposerAddressLength();
    error OnlyExistenceProofsSupported();
    error UnsupportedProofType();
    error InvalidServiceAddressLength();
    error Load32OutOfBounds();

    /// @dev Parses SeiStateProof proto fields.
    function parseStateProof(bytes memory data)
        internal
        pure
        returns (
            bytes memory signedHeader,
            bytes memory storeKey,
            bytes memory multistoreProof,
            bytes[] memory storageProofEntries
        )
    {
        // Count storage proof entries first
        uint256 count;
        {
            uint256 cOff;
            while (cOff < data.length) {
                (uint64 fn_, uint8 wt, uint256 cOff2) = PB.decodeFieldKey(data, cOff);
                cOff = cOff2;
                if (fn_ == 4 && wt == 2) count++;
                cOff = PB.skipField(data, cOff, wt);
            }
        }
        storageProofEntries = new bytes[](count);
        uint256 idx;
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (fn_ == 1 && wt == 2) {
                (signedHeader, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 2 && wt == 2) {
                (storeKey, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 3 && wt == 2) {
                (multistoreProof, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 4 && wt == 2) {
                (storageProofEntries[idx++], off) = PB.decodeLengthDelimited(data, off);
            } else {
                off = PB.skipField(data, off, wt);
            }
        }
    }

    /// @dev Parses SeiSignedHeader proto: returns header and commit.
    function parseSignedHeader(bytes memory data)
        internal
        pure
        returns (CometBftLib.SeiHeader memory header, CometBftLib.SeiCommit memory commit)
    {
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (fn_ == 1 && wt == 2) {
                bytes memory hb;
                (hb, off) = PB.decodeLengthDelimited(data, off);
                header = parseHeader(hb);
            } else if (fn_ == 2 && wt == 2) {
                bytes memory cb;
                (cb, off) = PB.decodeLengthDelimited(data, off);
                commit = parseCommit(cb);
            } else {
                off = PB.skipField(data, off, wt);
            }
        }
    }

    /// @dev Parses SeiHeader proto.
    function parseHeader(bytes memory data) internal pure returns (CometBftLib.SeiHeader memory h) {
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            // Field numbers follow the relay/Hiero SeiHeader proto (clpr-evm-endpoint #180 /
            // clpr-hiero #165): version is split into two scalar fields (version_block=1,
            // version_app=2), and last_block_id (field 6) is the FLAT SeiBlockRef — not the
            // canonical CometBFT Header layout. The canonical layout is reconstructed only on the
            // hashing side (CometBftLib.headerHash), where the CometBFT block hash requires it.
            if (fn_ == 1 && wt == 0) {
                (h.versionBlock, off) = PB.decodeVarint(data, off);
            } else if (fn_ == 2 && wt == 0) {
                (h.versionApp, off) = PB.decodeVarint(data, off);
            } else if (fn_ == 3 && wt == 2) {
                bytes memory cb;
                (cb, off) = PB.decodeLengthDelimited(data, off);
                h.chainId = string(cb);
            } else if (fn_ == 4 && wt == 0) {
                uint64 v;
                (v, off) = PB.decodeVarint(data, off);
                // forge-lint: disable-next-line(unsafe-typecast)
                h.height = int64(v);
            } else if (fn_ == 5 && wt == 2) {
                bytes memory tb;
                (tb, off) = PB.decodeLengthDelimited(data, off);
                (h.timeSeconds, h.timeNanos) = parseTimestamp(tb);
            } else if (fn_ == 6 && wt == 2) {
                bytes memory bb;
                (bb, off) = PB.decodeLengthDelimited(data, off);
                (h.lastBlockIdHash, h.lastBlockIdPartSetTotal, h.lastBlockIdPartSetHash) = parseBlockId(bb);
            } else if (fn_ == 7 && wt == 2) {
                bytes memory v;
                (v, off) = PB.decodeLengthDelimited(data, off);
                h.lastCommitHash = load32(v, 0);
            } else if (fn_ == 8 && wt == 2) {
                bytes memory v;
                (v, off) = PB.decodeLengthDelimited(data, off);
                h.dataHash = load32(v, 0);
            } else if (fn_ == 9 && wt == 2) {
                bytes memory v;
                (v, off) = PB.decodeLengthDelimited(data, off);
                h.validatorsHash = load32(v, 0);
            } else if (fn_ == 10 && wt == 2) {
                bytes memory v;
                (v, off) = PB.decodeLengthDelimited(data, off);
                h.nextValidatorsHash = load32(v, 0);
            } else if (fn_ == 11 && wt == 2) {
                bytes memory v;
                (v, off) = PB.decodeLengthDelimited(data, off);
                h.consensusHash = load32(v, 0);
            } else if (fn_ == 12 && wt == 2) {
                bytes memory v;
                (v, off) = PB.decodeLengthDelimited(data, off);
                h.appHash = load32(v, 0);
            } else if (fn_ == 13 && wt == 2) {
                bytes memory v;
                (v, off) = PB.decodeLengthDelimited(data, off);
                h.lastResultsHash = load32(v, 0);
            } else if (fn_ == 14 && wt == 2) {
                bytes memory v;
                (v, off) = PB.decodeLengthDelimited(data, off);
                h.evidenceHash = load32(v, 0);
            } else if (fn_ == 15 && wt == 2) {
                bytes memory v;
                (v, off) = PB.decodeLengthDelimited(data, off);
                if (v.length != 20) revert InvalidProposerAddressLength();
                // forge-lint: disable-next-line(unsafe-typecast)
                h.proposerAddress = bytes20(v);
            } else {
                off = PB.skipField(data, off, wt);
            }
        }
    }

    function parseTimestamp(bytes memory data) internal pure returns (int64 seconds_, int32 nanos_) {
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (fn_ == 1 && wt == 0) {
                uint64 v;
                (v, off) = PB.decodeVarint(data, off);
                // forge-lint: disable-next-line(unsafe-typecast)
                seconds_ = int64(v);
            } else if (fn_ == 2 && wt == 0) {
                uint64 v;
                (v, off) = PB.decodeVarint(data, off);
                // forge-lint: disable-next-line(unsafe-typecast)
                nanos_ = int32(uint32(v));
            } else {
                off = PB.skipField(data, off, wt);
            }
        }
    }

    function parseBlockId(bytes memory data)
        internal
        pure
        returns (bytes32 hash_, uint32 partTotal_, bytes32 partHash_)
    {
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            // #180 SeiBlockRef is FLAT: hash=1, part_set_total=2 (varint), part_set_hash=3.
            if (fn_ == 1 && wt == 2) {
                bytes memory v;
                (v, off) = PB.decodeLengthDelimited(data, off);
                hash_ = load32(v, 0);
            } else if (fn_ == 2 && wt == 0) {
                uint64 v;
                (v, off) = PB.decodeVarint(data, off);
                // forge-lint: disable-next-line(unsafe-typecast)
                partTotal_ = uint32(v);
            } else if (fn_ == 3 && wt == 2) {
                bytes memory v;
                (v, off) = PB.decodeLengthDelimited(data, off);
                partHash_ = load32(v, 0);
            } else {
                off = PB.skipField(data, off, wt);
            }
        }
    }

    function parsePartSetHeader(bytes memory data) internal pure returns (uint32 total_, bytes32 hash_) {
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (fn_ == 1 && wt == 0) {
                uint64 v;
                (v, off) = PB.decodeVarint(data, off);
                // forge-lint: disable-next-line(unsafe-typecast)
                total_ = uint32(v);
            } else if (fn_ == 2 && wt == 2) {
                bytes memory v;
                (v, off) = PB.decodeLengthDelimited(data, off);
                hash_ = load32(v, 0);
            } else {
                off = PB.skipField(data, off, wt);
            }
        }
    }

    /// @dev Parses SeiCommit proto.
    function parseCommit(bytes memory data) internal pure returns (CometBftLib.SeiCommit memory c) {
        // Count signatures
        uint256 sigCount;
        {
            uint256 cOff;
            while (cOff < data.length) {
                (uint64 fn_, uint8 wt, uint256 cOff2) = PB.decodeFieldKey(data, cOff);
                cOff = cOff2;
                if (fn_ == 5 && wt == 2) sigCount++;
                cOff = PB.skipField(data, cOff, wt);
            }
        }
        c.signatures = new CometBftLib.CommitSig[](sigCount);
        uint256 idx;
        uint256 off;
        // #180 SeiCommit: round=1, part_set_total=2, part_set_hash=3, signers_bits=4,
        // signatures=5. (No height/block_id in the proto — the vote sign-bytes derive height from
        // the header and block_id from the proven header hash + part-set fields below.)
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (fn_ == 1 && wt == 0) {
                uint64 v;
                (v, off) = PB.decodeVarint(data, off);
                // forge-lint: disable-next-line(unsafe-typecast)
                c.round = int32(uint32(v));
            } else if (fn_ == 2 && wt == 0) {
                uint64 v;
                (v, off) = PB.decodeVarint(data, off);
                // forge-lint: disable-next-line(unsafe-typecast)
                c.partSetTotal = uint32(v);
            } else if (fn_ == 3 && wt == 2) {
                bytes memory v;
                (v, off) = PB.decodeLengthDelimited(data, off);
                c.partSetHash = load32(v, 0);
            } else if (fn_ == 4 && wt == 2) {
                (c.signersBits, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 5 && wt == 2) {
                bytes memory sb;
                (sb, off) = PB.decodeLengthDelimited(data, off);
                c.signatures[idx++] = parseCommitSig(sb);
            } else {
                off = PB.skipField(data, off, wt);
            }
        }
    }

    function parseCommitSig(bytes memory data) internal pure returns (CometBftLib.CommitSig memory sig) {
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            // #180 SeiCommitSig: timestamp=1, signature=2.
            if (fn_ == 1 && wt == 2) {
                bytes memory tb;
                (tb, off) = PB.decodeLengthDelimited(data, off);
                (sig.timestampSeconds, sig.timestampNanos) = parseTimestamp(tb);
            } else if (fn_ == 2 && wt == 2) {
                (sig.signature, off) = PB.decodeLengthDelimited(data, off);
            } else {
                off = PB.skipField(data, off, wt);
            }
        }
    }

    /// @dev Parses SeiStorageProofEntry proto.
    function parseStorageProofEntry(bytes memory data)
        internal
        pure
        returns (bytes memory key, bytes memory value, bytes memory iavlProof)
    {
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (fn_ == 1 && wt == 2) (key, off) = PB.decodeLengthDelimited(data, off);
            else if (fn_ == 2 && wt == 2) (value, off) = PB.decodeLengthDelimited(data, off);
            else if (fn_ == 3 && wt == 2) (iavlProof, off) = PB.decodeLengthDelimited(data, off);
            else off = PB.skipField(data, off, wt);
        }
    }

    /// @dev Parses ClprLedgerConfiguration proto.
    function parseLedgerConfiguration(bytes memory data)
        internal
        pure
        returns (
            string memory chainId,
            bytes20 serviceAddr,
            uint96 configNanos,
            ClprTypes.Throttles memory throttles,
            ClprTypes.Endpoint[] memory endpoints
        )
    {
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (fn_ == 1 && wt == 2) {
                bytes memory v;
                (v, off) = PB.decodeLengthDelimited(data, off);
                chainId = string(v);
            } else if (fn_ == 2 && wt == 2) {
                bytes memory v;
                (v, off) = PB.decodeLengthDelimited(data, off);
                if (v.length != 20) revert InvalidServiceAddressLength();
                // forge-lint: disable-next-line(unsafe-typecast)
                serviceAddr = bytes20(v);
            } else if (fn_ == 3 && wt == 0) {
                uint64 v;
                (v, off) = PB.decodeVarint(data, off);
                configNanos = uint96(v);
            } else if (fn_ == 4 && wt == 2) {
                bytes memory v;
                (v, off) = PB.decodeLengthDelimited(data, off);
                throttles = parseThrottles(v);
            } else {
                off = PB.skipField(data, off, wt);
            }
        }
        endpoints = new ClprTypes.Endpoint[](0);
    }

    function parseThrottles(bytes memory data) internal pure returns (ClprTypes.Throttles memory t) {
        uint256 off;
        while (off < data.length) {
            (uint64 fn_,, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            uint64 v;
            (v, off) = PB.decodeVarint(data, off);
            // forge-lint: disable-next-line(unsafe-typecast)
            if (fn_ == 1) t.maxMessagesPerBundle = uint32(v);
            else if (fn_ == 2) t.maxMessagePayloadBytes = v;
            else if (fn_ == 3) t.maxGasPerMessage = v;
            // forge-lint: disable-next-line(unsafe-typecast)
            else if (fn_ == 4) t.maxQueueDepth = uint32(v);
            else if (fn_ == 5) t.maxSyncBytes = v;
            // forge-lint: disable-next-line(unsafe-typecast)
            else if (fn_ == 6) t.maxLocalEndpoints = uint32(v);
            // forge-lint: disable-next-line(unsafe-typecast)
            else if (fn_ == 7) t.maxPeerEndpoints = uint32(v);
        }
    }

    /// @dev Parses ICS-23 CommitmentProof (existence proof only).
    function parseExistenceProof(bytes memory data) internal pure returns (Ics23Lib.ExistenceProof memory proof) {
        // CommitmentProof field 1 (LEN) = ExistenceProof
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (fn_ != 1 || wt != 2) revert OnlyExistenceProofsSupported();
            bytes memory ep;
            (ep, off) = PB.decodeLengthDelimited(data, off);
            proof = parseExistenceProofInner(ep);
        }
    }

    /// @dev Parses an ICS-23 CommitmentProof, distinguishing existence (field 1) from
    ///      non-existence (field 2). Batch/compressed proofs are unsupported.
    function parseCommitmentProof(bytes memory data)
        internal
        pure
        returns (bool isExistence, Ics23Lib.ExistenceProof memory ep, Ics23Lib.NonExistenceProof memory nep)
    {
        uint256 off;
        bool found;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (fn_ == 1 && wt == 2) {
                bytes memory b;
                (b, off) = PB.decodeLengthDelimited(data, off);
                ep = parseExistenceProofInner(b);
                isExistence = true;
                found = true;
            } else if (fn_ == 2 && wt == 2) {
                bytes memory b;
                (b, off) = PB.decodeLengthDelimited(data, off);
                nep = parseNonExistenceProof(b);
                isExistence = false;
                found = true;
            } else {
                off = PB.skipField(data, off, wt);
            }
        }
        if (!found) revert UnsupportedProofType();
    }

    function parseNonExistenceProof(bytes memory data) internal pure returns (Ics23Lib.NonExistenceProof memory nep) {
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (fn_ == 1 && wt == 2) {
                (nep.key, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 2 && wt == 2) {
                bytes memory b;
                (b, off) = PB.decodeLengthDelimited(data, off);
                nep.left = parseExistenceProofInner(b);
                nep.hasLeft = true;
            } else if (fn_ == 3 && wt == 2) {
                bytes memory b;
                (b, off) = PB.decodeLengthDelimited(data, off);
                nep.right = parseExistenceProofInner(b);
                nep.hasRight = true;
            } else {
                off = PB.skipField(data, off, wt);
            }
        }
    }

    function parseExistenceProofInner(bytes memory data) internal pure returns (Ics23Lib.ExistenceProof memory proof) {
        // Count inner ops
        uint256 pathCount;
        {
            uint256 cOff;
            while (cOff < data.length) {
                (uint64 fn_, uint8 wt, uint256 cOff2) = PB.decodeFieldKey(data, cOff);
                cOff = cOff2;
                if (fn_ == 4 && wt == 2) pathCount++;
                cOff = PB.skipField(data, cOff, wt);
            }
        }
        proof.path = new Ics23Lib.InnerOp[](pathCount);
        uint256 pathIdx;
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (fn_ == 1 && wt == 2) {
                (proof.key, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 2 && wt == 2) {
                (proof.value, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 3 && wt == 2) {
                bytes memory lb;
                (lb, off) = PB.decodeLengthDelimited(data, off);
                proof.leaf = parseLeafOp(lb);
            } else if (fn_ == 4 && wt == 2) {
                bytes memory ib;
                (ib, off) = PB.decodeLengthDelimited(data, off);
                proof.path[pathIdx++] = parseInnerOp(ib);
            } else {
                off = PB.skipField(data, off, wt);
            }
        }
    }

    function parseLeafOp(bytes memory data) internal pure returns (Ics23Lib.LeafOp memory leaf) {
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (fn_ == 1 && wt == 0) {
                uint64 v;
                (v, off) = PB.decodeVarint(data, off);
                // forge-lint: disable-next-line(unsafe-typecast)
                leaf.hashOp = uint8(v);
            } else if (fn_ == 2 && wt == 0) {
                uint64 v;
                (v, off) = PB.decodeVarint(data, off);
                // forge-lint: disable-next-line(unsafe-typecast)
                leaf.prehashKey = uint8(v);
            } else if (fn_ == 3 && wt == 0) {
                uint64 v;
                (v, off) = PB.decodeVarint(data, off);
                // forge-lint: disable-next-line(unsafe-typecast)
                leaf.prehashValue = uint8(v);
            } else if (fn_ == 4 && wt == 0) {
                uint64 v;
                (v, off) = PB.decodeVarint(data, off);
                // forge-lint: disable-next-line(unsafe-typecast)
                leaf.lengthOp = uint8(v);
            } else if (fn_ == 5 && wt == 2) {
                (leaf.prefix, off) = PB.decodeLengthDelimited(data, off);
            } else {
                off = PB.skipField(data, off, wt);
            }
        }
    }

    function parseInnerOp(bytes memory data) internal pure returns (Ics23Lib.InnerOp memory op) {
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (fn_ == 1 && wt == 0) {
                uint64 v;
                (v, off) = PB.decodeVarint(data, off);
                // forge-lint: disable-next-line(unsafe-typecast)
                op.hashOp = uint8(v);
            } else if (fn_ == 2 && wt == 2) {
                (op.prefix, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 3 && wt == 2) {
                (op.suffix, off) = PB.decodeLengthDelimited(data, off);
            } else {
                off = PB.skipField(data, off, wt);
            }
        }
    }

    function load32(bytes memory data, uint256 offset) internal pure returns (bytes32 result) {
        if (data.length < offset + 32) revert Load32OutOfBounds();
        assembly {
            result := mload(add(add(data, 32), offset))
        }
    }
}
