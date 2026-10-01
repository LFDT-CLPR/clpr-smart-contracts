// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Blake2b} from "@hiero-ledger/clpr/libraries/proof/substrate/Blake2b.sol";
import {ScaleCodec} from "@hiero-ledger/clpr/libraries/proof/substrate/ScaleCodec.sol";

/// @title SubstrateHeader
/// @notice Decodes a SCALE-encoded Substrate block header (`sp_runtime::generic::Header` with a
///         `u32` block number and `BlakeTwo256`) and the GRANDPA authority-set signal in its digest.
///
///         Header = parent_hash(32) ‖ Compact<u32> number ‖ state_root(32) ‖ extrinsics_root(32) ‖
///                  digest: Vec<DigestItem>
///         Block hash = blake2_256(SCALE(header)) (the header as imported, seal included).
///
///         DigestItem (sp_runtime::generic::digest): 0 Other(Vec<u8>) · 4 Consensus(engine[4], Vec<u8>)
///         · 5 Seal(engine[4], Vec<u8>) · 6 PreRuntime(engine[4], Vec<u8>) · 8 RuntimeEnvironmentUpdated.
///         GRANDPA signals use Consensus(*b"FRNK", ConsensusLog) where ConsensusLog (sp_consensus_grandpa)
///         is 1 ScheduledChange{next_authorities: Vec<(AuthorityId[32], u64)>, delay: N} ·
///         2 ForcedChange(N, ScheduledChange) · 3 OnDisabled · 4 Pause · 5 Resume.
library SubstrateHeader {
    bytes4 internal constant GRANDPA_ENGINE_ID = "FRNK";
    uint256 internal constant AUTHORITY_ENTRY_LENGTH = 40; // ed25519 key(32) ‖ weight(u64 LE)

    struct Header {
        bytes32 parentHash;
        uint32 number;
        bytes32 stateRoot;
        bytes32 extrinsicsRoot;
        /// @dev Offset of the digest (its compact item count) inside the encoded header.
        uint256 digestOffset;
    }

    /// @dev A GRANDPA `ScheduledChange` found in a header digest.
    struct GrandpaChange {
        bool present;
        /// @dev Offset and byte length of the packed `(key ‖ weight)` list inside the header.
        uint256 authoritiesOffset;
        uint256 authoritiesLength;
        uint32 delay;
    }

    error InvalidHeader();
    error InvalidDigestItem();
    error InvalidGrandpaLog();
    error BlockNumberTooLarge();
    /// @dev A GRANDPA `ForcedChange` is only applied by governance/emergency recovery; a light client
    ///      cannot follow it from finality proofs, so the channel must be re-bootstrapped.
    error ForcedChangeUnsupported();

    /// @notice blake2_256 of the encoded header, i.e. the block hash.
    function hash(bytes memory header) internal view returns (bytes32) {
        return Blake2b.hash256(header);
    }

    /// @notice Decodes the fixed fields and walks the digest to check the whole header is well formed.
    function decode(bytes memory h) internal pure returns (Header memory r) {
        r.parentHash = ScaleCodec.readBytes32(h, 0);
        (uint256 number, uint256 off) = ScaleCodec.readCompact(h, 32);
        if (number > type(uint32).max) revert BlockNumberTooLarge();
        // forge-lint: disable-next-line(unsafe-typecast)
        r.number = uint32(number);
        r.stateRoot = ScaleCodec.readBytes32(h, off);
        r.extrinsicsRoot = ScaleCodec.readBytes32(h, off + 32);
        r.digestOffset = off + 64;
        if (_skipDigest(h, r.digestOffset) != h.length) revert InvalidHeader();
    }

    /// @notice Scans the digest of a decoded header for a GRANDPA authority-set signal. Returns the
    ///         first `ScheduledChange` (the one GRANDPA respects); reverts on any `ForcedChange`.
    function grandpaChange(bytes memory h, Header memory hd) internal pure returns (GrandpaChange memory c) {
        (uint256 count, uint256 off) = ScaleCodec.readCompact(h, hd.digestOffset);
        for (uint256 i; i < count; ++i) {
            uint8 kind = uint8(h[off]);
            if (kind == 4) {
                bytes4 engine = bytes4(ScaleCodec.readFixed(h, off + 1, 4));
                (uint256 len, uint256 dataOff) = ScaleCodec.readCompact(h, off + 5);
                if (engine == GRANDPA_ENGINE_ID && len > 0) {
                    uint8 logKind = uint8(h[dataOff]);
                    if (logKind == 2) revert ForcedChangeUnsupported();
                    if (logKind == 1 && !c.present) c = _decodeScheduledChange(h, dataOff + 1, dataOff + len);
                }
                off = dataOff + len;
            } else {
                off = _skipItem(h, off);
            }
        }
    }

    function _decodeScheduledChange(bytes memory h, uint256 off, uint256 end)
        private
        pure
        returns (GrandpaChange memory c)
    {
        (uint256 n, uint256 listOff) = ScaleCodec.readCompact(h, off);
        uint256 listLen = n * AUTHORITY_ENTRY_LENGTH;
        if (n == 0 || listOff + listLen + 4 != end) revert InvalidGrandpaLog();
        c.present = true;
        c.authoritiesOffset = listOff;
        c.authoritiesLength = listLen;
        c.delay = ScaleCodec.readU32(h, listOff + listLen);
    }

    function _skipDigest(bytes memory h, uint256 off) private pure returns (uint256) {
        uint256 count;
        (count, off) = ScaleCodec.readCompact(h, off);
        for (uint256 i; i < count; ++i) {
            off = _skipItem(h, off);
        }
        return off;
    }

    function _skipItem(bytes memory h, uint256 off) private pure returns (uint256) {
        if (off >= h.length) revert InvalidDigestItem();
        uint8 kind = uint8(h[off]);
        uint256 len;
        uint256 dataOff;
        if (kind == 0) {
            (len, dataOff) = ScaleCodec.readCompact(h, off + 1);
        } else if (kind == 4 || kind == 5 || kind == 6) {
            (len, dataOff) = ScaleCodec.readCompact(h, off + 5);
        } else if (kind == 8) {
            return off + 1;
        } else {
            revert InvalidDigestItem();
        }
        if (dataOff + len > h.length) revert InvalidDigestItem();
        return dataOff + len;
    }
}
