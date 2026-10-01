// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {WavesBls} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/lib/WavesBls.sol";
import {Blake2b256} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/lib/Blake2b256.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";

/// @title WavesFinalityVerifier
/// @notice The finality half of a Waves → Hiero verifier. NOT a CLPR bundle verifier (it does not implement the verifier interface): Waves has no public
///         state proof for a Ride dApp's data entries (see the family README, "Limits and known gaps"),
///         so this contract proves only that a block is final.
///
///         Waves Deterministic Finality (feature 25; active on testnet since height 4,044,000, still
///         in voting on mainnet on 2026-10-01): generators commit for a generation period with a
///         `CommitToGeneration` transaction that registers a BLS12-381 key. Each generator signs an
///         endorsement of the parent block, `finalizedId ‖ BE32(finalizedHeight) ‖ endorsedId`
///         (`BlockEndorsement.mkMessage`). The next block carries the aggregated signature and the
///         endorser indexes (`FinalizationVoting`). A block is final when the endorsing generators
///         hold at least 2/3 of the period's generating balance (`endorsed × 3 ≥ total × 2`,
///         `FinalizationVoting.isFinalized`).
///
///         This contract checks: the generator set matches the trusted commitment; the endorser
///         indexes are strictly ascending; their balance × 3 ≥ total × 2; the aggregated BLS signature
///         over the message whose `endorsedId` is the BLAKE2b-256 of the supplied block header
///         protobuf (`Block.protoHeaderHash`, the block id). It returns the header's state hash,
///         transactions root, reference and timestamp.
///
/// ## Differences from the node's rule (all make it stricter)
/// - The block producer counts as an endorser in the node without a BLS signature (its block
///   signature stands in). Checking that would need a Curve25519 (XEdDSA) signature check here,
///   so the producer's balance is never counted: only blocks whose BLS endorsers alone reach 2/3
///   are proven. On testnet these appear every few blocks.
/// - Conflicting endorsers are removed from the total in the node; here the total stays the full
///   set, which only raises the bar.
///
/// ## Trust
/// The generator set (BLS keys and generating balances) is TRUSTED: `trustedSetHash` comes from the
/// caller's anchor. Keys could be proven from `CommitToGeneration` transactions in final blocks
/// (transactions-root proofs), but generating balances are account state, which Waves headers
/// do not commit to in a provable form. Rotation every generation period (3,000 blocks on
/// testnet, about two days) therefore needs a trusted step.
///
/// ## Generator set encoding
/// `periodStart(u32) ‖ periodEnd(u32) ‖ n × (uncompressed G1 key (128) ‖ balance (u64))`, entries in
/// the node's generator index order; its commitment is `keccak256` of these bytes.
contract WavesFinalityVerifier {
    uint256 internal constant SET_HEADER = 8;
    uint256 internal constant ENTRY = 136;

    struct Endorsement {
        bytes32 finalizedId;
        uint32 finalizedHeight;
        uint32[] endorserIndexes;
        /// @dev Aggregated endorsement signature, uncompressed G2 (256 bytes).
        bytes signature;
    }

    struct FinalBlock {
        bytes32 id;
        bytes32 parentId;
        bytes32 transactionsRoot;
        bytes32 stateHash;
        uint64 timestamp;
        uint256 endorsedBalance;
        uint256 totalBalance;
    }

    error GeneratorSetMismatch();
    error InvalidGeneratorSet();
    error EndorserIndexesNotAscending();
    error EndorserIndexOutOfRange();
    error BelowTwoThirds(uint256 endorsed, uint256 total);
    error OutsideGenerationPeriod();
    error InvalidHeader();

    /// @notice Verify that the block with header protobuf `header` is final under `generatorSet`,
    ///         whose keccak256 must be `trustedSetHash`.
    function verifyFinalized(
        bytes calldata header,
        Endorsement calldata e,
        bytes calldata generatorSet,
        bytes32 trustedSetHash
    ) external view returns (FinalBlock memory b) {
        if (keccak256(generatorSet) != trustedSetHash) revert GeneratorSetMismatch();
        if (generatorSet.length < SET_HEADER || (generatorSet.length - SET_HEADER) % ENTRY != 0) {
            revert InvalidGeneratorSet();
        }
        uint32 periodStart = uint32(bytes4(generatorSet[0:4]));
        uint32 periodEnd = uint32(bytes4(generatorSet[4:8]));
        // The endorsed block follows the finalized one; its height is not in the header, so the
        // signed finalizedHeight bounds it to the set's period.
        if (uint256(e.finalizedHeight) + 1 < periodStart || e.finalizedHeight >= periodEnd) {
            revert OutsideGenerationPeriod();
        }
        uint256 n = (generatorSet.length - SET_HEADER) / ENTRY;

        bytes memory aggregate;
        for (uint256 i = 0; i < n; i++) {
            b.totalBalance += uint64(bytes8(generatorSet[SET_HEADER + i * ENTRY + 128:SET_HEADER + (i + 1) * ENTRY]));
        }
        for (uint256 j = 0; j < e.endorserIndexes.length; j++) {
            uint256 idx = e.endorserIndexes[j];
            if (j > 0 && idx <= e.endorserIndexes[j - 1]) revert EndorserIndexesNotAscending();
            if (idx >= n) revert EndorserIndexOutOfRange();
            uint256 off = SET_HEADER + idx * ENTRY;
            bytes memory key = generatorSet[off:off + 128];
            aggregate = j == 0 ? key : WavesBls.addG1(aggregate, key);
            b.endorsedBalance += uint64(bytes8(generatorSet[off + 128:off + ENTRY]));
        }
        if (b.endorsedBalance * 3 < b.totalBalance * 2 || e.endorserIndexes.length == 0) {
            revert BelowTwoThirds(b.endorsedBalance, b.totalBalance);
        }

        b.id = Blake2b256.hash(header);
        WavesBls.verify(aggregate, abi.encodePacked(e.finalizedId, e.finalizedHeight, b.id), e.signature);
        (b.parentId, b.transactionsRoot, b.stateHash, b.timestamp) = _parseHeader(header);
    }

    /// @notice Commitment of a generator set (see the contract doc for the encoding).
    function generatorSetHash(bytes calldata generatorSet) external pure returns (bytes32) {
        return keccak256(generatorSet);
    }

    /// @notice Waves block id of a v5 header: BLAKE2b-256 of the header protobuf.
    function blockId(bytes calldata header) external view returns (bytes32) {
        return Blake2b256.hash(header);
    }

    /// @dev `waves.Block.Header`: 2 reference, 6 timestamp, 10 transactions_root, 11 state_hash.
    function _parseHeader(bytes calldata header)
        internal
        pure
        returns (bytes32 parentId, bytes32 transactionsRoot, bytes32 stateHash, uint64 timestamp)
    {
        bytes memory h = header;
        uint256 off;
        while (off < h.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(h, off);
            off = off2;
            if (wt == 2 && (fn_ == 2 || fn_ == 10 || fn_ == 11)) {
                bytes memory v;
                (v, off) = PB.decodeLengthDelimited(h, off);
                if (v.length != 32) revert InvalidHeader();
                // forge-lint: disable-next-line(unsafe-typecast)
                bytes32 w = bytes32(v);
                if (fn_ == 2) parentId = w;
                else if (fn_ == 10) transactionsRoot = w;
                else stateHash = w;
            } else if (wt == 0 && fn_ == 6) {
                (timestamp, off) = PB.decodeVarint(h, off);
            } else {
                off = PB.skipField(h, off, wt);
            }
        }
    }
}
