// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {BitcoinVerifier} from "@hiero-ledger/clpr/verifiers/bitcoin/BitcoinVerifier.sol";
import {BitcoinLib} from "@hiero-ledger/clpr/verifiers/bitcoin/BitcoinLib.sol";

/// @title BitcoinCashVerifier
/// @notice The Bitcoin Cash profile of {BitcoinVerifier} (direction Bitcoin Cash → Hiero). Bitcoin Cash
///         keeps Bitcoin's 80-byte header, double-SHA256 proof of work, compact targets, transaction
///         Merkle tree and legacy txid serialization, so headers, Merkle branches, messages and the
///         UTXO cursor queue are verified by the unchanged base contract. Only the difficulty rule
///         differs: since the November 2020 upgrade every block's nBits is set by ASERT (aserti3-2d),
///         an absolutely scheduled exponential rule anchored at one fixed block, instead of Bitcoin's
///         2016-block retarget. This contract replaces {BitcoinVerifier-_checkWork} with that rule.
///
/// @dev Reference: Bitcoin Cash Node `src/pow.cpp` (`GetNextASERTWorkRequired`, `CalculateASERT`) and
///      `src/chainparams.cpp` (mainnet `asertAnchorParams` = {661647, 0x1804dafe, 1605447844},
///      `nASERTHalfLife` = 2 days). The testnet minimum-difficulty rule is not supported: the base
///      constructor is called with `noRetargeting = false` and `allowMinDifficulty = false`.
///      `Checkpoint.periodStartTime` has no meaning under ASERT and is carried unchanged.
contract BitcoinCashVerifier is BitcoinVerifier {
    /// @notice The ASERT anchor block, as in BCHN `Consensus::Params::ASERTAnchor`.
    struct AsertAnchor {
        uint32 height; // anchor block height
        uint32 bits; // anchor block nBits
        uint32 prevBlockTime; // timestamp of the anchor block's parent
    }

    error HeaderBeforeAsertAnchor(uint256 height);

    uint32 public immutable ASERT_ANCHOR_HEIGHT;
    uint32 public immutable ASERT_ANCHOR_BITS;
    uint32 public immutable ASERT_ANCHOR_PREV_TIME;
    /// @notice Seconds ahead of (behind) schedule that double (halve) the target; 172,800 on mainnet.
    uint32 public immutable ASERT_HALF_LIFE;

    /// @param powLimit Network maximum target (mainnet 0x00000000ffff…ff, i.e. 2^224 - 1).
    /// @param confirmations k (≥ 1).
    /// @param maxPayloadBytes Oversized-payload threshold (keep ≤ the local maxMessagePayloadBytes).
    /// @param caip2ChainId CAIP-2 id, mainnet `bip122:000000000000000000651ef99cb9fcbe`.
    /// @param checkpoint A trusted block at or above the ASERT anchor height.
    /// @param asert The network's ASERT anchor.
    /// @param halfLife The network's ASERT half-life in seconds.
    constructor(
        uint256 powLimit,
        uint8 confirmations,
        uint256 maxPayloadBytes,
        string memory caip2ChainId,
        Checkpoint memory checkpoint,
        AsertAnchor memory asert,
        uint32 halfLife
    ) BitcoinVerifier(powLimit, false, false, confirmations, maxPayloadBytes, caip2ChainId, checkpoint) {
        // CalculateASERT needs 32 leading zero bits in powLimit and a reference target in (0, powLimit].
        if (halfLife == 0 || powLimit >> 224 != 0 || checkpoint.height < asert.height) revert InvalidNetworkParams();
        if (BitcoinLib.bitsToTarget(asert.bits) > powLimit) revert InvalidNetworkParams();
        ASERT_ANCHOR_HEIGHT = asert.height;
        ASERT_ANCHOR_BITS = asert.bits;
        ASERT_ANCHOR_PREV_TIME = asert.prevBlockTime;
        ASERT_HALF_LIFE = halfLife;
    }

    /// @dev Every header above the checkpoint must carry exactly the ASERT nBits computed from its
    ///      parent's height and time, and meet that target. Advances `s` (bits, time, chainwork).
    ///      As in the base contract, median-time-past and the future-time rule are not checked.
    function _checkWork(bytes memory header, bytes32 hash, uint256 height, Checkpoint memory s) internal view override {
        // s.height is the parent's height (headers above the checkpoint are consecutive).
        if (uint256(s.height) < ASERT_ANCHOR_HEIGHT) revert HeaderBeforeAsertAnchor(height);
        uint32 bits = BitcoinLib.nBits(header);
        uint32 expected = BitcoinLib.asertBits(
            ASERT_ANCHOR_BITS, ASERT_ANCHOR_PREV_TIME, ASERT_ANCHOR_HEIGHT, s.height, s.time, POW_LIMIT, ASERT_HALF_LIFE
        );
        if (bits != expected) revert WrongDifficultyBits(height, expected, bits);

        uint256 target = BitcoinLib.bitsToTarget(bits);
        if (target > POW_LIMIT) revert TargetAbovePowLimit(height);
        if (BitcoinLib.reverse256(uint256(hash)) > target) revert InsufficientProofOfWork(height);
        s.bits = bits;
        s.chainWork += BitcoinLib.work(target);
        s.time = BitcoinLib.timestamp(header);
    }
}
