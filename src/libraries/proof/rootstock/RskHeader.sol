// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";
import {BitcoinLib} from "@hiero-ledger/clpr/verifiers/bitcoin/BitcoinLib.sol";
import {Sha256Midstate} from "@hiero-ledger/clpr/libraries/crypto/Sha256Midstate.sol";

/// @title RskHeader
/// @notice Rootstock block headers and their merged-mining proof of work, checked the way RSKj
///         9.x (VETIVER, the mainnet release on 2026-10-01) checks them. Source references are to
///         rsksmart/rskj `rskj-core/src/main/java`.
///
/// Header (`BlockHeaderV0`; RSKIP351 header versions are not active on mainnet): the block hash is
/// keccak256 of an RLP list of 17 or 18 items (`BlockHeader#getEncoded`, RSKIP92 form):
/// ```
/// 0 parentHash 1 unclesHash 2 coinbase 3 stateRoot 4 txTrieRoot 5 receiptTrieRoot 6 logsBloom
/// 7 difficulty 8 number 9 gasLimit 10 gasUsed 11 timestamp 12 extraData 13 paidFees
/// 14 minimumGasPrice 15 uncleCount [16 ummRoot, from RSKIPUMM] ‖ bitcoinMergedMiningHeader (80 B)
/// ```
/// RSKj encodes some of these non-minimally (signed BigInteger bytes), so a header is never
/// re-encoded here: the relayer supplies the exact preimage (`rsk_getRawBlockHeaderByNumber`).
///
/// Merged mining (`co.rsk.validators.ProofOfWorkRule#isValid`, RSKIP92 merkle proofs, RSKIP110 fork
/// detection data):
///  1. hashForMergedMining: `base = keccak256(RLP(items without the bitcoin header))`; for a UMM block
///     `base = keccak256(base[0:20] ‖ ummRoot)`; from the RSKIP110 height (and block 449) its last 12
///     bytes are the fork-detection data copied from the coinbase.
///  2. sha256d(bitcoin header) read little-endian ≤ 2^256 / max(difficulty, 3). The bitcoin header's own
///     nBits is NOT checked: the work is the RSK difficulty.
///  3. Coinbase field = byteCount(8, BE) ‖ SHA-256 midstate H0..H7(32) ‖ tail. The last "RSKBLOCK:" tag
///     in the tail is followed by hashForMergedMining, sits at offset < 64 and has ≤ 128 bytes after the
///     hash; byteCount + tail > 64. txid = sha256(resume(midstate, byteCount, tail)).
///  4. The txid folds through the RSKIP92 branch (siblings in display order, the coinbase always on
///     the left, at most 960 bytes) to the bitcoin header's merkle root; no pair may parse as a 64-byte
///     transaction (`MerkleTreeUtils#checkNotAValid64ByteTransaction`, applied to display-order bytes).
library RskHeader {
    using Memory for Memory.Slice;

    bytes9 internal constant RSK_TAG = "RSKBLOCK:";
    uint256 internal constant MAX_BYTES_AFTER_MM_HASH = 128;
    uint256 internal constant MAX_MERKLE_PROOF_LENGTH = 960; // RSKIP180
    /// @dev Below this height RSKj never includes fork-detection data (`MiningConfig` REQUIRED_NUMBER_OF_BLOCKS_FOR_FORK_DETECTION_CALCULATION).
    uint256 internal constant FORK_DETECTION_MIN_HEIGHT = 449;

    error RskBadHeader();
    error RskBadUmmRoot();
    error RskInsufficientWork();
    error RskTagMissing();
    error RskTagTooFar();
    error RskTooManyBytesAfterTag();
    error RskCoinbaseTooShort();
    error RskBadMerkleProof();
    error RskMerkleRootMismatch();
    error RskMerkle64ByteTx();

    struct Header {
        bytes32 hash;
        bytes32 parentHash;
        bytes32 stateRoot;
        uint256 difficulty;
        uint256 number;
        uint256 timestamp;
        uint256 uncleCount;
        bytes32 hashForMergedMining;
        bytes btcHeader;
    }

    /// @notice Parse a header hash preimage. `forkDetectionFrom` is the RSKIP110 activation height.
    /// @dev The fork-detection bytes of hashForMergedMining come from the coinbase, so the coinbase
    ///      is needed here too.
    function parse(bytes memory raw, bytes memory cb, uint256 forkDetectionFrom)
        internal
        pure
        returns (Header memory h)
    {
        Memory.Slice[] memory it = RLP.decodeList(raw);
        uint256 n = it.length;
        if (n != 17 && n != 18) revert RskBadHeader();
        h.hash = keccak256(raw);
        h.parentHash = RLP.readBytes32(it[0]);
        h.stateRoot = RLP.readBytes32(it[3]);
        h.difficulty = RLP.readUint256(it[7]);
        h.number = RLP.readUint256(it[8]);
        h.timestamp = RLP.readUint256(it[11]);
        h.uncleCount = RLP.readUint256(it[15]);
        h.btcHeader = RLP.readBytes(it[n - 1]);
        if (h.btcHeader.length != BitcoinLib.HEADER_LENGTH) revert RskBadHeader(); // BtcHeaderSizeRule (RSKIP98)

        // keccak256 of the list without the bitcoin header (getEncoded(false, false, true)).
        uint256 payloadLen = 0;
        for (uint256 i = 0; i + 1 < n; ++i) {
            payloadLen += it[i].length();
        }
        bytes memory noMm = new bytes(payloadLen);
        uint256 o = 0;
        for (uint256 i = 0; i + 1 < n; ++i) {
            bytes memory item = it[i].toBytes();
            assembly ("memory-safe") {
                mcopy(add(add(noMm, 0x20), o), add(item, 0x20), mload(item))
            }
            o += item.length;
        }
        bytes32 base = keccak256(abi.encodePacked(_listPrefix(payloadLen), noMm));
        if (n == 18) {
            bytes memory umm = RLP.readBytes(it[16]);
            if (umm.length == 20) {
                base = keccak256(abi.encodePacked(bytes20(base), umm));
            } else if (umm.length != 0) {
                revert RskBadUmmRoot();
            }
        }
        if (h.number >= FORK_DETECTION_MIN_HEIGHT && h.number >= forkDetectionFrom) {
            // RSKIP110: hashForMergedMining = base[0:20] ‖ the 12 bytes following "RSKBLOCK:" ‖ base[0:20]
            // in the coinbase. Equivalent to RSKj's search (see the library notes): it must be at the
            // last tag of the tail, which {verifyMergedMining} enforces.
            (uint256 p,) = _lastTag(cb, 40);
            if (p + 9 + 32 > cb.length) revert RskTagMissing();
            bytes32 window;
            assembly ("memory-safe") {
                window := mload(add(add(cb, 0x29), p)) // cb[p+9 : p+41]
            }
            if (bytes20(window) != bytes20(base)) revert RskTagMissing();
            h.hashForMergedMining = window;
        } else {
            h.hashForMergedMining = base;
        }
    }

    /// @notice ProofOfWorkRule: the bitcoin header's hash meets the RSK difficulty and its coinbase
    ///         commits to hashForMergedMining.
    function verifyMergedMining(Header memory h, bytes memory cb, bytes memory merkleProof) internal pure {
        // 2. PoW at the RSK difficulty (DifficultyUtils.difficultyToTarget).
        uint256 d = h.difficulty < 3 ? 3 : h.difficulty;
        uint256 powHash = BitcoinLib.reverse256(uint256(BitcoinLib.hash256(h.btcHeader)));
        // target = 2^256 / d; compare without overflow: powHash ≤ floor(2^256 / d).
        if (powHash > type(uint256).max / d + ((type(uint256).max % d) + 1 == d ? 1 : 0)) {
            revert RskInsufficientWork();
        }

        // 3. Coinbase: byteCount ‖ midstate ‖ tail.
        if (cb.length < 40) revert RskTagMissing();
        (uint256 p, bool found) = _lastTag(cb, 40);
        if (!found) revert RskTagMissing();
        uint256 tagPos = p - 40; // position inside the tail
        if (p + 9 + 32 > cb.length) revert RskTagMissing();
        bytes32 committed;
        assembly ("memory-safe") {
            committed := mload(add(add(cb, 0x29), p))
        }
        if (committed != h.hashForMergedMining) revert RskTagMissing();
        if (tagPos >= 64) revert RskTagTooFar();
        uint256 tailLen = cb.length - 40;
        if (tailLen - tagPos - 9 - 32 > MAX_BYTES_AFTER_MM_HASH) revert RskTooManyBytesAfterTag();
        uint256 byteCount = uint64(bytes8(_word(cb, 0)));
        if (byteCount + tailLen <= 64) revert RskCoinbaseTooShort();
        bytes memory tail = new bytes(tailLen);
        assembly ("memory-safe") {
            mcopy(add(tail, 0x20), add(cb, 0x48), tailLen)
        }
        bytes32 midstate = _word(cb, 8);
        bytes32 txid = sha256(abi.encodePacked(Sha256Midstate.resume(midstate, byteCount, tail)));

        // 4. RSKIP92 coinbase branch.
        uint256 len = merkleProof.length;
        if (len % 32 != 0 || len > MAX_MERKLE_PROOF_LENGTH) revert RskBadMerkleProof();
        bytes32 cur = txid; // internal byte order
        for (uint256 o = 0; o < len; o += 32) {
            bytes32 sibDisplay = _word(merkleProof, o);
            _checkNot64ByteTx(bytes32(BitcoinLib.reverse256(uint256(cur))), sibDisplay);
            cur = BitcoinLib.hash256Pair(cur, bytes32(BitcoinLib.reverse256(uint256(sibDisplay))));
        }
        if (cur != BitcoinLib.merkleRoot(h.btcHeader)) revert RskMerkleRootMismatch();
    }

    /// @notice DifficultyCalculator#calcDifficulty for a post-RSKIP97 block (no 10-minute reset).
    function expectedDifficulty(
        uint256 parentDifficulty,
        uint256 parentTimestamp,
        uint256 timestamp,
        uint256 uncleCount,
        uint256 durationLimit,
        uint256 divisor,
        uint256 minDifficulty
    ) internal pure returns (uint256) {
        if (timestamp < parentTimestamp) return parentDifficulty;
        uint256 delta = timestamp - parentTimestamp;
        uint256 calcDur = (1 + uncleCount) * durationLimit;
        if (calcDur == delta) return parentDifficulty;
        uint256 q = parentDifficulty / divisor;
        uint256 v = calcDur > delta ? parentDifficulty + q : parentDifficulty - q;
        return v < minDifficulty ? minDifficulty : v;
    }

    /// @dev Index (in `cb`, at or after `from`) of the last "RSKBLOCK:" tag.
    function _lastTag(bytes memory cb, uint256 from) private pure returns (uint256 p, bool found) {
        uint256 len = cb.length;
        if (len < from + 9) return (0, false);
        for (uint256 i = len - 9 + 1; i > from;) {
            --i;
            bytes32 w;
            assembly ("memory-safe") {
                w := mload(add(add(cb, 0x20), i))
            }
            if (bytes9(w) == RSK_TAG) return (i, true);
        }
        return (0, false);
    }

    /// @dev MerkleTreeUtils#checkNotAValid64ByteTransaction on display-order `left ‖ right`.
    function _checkNot64ByteTx(bytes32 left, bytes32 right) private pure {
        bytes memory b = abi.encodePacked(left, right);
        if (uint8(b[4]) != 1) return; // input count
        uint256 out0Index = _le(b, 37, 4);
        if (out0Index > 1_000_000 && out0Index != 0xffffffff) return;
        int8 s1 = int8(uint8(b[41]));
        if (s1 < 0 || s1 > 4) return;
        uint256 o = 46 + uint256(uint8(s1));
        if (uint8(b[o]) != 1) return; // output count
        int64 value = int64(uint64(_le(b, o + 1, 8)));
        if (value < 1 || value > 21_000_000 * 100_000_000) return;
        int8 s2 = int8(uint8(b[o + 9]));
        if (s2 < 0 || s2 > 4) return;
        if (s1 + s2 != 4) return;
        revert RskMerkle64ByteTx();
    }

    function _le(bytes memory b, uint256 off, uint256 n) private pure returns (uint256 v) {
        for (uint256 i = 0; i < n; ++i) {
            v |= uint256(uint8(b[off + i])) << (8 * i);
        }
    }

    function _word(bytes memory b, uint256 off) private pure returns (bytes32 w) {
        if (off + 32 > b.length) revert RskBadHeader();
        assembly ("memory-safe") {
            w := mload(add(add(b, 0x20), off))
        }
    }

    function _listPrefix(uint256 len) private pure returns (bytes memory) {
        if (len <= 55) return abi.encodePacked(bytes1(uint8(0xc0 + len)));
        uint256 n = 0;
        for (uint256 t = len; t != 0; t >>= 8) {
            ++n;
        }
        bytes memory p = new bytes(1 + n);
        p[0] = bytes1(uint8(0xf7 + n));
        for (uint256 i = 0; i < n; ++i) {
            p[n - i] = bytes1(uint8(len >> (8 * i)));
        }
        return p;
    }
}
