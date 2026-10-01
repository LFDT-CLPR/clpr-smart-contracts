// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {CometBftLib} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftLib.sol";
import {CometBftProofCodec as Codec} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftProofCodec.sol";
import {CometBftLightClient} from "@hiero-ledger/clpr/verifiers/evm/cometbft/CometBftLightClient.sol";

/// @title CometBftCommitAccumulator
/// @notice Splits a CometBFT commit check across transactions. One CometBFT chain per deployment
///         (chain id and key scheme are immutable).
///
///         A commit with many Ed25519 signatures can cost more than one Hedera transaction allows
///         (~640k gas per signature, 15M per transaction). Anyone may call {accumulate} with the
///         validator set, the signed header and any subset of its commit signatures. Each call
///         verifies the new signatures, adds their power and marks those signers as counted. Once
///         more than 2/3 of the set's power is recorded, {finalizedHeader} returns the header
///         summary (app hash, next validator-set hash, height). A verifier then references the
///         header by hash and skips the signature work, so the state proof gets the whole next
///         transaction.
///
///         {checkHeader} is the one-transaction path: the same check, in a view call, for a commit
///         that fits.
///
/// ## Why a permissionless record is safe
///   A record only states "the validator set with hash S signed header h with more than 2/3 of its
///   power". The header hash commits to S (validators_hash), so every header has exactly one record
///   and one set. The record never says S is trusted. A verifier accepts it only when S equals the
///   set its own trust anchor (or a verified hop) names, which is the check {checkHeader} makes in
///   a single transaction. Every batch for a header must use the same commit round and part-set
///   header, so signatures from different rounds are never added together.
contract CometBftCommitAccumulator is CometBftLightClient {
    /// @notice What a verifier needs from a verified header.
    struct Header {
        bytes32 validatorsHash;
        bytes32 nextValidatorsHash;
        bytes32 appHash;
        uint64 height;
    }

    struct Record {
        bytes32 validatorsHash;
        bytes32 nextValidatorsHash;
        bytes32 appHash;
        /// @dev keccak256(round, part_set_total, part_set_hash) of the first batch.
        bytes32 commitId;
        uint64 height;
        uint64 signedPower;
        uint64 totalPower;
    }

    /// @notice header hash → accumulated record.
    mapping(bytes32 => Record) public records;
    /// @dev header hash → validator index / 256 → bitmap of signers already counted.
    mapping(bytes32 => mapping(uint256 => uint256)) internal _counted;

    string public chainId;

    event SignaturesAccumulated(
        bytes32 indexed headerHash, uint64 height, uint256 newSigners, uint64 signedPower, uint64 totalPower
    );
    event HeaderFinalized(bytes32 indexed headerHash, bytes32 indexed validatorsHash, uint64 height);

    error InvalidProfile();
    error CommitMismatch();
    error NoNewSignatures();
    error NotFinalized();

    constructor(string memory chainId_, KeyScheme keyScheme, address ed25519Verifier)
        CometBftLightClient(keccak256(bytes(chainId_)), keyScheme, ed25519Verifier)
    {
        if (bytes(chainId_).length == 0 || (keyScheme == KeyScheme.ED25519 && ed25519Verifier == address(0))) {
            revert InvalidProfile();
        }
        chainId = chainId_;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Multi-transaction path
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Verify and count the commit signatures in `signedHeader` that are not counted yet.
    /// @param validatorSet ValidatorSet{repeated bytes 1: SimpleValidator leaf}; must hash to the
    ///        header's validators_hash.
    /// @param signedHeader SignedHeader in the relay layout (README §4), carrying any subset of the
    ///        commit signatures (signers_bits marks which).
    /// @return headerHash The CometBFT block hash.
    /// @return finalized True once more than 2/3 of the set's power has been counted.
    function accumulate(bytes calldata validatorSet, bytes calldata signedHeader)
        external
        returns (bytes32 headerHash, bool finalized)
    {
        (Validator[] memory vals, bytes32 setHash) = _decodeValidatorSet(validatorSet);
        (CometBftLib.SeiHeader memory header, CometBftLib.SeiCommit memory commit) =
            Codec.parseSignedHeader(signedHeader);
        _checkHeaderBinding(header, setHash, 0);
        headerHash = CometBftLib.headerHash(header);
        bytes32 commitId = keccak256(abi.encode(commit.round, commit.partSetTotal, commit.partSetHash));

        Record storage r = records[headerHash];
        uint64 signed = r.signedPower;
        uint64 total = r.totalPower;
        if (total == 0) {
            for (uint256 i; i < vals.length; ++i) {
                // forge-lint: disable-next-line(unsafe-typecast)
                total += uint64(vals[i].power);
            }
            r.validatorsHash = setHash;
            r.nextValidatorsHash = header.nextValidatorsHash;
            r.appHash = header.appHash;
            r.commitId = commitId;
            // forge-lint: disable-next-line(unsafe-typecast)
            r.height = uint64(header.height);
            r.totalPower = total;
        } else if (r.commitId != commitId) {
            revert CommitMismatch();
        }
        bool wasFinal = _final(signed, total);

        (uint64 added, uint256 newSigners) = _countNew(headerHash, header, commit, vals);
        if (newSigners == 0) revert NoNewSignatures();
        signed += added;
        r.signedPower = signed;
        // forge-lint: disable-next-line(unsafe-typecast)
        emit SignaturesAccumulated(headerHash, uint64(header.height), newSigners, signed, total);
        finalized = _final(signed, total);
        // forge-lint: disable-next-line(unsafe-typecast)
        if (finalized && !wasFinal) emit HeaderFinalized(headerHash, setHash, uint64(header.height));
    }

    /// @notice The summary of a header whose commit has reached more than 2/3 of its set's power.
    function finalizedHeader(bytes32 headerHash) external view returns (Header memory h) {
        Record storage r = records[headerHash];
        if (!_final(r.signedPower, r.totalPower)) revert NotFinalized();
        h = Header({
            validatorsHash: r.validatorsHash,
            nextValidatorsHash: r.nextValidatorsHash,
            appHash: r.appHash,
            height: r.height
        });
    }

    /// @notice Whether validator `index` has been counted for `headerHash`.
    function isCounted(bytes32 headerHash, uint256 index) external view returns (bool) {
        return _counted[headerHash][index / 256] & (uint256(1) << (index % 256)) != 0;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   One-transaction path
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Full light-client check in one call: `validatorSet` hashes to `setHash`, the header
    ///         is this chain's, signed by that set at or above `minHeight`, with more than 2/3 of
    ///         its power. Reverts otherwise.
    function checkHeader(bytes calldata validatorSet, bytes calldata signedHeader, bytes32 setHash, uint64 minHeight)
        external
        view
        returns (bytes32 headerHash, Header memory h)
    {
        Validator[] memory vals = _parseValidatorSet(validatorSet, setHash);
        (CometBftLib.SeiHeader memory header, CometBftLib.SeiCommit memory commit) =
            Codec.parseSignedHeader(signedHeader);
        _checkHeaderBinding(header, setHash, minHeight);
        headerHash = CometBftLib.headerHash(header);
        _verifyCommit(commit, headerHash, header, vals);
        h = Header({
            validatorsHash: header.validatorsHash,
            nextValidatorsHash: header.nextValidatorsHash,
            appHash: header.appHash,
            // forge-lint: disable-next-line(unsafe-typecast)
            height: uint64(header.height)
        });
    }

    /// @dev Verifies the signatures of signers not counted yet, marks them counted and returns the
    ///      power they add. Signers counted by an earlier batch are skipped without verification.
    function _countNew(
        bytes32 headerHash,
        CometBftLib.SeiHeader memory header,
        CometBftLib.SeiCommit memory commit,
        Validator[] memory vals
    ) private returns (uint64 added, uint256 newSigners) {
        _checkSignersBits(commit.signersBits, vals.length);
        (bytes memory prefix, bytes memory suffix) = _voteTemplate(commit, headerHash, header);
        mapping(uint256 => uint256) storage counted = _counted[headerHash];
        uint256 sigIdx;
        uint256 word;
        uint256 wordIdx = type(uint256).max;
        for (uint256 i; i < vals.length; ++i) {
            if (!_bitSet(commit.signersBits, i)) continue;
            if (sigIdx == commit.signatures.length) revert TooFewSignatures();
            CometBftLib.CommitSig memory sig = commit.signatures[sigIdx++];
            if (i / 256 != wordIdx) {
                if (wordIdx != type(uint256).max) counted[wordIdx] = word;
                wordIdx = i / 256;
                word = counted[wordIdx];
            }
            uint256 mask = uint256(1) << (i % 256);
            if (word & mask != 0) continue;
            bytes memory signBytes =
                CometBftLib.precommitSignBytesHoisted(prefix, suffix, sig.timestampSeconds, sig.timestampNanos);
            if (!_verifyVote(vals[i].key, signBytes, sig.signature)) revert InvalidSignature();
            word |= mask;
            // forge-lint: disable-next-line(unsafe-typecast)
            added += uint64(vals[i].power);
            ++newSigners;
        }
        if (sigIdx != commit.signatures.length) revert ExtraSignatures();
        if (wordIdx != type(uint256).max) counted[wordIdx] = word;
    }

    function _final(uint64 signed, uint64 total) private pure returns (bool) {
        return total != 0 && uint256(signed) * 3 > uint256(total) * 2;
    }
}
