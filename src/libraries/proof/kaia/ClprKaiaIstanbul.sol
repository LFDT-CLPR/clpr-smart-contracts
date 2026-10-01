// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title ClprKaiaIstanbul
/// @notice Kaia (formerly Klaytn) Istanbul BFT header primitives: header decoding, the block hash
///         (which excludes committed seals and the round byte), committed-seal recovery and the
///         pre-permissionless quorum. Mirrors kaiachain/kaia `consensus/istanbul/sealer.go` and
///         `blockchain/block_validator.go` (checked at commit 2fbaab6, Oct 2026):
///   - Header RLP: [parentHash, rewardbase, root, txHash, receiptHash, bloom, blockScore, number,
///     gasUsed, time, timeFoS, extra, governance, vote, (baseFee), (randomReveal, mixHash),
///     (blobGasUsed, excessBlobGas), (vrank)].
///   - extra = vanity32 ‖ RLP([validators[], seal, committedSeals[]]); vanity[31] holds the round.
///   - Block hash = keccak256(RLP(header with committedSeals = [] and vanity[31] = 0)).
///   - Committed seal = secp256k1 signature over keccak256(blockHash ‖ 0x02), v ∈ {0, 1}.
///   - `validators` is the block's qualified validator set. Pre-permissionless quorum is 2f + 1 with
///     f = ceil(N/3) − 1, N = min(qualified, committeeSize); committers must be distinct.
library ClprKaiaIstanbul {
    uint256 internal constant EXTRA_VANITY = 32;
    uint256 internal constant SEAL_LENGTH = 65;
    uint256 internal constant MIN_HEADER_FIELDS = 14;
    uint256 internal constant MAX_HEADER_FIELDS = 20;
    uint256 internal constant IDX_STATE_ROOT = 2;
    uint256 internal constant IDX_NUMBER = 7;
    uint256 internal constant IDX_EXTRA = 11;
    /// @dev `bft.MsgCommit`, appended to the block hash in the committed-seal preimage.
    uint8 internal constant MSG_COMMIT = 2;
    /// @dev Bitmap bound for distinct-committer tracking.
    uint256 internal constant MAX_VALIDATORS = 256;

    error InvalidHeader();
    error InvalidExtraData();
    error InvalidValidatorSet();
    error InvalidCommittedSeal(uint256 index);
    error DuplicateCommitter(address committer);

    struct Header {
        bytes32 hash; // Istanbul block hash (committed seals stripped, round zeroed)
        bytes32 stateRoot;
        uint64 number;
        address[] validators; // qualified set, header order
        bytes32 validatorsHash; // keccak256(packed validators)
        address[] committers; // recovered committed-seal signers, seal order
    }

    /// @dev Decode a Kaia header, compute its block hash and recover every committed seal.
    function decodeHeader(Memory.Slice item) internal pure returns (Header memory h) {
        Memory.Slice[] memory f = RLP.readList(item);
        uint256 n = f.length;
        if (n < MIN_HEADER_FIELDS || n > MAX_HEADER_FIELDS) revert InvalidHeader();
        h.stateRoot = RLP.readBytes32(f[IDX_STATE_ROOT]);
        uint256 number = RLP.readUint256(f[IDX_NUMBER]);
        if (number > type(uint64).max) revert InvalidHeader();
        // forge-lint: disable-next-line(unsafe-typecast)
        h.number = uint64(number);

        bytes memory extra = RLP.readBytes(f[IDX_EXTRA]);
        if (extra.length <= EXTRA_VANITY) revert InvalidExtraData();
        bytes memory ist = new bytes(extra.length - EXTRA_VANITY);
        bytes memory vanity = new bytes(EXTRA_VANITY);
        assembly ("memory-safe") {
            mcopy(add(ist, 0x20), add(extra, 0x40), mload(ist))
            mcopy(add(vanity, 0x20), add(extra, 0x20), 32)
        }
        vanity[EXTRA_VANITY - 1] = 0; // round byte is not part of the block hash
        Memory.Slice[] memory e = RLP.decodeList(ist);
        if (e.length != 3) revert InvalidExtraData();

        // Validators.
        Memory.Slice[] memory vals = RLP.readList(e[0]);
        uint256 nv = vals.length;
        if (nv == 0 || nv > MAX_VALIDATORS) revert InvalidValidatorSet();
        h.validators = new address[](nv);
        for (uint256 i = 0; i < nv; i++) {
            h.validators[i] = RLP.readAddress(vals[i]);
        }
        h.validatorsHash = hashAddresses(h.validators);

        // Block hash: same header, extra' = vanity(round 0) ‖ RLP([validators, seal, []]).
        {
            bytes[] memory extraItems = new bytes[](3);
            extraItems[0] = Memory.toBytes(e[0]);
            extraItems[1] = Memory.toBytes(e[1]);
            extraItems[2] = RLP.encode(new bytes[](0));
            bytes memory filteredExtra = bytes.concat(vanity, RLP.encode(extraItems));
            bytes[] memory items = new bytes[](n);
            for (uint256 i = 0; i < n; i++) {
                items[i] = i == IDX_EXTRA ? RLP.encode(filteredExtra) : Memory.toBytes(f[i]);
            }
            h.hash = keccak256(RLP.encode(items));
        }

        // Committed seals over keccak256(hash ‖ MSG_COMMIT).
        Memory.Slice[] memory seals = RLP.readList(e[2]);
        bytes32 digest = keccak256(abi.encodePacked(h.hash, MSG_COMMIT));
        h.committers = new address[](seals.length);
        for (uint256 i = 0; i < seals.length; i++) {
            bytes memory s = RLP.readBytes(seals[i]);
            if (s.length != SEAL_LENGTH) revert InvalidCommittedSeal(i);
            bytes32 r;
            bytes32 ss;
            uint8 v;
            assembly ("memory-safe") {
                r := mload(add(s, 0x20))
                ss := mload(add(s, 0x40))
                v := byte(0, mload(add(s, 0x60)))
            }
            if (v > 1) revert InvalidCommittedSeal(i);
            address a = ecrecover(digest, v + 27, r, ss);
            if (a == address(0)) revert InvalidCommittedSeal(i);
            h.committers[i] = a;
        }
    }

    /// @dev Number of distinct committers that are members of `set`. Reverts on a repeated
    ///      committer (Kaia's `countValidCommittedSeals` rejects duplicates); non-members are skipped.
    function countMembers(address[] memory committers, address[] memory set) internal pure returns (uint256 count) {
        uint256 n = set.length;
        if (n > MAX_VALIDATORS) revert InvalidValidatorSet();
        uint256 seen;
        for (uint256 i = 0; i < committers.length; i++) {
            address c = committers[i];
            for (uint256 j = 0; j < i; j++) {
                if (committers[j] == c) revert DuplicateCommitter(c);
            }
            for (uint256 k = 0; k < n; k++) {
                if (set[k] == c) {
                    uint256 bit = uint256(1) << k;
                    if (seen & bit == 0) {
                        seen |= bit;
                        count++;
                    }
                    break;
                }
            }
        }
    }

    /// @dev keccak256 of `n × address20` (no padding), the anchor's set commitment.
    function hashAddresses(address[] memory addrs) internal pure returns (bytes32 h) {
        uint256 n = addrs.length;
        // 12 spare bytes: each 32-byte store below writes 12 bytes past its 20-byte slot.
        bytes memory packed = new bytes(n * 20 + 12);
        for (uint256 i = 0; i < n; i++) {
            address a = addrs[i];
            assembly ("memory-safe") {
                mstore(add(add(packed, 0x20), mul(i, 20)), shl(96, a))
            }
        }
        assembly ("memory-safe") {
            h := keccak256(add(packed, 0x20), mul(n, 20))
        }
    }

    /// @dev f = ceil(n/3) − 1, the Byzantine bound Kaia derives for a set of n validators.
    function faultBound(uint256 n) internal pure returns (uint256) {
        return (n + 2) / 3 - 1;
    }

    /// @dev Pre-permissionless commit quorum 2f + 1 over the full qualified set.
    function quorum(uint256 n) internal pure returns (uint256) {
        return 2 * faultBound(n) + 1;
    }
}
