// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";
import {MonadBls} from "@hiero-ledger/clpr/libraries/proof/monad/MonadBls.sol";
import {MonadPageProof} from "@hiero-ledger/clpr/libraries/proof/monad/MonadPageProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title MonadValsetRotation
/// @notice Validator-set rotation for {MonadVerifier}, proven from the Monad staking precompile's storage.
///         Stateless: the verifier passes the trust anchor in and stores what comes back. Kept in its own
///         contract so both stay under the EIP-170 code-size limit.
/// @dev A rotation to epoch E+1 runs over several bundles (Hedera: 15M gas / 128 KiB per transaction):
///        start     — in a finalized bundle (QC of epoch E): prove the staking contract is in epoch E's
///                    delay period and the full `valset_consensus` id array; pin the staking and
///                    ClprService storage roots of that state in the anchor;
///        chunk(s)  — prove each validator's stake (`consensus_view`) and keys (`val_execution`) against
///                    the pinned staking root, folding them into an array-order accumulator;
///        finalize  — present the set in consensus order (ascending secp key) with uncompressed G1 keys,
///                    recompute the accumulator, and install keccak256(set) for epoch E+1.
contract MonadValsetRotation {
    /// @dev `limits::active_valset_size()` in monad `staking/util/constants.hpp`.
    uint256 public constant MAX_VALIDATORS = 200;
    /// @dev Staking precompile (`STAKING_CA`).
    address public constant STAKING = address(0x1000);

    // Staking storage layout (monad `staking/staking_contract.hpp`, `storage_variable.hpp`).
    uint256 internal constant SLOT_EPOCH = 1; // u64_be in bytes[0..8]
    uint256 internal constant SLOT_IN_DELAY = 2; // bool in byte 0
    uint256 internal constant SLOT_VALSET_CONSENSUS = 0x02 << 248; // StorageArray<u64_be>: length, then items
    uint256 internal constant NS_CONSENSUS_STAKE = 0x04;
    uint256 internal constant NS_VAL_EXECUTION = 0x09;
    uint256 internal constant VAL_EXECUTION_KEYS_OFFSET = 3; // KeysPacked{secp[33], bls[48]} over 3 slots

    /// @dev One validator in the finalize blob: secp (33) || EIP-2537 G1 key (128) || stake (32).
    uint256 internal constant SORTED_ENTRY = 193;

    /// @dev One key-registry entry: val_id (8) || secp (33) || compressed BLS (48). Validator keys are
    ///      immutable per id (`ValExecution::keys`, "Immutable"; ids are never reused), so a rotation only
    ///      re-proves keys of validators that were not in the previous set.
    uint256 internal constant REGISTRY_ENTRY = 89;
    uint256 internal constant NEW_KEY = 0xffff;

    /// @dev Channel.trustAnchor of {MonadVerifier} (abi-encoded, 12 words).
    struct Anchor {
        uint64 epoch; // epoch whose validator set is `valsetHash`
        bytes32 valsetHash; // keccak256 of the bundle validator-set blob, sorted by secp key
        bytes32 codeHash; // pinned ClprService code hash
        uint64 pendingEpoch; // next epoch being rotated in (0 = none)
        uint64 pendingBlock; // Ethereum block number of the rotation state
        bytes32 stakingRoot; // staking precompile storage root at that state
        bytes32 serviceRoot; // ClprService storage root at that state
        uint64 pendingLength; // proven valset_consensus.length
        uint64 pendingProven; // entries accumulated so far (array order)
        bytes32 pendingAcc; // running keccak over (secp33, bls48, stake32) in array order
        bytes32 pendingIds; // keccak256 of valset_consensus as packed u64 ids (proven at start)
        bytes32 keysHash; // key registry of the current set: keccak256(n × (id8 || secp33 || bls48)), 0 = none
    }

    error InvalidProofShape();
    error RotationStateInvalid();
    error RotationStale();
    error RotationIncomplete();
    error RotationOverflow();
    error InvalidValidatorEntry();
    error ValidatorOrder();
    error InvalidPermutation();
    error RotationAccumulatorMismatch();

    /// @dev Begin rotating to epoch+1 from a finalized state in epoch `a.epoch`'s delay period. Mirrors
    ///      monad `staking/read_valset.cpp`: the next set is `valset_consensus` (with stakes from
    ///      `consensus_view`, keys from `val_execution`) when `epoch == requested - 1` and
    ///      `in_epoch_delay_period` is set. Both are only written by `syscall_snapshot` (guarded by the
    ///      delay flag) and `syscall_on_epoch_change`, so any state in the delay period yields exactly
    ///      the set consensus read at the boundary block.
    ///      rs = [stakingAccountProof, stakingPages] (pages covering slots 1, 2 and the whole array).
    function start(bytes calldata rsRlp, bytes32 stateRoot, uint64 blockNumber, bytes32 serviceRoot, Anchor memory a)
        external
        pure
        returns (Anchor memory)
    {
        Memory.Slice[] memory rs = RLP.decodeList(rsRlp);
        if (rs.length != 2) revert InvalidProofShape();
        if (a.pendingEpoch != 0 && blockNumber <= a.pendingBlock) revert RotationStale();
        (bytes32 stakingRoot,) = MonadPageProof.account(rs[0], stateRoot, STAKING);
        MonadPageProof.Page[] memory pages = MonadPageProof.verifyPages(rs[1], stakingRoot);
        uint256 contractEpoch = uint256(MonadPageProof.slotValue(pages, bytes32(SLOT_EPOCH))) >> 192;
        uint256 inDelay = uint256(MonadPageProof.slotValue(pages, bytes32(SLOT_IN_DELAY)));
        uint256 length = uint256(MonadPageProof.slotValue(pages, bytes32(SLOT_VALSET_CONSENSUS))) >> 192;
        if (contractEpoch != a.epoch || inDelay != uint256(1) << 248) revert RotationStateInvalid();
        if (length == 0 || length > MAX_VALIDATORS) revert RotationStateInvalid();
        // The whole id array (≤ 2 pages for 200 validators) is proven once; chunks then carry the ids in
        // calldata, bound by `pendingIds`.
        bytes memory ids = new bytes(length * 8);
        for (uint256 i = 0; i < length; ++i) {
            bytes32 v = MonadPageProof.slotValue(pages, bytes32(SLOT_VALSET_CONSENSUS + 1 + i));
            if (v == bytes32(0)) revert InvalidValidatorEntry();
            assembly ("memory-safe") {
                mstore(add(add(ids, 0x20), mul(i, 8)), v) // u64_be in the top 8 bytes
            }
        }

        bytes32 idsHash = keccak256(ids);
        // A restart from a later delay-period state (e.g. to refresh the ClprService root) keeps the
        // progress: valset_consensus, consensus_view and the keys cannot change inside the delay period,
        // so entries already folded into the accumulator are the same at the new state.
        bool keep = a.pendingEpoch == a.epoch + 1 && a.pendingIds == idsHash;
        a.pendingEpoch = a.epoch + 1;
        a.pendingBlock = blockNumber;
        a.stakingRoot = stakingRoot;
        a.serviceRoot = serviceRoot;
        // forge-lint: disable-next-line(unsafe-typecast)
        a.pendingLength = uint64(length);
        a.pendingIds = idsHash;
        if (!keep) {
            a.pendingProven = 0;
            a.pendingAcc = bytes32(0);
        }
        return a;
    }

    /// @dev chunk = [ids, registry, hints, stakingPages, count]: for valset_consensus[proven .. proven+count)
    ///      (ids from the array proven at start) prove each validator's consensus_view stake against the
    ///      pending staking root. Keys come from the previous set's registry (`hints[k]` = its index there)
    ///      or, for a validator new to the set (`hints[k]` = 0xffff), from its val_execution keys.
    function chunk(bytes calldata chunkRlp, Anchor memory a) external pure returns (Anchor memory) {
        Memory.Slice[] memory ch = RLP.decodeList(chunkRlp);
        if (ch.length != 5) revert InvalidProofShape();
        bytes memory ids = RLP.readBytes(ch[0]);
        if (keccak256(ids) != a.pendingIds) revert RotationStateInvalid();
        bytes memory registry = RLP.readBytes(ch[1]);
        if (registry.length != 0 && keccak256(registry) != a.keysHash) revert RotationStateInvalid();
        bytes memory hints = RLP.readBytes(ch[2]);
        MonadPageProof.Page[] memory pages = MonadPageProof.verifyPages(ch[3], a.stakingRoot);
        uint256 count = RLP.readUint256(ch[4]);
        uint256 first = a.pendingProven;
        if (count == 0 || first + count > a.pendingLength || hints.length != 2 * count) revert RotationOverflow();
        bytes32 acc = a.pendingAcc;
        for (uint256 i = first; i < first + count; ++i) {
            uint256 id;
            uint256 hint;
            assembly ("memory-safe") {
                id := shr(192, mload(add(add(ids, 0x20), mul(i, 8))))
                hint := shr(240, mload(add(add(hints, 0x20), mul(sub(i, first), 2))))
            }
            if (id == 0) revert InvalidValidatorEntry();
            uint256 stake = uint256(MonadPageProof.slotValue(pages, bytes32((NS_CONSENSUS_STAKE << 248) | (id << 184))));
            if (stake == 0) revert InvalidValidatorEntry();
            if (hint == NEW_KEY) {
                uint256 keyBase = ((NS_VAL_EXECUTION << 248) | (id << 184)) + VAL_EXECUTION_KEYS_OFFSET;
                bytes32 k0 = MonadPageProof.slotValue(pages, bytes32(keyBase));
                bytes32 k1 = MonadPageProof.slotValue(pages, bytes32(keyBase + 1));
                bytes32 k2 = MonadPageProof.slotValue(pages, bytes32(keyBase + 2));
                if (uint120(uint256(k2)) != 0) revert InvalidValidatorEntry();
                // KeysPacked: secp = k0 || k1[0]; bls = k1[1..32] || k2[0..17].
                // forge-lint: disable-next-line(unsafe-typecast)
                acc = keccak256(abi.encodePacked(acc, k0, bytes1(k1), bytes31(k1 << 8), bytes17(k2), stake));
            } else {
                if ((hint + 1) * REGISTRY_ENTRY > registry.length) revert InvalidValidatorEntry();
                uint256 rid;
                assembly ("memory-safe") {
                    rid := shr(192, mload(add(add(registry, 0x20), mul(hint, 89))))
                }
                if (rid != id) revert InvalidValidatorEntry();
                acc = _foldRegistry(acc, registry, hint, stake);
            }
        }
        a.pendingAcc = acc;
        // forge-lint: disable-next-line(unsafe-typecast)
        a.pendingProven = uint64(first + count);
        return a;
    }

    /// @dev acc' = keccak256(acc || secp33 || bls48 || stake32) with the keys taken from registry entry `j`.
    function _foldRegistry(bytes32 acc, bytes memory registry, uint256 j, uint256 stake)
        private
        pure
        returns (bytes32 out)
    {
        assembly ("memory-safe") {
            let buf := mload(0x40)
            mstore(buf, acc)
            mcopy(add(buf, 32), add(add(add(registry, 0x20), mul(j, 89)), 8), 81)
            mstore(add(buf, 113), stake)
            out := keccak256(buf, 145)
        }
    }

    /// @dev finalize = [sortedBlob, permutation, ids]: the full set in BTreeMap order (ascending compressed
    ///      secp key — `secp256k1_ec_pubkey_cmp`), each entry secp33 || G1 key 128 || stake32, and for
    ///      each sorted entry its index in valset_consensus (2 bytes each). Recomputes the array-order
    ///      accumulator from the sorted entries (compressing each G1 key) and, on a match, installs the
    ///      new validator set and its key registry (array order).
    function finalize(bytes calldata finRlp, Anchor memory a) external view returns (Anchor memory) {
        Memory.Slice[] memory fz = RLP.decodeList(finRlp);
        if (fz.length != 3) revert InvalidProofShape();
        bytes memory ids = RLP.readBytes(fz[2]);
        if (keccak256(ids) != a.pendingIds) revert RotationStateInvalid();
        uint256 n = a.pendingLength;
        if (a.pendingProven != n) revert RotationIncomplete();
        bytes memory sorted = RLP.readBytes(fz[0]);
        bytes memory perm = RLP.readBytes(fz[1]);
        if (sorted.length != n * SORTED_ENTRY || perm.length != n * 2) revert InvalidPermutation();

        // inv[arrayIndex] = sortedIndex; check strict secp ordering on the way.
        uint256[] memory inv = new uint256[](n);
        uint256 used;
        uint256 prevHi;
        uint256 prevLo;
        for (uint256 k = 0; k < n; ++k) {
            uint256 idx = (uint256(uint8(perm[2 * k])) << 8) | uint8(perm[2 * k + 1]);
            if (idx >= n || (used >> idx) & 1 == 1) revert InvalidPermutation();
            used |= uint256(1) << idx;
            inv[idx] = k;
            (uint256 hi, uint256 lo) = _secpKey(sorted, k);
            if (k > 0 && (hi < prevHi || (hi == prevHi && lo <= prevLo))) revert ValidatorOrder();
            prevHi = hi;
            prevLo = lo;
        }

        bytes32 acc;
        bytes memory registry = new bytes(n * REGISTRY_ENTRY);
        for (uint256 i = 0; i < n; ++i) {
            uint256 off = inv[i] * SORTED_ENTRY;
            bytes memory pk = new bytes(128);
            bytes32 secpA;
            bytes1 secpB;
            uint256 stake;
            assembly ("memory-safe") {
                let e := add(add(sorted, 0x20), off)
                secpA := mload(e)
                secpB := and(mload(add(e, 32)), shl(248, 0xff))
                mcopy(add(pk, 0x20), add(e, 33), 128)
                stake := mload(add(e, 161))
            }
            bytes memory blsC = ClprBls12381.compressG1(pk);
            acc = keccak256(abi.encodePacked(acc, secpA, secpB, blsC, stake));
            assembly ("memory-safe") {
                let r := add(add(registry, 0x20), mul(i, 89))
                mcopy(r, add(add(ids, 0x20), mul(i, 8)), 8)
                mstore(add(r, 8), secpA)
                mstore8(add(r, 40), shr(248, secpB))
                mcopy(add(r, 41), add(blsC, 0x20), 48)
            }
            // On-curve check (BLS12_G1ADD validates both inputs): with the x/sign binding above this fixes
            // the uncompressed key uniquely.
            MonadBls.g1Add(pk, new bytes(128));
        }
        if (acc != a.pendingAcc) revert RotationAccumulatorMismatch();

        bytes memory blob = new bytes(n * 160); // bundle format: G1 key 128 || stake 32
        for (uint256 k = 0; k < n; ++k) {
            assembly ("memory-safe") {
                let e := add(add(sorted, 0x20), mul(k, 193))
                mcopy(add(add(blob, 0x20), mul(k, 160)), add(e, 33), 160)
            }
        }
        a.epoch = a.pendingEpoch;
        a.valsetHash = keccak256(blob);
        a.keysHash = keccak256(registry);
        a.pendingEpoch = 0;
        a.pendingBlock = 0;
        a.stakingRoot = bytes32(0);
        a.serviceRoot = bytes32(0);
        a.pendingLength = 0;
        a.pendingProven = 0;
        a.pendingAcc = bytes32(0);
        a.pendingIds = bytes32(0);
        return a;
    }

    function _secpKey(bytes memory sorted, uint256 k) private pure returns (uint256 hi, uint256 lo) {
        assembly ("memory-safe") {
            let e := add(add(sorted, 0x20), mul(k, 193))
            hi := mload(e)
            lo := byte(0, mload(add(e, 32)))
        }
    }
}
