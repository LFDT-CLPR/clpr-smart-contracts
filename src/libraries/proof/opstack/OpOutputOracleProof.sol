// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title OpOutputOracleProof
/// @notice Proves, from an authenticated Ethereum L1 `state_root`, that an L2 output root is posted in an
///         output-oracle contract — an append-only `OutputProposal[] l2Outputs` array, each element
///         `{bytes32 outputRoot; uint128 timestamp; uint128 l2BlockNumber}`, where `timestamp` is the L1
///         time the output was posted. The settlement contracts of this shape are:
///
///         - `L2OutputOracle` (OP Stack before fault proofs; Blast): a permissioned proposer posts, a
///           challenger may delete outputs (`deleteL2Outputs` truncates the array length) until
///           `FINALIZATION_PERIOD_SECONDS` (an implementation immutable) has passed.
///         - `OPSuccinctL2OutputOracle` (Mantle): every post carries an SP1 validity proof unless the
///           oracle is in optimistic mode; deletion and finalization as above, the period in storage.
///         - `AggchainFEP` (Polygon AggLayer, Katana): the AgglayerManager appends an output only after
///           verifying the pessimistic proof that wraps the chain's OP Succinct FEP proof; there is no
///           deletion, so an output is final once posted (period 0), unless optimistic mode is on.
///
///         Accepted at index `i`, in the proven L1 state:
///           `i < l2Outputs.length` (not deleted) and `l2Outputs[i].outputRoot == outputRoot`;
///           the oracle's EIP-1967 implementation has the pinned code hash;
///           if the profile has an optimistic-mode flag, it is clear;
///           FINALIZED only: `l1Time > l2Outputs[i].timestamp + finalizationPeriod` — exactly the
///           `OptimismPortal._isFinalizationPeriodElapsed` rule the chain's own withdrawals use.
///
/// @dev Every slot is derived here from the profile (data), never read from the proof. Facts held in
///      implementation immutables (Blast's `FINALIZATION_PERIOD_SECONDS`) are bound by the pinned
///      implementation code hash: an upgrade makes verification revert instead of mis-reading state.
library OpOutputOracleProof {
    // ── Oracle proof RLP layout ──────────────────────────────────────────────
    // [outputIndex, oracleAccountProof, oracleStorageProof, oracleImplAccountProof]
    uint256 internal constant ORACLE_PROOF_FIELDS = 4;
    uint256 internal constant OP_IDX_OUTPUT_INDEX = 0;
    uint256 internal constant OP_IDX_ORACLE_ACCOUNT = 1;
    uint256 internal constant OP_IDX_ORACLE_STORAGE = 2;
    uint256 internal constant OP_IDX_IMPL_ACCOUNT = 3;

    /// @dev EIP-1967 implementation slot (`bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)`).
    bytes32 internal constant EIP1967_IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /// @dev Output indices are array positions; anything this large is malformed (and keeps
    ///      `base + 2·index` far from wrapping).
    uint256 internal constant MAX_OUTPUT_INDEX = type(uint64).max;

    /// @notice Where the finalization period comes from.
    enum PeriodSource {
        /// A value fixed by the implementation's code (an immutable, or 0 where outputs cannot be
        /// deleted); the pinned implementation code hash binds it.
        IMMUTABLE,
        /// A storage variable of the oracle, read at the proven L1 state.
        STORAGE
    }

    /// @notice The chain being verified. Values per chain are listed in the oracle README.
    struct Profile {
        address oracle; // the oracle proxy
        bytes32 oracleImplCodeHash; // pinned code hash of its EIP-1967 implementation
        uint256 outputsSlot; // `l2Outputs` (dynamic array base)
        PeriodSource periodSource;
        uint256 finalizationPeriodSeconds; // IMMUTABLE source only
        uint256 finalizationPeriodSlot; // STORAGE source only
        bool hasOptimisticMode; // the oracle has an `optimisticMode` flag that must be clear
        uint256 optimisticModeSlot;
        uint256 optimisticModeOffset; // byte offset of the bool in its slot
    }

    /// @notice The proven output proposal.
    struct Output {
        uint256 index;
        uint128 l1Timestamp;
        uint128 l2BlockNumber;
    }

    error InvalidOracleProof();
    error OracleImplMismatch(address implementation, bytes32 codeHash);
    error OutputNotPosted(uint256 index, uint256 length);
    error OutputRootMismatch(uint256 index, bytes32 posted, bytes32 claimed);
    error OptimisticModeEnabled();
    error OutputNotFinalized(uint256 index, uint256 postedAt, uint256 l1Time, uint256 finalizationPeriodSeconds);

    /// @notice Prove that `outputRoot` is posted (and, unless `acceptProposed`, final) in the oracle of
    ///         profile `p`, in the L1 state `l1StateRoot` whose wall-clock time is `l1Time`.
    /// @param oracleProofItem RLP `[outputIndex, oracleAccountProof, oracleStorageProof,
    ///        oracleImplAccountProof]`; the storage proof carries the slots {slotsFor} lists (extra entries
    ///        are ignored).
    function verify(
        Profile memory p,
        Memory.Slice oracleProofItem,
        bytes32 l1StateRoot,
        uint64 l1Time,
        bytes32 outputRoot,
        bool acceptProposed
    ) internal pure returns (Output memory out) {
        Memory.Slice[] memory op = RLP.readList(oracleProofItem);
        if (op.length != ORACLE_PROOF_FIELDS) revert InvalidOracleProof();
        out.index = RLP.readUint256(op[OP_IDX_OUTPUT_INDEX]);
        if (out.index > MAX_OUTPUT_INDEX) revert InvalidOracleProof();

        (bytes32 storageRoot,) = _account(op[OP_IDX_ORACLE_ACCOUNT], l1StateRoot, p.oracle);
        bytes32[] memory v = ClprEvmStateProof.verifyProvenSlots(
            RLP.readList(op[OP_IDX_ORACLE_STORAGE]), storageRoot, slotsFor(p, out.index)
        );

        // [1] implementation → pinned code hash (fixes the semantics and any immutable period).
        address impl = address(uint160(uint256(v[1])));
        (, bytes32 implCodeHash) = _account(op[OP_IDX_IMPL_ACCOUNT], l1StateRoot, impl);
        if (implCodeHash != p.oracleImplCodeHash) revert OracleImplMismatch(impl, implCodeHash);

        // [0] length: deleteL2Outputs truncates it and leaves the old elements in storage, so an element
        //     at or past the length is a deleted (or never posted) output.
        uint256 length = uint256(v[0]);
        if (out.index >= length) revert OutputNotPosted(out.index, length);
        // [2] outputRoot, [3] timestamp (low 128) | l2BlockNumber (high 128).
        if (v[2] != outputRoot) revert OutputRootMismatch(out.index, v[2], outputRoot);
        // forge-lint: disable-next-line(unsafe-typecast)
        out.l1Timestamp = uint128(uint256(v[3]));
        // forge-lint: disable-next-line(unsafe-typecast)
        out.l2BlockNumber = uint128(uint256(v[3]) >> 128);

        uint256 next = 4;
        uint256 period = p.finalizationPeriodSeconds;
        if (p.periodSource == PeriodSource.STORAGE) period = uint256(v[next++]);
        if (p.hasOptimisticMode && uint8(uint256(v[next]) >> (p.optimisticModeOffset * 8)) != 0) {
            revert OptimisticModeEnabled();
        }
        if (acceptProposed) return out;

        // OptimismPortal._isFinalizationPeriodElapsed: block.timestamp > timestamp + period.
        if (uint256(l1Time) <= uint256(out.l1Timestamp) + period) {
            revert OutputNotFinalized(out.index, out.l1Timestamp, l1Time, period);
        }
    }

    /// @notice The oracle slots a proof of output `index` must carry, in this order:
    ///         `[length, implementation, outputRoot, timestamp|l2BlockNumber, (period), (optimisticMode)]`.
    function slotsFor(Profile memory p, uint256 index) internal pure returns (bytes32[] memory slots) {
        uint256 n = 4 + (p.periodSource == PeriodSource.STORAGE ? 1 : 0) + (p.hasOptimisticMode ? 1 : 0);
        slots = new bytes32[](n);
        uint256 element = uint256(keccak256(abi.encode(p.outputsSlot))) + 2 * index;
        slots[0] = bytes32(p.outputsSlot);
        slots[1] = EIP1967_IMPLEMENTATION_SLOT;
        slots[2] = bytes32(element);
        slots[3] = bytes32(element + 1);
        uint256 next = 4;
        if (p.periodSource == PeriodSource.STORAGE) slots[next++] = bytes32(p.finalizationPeriodSlot);
        if (p.hasOptimisticMode) slots[next] = bytes32(p.optimisticModeSlot);
    }

    function _account(Memory.Slice accountProofItem, bytes32 stateRoot, address account)
        private
        pure
        returns (bytes32 storageRoot, bytes32 codeHash)
    {
        return ClprEvmStateProof.decodeAccount(ClprEvmStateProof.verifyAccount(accountProofItem, stateRoot, account));
    }
}
