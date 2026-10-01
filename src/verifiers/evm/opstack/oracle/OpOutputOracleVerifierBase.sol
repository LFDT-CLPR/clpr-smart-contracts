// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {OpStackBundleVerifierBase} from "@hiero-ledger/clpr/verifiers/evm/opstack/OpStackBundleVerifierBase.sol";
import {IEthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/lib/IEthL1StateVerifier.sol";
import {OpOutputOracleProof} from "@hiero-ledger/clpr/libraries/proof/opstack/OpOutputOracleProof.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title OpOutputOracleVerifierBase
/// @notice CLPR verifier for OP-Stack-derived L2s whose L1 settlement contract is an output-oracle array
///         rather than dispute games: Blast (`L2OutputOracle`), Mantle (`OPSuccinctL2OutputOracle`) and
///         Katana (Polygon AggLayer `AggchainFEP`) — see README. Steps 1, 3 and 4 are
///         {OpStackBundleVerifierBase}'s; step 2 is {OpOutputOracleProof.verify}:
///
///         L1 `state_root` → oracle account → `l2Outputs.length`, `l2Outputs[i]`, the implementation
///         (code hash pinned), the finalization period and the optimistic-mode flag → accepted output root.
///
///         Bundle item 1 is the oracle proof `[outputIndex, oracleAccountProof, oracleStorageProof,
///         oracleImplAccountProof]`.
///
/// @dev The L2 account leaf layout is data too: Ethereum's `[nonce, balance, storageRoot, codeHash]`
///      on Mantle and Katana, and Blast's 7-field `[nonce, flags, fixed, shares, remainder, storageRoot,
///      codeHash]` (blast-geth `types.StateAccount`, which carries the yield-share balance).
abstract contract OpOutputOracleVerifierBase is OpStackBundleVerifierBase {
    /// @notice RLP shape of an L2 account leaf.
    struct L2AccountFormat {
        uint256 fields;
        uint256 storageRootIndex;
        uint256 codeHashIndex;
    }

    // Profile (see {OpOutputOracleProof.Profile}); immutables, rebuilt in memory per call.
    address public immutable ORACLE;
    bytes32 public immutable ORACLE_IMPL_CODE_HASH;
    uint256 public immutable OUTPUTS_SLOT;
    OpOutputOracleProof.PeriodSource public immutable PERIOD_SOURCE;
    uint256 public immutable FINALIZATION_PERIOD_SECONDS;
    uint256 public immutable FINALIZATION_PERIOD_SLOT;
    bool public immutable HAS_OPTIMISTIC_MODE;
    uint256 public immutable OPTIMISTIC_MODE_SLOT;
    uint256 public immutable OPTIMISTIC_MODE_OFFSET;

    uint256 public immutable L2_ACCOUNT_FIELDS;
    uint256 public immutable L2_ACCOUNT_STORAGE_ROOT_INDEX;
    uint256 public immutable L2_ACCOUNT_CODE_HASH_INDEX;

    error InvalidL2Account();

    constructor(
        Finality finality,
        IEthL1StateVerifier l1StateVerifier,
        uint64 l1GenesisTime,
        uint64 l1SecondsPerSlot,
        OpOutputOracleProof.Profile memory profile_,
        L2AccountFormat memory accountFormat
    ) OpStackBundleVerifierBase(finality, l1StateVerifier, l1GenesisTime, l1SecondsPerSlot) {
        if (
            profile_.oracle == address(0) || profile_.oracleImplCodeHash == bytes32(0)
                || profile_.optimisticModeOffset > 31 || accountFormat.storageRootIndex >= accountFormat.fields
                || accountFormat.codeHashIndex >= accountFormat.fields
                || accountFormat.storageRootIndex == accountFormat.codeHashIndex
        ) revert InvalidDeployment();
        ORACLE = profile_.oracle;
        ORACLE_IMPL_CODE_HASH = profile_.oracleImplCodeHash;
        OUTPUTS_SLOT = profile_.outputsSlot;
        PERIOD_SOURCE = profile_.periodSource;
        FINALIZATION_PERIOD_SECONDS = profile_.finalizationPeriodSeconds;
        FINALIZATION_PERIOD_SLOT = profile_.finalizationPeriodSlot;
        HAS_OPTIMISTIC_MODE = profile_.hasOptimisticMode;
        OPTIMISTIC_MODE_SLOT = profile_.optimisticModeSlot;
        OPTIMISTIC_MODE_OFFSET = profile_.optimisticModeOffset;
        L2_ACCOUNT_FIELDS = accountFormat.fields;
        L2_ACCOUNT_STORAGE_ROOT_INDEX = accountFormat.storageRootIndex;
        L2_ACCOUNT_CODE_HASH_INDEX = accountFormat.codeHashIndex;
    }

    /// @notice The deployment's settlement profile.
    function profile() public view returns (OpOutputOracleProof.Profile memory p) {
        p.oracle = ORACLE;
        p.oracleImplCodeHash = ORACLE_IMPL_CODE_HASH;
        p.outputsSlot = OUTPUTS_SLOT;
        p.periodSource = PERIOD_SOURCE;
        p.finalizationPeriodSeconds = FINALIZATION_PERIOD_SECONDS;
        p.finalizationPeriodSlot = FINALIZATION_PERIOD_SLOT;
        p.hasOptimisticMode = HAS_OPTIMISTIC_MODE;
        p.optimisticModeSlot = OPTIMISTIC_MODE_SLOT;
        p.optimisticModeOffset = OPTIMISTIC_MODE_OFFSET;
    }

    /// @notice Step 2 alone, for relayers and monitoring: the output proposal `oracleProof` proves for
    ///         `outputRoot` in the L1 state `l1StateRoot` at time `l1Time`, at this deployment's tier.
    function verifyOutput(bytes calldata oracleProof, bytes32 l1StateRoot, uint64 l1Time, bytes32 outputRoot)
        external
        view
        returns (OpOutputOracleProof.Output memory)
    {
        bytes memory proofMem = oracleProof;
        return OpOutputOracleProof.verify(
            profile(), Memory.asSlice(proofMem), l1StateRoot, l1Time, outputRoot, FINALITY == Finality.PROPOSED
        );
    }

    /// @inheritdoc OpStackBundleVerifierBase
    function _verifyOutputRoot(Memory.Slice oracleProof, bytes32 l1StateRoot, uint64 l1Time, bytes32 outputRoot)
        internal
        view
        override
    {
        OpOutputOracleProof.verify(
            profile(), oracleProof, l1StateRoot, l1Time, outputRoot, FINALITY == Finality.PROPOSED
        );
    }

    /// @inheritdoc OpStackBundleVerifierBase
    function _verifyL2ServiceStorageRoot(
        Memory.Slice accountProofItem,
        bytes32 l2StateRoot,
        address service,
        bytes32 expectedCodeHash
    ) internal view override returns (bytes32 storageRoot) {
        Memory.Slice[] memory fields =
            RLP.decodeList(ClprEvmStateProof.verifyAccount(accountProofItem, l2StateRoot, service));
        if (fields.length != L2_ACCOUNT_FIELDS) revert InvalidL2Account();
        storageRoot = RLP.readBytes32(fields[L2_ACCOUNT_STORAGE_ROOT_INDEX]);
        bytes32 codeHash = RLP.readBytes32(fields[L2_ACCOUNT_CODE_HASH_INDEX]);
        if (expectedCodeHash != bytes32(0) && codeHash != expectedCodeHash) revert CodeHashMismatch();
    }
}
