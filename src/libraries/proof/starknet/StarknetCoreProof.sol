// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title StarknetCoreProof
/// @notice Reads the Starknet core contract's state out of an authenticated Ethereum `state_root`.
///
///         The core contract (`Starknet.sol`, cairo-lang `src/starkware/starknet/solidity/`) sits behind
///         a StarkWare `Proxy` and keeps `StarknetState.State {globalRoot, blockNumber, blockHash}` at
///         slot keccak256("STARKNET_1.0_INIT_STARKNET_STATE_STRUCT"). `updateState`/`updateStateKzgDA`
///         only write it after `IFactRegistry(verifier()).isValid(keccak(programHash, fact))`, i.e. after
///         the SHARP/STARK verifier accepted a proof of the Starknet OS run from the previous root, so
///         the stored `globalRoot` is a validity-proven Starknet state commitment of block `blockNumber`.
///
///         What governance can change without delay (upgrade delay is 0 on Sepolia and mainnet) — the
///         proxy implementation, `programHash`, `aggregatorProgramHash`, `configHash` — can be pinned:
///         the implementation by code hash, the rest as raw slot values (see {verify}).
/// @dev Proof item: RLP `[coreAccountProof, coreStorageProof, implAccountProof]`, where the storage
///      proof carries entries for globalRoot (STATE), blockNumber (STATE+1), the proxy implementation
///      slot, then every pinned slot. `implAccountProof` may be empty when no implementation is pinned.
library StarknetCoreProof {
    /// @dev keccak256("STARKNET_1.0_INIT_STARKNET_STATE_STRUCT").
    bytes32 internal constant STATE_SLOT = 0x71a8ef1b1265359d77973c3524afac225c0a0d829a0d4da5cac3b34532019fec;
    /// @dev keccak256("StarkWare2019.implemntation-slot") (sic) — StarkWare `Proxy` (starkex-contracts
    ///      `StorageSlots.sol`).
    bytes32 internal constant IMPLEMENTATION_SLOT = 0x177667240aeeea7e35eabe3a35e18306f336219e1386f7710a6bf8783f761b24;
    /// @dev keccak256("STARKNET_1.0_INIT_PROGRAM_HASH_UINT").
    bytes32 internal constant PROGRAM_HASH_SLOT = keccak256("STARKNET_1.0_INIT_PROGRAM_HASH_UINT");
    /// @dev keccak256("STARKNET_1.0_INIT_AGGREGATOR_PROGRAM_HASH_UINT").
    bytes32 internal constant AGGREGATOR_PROGRAM_HASH_SLOT =
        keccak256("STARKNET_1.0_INIT_AGGREGATOR_PROGRAM_HASH_UINT");
    /// @dev keccak256("STARKNET_1.0_INIT_VERIFIER_ADDRESS").
    bytes32 internal constant VERIFIER_ADDRESS_SLOT = keccak256("STARKNET_1.0_INIT_VERIFIER_ADDRESS");
    /// @dev keccak256("STARKNET_1.0_STARKNET_CONFIG_HASH").
    bytes32 internal constant CONFIG_HASH_SLOT = keccak256("STARKNET_1.0_STARKNET_CONFIG_HASH");

    uint256 internal constant PROOF_FIELDS = 3;
    uint256 internal constant FIXED_SLOTS = 3;

    struct CoreState {
        /// Starknet global state root (state commitment).
        uint256 globalRoot;
        /// Starknet block number the root is for.
        uint256 blockNumber;
        /// The proxy's implementation.
        address implementation;
    }

    error InvalidCoreProof();
    error StarknetNotInitialized();
    error CoreImplementationMismatch(address implementation, bytes32 codeHash);
    error CorePinnedSlotMismatch(bytes32 slot, bytes32 value);

    /// @notice Verify the core contract's state at `l1StateRoot`.
    /// @param implCodeHash pinned implementation code hash; zero = not pinned.
    /// @param pinnedSlots core-contract slots whose values must equal `pinnedValues`.
    function verify(
        Memory.Slice item,
        bytes32 l1StateRoot,
        address core,
        bytes32 implCodeHash,
        bytes32[] memory pinnedSlots,
        bytes32[] memory pinnedValues
    ) internal pure returns (CoreState memory s) {
        Memory.Slice[] memory p = RLP.readList(item);
        if (p.length != PROOF_FIELDS) revert InvalidCoreProof();

        (bytes32 storageRoot,) =
            ClprEvmStateProof.decodeAccount(ClprEvmStateProof.verifyAccount(p[0], l1StateRoot, core));
        bytes32[] memory slots = new bytes32[](FIXED_SLOTS + pinnedSlots.length);
        slots[0] = STATE_SLOT;
        slots[1] = bytes32(uint256(STATE_SLOT) + 1);
        slots[2] = IMPLEMENTATION_SLOT;
        for (uint256 i = 0; i < pinnedSlots.length; i++) {
            slots[FIXED_SLOTS + i] = pinnedSlots[i];
        }
        bytes32[] memory v = ClprEvmStateProof.verifyProvenSlots(RLP.readList(p[1]), storageRoot, slots);

        // int256 blockNumber: -1 before the first state update.
        if (int256(uint256(v[1])) < 0) revert StarknetNotInitialized();
        s.globalRoot = uint256(v[0]);
        s.blockNumber = uint256(v[1]);
        s.implementation = address(uint160(uint256(v[2])));

        if (implCodeHash != bytes32(0)) {
            (, bytes32 codeHash) =
                ClprEvmStateProof.decodeAccount(ClprEvmStateProof.verifyAccount(p[2], l1StateRoot, s.implementation));
            if (codeHash != implCodeHash) revert CoreImplementationMismatch(s.implementation, codeHash);
        }
        for (uint256 i = 0; i < pinnedSlots.length; i++) {
            if (v[FIXED_SLOTS + i] != pinnedValues[i]) {
                revert CorePinnedSlotMismatch(pinnedSlots[i], v[FIXED_SLOTS + i]);
            }
        }
    }
}
