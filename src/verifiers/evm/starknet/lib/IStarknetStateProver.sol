// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title IStarknetStateProver
/// @notice Stateless Starknet state-commitment prover: contract storage under a global state root.
interface IStarknetStateProver {
    /// @notice Prove `keys` of `contractAddress`'s storage under the Starknet global state root.
    /// @param globalRoot the Starknet state commitment (the core contract's `stateRoot()`).
    /// @param contractAddress the Starknet contract (felt, < 2²⁵¹).
    /// @param keys storage addresses (felts, < 2²⁵¹), derived by the caller.
    /// @param proof `abi.encode(contractsTreeRoot, classesTreeRoot, classHash, storageRoot, nonce,
    ///        uint256[] contractNodes, uint256[] storageNodes)`; nodes flattened 3 words each (see
    ///        {StarknetPatricia}).
    /// @return classHash the contract's class hash (from the proven contract leaf).
    /// @return nonce the contract's nonce.
    /// @return values the proven storage values, 0 for proven-absent keys.
    function verifyStorage(uint256 globalRoot, uint256 contractAddress, uint256[] calldata keys, bytes calldata proof)
        external
        view
        returns (uint256 classHash, uint256 nonce, uint256[] memory values);

    /// @notice Cairo `Map` entry address: Pedersen chain of `keyFelts` from `base`, mod 2²⁵¹ − 256.
    function mapAddress(uint256 base, uint256[] calldata keyFelts) external view returns (uint256);

    /// @notice Starknet Pedersen H(a, b).
    function pedersen(uint256 a, uint256 b) external view returns (uint256);

    /// @notice Starknet poseidon_hash_many.
    function poseidonHashMany(uint256[] calldata xs) external pure returns (uint256);

    /// @notice The global state root formula: 0 if both roots are 0, else
    ///         Poseidon('STARKNET_STATE_V0', contractsTreeRoot, classesTreeRoot).
    function globalStateRoot(uint256 contractsTreeRoot, uint256 classesTreeRoot) external pure returns (uint256);
}
