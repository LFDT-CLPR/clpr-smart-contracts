// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IStarknetStateProver} from "@hiero-ledger/clpr/verifiers/evm/starknet/lib/IStarknetStateProver.sol";
import {StarkPedersen} from "@hiero-ledger/clpr/libraries/proof/starknet/StarkPedersen.sol";
import {StarkPoseidon} from "@hiero-ledger/clpr/libraries/proof/starknet/StarkPoseidon.sol";
import {StarknetPatricia} from "@hiero-ledger/clpr/libraries/proof/starknet/StarknetPatricia.sol";
import {StarkTables} from "@hiero-ledger/clpr/libraries/proof/starknet/StarkTables.sol";

/// @title StarknetStateProver
/// @notice Deployed, stateless prover for Starknet's state commitment (Starknet docs "State";
///         sequencer `apollo_starknet_os_program/.../os/state/commitment.cairo`):
///
///           global root   = 0 if both tries are empty, else
///                           Poseidon('STARKNET_STATE_V0', contractsTreeRoot, classesTreeRoot)
///           contract leaf = H(H(H(classHash, storageRoot), nonce), 0)        (H = Pedersen)
///           storage leaf  = the stored felt
///
///         One call proves a contract's leaf in the contract trie and any number of its storage keys.
/// @dev Separate from the CLPR verifier so the hashing code and the Poseidon constants (~9 KB) stay out
///      of it; the Pedersen tables are two more data contracts whose code hashes are pinned here.
contract StarknetStateProver is IStarknetStateProver {
    uint256 internal constant P = 0x0800000000000011000000000000000000000000000000000000000000000001;
    uint256 internal constant ADDR_BOUND = (1 << 251) - 256;
    /// @dev Cairo short string 'STARKNET_STATE_V0'.
    uint256 internal constant STARKNET_STATE_V0 = 0x535441524b4e45545f53544154455f5630;

    address public immutable PEDERSEN_TABLE_A;
    address public immutable PEDERSEN_TABLE_B;

    error InvalidPedersenTables();
    error GlobalRootMismatch(uint256 expected, uint256 computed);
    error ContractNotInState(uint256 contractAddress);
    error ContractLeafMismatch(uint256 leaf, uint256 computed);

    constructor(address tableA, address tableB) {
        if (tableA.codehash != StarkTables.TABLE_A_CODEHASH || tableB.codehash != StarkTables.TABLE_B_CODEHASH) {
            revert InvalidPedersenTables();
        }
        PEDERSEN_TABLE_A = tableA;
        PEDERSEN_TABLE_B = tableB;
    }

    /// @inheritdoc IStarknetStateProver
    function verifyStorage(uint256 globalRoot, uint256 contractAddress, uint256[] calldata keys, bytes calldata proof)
        external
        view
        returns (uint256 classHash, uint256 nonce, uint256[] memory values)
    {
        (
            uint256 contractsRoot,
            uint256 classesRoot,
            uint256 classHash_,
            uint256 storageRoot,
            uint256 nonce_,
            uint256[] memory contractNodes,
            uint256[] memory storageNodes
        ) = abi.decode(proof, (uint256, uint256, uint256, uint256, uint256, uint256[], uint256[]));
        classHash = classHash_;
        nonce = nonce_;

        uint256 computed = _globalStateRoot(contractsRoot, classesRoot);
        if (computed != globalRoot) revert GlobalRootMismatch(globalRoot, computed);

        uint256 t = StarkPedersen.loadTables(PEDERSEN_TABLE_A, PEDERSEN_TABLE_B);
        uint256 leaf = StarknetPatricia.get(
            contractNodes, StarknetPatricia.hashNodes(t, contractNodes), contractsRoot, contractAddress
        );
        if (leaf == 0) revert ContractNotInState(contractAddress);
        uint256 expectedLeaf =
            StarkPedersen.hash(t, StarkPedersen.hash(t, StarkPedersen.hash(t, classHash, storageRoot), nonce), 0);
        if (leaf != expectedLeaf) revert ContractLeafMismatch(leaf, expectedLeaf);

        uint256[] memory storageHashes = StarknetPatricia.hashNodes(t, storageNodes);
        values = new uint256[](keys.length);
        for (uint256 i = 0; i < keys.length; i++) {
            values[i] = StarknetPatricia.get(storageNodes, storageHashes, storageRoot, keys[i]);
        }
    }

    /// @inheritdoc IStarknetStateProver
    function mapAddress(uint256 base, uint256[] calldata keyFelts) external view returns (uint256 h) {
        h = base;
        uint256 t = StarkPedersen.loadTables(PEDERSEN_TABLE_A, PEDERSEN_TABLE_B);
        for (uint256 i = 0; i < keyFelts.length; i++) {
            h = StarkPedersen.hash(t, h, keyFelts[i]);
        }
        // storage_base_address_from_felt252 wraps into [0, 2^251 - 256).
        h %= ADDR_BOUND;
    }

    /// @inheritdoc IStarknetStateProver
    function pedersen(uint256 a, uint256 b) external view returns (uint256) {
        return StarkPedersen.hash(StarkPedersen.loadTables(PEDERSEN_TABLE_A, PEDERSEN_TABLE_B), a, b);
    }

    /// @inheritdoc IStarknetStateProver
    function poseidonHashMany(uint256[] calldata xs) external pure returns (uint256) {
        return StarkPoseidon.hashMany(xs);
    }

    /// @inheritdoc IStarknetStateProver
    function globalStateRoot(uint256 contractsTreeRoot, uint256 classesTreeRoot) external pure returns (uint256) {
        return _globalStateRoot(contractsTreeRoot, classesTreeRoot);
    }

    function _globalStateRoot(uint256 contractsRoot, uint256 classesRoot) internal pure returns (uint256) {
        if (contractsRoot == 0 && classesRoot == 0) return 0;
        uint256[] memory xs = new uint256[](3);
        xs[0] = STARKNET_STATE_V0;
        xs[1] = contractsRoot;
        xs[2] = classesRoot;
        return StarkPoseidon.hashMany(xs);
    }
}
