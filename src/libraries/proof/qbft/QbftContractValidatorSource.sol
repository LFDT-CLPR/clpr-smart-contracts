// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {ClprQbftQuorum} from "@hiero-ledger/clpr/libraries/proof/qbft/ClprQbftQuorum.sol";
import {QbftValidators, ValidatorSet} from "@hiero-ledger/clpr/libraries/proof/qbft/QbftValidators.sol";

/// @title QbftContractValidatorSource
/// @notice A validator source that reads the set from a validator contract on the source chain.
library QbftContractValidatorSource {
    error InvalidProofShape();
    error EmptyValidatorSet();
    error TooManyValidators(uint256 count);
    error WrongValidatorContract(address got, address expected);
    error WrongArraySlot(bytes32 got, bytes32 expected);
    /// @notice The proven array holds the zero address as a member.
    error ZeroValidator();
    /// @notice The proven array holds duplicates, so its distinct size differs from its length.
    error DuplicateValidator(uint256 proven, uint256 distinct);

    /// @notice Prove the validator set held by a contract and return it.
    /// @dev The proof's contract address and array slot must equal the pinned ones. Without this
    ///      rule, a relay can prove the array of a contract it controls.
    /// @param sourceProof      `RLP([validatorContract, accountProof, arraySlot, storageProof])`.
    /// @param stateRoot        The state root already proven for the block.
    /// @param expectedContract The validator contract the trust anchor pins.
    /// @param expectedSlot     The array slot the trust anchor pins.
    /// @return set             The proven validator set, sorted ascending and deduped.
    function resolveSet(bytes memory sourceProof, bytes32 stateRoot, address expectedContract, bytes32 expectedSlot)
        internal
        pure
        returns (ValidatorSet memory set)
    {
        Memory.Slice[] memory p = RLP.decodeList(sourceProof);
        if (p.length != 4) revert InvalidProofShape();
        address validatorContract = RLP.readAddress(p[0]);
        bytes32 arraySlot = RLP.readBytes32(p[2]);
        if (validatorContract != expectedContract) revert WrongValidatorContract(validatorContract, expectedContract);
        if (arraySlot != expectedSlot) revert WrongArraySlot(arraySlot, expectedSlot);

        // 1. Account proof: state root -> the contract's storage root.
        bytes memory accountRlp = ClprEvmStateProof.verifyAccount(p[1], stateRoot, validatorContract);
        (bytes32 storageRoot,) = ClprEvmStateProof.decodeAccount(accountRlp);

        Memory.Slice[] memory entries = RLP.readList(p[3]);

        // 2. Prove the array length. The array slot holds the count.
        bytes32[] memory lengthSlot = new bytes32[](1);
        lengthSlot[0] = arraySlot;
        uint256 n = uint256(ClprEvmStateProof.verifyProvenSlots(entries, storageRoot, lengthSlot)[0]);
        if (n == 0) revert EmptyValidatorSet();
        if (n > ClprQbftQuorum.MAX_VALIDATORS) revert TooManyValidators(n);

        // 3. Prove each element. Element i is at keccak256(arraySlot) + i.
        bytes32 base = keccak256(abi.encodePacked(arraySlot));
        bytes32[] memory elementSlots = new bytes32[](n);
        for (uint256 i = 0; i < n;) {
            elementSlots[i] = bytes32(uint256(base) + i);
            unchecked {
                i++;
            }
        }
        bytes32[] memory values = ClprEvmStateProof.verifyProvenSlots(entries, storageRoot, elementSlots);

        address[] memory members = new address[](n);
        for (uint256 i = 0; i < n;) {
            // forge-lint: disable-next-line(unsafe-typecast)
            address member = address(uint160(uint256(values[i])));
            if (member == address(0)) revert ZeroValidator();
            members[i] = member;
            unchecked {
                i++;
            }
        }
        set.members = QbftValidators.sortedDedup(members);
        if (set.members.length != n) revert DuplicateValidator(n, set.members.length);
    }
}
