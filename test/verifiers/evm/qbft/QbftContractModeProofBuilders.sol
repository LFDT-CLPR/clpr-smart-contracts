// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {QbftContractProofs} from "@test/helpers/QbftContractProofs.sol";

abstract contract QbftContractModeProofBuilders is QbftContractProofs {
    address internal constant SERVICE_ADDR = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;
    bytes32 internal constant SERVICE_CODE_HASH = bytes32(uint256(0xC0DE));
    bytes32 internal constant SYNTHETIC_CHANNEL_ID = bytes32(uint256(0xC0FFEE));
    address internal constant VALIDATOR_CONTRACT = address(0xC04511AC);

    struct CurrentBlock {
        bytes32 arraySlot;
        bytes header;
        bytes svcAccountProof;
        bytes channelProofRlp;
        bytes currentVcProof;
    }

    /// @dev A 3-member set built from key seeds (each member is vm.addr(keccak256(seed))).
    function _set3(string memory s0, string memory s1, string memory s2) internal pure returns (address[] memory s) {
        s = new address[](3);
        s[0] = vm.addr(uint256(keccak256(bytes(s0))));
        s[1] = vm.addr(uint256(keccak256(bytes(s1))));
        s[2] = vm.addr(uint256(keccak256(bytes(s2))));
    }

    /// @dev The two sealer private keys for a 2-of-3 quorum, from the same seeds as _set3.
    function _pks2(string memory s0, string memory s1) internal pure returns (uint256[] memory p) {
        p = new uint256[](2);
        p[0] = uint256(keccak256(bytes(s0)));
        p[1] = uint256(keccak256(bytes(s1)));
    }

    /// @dev An `n`-member set from one seed: member i is vm.addr(keccak256(seed, i)). A larger `n`
    ///      with the same seed is a superset, so `_setN(seed, n + 1)` models adding one validator.
    function _setN(string memory seed, uint256 n) internal pure returns (address[] memory s) {
        s = new address[](n);
        for (uint256 i = 0; i < n; i++) {
            s[i] = vm.addr(uint256(keccak256(abi.encodePacked(seed, i))));
        }
    }

    /// @dev The first `count` sealer private keys from the same seed sequence as _setN.
    function _pksN(string memory seed, uint256 count) internal pure returns (uint256[] memory p) {
        p = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            p[i] = uint256(keccak256(abi.encodePacked(seed, i)));
        }
    }

    /// @dev ChannelContext matching the storage/account proofs built by _buildChannelStorageProof
    ///      and _buildTwoAccountState (keyed by SYNTHETIC_CHANNEL_ID / SERVICE_ADDR).
    function _syntheticChannelContext() internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({
                channelId: SYNTHETIC_CHANNEL_ID, remoteServiceAddress: abi.encodePacked(SERVICE_ADDR)
            })
        );
    }

    /// @dev A Contract-mode trust anchor:
    ///      abi.encode(mode=1, setCommitment, codeHash, validatorContract, arraySlot, anchorBlockNumber).
    function _contractAnchor(address[] memory validators, address validatorContract, bytes32 arraySlot, uint64 blockNo)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(uint8(1), _commit(validators), SERVICE_CODE_HASH, validatorContract, arraySlot, blockNo);
    }

    /// @dev One rotation hop: the change block at `blockNo` sealed by `sealers`, its state holding `nextSet`.
    function _buildHop(address[] memory nextSet, uint256[] memory sealers, uint64 blockNo)
        internal
        pure
        returns (bytes memory)
    {
        (bytes32 hopStateRoot,, bytes memory hopVcProof) = _validatorContractProof(VALIDATOR_CONTRACT, nextSet);
        return _hop(_buildListedSealedHeader(blockNo, hopStateRoot, new address[](0), sealers), hopVcProof);
    }

    /// @dev The current block at `blockNo`: header sealed by `sealers`, two-account state (service +
    ///      validator contract) whose validator array holds `currentSet`, plus the channel proof.
    function _buildCurrentBlock(address[] memory currentSet, uint256[] memory sealers, uint64 blockNo)
        internal
        pure
        returns (CurrentBlock memory cb)
    {
        bytes32 vcStorageRoot;
        (cb.arraySlot, vcStorageRoot,) = _validatorStorageProof(currentSet);
        bytes32 svcStorageRoot;
        (svcStorageRoot, cb.channelProofRlp) = _buildChannelStorageProof(SYNTHETIC_CHANNEL_ID);
        bytes32 stateRoot;
        bytes memory vcAccountProof;
        (stateRoot, cb.svcAccountProof, vcAccountProof) =
            _buildTwoAccountState(SERVICE_ADDR, svcStorageRoot, SERVICE_CODE_HASH, VALIDATOR_CONTRACT, vcStorageRoot);
        cb.currentVcProof = _wrapVcProof(VALIDATOR_CONTRACT, vcAccountProof, cb.arraySlot, currentSet);
        cb.header = _buildListedSealedHeader(blockNo, stateRoot, new address[](0), sealers);
    }

    /// @dev Assemble the 5-field bundle proof from a current block, a trusted set, and the hops.
    function _topProof(CurrentBlock memory cb, address[] memory trustedSet, bytes[] memory hops)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory top = new bytes[](5);
        top[0] = cb.header;
        top[1] = _contractSourceField(trustedSet, hops, cb.currentVcProof);
        top[2] = cb.svcAccountProof;
        top[3] = cb.channelProofRlp;
        top[4] = RLP.encode(new bytes(0));
        return RLP.encode(top);
    }

    /// @dev An 8-field Contract-mode config proof: descriptor [mode=1, service, codeHash,
    ///      validatorContract, arraySlot], the validator-contract proof at field 5, the header at field 6.
    function _buildContractConfigProof(bytes32 arraySlot, bytes memory vcProof, bytes memory header)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory throttleItems = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            throttleItems[i] = RLP.encode(uint256(0));
        }
        bytes[] memory taItems = new bytes[](5);
        taItems[0] = RLP.encode(uint256(1)); // mode = Contract
        taItems[1] = RLP.encode(abi.encodePacked(SERVICE_ADDR));
        taItems[2] = RLP.encode(SERVICE_CODE_HASH);
        taItems[3] = RLP.encode(VALIDATOR_CONTRACT);
        taItems[4] = RLP.encode(arraySlot);

        bytes[] memory items = new bytes[](8);
        items[0] = RLP.encode(abi.encodePacked(SERVICE_ADDR));
        items[1] = RLP.encode(bytes("eip155:1"));
        items[2] = RLP.encode(uint256(0));
        items[3] = RLP.encode(throttleItems);
        items[4] = RLP.encode(RLP.encode(taItems));
        items[5] = RLP.encode(vcProof);
        items[6] = header;
        items[7] = RLP.encode(uint256(30000));
        return RLP.encode(items);
    }
}
