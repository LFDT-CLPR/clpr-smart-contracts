// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {HeaderSetComplianceBase} from "@test/verifiers/compliance/HeaderSetComplianceBase.sol";
import {KaiaSynthetic} from "@test/helpers/KaiaSynthetic.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {KaiaIstanbulVerifier} from "@hiero-ledger/clpr/verifiers/evm/kaia/KaiaIstanbulVerifier.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @title KaiaIstanbulComplianceTest
/// @dev ClprVerifierComplianceTest adapter (via ClprEvmStorageComplianceTest) for KaiaIstanbulVerifier.
///      Every bundle carries a Kaia-layout header committed by 3 of 4 qualified validators (2f+1) over
///      a synthetic state trie whose service account uses Kaia's SmartContractAccount leaf.
contract KaiaIstanbulComplianceTest is HeaderSetComplianceBase, KaiaSynthetic {
    uint64 internal constant SET_BLOCK = 100;

    function _validatorKeys() internal pure returns (uint256[] memory) {
        return _keys(4, "compliance-kaia");
    }

    function _deployVerifier() internal override returns (IClprVerifier) {
        return IClprVerifier(address(new KaiaIstanbulVerifier(TEST_CHAIN_ID)));
    }

    function _caip2() internal pure override returns (string memory) {
        return "eip155:777";
    }

    function _finalityFor(bytes32 stateRoot) internal pure override returns (bytes memory, bytes[] memory hs) {
        uint256[] memory k = _validatorKeys();
        hs = new bytes[](1);
        hs[0] = _kaiaHeader(SET_BLOCK + 1, stateRoot, _addrs(k), _prefix(k, 3), 0).rlp;
        return (_packed(_addrs(k)), hs);
    }

    function _accountFor(bytes32 storageRoot) internal pure override returns (bytes32, bytes memory) {
        return _buildSyntheticMPTProof(
            keccak256(abi.encodePacked(SERVICE_ADDR)), _kaiaAccountLeaf(storageRoot, SERVICE_CODE_HASH, 2)
        );
    }

    function _anchorBytes() internal pure override returns (bytes memory) {
        return _anchor(_addrs(_validatorKeys()), SET_BLOCK);
    }

    function _configFor(string memory caip2) internal pure override returns (bytes memory) {
        uint256[] memory k = _validatorKeys();
        return _configProof(caip2, _kaiaHeader(SET_BLOCK, bytes32(0), _addrs(k), _prefix(k, 3), 0).rlp);
    }
}
