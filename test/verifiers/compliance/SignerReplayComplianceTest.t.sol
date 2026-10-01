// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {HeaderSetComplianceBase} from "@test/verifiers/compliance/HeaderSetComplianceBase.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {SignerReplayVerifier} from "@hiero-ledger/clpr/verifiers/evm/signer/SignerReplayVerifier.sol";

/// @title SignerReplayComplianceTest
/// @dev ClprVerifierComplianceTest adapter (via ClprEvmStorageComplianceTest) for SignerReplayVerifier.
///      Every bundle carries a real signer-replay run: two linked Clique-style headers sealed by two of
///      a 3-signer set (majority), the first committing to a synthetic MPT state root.
contract SignerReplayComplianceTest is HeaderSetComplianceBase {
    uint64 internal constant SET_BLOCK = 100;

    function _signerKeys() internal pure returns (uint256[] memory) {
        return _keys(3, "compliance-signer");
    }

    function _deployVerifier() internal override returns (IClprVerifier) {
        return IClprVerifier(address(new SignerReplayVerifier(_cliqueProfile())));
    }

    function _caip2() internal pure override returns (string memory) {
        return "eip155:777";
    }

    function _finalityFor(bytes32 stateRoot) internal pure override returns (bytes memory, bytes[] memory) {
        uint256[] memory k = _signerKeys();
        uint256[] memory seq = new uint256[](2);
        seq[0] = k[0];
        seq[1] = k[1];
        return (_packed(_sortedAddrs(k)), _run(SET_BLOCK + 1, stateRoot, seq));
    }

    function _accountFor(bytes32 storageRoot) internal pure override returns (bytes32, bytes memory) {
        return _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
    }

    function _anchorBytes() internal pure override returns (bytes memory) {
        return _anchor(_sortedAddrs(_signerKeys()), SET_BLOCK);
    }

    function _configFor(string memory caip2) internal pure override returns (bytes memory) {
        uint256[] memory k = _signerKeys();
        return _replayConfig(caip2, _boundaryRun(SET_BLOCK, _packed(_sortedAddrs(k)), k[0], k[1]));
    }
}
