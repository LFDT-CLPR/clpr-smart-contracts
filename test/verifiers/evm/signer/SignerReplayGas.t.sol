// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {SignerReplaySynthetic} from "@test/helpers/SignerReplaySynthetic.sol";
import {SignerReplayVerifier} from "@hiero-ledger/clpr/verifiers/evm/signer/SignerReplayVerifier.sol";

/// @dev SYNTHETIC gas scaling of SignerReplayVerifier with run length (15-field headers, 64-signer
///      set, round-robin sealers). Live numbers come from SignerReplayLive.t.sol and the anvil spec.
contract SignerReplayGasTest is SignerReplaySynthetic {
    function _measure(uint256 runLength) internal {
        SignerReplayVerifier verifier = new SignerReplayVerifier(_cliqueProfile());
        uint256[] memory k = _keys(64, "gas-signer");
        uint256[] memory seq = new uint256[](runLength);
        for (uint256 i = 0; i < runLength; i++) {
            seq[i] = k[i % 64];
        }
        (bytes32 root, bytes memory acct, bytes memory st) = _stateProofs();
        address[] memory set = _sortedAddrs(k);
        bytes memory proof = _bundle(set, _run(1, root, seq), acct, st);
        bytes memory anchor = _anchor(set, 0);
        uint256 g = gasleft();
        verifier.verifyBundle(proof, anchor, _ctx());
        console.log(
            "[signer-replay-gas] synthetic run length / execution gas / proof bytes:",
            runLength,
            g - gasleft(),
            proof.length
        );
    }

    function test_gas_run33() public {
        _measure(33); // majority of 64
    }

    function test_gas_run64() public {
        _measure(64);
    }
}
