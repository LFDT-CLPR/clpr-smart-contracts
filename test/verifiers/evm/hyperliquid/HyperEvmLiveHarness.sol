// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {HyperEvmVerifier} from "@hiero-ledger/clpr/verifiers/evm/hyperliquid/HyperEvmVerifier.sol";
import {ClprAttestorQuorum} from "@hiero-ledger/clpr/libraries/proof/attestor/ClprAttestorQuorum.sol";
import {ClprReceiptProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprReceiptProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @dev Live-data harness: runs verifyBundle's production steps (attestor set, rotations, block
///      attestation, header, receipts-trie proof, successful log) on a real HyperEVM block and
///      returns the proven log. There is no ClprHyperEvmBeacon on HyperEVM yet, so the real log is
///      not a ClprQueueRecord and verifyBundle itself stops at the emitter / event check.
contract HyperEvmLiveHarness is HyperEvmVerifier {
    constructor() HyperEvmVerifier("eip155:999", 999) {}

    function provenLog(bytes calldata proofBytes, bytes calldata trustAnchor)
        external
        view
        returns (uint256 number, address emitter, bytes32[] memory topics, bytes memory data, uint256 epoch)
    {
        Anchor memory a = _decodeAnchor(trustAnchor);
        Memory.Slice[] memory p = RLP.decodeList(proofBytes);
        ClprAttestorQuorum.Set memory set = ClprAttestorQuorum.decode(p[0], a.setHash);
        Memory.Slice[] memory rotations = RLP.readList(p[1]);
        for (uint256 i = 0; i < rotations.length; ++i) {
            set = _rotate(set, rotations[i], ++a.epoch);
        }
        ClprReceiptProof.Log memory log;
        (number, log) = _provenLog(set, p);
        return (number, log.emitter, log.topics, log.data, a.epoch);
    }
}
