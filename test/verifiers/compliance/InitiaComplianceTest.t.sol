// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprVerifierComplianceTest} from "./ClprVerifierComplianceTest.sol";
import {InitiaSyntheticChain} from "../evm/runtimes3/InitiaSyntheticChain.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";

/// @dev IClprVerifier compliance for InitiaMoveVerifier over synthetic ICS-23 proofs and a mock
///      header source (the CometBFT accumulator of PR #6 is not on this branch).
contract InitiaComplianceTest is ClprVerifierComplianceTest, InitiaSyntheticChain {
    function _deployVerifier() internal override returns (IClprVerifier) {
        _deployInitia();
        return IClprVerifier(address(initia));
    }

    function _resource(bytes32 commitment) internal pure returns (bytes memory) {
        return commitment == bytes32(0)
            ? abi.encodePacked(HANDLE, _le64(0), uint8(0))
            : abi.encodePacked(HANDLE, _le64(0), uint8(32), commitment);
    }

    function _validConfig() internal override returns (ConfigVector memory v) {
        v.configProof = _config("cosmos:interwoven-1", _resource(bytes32(0)));
        v.channelId = CHANNEL_ID;
        v.expectedChainId = "cosmos:interwoven-1";
        v.expectedServiceAddress = abi.encodePacked(SERVICE);
    }

    function _validBundle() internal override returns (BundleVector memory v) {
        v.proofBytes = _simpleBundle(_defaultRecord(), SET_A);
        v.trustAnchor = _anchor(SET_A, ANCHOR_HEIGHT);
        v.channelContext = _ctx();
        v.expectedNextMessageId = 7;
        v.expectedPayloadCount = 2;
    }

    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        return (_config("cosmos:interwoven-1", _resource(keccak256(committedPreimage))), CHANNEL_ID, carriedPreimage);
    }

    function _runningHashVector() internal override returns (RunningHashVector memory v) {
        v.proofBytes = _simpleBundle(_recordWithSent(1, 7, 3, 2, bytes32(0), _chainedSentHash(bytes32(0))), SET_A);
        v.trustAnchor = _anchor(SET_A, ANCHOR_HEIGHT);
        v.channelContext = _ctx();
        v.previousRunningHash = bytes32(0);
    }

    function _wrongChainConfigVector() internal override returns (bytes memory configProof, bytes32 channelId) {
        return (_config("eip155:1", _resource(bytes32(0))), CHANNEL_ID);
    }
}
