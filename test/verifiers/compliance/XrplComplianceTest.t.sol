// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprVerifierComplianceTest} from "@test/verifiers/compliance/ClprVerifierComplianceTest.sol";
import {XrplTestBuilder} from "@test/verifiers/evm/xrpl/XrplTestBuilder.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {XrplVerifier} from "@hiero-ledger/clpr/verifiers/evm/xrpl/XrplVerifier.sol";

/// @title XrplComplianceTest
/// @dev IClprVerifier compliance for XrplVerifier over synthetic UNL-validated XRPL ledgers carrying
///      clpr/v1 outbox messages (the encodings of the live fixtures; see test/verifiers/evm/xrpl).
contract XrplComplianceTest is ClprVerifierComplianceTest, XrplTestBuilder {
    function _deployVerifier() internal override returns (IClprVerifier) {
        return IClprVerifier(address(_deployXrpl("xrpl:0")));
    }

    function _validConfig() internal override returns (ConfigVector memory) {
        return ConfigVector({
            configProof: _config("xrpl:0", 0x00100000, ""),
            channelId: CHANNEL,
            expectedChainId: "xrpl:0",
            expectedServiceAddress: abi.encodePacked(OUTBOX)
        });
    }

    function _wrongChainConfigVector() internal override returns (bytes memory, bytes32) {
        return (_config("xrpl:1", 0x00100000, ""), CHANNEL);
    }

    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        return (_config("xrpl:0", 0x00100000, abi.encodePacked(keccak256(committedPreimage))), CHANNEL, carriedPreimage);
    }

    function _validBundle() internal override returns (BundleVector memory) {
        (bytes[] memory txs, bytes[] memory metas,) = _messages(2);
        return BundleVector({
            proofBytes: _bundle(txs, metas, QUORUM, bytes32(0)),
            trustAnchor: _anchor(),
            channelContext: _context(),
            expectedNextMessageId: 3,
            expectedPayloadCount: 2
        });
    }

    function _runningHashVector() internal override returns (RunningHashVector memory) {
        (bytes[] memory txs, bytes[] memory metas,) = _messages(3);
        bytes32 prev = keccak256("running hash before message 1");
        return RunningHashVector({
            proofBytes: _bundle(txs, metas, QUORUM, prev),
            trustAnchor: _anchor(),
            channelContext: _context(),
            previousRunningHash: prev
        });
    }
}
