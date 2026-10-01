// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprVerifierComplianceTest} from "@test/verifiers/compliance/ClprVerifierComplianceTest.sol";
import {SavannaBuilders} from "@test/verifiers/evm/antelope/SavannaBuilders.sol";
import {SavannaVerifier} from "@hiero-ledger/clpr/verifiers/evm/antelope/SavannaVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";

/// @title SavannaComplianceTest
/// @notice Compliance adapter binding `SavannaVerifier` to the shared verifier suite, with synthetic
///         Savanna proofs (real BLS12-381 QCs, finality digests and Merkle paths; see SavannaBuilders).
contract SavannaComplianceTest is ClprVerifierComplianceTest, SavannaBuilders {
    function _deployVerifier() internal override returns (IClprVerifier) {
        _initPolicies();
        return IClprVerifier(address(new SavannaVerifier(CHAIN_ID)));
    }

    function _configProof(Target memory t) internal view returns (bytes memory) {
        bytes[] memory c = new bytes[](4);
        c[0] = _rlpBytes(g1.pack);
        c[1] = _finalityRlp(_fin(t.finalityMroot, 1, 1), g1, ALL_BUT_ONE);
        c[2] = _blockRlp(t);
        c[3] = _actionRlp(t);
        return _rlpList(c);
    }

    function _configTarget(string memory chainId) internal pure returns (Target memory) {
        return _target(
            _actionBase(SERVICE_NAME, "ledgerconfig", "relayer"), "", _ledgerConfigReturn(chainId), SERVICE_NAME, 9
        );
    }

    function _validConfig() internal view override returns (ConfigVector memory v) {
        v.configProof = _configProof(_configTarget(CHAIN_ID));
        v.channelId = CHANNEL;
        v.expectedChainId = CHAIN_ID;
        v.expectedServiceAddress = _serviceAddress();
    }

    function _validBundle() internal view override returns (BundleVector memory v) {
        v.proofBytes = _simpleBundle(_queueTarget());
        v.trustAnchor = _anchor(g1);
        v.channelContext = _context();
        v.expectedNextMessageId = 7;
        v.expectedPayloadCount = 2;
    }

    /// @dev The `manifest` action returns `committedPreimage`; the proof carries `carriedPreimage`
    ///      as the action's return value, so a mismatch breaks the receipt digest.
    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        view
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        configProof = _configProof(_configTarget(CHAIN_ID));
        channelId = CHANNEL;
        Target memory t =
            _target(_actionBase(SERVICE_NAME, "manifest", "relayer"), "", committedPreimage, SERVICE_NAME, 11);
        bytes memory fin = _finalityRlp(_fin(t.finalityMroot, 1, 1), g1, ALL_BUT_ONE);
        t.ret = carriedPreimage;
        bytes[] memory m = new bytes[](3);
        m[0] = fin;
        m[1] = _blockRlp(t);
        m[2] = _actionRlp(t);
        manifestProof = _rlpList(m);
    }

    function _runningHashVector() internal view override returns (RunningHashVector memory v) {
        bytes32 h = sha256(abi.encodePacked(bytes32(0), sha256(hex"0a0b0c")));
        h = sha256(abi.encodePacked(h, sha256(hex"0d0e0f10")));
        Target memory t = _target(
            _actionBase(SERVICE_NAME, "queuestate", "relayer"),
            abi.encodePacked(CHANNEL),
            _queueState(CHANNEL, 1, 3, h, 0, bytes32(0), 1, bytes32(0)),
            SERVICE_NAME,
            1
        );
        bytes memory fin = _finalityRlp(_fin(t.finalityMroot, 1, 1), g1, ALL_BUT_ONE);
        v.proofBytes = _bundle(g1.pack, "", new bytes[](0), fin, t, "");
        v.trustAnchor = _anchor(g1);
        v.channelContext = _context();
        v.previousRunningHash = bytes32(0);
    }

    function _wrongChainConfigVector() internal view override returns (bytes memory configProof, bytes32 channelId) {
        configProof = _configProof(_configTarget("antelope:4667b205c6838ef70ff7988f6e8257e8"));
        channelId = CHANNEL;
    }
}
