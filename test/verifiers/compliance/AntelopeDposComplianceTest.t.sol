// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprVerifierComplianceTest} from "@test/verifiers/compliance/ClprVerifierComplianceTest.sol";
import {AntelopeDposBuilders} from "@test/verifiers/evm/antelope/AntelopeDposBuilders.sol";
import {AntelopeDposVerifier} from "@hiero-ledger/clpr/verifiers/evm/antelope/AntelopeDposVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";

/// @title AntelopeDposComplianceTest
/// @notice Compliance adapter binding `AntelopeDposVerifier` to the shared verifier suite, with
///         synthetic legacy-DPoS proofs (real K1 signatures, LIB rule, legacy action Merkle paths).
contract AntelopeDposComplianceTest is ClprVerifierComplianceTest, AntelopeDposBuilders {
    function _sched() internal pure returns (Sched memory) {
        return _mkSched(7, 4, 1);
    }

    function _deployVerifier() internal override returns (IClprVerifier) {
        return IClprVerifier(address(new AntelopeDposVerifier(CHAIN_ID)));
    }

    function _configProof(string memory chainId) internal pure returns (bytes memory) {
        Sched memory s = _sched();
        Act memory a =
            _act(_actionBase(SERVICE_NAME, "ledgerconfig", "relayer"), "", _ledgerConfigReturn(chainId), SERVICE_NAME);
        bytes[] memory c = new bytes[](4);
        c[0] = _rlpUint(s.version);
        c[1] = _schedRlp(s);
        c[2] = _rlpList(_chain(s, 1, a.actionMroot, hex"00", 64));
        c[3] = _actRlp(a);
        return _rlpList(c);
    }

    function _validConfig() internal pure override returns (ConfigVector memory v) {
        v.configProof = _configProof(CHAIN_ID);
        v.channelId = CHANNEL;
        v.expectedChainId = CHAIN_ID;
        v.expectedServiceAddress = _serviceAddress();
    }

    function _validBundle() internal pure override returns (BundleVector memory v) {
        Sched memory s = _sched();
        Act memory a = _queueAct();
        v.proofBytes = _bundle(s, new bytes[](0), _chain(s, 1, a.actionMroot, hex"00", 64), a);
        v.trustAnchor = _anchor(s);
        v.channelContext = _context();
        v.expectedNextMessageId = 7;
        v.expectedPayloadCount = 2;
    }

    /// @dev The `manifest` action returns `committedPreimage`; the proof carries `carriedPreimage`.
    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        pure
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        configProof = _configProof(CHAIN_ID);
        channelId = CHANNEL;
        Sched memory s = _sched();
        Act memory a = _act(_actionBase(SERVICE_NAME, "manifest", "relayer"), "", committedPreimage, SERVICE_NAME);
        bytes memory chain = _rlpList(_chain(s, 1, a.actionMroot, hex"00", 64));
        a.ret = carriedPreimage;
        manifestProof = _rlpList(_l2(chain, _actRlp(a)));
    }

    function _runningHashVector() internal pure override returns (RunningHashVector memory v) {
        bytes32 h = sha256(abi.encodePacked(bytes32(0), sha256(hex"0a0b0c")));
        h = sha256(abi.encodePacked(h, sha256(hex"0d0e0f10")));
        Sched memory s = _sched();
        Act memory a = _act(
            _actionBase(SERVICE_NAME, "queuestate", "relayer"),
            abi.encodePacked(CHANNEL),
            _queueState(CHANNEL, 1, 3, h, 0, bytes32(0), 1, bytes32(0)),
            SERVICE_NAME
        );
        v.proofBytes = _bundle(s, new bytes[](0), _chain(s, 1, a.actionMroot, hex"00", 64), a);
        v.trustAnchor = _anchor(s);
        v.channelContext = _context();
        v.previousRunningHash = bytes32(0);
    }

    function _wrongChainConfigVector() internal pure override returns (bytes memory configProof, bytes32 channelId) {
        configProof = _configProof("antelope:4667b205c6838ef70ff7988f6e8257e8");
        channelId = CHANNEL;
    }
}
