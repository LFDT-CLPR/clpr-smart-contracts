// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {PolygonPosVerifier} from "@hiero-ledger/clpr/verifiers/evm/polygon/PolygonPosVerifier.sol";
import {CometBftCommitAccumulator} from "@hiero-ledger/clpr/verifiers/evm/cometbft/CometBftCommitAccumulator.sol";
import {CometBftLightClient} from "@hiero-ledger/clpr/verifiers/evm/cometbft/CometBftLightClient.sol";
import {ClprVerifierComplianceTest} from "./ClprVerifierComplianceTest.sol";
import {PolygonSyntheticChain} from "@test/helpers/PolygonSyntheticChain.sol";

/// @notice PolygonPosVerifier against the shared IClprVerifier compliance suite, on a synthetic
///         Heimdall + Bor chain (test/helpers/PolygonSyntheticChain.sol).
contract PolygonPosComplianceTest is ClprVerifierComplianceTest, PolygonSyntheticChain {
    function setUp() public override {
        _initSets();
        super.setUp();
    }

    function _deployVerifier() internal override returns (IClprVerifier) {
        CometBftCommitAccumulator acc =
            new CometBftCommitAccumulator(CHAIN, CometBftLightClient.KeyScheme.SECP256K1_ETH, address(0));
        return new PolygonPosVerifier(
            PolygonPosVerifier.Profile({
                accumulator: acc,
                storeKey: bytes("milestone"),
                borChainId: BOR_CHAIN,
                bootstrapValidatorsHash: hashA,
                bootstrapHeight: ANCHOR_HEIGHT
            })
        );
    }

    function _configVector(bytes32 commitment, string memory chainId) internal view returns (bytes memory) {
        World memory w =
            _world2(bytes32(uint256(25)), _serviceSlotValue(SVC), bytes32(uint256(18)), uint256(commitment));
        (bytes memory ms, bytes32 appHash) = _storeProof(bytes("milestone"), w.tree.root);
        Block memory b = _block(120, hashA, hashA, appHash);
        b.header.chainId = chainId;
        Q memory q = _q(w, hashA);
        q.content = false;
        q.headerRef = _inlineRef(setA, _signedHeader(b, setA, _idx(0, 1)));
        q.multistore = ms;
        q.storageProof = _entries(w.st, _one(bytes32(uint256(25))));
        q.manifestStorageProof = w.extraProof;
        q.ledgerConfig = _ledgerConfig(SVC);
        return _enc(q);
    }

    function _validConfig() internal view override returns (ConfigVector memory v) {
        v.configProof = _configVector(keccak256("unused"), CHAIN);
        v.channelId = CHANNEL;
        v.expectedChainId = CHAIN;
        v.expectedServiceAddress = abi.encodePacked(SVC);
    }

    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        view
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        configProof = _configVector(keccak256(committedPreimage), CHAIN);
        channelId = CHANNEL;
        manifestProof = carriedPreimage;
    }

    function _wrongChainConfigVector() internal view override returns (bytes memory, bytes32) {
        return (_configVector(bytes32(0), "heimdallv2-80002"), CHANNEL);
    }

    function _validBundle() internal view override returns (BundleVector memory v) {
        v.proofBytes = _enc(_q(_defaultWorld(), hashA));
        v.trustAnchor = _anchor(hashA, ANCHOR_HEIGHT);
        v.channelContext = _ctxPoly();
        v.expectedNextMessageId = 3;
        v.expectedPayloadCount = 1;
    }

    function _runningHashVector() internal view override returns (RunningHashVector memory v) {
        bytes32 sent = sha256(abi.encodePacked(bytes32(0), sha256(PAYLOAD)));
        bytes32[] memory cs = _channelSlots();
        World memory w = _world2(cs[0], (uint256(1) << 160) | (uint256(2) << 168), cs[2], uint256(sent));
        v.proofBytes = _enc(_q(w, hashA));
        v.trustAnchor = _anchor(hashA, ANCHOR_HEIGHT);
        v.channelContext = _ctxPoly();
        v.previousRunningHash = bytes32(0);
    }
}
