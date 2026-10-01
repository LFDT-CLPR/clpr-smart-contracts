// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {CosmWasmVerifier} from "@hiero-ledger/clpr/verifiers/evm/provenance/CosmWasmVerifier.sol";
import {CometBftCommitAccumulator} from "@hiero-ledger/clpr/verifiers/evm/cometbft/CometBftCommitAccumulator.sol";
import {CometBftLightClient} from "@hiero-ledger/clpr/verifiers/evm/cometbft/CometBftLightClient.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {ClprVerifierComplianceTest} from "./ClprVerifierComplianceTest.sol";
import {CosmWasmSyntheticChain} from "@test/helpers/CosmWasmSyntheticChain.sol";

/// @notice CosmWasmVerifier (Provenance) against the shared IClprVerifier compliance suite, on a
///         synthetic CometBFT chain with real secp256k1eth signatures and a real IAVL-shaped
///         `wasm` store (test/helpers/CosmWasmSyntheticChain.sol).
contract CosmWasmComplianceTest is ClprVerifierComplianceTest, CosmWasmSyntheticChain {
    Val[] internal setA;
    bytes32 internal hashA;

    function setUp() public override {
        setA.push(_secpVal("a0", 40));
        setA.push(_secpVal("a1", 30));
        setA.push(_secpVal("a2", 20));
        setA.push(_secpVal("a3", 10));
        hashA = _setHash(setA);
        super.setUp();
    }

    function _deployVerifier() internal override returns (IClprVerifier) {
        CometBftCommitAccumulator acc =
            new CometBftCommitAccumulator(CHAIN, CometBftLightClient.KeyScheme.SECP256K1_ETH, address(0));
        return new CosmWasmVerifier(
            CosmWasmVerifier.Profile({
                accumulator: acc,
                storeKey: bytes("wasm"),
                bootstrapValidatorsHash: hashA,
                bootstrapHeight: ANCHOR_HEIGHT
            })
        );
    }

    function _ledgerConfig() internal pure returns (bytes memory) {
        return abi.encodePacked(
            PB.encodeBytesField(1, bytes(CHAIN)),
            PB.encodeBytesField(2, SERVICE),
            PB.encodeVarintField(3, uint64(1_700_000_000)),
            PB.encodeBytesField(4, PB.encodeVarintField(1, uint64(10)))
        );
    }

    function _configProof(bytes32 commitment, string memory chainId) internal view returns (bytes memory) {
        Tree memory t = _state(_record(0, 0, 0, 0), commitment);
        (bytes memory ms, bytes32 appHash) = _multistore(t.root);
        Block memory b = _block(120, hashA, hashA, appHash);
        b.header.chainId = chainId;
        P memory p;
        p.headerRef = _inlineRef(setA, _signedHeader(b, setA, _idx(0, 1)));
        p.multistore = ms;
        p.entry = t.entryR;
        p.ledgerConfig = _ledgerConfig();
        return _encode(p);
    }

    function _validConfig() internal view override returns (ConfigVector memory v) {
        v.configProof = _configProof(bytes32(0), CHAIN);
        v.channelId = CHANNEL;
        v.expectedChainId = CHAIN;
        v.expectedServiceAddress = SERVICE;
    }

    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        view
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        configProof = _configProof(keccak256(committedPreimage), CHAIN);
        channelId = CHANNEL;
        manifestProof = carriedPreimage;
    }

    function _wrongChainConfigVector() internal view override returns (bytes memory, bytes32) {
        return (_configProof(bytes32(0), "pio-testnet-1"), CHANNEL);
    }

    function _bundleWith(bytes memory record) internal view returns (bytes memory) {
        Tree memory t = _state(record, bytes32(0));
        return _bundle(t, 120, setA, hashA, t.entryL);
    }

    function _validBundle() internal view override returns (BundleVector memory v) {
        v.proofBytes = _bundleWith(_record(1, 3, 7, 1));
        v.trustAnchor = _anchor(hashA, ANCHOR_HEIGHT);
        v.channelContext = _ctx();
        v.expectedNextMessageId = 3;
        v.expectedPayloadCount = 1;
    }

    function _runningHashVector() internal view override returns (RunningHashVector memory v) {
        bytes32 sent = sha256(abi.encodePacked(bytes32(0), sha256(PAYLOAD)));
        v.proofBytes =
            _bundleWith(abi.encodePacked(uint8(1), uint8(1), uint64(2), uint64(0), uint64(1), sent, bytes32(0)));
        v.trustAnchor = _anchor(hashA, ANCHOR_HEIGHT);
        v.channelContext = _ctx();
        v.previousRunningHash = bytes32(0);
    }
}
