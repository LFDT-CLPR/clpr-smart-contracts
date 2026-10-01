// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprVerifierComplianceTest} from "./ClprVerifierComplianceTest.sol";
import {FuelSyntheticChain} from "../evm/runtimes3/FuelSyntheticChain.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {FuelVerifier} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/FuelVerifier.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @dev IClprVerifier compliance for FuelVerifier over a synthetic Fuel chain and a mock L1 light
///      client that accepts only the registered proof and configurations (the real
///      EthL1StateVerifier runs in fuel-live.spec.ts).
contract FuelComplianceTest is ClprVerifierComplianceTest, FuelSyntheticChain {
    bytes internal constant SERVICE_BYTES = abi.encodePacked(SERVICE);

    function setUp() public override {
        super.setUp();
        l1.expectProof(keccak256(bytes("light client proof (mocked)")));
    }

    function _deployVerifier() internal override returns (IClprVerifier) {
        _deployFuel();
        return IClprVerifier(address(fuel));
    }

    function _config(string memory chainId) internal returns (bytes memory cfg) {
        cfg = abi.encode(_anchor(CHANNEL_ID), abi.encodePacked(uint64(5)), _controlMessage(chainId, SERVICE_BYTES));
        l1.registerConfig(cfg);
    }

    function _validConfig() internal override returns (ConfigVector memory v) {
        v.configProof = _config("fuel:9889");
        v.channelId = CHANNEL_ID;
        v.expectedChainId = "fuel:9889";
        v.expectedServiceAddress = SERVICE_BYTES;
    }

    function _validBundle() internal override returns (BundleVector memory v) {
        v.proofBytes = _default();
        v.trustAnchor = _anchor(CHANNEL_ID);
        v.channelContext = _ctx();
        v.expectedNextMessageId = 7;
        v.expectedPayloadCount = 2;
    }

    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        Msg memory m = _msg("");
        m.data = abi.encodePacked(fuel.MANIFEST_TAG(), keccak256(committedPreimage));
        bytes[] memory outer = new bytes[](2);
        outer[0] = RLP.encode(_messageProof(_chain(m)));
        outer[1] = RLP.encode(carriedPreimage);
        return (_config("fuel:9889"), CHANNEL_ID, RLP.encode(outer));
    }

    function _runningHashVector() internal override returns (RunningHashVector memory v) {
        bytes memory record = _recordWithSent(1, 7, 3, 2, bytes32(0), _chainedSentHash(bytes32(0)));
        FuelChain memory c = _chain(_msg(record));
        v.proofBytes = _bundle(c, _l1(c), FINAL_SLOT, "");
        v.trustAnchor = _anchor(CHANNEL_ID);
        v.channelContext = _ctx();
        v.previousRunningHash = bytes32(0);
    }

    function _wrongChainConfigVector() internal override returns (bytes memory configProof, bytes32 channelId) {
        return (_config("eip155:1"), CHANNEL_ID);
    }

    /// @dev The FuelVerifier's own error must surface for a forged manifest message.
    function test_fuel_manifestFromOtherSender_reverts() public {
        Msg memory m = _msg("");
        m.sender = keccak256("other contract");
        bytes memory preimage = _manifest(SERVICE_BYTES);
        m.data = abi.encodePacked(fuel.MANIFEST_TAG(), keccak256(preimage));
        bytes[] memory outer = new bytes[](2);
        outer[0] = RLP.encode(_messageProof(_chain(m)));
        outer[1] = RLP.encode(preimage);
        bytes memory cfg = _config("fuel:9889");
        vm.expectRevert(FuelVerifier.InvalidManifestMessage.selector);
        fuel.verifyConfig(cfg, CHANNEL_ID, RLP.encode(outer));
    }
}
