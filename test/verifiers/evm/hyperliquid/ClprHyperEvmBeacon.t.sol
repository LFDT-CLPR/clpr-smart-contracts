// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test, Vm} from "forge-std/Test.sol";
import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprQueueRecord} from "@hiero-ledger/clpr/libraries/codec/ClprQueueRecord.sol";
import {ClprHyperEvmBeacon} from "@hiero-ledger/clpr/verifiers/evm/hyperliquid/ClprHyperEvmBeacon.sol";

/// @dev Stands in for the ClprService views the beacon reads.
contract ServiceViews {
    ClprTypes.Channel internal ch;

    constructor() {
        ch.status = ClprTypes.ChannelStatus.ACTIVE;
        ch.nextMessageId = 7;
        ch.receivedMessageId = 4;
        ch.sentRunningHash = keccak256("sent");
        ch.receivedRunningHash = keccak256("received");
        ch.endpointManifestVersion = 2;
    }

    function getChannel(bytes32) external view returns (ClprTypes.Channel memory) {
        return ch;
    }

    function getEndpointManifest() external pure returns (ClprTypes.ClprEndpointManifest memory m) {
        m.version = 3;
        m.serviceAddress = abi.encodePacked(address(0x5e7c));
        m.endpoints = new ClprTypes.Endpoint[](0);
    }

    function getLedgerConfiguration() external pure returns (ClprTypes.LedgerConfiguration memory lc) {
        lc.protocolVersion = 1;
        lc.chainId = "eip155:999";
        lc.serviceAddress = abi.encodePacked(address(0x5e7c));
        lc.throttles = ClprTypes.Throttles(10, 4096, 500_000, 100, 65_536, 4, 4);
    }
}

contract ClprHyperEvmBeaconTest is Test {
    function test_publish_emitsTheServiceState() public {
        ServiceViews svc = new ServiceViews();
        ClprHyperEvmBeacon beacon = new ClprHyperEvmBeacon(IClprService(address(svc)));
        bytes32 channel = bytes32(uint256(0xC0FFEE));
        vm.recordLogs();
        bytes memory record = beacon.publish(channel);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].topics[0], keccak256("ClprQueueRecord(address,bytes32,bytes)"));
        assertEq(logs[0].topics[1], bytes32(uint256(uint160(address(svc)))));
        assertEq(logs[0].topics[2], channel);
        assertEq(abi.decode(logs[0].data, (bytes)), record);
        ClprQueueRecord.Record memory r = ClprQueueRecord.decode(record, 0);
        assertEq(r.nextMessageId, 7);
        assertEq(r.receivedMessageId, 4);
        assertEq(r.sentRunningHash, keccak256("sent"));
        assertEq(r.endpointManifestVersion, 2);
        assertEq(r.configHash, keccak256(ClprProtobuf.encodeControlMessage(svc.getLedgerConfiguration())));
        assertEq(r.manifestCommitment, keccak256(ClprProtobuf.encodeEndpointManifest(svc.getEndpointManifest())));
    }
}
