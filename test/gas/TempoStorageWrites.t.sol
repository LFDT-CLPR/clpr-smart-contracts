// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {BundleLibTestBase} from "@test/libraries/service/bundle-lib/BundleLibTestBase.sol";

/// @notice Counts storage slot transitions per protocol operation. Tempo (TIP-1000) charges 250,000
///         gas for a zero-to-nonzero slot write instead of Ethereum's 20,000, so the number of new
///         slots is what changes the cost of an operation on Tempo. Reproduce with
///         `FOUNDRY_PROFILE=test forge test --match-path test/gas/TempoStorageWrites.t.sol -vv`.
contract TempoStorageWritesTest is BundleLibTestBase {
    /// @dev Measured on the Tempo localnet: a zero-to-nonzero SSTORE costs 232,200 gas more than on Ethereum.
    uint256 internal constant TEMPO_NEW_SLOT_EXTRA = 232_200;

    struct Counts {
        uint256 newSlots; // 0 -> nonzero
        uint256 updates; // nonzero -> nonzero
        uint256 clears; // nonzero -> 0
        uint256 otherNewSlots; // new slots in contracts other than the service (test doubles)
        uint256 gas;
    }

    function _count(Vm.AccountAccess[] memory acc, uint256 gasUsed) internal view returns (Counts memory c) {
        // Net transition per (account, slot): first previousValue -> last newValue.
        bytes32[] memory keys = new bytes32[](512);
        bytes32[] memory first = new bytes32[](512);
        bytes32[] memory last = new bytes32[](512);
        uint256 n;
        for (uint256 i = 0; i < acc.length; i++) {
            if (acc[i].reverted) continue;
            for (uint256 j = 0; j < acc[i].storageAccesses.length; j++) {
                Vm.StorageAccess memory s = acc[i].storageAccesses[j];
                if (!s.isWrite || s.reverted) continue;
                if (s.account != address(service)) {
                    if (s.previousValue == 0 && s.newValue != 0) c.otherNewSlots++;
                    continue;
                }
                bytes32 k = keccak256(abi.encode(s.account, s.slot));
                uint256 idx = n;
                for (uint256 q = 0; q < n; q++) {
                    if (keys[q] == k) {
                        idx = q;
                        break;
                    }
                }
                if (idx == n) {
                    keys[n] = k;
                    first[n] = s.previousValue;
                    n++;
                }
                last[idx] = s.newValue;
            }
        }
        for (uint256 q = 0; q < n; q++) {
            if (first[q] == 0 && last[q] != 0) c.newSlots++;
            else if (first[q] != 0 && last[q] != 0 && first[q] != last[q]) c.updates++;
            else if (first[q] != 0 && last[q] == 0) c.clears++;
        }
        c.gas = gasUsed;
    }

    function _log(string memory label, Counts memory c) internal {
        ClprTypes.Channel memory ch = service.getChannel(channelId);
        console.log(
            string.concat(
                label,
                " | eth gas ",
                vm.toString(c.gas),
                " | new slots ",
                vm.toString(c.newSlots),
                " | updates ",
                vm.toString(c.updates),
                " | clears ",
                vm.toString(c.clears),
                " | tempo gas ~",
                vm.toString(c.gas + c.newSlots * TEMPO_NEW_SLOT_EXTRA),
                " | non-service new slots ",
                vm.toString(c.otherNewSlots)
            )
        );
        console.log(
            string.concat(
                "    channel: status ",
                vm.toString(uint8(ch.status)),
                " next ",
                vm.toString(ch.nextMessageId),
                " acked ",
                vm.toString(ch.ackedMessageId),
                " received ",
                vm.toString(ch.receivedMessageId)
            )
        );
    }

    function _meta(uint64 next, bytes32 hash, uint64 acked, bytes[] memory msgs) internal {
        verifier.setVerifyBundleResult(
            ClprTypes.QueueMetadata({
                nextMessageId: next,
                sentRunningHash: hash,
                receivedMessageId: acked,
                receivedRunningHash: bytes32(0),
                state: ClprTypes.ChannelStatus.ACTIVE,
                endpointManifestVersion: 0,
                lastMessageId: msgs.length > 0 ? next - 1 : 0,
                lastMessageRunningHash: msgs.length > 0 ? hash : bytes32(0)
            }),
            msgs
        );
    }

    function test_storageWrites_perOperation() public {
        _registerTestConnector();
        bytes memory target = abi.encodePacked(address(app));
        bytes memory big = new bytes(512);
        for (uint256 i = 0; i < 512; i++) {
            // casting to 'uint8' is safe because only the low byte is wanted as filler
            // forge-lint: disable-next-line(unsafe-typecast)
            big[i] = bytes1(uint8(i + 1));
        }

        // 1. First outbound DATA on the channel (our slot 1). Initializes counters and the running hash.
        vm.startStateDiffRecording();
        uint256 g = gasleft();
        service.sendMessage(channelId, connectorId, target, hex"01020304050607080910111213141516");
        g -= gasleft();
        _log("sendMessage, first on channel, 16B data", _count(vm.stopAndReturnStateDiff(), g));

        // 2. Inbound DATA (5B) from the peer; dispatch enqueues our REPLY at slot 2.
        bytes memory data1 = ClprProtobuf.encodeDataMessage(connectorId, target, hex"AA01BB02", hex"48454C4C4F");
        vm.startStateDiffRecording();
        g = gasleft();
        _submitSingleInboundMessage(data1);
        g -= gasleft();
        _log("submitBundle, 1 inbound DATA 5B (+1 REPLY enqueued)", _count(vm.stopAndReturnStateDiff(), g));

        // 3. Inbound DATA (512B); our REPLY at slot 3.
        bytes memory data2 = ClprProtobuf.encodeDataMessage(connectorId, target, hex"AA01BB02", big);
        bytes32 h1 = sha256(abi.encodePacked(bytes32(0), sha256(data1)));
        bytes32 h2 = sha256(abi.encodePacked(h1, sha256(data2)));
        bytes[] memory one = new bytes[](1);
        one[0] = data2;
        _meta(3, h2, 0, one);
        vm.startStateDiffRecording();
        g = gasleft();
        _submitBundle(hex"00FF02");
        g -= gasleft();
        _log("submitBundle, 1 inbound DATA 512B (+1 REPLY enqueued)", _count(vm.stopAndReturnStateDiff(), g));

        // 4. Peer's REPLY for our DATA id 1, acking id 1: delivers the reply and deletes our slot 1.
        bytes memory reply = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"0102");
        bytes32 h3 = sha256(abi.encodePacked(h2, sha256(reply)));
        one[0] = reply;
        _meta(4, h3, 1, one);
        vm.startStateDiffRecording();
        g = gasleft();
        _submitBundle(hex"00FF03");
        g -= gasleft();
        _log("submitBundle, 1 inbound REPLY (acks our DATA 1)", _count(vm.stopAndReturnStateDiff(), g));

        // 5. Ack-only bundle: peer acked our REPLYs at slots 2 and 3; they are deleted.
        _meta(4, h3, 3, new bytes[](0));
        vm.startStateDiffRecording();
        g = gasleft();
        _submitBundle(hex"00FF04");
        g -= gasleft();
        _log("submitBundle, ack-only (acks our REPLYs 2 and 3)", _count(vm.stopAndReturnStateDiff(), g));

        // 6. Steady-state outbound DATA, 16B and 512B.
        vm.startStateDiffRecording();
        g = gasleft();
        service.sendMessage(channelId, connectorId, target, hex"01020304050607080910111213141516");
        g -= gasleft();
        _log("sendMessage, steady state, 16B data", _count(vm.stopAndReturnStateDiff(), g));

        vm.startStateDiffRecording();
        g = gasleft();
        service.sendMessage(channelId, connectorId, target, big);
        g -= gasleft();
        _log("sendMessage, steady state, 512B data", _count(vm.stopAndReturnStateDiff(), g));
    }
}
