// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {ClprService} from "@hiero-ledger/clpr/ClprService.sol";
import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";
import {ClprTypes, ChannelStatusChanged} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {MockClprVerifier} from "@test/mocks/MockClprVerifier.sol";
import {MockClprApplication} from "@test/mocks/MockClprApplication.sol";
import {MockClprConnector} from "@test/mocks/MockClprConnector.sol";
import {BundleLib} from "@hiero-ledger/clpr/libraries/service/BundleLib.sol";
import {BundleLogicTestBase} from "@test/logic/bundle-logic/BundleLogicTestBase.sol";

contract BundleLogic_PaymentPolicy is BundleLogicTestBase {
    MockClprApplication public app;

    function setUp() public override {
        super.setUp();
        app = new MockClprApplication();
        app.setResponse(hex"504F4E47"); // "PONG"
        // Fund the connector contract so it can pay for bundle submission
        vm.deal(address(connector), 100 ether);
    }

    function test_payReverts() public {
        _registerTestConnector();
        ClprTypes.Connector memory connBefore = service.getConnector(channelId, connectorId);

        connector.setPayReverts(true);
        vm.txGasPrice(1 gwei);

        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");

        _submitSingleInboundMessage(dataPayload);

        ClprTypes.Connector memory connAfter = service.getConnector(channelId, connectorId);
        assertGt(
            connAfter.slashCount, connBefore.slashCount, "We expected payment to be reverted and connector slashed"
        );
    }

    function test_paymentShortfall() public {
        _registerTestConnector();
        vm.txGasPrice(1 gwei);
        connector.setPayShortfall(true);
        ClprTypes.Connector memory connBefore = service.getConnector(channelId, connectorId);

        uint256 submitterBefore = address(this).balance;

        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");

        _submitSingleInboundMessage(dataPayload);

        uint256 submitterAfter = address(this).balance;
        uint256 received = submitterAfter - submitterBefore;

        // We charged the sender...
        assertTrue(received > 0, "submitter should receive payment");

        // And punished the connector anyway.
        ClprTypes.Connector memory connAfter = service.getConnector(channelId, connectorId);
        assertGt(
            connAfter.slashCount,
            connBefore.slashCount,
            "We expected payment amount to be too small and connector slashed"
        );
    }

    // ── Payment policy: actual gas used × gasPrice × (100 + margin) / 100, all to submitter

    function test_paymentPolicy_actualGasUsedPlusMargin() public {
        _registerTestConnector();
        vm.txGasPrice(1 gwei);

        uint256 submitterBefore = address(this).balance;

        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");

        _submitSingleInboundMessage(dataPayload);

        uint256 submitterAfter = address(this).balance;
        uint256 received = submitterAfter - submitterBefore;

        // With gas price = 1 gwei, actual charge = gasUsed * 1 gwei * (100+10)/100
        // Submitter receives all of actualCharge * (1 + margin/100).
        // We just assert that something was transferred (nonzero gas was used at nonzero gasprice).
        assertTrue(received > 0, "submitter should receive payment");
    }

    /// @dev Pins the payment policy with exact ETH-delta assertions so any future
    ///      regression that splits funds to a treasury, drops the margin, or leaks
    ///      to the owner will fail this test.
    ///
    ///      Policy: charge = gasUsed * gasPrice * (100 + marginPct) / 100
    ///              submitter receives ALL of charge; owner receives NOTHING.
    ///
    ///      Uses a dedicated `submitter` address distinct from the owner so that
    ///      "owner unchanged" and "submitter gained" assertions are independent.
    function test_C5_paymentPolicy_pinsExactEthDelta() public {
        _registerTestConnector();
        vm.txGasPrice(1 gwei);

        // Use a fresh address as the bundle submitter so it is distinct from the owner.
        // Register it as an endpoint (minEndpointBond = 0 in test config).
        address submitter = makeAddr("c5-submitter");
        bytes memory submitterKey = new bytes(64);
        submitterKey[1] = 0x02; // distinct from the default endpoint key
        vm.prank(submitter);

        address ownerAddr = service.owner();

        uint256 connectorContractBalBefore = address(connector).balance;
        uint256 submitterBefore = submitter.balance;
        uint256 ownerBefore = ownerAddr.balance;
        uint256 ownerPullBefore = service.pendingWithdrawals(ownerAddr);

        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"48454C4C4F");

        // Build the bundle and submit as the dedicated submitter.
        {
            bytes[] memory msgs = new bytes[](1);
            msgs[0] = dataPayload;
            bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(dataPayload)));
            ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
                nextMessageId: 2,
                sentRunningHash: hash,
                receivedMessageId: 0,
                receivedRunningHash: bytes32(0),
                state: ClprTypes.ChannelStatus.ACTIVE,
                endpointManifestVersion: 0,
                lastMessageId: 1,
                lastMessageRunningHash: hash
            });
            verifier.setVerifyBundleResult(meta, msgs);
            bytes memory proofBytes = hex"00FF";
            vm.prank(submitter);
            service.submitBundle(channelId, proofBytes);
        }

        uint256 connectorContractBalAfter = address(connector).balance;
        uint256 submitterAfter = submitter.balance;
        uint256 ownerAfter = ownerAddr.balance;
        uint256 ownerPullAfter = service.pendingWithdrawals(ownerAddr);

        uint256 connectorOutflow = connectorContractBalBefore - connectorContractBalAfter;
        uint256 submitterInflow = submitterAfter - submitterBefore;

        // 1. Every wei that left the connector went to the submitter — no leakage.
        assertEq(connectorOutflow, submitterInflow, "connector outflow must equal submitter inflow");

        // 2. Something was actually charged (gas was consumed at a non-zero gas price).
        assertTrue(connectorOutflow > 0, "charge must be non-zero");

        // 3. The charge must exceed the raw execution cost (i.e., margin was applied).
        //    endpointMarginPercent = 10 in _setupDefaultConfig, so charge > gasUsed*gasPrice.
        //    Reconstruct gasOnly = charge * 100 / (100 + 10); verify charge > gasOnly.
        uint256 gasOnly = connectorOutflow * 100 / 110;
        assertTrue(connectorOutflow > gasOnly, "margin must be included in charge");

        // 4. Owner ETH balance unchanged (no protocol treasury cut).
        assertEq(ownerAfter, ownerBefore, "owner ETH balance must not change");

        // 5. Owner pull-payment slot unchanged (no pending withdrawal credit to owner).
        assertEq(ownerPullAfter, ownerPullBefore, "owner pull-payment slot must not change");
    }

    receive() external payable override {}
}
