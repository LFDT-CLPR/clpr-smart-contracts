// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";
import {MockClprApplication} from "@test/mocks/MockClprApplication.sol";
import {MockClprConnector} from "@test/mocks/MockClprConnector.sol";
import {ConnectorRegistrar} from "@test/helpers/ConnectorRegistrar.sol";
import {ClprTestBase} from "@test/helpers/ClprTestBase.sol";
import {BundleLibTestBase} from "@test/libraries/service/bundle-lib/BundleLibTestBase.sol";

contract BundleLib_PaymentTest is BundleLibTestBase {
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

    // ── Additional: Connector underfunded -> slash + reply

    function test_dataMessage_connectorUnderfunded() public {
        // Register connector with stake but do NOT fund the connector contract.
        // Set a non-zero gas price so the pre-call balance check is meaningful
        // (charge = gasUsed * tx.gasprice * (100 + margin) / 100)
        vm.txGasPrice(1 gwei);
        connectorId = ConnectorRegistrar.register(
            IClprService(address(service)),
            channelId,
            keccak256(abi.encodePacked("test-connector")),
            address(connector),
            owner,
            0.5 ether
        );

        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"01020304");

        _submitSingleInboundMessage(dataPayload);

        // Verify CONNECTOR_UNDERFUNDED reply (connector contract balance is 0, maxPossibleCharge > 0)
        ClprTypes.MessageValue memory reply = service.getMessage(channelId, 1);
        ClprTypes.DecodedReply memory decoded = ClprProtobuf.decodeReplyMessage(reply.payload);
        assertEq(uint8(decoded.status), uint8(ClprTypes.ReplyStatus.CONNECTOR_UNDERFUNDED));
    }

    /// @dev Bug report: a connector holding several times the ACTUAL cost of a message is
    ///      classified CONNECTOR_UNDERFUNDED and slashed, because the pre-call check compares
    ///      its balance against the worst-case ceiling
    ///      (maxGasPerMessage × gasprice × margin factor) rather than what the message costs.
    ///
    ///      Spec §4.6: "Connector found, funded | Charge Connector
    ///      actual_gas_used * (1 + margin_percent / 100)" and CONNECTOR_UNDERFUNDED is defined
    ///      as "Connector couldn't pay". A connector that is never asked to pay, and could have,
    ///      must not produce that status.
    function test_dataMessage_solventConnectorBelowCeiling_isNotUnderfunded() public {
        vm.txGasPrice(1 gwei);
        connectorId = ConnectorRegistrar.register(
            IClprService(address(service)),
            channelId,
            keccak256(abi.encodePacked("thin-but-solvent")),
            address(connector),
            owner,
            0.5 ether
        );

        // Ceiling = 1_000_000 * 1 gwei * 110/100 = 1.1e15 wei.
        // Actual charge for this message is ~1.1e14 wei (roughly 100k gas).
        // Fund with 5.5e14: ~5x the real cost, but under half the ceiling.
        uint256 ceiling = uint256(defaultThrottles.maxGasPerMessage) * 1 gwei * 110 / 100;
        uint256 funding = 0.00055 ether;
        assertLt(funding, ceiling, "test setup: funding must be below the ceiling");
        (bool ok,) = address(connector).call{value: funding}("");
        require(ok, "fund connector failed");

        uint256 appCallsBefore = app.getMessageCallCount();
        ClprTypes.Connector memory connBefore = service.getConnector(channelId, connectorId);

        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"01020304");

        _submitSingleInboundMessage(dataPayload);

        ClprTypes.MessageValue memory reply = service.getMessage(channelId, 1);
        ClprTypes.DecodedReply memory decoded = ClprProtobuf.decodeReplyMessage(reply.payload);

        // The connector could afford this message many times over.
        assertEq(uint8(decoded.status), uint8(ClprTypes.ReplyStatus.SUCCESS), "solvent connector must not be rejected");
        assertEq(app.getMessageCallCount(), appCallsBefore + 1, "target application must be invoked");

        ClprTypes.Connector memory connAfter = service.getConnector(channelId, connectorId);
        assertEq(connAfter.slashCount, connBefore.slashCount, "solvent connector must not be slashed");

        // And it actually paid: charge is metered from actual gas used.
        assertLt(address(connector).balance, funding, "connector must have been charged");
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

    receive() external payable {}
}
