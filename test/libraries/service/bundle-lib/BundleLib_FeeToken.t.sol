// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";
import {ConnectorRegistrar} from "@test/helpers/ConnectorRegistrar.sol";
import {MockFeeToken} from "@test/mocks/MockFeeToken.sol";
import {BundleLibTestBase} from "@test/libraries/service/bundle-lib/BundleLibTestBase.sol";

/// @notice Inbound DATA charging and slashing on a token-mode service: gas priced in the token's
///         currency at 18 decimals, charges and penalties paid in a 6-decimal USD token.
contract BundleLib_FeeTokenTest is BundleLibTestBase {
    /// @dev Gas price in the token's currency at 18 decimals (2e-8 USD per gas).
    uint256 internal constant GAS_PRICE = 2e10;

    MockFeeToken internal usd;

    function _feeTokenForDeploy() internal override returns (address) {
        usd = new MockFeeToken(6);
        return address(usd);
    }

    function _beforeInitialize() internal override {
        defaultEcon.minLockedStake = 100e6;
        defaultEcon.basePenalty = 1e6;
        usd.mint(address(this), 1_000e6);
        usd.approve(address(service), type(uint256).max);
    }

    /// @dev Connector staked in the token, paying `payForExecution` from a token operating balance.
    function _registerTokenConnector(uint256 operatingBalance) internal {
        connectorId = ConnectorRegistrar.registerTokenMode(
            IClprService(address(service)), channelId, keccak256("fee-token-connector"), address(connector), owner
        );
        connector.setPayToken(address(usd));
        usd.mint(address(connector), operatingBalance);
    }

    function _inboundData() internal {
        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"01020304");
        _submitSingleInboundMessage(dataPayload);
    }

    function _replyStatus() internal returns (ClprTypes.ReplyStatus) {
        return ClprProtobuf.decodeReplyMessage(service.getMessage(channelId, 1).payload).status;
    }

    function _inboundReplyToFirstMessage() internal {
        vm.prank(address(app));
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"01020304");
        bytes memory replyPayload = ClprProtobuf.encodeReplyMessage(1, ClprTypes.ReplyStatus.SUCCESS, hex"0102");
        bytes[] memory msgs = new bytes[](1);
        msgs[0] = replyPayload;
        bytes32 hash = sha256(abi.encodePacked(bytes32(0), sha256(replyPayload)));
        verifier.setVerifyBundleResult(
            ClprTypes.QueueMetadata({
                nextMessageId: 2,
                sentRunningHash: hash,
                receivedMessageId: 1,
                receivedRunningHash: bytes32(0),
                state: ClprTypes.ChannelStatus.ACTIVE,
                endpointManifestVersion: 0,
                lastMessageId: 1,
                lastMessageRunningHash: hash
            }),
            msgs
        );
        _submitBundle(hex"00FF");
    }

    function test_tokenMode_chargesConnectorInTokenUnits() public {
        _registerTokenConnector(10e6);
        vm.txGasPrice(GAS_PRICE);
        uint256 submitterBefore = usd.balanceOf(address(this));

        _inboundData();

        assertEq(uint8(_replyStatus()), uint8(ClprTypes.ReplyStatus.SUCCESS));
        uint256 paid = 10e6 - usd.balanceOf(address(connector));
        assertGt(paid, 0, "connector is charged");
        assertEq(usd.balanceOf(address(this)) - submitterBefore, paid, "submitter receives the whole charge");
        // Bounded by maxGasPerMessage (1M) x 2e10 x 1.1 margin / 1e12 = 22,000 token units.
        assertLe(paid, 22_000, "charge is in token units, not 18-decimal gas cost");
        assertEq(usd.balanceOf(address(service)), 100e6, "service holds only the stake");
        assertEq(service.getConnector(channelId, connectorId).slashCount, 0);
    }

    function test_tokenMode_replyCallbackChargedInTokenUnits() public {
        _registerTokenConnector(10e6);
        vm.deal(address(connector), 1 ether);
        vm.txGasPrice(GAS_PRICE);
        uint256 submitterBefore = usd.balanceOf(address(this));

        _inboundReplyToFirstMessage();

        uint256 paid = 10e6 - usd.balanceOf(address(connector));
        assertGt(paid, 0, "connector is charged for the callback");
        assertLe(paid, 22_000, "charge is in token units, not 18-decimal gas cost");
        assertEq(usd.balanceOf(address(this)) - submitterBefore, paid, "submitter receives the whole charge");
        assertEq(address(connector).balance, 1 ether, "native balance is untouched");
        assertEq(app.getResponseCallCount(), 1);
    }

    function test_tokenMode_hugeConnectorBalance_doesNotOverflow() public {
        // Uncapped, balance x 10^12 x 100 overflows and reverts the whole bundle.
        _registerTokenConnector(type(uint256).max / 2);
        vm.txGasPrice(GAS_PRICE);

        _inboundData();

        assertEq(uint8(_replyStatus()), uint8(ClprTypes.ReplyStatus.SUCCESS));
        assertEq(app.getMessageCallCount(), 1, "application received the message");
    }

    function test_tokenMode_nativeBalanceIsIgnored_connectorUnderfunded() public {
        _registerTokenConnector(0);
        vm.deal(address(connector), 1 ether);
        vm.txGasPrice(GAS_PRICE);
        uint256 submitterBefore = usd.balanceOf(address(this));

        _inboundData();

        assertEq(uint8(_replyStatus()), uint8(ClprTypes.ReplyStatus.CONNECTOR_UNDERFUNDED));
        assertEq(service.getConnector(channelId, connectorId).lockedStake, 99e6, "1 USD base penalty");
        assertEq(usd.balanceOf(address(this)) - submitterBefore, 1e6, "penalty paid to the submitter in token");
    }

    function test_tokenMode_payShortfall_slashesConnector() public {
        _registerTokenConnector(10e6);
        connector.setPayShortfall(true);
        vm.txGasPrice(GAS_PRICE);

        _inboundData();

        assertEq(service.getConnector(channelId, connectorId).slashCount, 1);
        assertEq(service.getConnector(channelId, connectorId).lockedStake, 99e6);
    }

    function test_tokenMode_slashProceedsCredited_whenSubmitterAndOwnerRejectToken() public {
        _registerTokenConnector(0);
        vm.txGasPrice(GAS_PRICE);
        // The test contract is both the submitter and the owner (fallback recipient).
        usd.setBlocked(address(this), true);

        _inboundData();

        usd.setBlocked(address(this), false);
        assertEq(service.pendingWithdrawals(address(this)), 1e6);
        uint256 before = usd.balanceOf(address(this));
        service.collectPending();
        assertEq(usd.balanceOf(address(this)) - before, 1e6);
    }

    function test_tokenMode_freeExecution_skipsCharge() public {
        ClprTypes.EconomicConfig memory econ = defaultEcon;
        econ.messageExecutionCost = 0;
        service.updateEconomicConfiguration(econ);
        _registerTokenConnector(0);
        vm.txGasPrice(GAS_PRICE);

        _inboundData();

        assertEq(uint8(_replyStatus()), uint8(ClprTypes.ReplyStatus.SUCCESS));
        assertEq(service.getConnector(channelId, connectorId).slashCount, 0);
    }
}

/// @notice A fee token with more than 18 decimals: an 18-decimal gas cost is multiplied, not divided,
///         into token units.
contract BundleLib_FeeTokenHighDecimalsTest is BundleLibTestBase {
    uint256 internal constant GAS_PRICE = 2e10;
    uint256 internal constant TOKEN = 1e24;

    MockFeeToken internal usd;

    function _feeTokenForDeploy() internal override returns (address) {
        usd = new MockFeeToken(24);
        return address(usd);
    }

    function _beforeInitialize() internal override {
        defaultEcon.minLockedStake = 100 * TOKEN;
        defaultEcon.basePenalty = TOKEN;
        usd.mint(address(this), 1_000 * TOKEN);
        usd.approve(address(service), type(uint256).max);
    }

    function _registerTokenConnector(uint256 operatingBalance) internal {
        connectorId = ConnectorRegistrar.registerTokenMode(
            IClprService(address(service)), channelId, keccak256("fee-token-connector"), address(connector), owner
        );
        connector.setPayToken(address(usd));
        usd.mint(address(connector), operatingBalance);
    }

    function _inboundData() internal {
        bytes memory dataPayload =
            ClprProtobuf.encodeDataMessage(connectorId, abi.encodePacked(address(app)), hex"AA01BB02", hex"01020304");
        _submitSingleInboundMessage(dataPayload);
    }

    function _replyStatus() internal returns (ClprTypes.ReplyStatus) {
        return ClprProtobuf.decodeReplyMessage(service.getMessage(channelId, 1).payload).status;
    }

    function test_highDecimals_chargeIsGasCostScaledUp() public {
        _registerTokenConnector(10 * TOKEN);
        vm.txGasPrice(GAS_PRICE);
        uint256 submitterBefore = usd.balanceOf(address(this));

        _inboundData();

        assertEq(uint8(_replyStatus()), uint8(ClprTypes.ReplyStatus.SUCCESS));
        uint256 paid = 10 * TOKEN - usd.balanceOf(address(connector));
        assertGt(paid, 0, "connector is charged");
        assertEq(paid % 1e6, 0, "an 18-decimal cost times 10^6");
        // Bounded by maxGasPerMessage (1M) x 2e10 x 1.1 margin x 1e6.
        assertLe(paid, 22_000 * 1e18);
        assertEq(usd.balanceOf(address(this)) - submitterBefore, paid, "submitter receives the whole charge");
    }

    function test_highDecimals_balanceIsScaledDownForTheGasBound() public {
        // 1e15 units would pay for ~45,000 gas read as 18 decimals; at 24 decimals they pay for none.
        _registerTokenConnector(1e15);
        vm.txGasPrice(GAS_PRICE);

        _inboundData();

        assertEq(uint8(_replyStatus()), uint8(ClprTypes.ReplyStatus.CONNECTOR_UNDERFUNDED));
        assertEq(app.getMessageCallCount(), 0, "application is not called");
    }
}
