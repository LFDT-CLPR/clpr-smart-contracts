// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ConnectorLib} from "@hiero-ledger/clpr/libraries/service/ConnectorLib.sol";
import {ExactGasCall} from "@hiero-ledger/clpr/libraries/service/ExactGasCall.sol";
import {MockClprConnector} from "@test/mocks/MockClprConnector.sol";

/// @dev Contract that unconditionally rejects ETH — used to simulate non-payable recipients.
contract RejectingEth {
    receive() external payable {
        revert("no ETH");
    }
}

/// @dev Minimal harness that exposes ConnectorLib functions for unit-level testing.
contract ConnectorLibHarness {
    /// @dev The default `connectorInboundGasStipend`, the gas `payForExecution` receives.
    uint256 private constant PAY_GAS = 500_000;

    mapping(bytes32 => ClprTypes.Connector) internal _connectors;
    mapping(bytes32 => bool) internal _connectorExists;
    mapping(address => uint256) public pendingWithdrawals;

    address private _fallback = address(this);

    receive() external payable {}

    function setFallback(address fb) external {
        _fallback = fb;
    }

    function setupConnector(bytes32 channelId, bytes32 connectorId, address connectorContract, uint256 stake) external {
        bytes32 key = keccak256(abi.encodePacked(channelId, connectorId));
        _connectors[key] = ClprTypes.Connector({
            connectorId: connectorId,
            connectorContract: connectorContract,
            admin: address(0),
            lockedStake: stake,
            slashCount: 0
        });
        _connectorExists[key] = true;
    }

    function slash(
        bytes32 channelId,
        bytes32 connectorId,
        address recipient,
        uint256 basePenalty,
        uint256 penaltyMultiplier,
        uint32 slashBanThreshold
    ) external returns (uint256 penaltyAmount, bool banned) {
        return ConnectorLib.slash(
            _connectors,
            _connectorExists,
            pendingWithdrawals,
            _fallback,
            channelId,
            connectorId,
            recipient,
            basePenalty,
            penaltyMultiplier,
            slashBanThreshold
        );
    }

    function charge(bytes32 channelId, bytes32 connectorId, uint256 amount, address recipient)
        external
        returns (bool success)
    {
        return _charge(channelId, connectorId, amount, recipient, PAY_GAS);
    }

    function chargeWithGas(bytes32 channelId, bytes32 connectorId, uint256 amount, address recipient, uint256 payGas)
        external
        returns (bool success)
    {
        return _charge(channelId, connectorId, amount, recipient, payGas);
    }

    function _charge(bytes32 channelId, bytes32 connectorId, uint256 amount, address recipient, uint256 payGas)
        private
        returns (bool)
    {
        return ConnectorLib.charge(
            _connectors,
            _connectorExists,
            pendingWithdrawals,
            _fallback,
            channelId,
            connectorId,
            amount,
            recipient,
            payGas
        );
    }

    function topUpStake(bytes32 channelId, bytes32 connectorId, uint256 amount) external {
        ConnectorLib.topUpStake(_connectors, _connectorExists, channelId, connectorId, amount);
    }

    function hasConnector(bytes32 channelId, bytes32 connectorId) external view returns (bool) {
        return _connectorExists[keccak256(abi.encodePacked(channelId, connectorId))];
    }

    function getLockedStake(bytes32 channelId, bytes32 connectorId) external view returns (uint256) {
        return _connectors[keccak256(abi.encodePacked(channelId, connectorId))].lockedStake;
    }

    function getSlashCount(bytes32 channelId, bytes32 connectorId) external view returns (uint32) {
        return _connectors[keccak256(abi.encodePacked(channelId, connectorId))].slashCount;
    }

    // ── completeRegistration ──────────────────────────────────────────

    mapping(bytes32 => bool) internal _pendingConnectorCommitments;

    function registerCommitment(bytes32 commitment) external {
        _pendingConnectorCommitments[commitment] = true;
    }

    function completeRegistration(
        bytes32 connectorId,
        bytes calldata pubKey,
        bytes calldata sig,
        bytes32 salt,
        bytes32 channelId,
        address connectorContract,
        address admin,
        uint256 stake
    ) external {
        ClprTypes.EconomicConfig memory econ;
        ConnectorLib.completeRegistration(
            _connectors,
            _connectorExists,
            _pendingConnectorCommitments,
            econ,
            connectorId,
            pubKey,
            sig,
            salt,
            channelId,
            connectorContract,
            admin,
            stake
        );
    }
}

contract ConnectorLibTest is Test {
    // Mirror the event from ConnectorLib to assert emission
    event ConnectorCharged(bytes32 indexed connectorKey, uint256 amount, address recipient);
    ConnectorLibHarness internal harness;
    MockClprConnector internal dummyConnector;
    bytes32 internal cid = keccak256(abi.encodePacked("slash-test-connector"));
    bytes32 internal connId = keccak256(abi.encodePacked("test-channel"));

    function setUp() public {
        harness = new ConnectorLibHarness();
        dummyConnector = new MockClprConnector();
    }

    // ── Auto-ban when stake drains to zero via penalty clamping ────

    /// @dev With basePenalty=0.01, multiplier=2, threshold=5, stake=0.015:
    ///      slash-1 takes 0.01 → stake=0.005; slash-2 computes 0.02 but clamps to
    ///      0.005, leaving stake=0. The connector should be auto-banned on slash-2
    ///      even though slashCount (2) has not yet reached slashBanThreshold (5).
    function test_slash_autoBansWhenStakeDrainsToZero() public {
        uint256 base = 0.01 ether;
        uint256 stake = base + base / 2; // 0.015 ether — drains to zero on slash-2
        harness.setupConnector(connId, cid, address(dummyConnector), stake);
        vm.deal(address(harness), stake);

        // Slash 1: normal deduction — connector survives.
        (, bool banned1) = harness.slash(connId, cid, address(this), base, 2, 5);
        assertFalse(banned1, "slash-1 should not ban");
        assertTrue(harness.hasConnector(connId, cid), "connector should still exist after slash-1");
        assertEq(harness.getLockedStake(connId, cid), base / 2, "stake should be 0.005 after slash-1");

        // Slash 2: penalty overflows, clamps to remaining 0.005 ether → stake == 0.
        // B9: connector should be auto-banned even though slashCount < slashBanThreshold.
        (, bool banned2) = harness.slash(connId, cid, address(this), base, 2, 5);
        assertTrue(banned2, "should auto-ban when locked stake reaches zero");
        assertFalse(harness.hasConnector(connId, cid), "connector entry should be deleted on auto-ban");
    }

    function test_slash_setsPenaltyMultiplierTo1_whenMultiplierIsZero() public {
        uint256 base = 0.01 ether;
        uint256 stake = 1 ether;
        harness.setupConnector(connId, cid, address(dummyConnector), stake);
        vm.deal(address(harness), stake);

        // Advance slashCount to 1 so the penalty loop runs on the next slash.
        // With slashCount=0 the loop body never executes and the multiplier correction
        // at line 177 is never observable; a zero multiplier left uncorrected would
        // panic with division-by-zero inside the loop (max / penaltyMultiplier).
        harness.slash(connId, cid, address(this), base, 1, 100);

        // slashCount is now 1 — passing multiplier=0 would revert if not corrected to 1.
        (uint256 penalty, bool banned) = harness.slash(connId, cid, address(this), base, 0, 100);
        assertFalse(banned);
        assertEq(penalty, base, "corrected multiplier of 1 leaves penalty unchanged after one loop iteration");
    }

    /// @dev Verify that a connector is NOT auto-banned when stake is positive after a slash,
    ///      i.e., the fix does not affect the normal (non-draining) slash path.
    function test_slash_doesNotBanWhenStakeRemains() public {
        uint256 base = 0.01 ether;
        uint256 stake = 1 ether; // large enough that penalty never drains it
        harness.setupConnector(connId, cid, address(dummyConnector), stake);
        vm.deal(address(harness), stake);

        (, bool banned) = harness.slash(connId, cid, address(this), base, 2, 5);
        assertFalse(banned, "should not ban when stake remains after slash");
        assertTrue(harness.hasConnector(connId, cid));
        assertGt(harness.getLockedStake(connId, cid), 0, "stake should be positive");
    }

    /// @dev Verify that reaching slashBanThreshold still bans even if stake > 0.
    function test_slash_bansAtThreshold_withRemainingStake() public {
        uint256 base = 0.01 ether;
        uint256 stake = 10 ether; // large stake — threshold reached before zero
        uint32 threshold = 3;
        harness.setupConnector(connId, cid, address(dummyConnector), stake);
        vm.deal(address(harness), stake);
        assertEq(harness.getSlashCount(connId, cid), 0);

        for (uint32 i = 0; i < threshold - 1; i++) {
            (, bool b) = harness.slash(connId, cid, address(this), base, 1, threshold);
            assertFalse(b, "should not ban before threshold");
        }

        (, bool banned) = harness.slash(connId, cid, address(this), base, 1, threshold);
        assertTrue(banned, "should ban at threshold");
        assertFalse(harness.hasConnector(connId, cid));
    }

    /// @dev Verify that a slash against an unknown connectorId is a no-op.
    function test_slash_unknownConnector_returnsZero() public {
        (uint256 penalty, bool banned) =
            harness.slash(connId, keccak256(abi.encodePacked("nonexistent")), address(this), 0.01 ether, 2, 5);
        assertEq(penalty, 0);
        assertFalse(banned);
    }

    // ── B8: pull-payment accumulation when ETH delivery fails

    /// @dev When both recipient and fallback reject the slash proceeds, the amount
    ///      must land in pendingWithdrawals[recipient] rather than staying silently stuck.
    function test_slash_creditsRecipientPending_whenBothReject() public {
        RejectingEth rejecter = new RejectingEth();
        RejectingEth fallbackRejecter = new RejectingEth();
        harness.setFallback(address(fallbackRejecter));

        uint256 base = 0.01 ether;
        harness.setupConnector(connId, cid, address(dummyConnector), 1 ether);
        vm.deal(address(harness), 1 ether);

        (uint256 penalty,) = harness.slash(connId, cid, address(rejecter), base, 1, 5);
        assertGt(penalty, 0, "penalty must be positive");
        assertEq(harness.pendingWithdrawals(address(rejecter)), penalty, "proceeds should be credited to recipient");
        assertEq(address(rejecter).balance, 0, "rejecter should hold no ETH");
        assertEq(harness.pendingWithdrawals(address(fallbackRejecter)), 0, "fallback should not be credited");
    }

    /// @dev When the recipient accepts ETH normally, no pending balance is created.
    function test_slash_noPending_whenRecipientAccepts() public {
        uint256 base = 0.01 ether;
        harness.setupConnector(connId, cid, address(dummyConnector), 1 ether);
        vm.deal(address(harness), 1 ether);

        uint256 balBefore = address(this).balance;
        (uint256 penalty,) = harness.slash(connId, cid, address(this), base, 1, 5);

        assertEq(harness.pendingWithdrawals(address(this)), 0, "no pending when delivery succeeded");
        assertEq(address(this).balance, balBefore + penalty, "recipient should have received ETH directly");
    }

    /// @dev When recipient rejects but fallback accepts, funds go to fallback and no pending is created.
    function test_slash_noPending_whenOnlyFallbackAccepts() public {
        RejectingEth rejecter = new RejectingEth();
        harness.setFallback(address(this)); // test contract accepts ETH

        uint256 base = 0.01 ether;
        harness.setupConnector(connId, cid, address(dummyConnector), 1 ether);
        vm.deal(address(harness), 1 ether);

        uint256 balBefore = address(this).balance;
        (uint256 penalty,) = harness.slash(connId, cid, address(rejecter), base, 1, 5);

        assertEq(harness.pendingWithdrawals(address(rejecter)), 0, "no pending when fallback accepted");
        assertEq(address(this).balance, balBefore + penalty, "fallback (this) should have received ETH");
    }

    /// @dev charge: when both recipient and fallback reject, amount accumulates in pendingWithdrawals.
    function test_charge_creditsRecipientPending_whenBothReject() public {
        RejectingEth rejecter = new RejectingEth();
        RejectingEth fallbackRejecter = new RejectingEth();
        harness.setFallback(address(fallbackRejecter));

        uint256 amount = 0.01 ether;
        harness.setupConnector(connId, cid, address(dummyConnector), 1 ether);
        // Connector contract needs ETH to pay
        vm.deal(address(dummyConnector), 1 ether);
        vm.deal(address(harness), 0); // harness starts with 0 so we can track the inflow

        bool success = harness.charge(connId, cid, amount, address(rejecter));
        assertTrue(success, "charge should succeed even when delivery fails");
        assertEq(
            harness.pendingWithdrawals(address(rejecter)), amount, "undelivered charge should be credited to recipient"
        );
        assertEq(address(rejecter).balance, 0, "rejecter holds no ETH");
    }

    function test_slash_overflowGuard_clampsToLockedStakeAndBans() public {
        uint256 stake = 1 ether;
        harness.setupConnector(connId, cid, address(dummyConnector), stake);
        vm.deal(address(harness), stake);

        // First slash: basePenalty = 0 to increment slashCount without changing stake
        (uint256 p1, bool b1) = harness.slash(connId, cid, address(this), 0, 2, 100);
        assertEq(p1, 0, "first slash should have zero penalty");
        assertFalse(b1, "first slash should not ban");
        assertTrue(harness.hasConnector(connId, cid), "connector should still exist after first slash");
        assertEq(harness.getLockedStake(connId, cid), stake, "stake should remain unchanged after first slash");

        // Second slash: trigger overflow guard by using max basePenalty and multiplier>1
        uint256 balBefore = address(this).balance;
        (uint256 p2, bool b2) = harness.slash(connId, cid, address(this), type(uint256).max, 2, 100);
        assertEq(p2, stake, "penalty should clamp to lockedStake on overflow");
        assertTrue(b2, "should auto-ban when stake reduced to zero");
        assertFalse(harness.hasConnector(connId, cid), "connector should be deleted after ban");
        assertEq(address(this).balance, balBefore + stake, "recipient should receive the full locked stake");
    }

    function test_charge_returnsFalse_whenConnectorBalanceTooLow() public {
        harness.setupConnector(connId, cid, address(dummyConnector), 1 ether);
        bool ok = harness.charge(connId, cid, 0.01 ether, address(this));
        assertFalse(ok, "charge should return false when connector has insufficient balance");
    }

    /// A connector that sends the amount straight back pays within the smallest payment budget the
    /// configuration accepts.
    function test_charge_succeeds_withTheMinimumPaymentGasLimit() public {
        harness.setupConnector(connId, cid, address(dummyConnector), 1 ether);
        vm.deal(address(dummyConnector), 1 ether);
        bool ok =
            harness.chargeWithGas(connId, cid, 0.01 ether, address(this), ClprTypes.MIN_CONNECTOR_PAYMENT_GAS_LIMIT);
        assertTrue(ok, "a plain payment must fit the minimum payment budget");
    }

    /// The payment gets its whole budget or the charge reverts: a caller left with too little gas
    /// cannot make a funded connector's payment fail into a slash.
    function test_charge_reverts_whenThePaymentCannotGetItsFullGas() public {
        harness.setupConnector(connId, cid, address(dummyConnector), 1 ether);
        vm.deal(address(dummyConnector), 1 ether);
        uint256 payGas = ClprTypes.MIN_CONNECTOR_PAYMENT_GAS_LIMIT;
        (bool ok, bytes memory ret) = address(harness).call{gas: payGas}(
            abi.encodeCall(harness.chargeWithGas, (connId, cid, 0.01 ether, address(this), payGas))
        );
        assertFalse(ok, "the charge must not run short");
        // forge-lint: disable-next-line(unsafe-typecast)
        assertEq(bytes4(ret), ExactGasCall.InsufficientGasForCall.selector, "refused by the gas check");
    }

    /// An EIP-7702 account that cleared its delegation has no code: the call runs nothing and pays
    /// nothing, so the charge fails instead of reverting the bundle.
    function test_charge_returnsFalse_whenConnectorHasNoCode() public {
        address codeless = makeAddr("codeless-connector");
        harness.setupConnector(connId, cid, codeless, 1 ether);
        vm.deal(codeless, 1 ether);
        assertFalse(harness.charge(connId, cid, 0.01 ether, address(this)), "a connector without code pays nothing");
    }

    function test_charge_returnsFalse_whenPayReverts() public {
        dummyConnector.setPayReverts(true);
        harness.setupConnector(connId, cid, address(dummyConnector), 1 ether);
        vm.deal(address(dummyConnector), 1 ether);
        bool ok = harness.charge(connId, cid, 0.01 ether, address(this));
        assertFalse(ok, "charge should return false when payForExecution reverts");
    }

    function test_charge_returnsFalse_whenPaySendsShortfall() public {
        dummyConnector.setPayShortfall(true);
        harness.setupConnector(connId, cid, address(dummyConnector), 1 ether);
        vm.deal(address(dummyConnector), 1 ether);
        bool ok = harness.charge(connId, cid, 0.01 ether, address(this));
        assertFalse(ok, "charge should return false when connector sends shortfall");
    }

    function test_slash_fallbackReceivesFunds_whenRecipientRejects() public {
        RejectingEth rejecter = new RejectingEth();
        harness.setFallback(address(this)); // test contract accepts ETH

        uint256 stake = 1 ether;
        harness.setupConnector(connId, cid, address(dummyConnector), stake);
        vm.deal(address(harness), stake);

        uint256 balBefore = address(this).balance;
        (uint256 penalty,) = harness.slash(connId, cid, address(rejecter), 0.01 ether, 1, 100);
        assertGt(penalty, 0, "penalty must be positive");
        assertEq(harness.pendingWithdrawals(address(rejecter)), 0, "no pending when fallback accepted");
        assertEq(address(this).balance, balBefore + penalty, "fallback receives ETH");
    }

    function test_slash_overflowGuard_innerLoopBreak() public {
        uint256 stake = 1 ether;
        harness.setupConnector(connId, cid, address(dummyConnector), stake);
        vm.deal(address(harness), stake);

        harness.slash(connId, cid, address(this), 0, 2, 100);
        harness.slash(connId, cid, address(this), 0, 2, 100);

        uint256 basePenalty = type(uint256).max / 2 + 1;
        (uint256 p,) = harness.slash(connId, cid, address(this), basePenalty, 2, 100);
        assertEq(p, stake, "penalty should be clamped to locked stake on overflow");
    }

    function test_charge_returnsFalse_connectorNotRegistered() public {
        // No setupConnector call — key absent from _connectorExists.
        bool ok = harness.charge(connId, cid, 0.01 ether, address(this));
        assertFalse(ok, "charge must return false when connector is not registered");
    }

    function test_topUpStake_reverts_connectorNotFound() public {
        vm.expectRevert(ClprTypes.ClprConnectorNotFound.selector);
        harness.topUpStake(connId, cid, 0.01 ether);
    }

    // ── completeRegistration ──────────────────────────────────────────

    function test_completeRegistration_happyPath_passesBothGuards() public {
        uint256 pk = 0xBEEF;
        Vm.Wallet memory w = vm.createWallet(pk);
        bytes memory pubKey = abi.encodePacked(w.publicKeyX, w.publicKeyY);

        bytes32 salt = bytes32(0);
        bytes32 channelId = keccak256("test-conn-reg");
        bytes32 connectorId = keccak256(abi.encodePacked(channelId, pubKey, salt));

        bytes32 commitment = keccak256(abi.encodePacked(connectorId, pubKey));
        harness.registerCommitment(commitment);

        bytes32 msgHash = keccak256(abi.encodePacked(connectorId, address(harness)));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        harness.completeRegistration(
            connectorId, pubKey, sig, salt, channelId, address(dummyConnector), address(this), 0
        );

        assertTrue(
            harness.hasConnector(channelId, connectorId), "connector should be registered after completeRegistration"
        );
    }

    function test_completeRegistration_reverts_commitmentMismatch() public {
        uint256 pk = 0xBEEF;
        Vm.Wallet memory w = vm.createWallet(pk);
        bytes memory pubKey = abi.encodePacked(w.publicKeyX, w.publicKeyY);

        bytes32 salt = bytes32(0);
        bytes32 channelId = keccak256("test-conn-reg-mismatch");
        bytes32 connectorId = keccak256(abi.encodePacked(channelId, pubKey, salt));

        // No registerCommitment call — commitment is absent from the map.
        bytes memory sig = new bytes(65);

        vm.expectRevert(ClprTypes.ClprCommitmentMismatch.selector);
        harness.completeRegistration(
            connectorId, pubKey, sig, salt, channelId, address(dummyConnector), address(this), 0
        );
    }

    function test_completeRegistration_reverts_invalidConnectorId() public {
        uint256 pk = 0xBEEF;
        Vm.Wallet memory w = vm.createWallet(pk);
        bytes memory pubKey = abi.encodePacked(w.publicKeyX, w.publicKeyY);

        bytes32 salt = bytes32(0);
        bytes32 channelId = keccak256("test-conn-reg-invalid-id");
        bytes32 wrongConnectorId = keccak256("wrong-id");

        // Commitment is keyed on wrongConnectorId so line 60 passes.
        bytes32 commitment = keccak256(abi.encodePacked(wrongConnectorId, pubKey));
        harness.registerCommitment(commitment);

        // wrongConnectorId != deriveConnectorId(channelId, pubKey, salt) → line 64 reverts.
        bytes memory sig = new bytes(65);

        vm.expectRevert(ClprTypes.ClprInvalidChannelId.selector);
        harness.completeRegistration(
            wrongConnectorId, pubKey, sig, salt, channelId, address(dummyConnector), address(this), 0
        );
    }

    function test_completeRegistration_reverts_invalidSigLength() public {
        uint256 pk = 0xBEEF;
        Vm.Wallet memory w = vm.createWallet(pk);
        bytes memory pubKey = abi.encodePacked(w.publicKeyX, w.publicKeyY);

        bytes32 salt = bytes32(0);
        bytes32 channelId = keccak256("test-conn-reg-bad-sig");
        bytes32 connectorId = keccak256(abi.encodePacked(channelId, pubKey, salt));

        bytes32 commitment = keccak256(abi.encodePacked(connectorId, pubKey));
        harness.registerCommitment(commitment);

        bytes memory shortSig = new bytes(64); // not 65 bytes → triggers length guard

        vm.expectRevert(ClprTypes.ClprInvalidSignature.selector);
        harness.completeRegistration(
            connectorId, pubKey, shortSig, salt, channelId, address(dummyConnector), address(this), 0
        );
    }

    receive() external payable {}
}
