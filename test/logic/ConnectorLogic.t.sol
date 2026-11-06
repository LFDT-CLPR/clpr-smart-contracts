// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {ClprService} from "@hiero-ledger/clpr/ClprService.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";
import {ConnectorRegistrar} from "@test/helpers/ConnectorRegistrar.sol";
import {ClprTestBase} from "@test/helpers/ClprTestBase.sol";

/// @dev A contract that always reverts on ETH receive — used to exercise ClprTransferFailed.
contract RejectingReceiver {
    receive() external payable {
        revert();
    }
}

contract ConnectorLogicTest is ClprTestBase {
    function test_registerConnector_revert_clprDisabled() public {
        service.setClprEnabled(false);

        bytes32 dummyCommit = keccak256("dummy");
        vm.expectRevert(ClprTypes.ClprDisabled.selector);
        service.registerConnector(dummyCommit);
    }

    function test_completeConnector_revert_channelNotFound() public {
        bytes32 unknownConn = keccak256("unknown-channel");
        vm.expectRevert(ClprTypes.ClprChannelNotFound.selector);
        service.completeConnector(hex"01", hex"", hex"", bytes32(0), unknownConn, address(connector), owner);
    }

    function test_completeConnector_revert_tooManyConnectors_limitOne() public {
        ClprTypes.EconomicConfig memory econ = _defaultEconomicConfig();
        econ.maxConnectors = 1; // uint32 cast not required; struct uses uint32
        service.updateEconomicConfiguration(econ);

        bytes32 seed1 = keccak256(abi.encodePacked("svc-conn-1"));
        bytes32 cid1 = ConnectorRegistrar.register(service, channelId, seed1, address(connector), owner, 0.5 ether);
        cid1;

        bytes32 seed2 = keccak256(abi.encodePacked("svc-conn-2"));
        uint256 pk2 = uint256(keccak256(abi.encodePacked("clpr.test.connectorSigner", seed2)));
        Vm.Wallet memory w2 = vm.createWallet(pk2);
        bytes memory pubKey2 = abi.encodePacked(w2.publicKeyX, w2.publicKeyY);

        bytes32 connectorId2 = service.deriveConnectorId(channelId, pubKey2, bytes32(0));

        bytes32 commitment2 = keccak256(abi.encodePacked(connectorId2, pubKey2));
        service.registerConnector(commitment2);

        bytes32 msgHash2 = keccak256(abi.encodePacked(connectorId2, address(service)));
        bytes32 ethHash2 = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash2));
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(pk2, ethHash2);
        bytes memory sig2 = abi.encodePacked(r2, s2, v2);

        vm.expectRevert(ClprTypes.ClprTooManyConnectors.selector);
        service.completeConnector{value: 0.5 ether}(
            connectorId2, pubKey2, sig2, bytes32(0), channelId, address(connector), owner
        );
    }

    function test_topUpConnectorStake_revert_zeroAmount() public {
        _registerTestConnector();

        vm.expectRevert(ClprTypes.ClprInsufficientStake.selector);
        service.topUpConnectorStake(channelId, connectorId, 0);
    }

    function test_topUpConnectorStake_revert_connectorNotFound() public {
        bytes32 unknownConnector = keccak256("unknown-connector");
        vm.expectRevert(ClprTypes.ClprConnectorNotFound.selector);
        service.topUpConnectorStake{value: 0.1 ether}(channelId, unknownConnector, 0.1 ether);
    }

    function test_topUpConnectorStake_success_increasesStake() public {
        _registerTestConnector();

        ClprTypes.Connector memory before = service.getConnector(channelId, connectorId);
        uint256 topUp = 0.2 ether;

        service.topUpConnectorStake{value: topUp}(channelId, connectorId, topUp);

        ClprTypes.Connector memory after_ = service.getConnector(channelId, connectorId);
        assertEq(after_.lockedStake, before.lockedStake + topUp);
    }

    receive() external payable {}
}

contract ConnectorManagerTest is ClprTestBase {
    address public admin = address(0x1000);

    bytes32 internal cid; // populated by _register

    function _register(uint256 stake) internal {
        cid = _registerConnectorWithStake(keccak256(abi.encodePacked("cm-test")), admin, stake);
    }

    // ── Self-authenticating registration ───────────────────────────────

    function test_registerConnector_happyPath() public {
        _register(1 ether);

        // connectorId is always a 32-byte keccak256 hash packed as bytes
        assertEq(cid.length, 32);
        ClprTypes.Connector memory stored = service.getConnector(channelId, cid);
        assertEq(stored.connectorContract, address(connector));
        assertEq(stored.admin, admin);
        assertEq(stored.lockedStake, 1 ether);
    }

    function test_registerConnector_revert_badSignature() public {
        // Sign with key B, but supply key A's pubKey — sig won't recover to A's address.
        uint256 pkA = uint256(keccak256("A"));
        uint256 pkB = uint256(keccak256("B"));
        Vm.Wallet memory wA = vm.createWallet(pkA);
        bytes memory pubKeyA = abi.encodePacked(wA.publicKeyX, wA.publicKeyY);
        bytes32 connectorId = service.deriveConnectorId(channelId, pubKeyA, bytes32(0));

        // Commit with pubKeyA
        bytes32 commitment = keccak256(abi.encodePacked(connectorId, pubKeyA));
        service.registerConnector(commitment);

        // Sign with pkB (wrong key)
        bytes32 msgHash = keccak256(abi.encodePacked(connectorId, address(service)));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pkB, ethHash);
        bytes memory badSig = abi.encodePacked(r, s, v);

        vm.expectRevert(ClprTypes.ClprInvalidSignature.selector);
        service.completeConnector{value: 1 ether}(
            connectorId, pubKeyA, badSig, bytes32(0), channelId, address(connector), admin
        );
    }

    function test_registerConnector_revert_signatureFromAnotherManager() public {
        // Replay protection: a signature scoped to a different service address must
        // not register on this service.
        uint256 pk = uint256(keccak256("R"));
        Vm.Wallet memory w = vm.createWallet(pk);
        bytes memory pubKey = abi.encodePacked(w.publicKeyX, w.publicKeyY);
        bytes32 connectorId = service.deriveConnectorId(channelId, pubKey, bytes32(0));

        // Commit
        bytes32 commitment = keccak256(abi.encodePacked(connectorId, pubKey));
        service.registerConnector(commitment);

        // Sign for a DIFFERENT service address
        address otherService = address(0xDEAD);
        bytes32 msgHash = keccak256(abi.encodePacked(connectorId, otherService));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(ClprTypes.ClprInvalidSignature.selector);
        service.completeConnector{value: 1 ether}(
            connectorId, pubKey, sig, bytes32(0), channelId, address(connector), admin
        );
    }

    function test_registerConnector_revert_invalidPubKeyLength() public {
        // A 32-byte pubKey (not 64) should fail signature verification.
        // Must derive the connectorId from the short key so the derivation check passes,
        // then the sig check fires with ClprInvalidSignature.
        bytes memory shortKey = new bytes(32);
        bytes32 connectorId = service.deriveConnectorId(channelId, shortKey, bytes32(0));

        bytes32 commitment = keccak256(abi.encodePacked(connectorId, shortKey));
        service.registerConnector(commitment);

        bytes memory sig = new bytes(65);

        vm.expectRevert(ClprTypes.ClprInvalidSignature.selector);
        service.completeConnector{value: 1 ether}(
            connectorId, shortKey, sig, bytes32(0), channelId, address(connector), admin
        );
    }

    function test_registerConnector_revert_alreadyExists() public {
        _register(1 ether);

        // Re-derive the same connectorId and manually do commit-reveal to hit AlreadyExists.
        uint256 pk =
            uint256(keccak256(abi.encodePacked("clpr.test.connectorSigner", keccak256(abi.encodePacked("cm-test")))));
        Vm.Wallet memory w = vm.createWallet(pk);
        bytes memory pubKey = abi.encodePacked(w.publicKeyX, w.publicKeyY);
        bytes32 connectorId = service.deriveConnectorId(channelId, pubKey, bytes32(0));

        bytes32 commitment = keccak256(abi.encodePacked(connectorId, pubKey));
        service.registerConnector(commitment);

        bytes32 msgHash = keccak256(abi.encodePacked(connectorId, address(service)));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(ClprTypes.ClprConnectorAlreadyExists.selector);
        service.completeConnector{value: 1 ether}(
            connectorId, pubKey, sig, bytes32(0), channelId, address(connector), admin
        );
    }

    function test_registerConnector_revert_invalidContract() public {
        // Manually commit-reveal with an EOA connector contract to hit ClprInvalidconnector.
        uint256 pk = uint256(keccak256("invalid-contract-test"));
        Vm.Wallet memory w = vm.createWallet(pk);
        bytes memory pubKey = abi.encodePacked(w.publicKeyX, w.publicKeyY);
        bytes32 connectorId = service.deriveConnectorId(channelId, pubKey, bytes32(0));

        bytes32 commitment = keccak256(abi.encodePacked(connectorId, pubKey));
        service.registerConnector(commitment);

        bytes32 msgHash = keccak256(abi.encodePacked(connectorId, address(service)));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        address eoa = address(0x999);
        vm.expectRevert(ClprTypes.ClprInvalidConnectorContract.selector);
        service.completeConnector{value: 1 ether}(connectorId, pubKey, sig, bytes32(0), channelId, eoa, admin);
    }

    function test_registerConnector_revert_insufficientStake() public {
        // Manually commit-reveal with insufficient stake to hit ClprInsufficientStake.
        uint256 pk = uint256(keccak256("insufficient-stake-test"));
        Vm.Wallet memory w = vm.createWallet(pk);
        bytes memory pubKey = abi.encodePacked(w.publicKeyX, w.publicKeyY);
        bytes32 connectorId = service.deriveConnectorId(channelId, pubKey, bytes32(0));

        bytes32 commitment = keccak256(abi.encodePacked(connectorId, pubKey));
        service.registerConnector(commitment);

        bytes32 msgHash = keccak256(abi.encodePacked(connectorId, address(service)));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(ClprTypes.ClprInsufficientStake.selector);
        service.completeConnector{value: 0.05 ether}(
            connectorId, pubKey, sig, bytes32(0), channelId, address(connector), admin
        );
    }

    // ── Deregistration ─────────────────────────────────────────────────

    function test_removeConnector_returnsStake() public {
        _register(1 ether);
        address recipient = address(0x20);

        vm.prank(admin);
        service.removeConnector(channelId, cid, recipient);

        assertEq(recipient.balance, 1 ether);
        assertFalse(service.hasConnector(channelId, cid));
    }

    /// @dev removeConnector sends the connector's locked stake to `recipient`.
    ///      If `recipient` is a contract that reverts on receive, the call returns
    ///      ok=false and ConnectorLogic reverts with ClprTransferFailed.
    ///      The tx revert means the connector record is still intact, so the admin
    ///      can retry with a different recipient address.
    function test_removeConnector_transferFails_reverts() public {
        _register(1 ether);
        address rejecter = address(new RejectingReceiver());

        vm.prank(admin);
        vm.expectRevert(ClprTypes.ClprTransferFailed.selector);
        service.removeConnector(channelId, cid, rejecter);

        // Connector still exists — admin can retry with a valid recipient.
        assertTrue(service.hasConnector(channelId, cid));
    }

    function test_removeConnector_revert_unauthorized() public {
        _register(1 ether);
        vm.prank(address(0x99));
        vm.expectRevert(ClprTypes.ClprConnectorUnauthorized.selector);
        service.removeConnector(channelId, cid, address(0x99));
    }

    function test_removeConnector_revert_notFound() public {
        vm.prank(admin);
        vm.expectRevert(ClprTypes.ClprConnectorNotFound.selector);
        service.removeConnector(channelId, hex"DEAD", admin);
    }

    // ── TopUp Stake ────────────────────────────────────────────────────

    function test_topUpStake() public {
        _register(1 ether);
        service.topUpConnectorStake{value: 0.5 ether}(channelId, cid, 0.5 ether);
        assertEq(service.getConnector(channelId, cid).lockedStake, 1.5 ether);
    }

    // charge and slash are internal — tested via submitBundle in BundleProcessor tests

    // ── In-flight deregistration guard ──────────────────

    function test_removeConnector_revert_hasInflightMessages() public {
        _register(1 ether);
        _setupChannelForInflightTest();

        service.sendMessage(channelId, cid, abi.encodePacked(address(0xDEAD)), hex"01");

        vm.prank(admin);
        vm.expectRevert(ClprTypes.ClprConnectorHasInflightMessages.selector);
        service.removeConnector(channelId, cid, address(0x20));
    }

    function test_removeConnector_succeeds_afterInflightReplyProcessed() public {
        _register(1 ether);
        _setupChannelForInflightTest();

        service.sendMessage(channelId, cid, abi.encodePacked(address(0xDEAD)), hex"01");

        _submitFailureReplyBundle(1, ClprTypes.ReplyStatus.SUCCESS);

        address recipient = address(0x30);
        vm.prank(admin);
        service.removeConnector(channelId, cid, recipient);

        assertFalse(service.hasConnector(channelId, cid));
        assertEq(recipient.balance, 1 ether);
    }

    /// @dev Bug-report scenario: a failure reply (CONNECTOR_UNDERFUNDED / CONNECTOR_NOT_FOUND)
    ///      drives BOTH the in-flight decrement AND source-side slashing on the SAME connector.
    ///      Asserts the slash does not revert the in-flight decrement, so a partially-slashed
    ///      connector can still be deregistered and its remaining stake is not stuck on-ledger.
    function test_removeConnector_succeeds_afterSlashingReplyProcessed() public {
        _register(1 ether);
        _setupChannelForInflightTest();

        service.sendMessage(channelId, cid, abi.encodePacked(address(0xDEAD)), hex"01");

        // CONNECTOR_UNDERFUNDED reply: decrements inflight (1 -> 0) AND slashes the connector.
        _submitFailureReplyBundle(1, ClprTypes.ReplyStatus.CONNECTOR_UNDERFUNDED);

        // Slash must have fired but only partially (basePenalty 0.01 < 1 ether, threshold 5).
        ClprTypes.Connector memory c = service.getConnector(channelId, cid);
        assertEq(c.lockedStake, 1 ether - 0.01 ether, "stake reduced by basePenalty");

        // The slash must NOT have reverted the inflight decrement: deregister must succeed
        // and return the remaining stake (not leave it stuck on-ledger).
        address recipient = address(0x31);
        vm.prank(admin);
        service.removeConnector(channelId, cid, recipient);

        assertFalse(service.hasConnector(channelId, cid));
        assertEq(recipient.balance, 1 ether - 0.01 ether, "remaining stake returned, not stuck");
    }

    function _setupChannelForInflightTest() internal {
        // The channel is already set up in setUp(). Just add the ledger config and endpoint.
        service.updateLedgerConfiguration(hex"1234", defaultThrottles, "", "");

        bytes memory epKey = new bytes(64);
        epKey[0] = 0x02;
    }
}
