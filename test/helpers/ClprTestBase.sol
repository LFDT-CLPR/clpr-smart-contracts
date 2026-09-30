// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";
import {ClprService} from "@hiero-ledger/clpr/ClprService.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprDeployHelper} from "@test/helpers/ClprDeployHelper.sol";
import {ConnectorRegistrar} from "@test/helpers/ConnectorRegistrar.sol";
import {MockClprVerifier} from "@test/mocks/MockClprVerifier.sol";
import {MockClprConnector} from "@test/mocks/MockClprConnector.sol";

/// @notice Shared test base providing the channelId derivation helper and
///         peer-endpoint signature utilities.
/// @dev Local chain is "eip155:1337" (set in ClprService constructor in tests).
///      Peer chain is "eip155:1" (returned by MockClprVerifier.verifyConfig).
abstract contract ClprTestBase is Test {
    ClprService public service;
    MockClprVerifier public verifier;
    MockClprConnector public connector;

    address public owner = address(this);

    // Test keypair for ECDSA (use vm.sign for deterministic keys)
    uint256 internal signerPk = 0xBEEF;
    address internal signer;

    // populated by _registerTestConnector (= keccak256(pubKey))
    bytes32 internal connectorId;
    bytes32 public channelId;

    bytes32 internal testingSalt = bytes32(keccak256("salt"));

    ClprTypes.Throttles internal defaultThrottles = ClprTypes.Throttles({
        maxMessagesPerBundle: 100,
        maxMessagePayloadBytes: 1024,
        maxGasPerMessage: 1_000_000,
        maxQueueDepth: 1000,
        maxSyncBytes: 1_048_576,
        maxLocalEndpoints: 0,
        maxPeerEndpoints: 0
    });

    ClprTypes.EconomicConfig internal defaultEcon = ClprTypes.EconomicConfig({
        messageExecutionCost: 0.001 ether,
        endpointMarginPercent: 10,
        minLockedStake: 0.1 ether,
        minEndpointBond: 0,
        basePenalty: 0.01 ether,
        penaltyMultiplier: 2,
        slashBanThreshold: 5,
        connectorQueueQuotaPct: 50,
        connectorInboundGasStipend: 500_000,
        maxChannels: 0,
        maxConnectors: 0
    });

    function setUp() public virtual {
        _setUp();
        _createActiveChannel();
    }

    function _setUp() internal {
        signer = vm.addr(signerPk);

        // Derive channelId from chain pair, pubKey, and salt="salt"
        channelId = _deriveTestChannelId(_signerPubKey(), testingSalt);
        service = _deployClprService(1, "eip155:1337");

        verifier = MockClprVerifier(deployCode("MockClprVerifier.sol:MockClprVerifier"));
        verifier.setVerifyConfigResult("eip155:1", hex"AABB", 1000);
        verifier.setPeerThrottles(defaultThrottles);

        connector = MockClprConnector(payable(deployCode("MockClprConnector.sol:MockClprConnector")));

        // clprEnabled defaults to false; initialize() applies the first
        // config while still disabled, then setClprEnabled(true) is required to
        // reach an enabled state at all (see AdminLogic.setClprEnabled).
        _initializeAndEnable();

        // Register the test peer endpoint so submitBundle passes the roster check.
        ClprTypes.Endpoint[] memory seeds = new ClprTypes.Endpoint[](1);
        seeds[0] = _peerEndpointSeedEntry();
        verifier.setSeedEndpoints(seeds);
    }

    /// @dev Deploys a ClprService using standard test parameters.
    ///      This abstracts the delegated sub-contract deployment logic so test
    ///      files do not need to handle the complex initialization ceremony.
    ///      All tests should use this helper instead of `new ClprService(...)`.
    function _deployClprService(uint32 protocolVersion, string memory chainId) internal returns (ClprService) {
        ClprDeployHelper.Modules memory m = ClprDeployHelper.deployModules();
        bytes memory args = abi.encode(
            owner,
            protocolVersion,
            chainId,
            m.channelLogic,
            m.messagingLogic,
            m.bundleLogic,
            m.connectorLogic,
            m.adminLogic,
            m.bundleDecodeHelper
        );
        return ClprService(payable(deployCode("ClprService.sol:ClprService", args)));
    }

    /// @dev Fixed private key for the test peer endpoint that signs bundles.
    uint256 internal constant PEER_EP_PK = uint256(keccak256("clpr.test.peerEndpoint"));

    function _deriveTestChannelId(bytes memory pubKey, bytes32 salt) internal pure returns (bytes32) {
        bytes memory localChain = bytes("eip155:1337");
        bytes memory peerChain = bytes("eip155:1");
        bytes memory a;
        bytes memory b;
        if (keccak256(localChain) <= keccak256(peerChain)) {
            a = localChain;
            b = peerChain;
        } else {
            a = peerChain;
            b = localChain;
        }
        return keccak256(abi.encodePacked(a, b, pubKey, salt));
    }

    /// @dev Return the 64-byte uncompressed public key for PEER_EP_PK.
    function _peerEndpointPubKey() internal returns (bytes memory) {
        Vm.Wallet memory w = vm.createWallet(PEER_EP_PK);
        return abi.encodePacked(w.publicKeyX, w.publicKeyY);
    }

    /// @dev Build the ClprTypes.Endpoint seed entry for the test peer endpoint.
    ///      The roster is keyed by accountId, so the seed carries a non-empty account id.
    function _peerEndpointSeedEntry() internal pure returns (ClprTypes.Endpoint memory) {
        return ClprTypes.Endpoint({ipAddress: "127.0.0.1", port: 50211, tlsCertificate: hex"", accountId: hex"01"});
    }

    function _setupDefaultConfig() internal {
        ClprTypes.Throttles memory throttles = defaultThrottles;
        service.updateLedgerConfiguration(hex"1234", throttles, "", "");

        ClprTypes.EconomicConfig memory econ = defaultEcon;
        service.updateEconomicConfiguration(econ);
    }

    /// @dev Bootstraps a freshly-deployed `service`: applies the default ledger +
    ///      economic config via initialize() (while still disabled), then enables it.
    function _initializeAndEnable() internal {
        service.initialize(hex"1234", defaultThrottles, "", "", defaultEcon);
        service.setClprEnabled(true);
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    function _createActiveChannel() internal {
        bytes memory pubKey = _signerPubKey();
        channelId = _deriveTestChannelId(pubKey, testingSalt);
        bytes32 commitment = keccak256(abi.encodePacked(channelId, pubKey));
        service.registerChannel(channelId, commitment);

        bytes32 msgHash = keccak256(abi.encodePacked(channelId, address(service)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, _ethSignedHash(msgHash));
        bytes memory sig = abi.encodePacked(r, s, v);

        service.completeChannel(channelId, pubKey, sig, testingSalt, address(verifier), hex"0001", "");
    }

    function _openExtraChannel(bytes32 salt) internal returns (bytes32 connId) {
        bytes memory pubKey = _signerPubKey();
        connId = _deriveTestChannelId(pubKey, salt);
        bytes32 commitment = keccak256(abi.encodePacked(connId, pubKey));
        service.registerChannel(connId, commitment);
        bytes32 msgHash = keccak256(abi.encodePacked(connId, address(service)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, _ethSignedHash(msgHash));
        service.completeChannel(connId, pubKey, abi.encodePacked(r, s, v), salt, address(verifier), hex"0001", "");
    }

    function _signerPubKey() internal returns (bytes memory) {
        Vm.Wallet memory w = vm.createWallet(signerPk);
        return abi.encodePacked(w.publicKeyX, w.publicKeyY);
    }

    function _dummyEndpointKey() internal pure virtual returns (bytes memory) {
        bytes memory k = new bytes(64);
        k[0] = 0x04;
        return k;
    }

    function _key(uint8 marker) internal pure returns (bytes memory) {
        bytes memory k = new bytes(64);
        k[0] = bytes1(marker);
        return k;
    }

    function _ethSignedHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    function _defaultThrottles() internal view returns (ClprTypes.Throttles memory) {
        return defaultThrottles;
    }

    function _defaultEconomicConfig() internal pure returns (ClprTypes.EconomicConfig memory) {
        return ClprTypes.EconomicConfig({
            messageExecutionCost: 0.001 ether,
            endpointMarginPercent: 10,
            minLockedStake: 0.1 ether,
            minEndpointBond: 0,
            basePenalty: 0.01 ether,
            penaltyMultiplier: 2,
            slashBanThreshold: 5,
            connectorQueueQuotaPct: 50,
            connectorInboundGasStipend: 500_000,
            maxChannels: 0,
            maxConnectors: 0
        });
    }

    function _setupDefaultEconomicConfig() internal {
        service.updateEconomicConfiguration(_defaultEconomicConfig());
    }

    function _registerTestConnector() internal virtual {
        connectorId = ConnectorRegistrar.register(
            IClprService(address(service)),
            channelId,
            keccak256(abi.encodePacked("svc-test-connector")),
            address(connector),
            owner,
            0.5 ether
        );
        // Fund the connector contract for any inbound message charging.
        (bool ok,) = address(connector).call{value: 0.5 ether}("");
        require(ok, "fund connector failed");
    }

    /// @dev Registers a connector on `channelId` with a caller-chosen stake and admin,
    ///      for tests that need a stake amount other than _registerTestConnector()'s fixed
    ///      0.5 ether (e.g. exact-penalty-math assertions).
    function _registerConnectorWithStake(bytes32 salt, address admin, uint256 stake) internal returns (bytes32) {
        return
            ConnectorRegistrar.register(
                IClprService(address(service)), channelId, salt, address(connector), admin, stake
            );
    }

    /// @dev Submit a single inbound bundle carrying one REPLY message for `outboundMsgId` with
    ///      the given `status`, acking that message. Shared by connector-removal and
    ///      source-slash tests that drive submitBundle's reply-processing path directly.
    function _submitFailureReplyBundle(uint64 outboundMsgId, ClprTypes.ReplyStatus status) internal {
        bytes memory replyPayload = ClprProtobuf.encodeReplyMessage(outboundMsgId, status, hex"");
        bytes32 runningHash = sha256(abi.encodePacked(bytes32(0), sha256(replyPayload)));

        bytes[] memory msgs = new bytes[](1);
        msgs[0] = replyPayload;

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 2,
            sentRunningHash: runningHash,
            receivedMessageId: outboundMsgId,
            receivedRunningHash: bytes32(0),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 1,
            lastMessageRunningHash: runningHash
        });
        verifier.setVerifyBundleResult(meta, msgs);
        service.submitBundle(channelId, hex"00");
    }
}
