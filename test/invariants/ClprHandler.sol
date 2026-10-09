// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";

import {ClprService} from "@hiero-ledger/clpr/ClprService.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";
import {MockClprVerifier} from "@test/mocks/MockClprVerifier.sol";
import {MockClprConnector} from "@test/mocks/MockClprConnector.sol";
import {MockClprApplication} from "@test/mocks/MockClprApplication.sol";
import {EthRejector} from "@test/mocks/EthRejector.sol";
import {ConnectorRegistrar} from "@test/helpers/ConnectorRegistrar.sol";
import {ClprConnectorRegisterHelper} from "@test/helpers/ClprConnectorRegisterHelper.sol";
import {InvariantBundleHelper} from "@test/helpers/InvariantBundleHelper.sol";
import {ClprServiceStorageSlots} from "@test/helpers/ClprServiceStorageSlots.sol";
import {ClprStorageLayoutLib} from "@test/helpers/ClprServiceStorageSlots.sol";

/// @notice Fuzzer-facing handler for `ClprService` invariant tests.
contract ClprHandler is Test {
    struct TrackedChannel {
        bytes32 channelId;
        bytes32 commitment;
        bytes32 salt;
        bytes pubKey;
        uint256 signerPk;
        address signer;
        bool pending;
        bool completed;
    }

    struct TrackedConnector {
        bytes32 digest;
        bytes32 channelId;
        bytes32 connectorId;
        bytes32 connectorKey;
        bytes32 quotaKey;
        uint256 stake;
        bool live;
    }

    ClprService public immutable SERVICE;
    MockClprVerifier public immutable VERIFIER;
    MockClprApplication public immutable APP;
    EthRejector public immutable ETH_REJECTOR;
    ClprConnectorRegisterHelper public immutable CONNECTOR_REGISTER_HELPER;
    address public immutable OWNER;

    TrackedChannel[] internal _channels;
    TrackedConnector[] internal _connectors;
    address[] internal _actors;
    address[] internal _trackedAccounts;
    mapping(address => bool) internal _trackedAccountSet;
    /// @dev Addresses that may receive `pendingWithdrawals` in this harness (probed each step).
    address[] internal _pendingCandidates;
    mapping(address => bool) internal _pendingCandidateSet;
    mapping(address => bool) internal _endpointLive;

    mapping(bytes32 => bytes32) internal _commitmentByChannelId;
    mapping(bytes32 => bool) internal _pendingCommitmentGhost;
    mapping(bytes32 => bool) internal _completedChannelGhost;
    mapping(bytes32 => uint256) internal _connectorStakeGhost;
    mapping(bytes32 => uint256) internal _inflightGhost;
    mapping(bytes32 => uint32) internal _quotaGhost;

    /// @dev Service balance at handler construction (after bootstrap deposits).
    uint256 public initialServiceBalance;
    /// @dev Cumulative ETH credited to `SERVICE` since construction (balance deltas only).
    uint256 public ghostEthIn;
    /// @dev Cumulative ETH debited from `SERVICE` since construction (slash, charge payout, pull, returns).
    uint256 public ghostEthOut;
    uint256 internal _serviceBalanceBaseline;
    uint256 public ghostEndpointCount;
    uint256 public ghostConnectorCount;
    /// @dev Incremented only when `completeChannel` succeeds (including bootstrap seed).
    uint256 public ghostCompletedChannelCount;
    bool public ghostConnectorCountReaderMismatchSeen;
    bool public ghostMaxChannelsViolatedOnCreate;
    bool public ghostMaxConnectorsViolatedOnCreate;
    bool public ghostQuotaViolatedOnEnqueue;
    bool public ghostQueueDepthViolatedOnEnqueue;
    bool public ghostReEnableWhenDisabledOk;
    bool public ghostCollectPendingWhenDisabledOk;
    /// @dev Set if `setClprEnabled(true)` reverted with `ClprDisabled` while kill switch was off.
    bool public ghostReEnableBlockedByDisabled;
    /// @dev Set if `collectPending` reverted with `ClprDisabled` while kill switch was off.
    bool public ghostCollectPendingBlockedByDisabled;
    uint256 internal _bundleNonce;
    /// @dev Bumped on successful `updateLedger` / `updateEconomic` (queue depth / quota caps).
    uint256 public queueLimitsRevision;
    mapping(bytes32 => uint256) internal _lastEnqueueLimitsRevision;

    constructor(
        ClprService _service,
        MockClprVerifier _verifier,
        MockClprApplication _app,
        EthRejector _ethRejector,
        ClprConnectorRegisterHelper _connectorRegisterHelper,
        address _owner
    ) {
        SERVICE = _service;
        VERIFIER = _verifier;
        APP = _app;
        ETH_REJECTOR = _ethRejector;
        CONNECTOR_REGISTER_HELPER = _connectorRegisterHelper;
        OWNER = _owner;
        vm.deal(address(this), 50 ether);

        _addTrackedAccount(address(this));
        _addTrackedAccount(OWNER);
        _addTrackedAccount(SERVICE.owner());
        _addTrackedAccount(address(APP));
        _addTrackedAccount(address(ETH_REJECTOR));
        for (uint256 i = 0; i < 5; i++) {
            address actor = vm.addr(uint256(keccak256(abi.encodePacked("invariant-actor", i))));
            _actors.push(actor);
            vm.deal(actor, 500 ether);
            _addTrackedAccount(actor);
        }

        _seedBootstrapChannelAndConnector();
        _ensureEthRejectorEndpointRegistered();
        _syncPendingWithdrawalAccounts();
        initialServiceBalance = address(SERVICE).balance;
        _serviceBalanceBaseline = initialServiceBalance;
    }

    modifier reconcileEth() {
        _reconcileServiceBalance();
        _;
        _reconcileServiceBalance();
        _syncPendingWithdrawalAccounts();
    }

    /// @notice Probe the harness pending-withdrawal candidate set and track any account with a balance.
    function syncPendingWithdrawalAccounts() external {
        _syncPendingWithdrawalAccounts();
    }

    /// @notice Register an address the invariant harness may credit via `pendingWithdrawals`.
    function notePendingCandidate(address account) external {
        _notePendingCandidate(account);
    }

    function pendingCandidateLen() external view returns (uint256) {
        return _pendingCandidates.length;
    }

    function pendingCandidateAt(uint256 i) external view returns (address) {
        return _pendingCandidates[i];
    }

    function isTrackedAccount(address account) external view returns (bool) {
        return _trackedAccountSet[account];
    }

    function pendingWithdrawalsOf(address account) external view returns (uint256) {
        return _pendingWithdrawals(account);
    }

    function registerChannel(uint256 seed, uint256 saltSeed) external reconcileEth {
        uint256 pk = uint256(keccak256(abi.encodePacked("inv-conn-signer", seed)));
        Vm.Wallet memory wallet = vm.createWallet(pk);
        bytes memory pubKey = abi.encodePacked(wallet.publicKeyX, wallet.publicKeyY);
        bytes32 salt = bytes32(saltSeed);
        bytes32 channelId = _deriveChannelId(pubKey, salt);
        bytes32 commitment = keccak256(abi.encodePacked(channelId, pubKey));

        try SERVICE.registerChannel(channelId, commitment) {
            bool existsOnchain = _channelExistsOnchain(channelId);
            uint256 idx = _findChannel(channelId);
            if (idx == type(uint256).max) {
                _notePendingCandidate(wallet.addr);
                _channels.push(
                    TrackedChannel({
                        channelId: channelId,
                        commitment: commitment,
                        salt: salt,
                        pubKey: pubKey,
                        signerPk: pk,
                        signer: wallet.addr,
                        pending: !existsOnchain,
                        completed: existsOnchain
                    })
                );
                if (existsOnchain) {
                    _completedChannelGhost[channelId] = true;
                }
            } else {
                TrackedChannel storage existing = _channels[idx];
                if (!existsOnchain) {
                    existing.pending = true;
                    existing.completed = false;
                    _completedChannelGhost[channelId] = false;
                }
            }

            _pendingCommitmentGhost[commitment] = true;
            if (_commitmentByChannelId[channelId] == bytes32(0)) {
                _commitmentByChannelId[channelId] = commitment;
            }
        } catch {}
    }

    function completeChannel(uint256 channelIndexSeed) external reconcileEth {
        if (_channels.length == 0) return;
        uint256 idx = bound(channelIndexSeed, 0, _channels.length - 1);
        TrackedChannel storage tracked = _channels[idx];

        bytes32 msgHash = keccak256(abi.encodePacked(tracked.channelId, address(SERVICE)));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(tracked.signerPk, ethHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        try SERVICE.completeChannel(
            tracked.channelId, tracked.pubKey, sig, tracked.salt, address(VERIFIER), hex"01", ""
        ) {
            tracked.completed = true;
            tracked.pending = false;
            _completedChannelGhost[tracked.channelId] = true;
            _pendingCommitmentGhost[tracked.commitment] = false;
            _commitmentByChannelId[tracked.channelId] = bytes32(0);
            ghostCompletedChannelCount++;

            ClprTypes.EconomicConfig memory econ = SERVICE.getEconomicConfig();
            if (econ.maxChannels > 0 && SERVICE.channelCount() > econ.maxChannels) {
                ghostMaxChannelsViolatedOnCreate = true;
            }
        } catch {}
    }

    function closeChannel(uint256 channelIndexSeed) external reconcileEth {
        if (_channels.length == 0) return;
        uint256 idx = bound(channelIndexSeed, 0, _channels.length - 1);
        TrackedChannel storage tracked = _channels[idx];

        vm.prank(OWNER);
        try SERVICE.closeChannel(tracked.channelId) {
            if (tracked.pending) {
                tracked.pending = false;
                _pendingCommitmentGhost[tracked.commitment] = false;
                _commitmentByChannelId[tracked.channelId] = bytes32(0);
            }
        } catch {}
    }

    /// @dev Self-register as a PENDING endpoint with an escrowed bond. Pending entries are not in the
    ///      live manifest, so `ghostEndpointCount` (live count) is unchanged; the bond is tracked by
    ///      the ETH-conservation reconciliation (sumEndpointBonds enumerates the manifest entries).
    function registerEndpoint(uint256 actorSeed, uint256 bondSeed) external reconcileEth {
        address actor = _pickActor(actorSeed);
        uint256 bond = bound(bondSeed, 0, 2 ether);
        ClprTypes.Endpoint memory ep = ClprTypes.Endpoint({
            ipAddress: "10.0.0.1", port: 50211, tlsCertificate: "", accountId: abi.encodePacked(actor)
        });

        uint256 beforeBal = actor.balance;
        vm.prank(actor);
        try SERVICE.registerEndpoint{value: bond}(ep) {
            _endpointLive[actor] = true; // "has an escrowed manifest entry"
            assertEq(beforeBal, actor.balance + bond);
        } catch {}
    }

    /// @dev Self-remove (cancels a pending registration); the bond is credited to pendingWithdrawals.
    function removeEndpoint(uint256 actorSeed) external reconcileEth {
        address actor = _pickActor(actorSeed);

        vm.prank(actor);
        try SERVICE.removeEndpoint(actor) {
            _endpointLive[actor] = false;
        } catch {}
    }

    function registerConnector(uint256 channelIndexSeed, uint256 seed, uint256 stakeSeed) external reconcileEth {
        if (_channels.length == 0) return;
        uint256 cidx = bound(channelIndexSeed, 0, _channels.length - 1);
        TrackedChannel storage tracked = _channels[cidx];
        if (!tracked.completed) return;

        uint256 stake = bound(stakeSeed, 0.1 ether, 3 ether);
        MockClprConnector connector = MockClprConnector(payable(deployCode("MockClprConnector.sol:MockClprConnector")));
        _addTrackedAccount(address(connector));
        _fundConnector(address(connector));

        bytes32 regSeed = keccak256(abi.encodePacked("inv-connector", seed, tracked.channelId));
        try CONNECTOR_REGISTER_HELPER.register(
            IClprService(address(SERVICE)), tracked.channelId, regSeed, address(connector), OWNER, stake
        ) returns (
            bytes32 connectorId
        ) {
            bytes32 digest = keccak256(abi.encodePacked(tracked.channelId, connectorId));
            bytes32 quotaKey = keccak256(abi.encodePacked(tracked.channelId, keccak256(abi.encodePacked(connectorId))));
            bool liveBefore = _connectorStakeGhost[digest] > 0;

            _connectors.push(
                TrackedConnector({
                    digest: digest,
                    channelId: tracked.channelId,
                    connectorId: connectorId,
                    connectorKey: digest,
                    quotaKey: quotaKey,
                    stake: stake,
                    live: true
                })
            );
            _connectorStakeGhost[digest] += stake;
            if (!liveBefore) ghostConnectorCount++;

            uint256 connectorCountSlot =
                uint256(vm.load(address(SERVICE), bytes32(ClprServiceStorageSlots.CONNECTOR_COUNT)));
            if (SERVICE.connectorCount() != connectorCountSlot) {
                ghostConnectorCountReaderMismatchSeen = true;
            }

            ClprTypes.EconomicConfig memory econ = SERVICE.getEconomicConfig();
            if (econ.maxConnectors > 0 && SERVICE.connectorCount() > econ.maxConnectors) {
                ghostMaxConnectorsViolatedOnCreate = true;
            }
        } catch {}
    }

    function removeConnector(uint256 connectorIndexSeed) external reconcileEth {
        if (_connectors.length == 0) return;
        uint256 idx = bound(connectorIndexSeed, 0, _connectors.length - 1);
        TrackedConnector storage tracked = _connectors[idx];
        if (!tracked.live) return;

        address recipient = _pickActor(connectorIndexSeed);
        _notePendingCandidate(recipient);
        vm.prank(OWNER);
        try SERVICE.removeConnector(tracked.channelId, tracked.connectorId, recipient) {
            tracked.live = false;
            _addTrackedAccount(recipient);
            ghostConnectorCount--;
            _syncConnectorGhostsFor(tracked);
        } catch {}
    }

    function topUpConnectorStake(uint256 connectorIndexSeed, uint256 amountSeed) external reconcileEth {
        if (_connectors.length == 0) return;
        uint256 idx = bound(connectorIndexSeed, 0, _connectors.length - 1);
        TrackedConnector storage tracked = _connectors[idx];
        if (!tracked.live) return;

        uint256 amount = bound(amountSeed, 0, 1 ether);
        vm.prank(OWNER);
        try SERVICE.topUpConnectorStake{value: amount}(tracked.channelId, tracked.connectorId) {
            tracked.stake += amount;
            _connectorStakeGhost[tracked.digest] += amount;
            _syncConnectorGhostsFor(tracked);
        } catch {}
    }

    function sendMessage(uint256 connectorIndexSeed, uint256 actorSeed, uint256 payloadSeed) external reconcileEth {
        if (_connectors.length == 0) return;

        uint256 idx = bound(connectorIndexSeed, 0, _connectors.length - 1);
        TrackedConnector storage tracked = _connectors[idx];
        if (!tracked.live) return;

        bytes memory payload = abi.encodePacked(bytes32(payloadSeed));
        address sender = _pickActor(actorSeed);
        _notePendingCandidate(sender);
        vm.prank(sender);
        try SERVICE.sendMessage(tracked.channelId, tracked.connectorId, abi.encodePacked(sender), payload) returns (
            uint64
        ) {
            _syncConnectorGhostsFor(tracked);

            ClprTypes.LedgerConfiguration memory cfg = SERVICE.getLedgerConfiguration();
            ClprTypes.EconomicConfig memory econ = SERVICE.getEconomicConfig();
            uint32 quotaCap =
                uint32((uint256(cfg.throttles.maxQueueDepth) * uint256(econ.connectorQueueQuotaPct)) / 100);
            uint32 quotaOnchain = _quotaGhost[tracked.quotaKey];
            if (quotaOnchain > quotaCap) {
                ghostQuotaViolatedOnEnqueue = true;
            }

            ClprTypes.Channel memory connAfter = SERVICE.getChannel(tracked.channelId);
            uint256 depthAfter = connAfter.nextMessageId - connAfter.ackedMessageId - 1;
            if (depthAfter > cfg.throttles.maxQueueDepth) {
                ghostQueueDepthViolatedOnEnqueue = true;
            }
            _lastEnqueueLimitsRevision[tracked.channelId] = queueLimitsRevision;
        } catch {}
    }

    function setClprEnabled(bool enabled) external reconcileEth {
        vm.prank(OWNER);
        try SERVICE.setClprEnabled(enabled) {} catch {}
    }

    function updateLedger(uint64 maxQueueDepthRaw) external reconcileEth {
        uint32 maxQueueDepth = uint32(bound(maxQueueDepthRaw, 1, 5000));
        ClprTypes.Throttles memory throttles = ClprTypes.Throttles({
            maxMessagesPerBundle: 100,
            maxMessagePayloadBytes: 4096,
            maxGasPerMessage: 1_000_000,
            maxQueueDepth: maxQueueDepth,
            maxSyncBytes: 1_048_576,
            maxLocalEndpoints: 0,
            maxPeerEndpoints: 0
        });
        vm.prank(OWNER);
        try SERVICE.updateLedgerConfiguration(hex"1234", throttles, "", "") {
            _bumpQueueLimitsRevision();
        } catch {}
    }

    function updateEconomic(uint32 quotaPctRaw, uint32 maxChannelsRaw, uint32 maxConnectorsRaw) external reconcileEth {
        uint32 quotaPct = uint32(bound(quotaPctRaw, 0, 99));
        uint32 maxChannels = uint32(bound(maxChannelsRaw, 0, 32));
        uint32 maxConnectors = uint32(bound(maxConnectorsRaw, 0, 64));
        ClprTypes.EconomicConfig memory econ = ClprTypes.EconomicConfig({
            messageExecutionCost: 0.001 ether,
            endpointMarginPercent: 10,
            minLockedStake: 0.1 ether,
            minEndpointBond: 0,
            basePenalty: 0.01 ether,
            penaltyMultiplier: 2,
            slashBanThreshold: 5,
            connectorQueueQuotaPct: quotaPct,
            connectorInboundGasStipend: 500_000,
            maxChannels: maxChannels,
            maxConnectors: maxConnectors,
            connectorPaymentGasLimit: 200_000
        });
        vm.prank(OWNER);
        try SERVICE.updateEconomicConfiguration(econ) {
            _bumpQueueLimitsRevision();
        } catch {}
    }

    function submitEmptyBundle(uint256 channelIndexSeed, uint256 actorSeed, uint256 warpDeltaSeed)
        external
        reconcileEth
    {
        if (_channels.length == 0) return;
        uint256 idx = bound(channelIndexSeed, 0, _channels.length - 1);
        TrackedChannel storage tracked = _channels[idx];
        if (!tracked.completed) return;

        address actor = _pickActor(actorSeed);
        if (!_endpointLive[actor]) return;
        _notePendingCandidate(actor);

        uint256 warpDelta = bound(warpDeltaSeed, 0, 3);
        if (warpDelta > 0) vm.warp(block.timestamp + warpDelta);

        ClprTypes.Channel memory channel;
        try SERVICE.getChannel(tracked.channelId) returns (ClprTypes.Channel memory c) {
            channel = c;
        } catch {
            return;
        }

        if (channel.ackedMessageId + 1 != channel.nextMessageId) return;

        bytes[] memory emptyMsgs = new bytes[](0);
        ClprTypes.QueueMetadata memory meta = InvariantBundleHelper.emptyAckMetadata(channel);
        InvariantBundleHelper.configureVerifierInbound(VERIFIER, meta, emptyMsgs);
        bytes memory proof = _nextBundleProof();
        VERIFIER.setNewTrustAnchor(proof);

        vm.prank(actor);
        try SERVICE.submitBundle(tracked.channelId, proof) {
            _addTrackedAccount(actor);
            _resyncConnectorGhosts(tracked.channelId);
        } catch {}
    }

    function submitInboundBundle(uint256 channelIndexSeed, uint256 connectorIndexSeed, uint256 actorSeed)
        external
        reconcileEth
    {
        if (_channels.length == 0 || _connectors.length == 0) return;
        uint256 cidx = bound(channelIndexSeed, 0, _channels.length - 1);
        TrackedChannel storage tracked = _channels[cidx];
        if (!tracked.completed) return;

        address actor = _pickActor(actorSeed);
        if (!_endpointLive[actor]) return;
        _notePendingCandidate(actor);

        uint256 kidx = bound(connectorIndexSeed, 0, _connectors.length - 1);
        TrackedConnector storage connTracked = _connectors[kidx];
        if (!connTracked.live || connTracked.channelId != tracked.channelId) return;

        ClprTypes.Channel memory channel;
        try SERVICE.getChannel(tracked.channelId) returns (ClprTypes.Channel memory c) {
            channel = c;
        } catch {
            return;
        }
        if (channel.status != ClprTypes.ChannelStatus.ACTIVE) return;

        ClprTypes.Connector memory onchainConn = SERVICE.getConnector(tracked.channelId, connTracked.connectorId);
        _fundConnector(onchainConn.connectorContract);

        bytes memory payload = InvariantBundleHelper.buildInboundDataPayload(
            connTracked.connectorId, address(APP), abi.encodePacked(actor), hex"48454C4C4F"
        );
        bytes[] memory msgs = new bytes[](1);
        msgs[0] = payload;
        ClprTypes.QueueMetadata memory meta = InvariantBundleHelper.inboundMetadata(channel, payload);
        InvariantBundleHelper.configureVerifierInbound(VERIFIER, meta, msgs);
        bytes memory proof = _nextBundleProof();
        VERIFIER.setNewTrustAnchor(proof);

        vm.prank(actor);
        try SERVICE.submitBundle(tracked.channelId, proof) {
            _addTrackedAccount(actor);
            _resyncConnectorGhosts(tracked.channelId);
        } catch {}
    }

    /// @notice Inbound bundle with an underfunded connector so slash credits `pendingWithdrawals[ETH_REJECTOR]`.
    /// @dev Temporarily sets SERVICE OWNER to `ETH_REJECTOR` so submitter and fallback both reject direct ETH.
    function submitInboundSlashPendingEthRejector(uint256 channelIndexSeed, uint256 connectorIndexSeed)
        external
        reconcileEth
    {
        if (_channels.length == 0 || _connectors.length == 0) return;
        if (!_endpointLive[address(ETH_REJECTOR)]) return;

        uint256 cidx = bound(channelIndexSeed, 0, _channels.length - 1);
        TrackedChannel storage tracked = _channels[cidx];
        if (!tracked.completed) return;

        uint256 kidx = bound(connectorIndexSeed, 0, _connectors.length - 1);
        TrackedConnector storage connTracked = _connectors[kidx];
        if (!connTracked.live || connTracked.channelId != tracked.channelId) return;

        ClprTypes.Channel memory channel;
        try SERVICE.getChannel(tracked.channelId) returns (ClprTypes.Channel memory c) {
            channel = c;
        } catch {
            return;
        }
        if (channel.status != ClprTypes.ChannelStatus.ACTIVE) return;

        ClprTypes.Connector memory onchainConn = SERVICE.getConnector(tracked.channelId, connTracked.connectorId);
        MockClprConnector connector = MockClprConnector(payable(onchainConn.connectorContract));
        vm.deal(address(connector), 0);

        bytes memory payload = InvariantBundleHelper.buildInboundDataPayload(
            connTracked.connectorId, address(APP), abi.encodePacked(address(ETH_REJECTOR)), hex"534C415348"
        );
        bytes[] memory msgs = new bytes[](1);
        msgs[0] = payload;
        ClprTypes.QueueMetadata memory meta = InvariantBundleHelper.inboundMetadata(channel, payload);
        InvariantBundleHelper.configureVerifierInbound(VERIFIER, meta, msgs);
        bytes memory proof = _nextBundleProof();
        VERIFIER.setNewTrustAnchor(proof);

        if (SERVICE.owner() != address(ETH_REJECTOR)) {
            vm.prank(OWNER);
            SERVICE.transferOwnership(address(ETH_REJECTOR));
        }

        vm.prank(address(ETH_REJECTOR));
        try SERVICE.submitBundle(tracked.channelId, proof) {
            _addTrackedAccount(address(ETH_REJECTOR));
            _resyncConnectorGhosts(tracked.channelId);
        } catch {}

        if (SERVICE.owner() == address(ETH_REJECTOR) && OWNER != address(ETH_REJECTOR)) {
            ETH_REJECTOR.transferServiceOwnership(SERVICE, OWNER);
        }

        _notePendingCandidate(address(ETH_REJECTOR));
        _syncPendingWithdrawalAccounts();
    }

    /// @notice Inbound bundle where `payForExecution` fails and slash credits `pendingWithdrawals[ETH_REJECTOR]`.
    function submitInboundChargeFailSlashPendingEthRejector(uint256 channelIndexSeed, uint256 connectorIndexSeed)
        external
        reconcileEth
    {
        if (_channels.length == 0 || _connectors.length == 0) return;
        if (!_endpointLive[address(ETH_REJECTOR)]) return;

        uint256 cidx = bound(channelIndexSeed, 0, _channels.length - 1);
        TrackedChannel storage tracked = _channels[cidx];
        if (!tracked.completed) return;

        uint256 kidx = bound(connectorIndexSeed, 0, _connectors.length - 1);
        TrackedConnector storage connTracked = _connectors[kidx];
        if (!connTracked.live || connTracked.channelId != tracked.channelId) return;

        ClprTypes.Channel memory channel;
        try SERVICE.getChannel(tracked.channelId) returns (ClprTypes.Channel memory c) {
            channel = c;
        } catch {
            return;
        }
        if (channel.status != ClprTypes.ChannelStatus.ACTIVE) return;

        ClprTypes.Connector memory onchainConn = SERVICE.getConnector(tracked.channelId, connTracked.connectorId);
        MockClprConnector connector = MockClprConnector(payable(onchainConn.connectorContract));
        _fundConnector(address(connector));
        connector.setPayReverts(true);
        vm.fee(10 gwei);

        bytes memory payload = InvariantBundleHelper.buildInboundDataPayload(
            connTracked.connectorId, address(APP), abi.encodePacked(address(ETH_REJECTOR)), hex"434841524745"
        );
        bytes[] memory msgs = new bytes[](1);
        msgs[0] = payload;
        ClprTypes.QueueMetadata memory meta = InvariantBundleHelper.inboundMetadata(channel, payload);
        InvariantBundleHelper.configureVerifierInbound(VERIFIER, meta, msgs);
        bytes memory proof = _nextBundleProof();
        VERIFIER.setNewTrustAnchor(proof);

        if (SERVICE.owner() != address(ETH_REJECTOR)) {
            vm.prank(OWNER);
            SERVICE.transferOwnership(address(ETH_REJECTOR));
        }

        vm.prank(address(ETH_REJECTOR));
        try SERVICE.submitBundle(tracked.channelId, proof) {
            _addTrackedAccount(address(ETH_REJECTOR));
            _resyncConnectorGhosts(tracked.channelId);
        } catch {}

        connector.setPayReverts(false);
        vm.fee(1 gwei);

        if (SERVICE.owner() == address(ETH_REJECTOR) && OWNER != address(ETH_REJECTOR)) {
            ETH_REJECTOR.transferServiceOwnership(SERVICE, OWNER);
        }

        _notePendingCandidate(address(ETH_REJECTOR));
        _syncPendingWithdrawalAccounts();
    }

    function submitAckBundle(uint256 channelIndexSeed, uint256 actorSeed, uint256 warpDeltaSeed) external reconcileEth {
        if (_channels.length == 0) return;
        uint256 idx = bound(channelIndexSeed, 0, _channels.length - 1);
        TrackedChannel storage tracked = _channels[idx];
        if (!tracked.completed) return;

        address actor = _pickActor(actorSeed);
        if (!_endpointLive[actor]) return;
        _notePendingCandidate(actor);

        uint256 warpDelta = bound(warpDeltaSeed, 0, 3);
        if (warpDelta > 0) vm.warp(block.timestamp + warpDelta);

        ClprTypes.Channel memory channel;
        try SERVICE.getChannel(tracked.channelId) returns (ClprTypes.Channel memory c) {
            channel = c;
        } catch {
            return;
        }
        if (channel.status != ClprTypes.ChannelStatus.ACTIVE) return;
        if (channel.ackedMessageId + 1 >= channel.nextMessageId) return;

        bytes[] memory emptyMsgs = new bytes[](0);
        ClprTypes.QueueMetadata memory meta = InvariantBundleHelper.outboundAckMetadata(channel);
        InvariantBundleHelper.configureVerifierInbound(VERIFIER, meta, emptyMsgs);
        bytes memory proof = _nextBundleProof();
        VERIFIER.setNewTrustAnchor(proof);

        vm.prank(actor);
        try SERVICE.submitBundle(tracked.channelId, proof) {
            _addTrackedAccount(actor);
            _resyncConnectorGhosts(tracked.channelId);
        } catch {}
    }

    function collectPending(uint256 accountSeed) external reconcileEth {
        if (_trackedAccounts.length == 0) return;
        uint256 idx = accountSeed % _trackedAccounts.length;
        address account = _trackedAccounts[idx];
        uint256 pending = uint256(
            vm.load(
                address(SERVICE),
                ClprStorageLayoutLib.mapAddressSlot(account, ClprServiceStorageSlots.PENDING_WITHDRAWALS)
            )
        );
        if (pending == 0) return;

        _addTrackedAccount(account);
        if (account == address(ETH_REJECTOR)) {
            try ETH_REJECTOR.collect(SERVICE) {} catch {}
        } else {
            vm.prank(account);
            try SERVICE.collectPending() {} catch {}
        }
    }

    function setVerifierRevert(uint256 seed) external {
        if (seed % 2 == 0) {
            VERIFIER.setShouldRevert(false, "");
        } else {
            VERIFIER.setShouldRevert(true, "MockClprVerifier: invariant fuzz revert");
        }
    }

    /// @notice Sets low `maxChannels` / `maxConnectors` so cap-hit attempts are reachable.
    function setTightResourceCaps(uint32 maxChannelsRaw, uint32 maxConnectorsRaw) external reconcileEth {
        uint32 maxChannels = uint32(bound(maxChannelsRaw, 1, 8));
        uint32 maxConnectors = uint32(bound(maxConnectorsRaw, 1, 16));
        ClprTypes.EconomicConfig memory econ = ClprTypes.EconomicConfig({
            messageExecutionCost: 0.001 ether,
            endpointMarginPercent: 10,
            minLockedStake: 0.1 ether,
            minEndpointBond: 0,
            basePenalty: 0.01 ether,
            penaltyMultiplier: 2,
            slashBanThreshold: 5,
            connectorQueueQuotaPct: 50,
            connectorInboundGasStipend: 500_000,
            maxChannels: maxChannels,
            maxConnectors: maxConnectors,
            connectorPaymentGasLimit: 200_000
        });
        vm.prank(OWNER);
        try SERVICE.updateEconomicConfiguration(econ) {
            _bumpQueueLimitsRevision();
        } catch {}
    }

    /// @notice When already at `maxChannels`, try completing another pending channel (expect revert).
    function attemptCompleteAtChannelCap(uint256 channelIndexSeed) external reconcileEth {
        ClprTypes.EconomicConfig memory econ = SERVICE.getEconomicConfig();
        if (econ.maxChannels == 0) return;
        if (SERVICE.channelCount() < econ.maxChannels) return;
        if (_channels.length == 0) return;

        uint256 idx = bound(channelIndexSeed, 0, _channels.length - 1);
        TrackedChannel storage tracked = _channels[idx];
        if (tracked.completed) return;

        bytes32 msgHash = keccak256(abi.encodePacked(tracked.channelId, address(SERVICE)));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(tracked.signerPk, ethHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        try SERVICE.completeChannel(
            tracked.channelId, tracked.pubKey, sig, tracked.salt, address(VERIFIER), hex"01", ""
        ) {
            if (SERVICE.channelCount() > econ.maxChannels) {
                ghostMaxChannelsViolatedOnCreate = true;
            }
        } catch {}
    }

    /// @notice When already at `maxConnectors`, try registering another connector (expect revert).
    function attemptRegisterAtConnectorCap(uint256 channelIndexSeed, uint256 seed, uint256 stakeSeed)
        external
        reconcileEth
    {
        ClprTypes.EconomicConfig memory econ = SERVICE.getEconomicConfig();
        if (econ.maxConnectors == 0) return;
        if (SERVICE.connectorCount() < econ.maxConnectors) return;
        if (_channels.length == 0) return;

        uint256 cidx = bound(channelIndexSeed, 0, _channels.length - 1);
        TrackedChannel storage tracked = _channels[cidx];
        if (!tracked.completed) return;

        uint256 stake = bound(stakeSeed, 0.1 ether, 3 ether);
        MockClprConnector connector = MockClprConnector(payable(deployCode("MockClprConnector.sol:MockClprConnector")));
        _addTrackedAccount(address(connector));
        _fundConnector(address(connector));

        bytes32 regSeed = keccak256(abi.encodePacked("inv-connector-cap", seed, tracked.channelId));
        try CONNECTOR_REGISTER_HELPER.register(
            IClprService(address(SERVICE)), tracked.channelId, regSeed, address(connector), OWNER, stake
        ) returns (
            bytes32 connectorId
        ) {
            bytes32 digest = keccak256(abi.encodePacked(tracked.channelId, connectorId));
            if (SERVICE.connectorCount() > econ.maxConnectors) {
                ghostMaxConnectorsViolatedOnCreate = true;
            }
            if (SERVICE.hasConnector(tracked.channelId, connectorId)) {
                bytes32 quotaKey =
                    keccak256(abi.encodePacked(tracked.channelId, keccak256(abi.encodePacked(connectorId))));
                _connectors.push(
                    TrackedConnector({
                        digest: digest,
                        channelId: tracked.channelId,
                        connectorId: connectorId,
                        connectorKey: digest,
                        quotaKey: quotaKey,
                        stake: stake,
                        live: true
                    })
                );
                _connectorStakeGhost[digest] = stake;
                ghostConnectorCount++;
            }
        } catch {}
    }

    function probeReEnableWhenDisabled() external reconcileEth {
        if (_clprEnabledOnchain()) return;
        vm.prank(OWNER);
        try SERVICE.setClprEnabled(true) {
            ghostReEnableWhenDisabledOk = true;
            vm.prank(OWNER);
            try SERVICE.setClprEnabled(false) {} catch {}
        } catch (bytes memory revertData) {
            if (_isClprDisabled(revertData)) ghostReEnableBlockedByDisabled = true;
        }
    }

    function collectPendingWhileDisabled(uint256 accountSeed) external reconcileEth {
        if (_clprEnabledOnchain()) return;
        if (_trackedAccounts.length == 0) return;
        uint256 idx = accountSeed % _trackedAccounts.length;
        address account = _trackedAccounts[idx];
        uint256 pending = uint256(
            vm.load(
                address(SERVICE),
                ClprStorageLayoutLib.mapAddressSlot(account, ClprServiceStorageSlots.PENDING_WITHDRAWALS)
            )
        );
        if (pending == 0) return;

        _addTrackedAccount(account);
        if (account == address(ETH_REJECTOR)) {
            try ETH_REJECTOR.collect(SERVICE) {
                ghostCollectPendingWhenDisabledOk = true;
            } catch (bytes memory revertData) {
                if (_isClprDisabled(revertData)) ghostCollectPendingBlockedByDisabled = true;
            }
        } else {
            vm.prank(account);
            try SERVICE.collectPending() {
                ghostCollectPendingWhenDisabledOk = true;
            } catch (bytes memory revertData) {
                if (_isClprDisabled(revertData)) ghostCollectPendingBlockedByDisabled = true;
            }
        }
    }

    function channelLen() external view returns (uint256) {
        return _channels.length;
    }

    function getChannel(uint256 i)
        external
        view
        returns (bytes32 channelId, bytes32 commitment, address signer, bool pending, bool completed)
    {
        TrackedChannel storage c = _channels[i];
        return (c.channelId, c.commitment, c.signer, c.pending, c.completed);
    }

    function connectorLen() external view returns (uint256) {
        return _connectors.length;
    }

    function getConnector(uint256 i)
        external
        view
        returns (
            bytes32 digest,
            bytes32 channelId,
            bytes32 connectorId,
            bytes32 connectorKey,
            bytes32 quotaKey,
            uint256 stake,
            bool live
        )
    {
        TrackedConnector storage c = _connectors[i];
        return (c.digest, c.channelId, c.connectorId, c.connectorKey, c.quotaKey, c.stake, c.live);
    }

    function actorLen() external view returns (uint256) {
        return _actors.length;
    }

    function actorAt(uint256 i) external view returns (address) {
        return _actors[i];
    }

    function trackedAccountLen() external view returns (uint256) {
        return _trackedAccounts.length;
    }

    function trackedAccountAt(uint256 i) external view returns (address) {
        return _trackedAccounts[i];
    }

    function ghostChannelCommitment(bytes32 channelId) external view returns (bytes32) {
        return _commitmentByChannelId[channelId];
    }

    function ghostPendingCommitment(bytes32 commitment) external view returns (bool) {
        return _pendingCommitmentGhost[commitment];
    }

    function ghostChannelCompleted(bytes32 channelId) external view returns (bool) {
        return _completedChannelGhost[channelId];
    }

    function ghostEndpointRegistered(address actor) external view returns (bool) {
        return _endpointLive[actor];
    }

    function ghostConnectorStake(bytes32 digest) external view returns (uint256) {
        return _connectorStakeGhost[digest];
    }

    function ghostInflight(bytes32 key) external view returns (uint256) {
        return _inflightGhost[key];
    }

    function ghostQuota(bytes32 key) external view returns (uint32) {
        return _quotaGhost[key];
    }

    function lastEnqueueLimitsRevision(bytes32 channelId) external view returns (uint256) {
        return _lastEnqueueLimitsRevision[channelId];
    }

    function _channelExistsOnchain(bytes32 channelId) internal view returns (bool) {
        return uint256(
            vm.load(
            address(SERVICE), ClprStorageLayoutLib.mapBytes32Slot(channelId, ClprServiceStorageSlots.CHANNEL_EXISTS)
        )
        ) != 0;
    }

    function _pickActor(uint256 seed) internal view returns (address) {
        if (_actors.length == 0) return address(this);
        return _actors[seed % _actors.length];
    }

    function _addTrackedAccount(address account) internal {
        if (account == address(0)) return;
        _notePendingCandidate(account);
        if (_trackedAccountSet[account]) return;
        _trackedAccountSet[account] = true;
        _trackedAccounts.push(account);
    }

    function _notePendingCandidate(address account) internal {
        if (account == address(0)) return;
        if (_pendingCandidateSet[account]) return;
        _pendingCandidateSet[account] = true;
        _pendingCandidates.push(account);
    }

    function _pendingWithdrawals(address account) internal view returns (uint256) {
        return uint256(
            vm.load(
                address(SERVICE),
                ClprStorageLayoutLib.mapAddressSlot(account, ClprServiceStorageSlots.PENDING_WITHDRAWALS)
            )
        );
    }

    /// @dev Scan every address that may receive pull-payment credits in this harness.
    function _syncPendingWithdrawalAccounts() internal {
        _probePendingAddTracked(OWNER);
        _probePendingAddTracked(address(this));
        _probePendingAddTracked(SERVICE.owner());
        _probePendingAddTracked(address(APP));
        _probePendingAddTracked(address(ETH_REJECTOR));

        uint256 actorLength = _actors.length;
        for (uint256 i = 0; i < actorLength; i++) {
            _probePendingAddTracked(_actors[i]);
        }

        uint256 trackedLen = _trackedAccounts.length;
        for (uint256 i = 0; i < trackedLen; i++) {
            _probePendingAddTracked(_trackedAccounts[i]);
        }

        uint256 connLen = _channels.length;
        for (uint256 i = 0; i < connLen; i++) {
            _probePendingAddTracked(_channels[i].signer);
        }

        uint256 connectorLength = _connectors.length;
        for (uint256 i = 0; i < connectorLength; i++) {
            TrackedConnector storage tracked = _connectors[i];
            if (!tracked.live) continue;
            if (!SERVICE.hasConnector(tracked.channelId, tracked.connectorId)) continue;
            ClprTypes.Connector memory onchain = SERVICE.getConnector(tracked.channelId, tracked.connectorId);
            _probePendingAddTracked(onchain.connectorContract);
            _probePendingAddTracked(onchain.admin);
        }
    }

    function _probePendingAddTracked(address account) internal {
        _notePendingCandidate(account);
        if (_pendingWithdrawals(account) > 0) {
            _addTrackedAccount(account);
        }
    }

    function _bumpQueueLimitsRevision() internal {
        queueLimitsRevision++;
    }

    function _findChannel(bytes32 channelId) internal view returns (uint256) {
        for (uint256 i = 0; i < _channels.length; i++) {
            if (_channels[i].channelId == channelId) return i;
        }
        return type(uint256).max;
    }

    function _deriveChannelId(bytes memory pubKey, bytes32 salt) internal pure returns (bytes32) {
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

    function _dummySigningKey(address actor) internal pure returns (bytes memory out) {
        out = new bytes(64);
        bytes32 seed = keccak256(abi.encodePacked("endpoint-signing-key", actor));
        assembly ("memory-safe") {
            mstore(add(out, 32), seed)
            mstore(add(out, 64), seed)
        }
    }

    function _ensureEthRejectorEndpointRegistered() internal {
        if (_endpointLive[address(ETH_REJECTOR)]) return;
        vm.deal(address(ETH_REJECTOR), 10 ether);
        ClprTypes.Endpoint memory ep = ClprTypes.Endpoint({
            ipAddress: "10.0.0.9", port: 50211, tlsCertificate: "", accountId: abi.encodePacked(address(ETH_REJECTOR))
        });
        vm.prank(address(ETH_REJECTOR));
        try SERVICE.registerEndpoint{value: 0}(ep) {
            _endpointLive[address(ETH_REJECTOR)] = true; // has an escrowed (pending) entry
        } catch {}
    }

    function _seedBootstrapChannelAndConnector() internal {
        uint256 pk = uint256(keccak256("invariant-bootstrap-channel-signer"));
        Vm.Wallet memory wallet = vm.createWallet(pk);
        bytes memory pubKey = abi.encodePacked(wallet.publicKeyX, wallet.publicKeyY);
        bytes32 salt = bytes32(uint256(1));
        bytes32 channelId = _deriveChannelId(pubKey, salt);
        bytes32 commitment = keccak256(abi.encodePacked(channelId, pubKey));

        SERVICE.registerChannel(channelId, commitment);
        bytes32 msgHash = keccak256(abi.encodePacked(channelId, address(SERVICE)));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethHash);
        bytes memory sig = abi.encodePacked(r, s, v);
        SERVICE.completeChannel(channelId, pubKey, sig, salt, address(VERIFIER), hex"01", "");
        ghostCompletedChannelCount = 1;

        _channels.push(
            TrackedChannel({
                channelId: channelId,
                commitment: commitment,
                salt: salt,
                pubKey: pubKey,
                signerPk: pk,
                signer: wallet.addr,
                pending: false,
                completed: true
            })
        );
        _completedChannelGhost[channelId] = true;
        _pendingCommitmentGhost[commitment] = false;
        _commitmentByChannelId[channelId] = bytes32(0);

        uint256 stake = 1 ether;
        MockClprConnector connector = MockClprConnector(payable(deployCode("MockClprConnector.sol:MockClprConnector")));
        _addTrackedAccount(address(connector));
        _fundConnector(address(connector));
        bytes32 connectorId = ConnectorRegistrar.register(
            IClprService(address(SERVICE)),
            channelId,
            keccak256("invariant-bootstrap-connector"),
            address(connector),
            OWNER,
            stake
        );

        bytes32 digest = keccak256(abi.encodePacked(channelId, connectorId));
        bytes32 quotaKey = keccak256(abi.encodePacked(channelId, keccak256(abi.encodePacked(connectorId))));
        _connectors.push(
            TrackedConnector({
                digest: digest,
                channelId: channelId,
                connectorId: connectorId,
                connectorKey: digest,
                quotaKey: quotaKey,
                stake: stake,
                live: true
            })
        );
        _connectorStakeGhost[digest] = stake;
        ghostConnectorCount = 1;

        uint256 connectorCountSlot =
            uint256(vm.load(address(SERVICE), bytes32(ClprServiceStorageSlots.CONNECTOR_COUNT)));
        if (SERVICE.connectorCount() != connectorCountSlot) {
            ghostConnectorCountReaderMismatchSeen = true;
        }
    }

    function _fundConnector(address connectorContract) internal {
        if (connectorContract.balance < 5 ether) {
            vm.deal(connectorContract, 5 ether);
        }
    }

    function _nextBundleProof() internal returns (bytes memory proof) {
        _bundleNonce++;
        proof = abi.encodePacked(bytes32(_bundleNonce));
    }

    function _reconcileServiceBalance() internal {
        uint256 current = address(SERVICE).balance;
        if (current > _serviceBalanceBaseline) {
            ghostEthIn += current - _serviceBalanceBaseline;
        } else if (current < _serviceBalanceBaseline) {
            ghostEthOut += _serviceBalanceBaseline - current;
        }
        _serviceBalanceBaseline = current;
    }

    function _clprEnabledOnchain() internal view returns (bool) {
        bytes32 packed = vm.load(address(SERVICE), bytes32(ClprServiceStorageSlots.PACKED_MISC));
        return ((uint256(packed) >> ClprServiceStorageSlots.CLPR_ENABLED_BIT_SHIFT) & 0xFF) != 0;
    }

    function _isClprDisabled(bytes memory revertData) internal pure returns (bool) {
        // casting to 'bytes4' is safe because there is a check for revertData.length to be greater than 4
        // forge-lint: disable-next-line(unsafe-typecast)
        return revertData.length >= 4 && bytes4(revertData) == ClprTypes.ClprDisabled.selector;
    }

    /// @dev Resync inflight, quota, and locked stake from chain (covers slash, bundle ack).
    function _syncConnectorGhostsFor(TrackedConnector storage tracked) internal {
        if (tracked.live && SERVICE.hasConnector(tracked.channelId, tracked.connectorId)) {
            ClprTypes.Connector memory onchain = SERVICE.getConnector(tracked.channelId, tracked.connectorId);
            _connectorStakeGhost[tracked.digest] = onchain.lockedStake;
            tracked.stake = onchain.lockedStake;
        } else {
            _connectorStakeGhost[tracked.digest] = 0;
        }

        _inflightGhost[tracked.connectorKey] = uint256(
            vm.load(
                address(SERVICE),
                ClprStorageLayoutLib.mapBytes32Slot(tracked.connectorKey, ClprServiceStorageSlots.CONNECTOR_INFLIGHT)
            )
        );
        _quotaGhost[tracked.quotaKey] = uint32(
            uint256(
                vm.load(
                    address(SERVICE),
                    ClprStorageLayoutLib.nestedMapBytes32Bytes32Slot(
                        tracked.channelId,
                        keccak256(abi.encodePacked(tracked.connectorId)),
                        ClprServiceStorageSlots.CONNECTOR_QUEUE_COUNTS
                    )
                )
            )
        );
    }

    function _resyncConnectorGhosts(bytes32 channelId) internal {
        for (uint256 i = 0; i < _connectors.length; i++) {
            TrackedConnector storage c = _connectors[i];
            if (!c.live || c.channelId != channelId) continue;
            _syncConnectorGhostsFor(c);
        }
    }
}
