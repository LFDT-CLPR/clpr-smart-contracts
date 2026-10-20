// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {console} from "forge-std/Test.sol";
import {EthBundleProofFactory} from "@test/verifiers/evm/ethereum/EthBundleProofFactory.sol";
import {ClprDeployHelper} from "@test/helpers/ClprDeployHelper.sol";
import {CalldataGas} from "@test/helpers/CalldataGas.sol";
import {ConnectorRegistrar} from "@test/helpers/ConnectorRegistrar.sol";
import {MinimalMockApplication} from "@test/mocks/MinimalMockApplication.sol";
import {MinimalMockConnector} from "@test/mocks/MinimalMockConnector.sol";
import {ClprService} from "@hiero-ledger/clpr/ClprService.sol";
import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {EthMainnetVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/EthMainnetVerifier.sol";
import {ClprBeaconSsz} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconSsz.sol";
import {ClprBeaconBls} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconBls.sol";
import {ClprCommitteeMerkle} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprCommitteeMerkle.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

contract InstrumentedEthMainnetVerifier is EthMainnetVerifier {
    uint256 public constant STEP_COUNT = 14;

    constructor() {}

    // Step indices
    uint256 internal constant S_ANCHOR = 0;
    uint256 internal constant S_PAYLOAD_RLP = 1;
    uint256 internal constant S_HEADER_DECODE = 2;
    uint256 internal constant S_HEADER_ROOT = 3;
    uint256 internal constant S_SYNC_AGG_READ = 4;
    uint256 internal constant S_BLS = 5;
    uint256 internal constant S_EXEC_BRANCH = 6;
    uint256 internal constant S_CHANNEL_CTX = 7;
    uint256 internal constant S_ACCOUNT_PROOF = 8;
    uint256 internal constant S_STORAGE_PROOF = 9;
    uint256 internal constant S_BUNDLE_CONTENT = 10;
    uint256 internal constant S_MANIFEST = 11;
    uint256 internal constant S_ROTATION = 12;
    uint256 internal constant S_PERIOD_ID = 13;

    /// @dev Everything `_verifyTailSteps` needs from the committee-selection step, bundled so the
    ///      tail frame stays clear of the stack limit.
    struct Selection {
        uint64 signaturePeriod;
        uint64 attestedPeriod;
        uint256 committeeIndex;
        bytes32 channelId;
    }

    function verifyBundleSteps(bytes calldata proofBytes, bytes calldata trustAnchor, bytes calldata channelContext)
        external
        view
        returns (uint256[] memory g, bytes memory newTrustAnchorId)
    {
        g = new uint256[](STEP_COUNT);
        uint256 t = gasleft();

        // ── Step 1: trust anchor (flat packed reads) ─────────────────────────
        AnchorScalars memory anchor = _decodeAnchorScalars(trustAnchor);
        bytes32 gvr = anchor.gvr;
        bytes memory forkVersion = anchor.forkVersion;
        Selection memory sel;
        sel.channelId = anchor.channelId;
        uint64 anchorPeriod = anchor.period;
        t = _mark(g, S_ANCHOR, t);

        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory payload = RLP.decodeList(proofMem);
        if (payload.length != PAYLOAD_FIELDS && payload.length != PAYLOAD_FIELDS_WITH_MANIFEST) {
            revert InvalidPayloadShape();
        }
        t = _mark(g, S_PAYLOAD_RLP, t);

        // ── Step 2: attested beacon header → SSZ hash_tree_root ──────────────
        BeaconHeader memory header = _decodeBeaconHeader(payload[IDX_ATTESTED_HEADER]);
        t = _mark(g, S_HEADER_DECODE, t);

        bytes32 beaconBlockRoot = ClprBeaconSsz.beaconBlockHeaderRoot(
            header.slot, header.proposerIndex, header.parentRoot, header.stateRoot, header.bodyRoot
        );
        t = _mark(g, S_HEADER_ROOT, t);

        // ── Step 3: signature slot → window member, then supermajority + BLS ─
        uint64 signatureSlot = uint64(RLP.readUint256(payload[IDX_SIGNATURE_SLOT]));
        sel.signaturePeriod = signatureSlot / SLOTS_PER_SYNC_COMMITTEE_PERIOD;
        sel.attestedPeriod = header.slot / SLOTS_PER_SYNC_COMMITTEE_PERIOD;
        if (signatureSlot <= header.slot || sel.signaturePeriod > sel.attestedPeriod + 1) {
            revert InvalidSignatureSlot(signatureSlot, header.slot);
        }
        if (sel.signaturePeriod == anchorPeriod) {
            sel.committeeIndex = COMMITTEE_CURRENT;
        } else if (sel.signaturePeriod == anchorPeriod + 1) {
            sel.committeeIndex = COMMITTEE_NEXT;
        } else {
            revert SignaturePeriodOutOfWindow(sel.signaturePeriod, anchorPeriod);
        }

        Memory.Slice[] memory agg = RLP.readList(payload[IDX_SYNC_AGGREGATE]);
        if (agg.length != SYNC_AGGREGATE_FIELDS) revert InvalidSyncAggregate();
        bytes memory bits = RLP.readBytes(agg[0]);
        bytes memory signature = RLP.readBytes(agg[1]);
        if (bits.length != SYNC_BITS_LENGTH || signature.length != BLS_SIGNATURE_LENGTH) revert InvalidSyncAggregate();
        t = _mark(g, S_SYNC_AGG_READ, t);

        _verifyBls(
            trustAnchor,
            sel.committeeIndex,
            payload[IDX_NON_SIGNER_PROOFS],
            signature,
            bits,
            beaconBlockRoot,
            forkVersion,
            gvr
        );
        t = _mark(g, S_BLS, t);

        // ── Step 4: execution state root SSZ branch ──────────────────────────
        bytes32 executionStateRoot = RLP.readBytes32(payload[IDX_EXECUTION_STATE_ROOT]);
        bytes32[] memory execBranch = _decodeBranch(payload[IDX_EXECUTION_BRANCH], EXECUTION_BRANCH_DEPTH);
        if (!ClprBeaconSsz.verifyProof(
                executionStateRoot, execBranch, header.bodyRoot, ClprBeaconSsz.GINDEX_EXECUTION_STATE_ROOT_IN_BODY
            )) {
            revert ExecutionBranchInvalid();
        }
        t = _mark(g, S_EXEC_BRANCH, t);

        newTrustAnchorId = _verifyTailSteps(g, t, payload, trustAnchor, channelContext, executionStateRoot, header, sel);
    }

    // Steps 5-7 run in their own stack frame to avoid stack too deep
    function _verifyTailSteps(
        uint256[] memory g,
        uint256 t,
        Memory.Slice[] memory payload,
        bytes calldata trustAnchor,
        bytes calldata channelContext,
        bytes32 executionStateRoot,
        BeaconHeader memory header,
        Selection memory sel
    ) private view returns (bytes memory newTrustAnchorId) {
        // ── Step 5: MPT account proof ────────────────────────────────────────
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        address clprService = _toAddress(ctx.remoteServiceAddress);
        bytes32 expectedCodeHash = bytes32(trustAnchor[ANCHOR_OFF_CODE_HASH:ANCHOR_OFF_CODE_HASH + 32]);
        t = _mark(g, S_CHANNEL_CTX, t);

        bytes32 storageRoot =
            _verifyServiceStorageRoot(payload[IDX_ACCOUNT_PROOF], executionStateRoot, clprService, expectedCodeHash);
        t = _mark(g, S_ACCOUNT_PROOF, t);

        // ── Step 6: MPT storage proof of the queue-metadata slots ────────────
        bytes[] memory messagePayloads = _decodeBundleContent(RLP.readBytes(payload[IDX_BUNDLE_CONTENT]));
        t = _mark(g, S_BUNDLE_CONTENT, t);

        ClprTypes.QueueMetadata memory metadata =
            _verifyChannelStorage(payload[IDX_STORAGE_PROOF], storageRoot, sel.channelId, messagePayloads.length);
        t = _mark(g, S_STORAGE_PROOF, t);

        ClprTypes.ClprEndpointManifest memory manifest;
        if (payload.length == PAYLOAD_FIELDS_WITH_MANIFEST) {
            manifest = _verifyEndpointManifest(
                payload[IDX_MANIFEST_STORAGE_PROOF],
                storageRoot,
                RLP.readBytes(payload[IDX_MANIFEST_PREIMAGE]),
                ctx.remoteServiceAddress
            );
        } else {
            manifest = _absentEndpointManifest();
        }
        t = _mark(g, S_MANIFEST, t);

        // ── Step 7: optional next-sync-committee rotation (widen or shift) ───
        bytes memory newTrustAnchor = _verifyRotation(
            payload[IDX_NEXT_COMMITTEE],
            payload[IDX_NEXT_COMMITTEE_BRANCH],
            header.stateRoot,
            trustAnchor,
            sel.signaturePeriod,
            sel.attestedPeriod,
            sel.committeeIndex
        );
        t = _mark(g, S_ROTATION, t);

        newTrustAnchorId = newTrustAnchor.length == 0 ? newTrustAnchor : abi.encodePacked(sel.signaturePeriod);
        _mark(g, S_PERIOD_ID, t);

        // Keep the decoded results live so the optimiser cannot elide the work being measured.
        require(metadata.nextMessageId != type(uint64).max, "sentinel");
        require(messagePayloads.length < type(uint16).max, "sentinel");
        require(manifest.endpoints.length < type(uint16).max, "sentinel");
    }

    /// @dev Record `prev - gasleft()` into `g[i]` and return the new watermark. Its own cost lands in
    ///      the *following* bucket, uniformly, and is bounded by the total-vs-sum assertion.
    function _mark(uint256[] memory g, uint256 i, uint256 prev) private view returns (uint256 now_) {
        now_ = gasleft();
        g[i] = prev - now_;
    }

    // ── Sub-step probes (production primitives, isolated) ───────────────────

    /// @dev The pairing half of `_verifyBlsCore`: EIP-2537 G1MSM complement aggregation +
    ///      RFC-9380 hash-to-G2 + pairing. Excludes popcount and non-signer Merkle work.
    function pairingGas(
        bytes memory aggregatePubkey,
        bytes[] memory nonParticipants,
        bytes memory signature,
        bytes32 signingRoot
    ) external view returns (uint256 gasUsed) {
        uint256 g0 = gasleft();
        ClprBeaconBls.aggregateVerifyComplement(aggregatePubkey, nonParticipants, signature, signingRoot);
        gasUsed = g0 - gasleft();
    }

    /// @dev Signing-domain derivation: `computeSyncCommitteeDomain` + `computeSigningRoot`.
    function domainGas(bytes memory forkVersion, bytes32 gvr, bytes32 beaconBlockRoot)
        external
        view
        returns (uint256 gasUsed)
    {
        uint256 g0 = gasleft();
        bytes32 domain = ClprBeaconSsz.computeSyncCommitteeDomain(_toBytes4(forkVersion), gvr);
        bytes32 signingRoot = ClprBeaconSsz.computeSigningRoot(beaconBlockRoot, domain);
        gasUsed = g0 - gasleft();
        require(signingRoot != bytes32(0), "sentinel");
    }

    /// @dev Per-non-signer Merkle authentication against the anchor's committee root — the
    ///      load-bearing check inside `_collectNonSigners` (9 keccaks + one 128-byte copy each).
    /// @param firstIndex Committee index of the first non-signer, so the folds run at real indices.
    function nonSignerAuthGas(bytes memory entriesRlp, uint256 count, uint256 firstIndex, bytes32 committeeRoot)
        external
        view
        returns (uint256 gasUsed)
    {
        Memory.Slice[] memory entries = RLP.decodeList(entriesRlp);
        uint256 g0 = gasleft();
        for (uint256 i = 0; i < count; i++) {
            (bool ok,) = ClprCommitteeMerkle.verifyAndExtractKey(
                Memory.slice(entries[i], ENTRY_RLP_PREFIX_LENGTH), firstIndex + i, committeeRoot
            );
            if (!ok) revert NonSignerProofInvalid(firstIndex + i);
        }
        gasUsed = g0 - gasleft();
    }
}

/// @title EthGasReport
/// @notice The measurement suite behind `src/verifiers/evm/GAS_REPORT.md`.
///
/// A real {ClprService} owns a channel whose verifier is a real {EthMainnetVerifier}, seeded through that verifier's own `verifyConfig`.
/// Bundles are complete proofs from {EthBundleProofFactory}: real EIP-2537 BLS, real SSZ folds, real
/// Merkle-Patricia proofs at mainnet-shaped trie depth.
///
/// @dev Each N is measured in its **own test function**. Each test runs against cold storage so warming it up would
///      shave ~2.5k gas off whichever ran second.
///
///      {EthGasReportBase} holds the service, channel and spec plumbing; {EthGasReportTest} the
///      measurements against a channel opened on the attested-period window; {EthGasReportShiftTest} the
///      one measurement that needs the channel opened a period behind.
abstract contract EthGasReportBase is EthBundleProofFactory {
    uint256 internal constant ACCOUNT_DEPTH = 7; // 7 branches + leaf = 8 nodes
    uint256 internal constant STORAGE_DEPTH = 3; // 3 branches + leaf = 4 nodes

    bytes32 internal constant PEER_CODE_HASH = bytes32(uint256(0xC0DE));
    address internal constant PEER_SERVICE = address(0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C);
    string internal constant LOCAL_CHAIN = "eip155:1337";
    string internal constant PEER_CHAIN = "eip155:1";

    uint256 internal signerPk = 0xBEEF;

    ClprService internal service;
    EthMainnetVerifier internal ethVerifier;
    InstrumentedEthMainnetVerifier internal probe; // breakdown only, never wired
    MinimalMockApplication internal app;
    MinimalMockConnector internal connector;

    bytes32 internal channelId;
    bytes32 internal connectorId;
    address internal owner = address(this);

    receive() external payable {}

    function setUp() public virtual override {
        super.setUp(); // EthCommitteeFixtures: genUncompressed

        service = _deployService();
        ethVerifier = EthMainnetVerifier(deployCode("EthMainnetVerifier.sol:EthMainnetVerifier"));
        probe = new InstrumentedEthMainnetVerifier();
        app = new MinimalMockApplication();
        app.setResponse(hex"504F4E47"); // "PONG"
        connector = new MinimalMockConnector();

        service.initialize(hex"1234", _localThrottles(), "", "", _econ());
        service.setClprEnabled(true);

        _openChannel();
        _registerConnector();
    }

    // ═════════════════════════════════════════════════════════════════════════
    //   Setup
    // ═════════════════════════════════════════════════════════════════════════

    function _deployService() private returns (ClprService) {
        ClprDeployHelper.Modules memory m = ClprDeployHelper.deployModules();
        bytes memory args = abi.encode(
            owner,
            uint32(1),
            LOCAL_CHAIN,
            m.channelLogic,
            m.messagingLogic,
            m.bundleLogic,
            m.connectorLogic,
            m.adminLogic,
            m.bundleDecodeHelper,
            address(0) // feeToken: native value
        );
        return ClprService(payable(deployCode("ClprService.sol:ClprService", args)));
    }

    function _localThrottles() private pure returns (ClprTypes.Throttles memory) {
        return ClprTypes.Throttles({
            maxMessagesPerBundle: 100,
            maxMessagePayloadBytes: 1024,
            maxGasPerMessage: 1_000_000,
            maxQueueDepth: 1000,
            maxSyncBytes: 1_048_576,
            maxLocalEndpoints: 0,
            maxPeerEndpoints: 0
        });
    }

    function _econ() private pure returns (ClprTypes.EconomicConfig memory) {
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
            maxConnectors: 0,
            connectorPaymentGasLimit: 200_000
        });
    }

    /// @dev Open the channel through the verifier's own `verifyConfig`, so the stored trust anchor is
    ///      the one production code derives rather than a value the test injected.
    function _openChannel() private {
        Vm.Wallet memory w = vm.createWallet(signerPk);
        bytes memory pubKey = abi.encodePacked(w.publicKeyX, w.publicKeyY);

        bytes memory a = bytes(LOCAL_CHAIN);
        bytes memory b = bytes(PEER_CHAIN);
        channelId = keccak256(a) <= keccak256(b)
            ? keccak256(abi.encodePacked(a, b, pubKey, bytes32(0)))
            : keccak256(abi.encodePacked(b, a, pubKey, bytes32(0)));

        service.registerChannel(channelId, keccak256(abi.encodePacked(channelId, pubKey)));

        bytes32 msgHash = keccak256(abi.encodePacked(channelId, address(service)));
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(signerPk, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash)));

        service.completeChannel(
            channelId,
            pubKey,
            abi.encodePacked(r, s, v),
            bytes32(0),
            address(ethVerifier),
            _configProof(_configSpec(), PEER_CHAIN),
            ""
        );
    }

    function _registerConnector() private {
        connectorId = ConnectorRegistrar.register(
            IClprService(address(service)),
            channelId,
            keccak256(abi.encodePacked("eth-gas-report-connector")),
            address(connector),
            owner,
            1 ether
        );
        (bool ok,) = address(connector).call{value: 9 ether}("");
        require(ok, "fund connector");
        (ok,) = address(service).call{value: 10 ether}("");
        require(ok, "fund service");
    }

    /// @dev The window the channel is opened with.
    function _configSpec() internal view virtual returns (BundleSpec memory) {
        return _spec(0);
    }

    function _spec(uint256 n) internal view returns (BundleSpec memory) {
        return BundleSpec({
            messageCount: n,
            signers: SYNC_COMMITTEE_SIZE,
            accountDepth: ACCOUNT_DEPTH,
            storageDepth: STORAGE_DEPTH,
            denseBranches: true,
            rotation: Rotation.None,
            manifest: false,
            ackedByPeer: 0,
            channelId: channelId,
            peerService: PEER_SERVICE,
            codeHash: PEER_CODE_HASH,
            connectorId: connectorId,
            targetApp: address(app)
        });
    }

    function _calldataGas(bytes memory data) internal pure returns (uint256) {
        return CalldataGas.eip2028(data);
    }
}

/// @title EthGasReportTest
/// @notice The headline and breakdown measurements, against a channel whose stored window is
///         `{ signer, peer }` at the attested period.
contract EthGasReportTest is EthGasReportBase {
    // ═════════════════════════════════════════════════════════════════════════
    //   Smoke: the proof is genuinely accepted end to end
    // ═════════════════════════════════════════════════════════════════════════

    /// @dev Underwrites every number in the report
    function test_syntheticBundle_isAcceptedEndToEnd() public {
        BuiltBundle memory bundle = _buildBundle(_spec(1));

        assertEq(bundle.accountProofDepth, ACCOUNT_DEPTH + 1, "account proof depth");
        assertEq(bundle.storageProofDepth, STORAGE_DEPTH + 1, "storage proof depth");

        (ClprTypes.QueueMetadata memory md, bytes[] memory payloads,,,) =
            ethVerifier.verifyBundle(bundle.proof, bundle.trustAnchor, bundle.channelContext);

        assertEq(payloads.length, 1, "one message decoded");
        assertEq(md.nextMessageId, 2, "proven nextMessageId");
        assertEq(md.sentRunningHash, bundle.sentRunningHash, "proven running hash");
        assertEq(uint8(md.state), uint8(ClprTypes.ChannelStatus.ACTIVE), "proven channel state");

        service.submitBundle(channelId, bundle.proof);
        assertEq(service.getChannel(channelId).receivedMessageId, 1, "service advanced the receive cursor");
    }

    // ═════════════════════════════════════════════════════════════════════════
    //   Headline: submitBundle TOTAL by N (one pristine channel each)
    // ═════════════════════════════════════════════════════════════════════════

    function test_gas_submitBundle_ackOnly() public {
        // Give the peer something to ack: one outbound message, so channel.nextMessageId becomes 2
        // and an acked cursor of 1 is valid.
        service.sendMessage(channelId, connectorId, abi.encodePacked(address(app)), hex"48454C4C4F");

        BundleSpec memory spec = _spec(0);
        spec.ackedByPeer = 1;
        BuiltBundle memory bundle = _buildBundle(spec);

        uint256 g0 = gasleft();
        service.submitBundle(channelId, bundle.proof);
        uint256 total = g0 - gasleft();

        console.log("submitBundle TOTAL, ACK-only (N=0) :", total);
        console.log("  proof calldata bytes         :", bundle.proof.length);
        console.log("  proof calldata intrinsic gas :", _calldataGas(bundle.proof));
    }

    function test_gas_verifyBundle_ackOnly() public {
        BundleSpec memory spec = _spec(0);
        spec.ackedByPeer = 1;
        BuiltBundle memory bundle = _buildBundle(spec);

        uint256 g0 = gasleft();
        ethVerifier.verifyBundle(bundle.proof, bundle.trustAnchor, bundle.channelContext);
        uint256 used = g0 - gasleft();

        console.log("verifyBundle, ACK-only (N=0) :", used);
    }

    function test_gas_submitBundle_n1() public {
        _reportSubmit(1);
    }

    function test_gas_submitBundle_n2() public {
        _reportSubmit(2);
    }

    function test_gas_submitBundle_n5() public {
        _reportSubmit(5);
    }

    function test_gas_submitBundle_n10() public {
        _reportSubmit(10);
    }

    function _reportSubmit(uint256 n) internal {
        BuiltBundle memory bundle = _buildBundle(_spec(n));
        uint256 g0 = gasleft();
        service.submitBundle(channelId, bundle.proof);
        uint256 total = g0 - gasleft();

        console.log("submitBundle TOTAL, N =", n, ":", total);
        console.log("  proof calldata bytes         :", bundle.proof.length);
        console.log("  proof calldata intrinsic gas :", _calldataGas(bundle.proof));
    }

    // ═════════════════════════════════════════════════════════════════════════
    //   Headline: verifyBundle in isolation by N (same bundles, cold)
    // ═════════════════════════════════════════════════════════════════════════

    function test_gas_verifyBundle_n1() public {
        _reportVerify(1);
    }

    function test_gas_verifyBundle_n2() public {
        _reportVerify(2);
    }

    function test_gas_verifyBundle_n5() public {
        _reportVerify(5);
    }

    function test_gas_verifyBundle_n10() public {
        _reportVerify(10);
    }

    function _reportVerify(uint256 n) internal {
        BuiltBundle memory bundle = _buildBundle(_spec(n));
        uint256 g0 = gasleft();
        ethVerifier.verifyBundle(bundle.proof, bundle.trustAnchor, bundle.channelContext);
        uint256 used = g0 - gasleft();

        console.log("verifyBundle, N =", n, ":", used);
    }

    // ═════════════════════════════════════════════════════════════════════════
    //   Inside verifyBundle
    // ═════════════════════════════════════════════════════════════════════════

    function test_report_verifyBundleBreakdown() public {
        BuiltBundle memory bundle = _buildBundle(_spec(1));

        (uint256[] memory g,) = probe.verifyBundleSteps(bundle.proof, bundle.trustAnchor, bundle.channelContext);

        uint256 g0 = gasleft();
        ethVerifier.verifyBundle(bundle.proof, bundle.trustAnchor, bundle.channelContext);
        uint256 real = g0 - gasleft();

        string[14] memory labels = [
            "1  trust-anchor reads      ",
            "   top-level RLP decode    ",
            "2  beacon header decode    ",
            "   beacon header SSZ root  ",
            "3  sig slot + sync-agg read",
            "   BLS verify (total)      ",
            "4  execution SSZ branch    ",
            "5  channel context decode  ",
            "   MPT account proof       ",
            "6  MPT storage proof       ",
            "   bundle content protobuf ",
            "   endpoint manifest       ",
            "7  rotation (absent)       ",
            "   trust-anchor id         "
        ];

        uint256 sum;
        console.log("=== inside verifyBundle (N=1, 512/512 participation) ===");
        for (uint256 i = 0; i < g.length; i++) {
            console.log(labels[i], g[i]);
            sum += g[i];
        }
        console.log("----------------------------------------");
        console.log("sum of steps           :", sum);
        console.log("real verifyBundle call :", real);

        assertApproxEqAbs(sum, real, real / 20 + 5000, "instrumented body drifted from production verifyBundle");
    }

    /// @dev Split the BLS step — into the production primitives
    function test_report_blsBreakdown() public {
        uint256[6] memory signerCounts = [uint256(512), 507, 502, 497, 492, 342];

        console.log("=== inside the BLS step, by participation ===");
        for (uint256 i = 0; i < signerCounts.length; i++) {
            uint256 signers = signerCounts[i];
            BundleSpec memory spec = _spec(1);
            spec.signers = signers;
            BuiltBundle memory bundle = _buildBundle(spec);

            uint256 nonSigners = SYNC_COMMITTEE_SIZE - signers;
            uint256 pairing = probe.pairingGas(
                bundle.aggregatePubkey, _uncompressedKeys(nonSigners), bundle.signature, bundle.signingRoot
            );
            uint256 domain = probe.domainGas(abi.encodePacked(FORK_VERSION), GVR, bundle.beaconBlockRoot);
            uint256 auth = nonSigners == 0
                ? 0
                : probe.nonSignerAuthGas(_nonSignerListRlp(nonSigners), nonSigners, signers, bundle.committeeRoot);

            (uint256[] memory steps,) = probe.verifyBundleSteps(bundle.proof, bundle.trustAnchor, bundle.channelContext);
            uint256 blsTotal = steps[5];

            console.log("signers / non-signers  :", signers, nonSigners);
            console.log("  BLS step total               :", blsTotal);
            console.log("  - aggregateVerifyComplement  :", pairing);
            console.log("  - non-signer Merkle auth     :", auth);
            console.log("  - signing domain + root      :", domain);
            console.log("  - residual (popcount/RLP/mem):", blsTotal - pairing - auth - domain);
            console.log("  proof calldata bytes         :", bundle.proof.length);
            console.log("  proof calldata gas           :", _calldataGas(bundle.proof));
            console.log("");
        }
    }

    /// @dev MPT walk gas is proportional to proof depth, so report the sensitivity
    function test_report_mptDepthSensitivity() public {
        uint256[4] memory depths = [uint256(1), 3, 5, 7];

        console.log("=== verifyBundle vs MPT trie depth (N=1, 512/512) ===");
        for (uint256 i = 0; i < depths.length; i++) {
            BundleSpec memory spec = _spec(1);
            spec.accountDepth = depths[i];
            spec.storageDepth = depths[i];
            BuiltBundle memory bundle = _buildBundle(spec);

            (uint256[] memory steps,) = probe.verifyBundleSteps(bundle.proof, bundle.trustAnchor, bundle.channelContext);

            uint256 g0 = gasleft();
            ethVerifier.verifyBundle(bundle.proof, bundle.trustAnchor, bundle.channelContext);
            uint256 total = g0 - gasleft();

            console.log("proof nodes per trie   :", depths[i] + 1);
            console.log("  MPT account proof    :", steps[8]);
            console.log("  MPT storage proof    :", steps[9]);
            console.log("  verifyBundle total   :", total);
            console.log("");
        }
    }

    /// @dev Branch-node width, held at the headline depths. A 2-child branch encodes to ~81 bytes and
    ///      a full one to ~529, and the walker keccaks and copies every node it visits.
    function test_report_branchDensity() public {
        console.log("=== verifyBundle vs branch-node width (N=1, 512/512, headline depths) ===");
        for (uint256 i = 0; i < 2; i++) {
            bool dense = i == 1;
            BundleSpec memory spec = _spec(1);
            spec.denseBranches = dense;
            BuiltBundle memory bundle = _buildBundle(spec);

            (uint256[] memory steps,) = probe.verifyBundleSteps(bundle.proof, bundle.trustAnchor, bundle.channelContext);

            uint256 g0 = gasleft();
            ethVerifier.verifyBundle(bundle.proof, bundle.trustAnchor, bundle.channelContext);
            uint256 total = g0 - gasleft();

            console.log(dense ? "16 children per branch (dense)" : "2 children per branch (sparse)");
            console.log("  MPT account proof    :", steps[8]);
            console.log("  MPT storage proof    :", steps[9]);
            console.log("  verifyBundle total   :", total);
            console.log("  proof calldata bytes :", bundle.proof.length);
            console.log("");
        }
    }

    // ═════════════════════════════════════════════════════════════════════════
    //   Optional payload items — one test each, so no measurement inherits the caller-side memory
    //   expansion of an earlier bundle build in the same frame
    // ═════════════════════════════════════════════════════════════════════════

    /// @dev Widen: the bundle re-proves the window's stored `next` from the attested state.
    function test_report_rotationWiden() public {
        BundleSpec memory spec = _spec(1);
        spec.rotation = Rotation.Widen;
        BuiltBundle memory bundle = _buildBundle(spec);

        uint256 g0 = gasleft();
        (,, bytes memory newAnchor,,) =
            ethVerifier.verifyBundle(bundle.proof, bundle.trustAnchor, bundle.channelContext);
        uint256 used = g0 - gasleft();
        assertEq(newAnchor.length, 0, "widen must not move the window");

        _reportOptional("rotation: widen (window unchanged)", bundle, used);
    }

    /// @dev Shift: the anchor is one period behind, the bundle is verified by its `next` member and
    ///      proves the committee after it.
    function test_report_rotationShift() public {
        BundleSpec memory spec = _spec(1);
        spec.rotation = Rotation.Shift;
        BuiltBundle memory bundle = _buildBundle(spec);

        uint256 g0 = gasleft();
        (,, bytes memory newAnchor, bytes memory newId,) =
            ethVerifier.verifyBundle(bundle.proof, bundle.trustAnchor, bundle.channelContext);
        uint256 used = g0 - gasleft();
        assertEq(newAnchor.length, bundle.trustAnchor.length, "shift must return the successor anchor");
        assertEq(newId, abi.encodePacked(ATTESTED_PERIOD), "shift id is the new window start");

        _reportOptional("rotation: shift (window advances)", bundle, used);
    }

    function test_report_endpointManifest() public {
        BundleSpec memory spec = _spec(1);
        spec.manifest = true;
        BuiltBundle memory bundle = _buildBundle(spec);

        uint256 g0 = gasleft();
        ethVerifier.verifyBundle(bundle.proof, bundle.trustAnchor, bundle.channelContext);
        uint256 used = g0 - gasleft();

        _reportOptional("endpoint manifest", bundle, used);
    }

    /// @dev A Widen through the service: the stored window `{ signer, peer }` is unchanged afterwards.
    function test_gas_submitBundle_widen() public {
        BundleSpec memory spec = _spec(1);
        spec.rotation = Rotation.Widen;
        BuiltBundle memory bundle = _buildBundle(spec);
        bytes memory before = service.getChannel(channelId).trustAnchor;

        uint256 g0 = gasleft();
        service.submitBundle(channelId, bundle.proof);
        uint256 total = g0 - gasleft();
        assertEq(service.getChannel(channelId).trustAnchor, before, "widen leaves the stored anchor alone");

        console.log("submitBundle TOTAL, N = 1, rotation: widen :", total);
        console.log("  proof calldata bytes         :", bundle.proof.length);
        console.log("  proof calldata intrinsic gas :", _calldataGas(bundle.proof));
    }

    /// @dev Print one optional-item measurement next to the probe's own reading of the item's step.
    function _reportOptional(string memory label, BuiltBundle memory bundle, uint256 verifyGas) internal view {
        (uint256[] memory steps,) = probe.verifyBundleSteps(bundle.proof, bundle.trustAnchor, bundle.channelContext);
        console.log("=== optional payload item (N=1, 512/512):", label, "===");
        console.log("verifyBundle total          :", verifyGas);
        console.log("  step 7 rotation (probe)   :", steps[12]);
        console.log("  endpoint manifest (probe) :", steps[11]);
        console.log("  proof calldata bytes      :", bundle.proof.length);
        console.log("  proof calldata gas        :", _calldataGas(bundle.proof));
    }
}

/// @title EthGasReportShiftTest
/// @notice The same service and channel, opened one period behind — window `{ peer, signer }` — so a
///         Shift bundle can go through `submitBundle` and the cost of storing the 428-byte successor
///         anchor is measured alongside the verification.
contract EthGasReportShiftTest is EthGasReportBase {
    function _configSpec() internal view override returns (BundleSpec memory spec) {
        spec = _spec(0);
        spec.rotation = Rotation.Shift;
    }

    function test_gas_submitBundle_shift() public {
        BundleSpec memory spec = _spec(1);
        spec.rotation = Rotation.Shift;
        BuiltBundle memory bundle = _buildBundle(spec);
        assertEq(service.getChannel(channelId).trustAnchor, bundle.trustAnchor, "channel opened on the shift window");

        uint256 g0 = gasleft();
        service.submitBundle(channelId, bundle.proof);
        uint256 total = g0 - gasleft();

        ClprTypes.Channel memory updated = service.getChannel(channelId);
        assertEq(updated.trustAnchorId, abi.encodePacked(ATTESTED_PERIOD), "window advanced to the attested period");
        assertEq(updated.receivedMessageId, 1, "message delivered in the same bundle");

        console.log("submitBundle TOTAL, N = 1, rotation: shift :", total);
        console.log("  proof calldata bytes         :", bundle.proof.length);
        console.log("  proof calldata intrinsic gas :", _calldataGas(bundle.proof));
    }
}
