// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {console} from "forge-std/console.sol";
import {ClprService} from "@hiero-ledger/clpr/ClprService.sol";
import {IClprService} from "@hiero-ledger/clpr/interfaces/IClprService.sol";
import {TSSVerifier} from "@hiero-ledger/clpr/verifiers/hiero/TSSVerifier.sol";
import {WRAPSVerifierContract} from "@hiero-ledger/clpr/verifiers/hiero/wraps/WRAPSVerifierContract.sol";
import {PoseidonBN254Contract} from "@hiero-ledger/clpr/verifiers/hiero/wraps/PoseidonBN254Contract.sol";
import {PoseidonPermuteA} from "@hiero-ledger/clpr/verifiers/hiero/wraps/PoseidonPermuteA.sol";
import {PoseidonPermuteB} from "@hiero-ledger/clpr/verifiers/hiero/wraps/PoseidonPermuteB.sol";
import {HieroVerifier} from "@hiero-ledger/clpr/verifiers/hiero/HieroVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {MockClprConnector} from "@test/mocks/MockClprConnector.sol";
import {ConnectorRegistrar} from "@test/helpers/ConnectorRegistrar.sol";
import {ClprTestBase} from "@test/helpers/ClprTestBase.sol";

/// @dev E2E test: real ClprService + real HieroVerifier + real stateProof.bin fixture.
///      Calls submitBundle and asserts the channel state is correctly updated.
///
///      Setup preconditions for the real proof (stateProof.bin):
///        - proof carries 1 inbound REPLY for our outbound message #1
///        - metadata.receivedMessageId = 1  (peer acked our msg #1)
///        - metadata.nextMessageId     = 2  (peer has sent 1 message = our 1 inbound)
///        - metadata.sentRunningHash   = sha256(0 || sha256(inboundPayload))
///        - metadata.state             = ACTIVE
///
///      For the ack-check to pass (receivedMessageId=1 < channel.nextMessageId), we must
///      have at least one outbound message queued before submitBundle.  setUp sends
///      one DATA message (slot 2 after the auto-queued config-update CONTROL at slot 1),
///      leaving channel.nextMessageId = 3 so the peer's ack of slot 1 is valid.
contract HieroSubmitBundleTest is ClprTestBase {
    TSSVerifier internal tssVerifier;
    HieroVerifier internal hieroVerifier;

    // First 128 bytes of the blockSignature (hintsVK section, n=4) — pinned key.
    bytes internal constant HINTS_KEY = hex"0400000000000000010000000000000000000000000000000000000000000000"
        hex"000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905"
        hex"a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1"
        hex"a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae4";

    bytes internal constant LEDGER_ID = hex"8b85b56b7349eb88bdaeb16b3ea396266e4682b53ba0df8ef74bf2b27a37f008";

    // Expected post-verification values decoded from the fixture's ClprChannel proto.
    bytes32 internal constant EXPECTED_SENT_RUNNING_HASH =
        0x81144f98abe92e6b4f00346caf2a08d157e42024e3d8032aa5e568ffc4123a5f;

    bytes32 internal constant EXPECTED_RECV_RUNNING_HASH =
        0xfafa3f38458c8b54b86d393432de11d60420705a627f5183d26f18b5f03c6a28;

    // The peer (Besu) ClprService address proven in the fixture's ClprChannel
    // (field 3). completeChannel stores this as channel.peerServiceAddress; submitBundle
    // then requires the proof's proven service_address to match it.
    bytes internal constant PEER_SERVICE_ADDRESS = hex"ade986b5973ec38f3996f3a128f7d8c3e8ffcd9d";

    // ── Fixtures ─────────────────────────────────────────────────────────────

    function _loadProof() internal view returns (bytes memory) {
        return vm.readFileBinary("test/verifiers/hiero/fixtures/stateProof.bin");
    }

    function _loadTrustAnchor() internal view returns (bytes memory) {
        return vm.readFileBinary("test/verifiers/hiero/fixtures/trustAnchor.bin");
    }

    // ── setUp ─────────────────────────────────────────────────────────────────

    function setUp() public override {
        // ── 1. Deploy service and verifier stack ─────────────────────────────
        service = _deployClprService(1, "eip155:1337");
        connector = MockClprConnector(payable(deployCode("MockClprConnector.sol:MockClprConnector")));
        address permuteA = deployCode("PoseidonPermuteA.sol:PoseidonPermuteA");
        address permuteB = deployCode("PoseidonPermuteB.sol:PoseidonPermuteB");
        address poseidon = deployCode("PoseidonBN254Contract.sol:PoseidonBN254Contract", abi.encode(permuteA, permuteB));
        address wraps = deployCode("WRAPSVerifierContract.sol:WRAPSVerifierContract", abi.encode(poseidon));
        tssVerifier = TSSVerifier(deployCode("TSSVerifier.sol:TSSVerifier", abi.encode(wraps)));
        hieroVerifier =
            HieroVerifier(deployCode("HieroVerifier.sol:HieroVerifier", abi.encode(LEDGER_ID, address(tssVerifier))));

        // ── 2. Mock verifyConfig ──────────────────────────────────────────────
        // Stub HieroVerifier.verifyConfig to return a controlled peer config so
        // completeChannel can derive and validate the channelId.
        // peerChainId="hiero:localnet" must match what service.deriveChannelId expects.
        {
            ClprTypes.Endpoint[] memory seeds = new ClprTypes.Endpoint[](0);
            bytes memory peerServiceAddress = PEER_SERVICE_ADDRESS;
            vm.mockCall(
                address(hieroVerifier),
                abi.encodeWithSelector(IClprVerifier.verifyConfig.selector),
                abi.encode(
                    // channelId must match the fixture's proven ClprChannel leaf (field 1).
                    ClprTypes.encodeChannelContext(
                        ClprTypes.ChannelContext({
                            channelId: 0xe1022276af73c7a88c9fa00f7e844bbc4a8fda0cc6051d9c99926b74cf9c3d84,
                            remoteServiceAddress: peerServiceAddress
                        })
                    ),
                    "hiero:localnet",
                    peerServiceAddress,
                    uint96(0),
                    defaultThrottles,
                    _loadTrustAnchor(),
                    bytes(""), // initialTrustAnchorId
                    ClprTypes.ClprEndpointManifest({version: 1, serviceAddress: peerServiceAddress, endpoints: seeds})
                )
            );
        }

        // ── 3. Configure service ──────────────────────────────────────────────
        service.initialize(
            hex"",
            defaultThrottles,
            hex"",
            hex"",
            ClprTypes.EconomicConfig({
                messageExecutionCost: 0.001 ether,
                endpointMarginPercent: 10,
                minLockedStake: 0,
                minEndpointBond: 0,
                basePenalty: 0.01 ether,
                penaltyMultiplier: 2,
                slashBanThreshold: 5,
                connectorQueueQuotaPct: 50,
                connectorInboundGasStipend: 500_000,
                maxChannels: 0,
                maxConnectors: 0,
                connectorPaymentGasLimit: 200_000
            })
        );
        service.setClprEnabled(true);

        // ── 4. Create channel with HieroVerifier ───────────────────────────
        bytes memory pubKey = _signerPubKey();
        channelId = service.deriveChannelId("hiero:localnet", pubKey, bytes32(0));

        bytes32 commitment = keccak256(abi.encodePacked(channelId, pubKey));
        service.registerChannel(channelId, commitment);

        bytes32 msgHash = keccak256(abi.encodePacked(channelId, address(service)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, _ethSignedHash(msgHash));
        service.completeChannel(
            channelId, pubKey, abi.encodePacked(r, s, v), bytes32(0), address(hieroVerifier), hex"", ""
        );

        // ── 5. Register endpoint (submitBundle requires the caller to be registered) ─

        // ── 6. Register connector + send one outbound DATA message ─────────────
        // The proof's metadata carries receivedMessageId=1 (peer acked our msg #1).
        // To pass the ack-validity check we need channel.nextMessageId > 1.
        // updateLedgerConfiguration above sets nanosSinceEpoch = block.timestamp*1e9 > 0,
        // so the first sendMessage auto-queues a config CONTROL at slot 1 (nextMessageId→2)
        // and our DATA lands at slot 2 (nextMessageId→3).  The peer's ack of slot 1 (≤3-1)
        // is therefore valid.
        connectorId = ConnectorRegistrar.register(
            IClprService(address(service)), channelId, keccak256("hiero-e2e-connector"), address(connector), owner, 0
        );
        service.sendMessage(channelId, connectorId, abi.encodePacked(owner), hex"deadbeef");
    }

    // ── E2E test ──────────────────────────────────────────────────────────────

    /// @notice Full pipeline: real HieroVerifier verifies the stateProof.bin fixture
    ///         and the channel state is updated correctly.
    ///
    /// @dev The stateProof.bin fixture was regenerated from a live end to end localnet
    ///      round trip after the running-hash fold changed to `sha256(prev || sha256(payload))`.
    ///      Its proven `sentRunningHash` (0x81144f98…) is therefore the new-formula value, so
    ///      `BundleLib`'s inbound re-fold matches and submitBundle succeeds. The proof's crypto
    ///      path is also covered by
    ///      `test/verifiers/hiero/HieroVerifier.t.sol::test_verifyBundle_fullPipeline`.
    function test_submitBundle_realStateProof() public {
        bytes memory proof = _loadProof();

        service.submitBundle(channelId, proof);

        ClprTypes.Channel memory channel = service.getChannel(channelId);

        assertEq(channel.receivedMessageId, 1, "receivedMessageId must advance to 1");
        assertEq(channel.receivedRunningHash, EXPECTED_SENT_RUNNING_HASH, "receivedRunningHash mismatch");
        assertEq(channel.ackedMessageId, 1, "ackedMessageId must be 1 (peer acked our slot 1)");
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE), "channel must remain ACTIVE");
        // submitBundle only reaches here if the proven peer service address matched the
        // stored one — i.e. HieroVerifier surfaced channel.service_address.
        assertEq(channel.peerServiceAddress, PEER_SERVICE_ADDRESS, "peer service address invariant satisfied");

        console.log("receivedMessageId :", channel.receivedMessageId);
        console.log("ackedMessageId    :", channel.ackedMessageId);
        console.logBytes32(channel.receivedRunningHash);
    }

    receive() external payable {}
}
