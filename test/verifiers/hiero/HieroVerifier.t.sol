// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {TSSVerifier} from "@hiero-ledger/clpr/verifiers/hiero/TSSVerifier.sol";
import {WRAPSVerifierContract} from "@hiero-ledger/clpr/verifiers/hiero/wraps/WRAPSVerifierContract.sol";
import {PoseidonBN254Contract} from "@hiero-ledger/clpr/verifiers/hiero/wraps/PoseidonBN254Contract.sol";
import {PoseidonPermuteA} from "@hiero-ledger/clpr/verifiers/hiero/wraps/PoseidonPermuteA.sol";
import {PoseidonPermuteB} from "@hiero-ledger/clpr/verifiers/hiero/wraps/PoseidonPermuteB.sol";
import {HieroVerifier} from "@hiero-ledger/clpr/verifiers/hiero/HieroVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprStateProof} from "@hiero-ledger/clpr/libraries/proof/hiero/ClprStateProof.sol";
import {ClprMerkleProof} from "@hiero-ledger/clpr/libraries/proof/hiero/ClprMerkleProof.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

/// @dev Integration test for HieroVerifier.verifyBundle using real state-proof data
///      captured from a localnet block. Fixtures live in test/verifiers/hiero/fixtures/.
///
///      The stateProof.bin is a serialised Hiero StateProof proto with:
///        - 2 MerklePath entries (one Channel leaf, one MessageValue leaf)
///        - A TssSignedBlockProof carrying a 3432-byte WRAPS hinTS signature (n=4)
///
///      Proof structure:
///        paths[0] — StateItem leaf: ClprChannel (SV_CHANNEL_TAG=482)
///        paths[1] — StateItem leaf: ClprMessageValue (SV_MESSAGE_TAG=498)
///        Both paths stand alone (nextPathIndex = TERMINATOR).
///
///      Expected post-verification values (decoded from raw proto):
///        channel.status             = ACTIVE (1)
///        channel.nextMessageId      = 2
///        channel.ackedMessageId     = 0 (proto3 default)
///        channel.sentRunningHash    = 0x81144f98...
///        channel.receivedMessageId  = 1
///        channel.receivedRunningHash = 0xfafa3f38...
///        messagePayloads.length        = 1
///        metadata.nextMessageId        = ackedMessageId + 1 + payloads.length = 2
contract HieroVerifierTest is Test {
    TSSVerifier internal tssVerifier;
    HieroVerifier internal hieroVerifier;

    // First 128 bytes of the blockSignature (hintsVK section, n=4).
    // Used as the pinned key in the HieroVerifier constructor.
    bytes internal constant HINTS_KEY = hex"0400000000000000010000000000000000000000000000000000000000000000"
        hex"000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905"
        hex"a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1"
        hex"a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae4";

    // Ledger ID for this localnet block; matches the trustAnchor.bin bytes.
    bytes internal constant LEDGER_ID = hex"8b85b56b7349eb88bdaeb16b3ea396266e4682b53ba0df8ef74bf2b27a37f008";

    // Expected proof outputs decoded manually from the proto (see test header).
    bytes32 internal constant EXPECTED_SENT_RUNNING_HASH =
        0x81144f98abe92e6b4f00346caf2a08d157e42024e3d8032aa5e568ffc4123a5f;
    bytes32 internal constant EXPECTED_RECV_RUNNING_HASH =
        0xfafa3f38458c8b54b86d393432de11d60420705a627f5183d26f18b5f03c6a28;

    // channel_id (field 1) and service_address (field 3) proven in the fixture's ClprChannel leaf.
    bytes32 internal constant EXPECTED_CHANNEL_ID = 0xe1022276af73c7a88c9fa00f7e844bbc4a8fda0cc6051d9c99926b74cf9c3d84;
    bytes internal constant PEER_SERVICE_ADDRESS = hex"ade986b5973ec38f3996f3a128f7d8c3e8ffcd9d";

    function setUp() public {
        address permuteA = deployCode("PoseidonPermuteA.sol:PoseidonPermuteA");
        address permuteB = deployCode("PoseidonPermuteB.sol:PoseidonPermuteB");
        address poseidon = deployCode("PoseidonBN254Contract.sol:PoseidonBN254Contract", abi.encode(permuteA, permuteB));
        address wraps = deployCode("WRAPSVerifierContract.sol:WRAPSVerifierContract", abi.encode(poseidon));
        tssVerifier = TSSVerifier(deployCode("TSSVerifier.sol:TSSVerifier", abi.encode(wraps)));
        hieroVerifier =
            HieroVerifier(deployCode("HieroVerifier.sol:HieroVerifier", abi.encode(LEDGER_ID, address(tssVerifier))));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    function _loadProof() internal view returns (bytes memory) {
        return vm.readFileBinary("test/verifiers/hiero/fixtures/stateProof.bin");
    }

    function _loadTrustAnchor() internal view returns (bytes memory) {
        return vm.readFileBinary("test/verifiers/hiero/fixtures/trustAnchor.bin");
    }

    /// @dev A channelContext bound to the fixture's proven channel id.
    function _ctx() internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: EXPECTED_CHANNEL_ID, remoteServiceAddress: PEER_SERVICE_ADDRESS})
        );
    }

    // ── Decode smoke: state-proof can be parsed and has 2 paths ─────────────

    function test_decode_stateProof_hasTwoPaths() public view {
        bytes memory proof = _loadProof();
        ClprStateProof.StateProofDecoded memory sp = ClprStateProof.decode(proof);

        assertEq(sp.paths.length, 2, "expect 2 MerklePath entries");
        assertTrue(sp.signature.length > 0, "signature must be present");
        assertEq(sp.signature.length, 3432, "WRAPS signature is 3432 bytes");
    }

    function test_decode_firstPath_isStateItemLeaf() public view {
        bytes memory proof = _loadProof();
        ClprStateProof.StateProofDecoded memory sp = ClprStateProof.decode(proof);

        uint256 idx = ClprMerkleProof.findFirstPath(sp.paths, ClprMerkleProof.LeafKind.StateItemLeaf);
        assertEq(idx, 0, "first state-item-leaf must be at index 0");
    }

    // ── Merkle root computation ───────────────────────────────────────────────

    function test_computeBlockRoot_returnsFortyEightBytes() public view {
        bytes memory proof = _loadProof();
        ClprStateProof.StateProofDecoded memory sp = ClprStateProof.decode(proof);

        bytes memory root = ClprMerkleProof.computeChainedRoot(sp.paths, 0);
        assertEq(root.length, 48, "SHA-384 block root must be 48 bytes");

        // Both paths are standalone (nextPathIndex = TERMINATOR) and should
        // converge to the same block root.
        bytes memory root1 = ClprMerkleProof.computeChainedRoot(sp.paths, 1);
        assertEq(keccak256(root), keccak256(root1), "both paths must produce the same block root");

        console.log("Block root (hex):");
        console.logBytes(root);
    }

    // ── extractDecodedQueueData ───────────────────────────────────────────────

    function test_extractDecodedQueueData_channelAndOneMessage() public view {
        bytes memory proof = _loadProof();
        ClprStateProof.StateProofDecoded memory sp = ClprStateProof.decode(proof);
        bytes memory blockRoot = ClprMerkleProof.computeChainedRoot(sp.paths, 0);

        (ClprTypes.Channel memory channel, bytes[] memory payloads, bytes memory manifestWire) =
            ClprStateProof.extractDecodedQueueData(sp.paths, blockRoot);
        assertEq(manifestWire.length, 0, "fixture carries no manifest leaf");

        // Channel
        assertEq(uint8(channel.status), uint8(ClprTypes.ChannelStatus.ACTIVE), "status must be ACTIVE");
        assertEq(channel.nextMessageId, 2, "nextMessageId == 2");
        assertEq(channel.ackedMessageId, 0, "ackedMessageId == 0 (proto3 default)");
        assertEq(channel.receivedMessageId, 1, "receivedMessageId == 1");
        assertEq(channel.sentRunningHash, EXPECTED_SENT_RUNNING_HASH, "sentRunningHash mismatch");
        assertTrue(channel.peerServiceAddress.length > 0, "peerServiceAddress decoded from channel field 3");

        // Message bundle
        assertEq(payloads.length, 1, "must have exactly 1 message payload");
        assertTrue(payloads[0].length > 0, "payload must not be empty");

        console.log("payload[0] length:", payloads[0].length);
    }

    // ── Full verifyBundle pipeline ────────────────────────────────────────────

    function test_verifyBundle_fullPipeline() public view {
        bytes memory proof = _loadProof();
        bytes memory ta = _loadTrustAnchor();

        (ClprTypes.QueueMetadata memory meta, bytes[] memory payloads, bytes memory newTrustAnchor,,) =
            hieroVerifier.verifyBundle(proof, ta, _ctx());

        // Structural checks
        assertEq(uint8(meta.state), uint8(ClprTypes.ChannelStatus.ACTIVE), "state must be ACTIVE");
        assertEq(meta.nextMessageId, 2, "nextMessageId = ackedMessageId(0) + 1 + payloads.length(1)");
        assertEq(meta.receivedMessageId, 1, "receivedMessageId == 1");
        assertEq(meta.sentRunningHash, EXPECTED_SENT_RUNNING_HASH, "sentRunningHash mismatch");
        assertEq(meta.receivedRunningHash, EXPECTED_RECV_RUNNING_HASH, "receivedRunningHash mismatch");

        assertEq(payloads.length, 1, "must contain exactly 1 message payload");
        assertTrue(payloads[0].length > 0, "payload must not be empty");
        assertEq(newTrustAnchor.length, 32, "HieroVerifier returns newTrustAnchor = keccak256(hintsVK)");

        console.log("nextMessageId:", meta.nextMessageId);
        console.log("receivedMessageId:", meta.receivedMessageId);
        console.log("payload[0] length:", payloads[0].length);
        console.logBytes32(meta.sentRunningHash);
        console.logBytes32(meta.receivedRunningHash);
    }

    /// @notice A genuine, correctly-signed proof of one channel must not be accepted for a
    ///         different local channel id (Finding 2: leaves not bound to the channel).
    function test_verifyBundle_wrongChannelId_reverts() public {
        bytes memory proof = _loadProof();
        bytes memory ta = _loadTrustAnchor();

        bytes memory foreignCtx = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({
                channelId: bytes32(uint256(0xBEEF)), // not the fixture's proven channel id
                remoteServiceAddress: PEER_SERVICE_ADDRESS
            })
        );

        vm.expectRevert(HieroVerifier.ClprHieroChannelMismatch.selector);
        hieroVerifier.verifyBundle(proof, ta, foreignCtx);
    }

    // ── Negative tests ───────────────────────────────────────────────────────

    function test_verifyBundle_revertsOnEmptyProof() public {
        bytes memory ta = _loadTrustAnchor();
        vm.expectRevert(HieroVerifier.ClprHieroBlockProofMissing.selector);
        hieroVerifier.verifyBundle(new bytes(0), ta, "");
    }

    function test_verifyBundle_revertsOnBadBlockRootHash() public {
        bytes memory proof = _loadProof();
        bytes memory ta = _loadTrustAnchor();

        // Decode the proof and flip one byte in path[0]'s first sibling hash.
        // path[0] is encoded at offset 3 (tag 0x0a + 2-byte length varint).
        // The first sibling hash starts early in the path bytes; byte 10 is
        // deep inside path[0]'s first sibling (well past the path header).
        proof[10] ^= 0xff;

        // path[0]'s Merkle root will now differ from the block root over which
        // the TSS signature was produced, causing HieroHintsFinalPairingFailed
        // (TSS step 4 uses the wrong block root) or StateProofPathInvalid
        // (extractDecodedQueueData root mismatch). Either is a valid revert.
        vm.expectRevert();
        hieroVerifier.verifyBundle(proof, ta, "");
    }

    // ── Constructor edge cases ────────────────────────────────────────────────

    function test_constructor_revertsOnEmptyLedgerId() public {
        vm.expectRevert(HieroVerifier.ClprHieroEmptyLedgerId.selector);
        new HieroVerifier(new bytes(0), tssVerifier);
    }

    function test_constructor_storesLedgerId() public view {
        assertEq(keccak256(hieroVerifier.ledgerId()), keccak256(LEDGER_ID));
    }

    // ── verifyConfig — empty input ────────────────────────────────────────────

    function test_verifyConfig_emptyInput_reverts() public {
        vm.expectRevert(HieroVerifier.InvalidPayloadShape.selector);
        hieroVerifier.verifyConfig(new bytes(0), bytes32(0), "");
    }

    // ── verifyConfig — non-empty input (decodes LedgerConfiguration) ──────────

    function _minimalCfg() internal pure returns (ClprTypes.LedgerConfiguration memory cfg) {
        cfg.protocolVersion = 1;
        cfg.chainId = "testnet-42";
        cfg.serviceAddress = hex"deadbeef";
        cfg.nanosSinceEpoch = 1_000_000_000; // 1 second exactly
        cfg.throttles = ClprTypes.Throttles({
            maxMessagesPerBundle: 50,
            maxMessagePayloadBytes: 2000,
            maxGasPerMessage: 500_000,
            maxQueueDepth: 200,
            maxSyncBytes: 2000,
            maxLocalEndpoints: 0,
            maxPeerEndpoints: 0
        });
        cfg.trustAnchor = "";
        cfg.trustAnchorId = "";
    }

    /// @dev Build an encoded ClprEndpointManifest proof (version 1) carrying `eps`, for the
    ///      third `verifyConfig` argument.
    function _manifestProof(ClprTypes.Endpoint[] memory eps, bytes memory svcAddr)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory manifestWire = ClprProtobuf.encodeEndpointManifest(
            ClprTypes.ClprEndpointManifest({version: 1, serviceAddress: svcAddr, endpoints: eps})
        );
        bytes memory leaf = PB.encodeBytesField(3, PB.encodeBytesField(64, manifestWire));
        bytes memory path =
            abi.encodePacked(PB.encodeVarintField(2, uint64(type(uint32).max)), PB.encodeBytesField(4, leaf));
        bytes memory signedBlockProof = PB.encodeBytesField(ClprStateProof.SBP_BLOCK_SIGNATURE, hex"DEADBEEF");
        return abi.encodePacked(PB.encodeBytesField(1, path), PB.encodeBytesField(2, signedBlockProof));
    }

    /// @notice The endpoint-limit throttles (maxLocalEndpoints/maxPeerEndpoints, proto fields 8/9)
    ///         round-trip through the config proof and are returned by verifyConfig — not dropped.
    function test_verifyConfig_nonEmpty_carriesEndpointLimits() public view {
        ClprTypes.LedgerConfiguration memory cfg = _minimalCfg();
        cfg.throttles.maxLocalEndpoints = 7;
        cfg.throttles.maxPeerEndpoints = 13;
        bytes memory encoded = ClprProtobuf.encodeControlMessage(cfg);

        (,,,, ClprTypes.Throttles memory throttles,,,) = hieroVerifier.verifyConfig(encoded, bytes32(0), "");
        assertEq(throttles.maxLocalEndpoints, 7, "maxLocalEndpoints must survive the config proof");
        assertEq(throttles.maxPeerEndpoints, 13, "maxPeerEndpoints must survive the config proof");
    }

    function test_verifyConfig_nonEmpty_decodesBasicFields() public view {
        ClprTypes.LedgerConfiguration memory cfg = _minimalCfg();
        bytes memory encoded = ClprProtobuf.encodeControlMessage(cfg);

        (
            bytes memory channelContext,
            string memory chainId,
            bytes memory serviceAddress,
            uint96 peerConfigNanos,
            ClprTypes.Throttles memory throttles,
            bytes memory initialTrustAnchor,
            bytes memory initialTrustAnchorId,
            ClprTypes.ClprEndpointManifest memory endpointManifest
        ) = hieroVerifier.verifyConfig(encoded, bytes32(0), "");

        assertEq(chainId, "testnet-42");
        assertEq(keccak256(serviceAddress), keccak256(hex"deadbeef"));
        assertEq(peerConfigNanos, 1_000_000_000);
        assertEq(throttles.maxMessagesPerBundle, 50);
        assertEq(keccak256(initialTrustAnchor), keccak256(LEDGER_ID), "initialTrustAnchor must be ledgerId");
        assertEq(initialTrustAnchorId.length, 0);
        assertEq(endpointManifest.endpoints.length, 0);

        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        assertEq(ctx.channelId, bytes32(0));
        assertEq(keccak256(ctx.remoteServiceAddress), keccak256(hex"deadbeef"));
    }

    function test_verifyConfig_nonEmpty_withNanos() public view {
        ClprTypes.LedgerConfiguration memory cfg = _minimalCfg();
        cfg.nanosSinceEpoch = 1_000_000_000_500_000_000; // 1e9 seconds + 500ms
        bytes memory encoded = ClprProtobuf.encodeControlMessage(cfg);

        (,,, uint96 nanos,,,,) = hieroVerifier.verifyConfig(encoded, bytes32(0), "");
        assertEq(nanos, 1_000_000_000_500_000_000);
    }

    // ── verifyConfig — endpoint passthrough (discovery records) ───────────────

    /// @dev Endpoints carry no signing key; the verifier passes the decoded discovery
    ///      records (ip / port / tls / account_id) through unchanged.
    function test_verifyConfig_endpoints_passedThrough() public {
        // The manifest proof's TSS signature is checked against the pinned ledgerId; mock the
        // TSS verifier so this test exercises the leaf-extraction + bind layers.
        vm.mockCall(
            address(tssVerifier), abi.encodeWithSelector(TSSVerifier.verifyTss.selector), abi.encode(true, bytes(""))
        );
        ClprTypes.Endpoint[] memory eps = new ClprTypes.Endpoint[](2);
        eps[0] = ClprTypes.Endpoint({ipAddress: "127.0.0.1", port: 8080, tlsCertificate: hex"aa", accountId: hex"01"});
        eps[1] = ClprTypes.Endpoint({ipAddress: "10.0.0.1", port: 9090, tlsCertificate: hex"bb", accountId: hex"02"});

        ClprTypes.LedgerConfiguration memory cfg = _minimalCfg();
        bytes memory encoded = ClprProtobuf.encodeControlMessage(cfg);

        (,,,,,,, ClprTypes.ClprEndpointManifest memory manifest) =
            hieroVerifier.verifyConfig(encoded, bytes32(0), _manifestProof(eps, cfg.serviceAddress));
        ClprTypes.Endpoint[] memory decodedEps = manifest.endpoints;

        assertEq(decodedEps.length, 2);
        assertEq(decodedEps[0].ipAddress, "127.0.0.1");
        assertEq(decodedEps[0].port, 8080);
        assertEq(keccak256(decodedEps[0].accountId), keccak256(hex"01"));
        assertEq(decodedEps[1].port, 9090);
        assertEq(keccak256(decodedEps[1].accountId), keccak256(hex"02"));
    }

    // ── verifyBundle early-revert paths ──────────────────────────────────────

    /// @dev A proof with an empty signature → ClprHieroBlockProofMissing.
    function test_verifyBundle_emptyProof_revertsBlockProofMissing() public {
        vm.expectRevert(HieroVerifier.ClprHieroBlockProofMissing.selector);
        hieroVerifier.verifyBundle(new bytes(0), LEDGER_ID, "");
    }

    function test_verifyBundle_ambiguousContentPath_reverts() public {
        bytes memory dummySig = hex"0102030405";
        bytes memory tssProof = PB.encodeBytesField(ClprStateProof.SBP_BLOCK_SIGNATURE, dummySig);
        // Path has both MP_HASH and MP_STATE_ITEM_LEAF set — the leaf-forgery shape:
        // an explicit hash supplied *alongside* the leaf so authentication would use one
        // field and extraction the other. _baseHashOf now rejects this ambiguity: a
        // leaf-bearing path is authenticated by hashing the leaf that extraction consumes,
        // never by a separately-supplied hash. See HieroLeafForgeryPoC for the exploit.
        bytes memory path = abi.encodePacked(
            PB.encodeVarintField(ClprStateProof.MP_NEXT_PATH_INDEX, uint64(type(uint32).max)), // TERMINATOR
            PB.encodeBytesField(ClprStateProof.MP_HASH, hex"aabbccdd"), // explicitHash alongside a leaf
            PB.encodeBytesField(ClprStateProof.MP_STATE_ITEM_LEAF, hex"abcd")
        );
        bytes memory stateProof = abi.encodePacked(
            PB.encodeBytesField(ClprStateProof.SP_PATHS, path),
            PB.encodeBytesField(ClprStateProof.SP_SIGNED_BLOCK_PROOF, tssProof)
        );

        vm.expectRevert(ClprStateProof.StateProofPathAmbiguousContent.selector);
        hieroVerifier.verifyBundle(stateProof, LEDGER_ID, "");
    }

    function test_verifyBundle_tssReturnsFalse_reverts() public {
        bytes memory dummySig = hex"0102030405";
        bytes memory tssProof = PB.encodeBytesField(ClprStateProof.SBP_BLOCK_SIGNATURE, dummySig);
        // Single path: only stateItemLeaf, no explicitHash → computeChainedRoot returns SHA-384 (48 bytes).
        // TERMINATOR is required; omitting it leaves nextPathIndex=0, causing _walkChain to loop.
        bytes memory path = abi.encodePacked(
            PB.encodeVarintField(ClprStateProof.MP_NEXT_PATH_INDEX, uint64(type(uint32).max)), // TERMINATOR
            PB.encodeBytesField(ClprStateProof.MP_STATE_ITEM_LEAF, hex"abcd")
        );
        bytes memory stateProof = abi.encodePacked(
            PB.encodeBytesField(ClprStateProof.SP_PATHS, path),
            PB.encodeBytesField(ClprStateProof.SP_SIGNED_BLOCK_PROOF, tssProof)
        );

        // Force verifyTss to return false (real impl never does) so the HieroVerifier
        // guard fires ClprHieroTssVerificationFailed rather than propagating a TSSVerifier revert.
        vm.mockCall(
            address(tssVerifier), abi.encodeWithSelector(TSSVerifier.verifyTss.selector), abi.encode(false, hex"")
        );

        vm.expectRevert(HieroVerifier.ClprHieroTssVerificationFailed.selector);
        hieroVerifier.verifyBundle(stateProof, LEDGER_ID, "");
    }

    /// @dev A proof with a non-empty signature but no state_item_leaf paths
    ///      → ClprHieroNoStateItemLeaf. The TSS check is never reached.
    function test_verifyBundle_noStateItemLeaf_revertsNoStateItemLeaf() public {
        // Build a minimal StateProof: one hash path (no stateItemLeaf) + a dummy signature.
        bytes memory dummySig = hex"0102030405"; // non-empty, length != 2920 or 3432 is fine here
        bytes memory tssProof = PB.encodeBytesField(ClprStateProof.SBP_BLOCK_SIGNATURE, dummySig);
        bytes memory hashPath = PB.encodeBytesField(ClprStateProof.MP_HASH, hex"aabbccdd");
        bytes memory stateProof = abi.encodePacked(
            PB.encodeBytesField(ClprStateProof.SP_PATHS, hashPath),
            PB.encodeBytesField(ClprStateProof.SP_SIGNED_BLOCK_PROOF, tssProof)
        );

        vm.expectRevert(HieroVerifier.ClprHieroNoStateItemLeaf.selector);
        hieroVerifier.verifyBundle(stateProof, LEDGER_ID, "");
    }
}

// NOTE: HieroVerifierHarness + HieroVerifier_NormalizeKeyTest removed — endpoint signing keys were
// dropped from ClprEndpoint (spec alignment), so there is no _normalizeEndpointKey to unit-test.
