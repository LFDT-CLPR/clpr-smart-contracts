// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {HieroVerifier} from "../../../src/verifiers/hiero/HieroVerifier.sol";
import {TSSVerifier} from "../../../src/verifiers/hiero/TSSVerifier.sol";
import {ClprTypes} from "../../../src/libraries/ClprTypes.sol";
import {ClprProtobuf} from "../../../src/libraries/codec/ClprProtobuf.sol";
import {ClprProtobufHelpers as PB} from "../../../src/libraries/codec/ClprProtobufHelpers.sol";
import {Sha384} from "../../../src/libraries/crypto/Sha384.sol";
import {ClprStateProof} from "../../../src/libraries/proof/hiero/ClprStateProof.sol";

/// @notice HieroVerifier endpoint-manifest leaf support: a `ClprEndpointManifest` state-item leaf
///         (StateValue field 64, tag 514) in the StateProof is authenticated against the signed
///         block root, decoded, bound to ctx.remoteServiceAddress, and returned as
///         `newEndpointManifest`; the proven `ClprChannel` leaf's field 20 populates
///         `QueueMetadata.endpointManifestVersion`.
/// @dev    The TSS check is mocked (always-valid) — these tests exercise the Merkle-path and
///         decode/bind layers with synthetic two-leaf StateProofs; the real TSS pipeline is
///         covered by the captured-fixture tests in HieroVerifier.t.sol.
contract HieroManifestLeafTest is Test {
    bytes internal constant LEDGER_ID = hex"0102030405060708";
    bytes internal constant PEER_SERVICE_ADDRESS = hex"00000000000000000000000000000000000000000000AA";

    HieroVerifier internal verifier;
    address internal tss;

    uint32 internal constant PATH_TERMINATOR = type(uint32).max;

    function setUp() public {
        tss = makeAddr("mock-tss");
        vm.etch(tss, hex"01"); // give the mock target code so calls do not revert pre-mock
        vm.mockCall(tss, abi.encodeWithSelector(TSSVerifier.verifyTss.selector), abi.encode(true, bytes("")));
        verifier = new HieroVerifier(LEDGER_ID, TSSVerifier(tss));
    }

    // ── Protobuf builders (mirror block/stream/state_proof.proto shapes) ────────

    /// @dev ClprChannel wire: status=7, next=8, received=11 (varints); running hashes 10/12
    ///      (32-byte LEN); endpoint_manifest_version=20 (varint).
    function _channelWire(uint64 manifestVersion) internal pure returns (bytes memory) {
        return abi.encodePacked(
            PB.encodeBytesField(1, abi.encodePacked(bytes32(uint256(1)))), // channel_id
            PB.encodeVarintField(7, uint64(uint8(ClprTypes.ChannelStatus.ACTIVE))),
            PB.encodeVarintField(8, uint64(2)), // nextMessageId
            PB.encodeBytesField(10, abi.encodePacked(bytes32(uint256(1)))), // sentRunningHash
            PB.encodeVarintField(11, uint64(1)), // receivedMessageId
            PB.encodeBytesField(12, abi.encodePacked(bytes32(uint256(2)))), // receivedRunningHash
            PB.encodeVarintField(20, manifestVersion)
        );
    }

    function _manifest(uint64 version, bytes memory serviceAddress)
        internal
        pure
        returns (ClprTypes.ClprEndpointManifest memory m)
    {
        m.version = version;
        m.serviceAddress = serviceAddress;
        m.endpoints = new ClprTypes.Endpoint[](1);
        m.endpoints[0] =
            ClprTypes.Endpoint({ipAddress: "10.1.1.1", port: 50211, tlsCertificate: hex"AA", accountId: hex"07"});
    }

    /// @dev Wrap `inner` as a StateItem leaf: StateItem.value(3) = StateValue{ svField (LEN) = inner }.
    function _stateItemLeaf(uint64 svField, bytes memory inner) internal pure returns (bytes memory) {
        bytes memory stateValue = PB.encodeBytesField(svField, inner);
        return PB.encodeBytesField(3, stateValue);
    }

    function _sibling(bool isLeft, bytes memory hash_) internal pure returns (bytes memory) {
        return abi.encodePacked(PB.encodeVarintField(1, isLeft ? 1 : 0), PB.encodeBytesField(2, hash_));
    }

    /// @dev MerklePath: siblings(1, repeated), next_path_index(2), state_item_leaf(4).
    function _merklePath(bytes memory leaf, bytes memory siblingNode) internal pure returns (bytes memory) {
        return abi.encodePacked(
            PB.encodeBytesField(1, siblingNode),
            PB.encodeVarintField(2, uint64(PATH_TERMINATOR)),
            PB.encodeBytesField(4, leaf)
        );
    }

    /// @dev Two-leaf StateProof: root = sha384(0x02 || h(channel) || h(manifest)); both paths converge.
    function _stateProof(bytes memory connLeaf, bytes memory manifestLeaf) internal pure returns (bytes memory) {
        bytes memory h0 = Sha384.hash(abi.encodePacked(bytes1(0x00), connLeaf));
        bytes memory h1 = Sha384.hash(abi.encodePacked(bytes1(0x00), manifestLeaf));

        bytes memory path0 = _merklePath(connLeaf, _sibling(false, h1));
        bytes memory path1 = _merklePath(manifestLeaf, _sibling(true, h0));

        bytes memory signedBlockProof = PB.encodeBytesField(1, hex"DEADBEEF"); // TssSignedBlockProof.block_signature
        return abi.encodePacked(
            PB.encodeBytesField(1, path0), PB.encodeBytesField(1, path1), PB.encodeBytesField(2, signedBlockProof)
        );
    }

    function _ctx() internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: bytes32(uint256(1)), remoteServiceAddress: PEER_SERVICE_ADDRESS})
        );
    }

    // ── Tests ───────────────────────────────────────────────────────────────────

    function test_verifyBundle_manifestLeaf_returnedAndBound() public view {
        ClprTypes.ClprEndpointManifest memory m = _manifest(3, PEER_SERVICE_ADDRESS);
        bytes memory proof = _stateProof(
            _stateItemLeaf(60, _channelWire(5)), _stateItemLeaf(64, ClprProtobuf.encodeEndpointManifest(m))
        );

        (ClprTypes.QueueMetadata memory metadata,,,, ClprTypes.ClprEndpointManifest memory newManifest) =
            verifier.verifyBundle(proof, "", _ctx());

        assertEq(newManifest.version, 3, "manifest version");
        assertEq(newManifest.endpoints.length, 1, "manifest endpoints");
        assertEq(keccak256(newManifest.serviceAddress), keccak256(PEER_SERVICE_ADDRESS), "manifest service address");

        // ClprChannel proto field 20 → QueueMetadata.endpointManifestVersion (proto field 7).
        assertEq(metadata.endpointManifestVersion, 5, "proven channel manifest version");
    }

    function test_verifyBundle_noManifestLeaf_returnsAbsent() public view {
        // Second leaf is a message leaf (tag 498), not a manifest.
        bytes memory msgWire = PB.encodeBytesField(1, hex"010203"); // ClprMessageValue.payload
        // StateItem.key(2) = StateKey{62: ClprMessageKey{message_id(2) = 1}}; the verifier reads the id from it.
        bytes memory msgKey = PB.encodeBytesField(2, PB.encodeBytesField(62, PB.encodeVarintField(2, 1)));
        bytes memory proof =
            _stateProof(_stateItemLeaf(60, _channelWire(0)), bytes.concat(msgKey, _stateItemLeaf(62, msgWire)));

        (ClprTypes.QueueMetadata memory metadata,,,, ClprTypes.ClprEndpointManifest memory newManifest) =
            verifier.verifyBundle(proof, "", _ctx());

        assertEq(newManifest.version, 0, "absent manifest is version 0");
        assertEq(metadata.endpointManifestVersion, 0, "field 20 absent decodes to 0");
    }

    function test_verifyBundle_lastMessageId_readFromMessageKey() public view {
        bytes memory msgWire = abi.encodePacked(
            PB.encodeBytesField(1, hex"010203"), PB.encodeBytesField(2, abi.encodePacked(bytes32(uint256(0xAB))))
        );
        bytes memory msgKey = PB.encodeBytesField(2, PB.encodeBytesField(62, PB.encodeVarintField(2, 7)));
        bytes memory proof =
            _stateProof(_stateItemLeaf(60, _channelWire(0)), bytes.concat(msgKey, _stateItemLeaf(62, msgWire)));

        (ClprTypes.QueueMetadata memory metadata,,,,) = verifier.verifyBundle(proof, "", _ctx());

        assertEq(metadata.lastMessageId, 7, "id from ClprMessageKey.message_id");
        assertEq(metadata.lastMessageRunningHash, bytes32(uint256(0xAB)), "last leaf's runningHashAfterProcessing");
    }

    function test_verifyBundle_messageLeafWithoutKey_reverts() public {
        bytes memory proof =
            _stateProof(_stateItemLeaf(60, _channelWire(0)), _stateItemLeaf(62, PB.encodeBytesField(1, hex"010203")));

        vm.expectRevert(ClprStateProof.StateProofMissingMessageKey.selector);
        verifier.verifyBundle(proof, "", _ctx());
    }

    function test_verifyBundle_manifestServiceAddressMismatch_reverts() public {
        ClprTypes.ClprEndpointManifest memory m = _manifest(3, hex"BEEF"); // wrong service address
        bytes memory proof = _stateProof(
            _stateItemLeaf(60, _channelWire(0)), _stateItemLeaf(64, ClprProtobuf.encodeEndpointManifest(m))
        );

        vm.expectRevert(abi.encodeWithSelector(ClprTypes.VerifyFailed.selector, "manifest service_address mismatch"));
        verifier.verifyBundle(proof, "", _ctx());
    }

    function test_verifyBundle_manifestVersionZero_reverts() public {
        ClprTypes.ClprEndpointManifest memory m = _manifest(0, PEER_SERVICE_ADDRESS);
        bytes memory proof = _stateProof(
            _stateItemLeaf(60, _channelWire(0)), _stateItemLeaf(64, ClprProtobuf.encodeEndpointManifest(m))
        );

        vm.expectRevert(abi.encodeWithSelector(ClprTypes.VerifyFailed.selector, "manifest version 0"));
        verifier.verifyBundle(proof, "", _ctx());
    }

    function test_verifyBundle_manifestLeaf_badPath_reverts() public {
        ClprTypes.ClprEndpointManifest memory m = _manifest(3, PEER_SERVICE_ADDRESS);
        bytes memory connLeaf = _stateItemLeaf(60, _channelWire(0));
        bytes memory manifestLeaf = _stateItemLeaf(64, ClprProtobuf.encodeEndpointManifest(m));

        bytes memory h1 = Sha384.hash(abi.encodePacked(bytes1(0x00), manifestLeaf));
        bytes memory path0 = _merklePath(connLeaf, _sibling(false, h1));
        // Manifest path carries a WRONG sibling — its chain cannot converge on the block root.
        bytes memory badSibling = _sibling(true, Sha384.hash(hex"BAD0"));
        bytes memory path1 = _merklePath(manifestLeaf, badSibling);

        bytes memory signedBlockProof = PB.encodeBytesField(1, hex"DEADBEEF");
        bytes memory proof = abi.encodePacked(
            PB.encodeBytesField(1, path0), PB.encodeBytesField(1, path1), PB.encodeBytesField(2, signedBlockProof)
        );

        vm.expectRevert(ClprStateProofPathInvalid());
        verifier.verifyBundle(proof, "", _ctx());
    }

    /// @dev A minimal config proof (decoded LedgerConfiguration) whose serviceAddress the
    ///      manifest must bind against.
    function _configProof() internal pure returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory cfg;
        cfg.chainId = "hiero:localnet";
        cfg.serviceAddress = PEER_SERVICE_ADDRESS;
        return ClprProtobuf.encodeControlMessage(cfg);
    }

    /// @dev Manifest-only StateProof
    function _manifestOnlyStateProof(ClprTypes.ClprEndpointManifest memory m) internal pure returns (bytes memory) {
        bytes memory leaf = _stateItemLeaf(64, ClprProtobuf.encodeEndpointManifest(m));
        bytes memory path = _merklePath(leaf, _sibling(false, ""));
        bytes memory signedBlockProof = PB.encodeBytesField(1, hex"DEADBEEF");
        return abi.encodePacked(PB.encodeBytesField(1, path), PB.encodeBytesField(2, signedBlockProof));
    }

    /// @dev Happy path: the config-time manifest proof is TSS-verified against the pinned
    ///      ledgerId (the same trust anchor verifyConfig establishes), then bound and returned.
    function test_verifyConfig_manifestStateProof_verifiedAndReturned() public view {
        (,,,,,,, ClprTypes.ClprEndpointManifest memory manifest) = verifier.verifyConfig(
            _configProof(), bytes32(0), _manifestOnlyStateProof(_manifest(2, PEER_SERVICE_ADDRESS))
        );
        assertEq(manifest.version, 2, "manifest version");
        assertEq(manifest.endpoints.length, 1, "manifest endpoints");
    }

    /// @dev Cryptographic binding: when the TSS check against the pinned ledgerId fails, the
    ///      config-time manifest proof MUST revert.
    function test_verifyConfig_manifestStateProof_tssInvalid_reverts() public {
        vm.mockCall(tss, abi.encodeWithSelector(TSSVerifier.verifyTss.selector), abi.encode(false, bytes("")));

        bytes memory proof = _manifestOnlyStateProof(_manifest(2, PEER_SERVICE_ADDRESS));
        bytes memory configProof = _configProof();

        vm.expectRevert(HieroVerifier.ClprHieroTssVerificationFailed.selector);
        verifier.verifyConfig(configProof, bytes32(0), proof);
    }

    /// @dev A StateProof that authenticates fine but carries no manifest leaf MUST revert.
    function test_verifyConfig_manifestStateProof_missingLeaf_reverts() public {
        // Channel leaf only (tag 482), no manifest leaf.
        bytes memory leaf = _stateItemLeaf(60, _channelWire(0));
        bytes memory path = _merklePath(leaf, _sibling(false, ""));
        bytes memory proof = abi.encodePacked(
            PB.encodeBytesField(1, path), PB.encodeBytesField(2, PB.encodeBytesField(1, hex"DEADBEEF"))
        );
        bytes memory configProof = _configProof();

        vm.expectRevert(abi.encodeWithSelector(ClprTypes.VerifyFailed.selector, "manifest leaf missing"));
        verifier.verifyConfig(configProof, bytes32(0), proof);
    }

    /// @dev Selector helper: ClprStateProof.StateProofPathInvalid is a library error.
    function ClprStateProofPathInvalid() internal pure returns (bytes4) {
        return bytes4(keccak256("StateProofPathInvalid()"));
    }
}
