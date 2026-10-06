// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {TempoSyntheticProofs} from "@test/helpers/TempoSyntheticProofs.sol";
import {TempoVerifier} from "@hiero-ledger/clpr/verifiers/evm/tempo/TempoVerifier.sol";
import {ClprTempoBls} from "@hiero-ledger/clpr/libraries/proof/tempo/ClprTempoBls.sol";
import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @dev Exposes the certificate check for real mainnet certificates.
contract TempoVerifierHarness is TempoVerifier {
    function certify(
        bytes memory header,
        bytes memory proposal,
        bytes memory sigCompressed,
        bytes memory sigUncompressed,
        bytes memory key,
        uint64 epochLength
    ) external view returns (uint64 number, uint64 epoch, bytes32 stateRoot) {
        bytes[] memory items = new bytes[](4);
        items[0] = header;
        items[1] = RLP.encode(proposal);
        items[2] = RLP.encode(sigCompressed);
        items[3] = RLP.encode(sigUncompressed);
        Memory.Slice[] memory s = RLP.decodeList(RLP.encode(items));
        CertifiedHeader memory h = _verifyCertifiedHeader(
            s[0], Certificate({proposal: s[1], sigCompressed: s[2], sigUncompressed: s[3]}), key, epochLength
        );
        return (h.number, h.epoch, h.stateRoot);
    }
}

/// @title TempoVerifierTest
/// @notice Real mainnet certificates, plus full verifyBundle and verifyConfig paths with a test key.
contract TempoVerifierTest is TempoSyntheticProofs {
    uint64 internal constant MAINNET_EPOCH_LENGTH = 21600;
    uint64 internal constant L = 100;
    address internal constant SERVICE = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;
    bytes32 internal constant CODE_HASH = bytes32(uint256(0xC0DE));
    bytes32 internal constant CHANNEL_ID = bytes32(uint256(0xC0FFEE));

    TempoVerifierHarness internal v;
    uint256 internal sk1;
    uint256 internal sk2;
    uint256 internal sk3;
    bytes internal pk1;
    bytes internal pk2;
    bytes internal pk3;

    struct Built {
        bytes header;
        CertificateBytes cert;
        bytes32 stateRoot;
        bytes accountProof;
        bytes storageProof;
    }

    function setUp() public {
        v = new TempoVerifierHarness();
        sk1 = _testKey("tempo-key-1");
        sk2 = _testKey("tempo-key-2");
        sk3 = _testKey("tempo-key-3");
        pk1 = _blsPublicKey(sk1);
        pk2 = _blsPublicKey(sk2);
        pk3 = _blsPublicKey(sk3);
    }

    function test_certify_mainnetTip() public view {
        TempoFixture memory f = _loadTempoFixture("presto-tip");
        (uint64 number, uint64 epoch, bytes32 stateRoot) = v.certify(
            f.headerRlp, f.proposal, f.sigCompressed, f.sigUncompressed, f.keyUncompressed, MAINNET_EPOCH_LENGTH
        );
        assertEq(number, f.blockNumber);
        assertEq(epoch, f.epoch);
        assertEq(stateRoot, bytes32(_innerField(f.headerRlp, 3)));
    }

    function test_certify_mainnetBoundary() public view {
        TempoFixture memory f = _loadTempoFixture("presto-boundary");
        (uint64 number, uint64 epoch,) = v.certify(
            f.headerRlp, f.proposal, f.sigCompressed, f.sigUncompressed, f.keyUncompressed, MAINNET_EPOCH_LENGTH
        );
        assertEq(number, f.blockNumber);
        assertEq((number + 1) % MAINNET_EPOCH_LENGTH, 0, "boundary is the last block of its epoch");
        assertEq(epoch, f.epoch);
    }

    function test_certify_rejectsTamperedHeader() public {
        TempoFixture memory f = _loadTempoFixture("presto-tip");
        bytes memory header = f.headerRlp;
        header[header.length - 1] ^= 0x01;
        vm.expectRevert(TempoVerifier.BlockDigestMismatch.selector);
        v.certify(header, f.proposal, f.sigCompressed, f.sigUncompressed, f.keyUncompressed, MAINNET_EPOCH_LENGTH);
    }

    function test_certify_rejectsWrongEpochLength() public {
        TempoFixture memory f = _loadTempoFixture("presto-tip");
        uint64 wrongL = MAINNET_EPOCH_LENGTH / 2; // 39.5M / 10800 lands in a different epoch
        vm.expectRevert(
            abi.encodeWithSelector(TempoVerifier.EpochMismatch.selector, f.blockNumber, f.blockNumber / wrongL, f.epoch)
        );
        v.certify(f.headerRlp, f.proposal, f.sigCompressed, f.sigUncompressed, f.keyUncompressed, wrongL);
    }

    function test_certify_rejectsForeignKey() public {
        TempoFixture memory f = _loadTempoFixture("presto-tip");
        vm.expectRevert(ClprTempoBls.BlsSignatureInvalid.selector);
        v.certify(f.headerRlp, f.proposal, f.sigCompressed, f.sigUncompressed, pk1, MAINNET_EPOCH_LENGTH);
    }

    function test_certify_rejectsSignatureEncodingMismatch() public {
        TempoFixture memory f = _loadTempoFixture("presto-tip");
        bytes memory sigC = f.sigCompressed;
        sigC[47] ^= 0x01;
        vm.expectRevert(TempoVerifier.SignatureEncodingMismatch.selector);
        v.certify(f.headerRlp, f.proposal, sigC, f.sigUncompressed, f.keyUncompressed, MAINNET_EPOCH_LENGTH);
    }

    function test_certify_rejectsSignatureLengths() public {
        TempoFixture memory f = _loadTempoFixture("presto-tip");
        vm.expectRevert(TempoVerifier.InvalidSignatureEncoding.selector);
        v.certify(f.headerRlp, f.proposal, new bytes(47), f.sigUncompressed, f.keyUncompressed, MAINNET_EPOCH_LENGTH);
        vm.expectRevert(TempoVerifier.InvalidSignatureEncoding.selector);
        v.certify(f.headerRlp, f.proposal, f.sigCompressed, new bytes(96), f.keyUncompressed, MAINNET_EPOCH_LENGTH);
    }

    /// @dev A header with more inner fields than today's (a later fork) still verifies.
    function test_certify_acceptsInnerHeaderWithExtraFields() public view {
        uint64 number = 4 * L + 1;
        bytes32 stateRoot = bytes32(uint256(0x5a7e));
        bytes[] memory base = _innerHeader(number, stateRoot, "");
        bytes[] memory inner = new bytes[](30);
        for (uint256 i = 0; i < inner.length; i++) {
            inner[i] = i < base.length ? base[i] : RLP.encode(bytes32(i));
        }
        bytes memory header = _tempoHeaderWithInner(inner, true);
        CertificateBytes memory c = _certify(sk1, L, header, number, 10);
        (uint64 gotNumber, uint64 epoch, bytes32 gotStateRoot) =
            v.certify(header, c.proposal, c.sigCompressed, c.sigUncompressed, pk1, L);
        assertEq(gotNumber, number);
        assertEq(epoch, 4);
        assertEq(gotStateRoot, stateRoot);
    }

    /// @dev The identity signature verifies any message under the identity key.
    function test_certify_rejectsIdentitySignature() public {
        bytes memory header = _tempoHeader(5, bytes32(0), "", true);
        CertificateBytes memory c = _certify(sk1, L, header, 5, 9);
        bytes memory identity = new bytes(128);
        bytes memory identityCompressed = ClprBls12381.compressG1(identity);
        vm.expectRevert(TempoVerifier.InfinityPoint.selector);
        v.certify(header, c.proposal, identityCompressed, identity, pk1, L);
    }

    function test_certify_rejectsMalformedTempoHeader() public {
        TempoFixture memory f = _loadTempoFixture("presto-tip");
        bytes[] memory three = new bytes[](3);
        three[0] = RLP.encode(uint256(1));
        three[1] = RLP.encode(uint256(1));
        three[2] = RLP.encode(uint256(1));
        vm.expectRevert(TempoVerifier.InvalidHeader.selector);
        v.certify(RLP.encode(three), f.proposal, f.sigCompressed, f.sigUncompressed, f.keyUncompressed, L);

        bytes[] memory six = new bytes[](6);
        for (uint256 i = 0; i < 6; i++) {
            six[i] = RLP.encode(uint256(1));
        }
        six[3] = RLP.encode(_innerHeader(5, bytes32(0), ""));
        vm.expectRevert(TempoVerifier.InvalidHeader.selector);
        v.certify(RLP.encode(six), f.proposal, f.sigCompressed, f.sigUncompressed, f.keyUncompressed, L);

        bytes[] memory inner = new bytes[](14);
        for (uint256 i = 0; i < 14; i++) {
            inner[i] = RLP.encode(uint256(0));
        }
        vm.expectRevert(TempoVerifier.InvalidHeader.selector);
        v.certify(
            _tempoHeaderWithInner(inner, false), f.proposal, f.sigCompressed, f.sigUncompressed, f.keyUncompressed, L
        );
    }

    function test_verifyBundle_steadyState() public view {
        Built memory b = _built(sk1, 250, "");
        (
            ClprTypes.QueueMetadata memory metadata,
            bytes[] memory payloads,
            bytes memory newAnchor,
            bytes memory newAnchorId,
        ) = v.verifyBundle(_bundle(b, new bytes[](0), ""), _anchor(249, pk1), _ctx(CHANNEL_ID));
        assertEq(metadata.nextMessageId, 1);
        assertEq(payloads.length, 0);
        assertEq(newAnchor.length, 0, "no rotation");
        assertEq(newAnchorId.length, 0);
    }

    function test_verifyBundle_headerWithoutConsensusContext() public view {
        Built memory b = _builtWithContext(sk1, 250, "", false);
        (ClprTypes.QueueMetadata memory metadata,,,,) =
            v.verifyBundle(_bundle(b, new bytes[](0), ""), _anchor(249, pk1), _ctx(CHANNEL_ID));
        assertEq(metadata.nextMessageId, 1);
    }

    /// @dev The proven channel holds messages 1 and 2, so a two-message bundle ends at message 2.
    function test_verifyBundle_returnsPayloads() public view {
        bytes[] memory msgs = new bytes[](2);
        msgs[0] = hex"01";
        msgs[1] = hex"0203";
        bytes32 sentHash =
            sha256(abi.encodePacked(sha256(abi.encodePacked(bytes32(0), sha256(msgs[0]))), sha256(msgs[1])));
        (bytes32 storageRoot, bytes memory storageProof) =
            _buildChannelStorageEntriesWithSentHash(keccak256(abi.encode(CHANNEL_ID, uint256(15))), 3, sentHash);
        Built memory b = _builtOver(sk1, 250, "", true, storageRoot, storageProof);
        ClprTypes.QueueMetadata memory dummy;
        (ClprTypes.QueueMetadata memory meta, bytes[] memory payloads,,,) = v.verifyBundle(
            _bundle(b, new bytes[](0), ClprProtobuf.encodeBundleContent(dummy, msgs)),
            _anchor(249, pk1),
            _ctx(CHANNEL_ID)
        );
        assertEq(payloads.length, 2);
        assertEq(payloads[1], hex"0203");
        assertEq(meta.lastMessageId, 2);
        assertEq(meta.lastMessageRunningHash, sentHash);
    }

    function test_verifyBundle_withManifestUpdate() public view {
        Built memory b = _built(sk1, 250, "");
        ClprTypes.ClprEndpointManifest memory m = _manifest(7);
        bytes memory preimage = ClprProtobuf.encodeEndpointManifest(m);
        bytes memory bundle = _bundleWithManifest(b, preimage);
        (,,,, ClprTypes.ClprEndpointManifest memory got) = v.verifyBundle(bundle, _anchor(249, pk1), _ctx(CHANNEL_ID));
        assertEq(got.version, 7);
    }

    function test_verifyBundle_rejectsCurrentAtOrBehindAnchor() public {
        Built memory b = _built(sk1, 250, "");
        vm.expectRevert(abi.encodeWithSelector(TempoVerifier.CurrentHeaderBehindWalk.selector, 250, 250));
        v.verifyBundle(_bundle(b, new bytes[](0), ""), _anchor(250, pk1), _ctx(CHANNEL_ID));
    }

    function test_verifyBundle_rejectsForeignKeyInAnchor() public {
        Built memory b = _built(sk1, 250, "");
        vm.expectRevert(ClprTempoBls.BlsSignatureInvalid.selector);
        v.verifyBundle(_bundle(b, new bytes[](0), ""), _anchor(249, pk2), _ctx(CHANNEL_ID));
    }

    function test_verifyBundle_rejectsWrongCodeHash() public {
        Built memory b = _built(sk1, 250, "");
        bytes memory anchor = _tempoAnchor(bytes32(uint256(0xBAD)), L, 249, pk1);
        vm.expectRevert(ClprEvmBundleVerifier.CodeHashMismatch.selector);
        v.verifyBundle(_bundle(b, new bytes[](0), ""), anchor, _ctx(CHANNEL_ID));
    }

    // ── Rotations at epoch-boundary blocks ───────────────────────────────────────

    function test_verifyBundle_crossesOneRotation() public view {
        // Anchor in epoch 3 under key 1. The boundary of epoch 3 names key 2.
        bytes memory rotation = _boundaryRotation(sk1, 3, pk2);
        Built memory b = _built(sk2, 4 * L + 1, "");
        bytes[] memory rotations = new bytes[](1);
        rotations[0] = rotation;
        (,, bytes memory newAnchor, bytes memory newAnchorId,) =
            v.verifyBundle(_bundle(b, rotations, ""), _anchor(3 * L, pk1), _ctx(CHANNEL_ID));

        (bytes32 codeHash, uint64 epochLength, uint64 anchorBlock, bytes memory identity) =
            abi.decode(newAnchor, (bytes32, uint64, uint64, bytes));
        assertEq(codeHash, CODE_HASH);
        assertEq(epochLength, L);
        assertEq(anchorBlock, 4 * L + 1);
        assertEq(identity, pk2, "anchor must now hold key 2");
        assertEq(newAnchorId, abi.encodePacked(uint64(4 * L + 1)));
    }

    function test_verifyBundle_crossesTwoRotations() public view {
        bytes[] memory rotations = new bytes[](2);
        rotations[0] = _boundaryRotation(sk1, 3, pk2);
        rotations[1] = _boundaryRotation(sk2, 4, pk3);
        Built memory b = _built(sk3, 5 * L + 7, "");
        (,, bytes memory newAnchor,,) = v.verifyBundle(_bundle(b, rotations, ""), _anchor(3 * L, pk1), _ctx(CHANNEL_ID));
        (,,, bytes memory identity) = abi.decode(newAnchor, (bytes32, uint64, uint64, bytes));
        assertEq(identity, pk3);
    }

    function test_verifyBundle_reshareNeedsNoRotation() public view {
        // A reshare keeps the key, so no rotation is needed.
        Built memory b = _built(sk1, 4 * L + 1, "");
        (,, bytes memory newAnchor,,) =
            v.verifyBundle(_bundle(b, new bytes[](0), ""), _anchor(3 * L, pk1), _ctx(CHANNEL_ID));
        assertEq(newAnchor.length, 0);
    }

    function test_verifyBundle_missingRotationFailsSignature() public {
        Built memory b = _built(sk2, 4 * L + 1, "");
        vm.expectRevert(ClprTempoBls.BlsSignatureInvalid.selector);
        v.verifyBundle(_bundle(b, new bytes[](0), ""), _anchor(3 * L, pk1), _ctx(CHANNEL_ID));
    }

    function test_verifyBundle_rotationMustBeEpochBoundary() public {
        uint64 number = 4 * L - 2; // one before the boundary
        bytes memory header = _tempoHeader(number, bytes32(0), _dkgOutcome(4, ClprBls12381.compressG2(pk2)), true);
        bytes[] memory rotations = new bytes[](1);
        rotations[0] = _encodeRotation(header, _certify(sk1, L, header, number, 10), pk2);
        Built memory b = _built(sk2, 4 * L + 1, "");
        vm.expectRevert(abi.encodeWithSelector(TempoVerifier.RotationNotEpochBoundary.selector, number));
        v.verifyBundle(_bundle(b, rotations, ""), _anchor(3 * L, pk1), _ctx(CHANNEL_ID));
    }

    function test_verifyBundle_rotationOutcomeEpochMustBeNext() public {
        uint64 number = 4 * L - 1;
        bytes memory header = _tempoHeader(number, bytes32(0), _dkgOutcome(5, ClprBls12381.compressG2(pk2)), true);
        bytes[] memory rotations = new bytes[](1);
        rotations[0] = _encodeRotation(header, _certify(sk1, L, header, number, 10), pk2);
        Built memory b = _built(sk2, 4 * L + 1, "");
        vm.expectRevert(abi.encodeWithSelector(TempoVerifier.OutcomeEpochMismatch.selector, 4, 5));
        v.verifyBundle(_bundle(b, rotations, ""), _anchor(3 * L, pk1), _ctx(CHANNEL_ID));
    }

    function test_verifyBundle_rotationKeyMustMatchCommittedKey() public {
        uint64 number = 4 * L - 1;
        bytes memory header = _tempoHeader(number, bytes32(0), _dkgOutcome(4, ClprBls12381.compressG2(pk2)), true);
        bytes[] memory rotations = new bytes[](1);
        rotations[0] = _encodeRotation(header, _certify(sk1, L, header, number, 10), pk3); // relay claims key 3
        Built memory b = _built(sk3, 4 * L + 1, "");
        vm.expectRevert(TempoVerifier.KeyEncodingMismatch.selector);
        v.verifyBundle(_bundle(b, rotations, ""), _anchor(3 * L, pk1), _ctx(CHANNEL_ID));
    }

    function test_verifyBundle_rotationRejectsIdentityKey() public {
        bytes[] memory rotations = new bytes[](1);
        rotations[0] = _boundaryRotation(sk1, 3, new bytes(256));
        Built memory b = _built(sk2, 4 * L + 1, "");
        vm.expectRevert(TempoVerifier.InfinityPoint.selector);
        v.verifyBundle(_bundle(b, rotations, ""), _anchor(3 * L, pk1), _ctx(CHANNEL_ID));
    }

    function test_verifyBundle_rotationKeyLengthGuard() public {
        uint64 number = 4 * L - 1;
        bytes memory header = _tempoHeader(number, bytes32(0), _dkgOutcome(4, ClprBls12381.compressG2(pk2)), true);
        bytes[] memory rotations = new bytes[](1);
        rotations[0] = _encodeRotation(header, _certify(sk1, L, header, number, 10), new bytes(128));
        Built memory b = _built(sk2, 4 * L + 1, "");
        vm.expectRevert(TempoVerifier.InvalidKeyLength.selector);
        v.verifyBundle(_bundle(b, rotations, ""), _anchor(3 * L, pk1), _ctx(CHANNEL_ID));
    }

    function test_verifyBundle_firstRotationCanBeTheAnchorBlock() public view {
        bytes[] memory rotations = new bytes[](1);
        rotations[0] = _boundaryRotation(sk1, 3, pk2);
        Built memory b = _built(sk2, 4 * L + 1, "");
        (,, bytes memory newAnchor,,) =
            v.verifyBundle(_bundle(b, rotations, ""), _anchor(4 * L - 1, pk1), _ctx(CHANNEL_ID));
        (,,, bytes memory identity) = abi.decode(newAnchor, (bytes32, uint64, uint64, bytes));
        assertEq(identity, pk2);
    }

    /// @dev A reshare rotation keeps the key, so it verifies but leaves the anchor where it is. A bundle
    ///      proven below its header then still verifies against the unchanged anchor.
    function test_verifyBundle_reshareRotationKeepsAnchor() public view {
        bytes memory anchor = _anchor(2 * L, pk1);
        bytes[] memory reshare = new bytes[](1);
        reshare[0] = _boundaryRotation(sk1, 2, pk1);
        (,, bytes memory newAnchor, bytes memory newAnchorId,) =
            v.verifyBundle(_bundle(_built(sk1, 4 * L + 7, ""), reshare, ""), anchor, _ctx(CHANNEL_ID));
        assertEq(newAnchor.length, 0, "a reshare must not move the anchor");
        assertEq(newAnchorId.length, 0);

        v.verifyBundle(_bundle(_built(sk1, 3 * L + 1, ""), new bytes[](0), ""), anchor, _ctx(CHANNEL_ID));
    }

    /// @dev A reshare and then a full DKG in one bundle: the anchor moves to the new key.
    function test_verifyBundle_reshareThenFullDkgRotates() public view {
        bytes[] memory rotations = new bytes[](2);
        rotations[0] = _boundaryRotation(sk1, 2, pk1);
        rotations[1] = _boundaryRotation(sk1, 3, pk2);
        (,, bytes memory newAnchor,,) =
            v.verifyBundle(_bundle(_built(sk2, 4 * L + 1, ""), rotations, ""), _anchor(2 * L, pk1), _ctx(CHANNEL_ID));
        (,, uint64 anchorBlock, bytes memory identity) = abi.decode(newAnchor, (bytes32, uint64, uint64, bytes));
        assertEq(identity, pk2);
        assertEq(anchorBlock, 4 * L + 1);
    }

    function test_verifyBundle_rotationsMustNotPrecedeAnchor() public {
        bytes[] memory rotations = new bytes[](1);
        rotations[0] = _boundaryRotation(sk1, 3, pk2);
        Built memory b = _built(sk2, 4 * L + 1, "");
        vm.expectRevert(abi.encodeWithSelector(TempoVerifier.HandoffHeaderNotAscending.selector, 4 * L - 1, 4 * L));
        v.verifyBundle(_bundle(b, rotations, ""), _anchor(4 * L, pk1), _ctx(CHANNEL_ID));
    }

    function test_verifyBundle_rotationCannotRepeat() public {
        bytes[] memory rotations = new bytes[](2);
        rotations[0] = _boundaryRotation(sk1, 3, pk2);
        rotations[1] = _boundaryRotation(sk2, 3, pk3);
        Built memory b = _built(sk3, 4 * L + 1, "");
        vm.expectRevert(abi.encodeWithSelector(TempoVerifier.HandoffHeaderNotAscending.selector, 4 * L - 1, 4 * L - 1));
        v.verifyBundle(_bundle(b, rotations, ""), _anchor(3 * L, pk1), _ctx(CHANNEL_ID));
    }

    function test_verifyBundle_currentMustBeAfterLastRotation() public {
        bytes[] memory rotations = new bytes[](1);
        rotations[0] = _boundaryRotation(sk1, 3, pk2);
        Built memory b = _built(sk2, 4 * L - 1, ""); // same height as the rotation
        vm.expectRevert(abi.encodeWithSelector(TempoVerifier.CurrentHeaderBehindWalk.selector, 4 * L - 1, 4 * L - 1));
        v.verifyBundle(_bundle(b, rotations, ""), _anchor(3 * L, pk1), _ctx(CHANNEL_ID));
    }

    function test_verifyBundle_acceptedRisk_retiredKeyCertifiesLaterEpoch() public view {
        bytes memory preDkgAnchor = _anchor(3 * L, pk1);

        bytes[] memory fullDkg = new bytes[](1);
        fullDkg[0] = _boundaryRotation(sk1, 3, pk2);
        (,, bytes memory honestAnchor,,) =
            v.verifyBundle(_bundle(_built(sk2, 4 * L + 1, ""), fullDkg, ""), preDkgAnchor, _ctx(CHANNEL_ID));
        (,,, bytes memory honestKey) = abi.decode(honestAnchor, (bytes32, uint64, uint64, bytes));
        assertEq(honestKey, pk2, "the chain moved to key 2");

        Built memory forged = _built(sk1, 5 * L + 7, "");
        (,, bytes memory newAnchor,,) =
            v.verifyBundle(_bundle(forged, new bytes[](0), ""), preDkgAnchor, _ctx(CHANNEL_ID));
        assertEq(newAnchor.length, 0, "retired key 1 certified an epoch-5 header");
    }

    function test_verifyBundle_acceptedRisk_retiredKeyCapturesAnchor() public {
        bytes[] memory forgedRotation = new bytes[](1);
        forgedRotation[0] = _boundaryRotation(sk1, 4, pk3);
        (,, bytes memory captured,,) = v.verifyBundle(
            _bundle(_built(sk3, 5 * L + 1, ""), forgedRotation, ""), _anchor(3 * L, pk1), _ctx(CHANNEL_ID)
        );
        (,,, bytes memory capturedKey) = abi.decode(captured, (bytes32, uint64, uint64, bytes));
        assertEq(capturedKey, pk3, "attacker key installed");

        Built memory honest = _built(sk2, 5 * L + 7, "");
        vm.expectRevert(ClprTempoBls.BlsSignatureInvalid.selector);
        v.verifyBundle(_bundle(honest, new bytes[](0), ""), captured, _ctx(CHANNEL_ID));

        bytes[] memory realDkg = new bytes[](1);
        realDkg[0] = _boundaryRotation(sk1, 3, pk2);
        vm.expectRevert(ClprTempoBls.BlsSignatureInvalid.selector);
        v.verifyBundle(_bundle(honest, realDkg, ""), captured, _ctx(CHANNEL_ID));
    }

    function test_verifyBundle_rotationWithWrongItemCount() public {
        bytes[] memory four = new bytes[](4);
        for (uint256 i = 0; i < 4; i++) {
            four[i] = RLP.encode(uint256(0));
        }
        bytes[] memory rotations = new bytes[](1);
        rotations[0] = RLP.encode(four);
        Built memory b = _built(sk1, 250, "");
        vm.expectRevert(TempoVerifier.InvalidPayloadShape.selector);
        v.verifyBundle(_bundle(b, rotations, ""), _anchor(249, pk1), _ctx(CHANNEL_ID));
    }

    function test_verifyBundle_rejectsSixItemPayload() public {
        Built memory b = _built(sk1, 250, "");
        bytes memory six = _replaceItem(_bundle(b, new bytes[](0), ""), 5, RLP.encode(uint256(0)));
        vm.expectRevert(TempoVerifier.InvalidPayloadShape.selector);
        v.verifyBundle(six, _anchor(249, pk1), _ctx(CHANNEL_ID));
    }

    function test_verifyBundle_rejectsThreeItemSource() public {
        Built memory b = _built(sk1, 250, "");
        bytes[] memory threeSource = new bytes[](3);
        threeSource[0] = RLP.encode(b.cert.proposal);
        threeSource[1] = RLP.encode(b.cert.sigCompressed);
        threeSource[2] = RLP.encode(b.cert.sigUncompressed);
        bytes memory bad = _replaceItem(_bundle(b, new bytes[](0), ""), 1, RLP.encode(threeSource));
        vm.expectRevert(TempoVerifier.InvalidPayloadShape.selector);
        v.verifyBundle(bad, _anchor(249, pk1), _ctx(CHANNEL_ID));
    }

    function test_verifyBundle_rejectsAnchorShapes() public {
        Built memory b = _built(sk1, 250, "");
        bytes memory bundle = _bundle(b, new bytes[](0), "");
        vm.expectRevert(TempoVerifier.InvalidTrustAnchor.selector);
        v.verifyBundle(bundle, hex"", _ctx(CHANNEL_ID));
        vm.expectRevert(TempoVerifier.InvalidTrustAnchor.selector);
        v.verifyBundle(bundle, _tempoAnchor(CODE_HASH, L, 249, new bytes(128)), _ctx(CHANNEL_ID));
        vm.expectRevert(TempoVerifier.InvalidTrustAnchor.selector);
        v.verifyBundle(bundle, _tempoAnchor(CODE_HASH, 1, 249, pk1), _ctx(CHANNEL_ID));
    }

    /// @dev A 416-byte anchor whose identity length word says 200 passes the size check and must
    ///      fail the identity check.
    function test_verifyBundle_rejectsAnchorWithShortIdentity() public {
        Built memory b = _built(sk1, 250, "");
        bytes memory anchor = _anchor(249, pk1);
        assembly ("memory-safe") {
            mstore(add(anchor, 0xa0), 200) // word 4: identity length
        }
        assertEq(anchor.length, 416);
        vm.expectRevert(TempoVerifier.InvalidTrustAnchor.selector);
        v.verifyBundle(_bundle(b, new bytes[](0), ""), anchor, _ctx(CHANNEL_ID));
    }

    struct ConfigOut {
        bytes channelContext;
        string chainId;
        bytes serviceAddress;
        bytes anchor;
        bytes anchorId;
        uint64 manifestVersion;
    }

    function _config(bytes memory proof, bytes memory manifestProof) internal view returns (ConfigOut memory o) {
        ClprTypes.ClprEndpointManifest memory manifest;
        (o.channelContext, o.chainId, o.serviceAddress,,, o.anchor, o.anchorId, manifest) =
            v.verifyConfig(proof, CHANNEL_ID, manifestProof);
        o.manifestVersion = manifest.version;
    }

    /// @dev Config parts for key 1 over `header`.
    function _cfg(bytes memory header, CertificateBytes memory c) internal view returns (ConfigParts memory parts) {
        parts.service = SERVICE;
        parts.chainId = "eip155:4217";
        parts.codeHash = CODE_HASH;
        parts.epochLength = L;
        parts.keyCompressed = ClprBls12381.compressG2(pk1);
        parts.keyUncompressed = pk1;
        parts.header = header;
        parts.cert = c;
        parts.throttles = _defaultThrottles();
    }

    function _goodConfigProof(bytes memory header, CertificateBytes memory c) internal view returns (bytes memory) {
        return _encodeConfigProof(_cfg(header, c));
    }

    function test_verifyConfig_happyPath() public view {
        bytes memory header = _tempoHeader(3 * L + 5, bytes32(0), "", true);
        ConfigOut memory o = _config(_goodConfigProof(header, _certify(sk1, L, header, 3 * L + 5, 9)), "");
        assertEq(o.chainId, "eip155:4217");
        assertEq(o.serviceAddress, abi.encodePacked(SERVICE));
        assertEq(o.channelContext, _ctx(CHANNEL_ID));
        assertEq(o.anchor, _tempoAnchor(CODE_HASH, L, 3 * L + 5, pk1));
        assertEq(o.anchorId, abi.encodePacked(uint64(3 * L + 5)));
        assertEq(o.manifestVersion, 0, "no manifest proof: uninitialized manifest");
    }

    function test_verifyConfig_sevenThrottles() public view {
        bytes memory header = _tempoHeader(5, bytes32(0), "", true);
        CertificateBytes memory c = _certify(sk1, L, header, 5, 9);
        ConfigParts memory parts = _cfg(header, c);
        parts.throttles = new bytes[](7);
        for (uint256 i = 0; i < 7; i++) {
            parts.throttles[i] = RLP.encode(uint256(i + 1));
        }
        (,,,, ClprTypes.Throttles memory throttles,,,) = v.verifyConfig(_encodeConfigProof(parts), CHANNEL_ID, "");
        assertEq(throttles.maxLocalEndpoints, 6);
        assertEq(throttles.maxPeerEndpoints, 7);
    }

    function test_verifyConfig_withManifestProof() public view {
        bytes memory header = _tempoHeader(5, bytes32(0), "", true);
        bytes memory preimage = ClprProtobuf.encodeEndpointManifest(_manifest(3));
        ConfigOut memory o = _config(
            _goodConfigProof(header, _certify(sk1, L, header, 5, 9)), _configManifestProof(sk1, preimage, preimage)
        );
        assertEq(o.manifestVersion, 3);
    }

    function test_verifyConfig_manifestProofPinsCodeHash() public {
        bytes memory header = _tempoHeader(5, bytes32(0), "", true);
        CertificateBytes memory c = _certify(sk1, L, header, 5, 9);
        bytes memory preimage = ClprProtobuf.encodeEndpointManifest(_manifest(3));
        bytes memory manifestProof = _configManifestProof(sk1, preimage, preimage);
        ConfigParts memory parts = _cfg(header, c);

        parts.codeHash = bytes32(0);
        (,,,,,,, ClprTypes.ClprEndpointManifest memory m) =
            v.verifyConfig(_encodeConfigProof(parts), CHANNEL_ID, manifestProof);
        assertEq(m.version, 3, "a zero code hash turns the pin off");

        parts.codeHash = bytes32(uint256(0xBAD));
        bytes memory proof = _encodeConfigProof(parts);
        vm.expectRevert(ClprEvmBundleVerifier.CodeHashMismatch.selector);
        v.verifyConfig(proof, CHANNEL_ID, manifestProof);
    }

    function test_verifyConfig_manifestProofShapeAndSignature() public {
        bytes memory header = _tempoHeader(5, bytes32(0), "", true);
        bytes memory proof = _goodConfigProof(header, _certify(sk1, L, header, 5, 9));
        bytes memory preimage = ClprProtobuf.encodeEndpointManifest(_manifest(3));
        bytes[] memory two = new bytes[](2);
        two[0] = RLP.encode(uint256(1));
        two[1] = RLP.encode(uint256(2));
        // Build this proof before expectRevert. Signing calls a precompile, which expectRevert watches.
        bytes memory foreignManifestProof = _configManifestProof(sk2, preimage, preimage);
        vm.expectRevert(TempoVerifier.InvalidProofPayloadShape.selector);
        v.verifyConfig(proof, CHANNEL_ID, RLP.encode(two));
        vm.expectRevert(ClprTempoBls.BlsSignatureInvalid.selector);
        v.verifyConfig(proof, CHANNEL_ID, foreignManifestProof);
    }

    function test_verifyConfig_rejectsEmptyAndSixItemProofs() public {
        bytes memory header = _tempoHeader(5, bytes32(0), "", true);
        bytes memory good = _goodConfigProof(header, _certify(sk1, L, header, 5, 9));
        vm.expectRevert(TempoVerifier.InvalidPayloadShape.selector);
        v.verifyConfig(hex"", CHANNEL_ID, "");
        vm.expectRevert(TempoVerifier.InvalidProofPayloadShape.selector);
        v.verifyConfig(_withItems(good, 6), CHANNEL_ID, "");
    }

    function test_verifyConfig_rejectsSixThrottles() public {
        bytes memory header = _tempoHeader(5, bytes32(0), "", true);
        CertificateBytes memory c = _certify(sk1, L, header, 5, 9);
        ConfigParts memory parts = _cfg(header, c);
        parts.throttles = new bytes[](6);
        for (uint256 i = 0; i < 6; i++) {
            parts.throttles[i] = RLP.encode(uint256(0));
        }
        bytes memory proof = _encodeConfigProof(parts);
        vm.expectRevert(TempoVerifier.InvalidConfigThrottleFieldCount.selector);
        v.verifyConfig(proof, CHANNEL_ID, "");
    }

    function test_verifyConfig_rejectsThreeItemDescriptor() public {
        bytes memory header = _tempoHeader(5, bytes32(0), "", true);
        bytes memory good = _goodConfigProof(header, _certify(sk1, L, header, 5, 9));
        bytes[] memory d3 = new bytes[](3);
        d3[0] = RLP.encode(CODE_HASH);
        d3[1] = RLP.encode(uint256(L));
        d3[2] = RLP.encode(pk1);
        vm.expectRevert(TempoVerifier.InvalidTrustAnchorFields.selector);
        v.verifyConfig(_replaceItem(good, 4, RLP.encode(RLP.encode(d3))), CHANNEL_ID, "");
    }

    function test_verifyConfig_rejectsWrongKeyLength() public {
        bytes memory header = _tempoHeader(5, bytes32(0), "", true);
        bytes memory good = _goodConfigProof(header, _certify(sk1, L, header, 5, 9));
        bytes[] memory d = new bytes[](4);
        d[0] = RLP.encode(CODE_HASH);
        d[1] = RLP.encode(uint256(L));
        d[2] = RLP.encode(ClprBls12381.compressG2(pk1));
        d[3] = RLP.encode(new bytes(128));
        vm.expectRevert(TempoVerifier.InvalidKeyLength.selector);
        v.verifyConfig(_replaceItem(good, 4, RLP.encode(RLP.encode(d))), CHANNEL_ID, "");
    }

    function test_verifyConfig_rejectsWrongServiceAddressLength() public {
        bytes memory header = _tempoHeader(5, bytes32(0), "", true);
        bytes memory good = _goodConfigProof(header, _certify(sk1, L, header, 5, 9));
        bytes memory proof = _replaceItem(good, 0, RLP.encode(new bytes(32)));
        vm.expectRevert(ClprEvmBundleVerifier.InvalidServiceAddressLength.selector);
        v.verifyConfig(proof, CHANNEL_ID, "");
    }

    function test_verifyConfig_rejectsTwoItemCertificate() public {
        bytes memory header = _tempoHeader(5, bytes32(0), "", true);
        CertificateBytes memory c = _certify(sk1, L, header, 5, 9);
        bytes memory good = _goodConfigProof(header, c);
        bytes[] memory c2 = new bytes[](2);
        c2[0] = RLP.encode(c.proposal);
        c2[1] = RLP.encode(c.sigCompressed);
        vm.expectRevert(TempoVerifier.InvalidProofPayloadShape.selector);
        v.verifyConfig(_replaceItem(good, 5, RLP.encode(c2)), CHANNEL_ID, "");
    }

    function test_verifyConfig_rejectsKeyMismatch() public {
        bytes memory header = _tempoHeader(5, bytes32(0), "", true);
        CertificateBytes memory c = _certify(sk1, L, header, 5, 9);
        ConfigParts memory parts = _cfg(header, c);
        parts.keyCompressed = ClprBls12381.compressG2(pk2);
        bytes memory proof = _encodeConfigProof(parts);
        vm.expectRevert(TempoVerifier.KeyEncodingMismatch.selector);
        v.verifyConfig(proof, CHANNEL_ID, "");
    }

    function test_verifyConfig_rejectsIdentityKey() public {
        bytes memory header = _tempoHeader(5, bytes32(0), "", true);
        CertificateBytes memory c = _certify(sk1, L, header, 5, 9);
        c.sigUncompressed = new bytes(128);
        c.sigCompressed = ClprBls12381.compressG1(c.sigUncompressed);
        ConfigParts memory parts = _cfg(header, c);
        parts.keyUncompressed = new bytes(256);
        parts.keyCompressed = ClprBls12381.compressG2(parts.keyUncompressed);
        bytes memory proof = _encodeConfigProof(parts);
        vm.expectRevert(TempoVerifier.InfinityPoint.selector);
        v.verifyConfig(proof, CHANNEL_ID, "");
    }

    function test_verifyConfig_rejectsEpochLengthOne() public {
        bytes memory header = _tempoHeader(5, bytes32(0), "", true);
        CertificateBytes memory c = _certify(sk1, L, header, 5, 9);
        ConfigParts memory parts = _cfg(header, c);
        parts.epochLength = 1;
        bytes memory proof = _encodeConfigProof(parts);
        vm.expectRevert(TempoVerifier.InvalidEpochLength.selector);
        v.verifyConfig(proof, CHANNEL_ID, "");
    }

    function test_verifyConfig_declaredKeyMustFinalizeHeader() public {
        bytes memory header = _tempoHeader(5, bytes32(0), "", true);
        CertificateBytes memory c = _certify(sk1, L, header, 5, 9);
        ConfigParts memory parts = _cfg(header, c);
        parts.keyCompressed = ClprBls12381.compressG2(pk2);
        parts.keyUncompressed = pk2;
        bytes memory proof = _encodeConfigProof(parts);
        vm.expectRevert(ClprTempoBls.BlsSignatureInvalid.selector);
        v.verifyConfig(proof, CHANNEL_ID, "");
    }

    /// @dev The first `count` items of an RLP list.
    function _withItems(bytes memory list, uint256 count) internal pure returns (bytes memory) {
        Memory.Slice[] memory items = RLP.decodeList(list);
        bytes[] memory kept = new bytes[](count);
        for (uint256 i = 0; i < count; i++) {
            kept[i] = Memory.toBytes(items[i]);
        }
        return RLP.encode(kept);
    }

    /// @dev `list` with item `index` replaced. An index one past the end appends.
    function _replaceItem(bytes memory list, uint256 index, bytes memory replacement)
        internal
        pure
        returns (bytes memory)
    {
        Memory.Slice[] memory items = RLP.decodeList(list);
        uint256 n = index >= items.length ? index + 1 : items.length;
        bytes[] memory all = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            all[i] = i == index ? replacement : Memory.toBytes(items[i]);
        }
        return RLP.encode(all);
    }

    // ── builders ────────────────────────────────────────────────────────────

    function _built(uint256 sk, uint64 number, bytes memory extraData) internal view returns (Built memory b) {
        return _builtWithContext(sk, number, extraData, true);
    }

    function _builtWithContext(uint256 sk, uint64 number, bytes memory extraData, bool withContext)
        internal
        view
        returns (Built memory b)
    {
        (bytes32 storageRoot, bytes memory storageProof) = _buildChannelStorageProof6(CHANNEL_ID);
        return _builtOver(sk, number, extraData, withContext, storageRoot, storageProof);
    }

    function _builtOver(
        uint256 sk,
        uint64 number,
        bytes memory extraData,
        bool withContext,
        bytes32 storageRoot,
        bytes memory storageProof
    ) internal view returns (Built memory b) {
        b.storageProof = storageProof;
        (b.stateRoot, b.accountProof) = _buildSyntheticAccountProof(SERVICE, storageRoot, CODE_HASH);
        b.header = _tempoHeader(number, b.stateRoot, extraData, withContext);
        b.cert = _certify(sk, L, b.header, number, 42);
    }

    function _bundle(Built memory b, bytes[] memory rotations, bytes memory bundleContent)
        internal
        pure
        returns (bytes memory)
    {
        BundleParts memory parts;
        parts.header = b.header;
        parts.cert = b.cert;
        parts.rotations = rotations;
        parts.accountProof = b.accountProof;
        parts.storageProof = b.storageProof;
        parts.content = bundleContent;
        return _encodeBundle(parts);
    }

    /// @dev A 7-field bundle with a manifest commitment at slot 18.
    function _bundleWithManifest(Built memory, bytes memory preimage) internal view returns (bytes memory) {
        BundleParts memory parts;
        bytes32 storageRoot;
        (storageRoot, parts.storageProof, parts.manifestProof) = _storageWithManifest(preimage);
        bytes32 stateRoot;
        (stateRoot, parts.accountProof) = _buildSyntheticAccountProof(SERVICE, storageRoot, CODE_HASH);
        parts.header = _tempoHeader(250, stateRoot, "", true);
        parts.cert = _certify(sk1, L, parts.header, 250, 42);
        parts.rotations = new bytes[](0);
        parts.manifestPreimage = preimage;
        return _encodeBundle(parts);
    }

    /// @dev One trie with the manifest slot. The channel slots prove zero.
    function _storageWithManifest(bytes memory preimage)
        internal
        pure
        returns (bytes32 storageRoot, bytes memory storageProof, bytes memory manifestProof)
    {
        bytes32 slot = bytes32(uint256(18));
        bytes memory nodes;
        (storageRoot, nodes) =
            _buildSyntheticMPTProof(keccak256(abi.encodePacked(slot)), RLP.encode(uint256(keccak256(preimage))));
        bytes32 cBase = keccak256(abi.encode(CHANNEL_ID, uint256(15)));
        uint8[5] memory offsets = [1, 2, 4, 5, 16];
        bytes[] memory entries = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            bytes[] memory entry = new bytes[](2);
            entry[0] = RLP.encode(abi.encodePacked(bytes32(uint256(cBase) + offsets[i])));
            entry[1] = nodes;
            entries[i] = RLP.encode(entry);
        }
        storageProof = RLP.encode(entries);
        bytes[] memory m = new bytes[](2);
        m[0] = RLP.encode(abi.encodePacked(slot));
        m[1] = nodes;
        bytes[] memory one = new bytes[](1);
        one[0] = RLP.encode(m);
        manifestProof = RLP.encode(one);
    }

    /// @dev Config-time manifest proof certified under `sk`, carrying `carried` as manifest bytes.
    function _configManifestProof(uint256 sk, bytes memory committed, bytes memory carried)
        internal
        view
        returns (bytes memory)
    {
        (bytes32 storageRoot,, bytes memory manifestProof) = _storageWithManifest(committed);
        (bytes32 stateRoot, bytes memory accountProof) = _buildSyntheticAccountProof(SERVICE, storageRoot, CODE_HASH);
        bytes memory header = _tempoHeader(6, stateRoot, "", true);
        return _configManifestProofItem(header, _certify(sk, L, header, 6, 9), accountProof, manifestProof, carried);
    }

    /// @dev The last block of epoch `e`, certified under `sk`, naming `nextKey`.
    function _boundaryRotation(uint256 sk, uint64 e, bytes memory nextKey) internal view returns (bytes memory) {
        uint64 number = (e + 1) * L - 1;
        bytes memory header =
            _tempoHeader(number, bytes32(0), _dkgOutcome(e + 1, ClprBls12381.compressG2(nextKey)), true);
        return _encodeRotation(header, _certify(sk, L, header, number, 10), nextKey);
    }

    function _anchor(uint64 anchorBlock, bytes memory key) internal pure returns (bytes memory) {
        return _tempoAnchor(CODE_HASH, L, anchorBlock, key);
    }

    function _ctx(bytes32 channelId) internal pure returns (bytes memory) {
        return _tempoChannelContext(channelId, SERVICE);
    }

    function _manifest(uint64 version) internal pure returns (ClprTypes.ClprEndpointManifest memory m) {
        m.version = version;
        m.serviceAddress = abi.encodePacked(SERVICE);
        m.endpoints = new ClprTypes.Endpoint[](0);
    }
}
