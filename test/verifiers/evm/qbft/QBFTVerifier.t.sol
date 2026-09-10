// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "forge-std/console.sol";
import {stdError} from "forge-std/StdError.sol";

import {QBFTVerifier} from "@hiero-ledger/clpr/verifiers/evm/qbft/QBFTVerifier.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprQbftSeal} from "@hiero-ledger/clpr/libraries/proof/qbft/ClprQbftSeal.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";
import {QbftSyntheticProofs} from "@test/helpers/QbftSyntheticProofs.sol";

/// @dev Exposes internal `_decodeBundleContent` for unit testing.
contract QBFTVerifierHarness is QBFTVerifier {
    constructor() QBFTVerifier(1) {}

    function decodeBundleContent(bytes memory data) external pure returns (bytes[] memory messages) {
        return _decodeBundleContent(data);
    }
}

contract QBFTVerifierTest is QbftSyntheticProofs {
    QBFTVerifier internal verifier;
    QBFTVerifierHarness internal harness;

    // ── Synthetic constants used by the negative-path tests below ────────────
    uint256 internal constant VALIDATOR_PK = uint256(keccak256("qbft-validator"));
    address internal validatorAddr;
    address internal constant SERVICE_ADDR = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;
    bytes32 internal constant SERVICE_CODE_HASH = bytes32(uint256(0xC0DE));
    uint64 internal constant GENESIS_EPOCH_LENGTH = 30000;
    uint64 internal constant GENESIS_EPOCH_NUMBER = 0;
    bytes32 internal constant SYNTHETIC_CHANNEL_ID = bytes32(uint256(0xC0FFEE));

    // ── Real-Besu happy-path fixture ────────────────────────────────────────
    string internal constant PROOF_PATH = "test/verifiers/evm/qbft/fixtures/bundlePayload.hex";
    string internal constant TRUST_ANCHOR_PATH = "test/verifiers/evm/qbft/fixtures/trustAnchor.hex";

    function setUp() public {
        validatorAddr = vm.addr(VALIDATOR_PK);
        verifier = _qbftVerifier(2);
        harness = QBFTVerifierHarness(deployCode("QBFTVerifier.t.sol:QBFTVerifierHarness"));
    }

    function _qbftVerifier(uint8 n) private returns (QBFTVerifier) {
        return QBFTVerifier(deployCode("QBFTVerifier.sol:QBFTVerifier", abi.encode(n)));
    }

    function _deployAndExpectRevert(string memory artifact, bytes memory args) private {
        bytes memory code = abi.encodePacked(vm.getCode(artifact), args);
        assembly {
            let addr := create(0, add(code, 0x20), mload(code))
            if iszero(addr) {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
        }
    }

    function _loadProof() internal view returns (bytes memory) {
        return _readHexFile(PROOF_PATH);
    }

    /// @dev Fixture stores the trust anchor as `RLP([validator20, service20, codeHash32])`.
    ///      We append the synthetic epochLength/epochNumber to produce the 4-field ABI encoding
    function _loadTrustAnchor() internal view returns (bytes memory) {
        bytes memory rlpBytes = _readHexFile(TRUST_ANCHOR_PATH);
        Memory.Slice[] memory fields = RLP.decodeList(rlpBytes);
        require(fields.length == 3, "trustAnchor: expected 3 fields");
        return
            abi.encode(
                RLP.readAddress(fields[0]), RLP.readBytes32(fields[2]), GENESIS_EPOCH_LENGTH, GENESIS_EPOCH_NUMBER
            );
    }

    function _readHexFile(string memory path) internal view returns (bytes memory) {
        string memory raw = vm.readFile(path);
        bytes memory b = bytes(raw);
        // Strip trailing CR/LF so vm.parseBytes doesn't choke on whitespace.
        while (b.length > 0 && (b[b.length - 1] == 0x0a || b[b.length - 1] == 0x0d)) {
            assembly {
                mstore(b, sub(mload(b), 1))
            }
        }
        return vm.parseBytes(string.concat("0x", string(b)));
    }

    function test_revertWhen_SealSignatureIsZero() public {
        vm.expectRevert(QBFTVerifier.InvalidNumberOfSealSignatures.selector);
        _deployAndExpectRevert("QBFTVerifier.sol:QBFTVerifier", abi.encode(uint8(0)));
    }

    function test_getCommittedSeals() public view {
        uint8 minSeals = verifier.MIN_COMMITTED_SEALS();
        assertEq(minSeals, 2);
    }

    function test_revertWhen_TrustAnchorWrongLength() public {
        bytes memory badTrustAnchor = hex"deadbeef";
        vm.expectRevert(QBFTVerifier.InvalidTrustAnchor.selector);
        verifier.verifyBundle(hex"c0", badTrustAnchor, "");
    }

    function test_revertWhen_PayloadNotFiveItems() public {
        // Use a 4-item payload — the new layout requires exactly 5 items.
        bytes[] memory items = new bytes[](4);
        items[0] = hex"80";
        items[1] = hex"80";
        items[2] = hex"80";
        items[3] = hex"80";
        bytes memory payload = RLP.encode(items);
        vm.expectRevert(QBFTVerifier.InvalidPayloadShape.selector);
        verifier.verifyBundle(payload, _syntheticTrustAnchor(), _syntheticChannelContext());
    }

    function test_revertWhen_HeaderTooFewFields() public {
        bytes memory header = _emptyHeader(14);
        bytes memory payload = _buildPayloadWithHeader(header);
        vm.expectRevert(QBFTVerifier.InvalidHeader.selector);
        verifier.verifyBundle(payload, _syntheticTrustAnchor(), _syntheticChannelContext());
    }

    function test_revertWhen_HeaderTooManyFields() public {
        bytes memory header = _emptyHeader(24);
        bytes memory payload = _buildPayloadWithHeader(header);
        vm.expectRevert(QBFTVerifier.InvalidHeader.selector);
        verifier.verifyBundle(payload, _syntheticTrustAnchor(), _syntheticChannelContext());
    }

    // ════════════════════════════════════════════════════════════════════════
    //   verifyBundle — QBFT seal
    // ════════════════════════════════════════════════════════════════════════

    function test_revertWhen_ExtraDataNotFiveItems() public {
        bytes[] memory extra4 = new bytes[](4);
        extra4[0] = hex"80";
        extra4[1] = hex"c0";
        extra4[2] = hex"80";
        extra4[3] = hex"80";
        bytes memory innerExtra = RLP.encode(extra4);
        bytes memory header = _buildHeader(bytes32(0), innerExtra);
        bytes memory payload = _buildPayloadWithHeader(header);
        vm.expectRevert(ClprQbftSeal.InvalidExtraData.selector);
        verifier.verifyBundle(payload, _syntheticTrustAnchor(), _syntheticChannelContext());
    }

    /// @dev Empty extraData must surface the library's structural error, not the generic
    ///      RLPInvalidEncoding that RLP.decodeList raises on empty input.
    function test_revertWhen_ExtraDataEmpty() public {
        bytes memory header = _buildHeader(bytes32(0), new bytes(0));
        bytes memory payload = _buildPayloadWithHeader(header);
        vm.expectRevert(ClprQbftSeal.InvalidExtraData.selector);
        verifier.verifyBundle(payload, _syntheticTrustAnchor(), _syntheticChannelContext());
    }

    function test_revertWhen_NoCommittedSeal() public {
        bytes memory innerExtra = _buildExtraData(new bytes[](0), 0);
        bytes memory header = _buildHeader(bytes32(0), innerExtra);
        bytes memory payload = _buildPayloadWithHeader(header);
        vm.expectRevert(abi.encodeWithSelector(ClprQbftSeal.WrongSealCount.selector, uint256(0), uint256(2)));
        verifier.verifyBundle(payload, _syntheticTrustAnchor(), _syntheticChannelContext());
    }

    function test_revertWhen_OnlyOneCommittedSeal() public {
        bytes[] memory seals = new bytes[](1);
        seals[0] = _placeholderSeal();
        bytes memory innerExtra = _buildExtraData(seals, 0);
        bytes memory header = _buildHeader(bytes32(0), innerExtra);
        bytes memory payload = _buildPayloadWithHeader(header);
        // MIN_COMMITTED_SEALS == 2; 1 < 2 → WrongSealCount
        vm.expectRevert(abi.encodeWithSelector(ClprQbftSeal.WrongSealCount.selector, uint256(1), uint256(2)));
        verifier.verifyBundle(payload, _syntheticTrustAnchor(), _syntheticChannelContext());
    }

    function test_revertWhen_SealLengthWrong() public {
        // Need >= MIN_COMMITTED_SEALS (2) seals; first one has wrong length.
        bytes[] memory seals = new bytes[](2);
        seals[0] = new bytes(64); // 64 bytes, not 65
        seals[1] = new bytes(64);
        bytes memory innerExtra = _buildExtraData(seals, 0);
        bytes memory header = _buildHeader(bytes32(0), innerExtra);
        bytes memory payload = _buildPayloadWithHeader(header);
        vm.expectRevert(abi.encodeWithSelector(ClprQbftSeal.SealLengthMismatch.selector, uint256(64)));
        verifier.verifyBundle(payload, _syntheticTrustAnchor(), _syntheticChannelContext());
    }

    function test_revertWhen_SealRecoversWrongValidator() public {
        // Build a header whose 2 committed seals are both signed by a stranger —
        // not the expectedValidator.  WrongSealCount is NOT expected; the count (2)
        // satisfies MIN_COMMITTED_SEALS, so we expect ValidatorSealNotFound.
        uint256 otherPk = uint256(keccak256("not-the-validator"));
        uint256 otherPk2 = uint256(keccak256("not-the-validator-2"));
        bytes memory header = _buildMultiSealedHeader(new uint256[](0), bytes32(0), 0, otherPk, otherPk2);
        bytes memory payload = _buildPayloadWithHeader(header);
        vm.expectRevert(abi.encodeWithSelector(ClprQbftSeal.ValidatorSealNotFound.selector, validatorAddr));
        verifier.verifyBundle(payload, _syntheticTrustAnchor(), _syntheticChannelContext());
    }

    /// @dev Requires fixture regeneration: `node tools/qbft-proof-generator/generate-fixture.js`
    ///      The bundlePayload.hex fixture must be rebuilt with the 5-item layout
    ///      (epochHeaders[], currentHeader, accountProof, storageProof, bundleContent).
    function test_success_verifyBundle() public {
        QBFTVerifier v1 = _qbftVerifier(1);

        (bytes32 storageRoot, bytes memory storageProofRlp) = _buildChannelStorageProof(SYNTHETIC_CHANNEL_ID);
        (bytes32 stateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        bytes memory header = _buildSealedCurrentHeader(1, stateRoot, VALIDATOR_PK);

        bytes[] memory top = new bytes[](5);
        top[0] = header;
        top[1] = hex"c0";
        top[2] = accountProofRlp;
        top[3] = storageProofRlp;
        top[4] = RLP.encode(new bytes(0));

        (ClprTypes.QueueMetadata memory metadata, bytes[] memory msgs, bytes memory newTrustAnchor,,) =
            v1.verifyBundle(RLP.encode(top), _syntheticTrustAnchor(), _syntheticChannelContext());

        assertEq(uint8(metadata.state), uint8(ClprTypes.ChannelStatus(0)));
        assertEq(metadata.nextMessageId, 0);
        assertEq(metadata.receivedMessageId, 0);
        assertEq(metadata.sentRunningHash, bytes32(0));
        assertEq(msgs.length, 0);
        assertEq(newTrustAnchor.length, 0, "no epoch transition: trust anchor must stay empty");
    }

    /// @dev The 5th proven Channel slot (+16, endpointManifestVersion) must surface in
    ///      QueueMetadata.endpointManifestVersion (proto field 7).
    function test_verifyBundle_provesEndpointManifestVersion() public {
        QBFTVerifier v1 = _qbftVerifier(1);

        (bytes32 storageRoot, bytes memory storageProofRlp) =
            _buildChannelStorageProofWithManifestVersion(SYNTHETIC_CHANNEL_ID, 42);
        (bytes32 stateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        bytes memory header = _buildSealedCurrentHeader(1, stateRoot, VALIDATOR_PK);

        bytes[] memory top = new bytes[](5);
        top[0] = header;
        top[1] = hex"c0";
        top[2] = accountProofRlp;
        top[3] = storageProofRlp;
        top[4] = RLP.encode(new bytes(0));

        (ClprTypes.QueueMetadata memory metadata,,,,) =
            v1.verifyBundle(RLP.encode(top), _syntheticTrustAnchor(), _syntheticChannelContext());

        assertEq(metadata.endpointManifestVersion, 42, "proven +16 slot must surface in metadata");
    }

    function test_success_verifyBundle_6entries() public {
        QBFTVerifier v1 = _qbftVerifier(1);

        (bytes32 storageRoot, bytes memory storageProofRlp) = _buildChannelStorageProof6(SYNTHETIC_CHANNEL_ID);
        (bytes32 stateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        bytes memory header = _buildSealedCurrentHeader(1, stateRoot, VALIDATOR_PK);

        bytes[] memory top = new bytes[](5);
        top[0] = header;
        top[1] = hex"c0";
        top[2] = accountProofRlp;
        top[3] = storageProofRlp;
        top[4] = RLP.encode(new bytes(0));

        (ClprTypes.QueueMetadata memory metadata,,,,) =
            v1.verifyBundle(RLP.encode(top), _syntheticTrustAnchor(), _syntheticChannelContext());

        assertEq(metadata.nextMessageId, 1, "nextMessageId must be 1 from 5-entry proof");
    }

    /// @dev A 6-entry (message-bearing) storage proof supplied for a channel with nextMessageId=0
    ///      is malformed: per the CLPR spec nextMessageId starts at 1, so 0 means no message was ever
    ///      sent and no last-message running-hash slot exists to verify against the 6th entry.
    ///      The guard lives in the shared ClprEvmBundleVerifier._verifyChannelStorage, so this also
    ///      covers EthMainnetVerifier (identical inherited code path).
    function test_verifyBundle_zeroNextMessageId_sixEntries_reverts() public {
        QBFTVerifier v1 = _qbftVerifier(1);

        (bytes32 storageRoot, bytes memory storageProofRlp) =
            _buildChannelStorageProof6ZeroNextMessageId(SYNTHETIC_CHANNEL_ID);
        (bytes32 stateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        bytes memory header = _buildSealedCurrentHeader(1, stateRoot, VALIDATOR_PK);

        bytes[] memory top = new bytes[](5);
        top[0] = header;
        top[1] = hex"c0";
        top[2] = accountProofRlp;
        top[3] = storageProofRlp;
        top[4] = RLP.encode(new bytes(0));

        vm.expectRevert(ClprEvmBundleVerifier.InvalidNextMessageId.selector);
        v1.verifyBundle(RLP.encode(top), _syntheticTrustAnchor(), _syntheticChannelContext());
    }

    function _syntheticTrustAnchor() internal view returns (bytes memory) {
        return abi.encode(validatorAddr, SERVICE_CODE_HASH, GENESIS_EPOCH_LENGTH, GENESIS_EPOCH_NUMBER);
    }

    /// @dev ChannelContext matching the storage/account proofs built by _buildChannelStorageProof
    ///      and _buildSyntheticAccountProof (both keyed by SYNTHETIC_CHANNEL_ID / SERVICE_ADDR).
    function _syntheticChannelContext() internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({
                channelId: SYNTHETIC_CHANNEL_ID, remoteServiceAddress: abi.encodePacked(SERVICE_ADDR)
            })
        );
    }

    function _placeholderSeal() internal pure returns (bytes memory) {
        return new bytes(65);
    }

    // ════════════════════════════════════════════════════════════════════════
    //   Epoch header block-number validation
    // ════════════════════════════════════════════════════════════════════════

    /// @dev Epoch header 0 must be at block (trustAnchorEpoch + 1) * epochLength.
    ///      Providing a header at block 1 (≠ 30000) must revert with InvalidHeader.
    function test_revertWhen_EpochHeaderWrongBlockNumber() public {
        // _buildHeader hardcodes block number 1; expected = (0 + 0 + 1) * 30000 = 30000.
        bytes memory epochHeader = _buildHeader(bytes32(0), _buildExtraData(new bytes[](0), 0));
        bytes[] memory epochList = new bytes[](1);
        epochList[0] = epochHeader;

        bytes[] memory top = new bytes[](5);
        top[0] = _emptyHeader(15); // current header placeholder — never reached
        top[1] = RLP.encode(epochList);
        top[2] = hex"c0";
        top[3] = hex"c0";
        top[4] = RLP.encode(new bytes(0));

        vm.expectRevert(QBFTVerifier.InvalidHeader.selector);
        verifier.verifyBundle(RLP.encode(top), _syntheticTrustAnchor(), _syntheticChannelContext());
    }

    /// @dev Second epoch header must be at (trustAnchorEpoch + 2) * epochLength, not the same
    ///      block as the first. Providing the same header twice must revert on the second.
    function test_revertWhen_EpochHeadersDuplicated() public {
        // Use a 1-seal verifier so the first epoch header can fully pass verification.
        QBFTVerifier v1 = _qbftVerifier(1);
        // First epoch header at block 30000 — valid: block == (0+1)*30000, signed by VALIDATOR_PK.
        bytes memory epochHeader = _buildSignedEpochHeader(GENESIS_EPOCH_LENGTH, validatorAddr, VALIDATOR_PK);

        // Duplicate: second entry still at 30000, but expected = (0+2)*30000 = 60000.
        bytes[] memory epochList = new bytes[](2);
        epochList[0] = epochHeader;
        epochList[1] = epochHeader;

        bytes[] memory top = new bytes[](5);
        top[0] = _emptyHeader(15);
        top[1] = RLP.encode(epochList);
        top[2] = hex"c0";
        top[3] = hex"c0";
        top[4] = RLP.encode(new bytes(0));

        vm.expectRevert(QBFTVerifier.InvalidHeader.selector);
        v1.verifyBundle(RLP.encode(top), _syntheticTrustAnchor(), _syntheticChannelContext());
    }

    // ════════════════════════════════════════════════════════════════════════
    //   Epoch header field-count guard
    // ════════════════════════════════════════════════════════════════════════

    /// @dev An epoch header whose RLP list has fewer than MIN_BLOCK_HEADER_FIELDS items must revert.
    function test_revertWhen_EpochHeaderTooFewFields() public {
        bytes[] memory epochList = new bytes[](1);
        epochList[0] = _emptyHeader(14); // 14 < MIN_BLOCK_HEADER_FIELDS (15)

        bytes[] memory top = new bytes[](5);
        top[0] = _emptyHeader(15);
        top[1] = RLP.encode(epochList);
        top[2] = hex"c0";
        top[3] = hex"c0";
        top[4] = RLP.encode(new bytes(0));

        vm.expectRevert(QBFTVerifier.InvalidHeader.selector);
        verifier.verifyBundle(RLP.encode(top), _syntheticTrustAnchor(), _syntheticChannelContext());
    }

    // ════════════════════════════════════════════════════════════════════════
    //   Epoch boundary check
    // ════════════════════════════════════════════════════════════════════════

    /// @dev Current block is in epoch 1 (block == GENESIS_EPOCH_LENGTH) but the trust anchor
    ///      expects epoch 0 with no epoch headers → EpochMismatch.
    ///      Uses QBFTVerifier(1) so a single seal suffices.
    function test_revertWhen_EpochMismatch() public {
        QBFTVerifier v1 = _qbftVerifier(1);
        // Block 30000 → currentEpoch = 30000/30000 = 1; expected = trustAnchorEpoch(0) + 0 = 0.
        bytes memory header = _buildSignedEpochHeader(GENESIS_EPOCH_LENGTH, validatorAddr, VALIDATOR_PK);

        bytes[] memory top = new bytes[](5);
        top[0] = header;
        top[1] = hex"c0";
        top[2] = hex"c0";
        top[3] = hex"c0";
        top[4] = RLP.encode(new bytes(0));

        vm.expectRevert(QBFTVerifier.EpochMismatch.selector);
        v1.verifyBundle(RLP.encode(top), _syntheticTrustAnchor(), _syntheticChannelContext());
    }

    // ════════════════════════════════════════════════════════════════════════
    //   _extractValidatorFromEpochHeader guards
    // ════════════════════════════════════════════════════════════════════════

    /// @dev Epoch header with an empty validators list must revert with EmptyValidator.
    function test_revertWhen_EmptyValidatorInEpochHeader() public {
        QBFTVerifier v1 = _qbftVerifier(1);
        bytes memory epochHeader =
            _buildSignedEpochHeaderCustomValidators(GENESIS_EPOCH_LENGTH, RLP.encode(new bytes[](0)), VALIDATOR_PK);

        bytes[] memory epochList = new bytes[](1);
        epochList[0] = epochHeader;

        bytes[] memory top = new bytes[](5);
        top[0] = _emptyHeader(15);
        top[1] = RLP.encode(epochList);
        top[2] = hex"c0";
        top[3] = hex"c0";
        top[4] = RLP.encode(new bytes(0));

        vm.expectRevert(QBFTVerifier.EmptyValidator.selector);
        v1.verifyBundle(RLP.encode(top), _syntheticTrustAnchor(), _syntheticChannelContext());
    }

    /// @dev Epoch header with two validators must revert with MultiValidatorNotSupported.
    function test_revertWhen_MultiValidatorInEpochHeader() public {
        QBFTVerifier v1 = _qbftVerifier(1);
        bytes[] memory twoItems = new bytes[](2);
        twoItems[0] = RLP.encode(validatorAddr);
        twoItems[1] = RLP.encode(validatorAddr);
        bytes memory epochHeader =
            _buildSignedEpochHeaderCustomValidators(GENESIS_EPOCH_LENGTH, RLP.encode(twoItems), VALIDATOR_PK);

        bytes[] memory epochList = new bytes[](1);
        epochList[0] = epochHeader;

        bytes[] memory top = new bytes[](5);
        top[0] = _emptyHeader(15);
        top[1] = RLP.encode(epochList);
        top[2] = hex"c0";
        top[3] = hex"c0";
        top[4] = RLP.encode(new bytes(0));

        vm.expectRevert(QBFTVerifier.MultiValidatorNotSupported.selector);
        v1.verifyBundle(RLP.encode(top), _syntheticTrustAnchor(), _syntheticChannelContext());
    }

    // ════════════════════════════════════════════════════════════════════════
    //   _decodeBundleContent — skipField in pass 2
    // ════════════════════════════════════════════════════════════════════════

    /// @dev Bundle content with a field-1 (metadata) prefix before field-2 (message payload).
    ///      Pass 2 must skip the field-1 entry before collecting the field-2 payload.
    function test_decodeBundleContent_skipsFieldOne() public view {
        // 0x0a = field 1, wire type 2 (LEN); 0x12 = field 2, wire type 2 (LEN)
        bytes memory data = hex"0a02dead1202beef";
        bytes[] memory msgs = harness.decodeBundleContent(data);
        assertEq(msgs.length, 1);
        assertEq(msgs[0], hex"beef");
    }

    // ════════════════════════════════════════════════════════════════════════
    //   verifyConfig — header field-count guard
    // ════════════════════════════════════════════════════════════════════════

    /// @dev A 10-field configProof where field 8 is a 14-field header (too short) must revert
    ///      before reaching seal verification.
    function test_revertWhen_verifyConfig_headerTooFewFields() public {
        bytes[] memory proof = new bytes[](10);
        proof[0] = RLP.encode(address(0)); // validator
        proof[1] = RLP.encode(new bytes(0)); // serviceAddr
        proof[2] = RLP.encode(bytes32(0)); // codeHash
        proof[3] = RLP.encode(new bytes(0)); // chainId
        proof[4] = RLP.encode(uint256(0)); // peerConfigNanos
        proof[5] = hex"c0"; // throttles (empty — never reached)
        proof[6] = RLP.encode(new bytes(0)); // trustAnchor
        proof[7] = RLP.encode(new bytes(0)); // trustAnchorId
        proof[8] = _emptyHeader(14); // 14 fields < MIN_BLOCK_HEADER_FIELDS (15)
        proof[9] = RLP.encode(uint256(30000)); // epochLength

        vm.expectRevert(QBFTVerifier.InvalidConfigHeader.selector);
        verifier.verifyConfig(RLP.encode(proof), bytes32(0), "");
    }

    // ════════════════════════════════════════════════════════════════════════
    //   verifyConfig — throttle and trust-anchor field-count guards
    // ════════════════════════════════════════════════════════════════════════

    function test_verifyConfig_reverts_wrongFieldCount() public {
        // Malformed RLP list with only 1 item
        bytes memory malformed = hex"c180";

        vm.expectRevert(QBFTVerifier.InvalidProofPayloadShape.selector);

        verifier.verifyConfig(malformed, bytes32(0), "");
    }

    function test_revertWhen_verifyConfig_emptyProof() public {
        vm.expectRevert(QBFTVerifier.InvalidPayloadShape.selector);
        verifier.verifyConfig("", bytes32(0), "");
    }

    /// @dev Build a minimal 10-field config proof with a valid 1-seal header at proof[8]
    ///      and the supplied bytes at proof[5] (throttles) and proof[6] (trust anchor).
    function _buildConfigProofWith(bytes memory throttlesRlp, bytes memory trustAnchorBytes)
        internal
        view
        returns (bytes memory)
    {
        bytes[] memory proof = new bytes[](10);
        proof[0] = RLP.encode(validatorAddr);
        proof[1] = RLP.encode(new bytes(0));
        proof[2] = RLP.encode(bytes32(0));
        proof[3] = RLP.encode(bytes("eip155:1"));
        proof[4] = RLP.encode(uint256(0));
        proof[5] = throttlesRlp;
        proof[6] = trustAnchorBytes;
        proof[7] = RLP.encode(new bytes(0));
        proof[8] = _buildSealedCurrentHeader(0, bytes32(0), VALIDATOR_PK);
        proof[9] = RLP.encode(uint256(30000));
        return RLP.encode(proof);
    }

    /// @dev Proof passes line 219 (10 fields) and line 224 (≥15-field header + valid seal),
    ///      but throttle list has 6 items instead of 7 → line 231 reverts.
    function test_verifyConfig_reverts_wrongThrottleFieldCount() public {
        QBFTVerifier v1 = _qbftVerifier(1);
        bytes[] memory throttleItems = new bytes[](6);
        for (uint256 i = 0; i < 6; i++) {
            throttleItems[i] = hex"80";
        }
        bytes memory configProof = _buildConfigProofWith(RLP.encode(throttleItems), RLP.encode(new bytes(0)));

        vm.expectRevert(QBFTVerifier.InvalidConfigThrottleFieldCount.selector);
        v1.verifyConfig(configProof, bytes32(0), "");
    }

    /// @dev Proof passes lines 219, 224, and 231 (7-item throttles), but the trust anchor
    ///      RLP list has 2 fields instead of 3 → line 261 reverts.
    function test_verifyConfig_reverts_trustAnchorWrongFieldCount() public {
        QBFTVerifier v1 = _qbftVerifier(1);
        bytes[] memory throttleItems = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            throttleItems[i] = hex"80";
        }

        bytes[] memory taItems = new bytes[](2);
        taItems[0] = hex"80";
        taItems[1] = hex"80";
        bytes memory trustAnchorBytes = RLP.encode(RLP.encode(taItems));

        bytes memory configProof = _buildConfigProofWith(RLP.encode(throttleItems), trustAnchorBytes);

        vm.expectRevert(QBFTVerifier.InvalidTrustAnchorFields.selector);
        v1.verifyConfig(configProof, bytes32(0), "");
    }

    /// @dev A 7-item throttle list carries the endpoint-limit throttles at slots 5 and 6
    ///      (maxLocalEndpoints, maxPeerEndpoints); verifyConfig must read them into
    ///      peerThrottles rather than defaulting to 0.
    function test_verifyConfig_reads7FieldThrottles_endpointLimits() public {
        QBFTVerifier v1 = _qbftVerifier(1);
        bytes[] memory throttleItems = new bytes[](7);
        for (uint256 i = 0; i < 5; i++) {
            throttleItems[i] = hex"80"; // core throttles = 0
        }
        throttleItems[5] = RLP.encode(uint256(11)); // maxLocalEndpoints
        throttleItems[6] = RLP.encode(uint256(22)); // maxPeerEndpoints

        // Valid 3-field trust anchor: [validator, service, codeHash].
        bytes[] memory taItems = new bytes[](3);
        taItems[0] = RLP.encode(validatorAddr);
        taItems[1] = RLP.encode(new bytes(0));
        taItems[2] = RLP.encode(bytes32(0));
        bytes memory trustAnchorBytes = RLP.encode(RLP.encode(taItems));

        bytes memory configProof = _buildConfigProofWith(RLP.encode(throttleItems), trustAnchorBytes);
        (,,,, ClprTypes.Throttles memory throttles,,,) = v1.verifyConfig(configProof, bytes32(0), "");
        assertEq(throttles.maxLocalEndpoints, 11);
        assertEq(throttles.maxPeerEndpoints, 22);
    }

    /// @dev A throttle list that is neither 5 nor 7 entries (here 6) must revert.
    function test_verifyConfig_reverts_sixFieldThrottles() public {
        QBFTVerifier v1 = _qbftVerifier(1);
        bytes[] memory throttleItems = new bytes[](6);
        for (uint256 i = 0; i < 6; i++) {
            throttleItems[i] = hex"80";
        }
        bytes memory configProof = _buildConfigProofWith(RLP.encode(throttleItems), RLP.encode(new bytes(0)));

        vm.expectRevert(QBFTVerifier.InvalidConfigThrottleFieldCount.selector);
        v1.verifyConfig(configProof, bytes32(0), "");
    }

    function _validSevenThrottles() private pure returns (bytes memory) {
        bytes[] memory throttleItems = new bytes[](7);
        for (uint256 i = 0; i < 7; i++) {
            throttleItems[i] = hex"80";
        }
        return RLP.encode(throttleItems);
    }

    /// @dev A config-time endpoint-manifest proof that is not the 4-field RLP shape must revert.
    function test_verifyConfig_manifestProof_wrongFieldCount_reverts() public {
        QBFTVerifier v1 = _qbftVerifier(1);
        bytes memory configProof = _buildConfigProofWith(_validSevenThrottles(), RLP.encode(new bytes(0)));

        bytes[] memory manifestProof = new bytes[](3); // must be 4
        manifestProof[0] = RLP.encode(new bytes(0));
        manifestProof[1] = RLP.encode(new bytes(0));
        manifestProof[2] = RLP.encode(new bytes(0));

        vm.expectRevert(QBFTVerifier.InvalidProofPayloadShape.selector);
        v1.verifyConfig(configProof, bytes32(0), RLP.encode(manifestProof));
    }

    /// @dev A 4-field manifest proof whose header list is too short must revert.
    function test_verifyConfig_manifestProof_shortHeader_reverts() public {
        QBFTVerifier v1 = _qbftVerifier(1);
        bytes memory configProof = _buildConfigProofWith(_validSevenThrottles(), RLP.encode(new bytes(0)));

        bytes[] memory shortHeader = new bytes[](2); // < MIN_BLOCK_HEADER_FIELDS
        shortHeader[0] = RLP.encode(bytes32(0));
        shortHeader[1] = RLP.encode(bytes32(0));
        bytes[] memory manifestProof = new bytes[](4);
        manifestProof[0] = RLP.encode(shortHeader);
        manifestProof[1] = RLP.encode(new bytes(0));
        manifestProof[2] = RLP.encode(new bytes(0));
        manifestProof[3] = RLP.encode(new bytes(0));

        vm.expectRevert(QBFTVerifier.InvalidConfigHeader.selector);
        v1.verifyConfig(configProof, bytes32(0), RLP.encode(manifestProof));
    }

    /// @dev A sealed manifest proof whose config serviceAddress is not 20 bytes reaches the
    ///      `_toAddress` length guard.
    function test_verifyConfig_manifestProof_badServiceAddressLength_reverts() public {
        QBFTVerifier v1 = _qbftVerifier(1);

        // Config proof identical to _buildConfigProofWith but with a 5-byte serviceAddress.
        bytes[] memory proof = new bytes[](10);
        proof[0] = RLP.encode(validatorAddr);
        proof[1] = RLP.encode(bytes(hex"0102030405")); // serviceAddress: wrong length
        proof[2] = RLP.encode(bytes32(0));
        proof[3] = RLP.encode(bytes("eip155:1"));
        proof[4] = RLP.encode(uint256(0));
        proof[5] = _validSevenThrottles();
        proof[6] = RLP.encode(new bytes(0));
        proof[7] = RLP.encode(new bytes(0));
        proof[8] = _buildSealedCurrentHeader(0, bytes32(0), VALIDATOR_PK);
        proof[9] = RLP.encode(uint256(30000));

        bytes[] memory manifestProof = new bytes[](4);
        manifestProof[0] = _buildSealedCurrentHeader(0, bytes32(0), VALIDATOR_PK);
        manifestProof[1] = RLP.encode(new bytes(0));
        manifestProof[2] = RLP.encode(new bytes(0));
        manifestProof[3] = RLP.encode(new bytes(0));

        vm.expectRevert(ClprEvmBundleVerifier.InvalidServiceAddressLength.selector);
        v1.verifyConfig(RLP.encode(proof), bytes32(0), RLP.encode(manifestProof));
    }

    /// @dev Full verifyConfig success using the synthetic proof builder.
    ///      Covers the pass-branches of all four require statements (lines 219, 224, 231, 261).
    function test_verifyConfig_synthetic_success() public {
        bytes memory configProof =
            _buildSyntheticConfigProof(VALIDATOR_PK, SERVICE_ADDR, SERVICE_CODE_HASH, "eip155:1", 30000);

        (
            bytes memory channelContext,
            string memory chainId,
            bytes memory serviceAddress,
            uint96 peerConfigNanos,
            ClprTypes.Throttles memory throttles,
            bytes memory initialTrustAnchor,
            bytes memory initialTrustAnchorId,
        ) = _qbftVerifier(1).verifyConfig(configProof, SYNTHETIC_CHANNEL_ID, "");

        assertEq(chainId, "eip155:1");
        assertEq(serviceAddress, abi.encodePacked(SERVICE_ADDR));
        assertEq(peerConfigNanos, 0);
        assertEq(throttles.maxMessagesPerBundle, 0);
        assertGt(initialTrustAnchor.length, 0);
        assertEq(initialTrustAnchorId, abi.encodePacked(uint64(0)));

        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        assertEq(ctx.channelId, SYNTHETIC_CHANNEL_ID);
        assertEq(ctx.remoteServiceAddress, abi.encodePacked(SERVICE_ADDR));
    }

    // ════════════════════════════════════════════════════════════════════════
    //   Trust-anchor rotation
    // ════════════════════════════════════════════════════════════════════════

    /// @dev No epoch headers in the proof → newTrustAnchor must be empty.
    function test_trustAnchorRotation_noRotation_returnsEmpty() public {
        QBFTVerifier v1 = _qbftVerifier(1);

        (bytes32 storageRoot, bytes memory storageProofRlp) = _buildChannelStorageProof(SYNTHETIC_CHANNEL_ID);
        (bytes32 stateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        bytes memory header = _buildSealedCurrentHeader(1, stateRoot, VALIDATOR_PK);

        bytes[] memory top = new bytes[](5);
        top[0] = header;
        top[1] = hex"c0"; // empty epoch headers — no rotation
        top[2] = accountProofRlp;
        top[3] = storageProofRlp;
        top[4] = RLP.encode(new bytes(0));

        (,, bytes memory newTrustAnchor,,) =
            v1.verifyBundle(RLP.encode(top), _syntheticTrustAnchor(), _syntheticChannelContext());

        assertEq(newTrustAnchor.length, 0);
    }

    // ════════════════════════════════════════════════════════════════════════
    //   verifyBundle — synthetic MPT proof paths
    // ════════════════════════════════════════════════════════════════════════

    /// @dev verifyAccount succeeds but returns a codeHash that differs from the trust-anchor
    ///      expectedCodeHash → CodeHashMismatch.
    function test_revertWhen_CodeHashMismatch() public {
        QBFTVerifier v1 = _qbftVerifier(1);
        bytes32 wrongCodeHash = bytes32(uint256(0xBAD));
        (bytes32 stateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, bytes32(0), wrongCodeHash);

        bytes memory header = _buildSealedCurrentHeader(1, stateRoot, VALIDATOR_PK);

        bytes[] memory top = new bytes[](5);
        top[0] = header;
        top[1] = hex"c0";
        top[2] = accountProofRlp;
        top[3] = hex"c0";
        top[4] = RLP.encode(new bytes(0));

        vm.expectRevert(ClprEvmBundleVerifier.CodeHashMismatch.selector);
        v1.verifyBundle(RLP.encode(top), _syntheticTrustAnchor(), _syntheticChannelContext());
    }

    /// @dev verifyAccount succeeds and codeHash matches, but the storage list has 3 entries
    ///      (neither 4 nor 5) → InvalidStorageProofShape.
    function test_revertWhen_StorageCountWrong() public {
        QBFTVerifier v1 = _qbftVerifier(1);
        (bytes32 stateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, bytes32(0), SERVICE_CODE_HASH);

        bytes memory header = _buildSealedCurrentHeader(1, stateRoot, VALIDATOR_PK);

        bytes[] memory storageItems = new bytes[](3);
        storageItems[0] = hex"80";
        storageItems[1] = hex"80";
        storageItems[2] = hex"80";

        bytes[] memory top = new bytes[](5);
        top[0] = header;
        top[1] = hex"c0";
        top[2] = accountProofRlp;
        top[3] = RLP.encode(storageItems);
        top[4] = RLP.encode(new bytes(0));

        vm.expectRevert(ClprEvmBundleVerifier.InvalidStorageProofShape.selector);
        v1.verifyBundle(RLP.encode(top), _syntheticTrustAnchor(), _syntheticChannelContext());
    }

    /// @dev One epoch header advances the trust anchor to a new validator; the current header
    ///      is in epoch 1 and signed by that new validator. verifyBundle must return a non-empty
    ///      newTrustAnchor encoding the new validator and epoch number 1.
    function test_trustAnchorRotation_withRotation_updatesAnchor() public {
        QBFTVerifier v1 = _qbftVerifier(1);
        uint256 nextValidatorPk = uint256(keccak256("next-validator"));
        address nextValidatorAddr = vm.addr(nextValidatorPk);

        // Epoch header at block 30000: signed by VALIDATOR_PK, announces nextValidatorAddr.
        bytes memory epochHeader = _buildSignedEpochHeader(GENESIS_EPOCH_LENGTH, nextValidatorAddr, VALIDATOR_PK);
        bytes[] memory epochList = new bytes[](1);
        epochList[0] = epochHeader;

        // Synthetic storage proof: 4 channel metadata slots; channelId comes from ChannelContext.
        (bytes32 storageRoot, bytes memory storageProofRlp) = _buildChannelStorageProof(SYNTHETIC_CHANNEL_ID);

        // Synthetic account proof for SERVICE_ADDR with SERVICE_CODE_HASH and the storage root.
        (bytes32 stateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);

        // Current header at block 30001 (epoch 1), signed by the new validator.
        bytes memory header = _buildSealedCurrentHeader(30001, stateRoot, nextValidatorPk);

        bytes[] memory top = new bytes[](5);
        top[0] = header;
        top[1] = RLP.encode(epochList);
        top[2] = accountProofRlp;
        top[3] = storageProofRlp;
        top[4] = RLP.encode(new bytes(0));

        (,, bytes memory newTrustAnchor, bytes memory newTrustAnchorId,) =
            v1.verifyBundle(RLP.encode(top), _syntheticTrustAnchor(), _syntheticChannelContext());

        bytes memory expectedAnchor = abi.encode(nextValidatorAddr, SERVICE_CODE_HASH, GENESIS_EPOCH_LENGTH, uint64(1));
        assertEq(newTrustAnchor, expectedAnchor);
        assertEq(newTrustAnchorId, abi.encodePacked(uint64(1)));
    }

    // Channel 1 cannot submit a storage proof built for channel 2's slots.
    // The verifier derives expected slot keys from ChannelContext's channelId, so
    // a proof carrying the wrong channel's slots is rejected with SlotNotProven.
    function test_revertWhen_StorageProofIsForDifferentChannel() public {
        QBFTVerifier v1 = _qbftVerifier(1);
        bytes32 attackerConnId = bytes32(uint256(0xDEADBEEF));

        // Proof built honestly for SYNTHETIC_CHANNEL_ID (the "victim" channel)
        (bytes32 storageRoot, bytes memory storageProofRlp) = _buildChannelStorageProof(SYNTHETIC_CHANNEL_ID);

        (bytes32 stateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);

        bytes memory header = _buildSealedCurrentHeader(1, stateRoot, VALIDATOR_PK);

        bytes[] memory top = new bytes[](5);
        top[0] = header;
        top[1] = hex"c0";
        top[2] = accountProofRlp;
        top[3] = storageProofRlp;
        top[4] = RLP.encode(new bytes(0));

        // ChannelContext claims this bundle is for attackerConnId — verifier derives
        // attackerConnId's storage slots and finds none of them in the proof.
        bytes memory attackerContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: attackerConnId, remoteServiceAddress: abi.encodePacked(SERVICE_ADDR)})
        );

        bytes32 expectedMissingSlot = bytes32(uint256(keccak256(abi.encode(attackerConnId, uint256(15)))) + 1);

        vm.expectRevert(abi.encodeWithSelector(ClprEvmStateProof.SlotNotProven.selector, expectedMissingSlot));
        v1.verifyBundle(RLP.encode(top), _syntheticTrustAnchor(), attackerContext);
    }
    // ════════════════════════════════════════════════════════════════════════
    //   Endpoint-manifest proofs — verifyBundle (7-field shape) and verifyConfig
    // ════════════════════════════════════════════════════════════════════════

    /// @dev Manifest commitment slot: `EndpointManifestState.commitment` at absolute slot 18
    ///      (= ClprEvmBundleVerifier.ENDPOINT_MANIFEST_COMMITMENT_SLOT; pinned by
    ///      ClprStorageLayoutGuard.test_manifestCommitmentMemberSlotMatchesLayout).
    uint256 internal constant MANIFEST_COMMITMENT_SLOT = 18;

    function _manifestPreimage(bytes memory serviceAddress) internal pure returns (bytes memory) {
        ClprTypes.Endpoint[] memory eps = new ClprTypes.Endpoint[](1);
        eps[0] = ClprTypes.Endpoint({ipAddress: "10.9.9.9", port: 50211, tlsCertificate: hex"DD", accountId: hex"0A"});
        return ClprProtobuf.encodeEndpointManifest(
            ClprTypes.ClprEndpointManifest({version: 3, serviceAddress: serviceAddress, endpoints: eps})
        );
    }

    /// @dev Storage trie anchored at the manifest-commitment slot with keccak256(preimage);
    ///      the five channel slots diverge in the same trie and prove zero.
    function _manifestAnchoredStorage(bytes memory preimage)
        internal
        pure
        returns (bytes32 storageRoot, bytes memory connStorageProofRlp, bytes memory manifestStorageProofRlp)
    {
        bytes memory proofNodesRlp;
        (storageRoot, proofNodesRlp) = _buildSyntheticMPTProof(
            keccak256(abi.encodePacked(bytes32(MANIFEST_COMMITMENT_SLOT))), RLP.encode(uint256(keccak256(preimage)))
        );

        bytes32 cBase = keccak256(abi.encode(SYNTHETIC_CHANNEL_ID, uint256(15)));
        uint8[5] memory offsets = [1, 2, 4, 5, 16];
        bytes[] memory connEntries = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            bytes[] memory entry = new bytes[](2);
            entry[0] = RLP.encode(abi.encodePacked(bytes32(uint256(cBase) + offsets[i])));
            entry[1] = proofNodesRlp;
            connEntries[i] = RLP.encode(entry);
        }
        connStorageProofRlp = RLP.encode(connEntries);

        bytes[] memory manifestEntries = new bytes[](1);
        bytes[] memory mEntry = new bytes[](2);
        mEntry[0] = RLP.encode(abi.encodePacked(bytes32(MANIFEST_COMMITMENT_SLOT)));
        mEntry[1] = proofNodesRlp;
        manifestEntries[0] = RLP.encode(mEntry);
        manifestStorageProofRlp = RLP.encode(manifestEntries);
    }

    function _manifestBundlePayload(bytes memory preimage) internal pure returns (bytes memory) {
        (bytes32 storageRoot, bytes memory connStorageProofRlp, bytes memory manifestStorageProofRlp) =
            _manifestAnchoredStorage(preimage);
        (bytes32 stateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        bytes memory header = _buildSealedCurrentHeader(1, stateRoot, VALIDATOR_PK);

        bytes[] memory top = new bytes[](7);
        top[0] = header;
        top[1] = hex"c0";
        top[2] = accountProofRlp;
        top[3] = connStorageProofRlp;
        top[4] = RLP.encode(new bytes(0));
        top[5] = manifestStorageProofRlp;
        top[6] = RLP.encode(preimage);
        return RLP.encode(top);
    }

    function test_verifyBundle_manifestProof_returnedAndBound() public {
        QBFTVerifier v1 = _qbftVerifier(1);
        bytes memory preimage = _manifestPreimage(abi.encodePacked(SERVICE_ADDR));

        (,,,, ClprTypes.ClprEndpointManifest memory newManifest) =
            v1.verifyBundle(_manifestBundlePayload(preimage), _syntheticTrustAnchor(), _syntheticChannelContext());

        assertEq(newManifest.version, 3, "manifest version");
        assertEq(newManifest.endpoints.length, 1, "manifest endpoints");
        assertEq(
            keccak256(newManifest.serviceAddress), keccak256(abi.encodePacked(SERVICE_ADDR)), "manifest svc address"
        );
    }

    /// @dev Spec (IClprVerifier): MUST revert when manifest.service_address does not match
    ///      ctx.service_address.
    function test_verifyBundle_manifestServiceAddressMismatch_reverts() public {
        QBFTVerifier v1 = _qbftVerifier(1);
        bytes memory preimage = _manifestPreimage(hex"BEEF"); // committed, but wrong service address

        vm.expectRevert(ClprEvmBundleVerifier.ManifestServiceAddressMismatch.selector);
        v1.verifyBundle(_manifestBundlePayload(preimage), _syntheticTrustAnchor(), _syntheticChannelContext());
    }

    /// @dev Spec (IClprVerifier): MUST revert when the manifest version is 0, even if the
    ///      preimage matches the proven commitment.
    function test_verifyBundle_manifestVersionZero_reverts() public {
        QBFTVerifier v1 = _qbftVerifier(1);
        bytes memory preimage = ClprProtobuf.encodeEndpointManifest(
            ClprTypes.ClprEndpointManifest({
                version: 0, serviceAddress: abi.encodePacked(SERVICE_ADDR), endpoints: new ClprTypes.Endpoint[](0)
            })
        );

        vm.expectRevert(ClprEvmBundleVerifier.ManifestVersionZero.selector);
        v1.verifyBundle(_manifestBundlePayload(preimage), _syntheticTrustAnchor(), _syntheticChannelContext());
    }

    /// @dev Spec (IClprVerifier): MUST revert when proof verification fails — here the supplied
    ///      preimage does not hash to the proven on-ledger commitment.
    function test_verifyBundle_manifestCommitmentMismatch_reverts() public {
        QBFTVerifier v1 = _qbftVerifier(1);
        bytes memory committed = _manifestPreimage(abi.encodePacked(SERVICE_ADDR));

        // Prove `committed`'s commitment but supply a DIFFERENT preimage.
        (bytes32 storageRoot, bytes memory connStorageProofRlp, bytes memory manifestStorageProofRlp) =
            _manifestAnchoredStorage(committed);
        (bytes32 stateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);

        bytes[] memory top = new bytes[](7);
        top[0] = _buildSealedCurrentHeader(1, stateRoot, VALIDATOR_PK);
        top[1] = hex"c0";
        top[2] = accountProofRlp;
        top[3] = connStorageProofRlp;
        top[4] = RLP.encode(new bytes(0));
        top[5] = manifestStorageProofRlp;
        top[6] = RLP.encode(bytes(hex"DEAD"));

        vm.expectRevert(ClprEvmBundleVerifier.ManifestCommitmentMismatch.selector);
        v1.verifyBundle(RLP.encode(top), _syntheticTrustAnchor(), _syntheticChannelContext());
    }

    // ── verifyConfig — manifest proof cryptographic binding ─────────────────

    /// @dev A valid config proof whose serviceAddr is SERVICE_ADDR, so the manifest binds to it.
    function _configProofForManifest() internal view returns (bytes memory) {
        bytes[] memory proof = new bytes[](10);
        proof[0] = RLP.encode(validatorAddr);
        proof[1] = RLP.encode(abi.encodePacked(SERVICE_ADDR));
        proof[2] = RLP.encode(bytes32(0));
        proof[3] = RLP.encode(bytes("eip155:1"));
        proof[4] = RLP.encode(uint256(0));
        bytes[] memory throttleItems = new bytes[](7);
        for (uint256 i = 0; i < 7; i++) {
            throttleItems[i] = hex"80";
        }
        proof[5] = RLP.encode(throttleItems);
        // Valid 3-field RLP trust anchor: [validator, service, codeHash].
        bytes[] memory taItems = new bytes[](3);
        taItems[0] = RLP.encode(validatorAddr);
        taItems[1] = RLP.encode(abi.encodePacked(SERVICE_ADDR));
        taItems[2] = RLP.encode(SERVICE_CODE_HASH);
        proof[6] = RLP.encode(RLP.encode(taItems));
        proof[7] = RLP.encode(new bytes(0));
        proof[8] = _buildSealedCurrentHeader(0, bytes32(0), VALIDATOR_PK);
        proof[9] = RLP.encode(uint256(30000));
        return RLP.encode(proof);
    }

    /// @dev Build the 4-field config-time manifest proof: RLP([sealedHeader, accountProof,
    ///      manifestStorageProof, manifestPreimage]), sealed by `sealerPk`.
    function _configManifestProof(bytes memory preimage, uint256 sealerPk) internal pure returns (bytes memory) {
        (bytes32 storageRoot,, bytes memory manifestStorageProofRlp) = _manifestAnchoredStorage(preimage);
        (bytes32 stateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);

        bytes[] memory p = new bytes[](4);
        p[0] = _buildSealedCurrentHeader(0, stateRoot, sealerPk);
        p[1] = accountProofRlp;
        p[2] = manifestStorageProofRlp;
        p[3] = RLP.encode(preimage);
        return RLP.encode(p);
    }

    /// @dev Happy path: the manifest proof is authenticated against the SAME validator the config
    ///      proof establishes as the initial trust anchor, then bound and returned.
    function test_verifyConfig_manifestProof_verifiedAndReturned() public {
        QBFTVerifier v1 = _qbftVerifier(1);
        bytes memory preimage = _manifestPreimage(abi.encodePacked(SERVICE_ADDR));

        (,,,,,,, ClprTypes.ClprEndpointManifest memory manifest) =
            v1.verifyConfig(_configProofForManifest(), bytes32(0), _configManifestProof(preimage, VALIDATOR_PK));

        assertEq(manifest.version, 3, "manifest version");
        assertEq(manifest.endpoints.length, 1, "manifest endpoints");
    }

    /// @dev Cryptographic binding: a manifest proof whose header is sealed by a DIFFERENT
    ///      validator than the config's trust anchor must revert — the manifest MUST be
    ///      verifiable against the same trust anchor verifyConfig establishes.
    function test_verifyConfig_manifestProof_sealedByWrongValidator_reverts() public {
        QBFTVerifier v1 = _qbftVerifier(1);
        bytes memory preimage = _manifestPreimage(abi.encodePacked(SERVICE_ADDR));
        uint256 roguePk = uint256(keccak256("qbft-rogue-validator"));

        vm.expectRevert();
        v1.verifyConfig(_configProofForManifest(), bytes32(0), _configManifestProof(preimage, roguePk));
    }

    /// @dev Cryptographic binding: a manifest storage proof built against a DIFFERENT state root
    ///      (the sealed header commits to another trie) must revert — a wrong Merkle path cannot
    ///      bind the manifest to the proven state.
    function test_verifyConfig_manifestProof_wrongStateRoot_reverts() public {
        QBFTVerifier v1 = _qbftVerifier(1);
        bytes memory preimage = _manifestPreimage(abi.encodePacked(SERVICE_ADDR));

        // Storage proof for `preimage`, but the header seals an account proof anchored to a
        // DIFFERENT storage root, so the manifest slot cannot be proven against it.
        (bytes32 otherRoot,,) = _manifestAnchoredStorage(_manifestPreimage(hex"1234"));
        (,, bytes memory manifestStorageProofRlp) = _manifestAnchoredStorage(preimage);
        (bytes32 stateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, otherRoot, SERVICE_CODE_HASH);

        bytes[] memory p = new bytes[](4);
        p[0] = _buildSealedCurrentHeader(0, stateRoot, VALIDATOR_PK);
        p[1] = accountProofRlp;
        p[2] = manifestStorageProofRlp;
        p[3] = RLP.encode(preimage);

        vm.expectRevert();
        v1.verifyConfig(_configProofForManifest(), bytes32(0), RLP.encode(p));
    }
}
