// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmStorageComplianceTest} from "@test/verifiers/compliance/ClprEvmStorageComplianceTest.sol";
import {QbftContractProofs} from "@test/helpers/QbftContractProofs.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {QbftHeaderModeVerifier} from "@hiero-ledger/clpr/verifiers/evm/qbft/QbftHeaderModeVerifier.sol";
import {ClprQbftQuorum} from "@hiero-ledger/clpr/libraries/proof/qbft/ClprQbftQuorum.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title QBFTComplianceTest
/// @notice ClprVerifierComplianceTest adapter for QbftHeaderModeVerifier.
contract QBFTComplianceTest is ClprEvmStorageComplianceTest, QbftContractProofs {
    uint256 internal constant VALIDATOR_PK = uint256(keccak256("qbft-validator"));
    address internal constant SERVICE_ADDR = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;
    bytes32 internal constant SERVICE_CODE_HASH = bytes32(uint256(0xC0DE));
    bytes32 internal constant SYNTHETIC_CHANNEL_ID = bytes32(uint256(0xC0FFEE));

    address internal validatorAddr;

    function _deployVerifier() internal override returns (IClprVerifier) {
        validatorAddr = vm.addr(VALIDATOR_PK);
        return IClprVerifier(new QbftHeaderModeVerifier());
    }

    function _validConfig() internal pure override returns (ConfigVector memory) {
        return ConfigVector({
            configProof: _buildSyntheticConfigProof(VALIDATOR_PK, SERVICE_ADDR, SERVICE_CODE_HASH, "eip155:1"),
            channelId: SYNTHETIC_CHANNEL_ID,
            expectedChainId: "eip155:1",
            expectedServiceAddress: abi.encodePacked(SERVICE_ADDR)
        });
    }

    function _validBundle() internal view override returns (BundleVector memory) {
        return BundleVector({
            proofBytes: _buildValidBundleProof(),
            trustAnchor: _validTrustAnchor(),
            channelContext: _validChannelContext(),
            expectedNextMessageId: 0,
            expectedPayloadCount: 0
        });
    }

    function _crossChannelVector()
        internal
        view
        override
        returns (bytes memory, bytes memory, bytes memory, bytes memory)
    {
        bytes32 attackerConnId = bytes32(uint256(0xDEADBEEF));
        bytes memory attackerContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: attackerConnId, remoteServiceAddress: abi.encodePacked(SERVICE_ADDR)})
        );
        // The verifier derives attackerConnId's slot +1 and finds it absent from the proof.
        bytes32 expectedMissingSlot = bytes32(uint256(keccak256(abi.encode(attackerConnId, uint256(15)))) + 1);
        return (
            _buildValidBundleProof(),
            _validTrustAnchor(),
            attackerContext,
            abi.encodeWithSelector(ClprEvmStateProof.SlotNotProven.selector, expectedMissingSlot)
        );
    }

    /// @dev The config-time manifest proof is independent of the config proof: its own sealed
    ///      header anchors an account proof for the config's service address, and the
    ///      manifest-commitment slot is proven under that account's storage root.
    ///      Shape: `RLP([sealedHeader, accountProof, manifestStorageProof, manifestPreimage])`.
    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        pure
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        configProof = _buildSyntheticConfigProof(VALIDATOR_PK, SERVICE_ADDR, SERVICE_CODE_HASH, "eip155:1");
        channelId = SYNTHETIC_CHANNEL_ID;

        bytes32 slot = bytes32(MANIFEST_COMMITMENT_SLOT);
        (bytes32 storageRoot, bytes memory proofNodes) = _buildSyntheticMPTProof(
            keccak256(abi.encodePacked(slot)), RLP.encode(uint256(keccak256(committedPreimage)))
        );

        bytes[] memory entry = new bytes[](2);
        entry[0] = RLP.encode(abi.encodePacked(slot));
        entry[1] = proofNodes;
        bytes[] memory entries = new bytes[](1);
        entries[0] = RLP.encode(entry);

        (bytes32 stateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);

        bytes[] memory p = new bytes[](4);
        p[0] = _buildSealedCurrentHeader(1, stateRoot, VALIDATOR_PK);
        p[1] = accountProofRlp;
        p[2] = RLP.encode(entries);
        p[3] = RLP.encode(carriedPreimage);
        manifestProof = RLP.encode(p);
    }

    // ── QBFT proof assembly ──────────

    /// @dev A 5-item bundle: current header listing the validator, the trusted set with no hops,
    ///      account proof and the 5-slot channel storage proof.
    function _buildValidBundleProof() private view returns (bytes memory) {
        (bytes32 storageRoot, bytes memory storageProofRlp) = _buildChannelStorageProof(SYNTHETIC_CHANNEL_ID);
        (bytes32 stateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        return _top(_buildSealedCurrentHeader(1, stateRoot, VALIDATOR_PK), accountProofRlp, storageProofRlp);
    }

    function _top(bytes memory header, bytes memory accountProofRlp, bytes memory storageProofRlp)
        private
        view
        returns (bytes memory)
    {
        bytes[] memory top = new bytes[](5);
        top[0] = header;
        top[1] = _sourceField();
        top[2] = accountProofRlp;
        top[3] = storageProofRlp;
        top[4] = RLP.encode(new bytes(0));
        return RLP.encode(top);
    }

    function _set() private view returns (address[] memory set) {
        set = new address[](1);
        set[0] = validatorAddr;
    }

    /// @dev Field 1: RLP([trustedSet, hops = []]).
    function _sourceField() private view returns (bytes memory) {
        bytes[] memory source = new bytes[](2);
        source[0] = _memberListRlp(_set());
        source[1] = RLP.encode(new bytes[](0));
        return RLP.encode(source);
    }

    function _validTrustAnchor() private view returns (bytes memory) {
        return abi.encode(uint8(0), _commit(_set()), SERVICE_CODE_HASH, uint64(0));
    }

    function _validChannelContext() private pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({
                channelId: SYNTHETIC_CHANNEL_ID, remoteServiceAddress: abi.encodePacked(SERVICE_ADDR)
            })
        );
    }

    // ── Hook implementations ─────────────────────────────────────────────────

    function _fiveSlotBundleVector(uint64 nextMessageId, bytes32 sentRunningHash, bytes memory bundleContent)
        internal
        view
        override
        returns (bytes memory, bytes memory, bytes memory)
    {
        return (
            _buildBundleProofWithSentHash(nextMessageId, sentRunningHash, bundleContent),
            _validTrustAnchor(),
            _validChannelContext()
        );
    }

    function _runningHashVector() internal view override returns (RunningHashVector memory) {
        bytes memory payload = ClprProtobuf.encodeDataMessage(hex"01", hex"02", hex"03", hex"04");
        bytes32 expectedSentRunningHash = sha256(abi.encodePacked(bytes32(0), sha256(payload)));

        bytes[] memory payloads = new bytes[](1);
        payloads[0] = payload;
        ClprTypes.QueueMetadata memory dummyMeta;
        bytes memory bundleContent = ClprProtobuf.encodeBundleContent(dummyMeta, payloads);

        return RunningHashVector({
            proofBytes: _buildBundleProofWithSentHash(
                ONE_MESSAGE_NEXT_MESSAGE_ID, expectedSentRunningHash, bundleContent
            ),
            trustAnchor: _validTrustAnchor(),
            channelContext: _validChannelContext(),
            previousRunningHash: bytes32(0)
        });
    }

    /// @dev For QBFT the network identity is the validator set that seals the config header. A header
    ///      that lists our validator but is sealed by someone else is the QBFT realization of "proof
    ///      from a different chain": its own list did not seal it.
    function _wrongChainConfigVector() internal pure override returns (bytes memory, bytes32) {
        address[] memory listed = new address[](1);
        listed[0] = vm.addr(VALIDATOR_PK);
        uint256[] memory foreignSealer = new uint256[](1);
        foreignSealer[0] = uint256(keccak256("different-network-validator"));
        bytes memory header = _buildListedSealedHeader(0, bytes32(0), listed, foreignSealer);
        return
            (_buildHeaderModeConfigProof(header, SERVICE_ADDR, SERVICE_CODE_HASH, "eip155:999"), SYNTHETIC_CHANNEL_ID);
    }

    /// @dev verifyConfig requires exactly 6 RLP items; a 5-item proof (block header absent) is the
    ///      QBFT realization of "partial field coverage."
    function _partialSlotCoverageVector() internal pure override returns (bytes memory, bytes32) {
        bytes memory full = _buildSyntheticConfigProof(VALIDATOR_PK, SERVICE_ADDR, SERVICE_CODE_HASH, "eip155:1");
        Memory.Slice[] memory items = RLP.decodeList(full);
        bytes[] memory five = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            five[i] = Memory.toBytes(items[i]);
        }
        return (RLP.encode(five), SYNTHETIC_CHANNEL_ID);
    }

    function _wrongServiceAddressVector() internal view override returns (bytes memory, bytes memory, bytes memory) {
        address differentService = address(uint160(uint256(keccak256("different-service"))));
        bytes memory wrongContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({
                channelId: SYNTHETIC_CHANNEL_ID, remoteServiceAddress: abi.encodePacked(differentService)
            })
        );
        return (_buildValidBundleProof(), _validTrustAnchor(), wrongContext);
    }

    /// @dev 3-entry storage proof: offsets [+1, +2, +4] — the remaining required slots absent.
    ///      The verifier requires exactly 5 or 6 entries; 3 triggers InvalidStorageProofShape.
    function _threeSlotStorageVector() internal view override returns (bytes memory, bytes memory, bytes memory) {
        uint8[3] memory offsets = [1, 2, 4];
        bytes32[] memory slotOffsets = new bytes32[](3);
        for (uint256 i = 0; i < 3; i++) {
            slotOffsets[i] = bytes32(uint256(offsets[i]));
        }
        return _bundleWithSlotOffsets(slotOffsets);
    }

    /// @dev 5-entry storage proof with offsets [+1, +2, +3, +5, +16] — uses cBase+3 instead of
    ///      cBase+4 (sentRunningHash slot). The verifier derives cBase+4 from the layout and cannot
    ///      find it in the proof, so it reverts with SlotNotProven(cBase+4).
    function _wrongSlotIndexVector() internal view override returns (bytes memory, bytes memory, bytes memory) {
        uint8[5] memory offsets = [1, 2, 3, 5, 16];
        bytes32[] memory slotOffsets = new bytes32[](5);
        for (uint256 i = 0; i < 5; i++) {
            slotOffsets[i] = bytes32(uint256(offsets[i]));
        }
        return _bundleWithSlotOffsets(slotOffsets);
    }

    /// @dev A bundle whose storage proof carries one entry per `slotOffsets[i]` from the channel
    ///      base, all pointing at a one-leaf trie keyed at slot +1.
    function _bundleWithSlotOffsets(bytes32[] memory slotOffsets)
        private
        view
        returns (bytes memory, bytes memory, bytes memory)
    {
        bytes32 cBase = keccak256(abi.encode(SYNTHETIC_CHANNEL_ID, uint256(15)));
        (bytes32 storageRoot, bytes memory proofNodesRlp) =
            _buildSyntheticMPTProof(keccak256(abi.encodePacked(bytes32(uint256(cBase) + 1))), RLP.encode(uint256(0)));

        bytes[] memory entries = new bytes[](slotOffsets.length);
        for (uint256 i = 0; i < slotOffsets.length; i++) {
            bytes[] memory entry = new bytes[](2);
            entry[0] = RLP.encode(abi.encodePacked(bytes32(uint256(cBase) + uint256(slotOffsets[i]))));
            entry[1] = proofNodesRlp;
            entries[i] = RLP.encode(entry);
        }

        (bytes32 stateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        bytes memory header = _buildSealedCurrentHeader(1, stateRoot, VALIDATOR_PK);
        return (_top(header, accountProofRlp, RLP.encode(entries)), _validTrustAnchor(), _validChannelContext());
    }

    /// @dev Build a bundle proof where Channel slot +4 (`sentRunningHash`) proves `sentHash`; the
    ///      other four channel slots diverge in the one-leaf trie and prove zero.
    function _buildBundleProofWithSentHash(uint64 nextMessageId, bytes32 sentHash, bytes memory bundleContent)
        private
        view
        returns (bytes memory)
    {
        bytes32 cBase = keccak256(abi.encode(SYNTHETIC_CHANNEL_ID, uint256(15)));
        (bytes32 storageRoot, bytes memory storageEntries) =
            _buildChannelStorageEntriesWithSentHash(cBase, nextMessageId, sentHash);

        (bytes32 stateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);

        bytes[] memory top = new bytes[](5);
        top[0] = _buildSealedCurrentHeader(1, stateRoot, VALIDATOR_PK);
        top[1] = _sourceField();
        top[2] = accountProofRlp;
        top[3] = storageEntries;
        top[4] = RLP.encode(bundleContent);
        return RLP.encode(top);
    }
}
