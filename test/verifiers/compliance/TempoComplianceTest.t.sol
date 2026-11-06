// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmStorageComplianceTest} from "@test/verifiers/compliance/ClprEvmStorageComplianceTest.sol";
import {TempoSyntheticProofs} from "@test/helpers/TempoSyntheticProofs.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {TempoVerifier} from "@hiero-ledger/clpr/verifiers/evm/tempo/TempoVerifier.sol";
import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title TempoComplianceTest
/// @notice ClprVerifierComplianceTest adapter for TempoVerifier. A precompile-built BLS key certifies the headers.
contract TempoComplianceTest is ClprEvmStorageComplianceTest, TempoSyntheticProofs {
    uint64 internal constant L = 100;
    address internal constant SERVICE_ADDR = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;
    bytes32 internal constant SERVICE_CODE_HASH = bytes32(uint256(0xC0DE));
    bytes32 internal constant SYNTHETIC_CHANNEL_ID = bytes32(uint256(0xC0FFEE));

    uint256 internal sk;
    bytes internal pk;

    function _deployVerifier() internal override returns (IClprVerifier) {
        sk = _testKey("tempo-compliance");
        pk = _blsPublicKey(sk);
        return IClprVerifier(new TempoVerifier());
    }

    function _validConfig() internal view override returns (ConfigVector memory) {
        return ConfigVector({
            configProof: _configProofAt(0, sk, pk, "eip155:4217"),
            channelId: SYNTHETIC_CHANNEL_ID,
            expectedChainId: "eip155:4217",
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
        bytes memory attackerContext = _tempoChannelContext(attackerConnId, SERVICE_ADDR);
        bytes32 expectedMissingSlot = bytes32(uint256(keccak256(abi.encode(attackerConnId, uint256(15)))) + 1);
        return (
            _buildValidBundleProof(),
            _validTrustAnchor(),
            attackerContext,
            abi.encodeWithSelector(ClprEvmStateProof.SlotNotProven.selector, expectedMissingSlot)
        );
    }

    /// @dev Config-time manifest proof with a header certified under the identity.
    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        view
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        configProof = _configProofAt(0, sk, pk, "eip155:4217");
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

        bytes memory header = _tempoHeader(1, stateRoot, "", true);
        manifestProof = _configManifestProofItem(
            header, _certify(sk, L, header, 1, 5), accountProofRlp, RLP.encode(entries), carriedPreimage
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

    /// @dev A different chain is a different group key: the header is certified by another key.
    function _wrongChainConfigVector() internal view override returns (bytes memory, bytes32) {
        return (_configProofAt(0, _testKey("different-network"), pk, "eip155:999"), SYNTHETIC_CHANNEL_ID);
    }

    /// @dev A 6-item config proof, the header removed.
    function _partialSlotCoverageVector() internal view override returns (bytes memory, bytes32) {
        bytes memory full = _configProofAt(0, sk, pk, "eip155:4217");
        Memory.Slice[] memory items = RLP.decodeList(full);
        bytes[] memory six = new bytes[](6);
        for (uint256 i = 0; i < 6; i++) {
            six[i] = Memory.toBytes(items[i]);
        }
        return (RLP.encode(six), SYNTHETIC_CHANNEL_ID);
    }

    function _wrongServiceAddressVector() internal view override returns (bytes memory, bytes memory, bytes memory) {
        address differentService = address(uint160(uint256(keccak256("different-service"))));
        return
            (
                _buildValidBundleProof(),
                _validTrustAnchor(),
                _tempoChannelContext(SYNTHETIC_CHANNEL_ID, differentService)
            );
    }

    function _threeSlotStorageVector() internal view override returns (bytes memory, bytes memory, bytes memory) {
        uint8[3] memory offsets = [1, 2, 4];
        bytes32[] memory slotOffsets = new bytes32[](3);
        for (uint256 i = 0; i < 3; i++) {
            slotOffsets[i] = bytes32(uint256(offsets[i]));
        }
        return _bundleWithSlotOffsets(slotOffsets);
    }

    function _wrongSlotIndexVector() internal view override returns (bytes memory, bytes memory, bytes memory) {
        uint8[5] memory offsets = [1, 2, 3, 5, 16];
        bytes32[] memory slotOffsets = new bytes32[](5);
        for (uint256 i = 0; i < 5; i++) {
            slotOffsets[i] = bytes32(uint256(offsets[i]));
        }
        return _bundleWithSlotOffsets(slotOffsets);
    }

    // ── Tempo proof assembly ────────────────────────────────────────────────

    function _configProofAt(uint64 number, uint256 signer, bytes memory identity, string memory chainId)
        private
        view
        returns (bytes memory)
    {
        ConfigParts memory parts;
        parts.service = SERVICE_ADDR;
        parts.chainId = chainId;
        parts.codeHash = SERVICE_CODE_HASH;
        parts.epochLength = L;
        parts.keyCompressed = ClprBls12381.compressG2(identity);
        parts.keyUncompressed = identity;
        parts.header = _tempoHeader(number, bytes32(0), "", true);
        parts.cert = _certify(signer, L, parts.header, number, 5);
        parts.throttles = _defaultThrottles();
        return _encodeConfigProof(parts);
    }

    /// @dev A bundle at block 1 with 5 channel slots and no rotations.
    function _buildValidBundleProof() private view returns (bytes memory) {
        (bytes32 storageRoot, bytes memory storageProofRlp) = _buildChannelStorageProof(SYNTHETIC_CHANNEL_ID);
        (bytes32 stateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        return _top(stateRoot, accountProofRlp, storageProofRlp, new bytes(0));
    }

    function _top(bytes32 stateRoot, bytes memory accountProofRlp, bytes memory storageProofRlp, bytes memory content)
        private
        view
        returns (bytes memory)
    {
        BundleParts memory parts;
        parts.header = _tempoHeader(1, stateRoot, "", true);
        parts.cert = _certify(sk, L, parts.header, 1, 5);
        parts.rotations = new bytes[](0);
        parts.accountProof = accountProofRlp;
        parts.storageProof = storageProofRlp;
        parts.content = content;
        return _encodeBundle(parts);
    }

    function _validTrustAnchor() private view returns (bytes memory) {
        return _tempoAnchor(SERVICE_CODE_HASH, L, 0, pk);
    }

    function _validChannelContext() private pure returns (bytes memory) {
        return _tempoChannelContext(SYNTHETIC_CHANNEL_ID, SERVICE_ADDR);
    }

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
        return (
            _top(stateRoot, accountProofRlp, RLP.encode(entries), new bytes(0)),
            _validTrustAnchor(),
            _validChannelContext()
        );
    }

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

    /// @dev Channel slots +1 (`nextMessageId`) and +4 (`sentRunningHash`) prove the given values; the
    ///      other three prove zero.
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
        return _top(stateRoot, accountProofRlp, storageEntries, bundleContent);
    }
}
