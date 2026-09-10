// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmStorageComplianceTest} from "@test/verifiers/compliance/ClprEvmStorageComplianceTest.sol";
import {QbftContractProofs} from "@test/helpers/QbftContractProofs.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @title QbftContractModeComplianceTest
/// @dev The ClprVerifierComplianceTest adapter (via ClprEvmStorageComplianceTest) for
///      QbftContractModeVerifier.
contract QbftContractModeComplianceTest is ClprEvmStorageComplianceTest, QbftContractProofs {
    uint256 internal constant VALIDATOR_PK = uint256(keccak256("qbft-validator"));
    address internal constant SERVICE_ADDR = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;
    bytes32 internal constant SERVICE_CODE_HASH = bytes32(uint256(0xC0DE));
    bytes32 internal constant SYNTHETIC_CHANNEL_ID = bytes32(uint256(0xC0FFEE));
    address internal constant VALIDATOR_CONTRACT = address(0xC04511AC);

    /// @dev Deploys the Header-mode {QBFTVerifier}: every vector here is Contract mode, so each
    ///      call forwards to the embedded QbftContractModeVerifier.
    function _deployVerifier() internal override returns (IClprVerifier) {
        return IClprVerifier(deployCode("QBFTVerifier.sol:QBFTVerifier", abi.encode(uint8(1))));
    }

    /// @dev The single-member trusted set the fixtures anchor on.
    function _cmSet() private pure returns (address[] memory s) {
        s = new address[](1);
        s[0] = vm.addr(VALIDATOR_PK);
    }

    function _validConfig() internal pure override returns (ConfigVector memory) {
        return ConfigVector({
            configProof: _validConfigProofBytes("eip155:1"),
            channelId: SYNTHETIC_CHANNEL_ID,
            expectedChainId: "eip155:1",
            expectedServiceAddress: abi.encodePacked(SERVICE_ADDR)
        });
    }

    function _validBundle() internal pure override returns (BundleVector memory) {
        (bytes32 svcStorageRoot, bytes memory storageProofRlp) = _buildChannelStorageProof(SYNTHETIC_CHANNEL_ID);
        return BundleVector({
            proofBytes: _cmTop(svcStorageRoot, storageProofRlp, RLP.encode(new bytes(0))),
            trustAnchor: _validTrustAnchor(),
            channelContext: _validChannelContext(),
            expectedNextMessageId: 0,
            expectedPayloadCount: 0
        });
    }

    function _crossChannelVector()
        internal
        pure
        override
        returns (bytes memory, bytes memory, bytes memory, bytes memory)
    {
        bytes32 attackerConnId = bytes32(uint256(0xDEADBEEF));
        bytes memory attackerContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: attackerConnId, remoteServiceAddress: abi.encodePacked(SERVICE_ADDR)})
        );
        // The verifier derives attackerConnId's slot +1 and finds it absent from the proof.
        bytes32 expectedMissingSlot = bytes32(uint256(keccak256(abi.encode(attackerConnId, uint256(15)))) + 1);
        (bytes32 svcStorageRoot, bytes memory storageProofRlp) = _buildChannelStorageProof(SYNTHETIC_CHANNEL_ID);
        return (
            _cmTop(svcStorageRoot, storageProofRlp, RLP.encode(new bytes(0))),
            _validTrustAnchor(),
            attackerContext,
            abi.encodeWithSelector(ClprEvmStateProof.SlotNotProven.selector, expectedMissingSlot)
        );
    }

    /// @dev The config-time manifest proof stays independent of the config proof: its own sealed
    ///      header anchors an account proof for the config's service address, and the
    ///      manifest-commitment slot is proven under that account's storage root.
    ///      Shape: `RLP([sealedHeader, accountProof, manifestStorageProof, manifestPreimage])`.
    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        pure
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        configProof = _validConfigProofBytes("eip155:1");
        channelId = SYNTHETIC_CHANNEL_ID;

        // Prove slot 18 == keccak256(preimage) so the verifier can bind the supplied preimage to the
        // on-ledger commitment.
        bytes32 slot = bytes32(MANIFEST_COMMITMENT_SLOT);
        (bytes32 storageRoot, bytes memory proofNodes) = _buildSyntheticMPTProof(
            keccak256(abi.encodePacked(slot)), RLP.encode(uint256(keccak256(committedPreimage)))
        );

        bytes[] memory entry = new bytes[](2);
        entry[0] = RLP.encode(abi.encodePacked(slot));
        entry[1] = proofNodes;
        bytes[] memory entries = new bytes[](1);
        entries[0] = RLP.encode(entry);

        // codeHash is unpinned at config time (the trust anchor establishes the account), but supply
        // the real one so the fixture stays representative of a live proof.
        (bytes32 stateRoot, bytes memory accountProofRlp) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);

        bytes[] memory p = new bytes[](4);
        p[0] = _buildSealedCurrentHeader(1, stateRoot, VALIDATOR_PK);
        p[1] = accountProofRlp;
        p[2] = RLP.encode(entries);
        p[3] = RLP.encode(carriedPreimage);
        manifestProof = RLP.encode(p);
    }

    // ── Contract-mode proof assembly ──────────

    /// @dev An 8-field Contract-mode config proof: the contract proof at field 5 proves the set
    ///      under the field-6 header's state root, and the header is sealed by that set.
    function _validConfigProofBytes(string memory chainId) private pure returns (bytes memory) {
        (bytes32 stateRoot, bytes32 arraySlot, bytes memory vcProof) =
            _validatorContractProof(VALIDATOR_CONTRACT, _cmSet());
        bytes memory header = _buildSealedCurrentHeader(1, stateRoot, VALIDATOR_PK);
        return _buildContractConfigProof(arraySlot, vcProof, header, chainId, RLP.encode(uint256(1)));
    }

    /// @dev Assemble the 8-field config proof with a chosen descriptor mode item.
    function _buildContractConfigProof(
        bytes32 arraySlot,
        bytes memory vcProof,
        bytes memory header,
        string memory chainId,
        bytes memory modeItemRlp
    ) private pure returns (bytes memory) {
        bytes[] memory throttleItems = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            throttleItems[i] = RLP.encode(uint256(0));
        }
        bytes[] memory taItems = new bytes[](5);
        taItems[0] = modeItemRlp;
        taItems[1] = RLP.encode(abi.encodePacked(SERVICE_ADDR));
        taItems[2] = RLP.encode(SERVICE_CODE_HASH);
        taItems[3] = RLP.encode(VALIDATOR_CONTRACT);
        taItems[4] = RLP.encode(arraySlot);

        bytes[] memory items = new bytes[](8);
        items[0] = RLP.encode(abi.encodePacked(SERVICE_ADDR));
        items[1] = RLP.encode(bytes(chainId));
        items[2] = RLP.encode(uint256(0));
        items[3] = RLP.encode(throttleItems);
        items[4] = RLP.encode(RLP.encode(taItems));
        items[5] = RLP.encode(vcProof);
        items[6] = header;
        items[7] = RLP.encode(uint256(30000));
        return RLP.encode(items);
    }

    /// @dev A 5-field bundle around the given service storage proof: two-account state (service +
    ///      validator contract), field 1 = [trustedSet, no hops, contract proof], header sealed by
    ///      the trusted single validator.
    function _cmTop(bytes32 svcStorageRoot, bytes memory storageProofRlp, bytes memory contentRlp)
        private
        pure
        returns (bytes memory)
    {
        (bytes32 arraySlot, bytes32 vcStorageRoot,) = _validatorStorageProof(_cmSet());
        (bytes32 stateRoot, bytes memory svcAccountProof, bytes memory vcAccountProof) =
            _buildTwoAccountState(SERVICE_ADDR, svcStorageRoot, SERVICE_CODE_HASH, VALIDATOR_CONTRACT, vcStorageRoot);
        bytes memory vcProof = _wrapVcProof(VALIDATOR_CONTRACT, vcAccountProof, arraySlot, _cmSet());
        bytes memory header = _buildSealedCurrentHeader(1, stateRoot, VALIDATOR_PK);

        bytes[] memory top = new bytes[](5);
        top[0] = header;
        top[1] = _contractSourceField(_cmSet(), new bytes[](0), vcProof);
        top[2] = svcAccountProof;
        top[3] = storageProofRlp;
        top[4] = contentRlp;
        return RLP.encode(top);
    }

    function _validTrustAnchor() private pure returns (bytes memory) {
        (bytes32 arraySlot,,) = _validatorStorageProof(_cmSet());
        return abi.encode(
            uint8(1),
            _commit(_cmSet()),
            SERVICE_CODE_HASH,
            VALIDATOR_CONTRACT,
            arraySlot,
            uint64(0),
            VALIDATOR_CODE_HASH
        );
    }

    function _validChannelContext() private pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({
                channelId: SYNTHETIC_CHANNEL_ID, remoteServiceAddress: abi.encodePacked(SERVICE_ADDR)
            })
        );
    }

    // ── Hook implementations ─────────────────────────────────────────────────

    function _runningHashVector() internal pure override returns (RunningHashVector memory) {
        bytes memory payload = ClprProtobuf.encodeDataMessage(hex"01", hex"02", hex"03", hex"04");
        bytes32 expectedSentRunningHash = sha256(abi.encodePacked(bytes32(0), sha256(payload)));

        bytes[] memory payloads = new bytes[](1);
        payloads[0] = payload;
        ClprTypes.QueueMetadata memory dummyMeta;
        bytes memory bundleContent = ClprProtobuf.encodeBundleContent(dummyMeta, payloads);

        return RunningHashVector({
            proofBytes: _buildBundleProofWithSentHash(expectedSentRunningHash, bundleContent),
            trustAnchor: _validTrustAnchor(),
            channelContext: _validChannelContext(),
            previousRunningHash: bytes32(0)
        });
    }

    /// @dev A structurally valid Contract-mode config proof for a different chain: the chain id
    ///      differs and the descriptor's mode word is not Contract, so verifyConfig reverts.
    function _wrongChainConfigVector() internal pure override returns (bytes memory, bytes32) {
        (bytes32 stateRoot, bytes32 arraySlot, bytes memory vcProof) =
            _validatorContractProof(VALIDATOR_CONTRACT, _cmSet());
        bytes memory header = _buildSealedCurrentHeader(1, stateRoot, VALIDATOR_PK);
        // Descriptor mode item = a Header-mode (0) tag: this verifier serves Contract mode only.
        bytes memory proof =
            _buildContractConfigProof(arraySlot, vcProof, header, "eip155:999", RLP.encode(new bytes(0)));
        return (proof, SYNTHETIC_CHANNEL_ID);
    }

    /// @dev verifyConfig requires exactly 8 RLP items. A 7-item proof (epochLength absent) is the
    ///      Contract-mode realization of "partial field coverage."
    function _partialSlotCoverageVector() internal pure override returns (bytes memory, bytes32) {
        (bytes32 stateRoot, bytes32 arraySlot, bytes memory vcProof) =
            _validatorContractProof(VALIDATOR_CONTRACT, _cmSet());
        bytes memory header = _buildSealedCurrentHeader(1, stateRoot, VALIDATOR_PK);

        bytes[] memory throttleItems = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            throttleItems[i] = RLP.encode(uint256(0));
        }
        bytes[] memory taItems = new bytes[](5);
        taItems[0] = RLP.encode(uint256(1));
        taItems[1] = RLP.encode(abi.encodePacked(SERVICE_ADDR));
        taItems[2] = RLP.encode(SERVICE_CODE_HASH);
        taItems[3] = RLP.encode(VALIDATOR_CONTRACT);
        taItems[4] = RLP.encode(arraySlot);

        bytes[] memory items = new bytes[](7); // omits items[7] (epochLength)
        items[0] = RLP.encode(abi.encodePacked(SERVICE_ADDR));
        items[1] = RLP.encode(bytes("eip155:1"));
        items[2] = RLP.encode(uint256(0));
        items[3] = RLP.encode(throttleItems);
        items[4] = RLP.encode(RLP.encode(taItems));
        items[5] = RLP.encode(vcProof);
        items[6] = header;

        return (RLP.encode(items), SYNTHETIC_CHANNEL_ID);
    }

    function _wrongServiceAddressVector() internal pure override returns (bytes memory, bytes memory, bytes memory) {
        address differentService = address(uint160(uint256(keccak256("different-service"))));
        bytes memory wrongContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({
                channelId: SYNTHETIC_CHANNEL_ID, remoteServiceAddress: abi.encodePacked(differentService)
            })
        );
        (bytes32 svcStorageRoot, bytes memory storageProofRlp) = _buildChannelStorageProof(SYNTHETIC_CHANNEL_ID);
        return (_cmTop(svcStorageRoot, storageProofRlp, RLP.encode(new bytes(0))), _validTrustAnchor(), wrongContext);
    }

    /// @dev 3-entry storage proof: offsets [+1, +2, +4] — the remaining required slots absent.
    ///      The verifier requires exactly 5 or 6 entries; 3 triggers InvalidStorageProofShape.
    function _threeSlotStorageVector() internal pure override returns (bytes memory, bytes memory, bytes memory) {
        bytes32 cBase = keccak256(abi.encode(SYNTHETIC_CHANNEL_ID, uint256(15)));
        (bytes32 storageRoot, bytes memory proofNodesRlp) =
            _buildSyntheticMPTProof(keccak256(abi.encodePacked(bytes32(uint256(cBase) + 1))), RLP.encode(uint256(0)));

        uint8[3] memory offsets = [1, 2, 4];
        bytes[] memory entries = new bytes[](3);
        for (uint256 i = 0; i < 3; i++) {
            bytes32 slotKey = bytes32(uint256(cBase) + offsets[i]);
            bytes[] memory entry = new bytes[](2);
            entry[0] = RLP.encode(abi.encodePacked(slotKey));
            entry[1] = proofNodesRlp;
            entries[i] = RLP.encode(entry);
        }

        return (
            _cmTop(storageRoot, RLP.encode(entries), RLP.encode(new bytes(0))),
            _validTrustAnchor(),
            _validChannelContext()
        );
    }

    /// @dev 5-entry storage proof with offsets [+1, +2, +3, +5, +16] — uses cBase+3 instead of
    ///      cBase+4 (sentRunningHash slot). The verifier derives cBase+4 from the layout and cannot
    ///      find it in the proof, so it reverts with SlotNotProven(cBase+4).
    function _wrongSlotIndexVector() internal pure override returns (bytes memory, bytes memory, bytes memory) {
        bytes32 cBase = keccak256(abi.encode(SYNTHETIC_CHANNEL_ID, uint256(15)));
        (bytes32 storageRoot, bytes memory proofNodesRlp) =
            _buildSyntheticMPTProof(keccak256(abi.encodePacked(bytes32(uint256(cBase) + 1))), RLP.encode(uint256(0)));

        uint8[5] memory offsets = [1, 2, 3, 5, 16]; // +3 in place of +4
        bytes[] memory entries = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            bytes32 slotKey = bytes32(uint256(cBase) + offsets[i]);
            bytes[] memory entry = new bytes[](2);
            entry[0] = RLP.encode(abi.encodePacked(slotKey));
            entry[1] = proofNodesRlp;
            entries[i] = RLP.encode(entry);
        }

        return (
            _cmTop(storageRoot, RLP.encode(entries), RLP.encode(new bytes(0))),
            _validTrustAnchor(),
            _validChannelContext()
        );
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    /// @dev Build a bundle proof where the sentRunningHash slot (Channel slot +4) proves sentHash;
    ///      the remaining channel slots are absent from the trie (value = 0).
    function _buildBundleProofWithSentHash(bytes32 sentHash, bytes memory bundleContent)
        private
        pure
        returns (bytes memory)
    {
        bytes32 cBase = keccak256(abi.encode(SYNTHETIC_CHANNEL_ID, uint256(15)));
        (bytes32 storageRoot, bytes memory proofNodes) = _buildSyntheticMPTProof(
            keccak256(abi.encodePacked(bytes32(uint256(cBase) + 4))), RLP.encode(uint256(sentHash))
        );

        uint8[5] memory offsets = [1, 2, 4, 5, 16];
        bytes[] memory storageEntries = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            bytes32 slotKey = bytes32(uint256(cBase) + offsets[i]);
            bytes[] memory entry = new bytes[](2);
            entry[0] = RLP.encode(abi.encodePacked(slotKey));
            entry[1] = proofNodes;
            storageEntries[i] = RLP.encode(entry);
        }

        return _cmTop(storageRoot, RLP.encode(storageEntries), RLP.encode(bundleContent));
    }
}
