// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmStorageComplianceTest} from "@test/verifiers/compliance/ClprEvmStorageComplianceTest.sol";
import {SignerReplaySynthetic} from "@test/helpers/SignerReplaySynthetic.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @dev Shared compliance plumbing for verifiers whose bundle is
///      `[setBytes, headers, accountProof, storageProof, bundleContent]` and whose config-time
///      manifest proof is `[setBytes, headers, accountProof, manifestStorageProof, preimage]`
///      (SignerReplayVerifier, KaiaIstanbulVerifier). Adapters supply the header authentication
///      (`_finalityFor`), the account-leaf encoding (`_accountFor`), the anchor and the config proof.
abstract contract HeaderSetComplianceBase is ClprEvmStorageComplianceTest, SignerReplaySynthetic {
    function _finalityFor(bytes32 stateRoot) internal virtual returns (bytes memory setPacked, bytes[] memory headers);
    function _accountFor(bytes32 storageRoot) internal virtual returns (bytes32 stateRoot, bytes memory accountProof);
    function _anchorBytes() internal virtual returns (bytes memory);
    function _configFor(string memory caip2) internal virtual returns (bytes memory);
    function _caip2() internal pure virtual returns (string memory);

    function _assemble(bytes32 storageRoot, bytes memory storageRlp, bytes memory content)
        internal
        returns (bytes memory)
    {
        (bytes32 stateRoot, bytes memory account) = _accountFor(storageRoot);
        (bytes memory setPacked, bytes[] memory headers) = _finalityFor(stateRoot);
        bytes[] memory top = new bytes[](5);
        top[0] = RLP.encode(setPacked);
        top[1] = RLP.encode(headers);
        top[2] = account;
        top[3] = storageRlp;
        top[4] = RLP.encode(content);
        return RLP.encode(top);
    }

    function _validProof() internal returns (bytes memory) {
        (bytes32 storageRoot, bytes memory storageRlp) = _buildChannelStorageProof(SYNTHETIC_CHANNEL_ID);
        return _assemble(storageRoot, storageRlp, new bytes(0));
    }

    function _validConfig() internal override returns (ConfigVector memory) {
        return ConfigVector({
            configProof: _configFor(_caip2()),
            channelId: SYNTHETIC_CHANNEL_ID,
            expectedChainId: _caip2(),
            expectedServiceAddress: abi.encodePacked(SERVICE_ADDR)
        });
    }

    function _validBundle() internal override returns (BundleVector memory) {
        return BundleVector({
            proofBytes: _validProof(),
            trustAnchor: _anchorBytes(),
            channelContext: _ctx(),
            expectedNextMessageId: 0,
            expectedPayloadCount: 0
        });
    }

    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        configProof = _configFor(_caip2());
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
        (bytes32 stateRoot, bytes memory account) = _accountFor(storageRoot);
        (bytes memory setPacked, bytes[] memory headers) = _finalityFor(stateRoot);
        bytes[] memory p = new bytes[](5);
        p[0] = RLP.encode(setPacked);
        p[1] = RLP.encode(headers);
        p[2] = account;
        p[3] = RLP.encode(entries);
        p[4] = RLP.encode(carriedPreimage);
        manifestProof = RLP.encode(p);
    }

    function _runningHashVector() internal override returns (RunningHashVector memory) {
        bytes memory payload = ClprProtobuf.encodeDataMessage(hex"01", hex"02", hex"03", hex"04");
        bytes32 sent = sha256(abi.encodePacked(bytes32(0), sha256(payload)));
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = payload;
        ClprTypes.QueueMetadata memory dummy;
        bytes memory content = ClprProtobuf.encodeBundleContent(dummy, payloads);

        bytes32 cBase = keccak256(abi.encode(SYNTHETIC_CHANNEL_ID, uint256(15)));
        (bytes32 storageRoot, bytes memory proofNodes) =
            _buildSyntheticMPTProof(keccak256(abi.encodePacked(bytes32(uint256(cBase) + 4))), RLP.encode(uint256(sent)));
        return RunningHashVector({
            proofBytes: _assemble(storageRoot, _entries(cBase, [uint8(1), 2, 4, 5, 16], proofNodes), content),
            trustAnchor: _anchorBytes(),
            channelContext: _ctx(),
            previousRunningHash: bytes32(0)
        });
    }

    function _wrongChainConfigVector() internal override returns (bytes memory, bytes32) {
        return (_configFor("eip155:999999"), SYNTHETIC_CHANNEL_ID);
    }

    function _crossChannelVector() internal override returns (bytes memory, bytes memory, bytes memory, bytes memory) {
        bytes32 attacker = bytes32(uint256(0xDEADBEEF));
        bytes memory attackerContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: attacker, remoteServiceAddress: abi.encodePacked(SERVICE_ADDR)})
        );
        bytes32 missing = bytes32(uint256(keccak256(abi.encode(attacker, uint256(15)))) + 1);
        return (
            _validProof(),
            _anchorBytes(),
            attackerContext,
            abi.encodeWithSelector(ClprEvmStateProof.SlotNotProven.selector, missing)
        );
    }

    /// @dev The config payload has exactly three fields; dropping the code hash must revert.
    function _partialSlotCoverageVector() internal override returns (bytes memory, bytes32) {
        Memory.Slice[] memory full = RLP.decodeList(_configFor(_caip2()));
        bytes[] memory items = new bytes[](2);
        items[0] = Memory.toBytes(full[0]);
        items[1] = Memory.toBytes(full[1]);
        return (RLP.encode(items), SYNTHETIC_CHANNEL_ID);
    }

    function _wrongServiceAddressVector() internal override returns (bytes memory, bytes memory, bytes memory) {
        bytes memory wrongContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({
                channelId: SYNTHETIC_CHANNEL_ID,
                remoteServiceAddress: abi.encodePacked(address(uint160(uint256(keccak256("different-service")))))
            })
        );
        return (_validProof(), _anchorBytes(), wrongContext);
    }

    function _threeSlotStorageVector() internal override returns (bytes memory, bytes memory, bytes memory) {
        bytes32 cBase = keccak256(abi.encode(SYNTHETIC_CHANNEL_ID, uint256(15)));
        (bytes32 storageRoot, bytes memory proofNodes) =
            _buildSyntheticMPTProof(keccak256(abi.encodePacked(bytes32(uint256(cBase) + 1))), RLP.encode(uint256(0)));
        bytes[] memory entries = new bytes[](3);
        uint8[3] memory offsets = [1, 2, 4];
        for (uint256 i = 0; i < 3; i++) {
            bytes[] memory entry = new bytes[](2);
            entry[0] = RLP.encode(abi.encodePacked(bytes32(uint256(cBase) + offsets[i])));
            entry[1] = proofNodes;
            entries[i] = RLP.encode(entry);
        }
        return (_assemble(storageRoot, RLP.encode(entries), new bytes(0)), _anchorBytes(), _ctx());
    }

    function _wrongSlotIndexVector() internal override returns (bytes memory, bytes memory, bytes memory) {
        bytes32 cBase = keccak256(abi.encode(SYNTHETIC_CHANNEL_ID, uint256(15)));
        (bytes32 storageRoot, bytes memory proofNodes) =
            _buildSyntheticMPTProof(keccak256(abi.encodePacked(bytes32(uint256(cBase) + 1))), RLP.encode(uint256(0)));
        return (
            _assemble(storageRoot, _entries(cBase, [uint8(1), 2, 3, 5, 16], proofNodes), new bytes(0)),
            _anchorBytes(),
            _ctx()
        );
    }

    function _entries(bytes32 cBase, uint8[5] memory offsets, bytes memory proofNodes)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory entries = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            bytes[] memory entry = new bytes[](2);
            entry[0] = RLP.encode(abi.encodePacked(bytes32(uint256(cBase) + offsets[i])));
            entry[1] = proofNodes;
            entries[i] = RLP.encode(entry);
        }
        return RLP.encode(entries);
    }
}

