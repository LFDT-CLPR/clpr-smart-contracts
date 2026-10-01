// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmStorageComplianceTest} from "@test/verifiers/compliance/ClprEvmStorageComplianceTest.sol";
import {BscParliaFixtures} from "@test/verifiers/evm/bsc/BscParliaFixtures.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {BscParliaVerifier} from "@hiero-ledger/clpr/verifiers/evm/bsc/BscParliaVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title BscParliaComplianceTest
/// @dev ClprVerifierComplianceTest adapter (via ClprEvmStorageComplianceTest) for BscParliaVerifier. Every bundle carries a real Parlia finality proof:
///      a BSC-shaped header sealed (secp256k1, chain-id seal hash) by a validator of a 4-member set,
///      finalized by a BLS12-381 vote attestation from all four, over synthetic MPT service state.
contract BscParliaComplianceTest is ClprEvmStorageComplianceTest, BscParliaFixtures {
    uint64 internal constant E = 1000;
    uint64 internal constant ACTIVE = 1010;
    uint64 internal constant STATE_BLOCK = 1100;
    bytes32 internal constant SYNTHETIC_CHANNEL_ID = CHANNEL_ID;

    Val[] internal vals;

    function setUp() public override {
        Val[] memory v = _makeSet(4, "compliance");
        for (uint256 i = 0; i < v.length; i++) {
            vals.push(v[i]);
        }
        super.setUp();
    }

    function _deployVerifier() internal override returns (IClprVerifier) {
        return IClprVerifier(new BscParliaVerifier());
    }

    // ── Shared builders ───────────────────────────────────────────────────────

    function _set() internal view returns (Val[] memory) {
        return vals;
    }

    function _epoch() internal view returns (Hdr memory) {
        return _header(E, keccak256("parent"), bytes32(0), _epochExtraBody(_set(), TURN_LENGTH), vals[0].ecdsaPk);
    }

    function _config(string memory caip2) internal view returns (bytes memory) {
        return _configProof(caip2, CHAIN_ID, _epoch(), ACTIVE, _set(), SERVICE_CODE_HASH);
    }

    function _anchorFor(bytes32 channelId) internal view returns (bytes memory a) {
        a = _anchor(_set(), E, ACTIVE);
        assembly {
            mstore(add(a, 0x20), channelId) // anchor[0..32) = channelId
        }
    }

    /// Finality for a state header committing to `stateRoot`, under the anchor set.
    function _finalityFor(bytes32 stateRoot) internal view returns (bytes memory) {
        Hdr memory h = _header(STATE_BLOCK, keccak256("p"), stateRoot, _plainExtraBody(), vals[0].ecdsaPk);
        return _pair(_chain(h), _finalize(_set(), _allBits(4), h));
    }

    function _bundleFor(bytes32 stateRoot, bytes memory account, bytes memory storage_, bytes memory contentItem)
        internal
        view
        returns (bytes memory)
    {
        bytes[] memory top = new bytes[](6);
        top[0] = _emptyList();
        top[1] = _entries(_set());
        top[2] = _finalityFor(stateRoot);
        top[3] = account;
        top[4] = storage_;
        top[5] = contentItem;
        return RLP.encode(top);
    }

    function _bundleForService(address svc, bytes32 codeHash, bytes32 channelId) internal view returns (bytes memory) {
        (bytes32 storageRoot, bytes memory sp) = _buildChannelStorageProof(channelId);
        (bytes32 root, bytes memory ap) = _buildSyntheticAccountProof(svc, storageRoot, codeHash);
        return _bundleFor(root, ap, sp, RLP.encode(new bytes(0)));
    }

    // ── Adapter hooks ─────────────────────────────────────────────────────────

    function _validConfig() internal view override returns (ConfigVector memory) {
        return ConfigVector({
            configProof: _config("eip155:97"),
            channelId: SYNTHETIC_CHANNEL_ID,
            expectedChainId: "eip155:97",
            expectedServiceAddress: abi.encodePacked(SERVICE_ADDR)
        });
    }

    function _validBundle() internal view override returns (BundleVector memory) {
        return BundleVector({
            proofBytes: _bundleForService(SERVICE_ADDR, SERVICE_CODE_HASH, SYNTHETIC_CHANNEL_ID),
            trustAnchor: _anchorFor(SYNTHETIC_CHANNEL_ID),
            channelContext: _channelContext(),
            expectedNextMessageId: 0,
            expectedPayloadCount: 0
        });
    }

    /// @dev The peer advertises a different CAIP-2 chain than the one its seals are bound to.
    function _wrongChainConfigVector() internal view override returns (bytes memory, bytes32) {
        return (_config("eip155:56"), SYNTHETIC_CHANNEL_ID);
    }

    function _crossChannelVector()
        internal
        view
        override
        returns (bytes memory proofBytes, bytes memory trustAnchor, bytes memory attackerContext, bytes memory)
    {
        bytes32 attacker = bytes32(uint256(0xDEADBEEF));
        attackerContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: attacker, remoteServiceAddress: abi.encodePacked(SERVICE_ADDR)})
        );
        bytes32 missing = bytes32(uint256(keccak256(abi.encode(attacker, uint256(15)))) + 1);
        return (
            _bundleForService(SERVICE_ADDR, SERVICE_CODE_HASH, SYNTHETIC_CHANNEL_ID),
            _anchorFor(attacker),
            attackerContext,
            abi.encodeWithSelector(ClprEvmStateProof.SlotNotProven.selector, missing)
        );
    }

    function _partialSlotCoverageVector() internal view override returns (bytes memory, bytes32) {
        bytes[] memory c = new bytes[](4); // 4 of the 7 config fields
        Memory.Slice[] memory full = RLP.decodeList(_config("eip155:97"));
        for (uint256 i = 0; i < 4; i++) {
            c[i] = Memory.toBytes(full[i]);
        }
        return (RLP.encode(c), SYNTHETIC_CHANNEL_ID);
    }

    function _wrongServiceAddressVector() internal view override returns (bytes memory, bytes memory, bytes memory) {
        address other = address(uint160(uint256(keccak256("different-service"))));
        return (
            _bundleForService(other, SERVICE_CODE_HASH, SYNTHETIC_CHANNEL_ID),
            _anchorFor(SYNTHETIC_CHANNEL_ID),
            _channelContext()
        );
    }

    function _threeSlotStorageVector() internal view override returns (bytes memory, bytes memory, bytes memory) {
        bytes32 cBase = keccak256(abi.encode(SYNTHETIC_CHANNEL_ID, uint256(15)));
        (bytes32 storageRoot, bytes memory nodes) =
            _buildSyntheticMPTProof(keccak256(abi.encodePacked(bytes32(uint256(cBase) + 1))), RLP.encode(uint256(0)));
        bytes[] memory entries = new bytes[](3);
        for (uint256 i = 0; i < 3; i++) {
            entries[i] = _pair(RLP.encode(abi.encodePacked(bytes32(uint256(cBase) + i + 1))), nodes);
        }
        (bytes32 root, bytes memory ap) = _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        return (
            _bundleFor(root, ap, RLP.encode(entries), RLP.encode(new bytes(0))),
            _anchorFor(SYNTHETIC_CHANNEL_ID),
            _channelContext()
        );
    }

    function _wrongSlotIndexVector() internal view override returns (bytes memory, bytes memory, bytes memory) {
        bytes32 cBase = keccak256(abi.encode(SYNTHETIC_CHANNEL_ID, uint256(15)));
        (bytes32 storageRoot, bytes memory nodes) =
            _buildSyntheticMPTProof(keccak256(abi.encodePacked(bytes32(uint256(cBase) + 1))), RLP.encode(uint256(0)));
        uint8[5] memory offsets = [1, 2, 3, 5, 16]; // +3 in place of +4
        bytes[] memory entries = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            entries[i] = _pair(RLP.encode(abi.encodePacked(bytes32(uint256(cBase) + offsets[i]))), nodes);
        }
        (bytes32 root, bytes memory ap) = _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        return (
            _bundleFor(root, ap, RLP.encode(entries), RLP.encode(new bytes(0))),
            _anchorFor(SYNTHETIC_CHANNEL_ID),
            _channelContext()
        );
    }

    function _runningHashVector() internal view override returns (RunningHashVector memory) {
        bytes memory payload = ClprProtobuf.encodeDataMessage(hex"01", hex"02", hex"03", hex"04");
        bytes32 sentHash = sha256(abi.encodePacked(bytes32(0), sha256(payload)));
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = payload;
        ClprTypes.QueueMetadata memory meta;
        bytes memory content = ClprProtobuf.encodeBundleContent(meta, payloads);

        bytes32 cBase = keccak256(abi.encode(SYNTHETIC_CHANNEL_ID, uint256(15)));
        bytes32 sentSlot = bytes32(uint256(cBase) + 4);
        (bytes32 storageRoot, bytes memory nodes) =
            _buildSyntheticMPTProof(keccak256(abi.encodePacked(sentSlot)), RLP.encode(uint256(sentHash)));
        uint8[5] memory offsets = [1, 2, 4, 5, 16];
        bytes[] memory entries = new bytes[](5);
        for (uint256 i = 0; i < 5; i++) {
            entries[i] = _pair(RLP.encode(abi.encodePacked(bytes32(uint256(cBase) + offsets[i]))), nodes);
        }
        (bytes32 root, bytes memory ap) = _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        return RunningHashVector({
            proofBytes: _bundleFor(root, ap, RLP.encode(entries), RLP.encode(content)),
            trustAnchor: _anchorFor(SYNTHETIC_CHANNEL_ID),
            channelContext: _channelContext(),
            previousRunningHash: bytes32(0)
        });
    }

    /// @dev Config-time manifest proof `[finality, accountProof, manifestStorageProof, preimage]`,
    ///      finalized by the configured validator set.
    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        view
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        bytes32 slot = bytes32(MANIFEST_COMMITMENT_SLOT);
        (bytes32 storageRoot, bytes memory nodes) = _buildSyntheticMPTProof(
            keccak256(abi.encodePacked(slot)), RLP.encode(uint256(keccak256(committedPreimage)))
        );
        (bytes32 root, bytes memory ap) = _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        bytes[] memory p = new bytes[](4);
        p[0] = _finalityFor(root);
        p[1] = ap;
        p[2] = _list1(_pair(RLP.encode(abi.encodePacked(slot)), nodes));
        p[3] = RLP.encode(carriedPreimage);
        return (_config("eip155:97"), SYNTHETIC_CHANNEL_ID, RLP.encode(p));
    }
}
