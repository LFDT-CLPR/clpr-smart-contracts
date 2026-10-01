// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmStorageComplianceTest} from "@test/verifiers/compliance/ClprEvmStorageComplianceTest.sol";
import {QbftSyntheticProofs} from "@test/helpers/QbftSyntheticProofs.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @title EvmCertifiedStateCompliance
/// @dev Shared compliance-adapter body for verifiers whose bundle is
///      `RLP([...finality, serviceAccountProof, storageProof, bundleContent])` and whose config is
///      `RLP([...finality, serviceAccountProof, slot25Proof, ledgerConfiguration])`, with the
///      ClprService account proven against the EVM `stateRoot` the finality items certify
///      (ArcMalachiteVerifier, PlasmaBftVerifier). An adapter supplies only `_finality(stateRoot)`
///      and the trust anchor; every vector here builds synthetic MPT state under that root.
abstract contract EvmCertifiedStateCompliance is ClprEvmStorageComplianceTest, QbftSyntheticProofs {
    address internal constant SERVICE_ADDR = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;
    bytes32 internal constant SERVICE_CODE_HASH = bytes32(uint256(0xC0DE));
    bytes32 internal constant SYNTHETIC_CHANNEL_ID = bytes32(uint256(0xC0FFEE));
    uint256 internal constant SERVICE_ADDRESS_SLOT = 25;

    // ── adapter hooks ─────────────────────────────────────────────────────────

    /// @dev Finality items (RLP-encoded) that certify a block with EVM state root `stateRoot`.
    function _finality(bytes32 stateRoot) internal virtual returns (bytes[] memory);

    function _anchor() internal view virtual returns (bytes memory);

    function _chainId() internal pure virtual returns (string memory);

    function _otherChainId() internal pure virtual returns (string memory);

    // ── assembly ──────────────────────────────────────────────────────────────

    function _ctx(bytes32 channelId, address svc) internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: abi.encodePacked(svc)})
        );
    }

    /// @dev ClprLedgerConfiguration{1: chain_id, 2: service_address(20)}.
    function _ledgerConfig(string memory chainId) internal pure returns (bytes memory) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return abi.encodePacked(hex"0a", uint8(bytes(chainId).length), chainId, hex"1214", SERVICE_ADDR);
    }

    function _wrap(bytes[] memory finality, bytes memory a, bytes memory b, bytes memory c)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory top = new bytes[](finality.length + 3);
        for (uint256 i; i < finality.length; ++i) {
            top[i] = finality[i];
        }
        top[finality.length] = a;
        top[finality.length + 1] = b;
        top[finality.length + 2] = c;
        return RLP.encode(top);
    }

    function _bundle(bytes32 storageRoot, bytes memory storageProof, bytes memory content)
        internal
        returns (bytes memory)
    {
        (bytes32 stateRoot, bytes memory accountProof) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        return _wrap(_finality(stateRoot), accountProof, storageProof, RLP.encode(content));
    }

    function _validBundleProof() internal returns (bytes memory) {
        (bytes32 storageRoot, bytes memory sp) = _buildChannelStorageProof(SYNTHETIC_CHANNEL_ID);
        return _bundle(storageRoot, sp, "");
    }

    function _entries(bytes32 slot, bytes memory nodes) internal pure returns (bytes memory) {
        bytes[] memory entry = new bytes[](2);
        entry[0] = RLP.encode(abi.encodePacked(slot));
        entry[1] = nodes;
        bytes[] memory list = new bytes[](1);
        list[0] = RLP.encode(entry);
        return RLP.encode(list);
    }

    function _slot25Value() internal pure returns (bytes memory) {
        return RLP.encode(uint256(bytes32(bytes20(SERVICE_ADDR))) | 0x28);
    }

    /// @dev Config over a one-leaf storage trie holding slot 25. `slotProofs` may be empty (partial).
    function _config(string memory chainId, bool withSlot) internal returns (bytes memory) {
        bytes32 slot = bytes32(SERVICE_ADDRESS_SLOT);
        (bytes32 storageRoot, bytes memory nodes) =
            _buildSyntheticMPTProof(keccak256(abi.encodePacked(slot)), _slot25Value());
        (bytes32 stateRoot, bytes memory accountProof) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        bytes memory slotProof = withSlot ? _entries(slot, nodes) : RLP.encode(new bytes[](0));
        return _wrap(_finality(stateRoot), accountProof, slotProof, RLP.encode(_ledgerConfig(chainId)));
    }

    // ── two-leaf storage trie (slot 25 + manifest slot 18) ────────────────────

    function _leaf(bytes32 keyHash, bytes memory value) internal pure returns (bytes memory) {
        // Odd-length leaf path: the first nibble is consumed by the branch.
        bytes memory path = new bytes(32);
        path[0] = bytes1(0x30 | (uint8(keyHash[0]) & 0x0f));
        for (uint256 i = 1; i < 32; ++i) {
            path[i] = keyHash[i];
        }
        bytes[] memory items = new bytes[](2);
        items[0] = RLP.encode(path);
        items[1] = RLP.encode(value);
        return RLP.encode(items);
    }

    /// @dev Branch root with two leaves whose hashed keys differ in the first nibble.
    function _twoLeafTrie(bytes32 slotA, bytes memory valA, bytes32 slotB, bytes memory valB)
        internal
        pure
        returns (bytes32 root, bytes memory nodesA, bytes memory nodesB)
    {
        bytes32 ka = keccak256(abi.encodePacked(slotA));
        bytes32 kb = keccak256(abi.encodePacked(slotB));
        uint8 na = uint8(ka[0]) >> 4;
        uint8 nb = uint8(kb[0]) >> 4;
        require(na != nb, "two-leaf trie: keys share the first nibble");
        bytes memory la = _leaf(ka, valA);
        bytes memory lb = _leaf(kb, valB);
        bytes[] memory branch = new bytes[](17);
        for (uint256 i; i < 17; ++i) {
            branch[i] = hex"80";
        }
        branch[na] = RLP.encode(keccak256(la));
        branch[nb] = RLP.encode(keccak256(lb));
        bytes memory branchNode = RLP.encode(branch);
        root = keccak256(branchNode);
        bytes[] memory pa = new bytes[](2);
        pa[0] = RLP.encode(branchNode);
        pa[1] = RLP.encode(la);
        bytes[] memory pb = new bytes[](2);
        pb[0] = RLP.encode(branchNode);
        pb[1] = RLP.encode(lb);
        nodesA = RLP.encode(pa);
        nodesB = RLP.encode(pb);
    }

    // ── base hooks ────────────────────────────────────────────────────────────

    function _validConfig() internal override returns (ConfigVector memory) {
        return ConfigVector({
            configProof: _config(_chainId(), true),
            channelId: SYNTHETIC_CHANNEL_ID,
            expectedChainId: _chainId(),
            expectedServiceAddress: abi.encodePacked(SERVICE_ADDR)
        });
    }

    function _validBundle() internal override returns (BundleVector memory) {
        return BundleVector({
            proofBytes: _validBundleProof(),
            trustAnchor: _anchor(),
            channelContext: _ctx(SYNTHETIC_CHANNEL_ID, SERVICE_ADDR),
            expectedNextMessageId: 0,
            expectedPayloadCount: 0
        });
    }

    /// @dev The manifest is proven against the same service storage as slot 25, so both slots
    ///      live in one two-leaf trie under the certified state root.
    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        bytes32 s25 = bytes32(SERVICE_ADDRESS_SLOT);
        bytes32 s18 = bytes32(MANIFEST_COMMITMENT_SLOT);
        (bytes32 storageRoot, bytes memory n25, bytes memory n18) =
            _twoLeafTrie(s25, _slot25Value(), s18, RLP.encode(uint256(keccak256(committedPreimage))));
        (bytes32 stateRoot, bytes memory accountProof) =
            _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        configProof =
            _wrap(_finality(stateRoot), accountProof, _entries(s25, n25), RLP.encode(_ledgerConfig(_chainId())));
        channelId = SYNTHETIC_CHANNEL_ID;
        bytes[] memory m = new bytes[](2);
        m[0] = _entries(s18, n18);
        m[1] = RLP.encode(carriedPreimage);
        manifestProof = RLP.encode(m);
    }

    function _runningHashVector() internal override returns (RunningHashVector memory) {
        bytes memory payload = ClprProtobuf.encodeDataMessage(hex"01", hex"02", hex"03", hex"04");
        bytes32 sent = sha256(abi.encodePacked(bytes32(0), sha256(payload)));
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = payload;
        ClprTypes.QueueMetadata memory dummy;
        bytes memory content = ClprProtobuf.encodeBundleContent(dummy, payloads);

        bytes32 cBase = keccak256(abi.encode(SYNTHETIC_CHANNEL_ID, uint256(15)));
        (bytes32 storageRoot, bytes memory nodes) =
            _buildSyntheticMPTProof(keccak256(abi.encodePacked(bytes32(uint256(cBase) + 4))), RLP.encode(uint256(sent)));
        return RunningHashVector({
            proofBytes: _bundle(storageRoot, _channelEntries(cBase, _offsets(1, 2, 4, 5, 16), nodes), content),
            trustAnchor: _anchor(),
            channelContext: _ctx(SYNTHETIC_CHANNEL_ID, SERVICE_ADDR),
            previousRunningHash: bytes32(0)
        });
    }

    function _wrongChainConfigVector() internal override returns (bytes memory, bytes32) {
        return (_config(_otherChainId(), true), SYNTHETIC_CHANNEL_ID);
    }

    function _crossChannelVector() internal override returns (bytes memory, bytes memory, bytes memory, bytes memory) {
        bytes32 attacker = bytes32(uint256(0xDEADBEEF));
        bytes32 missing = bytes32(uint256(keccak256(abi.encode(attacker, uint256(15)))) + 1);
        return (
            _validBundleProof(),
            _anchor(),
            _ctx(attacker, SERVICE_ADDR),
            abi.encodeWithSelector(ClprEvmStateProof.SlotNotProven.selector, missing)
        );
    }

    /// @dev The slot 25 proof is omitted: the service address would be taken on trust.
    function _partialSlotCoverageVector() internal override returns (bytes memory, bytes32) {
        return (_config(_chainId(), false), SYNTHETIC_CHANNEL_ID);
    }

    function _wrongServiceAddressVector() internal override returns (bytes memory, bytes memory, bytes memory) {
        return (
            _validBundleProof(),
            _anchor(),
            _ctx(SYNTHETIC_CHANNEL_ID, address(uint160(uint256(keccak256("different-service")))))
        );
    }

    function _offsets(uint8 a, uint8 b, uint8 c, uint8 d, uint8 e) internal pure returns (uint8[] memory o) {
        o = new uint8[](5);
        (o[0], o[1], o[2], o[3], o[4]) = (a, b, c, d, e);
    }

    function _channelEntries(bytes32 cBase, uint8[] memory offsets, bytes memory nodes)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory entries = new bytes[](offsets.length);
        for (uint256 i; i < offsets.length; ++i) {
            bytes[] memory e = new bytes[](2);
            e[0] = RLP.encode(abi.encodePacked(bytes32(uint256(cBase) + offsets[i])));
            e[1] = nodes;
            entries[i] = RLP.encode(e);
        }
        return RLP.encode(entries);
    }

    function _slotsVector(uint8[] memory offsets) internal returns (bytes memory) {
        bytes32 cBase = keccak256(abi.encode(SYNTHETIC_CHANNEL_ID, uint256(15)));
        (bytes32 storageRoot, bytes memory nodes) =
            _buildSyntheticMPTProof(keccak256(abi.encodePacked(bytes32(uint256(cBase) + 1))), RLP.encode(uint256(0)));
        return _bundle(storageRoot, _channelEntries(cBase, offsets, nodes), "");
    }

    function _threeSlotStorageVector() internal override returns (bytes memory, bytes memory, bytes memory) {
        uint8[] memory o = new uint8[](3);
        (o[0], o[1], o[2]) = (1, 2, 4);
        return (_slotsVector(o), _anchor(), _ctx(SYNTHETIC_CHANNEL_ID, SERVICE_ADDR));
    }

    function _wrongSlotIndexVector() internal override returns (bytes memory, bytes memory, bytes memory) {
        return (_slotsVector(_offsets(1, 2, 3, 5, 16)), _anchor(), _ctx(SYNTHETIC_CHANNEL_ID, SERVICE_ADDR));
    }
}
