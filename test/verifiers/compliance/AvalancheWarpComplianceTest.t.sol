// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmStorageComplianceTest} from "@test/verifiers/compliance/ClprEvmStorageComplianceTest.sol";
import {AvalancheWarpFixtures} from "@test/verifiers/evm/avalanche/AvalancheWarpFixtures.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {AvalancheWarpVerifier} from "@hiero-ledger/clpr/verifiers/evm/avalanche/AvalancheWarpVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title AvalancheWarpComplianceTest
/// @dev ClprVerifierComplianceTest adapter (via ClprEvmStorageComplianceTest) for AvalancheWarpVerifier.
///      Every bundle carries a real Warp quorum certificate: a coreth-shaped header whose hash is
///      BLS-signed (avalanchego UnsignedMessage + payload.Hash, `_POP_` DST) by all four validators of
///      a canonical set, over synthetic MPT service state with coreth 5-field accounts.
contract AvalancheWarpComplianceTest is ClprEvmStorageComplianceTest, AvalancheWarpFixtures {
    bytes32 internal constant SYNTHETIC_CHANNEL_ID = CHANNEL_ID;

    Val[] internal vals;
    bytes internal packedSet;
    uint256 internal totalWeight;

    function setUp() public override {
        _setupAttestors();
        Set memory s = _equalSet(4, "compliance");
        for (uint256 i = 0; i < s.vals.length; i++) {
            vals.push(s.vals[i]);
        }
        packedSet = s.packed;
        totalWeight = s.totalWeight;
        super.setUp();
    }

    function _deployVerifier() internal override returns (IClprVerifier) {
        return IClprVerifier(new AvalancheWarpVerifier());
    }

    // ── Shared builders ───────────────────────────────────────────────────────

    function _set() internal view returns (Set memory s) {
        s.vals = vals;
        s.packed = packedSet;
        s.totalWeight = totalWeight;
    }

    function _config(string memory caip2, uint256 evmChainId) internal view returns (bytes memory) {
        return _configProof(caip2, evmChainId, _set(), 2);
    }

    function _anchorFor(bytes32 channelId) internal view returns (bytes memory a) {
        a = _anchor(_set(), P_HEIGHT, P_TIME);
        assembly {
            mstore(add(a, 68), channelId) // anchor[36..68) = channelId
        }
    }

    /// Bundle over `stateRoot`, Warp-signed by the whole set.
    function _bundleFor(bytes32 stateRoot, bytes memory account, bytes memory storage_, bytes memory contentItem)
        internal
        view
        returns (bytes memory)
    {
        Hdr memory h = _header(100, stateRoot, BLOCK_TIME);
        bytes[] memory top = new bytes[](7);
        top[0] = RLP.encode(h.rlp);
        top[1] = _warpSig(_set(), _range(0, 4), h.hash);
        top[2] = RLP.encode(packedSet);
        top[3] = _noRotation();
        top[4] = account;
        top[5] = storage_;
        top[6] = contentItem;
        return RLP.encode(top);
    }

    function _bundleForService(address svc, bytes32 codeHash, bytes32 channelId) internal view returns (bytes memory) {
        (bytes32 storageRoot, bytes memory sp) = _buildChannelStorageProof(channelId);
        (bytes32 root, bytes memory ap) = _corethAccountProof(svc, storageRoot, codeHash);
        return _bundleFor(root, ap, sp, RLP.encode(new bytes(0)));
    }

    // ── Adapter hooks ─────────────────────────────────────────────────────────

    function _validConfig() internal view override returns (ConfigVector memory) {
        return ConfigVector({
            configProof: _config("eip155:43113", EVM_CHAIN_ID),
            channelId: SYNTHETIC_CHANNEL_ID,
            expectedChainId: "eip155:43113",
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

    /// Fuji's validators and C-Chain advertised as Avalanche mainnet (eip155:43114).
    function _wrongChainConfigVector() internal view override returns (bytes memory, bytes32) {
        return (_config("eip155:43114", 43114), SYNTHETIC_CHANNEL_ID);
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
        bytes[] memory c = new bytes[](7); // 7 of the 12 config fields
        Memory.Slice[] memory full = RLP.decodeList(_config("eip155:43113", EVM_CHAIN_ID));
        for (uint256 i = 0; i < 7; i++) {
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
        (bytes32 root, bytes memory ap) = _corethAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
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
        (bytes32 root, bytes memory ap) = _corethAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
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
        (bytes32 root, bytes memory ap) = _corethAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        return RunningHashVector({
            proofBytes: _bundleFor(root, ap, RLP.encode(entries), RLP.encode(content)),
            trustAnchor: _anchorFor(SYNTHETIC_CHANNEL_ID),
            channelContext: _channelContext(),
            previousRunningHash: bytes32(0)
        });
    }

    /// Config-time manifest proof `[header, warpSignature, accountProof, manifestStorageProof, preimage]`,
    /// Warp-signed by the configured set.
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
        (bytes32 root, bytes memory ap) = _corethAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
        Hdr memory h = _header(5, root, BLOCK_TIME);
        bytes[] memory p = new bytes[](5);
        p[0] = RLP.encode(h.rlp);
        p[1] = _warpSig(_set(), _range(0, 4), h.hash);
        p[2] = ap;
        p[3] = _list1(_pair(RLP.encode(abi.encodePacked(slot)), nodes));
        p[4] = RLP.encode(carriedPreimage);
        return (_config("eip155:43113", EVM_CHAIN_ID), SYNTHETIC_CHANNEL_ID, RLP.encode(p));
    }

    /// verifyConfig is the trusted bootstrap (as in every light client): validator WEIGHTS and the
    /// attestor policy are taken as given, so a flipped weight byte yields a different but well-formed
    /// config. Key bytes, by contrast, are checked on-chain (canonical order + on-curve), so the
    /// corruption is applied to a key coordinate here.
    function test_compliance_verifyConfig_revertsOnCorruptedProof() public override {
        bytes memory cfg = _validConfig().configProof;
        uint256 at = _indexOf(cfg, packedSet) + 104 + 60; // y of validator 1
        vm.expectRevert();
        verifier.verifyConfig(_flipByte(cfg, at), SYNTHETIC_CHANNEL_ID, "");
    }

    function _indexOf(bytes memory hay, bytes memory needle) internal pure returns (uint256) {
        bytes32 h = keccak256(needle);
        for (uint256 i = 0; i + needle.length <= hay.length; i++) {
            bytes memory w = new bytes(needle.length);
            for (uint256 k = 0; k < needle.length; k++) {
                w[k] = hay[i + k];
            }
            if (keccak256(w) == h) return i;
        }
        revert("needle not found");
    }
}
