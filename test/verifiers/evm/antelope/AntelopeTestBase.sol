// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test, Vm} from "forge-std/Test.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {AntelopeLib} from "@hiero-ledger/clpr/verifiers/evm/antelope/AntelopeLib.sol";
import {AntelopeBls} from "@hiero-ledger/clpr/verifiers/evm/antelope/AntelopeBls.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @dev Shared helpers for the Antelope verifier tests: CLPR action payloads, action bases,
///      Merkle trees (built the way Spring/Leap build them), RLP glue, and BLS12-381 key and
///      signature generation on the EIP-2537 precompiles (Spring encodings).
abstract contract AntelopeTestBase is Test {
    string internal constant SERVICE_NAME = "clpr.service";
    string internal constant CHAIN_ID = "antelope:aca376f206b8fc25a6ed44dbdc66547c";
    bytes32 internal constant CHANNEL = bytes32(uint256(0xC1A55E));

    function _serviceAddress() internal pure returns (bytes memory) {
        return abi.encodePacked(AntelopeLib.le64(AntelopeLib.nameValue(SERVICE_NAME)));
    }

    function _context() internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: CHANNEL, remoteServiceAddress: _serviceAddress()})
        );
    }

    /// @dev pack(account, name, [actor@active]).
    function _actionBase(string memory account, string memory name, string memory actor)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            AntelopeLib.le64(AntelopeLib.nameValue(account)),
            AntelopeLib.le64(AntelopeLib.nameValue(name)),
            uint8(1),
            AntelopeLib.le64(AntelopeLib.nameValue(actor)),
            AntelopeLib.le64(AntelopeLib.nameValue("active"))
        );
    }

    /// @dev The 153-byte `queuestate` return value.
    function _queueState(
        bytes32 channelId,
        uint8 status,
        uint64 nextMessageId,
        bytes32 sentRunningHash,
        uint64 receivedMessageId,
        bytes32 receivedRunningHash,
        uint64 manifestVersion,
        bytes32 manifestCommitment
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            channelId,
            status,
            AntelopeLib.le64(nextMessageId),
            sentRunningHash,
            AntelopeLib.le64(receivedMessageId),
            receivedRunningHash,
            AntelopeLib.le64(manifestVersion),
            manifestCommitment
        );
    }

    function _defaultQueueState() internal pure returns (bytes memory) {
        return _queueState(CHANNEL, 1, 7, keccak256("sent"), 3, keccak256("recv"), 1, bytes32(0));
    }

    function _bundleContent() internal pure returns (bytes memory) {
        bytes[] memory payloads = new bytes[](2);
        payloads[0] = hex"0a0b0c";
        payloads[1] = hex"0d0e0f10";
        ClprTypes.QueueMetadata memory meta;
        return ClprProtobuf.encodeBundleContent(meta, payloads);
    }

    function _ledgerConfigReturn(string memory chainId) internal pure returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory lc;
        lc.protocolVersion = 1;
        lc.chainId = chainId;
        lc.serviceAddress = _serviceAddress();
        lc.nanosSinceEpoch = 1_790_000_000_000_000_000;
        lc.throttles = ClprTypes.Throttles({
            maxMessagesPerBundle: 10,
            maxMessagePayloadBytes: 4096,
            maxGasPerMessage: 500_000,
            maxQueueDepth: 100,
            maxSyncBytes: 65_536,
            maxLocalEndpoints: 4,
            maxPeerEndpoints: 4
        });
        return ClprProtobuf.encodeControlMessage(lc);
    }

    // ── Merkle trees ──────────────────────────────────────────────────────────

    function _savannaRoot(bytes32[] memory leaves) internal pure returns (bytes32) {
        bytes32[] memory layer = leaves;
        while (layer.length > 1) {
            bytes32[] memory next = new bytes32[]((layer.length + 1) / 2);
            for (uint256 i = 0; i < layer.length; i += 2) {
                next[i / 2] = i + 1 < layer.length ? sha256(abi.encodePacked(layer[i], layer[i + 1])) : layer[i];
            }
            layer = next;
        }
        return layer[0];
    }

    function _savannaProof(bytes32[] memory leaves, uint256 index) internal pure returns (bytes32[] memory out) {
        bytes32[] memory tmp = new bytes32[](64);
        uint256 n;
        bytes32[] memory layer = leaves;
        while (layer.length > 1) {
            uint256 pair = index ^ 1;
            if (pair < layer.length) tmp[n++] = layer[pair];
            bytes32[] memory next = new bytes32[]((layer.length + 1) / 2);
            for (uint256 i = 0; i < layer.length; i += 2) {
                next[i / 2] = i + 1 < layer.length ? sha256(abi.encodePacked(layer[i], layer[i + 1])) : layer[i];
            }
            layer = next;
            index >>= 1;
        }
        out = new bytes32[](n);
        for (uint256 i = 0; i < n; ++i) {
            out[i] = tmp[i];
        }
    }

    /// @dev Number of siblings a Savanna proof for (index, count) needs.
    function _savannaSiblingCount(uint256 index, uint256 count) internal pure returns (uint256 n) {
        while (count > 1) {
            if (index & 1 == 1 || index + 1 < count) ++n;
            index >>= 1;
            count = (count + 1) >> 1;
        }
    }

    function _legacyPair(bytes32 l, bytes32 r) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(l & ~bytes32(uint256(0x80) << 248), r | bytes32(uint256(0x80) << 248)));
    }

    function _legacyLayer(bytes32[] memory layer) private pure returns (bytes32[] memory next) {
        next = new bytes32[]((layer.length + 1) / 2);
        for (uint256 i = 0; i < layer.length; i += 2) {
            next[i / 2] = _legacyPair(layer[i], i + 1 < layer.length ? layer[i + 1] : layer[i]);
        }
    }

    function _legacyRoot(bytes32[] memory leaves) internal pure returns (bytes32) {
        bytes32[] memory layer = leaves;
        while (layer.length > 1) {
            layer = _legacyLayer(layer);
        }
        return layer[0];
    }

    function _legacyProof(bytes32[] memory leaves, uint256 index) internal pure returns (bytes32[] memory out) {
        bytes32[] memory tmp = new bytes32[](64);
        uint256 n;
        bytes32[] memory layer = leaves;
        while (layer.length > 1) {
            uint256 pair = index ^ 1;
            if (pair < layer.length) tmp[n++] = layer[pair];
            layer = _legacyLayer(layer);
            index >>= 1;
        }
        out = new bytes32[](n);
        for (uint256 i = 0; i < n; ++i) {
            out[i] = tmp[i];
        }
    }

    function _filler(uint256 n, uint256 seed) internal pure returns (bytes32[] memory out) {
        out = new bytes32[](n);
        for (uint256 i = 0; i < n; ++i) {
            out[i] = keccak256(abi.encode(seed, i));
        }
    }

    // ── RLP ───────────────────────────────────────────────────────────────────

    function _rlpList(bytes[] memory items) internal pure returns (bytes memory) {
        return RLP.encode(items);
    }

    function _rlpEmptyList() internal pure returns (bytes memory) {
        return RLP.encode(new bytes[](0));
    }

    function _rlpB32s(bytes32[] memory xs) internal pure returns (bytes memory) {
        bytes[] memory items = new bytes[](xs.length);
        for (uint256 i = 0; i < xs.length; ++i) {
            items[i] = RLP.encode(xs[i]);
        }
        return RLP.encode(items);
    }

    function _rlpUint(uint256 v) internal pure returns (bytes memory) {
        return RLP.encode(v);
    }

    function _rlpBytes(bytes memory b) internal pure returns (bytes memory) {
        return RLP.encode(b);
    }

    function _l2(bytes memory a, bytes memory b) internal pure returns (bytes[] memory l) {
        l = new bytes[](2);
        l[0] = a;
        l[1] = b;
    }

    // ── BLS12-381 (EIP-2537) in Spring encodings ─────────────────────────────

    uint256 internal constant BLS_R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    bytes internal constant G1_GENERATOR =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    function _blsSecret(uint256 seed) internal pure returns (uint256) {
        return (uint256(keccak256(abi.encode("bls", seed))) % (BLS_R - 1)) + 1;
    }

    /// @dev sk·G1 in EIP-2537 encoding (G1MSM, 0x0c).
    function _g1Mul(uint256 sk) internal view returns (bytes memory) {
        (bool ok, bytes memory r) = address(0x0c).staticcall(abi.encodePacked(G1_GENERATOR, sk));
        require(ok && r.length == 128, "G1MSM");
        return r;
    }

    /// @dev sk·P in G2 (G2MSM, 0x0e).
    function _g2Mul(bytes memory p, uint256 sk) internal view returns (bytes memory) {
        (bool ok, bytes memory r) = address(0x0e).staticcall(abi.encodePacked(p, sk));
        require(ok && r.length == 256, "G2MSM");
        return r;
    }

    /// @dev EIP-2537 field elements (64-byte big-endian) → Spring (48-byte little-endian), in order.
    function _toSpring(bytes memory eip) internal pure returns (bytes memory out) {
        uint256 n = eip.length / 64;
        out = new bytes(n * 48);
        for (uint256 k = 0; k < n; ++k) {
            for (uint256 j = 0; j < 48; ++j) {
                out[k * 48 + j] = eip[k * 64 + 63 - j];
            }
        }
    }

    /// @dev Spring 96-byte public key of secret `sk`.
    function _blsPub(uint256 sk) internal view returns (bytes memory) {
        return _toSpring(_g1Mul(sk));
    }

    /// @dev Spring 192-byte signature by the sum of `sks` over `digest` (NUL ciphersuite).
    function _blsSign(uint256 skSum, bytes32 digest) internal view returns (bytes memory) {
        return _toSpring(_g2Mul(AntelopeBls.hashToG2(abi.encodePacked(digest)), skSum));
    }

    /// @dev Packed `finalizer_policy` with weight-1 finalizers "fin<i>" and keys from `sks`.
    function _packPolicy(uint32 generation, uint64 threshold, uint256[] memory sks)
        internal
        view
        returns (bytes memory pack)
    {
        pack = abi.encodePacked(
            AntelopeLib.le32(generation), AntelopeLib.le64(threshold), AntelopeLib.varUint(sks.length)
        );
        for (uint256 i = 0; i < sks.length; ++i) {
            bytes memory desc = abi.encodePacked("fin", vm.toString(i));
            pack = abi.encodePacked(
                pack,
                AntelopeLib.varUint(desc.length),
                desc,
                AntelopeLib.le64(1),
                AntelopeLib.varUint(96),
                _blsPub(sks[i])
            );
        }
    }

    // ── secp256k1 (Antelope K1) ──────────────────────────────────────────────

    /// @dev Antelope SIG_K1 payload: (27 + 4 + recid) || r || s.
    function _k1Sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(uint8(v + 4), r, s);
    }

    /// @dev Compressed key and uncompressed x||y of a secp256k1 secret.
    function _k1Keys(uint256 pk) internal returns (bytes memory compressed, bytes memory xy) {
        Vm.Wallet memory w = vm.createWallet(pk);
        compressed = abi.encodePacked(uint8(2 + (w.publicKeyY & 1)), bytes32(w.publicKeyX));
        xy = abi.encodePacked(bytes32(w.publicKeyX), bytes32(w.publicKeyY));
    }
}
