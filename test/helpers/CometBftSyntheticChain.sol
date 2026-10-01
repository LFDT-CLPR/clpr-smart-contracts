// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {CometBftLib} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftLib.sol";
import {SeiSyntheticProofs} from "@test/helpers/SeiSyntheticProofs.sol";

/// @dev Builds a small synthetic CometBFT chain for CometBftVerifier tests with REAL signatures:
///      secp256k1eth votes via `vm.sign` (Heimdall v2's scheme). Ed25519 commits are covered by
///      the live Cronos fixture (forge 1.5 has no Ed25519 signing cheatcode). Validator leaves, header hash and sign bytes follow the CometBFT
///      encodings the verifier rebuilds, so nothing in the commit path is stubbed.
abstract contract CometBftSyntheticChain is SeiSyntheticProofs {
    struct Val {
        uint256 secpKey; // secp256k1eth private key
        bytes leaf; // SimpleValidator bytes
        int64 power;
    }

    struct Block {
        CometBftLib.SeiHeader header;
        uint32 round;
        uint32 partTotal;
        bytes32 partHash;
    }

    string internal constant CHAIN = "testchain_9000-1";

    // ── Validators ───────────────────────────────────────────────────────────

    function _secpVal(string memory label, int64 power) internal returns (Val memory v) {
        Vm.Wallet memory w = vm.createWallet(label);
        bytes memory pub = abi.encodePacked(uint8(0x04), bytes32(w.publicKeyX), bytes32(w.publicKeyY));
        v.secpKey = w.privateKey;
        v.power = power;
        // forge-lint: disable-next-line(unsafe-typecast)
        v.leaf = abi.encodePacked(hex"0a43", hex"1a41", pub, hex"10", PB.encodeVarint(uint64(power)));
    }

    function _setHash(Val[] memory vals) internal pure returns (bytes32) {
        bytes[] memory leaves = new bytes[](vals.length);
        for (uint256 i; i < vals.length; ++i) {
            leaves[i] = vals[i].leaf;
        }
        return CometBftLib.simpleMerkleRoot(leaves);
    }

    function _encodeSet(Val[] memory vals) internal pure returns (bytes memory out) {
        for (uint256 i; i < vals.length; ++i) {
            out = abi.encodePacked(out, PB.encodeBytesField(1, vals[i].leaf));
        }
    }

    // ── Blocks ───────────────────────────────────────────────────────────────

    function _block(int64 height, bytes32 valsHash, bytes32 nextHash, bytes32 appHash)
        internal
        pure
        returns (Block memory b)
    {
        b.header = _syntheticHeader();
        b.header.chainId = CHAIN;
        b.header.height = height;
        b.header.validatorsHash = valsHash;
        b.header.nextValidatorsHash = nextHash;
        b.header.appHash = appHash;
        b.partTotal = 1;
        b.partHash = keccak256(abi.encode("parts", height));
    }

    function _signBytes(Block memory b, int64 ts) internal pure returns (bytes memory) {
        return CometBftLib.precommitSignBytes(
            b.header.chainId,
            b.header.height,
            // forge-lint: disable-next-line(unsafe-typecast)
            int32(b.round),
            CometBftLib.headerHash(b.header),
            b.partTotal,
            b.partHash,
            ts,
            0
        );
    }

    function _sign(Val memory v, bytes memory signBytes) internal pure returns (bytes memory) {
        (uint8 vv, bytes32 r, bytes32 s) = vm.sign(v.secpKey, keccak256(signBytes));
        return abi.encodePacked(r, s, vv - 27);
    }

    /// @dev SignedHeader{1: header, 2: commit} with signatures from `signers` (validator indices,
    ///      ascending). `sigOverride[i]` (if non-empty) replaces the i-th signature.
    function _signedHeader(Block memory b, Val[] memory vals, uint256[] memory signers, bytes[] memory sigOverride)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory bits = new bytes((vals.length + 7) / 8);
        bytes memory sigs;
        int64 ts = b.header.timeSeconds + 1;
        for (uint256 i; i < signers.length; ++i) {
            uint256 idx = signers[i];
            bits[idx / 8] = bytes1(uint8(bits[idx / 8]) | uint8(0x80 >> (idx % 8)));
            bytes memory sig = (sigOverride.length > i && sigOverride[i].length > 0)
                ? sigOverride[i]
                : _sign(vals[idx], _signBytes(b, ts));
            // forge-lint: disable-next-line(unsafe-typecast)
            bytes memory tsBytes = PB.encodeVarintField(1, uint64(ts));
            sigs = abi.encodePacked(
                sigs,
                PB.encodeBytesField(5, abi.encodePacked(PB.encodeBytesField(1, tsBytes), PB.encodeBytesField(2, sig)))
            );
        }
        bytes memory commit = abi.encodePacked(
            PB.encodeVarintField(1, b.round),
            PB.encodeVarintField(2, b.partTotal),
            PB.encodeBytesField(3, abi.encodePacked(b.partHash)),
            PB.encodeBytesField(4, bits),
            sigs
        );
        return abi.encodePacked(PB.encodeBytesField(1, _buildHeaderBytes(b.header)), PB.encodeBytesField(2, commit));
    }

    function _signedHeader(Block memory b, Val[] memory vals, uint256[] memory signers)
        internal
        pure
        returns (bytes memory)
    {
        return _signedHeader(b, vals, signers, new bytes[](0));
    }

    // ── State ────────────────────────────────────────────────────────────────

    function _channelKeys(uint8 prefix, address service, bytes32 channelId)
        internal
        pure
        returns (bytes[] memory keys)
    {
        bytes32 cBase = keccak256(abi.encode(channelId, uint256(15)));
        uint8[5] memory offsets = [1, 2, 4, 5, 16];
        keys = new bytes[](5);
        for (uint256 i; i < 5; ++i) {
            keys[i] = abi.encodePacked(prefix, service, bytes32(uint256(cBase) + offsets[i]));
        }
    }

    /// @dev StateProof{1: signed header, 2: "evm", 3: multistore proof, 4*: entries}.
    function _stateProof(bytes memory signedHeader, bytes memory multistore, bytes[] memory entries)
        internal
        pure
        returns (bytes memory out)
    {
        out = abi.encodePacked(
            PB.encodeBytesField(1, signedHeader),
            PB.encodeBytesField(2, bytes("evm")),
            PB.encodeBytesField(3, multistore)
        );
        for (uint256 i; i < entries.length; ++i) {
            out = abi.encodePacked(out, PB.encodeBytesField(4, entries[i]));
        }
    }

    function _hop(Val[] memory vals, bytes memory signedHeader) internal pure returns (bytes memory) {
        return abi.encodePacked(PB.encodeBytesField(1, _encodeSet(vals)), PB.encodeBytesField(2, signedHeader));
    }

    function _anchor(bytes32 setHash, uint64 height) internal pure returns (bytes memory) {
        return abi.encodePacked(setHash, height);
    }

    function _idx(uint256 a) internal pure returns (uint256[] memory r) {
        r = new uint256[](1);
        r[0] = a;
    }

    function _idx(uint256 a, uint256 b) internal pure returns (uint256[] memory r) {
        r = new uint256[](2);
        r[0] = a;
        r[1] = b;
    }

    function _idx(uint256 a, uint256 b, uint256 c) internal pure returns (uint256[] memory r) {
        r = new uint256[](3);
        r[0] = a;
        r[1] = b;
        r[2] = c;
    }
}

