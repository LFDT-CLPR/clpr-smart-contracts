// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {XrplLib} from "@hiero-ledger/clpr/verifiers/evm/xrpl/XrplLib.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title XrplUnlKeys
/// @notice Helpers for {XrplLightClient}, split out for EIP-170: turning a configured UNL's
///         compressed secp256k1 signing keys into addresses, applying validator manifests
///         (signing-key rotations) per rippled `Manifest::verify`, and state-tree (SHAMap) proofs.
contract XrplUnlKeys {
    bytes32 internal constant SKIP_KEY = 0xb4979a36cdc7f3d3d5c31a4eae2ac7d7209dda877588b9afc66799692ab0d66b;

    IEd25519Verifier public immutable ED25519;
    /// @dev {ClprSha512Hasher}, also used by {XrplLightClient}.
    address public immutable HASHER;

    error InvalidPayloadShape();
    error EmptyUnl();
    error UnknownManifestKey();
    error StaleManifest(uint32 have, uint32 got);
    error BadManifestSignature();
    error ZeroEd25519Verifier();

    constructor(IEd25519Verifier ed25519, address hasher) {
        if (address(ed25519) == address(0) || hasher.code.length == 0) revert ZeroEd25519Verifier();
        ED25519 = ed25519;
        HASHER = hasher;
    }

    /// @notice Config-time UNL, field 0 of `proof`: [[masterKey(33), compressedSigningKey(33), manifestSeq], ...].
    function configUnl(bytes calldata proof)
        external
        view
        returns (bytes[] memory masters, address[] memory signers, uint32[] memory seqs)
    {
        Memory.Slice[] memory top = RLP.decodeList(proof);
        if (top.length == 0) revert InvalidPayloadShape();
        Memory.Slice[] memory list = RLP.readList(top[0]);
        uint256 n = list.length;
        if (n == 0) revert EmptyUnl();
        masters = new bytes[](n);
        signers = new address[](n);
        seqs = new uint32[](n);
        for (uint256 k = 0; k < n; ++k) {
            Memory.Slice[] memory e = RLP.readList(list[k]);
            if (e.length != 3) revert InvalidPayloadShape();
            masters[k] = RLP.readBytes(e[0]);
            if (masters[k].length != 33) revert XrplLib.BadPublicKey();
            signers[k] = XrplLib.secpAddress(RLP.readBytes(e[1]));
            seqs[k] = uint32(RLP.readUint256(e[2]));
        }
    }

    /// @notice Apply serialized manifests in order: the master key signs,
    ///         the new ephemeral key countersigns, and the sequence must increase. The new key must be
    ///         secp256k1 because rippled only accepts secp256k1 validation keys (STValidation.h).
    function applyManifests(
        bytes[] memory masters,
        address[] memory signers,
        uint32[] memory seqs,
        bytes[] calldata manifests
    ) external view returns (address[] memory, uint32[] memory) {
        for (uint256 k = 0; k < manifests.length; ++k) {
            XrplLib.Manifest memory m = XrplLib.parseManifest(manifests[k]);
            uint256 idx = type(uint256).max;
            for (uint256 j = 0; j < masters.length; ++j) {
                if (keccak256(masters[j]) == keccak256(m.master)) {
                    idx = j;
                    break;
                }
            }
            if (idx == type(uint256).max) revert UnknownManifestKey();
            if (m.sequence <= seqs[idx] || m.sequence == type(uint32).max) {
                revert StaleManifest(seqs[idx], m.sequence);
            }
            if (!_masterSigned(m)) revert BadManifestSignature();
            address newSigner = XrplLib.secpAddress(m.signingKey);
            (bytes32 r, bytes32 s) = XrplLib.parseDer(m.signature, 0, m.signature.length);
            if (!XrplLib.signedBy(XrplLib.half(HASHER, m.signingData), r, s, newSigner)) revert BadManifestSignature();
            signers[idx] = newSigner;
            seqs[idx] = m.sequence;
        }
        return (signers, seqs);
    }

    /// @notice SHAMap state proof: `data` is the ledger entry for `key` under state root `root`.
    function verifyStateEntry(bytes32 root, bytes32 key, bytes[] memory inners, bytes memory data) external view {
        XrplLib.verifyPath(root, key, inners, XrplLib.stateLeafHash(data, key, HASHER), HASHER);
    }

    /// @notice Hash of ledger `seq` from the LedgerHashes skip list (keylet::skip() =
    ///         sha512Half(uint16(0x0073)), the last 256 ledger hashes, `Ledger::updateSkipList`) proven
    ///         under state root `root`.
    function skipListHash(bytes32 root, bytes[] memory inners, bytes memory entry, uint32 seq)
        external
        view
        returns (bytes32)
    {
        XrplLib.verifyPath(root, SKIP_KEY, inners, XrplLib.stateLeafHash(entry, SKIP_KEY, HASHER), HASHER);
        return XrplLib.skipListHash(entry, seq);
    }

    /// @notice Lookup in a skip list the caller has already proven with {skipListHash}.
    function skipListLookup(bytes memory entry, uint32 seq) external pure returns (bytes32) {
        return XrplLib.skipListHash(entry, seq);
    }

    function _masterSigned(XrplLib.Manifest memory m) internal view returns (bool) {
        if (uint8(m.master[0]) == 0xED) {
            if (m.masterSignature.length != 64) return false;
            bytes32 pk = XrplLib.readB32(m.master, 1);
            // ed25519 signs the raw signing data (PublicKey.cpp `verify`, Ed25519 branch)
            return ED25519.verify(pk, m.signingData, m.masterSignature);
        }
        (bytes32 r, bytes32 s) = XrplLib.parseDer(m.masterSignature, 0, m.masterSignature.length);
        return XrplLib.signedBy(XrplLib.half(HASHER, m.signingData), r, s, XrplLib.secpAddress(m.master));
    }
}
