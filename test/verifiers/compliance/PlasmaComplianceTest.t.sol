// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {EvmCertifiedStateCompliance} from "@test/verifiers/compliance/EvmCertifiedStateCompliance.sol";
import {PlasmaBftVerifierHarness} from "@test/verifiers/evm/plasma/PlasmaBftVerifierHarness.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {PlasmaBftVerifier} from "@hiero-ledger/clpr/verifiers/evm/plasma/PlasmaBftVerifier.sol";
import {ClprBeaconBls} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconBls.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @title PlasmaComplianceTest
/// @dev ClprVerifierComplianceTest adapter (via ClprEvmStorageComplianceTest) for PlasmaBftVerifier.
///      Each vector certifies a synthetic PlasmaBFT block B (and its child B+1) with two real BLS
///      quorum certificates from a 4-member committee whose keys are minted here with the EIP-2537
///      MSM precompiles. Nothing in the verifier is stubbed.
contract PlasmaComplianceTest is EvmCertifiedStateCompliance {
    bytes internal constant G1_GEN =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
    uint64 internal constant HEIGHT = 100;
    uint64 internal constant VIEW = 1000;
    uint256 internal constant N = 4;

    PlasmaBftVerifierHarness internal helper;
    uint256[] internal sks; // sorted by compressed public key
    bytes internal keys; // n × 128 B, same order
    bytes32 internal root;

    function _deployVerifier() internal override returns (IClprVerifier) {
        helper = new PlasmaBftVerifierHarness(
            PlasmaBftVerifier.Profile({chainId: "x", bootstrapCommitteeRoot: bytes32(uint256(1)), bootstrapHeight: 0})
        );
        uint256[] memory s = new uint256[](N);
        bytes[] memory pk = new bytes[](N);
        bytes[] memory c = new bytes[](N);
        for (uint256 i; i < N; ++i) {
            s[i] = uint256(keccak256(abi.encode("plasma-compliance", i))) >> 8;
            pk[i] = _msm(address(0x0c), abi.encodePacked(G1_GEN, s[i]), 128);
            c[i] = helper.compressG1(pk[i]);
        }
        // Insertion sort by compressed key bytes.
        for (uint256 i = 1; i < N; ++i) {
            for (uint256 j = i; j > 0 && _less(c[j], c[j - 1]); --j) {
                (c[j], c[j - 1]) = (c[j - 1], c[j]);
                (pk[j], pk[j - 1]) = (pk[j - 1], pk[j]);
                (s[j], s[j - 1]) = (s[j - 1], s[j]);
            }
        }
        for (uint256 i; i < N; ++i) {
            sks.push(s[i]);
            keys = bytes.concat(keys, pk[i]);
        }
        root = helper.committeeRoot(keys);
        return IClprVerifier(
            address(
                new PlasmaBftVerifier(
                    PlasmaBftVerifier.Profile({
                        chainId: _chainId(), bootstrapCommitteeRoot: root, bootstrapHeight: HEIGHT
                    })
                )
            )
        );
    }

    function _chainId() internal pure override returns (string memory) {
        return "9745";
    }

    function _otherChainId() internal pure override returns (string memory) {
        return "9746";
    }

    function _anchor() internal view override returns (bytes memory) {
        return abi.encodePacked(root, HEIGHT);
    }

    // ── synthetic PlasmaBFT ───────────────────────────────────────────────────

    function _msm(address pre, bytes memory input, uint256 outLen) internal view returns (bytes memory out) {
        bool ok;
        (ok, out) = pre.staticcall(input);
        require(ok && out.length == outLen, "msm");
    }

    function _less(bytes memory a, bytes memory b) internal pure returns (bool) {
        for (uint256 i; i < a.length; ++i) {
            if (a[i] != b[i]) return uint8(a[i]) < uint8(b[i]);
        }
        return false;
    }

    function _le64(uint64 v) internal pure returns (bytes8 r) {
        for (uint256 i; i < 8; ++i) {
            // forge-lint: disable-next-line(unsafe-typecast)
            r |= bytes8(bytes1(uint8(v >> (8 * i)))) >> (8 * i);
        }
    }

    function _leaves(uint64 view_, bytes32 parent, bytes32 qc, bytes32 body)
        internal
        view
        returns (bytes32[] memory l)
    {
        l = new bytes32[](11);
        l[0] = bytes32(_le64(view_));
        l[2] = parent;
        l[6] = qc;
        l[8] = body;
        l[9] = root;
        l[10] = root;
    }

    function _packed(bytes32[] memory l) internal pure returns (bytes memory b) {
        for (uint256 i; i < l.length; ++i) {
            b = bytes.concat(b, l[i]);
        }
    }

    /// @dev Aggregate BLS signature by `votes` over PlasmaBFT vote messages, as (sig96, sig256).
    function _sign(uint64[] memory votes, bytes32 hash, uint64 height, uint64 view_)
        internal
        view
        returns (bytes memory sig96, bytes memory sig256)
    {
        bytes memory input;
        for (uint256 i; i < votes.length; ++i) {
            uint64 v = votes[i];
            bytes memory pk = new bytes(128);
            for (uint256 j; j < 128; ++j) {
                pk[j] = keys[v * 128 + j];
            }
            bytes memory h = ClprBeaconBls.hashToG2Message(
                abi.encodePacked(helper.compressG1(pk), hash, _le64(height), _le64(v), _le64(view_))
            );
            input = bytes.concat(input, h, bytes32(sks[v]));
        }
        sig256 = _msm(address(0x0e), input, 256);
        // Compressed form: x.c1 ‖ x.c0 (48 B each) with the compression flag; y choice not needed.
        sig96 = new bytes(96);
        for (uint256 j; j < 48; ++j) {
            sig96[j] = sig256[80 + j];
            sig96[48 + j] = sig256[16 + j];
        }
        sig96[0] = bytes1(uint8(sig96[0]) | 0x80);
    }

    function _qcItem(uint64 height, uint64[] memory votes, bytes memory sig96, bytes memory sig256)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory v = new bytes[](votes.length);
        for (uint256 i; i < votes.length; ++i) {
            v[i] = RLP.encode(uint256(votes[i]));
        }
        bytes[] memory f = new bytes[](5);
        f[0] = RLP.encode(uint256(0));
        f[1] = RLP.encode(uint256(height));
        f[2] = RLP.encode(v);
        f[3] = RLP.encode(sig96);
        f[4] = RLP.encode(sig256);
        return RLP.encode(f);
    }

    function _votes(uint64 a, uint64 b, uint64 c) internal pure returns (uint64[] memory v) {
        v = new uint64[](3);
        (v[0], v[1], v[2]) = (a, b, c);
    }

    /// @dev finality = [committee, headerB, stateBranch, headerB1, qc1, qc2] for a block B whose
    ///      execution payload has `stateRoot` (other payload fields and graffiti zero).
    function _finality(bytes32 stateRoot) internal view override returns (bytes[] memory out) {
        bytes32[] memory w = new bytes32[](7);
        w[0] = stateRoot;
        bytes32 node = sha256(abi.encodePacked(stateRoot, w[1]));
        node = sha256(abi.encodePacked(w[2], node));
        node = sha256(abi.encodePacked(node, w[3]));
        node = sha256(abi.encodePacked(node, w[4]));
        node = sha256(abi.encodePacked(node, w[5]));
        bytes32 body = sha256(abi.encodePacked(w[6], node));

        bytes32[] memory hb = _leaves(VIEW, bytes32(0), bytes32(0), body);
        bytes32 hashB = helper.blockHash(hb);
        uint64[] memory v1 = _votes(0, 1, 2);
        (bytes memory s96a, bytes memory s256a) = _sign(v1, hashB, HEIGHT, VIEW);
        bytes32 qc1Root = helper.qcRoot(0, HEIGHT, v1, s96a, VIEW, hashB);

        bytes32[] memory hb1 = _leaves(VIEW + 1, hashB, qc1Root, bytes32(0));
        uint64[] memory v2 = _votes(1, 2, 3);
        (bytes memory s96b, bytes memory s256b) = _sign(v2, helper.blockHash(hb1), HEIGHT + 1, VIEW + 1);

        bytes[] memory f = new bytes[](6);
        f[0] = RLP.encode(keys);
        f[1] = RLP.encode(_packed(hb));
        f[2] = RLP.encode(_packed(w));
        f[3] = RLP.encode(_packed(hb1));
        f[4] = _qcItem(HEIGHT, v1, s96a, s256a);
        f[5] = _qcItem(HEIGHT + 1, v2, s96b, s256b);
        out = new bytes[](1);
        out[0] = RLP.encode(f);
    }
}
