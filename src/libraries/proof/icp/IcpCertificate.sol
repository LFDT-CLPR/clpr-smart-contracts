// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IcpBls} from "@hiero-ledger/clpr/libraries/proof/icp/IcpBls.sol";
import {IcpHashTree} from "@hiero-ledger/clpr/libraries/proof/icp/IcpHashTree.sol";

/// @title IcpCertificate
/// @notice Verification of Internet Computer certificates (IC interface specification,
///         "Certification"): a hash tree, a BLS signature on `domain_sep("ic-state-root") · root`, and
///         an optional delegation from the root (NNS) subnet to the signing subnet.
///
///         verify_cert(cert) =
///           root_hash = reconstruct(cert.tree)
///           check_delegation(cert.delegation)                 -- delegation cert signed by the root key,
///                                                               has no delegation itself, and certifies
///                                                               /subnet/<id>/public_key
///           verify_bls_signature(delegation_key, cert.signature, domain_sep("ic-state-root") · root_hash)
///
///         The delegation is scoped: the subnet may only certify canisters inside its canister ranges,
///         read from `/subnet/<id>/canister_ranges` (one blob) or from one shard
///         `/canister_ranges/<id>/<start>` of the delegation certificate.
library IcpCertificate {
    /// @notice A certificate as the relayer passes it. BLS points are uncompressed (EIP-2537); the
    ///         compressed bytes of the certificate are not needed because the points are checked
    ///         against the certified data they stand for (the subnet key) or are verified directly
    ///         (the signatures).
    struct Certificate {
        bytes tree; // CBOR hash tree of the certificate
        bytes signature; // G1 point, 128 bytes
        bytes subnetId; // empty = no delegation (certificate of the root subnet)
        bytes delegationTree; // CBOR hash tree of the delegation certificate
        bytes delegationSignature; // G1 point, 128 bytes, signed by the root key
        bytes subnetKey; // G2 point, 256 bytes; its x-coordinate must match /subnet/<id>/public_key
        bytes rangesShard; // empty = /subnet/<id>/canister_ranges, else the <start> label under /canister_ranges/<id>
    }

    /// @dev DER prefix of a BLS12-381 G2 public key (RFC 5480, OIDs 1.3.6.1.4.1.44668.5.3.1.2.1 and
    ///      1.3.6.1.4.1.44668.5.3.2.1), followed by the 96-byte compressed key.
    bytes internal constant DER_PREFIX =
        hex"308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100";
    uint256 internal constant DER_KEY_LENGTH = 133;

    /// @dev domain_sep("ic-state-root")
    bytes internal constant DS_STATE_ROOT = "\x0dic-state-root";

    /// @dev CBOR tag 55799 in front of the canister-ranges blob.
    bytes3 internal constant SELF_DESCRIBE = 0xd9d9f7;

    error BadDerKey();
    error CanisterNotInRanges();
    error MalformedRanges();
    error DelegationTooOld();

    /// @notice Verify `c` against the root key and require that it may certify `canisterId`.
    /// @param rootKey Uncompressed root public key (G2, 256 bytes).
    /// @param canisterId Principal bytes of the canister whose data is read.
    /// @param maxDelegationAgeNanos Reject delegations whose `/time` is older than the certificate's
    ///        `/time` by more than this (0 disables the check).
    /// @return root Root hash of `c.tree`.
    /// @return time `/time` of the certificate in nanoseconds since the Unix epoch.
    function verify(Certificate memory c, bytes memory rootKey, bytes memory canisterId, uint64 maxDelegationAgeNanos)
        internal
        view
        returns (bytes32 root, uint64 time)
    {
        root = IcpHashTree.reconstruct(c.tree);
        time = IcpHashTree.leb128(IcpHashTree.lookup(c.tree, _path1("time")));

        bytes memory signingKey = rootKey;
        if (c.subnetId.length != 0) {
            bytes32 droot = IcpHashTree.reconstruct(c.delegationTree);
            IcpBls.verify(rootKey, c.delegationSignature, abi.encodePacked(DS_STATE_ROOT, droot));

            bytes memory der = IcpHashTree.lookup(c.delegationTree, _path3("subnet", c.subnetId, "public_key"));
            IcpBls.requireMatchesCompressedG2(c.subnetKey, derToCompressed(der));
            signingKey = c.subnetKey;

            bytes memory ranges = c.rangesShard.length == 0
                ? IcpHashTree.lookup(c.delegationTree, _path3("subnet", c.subnetId, "canister_ranges"))
                : IcpHashTree.lookup(c.delegationTree, _path3("canister_ranges", c.subnetId, c.rangesShard));
            if (!inRanges(ranges, canisterId)) revert CanisterNotInRanges();

            if (maxDelegationAgeNanos != 0) {
                uint64 dtime = IcpHashTree.leb128(IcpHashTree.lookup(c.delegationTree, _path1("time")));
                if (dtime < time && time - dtime > maxDelegationAgeNanos) revert DelegationTooOld();
            }
        }
        IcpBls.verify(signingKey, c.signature, abi.encodePacked(DS_STATE_ROOT, root));
    }

    /// @notice The 96-byte compressed key inside a DER-encoded BLS key.
    function derToCompressed(bytes memory der) internal pure returns (bytes memory key) {
        if (der.length != DER_KEY_LENGTH) revert BadDerKey();
        for (uint256 i = 0; i < DER_PREFIX.length; i++) {
            if (der[i] != DER_PREFIX[i]) revert BadDerKey();
        }
        return IcpHashTree._slice(der, DER_PREFIX.length, 96);
    }

    /// @notice True if `id` lies in one of the closed intervals of the CBOR canister-ranges blob
    ///         `tagged<[*[principal principal]]>`, comparing principals lexicographically as bytes.
    function inRanges(bytes memory blob, bytes memory id) internal pure returns (bool) {
        uint256 off = 0;
        if (blob.length >= 3 && bytes3(_word3(blob)) == SELF_DESCRIBE) off = 3;
        (uint8 major, uint64 n, uint256 p) = IcpHashTree.readHead(blob, off);
        if (major != 4) revert MalformedRanges();
        for (uint256 i = 0; i < n; i++) {
            uint64 two;
            (major, two, p) = IcpHashTree.readHead(blob, p);
            if (major != 4 || two != 2) revert MalformedRanges();
            (uint256 s0, uint256 l0, uint256 p1) = IcpHashTree.readBytes(blob, p);
            (uint256 s1, uint256 l1, uint256 p2) = IcpHashTree.readBytes(blob, p1);
            p = p2;
            if (_cmp(blob, s0, l0, id) <= 0 && _cmp(blob, s1, l1, id) >= 0) return true;
        }
        if (p != blob.length) revert MalformedRanges();
        return false;
    }

    /// @dev Lexicographic comparison of blob[s .. s+l) with `id`: −1, 0 or 1.
    function _cmp(bytes memory blob, uint256 s, uint256 l, bytes memory id) private pure returns (int256) {
        uint256 m = l < id.length ? l : id.length;
        for (uint256 i = 0; i < m; i++) {
            uint8 a = uint8(blob[s + i]);
            uint8 b = uint8(id[i]);
            if (a != b) return a < b ? int256(-1) : int256(1);
        }
        if (l == id.length) return 0;
        return l < id.length ? int256(-1) : int256(1);
    }

    function _word3(bytes memory b) private pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(b, 0x20))
        }
    }

    // ── path builders ───────────────────────────────────────────────────────

    function _path1(bytes memory a) internal pure returns (bytes[] memory p) {
        p = new bytes[](1);
        p[0] = a;
    }

    function _path3(bytes memory a, bytes memory b, bytes memory c) internal pure returns (bytes[] memory p) {
        p = new bytes[](3);
        p[0] = a;
        p[1] = b;
        p[2] = c;
    }

    /// @notice `/canister/<canisterId>/certified_data` of a verified certificate tree.
    function certifiedData(bytes memory tree, bytes memory canisterId) internal pure returns (bytes32 data) {
        bytes memory v = IcpHashTree.lookup(tree, _path3("canister", canisterId, "certified_data"));
        if (v.length != 32) revert IcpHashTree.MalformedTree();
        assembly ("memory-safe") {
            data := mload(add(v, 0x20))
        }
    }
}
