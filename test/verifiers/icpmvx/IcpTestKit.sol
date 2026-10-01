// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {IcpBls} from "@hiero-ledger/clpr/libraries/proof/icp/IcpBls.sol";
import {IcpCertificate} from "@hiero-ledger/clpr/libraries/proof/icp/IcpCertificate.sol";
import {IcpHashTree} from "@hiero-ledger/clpr/libraries/proof/icp/IcpHashTree.sol";
import {IcpVerifier} from "@hiero-ledger/clpr/verifiers/icpmvx/IcpVerifier.sol";

/// @title IcpTestKit
/// @notice A synthetic Internet Computer for IcpVerifier tests: BLS keys and signatures made with the
///         EIP-2537 MSM precompiles (sk·G2 and sk·H(m)), CBOR hash trees, DER keys, canister ranges,
///         and a CLPR canister witness. Everything except the keys follows the mainnet formats that
///         IcpLive.t.sol checks against real certificates.
abstract contract IcpTestKit is Test {
    bytes internal constant G2_GENERATOR =
        hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";

    uint256 internal constant ROOT_SK = 0x1234567;
    uint256 internal constant SUBNET_SK = 0x7654321;
    string internal constant CHAIN = "icp:test";
    bytes32 internal constant CHANNEL = keccak256("icp-channel");
    uint64 internal constant TIME = 1_790_000_000_000_000_000;

    bytes internal SUBNET_ID = hex"4f82b62edffa3fa4e6a5c48327ce8cfb3f850db2e5abc90e955d77f002";
    bytes internal CANISTER = hex"00000000023000060101";
    bytes internal RANGE_START = hex"00000000023000000101";
    bytes internal RANGE_END = hex"000000000230ffff0101";

    // mutable world state used by the builders
    bytes internal record;
    bytes internal manifest;
    bytes internal control;
    uint64 internal delegationTime = TIME - 300e9;

    IcpVerifier internal v;
    bytes internal rootDer;
    bytes internal rootKey;
    bytes internal subnetKey;

    function setUp() public virtual {
        rootKey = _pk(ROOT_SK);
        rootDer = _der(rootKey);
        subnetKey = _pk(SUBNET_SK);
        v = new IcpVerifier(CHAIN, rootDer, rootKey, 1 days * 1e9);
        bytes32 sent =
            sha256(abi.encodePacked(sha256(abi.encodePacked(bytes32(0), sha256(hex"0a0101"))), sha256(hex"0a0102")));
        record = _record(1, 7, 5, sent, keccak256("recv"), 3);
        manifest = ClprProtobuf.encodeEndpointManifest(_manifest(2, CANISTER));
        control = _control(CHAIN, CANISTER);
    }

    // ── keys and signatures ─────────────────────────────────────────────────

    function _pk(uint256 sk) internal view returns (bytes memory) {
        (bool ok, bytes memory out) = address(0x0e).staticcall(abi.encodePacked(G2_GENERATOR, sk));
        require(ok && out.length == 256, "G2MSM");
        return out;
    }

    function _sign(uint256 sk, bytes32 root) internal view returns (bytes memory) {
        bytes memory h = IcpBls.hashToG1(abi.encodePacked(IcpCertificate.DS_STATE_ROOT, root));
        (bool ok, bytes memory out) = address(0x0c).staticcall(abi.encodePacked(h, sk));
        require(ok && out.length == 128, "G1MSM");
        return out;
    }

    /// @dev DER key carrying x of `pk` with the compression flag. The verifier never reads the y flag,
    ///      so the builder leaves it clear.
    function _der(bytes memory pk) internal pure returns (bytes memory) {
        bytes memory c = new bytes(96);
        for (uint256 i = 0; i < 48; i++) {
            c[i] = pk[80 + i];
            c[48 + i] = pk[16 + i];
        }
        c[0] = bytes1(uint8(c[0]) | 0x80);
        return bytes.concat(IcpCertificate.DER_PREFIX, c);
    }

    // ── CBOR hash trees ─────────────────────────────────────────────────────

    function _head(uint8 major, uint256 n) internal pure returns (bytes memory) {
        if (n < 24) return abi.encodePacked(uint8((major << 5) | n));
        if (n < 256) return abi.encodePacked(uint8((major << 5) | 24), uint8(n));
        if (n < 65536) return abi.encodePacked(uint8((major << 5) | 25), uint16(n));
        return abi.encodePacked(uint8((major << 5) | 26), uint32(n));
    }

    function _cbytes(bytes memory b) internal pure returns (bytes memory) {
        return bytes.concat(_head(2, b.length), b);
    }

    function _empty() internal pure returns (bytes memory) {
        return hex"8100";
    }

    function _fork(bytes memory a, bytes memory b) internal pure returns (bytes memory) {
        return bytes.concat(hex"8301", a, b);
    }

    function _labeled(bytes memory label, bytes memory t) internal pure returns (bytes memory) {
        return bytes.concat(hex"8302", _cbytes(label), t);
    }

    function _leaf(bytes memory value) internal pure returns (bytes memory) {
        return bytes.concat(hex"8203", _cbytes(value));
    }

    function _pruned(bytes32 h) internal pure returns (bytes memory) {
        return bytes.concat(hex"8204", _cbytes(abi.encodePacked(h)));
    }

    function _leb(uint64 x) internal pure returns (bytes memory out) {
        do {
            uint8 b = uint8(x & 0x7f);
            x >>= 7;
            out = bytes.concat(out, abi.encodePacked(x == 0 ? b : b | 0x80));
        } while (x != 0);
    }

    function _ranges(bytes memory lo, bytes memory hi) internal pure returns (bytes memory) {
        return bytes.concat(hex"d9d9f78182", _cbytes(lo), _cbytes(hi));
    }

    // ── the CLPR canister and its certificate ───────────────────────────────

    function _record(uint8 status, uint64 next, uint64 received, bytes32 sent, bytes32 recvHash, uint64 manifestVersion)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(status, next, received, sent, recvHash, manifestVersion);
    }

    function _witness() internal view returns (bytes memory) {
        return _witnessFor(CHANNEL, record);
    }

    function _witnessFor(bytes32 channel, bytes memory rec) internal view returns (bytes memory) {
        bytes memory queue = _labeled("queue", _labeled(abi.encodePacked(channel), _leaf(rec)));
        bytes memory cfg = _labeled("config", _leaf(abi.encodePacked(keccak256(control))));
        bytes memory man = _labeled("manifest", _leaf(abi.encodePacked(keccak256(manifest))));
        return _labeled("clpr", _fork(_fork(cfg, man), queue));
    }

    function _stateTree(bytes memory canister, bytes32 certifiedData, uint64 time)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory c = _labeled(
            "canister", _labeled(canister, _labeled("certified_data", _leaf(abi.encodePacked(certifiedData))))
        );
        return _fork(c, _labeled("time", _leaf(_leb(time))));
    }

    function _delegationTree(bytes memory pkDer, bytes memory ranges, bool sharded)
        internal
        view
        returns (bytes memory)
    {
        bytes memory subnet;
        if (sharded) {
            subnet = _fork(
                _labeled("canister_ranges", _labeled(SUBNET_ID, _labeled(RANGE_START, _leaf(ranges)))),
                _labeled("subnet", _labeled(SUBNET_ID, _labeled("public_key", _leaf(pkDer))))
            );
        } else {
            subnet = _labeled(
                "subnet",
                _labeled(
                    SUBNET_ID, _fork(_labeled("canister_ranges", _leaf(ranges)), _labeled("public_key", _leaf(pkDer)))
                )
            );
        }
        return _fork(subnet, _labeled("time", _leaf(_leb(delegationTime))));
    }

    /// @dev A delegated certificate of `canister`'s certified data.
    function _cert(bytes memory canister, bytes32 certifiedData)
        internal
        view
        returns (IcpCertificate.Certificate memory c)
    {
        c.tree = _stateTree(canister, certifiedData, TIME);
        c.signature = _sign(SUBNET_SK, IcpHashTree.reconstruct(c.tree));
        c.subnetId = SUBNET_ID;
        c.delegationTree = _delegationTree(_der(subnetKey), _ranges(RANGE_START, RANGE_END), false);
        c.delegationSignature = _sign(ROOT_SK, IcpHashTree.reconstruct(c.delegationTree));
        c.subnetKey = subnetKey;
    }

    /// @dev A certificate signed by the root key itself (root subnet, no delegation).
    function _rootCert(bytes memory canister, bytes32 certifiedData)
        internal
        view
        returns (IcpCertificate.Certificate memory c)
    {
        c.tree = _stateTree(canister, certifiedData, TIME);
        c.signature = _sign(ROOT_SK, IcpHashTree.reconstruct(c.tree));
    }

    function _resign(IcpCertificate.Certificate memory c) internal view {
        c.signature = _sign(SUBNET_SK, IcpHashTree.reconstruct(c.tree));
        if (c.delegationTree.length != 0) {
            c.delegationSignature = _sign(ROOT_SK, IcpHashTree.reconstruct(c.delegationTree));
        }
    }

    function _bundleContent() internal pure returns (bytes memory) {
        return hex"12030a0101" hex"12030a0102";
    }

    function _bundle(bool withManifest) internal view returns (IcpVerifier.BundleProof memory p) {
        bytes memory w = _witness();
        p.cert = _cert(CANISTER, IcpHashTree.reconstruct(w));
        p.witness = w;
        p.bundleContent = _bundleContent();
        if (withManifest) p.manifestPreimage = manifest;
    }

    function _configProofStruct() internal view returns (IcpVerifier.ConfigProof memory p) {
        bytes memory w = _witness();
        p.cert = _cert(CANISTER, IcpHashTree.reconstruct(w));
        p.witness = w;
        p.controlMessage = control;
    }

    /// @dev keccak256 of the DER root key (no external call, so it is safe under vm.expectRevert).
    function _anchor() internal view returns (bytes memory) {
        return abi.encodePacked(keccak256(rootDer));
    }

    function _ctx() internal view returns (bytes memory) {
        return
            ClprTypes.encodeChannelContext(
                ClprTypes.ChannelContext({channelId: CHANNEL, remoteServiceAddress: CANISTER})
            );
    }

    function _control(string memory chainId, bytes memory service) internal pure returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory lc;
        lc.protocolVersion = 1;
        lc.chainId = chainId;
        lc.serviceAddress = service;
        lc.nanosSinceEpoch = 1_700_000_000_000_000_000;
        lc.throttles = ClprTypes.Throttles(10, 4096, 500_000, 100, 131_072, 4, 4);
        return ClprProtobuf.encodeControlMessage(lc);
    }

    function _manifest(uint64 version, bytes memory service)
        internal
        pure
        returns (ClprTypes.ClprEndpointManifest memory m)
    {
        m.version = version;
        m.serviceAddress = service;
        m.endpoints = new ClprTypes.Endpoint[](0);
    }
}
