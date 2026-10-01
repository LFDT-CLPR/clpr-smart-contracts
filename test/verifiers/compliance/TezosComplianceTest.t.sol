// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprVerifierComplianceTest} from "@test/verifiers/compliance/ClprVerifierComplianceTest.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {TezosBlake2b} from "@hiero-ledger/clpr/libraries/proof/tezos/TezosBlake2b.sol";
import {TezosLightClient} from "@hiero-ledger/clpr/verifiers/evm/tezos/TezosLightClient.sol";
import {TezosSignatureCache} from "@hiero-ledger/clpr/verifiers/evm/tezos/TezosSignatureCache.sol";
import {TezosContextVerifier} from "@hiero-ledger/clpr/verifiers/evm/tezos/TezosContextVerifier.sol";
import {TezosVerifier} from "@hiero-ledger/clpr/verifiers/evm/tezos/TezosVerifier.sol";
import {Ed25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/Ed25519Verifier.sol";

/// @dev TezosVerifier whose finality step only enforces "after the anchor" and returns the proof's
///      context root. The compliance suite needs context trees built on the fly, which real
///      attestation signatures cannot follow; the finality pipeline is covered by
///      TezosVerifier.t.sol (synthetic chain) and TezosLive.t.sol (mainnet data).
contract TezosVerifierFinalityStub is TezosVerifier {
    constructor(Profile memory p, IEd25519Verifier ed, TezosSignatureCache c, bytes memory service)
        TezosVerifier(
            p, ed, c, new TezosContextVerifier(), "tezos:NetXdQprcVkpaWU", service, 7, 1000, bytes32(uint256(1))
        )
    {}

    function _verifyFinality(FinalityProof memory p, uint32 anchorLevel, bytes32)
        internal
        pure
        override
        returns (uint32, bytes32)
    {
        if (p.level < 3 || p.level - 2 <= anchorLevel) revert NotAfterAnchor();
        return (p.level - 2, p.contextRoot);
    }
}

/// @title TezosComplianceTest
/// @notice Compliance adapter binding TezosVerifier to the shared verifier compliance suite. Context
///         trees (Tezos Irmin stable directories, BLAKE2b) are built here for each vector; only the
///         attestation-quorum step is stubbed (see {TezosVerifierFinalityStub}).
contract TezosComplianceTest is ClprVerifierComplianceTest {
    bytes internal constant SERVICE = hex"01111111111111111111111111111111111111111100";
    bytes32 internal constant CHANNEL = bytes32(uint256(0xc1));
    uint256 internal constant BIG_MAP = 7;

    bytes internal record;
    bytes internal manifestPreimage;
    bytes internal controlMessage;

    function _deployVerifier() internal override returns (IClprVerifier) {
        TezosLightClient.Profile memory p = TezosLightClient.Profile({
            chainId: 0x7a06a770,
            protocolLevel: 25,
            eraFirstLevel: 1,
            eraFirstCycle: 0,
            blocksPerCycle: 200,
            committeeSize: 100,
            threshold: 67
        });
        Ed25519Verifier ed = new Ed25519Verifier();
        TezosVerifierFinalityStub v = new TezosVerifierFinalityStub(p, ed, new TezosSignatureCache(ed), SERVICE);
        record = _record(7, keccak256("sent"));
        manifestPreimage = ClprProtobuf.encodeEndpointManifest(_buildManifest(1, SERVICE, 1));
        controlMessage = _control("tezos:NetXdQprcVkpaWU");
        return IClprVerifier(address(v));
    }

    // ── context tree (stable directories only) ─────────────────────────────

    function _hex(bytes memory b) internal pure returns (bytes memory out) {
        bytes16 digits = "0123456789abcdef";
        out = new bytes(b.length * 2);
        for (uint256 i = 0; i < b.length; i++) {
            out[2 * i] = digits[uint8(b[i]) >> 4];
            out[2 * i + 1] = digits[uint8(b[i]) & 0x0f];
        }
    }

    function _keyHex(bytes memory key) internal view returns (bytes memory) {
        return _hex(abi.encodePacked(TezosBlake2b.hash256(abi.encodePacked(bytes2(0x050a), uint32(key.length), key))));
    }

    function _contentsHash(bytes memory v) internal view returns (bytes32) {
        return TezosBlake2b.hash256(abi.encodePacked(uint64(v.length), v));
    }

    /// Stable directory preimage of entries already sorted by name (names < 128 bytes).
    function _dir(bytes[] memory names, bool[] memory isContents, bytes32[] memory hashes)
        internal
        pure
        returns (bytes memory pre)
    {
        pre = abi.encodePacked(uint64(names.length));
        for (uint256 i = 0; i < names.length; i++) {
            pre = abi.encodePacked(
                pre,
                isContents[i] ? bytes8(0xff00000000000000) : bytes8(0),
                uint8(names[i].length),
                names[i],
                uint64(32),
                hashes[i]
            );
        }
    }

    function _one(bytes memory name, bool isContents, bytes32 h) internal pure returns (bytes memory) {
        bytes[] memory n = new bytes[](1);
        n[0] = name;
        bool[] memory c = new bool[](1);
        c[0] = isContents;
        bytes32[] memory hs = new bytes32[](1);
        hs[0] = h;
        return _dir(n, c, hs);
    }

    function _lvl(bytes memory pre) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), uint16(pre.length), pre);
    }

    struct World {
        bytes32 root;
        bytes queueProof;
        bytes manifestProof;
        bytes configProof;
        bytes storageProof;
    }

    /// root{data{big_maps{index{7{contents{q‖ch, m, c}}}}, contracts{index{svc{data{storage}}}}}}
    function _world(bytes memory rec, bytes memory manifest, bytes memory control)
        internal
        view
        returns (World memory w)
    {
        bytes[3] memory vals = [
            abi.encodePacked(bytes1(0x0a), uint32(rec.length), rec),
            abi.encodePacked(bytes1(0x0a), uint32(32), keccak256(manifest)),
            abi.encodePacked(bytes1(0x0a), uint32(32), keccak256(control))
        ];
        bytes[3] memory names = [_keyHex(abi.encodePacked(bytes1("q"), CHANNEL)), _keyHex("m"), _keyHex("c")];
        bytes[3] memory entryDirs;
        bytes32[3] memory entryHashes;
        for (uint256 i = 0; i < 3; i++) {
            entryDirs[i] = _one("data", true, _contentsHash(vals[i]));
            entryHashes[i] = TezosBlake2b.hash256(entryDirs[i]);
        }
        // sort the three key-hash names
        uint256[3] memory ord = [uint256(0), 1, 2];
        for (uint256 a = 0; a < 3; a++) {
            for (uint256 b = a + 1; b < 3; b++) {
                if (keccak256(names[ord[a]]) != keccak256(names[ord[b]]) && _less(names[ord[b]], names[ord[a]])) {
                    (ord[a], ord[b]) = (ord[b], ord[a]);
                }
            }
        }
        bytes[] memory n = new bytes[](3);
        bool[] memory c = new bool[](3);
        bytes32[] memory h = new bytes32[](3);
        for (uint256 i = 0; i < 3; i++) {
            n[i] = names[ord[i]];
            h[i] = entryHashes[ord[i]];
        }
        bytes memory contents = _dir(n, c, h);
        bytes memory bm = _one("contents", false, TezosBlake2b.hash256(contents));
        bytes memory index = _one("7", false, TezosBlake2b.hash256(bm));
        bytes memory bigMaps = _one("index", false, TezosBlake2b.hash256(index));

        bytes memory storageVal = hex"0007"; // Int 7
        bytes memory sdata = _one("storage", true, _contentsHash(storageVal));
        bytes memory svc = _one("data", false, TezosBlake2b.hash256(sdata));
        bytes memory cindex = _one(_hex(SERVICE), false, TezosBlake2b.hash256(svc));
        bytes memory contracts = _one("index", false, TezosBlake2b.hash256(cindex));

        bytes[] memory dn = new bytes[](2);
        dn[0] = "big_maps";
        dn[1] = "contracts";
        bool[] memory dc = new bool[](2);
        bytes32[] memory dh = new bytes32[](2);
        dh[0] = TezosBlake2b.hash256(bigMaps);
        dh[1] = TezosBlake2b.hash256(contracts);
        bytes memory data = _dir(dn, dc, dh);
        bytes memory root = _one("data", false, TezosBlake2b.hash256(data));
        w.root = TezosBlake2b.hash256(root);

        bytes memory top =
            abi.encodePacked(_lvl(root), _lvl(data), _lvl(bigMaps), _lvl(index), _lvl(bm), _lvl(contents));
        w.queueProof = abi.encodePacked(top, _lvl(entryDirs[0]), uint32(vals[0].length), vals[0]);
        w.manifestProof = abi.encodePacked(top, _lvl(entryDirs[1]), uint32(vals[1].length), vals[1]);
        w.configProof = abi.encodePacked(top, _lvl(entryDirs[2]), uint32(vals[2].length), vals[2]);
        w.storageProof = abi.encodePacked(
            _lvl(root), _lvl(data), _lvl(contracts), _lvl(cindex), _lvl(svc), _lvl(sdata), uint32(2), storageVal
        );
    }

    function _less(bytes memory a, bytes memory b) internal pure returns (bool) {
        for (uint256 i = 0; i < a.length && i < b.length; i++) {
            if (a[i] != b[i]) return uint8(a[i]) < uint8(b[i]);
        }
        return a.length < b.length;
    }

    function _record(uint64 next, bytes32 sent) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(1), next, uint64(5), sent, keccak256("recv"), uint64(1));
    }

    function _control(string memory chainId) internal pure returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory lc;
        lc.protocolVersion = 1;
        lc.chainId = chainId;
        lc.serviceAddress = SERVICE;
        lc.nanosSinceEpoch = 1_790_000_000 * 1e9;
        lc.throttles.maxMessagesPerBundle = 50;
        return ClprProtobuf.encodeControlMessage(lc);
    }

    function _finality(bytes32 root, uint32 level) internal pure returns (TezosLightClient.FinalityProof memory f) {
        f.level = level;
        f.contextRoot = root;
    }

    function _anchor() internal pure returns (bytes memory) {
        return abi.encode(uint32(1001), bytes32(uint256(1))); // cycle 5; the bundle stays in cycle 5
    }

    function _ctx() internal pure returns (bytes memory) {
        return
            ClprTypes.encodeChannelContext(
                ClprTypes.ChannelContext({channelId: CHANNEL, remoteServiceAddress: SERVICE})
            );
    }

    function _content() internal pure returns (bytes memory) {
        return hex"12030a0101" // field 2 × 2 payloads
            hex"12030a0102";
    }

    function _bundle(World memory w) internal pure returns (bytes memory) {
        TezosVerifier.BundleProof memory b;
        b.finality = _finality(w.root, 1012);
        b.queueProof = w.queueProof;
        b.bundleContent = _content();
        return abi.encode(b);
    }

    function _configFor(World memory w, bytes memory control) internal pure returns (bytes memory) {
        TezosVerifier.ConfigProof memory c;
        c.finality = _finality(w.root, 1012);
        c.storageProof = w.storageProof;
        c.configProof = w.configProof;
        c.controlMessage = control;
        return abi.encode(c);
    }

    // ── adapter hooks ─────────────────────────────────────────────────────

    function _validConfig() internal view override returns (ConfigVector memory) {
        World memory w = _world(record, manifestPreimage, controlMessage);
        return ConfigVector(_configFor(w, controlMessage), CHANNEL, "tezos:NetXdQprcVkpaWU", SERVICE);
    }

    function _validBundle() internal view override returns (BundleVector memory) {
        World memory w = _world(record, manifestPreimage, controlMessage);
        return BundleVector(_bundle(w), _anchor(), _ctx(), 7, 2);
    }

    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        view
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        World memory w = _world(record, committedPreimage, controlMessage);
        configProof = _configFor(w, controlMessage);
        channelId = CHANNEL;
        manifestProof = abi.encode(TezosVerifier.ManifestProof(w.manifestProof, carriedPreimage));
    }

    function _runningHashVector() internal override returns (RunningHashVector memory) {
        bytes32 h = sha256(abi.encodePacked(bytes32(0), sha256(hex"0a0101")));
        h = sha256(abi.encodePacked(h, sha256(hex"0a0102")));
        record = _record(7, h);
        World memory w = _world(record, manifestPreimage, controlMessage);
        return RunningHashVector(_bundle(w), _anchor(), _ctx(), bytes32(0));
    }

    function _wrongChainConfigVector() internal view override returns (bytes memory, bytes32) {
        bytes memory other = _control("tezos:NetXnHfVqm9iesp");
        World memory w = _world(record, manifestPreimage, other);
        return (_configFor(w, other), CHANNEL);
    }
}
