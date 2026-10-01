// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprBeaconBls} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconBls.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprAvalancheWarp as Warp} from "@hiero-ledger/clpr/libraries/proof/avalanche/ClprAvalancheWarp.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {QbftSyntheticProofs} from "@test/helpers/QbftSyntheticProofs.sol";

/// @dev Synthetic Avalanche chain for AvalancheWarpVerifier tests: a canonical Warp validator set with
///      real BLS12-381 keys (pk = sk·G1 via G1MSM), real Warp signatures over the 80-byte
///      UnsignedMessage of a block-hash payload (σ = (Σ sk)·H(m) via G2MSM, H = RFC 9380 hash-to-G2 with
///      the `_POP_` DST), coreth-shaped 16-field headers, coreth 5-field accounts, the synthetic MPT
///      storage proofs from {QbftSyntheticProofs}, and secp256k1 attestor signatures for rotations.
abstract contract AvalancheWarpFixtures is QbftSyntheticProofs {
    address internal constant BLS12_G1MSM = address(0x0c);
    address internal constant BLS12_G2MSM = address(0x0e);
    bytes internal constant G1_GEN =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
    uint256 internal constant R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    uint32 internal constant NETWORK_ID = 5;
    bytes32 internal constant C_CHAIN_ID = 0x7fc93d85c6d62c5b2ac0b519c87010ea5294012d1e407030d6acd0021cac10d5;
    uint256 internal constant EVM_CHAIN_ID = 43113;
    address internal constant SERVICE_ADDR = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;
    bytes32 internal constant SERVICE_CODE_HASH = bytes32(uint256(0xC0DE));
    bytes32 internal constant CHANNEL_ID = bytes32(uint256(0xA7A));
    uint64 internal constant P_HEIGHT = 1000;
    uint64 internal constant P_TIME = 1_790_000_000;
    uint64 internal constant MAX_AGE = 12 hours;
    uint64 internal constant BLOCK_TIME = P_TIME + 600;
    bytes32 internal constant VALIDATOR_SET_TYPEHASH = keccak256(
        "ClprAvalancheValidatorSet(uint32 networkId,bytes32 sourceChainId,uint64 pChainHeight,uint64 pChainTimestamp,bytes32 setHash,uint256 totalWeight)"
    );

    struct Val {
        uint256 sk;
        bytes pub; // 128-byte EIP-2537
        uint64 weight;
    }

    struct Set {
        Val[] vals; // canonical order
        bytes packed;
        uint256 totalWeight;
    }

    struct Hdr {
        bytes rlp;
        bytes32 hash;
    }

    uint256[] internal attestorPks;
    address[] internal attestorAddrs; // ascending

    // ── Validators ────────────────────────────────────────────────────────────

    /// `n` validators in avalanchego canonical order (ascending uncompressed key), weight `w(i)`.
    function _makeSet(uint256 n, string memory seed, uint64[] memory weights) internal view returns (Set memory s) {
        Val[] memory vals = new Val[](n);
        uint256[] memory sortKey = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            uint256 sk = (uint256(keccak256(abi.encode(seed, i))) % (2 ** 200)) + 1;
            (bool ok, bytes memory pub) = BLS12_G1MSM.staticcall(abi.encodePacked(G1_GEN, bytes32(sk)));
            require(ok && pub.length == 128, "G1MSM");
            vals[i] = Val({sk: sk, pub: pub, weight: weights.length == 0 ? 1e9 : weights[i]});
            sortKey[i] = _w0(pub);
        }
        _sort(vals, sortKey);
        for (uint256 i = 1; i < n; i++) {
            require(sortKey[i - 1] < sortKey[i], "fixture: key prefix collision");
        }
        s.vals = vals;
        s.packed = _pack(vals);
        for (uint256 i = 0; i < n; i++) {
            s.totalWeight += vals[i].weight;
        }
    }

    function _equalSet(uint256 n, string memory seed) internal view returns (Set memory) {
        return _makeSet(n, seed, new uint64[](0));
    }

    /// First 32 bytes of the 96-byte uncompressed key `x ‖ y` (x starts at byte 16 of the EIP-2537 form).
    function _w0(bytes memory pub) internal pure returns (uint256 w) {
        assembly {
            w := mload(add(pub, 48))
        }
    }

    function _sort(Val[] memory vals, uint256[] memory k) internal pure {
        if (vals.length > 1) _quick(vals, k, 0, int256(vals.length - 1));
    }

    function _quick(Val[] memory v, uint256[] memory k, int256 lo, int256 hi) private pure {
        if (lo >= hi) return;
        uint256 p = k[uint256((lo + hi) / 2)];
        int256 i = lo;
        int256 j = hi;
        while (i <= j) {
            while (k[uint256(i)] < p) i++;
            while (k[uint256(j)] > p) j--;
            if (i <= j) {
                (k[uint256(i)], k[uint256(j)]) = (k[uint256(j)], k[uint256(i)]);
                (v[uint256(i)], v[uint256(j)]) = (v[uint256(j)], v[uint256(i)]);
                i++;
                j--;
            }
        }
        if (lo < j) _quick(v, k, lo, j);
        if (i < hi) _quick(v, k, i, hi);
    }

    /// Packed wire set: n × (x48 ‖ y48 ‖ weight8).
    function _pack(Val[] memory vals) internal pure returns (bytes memory out) {
        out = new bytes(vals.length * 104);
        for (uint256 i = 0; i < vals.length; i++) {
            bytes memory p = vals[i].pub;
            uint64 w = vals[i].weight;
            assembly {
                let dst := add(add(out, 32), mul(i, 104))
                mcopy(dst, add(p, 48), 48) // x
                mcopy(add(dst, 48), add(p, 112), 48) // y
                mstore(add(dst, 96), or(shl(192, w), and(mload(add(dst, 96)), sub(shl(192, 1), 1))))
            }
        }
    }

    // ── Signatures ────────────────────────────────────────────────────────────

    /// Minimal big-endian Avalanche bit set for `idx` (ascending), as `set.BitsFromBytes` expects.
    function _bits(uint256[] memory idx) internal pure returns (bytes memory b) {
        uint256 top;
        for (uint256 i = 0; i < idx.length; i++) {
            if (idx[i] + 1 > top) top = idx[i] + 1;
        }
        b = new bytes((top + 7) / 8);
        for (uint256 i = 0; i < idx.length; i++) {
            uint256 j = idx[i];
            b[b.length - 1 - j / 8] = bytes1(uint8(b[b.length - 1 - j / 8]) | uint8(1 << (j % 8)));
        }
    }

    function _range(uint256 from, uint256 to) internal pure returns (uint256[] memory r) {
        r = new uint256[](to - from);
        for (uint256 i = from; i < to; i++) {
            r[i - from] = i;
        }
    }

    function _signMessage(Set memory s, uint256[] memory idx, bytes memory message)
        internal
        view
        returns (bytes memory)
    {
        uint256 skSum;
        for (uint256 i = 0; i < idx.length; i++) {
            skSum = addmod(skSum, s.vals[idx[i]].sk, R);
        }
        bytes memory h = ClprBeaconBls.hashToG2Message(message);
        (bool ok, bytes memory sig) = BLS12_G2MSM.staticcall(abi.encodePacked(h, bytes32(skSum)));
        require(ok && sig.length == 256, "G2MSM");
        return sig;
    }

    /// RLP `[signers, signature]` over `payload.Hash(blockHash)` by validators `idx`.
    function _warpSig(Set memory s, uint256[] memory idx, bytes32 blockHash) internal view returns (bytes memory) {
        return _warpSigFor(s, idx, NETWORK_ID, C_CHAIN_ID, blockHash);
    }

    function _warpSigFor(Set memory s, uint256[] memory idx, uint32 networkId, bytes32 chainId, bytes32 blockHash)
        internal
        view
        returns (bytes memory)
    {
        bytes memory sig = _signMessage(s, idx, Warp.blockHashMessage(networkId, chainId, blockHash));
        return _pair(RLP.encode(_bits(idx)), RLP.encode(sig));
    }

    // ── Headers ───────────────────────────────────────────────────────────────

    /// Coreth-shaped header (geth's 15 fields + ExtDataHash).
    function _header(uint64 number, bytes32 stateRoot, uint64 time) internal pure returns (Hdr memory h) {
        bytes[] memory f = new bytes[](16);
        f[0] = RLP.encode(keccak256(abi.encode("parent", number)));
        f[1] = RLP.encode(bytes32(0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347));
        f[2] = RLP.encode(address(0x0100000000000000000000000000000000000000));
        f[3] = RLP.encode(stateRoot);
        f[4] = RLP.encode(bytes32(0));
        f[5] = RLP.encode(bytes32(0));
        f[6] = RLP.encode(new bytes(256));
        f[7] = RLP.encode(uint256(1));
        f[8] = RLP.encode(uint256(number));
        f[9] = RLP.encode(uint256(15_000_000));
        f[10] = RLP.encode(uint256(0));
        f[11] = RLP.encode(uint256(time));
        f[12] = RLP.encode(new bytes(0));
        f[13] = RLP.encode(bytes32(0));
        f[14] = RLP.encode(new bytes(8));
        f[15] = RLP.encode(bytes32(0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421));
        h.rlp = RLP.encode(f);
        h.hash = keccak256(h.rlp);
    }

    // ── Service state ─────────────────────────────────────────────────────────

    /// Coreth state account: `[nonce, balance, root, codeHash, isMultiCoin]` (5th field empty = false).
    function _corethAccountProof(address service, bytes32 storageRoot, bytes32 codeHash)
        internal
        pure
        returns (bytes32 stateRoot, bytes memory proof)
    {
        bytes[] memory f = new bytes[](5);
        f[0] = RLP.encode(uint256(1));
        f[1] = RLP.encode(uint256(0));
        f[2] = RLP.encode(storageRoot);
        f[3] = RLP.encode(codeHash);
        f[4] = RLP.encode(new bytes(0));
        return _buildSyntheticMPTProof(keccak256(abi.encodePacked(service)), RLP.encode(f));
    }

    function _serviceState() internal pure returns (bytes32 stateRoot, bytes memory account, bytes memory storage_) {
        bytes32 storageRoot;
        (storageRoot, storage_) = _buildChannelStorageProof6(CHANNEL_ID);
        (stateRoot, account) = _corethAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
    }

    // ── Anchor / bundle / rotation ────────────────────────────────────────────

    function _attestorsHash(uint256 threshold) internal view returns (bytes32) {
        return keccak256(abi.encode(threshold, attestorAddrs));
    }

    function _anchor(Set memory s, uint64 height, uint64 time) internal view returns (bytes memory) {
        return _anchorFull(s, height, time, MAX_AGE, NETWORK_ID, SERVICE_CODE_HASH, _attestorsHash(2));
    }

    function _anchorFull(
        Set memory s,
        uint64 height,
        uint64 time,
        uint64 maxAge,
        uint32 networkId,
        bytes32 codeHash,
        bytes32 attHash
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            networkId,
            C_CHAIN_ID,
            CHANNEL_ID,
            codeHash,
            keccak256(s.packed),
            s.totalWeight,
            height,
            time,
            maxAge,
            attHash
        );
    }

    function _channelContext() internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: CHANNEL_ID, remoteServiceAddress: abi.encodePacked(SERVICE_ADDR)})
        );
    }

    function _bundle(
        bytes memory header,
        bytes memory warpSig,
        bytes memory packedSet,
        bytes memory rotation,
        bytes memory account,
        bytes memory storage_
    ) internal pure returns (bytes memory) {
        bytes[] memory top = new bytes[](7);
        top[0] = RLP.encode(header);
        top[1] = warpSig;
        top[2] = RLP.encode(packedSet);
        top[3] = rotation;
        top[4] = account;
        top[5] = storage_;
        top[6] = RLP.encode(new bytes(0));
        return RLP.encode(top);
    }

    function _noRotation() internal pure returns (bytes memory) {
        return hex"80";
    }

    /// A complete bundle signed by `idx` of `s` over a header at BLOCK_TIME.
    function _signedBundle(Set memory s, uint256[] memory idx, bytes memory rotation)
        internal
        view
        returns (bytes memory)
    {
        (bytes32 stateRoot, bytes memory account, bytes memory storage_) = _serviceState();
        Hdr memory h = _header(100, stateRoot, BLOCK_TIME);
        return _bundle(h.rlp, _warpSig(s, idx, h.hash), s.packed, rotation, account, storage_);
    }

    function _setupAttestors() internal {
        delete attestorPks;
        delete attestorAddrs;
        uint256[3] memory pks = [uint256(0xA11CE), uint256(0xB0B), uint256(0xCAFE)];
        // insertion-sort by address
        for (uint256 i = 0; i < 3; i++) {
            attestorPks.push(pks[i]);
            attestorAddrs.push(vm.addr(pks[i]));
            for (uint256 j = attestorAddrs.length - 1; j > 0 && attestorAddrs[j - 1] > attestorAddrs[j]; j--) {
                (attestorAddrs[j - 1], attestorAddrs[j]) = (attestorAddrs[j], attestorAddrs[j - 1]);
                (attestorPks[j - 1], attestorPks[j]) = (attestorPks[j], attestorPks[j - 1]);
            }
        }
    }

    function _digest(uint64 height, uint64 time, bytes32 setHash, uint256 totalWeight) internal pure returns (bytes32) {
        return MessageHashUtils.toEthSignedMessageHash(
            keccak256(abi.encode(VALIDATOR_SET_TYPEHASH, NETWORK_ID, C_CHAIN_ID, height, time, setHash, totalWeight))
        );
    }

    function _attSig(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// Rotation item signed by attestors `who` (indices into the ascending attestor list).
    function _rotation(Set memory next, uint64 height, uint64 time, uint256 threshold, uint256[] memory who)
        internal
        view
        returns (bytes memory)
    {
        bytes32 d = _digest(height, time, keccak256(next.packed), next.totalWeight);
        bytes[] memory sigs = new bytes[](who.length);
        for (uint256 i = 0; i < who.length; i++) {
            sigs[i] = RLP.encode(_attSig(attestorPks[who[i]], d));
        }
        return _rotationRaw(height, time, next.totalWeight, threshold, _attestorList(), RLP.encode(sigs));
    }

    function _rotationRaw(
        uint64 height,
        uint64 time,
        uint256 totalWeight,
        uint256 threshold,
        bytes memory attestors,
        bytes memory sigs
    ) internal pure returns (bytes memory) {
        bytes[] memory r = new bytes[](6);
        r[0] = RLP.encode(uint256(height));
        r[1] = RLP.encode(uint256(time));
        r[2] = RLP.encode(totalWeight);
        r[3] = RLP.encode(threshold);
        r[4] = attestors;
        r[5] = sigs;
        return RLP.encode(r);
    }

    function _attestorList() internal view returns (bytes memory) {
        bytes[] memory a = new bytes[](attestorAddrs.length);
        for (uint256 i = 0; i < a.length; i++) {
            a[i] = RLP.encode(attestorAddrs[i]);
        }
        return RLP.encode(a);
    }

    // ── RLP helpers ───────────────────────────────────────────────────────────

    function _pair(bytes memory a, bytes memory b) internal pure returns (bytes memory) {
        bytes[] memory l = new bytes[](2);
        l[0] = a;
        l[1] = b;
        return RLP.encode(l);
    }

    function _list1(bytes memory a) internal pure returns (bytes memory) {
        bytes[] memory l = new bytes[](1);
        l[0] = a;
        return RLP.encode(l);
    }

    // ── Config ────────────────────────────────────────────────────────────────

    function _ledgerConfig(string memory chainId) internal pure returns (bytes memory) {
        return ClprProtobuf.encodeControlMessage(
            ClprTypes.LedgerConfiguration({
                protocolVersion: 1,
                chainId: chainId,
                serviceAddress: abi.encodePacked(SERVICE_ADDR),
                nanosSinceEpoch: 1_790_000_000 * 1e9,
                throttles: ClprTypes.Throttles({
                    maxMessagesPerBundle: 100,
                    maxMessagePayloadBytes: 10_000,
                    maxGasPerMessage: 1_000_000,
                    maxQueueDepth: 1000,
                    maxSyncBytes: 1_000_000,
                    maxLocalEndpoints: 8,
                    maxPeerEndpoints: 8
                }),
                trustAnchor: "",
                trustAnchorId: ""
            })
        );
    }

    function _configProof(string memory caip2, uint256 evmChainId, Set memory s, uint256 threshold)
        internal
        view
        returns (bytes memory)
    {
        return _configProofFull(_ledgerConfig(caip2), evmChainId, NETWORK_ID, C_CHAIN_ID, s, threshold, _attestorList());
    }

    function _configProofFull(
        bytes memory ledger,
        uint256 evmChainId,
        uint32 networkId,
        bytes32 chainId,
        Set memory s,
        uint256 threshold,
        bytes memory attestors
    ) internal pure returns (bytes memory) {
        bytes[] memory c = new bytes[](12);
        c[0] = RLP.encode(ledger);
        c[1] = RLP.encode(evmChainId);
        c[2] = RLP.encode(uint256(networkId));
        c[3] = RLP.encode(chainId);
        c[4] = RLP.encode(uint256(P_HEIGHT));
        c[5] = RLP.encode(uint256(P_TIME));
        c[6] = RLP.encode(s.packed);
        c[7] = RLP.encode(s.totalWeight);
        c[8] = RLP.encode(uint256(MAX_AGE));
        c[9] = RLP.encode(threshold);
        c[10] = attestors;
        c[11] = RLP.encode(SERVICE_CODE_HASH);
        return RLP.encode(c);
    }
}
