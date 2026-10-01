// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprBeaconBls} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconBls.sol";
import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {QbftSyntheticProofs} from "@test/helpers/QbftSyntheticProofs.sol";

/// @dev Synthetic Parlia (BSC) chain for BscParliaVerifier tests: validators with real secp256k1 keys
///      (vm.sign seals) and real BLS12-381 keys (pubkey = sk·G1 via G1MSM; aggregate signature
///      = (Σ sk)·H(m) via G2MSM), BSC-shaped 21-field headers sealed with the chain-id seal hash, and
///      the synthetic MPT account/storage proofs from {QbftSyntheticProofs}.
abstract contract BscParliaFixtures is QbftSyntheticProofs {
    address internal constant BLS12_G1MSM = address(0x0c);
    address internal constant BLS12_G2MSM = address(0x0e);
    bytes internal constant G1_GEN =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    uint64 internal constant CHAIN_ID = 97;
    uint64 internal constant EPOCH_LENGTH = 200;
    uint8 internal constant TURN_LENGTH = 4;
    address internal constant SERVICE_ADDR = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;
    bytes32 internal constant SERVICE_CODE_HASH = bytes32(uint256(0xC0DE));
    bytes32 internal constant CHANNEL_ID = bytes32(uint256(0xB5C));

    struct Val {
        address addr;
        uint256 ecdsaPk;
        uint256 blsSk;
        bytes pub; // 128-byte uncompressed
        bytes compressed; // 48-byte
    }

    struct Hdr {
        bytes rlp;
        bytes32 hash;
        uint64 number;
    }

    // ── Validators ────────────────────────────────────────────────────────────

    /// `n` validators sorted ascending by address (the order the vote bitset indexes).
    function _makeSet(uint256 n, string memory seed) internal view returns (Val[] memory vals) {
        vals = new Val[](n);
        for (uint256 i = 0; i < n; i++) {
            uint256 pk = uint256(keccak256(abi.encode(seed, "ecdsa", i))) % (2 ** 255);
            uint256 sk = (uint256(keccak256(abi.encode(seed, "bls", i))) % (2 ** 200)) + 1;
            (bool ok, bytes memory pub) = BLS12_G1MSM.staticcall(abi.encodePacked(G1_GEN, bytes32(sk)));
            require(ok && pub.length == 128, "G1MSM");
            vals[i] =
                Val({addr: vm.addr(pk), ecdsaPk: pk, blsSk: sk, pub: pub, compressed: ClprBls12381.compressG1(pub)});
        }
        for (uint256 i = 1; i < n; i++) {
            for (uint256 j = i; j > 0 && uint160(vals[j - 1].addr) > uint160(vals[j].addr); j--) {
                (vals[j - 1], vals[j]) = (vals[j], vals[j - 1]);
            }
        }
    }

    function _validatorBytes(Val[] memory vals) internal pure returns (bytes memory out) {
        for (uint256 i = 0; i < vals.length; i++) {
            out = abi.encodePacked(out, vals[i].addr, vals[i].compressed);
        }
    }

    function _keysHash(Val[] memory vals) internal pure returns (bytes32) {
        bytes memory b;
        for (uint256 i = 0; i < vals.length; i++) {
            b = abi.encodePacked(b, vals[i].addr, vals[i].pub);
        }
        return keccak256(b);
    }

    /// Bundle item 1: one byte string of `address20 ‖ uncompressedKey128` entries.
    function _entries(Val[] memory vals) internal pure returns (bytes memory) {
        bytes memory b;
        for (uint256 i = 0; i < vals.length; i++) {
            b = abi.encodePacked(b, vals[i].addr, vals[i].pub);
        }
        return RLP.encode(b);
    }

    /// Rotation `newKeys`: one byte string of uncompressed keys in header order.
    function _keysList(Val[] memory vals) internal pure returns (bytes memory) {
        bytes memory b;
        for (uint256 i = 0; i < vals.length; i++) {
            b = abi.encodePacked(b, vals[i].pub);
        }
        return RLP.encode(b);
    }

    /// Rotation `newKeys` for an epoch block that republishes the current set.
    function _noKeys() internal pure returns (bytes memory) {
        return hex"80";
    }

    function _checkLen(uint256 n, uint256 turn) internal pure returns (uint64) {
        return uint64((n / 2 + 1) * turn - 1);
    }

    function _anchor(Val[] memory vals, uint64 epochBlock, uint64 activeFrom) internal pure returns (bytes memory) {
        return _anchorFull(vals, epochBlock, activeFrom, CHAIN_ID, SERVICE_CODE_HASH);
    }

    function _anchorFull(Val[] memory vals, uint64 epochBlock, uint64 activeFrom, uint64 chainId, bytes32 codeHash)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            CHANNEL_ID,
            codeHash,
            keccak256(_validatorBytes(vals)),
            _keysHash(vals),
            chainId,
            EPOCH_LENGTH,
            epochBlock,
            activeFrom,
            TURN_LENGTH,
            uint8(vals.length)
        );
    }

    // ── Headers ───────────────────────────────────────────────────────────────

    function _epochExtraBody(Val[] memory vals, uint8 turnLength) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(uint256(0xbeef)), uint8(vals.length), _validatorBytes(vals), turnLength);
    }

    function _plainExtraBody() internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(uint256(0xbeef)));
    }

    /// The 21 BSC header fields with `extra` already final (seal appended or placeholder).
    function _headerFields(uint64 number, bytes32 parentHash, bytes32 stateRoot, bytes memory extra)
        internal
        pure
        returns (bytes[] memory h)
    {
        h = new bytes[](21);
        h[0] = RLP.encode(parentHash);
        h[1] = RLP.encode(bytes32(0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347));
        h[2] = RLP.encode(address(0x1234));
        h[3] = RLP.encode(stateRoot);
        h[4] = RLP.encode(bytes32(uint256(4)));
        h[5] = RLP.encode(bytes32(uint256(5)));
        h[6] = RLP.encode(new bytes(256));
        h[7] = RLP.encode(uint256(2));
        h[8] = RLP.encode(uint256(number));
        h[9] = RLP.encode(uint256(100_000_000));
        h[10] = RLP.encode(uint256(0));
        h[11] = RLP.encode(uint256(1_760_000_000 + number));
        h[12] = RLP.encode(extra);
        h[13] = RLP.encode(bytes32(uint256(300)));
        h[14] = RLP.encode(new bytes(8));
        h[15] = RLP.encode(uint256(0));
        h[16] = RLP.encode(bytes32(uint256(16)));
        h[17] = RLP.encode(uint256(0));
        h[18] = RLP.encode(uint256(0));
        h[19] = RLP.encode(bytes32(0));
        h[20] = RLP.encode(sha256(""));
    }

    /// Parlia SealHash: RLP([chainId, fields 0..11, extra[:-65], mixDigest, nonce, fields 15..20]).
    function _sealHash(uint64 chainId, bytes[] memory h, bytes memory extraBody) internal pure returns (bytes32) {
        bytes[] memory s = new bytes[](22);
        s[0] = RLP.encode(uint256(chainId));
        for (uint256 i = 0; i < 12; i++) {
            s[i + 1] = h[i];
        }
        s[13] = RLP.encode(extraBody);
        for (uint256 i = 13; i < 21; i++) {
            s[i + 1] = h[i];
        }
        return keccak256(RLP.encode(s));
    }

    function _header(uint64 number, bytes32 parentHash, bytes32 stateRoot, bytes memory extraBody, uint256 sealerPk)
        internal
        pure
        returns (Hdr memory)
    {
        return _headerForChain(CHAIN_ID, number, parentHash, stateRoot, extraBody, sealerPk);
    }

    function _headerForChain(
        uint64 chainId,
        uint64 number,
        bytes32 parentHash,
        bytes32 stateRoot,
        bytes memory extraBody,
        uint256 sealerPk
    ) internal pure returns (Hdr memory hd) {
        bytes[] memory h = _headerFields(number, parentHash, stateRoot, extraBody);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sealerPk, _sealHash(chainId, h, extraBody));
        h[12] = RLP.encode(abi.encodePacked(extraBody, r, s, v - 27));
        hd.rlp = RLP.encode(h);
        hd.hash = keccak256(hd.rlp);
        hd.number = number;
    }

    function _chain(Hdr memory a) internal pure returns (bytes memory) {
        bytes[] memory l = new bytes[](1);
        l[0] = a.rlp;
        return RLP.encode(l);
    }

    // ── Attestations ──────────────────────────────────────────────────────────

    function _voteHash(uint64 src, bytes32 srcHash, uint64 tgt, bytes32 tgtHash) internal pure returns (bytes32) {
        bytes[] memory d = new bytes[](4);
        d[0] = RLP.encode(uint256(src));
        d[1] = RLP.encode(srcHash);
        d[2] = RLP.encode(uint256(tgt));
        d[3] = RLP.encode(tgtHash);
        return keccak256(RLP.encode(d));
    }

    /// Aggregate signature over `msgHash` by the validators whose bit is set in `bits`.
    function _sign(Val[] memory vals, uint64 bits, bytes32 msgHash) internal view returns (bytes memory) {
        uint256 skSum;
        uint256 r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
        for (uint256 i = 0; i < vals.length; i++) {
            if ((bits >> i) & 1 == 1) skSum = addmod(skSum, vals[i].blsSk, r);
        }
        bytes memory h = ClprBeaconBls.hashToG2(msgHash);
        (bool ok, bytes memory sig) = BLS12_G2MSM.staticcall(abi.encodePacked(h, bytes32(skSum)));
        require(ok && sig.length == 256, "G2MSM");
        return sig;
    }

    function _attestationRaw(uint64 bits, bytes memory sig, uint64 src, bytes32 srcHash, uint64 tgt, bytes32 tgtHash)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory a = new bytes[](6);
        a[0] = RLP.encode(uint256(bits));
        a[1] = RLP.encode(sig);
        a[2] = RLP.encode(uint256(src));
        a[3] = RLP.encode(srcHash);
        a[4] = RLP.encode(uint256(tgt));
        a[5] = RLP.encode(tgtHash);
        return RLP.encode(a);
    }

    /// A finalizing attestation (source = `h`, target = h + 1) signed by `bits` of `vals`.
    function _finalize(Val[] memory vals, uint64 bits, Hdr memory h) internal view returns (bytes memory) {
        bytes32 tgtHash = keccak256(abi.encode("child", h.hash));
        bytes memory sig = _sign(vals, bits, _voteHash(h.number, h.hash, h.number + 1, tgtHash));
        return _attestationRaw(bits, sig, h.number, h.hash, h.number + 1, tgtHash);
    }

    function _allBits(uint256 n) internal pure returns (uint64) {
        return uint64((uint256(1) << n) - 1);
    }

    function _pair(bytes memory a, bytes memory b) internal pure returns (bytes memory) {
        bytes[] memory l = new bytes[](2);
        l[0] = a;
        l[1] = b;
        return RLP.encode(l);
    }

    function _triple(bytes memory a, bytes memory b, bytes memory c) internal pure returns (bytes memory) {
        bytes[] memory l = new bytes[](3);
        l[0] = a;
        l[1] = b;
        l[2] = c;
        return RLP.encode(l);
    }

    // ── Bundles ───────────────────────────────────────────────────────────────

    function _channelContext() internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: CHANNEL_ID, remoteServiceAddress: abi.encodePacked(SERVICE_ADDR)})
        );
    }

    /// Synthetic service state: (stateRoot, accountProof, storageProof) for CHANNEL_ID.
    function _serviceState() internal pure returns (bytes32 stateRoot, bytes memory account, bytes memory storage_) {
        bytes32 storageRoot;
        (storageRoot, storage_) = _buildChannelStorageProof6(CHANNEL_ID);
        (stateRoot, account) = _buildSyntheticAccountProof(SERVICE_ADDR, storageRoot, SERVICE_CODE_HASH);
    }

    function _bundle(
        bytes memory rotations,
        bytes memory validators,
        bytes memory finality,
        bytes memory account,
        bytes memory storage_
    ) internal pure returns (bytes memory) {
        bytes[] memory top = new bytes[](6);
        top[0] = rotations;
        top[1] = validators;
        top[2] = finality;
        top[3] = account;
        top[4] = storage_;
        top[5] = RLP.encode(new bytes(0));
        return RLP.encode(top);
    }

    function _emptyList() internal pure returns (bytes memory) {
        return hex"c0";
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
                nanosSinceEpoch: 1_760_000_000 * 1e9,
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

    function _configProof(
        string memory caip2,
        uint64 chainId,
        Hdr memory epoch,
        uint64 activeFrom,
        Val[] memory vals,
        bytes32 codeHash
    ) internal pure returns (bytes memory) {
        bytes[] memory c = new bytes[](7);
        c[0] = RLP.encode(_ledgerConfig(caip2));
        c[1] = RLP.encode(uint256(chainId));
        c[2] = RLP.encode(uint256(EPOCH_LENGTH));
        c[3] = epoch.rlp;
        c[4] = RLP.encode(uint256(activeFrom));
        c[5] = _keysList(vals);
        c[6] = RLP.encode(codeHash);
        return RLP.encode(c);
    }
}
