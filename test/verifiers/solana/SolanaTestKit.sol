// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {AlpenglowCert} from "@hiero-ledger/clpr/verifiers/solana/AlpenglowCert.sol";
import {ClprBeaconBls} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconBls.sol";
import {SolanaCommittee} from "@hiero-ledger/clpr/verifiers/solana/SolanaCommittee.sol";

/// @dev Synthetic Alpenglow validator sets and committee signatures for tests. BLS keys and
///      signatures are produced with the EIP-2537 MSM precompiles (pk = sk·G1, sig = Σsk·H(m)).
abstract contract SolanaTestKit is Test {
    bytes internal constant G1_GEN =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    struct SynthSet {
        AlpenglowCert.EpochSet set;
        uint256[] sks;
        bytes[] pubkeys;
        bytes32[] voteAccounts;
        uint64[] stakes;
        bytes32[][] levels; // levels[0] = padded leaves
    }

    function _g1Mul(bytes memory pt, uint256 s) internal view returns (bytes memory out) {
        (bool ok, bytes memory r) = address(0x0c).staticcall(abi.encodePacked(pt, s));
        require(ok && r.length == 128, "g1msm");
        return r;
    }

    function _g2Mul(bytes memory pt, uint256 s) internal view returns (bytes memory) {
        (bool ok, bytes memory r) = address(0x0e).staticcall(abi.encodePacked(pt, s));
        require(ok && r.length == 256, "g2msm");
        return r;
    }

    function _g1AddT(bytes memory a, bytes memory b) internal view returns (bytes memory) {
        (bool ok, bytes memory r) = address(0x0b).staticcall(abi.encodePacked(a, b));
        require(ok && r.length == 128, "g1add");
        return r;
    }

    /// @dev Stakes fall off quadratically by rank (mainnet-like concentration).
    function _synthSet(uint256 n, uint64 epoch, uint16 shredVersion) internal view returns (SynthSet memory s) {
        s.sks = new uint256[](n);
        s.pubkeys = new bytes[](n);
        s.voteAccounts = new bytes32[](n);
        s.stakes = new uint64[](n);
        uint8 depth = 0;
        while ((uint256(1) << depth) < n) depth++;
        bytes32[] memory leaves = new bytes32[](uint256(1) << depth);
        bytes memory apk = new bytes(128);
        uint256 total;
        for (uint256 i = 0; i < n; i++) {
            s.sks[i] = uint256(keccak256(abi.encode("sk", i)))
                % 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
            s.pubkeys[i] = _g1Mul(G1_GEN, s.sks[i]);
            s.voteAccounts[i] = keccak256(abi.encode("vote", i));
            s.stakes[i] = uint64(1e9 * (n - i) * (n - i) + 1);
            total += s.stakes[i];
            leaves[i] = AlpenglowCert.leafHash(uint16(i), s.voteAccounts[i], s.stakes[i], s.pubkeys[i]);
            apk = _g1AddT(apk, s.pubkeys[i]);
        }
        s.levels = new bytes32[][](depth + 1);
        s.levels[0] = leaves;
        for (uint256 d = 0; d < depth; d++) {
            bytes32[] memory lv = s.levels[d];
            bytes32[] memory nx = new bytes32[](lv.length / 2);
            for (uint256 j = 0; j < nx.length; j++) {
                nx[j] = keccak256(abi.encodePacked(lv[2 * j], lv[2 * j + 1]));
            }
            s.levels[d + 1] = nx;
        }
        s.set = AlpenglowCert.EpochSet({
            epoch: epoch,
            firstSlot: epoch * 432_000,
            lastSlot: epoch * 432_000 + 431_999,
            shredVersion: shredVersion,
            size: uint16(n),
            depth: depth,
            totalStake: uint64(total),
            root: s.levels[depth][0],
            aggregatePubkey: apk
        });
    }

    function _proof(SynthSet memory s, uint256 i) internal pure returns (bytes32[] memory) {
        return _path(s.levels, i);
    }

    function _path(bytes32[][] memory levels, uint256 i) internal pure returns (bytes32[] memory p) {
        p = new bytes32[](levels.length - 1);
        for (uint256 d = 0; d < p.length; d++) {
            p[d] = levels[d][(i >> d) ^ 1];
        }
    }

    function _entry(SynthSet memory s, uint256 i) internal pure returns (AlpenglowCert.SetEntry memory e) {
        e.rank = uint16(i);
        e.voteAccount = s.voteAccounts[i];
        e.stake = s.stakes[i];
        e.pubkey = s.pubkeys[i];
        e.proof = _path(s.levels, i);
    }

    /// @dev Signers = ranks where `signed[i]`. Builds a base2 bitmap truncated after the last signer.
    function _aggregate(SynthSet memory s, bool[] memory signed, bytes memory message, bool complement)
        internal
        view
        returns (AlpenglowCert.Aggregate memory a)
    {
        a.bitmap = _bitmap(signed);
        a.complement = complement;
        a.entries = _entries(s, signed, complement);
        a.signature = _g2Mul(ClprBeaconBls.hashBytesToG2(message), _skSum(s, signed));
    }

    function _skSum(SynthSet memory s, bool[] memory signed) internal pure returns (uint256 skSum) {
        uint256 r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
        for (uint256 i = 0; i < signed.length; i++) {
            if (signed[i]) skSum = addmod(skSum, s.sks[i], r);
        }
    }

    function _bitmap(bool[] memory signed) internal pure returns (bytes memory bm) {
        uint256 last = 0;
        for (uint256 i = 0; i < signed.length; i++) {
            if (signed[i]) last = i + 1;
        }
        bm = new bytes(3 + (last + 7) / 8);
        bm[1] = bytes1(uint8(last));
        bm[2] = bytes1(uint8(last >> 8));
        for (uint256 i = 0; i < last; i++) {
            if (signed[i]) bm[3 + i / 8] = bytes1(uint8(bm[3 + i / 8]) | uint8(1 << (i % 8)));
        }
    }

    function _entries(SynthSet memory s, bool[] memory signed, bool complement)
        internal
        pure
        returns (AlpenglowCert.SetEntry[] memory e)
    {
        uint256 m = 0;
        for (uint256 i = 0; i < signed.length; i++) {
            if (signed[i] != complement) m++;
        }
        e = new AlpenglowCert.SetEntry[](m);
        uint256 k = 0;
        for (uint256 i = 0; i < signed.length; i++) {
            if (signed[i] != complement) e[k++] = _entry(s, i);
        }
    }

    /// @dev Top-ranked validators sign until `pct`% of stake (plus `extra` more ranks).
    function _signersForPct(SynthSet memory s, uint256 pct, uint256 extra)
        internal
        pure
        returns (bool[] memory signed)
    {
        uint256 n = s.stakes.length;
        signed = new bool[](n);
        uint256 acc;
        uint256 i;
        for (; i < n && acc * 100 < pct * uint256(s.set.totalStake); i++) {
            signed[i] = true;
            acc += s.stakes[i];
        }
        for (uint256 j = 0; j < extra && i + j < n; j++) {
            signed[i + j] = true;
        }
    }

    // ── Committee ───────────────────────────────────────────────────────────

    function _committee(uint256 n, uint16 k, uint64 nonce, uint256 seed)
        internal
        pure
        returns (SolanaCommittee.Committee memory c, uint256[] memory keys)
    {
        keys = new uint256[](n);
        address[] memory addrs = new address[](n);
        for (uint256 i = 0; i < n; i++) {
            keys[i] = uint256(keccak256(abi.encode("attestor", seed, i))) % (type(uint128).max) + 1;
            addrs[i] = vm.addr(keys[i]);
        }
        // sort ascending by address (keys follow)
        for (uint256 i = 0; i < n; i++) {
            for (uint256 j = i + 1; j < n; j++) {
                if (addrs[j] < addrs[i]) {
                    (addrs[i], addrs[j]) = (addrs[j], addrs[i]);
                    (keys[i], keys[j]) = (keys[j], keys[i]);
                }
            }
        }
        c = SolanaCommittee.Committee({nonce: nonce, threshold: k, members: addrs});
    }

    function _sign(uint256[] memory keys, uint256[] memory idx, bytes32 digest)
        internal
        pure
        returns (SolanaCommittee.Signatures memory s)
    {
        s.memberIndex = new uint16[](idx.length);
        s.sigs = new bytes[](idx.length);
        for (uint256 i = 0; i < idx.length; i++) {
            (uint8 v, bytes32 r, bytes32 ss) = vm.sign(keys[idx[i]], digest);
            s.memberIndex[i] = uint16(idx[i]);
            s.sigs[i] = abi.encodePacked(r, ss, v);
        }
    }

    function _range(uint256 from, uint256 to) internal pure returns (uint256[] memory r) {
        r = new uint256[](to - from);
        for (uint256 i = from; i < to; i++) {
            r[i - from] = i;
        }
    }
}
