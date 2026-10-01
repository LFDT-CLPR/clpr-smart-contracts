// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {MonadBlake3} from "@hiero-ledger/clpr/libraries/proof/monad/MonadBlake3.sol";
import {MonadBls} from "@hiero-ledger/clpr/libraries/proof/monad/MonadBls.sol";
import {ClprBls12381} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBls12381.sol";
import {MonadValsetRotation} from "@hiero-ledger/clpr/verifiers/evm/monad/MonadValsetRotation.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @title MonadSyntheticProofs
/// @notice In-Solidity builder of MonadVerifier proofs for parameterised tests (the compliance suite):
///         a small validator set whose keys are all the G1 generator (so an aggregate signature by k
///         signers is k·H(m)), BLAKE3-identified consensus headers P/B and a QC on B, an Ethereum header
///         carrying the state root, and one-level MIP-8 page / account tries.
/// @dev The 196-validator fixture with distinct keys lives in fixtures/synthetic (TypeScript builder).
abstract contract MonadSyntheticProofs {
    using RLP for bytes;

    uint64 internal constant SYN_EPOCH = 7;
    uint256 internal constant SYN_VALIDATORS = 4;
    uint64 internal constant SYN_BLOCK = 1000;
    uint64 internal constant SYN_ROUND = 5000;

    bytes internal constant G1_GEN =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    struct Slot {
        bytes32 key;
        bytes32 value;
    }

    // ── validator set / QC ─────────────────────────────────────────────────────

    function _synValset() internal pure returns (bytes memory blob) {
        for (uint256 i = 0; i < SYN_VALIDATORS; ++i) {
            blob = abi.encodePacked(blob, G1_GEN, uint256(1));
        }
    }

    function _synAnchor(bytes32 codeHash) internal pure returns (bytes memory) {
        MonadValsetRotation.Anchor memory a;
        a.epoch = SYN_EPOCH;
        a.valsetHash = keccak256(_synValset());
        a.codeHash = codeHash;
        return abi.encode(a);
    }

    /// @dev QC on `blockId` signed by all SYN_VALIDATORS (keys = G1 generator): returns the QC RLP and the
    ///      uncompressed signature.
    function _synQc(bytes32 blockId, uint64 round) internal view returns (bytes memory qc, bytes memory sig) {
        bytes memory vote = _list3(RLP.encode(blockId), RLP.encode(uint256(round)), RLP.encode(uint256(SYN_EPOCH)));
        bytes memory h = MonadBls.hashToG2(abi.encodePacked("\x0dmonad/vote/1\n", vote));
        (bool ok, bytes memory s) = address(0x0e).staticcall(abi.encodePacked(h, uint256(SYN_VALIDATORS))); // G2MSM
        require(ok && s.length == 256, "G2MSM");
        sig = s;
        bytes[] memory signers = new bytes[](2);
        signers[0] = RLP.encode(SYN_VALIDATORS);
        signers[1] = RLP.encode(abi.encodePacked(bytes1(uint8((1 << SYN_VALIDATORS) - 1))));
        bytes[] memory sc = new bytes[](2);
        sc[0] = RLP.encode(signers);
        sc[1] = RLP.encode(_compressG2(sig));
        bytes[] memory q = new bytes[](2);
        q[0] = vote;
        q[1] = RLP.encode(sc);
        qc = RLP.encode(q);
    }

    function _compressG2(bytes memory s) internal pure returns (bytes memory out) {
        uint256 x0Hi;
        uint256 x0Lo;
        uint256 x1Hi;
        uint256 x1Lo;
        uint256 y0Hi;
        uint256 y0Lo;
        uint256 y1Hi;
        uint256 y1Lo;
        assembly ("memory-safe") {
            let p := add(s, 0x20)
            x0Hi := mload(p)
            x0Lo := mload(add(p, 32))
            x1Hi := mload(add(p, 64))
            x1Lo := mload(add(p, 96))
            y0Hi := mload(add(p, 128))
            y0Lo := mload(add(p, 160))
            y1Hi := mload(add(p, 192))
            y1Lo := mload(add(p, 224))
        }
        bool largest = (y1Hi != 0 || y1Lo != 0)
            ? ClprBls12381._gt(y1Hi, y1Lo, ClprBls12381.P_HALF_HI, ClprBls12381.P_HALF_LO)
            : ClprBls12381._gt(y0Hi, y0Lo, ClprBls12381.P_HALF_HI, ClprBls12381.P_HALF_LO);
        uint256 flags = 0x80 | (largest ? 0x20 : 0);
        out = abi.encodePacked(
            bytes16(uint128(x1Hi | (flags << 120))), bytes32(x1Lo), bytes16(uint128(x0Hi)), bytes32(x0Lo)
        );
    }

    // ── headers / finality ───────────────────────────────────────────────────────

    function _ethHeader(bytes32 stateRoot, uint64 number) internal pure returns (bytes memory) {
        bytes[] memory f = new bytes[](16);
        f[0] = RLP.encode(keccak256("parent"));
        f[1] = RLP.encode(keccak256("ommers"));
        f[2] = RLP.encode(abi.encodePacked(address(0)));
        f[3] = RLP.encode(stateRoot);
        f[4] = RLP.encode(keccak256("tx"));
        f[5] = RLP.encode(keccak256("rcpt"));
        f[6] = RLP.encode(new bytes(256));
        f[7] = RLP.encode(uint256(0));
        f[8] = RLP.encode(uint256(number));
        f[9] = RLP.encode(uint256(200_000_000));
        f[10] = RLP.encode(uint256(21_000));
        f[11] = RLP.encode(uint256(1_760_000_000));
        f[12] = RLP.encode(new bytes(32));
        f[13] = RLP.encode(keccak256("mix"));
        f[14] = RLP.encode(new bytes(8));
        f[15] = RLP.encode(uint256(100 gwei));
        return RLP.encode(f);
    }

    /// @dev `ConsensusBlockHeader` RLP (13 fields) with `qc` (raw RLP) as the parent QC.
    function _consensusHeader(uint64 round, bytes memory qc, uint64 seq, bytes memory delayedEth)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory delayed = new bytes[](delayedEth.length == 0 ? 0 : 1);
        if (delayedEth.length != 0) delayed[0] = delayedEth;
        bytes[] memory proposed = new bytes[](3);
        proposed[0] = RLP.encode(keccak256("ommers"));
        proposed[1] = RLP.encode(uint256(seq));
        proposed[2] = RLP.encode(uint256(200_000_000));
        bytes[] memory f = new bytes[](13);
        f[0] = RLP.encode(uint256(round));
        f[1] = RLP.encode(uint256(SYN_EPOCH));
        f[2] = qc;
        f[3] = RLP.encode(abi.encodePacked(bytes1(0x02), keccak256(abi.encode(round))));
        f[4] = RLP.encode(uint256(seq));
        f[5] = RLP.encode(uint256(seq) * 1e9);
        f[6] = RLP.encode(new bytes(96));
        f[7] = RLP.encode(delayed);
        f[8] = RLP.encode(proposed);
        f[9] = RLP.encode(keccak256(abi.encode(seq)));
        f[10] = RLP.encode(uint256(100 gwei));
        f[11] = RLP.encode(uint256(0));
        f[12] = RLP.encode(uint256(0));
        return RLP.encode(f);
    }

    /// @dev finality item [headerP, headerB, qcOnB, sig] making the block that carries `stateRoot` final.
    function _synFinality(bytes32 stateRoot) internal view returns (bytes memory) {
        bytes memory dummyQc = _list2(
            _list3(RLP.encode(bytes32(uint256(1))), RLP.encode(uint256(SYN_ROUND - 1)), RLP.encode(uint256(SYN_EPOCH))),
            _list2(_list2(RLP.encode(uint256(0)), RLP.encode(bytes(""))), RLP.encode(new bytes(96)))
        );
        bytes memory hP = _consensusHeader(SYN_ROUND, dummyQc, SYN_BLOCK + 3, _ethHeader(stateRoot, SYN_BLOCK));
        (bytes memory qcP,) = _synQc(MonadBlake3.hash(hP), SYN_ROUND);
        bytes memory hB = _consensusHeader(SYN_ROUND + 1, qcP, SYN_BLOCK + 4, _ethHeader(keccak256("x"), SYN_BLOCK + 1));
        (bytes memory qcB, bytes memory sig) = _synQc(MonadBlake3.hash(hB), SYN_ROUND + 1);
        bytes[] memory fin = new bytes[](4);
        fin[0] = RLP.encode(hP);
        fin[1] = RLP.encode(hB);
        fin[2] = qcB;
        fin[3] = RLP.encode(sig);
        return RLP.encode(fin);
    }

    // ── tries ─────────────────────────────────────────────────────────────────────

    /// @dev Storage pages for `slots` (any order, non-zero values): trie root and the pooled page-proof
    ///      batch [pool, pages]. Requires the page keys' trie paths to differ in their first nibble (true for
    ///      the fixed keys used here; asserted).
    function _pages(Slot[] memory slots) internal pure returns (bytes32 root, bytes memory batch) {
        bytes32[] memory keys = new bytes32[](slots.length);
        uint256 nk;
        for (uint256 i = 0; i < slots.length; ++i) {
            bytes32 k = bytes32(uint256(slots[i].key) >> 7);
            bool seen;
            for (uint256 j = 0; j < nk; ++j) {
                if (keys[j] == k) seen = true;
            }
            if (!seen) keys[nk++] = k;
        }
        bytes[] memory leaves = new bytes[](nk);
        bytes[] memory entries = new bytes[](nk);
        bytes32[] memory paths = new bytes32[](nk);
        for (uint256 j = 0; j < nk; ++j) {
            (uint128 bm, bytes32[] memory vals) = _pageContents(slots, keys[j]);
            bytes32 c = MonadBlake3.pageCommit(bm, vals);
            paths[j] = keccak256(abi.encode(keys[j]));
            bytes memory value = RLP.encode(abi.encodePacked(bytes1(0xa0), c)); // RLP string of (0xa0 || c)
            leaves[j] = nk == 1 ? _leaf(paths[j], 0, value) : _leaf(paths[j], 1, value);
            bytes[] memory vs = new bytes[](vals.length);
            for (uint256 v = 0; v < vals.length; ++v) {
                vs[v] = RLP.encode(vals[v]);
            }
            bytes[] memory idx = new bytes[](nk == 1 ? 1 : 2);
            if (nk == 1) {
                idx[0] = RLP.encode(uint256(0));
            } else {
                idx[0] = RLP.encode(uint256(0));
                idx[1] = RLP.encode(j + 1);
            }
            bytes[] memory e = new bytes[](4);
            e[0] = RLP.encode(keys[j]);
            e[1] = RLP.encode(idx);
            e[2] = RLP.encode(uint256(bm));
            e[3] = RLP.encode(vs);
            entries[j] = RLP.encode(e);
        }
        bytes[] memory pool;
        if (nk == 1) {
            pool = new bytes[](1);
            pool[0] = RLP.encode(leaves[0]);
            root = keccak256(leaves[0]);
        } else {
            bytes memory branch = _branch(paths, leaves);
            pool = new bytes[](nk + 1);
            pool[0] = RLP.encode(branch);
            for (uint256 j = 0; j < nk; ++j) {
                pool[j + 1] = RLP.encode(leaves[j]);
            }
            root = keccak256(branch);
        }
        bytes[] memory b = new bytes[](2);
        b[0] = RLP.encode(pool);
        b[1] = RLP.encode(entries);
        batch = RLP.encode(b);
    }

    function _pageContents(Slot[] memory slots, bytes32 pageKey)
        internal
        pure
        returns (uint128 bm, bytes32[] memory vals)
    {
        bytes32[128] memory byOff;
        uint256 count;
        for (uint256 i = 0; i < slots.length; ++i) {
            if (bytes32(uint256(slots[i].key) >> 7) != pageKey || slots[i].value == bytes32(0)) continue;
            uint256 off = uint256(slots[i].key) & 127;
            if (byOff[off] == bytes32(0)) ++count;
            byOff[off] = slots[i].value;
            bm |= uint128(1) << uint128(off);
        }
        vals = new bytes32[](count);
        uint256 k;
        for (uint256 off = 0; off < 128; ++off) {
            if (byOff[off] != bytes32(0)) vals[k++] = byOff[off];
        }
    }

    /// @dev Single-account state trie: (root, proof list [leaf]).
    function _account(address addr, bytes32 storageRoot, bytes32 codeHash)
        internal
        pure
        returns (bytes32 root, bytes memory proof)
    {
        bytes[] memory acct = new bytes[](4);
        acct[0] = RLP.encode(uint256(1));
        acct[1] = RLP.encode(uint256(0));
        acct[2] = RLP.encode(storageRoot);
        acct[3] = RLP.encode(codeHash);
        bytes memory leaf = _leaf(keccak256(abi.encodePacked(addr)), 0, RLP.encode(RLP.encode(acct)));
        root = keccak256(leaf);
        bytes[] memory p = new bytes[](1);
        p[0] = RLP.encode(leaf);
        proof = RLP.encode(p);
    }

    /// @dev Leaf node for `path` starting at nibble `from` (0 or 1); `value` is the already RLP-encoded item.
    function _leaf(bytes32 path, uint256 from, bytes memory value) internal pure returns (bytes memory) {
        bytes memory hp;
        if (from == 0) {
            hp = abi.encodePacked(bytes1(0x20), path);
        } else {
            // odd remaining length (63 nibbles): 0x3 || nibble 1, then bytes 1..31
            hp = abi.encodePacked(bytes1(uint8(0x30 | (uint8(path[0]) & 0x0f))));
            for (uint256 i = 1; i < 32; ++i) {
                hp = abi.encodePacked(hp, path[i]);
            }
        }
        return _list2(RLP.encode(hp), value);
    }

    function _branch(bytes32[] memory paths, bytes[] memory leaves) internal pure returns (bytes memory) {
        bytes[] memory items = new bytes[](17);
        for (uint256 n = 0; n < 17; ++n) {
            items[n] = RLP.encode(bytes(""));
        }
        for (uint256 j = 0; j < paths.length; ++j) {
            uint256 nib = uint8(paths[j][0]) >> 4;
            require(keccak256(items[nib]) == keccak256(RLP.encode(bytes(""))), "first-nibble collision");
            items[nib] = RLP.encode(keccak256(leaves[j]));
        }
        return RLP.encode(items);
    }

    function _list2(bytes memory a, bytes memory b) internal pure returns (bytes memory) {
        bytes[] memory l = new bytes[](2);
        l[0] = a;
        l[1] = b;
        return RLP.encode(l);
    }

    function _list3(bytes memory a, bytes memory b, bytes memory c) internal pure returns (bytes memory) {
        bytes[] memory l = new bytes[](3);
        l[0] = a;
        l[1] = b;
        l[2] = c;
        return RLP.encode(l);
    }
}
