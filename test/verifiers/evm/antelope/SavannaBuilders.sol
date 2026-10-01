// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {AntelopeLib} from "@hiero-ledger/clpr/verifiers/evm/antelope/AntelopeLib.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {AntelopeTestBase} from "./AntelopeTestBase.sol";

/// @dev Synthetic Savanna data built as Spring 1.2.2 builds it: finalizer policies with real BLS keys,
///      finality digests, strong QCs (EIP-2537 G2MSM signatures), finality leaves and Merkle paths.
abstract contract SavannaBuilders is AntelopeTestBase {
    uint256 internal constant N = 21;
    uint64 internal constant THRESHOLD = 15;
    uint256 internal constant ALL_BUT_ONE = (uint256(1) << N) - 1 - (uint256(1) << 7); // 20 of 21 voted
    uint256 internal constant FINALITY_LEAVES = (uint256(1) << 27) + 777; // ~28-level finality tree

    struct Pol {
        uint32 gen;
        uint256[] sks;
        bytes pack;
        bytes32 digest;
    }

    struct Fin {
        uint32 activeGen;
        uint32 lastPendingGen;
        bytes32 finalityMroot;
        uint32 lastPendingStartTs;
        bytes32 l3;
    }

    /// @dev Everything needed to prove one action receipt in one final block.
    struct Target {
        bytes actionBase;
        bytes data;
        bytes ret;
        uint64 receiver;
        uint64 recvSeq;
        bytes32 witness;
        uint256 aIndex;
        uint256 aCount;
        bytes32[] aSibs;
        uint32 num;
        uint32 ts;
        uint32 parentTs;
        bytes32 fd;
        uint256 fIndex;
        uint256 fCount;
        bytes32[] fSibs;
        bytes32 finalityMroot;
    }

    Pol internal g1;
    Pol internal g2;

    function _initPolicies() internal {
        g1 = _mkPolicy(1, 100, THRESHOLD);
        g2 = _mkPolicy(2, 200, THRESHOLD);
    }
    // ── Builders ──────────────────────────────────────────────────────────────

    function _mkPolicy(uint32 gen, uint256 seed, uint64 threshold) internal view returns (Pol memory p) {
        p.gen = gen;
        p.sks = new uint256[](N);
        for (uint256 i = 0; i < N; ++i) {
            p.sks[i] = _blsSecret(seed + i);
        }
        p.pack = _packPolicy(gen, threshold, p.sks);
        p.digest = sha256(p.pack);
    }

    function _target(bytes memory actionBase, bytes memory data, bytes memory ret, string memory receiver, uint256 seed)
        internal
        pure
        returns (Target memory t)
    {
        t.actionBase = actionBase;
        t.data = data;
        t.ret = ret;
        t.receiver = AntelopeLib.nameValue(receiver);
        t.recvSeq = 42;
        t.witness = sha256(abi.encode("witness", seed));
        bytes32 actDigest = AntelopeLib.actionDigest(actionBase, data, ret);
        bytes32 receipt = AntelopeLib.savannaReceiptDigest(
            t.receiver,
            t.recvSeq,
            AntelopeLib.readU64(actionBase, 0),
            AntelopeLib.readU64(actionBase, 8),
            actDigest,
            t.witness
        );
        bytes32[] memory receipts = _filler(12, seed);
        t.aIndex = 5;
        t.aCount = receipts.length;
        receipts[t.aIndex] = receipt;
        t.aSibs = _savannaProof(receipts, t.aIndex);
        bytes32 actionMroot = _savannaRoot(receipts);

        t.num = 523_000_000;
        t.ts = 1_800_000_000;
        t.parentTs = t.ts - 1;
        t.fd = sha256(abi.encode("finality digest", seed));
        bytes32 leaf = sha256(
            abi.encodePacked(
                AntelopeLib.le32(1),
                AntelopeLib.le32(0),
                AntelopeLib.le32(t.num),
                AntelopeLib.le32(t.ts),
                AntelopeLib.le32(t.parentTs),
                t.fd,
                actionMroot
            )
        );
        t.fCount = FINALITY_LEAVES;
        t.fIndex = FINALITY_LEAVES - 2;
        t.fSibs = _filler(_savannaSiblingCount(t.fIndex, t.fCount), seed + 1);
        t.finalityMroot = AntelopeLib.savannaMerkleRoot(leaf, t.fIndex, t.fCount, t.fSibs);
    }

    function _queueTarget() internal pure returns (Target memory) {
        return _target(
            _actionBase(SERVICE_NAME, "queuestate", "relayer"),
            abi.encodePacked(CHANNEL),
            _defaultQueueState(),
            SERVICE_NAME,
            1
        );
    }

    function _blockRlp(Target memory t) internal pure returns (bytes memory) {
        bytes[] memory b = new bytes[](7);
        b[0] = _rlpUint(t.num);
        b[1] = _rlpUint(t.ts);
        b[2] = _rlpUint(t.parentTs);
        b[3] = RLP.encode(t.fd);
        b[4] = _rlpUint(t.fIndex);
        b[5] = _rlpUint(t.fCount);
        b[6] = _rlpB32s(t.fSibs);
        return _rlpList(b);
    }

    function _actionRlp(Target memory t) internal pure returns (bytes memory) {
        bytes[] memory a = new bytes[](9);
        a[0] = _rlpBytes(t.actionBase);
        a[1] = _rlpBytes(t.data);
        a[2] = _rlpBytes(t.ret);
        a[3] = _rlpUint(t.receiver);
        a[4] = _rlpUint(t.recvSeq);
        a[5] = RLP.encode(t.witness);
        a[6] = _rlpUint(t.aIndex);
        a[7] = _rlpUint(t.aCount);
        a[8] = _rlpB32s(t.aSibs);
        return _rlpList(a);
    }

    function _finalityDigest(Fin memory f, bytes32 lastPendingDigest) internal pure returns (bytes32) {
        bytes32 l2 = sha256(abi.encodePacked(lastPendingDigest, AntelopeLib.le32(f.lastPendingStartTs), f.l3));
        return sha256(
            abi.encodePacked(
                AntelopeLib.le32(1),
                AntelopeLib.le32(0),
                AntelopeLib.le32(f.activeGen),
                AntelopeLib.le32(f.lastPendingGen),
                f.finalityMroot,
                l2
            )
        );
    }

    function _bitset(uint256 mask) internal pure returns (bytes memory b) {
        b = new bytes((N + 7) / 8);
        for (uint256 i = 0; i < N; ++i) {
            if ((mask >> i) & 1 == 1) b[i >> 3] = bytes1(uint8(b[i >> 3]) | uint8(1 << (i & 7)));
        }
    }

    function _skSum(Pol memory p, uint256 mask) internal pure returns (uint256 s) {
        for (uint256 i = 0; i < N; ++i) {
            if ((mask >> i) & 1 == 1) s = addmod(s, p.sks[i], BLS_R);
        }
    }

    /// @dev Strong QC by the finalizers in `bitsMask`, signed by those in `signMask`.
    function _qc(Pol memory p, uint256 bitsMask, uint256 signMask, bytes32 digest)
        internal
        view
        returns (bytes memory)
    {
        return _rlpList(_l2(_rlpBytes(_bitset(bitsMask)), _rlpBytes(_blsSign(_skSum(p, signMask), digest))));
    }

    function _fin(bytes32 finalityMroot, uint32 activeGen, uint32 lastPendingGen) internal pure returns (Fin memory f) {
        f.activeGen = activeGen;
        f.lastPendingGen = lastPendingGen;
        f.finalityMroot = finalityMroot;
        f.lastPendingStartTs = 1_700_000_000;
        f.l3 = sha256(abi.encode("l3", finalityMroot));
    }

    /// @dev FinalityProof with no pending policy, signed by `active`.
    function _finalityRlp(Fin memory f, Pol memory active, uint256 mask) internal view returns (bytes memory) {
        bytes32 digest = _finalityDigest(f, active.digest);
        return _finalityRlpRaw(f, _qc(active, mask, mask, digest), "", _rlpEmptyList());
    }

    /// @dev FinalityProof carrying pending policy `pend`, with strong QCs under both policies.
    function _finalityPendingRlp(Fin memory f, Pol memory active, Pol memory pend)
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest = _finalityDigest(f, pend.digest);
        return _finalityRlpRaw(
            f, _qc(active, ALL_BUT_ONE, ALL_BUT_ONE, digest), pend.pack, _qc(pend, ALL_BUT_ONE, ALL_BUT_ONE, digest)
        );
    }

    function _finalityRlpRaw(Fin memory f, bytes memory activeQc, bytes memory pendingPack, bytes memory pendingQc)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory l = new bytes[](8);
        l[0] = _rlpUint(f.activeGen);
        l[1] = _rlpUint(f.lastPendingGen);
        l[2] = RLP.encode(f.finalityMroot);
        l[3] = _rlpUint(f.lastPendingStartTs);
        l[4] = RLP.encode(f.l3);
        l[5] = activeQc;
        l[6] = _rlpBytes(pendingPack);
        l[7] = pendingQc;
        return _rlpList(l);
    }

    function _bundle(
        bytes memory activePack,
        bytes memory pendingPack,
        bytes[] memory rotations,
        bytes memory finality,
        Target memory t,
        bytes memory manifest
    ) internal pure returns (bytes memory) {
        bytes[] memory p = new bytes[](8);
        p[0] = _rlpBytes(activePack);
        p[1] = _rlpBytes(pendingPack);
        p[2] = _rlpList(rotations);
        p[3] = finality;
        p[4] = _blockRlp(t);
        p[5] = _actionRlp(t);
        p[6] = _rlpBytes(_bundleContent());
        p[7] = _rlpBytes(manifest);
        return _rlpList(p);
    }

    function _anchor(Pol memory active) internal pure returns (bytes memory) {
        return abi.encode(active.gen, active.digest, uint32(0), bytes32(0));
    }

    function _simpleBundle(Target memory t) internal view returns (bytes memory) {
        bytes memory fin = _finalityRlp(_fin(t.finalityMroot, 1, 1), g1, ALL_BUT_ONE);
        return _bundle(g1.pack, "", new bytes[](0), fin, t, "");
    }
}
