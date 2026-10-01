// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {AntelopeLib} from "@hiero-ledger/clpr/verifiers/evm/antelope/AntelopeLib.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {AntelopeTestBase} from "./AntelopeTestBase.sol";

/// @dev Synthetic legacy-DPoS data built as Leap builds it: producer schedules with real secp256k1 keys,
///      packed headers, signed header chains that satisfy the LIB rule, schedule-change extensions and
///      legacy action Merkle paths.
abstract contract AntelopeDposBuilders is AntelopeTestBase {
    struct Sched {
        uint32 version;
        uint64[] producers;
        uint256[] pks;
        address[] signers;
    }

    /// @dev One proven action and the receipts tree it sits in.
    struct Act {
        bytes actionBase;
        bytes data;
        bytes ret;
        uint64 receiver;
        bytes tail;
        uint256 index;
        uint256 count;
        bytes32[] siblings;
        bytes32 actionMroot;
    }

    uint32 internal constant TARGET = 406_000_000;
    bytes32 internal constant BMROOT_SEED = keccak256("bmroot");
    bytes32 internal constant PENDING_SCHEDULE_HASH = keccak256("pending schedule");
    // ── Builders ──────────────────────────────────────────────────────────────

    function _mkSched(uint32 version, uint256 n, uint256 seed) internal pure returns (Sched memory s) {
        s.version = version;
        s.producers = new uint64[](n);
        s.pks = new uint256[](n);
        s.signers = new address[](n);
        for (uint256 i = 0; i < n; ++i) {
            s.producers[i] = AntelopeLib.nameValue(
                string(abi.encodePacked("prod", bytes1(uint8(0x61 + i % 26)), bytes1(uint8(0x61 + (i / 26)))))
            );
            s.pks[i] = uint256(keccak256(abi.encode("k1", seed, i))) % (2 ** 255);
            s.signers[i] = vm.addr(s.pks[i]);
        }
    }

    function _schedRlp(Sched memory s) internal pure returns (bytes memory) {
        bytes[] memory items = new bytes[](s.producers.length);
        for (uint256 i = 0; i < items.length; ++i) {
            items[i] = _rlpList(_l2(_rlpUint(s.producers[i]), RLP.encode(s.signers[i])));
        }
        return _rlpList(items);
    }

    function _anchor(Sched memory s) internal pure returns (bytes memory) {
        return abi.encode(s.version, keccak256(abi.encode(s.version, s.producers, s.signers)));
    }

    function _le16(uint16 v) internal pure returns (bytes2) {
        return bytes2((v >> 8) | (v << 8));
    }

    function _header(
        uint32 ts,
        uint64 producer,
        uint16 confirmed,
        bytes32 previous,
        bytes32 actionMroot,
        uint32 version,
        bytes memory ext
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            AntelopeLib.le32(ts),
            AntelopeLib.le64(producer),
            _le16(confirmed),
            previous,
            bytes32(0),
            actionMroot,
            AntelopeLib.le32(version),
            uint8(0),
            ext
        );
    }

    struct Rule {
        uint256 r1;
        uint256 r2;
        uint256 seen1;
        uint256 seen2;
        uint256 c1;
        uint256 c2;
    }

    /// @dev Replays the verifier's DPoS rule for one header; true when the header counts.
    function _counts(Rule memory r, uint256 j, uint256 k, uint256 confirmed) internal pure returns (bool) {
        uint256 bit = uint256(1) << j;
        if (r.c1 < r.r1) {
            if (k <= confirmed && r.seen1 & bit == 0) {
                r.seen1 |= bit;
                ++r.c1;
                return true;
            }
            return false;
        }
        if (r.seen2 & bit == 0) {
            r.seen2 |= bit;
            ++r.c2;
            return true;
        }
        return false;
    }

    function _signedItem(bytes memory raw, uint256 pk, uint256 k) internal pure returns (bytes memory) {
        bytes32 bmroot = keccak256(abi.encode(BMROOT_SEED, k));
        bytes32 digest = sha256(abi.encodePacked(sha256(abi.encodePacked(sha256(raw), bmroot)), PENDING_SCHEDULE_HASH));
        bytes[] memory e = new bytes[](4);
        e[0] = _rlpBytes(raw);
        e[1] = _rlpBytes(_k1Sign(pk, digest));
        e[2] = RLP.encode(bmroot);
        e[3] = RLP.encode(PENDING_SCHEDULE_HASH);
        return _rlpList(e);
    }

    /// @dev A contiguous header chain from TARGET, producers in schedule order, `perRun` blocks
    ///      each; the first block of a run confirms everything since that producer's last run.
    ///      Signs exactly the headers the DPoS rule counts and stops when TARGET is irreversible.
    function _chain(Sched memory s, uint256 perRun, bytes32 actionMroot, bytes memory firstExt, uint256 maxHeaders)
        internal
        pure
        returns (bytes[] memory items)
    {
        uint256 n = s.producers.length;
        Rule memory r;
        r.r1 = n * 2 / 3 + 1;
        r.r2 = n - (n - 1) / 3;
        bytes[] memory tmp = new bytes[](maxHeaders);
        bytes32 previous = bytes32((uint256(TARGET - 1) << 224) | uint256(keccak256("genesis")) >> 32);
        uint256 k;
        for (; k < maxHeaders && r.c2 < r.r2; ++k) {
            uint256 j = (k / perRun) % n;
            uint16 confirmed = k % perRun == 0 && k > 0 ? uint16((n - 1) * perRun) : 0;
            bytes memory raw = _header(
                uint32(1_000_000 + k),
                s.producers[j],
                confirmed,
                previous,
                k == 0 ? actionMroot : bytes32(0),
                s.version,
                k == 0 ? firstExt : bytes(hex"00")
            );
            previous = AntelopeLib.blockId(sha256(raw), uint32(TARGET + k));
            if (_counts(r, j, k, confirmed)) {
                tmp[k] = _signedItem(raw, s.pks[j], k);
            } else {
                bytes[] memory e = new bytes[](1);
                e[0] = _rlpBytes(raw);
                tmp[k] = _rlpList(e);
            }
        }
        items = new bytes[](k);
        for (uint256 i = 0; i < k; ++i) {
            items[i] = tmp[i];
        }
    }

    function _act(bytes memory actionBase, bytes memory data, bytes memory ret, string memory receiver)
        internal
        pure
        returns (Act memory a)
    {
        a.actionBase = actionBase;
        a.data = data;
        a.ret = ret;
        a.receiver = AntelopeLib.nameValue(receiver);
        a.tail = abi.encodePacked(
            AntelopeLib.le64(123_456_789), // global_sequence
            AntelopeLib.le64(42), // recv_sequence
            uint8(1),
            AntelopeLib.le64(AntelopeLib.nameValue("relayer")),
            AntelopeLib.le64(7), // auth_sequence
            uint8(1), // code_sequence
            uint8(1) // abi_sequence
        );
        bytes32 receipt =
            AntelopeLib.legacyReceiptDigest(a.receiver, AntelopeLib.actionDigest(actionBase, data, ret), a.tail);
        bytes32[] memory leaves = _filler(9, 5);
        a.index = 3;
        a.count = leaves.length;
        leaves[a.index] = receipt;
        a.siblings = _legacyProof(leaves, a.index);
        a.actionMroot = _legacyRoot(leaves);
    }

    function _queueAct() internal pure returns (Act memory) {
        return _act(
            _actionBase(SERVICE_NAME, "queuestate", "relayer"),
            abi.encodePacked(CHANNEL),
            _defaultQueueState(),
            SERVICE_NAME
        );
    }

    function _actRlp(Act memory a) internal pure returns (bytes memory) {
        bytes[] memory l = new bytes[](8);
        l[0] = _rlpBytes(a.actionBase);
        l[1] = _rlpBytes(a.data);
        l[2] = _rlpBytes(a.ret);
        l[3] = _rlpUint(a.receiver);
        l[4] = _rlpBytes(a.tail);
        l[5] = _rlpUint(a.index);
        l[6] = _rlpUint(a.count);
        l[7] = _rlpB32s(a.siblings);
        return _rlpList(l);
    }

    function _bundle(Sched memory s, bytes[] memory rotations, bytes[] memory chain, Act memory a)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory p = new bytes[](6);
        p[0] = _schedRlp(s);
        p[1] = _rlpList(rotations);
        p[2] = _rlpList(chain);
        p[3] = _actRlp(a);
        p[4] = _rlpBytes(_bundleContent());
        p[5] = _rlpBytes("");
        return _rlpList(p);
    }

    /// @dev producer_schedule_change_extension (id 1) proposing `next`, single K1 key per producer.
    function _scheduleExt(Sched memory next) internal returns (bytes memory ext, bytes[] memory keys) {
        bytes memory data = abi.encodePacked(AntelopeLib.le32(next.version), AntelopeLib.varUint(next.producers.length));
        keys = new bytes[](next.producers.length);
        for (uint256 i = 0; i < next.producers.length; ++i) {
            (bytes memory compressed, bytes memory xy) = _k1Keys(next.pks[i]);
            data = abi.encodePacked(
                data,
                AntelopeLib.le64(next.producers[i]),
                uint8(0), // block_signing_authority_v0
                AntelopeLib.le32(1), // threshold
                uint8(1), // one key
                uint8(0), // K1
                compressed,
                _le16(1) // weight
            );
            keys[i] = _rlpList(_l2(_rlpUint(0), _rlpBytes(xy)));
        }
        ext = abi.encodePacked(uint8(1), _le16(1), AntelopeLib.varUint(data.length), data);
    }

    function _rotation(Sched memory old, Sched memory next, uint256 perRun) internal returns (bytes memory) {
        (bytes memory ext, bytes[] memory keys) = _scheduleExt(next);
        bytes[] memory chain = _chain(old, perRun, bytes32(0), ext, 400);
        return _rlpList(_l2(_rlpList(chain), _rlpList(keys)));
    }
}
