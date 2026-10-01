// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {AntelopeLib} from "@hiero-ledger/clpr/verifiers/evm/antelope/AntelopeLib.sol";
import {AntelopeClprBase} from "@hiero-ledger/clpr/verifiers/evm/antelope/AntelopeClprBase.sol";
import {AntelopeDposVerifier} from "@hiero-ledger/clpr/verifiers/evm/antelope/AntelopeDposVerifier.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";
import {AntelopeDposBuilders} from "./AntelopeDposBuilders.sol";

/// @dev Exposes the finality + inclusion step, so live actions that are not CLPR actions can be
///      checked end to end (and measured) without a CLPR Service on the source chain.
contract AntelopeDposHarness is AntelopeDposVerifier {
    constructor(string memory chainId) AntelopeDposVerifier(chainId) {}

    function proveAction(uint32 version, bytes calldata schedule, bytes calldata chain, bytes calldata action)
        external
        pure
        returns (uint64 receiver, uint64 account, uint64 name, bytes memory data)
    {
        bytes memory s = schedule;
        bytes memory c = chain;
        bytes memory a = action;
        Schedule memory sched = _decodeSchedule(Memory.asSlice(s), version);
        ProvenAction memory p = _proveAction(Memory.asSlice(c), Memory.asSlice(a), sched);
        return (p.receiver, p.account, p.name, p.data);
    }
}

/// @notice AntelopeDposVerifier on synthetic legacy-DPoS chains (real secp256k1 signatures, real
///         header/receipt encodings) and on live XPR Network data recorded from public RPC.
contract AntelopeDposVerifierTest is AntelopeDposBuilders {
    AntelopeDposHarness internal verifier;

    function setUp() public {
        verifier = new AntelopeDposHarness(CHAIN_ID);
    }

    // ── Happy paths ───────────────────────────────────────────────────────────

    function test_verifyBundle_smallSchedule() public {
        Sched memory s = _mkSched(7, 4, 1);
        Act memory a = _queueAct();
        bytes[] memory chain = _chain(s, 1, a.actionMroot, hex"00", 64);
        assertEq(chain.length, 6); // p0..p2 confirm, then 3 distinct producers after
        (ClprTypes.QueueMetadata memory m, bytes[] memory payloads, bytes memory newAnchor,,) =
            verifier.verifyBundle(_bundle(s, new bytes[](0), chain, a), _anchor(s), _context());
        assertEq(m.nextMessageId, 7);
        assertEq(m.receivedRunningHash, keccak256("recv"));
        assertEq(payloads.length, 2);
        assertEq(newAnchor.length, 0);
    }

    function test_verifyBundle_21producers_12blockRounds() public {
        Sched memory s = _mkSched(1414, 21, 2);
        Act memory a = _queueAct();
        bytes[] memory chain = _chain(s, 12, a.actionMroot, hex"00", 400);
        (ClprTypes.QueueMetadata memory m,,,,) =
            verifier.verifyBundle(_bundle(s, new bytes[](0), chain, a), _anchor(s), _context());
        assertEq(m.nextMessageId, 7);
    }

    function test_verifyBundle_rotation() public {
        Sched memory s = _mkSched(7, 4, 1);
        Sched memory s2 = _mkSched(8, 4, 2);
        bytes[] memory rotations = new bytes[](1);
        rotations[0] = _rotation(s, s2, 1);
        Act memory a = _queueAct();
        bytes[] memory chain = _chain(s2, 1, a.actionMroot, hex"00", 64);
        (,, bytes memory newAnchor, bytes memory newAnchorId,) =
            verifier.verifyBundle(_bundle(s, rotations, chain, a), _anchor(s), _context());
        assertEq(newAnchor, _anchor(s2));
        assertEq(newAnchorId, abi.encodePacked(uint32(8)));
    }

    function test_verifyConfig() public {
        Sched memory s = _mkSched(7, 4, 1);
        Act memory a =
            _act(_actionBase(SERVICE_NAME, "ledgerconfig", "relayer"), "", _ledgerConfigReturn(CHAIN_ID), SERVICE_NAME);
        bytes[] memory chain = _chain(s, 1, a.actionMroot, hex"00", 64);
        bytes[] memory c = new bytes[](4);
        c[0] = _rlpUint(s.version);
        c[1] = _schedRlp(s);
        c[2] = _rlpList(chain);
        c[3] = _actRlp(a);
        (bytes memory ctx, string memory chainId, bytes memory serviceAddress,,, bytes memory anchor,,) =
            verifier.verifyConfig(_rlpList(c), CHANNEL, "");
        assertEq(chainId, CHAIN_ID);
        assertEq(serviceAddress, _serviceAddress());
        assertEq(ctx, _context());
        assertEq(anchor, _anchor(s));
    }

    // ── Negative cases ────────────────────────────────────────────────────────

    function test_rejects_badSignature() public {
        Sched memory s = _mkSched(7, 4, 1);
        Act memory a = _queueAct();
        bytes[] memory chain = _chain(s, 1, a.actionMroot, hex"00", 64);
        // Re-sign header 1 with another key: the signature is valid but recovers a stranger.
        Memory.Slice[] memory e = RLP.decodeList(chain[1]);
        bytes memory raw = RLP.readBytes(e[0]);
        bytes32 digest = sha256(
            abi.encodePacked(sha256(abi.encodePacked(sha256(raw), RLP.readBytes32(e[2]))), PENDING_SCHEDULE_HASH)
        );
        bytes[] memory items = new bytes[](4);
        items[0] = _rlpBytes(raw);
        items[1] = _rlpBytes(_k1Sign(0xBAD, digest));
        items[2] = RLP.encode(RLP.readBytes32(e[2]));
        items[3] = RLP.encode(PENDING_SCHEDULE_HASH);
        chain[1] = _rlpList(items);
        vm.expectRevert(
            abi.encodeWithSelector(AntelopeDposVerifier.SignerMismatch.selector, s.producers[1], vm.addr(0xBAD))
        );
        verifier.verifyBundle(_bundle(s, new bytes[](0), chain, a), _anchor(s), _context());
    }

    function test_rejects_wrongBmrootUnderSignature() public {
        Sched memory s = _mkSched(7, 4, 1);
        Act memory a = _queueAct();
        bytes[] memory chain = _chain(s, 1, a.actionMroot, hex"00", 64);
        Memory.Slice[] memory e = RLP.decodeList(chain[2]);
        bytes[] memory items = new bytes[](4);
        items[0] = _rlpBytes(RLP.readBytes(e[0]));
        items[1] = _rlpBytes(RLP.readBytes(e[1]));
        items[2] = RLP.encode(keccak256("other accumulator"));
        items[3] = RLP.encode(PENDING_SCHEDULE_HASH);
        chain[2] = _rlpList(items);
        vm.expectPartialRevert(AntelopeDposVerifier.SignerMismatch.selector);
        verifier.verifyBundle(_bundle(s, new bytes[](0), chain, a), _anchor(s), _context());
    }

    function test_rejects_belowIrreversibility() public {
        Sched memory s = _mkSched(1414, 21, 2);
        Act memory a = _queueAct();
        bytes[] memory chain = _chain(s, 12, a.actionMroot, hex"00", 400);
        bytes[] memory cut = new bytes[](chain.length - 1);
        for (uint256 i = 0; i < cut.length; ++i) {
            cut[i] = chain[i];
        }
        vm.expectRevert(abi.encodeWithSelector(AntelopeDposVerifier.NotIrreversible.selector, 2, 14));
        verifier.verifyBundle(_bundle(s, new bytes[](0), cut, a), _anchor(s), _context());
        // Only half of the confirmations: stuck in stage 1.
        bytes[] memory half = new bytes[](100);
        for (uint256 i = 0; i < half.length; ++i) {
            half[i] = chain[i];
        }
        vm.expectRevert(abi.encodeWithSelector(AntelopeDposVerifier.NotIrreversible.selector, 1, 9));
        verifier.verifyBundle(_bundle(s, new bytes[](0), half, a), _anchor(s), _context());
    }

    function test_rejects_wrongProducerSet() public {
        Sched memory s = _mkSched(7, 4, 1);
        Sched memory rogue = _mkSched(7, 4, 99);
        Act memory a = _queueAct();
        bytes[] memory chain = _chain(rogue, 1, a.actionMroot, hex"00", 64);
        vm.expectRevert(AntelopeDposVerifier.ScheduleMismatch.selector);
        verifier.verifyBundle(_bundle(rogue, new bytes[](0), chain, a), _anchor(s), _context());
        vm.expectPartialRevert(AntelopeDposVerifier.SignerMismatch.selector);
        verifier.verifyBundle(_bundle(s, new bytes[](0), chain, a), _anchor(s), _context());
    }

    function test_rejects_unknownProducer() public {
        Sched memory s = _mkSched(7, 4, 1);
        Sched memory other = _mkSched(7, 5, 1); // prod "ea" is not in s
        Act memory a = _queueAct();
        // Rotate production so the fifth producer signs a counted block.
        bytes[] memory chain = _chain(other, 1, a.actionMroot, hex"00", 64);
        vm.expectRevert(abi.encodeWithSelector(AntelopeDposVerifier.UnknownProducer.selector, other.producers[4]));
        verifier.verifyBundle(_bundle(s, new bytes[](0), chain, a), _anchor(s), _context());
    }

    function test_rejects_brokenLink() public {
        Sched memory s = _mkSched(7, 4, 1);
        Act memory a = _queueAct();
        bytes[] memory chain = _chain(s, 1, a.actionMroot, hex"00", 64);
        bytes[] memory swapped = new bytes[](chain.length);
        for (uint256 i = 0; i < chain.length; ++i) {
            swapped[i] = chain[i];
        }
        (swapped[2], swapped[3]) = (chain[3], chain[2]);
        vm.expectRevert(abi.encodeWithSelector(AntelopeDposVerifier.HeaderChainBroken.selector, 2));
        verifier.verifyBundle(_bundle(s, new bytes[](0), swapped, a), _anchor(s), _context());
    }

    function test_rejects_wrongActionProof() public {
        Sched memory s = _mkSched(7, 4, 1);
        Act memory a = _queueAct();
        bytes[] memory chain = _chain(s, 1, a.actionMroot, hex"00", 64);
        a.ret = _queueState(CHANNEL, 1, 99, keccak256("sent"), 3, keccak256("recv"), 1, bytes32(0));
        vm.expectRevert(AntelopeDposVerifier.ActionRootMismatch.selector);
        verifier.verifyBundle(_bundle(s, new bytes[](0), chain, a), _anchor(s), _context());
    }

    function test_rejects_notServiceAction() public {
        Sched memory s = _mkSched(7, 4, 1);
        Act memory a = _act(_actionBase("eosio.token", "transfer", "relayer"), hex"01", "", "eosio.token");
        bytes[] memory chain = _chain(s, 1, a.actionMroot, hex"00", 64);
        uint64 tok = AntelopeLib.nameValue("eosio.token");
        vm.expectRevert(abi.encodeWithSelector(AntelopeClprBase.NotServiceAction.selector, tok, tok));
        verifier.verifyBundle(_bundle(s, new bytes[](0), chain, a), _anchor(s), _context());
    }

    function test_rejects_staleScheduleAfterRotation() public {
        Sched memory s = _mkSched(7, 4, 1);
        Sched memory s2 = _mkSched(8, 4, 2);
        Act memory a = _queueAct();
        bytes[] memory chain = _chain(s, 1, a.actionMroot, hex"00", 64);
        vm.expectRevert(AntelopeDposVerifier.ScheduleMismatch.selector);
        verifier.verifyBundle(_bundle(s, new bytes[](0), chain, a), _anchor(s2), _context());
        // Headers of the old schedule under the new anchor's schedule.
        vm.expectRevert(abi.encodeWithSelector(AntelopeDposVerifier.WrongScheduleVersion.selector, 7, 8));
        verifier.verifyBundle(_bundle(s2, new bytes[](0), chain, a), _anchor(s2), _context());
    }

    function test_rejects_rotationWithWrongKey() public {
        Sched memory s = _mkSched(7, 4, 1);
        Sched memory s2 = _mkSched(8, 4, 2);
        (bytes memory ext, bytes[] memory keys) = _scheduleExt(s2);
        (, bytes memory otherXy) = _k1Keys(0xBEEF);
        keys[1] = _rlpList(_l2(_rlpUint(0), _rlpBytes(otherXy)));
        bytes[] memory rchain = _chain(s, 1, bytes32(0), ext, 64);
        bytes[] memory rotations = new bytes[](1);
        rotations[0] = _rlpList(_l2(_rlpList(rchain), _rlpList(keys)));
        Act memory a = _queueAct();
        bytes[] memory chain = _chain(s2, 1, a.actionMroot, hex"00", 64);
        vm.expectRevert(AntelopeDposVerifier.RotationKeysMalformed.selector);
        verifier.verifyBundle(_bundle(s, rotations, chain, a), _anchor(s), _context());
    }

    function test_rejects_rotationSkippingVersion() public {
        Sched memory s = _mkSched(7, 4, 1);
        Sched memory s3 = _mkSched(9, 4, 2);
        bytes[] memory rotations = new bytes[](1);
        rotations[0] = _rotation(s, s3, 1);
        Act memory a = _queueAct();
        bytes[] memory chain = _chain(s3, 1, a.actionMroot, hex"00", 64);
        vm.expectRevert(AntelopeDposVerifier.ScheduleMismatch.selector);
        verifier.verifyBundle(_bundle(s, rotations, chain, a), _anchor(s), _context());
    }

    function test_rejects_rotationWithoutProposal() public {
        Sched memory s = _mkSched(7, 4, 1);
        bytes[] memory rchain = _chain(s, 1, bytes32(0), hex"00", 64);
        bytes[] memory rotations = new bytes[](1);
        rotations[0] = _rlpList(_l2(_rlpList(rchain), _rlpEmptyList()));
        Act memory a = _queueAct();
        bytes[] memory chain = _chain(s, 1, a.actionMroot, hex"00", 64);
        vm.expectRevert(AntelopeDposVerifier.NoScheduleChange.selector);
        verifier.verifyBundle(_bundle(s, rotations, chain, a), _anchor(s), _context());
    }

    // ── Live XPR Network data ─────────────────────────────────────────────────

    function _live(string memory network)
        internal
        view
        returns (string memory json, uint32 version, bytes memory schedule, bytes memory chain, bytes memory action)
    {
        json = vm.readFile(
            string.concat(vm.projectRoot(), "/test/verifiers/evm/antelope/fixtures/xpr-", network, ".json")
        );
        version = uint32(vm.parseJsonUint(json, ".scheduleVersion"));
        schedule = vm.parseJsonBytes(json, ".schedule");
        chain = vm.parseJsonBytes(json, ".chain");
        action = vm.parseJsonBytes(json, ".action");
    }

    function _liveFinalityAndInclusion(string memory network) internal view {
        (string memory json, uint32 version, bytes memory schedule, bytes memory chain, bytes memory action) =
            _live(network);
        uint256 g0 = gasleft();
        (uint64 receiver, uint64 account, uint64 name,) = verifier.proveAction(version, schedule, chain, action);
        uint256 used = g0 - gasleft();
        assertEq(account, AntelopeLib.nameValue(vm.parseJsonString(json, ".account")));
        assertEq(name, AntelopeLib.nameValue(vm.parseJsonString(json, ".name")));
        assertEq(receiver, account);
        console.log(string.concat("XPR ", network, " live finality + inclusion gas:"), used);
        console.log("  headers / signed:", vm.parseJsonUint(json, ".headers"), vm.parseJsonUint(json, ".signedHeaders"));
        console.log("  chain bytes / action bytes:", chain.length, action.length);
    }

    function test_live_xprMainnet_finalityAndInclusion() public view {
        _liveFinalityAndInclusion("mainnet");
    }

    function test_live_xprTestnet_finalityAndInclusion() public view {
        _liveFinalityAndInclusion("testnet");
    }

    /// @dev Full verifyBundle on the live data: finality and inclusion pass, then the CLPR rules
    ///      reject the action because it is not the service's `queuestate`.
    function test_live_xprMainnet_verifyBundleReachesClprRules() public {
        (string memory json,, bytes memory schedule, bytes memory chain, bytes memory action) = _live("mainnet");
        bytes[] memory p = new bytes[](6);
        p[0] = schedule;
        p[1] = _rlpEmptyList();
        p[2] = chain;
        p[3] = action;
        p[4] = _rlpBytes("");
        p[5] = _rlpBytes("");
        bytes memory anchor = vm.parseJsonBytes(json, ".trustAnchor");
        uint64 acct = AntelopeLib.nameValue(vm.parseJsonString(json, ".account"));
        vm.expectRevert(abi.encodeWithSelector(AntelopeClprBase.NotServiceAction.selector, acct, acct));
        verifier.verifyBundle(_rlpList(p), anchor, _context());
    }

    function test_live_xprMainnet_rejectsTamperedSignature() public {
        (string memory json, uint32 version, bytes memory schedule, bytes memory chain, bytes memory action) =
            _live("mainnet");
        uint256 off = vm.parseJsonUint(json, ".sigOffset");
        chain[off] = bytes1(uint8(chain[off]) ^ 0x01);
        vm.expectRevert();
        verifier.proveAction(version, schedule, chain, action);
    }

    function test_live_xprMainnet_rejectsOtherSchedule() public {
        (, uint32 version, bytes memory schedule, bytes memory chain, bytes memory action) = _live("mainnet");
        vm.expectRevert(
            abi.encodeWithSelector(AntelopeDposVerifier.WrongScheduleVersion.selector, version, version + 1)
        );
        verifier.proveAction(version + 1, schedule, chain, action);
    }

    // ── Gas ───────────────────────────────────────────────────────────────────

    function test_gas_verifyBundle_21producers() public {
        Sched memory s = _mkSched(1414, 21, 2);
        Act memory a = _queueAct();
        bytes[] memory chain = _chain(s, 12, a.actionMroot, hex"00", 400);
        bytes memory proof = _bundle(s, new bytes[](0), chain, a);
        bytes memory anchor = _anchor(s);
        bytes memory cd = abi.encodeCall(AntelopeDposVerifier.verifyBundle, (proof, anchor, _context()));
        uint256 g0 = gasleft();
        verifier.verifyBundle(proof, anchor, _context());
        uint256 used = g0 - gasleft();
        console.log("DPoS verifyBundle (21 producers, 12-block rounds) gas:", used);
        console.log("  headers:", chain.length, "proofBytes:", proof.length);
        console.log("  calldata:", cd.length);
        assertLt(used, 15_000_000);
        assertLt(cd.length, 128 * 1024);
    }

    function test_gas_verifyBundle_rotation21() public {
        Sched memory s = _mkSched(1414, 21, 2);
        Sched memory s2 = _mkSched(1415, 21, 3);
        bytes[] memory rotations = new bytes[](1);
        rotations[0] = _rotation(s, s2, 12);
        Act memory a = _queueAct();
        bytes[] memory chain = _chain(s2, 12, a.actionMroot, hex"00", 400);
        bytes memory proof = _bundle(s, rotations, chain, a);
        bytes memory anchor = _anchor(s);
        bytes memory cd = abi.encodeCall(AntelopeDposVerifier.verifyBundle, (proof, anchor, _context()));
        uint256 g0 = gasleft();
        verifier.verifyBundle(proof, anchor, _context());
        uint256 used = g0 - gasleft();
        console.log("DPoS verifyBundle with one schedule rotation (21 producers) gas:", used);
        console.log("  proofBytes:", proof.length, "calldata:", cd.length);
        assertLt(used, 15_000_000);
        assertLt(cd.length, 128 * 1024);
    }
}
