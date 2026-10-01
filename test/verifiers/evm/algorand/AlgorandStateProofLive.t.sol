// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {
    AlgorandStateProofAccumulator as Acc
} from "@hiero-ledger/clpr/verifiers/evm/algorand/AlgorandStateProofAccumulator.sol";
import {ClprAlgorandStateProof as SP} from "@hiero-ledger/clpr/libraries/proof/algorand/ClprAlgorandStateProof.sol";
import {AlgorandLiveKit} from "@test/verifiers/evm/algorand/AlgorandLiveKit.sol";
import {
    AlgorandStateProofVerifier as V
} from "@hiero-ledger/clpr/verifiers/evm/algorand/AlgorandStateProofVerifier.sol";

/// @notice A REAL Algorand mainnet state proof (63 reveals, 151 coins) accumulated on chain: bootstrap
///         from the previous interval's message, one reveal per transaction, then the coin check.
contract AlgorandStateProofLiveTest is AlgorandLiveKit {
    bytes32 internal root;

    function setUp() public {
        vm.pauseGasMetering();
        _initLive();
        vm.resumeGasMetering();
        root = acc.bootstrap(_msg(".prev"));
    }

    function test_message_hashMatchesFixture() public view {
        SP.Message memory m = _msg(".msg");
        assertEq(SP.encodeMessage(m), _b(".msgEncoding"));
        assertEq(SP.messageHash(m), vm.parseJsonBytes32(json, ".msgHash"));
    }

    function test_live_fullStateProof() public {
        Acc.SessionHeader memory h = _header(root);
        uint256 n = _revealCount();
        uint256 minGas = type(uint256).max;
        uint256 maxGas;
        uint256 total;
        // ~700 M gas in total, more than one test may use: the meter is reset after every reveal
        // transaction (each one is measured on its own, as it would be sent)
        for (uint256 i = 0; i < n; i++) {
            Acc.Reveal[] memory rs = _one(_reveal(i));
            uint256 g = gasleft();
            acc.submitReveals(h, rs);
            g -= gasleft();
            total += g;
            if (g < minGas) minGas = g;
            if (g > maxGas) maxGas = g;
            assertLt(g, 15_000_000, "one reveal per transaction must fit 15M gas");
            vm.resetGasMetering();
        }
        uint64[] memory positions = _positions();
        // swapped coin positions: some coin falls outside its claimed reveal
        uint64[] memory swapped = _positions();
        (swapped[0], swapped[1]) = (swapped[1], swapped[0]);
        if (swapped[0] != swapped[1]) {
            vm.expectRevert();
            acc.finalize(h, swapped);
        }
        // fewer coins than the weight inequality needs
        uint64[] memory few = new uint64[](positions.length / 2);
        for (uint256 i = 0; i < few.length; i++) {
            few[i] = positions[i];
        }
        vm.expectRevert(Acc.InsufficientWeight.selector);
        acc.finalize(h, few);

        uint256 gf = gasleft();
        acc.finalize(h, positions);
        gf -= gasleft();
        console.log("reveals", n);
        console.log("submitReveals(1) gas min", minGas);
        console.log("submitReveals(1) gas max", maxGas);
        console.log("submitReveals total gas", total);
        console.log("finalize gas", gf);
        Acc.Interval memory iv = acc.interval(root, h.message.lastAttestedRound);
        assertEq(iv.blockHeadersCommitment, h.message.blockHeadersCommitment);
        assertEq(iv.firstAttestedRound, h.message.firstAttestedRound);
        assertEq(abi.encodePacked(iv.votersHi, iv.votersLo), h.message.votersCommitment);

        // end to end: the live application call of round `header.round` is proven under the chained lineage
        V v = new V(acc);
        bytes memory tp = _txProof();
        bytes memory anchor = _liveAnchor(root);
        uint256 gt = gasleft();
        V.Proven memory pr = v.verifyTransaction(tp, anchor);
        console.log("verifyTransaction gas", gt - gasleft());
        console.log("verifyTransaction proof bytes", tp.length);
        assertEq(pr.round, _u(".header.round"));
        assertEq(pr.appId, _u(".tx.appId"));
        assertEq(pr.logs.length, 1);
        assertEq(pr.logs[0], _b(".tx.logs[0]"));

        // replay: the interval is accumulated once
        vm.expectRevert(abi.encodeWithSelector(Acc.IntervalExists.selector, root, h.message.lastAttestedRound));
        acc.finalize(h, positions);
        vm.expectRevert(abi.encodeWithSelector(Acc.IntervalExists.selector, root, h.message.lastAttestedRound));
        acc.submitReveals(h, _one(_reveal(0)));
    }

    function test_live_transactionUnderBootstrappedInterval() public {
        bytes32 r2 = acc.bootstrap(_msg(".msg"));
        V v = new V(acc);
        V.Proven memory pr = v.verifyTransaction(_txProof(), _liveAnchor(r2));
        assertEq(pr.appId, _u(".tx.appId"));
        // not a CLPR application: verifyBundle for this transaction is rejected
        V.BundleProof memory bp;
        bp.txn = abi.decode(_txProof(), (V.TxProof));
        vm.expectRevert(abi.encodeWithSelector(V.WrongApplication.selector, _u(".tx.appId")));
        v.verifyBundle(abi.encode(bp), _liveAnchor(r2), abi.encodePacked(bytes32(0), uint64(1)));
        // the previous interval's lineage does not hold this round
        vm.expectRevert();
        v.verifyTransaction(_txProof(), _liveAnchor(root));
    }

    function test_rejects_tamperedSignature() public {
        Acc.SessionHeader memory h = _header(root);
        Acc.Reveal memory r = _reveal(0);
        r.sigCT[900] ^= 0x01; // the signature slot no longer hashes into sigCommit
        vm.expectRevert(abi.encodeWithSelector(Acc.BadReveal.selector, r.pos, uint8(2)));
        acc.submitReveals(h, _one(r));
    }

    function test_rejects_signatureOverOtherMessage() public {
        Acc.SessionHeader memory h = _header(root);
        h.message.blockHeadersCommitment = keccak256("forged headers"); // same voters, different message
        Acc.Reveal memory r = _reveal(0);
        vm.expectRevert(abi.encodeWithSelector(Acc.BadReveal.selector, r.pos, uint8(4)));
        acc.submitReveals(h, _one(r));
    }

    function test_rejects_wrongVoterSet() public {
        SP.Message memory prev = _msg(".prev");
        prev.votersCommitment[7] ^= 0x01;
        bytes32 other = acc.bootstrap(prev);
        Acc.Reveal memory r = _reveal(0);
        vm.expectRevert(abi.encodeWithSelector(Acc.BadReveal.selector, r.pos, uint8(3)));
        acc.submitReveals(_header(other), _one(r));
    }

    function test_rejects_wrongKeyPathOrWeight() public {
        Acc.SessionHeader memory h = _header(root);
        Acc.Reveal memory r = _reveal(0);
        r.keyPath[3] ^= 0x01; // key path no longer reaches the participant's commitment
        vm.expectRevert(abi.encodeWithSelector(Acc.BadReveal.selector, r.pos, uint8(1)));
        acc.submitReveals(h, _one(r));
        r = _reveal(0);
        r.weight += 1; // claimed weight is not the participant's
        vm.expectRevert(abi.encodeWithSelector(Acc.BadReveal.selector, r.pos, uint8(3)));
        acc.submitReveals(h, _one(r));
    }

    function test_rejects_saltVersionAndShape() public {
        Acc.SessionHeader memory h = _header(root);
        h.saltVersion = 1;
        Acc.Reveal memory r = _reveal(0);
        vm.expectRevert(abi.encodeWithSelector(Acc.BadReveal.selector, r.pos, uint8(5)));
        acc.submitReveals(h, _one(r));
        h = _header(root);
        h.treeDepth = 9;
        vm.expectRevert(abi.encodeWithSelector(Acc.BadReveal.selector, r.pos, uint8(0)));
        acc.submitReveals(h, _one(r));
    }

    function test_rejects_notNextIntervalOrUnknownRoot() public {
        Acc.SessionHeader memory h = _header(root);
        h.root = keccak256("unknown");
        vm.expectRevert(abi.encodeWithSelector(Acc.UnknownInterval.selector, h.root, h.prevLastRound));
        acc.submitReveals(h, _one(_reveal(0)));
        h = _header(root);
        h.message.firstAttestedRound += 256;
        h.message.lastAttestedRound += 256;
        vm.expectRevert(Acc.NotNextInterval.selector);
        acc.submitReveals(h, _one(_reveal(0)));
    }

    function test_rejects_finalizeBeforeReveals() public {
        Acc.SessionHeader memory h = _header(root);
        acc.submitReveals(h, _one(_reveal(0)));
        vm.expectRevert();
        acc.finalize(h, _positions());
    }

    function test_live_twoRevealsPerTransaction() public {
        Acc.SessionHeader memory h = _header(root);
        Acc.Reveal[] memory rs = new Acc.Reveal[](2);
        rs[0] = _reveal(0);
        rs[1] = _reveal(1);
        uint256 g = gasleft();
        acc.submitReveals(h, rs);
        console.log("submitReveals(2) gas", g - gasleft());
    }
}
