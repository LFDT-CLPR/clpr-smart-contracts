// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {MixinTestBuilder} from "@test/verifiers/evm/mixin/MixinTestBuilder.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprBlake3} from "@hiero-ledger/clpr/libraries/crypto/ClprBlake3.sol";
import {MixinKernelVerifier} from "@hiero-ledger/clpr/verifiers/evm/mixin/MixinKernelVerifier.sol";
import {MixinCosi} from "@hiero-ledger/clpr/verifiers/evm/mixin/MixinCosi.sol";

contract MixinKernelVerifierTest is MixinTestBuilder {
    function setUp() public {
        _deployMixin();
    }

    function test_bundle_happy() public view {
        (bytes memory content, bytes32 running) = _content(2);
        (bytes memory proof,) = _bundleProof(_defaults(content, running, 3));
        (ClprTypes.QueueMetadata memory m, bytes[] memory p, bytes memory a,,) =
            mv.verifyBundle(proof, _anchor(), _context());
        assertEq(m.nextMessageId, 3);
        assertEq(m.sentRunningHash, running);
        assertEq(p.length, 2);
        assertEq(a.length, 0);
    }

    function test_gas_bundle() public {
        (bytes memory content, bytes32 running) = _content(2);
        (bytes memory proof,) = _bundleProof(_defaults(content, running, 3));
        uint256 g = gasleft();
        mv.verifyBundle(proof, _anchor(), _context());
        emit log_named_uint("bundle, 6-of-8 CoSi, thread of 2", g - gasleft());
    }

    function test_checkpoint_advancesTip() public view {
        B memory b = _defaults("", 0, 1);
        b.checkpoint = true;
        b.threadLength = 3;
        (bytes memory proof, bytes32 lastTx) = _bundleProof(b);
        (,, bytes memory a, bytes memory id,) = mv.verifyBundle(proof, _anchor(), _context());
        assertEq(a, _anchorOf(_list(), lastTx, 0, 0, T0 - 24 * HOUR));
        assertEq(id, abi.encodePacked(lastTx));
    }

    function test_reverts_belowThreshold() public {
        B memory b = _defaults("", 0, 1);
        b.mask = 0x1f; // 5 of 8
        (bytes memory proof,) = _bundleProof(b);
        vm.expectRevert(abi.encodeWithSelector(MixinKernelVerifier.BelowThreshold.selector, 5, THRESHOLD));
        mv.verifyBundle(proof, _anchor(), _context());
    }

    function test_reverts_badSignature() public {
        B memory b = _defaults("", 0, 1);
        b.flipSig = true;
        (bytes memory proof,) = _bundleProof(b);
        vm.expectRevert(MixinKernelVerifier.BadCosiSignature.selector);
        mv.verifyBundle(proof, _anchor(), _context());
    }

    function test_reverts_maskClaimsOtherSigners() public {
        // signed by nodes 0..5 but the mask names 1..6: the summed key no longer matches
        B memory b = _defaults("", 0, 1);
        (bytes memory proof,) = _bundleProof(b);
        b.mask = 0x7e;
        (bytes memory other,) = _bundleProof(b);
        assertTrue(keccak256(proof) != keccak256(other));
        vm.expectRevert(MixinKernelVerifier.BadCosiSignature.selector);
        mv.verifyBundle(_swapSig(other, proof), _anchor(), _context());
    }

    function test_reverts_wrongNodeSet() public {
        (bytes memory proof,) = _bundleProof(_defaults("", 0, 1));
        vm.expectRevert(MixinKernelVerifier.NodeSetMismatch.selector);
        mv.verifyBundle(proof, abi.encode(keccak256("other nodes"), TIP, 0, 0, 0), _context());
    }

    function test_reverts_signedByForeignSet() public {
        // a correct CoSi by a node outside the anchored set: the anchored keys do not sum to it
        B memory b = _defaults("", 0, 1);
        uint256[] memory foreign = _with(_without(_list(), 0), NEW_NODE);
        b.signers = foreign;
        (bytes memory proof,) = _bundleProof(b);
        vm.expectRevert();
        mv.verifyBundle(proof, _anchor(), _context());
    }

    function test_reverts_wrongPoint() public {
        (bytes memory proof,) = _bundleProof(_defaults("", 0, 1));
        // the x of node 0 replaced by node 1's x: off the curve for node 0's y
        bytes memory bad = _replace(proof, abi.encodePacked(xsOf[0]), abi.encodePacked(xsOf[1]));
        vm.expectRevert(abi.encodeWithSelector(MixinCosi.BadPoint.selector, 0));
        mv.verifyBundle(bad, _anchor(), _context());
    }

    function test_reverts_txNotInSnapshot() public {
        B memory b = _defaults("", 0, 1);
        b.txOutsideSnapshot = true;
        (bytes memory proof, bytes32 lastTx) = _bundleProof(b);
        vm.expectRevert(abi.encodeWithSelector(MixinKernelVerifier.TransactionNotInSnapshot.selector, lastTx));
        mv.verifyBundle(proof, _anchor(), _context());
    }

    function test_reverts_threadNotFromTip_staleOrForeign() public {
        // a valid, final record transaction that does not extend the anchored thread
        (bytes memory proof,) = _bundleProof(_defaults("", 0, 1));
        vm.expectRevert(abi.encodeWithSelector(MixinKernelVerifier.ThreadBroken.selector, 0));
        mv.verifyBundle(proof, _anchorOf(_list(), keccak256("advanced tip"), 0, 0, 0), _context());
    }

    function test_reverts_wrongChannel() public {
        B memory b = _defaults("", 0, 1);
        b.record = _record(bytes32(uint256(0xBEEF)), 1, 0, "", "");
        (bytes memory proof,) = _bundleProof(b);
        vm.expectRevert();
        mv.verifyBundle(proof, _anchor(), _context());
    }

    function test_reverts_badAnchor() public {
        (bytes memory proof,) = _bundleProof(_defaults("", 0, 1));
        vm.expectRevert(MixinKernelVerifier.InvalidTrustAnchor.selector);
        mv.verifyBundle(proof, abi.encode(_nodesHash(), uint256(6), TIP), _context());
        vm.expectRevert(MixinKernelVerifier.InvalidTrustAnchor.selector);
        mv.verifyBundle(proof, _anchorOf(_list(), TIP, keccak256("k"), 0, 0), _context());
    }

    // ── node-set rotation ────────────────────────────────────────────────────

    function test_rotation_acceptMakesPending_tipOnly() public view {
        bytes memory tipTx = _tx(keccak256("prev"), 0, _record(CHANNEL, 3, 0, "", ""));
        B memory b = _defaults("", 0, 3);
        b.tipTx = tipTx;
        b.changes = new bytes[](1);
        b.changes[0] = _acceptChange(_list(), T0);
        (bytes memory proof,) = _bundleProof(b);
        bytes32 tip = ClprBlake3.hash(tipTx);
        (ClprTypes.QueueMetadata memory m, bytes[] memory p, bytes memory a, bytes memory id,) =
            mv.verifyBundle(proof, _anchorOf(_list(), tip, 0, 0, T0 - 24 * HOUR), _context());
        assertEq(m.nextMessageId, 3); // the tip's record, re-read
        assertEq(p.length, 0);
        assertEq(a, _anchorOf(_list(), tip, pubs[NEW_NODE], T0, T0));
        assertEq(id, abi.encodePacked(tip));
    }

    function test_rotation_pendingJoinsAfter12h() public view {
        bytes memory anchor = _anchorOf(_list(), TIP, pubs[NEW_NODE], T0, T0);
        uint256[] memory nine = _with(_list(), NEW_NODE);
        B memory b = _defaults("", 0, 1);
        b.ts = T0 + 12 * HOUR + 1;
        b.signers = nine;
        b.mask = _lowMask(7); // 9*2/3+1 = 7
        (bytes memory proof,) = _bundleProof(b);
        (,, bytes memory a,,) = mv.verifyBundle(proof, anchor, _context());
        assertEq(a, _anchorOf(nine, TIP, 0, 0, T0));
    }

    function test_rotation_pendingNotReadyBefore12h() public {
        bytes memory anchor = _anchorOf(_list(), TIP, pubs[NEW_NODE], T0, T0);
        // before 12 h the pending node is not a signer, but it counts toward the base (9 → 7)
        B memory b = _defaults("", 0, 1);
        b.ts = T0 + 12 * HOUR;
        b.mask = _lowMask(6);
        (bytes memory proof,) = _bundleProof(b);
        vm.expectRevert(abi.encodeWithSelector(MixinKernelVerifier.BelowThreshold.selector, 6, 7));
        mv.verifyBundle(proof, anchor, _context());
        // a signature that already includes it is rejected (the mask points past the list)
        b.signers = _with(_list(), NEW_NODE);
        b.mask = _lowMask(9);
        (proof,) = _bundleProof(b);
        vm.expectRevert(abi.encodeWithSelector(MixinCosi.BadPoint.selector, 8));
        mv.verifyBundle(proof, anchor, _context());
        // the 8 ready nodes alone pass
        b.signers = _list();
        b.mask = _lowMask(8);
        (proof,) = _bundleProof(b);
        (,, bytes memory a,,) = mv.verifyBundle(proof, anchor, _context());
        assertEq(a.length, 0);
    }

    function test_rotation_removeThenRecord() public view {
        uint256[] memory seven = _without(_list(), 3);
        B memory b = _defaults("", 0, 1);
        b.changes = new bytes[](1);
        b.changes[0] = _removeChange(_list(), 3, T0 - HOUR);
        b.signers = seven;
        b.mask = _lowMask(5); // 7*2/3+1 = 5
        (bytes memory proof,) = _bundleProof(b);
        (,, bytes memory a,,) = mv.verifyBundle(proof, _anchor(), _context());
        assertEq(a, _anchorOf(seven, TIP, 0, 0, T0 - HOUR));
    }

    function test_rotation_acceptRemovePromote_gas() public {
        // accept at T0-20h, remove node 0 at T0-13h (old set incl. node 0), record at T0 (new list)
        uint256[] memory seven = _without(_list(), 0);
        uint256[] memory eight = _with(seven, NEW_NODE);
        B memory b = _defaults("", 0, 1);
        b.changes = new bytes[](2);
        b.changes[0] = _acceptChange(_list(), T0 - 20 * HOUR);
        b.changes[1] = _removeChange(_list(), 0, T0 - 13 * HOUR);
        b.signers = eight;
        b.mask = _lowMask(6);
        (bytes memory proof,) = _bundleProof(b);
        uint256 g = gasleft();
        (,, bytes memory a,,) = mv.verifyBundle(proof, _anchor(), _context());
        emit log_named_uint("bundle + accept + remove, 8 nodes", g - gasleft());
        assertEq(a, _anchorOf(eight, TIP, 0, 0, T0 - 13 * HOUR));
    }

    function test_reverts_rotation_replayedChange() public {
        // the accept was already applied (changedAt = its timestamp)
        B memory b = _defaults("", 0, 1);
        b.changes = new bytes[](1);
        b.changes[0] = _acceptChange(_list(), T0 - 20 * HOUR);
        (bytes memory proof,) = _bundleProof(b);
        vm.expectRevert(abi.encodeWithSelector(MixinKernelVerifier.StaleNodeChange.selector, 0));
        mv.verifyBundle(proof, _anchorOf(_list(), TIP, 0, 0, T0 - 20 * HOUR), _context());
    }

    function test_reverts_rotation_secondAcceptWhilePending() public {
        B memory b = _defaults("", 0, 1);
        b.changes = new bytes[](1);
        b.changes[0] = _acceptChange(_list(), T0 - 2 * HOUR);
        (bytes memory proof,) = _bundleProof(b);
        vm.expectRevert(abi.encodeWithSelector(MixinKernelVerifier.NodeAlreadyPending.selector, 0));
        mv.verifyBundle(
            proof, _anchorOf(_list(), TIP, keccak256("other pending"), T0 - 3 * HOUR, T0 - 3 * HOUR), _context()
        );
    }

    function test_reverts_rotation_removeUnknownNode() public {
        B memory b = _defaults("", 0, 1);
        b.changes = new bytes[](1);
        b.changes[0] = _change(_nodeTx(REMOVE, NEW_NODE), _list(), _lowMask(8), T0 - HOUR, 77);
        (bytes memory proof,) = _bundleProof(b);
        vm.expectRevert(abi.encodeWithSelector(MixinKernelVerifier.UnknownNode.selector, 0));
        mv.verifyBundle(proof, _anchor(), _context());
    }

    function test_reverts_rotation_notANodeChange() public {
        B memory b = _defaults("", 0, 1);
        b.changes = new bytes[](1);
        // a final XIN transfer whose extra looks like signer ‖ payee
        bytes memory transfer = _txOf(XIN, keccak256("utxo"), 0, abi.encodePacked(pubs[NEW_NODE], keccak256("payee")));
        b.changes[0] = _change(transfer, _list(), _lowMask(8), T0 - HOUR, 77);
        (bytes memory proof,) = _bundleProof(b);
        vm.expectRevert(abi.encodeWithSelector(MixinKernelVerifier.NotANodeChange.selector, 0));
        mv.verifyBundle(proof, _anchor(), _context());
        // an accept-typed output in a non-XIN asset
        b.changes[0] = _change(
            _txOf(
                keccak256("other asset"), keccak256("utxo"), ACCEPT, abi.encodePacked(pubs[NEW_NODE], keccak256("p"))
            ),
            _list(),
            _lowMask(8),
            T0 - HOUR,
            0
        );
        (proof,) = _bundleProof(b);
        vm.expectRevert(abi.encodeWithSelector(MixinKernelVerifier.NotANodeChange.selector, 0));
        mv.verifyBundle(proof, _anchor(), _context());
    }

    function test_reverts_rotation_changeBelowThreshold() public {
        B memory b = _defaults("", 0, 1);
        b.changes = new bytes[](1);
        b.changes[0] = _change(_nodeTx(REMOVE, 3), _list(), _lowMask(5), T0 - HOUR, 77);
        (bytes memory proof,) = _bundleProof(b);
        vm.expectRevert(abi.encodeWithSelector(MixinKernelVerifier.BelowThreshold.selector, 5, THRESHOLD));
        mv.verifyBundle(proof, _anchor(), _context());
    }

    function test_reverts_rotation_acceptNotRoundZero() public {
        B memory b = _defaults("", 0, 1);
        b.changes = new bytes[](1);
        b.changes[0] = _change(_nodeTx(ACCEPT, NEW_NODE), _with(_list(), NEW_NODE), _lowMask(9), T0 - HOUR, 5);
        (bytes memory proof,) = _bundleProof(b);
        vm.expectRevert(abi.encodeWithSelector(MixinKernelVerifier.NotANodeChange.selector, 0));
        mv.verifyBundle(proof, _anchor(), _context());
    }

    function test_tipOnly_rereadsRecord_onlyAtTheTip() public {
        bytes memory tipTx = _tx(keccak256("prev"), 0, _record(CHANNEL, 3, 0, "", ""));
        B memory b = _defaults("", 0, 3);
        b.tipTx = tipTx;
        (bytes memory proof,) = _bundleProof(b);
        // a tip-only thread must not come with a finality proof, and vice versa
        bytes memory anchor = _anchorOf(_list(), ClprBlake3.hash(tipTx), 0, 0, 0);
        (,, bytes memory a,,) = mv.verifyBundle(proof, anchor, _context());
        assertEq(a.length, 0); // nothing changed
        vm.expectRevert(abi.encodeWithSelector(MixinKernelVerifier.ThreadBroken.selector, 0));
        mv.verifyBundle(proof, _anchor(), _context());
    }

    function test_config() public view {
        (bytes memory ctx, string memory chainId, bytes memory service,,, bytes memory anchor,,) =
            mv.verifyConfig(_configProof("mixin:mainnet", ""), CHANNEL, "");
        assertEq(chainId, "mixin:mainnet");
        assertEq(service, abi.encodePacked(APP));
        assertEq(ctx, _context());
        assertEq(anchor.length, 160);
    }

    function _replace(bytes memory hay, bytes memory a, bytes memory b) internal pure returns (bytes memory out) {
        out = bytes.concat(hay);
        for (uint256 i = 0; i + a.length <= out.length; ++i) {
            bool m = true;
            for (uint256 j = 0; j < a.length; ++j) {
                if (out[i + j] != a[j]) {
                    m = false;
                    break;
                }
            }
            if (m) {
                for (uint256 j = 0; j < b.length; ++j) {
                    out[i + j] = b[j];
                }
                return out;
            }
        }
        revert("not found");
    }

    /// @dev Put the 64-byte signature of `from` into `into` (both proofs share layout and lengths).
    function _swapSig(bytes memory into, bytes memory from) internal pure returns (bytes memory) {
        // the signature is the only 64-byte RLP string (prefix 0xb840) after the snapshot payload
        uint256 a = _lastIndexOf(into, hex"b840");
        uint256 b = _lastIndexOf(from, hex"b840");
        bytes memory out = bytes.concat(into);
        for (uint256 i = 0; i < 66; ++i) {
            out[a + i] = from[b + i];
        }
        return out;
    }

    function _lastIndexOf(bytes memory hay, bytes memory n) internal pure returns (uint256 idx) {
        bool found;
        for (uint256 i = 0; i + n.length <= hay.length; ++i) {
            if (hay[i] == n[0] && hay[i + 1] == n[1]) {
                idx = i;
                found = true;
            }
        }
        require(found, "sig not found");
    }
}
