// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {CardanoTestKit} from "./CardanoTestKit.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprMithrilStm} from "@hiero-ledger/clpr/libraries/proof/cardano/ClprMithrilStm.sol";
import {ClprCardanoLedger} from "@hiero-ledger/clpr/libraries/proof/cardano/ClprCardanoLedger.sol";
import {CardanoMithrilVerifier} from "@hiero-ledger/clpr/verifiers/evm/cardano/CardanoMithrilVerifier.sol";

/// @notice CardanoMithrilVerifier on synthetic, cryptographically real worlds: positive paths and the
///         negative cases (bad signature, below threshold, wrong aggregate key, wrong state proof,
///         stale epoch, invalid transaction, malformed lottery).
contract CardanoMithrilVerifierTest is Test, CardanoTestKit {
    Network internal netA; // epoch 100
    Network internal netB; // epoch 101 (rotated to)

    function setUp() public {
        _initKit();
        netA = _network(100, 1, 4, 10);
        netB = _network(101, 2, 5, 10);
    }

    function _bundle(Queue memory q) internal view returns (World memory w) {
        w = _world(netA, netB, q);
    }

    function test_bundle_happyPath() public view {
        Queue memory q = defaultQueue();
        World memory w = _bundle(q);
        (ClprTypes.QueueMetadata memory m, bytes[] memory payloads, bytes memory na, bytes memory naId,) =
            cv.verifyBundle(_encode(w), _anchor(netA), ctx());
        assertEq(m.nextMessageId, q.nextMessageId);
        assertEq(m.receivedMessageId, q.receivedMessageId);
        assertEq(m.sentRunningHash, q.sentRunningHash);
        assertEq(m.receivedRunningHash, q.receivedRunningHash);
        assertEq(m.endpointManifestVersion, q.peerManifestVersion);
        assertEq(uint8(m.state), q.status);
        assertEq(payloads.length, 1);
        assertEq(na.length, 0);
        assertEq(naId.length, 0);
    }

    function test_bundle_withRotation_advancesAnchor() public view {
        World memory w = _world(netB, _network(102, 3, 3, 10), defaultQueue());
        w.rotations = _one(_rotation(netA, netB));
        (,, bytes memory na, bytes memory naId,) = cv.verifyBundle(_encode(w), _anchor(netA), ctx());
        assertEq(na, _anchor(netB));
        assertEq(naId, abi.encodePacked(uint64(101)));
    }

    function test_bundle_withManifest() public view {
        Queue memory q = defaultQueue();
        bytes memory man = manifest(abi.encodePacked(SCRIPT), 5);
        q.manifestCommitment = keccak256(man);
        World memory w = _bundle(q);
        w.withManifest = true;
        w.manifest = man;
        (,,,, ClprTypes.ClprEndpointManifest memory em) = cv.verifyBundle(_encode(w), _anchor(netA), ctx());
        assertEq(em.version, 5);
    }

    function test_bundle_definiteDatumAndInvalidTxsElsewhere() public view {
        // a block whose invalid_transactions lists ANOTHER index: the full body array is opened
        World memory w = _bundle(defaultQueue());
        bytes memory other = hex"a0";
        w.bodies = bytes.concat(hex"82", other, w.txBody);
        w.txIndex = 1;
        w.invalidTxs = hex"8100";
        cv.verifyBundle(_encode(w), _anchor(netA), ctx());
    }

    function test_config_happyPath() public view {
        (bytes memory c, string memory chainId, bytes memory svc,,, bytes memory anchor, bytes memory id,) =
            cv.verifyConfig(_config(netA, "cip34:0-1"), CHANNEL_ID, "");
        assertEq(chainId, "cip34:0-1");
        assertEq(svc, abi.encodePacked(SCRIPT));
        assertEq(c, ctx());
        assertEq(anchor, _anchor(netA));
        assertEq(id, abi.encodePacked(uint64(100)));
    }

    // ── negative: signatures / threshold / key set ─────────────────────────

    function test_rejects_badSignature() public {
        World memory w = _bundle(defaultQueue());
        bytes memory p = _encode(w);
        // a certificate signed by a different network (keys not in the anchor's registration tree)
        World memory forged = _world(_network(100, 99, 4, 10), netB, defaultQueue());
        bytes memory proof_ = _encode(forged);
        bytes memory anchor_ = _anchor(netA);
        vm.expectRevert();
        this.callBundle(proof_, anchor_);
        p; // valid proof stays valid
    }

    function test_rejects_encodingNotNamingThePoint() public {
        // the compressed key bytes (hashed into the registration leaf) must name the uncompressed key
        bytes memory proof_ = _encode(_bundle(defaultQueue()));
        bytes memory enc = encG2(netA.vks[0]);
        uint256 at = _find(proof_, enc);
        proof_[at + 20] ^= 0x01;
        bytes memory anchor_ = _anchor(netA);
        vm.expectRevert(abi.encodeWithSelector(ClprMithrilStm.EncodingMismatch.selector, 0));
        this.callBundle(proof_, anchor_);
    }

    function test_rejects_sameSignatureOtherFlagEncoding() public {
        // the signature's compressed bytes (hashed by the lottery) with the third flag bit flipped: same
        // point, other encoding — must not be accepted as a second lottery presentation
        bytes memory proof_ = _encode(_bundle(defaultQueue()));
        uint256 at = _find(proof_, encG2(netA.vks[0])) - 48; // σ compressed precedes vk compressed
        proof_[at] ^= 0x20;
        bytes memory anchor_ = _anchor(netA);
        vm.expectRevert(abi.encodeWithSelector(ClprMithrilStm.EncodingMismatch.selector, 0));
        this.callBundle(proof_, anchor_);
    }

    function _find(bytes memory hay, bytes memory needle) internal pure returns (uint256) {
        for (uint256 i = 0; i + needle.length <= hay.length; i++) {
            bool ok = true;
            for (uint256 j = 0; j < needle.length && ok; j++) {
                ok = hay[i + j] == needle[j];
            }
            if (ok) return i;
        }
        revert("not found");
    }

    function test_rejects_forgedSigmaInsideValidTree() public {
        // replace party 0's signature with a signature by a key outside the tree → pairing fails
        Network memory n = netA;
        uint256 sk0 = n.sks[0];
        n.sks[0] = sk0 + 1; // keeps vk (tree) of the real key
        World memory w = _world(n, netB, defaultQueue());
        bytes memory proof_ = _encode(w);
        bytes memory anchor_ = _anchor(netA);
        vm.expectRevert(ClprMithrilStm.AggregateSignatureInvalid.selector);
        this.callBundle(proof_, anchor_);
    }

    function test_rejects_belowThreshold() public {
        Network memory n = netA;
        n.k = 40; // more indexes than the signers can win
        World memory w = _world(n, netB, defaultQueue());
        bytes memory proof_ = _encode(w);
        bytes memory anchor_ = _anchor(n);
        vm.expectRevert();
        this.callBundle(proof_, anchor_);
    }

    function test_rejects_wrongAggregateKey() public {
        World memory w = _bundle(defaultQueue());
        bytes memory proof_ = _encode(w);
        bytes memory anchor_ = _anchor(netB.epoch == 0 ? netB : _withEpoch(netB, 100));
        vm.expectRevert(ClprMithrilStm.BatchPathInvalid.selector);
        this.callBundle(proof_, anchor_);
    }

    function test_rejects_staleEpoch() public {
        // a certificate of epoch 100 against an anchor already rotated to 101
        World memory w = _bundle(defaultQueue());
        bytes memory proof_ = _encode(w);
        bytes memory anchor_ = _anchor(netB);
        vm.expectRevert();
        this.callBundle(proof_, anchor_);
    }

    function test_rejects_rotationWithoutNextKey() public {
        World memory w = _world(netB, netB, defaultQueue());
        // a "rotation" certificate whose message lacks next_aggregate_verification_key
        (uint256[] memory ids, bytes[] memory vals) = _parts(100, keccak256("r"), netB);
        uint256[] memory ids2 = new uint256[](4);
        bytes[] memory vals2 = new bytes[](4);
        (ids2[0], vals2[0]) = (ids[0], vals[0]);
        (ids2[1], vals2[1]) = (ids[2], vals[2]);
        (ids2[2], vals2[2]) = (ids[3], vals[3]);
        (ids2[3], vals2[3]) = (ids[4], vals[4]);
        bool[] memory all = new bool[](4);
        for (uint256 i = 0; i < 4; i++) {
            all[i] = true;
        }
        w.rotations = _one(_cert(netA, all, ids2, vals2));
        bytes memory proof_ = _encode(w);
        bytes memory anchor_ = _anchor(netA);
        vm.expectRevert(abi.encodeWithSelector(CardanoMithrilVerifier.MissingMessagePart.selector, uint8(3)));
        this.callBundle(proof_, anchor_);
    }

    function test_rejects_phiChangeOnRotation() public {
        World memory w = _world(netB, netB, defaultQueue());
        (uint256[] memory ids, bytes[] memory vals) = _parts(100, keccak256("r"), netB);
        vals[2] = abi.encodePacked(netB.k, netB.m, uint32(PHI + 1));
        bool[] memory all = new bool[](4);
        for (uint256 i = 0; i < 4; i++) {
            all[i] = true;
        }
        w.rotations = _one(_cert(netA, all, ids, vals));
        bytes memory proof_ = _encode(w);
        bytes memory anchor_ = _anchor(netA);
        vm.expectRevert(CardanoMithrilVerifier.PhiFChanged.selector);
        this.callBundle(proof_, anchor_);
    }

    // ── negative: state proof ─────────────────────────────────────────────

    function test_rejects_tamperedCertifiedRoot() public {
        World memory w = _bundle(defaultQueue());
        w.values[0] = abi.encodePacked(keccak256("not the root")); // signed, but not the tree's root
        bytes memory proof_ = _encode(w);
        bytes memory anchor_ = _anchor(netA);
        vm.expectRevert(CardanoMithrilVerifier.InclusionProofInvalid.selector);
        this.callBundle(proof_, anchor_);
    }

    function test_rejects_tamperedDatumAfterSigning() public {
        World memory w = _bundle(defaultQueue());
        bytes memory p = _encode(w);
        // swap the transaction body for one with a different datum, keeping the rest of the proof
        Queue memory q = defaultQueue();
        q.nextMessageId = 4;
        bytes memory forgedBody = _txBody(_output(SCRIPT, CHANNEL_ID, _datum(q)));
        bytes memory forged = _replace(p, w.txBody, forgedBody);
        bytes memory proof_ = forged;
        bytes memory anchor_ = _anchor(netA);
        vm.expectRevert(CardanoMithrilVerifier.InclusionProofInvalid.selector);
        this.callBundle(proof_, anchor_);
    }

    function test_rejects_invalidTransaction() public {
        World memory w = _bundle(defaultQueue());
        w.bodies = bytes.concat(hex"81", w.txBody);
        w.txIndex = 0;
        w.invalidTxs = hex"8100"; // our transaction failed phase 2
        bytes memory proof_ = _encode(w);
        bytes memory anchor_ = _anchor(netA);
        vm.expectRevert(abi.encodeWithSelector(ClprCardanoLedger.TransactionInvalid.selector, 0));
        this.callBundle(proof_, anchor_);
    }

    function test_rejects_hashOnlyBodyWithInvalidTxs() public {
        World memory w = _bundle(defaultQueue());
        w.invalidTxs = hex"8100";
        bytes memory proof_ = _encode(w);
        bytes memory anchor_ = _anchor(netA);
        vm.expectRevert();
        this.callBundle(proof_, anchor_);
    }

    function test_rejects_wrongScript() public {
        World memory w = _bundle(defaultQueue());
        w.txBody = _txBody(_output(bytes28(keccak256("other script")), CHANNEL_ID, _datum(defaultQueue())));
        bytes memory proof_ = _encode(w);
        bytes memory anchor_ = _anchor(netA);
        vm.expectRevert(ClprCardanoLedger.ScriptCredentialMismatch.selector);
        this.callBundle(proof_, anchor_);
    }

    function test_rejects_wrongChannelToken() public {
        World memory w = _bundle(defaultQueue());
        w.txBody = _txBody(_output(SCRIPT, keccak256("other channel"), _datum(defaultQueue())));
        bytes memory proof_ = _encode(w);
        bytes memory anchor_ = _anchor(netA);
        vm.expectRevert(ClprCardanoLedger.ThreadTokenMissing.selector);
        this.callBundle(proof_, anchor_);
    }

    function test_rejects_wrongOutputIndex() public {
        World memory w = _bundle(defaultQueue());
        w.outputIndex = 0; // the change output
        bytes memory proof_ = _encode(w);
        bytes memory anchor_ = _anchor(netA);
        vm.expectRevert();
        this.callBundle(proof_, anchor_);
    }

    function test_rejects_blockRangeMismatch() public {
        World memory w = _bundle(defaultQueue());
        w.rangeStart = 2000;
        bytes memory proof_ = _encode(w);
        bytes memory anchor_ = _anchor(netA);
        vm.expectRevert(CardanoMithrilVerifier.BlockRangeMismatch.selector);
        this.callBundle(proof_, anchor_);
    }

    function test_rejects_forgedSiblingLeaf() public {
        World memory w = _bundle(defaultQueue());
        w.sibLeaf = "not-a-leaf";
        bytes memory proof_ = _encode(w);
        bytes memory anchor_ = _anchor(netA);
        vm.expectRevert(CardanoMithrilVerifier.InclusionProofInvalid.selector);
        this.callBundle(proof_, anchor_);
    }

    // ── lottery / message ─────────────────────────────────────────────────

    function test_lotteryThreshold_matchesReference() public pure {
        // 1 − 0.35^(1/4) = 0.230823…  (|ln 0.35| / 4 = 0.262449…)
        ClprMithrilStm.Params memory p = ClprMithrilStm.Params(1, 1, PHI, LN_MANT, LN_EXP);
        uint256 t = ClprMithrilStm.lotteryThreshold(1, 4, p);
        uint256 want = 0.230839432686541e18; // 1 - exp(-|ln 0.35|/4), |ln 0.35| = the f64 constant
        assertApproxEqAbs((t * 1e18) >> 120, want, 1e4);
        p.phiFixed = 1 << 24;
        assertEq(ClprMithrilStm.lotteryThreshold(1, 4, p), type(uint256).max);
    }

    function test_rejects_duplicateLotteryIndex() public {
        World memory w = _bundle(defaultQueue());
        bytes memory proof = _encode(w);
        // duplicate the first signer entry → same lottery indexes twice (and same leaf)
        bytes memory proof_ = _dupFirstSigner(w);
        bytes memory anchor_ = _anchor(netA);
        vm.expectRevert();
        this.callBundle(proof_, anchor_);
        proof;
    }

    // ── helpers ───────────────────────────────────────────────────────────

    function callBundle(bytes calldata p, bytes calldata a) external view {
        cv.verifyBundle(p, a, ctx());
    }

    function _withEpoch(Network memory n, uint64 e) internal pure returns (Network memory) {
        n.epoch = e;
        return n;
    }

    function _dupFirstSigner(World memory w) internal view returns (bytes memory) {
        bool[] memory s = new bool[](w.signs.length);
        s[0] = true;
        s[2] = true;
        w.signs = s;
        // re-sign with leaf indexes 0 and 0 by aliasing party 2 to party 0
        w.net.sks[2] = w.net.sks[0];
        w.net.vks[2] = w.net.vks[0];
        w.net.stakes[2] = w.net.stakes[0];
        return _encode(w);
    }

    function _replace(bytes memory hay, bytes memory needle, bytes memory with) internal pure returns (bytes memory) {
        require(needle.length == with.length, "same length only");
        for (uint256 i = 0; i + needle.length <= hay.length; i++) {
            bool eq = true;
            for (uint256 j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) {
                    eq = false;
                    break;
                }
            }
            if (eq) {
                for (uint256 j = 0; j < with.length; j++) {
                    hay[i + j] = with[j];
                }
                return hay;
            }
        }
        revert("needle not found");
    }
}
