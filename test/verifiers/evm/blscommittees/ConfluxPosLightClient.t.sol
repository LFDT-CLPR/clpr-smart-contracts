// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ConfluxPosLightClient as LC} from "@hiero-ledger/clpr/verifiers/evm/blscommittees/ConfluxPosLightClient.sol";
import {ClprBlsCommittee as Bls} from "@hiero-ledger/clpr/libraries/proof/blscommittee/ClprBlsCommittee.sol";
import {ClprConfluxPos as Pos} from "@hiero-ledger/clpr/libraries/proof/conflux/ClprConfluxPos.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @dev ConfluxPosLightClient against REAL Conflux mainnet data
///      (test/e2e/fixtures/conflux-live/vectors.json, refresh: `npm run conflux-live:refresh`):
///      the epoch E-1 committee, the real E-1 → E rotation ledger info and an epoch-E ledger info
///      whose pivot block header carries the deferred state root. Negative cases mutate those inputs.
contract ConfluxPosLightClientTest is Test {
    LC internal lc;
    string internal json;

    uint64 internal bootEpoch;
    uint64 internal nextEpoch;
    bytes32 internal bootHash;
    bytes32 internal nextHash;
    bytes internal bootKeys;
    bytes internal nextKeys;
    uint256[] internal bootWeights;
    uint256[] internal nextWeights;
    uint256 internal bootQuorum;
    uint256 internal nextQuorum;

    bytes internal rotLi;
    bytes internal rotBm;
    bytes internal rotSig;
    bytes internal li;
    bytes internal bm;
    bytes internal sig;
    bytes internal header;

    function setUp() public {
        json = vm.readFile(string.concat(vm.projectRoot(), "/test/e2e/fixtures/conflux-live/vectors.json"));
        bootEpoch = uint64(vm.parseUint(vm.parseJsonString(json, ".bootstrap.epoch")));
        nextEpoch = uint64(vm.parseUint(vm.parseJsonString(json, ".next.epoch")));
        bootHash = vm.parseJsonBytes32(json, ".bootstrap.hash");
        nextHash = vm.parseJsonBytes32(json, ".next.hash");
        bootKeys = vm.parseJsonBytes(json, ".bootstrap.keys");
        nextKeys = vm.parseJsonBytes(json, ".next.keys");
        bootWeights = _uints(".bootstrap.weights");
        nextWeights = _uints(".next.weights");
        bootQuorum = vm.parseUint(vm.parseJsonString(json, ".bootstrap.quorum"));
        nextQuorum = vm.parseUint(vm.parseJsonString(json, ".next.quorum"));
        rotLi = vm.parseJsonBytes(json, ".rotation.ledgerInfo");
        rotBm = vm.parseJsonBytes(json, ".rotation.bitmap");
        rotSig = vm.parseJsonBytes(json, ".rotation.signature");
        li = vm.parseJsonBytes(json, ".bundle.ledgerInfo");
        bm = vm.parseJsonBytes(json, ".bundle.bitmap");
        sig = vm.parseJsonBytes(json, ".bundle.signature");
        header = vm.parseJsonBytes(json, ".bundle.header");
        lc = new LC(bootHash, bootEpoch);
    }

    function _uints(string memory key) internal view returns (uint256[] memory out) {
        string[] memory s = vm.parseJsonStringArray(json, key);
        out = new uint256[](s.length);
        for (uint256 i = 0; i < s.length; i++) {
            out[i] = vm.parseUint(s[i]);
        }
    }

    // ── encoders ──────────────────────────────────────────────────────────────────────────

    function _committee(bytes memory keys, uint256[] memory w, uint256 quorum) internal pure returns (bytes memory) {
        bytes[] memory ws = new bytes[](w.length);
        for (uint256 i = 0; i < w.length; i++) {
            ws[i] = RLP.encode(w[i]);
        }
        bytes[] memory c = new bytes[](3);
        c[0] = RLP.encode(keys);
        c[1] = RLP.encode(ws);
        c[2] = RLP.encode(quorum);
        return RLP.encode(c);
    }

    function _bootCommittee() internal view returns (bytes memory) {
        return _committee(bootKeys, bootWeights, bootQuorum);
    }

    function _nextCommittee() internal view returns (bytes memory) {
        return _committee(nextKeys, nextWeights, nextQuorum);
    }

    function _transition(bytes memory l, bytes memory b, bytes memory s, bytes memory keys)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory t = new bytes[](4);
        t[0] = RLP.encode(l);
        t[1] = RLP.encode(b);
        t[2] = RLP.encode(s);
        t[3] = RLP.encode(keys);
        return RLP.encode(t);
    }

    function _list1(bytes memory item) internal pure returns (bytes memory) {
        bytes[] memory l = new bytes[](1);
        l[0] = item;
        return RLP.encode(l);
    }

    function _proof(
        bytes memory committee,
        bytes memory transitions,
        bytes memory l,
        bytes memory b,
        bytes memory s,
        bytes memory h
    ) internal pure returns (bytes memory) {
        bytes[] memory p = new bytes[](6);
        p[0] = committee;
        p[1] = transitions;
        p[2] = RLP.encode(l);
        p[3] = RLP.encode(b);
        p[4] = RLP.encode(s);
        p[5] = RLP.encode(h);
        return RLP.encode(p);
    }

    function _rotation() internal view returns (bytes memory) {
        return _list1(_transition(rotLi, rotBm, rotSig, nextKeys));
    }

    function _bootAnchor() internal view returns (bytes memory) {
        return abi.encode(bootHash, bootEpoch, uint64(0));
    }

    function _nextAnchor(uint64 pivot) internal view returns (bytes memory) {
        return abi.encode(nextHash, nextEpoch, pivot);
    }

    function _bundleNext() internal view returns (bytes memory) {
        return _proof(_nextCommittee(), hex"c0", li, bm, sig, header);
    }

    // ── live data, positive ───────────────────────────────────────────────────────────────

    function test_live_fixtureCommitteeHashes() public view {
        assertEq(lc.committeeHash(bootEpoch, LC.Committee(bootKeys, bootWeights, uint64(bootQuorum))), bootHash);
        assertEq(lc.committeeHash(nextEpoch, LC.Committee(nextKeys, nextWeights, uint64(nextQuorum))), nextHash);
        assertEq(lc.bootstrapAnchor(), _bootAnchor());
    }

    function test_live_bundleWithRotation() public {
        bytes memory proof = _proof(_bootCommittee(), _rotation(), li, bm, sig, header);
        assertEq(proof, vm.parseJsonBytes(json, ".proofs.bundleWithRotation"));
        uint256 g = gasleft();
        (LC.Result memory r, bytes memory na) = lc.verifyPivotStateRoot(proof, _bootAnchor());
        emit log_named_uint("bundle + rotation gas (execution)", g - gasleft());
        emit log_named_uint("bundle + rotation proof bytes", proof.length);
        assertEq(r.deferredStateRoot, vm.parseJsonBytes32(json, ".bundle.deferredStateRoot"));
        assertEq(r.deferredStateRoot, vm.parseJsonBytes32(json, ".bundle.espaceStateRoot"));
        assertEq(r.pivotBlockHash, vm.parseJsonBytes32(json, ".bundle.pivotHash"));
        assertEq(r.pivotHeight, vm.parseUint(vm.parseJsonString(json, ".bundle.pivotHeight")));
        assertEq(r.epoch, nextEpoch);
        assertEq(na, _nextAnchor(r.pivotHeight));
    }

    function test_live_bundle() public {
        bytes memory proof = _bundleNext();
        assertEq(proof, vm.parseJsonBytes(json, ".proofs.bundle"));
        uint256 g = gasleft();
        (LC.Result memory r,) = lc.verifyPivotStateRoot(proof, _nextAnchor(0));
        emit log_named_uint("bundle gas (execution)", g - gasleft());
        emit log_named_uint("bundle proof bytes", proof.length);
        assertEq(r.deferredStateRoot, vm.parseJsonBytes32(json, ".bundle.deferredStateRoot"));
    }

    function test_live_catchUp() public {
        bytes[] memory p = new bytes[](2);
        p[0] = _bootCommittee();
        p[1] = _rotation();
        bytes memory proof = RLP.encode(p);
        assertEq(proof, vm.parseJsonBytes(json, ".proofs.catchUp"));
        uint256 g = gasleft();
        bytes memory na = lc.verifyEpochChanges(proof, _bootAnchor());
        emit log_named_uint("rotation gas (execution)", g - gasleft());
        emit log_named_uint("rotation proof bytes", proof.length);
        assertEq(na, _nextAnchor(0));
    }

    // ── negatives ─────────────────────────────────────────────────────────────────────────

    function test_rejects_tamperedSignature() public {
        bytes memory s = bytes.concat(sig);
        s[100] = bytes1(uint8(s[100]) ^ 1);
        vm.expectRevert(); // off-curve (precompile) or invalid signature
        lc.verifyPivotStateRoot(_proof(_nextCommittee(), hex"c0", li, bm, s, header), _nextAnchor(0));
    }

    function test_rejects_signatureOverOtherLedgerInfo() public {
        vm.expectRevert(Bls.BlsSignatureInvalid.selector);
        lc.verifyPivotStateRoot(_proof(_nextCommittee(), hex"c0", li, bm, rotSig, header), _nextAnchor(0));
    }

    function test_rejects_belowQuorum() public {
        bytes memory one = new bytes(bm.length);
        one[0] = 0x01;
        vm.expectRevert(abi.encodeWithSelector(LC.BelowQuorum.selector, nextWeights[0], uint64(nextQuorum)));
        lc.verifyPivotStateRoot(_proof(_nextCommittee(), hex"c0", li, one, sig, header), _nextAnchor(0));
    }

    function test_rejects_signerBitmapNotMatchingSignature() public {
        // Drop one real signer: power stays above quorum but the aggregate no longer matches.
        bytes memory b = bytes.concat(bm);
        uint256 i = 0;
        while ((uint8(b[i / 8]) >> (i % 8)) & 1 == 0) i++;
        b[i / 8] = bytes1(uint8(b[i / 8]) ^ uint8(1 << (i % 8)));
        vm.expectRevert(Bls.BlsSignatureInvalid.selector);
        lc.verifyPivotStateRoot(_proof(_nextCommittee(), hex"c0", li, b, sig, header), _nextAnchor(0));
    }

    function test_rejects_wrongCommittee() public {
        // The anchor commits to epoch E; the relayer passes the E-1 committee.
        vm.expectRevert(LC.CommitteeMismatch.selector);
        lc.verifyPivotStateRoot(_proof(_bootCommittee(), hex"c0", li, bm, sig, header), _nextAnchor(0));
    }

    function test_rejects_inflatedWeights() public {
        uint256[] memory w = new uint256[](nextWeights.length);
        for (uint256 i = 0; i < w.length; i++) {
            w[i] = nextWeights[i] * 100;
        }
        vm.expectRevert(LC.CommitteeMismatch.selector);
        lc.verifyPivotStateRoot(
            _proof(_committee(nextKeys, w, nextQuorum), hex"c0", li, bm, sig, header), _nextAnchor(0)
        );
    }

    function test_rejects_ledgerInfoFromOtherEpoch() public {
        // Epoch E ledger info presented under the E-1 committee, with no rotation.
        vm.expectRevert(abi.encodeWithSelector(LC.EpochMismatch.selector, nextEpoch, bootEpoch));
        lc.verifyPivotStateRoot(_proof(_bootCommittee(), hex"c0", li, bm, sig, header), _bootAnchor());
    }

    function test_rejects_replayedRotation() public {
        bytes[] memory p = new bytes[](2);
        p[0] = _nextCommittee();
        p[1] = _rotation();
        vm.expectRevert(abi.encodeWithSelector(LC.EpochMismatch.selector, bootEpoch, nextEpoch));
        lc.verifyEpochChanges(RLP.encode(p), _nextAnchor(0));
    }

    function test_rejects_rotationKeyNotCertified() public {
        bytes memory k = bytes.concat(nextKeys);
        // Swap keys 0 and 1: both valid G1 points, neither matches its certified slot.
        for (uint256 i = 0; i < 128; i++) {
            (k[i], k[128 + i]) = (k[128 + i], k[i]);
        }
        vm.expectRevert(abi.encodeWithSelector(LC.NextKeyMismatch.selector, 0));
        lc.verifyPivotStateRoot(
            _proof(_bootCommittee(), _list1(_transition(rotLi, rotBm, rotSig, k)), li, bm, sig, header), _bootAnchor()
        );
    }

    function test_rejects_transitionWithoutEpochChange() public {
        // A normal (non-boundary) epoch-E ledger info cannot rotate the committee.
        bytes[] memory p = new bytes[](2);
        p[0] = _nextCommittee();
        p[1] = _list1(_transition(li, bm, sig, nextKeys));
        vm.expectRevert(LC.NotEpochChange.selector);
        lc.verifyEpochChanges(RLP.encode(p), _nextAnchor(0));
    }

    function test_rejects_replayedPivot() public {
        uint64 h = uint64(vm.parseUint(vm.parseJsonString(json, ".bundle.pivotHeight")));
        vm.expectRevert(abi.encodeWithSelector(LC.PivotNotNewer.selector, h, h));
        lc.verifyPivotStateRoot(_bundleNext(), _nextAnchor(h));
    }

    function test_rejects_headerNotMatchingPivot() public {
        bytes memory h = bytes.concat(header);
        h[h.length - 1] = bytes1(uint8(h[h.length - 1]) ^ 1);
        vm.expectRevert(LC.PivotHeaderMismatch.selector);
        lc.verifyPivotStateRoot(_proof(_nextCommittee(), hex"c0", li, bm, sig, h), _nextAnchor(0));
    }

    function test_rejects_ledgerInfoTrailingBytes() public {
        vm.expectRevert(Pos.BcsTrailingBytes.selector);
        lc.verifyPivotStateRoot(
            _proof(_nextCommittee(), hex"c0", bytes.concat(li, hex"00"), bm, sig, header), _nextAnchor(0)
        );
    }

    function test_rejects_badAnchorLength() public {
        vm.expectRevert(LC.InvalidTrustAnchor.selector);
        lc.verifyPivotStateRoot(_bundleNext(), abi.encode(nextHash, nextEpoch));
    }
}
