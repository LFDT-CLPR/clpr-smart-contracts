// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {console} from "forge-std/console.sol";
import {AlpenglowCert} from "@hiero-ledger/clpr/verifiers/solana/AlpenglowCert.sol";
import {AlpenglowFinalityVerifier} from "@hiero-ledger/clpr/verifiers/solana/AlpenglowFinalityVerifier.sol";
import {ClprBeaconBls} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconBls.sol";
import {SolanaTestKit} from "./SolanaTestKit.sol";

/// @notice AlpenglowFinalityVerifier on the REAL devnet Alpenglow genesis certificate
///         (test/e2e/fixtures/solana-live, `npm run solana-live:refresh`) and on synthetic sets.
contract AlpenglowCertTest is SolanaTestKit {
    AlpenglowFinalityVerifier internal v;

    function setUp() public {
        v = new AlpenglowFinalityVerifier();
    }

    function _live() internal view returns (AlpenglowCert.FinalityProof memory p, AlpenglowCert.EpochSet memory s) {
        string memory h = vm.readFile("test/e2e/fixtures/solana-live/devnet-genesis.proof.hex");
        bytes memory raw = vm.parseBytes(vm.replace(h, "\n", ""));
        (p, s) = abi.decode(raw, (AlpenglowCert.FinalityProof, AlpenglowCert.EpochSet));
    }

    // ── Payload encoding (votor-messages wire.rs) ───────────────────────────

    function test_payload_layout() public view {
        bytes memory notar = v.payload(1, 0x0102030405060708, bytes32(uint256(0xaa)), true, 0x1b68);
        assertEq(notar.length, 43);
        assertEq(uint8(notar[0]), 1);
        assertEq(uint8(notar[1]), 0x08); // slot little-endian
        assertEq(uint8(notar[8]), 0x01);
        assertEq(uint8(notar[40]), 0xaa);
        assertEq(uint8(notar[41]), 0x68); // shred version little-endian
        assertEq(uint8(notar[42]), 0x1b);
        assertEq(v.payload(2, 7, bytes32(0), false, 1).length, 11);
    }

    // ── Live devnet genesis certificate ─────────────────────────────────────

    function test_live_devnet_genesis_cert_verifies() public view {
        (AlpenglowCert.FinalityProof memory p, AlpenglowCert.EpochSet memory s) = _live();
        assertEq(p.slot, 504_148_999);
        assertEq(p.kind, 3);
        uint256 g = gasleft();
        uint256 signed = v.verifyFinality(p, s);
        g -= gasleft();
        assertGe(signed * 100, 82 * uint256(s.totalStake));
        console.log(
            "devnet genesis cert: set %d, non-signer entries %d, gas %d", s.size, p.aggregates[0].entries.length, g
        );
    }

    function test_live_rejects_wrong_shred_version() public {
        (AlpenglowCert.FinalityProof memory p, AlpenglowCert.EpochSet memory s) = _live();
        s.shredVersion ^= 1;
        vm.expectRevert(ClprBeaconBls.BlsSignatureInvalid.selector);
        v.verifyFinality(p, s);
    }

    function test_live_rejects_wrong_block_id() public {
        (AlpenglowCert.FinalityProof memory p, AlpenglowCert.EpochSet memory s) = _live();
        p.blockId = bytes32(uint256(p.blockId) ^ 1);
        vm.expectRevert(ClprBeaconBls.BlsSignatureInvalid.selector);
        v.verifyFinality(p, s);
    }

    function test_live_rejects_genesis_cert_presented_as_fast_finalize() public {
        (AlpenglowCert.FinalityProof memory p, AlpenglowCert.EpochSet memory s) = _live();
        p.kind = 1; // Notar payload (tag 1) instead of Genesis (tag 6)
        vm.expectRevert(ClprBeaconBls.BlsSignatureInvalid.selector);
        v.verifyFinality(p, s);
    }

    function test_live_rejects_flipped_bitmap_bit() public {
        (AlpenglowCert.FinalityProof memory p, AlpenglowCert.EpochSet memory s) = _live();
        // rank 0 signed; clearing it makes the entry count disagree with the bitmap
        p.aggregates[0].bitmap[3] = bytes1(uint8(p.aggregates[0].bitmap[3]) & 0xfe);
        vm.expectRevert();
        v.verifyFinality(p, s);
    }

    function test_live_rejects_tampered_set_entry() public {
        (AlpenglowCert.FinalityProof memory p, AlpenglowCert.EpochSet memory s) = _live();
        p.aggregates[0].entries[0].stake -= 1;
        uint256 rank = p.aggregates[0].entries[0].rank;
        vm.expectRevert(abi.encodeWithSelector(AlpenglowCert.EntryProofInvalid.selector, rank));
        v.verifyFinality(p, s);
    }

    function test_live_rejects_dropped_nonsigner() public {
        (AlpenglowCert.FinalityProof memory p, AlpenglowCert.EpochSet memory s) = _live();
        AlpenglowCert.SetEntry[] memory e = p.aggregates[0].entries;
        AlpenglowCert.SetEntry[] memory shorter = new AlpenglowCert.SetEntry[](e.length - 1);
        for (uint256 i = 1; i < e.length; i++) {
            shorter[i - 1] = e[i];
        }
        p.aggregates[0].entries = shorter;
        vm.expectRevert(abi.encodeWithSelector(AlpenglowCert.EntryCountMismatch.selector, e.length - 1, e.length));
        v.verifyFinality(p, s);
    }

    function test_live_rejects_wrong_validator_set() public {
        (AlpenglowCert.FinalityProof memory p, AlpenglowCert.EpochSet memory s) = _live();
        s.root = bytes32(uint256(s.root) ^ 1);
        vm.expectRevert();
        v.verifyFinality(p, s);
    }

    function test_live_rejects_slot_outside_epoch() public {
        (AlpenglowCert.FinalityProof memory p, AlpenglowCert.EpochSet memory s) = _live();
        s.firstSlot = p.slot + 1;
        s.lastSlot = p.slot + 432_000;
        vm.expectRevert(
            abi.encodeWithSelector(AlpenglowCert.SlotOutsideEpoch.selector, p.slot, s.firstSlot, s.lastSlot)
        );
        v.verifyFinality(p, s);
    }

    // ── Synthetic mainnet-scale sets ─────────────────────────────────────────

    /// @dev `offlineEvery` > 0: every k-th validator (from rank 3 on) is offline, all others sign —
    ///      the shape of a real certificate (devnet genesis: 8 of 19 absent). 0: only the top ranks
    ///      sign, just enough for 80% — the worst case for proof size.
    function _fast(uint256 n, uint256 offlineEvery)
        internal
        returns (uint256 gasUsed, uint256 entries, uint256 bytesLen)
    {
        vm.pauseGasMetering();
        SynthSet memory s = _synthSet(n, 1100, 50_093);
        bool[] memory signed;
        if (offlineEvery == 0) {
            signed = _signersForPct(s, 80, 0);
        } else {
            signed = new bool[](n);
            for (uint256 i = 0; i < n; i++) {
                signed[i] = i < 3 || i % offlineEvery != 0;
            }
        }
        uint256 cnt;
        for (uint256 i = 0; i < n; i++) {
            if (signed[i]) cnt++;
        }
        bool complement = n - cnt < cnt;
        bytes32 blockId = keccak256("block");
        uint64 slot = 1100 * 432_000 + 77;
        AlpenglowCert.FinalityProof memory p;
        p.kind = 1;
        p.slot = slot;
        p.blockId = blockId;
        p.aggregates = new AlpenglowCert.Aggregate[](1);
        p.aggregates[0] = _aggregate(s, signed, v.payload(1, slot, blockId, true, 50_093), complement);
        bytesLen = abi.encode(p, s.set).length;
        entries = p.aggregates[0].entries.length;
        vm.resumeGasMetering();
        uint256 g = gasleft();
        v.verifyFinality(p, s.set);
        gasUsed = g - gasleft();
    }

    function test_synthetic_fast_finalize_700_validators_8pct_offline_gas() public {
        (uint256 g, uint256 e, uint256 b) = _fast(700, 12);
        console.log("fast-finalize 700 vals, ~8%% offline: entries %d gas %d abi bytes %d", e, g, b);
        assertLt(g, 15_000_000);
        assertLt(b, 128 * 1024);
    }

    function test_synthetic_fast_finalize_2000_validators_8pct_offline_gas() public {
        (uint256 g, uint256 e, uint256 b) = _fast(2000, 12);
        console.log("fast-finalize 2000 vals, ~8%% offline: entries %d gas %d abi bytes %d", e, g, b);
    }

    function test_synthetic_fast_finalize_700_validators_worst_case_gas() public {
        (uint256 g, uint256 e, uint256 b) = _fast(700, 0);
        console.log("fast-finalize 700 vals, top-80%% only: entries %d gas %d abi bytes %d", e, g, b);
    }

    function test_synthetic_slow_finalize_signers_mode() public {
        vm.pauseGasMetering();
        SynthSet memory s = _synthSet(64, 1100, 7);
        bool[] memory signed = _signersForPct(s, 60, 0);
        bytes32 blockId = keccak256("b");
        uint64 slot = 1100 * 432_000 + 5;
        AlpenglowCert.FinalityProof memory p;
        p.kind = 2;
        p.slot = slot;
        p.blockId = blockId;
        p.aggregates = new AlpenglowCert.Aggregate[](2);
        p.aggregates[0] = _aggregate(s, signed, v.payload(1, slot, blockId, true, 7), false);
        p.aggregates[1] = _aggregate(s, signed, v.payload(2, slot, bytes32(0), false, 7), true);
        vm.resumeGasMetering();
        uint256 signedStake = v.verifyFinality(p, s.set);
        assertGe(signedStake * 100, 60 * uint256(s.set.totalStake));
    }

    function test_synthetic_rejects_below_threshold() public {
        SynthSet memory s = _synthSet(32, 1100, 7);
        bool[] memory signed = _signersForPct(s, 79, 0); // < 80% for fast finalize
        // drop the last signer so it is strictly below 80%
        uint256 last;
        for (uint256 i = 0; i < signed.length; i++) {
            if (signed[i]) last = i;
        }
        signed[last] = false;
        uint64 slot = 1100 * 432_000;
        AlpenglowCert.FinalityProof memory p;
        p.kind = 1;
        p.slot = slot;
        p.aggregates = new AlpenglowCert.Aggregate[](1);
        p.aggregates[0] = _aggregate(s, signed, v.payload(1, slot, bytes32(0), true, 7), false);
        vm.expectRevert();
        v.verifyFinality(p, s.set);
        // and a 60% Notar aggregate does not pass as a fast-finalize
        bool[] memory sixty = _signersForPct(s, 60, 0);
        p.aggregates[0] = _aggregate(s, sixty, v.payload(1, slot, bytes32(0), true, 7), false);
        vm.expectPartialRevert(AlpenglowCert.InsufficientStake.selector);
        v.verifyFinality(p, s.set);
    }

    function test_synthetic_rejects_signature_by_other_keys() public {
        SynthSet memory s = _synthSet(16, 1100, 7);
        SynthSet memory other = _synthSet(17, 1100, 7); // same keys; signs a different slot below
        bool[] memory signed = _signersForPct(s, 90, 0);
        uint64 slot = 1100 * 432_000;
        AlpenglowCert.FinalityProof memory p;
        p.kind = 1;
        p.slot = slot;
        p.aggregates = new AlpenglowCert.Aggregate[](1);
        p.aggregates[0] = _aggregate(s, signed, v.payload(1, slot, bytes32(0), true, 7), false);
        // signature over a different slot
        p.aggregates[0].signature =
        _aggregate(other, signed, v.payload(1, slot + 1, bytes32(0), true, 7), false).signature;
        vm.expectRevert(ClprBeaconBls.BlsSignatureInvalid.selector);
        v.verifyFinality(p, s.set);
    }

    function test_synthetic_rejects_base3_bitmap_and_unsorted_entries() public {
        SynthSet memory s = _synthSet(16, 1100, 7);
        bool[] memory signed = _signersForPct(s, 90, 0);
        uint64 slot = 1100 * 432_000;
        AlpenglowCert.FinalityProof memory p;
        p.kind = 1;
        p.slot = slot;
        p.aggregates = new AlpenglowCert.Aggregate[](1);
        p.aggregates[0] = _aggregate(s, signed, v.payload(1, slot, bytes32(0), true, 7), false);
        bytes memory bm = p.aggregates[0].bitmap;
        bm[0] = 0x01;
        vm.expectRevert(AlpenglowCert.BitmapUnsupportedEncoding.selector);
        v.verifyFinality(p, s.set);
        bm[0] = 0x00;
        AlpenglowCert.SetEntry memory t = p.aggregates[0].entries[0];
        p.aggregates[0].entries[0] = p.aggregates[0].entries[1];
        p.aggregates[0].entries[1] = t;
        vm.expectRevert(AlpenglowCert.EntriesNotSorted.selector);
        v.verifyFinality(p, s.set);
    }
}
