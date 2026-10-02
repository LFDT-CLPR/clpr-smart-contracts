// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {BitcoinLibHarness} from "./BitcoinTestBuilder.sol";
import {BitcoinVerifier} from "@hiero-ledger/clpr/verifiers/bitcoin/BitcoinVerifier.sol";
import {BitcoinCashVerifier} from "@hiero-ledger/clpr/verifiers/bitcoin/BitcoinCashVerifier.sol";
import {BitcoinLib} from "@hiero-ledger/clpr/verifiers/bitcoin/BitcoinLib.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";

/// @notice BitcoinCashVerifier (the Bitcoin Cash profile of BitcoinVerifier) against REAL Bitcoin Cash
///         mainnet headers and a real transaction, recorded by `npm run bitcoin-cash-live:refresh`
///         into test/e2e/fixtures/bitcoin-cash-live/. Also: the ASERT reference vectors from
///         Bitcoin Cash Node `src/test/pow_tests.cpp` (`calculate_asert_test`).
contract BitcoinCashMainnetTest is Test {
    // BCHN src/chainparams.cpp, mainnet.
    uint256 internal constant BCH_POW_LIMIT = (uint256(1) << 224) - 1;
    uint32 internal constant ANCHOR_HEIGHT = 661647;
    uint32 internal constant ANCHOR_BITS = 0x1804dafe;
    uint32 internal constant ANCHOR_PREV_TIME = 1605447844;
    uint32 internal constant HALF_LIFE = 2 days;
    string internal constant BCH_CHAIN_ID = "bip122:000000000000000000651ef99cb9fcbe";
    uint8 internal constant K = 6;

    string internal constant DIR = "test/e2e/fixtures/bitcoin-cash-live/";

    BitcoinLibHarness internal lib;
    bytes internal channelContext = abi.encodePacked(keccak256("bch channel"), hex"0014", bytes20(0));

    struct Fixture {
        uint32 startHeight;
        bytes headers;
        uint256 count;
    }

    function setUp() public {
        lib = new BitcoinLibHarness();
    }

    function _load(string memory name) internal view returns (Fixture memory f) {
        string memory json = vm.readFile(string.concat(DIR, name, ".json"));
        f.startHeight = uint32(vm.parseJsonUint(json, ".startHeight"));
        f.headers = vm.parseJsonBytes(json, ".headersConcat");
        f.count = f.headers.length / 80;
    }

    function _hdr(Fixture memory f, uint256 i) internal pure returns (bytes memory) {
        return BitcoinLib.slice(f.headers, i * 80, 80);
    }

    function _anchor() internal pure returns (BitcoinCashVerifier.AsertAnchor memory) {
        return
            BitcoinCashVerifier.AsertAnchor({height: ANCHOR_HEIGHT, bits: ANCHOR_BITS, prevBlockTime: ANCHOR_PREV_TIME});
    }

    function _checkpoint(Fixture memory f, uint256 i) internal view returns (BitcoinVerifier.Checkpoint memory) {
        bytes memory h = _hdr(f, i);
        return BitcoinVerifier.Checkpoint({
            blockHash: lib.hash256(h),
            height: uint32(f.startHeight + i),
            chainWork: 1e30, // arbitrary base; only deltas are checked
            bits: BitcoinLib.nBits(h),
            time: BitcoinLib.timestamp(h),
            periodStartTime: 0 // unused under ASERT
        });
    }

    function _trustAnchor(BitcoinVerifier.Checkpoint memory cp) internal pure returns (bytes memory) {
        return abi.encode(
            BitcoinVerifier.TrustAnchor({
                checkpoint: cp,
                cursorTxid: keccak256("cursor"),
                cursorVout: 1,
                lastMessageId: 0,
                runningHash: bytes32(0),
                confirmations: K
            })
        );
    }

    /// @dev Verifier with a checkpoint at fixture header `cpIndex`, plus the matching trust anchor.
    function _setup(Fixture memory f, uint256 cpIndex) internal returns (BitcoinCashVerifier v, bytes memory anchor) {
        BitcoinVerifier.Checkpoint memory cp = _checkpoint(f, cpIndex);
        v = new BitcoinCashVerifier(BCH_POW_LIMIT, K, 4096, BCH_CHAIN_ID, cp, _anchor(), HALF_LIFE);
        anchor = _trustAnchor(cp);
    }

    function _proof(uint32 startHeight, bytes memory headers) internal pure returns (bytes memory) {
        BitcoinVerifier.BundleProof memory p;
        p.startHeight = startHeight;
        p.headers = headers;
        return abi.encode(p);
    }

    /// @dev Headers [from, from + n) of the fixture.
    function _range(Fixture memory f, uint256 from, uint256 n) internal pure returns (bytes memory) {
        return BitcoinLib.slice(f.headers, from * 80, n * 80);
    }

    // ── Real headers: hash, PoW, linkage, chain parameters ───────────────────

    function test_realHeadersHashLinkAndMeetTarget() public view {
        string[2] memory names = ["asert-activation", "mainnet-recent"];
        for (uint256 n = 0; n < 2; ++n) {
            Fixture memory f = _load(names[n]);
            string memory json = vm.readFile(string.concat(DIR, names[n], ".json"));
            for (uint256 i = 0; i < f.count; ++i) {
                bytes memory h = _hdr(f, i);
                bytes32 hash = lib.hash256(h);
                assertEq(
                    hash,
                    vm.parseJsonBytes32(json, string.concat(".headers[", vm.toString(i), "].hashInternal")),
                    "hash256(header) = block hash"
                );
                assertLe(lib.reverse256(uint256(hash)), lib.bitsToTarget(BitcoinLib.nBits(h)), "PoW");
                if (i > 0) assertEq(BitcoinLib.prevHash(h), lib.hash256(_hdr(f, i - 1)), "linkage");
            }
        }
    }

    /// @dev The hard-coded BCHN anchor params match the real chain: block 661646's time and block
    ///      661647's nBits.
    function test_asertAnchorParamsMatchRealChain() public view {
        Fixture memory f = _load("asert-activation");
        assertEq(f.startHeight, ANCHOR_HEIGHT - 1);
        assertEq(BitcoinLib.timestamp(_hdr(f, 0)), ANCHOR_PREV_TIME, "anchor parent time");
        assertEq(BitcoinLib.nBits(_hdr(f, 1)), ANCHOR_BITS, "anchor bits");
    }

    // ── ASERT on every real header ───────────────────────────────────────────

    function _checkAsertAll(string memory name) internal view returns (uint256 checked) {
        Fixture memory f = _load(name);
        for (uint256 i = 1; i < f.count; ++i) {
            uint256 parentHeight = f.startHeight + i - 1;
            if (parentHeight < ANCHOR_HEIGHT) continue;
            bytes memory parent = _hdr(f, i - 1);
            uint32 expected = lib.asertBits(
                ANCHOR_BITS,
                ANCHOR_PREV_TIME,
                ANCHOR_HEIGHT,
                parentHeight,
                BitcoinLib.timestamp(parent),
                BCH_POW_LIMIT,
                HALF_LIFE
            );
            assertEq(expected, BitcoinLib.nBits(_hdr(f, i)), "asertBits(parent) = real nBits");
            ++checked;
        }
    }

    function test_asert_firstBlocksAfterActivation() public view {
        assertEq(_checkAsertAll("asert-activation"), 23);
    }

    function test_asert_recentBlocks() public view {
        assertEq(_checkAsertAll("mainnet-recent"), 144);
    }

    // ── Full verifyBundle on real headers ────────────────────────────────────

    function _verifyAndCheck(string memory name, uint256 cpIndex, uint256 n) internal returns (uint256 gasUsed) {
        Fixture memory f = _load(name);
        (BitcoinCashVerifier v, bytes memory anchor) = _setup(f, cpIndex);
        bytes memory proof = _proof(uint32(f.startHeight + cpIndex + 1), _range(f, cpIndex + 1, n));
        uint256 g = gasleft();
        (ClprTypes.QueueMetadata memory meta, bytes[] memory out, bytes memory na,,) =
            v.verifyBundle(proof, anchor, channelContext);
        gasUsed = g - gasleft();
        assertEq(out.length, 0);
        assertEq(meta.nextMessageId, 1);

        BitcoinVerifier.TrustAnchor memory a = abi.decode(na, (BitcoinVerifier.TrustAnchor));
        uint256 tip = f.startHeight + cpIndex + n;
        uint256 expectedCp = tip - K + 1;
        uint256 idx = expectedCp - f.startHeight;
        assertEq(a.checkpoint.height, expectedCp, "checkpoint = tip - k + 1");
        assertEq(a.checkpoint.blockHash, lib.hash256(_hdr(f, idx)));
        assertEq(a.checkpoint.bits, BitcoinLib.nBits(_hdr(f, idx)));
        assertEq(a.checkpoint.time, BitcoinLib.timestamp(_hdr(f, idx)));
        assertEq(a.checkpoint.periodStartTime, 0, "carried unchanged");
        uint256 w;
        for (uint256 i = cpIndex + 1; i <= idx; ++i) {
            w += lib.work(lib.bitsToTarget(BitcoinLib.nBits(_hdr(f, i))));
        }
        assertEq(a.checkpoint.chainWork - 1e30, w, "chainwork");
        console.log(string.concat("[bch-live] ", name, " headers / proofBytes / execution gas:"), n, proof.length);
        console.log("                                                         ", gasUsed);
    }

    /// @dev Checkpoint at the anchor block 661647; the next 23 headers are the first ASERT blocks.
    function test_verifyBundle_asertActivation() public {
        _verifyAndCheck("asert-activation", 1, 23);
    }

    /// @dev Typical bundle: 6 new real headers (k = 6) across the Bitcoin 2016 boundary at 969696.
    function test_verifyBundle_recent_6headers() public {
        _verifyAndCheck("mainnet-recent", 0, 6);
    }

    /// @dev One day of lag: 144 real headers in one bundle.
    function test_verifyBundle_recent_144headers() public {
        uint256 gasUsed = _verifyAndCheck("mainnet-recent", 0, 144);
        assertLt(gasUsed, 15_000_000);
    }

    // ── The Bitcoin rule does not accept Bitcoin Cash, and vice versa ────────

    /// @dev BitcoinVerifier with Bitcoin's 2016-block retarget rejects real BCH headers: BCH's nBits
    ///      changes at every block, which Bitcoin allows only at a period boundary.
    function test_bitcoinRetargetRuleRejectsBitcoinCash() public {
        Fixture memory f = _load("mainnet-recent");
        BitcoinVerifier.Checkpoint memory cp = _checkpoint(f, 0);
        BitcoinVerifier v = new BitcoinVerifier(BCH_POW_LIMIT, false, false, K, 4096, BCH_CHAIN_ID, cp);
        assertTrue(BitcoinLib.nBits(_hdr(f, 1)) != cp.bits, "nBits changes inside a Bitcoin period");
        vm.expectPartialRevert(BitcoinVerifier.WrongDifficultyBits.selector);
        v.verifyBundle(_proof(f.startHeight + 1, _range(f, 1, 6)), _trustAnchor(cp), channelContext);
    }

    /// @dev BitcoinCashVerifier rejects real Bitcoin headers (ASERT gives other nBits).
    function test_asertRuleRejectsBitcoinHeaders() public {
        string memory json = vm.readFile("test/verifiers/bitcoin/fixtures/mainnet-967680.json");
        Fixture memory f;
        f.startHeight = uint32(vm.parseJsonUint(json, ".startHeight"));
        f.headers = vm.parseJsonBytes(json, ".headersConcat");
        f.count = f.headers.length / 80;
        (BitcoinCashVerifier v, bytes memory anchor) = _setup(f, 0);
        vm.expectPartialRevert(BitcoinVerifier.WrongDifficultyBits.selector);
        v.verifyBundle(_proof(f.startHeight + 1, _range(f, 1, 6)), anchor, channelContext);
    }

    // ── Negative cases on real data ──────────────────────────────────────────

    function test_rejects_easierBits() public {
        Fixture memory f = _load("mainnet-recent");
        (BitcoinCashVerifier v, bytes memory anchor) = _setup(f, 0);
        bytes memory headers = _range(f, 1, 6);
        uint32 real = BitcoinLib.nBits(_hdr(f, 3));
        headers[2 * 80 + 72] = bytes1(uint8(headers[2 * 80 + 72]) + 1); // header 3 claims a larger target
        vm.expectRevert(
            abi.encodeWithSelector(BitcoinVerifier.WrongDifficultyBits.selector, f.startHeight + 3, real, real + 1)
        );
        v.verifyBundle(_proof(f.startHeight + 1, headers), anchor, channelContext);
    }

    function test_rejects_badProofOfWork() public {
        Fixture memory f = _load("mainnet-recent");
        (BitcoinCashVerifier v, bytes memory anchor) = _setup(f, 0);
        bytes memory headers = _range(f, 1, 6);
        headers[2 * 80 + 76] ^= 0x01; // nonce of header 3
        vm.expectRevert(abi.encodeWithSelector(BitcoinVerifier.InsufficientProofOfWork.selector, f.startHeight + 3));
        v.verifyBundle(_proof(f.startHeight + 1, headers), anchor, channelContext);
    }

    function test_rejects_brokenLinkage() public {
        Fixture memory f = _load("mainnet-recent");
        (BitcoinCashVerifier v, bytes memory anchor) = _setup(f, 0);
        bytes memory headers = abi.encodePacked(_range(f, 1, 2), _range(f, 4, 5)); // skip header 3
        vm.expectRevert(abi.encodeWithSelector(BitcoinVerifier.BrokenLinkage.selector, 2));
        v.verifyBundle(_proof(f.startHeight + 1, headers), anchor, channelContext);
    }

    /// @dev A deployment with the wrong anchor height computes other nBits for every real block.
    function test_rejects_wrongAsertAnchor() public {
        Fixture memory f = _load("mainnet-recent");
        BitcoinVerifier.Checkpoint memory cp = _checkpoint(f, 0);
        BitcoinCashVerifier.AsertAnchor memory a = _anchor();
        a.height += 1;
        BitcoinCashVerifier v = new BitcoinCashVerifier(BCH_POW_LIMIT, K, 4096, BCH_CHAIN_ID, cp, a, HALF_LIFE);
        vm.expectPartialRevert(BitcoinVerifier.WrongDifficultyBits.selector);
        v.verifyBundle(_proof(f.startHeight + 1, _range(f, 1, 6)), _trustAnchor(cp), channelContext);
    }

    /// @dev A trust anchor whose checkpoint lies below the ASERT anchor cannot validate headers.
    function test_rejects_checkpointBelowAsertAnchor() public {
        Fixture memory f = _load("asert-activation");
        (BitcoinCashVerifier v,) = _setup(f, 1);
        BitcoinVerifier.Checkpoint memory below = _checkpoint(f, 0); // 661646
        vm.expectRevert(abi.encodeWithSelector(BitcoinCashVerifier.HeaderBeforeAsertAnchor.selector, ANCHOR_HEIGHT));
        v.verifyBundle(_proof(f.startHeight + 1, _range(f, 1, 7)), _trustAnchor(below), channelContext);
    }

    function test_constructor_rejectsBadParams() public {
        Fixture memory f = _load("asert-activation");
        BitcoinVerifier.Checkpoint memory below = _checkpoint(f, 0);
        vm.expectRevert(BitcoinVerifier.InvalidNetworkParams.selector);
        new BitcoinCashVerifier(BCH_POW_LIMIT, K, 4096, BCH_CHAIN_ID, below, _anchor(), HALF_LIFE);

        BitcoinVerifier.Checkpoint memory cp = _checkpoint(f, 1);
        vm.expectRevert(BitcoinVerifier.InvalidNetworkParams.selector);
        new BitcoinCashVerifier(BCH_POW_LIMIT, K, 4096, BCH_CHAIN_ID, cp, _anchor(), 0);

        vm.expectRevert(BitcoinVerifier.InvalidNetworkParams.selector);
        new BitcoinCashVerifier(uint256(0x7fffff) << 232, K, 4096, BCH_CHAIN_ID, cp, _anchor(), HALF_LIFE);
    }

    // ── Real transaction: txid and Merkle branch ─────────────────────────────

    function test_realTx_txidAndMerkle() public view {
        string memory json = vm.readFile(string.concat(DIR, "mainnet-tx.json"));
        bytes memory raw = vm.parseJsonBytes(json, ".raw");
        BitcoinLib.Tx memory t = lib.parseTx(raw);
        assertEq(t.txid, vm.parseJsonBytes32(json, ".txidInternal"), "txid");
        bytes32[] memory branch = vm.parseJsonBytes32Array(json, ".branch");
        uint256 idx = vm.parseJsonUint(json, ".txIndex");
        bytes32 root = BitcoinLib.merkleRoot(vm.parseJsonBytes(json, ".blockHeader"));
        assertEq(lib.computeMerkleRoot(t.txid, idx, branch), root, "merkle root");
        assertTrue(lib.computeMerkleRoot(t.txid, idx ^ 1, branch) != root, "wrong index");
        branch[0] = bytes32(uint256(branch[0]) ^ 1);
        assertTrue(lib.computeMerkleRoot(t.txid, idx, branch) != root, "tampered sibling");
    }

    // ── BCHN reference vectors (src/test/pow_tests.cpp, calculate_asert_test) ─

    uint256 internal constant PARENT_TIME_DIFF = 600;

    function _asert(uint256 ref, int256 timeDiff, uint256 heightDiff) internal view returns (uint256) {
        return lib.asertTarget(ref, int256(PARENT_TIME_DIFF) + timeDiff, heightDiff, BCH_POW_LIMIT, HALF_LIFE);
    }

    function test_bchnVectors_steadyAndHalfLife() public view {
        uint256 initial = BCH_POW_LIMIT >> 4;
        // Steady, half time, make-up block (heights 1, 2, 3).
        assertEq(_asert(initial, 600, 1), initial);
        uint256 fast = _asert(initial, 600 + 300, 2);
        assertLt(fast, initial);
        assertEq(_asert(initial, 600 + 300 + 900, 3), initial);
        // Two days ahead doubles the target; two days behind halves it.
        assertEq(_asert(initial, 288 * 1200, 288), initial * 2);
        assertEq(_asert(initial * 2, 0, 288), initial);
    }

    struct Vec {
        uint256 ref;
        int256 timeDiff;
        uint256 heightDiff;
        uint256 expectedTarget;
        uint32 expectedBits;
    }

    function test_bchnVectors_table() public view {
        uint256 pl = BCH_POW_LIMIT;
        uint32 plBits = lib.targetToBits(pl);
        assertEq(plBits, 0x1d00ffff);
        Vec[18] memory v = [
            Vec(pl, 0, 2 * 144, pl >> 1, 0x1c7fffff),
            Vec(pl, 0, 4 * 144, pl >> 2, 0x1c3fffff),
            Vec(pl >> 1, 0, 2 * 144, pl >> 2, 0x1c3fffff),
            Vec(pl >> 2, 0, 2 * 144, pl >> 3, 0x1c1fffff),
            Vec(pl >> 3, 0, 2 * 144, pl >> 4, 0x1c0fffff),
            Vec(pl, 0, 2 * (256 - 34) * 144, 3, 0x01030000),
            Vec(pl, 0, 2 * (256 - 34) * 144 + 119, 3, 0x01030000),
            Vec(pl, 0, 2 * (256 - 34) * 144 + 120, 2, 0x01020000),
            Vec(pl, 0, 2 * (256 - 33) * 144 - 1, 2, 0x01020000),
            Vec(pl, 0, 2 * (256 - 33) * 144, 1, 0x01010000),
            Vec(pl, 0, 2 * (256 - 32) * 144, 1, 0x01010000),
            Vec(1, 0, 2 * (256 - 32) * 144, 1, 0x01010000),
            Vec(pl, 2 * (512 - 32) * 144, 0, pl, plBits),
            Vec(1, (512 - 64) * 144 * 600, 0, pl, plBits),
            Vec(pl, 300, 1, 0x00000000ffb1ffffffffffffffffffffffffffffffffffffffffffffffffffff, 0x1d00ffb1),
            Vec(0x000000008000000000000000000fffffffffffffffffffffffffffffffffffff, 600 * 2 * 33 * 144, 0, pl, plBits),
            Vec(1, 600 * 2 * 256 * 144, 0, pl, plBits),
            Vec(1, 600 * 2 * 224 * 144 - 1, 0, uint256(0xffff8) << 204, plBits)
        ];
        for (uint256 i = 0; i < v.length; ++i) {
            uint256 t = _asert(v[i].ref, v[i].timeDiff, v[i].heightDiff);
            assertEq(t, v[i].expectedTarget, string.concat("target, vector ", vm.toString(i)));
            assertEq(lib.targetToBits(t), v[i].expectedBits, string.concat("nBits, vector ", vm.toString(i)));
        }
    }
}
