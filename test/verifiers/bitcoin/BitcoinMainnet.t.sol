// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {BitcoinLibHarness} from "./BitcoinTestBuilder.sol";
import {BitcoinVerifier} from "@hiero-ledger/clpr/verifiers/bitcoin/BitcoinVerifier.sol";
import {BitcoinLib} from "@hiero-ledger/clpr/verifiers/bitcoin/BitcoinLib.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";

/// @notice BitcoinVerifier / BitcoinLib against REAL Bitcoin mainnet data (fixtures fetched once
///         from blockstream.info by `fixtures/fetch-mainnet.ts`). Each header fixture spans a
///         2016-block retarget boundary: heights boundary-2 .. boundary+14.
contract BitcoinMainnetTest is Test {
    uint256 internal constant MAINNET_POW_LIMIT = uint256(0xffff) << 208;
    string internal constant MAINNET_CHAIN_ID = "bip122:000000000019d6689c085ae165831e93";
    uint8 internal constant K = 6;

    BitcoinLibHarness internal lib;
    bytes internal channelContext = abi.encodePacked(keccak256("mainnet channel"), hex"0014", bytes20(0));

    struct Fixture {
        uint32 boundary;
        uint32 startHeight;
        uint32 periodStartTime;
        bytes headers; // concatenated
        uint256 count;
    }

    function setUp() public {
        lib = new BitcoinLibHarness();
    }

    function _load(string memory name) internal view returns (Fixture memory f) {
        string memory json = vm.readFile(string.concat("test/verifiers/bitcoin/fixtures/", name, ".json"));
        f.boundary = uint32(vm.parseJsonUint(json, ".boundary"));
        f.startHeight = uint32(vm.parseJsonUint(json, ".startHeight"));
        f.periodStartTime = uint32(vm.parseJsonUint(json, ".periodStart.time"));
        f.headers = vm.parseJsonBytes(json, ".headersConcat");
        f.count = f.headers.length / 80;
    }

    function _hdr(Fixture memory f, uint256 i) internal pure returns (bytes memory) {
        return BitcoinLib.slice(f.headers, i * 80, 80);
    }

    function _hashAt(string memory name, uint256 i) internal view returns (bytes32) {
        string memory json = vm.readFile(string.concat("test/verifiers/bitcoin/fixtures/", name, ".json"));
        return vm.parseJsonBytes32(json, string.concat(".headers[", vm.toString(i), "].hashInternal"));
    }

    /// @dev Anchor at the first fixture header (boundary-2) and a verifier with mainnet params.
    function _setupChain(Fixture memory f)
        internal
        returns (BitcoinVerifier v, bytes memory anchor, BitcoinVerifier.Checkpoint memory cp)
    {
        bytes memory h0 = _hdr(f, 0);
        cp = BitcoinVerifier.Checkpoint({
            blockHash: lib.hash256(h0),
            height: f.startHeight,
            chainWork: 1e30, // arbitrary base; only deltas are checked
            bits: BitcoinLib.nBits(h0),
            time: BitcoinLib.timestamp(h0),
            periodStartTime: f.periodStartTime
        });
        v = new BitcoinVerifier(MAINNET_POW_LIMIT, false, false, K, 4096, MAINNET_CHAIN_ID, cp);
        anchor = abi.encode(
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

    function _proof(uint32 startHeight, bytes memory headers) internal pure returns (bytes memory) {
        BitcoinVerifier.BundleProof memory p;
        p.startHeight = startHeight;
        p.headers = headers;
        return abi.encode(p);
    }

    // ── Header hashing / PoW on real data ────────────────────────────────────

    function test_realHeadersHashToExplorerHashes() public view {
        string[3] memory names = ["mainnet-2016", "mainnet-32256", "mainnet-967680"];
        for (uint256 n = 0; n < 3; ++n) {
            Fixture memory f = _load(names[n]);
            for (uint256 i = 0; i < f.count; ++i) {
                bytes memory h = _hdr(f, i);
                bytes32 hash = lib.hash256(h);
                assertEq(hash, _hashAt(names[n], i), "hash256(header) = block hash");
                // Real PoW: hash (LE integer) ≤ target(nBits).
                assertLe(lib.reverse256(uint256(hash)), lib.bitsToTarget(BitcoinLib.nBits(h)), "PoW");
                if (i > 0) assertEq(BitcoinLib.prevHash(h), lib.hash256(_hdr(f, i - 1)), "linkage");
            }
        }
    }

    // ── Retarget math on real boundaries ─────────────────────────────────────

    function _checkRetarget(string memory name, uint32 expectedOld, uint32 expectedNew) internal view {
        Fixture memory f = _load(name);
        bytes memory last = _hdr(f, 1); // boundary-1
        bytes memory first = _hdr(f, 2); // boundary
        assertEq(BitcoinLib.nBits(last), expectedOld);
        assertEq(BitcoinLib.nBits(first), expectedNew);
        uint32 computed =
            lib.retarget(BitcoinLib.nBits(last), f.periodStartTime, BitcoinLib.timestamp(last), MAINNET_POW_LIMIT);
        assertEq(computed, expectedNew, "retarget(boundary) = real nBits");
    }

    /// @dev Height 2016: blocks came slower than 10 min; the new target is capped at powLimit.
    function test_retarget_2016_cappedAtPowLimit() public view {
        _checkRetarget("mainnet-2016", 0x1d00ffff, 0x1d00ffff);
    }

    /// @dev Height 32256: the first real difficulty increase (Dec 2009).
    function test_retarget_32256_firstIncrease() public view {
        _checkRetarget("mainnet-32256", 0x1d00ffff, 0x1d00d86a);
    }

    /// @dev Height 967680: a recent boundary (Sep 2026).
    function test_retarget_967680_recent() public view {
        _checkRetarget("mainnet-967680", 0x1702355e, 0x17021ec5);
    }

    function test_compactRoundTrip() public view {
        uint32[6] memory bits = [uint32(0x1d00ffff), 0x1d00d86a, 0x17021ec5, 0x1702355e, 0x207fffff, 0x03123456];
        for (uint256 i = 0; i < bits.length; ++i) {
            assertEq(lib.targetToBits(lib.bitsToTarget(bits[i])), bits[i]);
        }
        assertEq(lib.bitsToTarget(0x1d00ffff), MAINNET_POW_LIMIT);
        // Genesis work: 2^256 / (powLimit+1) = 0x100010001.
        assertEq(lib.work(MAINNET_POW_LIMIT), 0x100010001);
    }

    function test_compactRejectsNegativeAndOverflow() public {
        vm.expectRevert(BitcoinLib.BtcNegativeTarget.selector);
        lib.bitsToTarget(0x1d80ffff);
        vm.expectRevert(BitcoinLib.BtcTargetOverflow.selector);
        lib.bitsToTarget(0x23000001 + 0x00010000);
        vm.expectRevert(BitcoinLib.BtcZeroTarget.selector);
        lib.bitsToTarget(0x1d000000);
    }

    // ── Full verifyBundle over a real boundary ───────────────────────────────

    function _verifyRealChain(string memory name) internal {
        Fixture memory f = _load(name);
        (BitcoinVerifier v, bytes memory anchor, BitcoinVerifier.Checkpoint memory cp) = _setupChain(f);
        bytes memory headers = BitcoinLib.slice(f.headers, 80, (f.count - 1) * 80);
        (ClprTypes.QueueMetadata memory meta, bytes[] memory out, bytes memory na,,) =
            v.verifyBundle(_proof(f.startHeight + 1, headers), anchor, channelContext);
        assertEq(out.length, 0);
        assertEq(meta.nextMessageId, 1);

        BitcoinVerifier.TrustAnchor memory a = abi.decode(na, (BitcoinVerifier.TrustAnchor));
        uint256 tip = f.startHeight + f.count - 1;
        uint256 expectedCp = tip - K + 1;
        uint256 idx = expectedCp - f.startHeight;
        assertEq(a.checkpoint.height, expectedCp, "checkpoint = tip - k + 1");
        assertEq(a.checkpoint.blockHash, _hashAt(name, idx));
        bytes memory cpHeader = _hdr(f, idx);
        assertEq(a.checkpoint.bits, BitcoinLib.nBits(cpHeader), "post-retarget bits");
        assertEq(a.checkpoint.time, BitcoinLib.timestamp(cpHeader));
        assertEq(a.checkpoint.periodStartTime, BitcoinLib.timestamp(_hdr(f, 2)), "new period starts at the boundary");
        uint256 w;
        for (uint256 i = 1; i <= idx; ++i) {
            w += lib.work(lib.bitsToTarget(BitcoinLib.nBits(_hdr(f, i))));
        }
        assertEq(a.checkpoint.chainWork - cp.chainWork, w, "chainwork");
    }

    function test_verifyBundle_realBoundary_2016() public {
        _verifyRealChain("mainnet-2016");
    }

    function test_verifyBundle_realBoundary_32256() public {
        _verifyRealChain("mainnet-32256");
    }

    function test_verifyBundle_realBoundary_967680() public {
        _verifyRealChain("mainnet-967680");
    }

    /// @dev 967679's timestamp is earlier than 967678's — legal on Bitcoin (only MTP is enforced)
    ///      and it must not trip the verifier.
    function test_realNonMonotonicTimestampAccepted() public view {
        Fixture memory f = _load("mainnet-967680");
        assertLt(BitcoinLib.timestamp(_hdr(f, 1)), BitcoinLib.timestamp(_hdr(f, 0)));
    }

    // ── Negative tests on real data ──────────────────────────────────────────

    function test_rejects_badProofOfWork() public {
        Fixture memory f = _load("mainnet-967680");
        (BitcoinVerifier v, bytes memory anchor,) = _setupChain(f);
        bytes memory headers = BitcoinLib.slice(f.headers, 80, (f.count - 1) * 80);
        headers[3 * 80 + 76] ^= 0x01; // nonce of height boundary+2
        vm.expectRevert(abi.encodeWithSelector(BitcoinVerifier.InsufficientProofOfWork.selector, f.boundary + 2));
        v.verifyBundle(_proof(f.startHeight + 1, headers), anchor, channelContext);
    }

    function test_rejects_brokenLinkage() public {
        Fixture memory f = _load("mainnet-967680");
        (BitcoinVerifier v, bytes memory anchor,) = _setupChain(f);
        // Skip boundary+1: boundary+2 no longer links.
        bytes memory headers = abi.encodePacked(
            BitcoinLib.slice(f.headers, 80, 2 * 80), BitcoinLib.slice(f.headers, 4 * 80, (f.count - 4) * 80)
        );
        vm.expectRevert(abi.encodeWithSelector(BitcoinVerifier.BrokenLinkage.selector, 2));
        v.verifyBundle(_proof(f.startHeight + 1, headers), anchor, channelContext);
    }

    function test_rejects_wrongBitsAtBoundary() public {
        Fixture memory f = _load("mainnet-32256");
        (BitcoinVerifier v, bytes memory anchor,) = _setupChain(f);
        bytes memory headers = BitcoinLib.slice(f.headers, 80, (f.count - 1) * 80);
        // Keep the old difficulty (0x1d00ffff) across the boundary.
        headers[80 + 72] = 0xff;
        headers[80 + 73] = 0xff;
        vm.expectRevert(
            abi.encodeWithSelector(
                BitcoinVerifier.WrongDifficultyBits.selector, f.boundary, uint32(0x1d00d86a), uint32(0x1d00ffff)
            )
        );
        v.verifyBundle(_proof(f.startHeight + 1, headers), anchor, channelContext);
    }

    function test_rejects_bitsChangeInsidePeriod() public {
        Fixture memory f = _load("mainnet-967680");
        (BitcoinVerifier v, bytes memory anchor,) = _setupChain(f);
        bytes memory headers = BitcoinLib.slice(f.headers, 80, (f.count - 1) * 80);
        headers[5 * 80 + 72] ^= 0x01; // boundary+4 claims different bits
        uint32 real = BitcoinLib.nBits(_hdr(f, 6));
        vm.expectRevert(
            abi.encodeWithSelector(BitcoinVerifier.WrongDifficultyBits.selector, f.boundary + 4, real, real ^ 0x01)
        );
        v.verifyBundle(_proof(f.startHeight + 1, headers), anchor, channelContext);
    }

    function test_rejects_wrongPeriodStartInAnchor() public {
        Fixture memory f = _load("mainnet-967680");
        (BitcoinVerifier v, bytes memory anchor,) = _setupChain(f);
        BitcoinVerifier.TrustAnchor memory a = abi.decode(anchor, (BitcoinVerifier.TrustAnchor));
        a.checkpoint.periodStartTime -= 3 days; // lie about the period's timespan
        bytes memory headers = BitcoinLib.slice(f.headers, 80, (f.count - 1) * 80);
        vm.expectPartialRevert(BitcoinVerifier.WrongDifficultyBits.selector);
        v.verifyBundle(_proof(f.startHeight + 1, headers), abi.encode(a), channelContext);
    }

    function test_rejects_regtestHeaderOnMainnet() public {
        Fixture memory f = _load("mainnet-967680");
        (BitcoinVerifier v, bytes memory anchor,) = _setupChain(f);
        bytes memory headers = BitcoinLib.slice(f.headers, 80, 80);
        // Claim the powLimit-exceeding regtest difficulty right after the checkpoint.
        headers[72] = 0xff;
        headers[73] = 0xff;
        headers[74] = 0x7f;
        headers[75] = 0x20;
        vm.expectPartialRevert(BitcoinVerifier.WrongDifficultyBits.selector);
        v.verifyBundle(_proof(f.startHeight + 1, headers), anchor, channelContext);
    }

    // ── Real transactions: txid over non-witness serialization + real Merkle branch ──

    function _checkRealTx(string memory name, bool expectSegwit) internal view {
        string memory json = vm.readFile(string.concat("test/verifiers/bitcoin/fixtures/", name, ".json"));
        bytes memory raw = vm.parseJsonBytes(json, ".raw");
        assertEq(raw[4] == 0x00 && raw[5] == 0x01, expectSegwit, "serialization kind");
        BitcoinLib.Tx memory t = lib.parseTx(raw);
        assertEq(t.txid, vm.parseJsonBytes32(json, ".txidInternal"), "txid");
        bytes32 root = lib.computeMerkleRoot(
            t.txid, vm.parseJsonUint(json, ".txIndex"), vm.parseJsonBytes32Array(json, ".branch")
        );
        assertEq(root, BitcoinLib.merkleRoot(vm.parseJsonBytes(json, ".blockHeader")), "merkle root");
    }

    function test_realSegwitTx_txidAndMerkle() public view {
        _checkRealTx("mainnet-tx-segwit", true);
    }

    function test_realLegacyTx_txidAndMerkle() public view {
        _checkRealTx("mainnet-tx-legacy", false);
    }

    function test_realTx_wrongMerkleBranchRejected() public view {
        string memory json = vm.readFile("test/verifiers/bitcoin/fixtures/mainnet-tx-segwit.json");
        BitcoinLib.Tx memory t = lib.parseTx(vm.parseJsonBytes(json, ".raw"));
        bytes32[] memory branch = vm.parseJsonBytes32Array(json, ".branch");
        uint256 idx = vm.parseJsonUint(json, ".txIndex");
        bytes32 realRoot = BitcoinLib.merkleRoot(vm.parseJsonBytes(json, ".blockHeader"));
        assertTrue(lib.computeMerkleRoot(t.txid, idx ^ 1, branch) != realRoot, "wrong index");
        branch[branch.length - 1] = bytes32(uint256(branch[branch.length - 1]) ^ 1);
        assertTrue(lib.computeMerkleRoot(t.txid, idx, branch) != realRoot, "tampered sibling");
    }

    function test_realTx_witnessTamperDoesNotChangeTxidButTruncationRejected() public {
        string memory json = vm.readFile("test/verifiers/bitcoin/fixtures/mainnet-tx-segwit.json");
        bytes memory raw = vm.parseJsonBytes(json, ".raw");
        bytes32 txid = lib.parseTx(raw).txid;
        // Flip a byte inside the witness (just before the 4-byte locktime): txid is unchanged.
        raw[raw.length - 6] ^= 0x01;
        assertEq(lib.parseTx(raw).txid, txid, "witness is not part of the txid");
        // Truncated / extended serializations are rejected cleanly.
        vm.expectRevert(BitcoinLib.BtcTxTrailingBytes.selector);
        lib.parseTx(abi.encodePacked(raw, hex"00"));
        vm.expectRevert();
        lib.parseTx(BitcoinLib.slice(raw, 0, raw.length - 5));
    }
}
