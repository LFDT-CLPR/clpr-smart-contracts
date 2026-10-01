// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {RootstockVerifier} from "../../../src/verifiers/evm/rootstock/RootstockVerifier.sol";
import {RskHeader} from "../../../src/libraries/proof/rootstock/RskHeader.sol";
import {RskUnitrie} from "../../../src/libraries/proof/rootstock/RskUnitrie.sol";
import {ClprEvmBundleVerifier} from "../../../src/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "../../../src/libraries/ClprTypes.sol";

/// RootstockVerifier on recorded live data (test/e2e/fixtures/rootstock-live/):
///   - mainnet.json: 40 consecutive real RSK mainnet headers with their merged-mining proofs;
///   - regtest.json: a real RSKj regtest chain with a contract holding a CLPR Channel record at the
///     ClprService slots and Unitrie proofs from the node's own trie store.
contract RootstockVerifierTest is Test {
    string internal mainnetJson;
    string internal regtestJson;

    uint64 internal constant MAINNET_K = 12;
    uint64 internal constant REGTEST_K = 3;

    function setUp() public {
        mainnetJson = vm.readFile("test/e2e/fixtures/rootstock-live/mainnet.json");
        regtestJson = vm.readFile("test/e2e/fixtures/rootstock-live/regtest.json");
    }

    // ── fixture helpers ──────────────────────────────────────────────────────

    function _mainnetParams() internal pure returns (RootstockVerifier.Params memory) {
        return RootstockVerifier.Params({
            chainId: "eip155:30",
            confirmations: MAINNET_K,
            minDifficulty: 7e15,
            difficultyDivisor: 400,
            durationLimit: 14,
            forkDetectionFrom: 1_591_000,
            maxBtcTimestampDiff: 300
        });
    }

    function _regtestParams() internal pure returns (RootstockVerifier.Params memory) {
        return RootstockVerifier.Params({
            chainId: "eip155:33",
            confirmations: REGTEST_K,
            minDifficulty: 1,
            difficultyDivisor: 2048,
            durationLimit: 10,
            forkDetectionFrom: 0,
            maxBtcTimestampDiff: 0
        });
    }

    function _checkpoint(string memory json) internal pure returns (RootstockVerifier.Checkpoint memory c) {
        c.blockHash = vm.parseJsonBytes32(json, ".checkpoint.hash");
        c.number = vm.parseJsonUint(json, ".checkpoint.number");
        c.difficulty = vm.parseUint(vm.parseJsonString(json, ".checkpoint.difficulty"));
        c.timestamp = vm.parseJsonUint(json, ".checkpoint.timestamp");
    }

    function _headers(string memory json, uint256 from, uint256 count)
        internal
        pure
        returns (RootstockVerifier.MinedHeader[] memory hs)
    {
        hs = new RootstockVerifier.MinedHeader[](count);
        for (uint256 i = 0; i < count; ++i) {
            string memory k = string.concat(".headers[", vm.toString(from + i), "]");
            hs[i].header = vm.parseJsonBytes(json, string.concat(k, ".header"));
            hs[i].coinbase = vm.parseJsonBytes(json, string.concat(k, ".coinbase"));
            hs[i].merkleProof = vm.parseJsonBytes(json, string.concat(k, ".merkleProof"));
        }
    }

    function _mainnet() internal returns (RootstockVerifier v, RootstockVerifier.Checkpoint memory cp) {
        cp = _checkpoint(mainnetJson);
        v = new RootstockVerifier(_mainnetParams(), cp);
    }

    // ── mainnet: header chain + merged mining ───────────────────────────────

    function test_mainnet_40LiveHeaders() public {
        (RootstockVerifier v, RootstockVerifier.Checkpoint memory cp) = _mainnet();
        RootstockVerifier.MinedHeader[] memory hs = _headers(mainnetJson, 0, 40);
        uint256 g = gasleft();
        RootstockVerifier.Checkpoint memory f = v.verifyHeaders(cp, hs);
        console.log("40 mainnet headers, gas:", g - gasleft());
        assertEq(f.number, cp.number + 40 - MAINNET_K + 1);
        assertEq(
            f.blockHash,
            vm.parseJsonBytes32(mainnetJson, string.concat(".headers[", vm.toString(40 - MAINNET_K), "].hash"))
        );
        assertGt(f.work, 0);
    }

    function test_mainnet_gas_k12() public {
        (RootstockVerifier v, RootstockVerifier.Checkpoint memory cp) = _mainnet();
        RootstockVerifier.MinedHeader[] memory hs = _headers(mainnetJson, 0, MAINNET_K);
        uint256 g = gasleft();
        v.verifyHeaders(cp, hs);
        console.log("12 mainnet headers (one k-window), gas:", g - gasleft());
    }

    /// Catch-up across two transactions: header runs recorded by extend() chain back to the anchor.
    function test_mainnet_extend_catchUpInTwoRuns() public {
        (RootstockVerifier v, RootstockVerifier.Checkpoint memory cp) = _mainnet();
        RootstockVerifier.MinedHeader[] memory first = _headers(mainnetJson, 0, 20);
        RootstockVerifier.MinedHeader[] memory second = _headers(mainnetJson, 9, 31);
        RootstockVerifier.Checkpoint memory x = v.extend(cp, first);
        assertEq(x.number, cp.number + 9); // index 20 − k
        assertEq(v.extendedFrom(v.checkpointId(x)), v.checkpointId(cp));
        RootstockVerifier.Checkpoint memory y = v.extend(x, second);
        assertEq(y.number, cp.number + 29);
        v.requireDescends(cp, y);
        v.requireDescends(cp, cp);
        // y is not an ancestor of x, and an unrecorded checkpoint is not reachable
        vm.expectRevert(RootstockVerifier.RskStartNotRecorded.selector);
        v.requireDescends(y, x);
        RootstockVerifier.Checkpoint memory forged = y;
        forged.work += 1;
        vm.expectRevert(RootstockVerifier.RskStartNotRecorded.selector);
        v.requireDescends(cp, forged);
    }

    function test_mainnet_extend_gas40() public {
        (RootstockVerifier v, RootstockVerifier.Checkpoint memory cp) = _mainnet();
        RootstockVerifier.MinedHeader[] memory hs = _headers(mainnetJson, 0, 40);
        uint256 g = gasleft();
        v.extend(cp, hs);
        console.log("extend, 40 mainnet headers, gas:", g - gasleft());
    }

    function test_mainnet_extend_rejects_wrongStart() public {
        (RootstockVerifier v, RootstockVerifier.Checkpoint memory cp) = _mainnet();
        RootstockVerifier.MinedHeader[] memory hs = _headers(mainnetJson, 1, MAINNET_K);
        vm.expectRevert(RootstockVerifier.RskParentMismatch.selector);
        v.extend(cp, hs);
    }

    /// A bundle may not start from a checkpoint that was never recorded from its anchor.
    function test_regtest_rejects_unrecordedStart() public {
        (RootstockVerifier v,, bytes memory ctx) = _regtest();
        bytes memory anchor = _anchorAtCheckpoint(v);
        RootstockVerifier.BundleProof memory p = _bundle();
        p.start = _checkpoint(regtestJson);
        p.start.work = 7;
        vm.expectRevert(RootstockVerifier.RskStartNotRecorded.selector);
        v.verifyBundle(abi.encode(p), anchor, ctx);
    }

    function test_mainnet_rejects_belowConfirmations() public {
        (RootstockVerifier v, RootstockVerifier.Checkpoint memory cp) = _mainnet();
        vm.expectRevert(RootstockVerifier.RskNotFinal.selector);
        v.verifyHeaders(cp, _headers(mainnetJson, 0, MAINNET_K - 1));
    }

    function test_mainnet_rejects_gapInChain() public {
        (RootstockVerifier v, RootstockVerifier.Checkpoint memory cp) = _mainnet();
        RootstockVerifier.MinedHeader[] memory hs = _headers(mainnetJson, 0, MAINNET_K + 1);
        hs[5] = hs[6]; // drop one header
        vm.expectRevert(RootstockVerifier.RskParentMismatch.selector);
        v.verifyHeaders(cp, hs);
    }

    function test_mainnet_rejects_wrongCheckpoint() public {
        (RootstockVerifier v, RootstockVerifier.Checkpoint memory cp) = _mainnet();
        cp.blockHash = keccak256("not the parent");
        vm.expectRevert(RootstockVerifier.RskParentMismatch.selector);
        v.verifyHeaders(cp, _headers(mainnetJson, 0, MAINNET_K));
    }

    function test_mainnet_rejects_difficultyRuleMismatch() public {
        RootstockVerifier.Params memory p = _mainnetParams();
        p.difficultyDivisor = 50; // pre-RSKIP156 divisor
        RootstockVerifier.Checkpoint memory cp = _checkpoint(mainnetJson);
        RootstockVerifier v = new RootstockVerifier(p, cp);
        vm.expectRevert(RootstockVerifier.RskDifficultyMismatch.selector);
        v.verifyHeaders(cp, _headers(mainnetJson, 0, MAINNET_K));
    }

    function test_mainnet_rejects_tamperedBitcoinHeader() public {
        (RootstockVerifier v, RootstockVerifier.Checkpoint memory cp) = _mainnet();
        RootstockVerifier.MinedHeader[] memory hs = _headers(mainnetJson, 0, MAINNET_K);
        // Flip the nonce byte of the bitcoin header (last byte of the header preimage). The block hash
        // changes too, so the next header's parent link would fail; tamper the last header.
        bytes memory raw = hs[MAINNET_K - 1].header;
        raw[raw.length - 1] = bytes1(uint8(raw[raw.length - 1]) ^ 0x01);
        vm.expectRevert(RskHeader.RskInsufficientWork.selector);
        v.verifyHeaders(cp, hs);
    }

    function test_mainnet_rejects_tamperedCoinbaseTail() public {
        (RootstockVerifier v, RootstockVerifier.Checkpoint memory cp) = _mainnet();
        RootstockVerifier.MinedHeader[] memory hs = _headers(mainnetJson, 0, MAINNET_K);
        bytes memory cb = hs[3].coinbase;
        cb[cb.length - 1] = bytes1(uint8(cb[cb.length - 1]) ^ 0x01); // tail byte after the commitment
        vm.expectRevert(RskHeader.RskMerkleRootMismatch.selector);
        v.verifyHeaders(cp, hs);
    }

    function test_mainnet_rejects_tamperedMidstate() public {
        (RootstockVerifier v, RootstockVerifier.Checkpoint memory cp) = _mainnet();
        RootstockVerifier.MinedHeader[] memory hs = _headers(mainnetJson, 0, MAINNET_K);
        hs[2].coinbase[12] = bytes1(uint8(hs[2].coinbase[12]) ^ 0x80);
        vm.expectRevert(RskHeader.RskMerkleRootMismatch.selector);
        v.verifyHeaders(cp, hs);
    }

    function test_mainnet_rejects_tamperedMerkleBranch() public {
        (RootstockVerifier v, RootstockVerifier.Checkpoint memory cp) = _mainnet();
        RootstockVerifier.MinedHeader[] memory hs = _headers(mainnetJson, 0, MAINNET_K);
        require(hs[1].merkleProof.length >= 32, "fixture: branch expected");
        hs[1].merkleProof[0] = bytes1(uint8(hs[1].merkleProof[0]) ^ 0x01);
        vm.expectRevert(RskHeader.RskMerkleRootMismatch.selector);
        v.verifyHeaders(cp, hs);
    }

    function test_mainnet_rejects_wrongCommitment() public {
        (RootstockVerifier v, RootstockVerifier.Checkpoint memory cp) = _mainnet();
        RootstockVerifier.MinedHeader[] memory hs = _headers(mainnetJson, 0, MAINNET_K);
        // Swap in another block's coinbase: its RSKBLOCK: commitment names a different header.
        hs[4].coinbase = hs[5].coinbase;
        vm.expectRevert(RskHeader.RskTagMissing.selector);
        v.verifyHeaders(cp, hs);
    }

    // ── regtest: full CLPR bundle through the Unitrie ───────────────────────

    function _regtest() internal returns (RootstockVerifier v, bytes memory anchor, bytes memory ctx) {
        v = new RootstockVerifier(_regtestParams(), _checkpoint(regtestJson));
        address service = vm.parseJsonAddress(regtestJson, ".service");
        RootstockVerifier.ConfigProof memory c;
        c.headers = _headers(regtestJson, 0, 4);
        c.stateIndex = 0;
        c.service = service;
        c.codeProof = vm.parseJsonBytesArray(regtestJson, ".proofs.code");
        c.peerConfigNanos = 1;
        c.throttles.maxMessagesPerBundle = 16;
        bytes32 channelId = vm.parseJsonBytes32(regtestJson, ".channelId");
        (ctx,,,,, anchor,,) = v.verifyConfig(abi.encode(c), channelId, "");
    }

    function _bundle() internal view returns (RootstockVerifier.BundleProof memory p) {
        p.headers = _headers(regtestJson, 0, 4);
        p.stateIndex = 0;
        p.codeProof = vm.parseJsonBytesArray(regtestJson, ".proofs.code");
        p.slotProofs = new bytes[][](6);
        for (uint256 i = 0; i < 6; ++i) {
            p.slotProofs[i] = vm.parseJsonBytesArray(regtestJson, string.concat(".proofs.slots[", vm.toString(i), "]"));
        }
        p.bundleContent = hex"12060a04010203041205" hex"0a03050607";
    }

    /// verifyConfig re-anchors at the k-final block and reads the code hash from the trie.
    function test_regtest_verifyConfig() public {
        (RootstockVerifier v, bytes memory anchor, bytes memory ctx) = _regtest();
        RootstockVerifier.Anchor memory a = abi.decode(anchor, (RootstockVerifier.Anchor));
        bytes memory runtime = new bytes(64);
        for (uint256 i = 0; i < 64; ++i) {
            runtime[i] = 0xfe;
        }
        assertEq(a.codeHash, keccak256(runtime));
        assertEq(a.checkpoint.number, 5); // headers 4..7, k = 3 → final = 5
        assertEq(ctx.length, 52);
        assertGt(address(v).code.length, 0);
    }

    function test_regtest_verifyBundle_fullPipeline() public {
        (RootstockVerifier v,, bytes memory ctx) = _regtest();
        // Anchor at the pre-deploy checkpoint so the bundle carries the deploy block.
        bytes memory anchor = _anchorAtCheckpoint(v);
        uint256 g = gasleft();
        (ClprTypes.QueueMetadata memory m, bytes[] memory msgs, bytes memory na, bytes memory naId,) =
            v.verifyBundle(abi.encode(_bundle()), anchor, ctx);
        console.log("regtest bundle (4 headers, code + 6 slot proofs), gas:", g - gasleft());
        assertEq(m.nextMessageId, 3);
        assertEq(m.receivedMessageId, 2);
        assertEq(uint8(m.state), uint8(ClprTypes.ChannelStatus.ACTIVE));
        assertEq(m.sentRunningHash, keccak256("sent running hash"));
        assertEq(m.receivedRunningHash, keccak256("received running hash"));
        assertEq(m.endpointManifestVersion, 0); // proven by exclusion
        assertEq(msgs.length, 2);
        RootstockVerifier.Anchor memory a = abi.decode(na, (RootstockVerifier.Anchor));
        assertEq(a.checkpoint.number, 5);
        assertEq(bytes32(naId), a.checkpoint.blockHash);
    }

    function test_regtest_rejects_replayedBundle() public {
        (RootstockVerifier v,, bytes memory ctx) = _regtest();
        bytes memory anchor = _anchorAtCheckpoint(v);
        (,, bytes memory na,,) = v.verifyBundle(abi.encode(_bundle()), anchor, ctx);
        vm.expectRevert(RootstockVerifier.RskParentMismatch.selector);
        v.verifyBundle(abi.encode(_bundle()), na, ctx);
    }

    function test_regtest_rejects_swappedSlotProof() public {
        (RootstockVerifier v,, bytes memory ctx) = _regtest();
        RootstockVerifier.BundleProof memory p = _bundle();
        (p.slotProofs[2], p.slotProofs[3]) = (p.slotProofs[3], p.slotProofs[2]);
        vm.expectRevert();
        v.verifyBundle(abi.encode(p), _anchorAtCheckpoint(v), ctx);
    }

    function test_regtest_rejects_tamperedTrieNode() public {
        (RootstockVerifier v,, bytes memory ctx) = _regtest();
        RootstockVerifier.BundleProof memory p = _bundle();
        bytes memory last = p.slotProofs[0][p.slotProofs[0].length - 1];
        last[last.length - 1] = bytes1(uint8(last[last.length - 1]) ^ 0x01);
        vm.expectRevert(RskUnitrie.UnitrieHashMismatch.selector);
        v.verifyBundle(abi.encode(p), _anchorAtCheckpoint(v), ctx);
    }

    function test_regtest_rejects_wrongChannel() public {
        (RootstockVerifier v,,) = _regtest();
        bytes memory ctx = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({
                channelId: keccak256("another channel"),
                remoteServiceAddress: abi.encodePacked(vm.parseJsonAddress(regtestJson, ".service"))
            })
        );
        vm.expectRevert();
        v.verifyBundle(abi.encode(_bundle()), _anchorAtCheckpoint(v), ctx);
    }

    function test_regtest_rejects_wrongCodeHash() public {
        (RootstockVerifier v,, bytes memory ctx) = _regtest();
        RootstockVerifier.Anchor memory a = abi.decode(_anchorAtCheckpoint(v), (RootstockVerifier.Anchor));
        a.codeHash = keccak256("other code");
        vm.expectRevert(ClprEvmBundleVerifier.CodeHashMismatch.selector);
        v.verifyBundle(abi.encode(_bundle()), abi.encode(a), ctx);
    }

    function test_regtest_rejects_stateNotFinal() public {
        (RootstockVerifier v,, bytes memory ctx) = _regtest();
        RootstockVerifier.BundleProof memory p = _bundle();
        p.stateIndex = 2; // only 2 confirmations
        vm.expectRevert(RootstockVerifier.RskNotFinal.selector);
        v.verifyBundle(abi.encode(p), _anchorAtCheckpoint(v), ctx);
    }

    /// @dev An anchor at the pre-deploy block, so a bundle can carry the deploy block itself.
    function _anchorAtCheckpoint(RootstockVerifier) internal view returns (bytes memory) {
        RootstockVerifier.Anchor memory a;
        a.checkpoint = _checkpoint(regtestJson);
        bytes memory runtime = new bytes(64);
        for (uint256 i = 0; i < 64; ++i) {
            runtime[i] = 0xfe;
        }
        a.codeHash = keccak256(runtime);
        return abi.encode(a);
    }
}
