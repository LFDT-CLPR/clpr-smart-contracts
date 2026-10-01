// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {TonVerifier} from "@hiero-ledger/clpr/verifiers/evm/neartons/TonVerifier.sol";
import {TonCells} from "@hiero-ledger/clpr/libraries/proof/ton/TonCells.sol";
import {TonBlocks} from "@hiero-ledger/clpr/libraries/proof/ton/TonBlocks.sol";
import {ClprEd25519SignatureCache} from "@hiero-ledger/clpr/verifiers/evm/neartons/ClprEd25519SignatureCache.sol";
import {ClprEd25519Check} from "@hiero-ledger/clpr/verifiers/evm/neartons/ClprEd25519Check.sol";
import {ClprNearTonBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/neartons/ClprNearTonBundleVerifier.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {MockEd25519, NearTonFixtures} from "./NearTonTestKit.sol";
import {TonCellBuilder as B} from "./TonCellBuilder.sol";

/// @notice Synthetic TonVerifier suite. A masterchain CLPR Service (workchain −1, exercising the
///         path the live basechain fixtures do not), 4 validators (weights 10/20/30/40), catchain and
///         Simplex signature modes, a key-block rotation, verifyConfig, and the negative cases.
abstract contract TonVerifierFixture is Test {
    MockEd25519 internal ed;
    ClprEd25519SignatureCache internal cache;
    TonVerifier internal v;

    string internal constant CHAIN = "ton:testnet";
    bytes32 internal constant ADDR = keccak256("clpr-service");
    bytes32 internal constant CHANNEL = keccak256("channel-1");
    uint32 internal constant KEY0 = 100;
    uint32 internal constant KEY1 = 150;

    bytes internal valsA;
    bytes internal valsB;
    bytes32[4] internal keysA;
    bytes32[4] internal keysB;
    bytes internal manifest;
    bytes internal control;
    bytes32 internal sentHash = keccak256("sent");

    function setUp() public virtual {
        ed = new MockEd25519();
        cache = new ClprEd25519SignatureCache(ed);
        for (uint256 i = 0; i < 4; i++) {
            keysA[i] = keccak256(abi.encode("A", i));
            keysB[i] = keccak256(abi.encode("B", i));
            valsA = abi.encodePacked(valsA, keysA[i], uint64((i + 1) * 10));
            valsB = abi.encodePacked(valsB, keysB[i], uint64((i + 1) * 10));
        }
        manifest = NearTonFixtures.manifest(_svc(), 4);
        control = NearTonFixtures.controlMessage(CHAIN, _svc());
        v = new TonVerifier(CHAIN, KEY0, keccak256(valsA), ed, cache);
    }

    function _svc() internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0xff), ADDR);
    }

    function _anchor(uint32 seq, bytes memory vals) internal pure returns (bytes memory) {
        return abi.encodePacked(seq, keccak256(vals));
    }

    function _ctx() internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(ClprTypes.ChannelContext(CHANNEL, _svc()));
    }

    // ── state builders ──────────────────────────────────────────────────────

    function _accountBoc(bytes32 cfgC, bytes32 manC, uint64 nextId) internal view returns (bytes memory) {
        B.Tree memory t = B.tree();
        B.W memory q = B.w();
        B.u(q, 1, 8);
        B.u(q, nextId, 64);
        B.u(q, 5, 64);
        B.b32(q, sentHash);
        B.b32(q, keccak256("recv"));
        B.u(q, 3, 64);
        uint256 queue = B.leaf(t, q);
        B.W memory e = B.w();
        B.label(e, uint256(CHANNEL), 256, 256);
        uint256 dict = B.add1(t, e, queue);
        B.W memory d = B.w();
        B.b32(d, cfgC);
        B.b32(d, manC);
        B.u(d, 1, 1);
        uint256 data = B.add1(t, d, dict);
        uint256 code = B.dummy(t, "code");
        B.W memory a = B.w();
        B.u(a, 1, 1); // account$1
        B.u(a, 2, 2); // addr_std$10
        B.u(a, 0, 1); // no anycast
        B.u(a, 0xff, 8); // workchain -1
        B.b32(a, ADDR);
        B.u(a, 1, 3);
        B.u(a, 5, 8); // cells
        B.u(a, 1, 3);
        B.u(a, 100, 8); // bits
        B.u(a, 0, 3); // storage_extra_none
        B.u(a, 0, 32); // last_paid
        B.u(a, 0, 1); // due_payment
        B.u(a, 7, 64); // last_trans_lt
        B.u(a, 1, 4);
        B.u(a, 9, 8); // grams
        B.u(a, 0, 1); // extra currencies
        B.u(a, 1, 1); // account_active
        B.u(a, 0, 1); // fixed_prefix_length
        B.u(a, 0, 1); // special
        B.u(a, 1, 1); // code
        B.u(a, 1, 1); // data
        B.u(a, 0, 1); // library
        uint256 acc = B.add2(t, a, code, data);
        return B.boc(t, acc);
    }

    function _stateBoc(bytes32 accountHash, uint16 accountDepth, bytes32 addr) internal pure returns (bytes memory) {
        B.Tree memory t = B.tree();
        uint256 acc = B.pruned(t, accountHash, accountDepth);
        B.W memory l = B.w();
        B.label(l, uint256(addr), 256, 256);
        B.u(l, 0, 5); // split_depth
        B.u(l, 0, 4); // grams
        B.u(l, 0, 1); // extra currencies
        B.b32(l, keccak256("last tx"));
        B.u(l, 7, 64);
        uint256 leaf = B.add1(t, l, acc);
        B.W memory ac = B.w();
        B.u(ac, 1, 1);
        B.u(ac, 0, 5);
        B.u(ac, 0, 4);
        B.u(ac, 0, 1);
        uint256 accounts = B.add1(t, ac, leaf);
        B.W memory s = B.w();
        B.u(s, 0x9023afe2, 32);
        B.u(s, 0xfffffffd, 32); // global_id -3
        B.u(s, 0, 2);
        B.u(s, 0, 6);
        B.u(s, 0xffffffff, 32);
        B.u(s, 0x8000000000000000, 64);
        B.u(s, 160, 32);
        B.u(s, 0, 32);
        B.u(s, 1_790_000_000, 32);
        B.u(s, 1, 64);
        B.u(s, 159, 32);
        B.u(s, 0, 1); // before_split
        B.u(s, 0, 1); // custom: none
        uint256[] memory r = new uint256[](3);
        r[0] = B.dummy(t, "out_msg_queue");
        r[1] = accounts;
        r[2] = B.dummy(t, "state rest");
        return B.boc(t, B.add(t, s, r));
    }

    function _info(B.Tree memory t, uint32 seq, bool key, uint32 prevKey) internal pure returns (uint256) {
        B.W memory i = B.w();
        B.u(i, 0x9bc7a987, 32);
        B.u(i, 0, 32);
        B.u(i, 0, 6); // not_master after_merge before_split after_split want_split want_merge
        B.u(i, key ? 1 : 0, 1);
        B.u(i, 0, 1 + 8);
        B.u(i, seq, 32);
        B.u(i, 0, 32);
        B.u(i, 0, 2);
        B.u(i, 0, 6);
        B.u(i, 0xffffffff, 32);
        B.u(i, 0x8000000000000000, 64);
        B.u(i, 1_790_000_000, 32);
        B.u(i, 1, 64);
        B.u(i, 2, 64);
        B.u(i, 0xabcd, 32);
        B.u(i, 7, 32);
        B.u(i, seq - 1, 32);
        B.u(i, prevKey, 32);
        return B.add1(t, i, B.dummy(t, "prev_ref"));
    }

    function _blockBoc(uint32 seq, uint32 prevKey, bytes32 stateHash, uint16 stateDepth, bytes memory keyVals)
        internal
        pure
        returns (bytes memory)
    {
        B.Tree memory t = B.tree();
        bool key = keyVals.length != 0;
        uint256 info = _info(t, seq, key, prevKey);
        uint256 su = B.merkleUpdate(t, keccak256("old state"), stateHash, stateDepth);
        uint256 extra = key ? _keyExtra(t, keyVals) : B.dummy(t, "extra");
        B.W memory b = B.w();
        B.u(b, 0x11ef55aa, 32);
        B.u(b, 0xfffffffd, 32);
        uint256[] memory r = new uint256[](4);
        (r[0], r[1], r[2], r[3]) = (info, B.dummy(t, "value_flow"), su, extra);
        return B.boc(t, B.add(t, b, r));
    }

    function _keyExtra(B.Tree memory t, bytes memory vals) internal pure returns (uint256) {
        uint256 n = vals.length / 40;
        uint256 list = _validatorDict(t, vals, 0, n, 16);
        B.W memory vs = B.w();
        B.u(vs, 0x12, 8);
        B.u(vs, 1_790_000_000, 32);
        B.u(vs, 1_790_065_536, 32);
        B.u(vs, n, 16);
        B.u(vs, n, 16);
        B.u(vs, 100, 64);
        B.u(vs, 1, 1);
        uint256 vsCell = B.add1(t, vs, list);
        B.W memory c = B.w();
        B.label(c, 34, 32, 32);
        uint256 cfg = B.add1(t, c, vsCell);
        B.W memory m = B.w();
        B.u(m, 0xcca5, 16);
        B.u(m, 1, 1); // key_block
        B.u(m, 0, 1); // shard_hashes
        B.u(m, 0, 1); // shard_fees
        B.u(m, 0, 5); // fees
        B.u(m, 0, 5); // create
        B.b32(m, keccak256("config addr"));
        uint256 mce = B.add2(t, m, B.dummy(t, "prev sigs"), cfg);
        B.W memory e = B.w();
        B.u(e, 0x4a33f6fd, 32);
        B.b32(e, keccak256("rand"));
        B.b32(e, keccak256("creator"));
        B.u(e, 1, 1);
        uint256[] memory r = new uint256[](4);
        (r[0], r[1], r[2], r[3]) = (B.dummy(t, "in"), B.dummy(t, "out"), B.dummy(t, "acc blocks"), mce);
        return B.add(t, e, r);
    }

    /// Hashmap 16 over keys [lo, hi): a label of the common prefix, then a fork.
    function _validatorDict(B.Tree memory t, bytes memory vals, uint256 lo, uint256 hi, uint256 m)
        internal
        pure
        returns (uint256)
    {
        // prefix bits shared by every key in [lo, hi) within the remaining m bits
        uint256 l = 0;
        while (l < m && ((lo >> (m - 1 - l)) & 1) == (((hi - 1) >> (m - 1 - l)) & 1)) {
            l++;
        }
        B.W memory x = B.w();
        B.label(x, l == 0 ? 0 : (lo >> (m - l)) & ((1 << l) - 1), l, m);
        if (l == m) {
            B.u(x, 0x53, 8);
            B.u(x, 0x8e81278a, 32);
            B.b32(x, bytes32(_slice32(vals, lo * 40)));
            B.u(x, uint64(bytes8(_slice32(vals, lo * 40 + 32))), 64);
            return B.leaf(t, x);
        }
        uint256 rest = m - l - 1;
        uint256 mid = ((lo >> rest) | 1) << rest; // first key with the fork bit set
        uint256 left = _validatorDict(t, vals, lo, mid, rest);
        uint256 right = _validatorDict(t, vals, mid, hi, rest);
        return B.add2(t, x, left, right);
    }

    function _slice32(bytes memory b, uint256 off) internal pure returns (bytes32 w) {
        assembly {
            w := mload(add(add(b, 0x20), off))
        }
    }

    // ── signatures ──────────────────────────────────────────────────────────

    function _rootOf(bytes memory boc) internal view returns (bytes32 h) {
        TonCells.Boc memory b = TonCells.parse(boc);
        h = b.cells[b.root].hashes[0];
    }

    function _sign(bytes memory boc, uint32 seq, bytes32[4] memory keys, uint256[] memory signers, uint8 mode)
        internal
        view
        returns (TonVerifier.McBlock memory m)
    {
        m.boc = boc;
        bytes32 root = _rootOf(boc);
        m.sigs.mode = mode;
        m.sigs.fileHash = keccak256(abi.encode("file", seq));
        bytes memory message;
        if (mode == 0) {
            message = abi.encodePacked(bytes4(0x706e0bc5), root, m.sigs.fileHash);
        } else {
            m.sigs.sessionId = keccak256("session");
            m.sigs.slot = 42;
            m.sigs.candidate = abi.encodePacked(
                hex"dcbcf9e8", hex"ffffffff", hex"0000000000000080", _le32(seq), root, m.sigs.fileHash, hex"a9cccb22"
            );
            bytes memory vote = abi.encodePacked(hex"05e1a740", hex"3fcd91b6", _le32(42), sha256(m.sigs.candidate));
            message = abi.encodePacked(hex"f83de3a8", m.sigs.sessionId, uint8(44), vote, hex"000000");
        }
        m.sigs.signers = signers;
        m.sigs.signatures = new bytes[](signers.length);
        for (uint256 i = 0; i < signers.length; i++) {
            m.sigs.signatures[i] = ed.sign(keys[signers[i]], message);
        }
    }

    function _le32(uint32 x) internal pure returns (bytes4) {
        return bytes4(uint32((x & 0xff) << 24 | ((x >> 8) & 0xff) << 16 | ((x >> 16) & 0xff) << 8 | (x >> 24)));
    }

    function _s(uint256 a, uint256 b) internal pure returns (uint256[] memory s) {
        s = new uint256[](2);
        (s[0], s[1]) = (a, b);
    }

    // ── proofs ──────────────────────────────────────────────────────────────

    function _chain(uint64 nextId, uint32 prevKey, bytes32[4] memory keys, uint8 mode)
        internal
        view
        returns (TonVerifier.McBlock memory blk, TonVerifier.StateChain memory st)
    {
        st.account = _accountBoc(keccak256(control), keccak256(manifest), nextId);
        TonCells.Boc memory a = TonCells.parse(st.account);
        st.mcState = _stateBoc(a.cells[a.root].hashes[0], uint16(a.cells[a.root].depths[0]), ADDR);
        TonCells.Boc memory s = TonCells.parse(st.mcState);
        bytes memory blockBoc =
            _blockBoc(160, prevKey, s.cells[s.root].hashes[0], uint16(s.cells[s.root].depths[0]), "");
        blk = _sign(blockBoc, 160, keys, _s(2, 3), mode);
    }

    function _bundle(uint8 mode) internal view returns (TonVerifier.BundleProof memory p) {
        p.validators = valsA;
        p.keyBlocks = new TonVerifier.McBlock[](0);
        (p.block, p.state) = _chain(7, KEY0, keysA, mode);
        p.bundleContent = NearTonFixtures.bundleContent();
    }

    function _rotatingBundle() internal view returns (TonVerifier.BundleProof memory p) {
        p.validators = valsA;
        p.keyBlocks = new TonVerifier.McBlock[](1);
        p.keyBlocks[0] = _sign(_blockBoc(KEY1, KEY0, keccak256("k"), 3, valsB), KEY1, keysA, _s(2, 3), 1);
        (p.block, p.state) = _chain(7, KEY1, keysB, 1);
        p.bundleContent = NearTonFixtures.bundleContent();
    }

    function _expectBundleRevert(bytes memory proof, bytes memory anchor, bytes memory ctx, bytes memory err) internal {
        vm.expectRevert(err);
        v.verifyBundle(proof, anchor, ctx);
    }
}

contract TonVerifierTest is TonVerifierFixture {
    // ── happy paths ─────────────────────────────────────────────────────────

    function test_verifyBundle_catchain() public view {
        (
            ClprTypes.QueueMetadata memory m,
            bytes[] memory payloads,
            bytes memory na,,
            ClprTypes.ClprEndpointManifest memory man
        ) = v.verifyBundle(abi.encode(_bundle(0)), _anchor(KEY0, valsA), _ctx());
        assertEq(uint8(m.state), 1);
        assertEq(m.nextMessageId, 7);
        assertEq(m.receivedMessageId, 5);
        assertEq(m.sentRunningHash, keccak256("sent"));
        assertEq(m.receivedRunningHash, keccak256("recv"));
        assertEq(m.endpointManifestVersion, 3);
        assertEq(payloads.length, 2);
        assertEq(na.length, 0);
        assertEq(man.version, 0);
    }

    function test_verifyBundle_simplex_withManifest() public view {
        TonVerifier.BundleProof memory p = _bundle(1);
        p.manifestPreimage = manifest;
        (,,,, ClprTypes.ClprEndpointManifest memory man) = v.verifyBundle(abi.encode(p), _anchor(KEY0, valsA), _ctx());
        assertEq(man.version, 4);
        assertEq(man.serviceAddress, _svc());
    }

    function test_verifyBundle_keyBlockRotation() public view {
        (,, bytes memory na, bytes memory naId,) =
            v.verifyBundle(abi.encode(_rotatingBundle()), _anchor(KEY0, valsA), _ctx());
        assertEq(na, _anchor(KEY1, valsB));
        assertEq(naId, abi.encodePacked(KEY1));
    }

    function test_verifyConfig() public view {
        TonVerifier.ConfigProof memory p;
        p.validators = valsA;
        p.keyBlocks = new TonVerifier.McBlock[](0);
        (p.block, p.state) = _chain(7, KEY0, keysA, 1);
        p.controlMessage = control;
        (
            bytes memory ctx,
            string memory chainId,
            bytes memory svc,
            uint96 nanos,,
            bytes memory anchor,
            bytes memory anchorId,
            ClprTypes.ClprEndpointManifest memory man
        ) = v.verifyConfig(abi.encode(p), CHANNEL, manifest);
        assertEq(ctx, _ctx());
        assertEq(chainId, CHAIN);
        assertEq(svc, _svc());
        assertEq(nanos, 1_790_000_000_000_000_123);
        assertEq(anchor, _anchor(KEY0, valsA));
        assertEq(anchorId, abi.encodePacked(KEY0));
        assertEq(man.version, 4);
    }

    function test_validatorSetFromKeyBlock() public view {
        bytes memory boc = _blockBoc(KEY1, KEY0, keccak256("k"), 3, valsB);
        TonCells.Boc memory b = TonCells.parse(boc);
        (bytes memory packed, uint256 total) = TonBlocks.keyBlockValidators(b, b.root);
        assertEq(packed, valsB);
        assertEq(total, 100);
    }

    // ── negative cases ──────────────────────────────────────────────────────

    function test_rejects_badSignature() public {
        TonVerifier.BundleProof memory p = _bundle(0);
        p.block.sigs.signatures[0] = ed.sign(keysA[2], "other");
        _expectBundleRevert(
            abi.encode(p),
            _anchor(KEY0, valsA),
            _ctx(),
            abi.encodeWithSelector(ClprEd25519Check.BadSignature.selector, 2)
        );
    }

    function test_rejects_belowThreshold() public {
        TonVerifier.BundleProof memory p = _bundle(0);
        bytes memory boc = p.block.boc;
        p.block = _sign(boc, 160, keysA, _s(1, 3), 0); // 20 + 40 of 100
        _expectBundleRevert(
            abi.encode(p),
            _anchor(KEY0, valsA),
            _ctx(),
            abi.encodeWithSelector(TonVerifier.InsufficientWeight.selector, 60, 100)
        );
    }

    function test_rejects_wrongValidatorSet() public {
        TonVerifier.BundleProof memory p = _bundle(0);
        p.validators = valsB;
        _expectBundleRevert(
            abi.encode(p), _anchor(KEY0, valsA), _ctx(), abi.encodePacked(TonVerifier.ValidatorsMismatch.selector)
        );
    }

    function test_rejects_staleAnchorAfterRotation() public {
        // a block whose previous key block is K0 is not accepted once the anchor moved to K1
        TonVerifier.BundleProof memory p = _bundle(0);
        p.validators = valsB;
        _expectBundleRevert(
            abi.encode(p),
            _anchor(KEY1, valsB),
            _ctx(),
            abi.encodeWithSelector(TonVerifier.WrongKeyBlock.selector, KEY1, KEY0)
        );
    }

    function test_rejects_rotationSignedByWrongSet() public {
        TonVerifier.BundleProof memory p = _rotatingBundle();
        p.keyBlocks[0] = _sign(p.keyBlocks[0].boc, KEY1, keysB, _s(2, 3), 1);
        _expectBundleRevert(
            abi.encode(p),
            _anchor(KEY0, valsA),
            _ctx(),
            abi.encodeWithSelector(ClprEd25519Check.BadSignature.selector, 2)
        );
    }

    function test_rejects_nonKeyBlockAsHop() public {
        TonVerifier.BundleProof memory p = _rotatingBundle();
        p.keyBlocks[0] = _sign(_blockBoc(KEY1, KEY0, keccak256("k"), 3, ""), KEY1, keysA, _s(2, 3), 1);
        _expectBundleRevert(
            abi.encode(p), _anchor(KEY0, valsA), _ctx(), abi.encodePacked(TonVerifier.NotKeyBlock.selector)
        );
    }

    function test_rejects_candidateForOtherBlock() public {
        TonVerifier.BundleProof memory p = _bundle(1);
        bytes memory c = p.block.sigs.candidate;
        c[20] = bytes1(uint8(c[20]) ^ 1); // root hash in the candidate
        _expectBundleRevert(
            abi.encode(p), _anchor(KEY0, valsA), _ctx(), abi.encodePacked(TonVerifier.BadCandidate.selector)
        );
    }

    function test_rejects_tamperedAccountState() public {
        TonVerifier.BundleProof memory p = _bundle(0);
        p.state.account = _accountBoc(keccak256(control), keccak256(manifest), 9); // next id 7 → 9
        bytes memory enc = abi.encode(p);
        bytes memory anchor = _anchor(KEY0, valsA);
        vm.expectPartialRevert(TonCells.RootHashMismatch.selector);
        v.verifyBundle(enc, anchor, _ctx());
    }

    function test_rejects_wrongChannel() public {
        bytes memory ctx = ClprTypes.encodeChannelContext(ClprTypes.ChannelContext(keccak256("x"), _svc()));
        _expectBundleRevert(
            abi.encode(_bundle(0)), _anchor(KEY0, valsA), ctx, abi.encodePacked(TonCells.KeyNotFound.selector)
        );
    }

    function test_rejects_wrongService() public {
        bytes memory ctx = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext(CHANNEL, abi.encodePacked(uint8(0xff), keccak256("x")))
        );
        _expectBundleRevert(
            abi.encode(_bundle(0)), _anchor(KEY0, valsA), ctx, abi.encodePacked(TonCells.KeyNotFound.selector)
        );
    }

    function test_rejects_manifestMismatch() public {
        TonVerifier.BundleProof memory p = _bundle(0);
        p.manifestPreimage = NearTonFixtures.manifest(_svc(), 5);
        _expectBundleRevert(
            abi.encode(p),
            _anchor(KEY0, valsA),
            _ctx(),
            abi.encodePacked(ClprEvmBundleVerifier.ManifestCommitmentMismatch.selector)
        );
    }

    function test_rejects_uncachedSignature() public {
        TonVerifier.BundleProof memory p = _bundle(0);
        p.block.sigs.signatures[1] = "";
        _expectBundleRevert(
            abi.encode(p),
            _anchor(KEY0, valsA),
            _ctx(),
            abi.encodeWithSelector(ClprEd25519Check.SignatureNotCached.selector, 3)
        );
    }

    function test_rejects_corruptBoc() public {
        TonVerifier.BundleProof memory p = _bundle(0);
        p.block.boc[0] = 0x00;
        _expectBundleRevert(
            abi.encode(p), _anchor(KEY0, valsA), _ctx(), abi.encodeWithSelector(TonCells.BocMalformed.selector, 1)
        );
    }

    function test_config_rejects_wrongChain() public {
        TonVerifier.ConfigProof memory p;
        p.validators = valsA;
        p.keyBlocks = new TonVerifier.McBlock[](0);
        (p.block, p.state) = _chain(7, KEY0, keysA, 1);
        p.controlMessage = NearTonFixtures.controlMessage("ton:mainnet", _svc());
        bytes memory enc = abi.encode(p);
        vm.expectRevert(ClprNearTonBundleVerifier.WrongChainId.selector);
        v.verifyConfig(enc, CHANNEL, "");
    }

    function test_config_rejects_unprovenConfig() public {
        TonVerifier.ConfigProof memory p;
        p.validators = valsA;
        p.keyBlocks = new TonVerifier.McBlock[](0);
        (p.block, p.state) = _chain(7, KEY0, keysA, 1);
        // same chain id and service, different throttles: not the committed configuration
        p.controlMessage = abi.encodePacked(control);
        p.controlMessage[p.controlMessage.length - 1] = bytes1(uint8(p.controlMessage[p.controlMessage.length - 1]) ^ 1);
        bytes memory enc = abi.encode(p);
        vm.expectRevert();
        v.verifyConfig(enc, CHANNEL, "");
    }
}
