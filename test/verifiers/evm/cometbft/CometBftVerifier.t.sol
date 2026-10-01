// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {CometBftVerifier} from "@hiero-ledger/clpr/verifiers/evm/cometbft/CometBftVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {Ics23Lib} from "@hiero-ledger/clpr/libraries/proof/cometbft/Ics23Lib.sol";
import {CometBftSyntheticChain} from "@test/helpers/CometBftSyntheticChain.sol";

/// @notice CometBftVerifier on a synthetic chain with real signatures. The secp256k1eth profile
///         (Heimdall v2's scheme) runs every commit check through `ecrecover`; one Ed25519 profile
///         runs through the deployed pure-Solidity Ed25519Verifier.
contract CometBftVerifierTest is CometBftSyntheticChain {
    CometBftVerifier internal verifier;

    Val[] internal setA; // powers 40/30/20/10 → 2 signers clear 2/3
    Val[] internal setB;
    bytes32 internal hashA;
    bytes32 internal hashB;

    address internal constant SERVICE = address(0xC1C1c1c1C1C1C1c1c1C1C1C1c1C1C1C1c1C1c1c1);
    bytes32 internal constant CHANNEL = keccak256("channel-1");
    uint8 internal constant PREFIX = 0x02;
    uint64 internal constant ANCHOR_HEIGHT = 100;

    function setUp() public {
        setA.push(_secpVal("a0", 40));
        setA.push(_secpVal("a1", 30));
        setA.push(_secpVal("a2", 20));
        setA.push(_secpVal("a3", 10));
        setB.push(_secpVal("b0", 50));
        setB.push(_secpVal("b1", 25));
        setB.push(_secpVal("b2", 25));
        hashA = _setHash(setA);
        hashB = _setHash(setB);
        verifier = new CometBftVerifier(_profile(CometBftVerifier.KeyScheme.SECP256K1_ETH, address(0), hashA));
    }

    function _profile(CometBftVerifier.KeyScheme scheme, address ed, bytes32 bootstrap)
        internal
        pure
        returns (CometBftVerifier.Profile memory)
    {
        return CometBftVerifier.Profile({
            chainId: CHAIN,
            storeKey: bytes("evm"),
            evmStateKeyPrefix: PREFIX,
            keyScheme: scheme,
            ed25519Verifier: ed,
            bootstrapValidatorsHash: bootstrap,
            bootstrapHeight: ANCHOR_HEIGHT
        });
    }

    // ── Fixture builders ──────────────────────────────────────────────────────

    struct Bundle {
        Block blk;
        bytes multistore;
        bytes[] entries;
        bytes32[] values;
    }

    function _values(uint64 nextMessageId) internal pure returns (bytes32[] memory v) {
        v = new bytes32[](5);
        v[0] = bytes32((uint256(nextMessageId) << 168) | (uint256(1) << 160)); // status ACTIVE
        v[1] = bytes32(uint256(7) << 64); // receivedMessageId = 7
        v[2] = keccak256("sent");
        v[3] = keccak256("received");
        v[4] = bytes32(uint256(1)); // endpointManifestVersion
    }

    function _bundleState(
        int64 height,
        bytes32 valsHash,
        bytes32 nextHash,
        bytes[] memory keys,
        bytes32[] memory values
    ) internal pure returns (Bundle memory b) {
        (bytes[] memory entries, bytes32 root) = _buildLinearChainStorageProof(keys, values);
        (bytes memory ms, bytes32 appHash) = _buildMultistoreProof(root);
        b.blk = _block(height, valsHash, nextHash, appHash);
        b.multistore = ms;
        b.entries = entries;
        b.values = values;
    }

    function _defaultBundle(int64 height, bytes32 nextHash) internal pure returns (Bundle memory) {
        return _bundleState(height, bytes32(0), nextHash, _channelKeys(PREFIX, SERVICE, CHANNEL), _values(3));
    }

    function _payload(bytes memory stateProof, Val[] memory vals, bytes[] memory hops)
        internal
        pure
        returns (bytes memory out)
    {
        out = abi.encodePacked(
            PB.encodeBytesField(1, stateProof),
            PB.encodeBytesField(2, PB.encodeBytesField(2, hex"deadbeef")),
            PB.encodeBytesField(3, _encodeSet(vals))
        );
        for (uint256 i; i < hops.length; ++i) {
            out = abi.encodePacked(out, PB.encodeBytesField(6, hops[i]));
        }
    }

    function _ctx() internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: CHANNEL, remoteServiceAddress: abi.encodePacked(SERVICE)})
        );
    }

    /// @dev Bundle at `height` signed by `vals` (as signers), with set hash `valsHash`.
    function _signedBundle(
        int64 height,
        Val[] memory vals,
        uint256[] memory signers,
        bytes32 nextHash,
        bytes[] memory sigOverride
    ) internal pure returns (bytes memory) {
        Bundle memory b = _defaultBundle(height, nextHash);
        b.blk.header.validatorsHash = _setHash(vals);
        bytes memory sh = _signedHeader(b.blk, vals, signers, sigOverride);
        return _payload(_stateProof(sh, b.multistore, b.entries), vals, new bytes[](0));
    }

    function _happy() internal view returns (bytes memory) {
        return _signedBundle(120, setA, _idx(0, 1), hashA, new bytes[](0));
    }

    function _verify(bytes memory proof) internal view returns (ClprTypes.QueueMetadata memory m, bytes memory na) {
        bytes[] memory payloads;
        (m, payloads, na,,) = verifier.verifyBundle(proof, _anchor(hashA, ANCHOR_HEIGHT), _ctx());
        assertEq(payloads.length, 1);
        assertEq(payloads[0], hex"deadbeef");
    }

    function _call(bytes memory proof) internal view {
        verifier.verifyBundle(proof, _anchor(hashA, ANCHOR_HEIGHT), _ctx());
    }

    // ── Happy paths ───────────────────────────────────────────────────────────

    function test_verifyBundle_secp256k1eth_quorum() public view {
        (ClprTypes.QueueMetadata memory m, bytes memory na) = _verify(_happy());
        assertEq(m.nextMessageId, 3);
        assertEq(m.receivedMessageId, 7);
        assertEq(uint8(m.state), 1);
        assertEq(m.sentRunningHash, keccak256("sent"));
        assertEq(m.receivedRunningHash, keccak256("received"));
        assertEq(m.endpointManifestVersion, 1);
        assertEq(na.length, 0, "no rotation");
    }

    function test_verifyBundle_extraSignaturesPastQuorumAreIgnored() public view {
        // 3 signers; quorum is met after two, the third (corrupted) is never checked or counted.
        bytes[] memory o = new bytes[](3);
        o[2] = new bytes(65);
        _verify(_signedBundle(120, setA, _idx(0, 1, 2), hashA, o));
    }

    function test_verifyBundle_rotationReturnsNewAnchor() public view {
        bytes memory proof = _signedBundle(150, setA, _idx(0, 1), hashB, new bytes[](0));
        (, bytes memory na) = _verify(proof);
        assertEq(na, _anchor(hashB, 151));

        // The next bundle is signed by B against the new anchor.
        bytes memory next = _signedBundle(160, setB, _idx(0, 1), hashB, new bytes[](0));
        (,, bytes memory na2,,) = verifier.verifyBundle(next, na, _ctx());
        assertEq(na2.length, 0);
    }

    function test_verifyBundle_hopsCatchUpAcrossRotation() public view {
        // Anchor trusts A from 100. At 130 A hands over to B; the bundle at 200 is signed by B.
        Block memory hopBlk = _block(130, hashA, hashB, keccak256("app"));
        bytes[] memory hops = new bytes[](1);
        hops[0] = _hop(setA, _signedHeader(hopBlk, setA, _idx(0, 1)));

        Bundle memory b = _defaultBundle(200, hashB);
        b.blk.header.validatorsHash = hashB;
        bytes memory proof =
            _payload(_stateProof(_signedHeader(b.blk, setB, _idx(0, 1)), b.multistore, b.entries), setB, hops);
        (,, bytes memory na,,) = verifier.verifyBundle(proof, _anchor(hashA, ANCHOR_HEIGHT), _ctx());
        assertEq(na, _anchor(hashB, 201));
    }

    function test_verifyBundle_messageBearingSixthSlot() public view {
        bytes[] memory keys = new bytes[](6);
        bytes[] memory five = _channelKeys(PREFIX, SERVICE, CHANNEL);
        for (uint256 i; i < 5; ++i) {
            keys[i] = five[i];
        }
        bytes32 qBase = keccak256(abi.encode(CHANNEL, uint256(1)));
        keys[5] = abi.encodePacked(PREFIX, SERVICE, bytes32(uint256(keccak256(abi.encode(uint64(2), qBase))) + 1));
        bytes32[] memory vals = new bytes32[](6);
        bytes32[] memory base = _values(3);
        for (uint256 i; i < 5; ++i) {
            vals[i] = base[i];
        }
        vals[5] = keccak256("rh2");
        Bundle memory b = _bundleState(120, hashA, hashA, keys, vals);
        bytes memory proof = _payload(
            _stateProof(_signedHeader(b.blk, setA, _idx(0, 1)), b.multistore, b.entries), setA, new bytes[](0)
        );
        _verify(proof);
    }

    // ── Signatures and quorum ────────────────────────────────────────────────

    function test_revert_badSignature() public {
        bytes memory proof = _happy();
        // Flip one byte inside the first signature (the commit is near the end of the header).
        bytes memory good = _signedBundle(120, setA, _idx(0, 1), hashA, new bytes[](0));
        bytes[] memory o = new bytes[](1);
        Block memory blk = _defaultBundle(120, hashA).blk;
        blk.header.validatorsHash = hashA;
        bytes memory sig = _sign(setA[0], _signBytes(blk, blk.header.timeSeconds + 1));
        sig[10] ^= 0x01;
        o[0] = sig;
        proof = _signedBundle(120, setA, _idx(0, 1), hashA, o);
        assertTrue(keccak256(proof) != keccak256(good));
        vm.expectRevert(CometBftVerifier.InvalidSignature.selector);
        _call(proof);
    }

    function test_revert_signatureFromAnotherValidator() public {
        Block memory blk = _defaultBundle(120, hashA).blk;
        blk.header.validatorsHash = hashA;
        bytes[] memory o = new bytes[](1);
        o[0] = _sign(setA[2], _signBytes(blk, blk.header.timeSeconds + 1)); // a2 signs, slot claims a0
        bytes memory r1 = _signedBundle(120, setA, _idx(0, 1), hashA, o);
        vm.expectRevert(CometBftVerifier.InvalidSignature.selector);
        _call(r1);
    }

    function test_revert_signatureOverAnotherBlock() public {
        Block memory other = _defaultBundle(121, hashA).blk;
        other.header.validatorsHash = hashA;
        bytes[] memory o = new bytes[](1);
        o[0] = _sign(setA[0], _signBytes(other, other.header.timeSeconds + 1));
        bytes memory r2 = _signedBundle(120, setA, _idx(0, 1), hashA, o);
        vm.expectRevert(CometBftVerifier.InvalidSignature.selector);
        _call(r2);
    }

    function test_revert_highS() public {
        Block memory blk = _defaultBundle(120, hashA).blk;
        blk.header.validatorsHash = hashA;
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(setA[0].secpKey, keccak256(_signBytes(blk, blk.header.timeSeconds + 1)));
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes[] memory o = new bytes[](1);
        o[0] = abi.encodePacked(r, bytes32(n - uint256(s)), v == 27 ? uint8(1) : uint8(0)); // malleated twin
        bytes memory r3 = _signedBundle(120, setA, _idx(0, 1), hashA, o);
        vm.expectRevert(CometBftVerifier.InvalidSignature.selector);
        _call(r3);
    }

    function test_revert_belowThreshold() public {
        // 40 + 20 = 60 of 100: not > 2/3.
        bytes memory r4 = _signedBundle(120, setA, _idx(0, 2), hashA, new bytes[](0));
        vm.expectRevert(CometBftVerifier.QuorumNotMet.selector);
        _call(r4);
    }

    function test_revert_exactlyTwoThirdsIsNotEnough() public {
        Val[] memory s = new Val[](3);
        s[0] = setA[0];
        s[1] = setA[0];
        s[2] = setA[0];
        s[0] = _secpVal("t0", 1);
        s[1] = _secpVal("t1", 1);
        s[2] = _secpVal("t2", 1);
        bytes32 h = _setHash(s);
        bytes memory proof = _signedBundle(120, s, _idx(0, 1), h, new bytes[](0));
        vm.expectRevert(CometBftVerifier.QuorumNotMet.selector);
        verifier.verifyBundle(proof, _anchor(h, ANCHOR_HEIGHT), _ctx());
    }

    function test_revert_signersBitsShape() public {
        bytes memory proof = _happy();
        // Same bundle but the commit claims 3 signers with only 2 signatures.
        Bundle memory b = _defaultBundle(120, hashA);
        b.blk.header.validatorsHash = hashA;
        bytes memory sh = _signedHeader(b.blk, setA, _idx(0, 1));
        // bits byte is the 0x22 0x01 <bits> field inside the commit; find "2201c0" and set to e0.
        bytes memory needle = hex"2201c0";
        uint256 at = _find(sh, needle);
        sh[at + 2] = 0xe0;
        proof = _payload(_stateProof(sh, b.multistore, b.entries), setA, new bytes[](0));
        vm.expectRevert(CometBftVerifier.TooFewSignatures.selector);
        _call(proof);

        sh[at + 2] = 0x80;
        proof = _payload(_stateProof(sh, b.multistore, b.entries), setA, new bytes[](0));
        vm.expectRevert(CometBftVerifier.ExtraSignatures.selector);
        _call(proof);

        sh[at + 2] = 0xc1; // padding bit beyond the 4 validators
        proof = _payload(_stateProof(sh, b.multistore, b.entries), setA, new bytes[](0));
        vm.expectRevert(CometBftVerifier.SignersBitOutOfRange.selector);
        _call(proof);
    }

    // ── Validator set / anchor ───────────────────────────────────────────────

    function test_revert_wrongValidatorSet() public {
        // A bundle validly signed by B, presented against an anchor that trusts A.
        bytes memory proof = _signedBundle(120, setB, _idx(0, 1), hashB, new bytes[](0));
        vm.expectRevert(CometBftVerifier.ValidatorSetHashMismatch.selector);
        _call(proof);
    }

    function test_revert_tamperedVotingPower() public {
        Val[] memory forged = new Val[](4);
        for (uint256 i; i < 4; ++i) {
            forged[i] = setA[i];
        }
        // Inflate a0's power in the supplied leaf so a0 alone would clear 2/3.
        forged[0].leaf[forged[0].leaf.length - 1] = 0x7f;
        Bundle memory b = _defaultBundle(120, hashA);
        b.blk.header.validatorsHash = hashA;
        bytes memory proof =
            _payload(_stateProof(_signedHeader(b.blk, setA, _idx(0)), b.multistore, b.entries), forged, new bytes[](0));
        vm.expectRevert(CometBftVerifier.ValidatorSetHashMismatch.selector);
        _call(proof);
    }

    function test_revert_staleSetAfterRotation() public {
        // After rotating to B (anchor = B@151), a bundle still signed by A is rejected.
        bytes memory proof = _signedBundle(160, setA, _idx(0, 1), hashA, new bytes[](0));
        vm.expectRevert(CometBftVerifier.ValidatorSetHashMismatch.selector);
        verifier.verifyBundle(proof, _anchor(hashB, 151), _ctx());
    }

    function test_revert_staleHeight() public {
        bytes memory proof = _signedBundle(99, setA, _idx(0, 1), hashA, new bytes[](0));
        vm.expectRevert(CometBftVerifier.HeightTooOld.selector);
        _call(proof);
    }

    function test_revert_replayedHopBelowAnchorHeight() public {
        // A hop header from before the anchor height cannot be replayed to move the anchor.
        Block memory hopBlk = _block(90, hashA, hashB, keccak256("app"));
        bytes[] memory hops = new bytes[](1);
        hops[0] = _hop(setA, _signedHeader(hopBlk, setA, _idx(0, 1)));
        Bundle memory b = _defaultBundle(200, hashB);
        b.blk.header.validatorsHash = hashB;
        bytes memory proof =
            _payload(_stateProof(_signedHeader(b.blk, setB, _idx(0, 1)), b.multistore, b.entries), setB, hops);
        vm.expectRevert(CometBftVerifier.HeightTooOld.selector);
        _call(proof);
    }

    function test_revert_bundleBelowHopHeight() public {
        Block memory hopBlk = _block(130, hashA, hashB, keccak256("app"));
        bytes[] memory hops = new bytes[](1);
        hops[0] = _hop(setA, _signedHeader(hopBlk, setA, _idx(0, 1)));
        Bundle memory b = _defaultBundle(130, hashB); // B only signs from 131
        b.blk.header.validatorsHash = hashB;
        bytes memory proof =
            _payload(_stateProof(_signedHeader(b.blk, setB, _idx(0, 1)), b.multistore, b.entries), setB, hops);
        vm.expectRevert(CometBftVerifier.HeightTooOld.selector);
        _call(proof);
    }

    function test_revert_wrongChainId() public {
        Bundle memory b = _defaultBundle(120, hashA);
        b.blk.header.validatorsHash = hashA;
        b.blk.header.chainId = "otherchain_1-1";
        bytes memory proof = _payload(
            _stateProof(_signedHeader(b.blk, setA, _idx(0, 1)), b.multistore, b.entries), setA, new bytes[](0)
        );
        vm.expectRevert(CometBftVerifier.ChainIdMismatch.selector);
        _call(proof);
    }

    function test_revert_badAnchor() public {
        bytes memory proof = _happy();
        vm.expectRevert(CometBftVerifier.InvalidTrustAnchor.selector);
        verifier.verifyBundle(proof, abi.encodePacked(hashA), _ctx());
        vm.expectRevert(CometBftVerifier.InvalidTrustAnchor.selector);
        verifier.verifyBundle(proof, _anchor(bytes32(0), 1), _ctx());
    }

    function test_revert_malformedLeaf() public {
        Val[] memory s = new Val[](4);
        for (uint256 i; i < 4; ++i) {
            s[i] = setA[i];
        }
        s[1].leaf = abi.encodePacked(s[1].leaf, hex"00"); // trailing byte
        Bundle memory b = _defaultBundle(120, hashA);
        b.blk.header.validatorsHash = hashA;
        bytes memory proof =
            _payload(_stateProof(_signedHeader(b.blk, setA, _idx(0, 1)), b.multistore, b.entries), s, new bytes[](0));
        vm.expectRevert(CometBftVerifier.InvalidValidatorLeaf.selector);
        _call(proof);
    }

    // ── Storage proofs ───────────────────────────────────────────────────────

    function _withKeys(bytes[] memory keys, bytes32[] memory values) internal view returns (bytes memory) {
        Bundle memory b = _bundleState(120, hashA, hashA, keys, values);
        return
            _payload(_stateProof(_signedHeader(b.blk, setA, _idx(0, 1)), b.multistore, b.entries), setA, new bytes[](0));
    }

    function test_revert_wrongStorageValue() public {
        Bundle memory b = _defaultBundle(120, hashA);
        b.blk.header.validatorsHash = hashA;
        // Swap entry 0 for one proving a different value under a different root.
        bytes[] memory keys = _channelKeys(PREFIX, SERVICE, CHANNEL);
        bytes32[] memory forged = _values(99);
        (bytes[] memory other,) = _buildLinearChainStorageProof(keys, forged);
        b.entries[0] = other[0];
        bytes memory proof = _payload(
            _stateProof(_signedHeader(b.blk, setA, _idx(0, 1)), b.multistore, b.entries), setA, new bytes[](0)
        );
        vm.expectRevert(Ics23Lib.RootMismatch.selector);
        _call(proof);
    }

    function test_revert_otherChannelSlots() public {
        bytes memory r5 = _withKeys(_channelKeys(PREFIX, SERVICE, keccak256("channel-2")), _values(3));
        vm.expectRevert(CometBftVerifier.StorageKeyMismatch.selector);
        _call(r5);
    }

    function test_revert_otherServiceAddress() public {
        bytes memory r6 = _withKeys(_channelKeys(PREFIX, address(0xBEEF), CHANNEL), _values(3));
        vm.expectRevert(CometBftVerifier.StorageKeyMismatch.selector);
        _call(r6);
    }

    function test_revert_wrongKeyPrefix() public {
        // Sei's 0x03 layout presented to an Ethermint (0x02) profile.
        bytes memory r7 = _withKeys(_channelKeys(0x03, SERVICE, CHANNEL), _values(3));
        vm.expectRevert(CometBftVerifier.StorageKeyMismatch.selector);
        _call(r7);
    }

    function test_revert_wrongStoreKey() public {
        Bundle memory b = _defaultBundle(120, hashA);
        b.blk.header.validatorsHash = hashA;
        bytes memory sp = abi.encodePacked(
            PB.encodeBytesField(1, _signedHeader(b.blk, setA, _idx(0, 1))),
            PB.encodeBytesField(2, bytes("bank")),
            PB.encodeBytesField(3, b.multistore)
        );
        bytes memory r8 = _payload(sp, setA, new bytes[](0));
        vm.expectRevert(CometBftVerifier.InvalidStoreKey.selector);
        _call(r8);
    }

    function test_revert_appHashMismatch() public {
        Bundle memory b = _defaultBundle(120, hashA);
        b.blk.header.validatorsHash = hashA;
        b.blk.header.appHash = keccak256("another state");
        bytes memory proof = _payload(
            _stateProof(_signedHeader(b.blk, setA, _idx(0, 1)), b.multistore, b.entries), setA, new bytes[](0)
        );
        vm.expectRevert(Ics23Lib.RootMismatch.selector);
        _call(proof);
    }

    function test_revert_tooFewEntries() public {
        bytes[] memory keys = new bytes[](4);
        bytes32[] memory vals = new bytes32[](4);
        bytes[] memory five = _channelKeys(PREFIX, SERVICE, CHANNEL);
        for (uint256 i; i < 4; ++i) {
            keys[i] = five[i];
            vals[i] = bytes32(i + 1);
        }
        bytes memory r9 = _withKeys(keys, vals);
        vm.expectRevert(CometBftVerifier.StorageProofFailed.selector);
        _call(r9);
    }

    // ── verifyConfig ─────────────────────────────────────────────────────────

    function _ledgerConfig(address service) internal pure returns (bytes memory) {
        ClprTypes.Throttles memory t;
        t.maxMessagesPerBundle = 10;
        return abi.encodePacked(
            PB.encodeBytesField(1, bytes(CHAIN)),
            PB.encodeBytesField(2, abi.encodePacked(service)),
            PB.encodeVarintField(3, 42),
            PB.encodeBytesField(4, _buildThrottlesBytes(t))
        );
    }

    function _configProof(Val[] memory signedBy, uint256 slot, bytes32 value, bytes[] memory hops, int64 height)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory keys = new bytes[](1);
        keys[0] = abi.encodePacked(PREFIX, SERVICE, bytes32(slot));
        bytes32[] memory vals = new bytes32[](1);
        vals[0] = value;
        Bundle memory b = _bundleState(height, _setHash(signedBy), _setHash(signedBy), keys, vals);
        bytes memory out = abi.encodePacked(
            PB.encodeBytesField(1, _encodeSet(signedBy)),
            PB.encodeBytesField(2, _ledgerConfig(SERVICE)),
            PB.encodeBytesField(3, _stateProof(_signedHeader(b.blk, signedBy, _idx(0, 1)), b.multistore, b.entries))
        );
        for (uint256 i; i < hops.length; ++i) {
            out = abi.encodePacked(out, PB.encodeBytesField(4, hops[i]));
        }
        return out;
    }

    function _serviceSlotValue() internal pure returns (bytes32) {
        return bytes32(uint256(bytes32(bytes20(SERVICE))) | 0x28);
    }

    function test_verifyConfig_fromBootstrap() public view {
        (
            bytes memory ctx,
            string memory chainId,
            bytes memory service,
            uint96 nanos,
            ClprTypes.Throttles memory t,
            bytes memory anchor,
            bytes memory anchorId,
            ClprTypes.ClprEndpointManifest memory m
        ) = verifier.verifyConfig(_configProof(setA, 25, _serviceSlotValue(), new bytes[](0), 110), CHANNEL, "");
        assertEq(ctx, _ctx());
        assertEq(chainId, CHAIN);
        assertEq(service, abi.encodePacked(SERVICE));
        assertEq(nanos, 42);
        assertEq(t.maxMessagesPerBundle, 10);
        assertEq(anchor, _anchor(hashA, 111));
        assertEq(anchorId, anchor);
        assertEq(m.version, 0);
    }

    function test_verifyConfig_hopsFromBootstrap() public view {
        Block memory hopBlk = _block(105, hashA, hashB, keccak256("app"));
        bytes[] memory hops = new bytes[](1);
        hops[0] = _hop(setA, _signedHeader(hopBlk, setA, _idx(0, 1)));
        (,,,,, bytes memory anchor,,) =
            verifier.verifyConfig(_configProof(setB, 25, _serviceSlotValue(), hops, 300), CHANNEL, "");
        assertEq(anchor, _anchor(hashB, 301));
    }

    function test_revert_verifyConfig_selfSuppliedValidatorSet() public {
        // A config proof whose own validator set (B) signs everything is NOT trusted: bootstrap is A.
        bytes memory r10 = _configProof(setB, 25, _serviceSlotValue(), new bytes[](0), 110);
        vm.expectRevert(CometBftVerifier.ValidatorSetHashMismatch.selector);
        verifier.verifyConfig(r10, CHANNEL, "");
    }

    function test_revert_verifyConfig_wrongSlotOrValue() public {
        bytes memory r11 = _configProof(setA, 24, _serviceSlotValue(), new bytes[](0), 110);
        vm.expectRevert(CometBftVerifier.ServiceAddressSlotMismatch.selector);
        verifier.verifyConfig(r11, CHANNEL, "");
        bytes memory r12 = _configProof(setA, 25, keccak256("x"), new bytes[](0), 110);
        vm.expectRevert(CometBftVerifier.ServiceAddressSlotMismatch.selector);
        verifier.verifyConfig(r12, CHANNEL, "");
    }

    function test_revert_verifyConfig_beforeBootstrapHeight() public {
        bytes memory r13 = _configProof(setA, 25, _serviceSlotValue(), new bytes[](0), 99);
        vm.expectRevert(CometBftVerifier.HeightTooOld.selector);
        verifier.verifyConfig(r13, CHANNEL, "");
    }

    function test_revert_verifyConfig_empty() public {
        vm.expectRevert(CometBftVerifier.InvalidPayloadShape.selector);
        verifier.verifyConfig("", CHANNEL, "");
    }

    // ── Profile ──────────────────────────────────────────────────────────────

    function test_revert_invalidProfile() public {
        vm.expectRevert(CometBftVerifier.InvalidProfile.selector);
        new CometBftVerifier(_profile(CometBftVerifier.KeyScheme.ED25519, address(0), hashA));
        vm.expectRevert(CometBftVerifier.InvalidProfile.selector);
        new CometBftVerifier(_profile(CometBftVerifier.KeyScheme.SECP256K1_ETH, address(0), bytes32(0)));
        CometBftVerifier.Profile memory p = _profile(CometBftVerifier.KeyScheme.SECP256K1_ETH, address(0), hashA);
        p.chainId = "";
        vm.expectRevert(CometBftVerifier.InvalidProfile.selector);
        new CometBftVerifier(p);
    }

    function _find(bytes memory hay, bytes memory needle) internal pure returns (uint256) {
        for (uint256 i; i + needle.length <= hay.length; ++i) {
            bool ok = true;
            for (uint256 j; j < needle.length; ++j) {
                if (hay[i + j] != needle[j]) {
                    ok = false;
                    break;
                }
            }
            if (ok) return i;
        }
        revert("needle not found");
    }
}
