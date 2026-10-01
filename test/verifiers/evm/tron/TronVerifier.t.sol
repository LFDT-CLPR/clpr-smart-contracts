// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {TronTestBuilder} from "./TronTestBuilder.sol";
import {TronVerifier} from "@hiero-ledger/clpr/verifiers/evm/tron/TronVerifier.sol";
import {TronLib} from "@hiero-ledger/clpr/verifiers/evm/tron/TronLib.sol";
import {IClprTronAttestor} from "@hiero-ledger/clpr/verifiers/evm/tron/ClprTronAttestor.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

contract TronVerifierTest is TronTestBuilder {
    TronVerifier internal verifier;

    address internal constant ATTESTOR = address(0xA77E5700);
    address internal constant SERVICE = address(0x5E2F1CE0);
    bytes32 internal constant CHANNEL = keccak256("tron-channel");

    uint64 internal constant PERIOD = 994_901; // a Nile period
    uint64 internal constant T0 = OFFSET + PERIOD * INTERVAL + 60_000; // 1 min into PERIOD
    uint64 internal constant N0 = 71_431_000;

    bytes32 internal constant SENT_HASH = keccak256("sent");
    bytes32 internal constant RECV_HASH = keccak256("recv");

    function setUp() public {
        verifier = new TronVerifier(N, T, INTERVAL, OFFSET, NILE);
        _initSrs();
    }

    function _anchor(uint64 period, Sr[] memory s, uint64 watermark) internal pure returns (bytes memory) {
        return abi.encode(period, _setHash(s), ATTESTOR, watermark);
    }

    function _ctx() internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: CHANNEL, remoteServiceAddress: abi.encodePacked(SERVICE)})
        );
    }

    // ── Attestation helpers ───────────────────────────────────────────────────

    struct Att {
        address target;
        address service;
        bytes32 channelId;
        uint8 status;
        uint64 nextMessageId;
        uint64 receivedMessageId;
        uint64 manifestVersion;
        bytes32 commitment;
        uint64 contractRet;
    }

    function _defaultAtt() internal pure returns (Att memory) {
        return Att({
            target: ATTESTOR,
            service: SERVICE,
            channelId: CHANNEL,
            status: 1,
            nextMessageId: 4,
            receivedMessageId: 2,
            manifestVersion: 1,
            commitment: bytes32(0),
            contractRet: 1
        });
    }

    function _attTx(Att memory a) internal pure returns (bytes memory) {
        bytes memory data = abi.encodeCall(
            IClprTronAttestor.attestQueue,
            (
                a.service,
                a.channelId,
                a.status,
                a.nextMessageId,
                SENT_HASH,
                a.receivedMessageId,
                RECV_HASH,
                a.manifestVersion,
                a.commitment
            )
        );
        return _triggerTx(address(0x0123), a.target, data, a.contractRet);
    }

    function _bundle(
        Sr[] memory set,
        bytes memory keyUpdates,
        bytes memory rotation,
        bytes memory attestation,
        bytes memory manifest
    ) internal pure returns (bytes memory) {
        bytes[] memory payloads = new bytes[](2);
        payloads[0] = hex"0a0101";
        payloads[1] = hex"0a0102";
        ClprTypes.QueueMetadata memory meta;
        bytes[] memory items = new bytes[](6);
        items[0] = _setRlp(set);
        items[1] = keyUpdates;
        items[2] = rotation;
        items[3] = attestation;
        items[4] = RLP.encode(ClprProtobuf.encodeBundleContent(meta, payloads));
        items[5] = RLP.encode(manifest);
        return _rlpList(items);
    }

    function _simpleBundle(Att memory a, Sr[] memory producers, uint8[] memory modes)
        internal
        view
        returns (bytes memory)
    {
        return
            _bundle(_set(), _rlpEmptyList(), _rlpEmptyList(), _txProof(_attTx(a), N0 + 100, T0, producers, modes), "");
    }

    function _verify(bytes memory proof, bytes memory anchor)
        internal
        view
        returns (
            ClprTypes.QueueMetadata memory m,
            bytes[] memory payloads,
            bytes memory nta,
            bytes memory ntaId,
            ClprTypes.ClprEndpointManifest memory man
        )
    {
        return verifier.verifyBundle(proof, anchor, _ctx());
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    function test_verifyBundle_acceptsNineteenDistinctSrs() public view {
        bytes memory proof = _simpleBundle(_defaultAtt(), _firstN(T), _noModes());
        uint256 g = gasleft();
        (ClprTypes.QueueMetadata memory m, bytes[] memory payloads, bytes memory nta,,) =
            _verify(proof, _anchor(PERIOD, _set(), N0));
        g -= gasleft();
        console.log("typical bundle gas (19 headers):", g, "calldata bytes:", proof.length);
        assertEq(m.nextMessageId, 4);
        assertEq(m.receivedMessageId, 2);
        assertEq(m.sentRunningHash, SENT_HASH);
        assertEq(m.receivedRunningHash, RECV_HASH);
        assertEq(uint8(m.state), 1);
        assertEq(m.endpointManifestVersion, 1);
        assertEq(payloads.length, 2);
        assertEq(nta.length, 0, "no rotation -> no new anchor");
    }

    function test_verifyBundle_fullRoundOf27() public view {
        bytes memory proof = _simpleBundle(_defaultAtt(), _firstN(N), _noModes());
        uint256 g = gasleft();
        _verify(proof, _anchor(PERIOD, _set(), N0));
        g -= gasleft();
        console.log("bundle gas (27 headers):", g, "calldata bytes:", proof.length);
    }

    function test_unsignedHeadersAreLinksNotVotes() public view {
        // 20 headers, the 3rd carries no ECDSA signature (an FN-DSA-512 block on Nile): 19 votes remain.
        uint8[] memory modes = new uint8[](20);
        modes[2] = 1;
        _verify(_simpleBundle(_defaultAtt(), _firstN(20), modes), _anchor(PERIOD, _set(), N0));
    }

    // ── Negative: finality ────────────────────────────────────────────────────

    function test_revert_belowThreshold() public {
        Sr[] memory p = _firstN(T);
        p[T - 1] = p[0]; // SR 0 signs twice: only 18 distinct
        bytes memory proof = _simpleBundle(_defaultAtt(), p, _noModes());
        vm.expectRevert(abi.encodeWithSelector(TronVerifier.InsufficientConfirmations.selector, T - 1, T));
        verifier.verifyBundle(proof, _anchor(PERIOD, _set(), N0), _ctx());
    }

    function test_revert_badSignature() public {
        uint8[] memory modes = new uint8[](T);
        modes[5] = 2; // signed by a key that is not SR 5's
        bytes memory proof = _simpleBundle(_defaultAtt(), _firstN(T), modes);
        vm.expectRevert(abi.encodeWithSelector(TronVerifier.InsufficientConfirmations.selector, T - 1, T));
        verifier.verifyBundle(proof, _anchor(PERIOD, _set(), N0), _ctx());
    }

    function test_revert_unsignedHeaderBelowThreshold() public {
        uint8[] memory modes = new uint8[](T);
        modes[0] = 1;
        bytes memory proof = _simpleBundle(_defaultAtt(), _firstN(T), modes);
        vm.expectRevert(abi.encodeWithSelector(TronVerifier.InsufficientConfirmations.selector, T - 1, T));
        verifier.verifyBundle(proof, _anchor(PERIOD, _set(), N0), _ctx());
    }

    function test_revert_srSetNotInAnchor() public {
        bytes memory proof = _simpleBundle(_defaultAtt(), _firstN(T), _noModes());
        Sr[] memory other = _set();
        other[3].key = address(0xBAD);
        vm.expectRevert(TronVerifier.SrSetHashMismatch.selector);
        verifier.verifyBundle(proof, _anchor(PERIOD, other, N0), _ctx());
    }

    function test_revert_wrongValidatorSet() public {
        // A self-consistent set of 27 attacker keys, but the channel trusts the real one.
        Sr[] memory fake = new Sr[](N);
        for (uint256 i = 0; i < N; ++i) {
            uint256 pk = 0xF00D + i;
            fake[i] = Sr({witness: vm.addr(pk), pk: pk, key: vm.addr(pk)});
        }
        _sort(fake);
        Sr[] memory producers = new Sr[](T);
        for (uint256 i = 0; i < T; ++i) {
            producers[i] = fake[i];
        }
        bytes memory proof = _bundle(
            fake, _rlpEmptyList(), _rlpEmptyList(), _txProof(_attTx(_defaultAtt()), N0, T0, producers, _noModes()), ""
        );
        vm.expectRevert(TronVerifier.SrSetHashMismatch.selector);
        verifier.verifyBundle(proof, _anchor(PERIOD, _set(), N0), _ctx());

        // Real set supplied, but the headers are signed by the fake keys.
        proof = _bundle(
            _set(), _rlpEmptyList(), _rlpEmptyList(), _txProof(_attTx(_defaultAtt()), N0, T0, producers, _noModes()), ""
        );
        vm.expectRevert(abi.encodeWithSelector(TronVerifier.InsufficientConfirmations.selector, 0, T));
        verifier.verifyBundle(proof, _anchor(PERIOD, _set(), N0), _ctx());
    }

    function test_revert_brokenHeaderChain() public {
        Sr[] memory p = _firstN(T);
        bytes[] memory items = new bytes[](T);
        Hdr memory h = Hdr({number: N0, timestamp: T0, parentHash: 0, txTrieRoot: 0, witness: p[0].witness});
        for (uint256 i = 0; i < T; ++i) {
            if (i > 0) {
                h = Hdr({
                    number: h.number + 1,
                    timestamp: h.timestamp + SLOT,
                    parentHash: i == 7 ? keccak256("fork") : _blockId(h),
                    txTrieRoot: 0,
                    witness: p[i].witness
                });
            }
            bytes memory raw = _headerRaw(h);
            items[i] = _rlpHeader(raw, _sign(p[i].pk, raw));
        }
        bytes memory proof = _bundle(
            _set(), _rlpEmptyList(), _rlpEmptyList(), _rlpTxProof(_rlpList(items), hex"00", 0, 1, new bytes32[](0)), ""
        );
        vm.expectRevert(abi.encodeWithSelector(TronVerifier.HeaderChainBroken.selector, 7));
        verifier.verifyBundle(proof, _anchor(PERIOD, _set(), N0), _ctx());
    }

    // ── Negative: transaction inclusion ("storage proof") ──────────────────────

    function test_revert_wrongMerkleProof() public {
        bytes memory txBytes = _attTx(_defaultAtt());
        bytes32[] memory leaves = new bytes32[](3);
        leaves[0] = sha256("other tx 0");
        leaves[1] = sha256(txBytes);
        leaves[2] = sha256("other tx 2");
        Hdr memory first =
            Hdr({number: N0, timestamp: T0, parentHash: 0, txTrieRoot: _merkleRoot(leaves), witness: address(0)});
        (bytes memory headers,) = _chain(first, _firstN(T), _noModes());
        bytes32[] memory sib = _merkleProof(leaves, 1);
        sib[0] = keccak256("tampered");
        bytes memory proof =
            _bundle(_set(), _rlpEmptyList(), _rlpEmptyList(), _rlpTxProof(headers, txBytes, 1, 3, sib), "");
        vm.expectRevert(TronVerifier.TxRootMismatch.selector);
        verifier.verifyBundle(proof, _anchor(PERIOD, _set(), N0), _ctx());

        // Right siblings, wrong position.
        proof = _bundle(
            _set(), _rlpEmptyList(), _rlpEmptyList(), _rlpTxProof(headers, txBytes, 0, 3, _merkleProof(leaves, 1)), ""
        );
        vm.expectRevert(TronVerifier.TxRootMismatch.selector);
        verifier.verifyBundle(proof, _anchor(PERIOD, _set(), N0), _ctx());

        // Tampered transaction (different queue values) under the honest proof.
        Att memory a = _defaultAtt();
        a.nextMessageId = 99;
        proof = _bundle(
            _set(), _rlpEmptyList(), _rlpEmptyList(), _rlpTxProof(headers, _attTx(a), 1, 3, _merkleProof(leaves, 1)), ""
        );
        vm.expectRevert(TronVerifier.TxRootMismatch.selector);
        verifier.verifyBundle(proof, _anchor(PERIOD, _set(), N0), _ctx());
    }

    function test_revert_attestationReverted() public {
        Att memory a = _defaultAtt();
        a.contractRet = 2; // REVERT: the attested values did not match the TRON state
        bytes memory proof = _simpleBundle(a, _firstN(T), _noModes());
        vm.expectRevert(abi.encodeWithSelector(TronVerifier.AttestationFailed.selector, 2));
        verifier.verifyBundle(proof, _anchor(PERIOD, _set(), N0), _ctx());

        a.contractRet = 0; // no ret entry at all
        proof = _simpleBundle(a, _firstN(T), _noModes());
        vm.expectRevert(abi.encodeWithSelector(TronVerifier.AttestationFailed.selector, 0));
        verifier.verifyBundle(proof, _anchor(PERIOD, _set(), N0), _ctx());
    }

    function test_revert_wrongAttestor() public {
        Att memory a = _defaultAtt();
        a.target = address(0xE71C);
        bytes memory proof = _simpleBundle(a, _firstN(T), _noModes());
        vm.expectRevert(abi.encodeWithSelector(TronVerifier.WrongAttestor.selector, address(0xE71C)));
        verifier.verifyBundle(proof, _anchor(PERIOD, _set(), N0), _ctx());
    }

    function test_revert_wrongServiceOrChannel() public {
        Att memory a = _defaultAtt();
        a.service = address(0x5E2F1CE1);
        bytes memory proof = _simpleBundle(a, _firstN(T), _noModes());
        vm.expectRevert(TronVerifier.AttestedServiceMismatch.selector);
        verifier.verifyBundle(proof, _anchor(PERIOD, _set(), N0), _ctx());

        a = _defaultAtt();
        a.channelId = keccak256("another channel");
        proof = _simpleBundle(a, _firstN(T), _noModes());
        vm.expectRevert(TronVerifier.AttestedChannelMismatch.selector);
        verifier.verifyBundle(proof, _anchor(PERIOD, _set(), N0), _ctx());
    }

    function test_revert_invalidStatus() public {
        Att memory a = _defaultAtt();
        a.status = 6;
        bytes memory proof = _simpleBundle(a, _firstN(T), _noModes());
        vm.expectRevert(abi.encodeWithSelector(TronVerifier.InvalidChannelStatus.selector, 6));
        verifier.verifyBundle(proof, _anchor(PERIOD, _set(), N0), _ctx());
    }

    function test_revert_wrongSelectorOrContractType() public {
        bytes memory data = abi.encodeCall(IClprTronAttestor.attestManifest, (SERVICE, bytes32(0)));
        bytes memory txBytes = _triggerTx(address(1), ATTESTOR, data, 1);
        bytes memory proof =
            _bundle(_set(), _rlpEmptyList(), _rlpEmptyList(), _txProof(txBytes, N0, T0, _firstN(T), _noModes()), "");
        vm.expectRevert(TronVerifier.WrongAttestationCall.selector);
        verifier.verifyBundle(proof, _anchor(PERIOD, _set(), N0), _ctx());

        txBytes = _permissionUpdateTx(srs[0].witness, address(0x1234));
        proof = _bundle(_set(), _rlpEmptyList(), _rlpEmptyList(), _txProof(txBytes, N0, T0, _firstN(T), _noModes()), "");
        vm.expectRevert(abi.encodeWithSelector(TronVerifier.UnexpectedContractType.selector, 46));
        verifier.verifyBundle(proof, _anchor(PERIOD, _set(), N0), _ctx());
    }

    // ── Endpoint manifest ─────────────────────────────────────────────────────

    function _manifest() internal pure returns (bytes memory) {
        ClprTypes.ClprEndpointManifest memory m;
        m.version = 3;
        m.serviceAddress = abi.encodePacked(SERVICE);
        m.endpoints = new ClprTypes.Endpoint[](1);
        m.endpoints[0] = ClprTypes.Endpoint({ipAddress: "10.0.0.1", port: 50211, tlsCertificate: "", accountId: ""});
        return ClprProtobuf.encodeEndpointManifest(m);
    }

    function test_manifestBoundToAttestedCommitment() public view {
        bytes memory man = _manifest();
        Att memory a = _defaultAtt();
        a.commitment = keccak256(man);
        bytes memory proof =
            _bundle(_set(), _rlpEmptyList(), _rlpEmptyList(), _txProof(_attTx(a), N0, T0, _firstN(T), _noModes()), man);
        (,,,, ClprTypes.ClprEndpointManifest memory got) = _verify(proof, _anchor(PERIOD, _set(), N0));
        assertEq(got.version, 3);
        assertEq(got.endpoints.length, 1);
    }

    function test_revert_manifestNotCommitted() public {
        bytes memory man = _manifest();
        Att memory a = _defaultAtt();
        a.commitment = keccak256("some other manifest");
        bytes memory proof =
            _bundle(_set(), _rlpEmptyList(), _rlpEmptyList(), _txProof(_attTx(a), N0, T0, _firstN(T), _noModes()), man);
        vm.expectRevert(ClprEvmBundleVerifier.ManifestCommitmentMismatch.selector);
        verifier.verifyBundle(proof, _anchor(PERIOD, _set(), N0), _ctx());
    }

    // ── Signing-key updates ───────────────────────────────────────────────────

    function _keyUpdate(address witness, address newKey, uint64 number) internal view returns (bytes memory) {
        bytes[] memory items = new bytes[](1);
        items[0] = _txProof(_permissionUpdateTx(witness, newKey), number, T0 - 30_000, _firstN(T), _noModes());
        return _rlpList(items);
    }

    function test_keyUpdate_rotatesOneSigningKey() public view {
        // SR 0 moves to a new witness-permission key and then signs with it.
        uint256 newPk = 0x5EC0;
        Sr[] memory producers = _firstN(T);
        producers[0].pk = newPk;
        bytes memory upd = _keyUpdate(srs[0].witness, vm.addr(newPk), N0 + 10);
        bytes memory proof = _bundle(
            _set(), upd, _rlpEmptyList(), _txProof(_attTx(_defaultAtt()), N0 + 100, T0, producers, _noModes()), ""
        );
        (,, bytes memory nta, bytes memory ntaId,) = _verify(proof, _anchor(PERIOD, _set(), N0));

        Sr[] memory expected = _set();
        expected[0].key = vm.addr(newPk);
        assertEq(nta, abi.encode(PERIOD, _setHash(expected), ATTESTOR, N0 + 10));
        assertEq(ntaId, abi.encodePacked(PERIOD));
    }

    function test_revert_newKeyWithoutUpdateDoesNotCount() public {
        Sr[] memory producers = _firstN(T);
        producers[0].pk = 0x5EC0;
        bytes memory proof = _simpleBundle(_defaultAtt(), producers, _noModes());
        vm.expectRevert(abi.encodeWithSelector(TronVerifier.InsufficientConfirmations.selector, T - 1, T));
        verifier.verifyBundle(proof, _anchor(PERIOD, _set(), N0), _ctx());
    }

    function test_revert_keyUpdateReplay() public {
        bytes memory upd = _keyUpdate(srs[0].witness, address(0x5EC0), N0 + 10);
        bytes memory proof = _bundle(
            _set(), upd, _rlpEmptyList(), _txProof(_attTx(_defaultAtt()), N0 + 100, T0, _firstN(T), _noModes()), ""
        );
        // The anchor already reflects block N0 + 10.
        vm.expectRevert(abi.encodeWithSelector(TronVerifier.StaleKeyUpdate.selector, N0 + 10, N0 + 10));
        verifier.verifyBundle(proof, _anchor(PERIOD, _set(), N0 + 10), _ctx());
    }

    // ── SR-set rotation ───────────────────────────────────────────────────────

    /// @dev Next period's set: `out` leaves, the newcomer joins.
    function _nextSet(uint256 out) internal view returns (Sr[] memory s) {
        s = _set();
        s[out] = newcomer;
        _sort(s);
    }

    /// @dev Rotation proof into PERIOD+1: h0 (by `h0Producer`), a window of the next set's 27 SRs,
    ///      then `endorsers` (old-set members).
    function _rotation(Sr[] memory window, Sr[] memory endorsers, uint64 h0Ts, uint8[] memory modes)
        internal
        pure
        returns (bytes memory rlp, Hdr memory last)
    {
        Sr[] memory producers = new Sr[](1 + window.length + endorsers.length);
        producers[0] = window[0];
        for (uint256 i = 0; i < window.length; ++i) {
            producers[1 + i] = window[i];
        }
        for (uint256 i = 0; i < endorsers.length; ++i) {
            producers[1 + window.length + i] = endorsers[i];
        }
        Hdr memory first =
            Hdr({number: N0 + 600, timestamp: h0Ts, parentHash: keccak256("p"), txTrieRoot: 0, witness: address(0)});
        bytes memory headers;
        (headers, last) = _chain(first, producers, modes);
        bytes[] memory items = new bytes[](2);
        items[0] = headers;
        items[1] = RLP.encode(window.length);
        rlp = _rlpList(items);
    }

    function _endorsers(Sr[] memory nextSet, uint256 count) internal view returns (Sr[] memory e) {
        // old-set members that are still in the next set
        e = new Sr[](count);
        uint256 k;
        for (uint256 i = 0; i < nextSet.length && k < count; ++i) {
            if (nextSet[i].witness != newcomer.witness) e[k++] = nextSet[i];
        }
    }

    function _maintenanceTs() internal pure returns (uint64) {
        return OFFSET + (PERIOD + 1) * INTERVAL + 3000; // the first block of PERIOD+1 (maintenance block)
    }

    function test_rotation_replacesOneSr() public view {
        Sr[] memory next = _nextSet(26);
        (bytes memory rot, Hdr memory last) = _rotation(next, _endorsers(next, T), _maintenanceTs(), _noModes());
        // The attestation sits in a block after the rotation, confirmed by the NEW set incl. the newcomer.
        Sr[] memory producers = new Sr[](T);
        producers[0] = newcomer;
        Sr[] memory e = _endorsers(next, T - 1);
        for (uint256 i = 0; i < T - 1; ++i) {
            producers[i + 1] = e[i];
        }
        bytes memory att =
            _txProof(_attTx(_defaultAtt()), last.number + 50, last.timestamp + 150_000, producers, _noModes());
        bytes memory proof = _bundle(_set(), _rlpEmptyList(), rot, att, "");

        uint256 g = gasleft();
        (,, bytes memory nta, bytes memory ntaId,) = _verify(proof, _anchor(PERIOD, _set(), N0));
        g -= gasleft();
        console.log("rotation + bundle gas:", g, "calldata bytes:", proof.length);
        assertEq(nta, abi.encode(PERIOD + 1, _setHash(next), ATTESTOR, N0));
        assertEq(ntaId, abi.encodePacked(PERIOD + 1));

        // The next bundle runs against the rotated anchor.
        proof = _bundle(next, _rlpEmptyList(), _rlpEmptyList(), att, "");
        (,, nta,,) = _verify(proof, abi.encode(PERIOD + 1, _setHash(next), ATTESTOR, N0));
        assertEq(nta.length, 0);
    }

    function test_rotation_unsignedWindowHeaderKeepsOldKey() public view {
        // SR 3's window header carries no signature: it keeps its old key.
        Sr[] memory next = _nextSet(26);
        uint8[] memory modes = new uint8[](1 + N + T);
        uint256 victim = next[3].witness == newcomer.witness ? 4 : 3; // an old member
        modes[1 + victim] = 1;
        (bytes memory rot,) = _rotation(next, _endorsers(next, T), _maintenanceTs(), modes);
        bytes memory proof = _bundle(
            _set(),
            _rlpEmptyList(),
            rot,
            _txProof(_attTx(_defaultAtt()), N0 + 900, _maintenanceTs() + 600_000, _endorsers(next, T), _noModes()),
            ""
        );
        (,, bytes memory nta,,) = _verify(proof, _anchor(PERIOD, _set(), N0));
        assertEq(nta, abi.encode(PERIOD + 1, _setHash(next), ATTESTOR, N0));
    }

    function test_rotation_newcomerWithPermissionKey() public view {
        // The newcomer signs with a witness-permission key proven by an AccountPermissionUpdate.
        uint256 permPk = 0xC0FFEE;
        Sr memory nc = Sr({witness: newcomer.witness, pk: permPk, key: vm.addr(permPk)});
        Sr[] memory next = _set();
        next[26] = nc;
        _sort(next);
        (bytes memory rot,) = _rotation(next, _endorsers(next, T), _maintenanceTs(), _noModes());
        bytes memory proof = _bundle(
            _set(),
            _keyUpdate(nc.witness, nc.key, N0 + 10),
            rot,
            _txProof(_attTx(_defaultAtt()), N0 + 900, _maintenanceTs() + 600_000, _endorsers(next, T), _noModes()),
            ""
        );
        (,, bytes memory nta,,) = _verify(proof, _anchor(PERIOD, _set(), N0));
        assertEq(nta, abi.encode(PERIOD + 1, _setHash(next), ATTESTOR, N0 + 10));
    }

    function test_revert_rotationUnauthenticatedKey() public {
        // Same as above but without the permission-update proof.
        uint256 permPk = 0xC0FFEE;
        Sr memory nc = Sr({witness: newcomer.witness, pk: permPk, key: vm.addr(permPk)});
        Sr[] memory next = _set();
        next[26] = nc;
        _sort(next);
        (bytes memory rot,) = _rotation(next, _endorsers(next, T), _maintenanceTs(), _noModes());
        bytes memory proof = _bundle(
            _set(),
            _rlpEmptyList(),
            rot,
            _txProof(_attTx(_defaultAtt()), N0 + 900, _maintenanceTs() + 600_000, _endorsers(next, T), _noModes()),
            ""
        );
        vm.expectRevert(abi.encodeWithSelector(TronVerifier.UnauthenticatedSignerKey.selector, nc.witness, nc.key));
        verifier.verifyBundle(proof, _anchor(PERIOD, _set(), N0), _ctx());
    }

    function test_revert_rotationWindowSpansMaintenance() public {
        // h0 is the last block of PERIOD: the window could mix two schedules.
        Sr[] memory next = _nextSet(26);
        (bytes memory rot,) = _rotation(next, _endorsers(next, T), _maintenanceTs() - 6000, _noModes());
        bytes memory proof =
            _bundle(_set(), _rlpEmptyList(), rot, _txProof(_attTx(_defaultAtt()), N0, T0, _firstN(T), _noModes()), "");
        vm.expectRevert(TronVerifier.RotationPeriodMismatch.selector);
        verifier.verifyBundle(proof, _anchor(PERIOD, _set(), N0), _ctx());
    }

    function test_revert_rotationIncompleteWindow() public {
        Sr[] memory next = _nextSet(26);
        Sr[] memory window = new Sr[](N - 1);
        for (uint256 i = 0; i < N - 1; ++i) {
            window[i] = next[i];
        }
        (bytes memory rot,) = _rotation(window, _endorsers(next, T), _maintenanceTs(), _noModes());
        bytes memory proof =
            _bundle(_set(), _rlpEmptyList(), rot, _txProof(_attTx(_defaultAtt()), N0, T0, _firstN(T), _noModes()), "");
        vm.expectRevert(abi.encodeWithSelector(TronVerifier.RotationWitnessCount.selector, N - 1));
        verifier.verifyBundle(proof, _anchor(PERIOD, _set(), N0), _ctx());
    }

    function test_revert_rotationNotEndorsedByOldSet() public {
        // Window followed by only 17 old-set signatures (+ the window's last header = 18).
        Sr[] memory next = _nextSet(26);
        Sr[] memory window = next;
        // Make sure the last window header is by an old member.
        Sr[] memory e = _endorsers(next, T - 2);
        (bytes memory rot,) = _rotation(window, e, _maintenanceTs(), _noModes());
        bytes memory proof =
            _bundle(_set(), _rlpEmptyList(), rot, _txProof(_attTx(_defaultAtt()), N0, T0, _firstN(T), _noModes()), "");
        vm.expectPartialRevert(TronVerifier.InsufficientConfirmations.selector);
        verifier.verifyBundle(proof, _anchor(PERIOD, _set(), N0), _ctx());
    }

    function test_revert_rotationToOlderPeriod() public {
        Sr[] memory next = _nextSet(26);
        (bytes memory rot,) = _rotation(next, _endorsers(next, T), _maintenanceTs(), _noModes());
        bytes memory proof =
            _bundle(_set(), _rlpEmptyList(), rot, _txProof(_attTx(_defaultAtt()), N0, T0, _firstN(T), _noModes()), "");
        vm.expectRevert(abi.encodeWithSelector(TronVerifier.RotationStale.selector, PERIOD + 1, PERIOD + 2));
        verifier.verifyBundle(proof, _anchor(PERIOD + 2, _set(), N0), _ctx());
    }

    // ── verifyConfig ──────────────────────────────────────────────────────────

    function _ledgerConfig(string memory chainId) internal pure returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory lc;
        lc.protocolVersion = 1;
        lc.chainId = chainId;
        lc.serviceAddress = abi.encodePacked(SERVICE);
        lc.nanosSinceEpoch = 1_790_822_400 * 1e9;
        lc.throttles = ClprTypes.Throttles(10, 4096, 500_000, 100, 65_536, 4, 4);
        return ClprProtobuf.encodeControlMessage(lc);
    }

    function _config(Sr[] memory signers) internal view returns (bytes memory) {
        return _config(signers, NILE);
    }

    function _config(Sr[] memory signers, string memory chainId) internal view returns (bytes memory) {
        Hdr memory first =
            Hdr({number: N0, timestamp: T0, parentHash: keccak256("g"), txTrieRoot: 0, witness: address(0)});
        (bytes memory headers,) = _chain(first, signers, _noModes());
        bytes[] memory items = new bytes[](4);
        items[0] = _setRlp(_set());
        items[1] = RLP.encode(abi.encodePacked(ATTESTOR));
        items[2] = headers;
        items[3] = RLP.encode(_ledgerConfig(chainId));
        return _rlpList(items);
    }

    function test_verifyConfig() public view {
        bytes memory manifest = _manifest();
        bytes memory data = abi.encodeCall(IClprTronAttestor.attestManifest, (SERVICE, keccak256(manifest)));
        bytes[] memory mp = new bytes[](2);
        mp[0] = _txProof(_triggerTx(address(7), ATTESTOR, data, 1), N0 + 30, T0 + 90_000, _firstN(T), _noModes());
        mp[1] = RLP.encode(manifest);
        (
            bytes memory channelContext,
            string memory chainId,
            bytes memory serviceAddress,,
            ClprTypes.Throttles memory throttles,
            bytes memory anchor,
            bytes memory anchorId,
            ClprTypes.ClprEndpointManifest memory m
        ) = verifier.verifyConfig(_config(_firstN(T)), CHANNEL, _rlpList(mp));
        assertEq(channelContext, _ctx());
        assertEq(chainId, "tron:0xcd8690dc");
        assertEq(serviceAddress, abi.encodePacked(SERVICE));
        assertEq(throttles.maxMessagesPerBundle, 10);
        assertEq(anchor, abi.encode(PERIOD, _setHash(_set()), ATTESTOR, N0 + T - 1));
        assertEq(anchorId, abi.encodePacked(PERIOD));
        assertEq(m.version, 3);
    }

    function test_revert_verifyConfigWrongChain() public {
        bytes memory cfg = _config(_firstN(T), "tron:0x2b6653dc");
        vm.expectRevert(abi.encodeWithSelector(TronVerifier.WrongChain.selector, "tron:0x2b6653dc"));
        verifier.verifyConfig(cfg, CHANNEL, "");
    }

    function test_revert_verifyConfigUnconfirmedSet() public {
        bytes memory cfg = _config(_firstN(T - 1));
        vm.expectRevert(abi.encodeWithSelector(TronVerifier.InsufficientConfirmations.selector, T - 1, T));
        verifier.verifyConfig(cfg, CHANNEL, "");
    }

    // ── Constructor ───────────────────────────────────────────────────────────

    function test_revert_constructorRejectsWeakThreshold() public {
        vm.expectRevert(TronVerifier.InvalidConstructorParams.selector);
        new TronVerifier(27, 18, INTERVAL, OFFSET, NILE); // 18/27 is not above 2/3
        vm.expectRevert(TronVerifier.InvalidConstructorParams.selector);
        new TronVerifier(27, 19, INTERVAL, INTERVAL, NILE);
        vm.expectRevert(TronVerifier.InvalidConstructorParams.selector);
        new TronVerifier(27, 19, INTERVAL, OFFSET, "");
    }
}
