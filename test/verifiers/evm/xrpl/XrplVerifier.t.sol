// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {XrplTestBuilder} from "@test/verifiers/evm/xrpl/XrplTestBuilder.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {XrplVerifier} from "@hiero-ledger/clpr/verifiers/evm/xrpl/XrplVerifier.sol";
import {XrplLightClient} from "@hiero-ledger/clpr/verifiers/evm/xrpl/XrplLightClient.sol";
import {XrplUnlKeys} from "@hiero-ledger/clpr/verifiers/evm/xrpl/XrplUnlKeys.sol";
import {XrplLib} from "@hiero-ledger/clpr/verifiers/evm/xrpl/XrplLib.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @dev XrplVerifier / XrplLightClient rules over synthetic ledgers: consensus (signatures, quorum,
///      UNL, staleness, manifest rotation and replay), inclusion, and the clpr/v1 outbox shape.
contract XrplVerifierTest is XrplTestBuilder {
    XrplVerifier internal verifier;

    function setUp() public {
        verifier = _deployXrpl("xrpl:0");
    }

    function _verify(bytes memory proof)
        internal
        returns (ClprTypes.QueueMetadata memory m, bytes[] memory p, bytes memory a)
    {
        (m, p, a,,) = verifier.verifyBundle(proof, _anchor(), _context());
    }

    function _one(bytes memory txb, bytes memory meta) internal returns (bytes memory) {
        bytes[] memory txs = new bytes[](1);
        bytes[] memory metas = new bytes[](1);
        txs[0] = txb;
        metas[0] = meta;
        return _bundle(txs, metas, QUORUM, bytes32(0));
    }

    // ── happy paths ──────────────────────────────────────────────────────────

    function test_bundle_threeMessages() public {
        (bytes[] memory txs, bytes[] memory metas, bytes[] memory payloads) = _messages(3);
        (ClprTypes.QueueMetadata memory m, bytes[] memory p, bytes memory a) = _verify(_bundle(txs, metas, QUORUM, 0));
        assertEq(m.nextMessageId, 4);
        assertEq(m.receivedMessageId, 2);
        assertEq(uint8(m.state), uint8(ClprTypes.ChannelStatus.ACTIVE));
        assertEq(p.length, 3);
        bytes32 rh;
        for (uint256 i = 0; i < 3; ++i) {
            assertEq(p[i], payloads[i]);
            rh = sha256(abi.encodePacked(rh, sha256(payloads[i])));
        }
        assertEq(m.sentRunningHash, rh);
        assertEq(a.length, 0);
    }

    function test_gas_bundle_oneMessage_quorum() public {
        bytes memory proof = _one(_clprTx(_msg(1)), META_OK);
        uint256 g = gasleft();
        _verify(proof);
        emit log_named_uint("1 message, 4/5 validations", g - gasleft());
        emit log_named_uint("calldata bytes", proof.length);
    }

    // ── consensus ────────────────────────────────────────────────────────────

    function test_reverts_belowQuorum() public {
        (bytes[] memory txs, bytes[] memory metas,) = _messages(1);
        bytes memory proof = _bundle(txs, metas, QUORUM - 1, 0);
        vm.expectRevert(abi.encodeWithSelector(XrplLightClient.QuorumNotReached.selector, QUORUM - 1, QUORUM));
        _verify(proof);
    }

    function test_reverts_badSignature() public {
        // validator 1's key signs as validator 0
        uint256 k0 = valKeys[0];
        bytes memory unl = _unlAnchorList();
        valKeys[0] = valKeys[1];
        unlOverride = unl;
        bytes memory proof = _one(_clprTx(_msg(1)), META_OK);
        valKeys[0] = k0;
        vm.expectRevert(abi.encodeWithSelector(XrplLightClient.BadValidationSignature.selector, 0));
        _verify(proof);
    }

    function test_reverts_wrongValidatorSet() public {
        bytes memory proof = _one(_clprTx(_msg(1)), META_OK);
        vm.expectRevert(XrplLightClient.UnlMismatch.selector);
        verifier.verifyBundle(
            proof, abi.encode(keccak256("other UNL"), N_VALIDATORS, uint256(SEQ_BASE), uint256(0)), _context()
        );
        vm.expectRevert(XrplLightClient.UnlMismatch.selector);
        verifier.verifyBundle(
            proof, abi.encode(_unlHash(), N_VALIDATORS + 1, uint256(SEQ_BASE), uint256(0)), _context()
        );
    }

    function test_reverts_staleLedger() public {
        bytes memory proof = _one(_clprTx(_msg(1)), META_OK);
        vm.expectRevert(abi.encodeWithSelector(XrplLightClient.StaleLedger.selector, LEDGER, uint256(LEDGER) + 1));
        verifier.verifyBundle(
            proof, abi.encode(_unlHash(), N_VALIDATORS, uint256(SEQ_BASE), uint256(LEDGER) + 1), _context()
        );
    }

    function _manifest(uint256 masterPk, uint256 newPk, uint32 seq) internal returns (bytes memory) {
        bytes memory master = _compressed(masterPk);
        bytes memory signing = _compressed(newPk);
        bytes memory body = abi.encodePacked(hex"24", seq, hex"71", _vl(master), hex"73", _vl(signing));
        bytes32 digest = _half(abi.encodePacked(bytes4("MAN\x00"), body));
        return abi.encodePacked(body, hex"76", _vl(_signDer(newPk, digest)), hex"7012", _vl(_signDer(masterPk, digest)));
    }

    /// @dev Validator 0 (secp256k1 master) rotates its signing key; validations by the new key
    ///      count and the bundle returns the re-committed UNL. Replaying the manifest fails.
    function test_manifestRotation_andReplay() public {
        uint256 masterPk = uint256(keccak256("secp master 0"));
        masters[0] = _compressed(masterPk);
        bytes memory oldUnl = _unlAnchorList();
        bytes32 oldHash = _unlHash();
        uint256 newKey = uint256(keccak256("rotated signing key 0"));
        bytes[] memory ms = new bytes[](1);
        ms[0] = RLP.encode(_manifest(masterPk, newKey, 2));
        manifestsOverride = RLP.encode(ms);
        unlOverride = oldUnl;
        valKeys[0] = newKey;
        bytes memory proof = _one(_clprTx(_msg(1)), META_OK);
        bytes memory anchor = abi.encode(oldHash, N_VALIDATORS, uint256(SEQ_BASE), uint256(0));
        uint256 g = gasleft();
        (,, bytes memory newAnchor, bytes memory newId,) = verifier.verifyBundle(proof, anchor, _context());
        emit log_named_uint("1 message + 1 manifest rotation (secp master)", g - gasleft());
        // the new UNL commits to the rotated key with sequence 2
        bytes memory acc;
        for (uint256 i = 0; i < N_VALIDATORS; ++i) {
            acc = abi.encodePacked(acc, masters[i], vm.addr(valKeys[i]), uint32(i == 0 ? 2 : 1));
        }
        assertEq(newAnchor, abi.encode(keccak256(acc), N_VALIDATORS, uint256(SEQ_BASE), uint256(LEDGER)));
        assertEq(newId, abi.encodePacked(keccak256(acc)));

        // replay the same manifest against the rotated UNL: sequence must increase
        bytes[] memory es = new bytes[](N_VALIDATORS);
        for (uint256 i = 0; i < N_VALIDATORS; ++i) {
            bytes[] memory e = new bytes[](3);
            e[0] = RLP.encode(masters[i]);
            e[1] = RLP.encode(vm.addr(valKeys[i]));
            e[2] = RLP.encode(uint256(i == 0 ? 2 : 1));
            es[i] = RLP.encode(e);
        }
        unlOverride = RLP.encode(es);
        bytes memory replay = _one(_clprTx(_msg(1)), META_OK);
        vm.expectRevert(abi.encodeWithSelector(XrplUnlKeys.StaleManifest.selector, uint32(2), uint32(2)));
        verifier.verifyBundle(replay, newAnchor, _context());
    }

    function test_reverts_manifestSignedByWrongMaster() public {
        uint256 masterPk = uint256(keccak256("secp master 0"));
        masters[0] = _compressed(masterPk);
        unlOverride = _unlAnchorList();
        bytes32 h = _unlHash();
        uint256 newKey = uint256(keccak256("rotated signing key 0"));
        bytes[] memory ms = new bytes[](1);
        ms[0] = RLP.encode(_manifest(uint256(keccak256("impostor")), newKey, 2));
        manifestsOverride = RLP.encode(ms);
        bytes memory proof = _one(_clprTx(_msg(1)), META_OK);
        vm.expectRevert(XrplUnlKeys.UnknownManifestKey.selector);
        verifier.verifyBundle(proof, abi.encode(h, N_VALIDATORS, uint256(SEQ_BASE), uint256(0)), _context());
    }

    // ── inclusion and result ─────────────────────────────────────────────────

    function test_reverts_wrongInclusionProof() public {
        corruptInner = true;
        bytes memory proof = _one(_clprTx(_msg(1)), META_OK);
        vm.expectRevert(abi.encodeWithSelector(XrplLib.SHAMapHashMismatch.selector, 0));
        _verify(proof);
    }

    function test_reverts_tecResult() public {
        bytes memory proof = _one(_clprTx(_msg(1)), META_TEC);
        vm.expectRevert(XrplLightClient.TransactionFailed.selector);
        _verify(proof);
    }

    // ── clpr/v1 shape ────────────────────────────────────────────────────────

    function test_reverts_flags() public {
        bytes memory proof = _one(_clprTx(_msg(1), OUTBOX, "", 0x40000000, false), META_OK); // tfInnerBatchTxn
        vm.expectRevert();
        _verify(proof);
    }

    function test_reverts_ticketAndExtraFields() public {
        // TicketSequence (UINT32 41): ticketed transactions are forbidden
        bytes memory proof = _one(_clprTx(_msg(1), OUTBOX, hex"20290000000a", 0, false), META_OK);
        vm.expectRevert(abi.encodeWithSelector(XrplVerifier.NotClprMessage.selector, uint256(13)));
        _verify(proof);
        // SetFlag (UINT32 33)
        proof = _one(_clprTx(_msg(1), OUTBOX, hex"202100000004", 0, false), META_OK);
        vm.expectRevert(abi.encodeWithSelector(XrplVerifier.NotClprMessage.selector, uint256(13)));
        _verify(proof);
    }

    function test_reverts_memoFormat() public {
        bytes memory proof = _one(_clprTx(_msg(1), OUTBOX, "", 0, true), META_OK);
        vm.expectRevert(XrplVerifier.BadMemo.selector);
        _verify(proof);
    }

    function test_reverts_wrongSender() public {
        bytes memory proof = _one(_clprTx(_msg(1), bytes20(uint160(0xBAD)), "", 0, false), META_OK);
        vm.expectRevert(XrplVerifier.WrongSender.selector);
        _verify(proof);
    }

    function test_reverts_sequenceGap() public {
        bytes[] memory txs = new bytes[](2);
        bytes[] memory metas = new bytes[](2);
        txs[0] = _clprTx(_msg(1));
        txs[1] = _clprTx(_msg(3));
        metas[0] = META_OK;
        metas[1] = META_OK;
        bytes memory proof = _bundle(txs, metas, QUORUM, 0);
        vm.expectRevert(
            abi.encodeWithSelector(XrplVerifier.SequenceGap.selector, uint256(SEQ_BASE) + 1, uint256(SEQ_BASE) + 2)
        );
        _verify(proof);
    }

    function test_reverts_nextMessageIdMismatch() public {
        XrplTestBuilder.Msg memory m = _msg(1);
        m.next = 5;
        bytes memory proof = _one(_clprTx(m), META_OK);
        vm.expectRevert(abi.encodeWithSelector(XrplVerifier.NextMessageIdMismatch.selector, 2, 5));
        _verify(proof);
    }

    function test_reverts_wrongChannel() public {
        XrplTestBuilder.Msg memory m = _msg(1);
        m.channel = bytes32(uint256(0xBEEF));
        bytes memory proof = _one(_clprTx(m), META_OK);
        vm.expectRevert(XrplVerifier.ChannelMismatch.selector);
        _verify(proof);
    }

    // ── config ───────────────────────────────────────────────────────────────

    function test_config_anchor() public {
        (,,,,, bytes memory anchor, bytes memory id,) =
            verifier.verifyConfig(_config("xrpl:0", 0x00100000, ""), CHANNEL, "");
        assertEq(anchor, abi.encode(_unlHash(), N_VALIDATORS, uint256(SEQ_BASE), uint256(LEDGER)));
        assertEq(id, abi.encodePacked(_unlHash()));
    }

    function test_config_reverts_masterKeyEnabled() public {
        bytes memory proof = _config("xrpl:0", 0, "");
        vm.expectRevert(XrplVerifier.OutboxNotLocked.selector);
        verifier.verifyConfig(proof, CHANNEL, "");
    }
}
