// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {HyperEvmTestBuilder} from "@test/verifiers/evm/hyperliquid/HyperEvmTestBuilder.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {HyperEvmVerifier} from "@hiero-ledger/clpr/verifiers/evm/hyperliquid/HyperEvmVerifier.sol";
import {ClprAttestorQuorum} from "@hiero-ledger/clpr/libraries/proof/attestor/ClprAttestorQuorum.sol";
import {ClprReceiptProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprReceiptProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

contract HyperEvmVerifierTest is HyperEvmTestBuilder {
    function setUp() public {
        _deployHyper();
    }

    function test_bundle_happy() public view {
        (bytes memory content, bytes32 running) = _content(2);
        bytes memory proof = _bundleProof(_defaultBundle(content, running, 3));
        (ClprTypes.QueueMetadata memory m, bytes[] memory p, bytes memory a,,) =
            hv.verifyBundle(proof, _anchor(), _context());
        assertEq(m.nextMessageId, 3);
        assertEq(m.sentRunningHash, running);
        assertEq(p.length, 2);
        assertEq(a.length, 0);
    }

    function test_gas_bundle() public {
        (bytes memory content, bytes32 running) = _content(2);
        bytes memory proof = _bundleProof(_defaultBundle(content, running, 3));
        uint256 g = gasleft();
        hv.verifyBundle(proof, _anchor(), _context());
        emit log_named_uint("bundle, 3-of-5 attestation", g - gasleft());
    }

    function test_reverts_belowThreshold() public {
        Bundle memory b = _defaultBundle("", 0, 1);
        b.signers = K - 1;
        bytes memory proof = _bundleProof(b);
        vm.expectRevert(abi.encodeWithSelector(ClprAttestorQuorum.AttestorQuorumNotReached.selector, K - 1, K));
        hv.verifyBundle(proof, _anchor(), _context());
    }

    function test_reverts_badSignature_outsider() public {
        Bundle memory b = _defaultBundle("", 0, 1);
        (uint256[] memory outsiders,) = _setupAttestors("outsider");
        b.signerKeys = outsiders;
        bytes memory proof = _bundleProof(b);
        vm.expectRevert();
        hv.verifyBundle(proof, _anchor(), _context());
    }

    function test_reverts_wrongAttestorSet() public {
        bytes memory proof = _bundleProof(_defaultBundle("", 0, 1));
        vm.expectRevert(ClprAttestorQuorum.AttestorSetMismatch.selector);
        hv.verifyBundle(proof, abi.encode(keccak256("other"), uint256(0), uint256(0), BEACON), _context());
    }

    function test_reverts_staleBlock() public {
        bytes memory proof = _bundleProof(_defaultBundle("", 0, 1));
        vm.expectRevert(abi.encodeWithSelector(HyperEvmVerifier.StaleBlock.selector, BLOCK, BLOCK + 1));
        hv.verifyBundle(proof, abi.encode(_setHash(K, addrs), uint256(0), BLOCK + 1, BEACON), _context());
    }

    function test_reverts_wrongEmitter_wrongEvent_failedReceipt() public {
        Bundle memory b = _defaultBundle("", 0, 1);
        b.emitter = address(0xBAD);
        bytes memory proof = _bundleProof(b);
        vm.expectRevert(abi.encodeWithSelector(HyperEvmVerifier.WrongEmitter.selector, address(0xBAD)));
        hv.verifyBundle(proof, _anchor(), _context());
        b = _defaultBundle("", 0, 1);
        b.topic0 = keccak256("Transfer(address,address,uint256)");
        proof = _bundleProof(b);
        vm.expectRevert(HyperEvmVerifier.WrongEvent.selector);
        hv.verifyBundle(proof, _anchor(), _context());
        b = _defaultBundle("", 0, 1);
        b.status = 0;
        proof = _bundleProof(b);
        vm.expectRevert(ClprReceiptProof.ReceiptFailed.selector);
        hv.verifyBundle(proof, _anchor(), _context());
    }

    function test_reverts_wrongReceiptProof() public {
        Bundle memory b = _defaultBundle("", 0, 1);
        b.corruptReceiptNode = true;
        bytes memory proof = _bundleProof(b);
        vm.expectRevert(abi.encodeWithSelector(ClprReceiptProof.ReceiptProofHash.selector, 0));
        hv.verifyBundle(proof, _anchor(), _context());
    }

    function test_reverts_wrongServiceOrChannel() public {
        bytes memory proof = _bundleProof(_defaultBundle("", 0, 1));
        vm.expectRevert(HyperEvmVerifier.WrongService.selector);
        hv.verifyBundle(proof, _anchor(), abi.encodePacked(CHANNEL, address(0x1234)));
        vm.expectRevert();
        hv.verifyBundle(proof, _anchor(), abi.encodePacked(bytes32(uint256(0xBEEF)), SERVICE));
    }

    function test_rotation_and_replay() public {
        (uint256[] memory ks2, address[] memory as2) = _setupAttestors("next set");
        bytes32 newHash = _setHash(K, as2);
        bytes[] memory rot = new bytes[](2);
        rot[0] = _setRlp(K, as2);
        rot[1] = _sigs(keys, _first(K), hv.rotationDigest(1, newHash));
        bytes[] memory rots = new bytes[](1);
        rots[0] = RLP.encode(rot);
        Bundle memory b = _defaultBundle("", 0, 1);
        b.rotations = RLP.encode(rots);
        b.signerKeys = ks2; // the block is attested by the new set
        bytes memory proof = _bundleProof(b);
        uint256 g = gasleft();
        (,, bytes memory a, bytes memory id,) = hv.verifyBundle(proof, _anchor(), _context());
        emit log_named_uint("bundle + 1 attestor-set rotation", g - gasleft());
        assertEq(a, abi.encode(newHash, uint256(1), BLOCK, BEACON));
        assertEq(id, abi.encodePacked(uint256(1)));
        // replaying the epoch-1 rotation against the epoch-1 anchor: it now needs epoch 2
        bytes memory anchor1 = abi.encode(_setHash(K, addrs), uint256(1), uint256(0), BEACON);
        vm.expectRevert();
        hv.verifyBundle(proof, anchor1, _context());
    }

    function test_config() public view {
        (bytes memory ctx, string memory chainId, bytes memory service,,, bytes memory anchor,,) =
            hv.verifyConfig(_configProof("eip155:999", ""), CHANNEL, "");
        assertEq(chainId, "eip155:999");
        assertEq(service, abi.encodePacked(SERVICE));
        assertEq(ctx, _context());
        assertEq(anchor, abi.encode(_setHash(K, addrs), uint256(0), BLOCK, BEACON));
    }
}
