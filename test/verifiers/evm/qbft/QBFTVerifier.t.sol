// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {QbftVerifierBase} from "@hiero-ledger/clpr/verifiers/evm/qbft/QbftVerifierBase.sol";
import {QBFTVerifier} from "@hiero-ledger/clpr/verifiers/evm/qbft/QBFTVerifier.sol";
import {QbftHeaderModeVerifier} from "@hiero-ledger/clpr/verifiers/evm/qbft/QbftHeaderModeVerifier.sol";
import {QbftContractModeVerifier} from "@hiero-ledger/clpr/verifiers/evm/qbft/QbftContractModeVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";
import {QbftHeaderModeProofBuilders} from "@test/verifiers/evm/qbft/QbftHeaderModeProofBuilders.sol";

/// @dev The proxy only routes on the mode byte; everything else is the mode verifier's, so these
///      tests check the routing and nothing more.
contract QBFTVerifierTest is QbftHeaderModeProofBuilders {
    QBFTVerifier internal proxy;

    function setUp() public {
        proxy = new QBFTVerifier();
    }

    function test_headerAnchor_routesToHeaderMode() public view {
        (bytes memory proof, bytes memory anchor) = _steadyScenario("px", 3);
        (ClprTypes.QueueMetadata memory meta,, bytes memory newAnchor,,) =
            proxy.verifyBundle(proof, anchor, _syntheticChannelContext());
        assertEq(meta.nextMessageId, 0);
        assertEq(newAnchor.length, 0);
    }

    function test_contractAnchor_routesToContractMode() public {
        // A 224-byte mode-1 anchor reaches the contract-mode verifier, which rejects the empty proof.
        bytes memory anchor =
            abi.encode(uint8(1), bytes32(0), SERVICE_CODE_HASH, address(0), bytes32(0), uint64(0), bytes32(0));
        vm.expectRevert(QbftVerifierBase.InvalidPayloadShape.selector);
        proxy.verifyBundle(hex"c0", anchor, _syntheticChannelContext());
    }

    function test_headerAnchorWrongLength_rejectedByHeaderMode() public {
        // Mode 0 but 5 words: the header-mode verifier owns the length check.
        bytes memory anchor = abi.encode(uint8(0), bytes32(0), SERVICE_CODE_HASH, uint64(0), bytes32(0));
        vm.expectRevert(QbftVerifierBase.InvalidTrustAnchor.selector);
        proxy.verifyBundle(hex"c0", anchor, _syntheticChannelContext());
    }

    function test_shortAnchor_reverts() public {
        vm.expectRevert(QBFTVerifier.InvalidTrustAnchor.selector);
        proxy.verifyBundle(hex"c0", hex"deadbeef", _syntheticChannelContext());
    }

    function test_unknownModeAnchor_reverts() public {
        bytes memory anchor = abi.encode(uint8(2), bytes32(0), SERVICE_CODE_HASH, uint64(0));
        vm.expectRevert(abi.encodeWithSelector(QBFTVerifier.UnknownValidatorMode.selector, 2));
        proxy.verifyBundle(hex"c0", anchor, _syntheticChannelContext());
    }

    function test_config_routesByDescriptorMode() public {
        // Mode 0: the header-mode verifier accepts the header-mode config proof.
        (,,,,, bytes memory anchor,,) = proxy.verifyConfig(_configScenario("pc"), SYNTHETIC_CHANNEL_ID, "");
        assertEq(anchor.length, 128);

        // Mode 1 with a header-mode body: the contract-mode verifier wants 7 fields, not 6.
        bytes[] memory ta = new bytes[](2);
        ta[0] = RLP.encode(uint256(1));
        ta[1] = RLP.encode(SERVICE_CODE_HASH);
        bytes memory contractDescriptor = _withDescriptor(_configScenario("pc"), ta);
        vm.expectRevert(QbftVerifierBase.InvalidProofPayloadShape.selector);
        proxy.verifyConfig(contractDescriptor, SYNTHETIC_CHANNEL_ID, "");

        ta[0] = RLP.encode(uint256(5));
        vm.expectRevert(abi.encodeWithSelector(QBFTVerifier.UnknownValidatorMode.selector, 5));
        proxy.verifyConfig(_withDescriptor(_configScenario("pc"), ta), SYNTHETIC_CHANNEL_ID, "");
    }

    function test_config_shapeErrors() public {
        vm.expectRevert(QBFTVerifier.InvalidPayloadShape.selector);
        proxy.verifyConfig("", bytes32(0), "");
        // Too short to carry the descriptor at index 4.
        vm.expectRevert(QBFTVerifier.InvalidProofPayloadShape.selector);
        proxy.verifyConfig(hex"c180", bytes32(0), "");
        bytes memory emptyDescriptor = _withDescriptor(_configScenario("pc"), new bytes[](0));
        vm.expectRevert(QBFTVerifier.InvalidTrustAnchorFields.selector);
        proxy.verifyConfig(emptyDescriptor, bytes32(0), "");
    }

    function _withDescriptor(bytes memory configProof, bytes[] memory ta) private pure returns (bytes memory) {
        Memory.Slice[] memory items = RLP.decodeList(configProof);
        bytes[] memory out = new bytes[](items.length);
        for (uint256 i = 0; i < items.length; i++) {
            out[i] = i == 4 ? RLP.encode(RLP.encode(ta)) : Memory.toBytes(items[i]);
        }
        return RLP.encode(out);
    }
}
