// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {SignerReplayVerifier} from "@hiero-ledger/clpr/verifiers/evm/signer/SignerReplayVerifier.sol";
import {SignerReplayProfiles} from "@hiero-ledger/clpr/verifiers/evm/signer/SignerReplayProfiles.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/// @dev SignerReplayVerifier on REAL chain data recorded by
///      `npx tsx test/e2e/relay/buildSignerReplayLiveProof.ts --refresh` into
///      test/e2e/fixtures/signer-replay-live/: Immutable zkEVM mainnet and testnet (Clique), KUB
///      mainnet and testnet (Bitkub PoS), GRX Chain mainnet (Congress). Per network: verifyConfig on
///      a real boundary block B0, a bundle whose header run starts at the next boundary B1 (rotation
///      B0 → B1) and the same run under the rotated anchor (no rotation). No ClprService exists on
///      these chains, so the bundle proves a real contract with ITS code hash pinned; the
///      channelId-derived slots are empty there, so the storage step checks real exclusion proofs.
contract SignerReplayLiveTest is Test {
    struct Vectors {
        uint64 chainId;
        bytes configProof;
        bytes trustAnchor;
        bytes rotatedAnchor;
        bytes proofBytes;
        bytes proofBytesNoRotation;
        bytes channelContext;
        bytes32 channelId;
        uint64 b1;
    }

    function _load(string memory network) internal view returns (Vectors memory v) {
        string memory json =
            vm.readFile(string.concat("test/e2e/fixtures/signer-replay-live/", network, "-vectors.json"));
        v.chainId = uint64(vm.parseJsonUint(json, ".chainId"));
        v.configProof = vm.parseJsonBytes(json, ".configProof");
        v.trustAnchor = vm.parseJsonBytes(json, ".trustAnchor");
        v.rotatedAnchor = vm.parseJsonBytes(json, ".rotatedAnchor");
        v.proofBytes = vm.parseJsonBytes(json, ".proofBytes");
        v.proofBytesNoRotation = vm.parseJsonBytes(json, ".proofBytesNoRotation");
        v.channelContext = vm.parseJsonBytes(json, ".channelContext");
        v.channelId = vm.parseJsonBytes32(json, ".channelId");
        v.b1 = uint64(vm.parseJsonUint(json, ".b1"));
    }

    function _deploy(string memory family, uint64 chainId) internal returns (SignerReplayVerifier) {
        bytes32 f = keccak256(bytes(family));
        if (f == keccak256("immutable")) return new SignerReplayVerifier(SignerReplayProfiles.immutableZkEvm(chainId));
        if (f == keccak256("kub")) return new SignerReplayVerifier(SignerReplayProfiles.kub(chainId));
        return new SignerReplayVerifier(SignerReplayProfiles.grx(chainId));
    }

    function _check(string memory family, string memory network) internal {
        Vectors memory v = _load(network);
        SignerReplayVerifier verifier = _deploy(family, v.chainId);

        (bytes memory ctx, string memory chainId,,,, bytes memory anchor,,) =
            verifier.verifyConfig(v.configProof, v.channelId, "");
        assertEq(chainId, string.concat("eip155:", Strings.toString(v.chainId)));
        assertEq(anchor, v.trustAnchor, "verifyConfig anchor");
        assertEq(ctx, v.channelContext, "channel context");

        uint256 g = gasleft();
        (ClprTypes.QueueMetadata memory m, bytes[] memory msgs, bytes memory newAnchor, bytes memory newId,) =
            verifier.verifyBundle(v.proofBytes, v.trustAnchor, v.channelContext);
        uint256 rotGas = g - gasleft();
        assertEq(newAnchor, v.rotatedAnchor, "rotated anchor");
        assertEq(newId, abi.encodePacked(v.b1));
        assertEq(m.nextMessageId, 0, "channel slots absent in the probe account");
        assertEq(msgs.length, 0);

        g = gasleft();
        (,, newAnchor,,) = verifier.verifyBundle(v.proofBytesNoRotation, v.rotatedAnchor, v.channelContext);
        uint256 plainGas = g - gasleft();
        assertEq(newAnchor.length, 0, "boundary not newer than the rotated anchor");

        console.log(
            string.concat("[signer-replay-live] ", network, " verifyBundle with rotation (execution gas):"), rotGas
        );
        console.log(
            string.concat("[signer-replay-live] ", network, " verifyBundle without rotation (execution gas):"), plainGas
        );
        console.log(string.concat("[signer-replay-live] ", network, " proofBytes bytes:"), v.proofBytes.length);
    }

    function test_live_immutableMainnet() public {
        _check("immutable", "immutable-mainnet");
    }

    function test_live_immutableTestnet() public {
        _check("immutable", "immutable-testnet");
    }

    function test_live_kubMainnet() public {
        _check("kub", "kub-mainnet");
    }

    function test_live_kubTestnet() public {
        _check("kub", "kub-testnet");
    }

    function test_live_grxMainnet() public {
        _check("grx", "grx-mainnet");
    }

    // ── Negative cases on real data ───────────────────────────────────────────

    function test_live_revertWhen_codeHashNotPinned() public {
        Vectors memory v = _load("kub-mainnet");
        SignerReplayVerifier verifier = _deploy("kub", v.chainId);
        bytes memory anchor = v.trustAnchor;
        anchor[31] ^= 0x01;
        vm.expectRevert(ClprEvmBundleVerifier.CodeHashMismatch.selector);
        verifier.verifyBundle(v.proofBytes, anchor, v.channelContext);
    }

    function test_live_revertWhen_otherChainsSignerSet() public {
        Vectors memory kub = _load("kub-mainnet");
        Vectors memory imx = _load("immutable-mainnet");
        SignerReplayVerifier verifier = _deploy("kub", kub.chainId);
        vm.expectRevert(SignerReplayVerifier.SignerSetMismatch.selector);
        verifier.verifyBundle(kub.proofBytes, imx.trustAnchor, kub.channelContext);
    }

    function test_live_revertWhen_rotationReplayedUnderRotatedAnchor_setChanged() public {
        // KUB mainnet's fixture rotates into a different set; the old set's bytes no longer bind.
        Vectors memory v = _load("kub-mainnet");
        SignerReplayVerifier verifier = _deploy("kub", v.chainId);
        assertTrue(keccak256(v.trustAnchor) != keccak256(v.rotatedAnchor));
        vm.expectRevert(SignerReplayVerifier.SignerSetMismatch.selector);
        verifier.verifyBundle(v.proofBytes, v.rotatedAnchor, v.channelContext);
    }

    function test_live_revertWhen_runOlderThanAnchor() public {
        Vectors memory v = _load("grx-mainnet");
        SignerReplayVerifier verifier = _deploy("grx", v.chainId);
        bytes memory anchor = v.rotatedAnchor; // setBlock = B1
        uint64 later = v.b1 + 200;
        for (uint256 i = 0; i < 8; i++) {
            anchor[64 + i] = bytes1(uint8(later >> (56 - 8 * i)));
        }
        vm.expectRevert(abi.encodeWithSelector(SignerReplayVerifier.HeaderBeforeAnchor.selector, v.b1, later));
        verifier.verifyBundle(v.proofBytesNoRotation, anchor, v.channelContext);
    }

    function test_live_revertWhen_wrongSealProfile() public {
        // GRX headers checked with the all-fields (Clique) seal rule recover foreign addresses.
        Vectors memory v = _load("grx-mainnet");
        SignerReplayVerifier.Profile memory p = SignerReplayProfiles.grx(v.chainId);
        p.sealFields = 0;
        SignerReplayVerifier verifier = new SignerReplayVerifier(p);
        vm.expectPartialRevert(SignerReplayVerifier.InsufficientSigners.selector);
        verifier.verifyBundle(v.proofBytes, v.trustAnchor, v.channelContext);
    }

    function test_live_revertWhen_configForOtherChain() public {
        Vectors memory v = _load("immutable-testnet");
        SignerReplayVerifier verifier = _deploy("immutable", 13371);
        vm.expectRevert(SignerReplayVerifier.ChainIdMismatch.selector);
        verifier.verifyConfig(v.configProof, v.channelId, "");
    }
}
