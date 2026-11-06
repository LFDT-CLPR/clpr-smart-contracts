// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test, console2} from "forge-std/Test.sol";
import {TSSVerifier} from "@hiero-ledger/clpr/verifiers/hiero/TSSVerifier.sol";
import {HieroVerifier} from "@hiero-ledger/clpr/verifiers/hiero/HieroVerifier.sol";
import {WRAPSVerifierContract} from "@hiero-ledger/clpr/verifiers/hiero/wraps/WRAPSVerifierContract.sol";
import {ClprStateProof} from "@hiero-ledger/clpr/libraries/proof/hiero/ClprStateProof.sol";
import {ClprMerkleProof} from "@hiero-ledger/clpr/libraries/proof/hiero/ClprMerkleProof.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {TSSVerifierHarness} from "@test/helpers/TSSVerifierHarness.sol";
import {CalldataGas} from "@test/helpers/CalldataGas.sol";

/// @notice Component entry points so each `HieroVerifier.verifyBundle` step runs as its own call frame.
contract HieroParts {
    function decode(bytes calldata proof) external pure returns (uint256 paths, uint256 sigLen) {
        ClprStateProof.StateProofDecoded memory sp = ClprStateProof.decode(proof);
        return (sp.paths.length, sp.signature.length);
    }

    function decodeAndRoot(bytes calldata proof) external pure returns (bytes memory root, bytes memory sig) {
        ClprStateProof.StateProofDecoded memory sp = ClprStateProof.decode(proof);
        uint256 baseIdx = ClprMerkleProof.findFirstPath(sp.paths, ClprMerkleProof.LeafKind.StateItemLeaf);
        return (ClprMerkleProof.computeChainedRoot(sp.paths, baseIdx), sp.signature);
    }

    function decodeAndExtract(bytes calldata proof, bytes calldata root)
        external
        pure
        returns (uint256 nMsgs, uint256 leafPaths)
    {
        ClprStateProof.StateProofDecoded memory sp = ClprStateProof.decode(proof);
        (, bytes[] memory payloads,,,) = ClprStateProof.extractDecodedQueueData(sp.paths, root);
        for (uint256 i = 0; i < sp.paths.length; i++) {
            if (sp.paths[i].stateItemLeaf.length != 0) leafPaths++;
        }
        return (payloads.length, leafPaths);
    }
}

/// @notice Measurement suite behind `src/verifiers/hiero/GAS_REPORT.md`, over the real `stateProof.bin`.
contract HieroGasReportTest is Test {
    string internal constant STATE_PROOF_PATH = "test/verifiers/hiero/fixtures/stateProof.bin";
    string internal constant TRUST_ANCHOR_PATH = "test/verifiers/hiero/fixtures/trustAnchor.bin";

    HieroVerifier internal hiero;
    TSSVerifier internal tss;
    WRAPSVerifierContract internal wraps;
    HieroParts internal parts;
    TSSVerifierHarness internal hintsH;
    bytes internal proof;
    bytes internal ledgerId;
    /// @dev channelId(32) || remoteServiceAddress of the fixture's proven ClprChannel leaf; the verifier
    ///      binds that leaf to this channel id.
    bytes internal channelContext;

    function setUp() public {
        proof = vm.readFileBinary(STATE_PROOF_PATH);
        ledgerId = vm.readFileBinary(TRUST_ANCHOR_PATH);
        channelContext = abi.encodePacked(
            bytes32(0xe1022276af73c7a88c9fa00f7e844bbc4a8fda0cc6051d9c99926b74cf9c3d84),
            hex"ade986b5973ec38f3996f3a128f7d8c3e8ffcd9d"
        );
        address a = deployCode("PoseidonPermuteA.sol:PoseidonPermuteA");
        address b = deployCode("PoseidonPermuteB.sol:PoseidonPermuteB");
        address pos = deployCode("PoseidonBN254Contract.sol:PoseidonBN254Contract", abi.encode(a, b));
        wraps = WRAPSVerifierContract(deployCode("WRAPSVerifierContract.sol:WRAPSVerifierContract", abi.encode(pos)));
        tss = TSSVerifier(deployCode("TSSVerifier.sol:TSSVerifier", abi.encode(address(wraps))));
        hiero = HieroVerifier(deployCode("HieroVerifier.sol:HieroVerifier", abi.encode(ledgerId, address(tss))));
        parts = new HieroParts();
        hintsH = TSSVerifierHarness(deployCode("TSSVerifierHarness.sol:TSSVerifierHarness"));
    }

    function test_report() public view {
        bytes memory p = proof;
        bytes memory lid = ledgerId;

        console2.log("proof bytes", p.length);
        console2.log("calldata gas proof", CalldataGas.eip2028(p));
        console2.log("calldata gas anchor(ledgerId)", CalldataGas.eip2028(lid));

        // Full verifyBundle, anchor = ledgerId (as GasUsage.t.sol: Poseidon path).
        (ClprTypes.QueueMetadata memory md, bytes[] memory msgs, bytes memory newAnchor,,) =
            hiero.verifyBundle(p, lid, channelContext);
        console2.log("verifyBundle (anchor != keccak(vk), Poseidon)", vm.lastCallGas().gasTotalUsed);
        console2.log("  messages", msgs.length);
        console2.log("  state", uint256(md.state));
        console2.log("calldata gas anchor(keccak vk)", CalldataGas.eip2028(newAnchor));

        // Steady state: caller supplies the cached keccak256(hintsVk).
        hiero.verifyBundle(p, newAnchor, channelContext);
        console2.log("verifyBundle (anchor == keccak(vk), Poseidon skipped)", vm.lastCallGas().gasTotalUsed);
        hiero.verifyBundle(p, lid, channelContext);
        console2.log("verifyBundle repeat (Poseidon, warm)", vm.lastCallGas().gasTotalUsed);

        // Components, each its own call frame.
        (uint256 nPaths, uint256 sigLen) = parts.decode(p);
        uint256 gDecode = vm.lastCallGas().gasTotalUsed;
        console2.log("decode", gDecode);
        console2.log("  paths", nPaths);
        console2.log("  sigLen", sigLen);

        (bytes memory root, bytes memory sig) = parts.decodeAndRoot(p);
        uint256 gRoot = vm.lastCallGas().gasTotalUsed;
        console2.log("decode + block root", gRoot);

        (uint256 nMsgs, uint256 leafPaths) = parts.decodeAndExtract(p, root);
        uint256 gExtract = vm.lastCallGas().gasTotalUsed;
        console2.log("decode + extract", gExtract);
        console2.log("  msgs", nMsgs);
        console2.log("  leafPaths", leafPaths);

        tss.verifyTss(lid, sig, root, lid);
        console2.log("verifyTss (Poseidon)", vm.lastCallGas().gasTotalUsed);
        tss.verifyTss(lid, sig, root, newAnchor);
        console2.log("verifyTss (skip Poseidon)", vm.lastCallGas().gasTotalUsed);

        bytes memory vk = _slice(sig, 0, 1096);
        bytes memory hsig = _slice(sig, 1096, 1632);
        bytes memory ab = _slice(sig, 2728, sig.length - 2728);
        hintsH.verifyHintsAggregate(vk, hsig, root);
        console2.log("hinTS aggregate (real proof)", vm.lastCallGas().gasTotalUsed);
        wraps.verify(ab, vk, lid, false);
        console2.log("WRAPS (Poseidon)", vm.lastCallGas().gasTotalUsed);
        wraps.verify(ab, vk, lid, true);
        console2.log("WRAPS (skip Poseidon)", vm.lastCallGas().gasTotalUsed);
    }

    function test_steadyCold() public view {
        bytes memory p = proof;
        bytes memory vkHash = abi.encodePacked(keccak256(_slice(_sigOf(p), 0, 1096)));
        hiero.verifyBundle(p, vkHash, channelContext);
        console2.log("verifyBundle cold (anchor == keccak(vk))", vm.lastCallGas().gasTotalUsed);
    }

    function _sigOf(bytes memory p) internal view returns (bytes memory sig) {
        (, sig) = parts.decodeAndRoot(p);
    }

    function _slice(bytes memory d, uint256 o, uint256 l) internal pure returns (bytes memory out) {
        out = new bytes(l);
        for (uint256 i = 0; i < l; i++) {
            out[i] = d[o + i];
        }
    }
}
