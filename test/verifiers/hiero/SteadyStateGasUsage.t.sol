// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {TSSVerifier} from "@hiero-ledger/clpr/verifiers/hiero/TSSVerifier.sol";
import {HieroVerifier} from "@hiero-ledger/clpr/verifiers/hiero/HieroVerifier.sol";
import {ClprStateProof} from "@hiero-ledger/clpr/libraries/proof/hiero/ClprStateProof.sol";
import {BN254Util} from "@hiero-ledger/clpr/verifiers/hiero/wraps/BN254Util.sol";

/// @notice Steady-state gas for `HieroVerifier.verifyBundle`: the channel already stores the
///         `keccak256(hintsVk) ‖ WRAPS step` anchor for the proof's key set, so the Poseidon hash
///         of the hinTS VK is skipped. Kept apart from `GasUsage.t.sol` so each file's single
///         `verifyBundle` call is the `min` row its `script/gas/baselines.yml` entry reads.
contract HieroSteadyStateGasBenchmarkTest is Test {
    uint256 internal constant HINTS_VK_LEN = 1096;
    uint256 internal constant ABPROOF_OFFSET = 2728;

    function test_gas_verifyBundle_steadyState() public {
        bytes memory ledgerId = vm.readFileBinary("test/verifiers/hiero/fixtures/trustAnchor.bin");
        bytes memory proof = vm.readFileBinary("test/verifiers/hiero/fixtures/stateProof.bin");
        address permuteA = deployCode("PoseidonPermuteA.sol:PoseidonPermuteA");
        address permuteB = deployCode("PoseidonPermuteB.sol:PoseidonPermuteB");
        address poseidon = deployCode("PoseidonBN254Contract.sol:PoseidonBN254Contract", abi.encode(permuteA, permuteB));
        address wraps = deployCode("WRAPSVerifierContract.sol:WRAPSVerifierContract", abi.encode(poseidon));
        TSSVerifier tssVerifier = TSSVerifier(deployCode("TSSVerifier.sol:TSSVerifier", abi.encode(wraps)));
        HieroVerifier hieroVerifier =
            HieroVerifier(deployCode("HieroVerifier.sol:HieroVerifier", abi.encode(ledgerId, address(tssVerifier))));
        bytes memory channelContext = abi.encodePacked(
            bytes32(0xe1022276af73c7a88c9fa00f7e844bbc4a8fda0cc6051d9c99926b74cf9c3d84),
            hex"ade986b5973ec38f3996f3a128f7d8c3e8ffcd9d"
        );

        // Built from the proof rather than from a first verifyBundle call, so this file's only
        // verifyBundle row is the cached one.
        bytes memory signature = ClprStateProof.decode(proof).signature;
        bytes memory hintsVk = new bytes(HINTS_VK_LEN);
        for (uint256 i = 0; i < HINTS_VK_LEN; i++) {
            hintsVk[i] = signature[i];
        }
        bytes32 stepLe;
        assembly ("memory-safe") {
            stepLe := mload(add(add(signature, 0x20), ABPROOF_OFFSET))
        }
        bytes memory storedAnchor = abi.encodePacked(keccak256(hintsVk), BN254Util._bswap32(uint256(stepLe)));

        vm.expectCall(poseidon, abi.encodeWithSignature("hashHintsVk(bytes)"), 0);
        (,, bytes memory reported,,) = hieroVerifier.verifyBundle(proof, storedAnchor, channelContext);
        assertEq(reported.length, 0, "stored anchor matches the proof's key set");
    }
}
