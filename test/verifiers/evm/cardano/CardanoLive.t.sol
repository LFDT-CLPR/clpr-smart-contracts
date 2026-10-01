// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {CardanoMithrilVerifier} from "@hiero-ledger/clpr/verifiers/evm/cardano/CardanoMithrilVerifier.sol";
import {MithrilStmVerifier} from "@hiero-ledger/clpr/verifiers/evm/cardano/MithrilStmVerifier.sol";
import {ClprBlake2sHasher} from "@hiero-ledger/clpr/libraries/proof/cardano/ClprBlake2sHasher.sol";

/// @notice Replays REAL Mithril/Cardano data (test/e2e/fixtures/cardano-live, refresh with
///         `npx tsx test/e2e/relay/buildCardanoLiveProof.ts --refresh`):
///   preprod — anchor at epoch e, the real epoch-e certificate rotating to e+1, a real
///             CardanoBlocksTransactions certificate of e+1, the real MKMap proof, the real block
///             (fetched from a public relay) and transaction; the proven output must be the real one.
///   mainnet — real 57-signer STM certificates (k = 1944 lottery indexes), with and without rotation.
contract CardanoLiveTest is Test {
    CardanoMithrilVerifier internal v;
    string internal json;

    function setUp() public {
        v = new CardanoMithrilVerifier(new MithrilStmVerifier(), address(new ClprBlake2sHasher()));
        json = vm.readFile("test/e2e/fixtures/cardano-live/vectors.json");
    }

    function _b(string memory key) internal view returns (bytes memory) {
        return vm.parseJsonBytes(json, key);
    }

    function test_preprod_transactionOutput_withRotation() public view {
        uint256 g = gasleft();
        (CardanoMithrilVerifier.Proven memory p, bytes memory output, bytes memory newAnchor) =
            v.verifyTransactionOutput(_b(".preprod.txProof"), _b(".preprod.anchor"));
        console.log("preprod rotation + tx output gas", g - gasleft());
        assertEq(p.txId, vm.parseJsonBytes32(json, ".preprod.txHash"));
        assertEq(p.blockHash, vm.parseJsonBytes32(json, ".preprod.blockHash"));
        assertEq(uint256(p.blockNumber), vm.parseJsonUint(json, ".preprod.blockNumber"));
        assertEq(output, _b(".preprod.output"));
        assertEq(newAnchor, _b(".preprod.rotatedAnchor"));
    }

    function test_preprod_certificate_rotatedAnchor() public view {
        (bytes memory msg_, bytes memory newAnchor) =
            v.verifyCertificate(_b(".preprod.stateEpochCertProof"), _b(".preprod.rotatedAnchor"));
        assertEq(msg_.length, 64);
        assertEq(newAnchor.length, 0);
    }

    function test_mainnet_certificate() public view {
        uint256 g = gasleft();
        v.verifyCertificate(_b(".mainnet.certProof"), _b(".mainnet.anchor"));
        console.log("mainnet certificate gas", g - gasleft());
    }

    function test_mainnet_rotation() public view {
        uint256 g = gasleft();
        (bytes memory msg_, bytes memory newAnchor) =
            v.verifyCertificate(_b(".mainnet.rotationProof"), _b(".mainnet.anchor"));
        console.log("mainnet rotation + certificate gas", g - gasleft());
        assertEq(msg_, _b(".mainnet.signedMessage"));
        assertEq(newAnchor, _b(".mainnet.rotatedAnchor"));
    }

    function test_mainnet_rejectsWrongEpochAnchor() public {
        // the rotated anchor (epoch e+1) must not accept a certificate of epoch e
        vm.expectRevert();
        v.verifyCertificate(_b(".mainnet.certProof"), _b(".mainnet.rotatedAnchor"));
    }
}
