// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {Vm} from "forge-std/Vm.sol";
import {console} from "forge-std/console.sol";
import {ClprConfig} from "../../script/ClprConfig.sol";
import {ClprService} from "@hiero-ledger/clpr/ClprService.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {E2EVerifier} from "@test/E2EVerifier.sol";

/// @dev Completes a channel on the ClprService of the local Tempo network, through the E2EVerifier
///      test double. Env: PRIVATE_KEY, CLPR_SERVICE, SKIP_INIT=true when already initialized.
contract TempoLocalnetChannel is Script {
    string private constant PEER_CHAIN_ID = "eip155:31337";
    uint256 private constant PEER_SIGNER_PK = 0xC0DE;

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        ClprService svc = ClprService(payable(vm.envAddress("CLPR_SERVICE")));

        vm.startBroadcast(pk);
        if (!vm.envOr("SKIP_INIT", false)) {
            svc.initialize(hex"1234", ClprConfig.defaultThrottles(), "", "", ClprConfig.defaultEconomicConfig());
            svc.setClprEnabled(true);
        }

        E2EVerifier verifier = new E2EVerifier();
        verifier.configure(
            PEER_CHAIN_ID,
            abi.encodePacked(address(0xBEEF)),
            0,
            ClprConfig.defaultThrottles(),
            hex"01",
            hex"01",
            new ClprTypes.Endpoint[](0)
        );

        Vm.Wallet memory peer = vm.createWallet(PEER_SIGNER_PK);
        bytes memory peerPubKey = abi.encodePacked(peer.publicKeyX, peer.publicKeyY);
        bytes32 channelId = svc.deriveChannelId(PEER_CHAIN_ID, peerPubKey, bytes32(0));
        svc.registerChannel(channelId, keccak256(abi.encodePacked(channelId, peerPubKey)));
        bytes32 msgHash = keccak256(abi.encodePacked(channelId, address(svc)));
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PEER_SIGNER_PK, ethSigned);
        svc.completeChannel(channelId, peerPubKey, abi.encodePacked(r, s, v), bytes32(0), address(verifier), "", "");
        vm.stopBroadcast();

        console.log("FIXTURE_OUT::CHANNEL_ID", vm.toString(channelId));
        console.log("FIXTURE_OUT::E2E_VERIFIER", address(verifier));
    }
}
