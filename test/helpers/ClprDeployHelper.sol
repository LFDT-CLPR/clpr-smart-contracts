// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {ClprService} from "@hiero-ledger/clpr/ClprService.sol";

library ClprDeployHelper {
    Vm private constant _VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    struct Modules {
        address channelLogic;
        address messagingLogic;
        address bundleLogic;
        address connectorLogic;
        address adminLogic;
        address bundleDecodeHelper;
    }

    function _deployCode(string memory artifact) private returns (address addr) {
        bytes memory code = _VM.getCode(artifact);
        assembly {
            addr := create(0, add(code, 0x20), mload(code))
        }
    }

    function _deployCode(string memory artifact, bytes memory args) private returns (address addr) {
        bytes memory code = abi.encodePacked(_VM.getCode(artifact), args);
        assembly {
            addr := create(0, add(code, 0x20), mload(code))
        }
    }

    function deployModules() internal returns (Modules memory m) {
        m.channelLogic = _deployCode("ChannelLogic.sol:ChannelLogic");
        m.messagingLogic = _deployCode("MessagingLogic.sol:MessagingLogic");
        m.bundleLogic = _deployCode("BundleLogic.sol:BundleLogic");
        m.connectorLogic = _deployCode("ConnectorLogic.sol:ConnectorLogic");
        m.adminLogic = _deployCode("AdminLogic.sol:AdminLogic");
        m.bundleDecodeHelper = _deployCode("BundleDecodeHelper.sol:BundleDecodeHelper");
    }

    function deployServiceForTests(address owner, uint32 protocolVersion, string memory chainId)
        internal
        returns (ClprService)
    {
        Modules memory m = deployModules();
        bytes memory args = abi.encode(
            owner,
            protocolVersion,
            chainId,
            m.channelLogic,
            m.messagingLogic,
            m.bundleLogic,
            m.connectorLogic,
            m.adminLogic,
            m.bundleDecodeHelper,
            address(0) // feeToken: native value
        );
        return ClprService(payable(_deployCode("ClprService.sol:ClprService", args)));
    }

    function deployServiceForTests(address owner) internal returns (ClprService) {
        return deployServiceForTests(owner, 1, "eip155:1337");
    }
}
