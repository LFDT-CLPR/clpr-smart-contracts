// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprService} from "@hiero-ledger/clpr/ClprService.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprDeployHelper} from "@test/helpers/ClprDeployHelper.sol";
import {ClprServiceTestBase} from "@test/helpers/ClprServiceTestBase.sol";

contract ClprService_Constructor is ClprServiceTestBase {
    // None of these tests touch `service`/`verifier`/`channelId` — they only need `owner`
    // (a field initializer, set regardless) and ClprDeployHelper. Skip the full channel/
    // config setup ceremony from the base setUp() to avoid paying for it on every run.
    function setUp() public override {}

    function test_constructor_revertsOnZeroLogicAddress_channelLogic() public {
        ClprDeployHelper.Modules memory m = ClprDeployHelper.deployModules();

        vm.expectRevert(ClprService.ZeroLogicAddress.selector);
        new ClprService(
            owner,
            1,
            "eip155:1337",
            address(0),
            m.messagingLogic,
            m.bundleLogic,
            m.connectorLogic,
            m.adminLogic,
            m.bundleDecodeHelper,
            address(0)
        );
    }

    function test_constructor_revertsOnZeroLogicAddress_messagingLogic() public {
        ClprDeployHelper.Modules memory m = ClprDeployHelper.deployModules();

        vm.expectRevert(ClprService.ZeroLogicAddress.selector);
        new ClprService(
            owner,
            1,
            "eip155:1337",
            m.channelLogic,
            address(0),
            m.bundleLogic,
            m.connectorLogic,
            m.adminLogic,
            m.bundleDecodeHelper,
            address(0)
        );
    }

    function test_constructor_revertsOnZeroLogicAddress_bundleLogic() public {
        ClprDeployHelper.Modules memory m = ClprDeployHelper.deployModules();

        vm.expectRevert(ClprService.ZeroLogicAddress.selector);
        new ClprService(
            owner,
            1,
            "eip155:1337",
            m.channelLogic,
            m.messagingLogic,
            address(0),
            m.connectorLogic,
            m.adminLogic,
            m.bundleDecodeHelper,
            address(0)
        );
    }

    function test_constructor_revertsOnZeroLogicAddress_connectorLogic() public {
        ClprDeployHelper.Modules memory m = ClprDeployHelper.deployModules();

        vm.expectRevert(ClprService.ZeroLogicAddress.selector);
        new ClprService(
            owner,
            1,
            "eip155:1337",
            m.channelLogic,
            m.messagingLogic,
            m.bundleLogic,
            address(0),
            m.adminLogic,
            m.bundleDecodeHelper,
            address(0)
        );
    }

    function test_constructor_revertsOnZeroLogicAddress_adminLogic() public {
        ClprDeployHelper.Modules memory m = ClprDeployHelper.deployModules();

        vm.expectRevert(ClprService.ZeroLogicAddress.selector);
        new ClprService(
            owner,
            1,
            "eip155:1337",
            m.channelLogic,
            m.messagingLogic,
            m.bundleLogic,
            m.connectorLogic,
            address(0),
            m.bundleDecodeHelper,
            address(0)
        );
    }

    function test_constructor_revertsOnZeroLogicAddress_bundleDecodeHelper() public {
        ClprDeployHelper.Modules memory m = ClprDeployHelper.deployModules();

        vm.expectRevert(ClprService.ZeroLogicAddress.selector);
        new ClprService(
            owner,
            1,
            "eip155:1337",
            m.channelLogic,
            m.messagingLogic,
            m.bundleLogic,
            m.connectorLogic,
            m.adminLogic,
            address(0),
            address(0)
        );
    }

    function test_constructor_revertsOnModuleNotDeployed_channelLogic() public {
        ClprDeployHelper.Modules memory m = ClprDeployHelper.deployModules();
        address eoa = makeAddr("notDeployed"); // non-zero, code.length == 0

        vm.expectRevert(ClprTypes.ClprModuleNotDeployed.selector);
        new ClprService(
            owner,
            1,
            "eip155:1337",
            eoa,
            m.messagingLogic,
            m.bundleLogic,
            m.connectorLogic,
            m.adminLogic,
            m.bundleDecodeHelper,
            address(0)
        );
    }

    function test_constructor_revertsOnModuleNotDeployed_messagingLogic() public {
        ClprDeployHelper.Modules memory m = ClprDeployHelper.deployModules();
        address eoa = makeAddr("notDeployed"); // non-zero, code.length == 0

        vm.expectRevert(ClprTypes.ClprModuleNotDeployed.selector);
        new ClprService(
            owner,
            1,
            "eip155:1337",
            m.channelLogic,
            eoa,
            m.bundleLogic,
            m.connectorLogic,
            m.adminLogic,
            m.bundleDecodeHelper,
            address(0)
        );
    }

    function test_constructor_revertsOnModuleNotDeployed_bundleLogic() public {
        ClprDeployHelper.Modules memory m = ClprDeployHelper.deployModules();
        address eoa = makeAddr("notDeployed"); // non-zero, code.length == 0

        vm.expectRevert(ClprTypes.ClprModuleNotDeployed.selector);
        new ClprService(
            owner,
            1,
            "eip155:1337",
            m.channelLogic,
            m.messagingLogic,
            eoa,
            m.connectorLogic,
            m.adminLogic,
            m.bundleDecodeHelper,
            address(0)
        );
    }

    function test_constructor_revertsOnModuleNotDeployed_connectorLogic() public {
        ClprDeployHelper.Modules memory m = ClprDeployHelper.deployModules();
        address eoa = makeAddr("notDeployed"); // non-zero, code.length == 0

        vm.expectRevert(ClprTypes.ClprModuleNotDeployed.selector);
        new ClprService(
            owner,
            1,
            "eip155:1337",
            m.channelLogic,
            m.messagingLogic,
            m.bundleLogic,
            eoa,
            m.adminLogic,
            m.bundleDecodeHelper,
            address(0)
        );
    }

    function test_constructor_revertsOnModuleNotDeployed_adminLogic() public {
        ClprDeployHelper.Modules memory m = ClprDeployHelper.deployModules();
        address eoa = makeAddr("notDeployed"); // non-zero, code.length == 0

        vm.expectRevert(ClprTypes.ClprModuleNotDeployed.selector);
        new ClprService(
            owner,
            1,
            "eip155:1337",
            m.channelLogic,
            m.messagingLogic,
            m.bundleLogic,
            m.connectorLogic,
            eoa,
            m.bundleDecodeHelper,
            address(0)
        );
    }

    function test_constructor_revertsOnModuleNotDeployed_bundleDecodeHelper() public {
        ClprDeployHelper.Modules memory m = ClprDeployHelper.deployModules();
        address eoa = makeAddr("notDeployed"); // non-zero, code.length == 0

        vm.expectRevert(ClprTypes.ClprModuleNotDeployed.selector);
        new ClprService(
            owner,
            1,
            "eip155:1337",
            m.channelLogic,
            m.messagingLogic,
            m.bundleLogic,
            m.connectorLogic,
            m.adminLogic,
            eoa,
            address(0)
        );
    }

    /// @dev Deviation D4 (spec §7): clpr_enabled must default to false — the service is
    ///      inert until the owner explicitly enables it. Deliberately does NOT call
    ///      setClprEnabled(true) anywhere in this test's own setup, unlike every other
    ///      test suite's base setUp() (which enables immediately to avoid re-testing this
    ///      scenario in every unrelated test).
    function test_constructor_clprEnabled_defaultsFalseUntilOwnerEnables() public {
        ClprService freshService = _deployClprService(1, "eip155:1337");

        // Freshly deployed: a whenEnabled-gated call must be blocked.
        vm.expectRevert(ClprTypes.ClprDisabled.selector);
        freshService.updateLedgerConfiguration(hex"1234", defaultThrottles, "", "");

        // Cannot enable before initialize() has run.
        vm.expectRevert(ClprTypes.ClprNotInitialized.selector);
        freshService.setClprEnabled(true);

        // initialize() applies config while still disabled.
        freshService.initialize(hex"1234", defaultThrottles, "", "", defaultEcon);

        // Owner explicitly enables; the service is already configured.
        freshService.setClprEnabled(true);
        freshService.updateLedgerConfiguration(hex"1234", defaultThrottles, "", "");
    }

    function test_constructor_initialize_revertsIfCalledTwice() public {
        ClprService freshService = _deployClprService(1, "eip155:1337");
        freshService.initialize(hex"1234", defaultThrottles, "", "", defaultEcon);

        vm.expectRevert(ClprTypes.ClprAlreadyInitialized.selector);
        freshService.initialize(hex"1234", defaultThrottles, "", "", defaultEcon);
    }
}
