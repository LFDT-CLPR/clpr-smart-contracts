// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprTestBase} from "@test/helpers/ClprTestBase.sol";

/// @notice Base contract for ClprService test suite.
/// @dev Inherits from ClprTestBase and adds suite-specific helpers for service tests.
/// @dev Currently extends ClprTestBase without additional suite-specific helpers,
///      but provides a dedicated namespace for future ClprService-only utilities.
abstract contract ClprServiceTestBase is ClprTestBase {
    // ClprService tests use shared ClprTestBase helpers for channel registration,
    // message sending, and configuration updates. Additional suite-specific helpers
    // can be added here as test coverage expands.

    }
