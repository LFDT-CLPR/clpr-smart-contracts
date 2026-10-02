// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprServiceTestBase} from "@test/helpers/ClprServiceTestBase.sol";
import {SecurityAssertions} from "@test/security/SecurityAssertions.sol";

/// @notice Base for the service-level attack suites: a `ClprService` with an open channel, plus
///         the shared attack assertions.
abstract contract SecurityTestBase is ClprServiceTestBase, SecurityAssertions {}
