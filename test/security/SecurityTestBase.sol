// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprServiceTestBase} from "@test/helpers/ClprServiceTestBase.sol";
import {SecurityAssertions} from "@test/security/SecurityAssertions.sol";

/// @notice Base for the service-level attacker-framed suites in `test/security/`.
/// @dev Every test in this tree restates a row of `docs/security-test-matrix.md` from the
///      attacker's point of view, and carries that row's id in its name — `test_X1_...`
///      asserts row X1. The matrix is the canonical description of the attack, why it
///      matters, and which guard defends it; this tree only asserts.
///
///      Rows classified `E*` in the matrix are deliberately NOT restated here: their
///      existing assertion is adequate and duplicating it would give two places to rot.
///      The matrix points at the owning test instead.
abstract contract SecurityTestBase is ClprServiceTestBase, SecurityAssertions {}
