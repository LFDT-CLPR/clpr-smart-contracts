// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";

/// @title VerifierComplianceCoverageTest
/// @notice Asserts that every concrete IClprVerifier implementation in src/verifiers/evm has at
///         least one compliance test adapter in test/verifiers/evm
/// @dev If you add a new IClprVerifier under src/verifiers/evm you MUST also create an adapter that extends
///      ClprVerifierComplianceTest and references the new verifier contract by name — otherwise
///      this test will fail and block CI.
///
///      Exclusion rules:
///        • abstract contract
///        • contract name starts with "Mock"
contract VerifierComplianceCoverageTest is Test {
    // ── string helpers ────────────────────────────────────────────────────────

    function _contains(string memory haystack, string memory needle) internal pure returns (bool) {
        return vm.contains(haystack, needle);
    }

    function _endsWith(string memory s, string memory suffix) internal pure returns (bool) {
        bytes memory sb = bytes(s);
        bytes memory sfx = bytes(suffix);
        if (sfx.length > sb.length) return false;
        for (uint256 i = 0; i < sfx.length; i++) {
            if (sb[sb.length - sfx.length + i] != sfx[i]) return false;
        }
        return true;
    }

    /// @dev Strip path and .sol extension to get the bare filename (e.g. "QBFTVerifier").
    function _basename(string memory path) internal pure returns (string memory) {
        bytes memory pb = bytes(path);
        uint256 lastSlash = 0;
        for (uint256 i = 0; i < pb.length; i++) {
            if (pb[i] == "/") lastSlash = i + 1;
        }
        // strip .sol (4 chars) from the end
        uint256 end = pb.length >= 4 ? pb.length - 4 : pb.length;
        bytes memory out = new bytes(end - lastSlash);
        for (uint256 i = 0; i < out.length; i++) {
            out[i] = pb[lastSlash + i];
        }
        return string(out);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// @dev Returns true when a source file represents a concrete (non-abstract, non-mock)
    ///      IClprVerifier implementation.
    function _isConcreteVerifier(string memory content) internal pure returns (bool) {
        if (!_contains(content, "IClprVerifier")) return false;
        if (_contains(content, "abstract contract")) return false;
        // "interface" files declare IClprVerifier, not implement it
        if (_contains(content, "interface IClprVerifier")) return false;
        return true;
    }

    /// @dev Returns true when the contract in the file should be excluded from the coverage
    ///      requirement.  Currently excludes names that begin with "Mock".
    function _isExcluded(string memory contractName) internal pure returns (bool) {
        // TODO: remove the legacy QBFTVerifier (incorrect implementation)
        //      remove line below
        if (keccak256(bytes(contractName)) == keccak256(bytes("QBFTVerifier"))) return true;

        bytes memory n = bytes(contractName);
        bytes memory prefix = bytes("Mock");
        if (n.length < prefix.length) return false;
        for (uint256 i = 0; i < prefix.length; i++) {
            if (n[i] != prefix[i]) return false;
        }
        return true;
    }

    // ── test ──────────────────────────────────────────────────────────────────

    function test_allConcreteVerifiersHaveComplianceTestAdapters() public {
        // 1. Collect all compliance-test adapter file contents from test/verifiers/compliance
        Vm.DirEntry[] memory testEntries = vm.readDir("test/verifiers/compliance", 5);
        string[] memory adapterContents = new string[](testEntries.length);
        uint256 adapterCount = 0;
        for (uint256 i = 0; i < testEntries.length; i++) {
            if (testEntries[i].isDir) continue;
            if (!_endsWith(testEntries[i].path, ".sol")) continue;
            string memory content = vm.readFile(testEntries[i].path);
            if (_contains(content, "ClprVerifierComplianceTest")) {
                adapterContents[adapterCount++] = content;
            }
        }

        // 2. Scan src/verifiers/evm for concrete IClprVerifier implementations
        Vm.DirEntry[] memory srcEntries = vm.readDir("src/verifiers/evm", 5);
        bool anyVerifierFound = false;
        for (uint256 i = 0; i < srcEntries.length; i++) {
            if (srcEntries[i].isDir) continue;
            if (!_endsWith(srcEntries[i].path, ".sol")) continue;

            string memory content = vm.readFile(srcEntries[i].path);
            if (!_isConcreteVerifier(content)) continue;

            string memory contractName = _basename(srcEntries[i].path);
            if (_isExcluded(contractName)) continue;

            anyVerifierFound = true;
            // Debugging the found verifiers; use -vv to see the log
            emit log_string(string.concat("found concrete verifier: ", srcEntries[i].path));

            // 3. Assert that at least one adapter references this verifier by contract name.
            bool covered = false;
            for (uint256 j = 0; j < adapterCount; j++) {
                if (_contains(adapterContents[j], contractName)) {
                    covered = true;
                    break;
                }
            }
            assertTrue(
                covered,
                string.concat(
                    "Missing compliance test adapter for: ",
                    srcEntries[i].path,
                    ". Create a contract in test/verifiers/evm extending ClprVerifierComplianceTest that references ",
                    contractName
                )
            );
        }

        // Sanity check: if zero verifiers were found the scan itself is broken.
        assertTrue(anyVerifierFound, "No concrete IClprVerifier implementations found in src/verifiers/");
    }
}
