// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";

/// @dev Estimate of the contract trace a Hedera consensus node records for a transaction (the
///      `ContractActions` and `ContractStateChanges` sidecars), checked against
///      `contracts.maxSerializedTraceDataBytes` (default 262,144 B). Above it the node fails the
///      transaction with INSUFFICIENT_GAS after executing it, although gas estimation and forks succeed
///      (hiero-consensus-node `ConversionUtils.throwIfUnsuccessfulCall`).
///
///      Same model as a callTracer-based estimate over a fork: every call frame's input and output,
///      precompile calls included, plus a per-frame and a per-storage-slot allowance for the protobuf
///      fields around them. Frames come from Foundry's state-diff recording; a precompile's output size
///      follows from its EIP, the measured call's own output is its return data. A Service entry point
///      (`completeChannel`, `submitBundle`) reaches the verifier through two more frames that carry the
///      same payload, the ClprService call and the delegatecall into its logic module; `wrapperFrames`
///      adds those. The Service's own storage and message dispatch are not modelled here.
abstract contract HederaTraceEstimate is Test {
    uint256 internal constant HEDERA_TRACE_LIMIT = 262_144;
    uint256 internal constant PER_ACTION = 96; // call type, ids, gas, gas used, depth, length prefixes
    uint256 internal constant PER_SLOT = 112; // slot, value read, value written, length prefixes
    uint256 internal constant SERVICE_WRAPPER_FRAMES = 2;

    /// @return est estimated trace bytes; @return gasUsed gas of the measured call (test-side delta).
    function _measure(address target, bytes memory data, uint256 wrapperFrames)
        internal
        returns (uint256 est, uint256 gasUsed)
    {
        vm.startStateDiffRecording();
        uint256 g = gasleft();
        (bool ok, bytes memory ret) = target.call(data);
        gasUsed = g - gasleft();
        VmSafe.AccountAccess[] memory acc = vm.stopAndReturnStateDiff();
        require(ok, "measured call reverted");

        uint256 frames = 1 + wrapperFrames;
        uint256 raw = (data.length + ret.length) * (1 + wrapperFrames);
        uint256 slots;
        bytes32[] memory seen = new bytes32[](256);
        for (uint256 i = 0; i < acc.length; i++) {
            VmSafe.AccountAccess memory a = acc[i];
            for (uint256 s = 0; s < a.storageAccesses.length; s++) {
                bytes32 k = keccak256(abi.encode(a.storageAccesses[s].account, a.storageAccesses[s].slot));
                bool dup;
                for (uint256 j = 0; j < slots; j++) {
                    if (seen[j] == k) dup = true;
                }
                if (!dup && slots < seen.length) seen[slots++] = k;
            }
            if (i == 0) continue; // the measured call itself (counted above)
            if (
                a.kind != VmSafe.AccountAccessKind.Call && a.kind != VmSafe.AccountAccessKind.StaticCall
                    && a.kind != VmSafe.AccountAccessKind.DelegateCall && a.kind != VmSafe.AccountAccessKind.CallCode
            ) continue;
            frames++;
            raw += a.data.length + _outputLength(a.account, a.data);
        }
        est = raw + frames * PER_ACTION + slots * PER_SLOT;
    }

    /// @dev Output size of a precompile call (EIP-2537 for 0x0b-0x11); a nested contract call is
    ///      charged its input size again as a stand-in for its unknown output.
    function _outputLength(address account, bytes memory input) internal pure returns (uint256) {
        uint160 a = uint160(account);
        if (a == 0x04) return input.length; // identity
        if (a == 0x05) {
            // modexp: output is the modulus length (third 32-byte length word)
            uint256 modLen;
            assembly ("memory-safe") {
                modLen := mload(add(input, 96))
            }
            return modLen;
        }
        if (a == 0x06 || a == 0x07 || a == 0x09 || a == 0x0a) return 64;
        if (a == 0x0b || a == 0x0c || a == 0x10) return 128; // G1ADD, G1MSM, MAP_FP_TO_G1
        if (a == 0x0d || a == 0x0e || a == 0x11) return 256; // G2ADD, G2MSM, MAP_FP2_TO_G2
        if (a >= 0x01 && a <= 0x100) return 32; // ecrecover, sha256, ripemd160, pairings, p256verify
        return input.length;
    }
}
