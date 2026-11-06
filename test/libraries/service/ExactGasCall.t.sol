// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ExactGasCall} from "@hiero-ledger/clpr/libraries/service/ExactGasCall.sol";

contract ExactGasCallHarness {
    function callWithExactGas(address target, uint256 gasLimit, bytes memory data, bool decodeBytesReturn)
        external
        returns (bool success, bool wellFormed, bytes memory returnData)
    {
        return ExactGasCall.callWithExactGas(target, gasLimit, data, decodeBytesReturn);
    }
}

contract GasRecorder {
    error Boom(uint256 code);

    uint256 public seen;

    function record() external {
        seen = gasleft();
    }

    /// @dev Returns `raw` byte for byte, not ABI-encoded.
    function returnExactly(bytes calldata raw) external pure {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            calldatacopy(ptr, raw.offset, raw.length)
            return(ptr, raw.length)
        }
    }

    function boom(uint256 code) external pure {
        revert Boom(code);
    }
}

contract ExactGasCallTest is Test {
    /// @dev Nothing touches `recorder` before the helper calls it, so the callee pays a cold account
    ///      access (EIP-2929) from its budget.
    uint256 private constant COLD_ACCOUNT_ACCESS = 2_600;

    /// @dev The rest of what the callee can find missing from `gasLimit`: the instructions before the
    ///      CALL and the callee's dispatch before its first `gasleft()`.
    uint256 private constant ENTRY_GAS = 1_000;

    ExactGasCallHarness private harness;
    GasRecorder private recorder;

    function setUp() public {
        harness = new ExactGasCallHarness();
        recorder = new GasRecorder();
    }

    function _recordCall(uint256 gasLimit) private view returns (bytes memory) {
        return abi.encodeCall(
            harness.callWithExactGas, (address(recorder), gasLimit, abi.encodeCall(GasRecorder.record, ()), false)
        );
    }

    /// @dev Smallest gas for which `to.call(callData)` succeeds, by bisection between a failing `lo`
    ///      and a succeeding `hi`. Each attempt runs on a snapshot, so nothing it writes persists.
    function _minimalGas(address to, bytes memory callData, uint256 lo, uint256 hi) private returns (uint256) {
        assertFalse(_succeeds(to, callData, lo), "lower bound must fail");
        assertTrue(_succeeds(to, callData, hi), "upper bound must succeed");
        while (hi - lo > 1) {
            uint256 mid = (lo + hi) / 2;
            if (_succeeds(to, callData, mid)) hi = mid;
            else lo = mid;
        }
        return hi;
    }

    function _succeeds(address to, bytes memory callData, uint256 gasAmount) private returns (bool ok) {
        uint256 snapshot = vm.snapshotState();
        (ok,) = to.call{gas: gasAmount}(callData);
        vm.revertToState(snapshot);
    }

    /// At the smallest outer gas that lets the call return, the callee still received its
    /// `gasLimit`, less the CALL's own cost; one unit less and the helper refuses to call at all,
    /// and the gas it required was `gasLimit + gasLimit / 63`, with no fixed overhead.
    function test_calleeReceivesItsGasLessTheCallCostOrTheCallReverts() public {
        // Large enough that dropping the `gasLimit / 63` term leaves the callee visibly short.
        uint256 gasLimit = 2_000_000;
        bytes memory callData = _recordCall(gasLimit);
        uint256 gMin = _minimalGas(address(harness), callData, 10_000, 3_000_000);

        (bool ok, bytes memory ret) = address(harness).call{gas: gMin - 1}(callData);
        assertFalse(ok, "one gas less must fail");
        // Only the selector is compared.
        // forge-lint: disable-next-line(unsafe-typecast)
        assertEq(bytes4(ret), ExactGasCall.InsufficientGasForCall.selector, "and fail at the gas check");
        uint256 required;
        assembly ("memory-safe") {
            required := mload(add(ret, 36))
        }
        assertEq(required, gasLimit + gasLimit / 63, "the budget and the 63/64 reserve, nothing more");

        (ok,) = address(harness).call{gas: gMin}(callData);
        assertTrue(ok, "minimal gas must succeed");
        assertGe(
            recorder.seen(),
            gasLimit - COLD_ACCOUNT_ACCESS - ENTRY_GAS,
            "callee must receive gasLimit, less the CALL's cost"
        );
        assertLe(recorder.seen(), gasLimit, "and no more");
    }

    /// Whatever outer gas the caller picks, a call that returns never gave the callee less than
    /// `gasLimit`, less the CALL's own cost.
    function testFuzz_calleeIsNeverStarved(uint256 gasLimitSeed, uint256 outerSeed) public {
        uint256 gasLimit = bound(gasLimitSeed, 30_000, 2_000_000);
        uint256 outer = bound(outerSeed, 20_000, 3_000_000);
        (bool ok, bytes memory ret) = address(harness).call{gas: outer}(_recordCall(gasLimit));
        if (!ok) return;
        (bool success,,) = abi.decode(ret, (bool, bool, bytes));
        assertTrue(success, "a call that returns must not have starved the callee");
        assertGe(
            recorder.seen(),
            gasLimit - COLD_ACCOUNT_ACCESS - ENTRY_GAS,
            "callee must receive gasLimit, less the CALL's cost"
        );
        assertLe(recorder.seen(), gasLimit, "and no more");
    }

    function _decodeReturnOf(bytes memory raw) private returns (bool success, bool wellFormed, bytes memory ret) {
        return
            harness.callWithExactGas(address(recorder), 100_000, abi.encodeCall(GasRecorder.returnExactly, (raw)), true);
    }

    function _assertDecodes(bytes memory raw, bytes memory expected) private {
        (bool success, bool wellFormed, bytes memory ret) = _decodeReturnOf(raw);
        assertTrue(success);
        assertTrue(wellFormed, "a valid encoding of one `bytes` must decode");
        assertEq(ret, expected);
    }

    function _assertReturnedRaw(bytes memory raw) private {
        (bool success, bool wellFormed, bytes memory ret) = _decodeReturnOf(raw);
        assertTrue(success);
        assertFalse(wellFormed, "a malformed return must not decode");
        assertEq(ret, raw, "a malformed return comes back raw");
    }

    function test_wellFormedBytesReturnIsDecoded() public {
        _assertDecodes(abi.encode(bytes("hello")), "hello");
        _assertDecodes(abi.encode(bytes("")), "");
    }

    /// A single zero word is accepted, as `abi.decode` accepts it: offset 0 points at itself and
    /// reads as length 0.
    function test_aSingleZeroWordDecodesToEmptyBytes() public {
        _assertDecodes(new bytes(32), "");
    }

    /// Each bound accepts its last valid value and rejects one more.
    function test_decoderBounds() public {
        _assertReturnedRaw("");
        _assertReturnedRaw(new bytes(31));
        // A 64-byte return: the last valid offset is 32, with a zero length word there.
        _assertDecodes(abi.encodePacked(uint256(32), uint256(0)), "");
        _assertReturnedRaw(abi.encodePacked(uint256(33), uint256(0)));
        // A 96-byte return with offset 32: the last valid length is 32.
        _assertDecodes(abi.encodePacked(uint256(32), uint256(32), bytes32(0)), abi.encodePacked(bytes32(0)));
        _assertReturnedRaw(abi.encodePacked(uint256(32), uint256(33), bytes32(0)));
    }

    function test_noReturnDataIsCopiedWhenNotAsked() public {
        (bool success, bool wellFormed, bytes memory ret) = harness.callWithExactGas(
            address(recorder), 100_000, abi.encodeCall(GasRecorder.returnExactly, (abi.encode(bytes("hello")))), false
        );
        assertTrue(success);
        assertFalse(wellFormed, "nothing is decoded when not asked");
        assertEq(ret.length, 0);
    }

    /// The EVM reports a call to an address without code as a success. The helper reports it as a
    /// failure, so a caller cannot take a call that ran nothing for one that ran.
    function test_callToAnAddressWithoutCodeFails() public {
        (bool success,, bytes memory ret) =
            harness.callWithExactGas(makeAddr("no-code"), 100_000, abi.encodeCall(GasRecorder.record, ()), false);
        assertFalse(success, "a call that ran no code must not succeed");
        assertEq(ret.length, 0);
    }

    function test_revertDataIsReturnedWhenTheCallFails() public {
        (bool success, bool wellFormed, bytes memory ret) =
            harness.callWithExactGas(address(recorder), 100_000, abi.encodeCall(GasRecorder.boom, (7)), true);
        assertFalse(success);
        assertFalse(wellFormed);
        assertEq(ret, abi.encodeWithSelector(GasRecorder.Boom.selector, 7));
    }
}
