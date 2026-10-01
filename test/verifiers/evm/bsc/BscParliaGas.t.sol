// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {BscParliaVerifier} from "@hiero-ledger/clpr/verifiers/evm/bsc/BscParliaVerifier.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {BscParliaFixtures} from "@test/verifiers/evm/bsc/BscParliaFixtures.sol";

/// @dev Gas and calldata of BscParliaVerifier at mainnet scale (21 validators, every epoch a new
///      set — BEP-131 candidate rotation makes that the common case), for 0, 1, 4 and 16 rotations
///      in one bundle. Hedera limits: 15M gas per transaction, 128 KB calldata.
contract BscParliaGasTest is BscParliaFixtures {
    uint256 internal constant N = 21;
    uint64 internal constant E0 = 10_000;
    uint64 internal constant ACTIVE0 = E0 + 50;

    function _measure(uint256 rotations) internal returns (uint256 gasUsed, uint256 calldataBytes) {
        BscParliaVerifier verifier = new BscParliaVerifier();
        (bytes32 stateRoot, bytes memory account, bytes memory storage_) = _serviceState();

        Val[] memory first = _makeSet(N, "gas-0");
        Val[] memory cur = first;
        bytes[] memory steps = new bytes[](rotations);
        uint64 epoch = E0;
        uint64 activeFrom = ACTIVE0;
        for (uint256 i = 0; i < rotations; i++) {
            Val[] memory next = _makeSet(N, string.concat("gas-", vm.toString(i + 1)));
            epoch += EPOCH_LENGTH;
            Hdr memory e = _header(
                epoch, keccak256(abi.encode(epoch)), bytes32(0), _epochExtraBody(next, TURN_LENGTH), cur[0].ecdsaPk
            );
            uint64 bits = _allBits(N) & ~uint64(1 << 3); // 20/21, as on mainnet
            steps[i] = _triple(_chain(e), _finalize(cur, bits, e), _keysList(next));
            activeFrom = epoch + _checkLen(N, TURN_LENGTH) + 1;
            cur = next;
        }
        Hdr memory s = _header(activeFrom + 10, keccak256("p"), stateRoot, _plainExtraBody(), cur[0].ecdsaPk);
        bytes memory bundle = _bundle(
            RLP.encode(steps),
            _entries(first),
            _pair(_chain(s), _finalize(cur, _allBits(N) & ~uint64(1 << 3), s)),
            account,
            storage_
        );
        bytes memory anchor = _anchor(first, E0, ACTIVE0);
        bytes memory ctx = _channelContext();
        uint256 g = gasleft();
        verifier.verifyBundle(bundle, anchor, ctx);
        gasUsed = g - gasleft();
        calldataBytes = abi.encodeCall(verifier.verifyBundle, (bundle, anchor, ctx)).length;
    }

    function test_gas_rotationScaling() public {
        (uint256 g0, uint256 c0) = _measure(0);
        (uint256 g1, uint256 c1) = _measure(1);
        (uint256 g4, uint256 c4) = _measure(4);
        (uint256 g16, uint256 c16) = _measure(16);
        console.log("21 validators, synthetic 1-node MPT; execution gas / calldata bytes");
        console.log("  0 rotations:", g0, c0);
        console.log("  1 rotation: ", g1, c1);
        console.log("  4 rotations:", g4, c4);
        console.log(" 16 rotations:", g16, c16);
        console.log("  per rotation (gas, bytes):", (g16 - g0) / 16, (c16 - c0) / 16);
        assertLt(g16, 15_000_000, "16 rotations fit Hedera's 15M gas");
        assertLt(c16, 128 * 1024, "16 rotations fit 128 KB calldata");
    }
}
