// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Sha512t256} from "../../../src/libraries/crypto/Sha512t256.sol";
import {Sha256Midstate} from "../../../src/libraries/crypto/Sha256Midstate.sol";

contract ShaHarness {
    function h512(bytes memory d) external pure returns (bytes32) {
        return Sha512t256.hash(d);
    }

    function h256(bytes32 st, uint256 n, bytes memory d) external pure returns (bytes32) {
        return Sha256Midstate.resume(st, n, d);
    }
}
