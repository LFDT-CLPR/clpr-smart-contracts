// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title ClprAttestorQuorum
/// @notice A K-of-N set of secp256k1 attestors, committed as
///         `setHash = keccak256(abi.encode(threshold, attestors))` with `attestors` strictly
///         ascending. Signatures are 65-byte (r, s, v) over a 32-byte digest, low-s only; signers
///         must appear in strictly ascending order, so none counts twice.
library ClprAttestorQuorum {
    uint256 private constant HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    error AttestorSetMismatch();
    error AttestorSetInvalid();
    error AttestorSignatureInvalid(uint256 index);
    error AttestorNotInSet(address signer);
    error AttestorOrder(uint256 index);
    error AttestorQuorumNotReached(uint256 have, uint256 need);

    struct Set {
        uint256 threshold;
        address[] attestors;
    }

    /// @notice Decode RLP [threshold, [attestor, ...]] and check it against `setHash`.
    function decode(Memory.Slice item, bytes32 setHash) internal pure returns (Set memory s) {
        s = decodeUnchecked(item);
        if (hash(s) != setHash) revert AttestorSetMismatch();
    }

    /// @notice Decode RLP [threshold, [attestor, ...]] and check its shape (1 <= threshold <= N,
    ///         a strict majority of N, ascending attestors).
    function decodeUnchecked(Memory.Slice item) internal pure returns (Set memory s) {
        Memory.Slice[] memory f = RLP.readList(item);
        if (f.length != 2) revert AttestorSetInvalid();
        s.threshold = RLP.readUint256(f[0]);
        Memory.Slice[] memory list = RLP.readList(f[1]);
        s.attestors = new address[](list.length);
        for (uint256 i = 0; i < list.length; ++i) {
            s.attestors[i] = RLP.readAddress(list[i]);
            if (s.attestors[i] == address(0) || (i > 0 && s.attestors[i] <= s.attestors[i - 1])) {
                revert AttestorSetInvalid();
            }
        }
        if (s.threshold == 0 || s.threshold > list.length || s.threshold * 2 <= list.length) {
            revert AttestorSetInvalid();
        }
    }

    function hash(Set memory s) internal pure returns (bytes32) {
        return keccak256(abi.encode(s.threshold, s.attestors));
    }

    /// @notice Require at least `threshold` distinct members of `s` to have signed `digest`.
    function requireQuorum(Set memory s, bytes32 digest, Memory.Slice sigsItem) internal pure {
        Memory.Slice[] memory sigs = RLP.readList(sigsItem);
        if (sigs.length < s.threshold) revert AttestorQuorumNotReached(sigs.length, s.threshold);
        address prev;
        uint256 j; // cursor into the ascending attestor list
        for (uint256 i = 0; i < sigs.length; ++i) {
            address signer = _recover(digest, RLP.readBytes(sigs[i]), i);
            if (signer <= prev) revert AttestorOrder(i);
            prev = signer;
            while (j < s.attestors.length && s.attestors[j] < signer) ++j;
            if (j == s.attestors.length || s.attestors[j] != signer) revert AttestorNotInSet(signer);
        }
    }

    function _recover(bytes32 digest, bytes memory sig, uint256 index) private pure returns (address signer) {
        if (sig.length != 65) revert AttestorSignatureInvalid(index);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        if (v < 27) v += 27;
        if ((v != 27 && v != 28) || uint256(s) > HALF_N) revert AttestorSignatureInvalid(index);
        signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert AttestorSignatureInvalid(index);
    }
}
