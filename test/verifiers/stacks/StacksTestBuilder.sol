// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test, Vm} from "forge-std/Test.sol";
import {Sha512t256Call} from "../../../src/libraries/crypto/ClprSha512t256Hasher.sol";
import {StacksVerifier} from "../../../src/verifiers/stacks/StacksVerifier.sol";

/// @notice Builds synthetic Stacks data with the exact wire formats of stacks-core: a MARF proof
///         shaped like a real one for a fresh write (Node256 → Node256 → Node256 → Node4 → leaf,
///         plus a 24-hash shunt head), a Nakamoto header committing to its root, and signer
///         signatures from Foundry keys. Used where no live CLPR service exists (the queue record).
abstract contract StacksTestBuilder is Test {
    address internal hasher;

    struct Signer {
        uint256 key;
        address addr;
        bytes32 x;
        bytes32 y;
        uint64 weight;
    }

    function _h(bytes memory b) internal view returns (bytes32) {
        return Sha512t256Call.hash(hasher, b);
    }

    // ── signers ──────────────────────────────────────────────────────────────

    function _signers(string memory seed, uint64[] memory weights) internal returns (Signer[] memory s) {
        s = new Signer[](weights.length);
        for (uint256 i = 0; i < weights.length; ++i) {
            Vm.Wallet memory w = vm.createWallet(string.concat(seed, vm.toString(i)));
            s[i] = Signer({
                key: w.privateKey, addr: w.addr, x: bytes32(w.publicKeyX), y: bytes32(w.publicKeyY), weight: weights[i]
            });
        }
    }

    function _set(uint64 cycle, Signer[] memory s) internal pure returns (StacksVerifier.SignerSet memory set) {
        set.cycle = cycle;
        set.signers = new address[](s.length);
        set.weights = new uint64[](s.length);
        for (uint256 i = 0; i < s.length; ++i) {
            set.signers[i] = s[i].addr;
            set.weights[i] = s[i].weight;
        }
    }

    /// @dev Signatures of signers whose bit is set in `mask`, as `index ‖ recid ‖ r ‖ s`.
    function _sign(Signer[] memory s, bytes32 blockHash, uint256 mask) internal pure returns (bytes memory out) {
        for (uint256 i = 0; i < s.length; ++i) {
            if ((mask >> i) & 1 == 0) continue;
            (uint8 v, bytes32 r, bytes32 ss) = vm.sign(s[i].key, blockHash);
            out = bytes.concat(out, abi.encodePacked(uint16(i), uint8(v - 27), r, ss));
        }
    }

    // ── header ───────────────────────────────────────────────────────────────

    /// @dev A version-1 header preimage (no signer signatures) with the given chain length and state root.
    function _header(uint64 chainLength, bytes32 stateRoot) internal pure returns (bytes memory) {
        return bytes.concat(
            abi.encodePacked(uint8(1), chainLength, uint64(50_000), bytes20(keccak256("consensus"))),
            abi.encodePacked(keccak256(abi.encode("parent", chainLength)), keccak256("txroot"), stateRoot),
            abi.encodePacked(uint64(1_790_000_000 + chainLength), uint8(0), keccak256("minerR"), keccak256("minerS")),
            abi.encodePacked(uint16(1), uint32(1), uint8(1), uint32(0)) // pox_treatment = [1], no problematic txs
        );
    }

    function _blockHash(bytes memory header) internal view returns (bytes32) {
        return _h(header);
    }

    function _blockId(bytes memory header) internal view returns (bytes32) {
        bytes20 ch;
        assembly {
            ch := mload(add(header, 49)) // offset 17
        }
        return _h(abi.encodePacked(_h(header), ch));
    }

    // ── MARF proof (single segment, fresh write) ─────────────────────────────

    /// @dev Proof of `path → valueHash` in a 4-level trie shaped like mainnet's; returns the proof and the MARF root.
    function _marf(bytes32 path, bytes32 valueHash) internal view returns (bytes memory proof, bytes32 root) {
        return _marfShaped(path, valueHash, false);
    }

    /// @dev The same with Node4 at every level (about 2 KB instead of 53 KB), for tests that only need a
    ///      valid proof, such as the compliance suite's truncation sweep.
    function _marfCompact(bytes32 path, bytes32 valueHash) internal view returns (bytes memory proof, bytes32 root) {
        return _marfShaped(path, valueHash, true);
    }

    function _marfShaped(bytes32 path, bytes32 valueHash, bool compact)
        internal
        view
        returns (bytes memory proof, bytes32 root)
    {
        bytes memory leafPath = new bytes(28);
        for (uint256 i = 0; i < 28; ++i) {
            leafPath[i] = path[4 + i];
        }
        bytes memory leafData = abi.encodePacked(valueHash, bytes8(0));
        bytes32 h = _h(abi.encodePacked(uint8(1), uint8(28), leafPath, leafData));
        proof = abi.encodePacked(uint8(4), uint8(path[3]), uint32(28), leafPath, leafData);

        // Node4 at depth 3, child leaf at slot 0
        bytes memory n4;
        (n4, h) = _node(0, uint8(path[3]), 1, h, 3);
        proof = bytes.concat(proof, n4);
        // Node256 (or Node4 when compact) at depths 2, 1, 0 (root); child type ids Node4 (2), then Node256 (5)
        uint256 t = compact ? 0 : 3;
        uint8 upper = compact ? 2 : 5;
        bytes memory item;
        (item, h) = _node(t, uint8(path[2]), 2, h, 2);
        proof = bytes.concat(proof, item);
        (item, h) = _node(t, uint8(path[1]), upper, h, 1);
        proof = bytes.concat(proof, item);
        (item, h) = _node(t, uint8(path[0]), upper, h, 0);
        proof = bytes.concat(proof, item);

        bytes memory anc;
        for (uint256 i = 0; i < 24; ++i) {
            anc = bytes.concat(anc, keccak256(abi.encode("ancestor", i)));
        }
        proof = bytes.concat(proof, abi.encodePacked(uint8(5), uint64(0), uint32(24), anc));
        root = _h(bytes.concat(h, anc));
        proof = bytes.concat(abi.encodePacked(uint32(6)), proof); // leaf, Node4, 3 × Node256, shunt
    }

    /// @dev One node item and its hash. t: 0 = Node4, 3 = Node256. The child sits at `chr` (Node256:
    ///      slot chr; Node4: slot 0); other slots are back-pointers with random siblings.
    function _node(uint256 t, uint8 chr, uint8 childId, bytes32 child, uint256 depth)
        internal
        view
        returns (bytes memory item, bytes32 h)
    {
        uint256 n = t == 0 ? 4 : 256;
        uint256 at = t == 0 ? 0 : chr;
        bytes memory ptrs = new bytes(34 * n);
        bytes memory sibs = new bytes(32 * (n - 1));
        bytes memory kids = new bytes(32 * n);
        uint256 s;
        for (uint256 j = 0; j < n; ++j) {
            uint8 pid;
            uint8 c;
            bytes32 back;
            bytes32 kid;
            if (j == at) {
                (pid, c, back, kid) = (childId, chr, bytes32(0), child);
            } else {
                // a back-pointer child hashes as the block id it names
                back = keccak256(abi.encode("block", depth, j));
                (pid, c, kid) = (0x85, t == 0 ? uint8(uint256(chr) + j) : uint8(j), back);
                assembly {
                    mstore(add(add(sibs, 0x20), mul(s, 32)), back)
                }
                ++s;
            }
            assembly {
                let e := add(add(ptrs, 0x20), mul(j, 34))
                mstore8(e, pid)
                mstore8(add(e, 1), c)
                mstore(add(e, 2), back)
                mstore(add(add(kids, 0x20), mul(j, 32)), kid)
            }
        }
        uint8 id = uint8(t + 2);
        item = abi.encodePacked(uint8(t), chr, id, uint32(0), uint32(n), ptrs, sibs);
        h = _h(abi.encodePacked(id, ptrs, uint8(0), kids));
    }
}
