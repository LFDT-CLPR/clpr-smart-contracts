// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title MonadMpt
/// @notice Merkle-Patricia proof walker that parses trie nodes in place.
/// @dev Same semantics as {MerklePatriciaProof-getOrEmpty} (standard Ethereum hex-prefix MPT, keccak node
///      references, inline child nodes rejected) without per-node `bytes` copies or `Memory.Slice[]`
///      decoding of every node. Every node is bound to its parent by keccak, so node *contents* are honest
///      trie encodings; the parser still bounds-checks every length against the enclosing item.
///
///      Two proof encodings:
///        - a list of nodes (each an RLP string holding the node), root first;
///        - pooled: a shared node pool plus, per key, a list of indices into it. Proofs for many keys of
///          one trie share their upper nodes, so a pool roughly halves the calldata of a batch.
library MonadMpt {
    error MptInvalidProof();
    error MptHashMismatch();
    error MptInlineNode();

    uint256 private constant CONTINUE = 0;
    uint256 private constant DONE = 1;
    uint256 private constant BAD = 2;
    uint256 private constant HASH_BAD = 3;
    uint256 private constant INLINE = 4;

    /// @notice Walk the proof `nodes` (root first) along `key`. Returns the leaf's RLP value item (prefix
    ///         included, like {MerklePatriciaProof-getOrEmpty}) or an empty slice if `key` is proven absent.
    function getOrEmpty(bytes32 root, bytes32 key, Memory.Slice proofList) internal pure returns (Memory.Slice) {
        Memory.Slice[] memory nodes = RLP.readList(proofList);
        uint256[] memory idx = new uint256[](nodes.length);
        for (uint256 i = 0; i < idx.length; ++i) {
            idx[i] = i;
        }
        return _walk(root, key, nodes, idx);
    }

    /// @notice As {getOrEmpty} with nodes taken from `pool` at the positions listed in `idxList`.
    function getOrEmptyPooled(bytes32 root, bytes32 key, Memory.Slice[] memory pool, Memory.Slice idxList)
        internal
        pure
        returns (Memory.Slice)
    {
        Memory.Slice[] memory l = RLP.readList(idxList);
        uint256[] memory idx = new uint256[](l.length);
        for (uint256 i = 0; i < l.length; ++i) {
            idx[i] = RLP.readUint256(l[i]);
            if (idx[i] >= pool.length) revert MptInvalidProof();
        }
        return _walk(root, key, pool, idx);
    }

    function _walk(bytes32 root, bytes32 key, Memory.Slice[] memory pool, uint256[] memory idx)
        private
        pure
        returns (Memory.Slice value)
    {
        bytes32 expected = root;
        uint256 ki;
        for (uint256 i = 0; i < idx.length; ++i) {
            uint256 code;
            (code, expected, ki, value) = _node(pool[idx[i]], expected, key, ki);
            if (code == DONE) return value;
            if (code == HASH_BAD) revert MptHashMismatch();
            if (code == INLINE) revert MptInlineNode();
            if (code == BAD) revert MptInvalidProof();
        }
        revert MptInvalidProof(); // proof ended early
    }

    /// @dev Process one node item (an RLP string holding the node) at path position `ki`.
    function _node(Memory.Slice item, bytes32 expected, bytes32 key, uint256 ki)
        private
        pure
        returns (uint256 code, bytes32 next, uint256 nki, Memory.Slice value)
    {
        assembly ("memory-safe") {
            // RLP header at p, bounded by `end`: payload ptr, payload len, isList, ok.
            function hdr(p, end) -> dp, dl, isList, ok {
                ok := lt(p, end)
                let b := byte(0, mload(p))
                switch lt(b, 0x80)
                case 1 {
                    dp := p
                    dl := 1
                }
                default {
                    switch lt(b, 0xb8)
                    case 1 {
                        dp := add(p, 1)
                        dl := sub(b, 0x80)
                    }
                    default {
                        switch lt(b, 0xc0)
                        case 1 {
                            let ll := sub(b, 0xb7)
                            dl := shr(sub(256, mul(8, ll)), mload(add(p, 1)))
                            dp := add(add(p, 1), ll)
                        }
                        default {
                            isList := 1
                            switch lt(b, 0xf8)
                            case 1 {
                                dp := add(p, 1)
                                dl := sub(b, 0xc0)
                            }
                            default {
                                let ll := sub(b, 0xf7)
                                dl := shr(sub(256, mul(8, ll)), mload(add(p, 1)))
                                dp := add(add(p, 1), ll)
                            }
                        }
                    }
                }
                if gt(add(dp, dl), end) { ok := 0 }
            }
            function nib(k, i) -> n {
                n := and(shr(sub(252, mul(4, i)), k), 0xf)
            }

            nki := ki
            code := 2 // BAD unless proven otherwise
            for {} 1 {} {
                let ip := and(item, 0xffffffffffffffffffffffffffffffff)
                let iend := add(ip, shr(128, item))
                let np, nl, nIsL, nok := hdr(ip, iend)
                if or(iszero(nok), nIsL) { break }
                if iszero(eq(keccak256(np, nl), expected)) {
                    code := 3 // HASH_BAD
                    break
                }
                let lp, ll, lIsL, lok := hdr(np, add(np, nl))
                if or(iszero(lok), iszero(lIsL)) { break }
                let lend := add(lp, ll)
                // Locate the items: remember item 0, item 1 and the item at the key's next nibble.
                let want := 17
                if lt(ki, 64) { want := nib(key, ki) }
                let cnt := 0
                let it0 := 0
                let it1 := 0
                let itw := 0
                let okAll := 1
                for { let q := lp } lt(q, lend) {} {
                    if eq(cnt, 0) { it0 := q }
                    if eq(cnt, 1) { it1 := q }
                    if eq(cnt, want) { itw := q }
                    let dp, dl, isl, okk := hdr(q, lend)
                    if iszero(okk) {
                        okAll := 0
                        break
                    }
                    q := add(dp, dl)
                    cnt := add(cnt, 1)
                }
                if iszero(okAll) { break }
                switch cnt
                case 17 {
                    if gt(ki, 63) { break } // value-at-branch is not used for 32-byte keys
                    let cp, cl, cIsL, cok := hdr(itw, lend)
                    nki := add(ki, 1)
                    if cIsL {
                        code := 4 // INLINE
                        break
                    }
                    if iszero(cl) {
                        code := 1 // DONE: absent
                        break
                    }
                    if iszero(eq(cl, 32)) {
                        code := 4
                        break
                    }
                    next := mload(cp)
                    code := 0 // CONTINUE
                }
                case 2 {
                    let pp, pl, pIsL, pok := hdr(it0, lend)
                    if or(pIsL, iszero(pl)) { break }
                    let flag := shr(4, byte(0, mload(pp)))
                    let odd := and(flag, 1)
                    let skip := sub(2, odd)
                    let n := sub(mul(2, pl), skip) // path nibble count
                    if gt(add(ki, n), 64) {
                        code := 1 // diverges ⇒ absent
                        break
                    }
                    let mismatch := 0
                    for { let j := 0 } lt(j, n) { j := add(j, 1) } {
                        let pos := add(j, skip)
                        let pn := and(shr(sub(4, mul(4, and(pos, 1))), byte(0, mload(add(pp, shr(1, pos))))), 0xf)
                        if iszero(eq(pn, nib(key, add(ki, j)))) {
                            mismatch := 1
                            break
                        }
                    }
                    if mismatch {
                        code := 1 // absent
                        break
                    }
                    nki := add(ki, n)
                    let vp, vl, vIsL, vok := hdr(it1, lend)
                    if gt(flag, 1) {
                        // leaf
                        code := 1
                        if eq(nki, 64) { value := or(shl(128, sub(add(vp, vl), it1)), it1) }
                        break
                    }
                    if or(vIsL, iszero(eq(vl, 32))) {
                        code := 4
                        break
                    }
                    next := mload(vp)
                    code := 0
                }
                break
            }
        }
    }
}
