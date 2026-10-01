// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ILineaStateTrieVerifier} from "@hiero-ledger/clpr/verifiers/evm/zkrollup/lib/ILineaStateTrieVerifier.sol";

/// @title LineaStateTrieVerifier
/// @notice Verifies proofs against Linea state roots: the world-state trie (accounts) and an account's
///         storage trie. Both are Linea's Sparse Merkle Tree:
///
///         - depth 40; leaves are appended at `nextFreeNode` and form a doubly linked list sorted by
///           `hKey` (big-endian integer order), with head and tail sentinels;
///         - leaf hash = H(prev ‖ next ‖ hKey ‖ hValue), node = H(left ‖ right), empty leaf = 0;
///         - root = H(nextFreeNode ‖ subTreeRoot);
///         - H is Poseidon2 over KoalaBear in Merkle-Damgard mode on 32-byte words (the separately
///           deployed {LineaPoseidon2} Yul contract); keys and 32-byte values are first split into
///           16 two-byte limbs ({_pad}).
///
///         Account key: H(pad(address)) over 40 bytes. Account value: H(pad(nonce) ‖ pad(balance) ‖
///         storageRoot ‖ snarkCodeHash ‖ pad(keccakCodeHash) ‖ pad(codeSize)). Storage key and value:
///         H(pad(word)). A slot is absent when two adjacent leaves (`left.next = right`,
///         `right.prev = left`) bracket its hKey.
///
///         These formats were checked against `linea_getProof` responses for finalized Linea mainnet
///         blocks (fixture test/e2e/fixtures/linea-live). Several leaves of one tree are verified as a
///         multiproof, so paths they share are hashed once.
/// @dev Relayer-supplied hKeys used in an ordering comparison must be canonical (every 32-bit limb < p):
///      the hash reduces limbs mod p, so a non-canonical alias of a stored hKey would fold to the same
///      root while comparing differently.
contract LineaStateTrieVerifier is ILineaStateTrieVerifier {
    uint256 internal constant TREE_DEPTH = 40;
    uint256 internal constant KOALABEAR_P = 2130706433;

    /// @notice The LineaPoseidon2 hasher (calldata: words; returns the 32-byte hash).
    address public immutable POSEIDON2;

    error InvalidHasher();
    error HashFailed();
    error EmptyMultiProof();
    error LeafIndexOutOfRange(uint256 index);
    error LeavesNotSorted();
    error SiblingCountMismatch();
    error RootMismatch(bytes32 expected, bytes32 computed);
    error AccountKeyMismatch();
    error AccountValueMismatch();
    error SlotKeyMismatch(bytes32 slot);
    error SlotValueMismatch(bytes32 slot);
    error NonCanonicalKey();
    error AbsenceNotBracketed(bytes32 slot);
    error LeavesNotAdjacent(bytes32 slot);
    error InvalidClaim();

    constructor(address poseidon2) {
        if (poseidon2.code.length == 0) revert InvalidHasher();
        POSEIDON2 = poseidon2;
    }

    /// @inheritdoc ILineaStateTrieVerifier
    function verifyAccount(bytes calldata proof, bytes32 stateRoot, address account)
        external
        view
        returns (bytes32 storageRoot, bytes32 keccakCodeHash)
    {
        (Account memory a, MultiProof memory mp) = abi.decode(proof, (Account, MultiProof));
        if (mp.leaves.length != 1) revert InvalidClaim();
        Leaf memory leaf = mp.leaves[0];

        (uint256 k0, uint256 k1) = _pad(uint256(uint160(account)) << 96);
        if (leaf.hKey != _hash2(k0, k1 >> 192)) revert AccountKeyMismatch();

        uint256[] memory v = new uint256[](10);
        (v[0], v[1]) = _pad(a.nonce);
        (v[2], v[3]) = _pad(a.balance);
        v[4] = a.storageRoot;
        v[5] = a.snarkCodeHash;
        (v[6], v[7]) = _pad(a.keccakCodeHash);
        (v[8], v[9]) = _pad(a.codeSize);
        if (leaf.hValue != _hash(v)) revert AccountValueMismatch();

        _verifyMultiProof(mp, stateRoot);
        return (bytes32(a.storageRoot), bytes32(a.keccakCodeHash));
    }

    /// @inheritdoc ILineaStateTrieVerifier
    function verifyStorage(bytes calldata proof, bytes32 storageRoot)
        external
        view
        returns (bytes32[] memory slots, bytes32[] memory values)
    {
        (MultiProof memory mp, SlotClaim[] memory claims) = abi.decode(proof, (MultiProof, SlotClaim[]));
        slots = new bytes32[](claims.length);
        values = new bytes32[](claims.length);
        for (uint256 j = 0; j < claims.length; ++j) {
            slots[j] = bytes32(claims[j].slot);
            values[j] = _verifyClaim(mp.leaves, claims[j], slots[j]);
        }
        _verifyMultiProof(mp, storageRoot);
    }

    // ── Claims ───────────────────────────────────────────────────────────────

    function _verifyClaim(Leaf[] memory leaves, SlotClaim memory c, bytes32 slot) private view returns (bytes32) {
        if (c.leaf >= leaves.length || (c.absent && c.right >= leaves.length)) revert InvalidClaim();
        (uint256 s0, uint256 s1) = _pad(uint256(slot));
        uint256 hKey = _hash2(s0, s1);
        Leaf memory l = leaves[c.leaf];
        if (!c.absent) {
            if (l.hKey != hKey) revert SlotKeyMismatch(slot);
            (uint256 v0, uint256 v1) = _pad(c.value);
            if (l.hValue != _hash2(v0, v1)) revert SlotValueMismatch(slot);
            return bytes32(c.value);
        }
        Leaf memory r = leaves[c.right];
        if (!_isCanonical(l.hKey) || !_isCanonical(r.hKey)) revert NonCanonicalKey();
        if (!(l.hKey < hKey && hKey < r.hKey)) revert AbsenceNotBracketed(slot);
        (uint256 ri0, uint256 ri1) = _pad(r.index);
        (uint256 li0, uint256 li1) = _pad(l.index);
        if (l.next[0] != ri0 || l.next[1] != ri1 || r.prev[0] != li0 || r.prev[1] != li1) {
            revert LeavesNotAdjacent(slot);
        }
        return bytes32(0);
    }

    // ── Multiproof ───────────────────────────────────────────────────────────

    /// @dev Fold `mp.leaves` (strictly increasing indices < 2^40) up the depth-40 tree, pairing nodes
    ///      that are siblings of each other and taking every other sibling from `mp.siblings` in order;
    ///      then root = H(nextFreeNode ‖ subTreeRoot) must equal `root`.
    function _verifyMultiProof(MultiProof memory mp, bytes32 root) private view {
        uint256 n = mp.leaves.length;
        if (n == 0) revert EmptyMultiProof();
        uint256[] memory idx = new uint256[](n);
        uint256[] memory h = new uint256[](n);
        for (uint256 i = 0; i < n; ++i) {
            Leaf memory leaf = mp.leaves[i];
            if (leaf.index >> TREE_DEPTH != 0) revert LeafIndexOutOfRange(leaf.index);
            if (i > 0 && leaf.index <= idx[i - 1]) revert LeavesNotSorted();
            idx[i] = leaf.index;
            uint256[] memory w = new uint256[](6);
            (w[0], w[1], w[2], w[3], w[4], w[5]) =
            (leaf.prev[0], leaf.prev[1], leaf.next[0], leaf.next[1], leaf.hKey, leaf.hValue);
            h[i] = _hash(w);
        }

        uint256 sp = 0;
        uint256[] memory sib = mp.siblings;
        for (uint256 level = 0; level < TREE_DEPTH; ++level) {
            uint256 m = 0;
            uint256 i = 0;
            while (i < n) {
                uint256 x = idx[i];
                uint256 parent;
                if (x & 1 == 0 && i + 1 < n && idx[i + 1] == x + 1) {
                    parent = _hash2(h[i], h[i + 1]);
                    i += 2;
                } else {
                    if (sp >= sib.length) revert SiblingCountMismatch();
                    uint256 s = sib[sp++];
                    parent = x & 1 == 0 ? _hash2(h[i], s) : _hash2(s, h[i]);
                    i += 1;
                }
                idx[m] = x >> 1;
                h[m] = parent;
                ++m;
            }
            n = m;
        }
        if (sp != sib.length) revert SiblingCountMismatch();

        uint256[] memory top = new uint256[](3);
        (top[0], top[1], top[2]) = (mp.nextFreeNode[0], mp.nextFreeNode[1], h[0]);
        bytes32 computed = bytes32(_hash(top));
        if (computed != root) revert RootMismatch(root, computed);
    }

    // ── Hashing ──────────────────────────────────────────────────────────────

    function _hash2(uint256 a, uint256 b) private view returns (uint256 r) {
        address hasher = POSEIDON2;
        assembly ("memory-safe") {
            mstore(0x00, a)
            mstore(0x20, b)
            if iszero(staticcall(gas(), hasher, 0x00, 0x40, 0x00, 0x20)) { revert(0, 0) }
            if iszero(eq(returndatasize(), 0x20)) { revert(0, 0) }
            r := mload(0x00)
        }
    }

    function _hash(uint256[] memory words) private view returns (uint256 r) {
        (bool ok, bytes memory out) = POSEIDON2.staticcall(abi.encodePacked(words));
        if (!ok || out.length != 32) revert HashFailed();
        // forge-lint: disable-next-line(unsafe-typecast)
        r = uint256(bytes32(out));
    }

    /// @dev Split a 32-byte word into 16 two-byte limbs, each zero-extended to 4 bytes (two words).
    function _pad(uint256 input) private pure returns (uint256 hi, uint256 lo) {
        for (uint256 i = 0; i < 8; ++i) {
            hi |= ((input >> ((15 - i) * 16)) & 0xFFFF) << ((7 - i) * 32);
            lo |= ((input >> ((7 - i) * 16)) & 0xFFFF) << ((7 - i) * 32);
        }
    }

    function _isCanonical(uint256 w) private pure returns (bool) {
        for (uint256 i = 0; i < 8; ++i) {
            if ((w >> (i * 32)) & 0xFFFFFFFF >= KOALABEAR_P) return false;
        }
        return true;
    }
}
