// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {QbftValidators, ValidatorSet} from "@hiero-ledger/clpr/libraries/proof/qbft/QbftValidators.sol";
import {QbftSyntheticProofs} from "@test/helpers/QbftSyntheticProofs.sol";

/// @dev Proof-building utilities for QBFT Contract-mode tests, on top of {QbftSyntheticProofs}:
///      headers with an explicit (possibly empty) validator list, and synthetic MPT proofs for a
///      validator contract's `address[] validators` array.
abstract contract QbftContractProofs is QbftSyntheticProofs {
    /// @dev extraData carrying a validator list (already RLP-encoded) plus the committed seals.
    function _buildExtraDataFull(bytes memory validatorListRlp, bytes[] memory seals, uint256 round)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory extra = new bytes[](5);
        extra[0] = RLP.encode(new bytes(32)); // vanity
        extra[1] = validatorListRlp; // validators
        extra[2] = RLP.encode(new bytes(0)); // vote
        extra[3] = RLP.encode(round);
        bytes[] memory wrappedSeals = new bytes[](seals.length);
        for (uint256 i = 0; i < seals.length; i++) {
            wrappedSeals[i] = RLP.encode(seals[i]);
        }
        extra[4] = RLP.encode(wrappedSeals);
        return RLP.encode(extra);
    }

    /// @dev A header at `blockNumber` whose extraData lists `listed` and is sealed by every pk in
    ///      `sealerPks`. Contract-mode headers pass an empty `listed` list.
    function _buildListedSealedHeader(
        uint256 blockNumber,
        bytes32 stateRoot,
        address[] memory listed,
        uint256[] memory sealerPks
    ) internal pure returns (bytes memory) {
        bytes[] memory vItems = new bytes[](listed.length);
        for (uint256 i = 0; i < listed.length; i++) {
            vItems[i] = RLP.encode(listed[i]);
        }
        bytes memory vList = RLP.encode(vItems);

        bytes memory sealingHeader =
            _buildHeaderAtNumber(blockNumber, stateRoot, _buildExtraDataFull(vList, new bytes[](0), 0));
        bytes32 sealHash = keccak256(sealingHeader);

        bytes[] memory seals = new bytes[](sealerPks.length);
        for (uint256 i = 0; i < sealerPks.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(sealerPks[i], sealHash);
            seals[i] = abi.encodePacked(r, s, uint8(v - 27));
        }
        return _buildHeaderAtNumber(blockNumber, stateRoot, _buildExtraDataFull(vList, seals, 0));
    }

    /// @dev The anchor's set commitment for a member list, in the canonical (sorted, deduped) form.
    function _commit(address[] memory members) internal pure returns (bytes32) {
        return QbftValidators.commit(ValidatorSet({members: QbftValidators.sortedDedup(members)}));
    }

    /// @dev Payload field 1: RLP([trustedSet, hops, contractProof]). Each entry of `hops` must
    ///      already be an RLP-encoded `[blockHeader, contractProof]` pair.
    function _contractSourceField(address[] memory trustedSet, bytes[] memory hops, bytes memory contractProof)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory source = new bytes[](3);
        source[0] = _memberListRlp(trustedSet);
        source[1] = RLP.encode(hops);
        source[2] = RLP.encode(contractProof);
        return RLP.encode(source);
    }

    /// @dev One rotation hop: RLP([blockHeader, contractProof]).
    function _hop(bytes memory hopHeader, bytes memory contractProof) internal pure returns (bytes memory) {
        bytes[] memory items = new bytes[](2);
        items[0] = hopHeader;
        items[1] = RLP.encode(contractProof);
        return RLP.encode(items);
    }

    /// @dev Validator storage proof plus a placeholder vc-proof (the account proof is re-wrapped later
    ///      against the shared two-account state root).
    function _validatorStorageProofAndVcProof(address[] memory validators)
        internal
        pure
        returns (bytes32 vcStorageRoot, bytes32 arraySlot, bytes memory vcProof)
    {
        (arraySlot, vcStorageRoot,) = _validatorStorageProof(validators);
        vcProof = "";
    }

    /// @dev Assemble RLP([validatorContract, accountProof, arraySlot, storageProof]) from an account proof
    ///      built against a shared state root.
    function _wrapVcProof(
        address validatorContract,
        bytes memory accountProof,
        bytes32 arraySlot,
        address[] memory validators
    ) internal pure returns (bytes memory) {
        (,, bytes memory storageProofRlp) = _validatorStorageProof(validators);
        bytes[] memory items = new bytes[](4);
        items[0] = RLP.encode(validatorContract);
        items[1] = accountProof;
        items[2] = RLP.encode(arraySlot);
        items[3] = storageProofRlp;
        return RLP.encode(items);
    }

    /// @dev RLP list of member addresses — field 1 item 0, the commitment preimage.
    function _memberListRlp(address[] memory members) internal pure returns (bytes memory) {
        bytes[] memory items = new bytes[](members.length);
        for (uint256 i = 0; i < members.length; i++) {
            items[i] = RLP.encode(members[i]);
        }
        return RLP.encode(items);
    }

    // ── Multi-slot / multi-account trie (for QBFT contract-mode proofs) ─────────

    /// @dev Build a one-level Merkle-Patricia trie (root = 16-way branch, one leaf per key) over keys
    ///      whose FIRST nibble is distinct. Returns the root and, per key, the proof node list
    ///      [branchNode, leaf]. `pathKeys[i]` is the 32-byte trie key (keccak of the slot or address);
    ///      `values[i]` is the leaf value payload (RLP-wrapped once as the leaf value).
    function _buildBranchTrie(bytes32[] memory pathKeys, bytes[] memory values)
        internal
        pure
        returns (bytes32 root, bytes[] memory proofs)
    {
        uint256 n = pathKeys.length;
        bytes[] memory leaves = new bytes[](n);
        bytes[] memory branchItems = new bytes[](17);
        for (uint256 j = 0; j < 17; j++) {
            branchItems[j] = RLP.encode(new bytes(0));
        }
        for (uint256 i = 0; i < n; i++) {
            // Leaf path = nibbles 1..63 of the key (odd length -> compact prefix 0x3).
            bytes memory compact = new bytes(32);
            compact[0] = bytes1(0x30 | (uint8(pathKeys[i][0]) & 0x0f));
            for (uint256 b = 1; b < 32; b++) {
                compact[b] = pathKeys[i][b];
            }
            bytes[] memory leafItems = new bytes[](2);
            leafItems[0] = RLP.encode(compact);
            leafItems[1] = RLP.encode(values[i]);
            leaves[i] = RLP.encode(leafItems);
            uint8 nib = uint8(pathKeys[i][0]) >> 4;
            branchItems[nib] = RLP.encode(abi.encodePacked(keccak256(leaves[i])));
        }
        bytes memory branchNode = RLP.encode(branchItems);
        root = keccak256(branchNode);
        proofs = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            bytes[] memory nodes = new bytes[](2);
            nodes[0] = RLP.encode(branchNode);
            nodes[1] = RLP.encode(leaves[i]);
            proofs[i] = RLP.encode(nodes);
        }
    }

    /// @dev Two-level variant of {_buildBranchTrie} for key sets that outgrow one 16-way branch:
    ///      root branch on nibble 0, one child branch per occupied nibble-0 bucket on nibble 1,
    ///      leaves carrying the remaining 62 nibbles (even length -> 0x20 prefix). Requires keys
    ///      with distinct FIRST BYTES (nibbles 0+1), so up to 256 keys. Proof per key:
    ///      [rootBranch, childBranch, leaf].
    function _buildTwoLevelBranchTrie(bytes32[] memory pathKeys, bytes[] memory values)
        internal
        pure
        returns (bytes32 root, bytes[] memory proofs)
    {
        uint256 n = pathKeys.length;
        bytes[] memory leaves = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            // Leaf path = nibbles 2..63 of the key (even length -> 0x20 prefix byte).
            bytes memory compact = new bytes(32);
            compact[0] = 0x20;
            for (uint256 b = 1; b < 32; b++) {
                compact[b] = pathKeys[i][b];
            }
            bytes[] memory leafItems = new bytes[](2);
            leafItems[0] = RLP.encode(compact);
            leafItems[1] = RLP.encode(values[i]);
            leaves[i] = RLP.encode(leafItems);
        }

        bytes[] memory childNodes = new bytes[](16);
        for (uint256 nib0 = 0; nib0 < 16; nib0++) {
            bytes[] memory items = new bytes[](17);
            for (uint256 j = 0; j < 17; j++) {
                items[j] = RLP.encode(new bytes(0));
            }
            bool occupied = false;
            for (uint256 i = 0; i < n; i++) {
                if (uint8(pathKeys[i][0]) >> 4 != nib0) continue;
                items[uint8(pathKeys[i][0]) & 0x0f] = RLP.encode(abi.encodePacked(keccak256(leaves[i])));
                occupied = true;
            }
            if (occupied) childNodes[nib0] = RLP.encode(items);
        }

        bytes[] memory rootItems = new bytes[](17);
        for (uint256 j = 0; j < 17; j++) {
            rootItems[j] = RLP.encode(new bytes(0));
        }
        for (uint256 nib0 = 0; nib0 < 16; nib0++) {
            if (childNodes[nib0].length != 0) {
                rootItems[nib0] = RLP.encode(abi.encodePacked(keccak256(childNodes[nib0])));
            }
        }
        bytes memory rootNode = RLP.encode(rootItems);
        root = keccak256(rootNode);

        proofs = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            bytes[] memory nodes = new bytes[](3);
            nodes[0] = RLP.encode(rootNode);
            nodes[1] = RLP.encode(childNodes[uint8(pathKeys[i][0]) >> 4]);
            nodes[2] = RLP.encode(leaves[i]);
            proofs[i] = RLP.encode(nodes);
        }
    }

    /// @dev True when the length slot and every element slot map to distinct first BYTES (nibbles
    ///      0+1) — the condition {_buildTwoLevelBranchTrie} needs. Tracked as a 256-bit bitmap.
    function _distinctFirstBytes(bytes32 arraySlot, uint256 n) private pure returns (bool) {
        // The length-slot trie key is keccak256(arraySlot) == base itself.
        bytes32 base = keccak256(abi.encodePacked(arraySlot));
        uint256 seen = uint256(1) << uint8(base[0]);
        for (uint256 i = 0; i < n; i++) {
            uint256 bit = uint256(1) << uint8(keccak256(abi.encodePacked(bytes32(uint256(base) + i)))[0]);
            if (seen & bit != 0) return false;
            seen |= bit;
        }
        return true;
    }

    /// @dev True when the length slot and every element slot of a validator array at `arraySlot` map to
    ///      distinct first nibbles — the condition {_buildBranchTrie} needs.
    function _distinctFirstNibbles(bytes32 arraySlot, uint256 n) private pure returns (bool) {
        bytes32 base = keccak256(abi.encodePacked(arraySlot));
        bool[16] memory seen;
        seen[uint8(keccak256(abi.encodePacked(arraySlot))[0]) >> 4] = true;
        for (uint256 i = 0; i < n; i++) {
            uint8 nib = uint8(keccak256(abi.encodePacked(bytes32(uint256(base) + i)))[0]) >> 4;
            if (seen[nib]) return false;
            seen[nib] = true;
        }
        return true;
    }

    /// @dev A storage proof for an `address[] validators` array: the length slot plus every element slot,
    ///      all under one storage root. Picks an `arraySlot` whose slots land on distinct branch nibbles
    ///      (one-level trie, up to 15 validators) or, for larger sets, distinct first bytes (two-level
    ///      trie, up to 255 validators).
    function _validatorStorageProof(address[] memory validators)
        internal
        pure
        returns (bytes32 arraySlot, bytes32 storageRoot, bytes memory storageProofRlp)
    {
        uint256 n = validators.length;
        bool twoLevel = n + 1 > 16;
        uint256 bound = twoLevel ? 1 << 22 : 8192;
        for (uint256 slot = 1; slot < bound; slot++) {
            bool ok = twoLevel ? _distinctFirstBytes(bytes32(slot), n) : _distinctFirstNibbles(bytes32(slot), n);
            if (ok) {
                arraySlot = bytes32(slot);
                break;
            }
        }
        bytes32 base = keccak256(abi.encodePacked(arraySlot));
        bytes32[] memory slotKeys = new bytes32[](n + 1);
        bytes32[] memory pathKeys = new bytes32[](n + 1);
        bytes[] memory values = new bytes[](n + 1);
        slotKeys[0] = arraySlot;
        values[0] = RLP.encode(n);
        for (uint256 i = 0; i < n; i++) {
            slotKeys[i + 1] = bytes32(uint256(base) + i);
            values[i + 1] = RLP.encode(uint256(uint160(validators[i])));
        }
        for (uint256 i = 0; i < n + 1; i++) {
            pathKeys[i] = keccak256(abi.encodePacked(slotKeys[i]));
        }
        bytes[] memory proofs;
        if (twoLevel) {
            (storageRoot, proofs) = _buildTwoLevelBranchTrie(pathKeys, values);
        } else {
            (storageRoot, proofs) = _buildBranchTrie(pathKeys, values);
        }
        bytes[] memory entries = new bytes[](n + 1);
        for (uint256 i = 0; i < n + 1; i++) {
            bytes[] memory e = new bytes[](2);
            e[0] = RLP.encode(abi.encodePacked(slotKeys[i]));
            e[1] = proofs[i];
            entries[i] = RLP.encode(e);
        }
        storageProofRlp = RLP.encode(entries);
    }

    /// @dev The contract-mode validator source proof: RLP([validatorContract, accountProof, arraySlot,
    ///      storageProof]). The validator contract account (single leaf) sits under `stateRoot`.
    function _validatorContractProof(address validatorContract, address[] memory validators)
        internal
        pure
        returns (bytes32 stateRoot, bytes32 arraySlot, bytes memory vcProof)
    {
        bytes32 storageRoot;
        bytes memory storageProofRlp;
        (arraySlot, storageRoot, storageProofRlp) = _validatorStorageProof(validators);
        bytes memory accountProofRlp;
        (stateRoot, accountProofRlp) =
            _buildSyntheticAccountProof(validatorContract, storageRoot, bytes32(uint256(0xC0)));
        bytes[] memory items = new bytes[](4);
        items[0] = RLP.encode(validatorContract);
        items[1] = accountProofRlp;
        items[2] = RLP.encode(arraySlot);
        items[3] = storageProofRlp;
        vcProof = RLP.encode(items);
    }

    /// @dev A two-account state trie (service + validator contract) under one state root, returning each
    ///      account proof. `svc`/`vc` must map to distinct branch nibbles (the caller picks `vc`).
    function _buildTwoAccountState(
        address svc,
        bytes32 svcStorageRoot,
        bytes32 svcCodeHash,
        address vc,
        bytes32 vcStorageRoot
    ) internal pure returns (bytes32 stateRoot, bytes memory svcProof, bytes memory vcProof) {
        bytes32[] memory pathKeys = new bytes32[](2);
        pathKeys[0] = keccak256(abi.encodePacked(svc));
        pathKeys[1] = keccak256(abi.encodePacked(vc));
        bytes[] memory values = new bytes[](2);
        values[0] = _buildAccountRlp(svcStorageRoot, svcCodeHash);
        values[1] = _buildAccountRlp(vcStorageRoot, bytes32(uint256(0xC0)));
        bytes[] memory proofs;
        (stateRoot, proofs) = _buildBranchTrie(pathKeys, values);
        svcProof = proofs[0];
        vcProof = proofs[1];
    }
}
