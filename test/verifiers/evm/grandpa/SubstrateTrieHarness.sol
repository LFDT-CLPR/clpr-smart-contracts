// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Blake2b} from "@hiero-ledger/clpr/libraries/proof/substrate/Blake2b.sol";
import {BeefyLib} from "@hiero-ledger/clpr/libraries/proof/substrate/BeefyLib.sol";
import {ScaleCodec} from "@hiero-ledger/clpr/libraries/proof/substrate/ScaleCodec.sol";
import {SubstrateHeader} from "@hiero-ledger/clpr/libraries/proof/substrate/SubstrateHeader.sol";
import {SubstrateTrie} from "@hiero-ledger/clpr/libraries/proof/substrate/SubstrateTrie.sol";

/// @notice Exposes the Substrate proof libraries for tests (forge and the live anvil spec).
contract SubstrateTrieHarness {
    function get(bytes32 root, bytes[] calldata nodes, bytes calldata key)
        external
        view
        returns (bool exists, bytes memory value)
    {
        return SubstrateTrie.get(SubstrateTrie.load(nodes), root, key);
    }

    function blake2b256(bytes calldata data) external view returns (bytes32) {
        return Blake2b.hash256(data);
    }

    function blake2b128(bytes calldata data) external view returns (bytes16) {
        return Blake2b.hash128(data);
    }

    function headerStateRoot(bytes calldata header) external pure returns (bytes32 stateRoot, uint32 number) {
        SubstrateHeader.Header memory h = SubstrateHeader.decode(header);
        return (h.stateRoot, h.number);
    }

    function grandpaChange(bytes calldata header)
        external
        pure
        returns (bool present, bytes memory authorities, uint32 delay)
    {
        bytes memory h = header;
        SubstrateHeader.GrandpaChange memory c = SubstrateHeader.grandpaChange(h, SubstrateHeader.decode(h));
        if (c.present) authorities = ScaleCodec.slice(h, c.authoritiesOffset, c.authoritiesLength);
        return (c.present, authorities, c.delay);
    }

    function readCompact(bytes calldata b) external pure returns (uint256 value, uint256 next) {
        return ScaleCodec.readCompact(b, 0);
    }

    function encodeCompact(uint256 v) external pure returns (bytes memory) {
        return ScaleCodec.encodeCompact(v);
    }

    function decodeCommitment(bytes calldata c) external pure returns (BeefyLib.Commitment memory) {
        return BeefyLib.decodeCommitment(c);
    }

    function keysetRoot(bytes calldata addresses) external pure returns (bytes32) {
        return BeefyLib.keysetRoot(addresses);
    }

    function verifyMmrLeaf(bytes32 root, bytes calldata leaf, bytes32[] calldata path, uint256 sides) external pure {
        BeefyLib.verifyMmrLeaf(root, leaf, path, sides);
    }
}
