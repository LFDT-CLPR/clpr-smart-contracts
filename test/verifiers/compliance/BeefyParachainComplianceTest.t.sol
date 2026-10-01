// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {SubstrateEvmComplianceBase} from "@test/verifiers/compliance/SubstrateEvmComplianceBase.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {BeefyLib} from "@hiero-ledger/clpr/libraries/proof/substrate/BeefyLib.sol";
import {Blake2b} from "@hiero-ledger/clpr/libraries/proof/substrate/Blake2b.sol";
import {ScaleCodec} from "@hiero-ledger/clpr/libraries/proof/substrate/ScaleCodec.sol";
import {BeefyParachainVerifier} from "@hiero-ledger/clpr/verifiers/evm/grandpa/BeefyParachainVerifier.sol";

/// @title BeefyParachainComplianceTest
/// @notice ClprVerifierComplianceTest adapter (via ClprEvmStorageComplianceTest and
///         SubstrateEvmComplianceBase) for BeefyParachainVerifier. Every bundle carries a real BEEFY
///         proof: a commitment signed (secp256k1, `vm.sign`) by a one-authority set, an MMR leaf for
///         the commitment block, the relay header named by that leaf, relay state proving
///         Paras::Heads(2034), and the parachain header whose state root is the synthetic Frontier trie.
contract BeefyParachainComplianceTest is SubstrateEvmComplianceBase {
    string internal constant CHAIN_ID = "eip155:222222";
    uint32 internal constant RELAY_BLOCK = 100;
    uint256 internal constant AUTHORITY_PK = 0xbeef01;
    uint256 internal constant NEXT_AUTHORITY_PK = 0xbeef02;

    BeefyLib.AuthoritySet internal current;
    BeefyLib.AuthoritySet internal next;

    function _deployVerifier() internal override returns (IClprVerifier) {
        current = BeefyLib.AuthoritySet(10, 1, keccak256(abi.encodePacked(vm.addr(AUTHORITY_PK))));
        next = BeefyLib.AuthoritySet(11, 1, keccak256(abi.encodePacked(vm.addr(NEXT_AUTHORITY_PK))));
        BeefyParachainVerifier.Anchor memory boot = BeefyParachainVerifier.Anchor(current, next, 1);
        return IClprVerifier(address(new BeefyParachainVerifier(EVM_PALLET, CHAIN_ID, 2034, PARA_HEAD_KEY_2034, boot)));
    }

    function _chainId() internal pure override returns (string memory) {
        return CHAIN_ID;
    }

    function _anchor() internal view override returns (bytes memory) {
        return abi.encodePacked(current.id, current.len, current.root, next.id, next.len, next.root, uint32(1));
    }

    /// @dev Para header over `stateRoot` → relay state → relay header → MMR leaf → signed commitment.
    function _relay(bytes32 stateRoot)
        internal
        returns (BeefyParachainVerifier.Commit[] memory commits, bytes memory relayHeader, bytes[] memory relayProof)
    {
        bytes memory paraHeader = _header(keccak256("para parent"), 7, stateRoot);
        Entry[] memory relayEntries = new Entry[](2);
        relayEntries[0] =
            Entry(PARA_HEAD_KEY_2034, abi.encodePacked(ScaleCodec.encodeCompact(paraHeader.length), paraHeader), true);
        relayEntries[1] = Entry(bytes("relay-neighbour"), abi.encodePacked(bytes32(uint256(1))), false);
        bytes32 relayRoot;
        (relayRoot, relayProof) = _buildTrie(relayEntries);
        relayHeader = _header(keccak256("relay parent"), RELAY_BLOCK - 1, relayRoot);

        // A one-leaf MMR: the root is the leaf hash and the path is empty.
        bytes memory leaf = abi.encodePacked(
            uint8(0),
            ScaleCodec.le32(RELAY_BLOCK - 1),
            Blake2b.hash256(relayHeader),
            ScaleCodec.le64(next.id),
            ScaleCodec.le32(next.len),
            next.root,
            bytes32(0)
        );
        bytes memory commitment = abi.encodePacked(
            hex"04", "mh", hex"80", keccak256(leaf), ScaleCodec.le32(RELAY_BLOCK), ScaleCodec.le64(current.id)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(AUTHORITY_PK, keccak256(commitment));

        commits = new BeefyParachainVerifier.Commit[](1);
        commits[0] = BeefyParachainVerifier.Commit({
            commitment: commitment,
            signers: hex"80",
            signatures: abi.encodePacked(r, s, v - 27),
            authorities: abi.encodePacked(vm.addr(AUTHORITY_PK)),
            mmrLeaf: leaf,
            mmrPath: new bytes32[](0),
            mmrPathSides: 0
        });
    }

    function _bundleProof(bytes32 stateRoot, bytes[] memory nodes, bytes memory content)
        internal
        override
        returns (bytes memory)
    {
        (BeefyParachainVerifier.Commit[] memory commits, bytes memory relayHeader, bytes[] memory relayProof) =
            _relay(stateRoot);
        return
            abi.encode(BeefyParachainVerifier.BundleProof(commits, relayHeader, relayProof, nodes, false, content, ""));
    }

    function _configProof(bytes32 stateRoot, bytes[] memory nodes, bytes memory ledgerConfig)
        internal
        override
        returns (bytes memory)
    {
        (BeefyParachainVerifier.Commit[] memory commits, bytes memory relayHeader, bytes[] memory relayProof) =
            _relay(stateRoot);
        return abi.encode(BeefyParachainVerifier.ConfigProof(commits, relayHeader, relayProof, nodes, ledgerConfig));
    }
}
