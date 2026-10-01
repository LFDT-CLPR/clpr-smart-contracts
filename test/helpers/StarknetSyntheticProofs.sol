// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {EthCommitteeFixtures} from "@test/verifiers/evm/ethereum/EthCommitteeFixtures.sol";
import {QbftSyntheticProofs} from "@test/helpers/QbftSyntheticProofs.sol";
import {StarknetStateProver} from "@hiero-ledger/clpr/verifiers/evm/starknet/StarknetStateProver.sol";
import {StarkPedersenTableA, StarkPedersenTableB} from "@hiero-ledger/clpr/libraries/proof/starknet/StarkTables.sol";
import {StarknetCoreProof} from "@hiero-ledger/clpr/libraries/proof/starknet/StarknetCoreProof.sol";
import {EthBeaconLightClient} from "@hiero-ledger/clpr/libraries/proof/beacon/EthBeaconLightClient.sol";
import {ClprBeaconSsz} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconSsz.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @dev Builds complete StarknetVerifier proofs in Solidity, with no fixtures: a Starknet storage trie
///      (Pedersen Patricia, built here with the deployed prover's hash), a one-contract contract trie,
///      the global root, a one-leaf MPT of the core contract's `globalRoot` slot, and a beacon header
///      signed by the generator sync committee (all 512 sk = 1). The core implementation is not pinned
///      (its slot is proven absent).
abstract contract StarknetSyntheticProofs is EthCommitteeFixtures, QbftSyntheticProofs {
    uint256 internal constant STARK_P = 0x0800000000000011000000000000000000000000000000000000000000000001;
    address internal constant SYNTH_CORE = address(0xC07E);
    uint256 internal constant SYNTH_CLASSES_ROOT = 0x1c1a55;
    bytes4 internal constant SYNTH_FORK_VERSION = 0x06000000;
    bytes32 internal constant SYNTH_GVR = bytes32(uint256(0x5e9011a));
    uint64 internal constant SYNTH_L1_SLOT = 8192 * 3 + 5;

    StarknetStateProver internal starkProver;
    uint256[] private _acc;

    function _deployStarkProver() internal returns (StarknetStateProver) {
        starkProver = new StarknetStateProver(address(new StarkPedersenTableA()), address(new StarkPedersenTableB()));
        return starkProver;
    }

    // ── Starknet tries ───────────────────────────────────────────────────────

    /// @dev A Patricia trie over the non-zero (key, value) pairs; returns its root and every node,
    ///      flattened 3 words each.
    function _starkTrie(uint256[] memory keys, uint256[] memory vals)
        internal
        returns (uint256 root, uint256[] memory nodes)
    {
        uint256 n = 0;
        for (uint256 i = 0; i < keys.length; i++) {
            if (vals[i] != 0) n++;
        }
        uint256[] memory ks = new uint256[](n);
        uint256[] memory vs = new uint256[](n);
        n = 0;
        for (uint256 i = 0; i < keys.length; i++) {
            if (vals[i] == 0) continue;
            // insertion sort
            uint256 j = n++;
            while (j > 0 && ks[j - 1] > keys[i]) {
                ks[j] = ks[j - 1];
                vs[j] = vs[j - 1];
                j--;
            }
            ks[j] = keys[i];
            vs[j] = vals[i];
        }
        delete _acc;
        root = n == 0 ? 0 : _build(ks, vs, 0, n, 0);
        nodes = _acc;
    }

    function _bit(uint256 k, uint256 depth) private pure returns (uint256) {
        return (k >> (250 - depth)) & 1;
    }

    function _build(uint256[] memory ks, uint256[] memory vs, uint256 lo, uint256 hi, uint256 depth)
        private
        returns (uint256)
    {
        if (depth == 251) return vs[lo];
        uint256 l = 0;
        // Sorted keys: the common prefix of the first and last is the prefix of all.
        while (depth + l < 251 && _bit(ks[lo], depth + l) == _bit(ks[hi - 1], depth + l)) l++;
        if (l > 0) {
            uint256 child = _build(ks, vs, lo, hi, depth + l);
            uint256 path = (ks[lo] >> (251 - depth - l)) & ((1 << l) - 1);
            _acc.push(child);
            _acc.push(path);
            _acc.push(l);
            return addmod(starkProver.pedersen(child, path), l, STARK_P);
        }
        uint256 mid = lo;
        while (_bit(ks[mid], depth) == 0) mid++;
        uint256 left = _build(ks, vs, lo, mid, depth + 1);
        uint256 right = _build(ks, vs, mid, hi, depth + 1);
        _acc.push(left);
        _acc.push(right);
        _acc.push(0);
        return starkProver.pedersen(left, right);
    }

    /// @dev Global root and `starknetProof` for `service` (class `classHash`, nonce 0) holding `keys`.
    function _starknetState(uint256 service, uint256 classHash, uint256[] memory keys, uint256[] memory vals)
        internal
        returns (uint256 globalRoot, bytes memory starknetProof)
    {
        (uint256 storageRoot, uint256[] memory storageNodes) = _starkTrie(keys, vals);
        uint256 leaf = starkProver.pedersen(starkProver.pedersen(starkProver.pedersen(classHash, storageRoot), 0), 0);
        uint256[] memory contractNodes = new uint256[](3);
        contractNodes[0] = leaf;
        contractNodes[1] = service;
        contractNodes[2] = 251;
        uint256 contractsRoot = addmod(starkProver.pedersen(leaf, service), 251, STARK_P);
        globalRoot = starkProver.globalStateRoot(contractsRoot, SYNTH_CLASSES_ROOT);
        starknetProof = abi.encode(
            contractsRoot, SYNTH_CLASSES_ROOT, classHash, storageRoot, uint256(0), contractNodes, storageNodes
        );
    }

    // ── L1 ───────────────────────────────────────────────────────────────────

    /// @dev Core-contract proof whose storage holds only `globalRoot` (blockNumber 0, implementation
    ///      absent), and the L1 state root committing it.
    function _coreProof(uint256 globalRoot) internal pure returns (bytes32 l1StateRoot, bytes memory coreProof) {
        (bytes32 storageRoot, bytes memory nodes) =
            _buildSyntheticMPTProof(keccak256(abi.encodePacked(StarknetCoreProof.STATE_SLOT)), RLP.encode(globalRoot));
        bytes32[3] memory slots = [
            StarknetCoreProof.STATE_SLOT,
            bytes32(uint256(StarknetCoreProof.STATE_SLOT) + 1),
            StarknetCoreProof.IMPLEMENTATION_SLOT
        ];
        bytes[] memory entries = new bytes[](3);
        for (uint256 i = 0; i < 3; i++) {
            bytes[] memory e = new bytes[](2);
            e[0] = RLP.encode(abi.encodePacked(slots[i]));
            e[1] = nodes;
            entries[i] = RLP.encode(e);
        }
        bytes memory accountProof;
        (l1StateRoot, accountProof) = _buildSyntheticAccountProof(SYNTH_CORE, storageRoot, bytes32(0));
        bytes[] memory items = new bytes[](3);
        items[0] = accountProof;
        items[1] = RLP.encode(entries);
        items[2] = RLP.encode(new bytes[](0));
        coreProof = RLP.encode(items);
    }

    /// @dev `EthL1StateVerifier` proof: the generator committee (512/512) signs a header whose body
    ///      commits `l1StateRoot` (zero SSZ siblings), no rotation.
    function _syntheticLightClientProof(bytes32 l1StateRoot) internal view returns (bytes memory) {
        bytes32[] memory branch = new bytes32[](9);
        bytes32 bodyRoot = l1StateRoot;
        uint256 idx = ClprBeaconSsz.GINDEX_EXECUTION_STATE_ROOT_IN_BODY;
        for (uint256 i = 0; i < 9; i++) {
            bodyRoot = idx & 1 == 1
                ? sha256(abi.encodePacked(branch[i], bodyRoot))
                : sha256(abi.encodePacked(bodyRoot, branch[i]));
            idx >>= 1;
        }
        bytes32 headerRoot =
            ClprBeaconSsz.beaconBlockHeaderRoot(SYNTH_L1_SLOT, 7, bytes32(uint256(1)), bytes32(uint256(2)), bodyRoot);
        bytes32 signingRoot = ClprBeaconSsz.computeSigningRoot(
            headerRoot, ClprBeaconSsz.computeSyncCommitteeDomain(SYNTH_FORK_VERSION, SYNTH_GVR)
        );
        bytes[] memory header = new bytes[](5);
        header[0] = RLP.encode(uint256(SYNTH_L1_SLOT));
        header[1] = RLP.encode(uint256(7));
        header[2] = RLP.encode(bytes32(uint256(1)));
        header[3] = RLP.encode(bytes32(uint256(2)));
        header[4] = RLP.encode(bodyRoot);
        bytes memory bits = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            bits[i] = 0xff;
        }
        bytes[] memory agg = new bytes[](2);
        agg[0] = RLP.encode(bits);
        agg[1] = RLP.encode(_aggSig(signingRoot, SYNC_COMMITTEE_SIZE));
        bytes[] memory br = new bytes[](9);
        for (uint256 i = 0; i < 9; i++) {
            br[i] = RLP.encode(branch[i]);
        }
        bytes[] memory lc = new bytes[](7);
        lc[0] = RLP.encode(header);
        lc[1] = RLP.encode(agg);
        lc[2] = RLP.encode(l1StateRoot);
        lc[3] = RLP.encode(br);
        lc[4] = RLP.encode(bytes(""));
        lc[5] = RLP.encode(new bytes[](0));
        lc[6] = RLP.encode(new bytes[](0));
        return RLP.encode(lc);
    }

    /// @dev The 260-byte anchor of the generator committee for `channelId`, pinning `classHash`.
    function _syntheticAnchor(bytes32 channelId, uint256 classHash) internal view returns (bytes memory) {
        return EthBeaconLightClient.encodeTrustAnchor(
            _uncompressedKeys(SYNC_COMMITTEE_SIZE),
            _committeeAggregate(),
            SYNTH_GVR,
            abi.encodePacked(SYNTH_FORK_VERSION),
            channelId,
            bytes32(classHash)
        );
    }
}
