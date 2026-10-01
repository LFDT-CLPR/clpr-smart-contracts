// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {NearLightClient} from "@hiero-ledger/clpr/libraries/proof/near/NearLightClient.sol";
import {ClprEd25519SignatureCache} from "@hiero-ledger/clpr/verifiers/evm/neartons/ClprEd25519SignatureCache.sol";
import {ClprNearTonBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/neartons/ClprNearTonBundleVerifier.sol";

/// @title NearAnchoredVerifier
/// @notice The NEAR light-client half shared by {NearVerifier} (a NEAR-native CLPR Service) and
///         {AuroraVerifier} (the EVM ClprService running inside the Aurora engine on NEAR): the
///         epoch-window trust anchor, the deploy-time checkpoint, light-client block verification and
///         the shard state root the storage proofs start from.
///
/// Trust anchor (128 bytes): `epochId ‖ nextEpochId ‖ sha256(producers(epochId)) ‖ sha256(producers(nextEpochId))`,
/// exactly the state a NEP-25 light client keeps. Anchor id: `epochId`.
abstract contract NearAnchoredVerifier is ClprNearTonBundleVerifier {
    /// @dev Proven state root: the shard roots of the last block, in shard order, and the shard index.
    struct ShardRoots {
        bytes32[] roots;
        uint256 index;
    }

    uint256 internal constant ANCHOR_LENGTH = 128;

    IEd25519Verifier public immutable ED25519;
    /// @notice Optional (zero = disabled) cache that lets a relayer pre-verify approvals in earlier txs.
    ClprEd25519SignatureCache public immutable SIGNATURE_CACHE;
    /// @notice keccak256 of the CAIP-2 chain id this verifier accepts (e.g. "near:mainnet").
    bytes32 public immutable CHAIN_ID_HASH;
    /// @notice Weak-subjectivity checkpoint `verifyConfig` starts from.
    bytes32 public immutable CHECKPOINT_EPOCH_ID;
    bytes32 public immutable CHECKPOINT_NEXT_EPOCH_ID;
    bytes32 public immutable CHECKPOINT_EPOCH_BP_HASH;
    bytes32 public immutable CHECKPOINT_NEXT_BP_HASH;

    error InvalidAnchor();
    error NoBlocks();
    error ZeroAddress();

    constructor(
        string memory chainId,
        NearLightClient.EpochState memory checkpoint_,
        IEd25519Verifier ed25519,
        ClprEd25519SignatureCache signatureCache
    ) {
        if (address(ed25519) == address(0)) revert ZeroAddress();
        ED25519 = ed25519;
        SIGNATURE_CACHE = signatureCache;
        CHAIN_ID_HASH = keccak256(bytes(chainId));
        CHECKPOINT_EPOCH_ID = checkpoint_.epochId;
        CHECKPOINT_NEXT_EPOCH_ID = checkpoint_.nextEpochId;
        CHECKPOINT_EPOCH_BP_HASH = checkpoint_.epochBpHash;
        CHECKPOINT_NEXT_BP_HASH = checkpoint_.nextBpHash;
    }

    /// @notice The deploy-time checkpoint as an epoch window.
    function checkpoint() public view returns (NearLightClient.EpochState memory) {
        return NearLightClient.EpochState({
            epochId: CHECKPOINT_EPOCH_ID,
            nextEpochId: CHECKPOINT_NEXT_EPOCH_ID,
            epochBpHash: CHECKPOINT_EPOCH_BP_HASH,
            nextBpHash: CHECKPOINT_NEXT_BP_HASH
        });
    }

    function encodeAnchor(NearLightClient.EpochState memory st) public pure returns (bytes memory) {
        return abi.encodePacked(st.epochId, st.nextEpochId, st.epochBpHash, st.nextBpHash);
    }

    function decodeAnchor(bytes calldata a) public pure returns (NearLightClient.EpochState memory st) {
        if (a.length != ANCHOR_LENGTH) revert InvalidAnchor();
        st.epochId = bytes32(a[0:32]);
        st.nextEpochId = bytes32(a[32:64]);
        st.epochBpHash = bytes32(a[64:96]);
        st.nextBpHash = bytes32(a[96:128]);
    }

    /// @dev Apply light-client blocks in order from `st`; return the chosen shard's state root under
    ///      the last block and the (possibly rotated) epoch window.
    function _verifyBlocks(
        NearLightClient.EpochState memory st,
        NearLightClient.Block[] memory blocks,
        ShardRoots memory shards
    ) internal view returns (bytes32 shardRoot, NearLightClient.EpochState memory end) {
        if (blocks.length == 0) revert NoBlocks();
        NearLightClient.InnerLite memory lite;
        end = st;
        for (uint256 i = 0; i < blocks.length; i++) {
            (lite, end) = NearLightClient.verifyBlock(end, blocks[i], ED25519, SIGNATURE_CACHE);
        }
        shardRoot = NearLightClient.shardStateRoot(lite.prevStateRoot, shards.roots, shards.index);
    }

    /// @dev NEAR account ids are 2–64 bytes (nearcore `AccountId` validation); the trie key embeds it.
    function _checkAccountId(bytes memory id) internal pure {
        if (id.length < 2 || id.length > 64) revert InvalidServiceAddress();
        for (uint256 i = 0; i < id.length; i++) {
            bytes1 c = id[i];
            bool ok = (c >= "a" && c <= "z") || (c >= "0" && c <= "9") || c == "-" || c == "_" || c == ".";
            if (!ok) revert InvalidServiceAddress();
        }
    }
}
