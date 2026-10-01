// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {NearLightClient} from "@hiero-ledger/clpr/libraries/proof/near/NearLightClient.sol";
import {ClprEd25519SignatureCache} from "@hiero-ledger/clpr/verifiers/evm/neartons/ClprEd25519SignatureCache.sol";
import {NearAnchoredVerifier} from "@hiero-ledger/clpr/verifiers/evm/neartons/NearAnchoredVerifier.sol";

/// @title AuroraVerifier
/// @notice Aurora → Hiero CLPR verifier. Aurora is an EVM (aurora-engine) running as a NEAR contract,
///         so an Aurora block is final when the NEAR block that executed it is final. The verifier
///         is the NEAR light client of {NearAnchoredVerifier} plus a NEAR state-trie proof of each EVM
///         storage slot of the Solidity ClprService, read under the engine account's contract data.
///
/// Engine storage layout (aurora-engine `engine-types/src/storage.rs`, `engine/src/engine.rs`):
///   - EVM storage slot: `0x07 ‖ 0x04 ‖ address(20) ‖ slot(32)` when the address's generation is 0,
///     else `0x07 ‖ 0x04 ‖ address(20) ‖ u32le(generation) ‖ slot(32)`; the value is the 32-byte word.
///     A zero word is never stored (`Engine::apply` removes the key), so value 0 is proven by absence.
///   - generation: `0x07 ‖ 0x07 ‖ address(20)` → `u32be(generation)`; absent = 0. It grows each time
///     the address's storage is reset (self-destruct and re-creation), so it is always proven.
///   - engine state: `0x07 ‖ 0x00 ‖ "STATE"` → borsh `BorshableEngineState` (V1/V2/V3 enum tag,
///     then `chain_id: [u8; 32]`). Its existence proof pins the shard that holds the engine account
///     and binds the EIP-155 chain id.
///
/// The ClprService slots read are those of {ClprEvmBundleVerifier}: the five `Channel` slots, the
/// last sent message's running hash, and the endpoint-manifest commitment (slot 18).
contract AuroraVerifier is NearAnchoredVerifier {
    /// @dev One EVM storage slot of the service. `value == 0` = the nodes prove the key is absent.
    struct SlotProof {
        bytes[] nodes;
        bytes32 value;
    }

    /// @dev Engine-level facts every proof carries: the engine state (shard + chain id) and the
    ///      service address's storage generation (`generation == 0` = `generationNodes` prove absence).
    struct EngineProof {
        bytes[] stateNodes;
        bytes state;
        bytes[] generationNodes;
        uint32 generation;
    }

    struct BundleProof {
        NearLightClient.Block[] blocks; // applied in order; the last block's state root is used
        ShardRoots shards;
        EngineProof engine;
        SlotProof[] slots; // the five Channel slots, plus the last message's running hash (6 entries)
        bytes bundleContent; // ClprBundleContent protobuf
        SlotProof manifestSlot; // slot 18; ignored when manifestPreimage is empty
        bytes manifestPreimage; // empty = no manifest in this bundle
    }

    struct ConfigProof {
        NearLightClient.Block[] blocks; // from the deploy-time checkpoint
        ShardRoots shards;
        EngineProof engine;
        bytes controlMessage; // ClprMessagePayload{control{config_update}} protobuf
    }

    /// @dev Optional `endpointManifestProofBytes` of {verifyConfig}, against the config proof's root.
    struct ManifestProof {
        SlotProof manifestSlot;
        bytes manifestPreimage;
    }

    /// @dev Generic proof of any EVM storage slots in the engine (the live tests: no ClprService is
    ///      deployed on Aurora yet).
    struct StorageProof {
        NearLightClient.Block[] blocks;
        ShardRoots shards;
        EngineProof engine;
        address account;
        bytes32[] slots;
        SlotProof[] proofs;
    }

    uint8 internal constant VERSION_V1 = 0x07;
    uint8 internal constant PREFIX_CONFIG = 0x00;
    uint8 internal constant PREFIX_STORAGE = 0x04;
    uint8 internal constant PREFIX_GENERATION = 0x07;
    uint8 internal constant ENGINE_STATE_MAX_TAG = 2; // BorshableEngineState::{V1, V2, V3}

    /// @notice The NEAR account running aurora-engine (e.g. "aurora").
    bytes public engineAccount;
    /// @notice The EIP-155 chain id the engine state must carry (e.g. 1313161554).
    uint256 public immutable EVM_CHAIN_ID;

    error WrongEngineChainId(uint256 got);
    error BadEngineState();
    error BadGeneration();
    error SlotCountMismatch();

    /// @param chainId CLPR (CAIP-2) chain id of the Aurora network, e.g. "eip155:1313161554".
    /// @param checkpoint_ NEAR epoch window `verifyConfig` starts from.
    /// @param engineAccount_ NEAR account of the engine, e.g. "aurora".
    /// @param evmChainId EIP-155 chain id stored in the engine state.
    constructor(
        string memory chainId,
        NearLightClient.EpochState memory checkpoint_,
        IEd25519Verifier ed25519,
        ClprEd25519SignatureCache signatureCache,
        bytes memory engineAccount_,
        uint256 evmChainId
    ) NearAnchoredVerifier(chainId, checkpoint_, ed25519, signatureCache) {
        _checkAccountId(engineAccount_);
        engineAccount = engineAccount_;
        EVM_CHAIN_ID = evmChainId;
    }

    // ── IClprVerifier ────────────────────────────────────────────────────────

    /// @inheritdoc IClprVerifier
    /// @dev proofBytes = abi.encode(BundleProof).
    function verifyBundle(bytes calldata proofBytes, bytes calldata trustAnchor, bytes calldata channelContext)
        external
        view
        override
        returns (
            ClprTypes.QueueMetadata memory metadata,
            bytes[] memory messagePayloads,
            bytes memory newTrustAnchor,
            bytes memory newTrustAnchorId,
            ClprTypes.ClprEndpointManifest memory newEndpointManifest
        )
    {
        NearLightClient.EpochState memory st = decodeAnchor(trustAnchor);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        address service = _evmAddress(ctx.remoteServiceAddress);
        BundleProof memory p = abi.decode(proofBytes, (BundleProof));

        (bytes32 shardRoot, NearLightClient.EpochState memory end) = _verifyBlocks(st, p.blocks, p.shards);
        uint32 gen = _verifyEngine(shardRoot, service, p.engine);

        if (p.slots.length != 5 && p.slots.length != 6) revert InvalidStorageProofShape();
        bytes32[] memory keys = _channelMetadataSlots(ctx.channelId);
        bytes32[] memory values = new bytes32[](5);
        for (uint256 i = 0; i < 5; i++) {
            values[i] = _verifySlot(shardRoot, service, gen, keys[i], p.slots[i]);
        }
        metadata = _buildQueueMetadata(values);
        if (p.slots.length == 6) {
            if (metadata.nextMessageId == 0) revert InvalidNextMessageId();
            _verifySlot(
                shardRoot,
                service,
                gen,
                _lastMessageRunningHashSlot(ctx.channelId, uint64(metadata.nextMessageId - 1)),
                p.slots[5]
            );
        }
        messagePayloads = _decodeBundleContent(p.bundleContent);

        if (p.manifestPreimage.length == 0) {
            newEndpointManifest = _absentEndpointManifest();
        } else {
            bytes32 c = _verifySlot(shardRoot, service, gen, bytes32(ENDPOINT_MANIFEST_COMMITMENT_SLOT), p.manifestSlot);
            newEndpointManifest = _bindManifest(p.manifestPreimage, c, ctx.remoteServiceAddress);
        }

        if (end.epochId != st.epochId) {
            newTrustAnchor = encodeAnchor(end);
            newTrustAnchorId = abi.encodePacked(end.epochId);
        }
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes = abi.encode(ConfigProof), starting from the deploy-time NEAR checkpoint.
    ///      As for the other EVM-peer verifiers, the configuration fields come from the registration's
    ///      ControlMessage; the chain id must be this verifier's and the service address a 20-byte
    ///      EVM address. The engine state is proven (shard, EIP-155 chain id) under the same root as
    ///      the optional manifest commitment (`endpointManifestProofBytes` = abi.encode(ManifestProof)).
    function verifyConfig(bytes calldata configProofBytes, bytes32 channelId, bytes calldata endpointManifestProofBytes)
        external
        view
        override
        returns (
            bytes memory channelContext,
            string memory chainId,
            bytes memory serviceAddress,
            uint96 peerConfigNanos,
            ClprTypes.Throttles memory throttles,
            bytes memory initialTrustAnchor,
            bytes memory initialTrustAnchorId,
            ClprTypes.ClprEndpointManifest memory endpointManifest
        )
    {
        ConfigProof memory p = abi.decode(configProofBytes, (ConfigProof));
        ClprTypes.LedgerConfiguration memory lc = ClprProtobuf.decodeControlMessage(p.controlMessage).config;
        if (keccak256(bytes(lc.chainId)) != CHAIN_ID_HASH) revert WrongChainId();
        serviceAddress = lc.serviceAddress;
        address service = _evmAddress(serviceAddress);

        (bytes32 shardRoot, NearLightClient.EpochState memory end) = _verifyBlocks(checkpoint(), p.blocks, p.shards);
        uint32 gen = _verifyEngine(shardRoot, service, p.engine);

        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        chainId = lc.chainId;
        peerConfigNanos = lc.nanosSinceEpoch;
        throttles = lc.throttles;
        initialTrustAnchor = encodeAnchor(end);
        initialTrustAnchorId = abi.encodePacked(end.epochId);

        if (endpointManifestProofBytes.length == 0) {
            endpointManifest = _uninitializedEndpointManifest(serviceAddress);
        } else {
            ManifestProof memory mp = abi.decode(endpointManifestProofBytes, (ManifestProof));
            bytes32 c =
                _verifySlot(shardRoot, service, gen, bytes32(ENDPOINT_MANIFEST_COMMITMENT_SLOT), mp.manifestSlot);
            endpointManifest = _bindManifest(mp.manifestPreimage, c, serviceAddress);
        }
    }

    // ── Generic entry point ──────────────────────────────────────────────────

    /// @notice Verify light-client blocks from `trustAnchor`, the engine state and generation of
    ///         `account`, and the given storage slots. Returns the slot values, the generation, the
    ///         last NEAR block hash and height, and the new anchor (empty when the epoch did not change).
    function verifyEvmStorage(bytes calldata proofBytes, bytes calldata trustAnchor)
        external
        view
        returns (
            bytes32[] memory values,
            uint32 generation,
            bytes32 lastBlockHash,
            uint64 height,
            bytes memory newTrustAnchor
        )
    {
        NearLightClient.EpochState memory st = decodeAnchor(trustAnchor);
        StorageProof memory p = abi.decode(proofBytes, (StorageProof));
        if (p.slots.length != p.proofs.length) revert SlotCountMismatch();
        (bytes32 shardRoot, NearLightClient.EpochState memory end) = _verifyBlocks(st, p.blocks, p.shards);
        generation = _verifyEngine(shardRoot, p.account, p.engine);
        values = new bytes32[](p.slots.length);
        for (uint256 i = 0; i < p.slots.length; i++) {
            values[i] = _verifySlot(shardRoot, p.account, generation, p.slots[i], p.proofs[i]);
        }
        NearLightClient.Block memory last = p.blocks[p.blocks.length - 1];
        lastBlockHash = NearLightClient.blockHash(last);
        height = NearLightClient.parseInnerLite(last.innerLite).height;
        if (end.epochId != st.epochId) newTrustAnchor = encodeAnchor(end);
    }

    /// @notice The engine contract-data key of EVM storage `slot` of `account` at `generation`.
    function storageKey(address account, uint32 generation, bytes32 slot) public pure returns (bytes memory) {
        if (generation == 0) return abi.encodePacked(VERSION_V1, PREFIX_STORAGE, account, slot);
        return abi.encodePacked(VERSION_V1, PREFIX_STORAGE, account, _le32(generation), slot);
    }

    // ── internals ────────────────────────────────────────────────────────────

    /// @dev Prove the engine state (binds the shard root to the engine account and checks the
    ///      EIP-155 chain id) and the storage generation of `account`.
    function _verifyEngine(bytes32 shardRoot, address account, EngineProof memory e) internal view returns (uint32) {
        bytes memory engine = engineAccount;
        NearLightClient.verifyValue(
            shardRoot,
            NearLightClient.contractDataKey(engine, abi.encodePacked(VERSION_V1, PREFIX_CONFIG, "STATE")),
            e.stateNodes,
            e.state
        );
        if (e.state.length < 33 || uint8(e.state[0]) > ENGINE_STATE_MAX_TAG) revert BadEngineState();
        uint256 cid = uint256(_bytes32At(e.state, 1));
        if (cid != EVM_CHAIN_ID) revert WrongEngineChainId(cid);

        bytes memory genKey =
            NearLightClient.contractDataKey(engine, abi.encodePacked(VERSION_V1, PREFIX_GENERATION, account));
        if (e.generation == 0) {
            NearLightClient.verifyAbsent(shardRoot, genKey, e.generationNodes);
        } else {
            NearLightClient.verifyValue(shardRoot, genKey, e.generationNodes, abi.encodePacked(e.generation));
        }
        return e.generation;
    }

    function _verifySlot(bytes32 shardRoot, address account, uint32 generation, bytes32 slot, SlotProof memory s)
        internal
        view
        returns (bytes32)
    {
        bytes memory key = NearLightClient.contractDataKey(engineAccount, storageKey(account, generation, slot));
        if (s.value == bytes32(0)) {
            NearLightClient.verifyAbsent(shardRoot, key, s.nodes);
        } else {
            NearLightClient.verifyValue(shardRoot, key, s.nodes, abi.encodePacked(s.value));
        }
        return s.value;
    }

    function _evmAddress(bytes memory a) internal pure returns (address) {
        if (a.length != 20) revert InvalidServiceAddressLength();
        return address(bytes20(_bytes32At(a, 0)));
    }

    function _le32(uint32 v) private pure returns (bytes4) {
        return bytes4(uint32((v & 0xff) << 24 | ((v >> 8) & 0xff) << 16 | ((v >> 16) & 0xff) << 8 | (v >> 24)));
    }
}
