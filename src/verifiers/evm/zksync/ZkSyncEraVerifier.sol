// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {IEthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/lib/IEthL1StateVerifier.sol";
import {IZkSyncStateTreeVerifier} from "@hiero-ledger/clpr/verifiers/evm/zksync/lib/IZkSyncStateTreeVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {EthBeaconLightClient} from "@hiero-ledger/clpr/libraries/proof/beacon/EthBeaconLightClient.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title ZkSyncEraVerifier
/// @notice CLPR verifier for ZK Stack chains that run EraVM and settle on Ethereum (ZKsync Era, Abstract,
///         Sophon, Lens, Cronos zkEVM, … — see README). A bundle is trusted through:
///
///         1. Ethereum sync committee → L1 execution `state_root`             ({IEthL1StateVerifier})
///         2. L1 `state_root` → the chain's diamond proxy: `totalBatchesExecuted`, `storedBatchHashes[n]`
///            and `protocolVersion` (MPT)                                      ({ClprEvmStateProof})
///         3. `storedBatchHashes[n] == keccak256(abi.encode(StoredBatchInfo))`, `n ≤ totalBatchesExecuted`;
///            `StoredBatchInfo.batchHash` is the L2 state-tree root after batch `n`
///         4. L2 root → ClprService code hash (AccountCodeStorage) and channel queue slots, in ZKsync's
///            Blake2s sparse Merkle tree                                       ({IZkSyncStateTreeVerifier})
///
///         Only EXECUTED batches are accepted. An executed batch has a verified validity proof (its
///         commitment, which binds the state root, was the proof's public input) and can no longer be
///         reverted (`Executor.revertBatches` stops at `totalBatchesExecuted`).
///
/// ## Trust anchor
/// The 260-byte Ethereum anchor of {EthBeaconLightClient}. Its `codeHash` field pins the L2 ClprService's
/// versioned bytecode hash (the AccountCodeStorage value), or is zero to skip that check. It rotates with
/// the L1 sync committee exactly as for {EthMainnetVerifier}.
///
/// ## Bundle proof (top-level RLP list, 5 items; 7 with an endpoint-manifest update)
/// ```
/// [ 0: lightClientProof   RLP string wrapping the {IEthL1StateVerifier.verifyL1State} proof
///   1: diamondProof       [accountProof, storageProof] of the diamond proxy at the attested L1 block;
///                         storageProof holds [slot, nodes] entries for totalBatchesExecuted,
///                         storedBatchHashes[n] and protocolVersion
///   2: storedBatchInfo    abi.encode(StoredBatchInfo): 288 bytes (v27+) or 256 bytes (legacy, no
///                         dependencyRootsRollingHash). Word 0 is the batch number, word 1 the state root.
///   3: l2StorageProof     packed {IZkSyncStateTreeVerifier} entries: [code-hash entry if the anchor pins
///                         one], the five Channel slots, [the last message's running-hash slot]. Any entry
///                         may be RECORDED (proven earlier via `recordStorage`, see README §6).
///   4: bundleContent      protobuf ClprBundleContent
///  (5: manifestProof      one packed entry for the endpoint-manifest commitment slot,
///   6: manifestPreimage) ]
/// ```
/// @dev The chain-specific facts (diamond address, ZKChainStorage slots, accepted protocol versions) are
///      constructor data, so one bytecode serves every EraVM ZK Stack chain that settles on Ethereum.
contract ZkSyncEraVerifier is ClprEvmBundleVerifier {
    /// @notice Where a ZK chain keeps its batch state on L1 (ZKChainStorage, at slot 0 of the diamond).
    struct Profile {
        /// The chain's diamond proxy on L1 (`Bridgehub.getZKChain(chainId)`).
        address diamondProxy;
        /// `ZKChainStorage.totalBatchesExecuted` (11 for every current ZKChainStorage).
        uint256 totalBatchesExecutedSlot;
        /// `ZKChainStorage.storedBatchHashes` mapping base (14).
        uint256 storedBatchHashesSlot;
        /// `ZKChainStorage.protocolVersion` (33): packed semver `minor << 32 | patch`.
        uint256 protocolVersionSlot;
        /// Inclusive range of protocol versions whose layout this profile was checked against. A protocol
        /// upgrade outside it stalls the verifier until it is redeployed with a re-checked profile.
        uint256 minProtocolVersion;
        uint256 maxProtocolVersion;
    }

    // ── Bundle payload layout ────────────────────────────────────────────────
    uint256 internal constant PAYLOAD_FIELDS = 5;
    uint256 internal constant PAYLOAD_FIELDS_WITH_MANIFEST = 7;
    uint256 internal constant IDX_LIGHT_CLIENT_PROOF = 0;
    uint256 internal constant IDX_DIAMOND_PROOF = 1;
    uint256 internal constant IDX_STORED_BATCH_INFO = 2;
    uint256 internal constant IDX_L2_STORAGE_PROOF = 3;
    uint256 internal constant IDX_BUNDLE_CONTENT = 4;
    uint256 internal constant IDX_MANIFEST_PROOF = 5;
    uint256 internal constant IDX_MANIFEST_PREIMAGE = 6;

    // Config-time endpoint-manifest proof (verifyConfig's 3rd arg, when non-empty), verified under the
    // genesis anchor: [lightClientProof, diamondProof, storedBatchInfo, l2ManifestProof, manifestPreimage],
    // l2ManifestProof holding [code-hash entry if pinned, manifest-commitment entry].
    uint256 internal constant CONFIG_MANIFEST_PROOF_FIELDS = 5;
    uint256 internal constant CM_IDX_L2_MANIFEST_PROOF = 3;
    uint256 internal constant CM_IDX_MANIFEST_PREIMAGE = 4;

    /// @dev EraVM system contract holding every account's versioned bytecode hash, keyed by address.
    address internal constant ACCOUNT_CODE_STORAGE = address(0x8002);
    /// @dev Bytes per packed tree entry before its siblings: value(32) ‖ leafIndex(8) ‖ pathLen(2).
    uint256 internal constant ENTRY_HEADER = 42;
    /// @dev `pathLen` of an entry proven earlier through {IZkSyncStateTreeVerifier.recordStorage}.
    uint256 internal constant RECORDED = 0xffff;
    uint256 internal constant STORED_BATCH_INFO_LENGTH = 288;
    uint256 internal constant LEGACY_STORED_BATCH_INFO_LENGTH = 256;

    /// @notice Ethereum L1 light client (stateless helper).
    IEthL1StateVerifier public immutable L1_STATE_VERIFIER;
    /// @notice ZKsync state-tree (Blake2s SMT) proof verifier (stateless helper).
    IZkSyncStateTreeVerifier public immutable STATE_TREE_VERIFIER;
    address public immutable DIAMOND_PROXY;
    uint256 public immutable TOTAL_BATCHES_EXECUTED_SLOT;
    uint256 public immutable STORED_BATCH_HASHES_SLOT;
    uint256 public immutable PROTOCOL_VERSION_SLOT;
    uint256 public immutable MIN_PROTOCOL_VERSION;
    uint256 public immutable MAX_PROTOCOL_VERSION;

    error InvalidPayloadShape();
    error InvalidConfigPayload();
    error InvalidTrustAnchor();
    error InvalidDeployment();
    error InvalidStoredBatchInfo();
    error StoredBatchHashMismatch(uint256 batchNumber);
    error BatchNotExecuted(uint256 batchNumber, uint256 totalBatchesExecuted);
    error UnsupportedProtocolVersion(uint256 protocolVersion);
    error MalformedL2StorageProof();

    constructor(
        IEthL1StateVerifier l1StateVerifier,
        IZkSyncStateTreeVerifier stateTreeVerifier,
        Profile memory profile_
    ) {
        if (
            address(l1StateVerifier) == address(0) || address(stateTreeVerifier) == address(0)
                || profile_.diamondProxy == address(0) || profile_.minProtocolVersion > profile_.maxProtocolVersion
        ) revert InvalidDeployment();
        L1_STATE_VERIFIER = l1StateVerifier;
        STATE_TREE_VERIFIER = stateTreeVerifier;
        DIAMOND_PROXY = profile_.diamondProxy;
        TOTAL_BATCHES_EXECUTED_SLOT = profile_.totalBatchesExecutedSlot;
        STORED_BATCH_HASHES_SLOT = profile_.storedBatchHashesSlot;
        PROTOCOL_VERSION_SLOT = profile_.protocolVersionSlot;
        MIN_PROTOCOL_VERSION = profile_.minProtocolVersion;
        MAX_PROTOCOL_VERSION = profile_.maxProtocolVersion;
    }

    /// @notice The deployment's profile.
    function profile() external view returns (Profile memory) {
        return Profile({
            diamondProxy: DIAMOND_PROXY,
            totalBatchesExecutedSlot: TOTAL_BATCHES_EXECUTED_SLOT,
            storedBatchHashesSlot: STORED_BATCH_HASHES_SLOT,
            protocolVersionSlot: PROTOCOL_VERSION_SLOT,
            minProtocolVersion: MIN_PROTOCOL_VERSION,
            maxProtocolVersion: MAX_PROTOCOL_VERSION
        });
    }

    /// @inheritdoc IClprVerifier
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
        if (trustAnchor.length != EthBeaconLightClient.TRUST_ANCHOR_LENGTH) {
            revert InvalidTrustAnchor();
        }
        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory payload = RLP.decodeList(proofMem);
        if (payload.length != PAYLOAD_FIELDS && payload.length != PAYLOAD_FIELDS_WITH_MANIFEST) {
            revert InvalidPayloadShape();
        }

        // Steps 1–3: L1 light client → executed batch → L2 state root.
        bytes32 l2Root;
        (l2Root,, newTrustAnchor, newTrustAnchorId) = _verifyL2StateRoot(payload, trustAnchor);

        // Step 4: code hash and channel slots in the L2 tree, bound to channelId.
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        address service = _toAddress(ctx.remoteServiceAddress);
        bytes32 codeHash = bytes32(
            trustAnchor[EthBeaconLightClient.ANCHOR_OFF_CODE_HASH:EthBeaconLightClient.ANCHOR_OFF_CODE_HASH + 32]
        );
        bytes32 channelId = bytes32(
            trustAnchor[EthBeaconLightClient.ANCHOR_OFF_CHANNEL_ID:EthBeaconLightClient.ANCHOR_OFF_CHANNEL_ID + 32]
        );
        metadata =
            _verifyChannelSlots(RLP.readBytes(payload[IDX_L2_STORAGE_PROOF]), l2Root, service, codeHash, channelId);
        messagePayloads = _decodeBundleContent(RLP.readBytes(payload[IDX_BUNDLE_CONTENT]));

        if (payload.length == PAYLOAD_FIELDS_WITH_MANIFEST) {
            newEndpointManifest = _verifyZkEndpointManifest(
                RLP.readBytes(payload[IDX_MANIFEST_PROOF]),
                l2Root,
                service,
                bytes32(0),
                RLP.readBytes(payload[IDX_MANIFEST_PREIMAGE]),
                ctx.remoteServiceAddress
            );
        } else {
            newEndpointManifest = _absentEndpointManifest();
        }
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes is {EthMainnetVerifier}'s config RLP
    ///      `[slot, syncCommittee, gvr, forkVersion, ledgerConfiguration, codeHash]`, `codeHash` being the
    ///      L2 ClprService's versioned bytecode hash (or zero).
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
        if (configProofBytes.length == 0) revert InvalidPayloadShape();
        bytes memory ledgerConfiguration;
        (initialTrustAnchor, initialTrustAnchorId, ledgerConfiguration) =
            L1_STATE_VERIFIER.genesisTrustAnchor(configProofBytes, channelId);
        ClprTypes.LedgerConfiguration memory lc = ClprProtobuf.decodeControlMessage(ledgerConfiguration).config;
        serviceAddress = lc.serviceAddress;
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        chainId = lc.chainId;
        peerConfigNanos = lc.nanosSinceEpoch;
        throttles = lc.throttles;
        endpointManifest = _verifyConfigEndpointManifest(endpointManifestProofBytes, initialTrustAnchor, serviceAddress);
    }

    /// @notice Steps 1–3 only: the executed batch and L2 state root a proof commits to, under `trustAnchor`.
    ///         Exposed for relayers and monitoring.
    /// @param proof RLP list whose items 0–2 are `[lightClientProof, diamondProof, storedBatchInfo]`.
    function verifyL2StateRoot(bytes calldata proof, bytes calldata trustAnchor)
        external
        view
        returns (bytes32 l2StateRoot, uint256 batchNumber, bytes memory newTrustAnchor, bytes memory newTrustAnchorId)
    {
        if (trustAnchor.length != EthBeaconLightClient.TRUST_ANCHOR_LENGTH) revert InvalidTrustAnchor();
        bytes memory proofMem = proof;
        Memory.Slice[] memory items = RLP.decodeList(proofMem);
        if (items.length <= IDX_STORED_BATCH_INFO) revert InvalidPayloadShape();
        return _verifyL2StateRoot(items, trustAnchor);
    }

    function _verifyL2StateRoot(Memory.Slice[] memory items, bytes memory trustAnchor)
        internal
        view
        returns (bytes32 l2Root, uint256 batchNumber, bytes memory newTrustAnchor, bytes memory newTrustAnchorId)
    {
        bytes32 l1StateRoot;
        (l1StateRoot,, newTrustAnchor, newTrustAnchorId) =
            L1_STATE_VERIFIER.verifyL1State(RLP.readBytes(items[IDX_LIGHT_CLIENT_PROOF]), trustAnchor);
        (l2Root, batchNumber) =
            _verifyExecutedBatch(items[IDX_DIAMOND_PROOF], RLP.readBytes(items[IDX_STORED_BATCH_INFO]), l1StateRoot);
    }

    /// @dev Steps 2–3: authenticate `storedBatchInfo` as an executed batch of the pinned diamond.
    function _verifyExecutedBatch(Memory.Slice diamondProofItem, bytes memory info, bytes32 l1StateRoot)
        internal
        view
        returns (bytes32 l2Root, uint256 batchNumber)
    {
        if (info.length != STORED_BATCH_INFO_LENGTH && info.length != LEGACY_STORED_BATCH_INFO_LENGTH) {
            revert InvalidStoredBatchInfo();
        }
        assembly ("memory-safe") {
            batchNumber := mload(add(info, 0x20))
            l2Root := mload(add(info, 0x40))
        }
        if (batchNumber > type(uint64).max) revert InvalidStoredBatchInfo();

        Memory.Slice[] memory dp = RLP.readList(diamondProofItem);
        if (dp.length != 2) revert InvalidPayloadShape();
        (bytes32 storageRoot,) =
            ClprEvmStateProof.decodeAccount(ClprEvmStateProof.verifyAccount(dp[0], l1StateRoot, DIAMOND_PROXY));
        bytes32[] memory slots = new bytes32[](3);
        slots[0] = bytes32(TOTAL_BATCHES_EXECUTED_SLOT);
        slots[1] = keccak256(abi.encode(batchNumber, STORED_BATCH_HASHES_SLOT));
        slots[2] = bytes32(PROTOCOL_VERSION_SLOT);
        bytes32[] memory v = ClprEvmStateProof.verifyProvenSlots(RLP.readList(dp[1]), storageRoot, slots);

        uint256 protocolVersion = uint256(v[2]);
        if (protocolVersion < MIN_PROTOCOL_VERSION || protocolVersion > MAX_PROTOCOL_VERSION) {
            revert UnsupportedProtocolVersion(protocolVersion);
        }
        if (batchNumber > uint256(v[0])) revert BatchNotExecuted(batchNumber, uint256(v[0]));
        if (keccak256(info) != v[1]) revert StoredBatchHashMismatch(batchNumber);
    }

    /// @dev Step 4. Entries: [code hash if pinned], Channel +1, +2, +4, +5, +16, [last message's running
    ///      hash]. All keys are derived here; the message slot's key uses the claimed nextMessageId, which
    ///      the same tree verification then authenticates.
    function _verifyChannelSlots(
        bytes memory l2Proof,
        bytes32 l2Root,
        address service,
        bytes32 codeHash,
        bytes32 channelId
    ) internal view returns (ClprTypes.QueueMetadata memory metadata) {
        uint256 off = codeHash == bytes32(0) ? 0 : 1;
        uint256 count = _countEntries(l2Proof);
        if (count != off + 5 && count != off + 6) revert InvalidStorageProofShape();

        address[] memory accounts = new address[](count);
        bytes32[] memory keys = new bytes32[](count);
        if (off == 1) {
            accounts[0] = ACCOUNT_CODE_STORAGE;
            keys[0] = bytes32(uint256(uint160(service)));
        }
        bytes32[] memory chSlots = _channelMetadataSlots(channelId);
        for (uint256 i = 0; i < 5; i++) {
            accounts[off + i] = service;
            keys[off + i] = chSlots[i];
        }
        if (count == off + 6) {
            // nextMessageId as claimed by the proof's own value for Channel +1 (authenticated below).
            uint64 nextMessageId = uint64(uint256(_entryValue(l2Proof, off)) >> 168);
            if (nextMessageId == 0) revert InvalidNextMessageId();
            accounts[off + 5] = service;
            keys[off + 5] = _lastMessageRunningHashSlot(channelId, nextMessageId - 1);
        }

        bytes32[] memory values = STATE_TREE_VERIFIER.verifyStorage(l2Root, accounts, keys, l2Proof);
        if (off == 1 && values[0] != codeHash) revert CodeHashMismatch();
        bytes32[] memory ch = new bytes32[](5);
        for (uint256 i = 0; i < 5; i++) {
            ch[i] = values[off + i];
        }
        metadata = _buildQueueMetadata(ch);
    }

    /// @dev Prove the endpoint-manifest commitment slot (and, when `codeHash` is non-zero, the service's code
    ///      hash first) and bind `manifestProtobuf` to it, with the checks of
    ///      {ClprEvmBundleVerifier._verifyEndpointManifest}.
    function _verifyZkEndpointManifest(
        bytes memory l2Proof,
        bytes32 l2Root,
        address service,
        bytes32 codeHash,
        bytes memory manifestProtobuf,
        bytes memory expectedServiceAddress
    ) internal view returns (ClprTypes.ClprEndpointManifest memory manifest) {
        uint256 off = codeHash == bytes32(0) ? 0 : 1;
        if (_countEntries(l2Proof) != off + 1) revert InvalidStorageProofShape();
        address[] memory accounts = new address[](off + 1);
        bytes32[] memory keys = new bytes32[](off + 1);
        if (off == 1) {
            accounts[0] = ACCOUNT_CODE_STORAGE;
            keys[0] = bytes32(uint256(uint160(service)));
        }
        accounts[off] = service;
        keys[off] = bytes32(ENDPOINT_MANIFEST_COMMITMENT_SLOT);
        bytes32[] memory values = STATE_TREE_VERIFIER.verifyStorage(l2Root, accounts, keys, l2Proof);
        if (off == 1 && values[0] != codeHash) revert CodeHashMismatch();

        if (keccak256(manifestProtobuf) != values[off]) revert ManifestCommitmentMismatch();
        manifest = ClprProtobuf.decodeEndpointManifest(manifestProtobuf);
        if (manifest.version == 0) revert ManifestVersionZero();
        if (
            expectedServiceAddress.length > 0 && keccak256(manifest.serviceAddress) != keccak256(expectedServiceAddress)
        ) {
            revert ManifestServiceAddressMismatch();
        }
    }

    /// @dev Config-time endpoint-manifest proof, verified end to end under the genesis anchor; empty →
    ///      UNINITIALIZED manifest.
    function _verifyConfigEndpointManifest(
        bytes calldata proofBytes,
        bytes memory genesisAnchor,
        bytes memory serviceAddress
    ) private view returns (ClprTypes.ClprEndpointManifest memory) {
        if (proofBytes.length == 0) return _uninitializedEndpointManifest(serviceAddress);
        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory p = RLP.decodeList(proofMem);
        if (p.length != CONFIG_MANIFEST_PROOF_FIELDS) revert InvalidConfigPayload();

        (bytes32 l2Root,,,) = _verifyL2StateRoot(p, genesisAnchor);
        bytes32 codeHash;
        uint256 codeHashOffset = 0x20 + EthBeaconLightClient.ANCHOR_OFF_CODE_HASH;
        assembly ("memory-safe") {
            codeHash := mload(add(genesisAnchor, codeHashOffset))
        }
        return _verifyZkEndpointManifest(
            RLP.readBytes(p[CM_IDX_L2_MANIFEST_PROOF]),
            l2Root,
            _toAddress(serviceAddress),
            codeHash,
            RLP.readBytes(p[CM_IDX_MANIFEST_PREIMAGE]),
            serviceAddress
        );
    }

    // ── Packed tree-entry helpers (format: {IZkSyncStateTreeVerifier}) ────────

    /// @dev Bytes taken by the entry starting at `off`: header plus siblings (none for a RECORDED entry).
    function _entryLength(bytes memory proof, uint256 off) private pure returns (uint256) {
        uint256 pathLen;
        assembly ("memory-safe") {
            pathLen := shr(240, mload(add(add(proof, 0x20), add(off, 40))))
        }
        return pathLen == RECORDED ? ENTRY_HEADER : ENTRY_HEADER + 32 * pathLen;
    }

    /// @dev Number of entries in a packed proof; reverts if the entries do not tile it exactly.
    function _countEntries(bytes memory proof) internal pure returns (uint256 count) {
        uint256 off = 0;
        while (off < proof.length) {
            if (off + ENTRY_HEADER > proof.length) revert MalformedL2StorageProof();
            off += _entryLength(proof, off);
            unchecked {
                ++count;
            }
        }
        if (off != proof.length) revert MalformedL2StorageProof();
    }

    /// @dev The (unverified) value field of entry `index`; the proof's tiling was checked by {_countEntries}.
    function _entryValue(bytes memory proof, uint256 index) internal pure returns (bytes32 value) {
        uint256 off = 0;
        for (uint256 i = 0; i < index; i++) {
            off += _entryLength(proof, off);
        }
        assembly ("memory-safe") {
            value := mload(add(add(proof, 0x20), off))
        }
    }
}
