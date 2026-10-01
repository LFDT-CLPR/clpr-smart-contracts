// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprQueueRecordVerifier} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/ClprQueueRecordVerifier.sol";
import {FuelBlockProof} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/lib/FuelBlockProof.sol";
import {IEthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/lib/IEthL1StateVerifier.sol";
import {EthBeaconLightClient} from "@hiero-ledger/clpr/libraries/proof/beacon/EthBeaconLightClient.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title FuelVerifier
/// @notice Fuel (Ignition) → Hiero. Fuel posts block hashes to Ethereum, where `FuelChainState`
///         stores one committed block id per commit interval. Ethereum does not check the Fuel
///         state transition (no fault or validity proofs): **a commit is whatever the Fuel committer
///         posted**. This verifier therefore has a weaker trust tier than a light client: it trusts
///         the Ethereum sync committee AND the Fuel committer key (see the family README).
///
///         Proof chain:
///         1. Ethereum sync committee → L1 execution `state_root`          ({IEthL1StateVerifier})
///         2. `state_root` → FuelChainState account (code hash, EIP-1967 implementation pinned) →
///            storage: commit slot `c mod 240` (block id, timestamp) and `_paused` = false
///         3. commit timestamp + TIME_TO_FINALIZE ≤ L1 time of the signed beacon slot (the same
///            finalization delay Fuel's message portal enforces)
///         4. committed block header (76 bytes) → its id equals the committed block id
///         5. message block header (162 bytes, applicationHash recomputed) → its id is in the
///            committed block's `prevRoot` (block-history Merkle proof, height < commit height)
///         6. message id → the message block's `messageOutboxRoot` (outbox Merkle proof)
///         7. message: sender = the CLPR Sway contract (channel's remote service address),
///            recipient = `MESSAGE_RECIPIENT`, amount 0, data = `channelId ‖ ChannelQueue`
///
/// ## Why messages and not storage
/// Fuel block headers commit to no state root: fuel-core keeps contract storage in its database and
/// the transaction `stateRoot` fields hash only the slots a transaction touched
/// (`executor/src/contract_state_hash.rs`). What a block does commit to, and what Ethereum receives,
/// is the message outbox. The Fuel CLPR Service therefore emits its queue record as a message to L1
/// (`std::message::send_message(MESSAGE_RECIPIENT, channelId ‖ record, 0)`) whenever the record
/// changes. The message is never relayed on Ethereum; it is only proven here.
///
/// ## Trust anchor
/// The 260-byte Ethereum anchor of {EthBeaconLightClient}; its channel id must equal the channel's.
///
/// ## Bundle proof (RLP list, 9 items; 10 with an endpoint-manifest update)
/// ```
/// [ 0: lightClientProof   RLP string wrapping the {IEthL1StateVerifier.verifyL1State} proof
///   1: accountProof       MPT account proof of FuelChainState
///   2: storageProof       4 × [slot, proofNodes]: commit block id, commit timestamp, _paused, EIP-1967 impl
///   3: commitHeader       76-byte consensus header of the committed block
///   4: messageHeader      162-byte full header of the block that emitted the message
///   5: blockProof         [index = message block height, siblings]  (tree size = commit height)
///   6: messageProof       [index in outbox, siblings]               (tree size = messageReceiptCount)
///   7: message            [sender, recipient, nonce, amount, data]
///   8: bundleContent      protobuf ClprBundleContent
///  (9: manifestPreimage   bound to the record's endpoint-manifest commitment) ]
/// ```
/// At `verifyConfig` the manifest comes from a service-level message `MANIFEST_TAG ‖ commitment`
/// (the record of a channel that does not exist yet cannot carry it).
contract FuelVerifier is ClprQueueRecordVerifier {
    uint256 internal constant BUNDLE_FIELDS = 9;
    uint256 internal constant BUNDLE_FIELDS_WITH_MANIFEST = 10;
    uint256 internal constant MESSAGE_FIELDS = 5;
    uint256 internal constant QUEUE_OFFSET = 32;
    /// @dev First word of a service-level manifest message: `MANIFEST_TAG ‖ keccak256(manifest)`.
    bytes32 public constant MANIFEST_TAG = keccak256("clpr.fuel.endpoint-manifest");
    /// @dev ERC-1967 implementation slot.
    bytes32 internal constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /// @notice Per-deployment facts about Fuel's contracts on Ethereum, read from the chain.
    struct Profile {
        IEthL1StateVerifier l1StateVerifier;
        /// @dev L1 clock: beacon slot `s` starts at `l1GenesisTime + s × l1SecondsPerSlot`.
        uint64 l1GenesisTime;
        uint64 l1SecondsPerSlot;
        /// @dev FuelChainState proxy, its code hash and the pinned implementation behind it.
        address chainState;
        bytes32 chainStateCodeHash;
        address chainStateImplementation;
        /// @dev Storage slot of `_commitSlots[0].blockHash` (each Commit takes 2 slots) and of `_paused`.
        uint256 commitSlotsBase;
        uint256 pausedSlot;
        /// @dev FuelChainState immutables: NUM_COMMIT_SLOTS, BLOCKS_PER_COMMIT_INTERVAL, TIME_TO_FINALIZE.
        uint64 numCommitSlots;
        uint64 blocksPerCommitInterval;
        uint64 timeToFinalize;
        /// @dev L1 recipient every CLPR record message must name (the deployment's marker address).
        bytes32 messageRecipient;
    }

    IEthL1StateVerifier public immutable L1_STATE_VERIFIER;
    uint64 public immutable L1_GENESIS_TIME;
    uint64 public immutable L1_SECONDS_PER_SLOT;
    address public immutable CHAIN_STATE;
    bytes32 public immutable CHAIN_STATE_CODE_HASH;
    address public immutable CHAIN_STATE_IMPLEMENTATION;
    uint256 public immutable COMMIT_SLOTS_BASE;
    uint256 public immutable PAUSED_SLOT;
    uint64 public immutable NUM_COMMIT_SLOTS;
    uint64 public immutable BLOCKS_PER_COMMIT_INTERVAL;
    uint64 public immutable TIME_TO_FINALIZE;
    bytes32 public immutable MESSAGE_RECIPIENT;

    /// @notice A Fuel message proven to sit in a block the committer posted and that has finalized.
    struct FuelMessage {
        bytes32 sender;
        bytes32 recipient;
        bytes32 nonce;
        uint64 amount;
        bytes data;
        uint32 blockHeight;
        uint32 commitHeight;
        uint64 commitTimestamp;
    }

    error InvalidProfile();
    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error ChannelMismatch();
    error ImplementationMismatch();
    error ChainStatePaused();
    error CommitMismatch();
    error CommitNotFinal();
    error BlockNotInHistory();
    error MessageNotInBlock();
    error InvalidMessage();
    error InvalidManifestMessage();

    constructor(Profile memory p) {
        if (
            address(p.l1StateVerifier) == address(0) || p.chainState == address(0) || p.chainStateCodeHash == 0
                || p.chainStateImplementation == address(0) || p.numCommitSlots == 0 || p.blocksPerCommitInterval == 0
                || p.l1SecondsPerSlot == 0 || p.messageRecipient == 0
        ) revert InvalidProfile();
        L1_STATE_VERIFIER = p.l1StateVerifier;
        L1_GENESIS_TIME = p.l1GenesisTime;
        L1_SECONDS_PER_SLOT = p.l1SecondsPerSlot;
        CHAIN_STATE = p.chainState;
        CHAIN_STATE_CODE_HASH = p.chainStateCodeHash;
        CHAIN_STATE_IMPLEMENTATION = p.chainStateImplementation;
        COMMIT_SLOTS_BASE = p.commitSlotsBase;
        PAUSED_SLOT = p.pausedSlot;
        NUM_COMMIT_SLOTS = p.numCommitSlots;
        BLOCKS_PER_COMMIT_INTERVAL = p.blocksPerCommitInterval;
        TIME_TO_FINALIZE = p.timeToFinalize;
        MESSAGE_RECIPIENT = p.messageRecipient;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   IClprVerifier
    // ─────────────────────────────────────────────────────────────────────────

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
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        if (
            bytes32(
                    trustAnchor[EthBeaconLightClient.ANCHOR_OFF_CHANNEL_ID:EthBeaconLightClient.ANCHOR_OFF_CHANNEL_ID
                                + 32
                    ]
                ) != ctx.channelId
        ) revert ChannelMismatch();
        bytes32 service = _bytes32Address(ctx.remoteServiceAddress);

        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory items = RLP.decodeList(proofMem);
        if (items.length != BUNDLE_FIELDS && items.length != BUNDLE_FIELDS_WITH_MANIFEST) revert InvalidPayloadShape();

        FuelMessage memory m;
        (m, newTrustAnchor, newTrustAnchorId) = _verifyMessage(items, trustAnchor);
        if (m.sender != service || m.recipient != MESSAGE_RECIPIENT || m.amount != 0) revert InvalidMessage();
        if (m.data.length <= QUEUE_OFFSET || _word(m.data, 0) != ctx.channelId) revert InvalidMessage();

        bytes memory record = new bytes(m.data.length - QUEUE_OFFSET);
        for (uint256 i = 0; i < record.length; i++) {
            record[i] = m.data[QUEUE_OFFSET + i];
        }
        bytes32 commitment;
        (metadata, commitment) = _decodeQueueRecord(record);
        messagePayloads = _decodeBundleContent(RLP.readBytes(items[8]));
        newEndpointManifest = items.length == BUNDLE_FIELDS_WITH_MANIFEST
            ? _bindManifest(RLP.readBytes(items[9]), commitment, ctx.remoteServiceAddress)
            : _absentEndpointManifest();
    }

    /// @dev `configProofBytes` is {IEthL1StateVerifier.genesisTrustAnchor}'s config
    ///      `[slot, syncCommittee, gvr, forkVersion, ledgerConfiguration, codeHash]`; `codeHash` must be
    ///      the FuelChainState code hash. A config-time manifest proof is not supported: the first
    ///      manifest arrives with a bundle (bring-up, as for the other verifiers).
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
        if (_word(initialTrustAnchor, EthBeaconLightClient.ANCHOR_OFF_CODE_HASH) != CHAIN_STATE_CODE_HASH) {
            revert InvalidTrustAnchor();
        }
        ClprTypes.LedgerConfiguration memory lc = ClprProtobuf.decodeControlMessage(ledgerConfiguration).config;
        _requireNamespace(lc.chainId, "fuel:");
        _bytes32Address(lc.serviceAddress);
        serviceAddress = lc.serviceAddress;
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        chainId = lc.chainId;
        peerConfigNanos = lc.nanosSinceEpoch;
        throttles = lc.throttles;
        endpointManifest = endpointManifestProofBytes.length == 0
            ? _uninitializedEndpointManifest(serviceAddress)
            : _verifyConfigManifest(endpointManifestProofBytes, initialTrustAnchor, serviceAddress);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Generic entry point
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Steps 1–6 for any Fuel message: `proof` = RLP `[lightClientProof, accountProof,
    ///         storageProof, commitHeader, messageHeader, blockProof, messageProof, message]`.
    ///         Returns the proven message and, if the light-client proof rotated the sync
    ///         committee, the successor anchor.
    function verifyFuelMessage(bytes calldata proof, bytes calldata trustAnchor)
        external
        view
        returns (FuelMessage memory m, bytes memory newTrustAnchor, bytes memory newTrustAnchorId)
    {
        if (trustAnchor.length != EthBeaconLightClient.TRUST_ANCHOR_LENGTH) revert InvalidTrustAnchor();
        bytes memory proofMem = proof;
        Memory.Slice[] memory items = RLP.decodeList(proofMem);
        if (items.length != BUNDLE_FIELDS - 1) revert InvalidPayloadShape();
        return _verifyMessage(items, trustAnchor);
    }

    /// @notice The four FuelChainState slots a proof must cover for commit height `commitHeight`:
    ///         block id, timestamp word, `_paused`, EIP-1967 implementation.
    function chainStateSlots(uint256 commitHeight) public view returns (bytes32[] memory slots) {
        uint256 commitSlot = COMMIT_SLOTS_BASE + 2 * (commitHeight % NUM_COMMIT_SLOTS);
        slots = new bytes32[](4);
        slots[0] = bytes32(commitSlot);
        slots[1] = bytes32(commitSlot + 1);
        slots[2] = bytes32(PAUSED_SLOT);
        slots[3] = IMPLEMENTATION_SLOT;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Internal
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Config-time manifest: RLP `[messageProof, manifestPreimage]`, where `messageProof` is the
    ///      8-item {verifyFuelMessage} proof of a service message `MANIFEST_TAG ‖ keccak256(manifest)`
    ///      verified under the genesis anchor.
    function _verifyConfigManifest(bytes calldata proof, bytes memory anchor, bytes memory serviceAddress)
        internal
        view
        returns (ClprTypes.ClprEndpointManifest memory)
    {
        bytes memory proofMem = proof;
        Memory.Slice[] memory outer = RLP.decodeList(proofMem);
        if (outer.length != 2) revert InvalidPayloadShape();
        bytes memory inner = RLP.readBytes(outer[0]);
        Memory.Slice[] memory items = RLP.decodeList(inner);
        if (items.length != BUNDLE_FIELDS - 1) revert InvalidPayloadShape();
        (FuelMessage memory m,,) = _verifyMessage(items, anchor);
        if (
            m.sender != _bytes32Address(serviceAddress) || m.recipient != MESSAGE_RECIPIENT || m.amount != 0
                || m.data.length != 64 || _word(m.data, 0) != MANIFEST_TAG
        ) revert InvalidManifestMessage();
        return _bindManifest(RLP.readBytes(outer[1]), _word(m.data, 32), serviceAddress);
    }

    function _verifyMessage(Memory.Slice[] memory items, bytes memory trustAnchor)
        internal
        view
        returns (FuelMessage memory m, bytes memory newTrustAnchor, bytes memory newTrustAnchorId)
    {
        // 1. L1 state root under the sync committee.
        bytes32 l1StateRoot;
        uint64 slot;
        (l1StateRoot, slot, newTrustAnchor, newTrustAnchorId) =
            L1_STATE_VERIFIER.verifyL1State(RLP.readBytes(items[0]), trustAnchor);

        // 4. The committed block's consensus header (its height selects the commit slot).
        (bytes32 commitId, bytes32 commitPrevRoot, uint32 commitHeight,) =
            FuelBlockProof.consensusHeader(RLP.readBytes(items[3]));
        m.commitHeight = commitHeight;

        // 2–3. FuelChainState storage: commit slot, finalization delay, not paused, pinned implementation.
        m.commitTimestamp = _verifyCommit(items[1], items[2], l1StateRoot, commitId, commitHeight, slot);

        // 5. Message block in the committed block's history.
        FuelBlockProof.FullHeader memory mh = FuelBlockProof.fullHeader(RLP.readBytes(items[4]));
        (uint256 blockIndex, bytes32[] memory blockSiblings) = _readMerkleProof(items[5]);
        if (
            blockIndex != mh.height
                || !FuelBlockProof.verifyInclusion(commitPrevRoot, mh.id, blockIndex, commitHeight, blockSiblings)
        ) revert BlockNotInHistory();
        m.blockHeight = mh.height;

        // 6–7. Message in the block's outbox.
        Memory.Slice[] memory msgFields = RLP.readList(items[7]);
        if (msgFields.length != MESSAGE_FIELDS) revert InvalidMessage();
        m.sender = RLP.readBytes32(msgFields[0]);
        m.recipient = RLP.readBytes32(msgFields[1]);
        m.nonce = RLP.readBytes32(msgFields[2]);
        uint256 amount = RLP.readUint256(msgFields[3]);
        if (amount > type(uint64).max) revert InvalidMessage();
        // forge-lint: disable-next-line(unsafe-typecast)
        m.amount = uint64(amount);
        m.data = RLP.readBytes(msgFields[4]);
        (uint256 msgIndex, bytes32[] memory msgSiblings) = _readMerkleProof(items[6]);
        bytes32 id = FuelBlockProof.messageId(m.sender, m.recipient, m.nonce, m.amount, m.data);
        if (!FuelBlockProof.verifyInclusion(mh.messageOutboxRoot, id, msgIndex, mh.messageReceiptCount, msgSiblings)) {
            revert MessageNotInBlock();
        }
    }

    function _verifyCommit(
        Memory.Slice accountProof,
        Memory.Slice storageProof,
        bytes32 l1StateRoot,
        bytes32 commitId,
        uint32 commitHeight,
        uint64 slot
    ) internal view returns (uint64 commitTimestamp) {
        bytes32 storageRoot = _verifyServiceStorageRoot(accountProof, l1StateRoot, CHAIN_STATE, CHAIN_STATE_CODE_HASH);
        bytes32[] memory values = ClprEvmStateProof.verifyProvenSlots(
            RLP.readList(storageProof), storageRoot, chainStateSlots(commitHeight / BLOCKS_PER_COMMIT_INTERVAL)
        );
        if (values[0] != commitId) revert CommitMismatch();
        // Commit{blockHash; uint32 timestamp; address reserved1; uint16 reserved2}: timestamp is the low 4 bytes.
        // forge-lint: disable-next-line(unsafe-typecast)
        commitTimestamp = uint64(uint32(uint256(values[1])));
        if (values[2] != 0) revert ChainStatePaused();
        if (address(uint160(uint256(values[3]))) != CHAIN_STATE_IMPLEMENTATION) revert ImplementationMismatch();
        uint256 l1Time = uint256(L1_GENESIS_TIME) + uint256(slot) * L1_SECONDS_PER_SLOT;
        if (uint256(commitTimestamp) + TIME_TO_FINALIZE > l1Time) revert CommitNotFinal();
    }

    function _readMerkleProof(Memory.Slice item) internal pure returns (uint256 index, bytes32[] memory siblings) {
        Memory.Slice[] memory f = RLP.readList(item);
        if (f.length != 2) revert InvalidPayloadShape();
        index = RLP.readUint256(f[0]);
        Memory.Slice[] memory s = RLP.readList(f[1]);
        siblings = new bytes32[](s.length);
        for (uint256 i = 0; i < s.length; i++) {
            siblings[i] = RLP.readBytes32(s[i]);
        }
    }
}
