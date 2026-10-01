// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {IEthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/lib/IEthL1StateVerifier.sol";
import {IStarknetStateProver} from "@hiero-ledger/clpr/verifiers/evm/starknet/lib/IStarknetStateProver.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {EthBeaconLightClient} from "@hiero-ledger/clpr/libraries/proof/beacon/EthBeaconLightClient.sol";
import {StarknetCoreProof} from "@hiero-ledger/clpr/libraries/proof/starknet/StarknetCoreProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title StarknetVerifier
/// @notice CLPR verifier for Starknet (and Starknet-OS chains that settle the same way on Ethereum).
///         A bundle is trusted through:
///
///         1. Ethereum sync committee → L1 execution `state_root`               ({IEthL1StateVerifier})
///         2. L1 `state_root` → Starknet core contract → `globalRoot`, `blockNumber`; the core contract
///            only stores a root after the STARK (SHARP) verifier accepted the state transition
///                                                                               ({StarknetCoreProof})
///         3. `globalRoot` → contract trie → ClprService leaf (class hash pinned) → storage trie →
///            the channel's queue felts                                         ({IStarknetStateProver})
///
///         No Starknet sequencer, proposer or relayer is trusted. The latency is Starknet's L1 cadence
///         (Sepolia: a state update every ~30 min covering 1,000 blocks).
///
/// ## Trust anchor
/// The 260-byte Ethereum anchor of {EthBeaconLightClient}; its `codeHash` field pins the Cairo
/// ClprService's CLASS HASH (zero disables the pin). It rotates with the L1 sync committee.
///
/// ## Bundle proof (top-level RLP list, 5 items; 6 with an endpoint-manifest update)
/// ```
/// [ 0: lightClientProof   RLP string wrapping the {IEthL1StateVerifier.verifyL1State} proof
///   1: coreProof          see {StarknetCoreProof}
///   2: starknetProof      {IStarknetStateProver.verifyStorage} proof over the derived keys
///   3: lastMessageId      empty, or nextMessageId − 1 (adds that message's running-hash keys)
///   4: bundleContent      protobuf ClprBundleContent
///  (5: manifestPreimage   adds the manifest-commitment keys) ]
/// ```
/// The Starknet storage keys are derived here from `channelId` and the layout, in this order:
/// 8 channel keys, then the 2 message keys (when item 3 is set), then the 2 manifest keys.
///
/// @dev Where the Cairo ClprService keeps its queue state is constructor data ({Layout}): Cairo `Map`
///      bases (sn_keccak of the storage variable) and `Store`-struct member offsets, so a Cairo port
///      with different names needs a new deployment, not new code. Layout v0 is in the README.
contract StarknetVerifier is ClprEvmBundleVerifier {
    /// @notice Where a Cairo ClprService keeps the queue state. Map entries are
    ///         `pedersen-chain(base, key felts) mod (2²⁵¹ − 256)`; a u256 member takes two consecutive
    ///         felts (low, high) starting at its offset.
    struct Layout {
        /// `Map<u256 channelId, ChannelQueue>` base address.
        uint256 channelsBase;
        uint256 statusOffset;
        uint256 nextMessageIdOffset;
        uint256 receivedMessageIdOffset;
        uint256 sentRunningHashOffset;
        uint256 receivedRunningHashOffset;
        uint256 endpointManifestVersionOffset;
        /// `Map<(u256 channelId, u64 messageId), MessageValue>` base address.
        uint256 messagesBase;
        uint256 messageRunningHashOffset;
        /// Address of the u256 endpoint-manifest commitment (keccak256 of the manifest protobuf).
        uint256 manifestCommitmentAddress;
    }

    /// @notice Where Starknet settles on L1, and what of it is pinned.
    struct Profile {
        /// The Starknet core contract (StarkWare proxy) on Ethereum.
        address core;
        /// Pinned code hash of the core contract's implementation; zero = not pinned.
        bytes32 coreImplCodeHash;
        /// Core-contract slots pinned to fixed values (e.g. programHash, aggregatorProgramHash).
        bytes32[] pinnedSlots;
        bytes32[] pinnedValues;
    }

    uint256 internal constant ADDR_BOUND = (1 << 251) - 256;
    uint256 internal constant FELT_LIMIT = 1 << 251;
    uint256 internal constant CHANNEL_KEYS = 8;

    uint256 internal constant PAYLOAD_FIELDS = 5;
    uint256 internal constant PAYLOAD_FIELDS_WITH_MANIFEST = 6;
    uint256 internal constant IDX_LIGHT_CLIENT_PROOF = 0;
    uint256 internal constant IDX_CORE_PROOF = 1;
    uint256 internal constant IDX_STARKNET_PROOF = 2;
    uint256 internal constant IDX_LAST_MESSAGE_ID = 3;
    uint256 internal constant IDX_BUNDLE_CONTENT = 4;
    uint256 internal constant IDX_MANIFEST_PREIMAGE = 5;
    /// Config-time manifest proof: [lightClientProof, coreProof, starknetProof, manifestPreimage].
    uint256 internal constant CONFIG_MANIFEST_FIELDS = 4;
    uint256 internal constant CM_IDX_MANIFEST_PREIMAGE = 3;

    IEthL1StateVerifier public immutable L1_STATE_VERIFIER;
    IStarknetStateProver public immutable STATE_PROVER;
    address public immutable CORE_CONTRACT;
    bytes32 public immutable CORE_IMPL_CODE_HASH;

    uint256 internal immutable CHANNELS_BASE;
    uint256 internal immutable STATUS_OFFSET;
    uint256 internal immutable NEXT_MESSAGE_ID_OFFSET;
    uint256 internal immutable RECEIVED_MESSAGE_ID_OFFSET;
    uint256 internal immutable SENT_RUNNING_HASH_OFFSET;
    uint256 internal immutable RECEIVED_RUNNING_HASH_OFFSET;
    uint256 internal immutable MANIFEST_VERSION_OFFSET;
    uint256 internal immutable MESSAGES_BASE;
    uint256 internal immutable MESSAGE_RUNNING_HASH_OFFSET;
    uint256 internal immutable MANIFEST_COMMITMENT_ADDRESS;

    bytes32[] internal _pinnedSlots;
    bytes32[] internal _pinnedValues;

    error InvalidPayloadShape();
    error InvalidConfigPayload();
    error InvalidTrustAnchor();
    error InvalidDeployment();
    error InvalidStarknetAddress();
    error ClassHashMismatch(uint256 classHash);
    error FeltOutOfRange(uint256 index, uint256 value);
    error LastMessageIdMismatch(uint256 claimed, uint256 nextMessageId);

    constructor(
        IEthL1StateVerifier l1StateVerifier,
        IStarknetStateProver stateProver,
        Profile memory profile_,
        Layout memory layout_
    ) {
        if (
            address(l1StateVerifier) == address(0) || address(stateProver) == address(0) || profile_.core == address(0)
                || profile_.pinnedSlots.length != profile_.pinnedValues.length || layout_.channelsBase >= ADDR_BOUND
                || layout_.messagesBase >= ADDR_BOUND || layout_.manifestCommitmentAddress >= FELT_LIMIT - 1
                || !_offsetsFit(layout_)
        ) revert InvalidDeployment();
        L1_STATE_VERIFIER = l1StateVerifier;
        STATE_PROVER = stateProver;
        CORE_CONTRACT = profile_.core;
        CORE_IMPL_CODE_HASH = profile_.coreImplCodeHash;
        _pinnedSlots = profile_.pinnedSlots;
        _pinnedValues = profile_.pinnedValues;
        CHANNELS_BASE = layout_.channelsBase;
        STATUS_OFFSET = layout_.statusOffset;
        NEXT_MESSAGE_ID_OFFSET = layout_.nextMessageIdOffset;
        RECEIVED_MESSAGE_ID_OFFSET = layout_.receivedMessageIdOffset;
        SENT_RUNNING_HASH_OFFSET = layout_.sentRunningHashOffset;
        RECEIVED_RUNNING_HASH_OFFSET = layout_.receivedRunningHashOffset;
        MANIFEST_VERSION_OFFSET = layout_.endpointManifestVersionOffset;
        MESSAGES_BASE = layout_.messagesBase;
        MESSAGE_RUNNING_HASH_OFFSET = layout_.messageRunningHashOffset;
        MANIFEST_COMMITMENT_ADDRESS = layout_.manifestCommitmentAddress;
    }

    /// @notice The deployment's L1 profile.
    function profile() external view returns (Profile memory p) {
        p.core = CORE_CONTRACT;
        p.coreImplCodeHash = CORE_IMPL_CODE_HASH;
        p.pinnedSlots = _pinnedSlots;
        p.pinnedValues = _pinnedValues;
    }

    /// @notice The deployment's ClprService storage layout.
    function layout() external view returns (Layout memory) {
        return Layout({
            channelsBase: CHANNELS_BASE,
            statusOffset: STATUS_OFFSET,
            nextMessageIdOffset: NEXT_MESSAGE_ID_OFFSET,
            receivedMessageIdOffset: RECEIVED_MESSAGE_ID_OFFSET,
            sentRunningHashOffset: SENT_RUNNING_HASH_OFFSET,
            receivedRunningHashOffset: RECEIVED_RUNNING_HASH_OFFSET,
            endpointManifestVersionOffset: MANIFEST_VERSION_OFFSET,
            messagesBase: MESSAGES_BASE,
            messageRunningHashOffset: MESSAGE_RUNNING_HASH_OFFSET,
            manifestCommitmentAddress: MANIFEST_COMMITMENT_ADDRESS
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
        bool withManifest = payload.length == PAYLOAD_FIELDS_WITH_MANIFEST;

        // Steps 1–2: L1 light client → core contract → Starknet global root.
        StarknetCoreProof.CoreState memory core;
        (core, newTrustAnchor, newTrustAnchorId) = _verifyCore(payload, trustAnchor);

        // Step 3: the channel's keys, bound to channelId by derivation, proven under the global root.
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        bytes memory lastIdItem = RLP.readBytes(payload[IDX_LAST_MESSAGE_ID]);
        bool withMessage = lastIdItem.length != 0;
        uint256 lastMessageId = withMessage ? RLP.readUint256(payload[IDX_LAST_MESSAGE_ID]) : 0;
        uint256[] memory keys = _keys(ctx.channelId, withMessage, lastMessageId, withManifest);
        uint256[] memory values = _verifyServiceStorage(
            payload[IDX_STARKNET_PROOF], core.globalRoot, ctx.remoteServiceAddress, trustAnchor, keys
        );

        metadata = _buildStarknetQueueMetadata(values);
        if (withMessage && (metadata.nextMessageId == 0 || lastMessageId != metadata.nextMessageId - 1)) {
            revert LastMessageIdMismatch(lastMessageId, metadata.nextMessageId);
        }
        messagePayloads = _decodeBundleContent(RLP.readBytes(payload[IDX_BUNDLE_CONTENT]));

        if (withManifest) {
            uint256 at = keys.length - 2;
            newEndpointManifest = _verifyStarknetManifest(
                values[at], values[at + 1], RLP.readBytes(payload[IDX_MANIFEST_PREIMAGE]), ctx.remoteServiceAddress
            );
        } else {
            newEndpointManifest = _absentEndpointManifest();
        }
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes is {EthMainnetVerifier}'s config RLP
    ///      `[slot, syncCommittee, gvr, forkVersion, ledgerConfiguration, codeHash]`, `codeHash` being the
    ///      Cairo ClprService's class hash.
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
        _toFelt(serviceAddress); // a Starknet contract address: 32 bytes, < 2^251
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        chainId = lc.chainId;
        peerConfigNanos = lc.nanosSinceEpoch;
        throttles = lc.throttles;
        if (endpointManifestProofBytes.length == 0) {
            endpointManifest = _uninitializedEndpointManifest(serviceAddress);
        } else {
            endpointManifest = _verifyConfigManifest(endpointManifestProofBytes, initialTrustAnchor, serviceAddress);
        }
    }

    /// @notice Steps 1–2 only: the Starknet state the core contract holds under `trustAnchor`. For
    ///         relayers and monitoring (which Starknet block's proof to fetch).
    /// @param proof RLP list whose items 0–1 are `[lightClientProof, coreProof]`.
    function verifyStarknetState(bytes calldata proof, bytes calldata trustAnchor)
        external
        view
        returns (uint256 globalRoot, uint256 blockNumber, bytes memory newTrustAnchor, bytes memory newTrustAnchorId)
    {
        if (trustAnchor.length != EthBeaconLightClient.TRUST_ANCHOR_LENGTH) revert InvalidTrustAnchor();
        bytes memory proofMem = proof;
        Memory.Slice[] memory items = RLP.decodeList(proofMem);
        if (items.length <= IDX_CORE_PROOF) revert InvalidPayloadShape();
        StarknetCoreProof.CoreState memory core;
        (core, newTrustAnchor, newTrustAnchorId) = _verifyCore(items, trustAnchor);
        return (core.globalRoot, core.blockNumber, newTrustAnchor, newTrustAnchorId);
    }

    // ── internals ────────────────────────────────────────────────────────────

    function _verifyCore(Memory.Slice[] memory items, bytes memory trustAnchor)
        internal
        view
        returns (StarknetCoreProof.CoreState memory core, bytes memory newTrustAnchor, bytes memory newTrustAnchorId)
    {
        bytes32 l1StateRoot;
        (l1StateRoot,, newTrustAnchor, newTrustAnchorId) =
            L1_STATE_VERIFIER.verifyL1State(RLP.readBytes(items[IDX_LIGHT_CLIENT_PROOF]), trustAnchor);
        core = StarknetCoreProof.verify(
            items[IDX_CORE_PROOF], l1StateRoot, CORE_CONTRACT, CORE_IMPL_CODE_HASH, _pinnedSlots, _pinnedValues
        );
    }

    /// @dev Prove `keys` of the ClprService at `serviceAddress`, enforcing the class-hash pin in the anchor.
    function _verifyServiceStorage(
        Memory.Slice starknetProofItem,
        uint256 globalRoot,
        bytes memory serviceAddress,
        bytes memory trustAnchor,
        uint256[] memory keys
    ) internal view returns (uint256[] memory values) {
        uint256 classHash;
        (classHash,, values) =
            STATE_PROVER.verifyStorage(globalRoot, _toFelt(serviceAddress), keys, RLP.readBytes(starknetProofItem));
        bytes32 pinned;
        uint256 off = 0x20 + EthBeaconLightClient.ANCHOR_OFF_CODE_HASH;
        assembly ("memory-safe") {
            pinned := mload(add(trustAnchor, off))
        }
        if (pinned != bytes32(0) && bytes32(classHash) != pinned) revert ClassHashMismatch(classHash);
    }

    /// @dev Channel keys (8), then the last message's running-hash keys (2), then the manifest
    ///      commitment keys (2) — the order {_buildStarknetQueueMetadata} and the manifest path read.
    function _keys(bytes32 channelId, bool withMessage, uint256 lastMessageId, bool withManifest)
        internal
        view
        returns (uint256[] memory keys)
    {
        keys = new uint256[](CHANNEL_KEYS + (withMessage ? 2 : 0) + (withManifest ? 2 : 0));
        uint256[] memory felts = new uint256[](withMessage ? 3 : 2);
        felts[0] = uint256(channelId) & type(uint128).max;
        felts[1] = uint256(channelId) >> 128;
        uint256 b = STATE_PROVER.mapAddress(CHANNELS_BASE, _prefix(felts, 2));
        keys[0] = b + STATUS_OFFSET;
        keys[1] = b + NEXT_MESSAGE_ID_OFFSET;
        keys[2] = b + RECEIVED_MESSAGE_ID_OFFSET;
        keys[3] = b + SENT_RUNNING_HASH_OFFSET;
        keys[4] = b + SENT_RUNNING_HASH_OFFSET + 1;
        keys[5] = b + RECEIVED_RUNNING_HASH_OFFSET;
        keys[6] = b + RECEIVED_RUNNING_HASH_OFFSET + 1;
        keys[7] = b + MANIFEST_VERSION_OFFSET;
        uint256 k = CHANNEL_KEYS;
        if (withMessage) {
            if (lastMessageId > type(uint64).max) revert FeltOutOfRange(k, lastMessageId);
            felts[2] = lastMessageId;
            uint256 m = STATE_PROVER.mapAddress(MESSAGES_BASE, felts) + MESSAGE_RUNNING_HASH_OFFSET;
            keys[k++] = m;
            keys[k++] = m + 1;
        }
        if (withManifest) {
            keys[k++] = MANIFEST_COMMITMENT_ADDRESS;
            keys[k] = MANIFEST_COMMITMENT_ADDRESS + 1;
        }
    }

    /// @dev Decode the 8 channel felts; each must fit its Cairo type (u8 / u64 / u128 halves).
    function _buildStarknetQueueMetadata(uint256[] memory v) internal pure returns (ClprTypes.QueueMetadata memory m) {
        if (v[0] > uint8(type(ClprTypes.ChannelStatus).max)) revert FeltOutOfRange(0, v[0]);
        _requireBits(v, 1, 64);
        _requireBits(v, 2, 64);
        _requireBits(v, 3, 128);
        _requireBits(v, 4, 128);
        _requireBits(v, 5, 128);
        _requireBits(v, 6, 128);
        _requireBits(v, 7, 64);
        // forge-lint: disable-start(unsafe-typecast)
        m.state = ClprTypes.ChannelStatus(uint8(v[0]));
        m.nextMessageId = uint64(v[1]);
        m.receivedMessageId = uint64(v[2]);
        m.sentRunningHash = bytes32((v[4] << 128) | v[3]);
        m.receivedRunningHash = bytes32((v[6] << 128) | v[5]);
        m.endpointManifestVersion = uint64(v[7]);
        // forge-lint: disable-end(unsafe-typecast)
    }

    function _verifyStarknetManifest(uint256 low, uint256 high, bytes memory preimage, bytes memory expectedService)
        internal
        pure
        returns (ClprTypes.ClprEndpointManifest memory manifest)
    {
        if (low >> 128 != 0 || high >> 128 != 0) revert FeltOutOfRange(0, low >> 128 != 0 ? low : high);
        if (keccak256(preimage) != bytes32((high << 128) | low)) revert ManifestCommitmentMismatch();
        manifest = ClprProtobuf.decodeEndpointManifest(preimage);
        if (manifest.version == 0) revert ManifestVersionZero();
        if (expectedService.length > 0 && keccak256(manifest.serviceAddress) != keccak256(expectedService)) {
            revert ManifestServiceAddressMismatch();
        }
    }

    /// @dev Config-time manifest proof, verified end to end under the genesis anchor.
    function _verifyConfigManifest(bytes calldata proofBytes, bytes memory genesisAnchor, bytes memory serviceAddress)
        internal
        view
        returns (ClprTypes.ClprEndpointManifest memory)
    {
        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory p = RLP.decodeList(proofMem);
        if (p.length != CONFIG_MANIFEST_FIELDS) revert InvalidConfigPayload();
        (StarknetCoreProof.CoreState memory core,,) = _verifyCore(p, genesisAnchor);
        uint256[] memory keys = new uint256[](2);
        keys[0] = MANIFEST_COMMITMENT_ADDRESS;
        keys[1] = MANIFEST_COMMITMENT_ADDRESS + 1;
        uint256[] memory values =
            _verifyServiceStorage(p[IDX_STARKNET_PROOF], core.globalRoot, serviceAddress, genesisAnchor, keys);
        return _verifyStarknetManifest(values[0], values[1], RLP.readBytes(p[CM_IDX_MANIFEST_PREIMAGE]), serviceAddress);
    }

    /// @dev Cairo member offsets are u8 (`storage_address_from_base_and_offset`); u256 members use two.
    function _offsetsFit(Layout memory l) private pure returns (bool) {
        return l.statusOffset < 256 && l.nextMessageIdOffset < 256 && l.receivedMessageIdOffset < 256
            && l.sentRunningHashOffset < 255 && l.receivedRunningHashOffset < 255
            && l.endpointManifestVersionOffset < 256 && l.messageRunningHashOffset < 255;
    }

    function _requireBits(uint256[] memory v, uint256 i, uint256 bits) private pure {
        if (v[i] >> bits != 0) revert FeltOutOfRange(i, v[i]);
    }

    function _prefix(uint256[] memory a, uint256 n) private pure returns (uint256[] memory out) {
        out = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            out[i] = a[i];
        }
    }

    /// @dev A Starknet contract address from the opaque service-address bytes: 32 bytes, < 2^251.
    function _toFelt(bytes memory b) internal pure returns (uint256 felt) {
        if (b.length != 32) revert InvalidStarknetAddress();
        // forge-lint: disable-next-line(unsafe-typecast)
        felt = uint256(bytes32(b));
        if (felt >= FELT_LIMIT) revert InvalidStarknetAddress();
    }
}
