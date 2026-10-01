// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprQueueRecordVerifier} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/ClprQueueRecordVerifier.sol";
import {ICometBftHeaderSource} from "@hiero-ledger/clpr/verifiers/evm/runtimes3/lib/ICometBftHeaderSource.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {CometBftProofCodec as Codec} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftProofCodec.sol";
import {Ics23Lib} from "@hiero-ledger/clpr/libraries/proof/cometbft/Ics23Lib.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title InitiaMoveVerifier
/// @notice Initia → Hiero. Initia is a Cosmos SDK chain with CometBFT consensus and a MoveVM
///         (`x/move`). This verifier proves the CLPR Service's per-channel queue record, a Move
///         table entry, under a CometBFT header:
///
///         1. trust anchor (validator-set hash, height) → optional hops → header, each checked by an
///            {ICometBftHeaderSource} (the CometBFT family's `CometBftCommitAccumulator`): more than
///            2/3 of the set's voting power signed it;
///         2. header `app_hash` → `move` store root (ICS-23 Tendermint spec, the multistore proof);
///         3. store root → IAVL leaf `0x21 ‖ tableHandle ‖ 0x03 ‖ channelId` (ICS-23 IAVL spec);
///         4. leaf value → BCS `ChannelQueue` ({ClprQueueRecordVerifier}).
///
/// ## Move storage layout (initia-labs/initia `x/move/types/keys.go`)
/// The `move` KV store keeps every VM item under `VMStorePrefix = 0x21` (a `collections.Map` with
/// raw byte keys, so the full IAVL key is `0x21 ‖ vm key`):
///   resource     `address(32) ‖ 0x02 ‖ BCS(StructTag{address, module, name, type_args})`
///   table entry  `tableHandle(32) ‖ 0x03 ‖ BCS(key)`
/// The value is the BCS of the resource or entry. A Move `Table` value is `handle(32) ‖ length(u64)`.
///
/// ## The Initia CLPR Service (Move)
/// ```move
/// struct Service has key {                         // at the service address
///     channels: Table<address, ChannelQueue>,      // BCS: handle(32) ‖ length(u64)
///     endpoint_manifest_commitment: vector<u8>,    // 0 or 32 bytes; more fields may follow
/// }
/// ```
/// `verifyConfig` proves the `Service` resource and pins the table handle in the trust anchor;
/// `verifyBundle` proves the entry `channels[channelId]` (key `BCS(address) = channelId`).
///
/// ## Trust anchor (72 bytes)
/// `validatorSetHash(32) ‖ height(8, big-endian) ‖ tableHandle(32)`: the set trusted to sign every
/// header at or above `height`, and the channel table of the service.
///
/// ## Bundle proof (RLP list, 6 items; 7 with an endpoint-manifest update)
/// ```
/// [ 0: hops             list of HeaderRef: headers that move the trusted set forward
///   1: header           HeaderRef of the header whose app_hash commits to the state
///   2: multistoreProof  ICS-23 CommitmentProof (existence, Tendermint spec) of store "move"
///   3: entryProof       ICS-23 CommitmentProof (existence, IAVL spec) of the queue record
///   4: record           BCS ChannelQueue (the proven value)
///   5: bundleContent    protobuf ClprBundleContent
///  (6: manifestPreimage protobuf ClprEndpointManifest, bound to the record's commitment) ]
/// ```
/// A HeaderRef is the CometBFT family's protobuf `{1 validator_set, 2 signed_header}` (checked by
/// `checkHeader` in the same call) or `{3 header_hash}` (accumulated in earlier transactions).
/// The proofs 2 and 3 are the `ics23:simple` and `ics23:iavl` operations an Initia node returns
/// for `abci_query /store/move/key` at height H−1, whose app hash is in header H.
contract InitiaMoveVerifier is ClprQueueRecordVerifier {
    uint256 internal constant ANCHOR_LENGTH = 72;
    uint256 internal constant BASE_ANCHOR_LENGTH = 40;
    uint256 internal constant BUNDLE_FIELDS = 6;
    uint256 internal constant BUNDLE_FIELDS_WITH_MANIFEST = 7;
    uint256 internal constant CONFIG_FIELDS = 6;
    uint256 internal constant VALUE_PROOF_FIELDS = 5;

    bytes1 internal constant VM_STORE_PREFIX = 0x21;
    bytes1 internal constant RESOURCE_SEPARATOR = 0x02;
    bytes1 internal constant TABLE_ENTRY_SEPARATOR = 0x03;
    /// @dev Store key of `x/move` in the multistore.
    bytes32 internal constant MOVE_STORE_KEY_HASH = keccak256("move");
    /// @dev Module and struct of the service resource: `<service>::clpr::Service`.
    bytes internal constant SERVICE_MODULE = "clpr";
    bytes internal constant SERVICE_STRUCT = "Service";

    /// @notice Verifies CometBFT headers (deploy `CometBftCommitAccumulator` for the Initia chain id).
    ICometBftHeaderSource public immutable HEADER_SOURCE;
    /// @notice Validator-set hash trusted to sign the configuration header.
    bytes32 public immutable BOOTSTRAP_VALIDATORS_HASH;
    /// @notice Lowest height the bootstrap set is trusted at.
    uint64 public immutable BOOTSTRAP_HEIGHT;

    error InvalidProfile();
    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error InvalidHeaderRef();
    error ValidatorSetHashMismatch();
    error HeightTooOld();
    error InvalidStoreKey();
    error InvalidStoreRoot();
    error StorageKeyMismatch();
    error StorageValueMismatch();
    error InvalidServiceResource();

    constructor(ICometBftHeaderSource headerSource, bytes32 bootstrapValidatorsHash, uint64 bootstrapHeight) {
        if (address(headerSource) == address(0) || bootstrapValidatorsHash == bytes32(0)) revert InvalidProfile();
        HEADER_SOURCE = headerSource;
        BOOTSTRAP_VALIDATORS_HASH = bootstrapValidatorsHash;
        BOOTSTRAP_HEIGHT = bootstrapHeight;
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
        if (trustAnchor.length != ANCHOR_LENGTH) revert InvalidTrustAnchor();
        (bytes32 setHash, uint64 height) = _decodeBaseAnchor(trustAnchor[0:BASE_ANCHOR_LENGTH]);
        bytes32 tableHandle = bytes32(trustAnchor[BASE_ANCHOR_LENGTH:ANCHOR_LENGTH]);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        _bytes32Address(ctx.remoteServiceAddress);

        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory items = RLP.decodeList(proofMem);
        if (items.length != BUNDLE_FIELDS && items.length != BUNDLE_FIELDS_WITH_MANIFEST) {
            revert InvalidPayloadShape();
        }

        (ICometBftHeaderSource.Header memory h, bytes32 storeRoot) =
            _verifiedStoreRoot(_readHops(items[0]), RLP.readBytes(items[1]), RLP.readBytes(items[2]), setHash, height);
        bytes memory record = RLP.readBytes(items[4]);
        _proveValue(
            RLP.readBytes(items[3]), storeRoot, tableEntryKey(tableHandle, abi.encodePacked(ctx.channelId)), record
        );

        bytes32 commitment;
        (metadata, commitment) = _decodeQueueRecord(record);
        messagePayloads = _decodeBundleContent(RLP.readBytes(items[5]));
        newEndpointManifest = items.length == BUNDLE_FIELDS_WITH_MANIFEST
            ? _bindManifest(RLP.readBytes(items[6]), commitment, ctx.remoteServiceAddress)
            : _absentEndpointManifest();

        if (h.nextValidatorsHash != setHash) {
            newTrustAnchorId = abi.encodePacked(h.nextValidatorsHash, h.height + 1);
            newTrustAnchor = abi.encodePacked(newTrustAnchorId, tableHandle);
        }
    }

    /// @dev `configProofBytes` = RLP `[controlMessage, hops, header, multistoreProof, resourceProof,
    ///      resourceValue]`: the LedgerConfiguration, and the `<service>::clpr::Service` resource proven
    ///      under a header the bootstrap set reaches. `endpointManifestProofBytes` is the manifest
    ///      preimage bound to the resource's `endpoint_manifest_commitment`, or empty for bring-up.
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
        bytes memory configMem = configProofBytes;
        Memory.Slice[] memory cfg = RLP.decodeList(configMem);
        if (cfg.length != CONFIG_FIELDS) revert InvalidPayloadShape();

        ClprTypes.LedgerConfiguration memory lc = ClprProtobuf.decodeControlMessage(RLP.readBytes(cfg[0])).config;
        _requireNamespace(lc.chainId, "cosmos:");
        bytes32 service = _bytes32Address(lc.serviceAddress);

        (ICometBftHeaderSource.Header memory h, bytes32 storeRoot) = _verifiedStoreRoot(
            _readHops(cfg[1]), RLP.readBytes(cfg[2]), RLP.readBytes(cfg[3]), BOOTSTRAP_VALIDATORS_HASH, BOOTSTRAP_HEIGHT
        );
        bytes memory resource = RLP.readBytes(cfg[5]);
        _proveValue(RLP.readBytes(cfg[4]), storeRoot, resourceKey(service, SERVICE_MODULE, SERVICE_STRUCT), resource);
        (bytes32 tableHandle, bytes32 commitment) = _decodeServiceResource(resource);

        initialTrustAnchorId = abi.encodePacked(h.nextValidatorsHash, h.height + 1);
        initialTrustAnchor = abi.encodePacked(initialTrustAnchorId, tableHandle);
        serviceAddress = lc.serviceAddress;
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        chainId = lc.chainId;
        peerConfigNanos = lc.nanosSinceEpoch;
        throttles = lc.throttles;
        endpointManifest = endpointManifestProofBytes.length == 0
            ? _uninitializedEndpointManifest(serviceAddress)
            : _bindManifest(endpointManifestProofBytes, commitment, serviceAddress);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Generic entry point and key helpers
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Steps 1–3 for any `move` store key: proves `key` → value under the header the anchor
    ///         reaches. `proof` = RLP `[hops, header, multistoreProof, entryProof, value]`,
    ///         `baseAnchor` = `validatorSetHash(32) ‖ height(8)`. Returns the header and the value.
    function verifyMoveValue(bytes calldata proof, bytes calldata baseAnchor, bytes calldata key)
        external
        view
        returns (ICometBftHeaderSource.Header memory h, bytes memory value)
    {
        (bytes32 setHash, uint64 height) = _decodeBaseAnchor(baseAnchor);
        bytes memory proofMem = proof;
        Memory.Slice[] memory items = RLP.decodeList(proofMem);
        if (items.length != VALUE_PROOF_FIELDS) revert InvalidPayloadShape();
        bytes32 storeRoot;
        (h, storeRoot) =
            _verifiedStoreRoot(_readHops(items[0]), RLP.readBytes(items[1]), RLP.readBytes(items[2]), setHash, height);
        value = RLP.readBytes(items[4]);
        _proveValue(RLP.readBytes(items[3]), storeRoot, key, value);
    }

    /// @notice IAVL key of a resource without type arguments: `0x21 ‖ addr ‖ 0x02 ‖ BCS(StructTag)`.
    function resourceKey(bytes32 addr, bytes memory module, bytes memory name) public pure returns (bytes memory) {
        return abi.encodePacked(
            VM_STORE_PREFIX,
            addr,
            RESOURCE_SEPARATOR,
            addr,
            _uleb(module.length),
            module,
            _uleb(name.length),
            name,
            uint8(0)
        );
    }

    /// @notice IAVL key of a table entry: `0x21 ‖ handle ‖ 0x03 ‖ BCS(key)`.
    function tableEntryKey(bytes32 tableHandle, bytes memory bcsKey) public pure returns (bytes memory) {
        return abi.encodePacked(VM_STORE_PREFIX, tableHandle, TABLE_ENTRY_SEPARATOR, bcsKey);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Internal
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Hops, then the state header, then app_hash → `move` store root.
    function _verifiedStoreRoot(
        bytes[] memory hops,
        bytes memory header,
        bytes memory multistoreProof,
        bytes32 setHash,
        uint64 minHeight
    ) internal view returns (ICometBftHeaderSource.Header memory h, bytes32 storeRoot) {
        for (uint256 i; i < hops.length; ++i) {
            h = _resolveHeader(hops[i], setHash, minHeight);
            setHash = h.nextValidatorsHash;
            minHeight = h.height + 1;
        }
        h = _resolveHeader(header, setHash, minHeight);

        Ics23Lib.ExistenceProof memory ms = Codec.parseExistenceProof(multistoreProof);
        if (keccak256(ms.key) != MOVE_STORE_KEY_HASH) revert InvalidStoreKey();
        Ics23Lib.verifyMembershipTendermint(ms, h.appHash, ms.key, ms.value);
        if (ms.value.length != 32) revert InvalidStoreRoot();
        storeRoot = Codec.load32(ms.value, 0);
    }

    /// @dev HeaderRef{1 validator_set, 2 signed_header} (inline) or {3 header_hash} (accumulated).
    function _resolveHeader(bytes memory ref, bytes32 setHash, uint64 minHeight)
        internal
        view
        returns (ICometBftHeaderSource.Header memory h)
    {
        bytes memory valSet;
        bytes memory signedHeader;
        bytes memory headerHash;
        uint256 off;
        while (off < ref.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(ref, off);
            off = off2;
            if (wt != 2) off = PB.skipField(ref, off, wt);
            else if (fn_ == 1) (valSet, off) = PB.decodeLengthDelimited(ref, off);
            else if (fn_ == 2) (signedHeader, off) = PB.decodeLengthDelimited(ref, off);
            else if (fn_ == 3) (headerHash, off) = PB.decodeLengthDelimited(ref, off);
            else off = PB.skipField(ref, off, wt);
        }
        if (headerHash.length == 0) {
            if (valSet.length == 0 || signedHeader.length == 0) revert InvalidHeaderRef();
            (, h) = HEADER_SOURCE.checkHeader(valSet, signedHeader, setHash, minHeight);
        } else {
            if (headerHash.length != 32 || valSet.length != 0 || signedHeader.length != 0) revert InvalidHeaderRef();
            // forge-lint: disable-next-line(unsafe-typecast)
            h = HEADER_SOURCE.finalizedHeader(bytes32(headerHash));
            if (h.validatorsHash != setHash) revert ValidatorSetHashMismatch();
            if (h.height < minHeight) revert HeightTooOld();
        }
    }

    /// @dev An ICS-23 IAVL existence proof of exactly (`key`, `value`) under `storeRoot`.
    function _proveValue(bytes memory commitmentProof, bytes32 storeRoot, bytes memory key, bytes memory value)
        internal
        pure
    {
        Ics23Lib.ExistenceProof memory ep = Codec.parseExistenceProof(commitmentProof);
        if (keccak256(ep.key) != keccak256(key)) revert StorageKeyMismatch();
        if (keccak256(ep.value) != keccak256(value)) revert StorageValueMismatch();
        Ics23Lib.verifyMembershipIavl(ep, storeRoot, key, value);
    }

    /// @dev `Service` BCS: `handle(32) ‖ length(u64) ‖ uleb(len) ‖ commitment(len ∈ {0, 32}) ‖ …`.
    function _decodeServiceResource(bytes memory r) internal pure returns (bytes32 handle, bytes32 commitment) {
        if (r.length < 41) revert InvalidServiceResource();
        handle = _word(r, 0);
        if (handle == bytes32(0)) revert InvalidServiceResource();
        uint8 len = uint8(r[40]);
        if (len == 32) {
            if (r.length < 73) revert InvalidServiceResource();
            commitment = _word(r, 41);
        } else if (len != 0) {
            revert InvalidServiceResource();
        }
    }

    function _readHops(Memory.Slice item) internal pure returns (bytes[] memory hops) {
        Memory.Slice[] memory list = RLP.readList(item);
        hops = new bytes[](list.length);
        for (uint256 i; i < list.length; ++i) {
            hops[i] = RLP.readBytes(list[i]);
        }
    }

    function _decodeBaseAnchor(bytes calldata anchor) internal pure returns (bytes32 setHash, uint64 height) {
        if (anchor.length != BASE_ANCHOR_LENGTH) revert InvalidTrustAnchor();
        setHash = bytes32(anchor[0:32]);
        height = uint64(bytes8(anchor[32:40]));
        if (setHash == bytes32(0)) revert InvalidTrustAnchor();
    }

    /// @dev ULEB128 of a length below 2^14 (Move identifiers are short).
    function _uleb(uint256 n) internal pure returns (bytes memory) {
        // forge-lint: disable-next-line(unsafe-typecast)
        if (n < 0x80) return abi.encodePacked(uint8(n));
        if (n >= 0x4000) revert InvalidPayloadShape();
        // forge-lint: disable-next-line(unsafe-typecast)
        return abi.encodePacked(uint8((n & 0x7f) | 0x80), uint8(n >> 7));
    }
}
