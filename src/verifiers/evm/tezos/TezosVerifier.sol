// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {TezosBlake2b} from "@hiero-ledger/clpr/libraries/proof/tezos/TezosBlake2b.sol";
import {TezosContextVerifier} from "@hiero-ledger/clpr/verifiers/evm/tezos/TezosContextVerifier.sol";
import {TezosLightClient} from "@hiero-ledger/clpr/verifiers/evm/tezos/TezosLightClient.sol";
import {TezosSignatureCache} from "@hiero-ledger/clpr/verifiers/evm/tezos/TezosSignatureCache.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/// @title TezosVerifier
/// @notice Tezos L1 → Hiero CLPR verifier: Tenderbake finality ({TezosLightClient}) plus a Tezos
///         context proof of the CLPR Service's big_map entries.
///
/// Tezos CLPR Service storage profile (a Michelson contract whose whole storage is one
/// `big_map bytes bytes`, so its storage value is the constant `Int <big_map id>`):
///
/// | big_map key (Michelson `bytes`) | value (Michelson `bytes`) |
/// |---|---|
/// | `"q" ‖ channelId` (33 bytes) | ChannelQueue record, 89 bytes: status u8, next_message_id u64, received_message_id u64, sent_running_hash [32], received_running_hash [32], endpoint_manifest_version u64 |
/// | `"m"` | keccak256 of the current endpoint manifest (ClprProtobuf encoding) |
/// | `"c"` | keccak256 of the ControlMessage carrying the service's LedgerConfiguration |
///
/// A big_map entry lives at context path
/// `big_maps/index/<id>/contents/<hex BLAKE2b-256(PACK(key))>/data`, its value Micheline-encoded
/// (`0x0a ‖ u32be(len) ‖ bytes`). Message payloads travel in `ClprBundleContent` and ClprService
/// checks them against the proven sent running hash, as for every peer.
contract TezosVerifier is TezosLightClient, ClprEvmBundleVerifier {
    uint8 internal constant CHANNEL_STATUS_MAX = uint8(type(ClprTypes.ChannelStatus).max);
    uint256 internal constant QUEUE_RECORD_LENGTH = 89;

    /// @notice CAIP-2 chain id the peer's LedgerConfiguration must name (e.g. "tezos:NetXdQprcVkpaWU").
    bytes32 public immutable CHAIN_ID_HASH;
    /// @notice The CLPR Service contract (22-byte Tezos contract id: 0x01 ‖ hash ‖ 0x00).
    bytes32 internal immutable SERVICE_ADDRESS_HASH;
    bytes internal _serviceAddress;
    /// @notice big_map id holding the service's state.
    uint256 public immutable BIG_MAP_ID;
    /// @notice Deploy-time checkpoint: a trusted state level and its context tree root.
    uint32 public immutable CHECKPOINT_LEVEL;
    bytes32 public immutable CHECKPOINT_ROOT;

    struct BundleProof {
        FinalityProof finality;
        bytes queueProof; // context proof of the "q" ‖ channelId entry
        bytes bundleContent; // ClprBundleContent
        bytes manifestProof; // optional: context proof of the "m" entry
        bytes manifestPreimage;
    }

    struct ConfigProof {
        FinalityProof finality; // from the checkpoint
        bytes storageProof; // contracts/index/<service>/data/storage == Int <big_map id>
        bytes configProof; // context proof of the "c" entry
        bytes controlMessage;
    }

    struct ManifestProof {
        bytes manifestProof;
        bytes manifestPreimage;
    }

    error WrongServiceAddress();
    error WrongChainId();
    error ConfigCommitmentMismatch();
    error InvalidQueueRecord();
    error InvalidMichelsonBytes();
    error StorageMismatch();
    error ManifestNeedsConfigProof();

    constructor(
        Profile memory profile_,
        IEd25519Verifier ed25519,
        TezosSignatureCache cache,
        TezosContextVerifier context,
        string memory chainId,
        bytes memory serviceAddr,
        uint256 bigMapId,
        uint32 checkpointLevel,
        bytes32 checkpointRoot
    ) TezosLightClient(profile_, ed25519, cache, context) {
        if (serviceAddr.length != 22 || serviceAddr[0] != 0x01 || serviceAddr[21] != 0x00) {
            revert WrongServiceAddress();
        }
        CHAIN_ID_HASH = keccak256(bytes(chainId));
        SERVICE_ADDRESS_HASH = keccak256(serviceAddr);
        _serviceAddress = serviceAddr;
        BIG_MAP_ID = bigMapId;
        CHECKPOINT_LEVEL = checkpointLevel;
        CHECKPOINT_ROOT = checkpointRoot;
    }

    function serviceAddress() external view returns (bytes memory) {
        return _serviceAddress;
    }

    // ── IClprVerifier ───────────────────────────────────────────────────────

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
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        if (keccak256(ctx.remoteServiceAddress) != SERVICE_ADDRESS_HASH) revert WrongServiceAddress();
        (uint32 anchorLevel, bytes32 anchorRoot) = decodeAnchor(trustAnchor);
        BundleProof memory p = abi.decode(proofBytes, (BundleProof));

        (uint32 stateLevel, bytes32 root) = _verifyFinality(p.finality, anchorLevel, anchorRoot);

        bytes memory record =
        // casting is safe: a one-character literal.
        // forge-lint: disable-next-line(unsafe-typecast)
        _bigMapBytes(root, abi.encodePacked(bytes1("q"), ctx.channelId), p.queueProof, QUEUE_RECORD_LENGTH);
        metadata = decodeQueueRecord(record);
        messagePayloads = _decodeBundleContent(p.bundleContent);

        if (p.manifestProof.length == 0) {
            newEndpointManifest = _absentEndpointManifest();
        } else {
            bytes32 commitment = bytes32(_bigMapBytes(root, "m", p.manifestProof, 32));
            newEndpointManifest = _bindManifest(p.manifestPreimage, commitment, ctx.remoteServiceAddress);
        }
        // Rotate when the finalized state is in a later cycle than the anchor: Tezos's attestation
        // rights change per cycle and a state fixes them only `consensus_rights_delay` cycles ahead.
        // Within the anchor's cycle the anchor is kept (the CLPR Service treats a new anchor as progress).
        if (_cycleOf(stateLevel) > _cycleOf(anchorLevel)) {
            newTrustAnchor = encodeAnchor(stateLevel, root);
            newTrustAnchorId = abi.encodePacked(stateLevel);
        }
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes = abi.encode(ConfigProof): a finality proof from the deploy-time checkpoint,
    ///      a proof that the pinned service contract's storage is `Int <BIG_MAP_ID>`, and a proof of the
    ///      "c" entry, whose value is keccak256 of `controlMessage`. A non-empty
    ///      `endpointManifestProofBytes` = abi.encode(ManifestProof) under the same root.
    function verifyConfig(bytes calldata configProofBytes, bytes32 channelId, bytes calldata endpointManifestProofBytes)
        external
        view
        override
        returns (
            bytes memory channelContext,
            string memory chainId,
            bytes memory serviceAddress_,
            uint96 peerConfigNanos,
            ClprTypes.Throttles memory throttles,
            bytes memory initialTrustAnchor,
            bytes memory initialTrustAnchorId,
            ClprTypes.ClprEndpointManifest memory endpointManifest
        )
    {
        ConfigProof memory p = abi.decode(configProofBytes, (ConfigProof));
        (uint32 stateLevel, bytes32 root) = _verifyFinality(p.finality, CHECKPOINT_LEVEL, CHECKPOINT_ROOT);

        // The pinned contract really owns BIG_MAP_ID.
        bytes memory storageValue = _contextValue(root, _storagePath(), p.storageProof);
        if (keccak256(storageValue) != keccak256(abi.encodePacked(bytes1(0x00), _zarith(BIG_MAP_ID)))) {
            revert StorageMismatch();
        }

        bytes32 commitment = bytes32(_bigMapBytes(root, "c", p.configProof, 32));
        if (keccak256(p.controlMessage) != commitment) revert ConfigCommitmentMismatch();
        ClprTypes.LedgerConfiguration memory lc = ClprProtobuf.decodeControlMessage(p.controlMessage).config;
        if (keccak256(bytes(lc.chainId)) != CHAIN_ID_HASH) revert WrongChainId();
        if (keccak256(lc.serviceAddress) != SERVICE_ADDRESS_HASH) revert WrongServiceAddress();

        serviceAddress_ = lc.serviceAddress;
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress_})
        );
        chainId = lc.chainId;
        peerConfigNanos = lc.nanosSinceEpoch;
        throttles = lc.throttles;
        initialTrustAnchor = encodeAnchor(stateLevel, root);
        initialTrustAnchorId = abi.encodePacked(stateLevel);

        if (endpointManifestProofBytes.length == 0) {
            endpointManifest = _uninitializedEndpointManifest(serviceAddress_);
        } else {
            ManifestProof memory mp = abi.decode(endpointManifestProofBytes, (ManifestProof));
            bytes32 mc = bytes32(_bigMapBytes(root, "m", mp.manifestProof, 32));
            endpointManifest = _bindManifest(mp.manifestPreimage, mc, serviceAddress_);
        }
    }

    // ── generic entry points (live data without a CLPR Service) ─────────────

    /// @notice Verify finality from `trustAnchor` and return the value at `steps` of the final state
    ///         (context path relative to the root, e.g. ["data", "big_maps", …]), plus the new anchor.
    function verifyContextValue(
        FinalityProof calldata finality,
        bytes calldata trustAnchor,
        bytes[] calldata steps,
        bytes calldata valueProof
    ) external view returns (bytes memory value, bytes memory newTrustAnchor) {
        (uint32 anchorLevel, bytes32 anchorRoot) = decodeAnchor(trustAnchor);
        (uint32 stateLevel, bytes32 root) = _verifyFinality(finality, anchorLevel, anchorRoot);
        value = _contextValue(root, steps, valueProof);
        newTrustAnchor = encodeAnchor(stateLevel, root);
    }

    /// @notice Context path of big_map `bigMapId`'s entry for the Michelson `bytes` key `key`.
    function bigMapPath(uint256 bigMapId, bytes memory key) public view returns (bytes[] memory steps) {
        steps = new bytes[](7);
        steps[0] = "data";
        steps[1] = "big_maps";
        steps[2] = "index";
        steps[3] = bytes(Strings.toString(bigMapId));
        steps[4] = "contents";
        steps[5] = _hex(keyHash(key));
        steps[6] = "data";
    }

    /// @notice Tezos `script_expr_hash` of a Michelson `bytes` key: BLAKE2b-256(PACK(key)).
    function keyHash(bytes memory key) public view returns (bytes32) {
        return TezosBlake2b.hash256(abi.encodePacked(bytes2(0x050a), uint32(key.length), key));
    }

    /// @notice Decode the 89-byte ChannelQueue record.
    function decodeQueueRecord(bytes memory r) public pure returns (ClprTypes.QueueMetadata memory metadata) {
        if (r.length != QUEUE_RECORD_LENGTH) revert InvalidQueueRecord();
        uint8 status = uint8(r[0]);
        if (status > CHANNEL_STATUS_MAX) revert InvalidQueueRecord();
        bytes32 w0;
        bytes32 sent;
        bytes32 received;
        bytes32 w3;
        assembly ("memory-safe") {
            let b := add(r, 0x20)
            w0 := mload(add(b, 1)) // next(8) ‖ received id(8) ‖ …
            sent := mload(add(b, 17))
            received := mload(add(b, 49))
            w3 := mload(add(b, 81))
        }
        metadata = ClprTypes.QueueMetadata({
            nextMessageId: uint64(uint256(w0) >> 192),
            sentRunningHash: sent,
            receivedMessageId: uint64(uint256(w0) >> 128),
            receivedRunningHash: received,
            state: ClprTypes.ChannelStatus(status),
            endpointManifestVersion: uint64(uint256(w3) >> 192)
        });
    }

    // ── internals ──────────────────────────────────────────────────────────

    /// @dev Prove the big_map entry for `key` and unwrap its Michelson `bytes` value (`0x0a ‖ u32 ‖ b`).
    function _bigMapBytes(bytes32 root, bytes memory key, bytes memory proof, uint256 expectedLength)
        private
        view
        returns (bytes memory out)
    {
        bytes memory v = _contextValue(root, bigMapPath(BIG_MAP_ID, key), proof);
        if (v.length != 5 + expectedLength || v[0] != 0x0a) revert InvalidMichelsonBytes();
        uint256 len;
        assembly ("memory-safe") {
            len := shr(224, mload(add(v, 0x21)))
        }
        if (len != expectedLength) revert InvalidMichelsonBytes();
        out = new bytes(len);
        assembly ("memory-safe") {
            mcopy(add(out, 0x20), add(v, 0x25), len)
        }
    }

    function _bindManifest(bytes memory preimage, bytes32 commitment, bytes memory expectedServiceAddress)
        private
        pure
        returns (ClprTypes.ClprEndpointManifest memory manifest)
    {
        if (keccak256(preimage) != commitment) revert ManifestCommitmentMismatch();
        manifest = ClprProtobuf.decodeEndpointManifest(preimage);
        if (manifest.version == 0) revert ManifestVersionZero();
        if (keccak256(manifest.serviceAddress) != keccak256(expectedServiceAddress)) {
            revert ManifestServiceAddressMismatch();
        }
    }

    function _storagePath() private view returns (bytes[] memory steps) {
        steps = new bytes[](6);
        steps[0] = "data";
        steps[1] = "contracts";
        steps[2] = "index";
        steps[3] = _hexBytes(_serviceAddress);
        steps[4] = "data";
        steps[5] = "storage";
    }

    /// @dev `Data_encoding.z` of a non-negative integer (Micheline `Int`).
    function _zarith(uint256 v) private pure returns (bytes memory out) {
        out = new bytes(40);
        uint256 n = 0;
        uint256 b = v & 0x3f;
        v >>= 6;
        out[n++] = bytes1(uint8(v > 0 ? b | 0x80 : b));
        while (v > 0) {
            b = v & 0x7f;
            v >>= 7;
            out[n++] = bytes1(uint8(v > 0 ? b | 0x80 : b));
        }
        assembly ("memory-safe") {
            mstore(out, n)
        }
    }

    function _hex(bytes32 h) private pure returns (bytes memory) {
        return _hexBytes(abi.encodePacked(h));
    }

    function _hexBytes(bytes memory b) private pure returns (bytes memory out) {
        bytes16 digits = "0123456789abcdef";
        out = new bytes(b.length * 2);
        for (uint256 i = 0; i < b.length; i++) {
            out[2 * i] = digits[uint8(b[i]) >> 4];
            out[2 * i + 1] = digits[uint8(b[i]) & 0x0f];
        }
    }
}
