// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {IcpBls} from "@hiero-ledger/clpr/libraries/proof/icp/IcpBls.sol";
import {IcpCertificate} from "@hiero-ledger/clpr/libraries/proof/icp/IcpCertificate.sol";
import {IcpHashTree} from "@hiero-ledger/clpr/libraries/proof/icp/IcpHashTree.sol";

/// @title IcpVerifier
/// @notice Internet Computer → Hiero CLPR verifier. The CLPR Service on ICP is a canister that keeps
///         its queue state in its own hash tree and stores that tree's root as its `certified_data`
///         (32 bytes). The subnet certifies `certified_data` with a threshold BLS signature, and the
///         root (NNS) key certifies the subnet key through a delegation.
///
/// Proof chain:
///   root key ──BLS──▶ delegation tree ─▶ /subnet/<id>/public_key, canister ranges
///   subnet key ──BLS──▶ state tree ─▶ /canister/<canister>/certified_data
///   certified_data == reconstruct(canister witness) ─▶ /clpr/queue/<channelId>, /clpr/manifest, /clpr/config
///
/// Canister witness layout (labels in the canister's own hash tree, all leaves):
///   `clpr/queue/<channelId 32 bytes>` → ChannelQueue record, 89 bytes, big-endian:
///       status u8 ‖ next_message_id u64 ‖ received_message_id u64 ‖ sent_running_hash [32] ‖
///       received_running_hash [32] ‖ endpoint_manifest_version u64
///   `clpr/manifest` → keccak256 of the endpoint-manifest protobuf (32 bytes)
///   `clpr/config`   → keccak256 of the configuration ControlMessage protobuf (32 bytes)
///
/// Trust anchor: keccak256 of the DER root key (32 bytes). It never changes: subnet key changes are
/// carried by the delegation inside every certificate, so there is no rotation transaction.
contract IcpVerifier is IClprVerifier {
    struct BundleProof {
        IcpCertificate.Certificate cert;
        bytes witness; // CBOR hash tree of the canister; its root is the certified_data
        bytes bundleContent; // ClprBundleContent protobuf
        bytes manifestPreimage; // empty = no manifest in this bundle
    }

    struct ConfigProof {
        IcpCertificate.Certificate cert;
        bytes witness;
        bytes controlMessage; // ClprMessagePayload{control{config_update}}; keccak256 == clpr/config leaf
    }

    /// @dev `endpointManifestProofBytes` of {verifyConfig}: the manifest preimage, bound to the
    ///      `clpr/manifest` leaf of the same witness as the configuration.
    struct ManifestProof {
        bytes manifestPreimage;
    }

    uint256 internal constant QUEUE_RECORD_LENGTH = 89;
    uint8 internal constant CHANNEL_STATUS_MAX = uint8(type(ClprTypes.ChannelStatus).max);
    uint256 internal constant MAX_PRINCIPAL_LENGTH = 29;

    bytes internal constant L_CLPR = "clpr";
    bytes internal constant L_QUEUE = "queue";
    bytes internal constant L_MANIFEST = "manifest";
    bytes internal constant L_CONFIG = "config";

    bytes32 public immutable CHAIN_ID_HASH;
    bytes32 public immutable ROOT_KEY_ID;
    uint64 public immutable MAX_DELEGATION_AGE_NANOS;
    string public chainId;
    bytes public rootKey; // uncompressed G2, 256 bytes

    error InvalidTrustAnchor();
    error InvalidServiceAddress();
    error CertifiedDataMismatch();
    error InvalidQueueRecord();
    error WrongChainId();
    error ConfigCommitmentMismatch();
    error ManifestCommitmentMismatch();
    error ManifestServiceAddressMismatch();
    error ManifestVersionZero();

    /// @param chainId_ CAIP-2 style chain id the peer configuration must carry.
    /// @param rootKeyDer DER root public key (133 bytes), as published for the network.
    /// @param rootKeyUncompressed The same key uncompressed (EIP-2537 G2, 256 bytes); its x-coordinate
    ///        must match `rootKeyDer`.
    /// @param maxDelegationAgeNanos Maximum age of a delegation relative to its certificate (0 = off).
    constructor(
        string memory chainId_,
        bytes memory rootKeyDer,
        bytes memory rootKeyUncompressed,
        uint64 maxDelegationAgeNanos
    ) {
        IcpBls.requireMatchesCompressedG2(rootKeyUncompressed, IcpCertificate.derToCompressed(rootKeyDer));
        IcpBls.requireOnCurveG2(rootKeyUncompressed);
        chainId = chainId_;
        CHAIN_ID_HASH = keccak256(bytes(chainId_));
        ROOT_KEY_ID = keccak256(rootKeyDer);
        MAX_DELEGATION_AGE_NANOS = maxDelegationAgeNanos;
        rootKey = rootKeyUncompressed;
    }

    // ── IClprVerifier ────────────────────────────────────────────────────────

    /// @inheritdoc IClprVerifier
    /// @dev proofBytes = abi.encode(BundleProof); trustAnchor = ROOT_KEY_ID (32 bytes).
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
        _checkAnchor(trustAnchor);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        _checkPrincipal(ctx.remoteServiceAddress);
        BundleProof memory p = abi.decode(proofBytes, (BundleProof));

        _verifyWitness(p.cert, ctx.remoteServiceAddress, p.witness);

        bytes memory record = IcpHashTree.lookup(p.witness, _path3(L_CLPR, L_QUEUE, abi.encodePacked(ctx.channelId)));
        metadata = _decodeQueueRecord(record);
        messagePayloads = _decodeBundleContent(p.bundleContent);

        if (p.manifestPreimage.length == 0) {
            newEndpointManifest.endpoints = new ClprTypes.Endpoint[](0);
        } else {
            newEndpointManifest = _bindManifest(p.witness, p.manifestPreimage, ctx.remoteServiceAddress);
        }
        // no rotation: newTrustAnchor and newTrustAnchorId stay empty
        (newTrustAnchor, newTrustAnchorId);
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes = abi.encode(ConfigProof). The canister is named by the configuration
    ///      itself; proving keccak256(controlMessage) under `clpr/config` of that canister's certified
    ///      tree proves every field of the message. `endpointManifestProofBytes` = abi.encode(ManifestProof)
    ///      or empty.
    function verifyConfig(bytes calldata configProofBytes, bytes32 channelId, bytes calldata endpointManifestProofBytes)
        external
        view
        override
        returns (
            bytes memory channelContext,
            string memory chainId_,
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
        _checkPrincipal(lc.serviceAddress);

        _verifyWitness(p.cert, lc.serviceAddress, p.witness);
        if (_leaf32(p.witness, L_CONFIG) != keccak256(p.controlMessage)) revert ConfigCommitmentMismatch();

        serviceAddress = lc.serviceAddress;
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        chainId_ = lc.chainId;
        peerConfigNanos = lc.nanosSinceEpoch;
        throttles = lc.throttles;
        initialTrustAnchor = abi.encodePacked(ROOT_KEY_ID);
        initialTrustAnchorId = abi.encodePacked(ROOT_KEY_ID);

        if (endpointManifestProofBytes.length == 0) {
            endpointManifest.serviceAddress = serviceAddress;
            endpointManifest.endpoints = new ClprTypes.Endpoint[](0);
        } else {
            ManifestProof memory mp = abi.decode(endpointManifestProofBytes, (ManifestProof));
            endpointManifest = _bindManifest(p.witness, mp.manifestPreimage, serviceAddress);
        }
    }

    // ── Generic entry points (live tests and tooling) ────────────────────────

    /// @notice Verify a data certificate of `canisterId` and a value at `path` of the canister's
    ///         witness tree (whose root must equal the certified data).
    function verifyCertifiedValue(
        IcpCertificate.Certificate calldata cert,
        bytes calldata canisterId,
        bytes calldata witness,
        bytes[] calldata path
    ) external view returns (bytes memory value, uint64 time) {
        _checkPrincipal(canisterId);
        time = _verifyWitness(cert, canisterId, witness);
        value = IcpHashTree.lookup(witness, path);
    }

    /// @notice Verify a certificate (e.g. a `read_state` response) that may certify `canisterId`, and
    ///         return the value at `path` of its state tree.
    function verifyStateValue(
        IcpCertificate.Certificate calldata cert,
        bytes calldata canisterId,
        bytes[] calldata path
    ) external view returns (bytes memory value, uint64 time) {
        _checkPrincipal(canisterId);
        (, time) = IcpCertificate.verify(cert, rootKey, canisterId, MAX_DELEGATION_AGE_NANOS);
        value = IcpHashTree.lookup(cert.tree, path);
    }

    // ── internals ────────────────────────────────────────────────────────────

    function _verifyWitness(IcpCertificate.Certificate memory cert, bytes memory canisterId, bytes memory witness)
        internal
        view
        returns (uint64 time)
    {
        (, time) = IcpCertificate.verify(cert, rootKey, canisterId, MAX_DELEGATION_AGE_NANOS);
        if (IcpCertificate.certifiedData(cert.tree, canisterId) != IcpHashTree.reconstruct(witness)) {
            revert CertifiedDataMismatch();
        }
    }

    function _checkAnchor(bytes calldata trustAnchor) internal view {
        // casting to 'bytes32' is safe because the length is checked to be 32 first.
        // forge-lint: disable-next-line(unsafe-typecast)
        if (trustAnchor.length != 32 || bytes32(trustAnchor) != ROOT_KEY_ID) revert InvalidTrustAnchor();
    }

    function _checkPrincipal(bytes memory id) internal pure {
        if (id.length == 0 || id.length > MAX_PRINCIPAL_LENGTH) revert InvalidServiceAddress();
    }

    function _leaf32(bytes memory witness, bytes memory label) internal pure returns (bytes32 v) {
        bytes[] memory path = new bytes[](2);
        path[0] = L_CLPR;
        path[1] = label;
        bytes memory leaf = IcpHashTree.lookup(witness, path);
        if (leaf.length != 32) revert IcpHashTree.MalformedTree();
        assembly ("memory-safe") {
            v := mload(add(leaf, 0x20))
        }
    }

    function _bindManifest(bytes memory witness, bytes memory preimage, bytes memory expectedServiceAddress)
        internal
        pure
        returns (ClprTypes.ClprEndpointManifest memory manifest)
    {
        if (_leaf32(witness, L_MANIFEST) != keccak256(preimage)) revert ManifestCommitmentMismatch();
        manifest = ClprProtobuf.decodeEndpointManifest(preimage);
        if (manifest.version == 0) revert ManifestVersionZero();
        if (keccak256(manifest.serviceAddress) != keccak256(expectedServiceAddress)) {
            revert ManifestServiceAddressMismatch();
        }
    }

    function _decodeQueueRecord(bytes memory r) internal pure returns (ClprTypes.QueueMetadata memory m) {
        if (r.length != QUEUE_RECORD_LENGTH || uint8(r[0]) > CHANNEL_STATUS_MAX) revert InvalidQueueRecord();
        bytes32 w1;
        bytes32 w2;
        bytes32 w3;
        assembly ("memory-safe") {
            let d := add(r, 0x20)
            w1 := mload(add(d, 1)) // next(8) ‖ received(8) ‖ sent hash[0..16)
            w2 := mload(add(d, 17)) // sent hash
            w3 := mload(add(d, 49)) // received hash
        }
        m.state = ClprTypes.ChannelStatus(uint8(r[0]));
        m.nextMessageId = uint64(uint256(w1) >> 192);
        m.receivedMessageId = uint64(uint256(w1) >> 128);
        m.sentRunningHash = w2;
        m.receivedRunningHash = w3;
        m.endpointManifestVersion = _be64(r, 81);
    }

    function _be64(bytes memory b, uint256 off) internal pure returns (uint64 v) {
        for (uint256 i = 0; i < 8; i++) {
            v = (v << 8) | uint8(b[off + i]);
        }
    }

    /// @dev `ClprBundleContent` field 2 (repeated bytes) are the message payloads; field 1 (queue
    ///      metadata) is ignored because the metadata comes from the certified record.
    function _decodeBundleContent(bytes memory data) internal pure returns (bytes[] memory messages) {
        uint256 count;
        uint256 off;
        while (off < data.length) {
            (uint64 f, uint8 wt, uint256 o) = PB.decodeFieldKey(data, off);
            if (f == 2 && wt == 2) count++;
            off = PB.skipField(data, o, wt);
        }
        messages = new bytes[](count);
        uint256 idx;
        off = 0;
        while (off < data.length) {
            (uint64 f, uint8 wt, uint256 o) = PB.decodeFieldKey(data, off);
            if (f == 2 && wt == 2) {
                (messages[idx++], off) = PB.decodeLengthDelimited(data, o);
            } else {
                off = PB.skipField(data, o, wt);
            }
        }
    }

    function _path3(bytes memory a, bytes memory b, bytes memory c) internal pure returns (bytes[] memory p) {
        p = new bytes[](3);
        p[0] = a;
        p[1] = b;
        p[2] = c;
    }
}
