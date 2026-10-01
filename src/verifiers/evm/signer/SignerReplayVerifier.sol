// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprSignerReplay} from "@hiero-ledger/clpr/libraries/proof/signer/ClprSignerReplay.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/// @title SignerReplayVerifier
/// @notice CLPR verifier for PoA / PoSA chains with one ECDSA seal per block and no finality
///         gadget (Clique, Congress, Bitkub PoS). It replays a hash-linked run of real headers and
///         accepts the oldest header's state root once a strict majority of the trusted signer set
///         has sealed headers in that run. The signer set comes from boundary blocks (checkpoints,
///         epoch blocks, span-commit blocks) seen inside a verified run.
///
/// ## Trust anchor (flat packed, 74 bytes)
/// ```
///   [0..32)   codeHash   pinned ClprService runtime code hash
///   [32..64)  setHash    keccak256(packed ascending signer addresses)
///   [64..72)  setBlock   boundary block that published the set (0 for a genesis bootstrap)
///   [72..74)  setSize    number of signers
/// ```
///
/// ## Bundle proof (RLP list, 5 items; 7 with an endpoint-manifest update)
/// ```
/// [ 0: signers       anchor set, n × address20 ascending; keccak256 must equal setHash
///   1: headers       [h_0, …, h_m], each the parent of the next; h_0 carries the proven state root
///   2: accountProof  MPT account proof for the ClprService at h_0.stateRoot
///   3: storageProof  5 or 6 × [slot, proofNodes] for the channelId-derived slots
///   4: bundleContent protobuf ClprBundleContent
///   5: manifestStorageProof, 6: manifestPreimage (optional) ]
/// ```
///
/// ## Acceptance rule
/// Let j be the index of the newest boundary block in the run (0 if none). The run is accepted when
/// the headers h_j … h_m carry seals from at least ⌊n/2⌋ + 1 distinct members of the anchor set.
/// Every header in the run descends from h_0 and from h_j, so both are covered by those seals.
/// Headers sealed by addresses outside the anchor set are allowed (they may be newly added signers)
/// but do not count. A boundary block newer than `setBlock` rotates the anchor to its signer list.
contract SignerReplayVerifier is ClprEvmBundleVerifier {
    // ── Bundle layout ─────────────────────────────────────────────────────────
    uint256 internal constant PAYLOAD_FIELDS = 5;
    uint256 internal constant PAYLOAD_FIELDS_WITH_MANIFEST = 7;
    uint256 internal constant IDX_SIGNERS = 0;
    uint256 internal constant IDX_HEADERS = 1;
    uint256 internal constant IDX_ACCOUNT_PROOF = 2;
    uint256 internal constant IDX_STORAGE_PROOF = 3;
    uint256 internal constant IDX_BUNDLE_CONTENT = 4;
    uint256 internal constant IDX_MANIFEST_STORAGE_PROOF = 5;
    uint256 internal constant IDX_MANIFEST_PREIMAGE = 6;
    /// @dev Upper bound on headers per run (calldata bound well before gas).
    uint256 internal constant MAX_HEADERS = 256;

    // ── Trust anchor layout ───────────────────────────────────────────────────
    uint256 internal constant TRUST_ANCHOR_LENGTH = 74;

    // ── Config payload: [ledgerConfiguration, headers, codeHash]; headers[0] is a boundary block ──
    uint256 internal constant CONFIG_FIELDS = 3;
    /// @dev Config-time manifest proof: [signers, headers, accountProof, manifestStorageProof, manifestPreimage].
    uint256 internal constant CONFIG_MANIFEST_PROOF_FIELDS = 5;

    /// @notice Deployment profile. One deployment serves one chain.
    struct Profile {
        uint64 chainId; // EIP-155 chain id; the peer's CAIP-2 id must be eip155:<chainId>
        uint64 epochLength; // boundary period in blocks (Clique epoch, Congress epoch, Bitkub span)
        uint64 boundaryOffset; // block n is a boundary iff (n + boundaryOffset) % epochLength == 0
        uint64 maxAnchorAge; // h_0 must be ≤ setBlock + maxAnchorAge (0 = no limit)
        uint8 sealFields; // leading header fields covered by the seal (0 = all)
        uint8 entrySize; // bytes per signer-list entry (address first)
        uint8 trailerSize; // bytes after the list, before the seal
        uint8 trailerSignerOffset; // trailer offset of an extra signer, or 255 for none
    }

    uint64 public immutable CHAIN_ID;
    uint64 public immutable EPOCH_LENGTH;
    uint64 public immutable BOUNDARY_OFFSET;
    uint64 public immutable MAX_ANCHOR_AGE;
    uint8 public immutable SEAL_FIELDS;
    uint8 public immutable ENTRY_SIZE;
    uint8 public immutable TRAILER_SIZE;
    uint8 public immutable TRAILER_SIGNER_OFFSET;

    error InvalidProfile();
    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error InvalidConfigPayload();
    error ChainIdMismatch();
    error SignerSetMismatch();
    error NotBoundaryBlock(uint64 number);
    error HeaderBeforeAnchor(uint64 number, uint64 setBlock);
    error AnchorTooOld(uint64 number, uint64 setBlock);
    error InsufficientSigners(uint256 distinct, uint256 required);

    struct Anchor {
        bytes32 codeHash;
        bytes32 setHash;
        uint64 setBlock;
        uint16 setSize;
    }

    constructor(Profile memory p) {
        if (
            p.chainId == 0 || p.epochLength == 0 || p.boundaryOffset >= p.epochLength || p.entrySize < 20
                || (p.sealFields != 0 && p.sealFields < ClprSignerReplay.MIN_HEADER_FIELDS)
                || (p.trailerSignerOffset != ClprSignerReplay.NO_TRAILER_SIGNER
                    && uint256(p.trailerSignerOffset) + 20 > p.trailerSize)
        ) revert InvalidProfile();
        CHAIN_ID = p.chainId;
        EPOCH_LENGTH = p.epochLength;
        BOUNDARY_OFFSET = p.boundaryOffset;
        MAX_ANCHOR_AGE = p.maxAnchorAge;
        SEAL_FIELDS = p.sealFields;
        ENTRY_SIZE = p.entrySize;
        TRAILER_SIZE = p.trailerSize;
        TRAILER_SIGNER_OFFSET = p.trailerSignerOffset;
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
        Anchor memory anchor = _decodeAnchor(trustAnchor);
        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory payload = RLP.decodeList(proofMem);
        if (payload.length != PAYLOAD_FIELDS && payload.length != PAYLOAD_FIELDS_WITH_MANIFEST) {
            revert InvalidPayloadShape();
        }

        // 1. Replay the header run under the anchor set; may rotate `anchor` in place.
        (bytes32 stateRoot, bool rotated) = _replay(anchor, RLP.readBytes(payload[IDX_SIGNERS]), payload[IDX_HEADERS]);

        // 2. Account proof (codeHash pinned) → 3. channel storage slots bound to channelId.
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        bytes32 storageRoot = _verifyServiceStorageRoot(
            payload[IDX_ACCOUNT_PROOF], stateRoot, _toAddress(ctx.remoteServiceAddress), anchor.codeHash
        );
        metadata = _verifyChannelStorage(payload[IDX_STORAGE_PROOF], storageRoot, ctx.channelId);

        // 4. Bundle content → message payloads.
        messagePayloads = _decodeBundleContent(RLP.readBytes(payload[IDX_BUNDLE_CONTENT]));

        // 5. Optional endpoint-manifest update against the same storage root.
        if (payload.length == PAYLOAD_FIELDS_WITH_MANIFEST) {
            newEndpointManifest = _verifyEndpointManifest(
                payload[IDX_MANIFEST_STORAGE_PROOF],
                storageRoot,
                RLP.readBytes(payload[IDX_MANIFEST_PREIMAGE]),
                ctx.remoteServiceAddress
            );
        } else {
            newEndpointManifest = _absentEndpointManifest();
        }

        // 6. Successor anchor only when the run carried a newer boundary block.
        if (rotated) {
            newTrustAnchor = _encodeAnchor(anchor);
            newTrustAnchorId = abi.encodePacked(anchor.setBlock);
        }
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes = RLP([ledgerConfiguration (ClprMessagePayload control protobuf),
    ///      headers, codeHash]). `headers` is a linked run whose first header is a boundary block; the
    ///      signer list it publishes becomes the anchor set, and the run must carry seals from a
    ///      majority of that set (the set demonstrably produces the chain that follows). This is a
    ///      weak-subjectivity bootstrap: which boundary block to start from is the deployer's choice.
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
        bytes memory cfgMem = configProofBytes;
        Memory.Slice[] memory cfg = RLP.decodeList(cfgMem);
        if (cfg.length != CONFIG_FIELDS) revert InvalidConfigPayload();

        ClprTypes.LedgerConfiguration memory lc = ClprProtobuf.decodeControlMessage(RLP.readBytes(cfg[0])).config;
        if (keccak256(bytes(lc.chainId)) != keccak256(bytes(string.concat("eip155:", Strings.toString(CHAIN_ID))))) {
            revert ChainIdMismatch();
        }

        ClprSignerReplay.Header memory b = ClprSignerReplay.decodeHeader(RLP.readList(cfg[1])[0]);
        if (!_isBoundary(b.number)) revert NotBoundaryBlock(b.number);
        address[] memory set = _parseSigners(b.extra);
        {
            (, ClprSignerReplay.Header memory newest,) = _walk(set, cfg[1]);
            if (newest.number != b.number) revert InvalidConfigPayload(); // run crosses into the next epoch
        }

        Anchor memory anchor = Anchor({
            codeHash: RLP.readBytes32(cfg[2]),
            setHash: ClprSignerReplay.hashSigners(set),
            setBlock: b.number,
            // forge-lint: disable-next-line(unsafe-typecast)
            setSize: uint16(set.length)
        });

        serviceAddress = lc.serviceAddress;
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        endpointManifest = _verifyConfigEndpointManifest(endpointManifestProofBytes, anchor, serviceAddress);
        return (
            channelContext,
            lc.chainId,
            serviceAddress,
            lc.nanosSinceEpoch,
            lc.throttles,
            _encodeAnchor(anchor),
            abi.encodePacked(anchor.setBlock),
            endpointManifest
        );
    }

    // ── Internals ─────────────────────────────────────────────────────────────

    /// @dev Verify a header run against the anchor set and return h_0's state root. When the run
    ///      contains a boundary block newer than `anchor.setBlock`, `anchor` is rotated to its list.
    function _replay(Anchor memory anchor, bytes memory signerBytes, Memory.Slice headersItem)
        internal
        view
        returns (bytes32 stateRoot, bool rotated)
    {
        address[] memory set = ClprSignerReplay.decodeSignerBytes(signerBytes);
        if (set.length != anchor.setSize || ClprSignerReplay.hashSigners(set) != anchor.setHash) {
            revert SignerSetMismatch();
        }
        (ClprSignerReplay.Header memory first, ClprSignerReplay.Header memory boundary, bool hasBoundary) =
            _walk(set, headersItem);
        if (first.number < anchor.setBlock) revert HeaderBeforeAnchor(first.number, anchor.setBlock);
        if (MAX_ANCHOR_AGE != 0 && uint256(first.number) > uint256(anchor.setBlock) + MAX_ANCHOR_AGE) {
            revert AnchorTooOld(first.number, anchor.setBlock);
        }
        stateRoot = first.stateRoot;

        if (hasBoundary && boundary.number > anchor.setBlock) {
            address[] memory next = _parseSigners(boundary.extra);
            anchor.setHash = ClprSignerReplay.hashSigners(next);
            // forge-lint: disable-next-line(unsafe-typecast)
            anchor.setSize = uint16(next.length);
            anchor.setBlock = boundary.number;
            rotated = true;
        }
    }

    /// @dev Walk a linked run, recover every sealer, find the newest boundary block and require
    ///      ⌊n/2⌋ + 1 distinct members of `set` among the sealers from that boundary (or h_0) onward.
    function _walk(address[] memory set, Memory.Slice headersItem)
        internal
        view
        returns (ClprSignerReplay.Header memory first, ClprSignerReplay.Header memory boundary, bool hasBoundary)
    {
        Memory.Slice[] memory items = RLP.readList(headersItem);
        uint256 m = items.length;
        if (m == 0 || m > MAX_HEADERS) revert InvalidPayloadShape();

        address[] memory sealers = new address[](m);
        ClprSignerReplay.Header memory prev;
        uint256 boundaryIndex;
        for (uint256 i = 0; i < m; i++) {
            ClprSignerReplay.Header memory h = ClprSignerReplay.decodeHeader(items[i]);
            if (i == 0) first = h;
            else ClprSignerReplay.requireChild(prev, h, i);
            sealers[i] = ClprSignerReplay.sealSigner(h, SEAL_FIELDS);
            if (_isBoundary(h.number)) {
                boundary = h;
                boundaryIndex = i;
                hasBoundary = true;
            }
            prev = h;
        }

        uint256 seen;
        uint256 distinct;
        for (uint256 i = boundaryIndex; i < m; i++) {
            uint256 idx = ClprSignerReplay.indexOf(set, sealers[i]);
            if (idx == type(uint256).max) continue;
            uint256 bit = uint256(1) << idx;
            if (seen & bit == 0) {
                seen |= bit;
                distinct++;
            }
        }
        uint256 required = set.length / 2 + 1;
        if (distinct < required) revert InsufficientSigners(distinct, required);
    }

    function _isBoundary(uint64 number) internal view returns (bool) {
        return (uint256(number) + BOUNDARY_OFFSET) % EPOCH_LENGTH == 0;
    }

    function _parseSigners(bytes memory extra) internal view returns (address[] memory) {
        return ClprSignerReplay.parseSigners(extra, ENTRY_SIZE, TRAILER_SIZE, TRAILER_SIGNER_OFFSET);
    }

    /// @dev Optional config-time manifest proof, verified with the same replay rule under the
    ///      bootstrapped set (no rotation).
    function _verifyConfigEndpointManifest(bytes calldata proofBytes, Anchor memory anchor, bytes memory serviceAddress)
        internal
        view
        returns (ClprTypes.ClprEndpointManifest memory)
    {
        if (proofBytes.length == 0) return _uninitializedEndpointManifest(serviceAddress);
        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory p = RLP.decodeList(proofMem);
        if (p.length != CONFIG_MANIFEST_PROOF_FIELDS) revert InvalidConfigPayload();
        (bytes32 stateRoot,) = _replay(anchor, RLP.readBytes(p[0]), p[1]);
        bytes32 storageRoot = _verifyServiceStorageRoot(p[2], stateRoot, _toAddress(serviceAddress), anchor.codeHash);
        return _verifyEndpointManifest(p[3], storageRoot, RLP.readBytes(p[4]), serviceAddress);
    }

    function _decodeAnchor(bytes calldata ta) internal pure returns (Anchor memory a) {
        if (ta.length != TRUST_ANCHOR_LENGTH) revert InvalidTrustAnchor();
        a.codeHash = bytes32(ta[0:32]);
        a.setHash = bytes32(ta[32:64]);
        a.setBlock = uint64(bytes8(ta[64:72]));
        a.setSize = uint16(bytes2(ta[72:74]));
        if (a.setSize == 0 || a.setSize > ClprSignerReplay.MAX_SIGNERS) revert InvalidTrustAnchor();
    }

    function _encodeAnchor(Anchor memory a) internal pure returns (bytes memory) {
        return abi.encodePacked(a.codeHash, a.setHash, a.setBlock, a.setSize);
    }
}
