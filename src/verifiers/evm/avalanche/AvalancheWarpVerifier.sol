// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprBeaconBls} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconBls.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {ClprAvalancheWarp as Warp} from "@hiero-ledger/clpr/libraries/proof/avalanche/ClprAvalancheWarp.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title AvalancheWarpVerifier
/// @notice CLPR verifier for the Avalanche C-Chain (and other Avalanche EVM chains whose validators
///         Warp-sign accepted block hashes). A block is trusted when an Avalanche Warp `BitSetSignature`
///         by ≥ 67% of the tracked validator set's stake signs its hash; the CLPR Service's queue
///         storage is then proven against the header's state root with MPT proofs.
///
/// ## Trust anchor (flat packed, 220 bytes)
/// ```
///   [0..4)     networkId        Avalanche network id (1 mainnet, 5 Fuji)        ─┐ bound into every
///   [4..36)    sourceChainId    blockchain id of the source chain (C-Chain)       ─┘ signed message
///   [36..68)   channelId        binds the storage proof to one CLPR channel
///   [68..100)  codeHash         pinned ClprService runtime code hash
///   [100..132) setHash          keccak256 of the packed canonical validator set
///   [132..164) totalWeight      P-Chain total weight of the set (incl. validators without a BLS key)
///   [164..172) pChainHeight     P-Chain height the set was taken at (trust-anchor id)
///   [172..180) pChainTimestamp  P-Chain block timestamp at that height
///   [180..188) maxSetAge        seconds a set may be used after pChainTimestamp
///   [188..220) attestorsHash    keccak256(abi.encode(threshold, attestors)) of the rotation attestors
/// ```
///
/// ## Bundle proof (RLP list, 7 items, or 9 with an endpoint-manifest update)
/// ```
/// [ 0: header          RLP-encoded EVM block header (bytes); blockHash = keccak256(header)
///   1: warpSignature   [signers (minimal big-endian bit set), signature (256-byte uncompressed G2)]
///   2: validatorSet    packed canonical set n × (x48 ‖ y48 ‖ weight8) the signature is checked against
///   3: rotation        0x80 (none) or [pChainHeight, pChainTimestamp, totalWeight, threshold,
///                      attestors[], attestorSignatures[]] — item 2 is then the NEW set
///   4: accountProof    MPT proof of the ClprService account against header.stateRoot
///   5: storageProof    5 or 6 × [slot, proofNodes] for the channelId-derived slots
///   6: bundleContent   protobuf ClprBundleContent
///  [7: manifestStorageProof, 8: manifestPreimage] ]
/// ```
///
/// ## What is proven and what is trusted
/// - Proven from the chain: the block's finality (a Warp quorum certificate over its hash, rebuilt
///   on-chain as avalanchego serializes it), the state root (keccak of the supplied header), the
///   ClprService account and queue slots (MPT).
/// - Trusted: the validator set and weights. The P-Chain neither Warp-signs its own blocks nor its
///   validator set (its ACP-118 handler signs only the ACP-77 L1-validator messages), and the C-Chain
///   state does not contain it, so no on-chain proof of the Primary Network set exists. The initial
///   set comes from the channel config (weak subjectivity, as in every light client); later sets are
///   accepted when `threshold` of the anchor's attestors ECDSA-sign the set commitment. The set is
///   still checked for canonical order, key validity and weight consistency on-chain, and a set is
///   only usable for blocks in `[pChainTimestamp, pChainTimestamp + maxSetAge]`.
///
/// @dev Account proof, channel storage proof, queue-metadata decode and bundle-content decode are
///      inherited from {ClprEvmBundleVerifier}. Coreth state accounts carry a 5th RLP field
///      (`isMultiCoin`), so the account leaf is decoded here instead of by {ClprEvmStateProof.decodeAccount}.
contract AvalancheWarpVerifier is ClprEvmBundleVerifier {
    // ── Bundle payload layout ────────────────────────────────────────────────
    uint256 internal constant PAYLOAD_FIELDS = 7;
    uint256 internal constant PAYLOAD_FIELDS_WITH_MANIFEST = 9;
    uint256 internal constant IDX_HEADER = 0;
    uint256 internal constant IDX_WARP_SIGNATURE = 1;
    uint256 internal constant IDX_VALIDATOR_SET = 2;
    uint256 internal constant IDX_ROTATION = 3;
    uint256 internal constant IDX_ACCOUNT_PROOF = 4;
    uint256 internal constant IDX_STORAGE_PROOF = 5;
    uint256 internal constant IDX_BUNDLE_CONTENT = 6;
    uint256 internal constant IDX_MANIFEST_STORAGE_PROOF = 7;
    uint256 internal constant IDX_MANIFEST_PREIMAGE = 8;

    uint256 internal constant ROTATION_FIELDS = 6;

    // ── Header ───────────────────────────────────────────────────────────────
    /// @dev Coreth headers have 16+ fields (geth's 15 + ExtDataHash, then optional fork fields; 29 at
    ///      Granite); subnet-evm headers have 15+. Only stateRoot and time are read.
    uint256 internal constant MIN_HEADER_FIELDS = 15;
    uint256 internal constant MAX_HEADER_FIELDS = 40;
    uint256 internal constant HEADER_STATE_ROOT_INDEX = 3;
    uint256 internal constant HEADER_TIME_INDEX = 11;

    uint256 internal constant BLS_SIGNATURE_LENGTH = 256;

    // ── Trust anchor ─────────────────────────────────────────────────────────
    uint256 internal constant TRUST_ANCHOR_LENGTH = 220;

    // ── Config ───────────────────────────────────────────────────────────────
    uint256 internal constant CONFIG_FIELDS = 12;
    uint256 internal constant CFG_LEDGER = 0;
    uint256 internal constant CFG_EVM_CHAIN_ID = 1;
    uint256 internal constant CFG_NETWORK_ID = 2;
    uint256 internal constant CFG_SOURCE_CHAIN_ID = 3;
    uint256 internal constant CFG_P_CHAIN_HEIGHT = 4;
    uint256 internal constant CFG_P_CHAIN_TIMESTAMP = 5;
    uint256 internal constant CFG_VALIDATOR_SET = 6;
    uint256 internal constant CFG_TOTAL_WEIGHT = 7;
    uint256 internal constant CFG_MAX_SET_AGE = 8;
    uint256 internal constant CFG_ATTESTOR_THRESHOLD = 9;
    uint256 internal constant CFG_ATTESTORS = 10;
    uint256 internal constant CFG_CODE_HASH = 11;
    /// @dev Config-time manifest proof: [header, warpSignature, accountProof, manifestStorageProof, preimage].
    uint256 internal constant CONFIG_MANIFEST_PROOF_FIELDS = 5;

    /// @dev Domain tag of the validator-set attestation (EIP-191 personal-sign over this digest).
    bytes32 internal constant VALIDATOR_SET_TYPEHASH = keccak256(
        "ClprAvalancheValidatorSet(uint32 networkId,bytes32 sourceChainId,uint64 pChainHeight,uint64 pChainTimestamp,bytes32 setHash,uint256 totalWeight)"
    );

    // ── Known C-Chains: (networkId, blockchainId) ↔ EVM chain id ─────────────
    bytes32 internal constant MAINNET_C_CHAIN_ID = 0x0427d4b22a2a78bcddd456742caf91b56badbff985ee19aef14573e7343fd652;
    bytes32 internal constant FUJI_C_CHAIN_ID = 0x7fc93d85c6d62c5b2ac0b519c87010ea5294012d1e407030d6acd0021cac10d5;
    bytes32 internal constant FLARE_C_CHAIN_ID = 0x77d3074dc510f43b09ac5be77edee276ef3b55f0097d504846aa8eec613fc625;
    bytes32 internal constant COSTON2_C_CHAIN_ID = 0x78db5c30bed04c05ce209179812850bbb3fe6d46d7eef3744d814c0da5552479;

    // ── Errors ───────────────────────────────────────────────────────────────
    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error InvalidHeader();
    error InvalidWarpSignature();
    error InvalidAccount();
    error InvalidConfigPayload();
    error ChainIdMismatch();
    /// @dev The supplied validator set is not the one the trust anchor commits to.
    error ValidatorSetMismatch();
    /// @dev The block predates the P-Chain height the set was taken at.
    error BlockBeforeValidatorSet(uint64 blockTime, uint64 setTimestamp);
    /// @dev The set is older than `maxSetAge` at the block's time; rotate first.
    error ValidatorSetExpired(uint64 blockTime, uint64 expiresAt);
    error RotationDisabled();
    error RotationNotNewer(uint64 pChainHeight, uint64 currentHeight);
    error AttestorSetMismatch();
    error AttestorsNotSorted();
    error InsufficientAttestations(uint256 valid, uint256 threshold);

    struct Anchor {
        uint32 networkId;
        bytes32 sourceChainId;
        bytes32 channelId;
        bytes32 codeHash;
        bytes32 setHash;
        uint256 totalWeight;
        uint64 pChainHeight;
        uint64 pChainTimestamp;
        uint64 maxSetAge;
        bytes32 attestorsHash;
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
        Anchor memory a = _decodeAnchor(trustAnchor);

        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory payload = RLP.decodeList(proofMem);
        if (payload.length != PAYLOAD_FIELDS && payload.length != PAYLOAD_FIELDS_WITH_MANIFEST) {
            revert InvalidPayloadShape();
        }

        // 1. Validator set: the anchor's own, or an attested successor (rotation). `a` is advanced in
        //    place on rotation so every following check runs against the NEW set.
        bytes memory set = RLP.readBytes(payload[IDX_VALIDATOR_SET]);
        bool rotated = _firstByte(payload[IDX_ROTATION]) != 0x80;
        if (rotated) {
            _applyRotation(a, payload[IDX_ROTATION], set);
        } else if (keccak256(set) != a.setHash) {
            revert ValidatorSetMismatch();
        }

        // 2. Warp quorum certificate over the block hash → state root.
        bytes32 stateRoot = _verifyWarpBlock(a, set, payload[IDX_HEADER], payload[IDX_WARP_SIGNATURE]);

        // 3. ClprService account (code hash pinned) → storage root → channel queue slots.
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        bytes32 storageRoot = _serviceStorageRoot(
            payload[IDX_ACCOUNT_PROOF], stateRoot, _toAddress(ctx.remoteServiceAddress), a.codeHash
        );
        metadata = _verifyChannelStorage(payload[IDX_STORAGE_PROOF], storageRoot, a.channelId);
        messagePayloads = _decodeBundleContent(RLP.readBytes(payload[IDX_BUNDLE_CONTENT]));

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

        if (rotated) {
            newTrustAnchor = _encodeAnchor(a);
            newTrustAnchorId = abi.encodePacked(a.pChainHeight);
        }
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes is RLP `[ledgerConfiguration, evmChainId, networkId, sourceChainId,
    ///      pChainHeight, pChainTimestamp, validatorSet, totalWeight, maxSetAge, attestorThreshold,
    ///      attestors[], codeHash]`. This is the bootstrap: the set is a trusted input (checked for
    ///      well-formedness only), as is the attestor policy for later rotations.
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

        ClprTypes.LedgerConfiguration memory lc =
        ClprProtobuf.decodeControlMessage(RLP.readBytes(cfg[CFG_LEDGER])).config;

        Anchor memory a;
        a.networkId = _u32(cfg[CFG_NETWORK_ID]);
        a.sourceChainId = RLP.readBytes32(cfg[CFG_SOURCE_CHAIN_ID]);
        _requireChainBinding(lc.chainId, RLP.readUint256(cfg[CFG_EVM_CHAIN_ID]), a.networkId, a.sourceChainId);

        a.channelId = channelId;
        a.codeHash = RLP.readBytes32(cfg[CFG_CODE_HASH]);
        a.pChainHeight = _u64(cfg[CFG_P_CHAIN_HEIGHT]);
        a.pChainTimestamp = _u64(cfg[CFG_P_CHAIN_TIMESTAMP]);
        a.maxSetAge = _u64(cfg[CFG_MAX_SET_AGE]);
        if (a.maxSetAge == 0) revert InvalidConfigPayload();
        a.totalWeight = RLP.readUint256(cfg[CFG_TOTAL_WEIGHT]);

        bytes memory set = RLP.readBytes(cfg[CFG_VALIDATOR_SET]);
        Warp.validate(set, a.totalWeight);
        a.setHash = keccak256(set);
        a.attestorsHash = _attestorPolicyHash(cfg[CFG_ATTESTOR_THRESHOLD], cfg[CFG_ATTESTORS]);

        serviceAddress = lc.serviceAddress;
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        initialTrustAnchor = _encodeAnchor(a);
        return (
            channelContext,
            lc.chainId,
            serviceAddress,
            lc.nanosSinceEpoch,
            lc.throttles,
            initialTrustAnchor,
            abi.encodePacked(a.pChainHeight),
            _verifyConfigEndpointManifest(endpointManifestProofBytes, a, set, serviceAddress)
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Warp block certificate
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Verify the Warp `BitSetSignature` over `payload.Hash(keccak256(header))` against `set`
    ///      (already bound to `a`), enforce the set's validity window at the block time, and return
    ///      the header's state root. Cheap failures (shape, window, quorum) come before the pairing.
    function _verifyWarpBlock(Anchor memory a, bytes memory set, Memory.Slice headerItem, Memory.Slice sigItem)
        internal
        view
        returns (bytes32 stateRoot)
    {
        bytes memory header = RLP.readBytes(headerItem);
        bytes32 blockHash = keccak256(header);
        Memory.Slice[] memory h = RLP.decodeList(header);
        if (h.length < MIN_HEADER_FIELDS || h.length > MAX_HEADER_FIELDS) revert InvalidHeader();
        stateRoot = RLP.readBytes32(h[HEADER_STATE_ROOT_INDEX]);
        uint64 blockTime = _u64(h[HEADER_TIME_INDEX]);
        if (blockTime < a.pChainTimestamp) revert BlockBeforeValidatorSet(blockTime, a.pChainTimestamp);
        uint64 expiresAt = a.pChainTimestamp + a.maxSetAge;
        if (blockTime > expiresAt) revert ValidatorSetExpired(blockTime, expiresAt);

        Memory.Slice[] memory sig = RLP.readList(sigItem);
        if (sig.length != 2) revert InvalidWarpSignature();
        bytes memory signature = RLP.readBytes(sig[1]);
        if (signature.length != BLS_SIGNATURE_LENGTH) revert InvalidWarpSignature();

        (bytes memory aggregatePubkey, uint256 signedWeight) = Warp.aggregateSigners(set, RLP.readBytes(sig[0]));
        Warp.requireQuorum(signedWeight, a.totalWeight);
        ClprBeaconBls.verifyMessage(
            aggregatePubkey, signature, Warp.blockHashMessage(a.networkId, a.sourceChainId, blockHash)
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Validator-set rotation (attested)
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Accept `newSet` as the successor of the anchor's set: strictly newer P-Chain height, not
    ///      older timestamp, well-formed set, and `threshold` distinct attestors from the anchor's
    ///      policy signing `(networkId, sourceChainId, height, timestamp, setHash, totalWeight)`.
    ///      Advances `a` in place.
    function _applyRotation(Anchor memory a, Memory.Slice rotationItem, bytes memory newSet) internal view {
        Memory.Slice[] memory r = RLP.readList(rotationItem);
        if (r.length != ROTATION_FIELDS) revert InvalidPayloadShape();

        uint64 height = _u64(r[0]);
        uint64 timestamp = _u64(r[1]);
        uint256 totalWeight = RLP.readUint256(r[2]);
        if (height <= a.pChainHeight || timestamp < a.pChainTimestamp) {
            revert RotationNotNewer(height, a.pChainHeight);
        }

        // Attestor policy: the rotation must present the exact (threshold, attestors) the anchor commits to.
        uint256 threshold = RLP.readUint256(r[3]);
        Memory.Slice[] memory attestorItems = RLP.readList(r[4]);
        address[] memory attestors = new address[](attestorItems.length);
        for (uint256 i = 0; i < attestors.length; i++) {
            attestors[i] = RLP.readAddress(attestorItems[i]);
        }
        if (keccak256(abi.encode(threshold, attestors)) != a.attestorsHash) revert AttestorSetMismatch();
        if (threshold == 0) revert RotationDisabled();

        Warp.validate(newSet, totalWeight);
        bytes32 setHash = keccak256(newSet);

        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(
            keccak256(
                abi.encode(
                    VALIDATOR_SET_TYPEHASH, a.networkId, a.sourceChainId, height, timestamp, setHash, totalWeight
                )
            )
        );
        _requireAttestations(digest, RLP.readList(r[5]), attestors, threshold);

        a.setHash = setHash;
        a.totalWeight = totalWeight;
        a.pChainHeight = height;
        a.pChainTimestamp = timestamp;
    }

    /// @dev Count signatures from distinct policy attestors. Signatures must be ordered by strictly
    ///      ascending recovered address (rules out duplicates without a seen-set).
    function _requireAttestations(
        bytes32 digest,
        Memory.Slice[] memory sigItems,
        address[] memory attestors,
        uint256 threshold
    ) private pure {
        uint256 valid;
        address last;
        for (uint256 i = 0; i < sigItems.length; i++) {
            address signer = ECDSA.recover(digest, RLP.readBytes(sigItems[i]));
            if (signer <= last) revert AttestorsNotSorted();
            last = signer;
            for (uint256 j = 0; j < attestors.length; j++) {
                if (attestors[j] == signer) {
                    valid++;
                    break;
                }
            }
        }
        if (valid < threshold) revert InsufficientAttestations(valid, threshold);
    }

    /// @dev `keccak256(abi.encode(threshold, attestors))` after checking the policy: attestors
    ///      strictly ascending and non-zero, `threshold ≤ attestors.length` (0 disables rotation).
    function _attestorPolicyHash(Memory.Slice thresholdItem, Memory.Slice attestorsItem)
        private
        pure
        returns (bytes32)
    {
        uint256 threshold = RLP.readUint256(thresholdItem);
        Memory.Slice[] memory items = RLP.readList(attestorsItem);
        address[] memory attestors = new address[](items.length);
        address last;
        for (uint256 i = 0; i < items.length; i++) {
            attestors[i] = RLP.readAddress(items[i]);
            if (attestors[i] <= last) revert AttestorsNotSorted();
            last = attestors[i];
        }
        if (threshold > attestors.length) revert InvalidConfigPayload();
        return keccak256(abi.encode(threshold, attestors));
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Config helpers
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev The advertised CAIP-2 id must be `eip155:<evmChainId>`. For the known C-Chains the EVM
    ///      chain id must also match the (networkId, blockchainId) pair that the Warp message binds,
    ///      so a config cannot pair Fuji's validators and chain with mainnet's CAIP-2 id.
    function _requireChainBinding(string memory caip2, uint256 evmChainId, uint32 networkId, bytes32 sourceChainId)
        private
        pure
    {
        if (keccak256(bytes(caip2)) != keccak256(abi.encodePacked("eip155:", Strings.toString(evmChainId)))) {
            revert ChainIdMismatch();
        }
        uint256 expected;
        if (sourceChainId == MAINNET_C_CHAIN_ID) expected = networkId == 1 ? 43114 : type(uint256).max;
        else if (sourceChainId == FUJI_C_CHAIN_ID) expected = networkId == 5 ? 43113 : type(uint256).max;
        else if (sourceChainId == FLARE_C_CHAIN_ID) expected = networkId == 14 ? 14 : type(uint256).max;
        else if (sourceChainId == COSTON2_C_CHAIN_ID) expected = networkId == 114 ? 114 : type(uint256).max;
        if (expected != 0 && expected != evmChainId) revert ChainIdMismatch();
    }

    /// @dev Config-time manifest proof against the CONFIG set: the same Warp → MPT chain as a bundle.
    ///      Empty proof → UNINITIALIZED manifest (bring-up).
    function _verifyConfigEndpointManifest(
        bytes calldata proofBytes,
        Anchor memory a,
        bytes memory set,
        bytes memory serviceAddress
    ) private view returns (ClprTypes.ClprEndpointManifest memory) {
        if (proofBytes.length == 0) return _uninitializedEndpointManifest(serviceAddress);
        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory p = RLP.decodeList(proofMem);
        if (p.length != CONFIG_MANIFEST_PROOF_FIELDS) revert InvalidConfigPayload();
        bytes32 stateRoot = _verifyWarpBlock(a, set, p[0], p[1]);
        bytes32 storageRoot = _serviceStorageRoot(p[2], stateRoot, _toAddress(serviceAddress), a.codeHash);
        return _verifyEndpointManifest(p[3], storageRoot, RLP.readBytes(p[4]), serviceAddress);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Account (coreth layout)
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Like {ClprEvmBundleVerifier._verifyServiceStorageRoot}, but accepts coreth's account
    ///      RLP `[nonce, balance, root, codeHash, isMultiCoin]` (live Fuji accounts carry the 5th field,
    ///      empty for false) as well as the plain 4-field form (subnet-evm).
    function _serviceStorageRoot(
        Memory.Slice accountProofItem,
        bytes32 stateRoot,
        address service,
        bytes32 expectedCodeHash
    ) internal pure returns (bytes32 storageRoot) {
        Memory.Slice[] memory f = RLP.decodeList(ClprEvmStateProof.verifyAccount(accountProofItem, stateRoot, service));
        if (f.length != 4 && f.length != 5) revert InvalidAccount();
        if (f.length == 5 && RLP.readUint256(f[4]) > 1) revert InvalidAccount();
        storageRoot = RLP.readBytes32(f[2]);
        bytes32 codeHash = RLP.readBytes32(f[3]);
        if (expectedCodeHash != bytes32(0) && codeHash != expectedCodeHash) revert CodeHashMismatch();
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Anchor codec + small decoders
    // ─────────────────────────────────────────────────────────────────────────

    function _decodeAnchor(bytes calldata t) internal pure returns (Anchor memory a) {
        if (t.length != TRUST_ANCHOR_LENGTH) revert InvalidTrustAnchor();
        a.networkId = uint32(bytes4(t[0:4]));
        a.sourceChainId = bytes32(t[4:36]);
        a.channelId = bytes32(t[36:68]);
        a.codeHash = bytes32(t[68:100]);
        a.setHash = bytes32(t[100:132]);
        a.totalWeight = uint256(bytes32(t[132:164]));
        a.pChainHeight = uint64(bytes8(t[164:172]));
        a.pChainTimestamp = uint64(bytes8(t[172:180]));
        a.maxSetAge = uint64(bytes8(t[180:188]));
        a.attestorsHash = bytes32(t[188:220]);
    }

    function _encodeAnchor(Anchor memory a) internal pure returns (bytes memory) {
        return abi.encodePacked(
            a.networkId,
            a.sourceChainId,
            a.channelId,
            a.codeHash,
            a.setHash,
            a.totalWeight,
            a.pChainHeight,
            a.pChainTimestamp,
            a.maxSetAge,
            a.attestorsHash
        );
    }

    function _u64(Memory.Slice item) private pure returns (uint64) {
        uint256 v = RLP.readUint256(item);
        if (v > type(uint64).max) revert InvalidPayloadShape();
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(v); // range-checked above
    }

    function _u32(Memory.Slice item) private pure returns (uint32) {
        uint256 v = RLP.readUint256(item);
        if (v > type(uint32).max) revert InvalidConfigPayload();
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint32(v); // range-checked above
    }

    function _firstByte(Memory.Slice item) private pure returns (uint8) {
        return uint8(bytes1(Memory.load(item, 0)));
    }
}
