// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {MptMultiProof} from "@hiero-ledger/clpr/libraries/proof/evm/MptMultiProof.sol";
import {CometBftProofCodec as Codec} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftProofCodec.sol";
import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title ArcMalachiteVerifier
/// @notice "Arc → Hiero" verifier. Arc (Circle) runs Malachite, a Tendermint-algorithm BFT engine,
///         over a reth execution layer. A block is final once more than 2/3 of the voting power has
///         precommitted its hash; the validator set lives in EVM storage of the ValidatorRegistry
///         contract. See README.md in this directory.
///
/// ## Verification chain (one "step")
///   0. Trust anchor = setHash(32) ‖ registryRoot(32) ‖ height(8, big-endian): the set with
///      `setHash` is the one ValidatorRegistry storage with root `registryRoot` yields; it signs
///      heights ≥ `height`.
///   1. The RLP header hashes (keccak256) to the certified block hash; its number is the height H.
///      The parent header (keccak == header.parentHash) gives stateRoot(H-1).
///   2. MPT account proof: the registry's storage root at stateRoot(H-1) equals `registryRoot`.
///      Arc's signing set for H is `getActiveValidatorSet()` at state H-1
///      (`get_signing_validator_set(H)` → eth_call at H-1), so this pins the exact signing set.
///   3. The supplied validator set must hash to `setHash`.
///   4. Commit certificate: Ed25519 signatures over the SSZ precommit
///      `Vote{Precommit, H, Some(round), Some(blockHash), keccak256(pubkey)[0:20]}` from validators
///      holding more than 2/3 of the set's voting power (Malachite `ThresholdParam::TWO_F_PLUS_ONE`).
///   5. Optional rotation: registry root at stateRoot(H) + a storage multiproof re-derive the set
///      for H+1; the anchor becomes (newSetHash, newRegistryRoot, H+1).
///
/// verifyBundle = optional hops (rotation steps at registry-change heights) + one step at the bundle block,
/// then the ClprService account and channel-slot MPT proofs against stateRoot(H).
/// verifyConfig = the same from the deploy-time checkpoint, proving ClprService
/// `_config.serviceAddress` (slot 25).
contract ArcMalachiteVerifier is ClprEvmBundleVerifier {
    // ── Types ─────────────────────────────────────────────────────────────────

    /// @param chainId              CLPR chain id of the Arc network (returned by verifyConfig).
    /// @param ed25519Verifier      {IEd25519Verifier} (Hedera has no Ed25519 precompile).
    /// @param registry             ValidatorRegistry proxy (0x3600…0002 on Arc).
    /// @param bootstrapSetHash     Weak-subjectivity checkpoint: set hash …
    /// @param bootstrapRegistryRoot … the registry storage root it was derived from …
    /// @param bootstrapHeight      … and the first height it signs.
    struct Profile {
        string chainId;
        address ed25519Verifier;
        address registry;
        bytes32 bootstrapSetHash;
        bytes32 bootstrapRegistryRoot;
        uint64 bootstrapHeight;
    }

    struct Anchor {
        bytes32 setHash;
        bytes32 registryRoot;
        uint64 height;
    }

    // ── Constants ─────────────────────────────────────────────────────────────

    /// @dev ERC-7201 base of `ValidatorRegistryStorage` ("arc.storage.ValidatorRegistry"):
    ///      +0 _validatorsByRegistrationId, +1 _activeValidatorRegistrations._values,
    ///      +2 ._positions, +3 _registeredPublicKeys, +4 _nextRegistrationId.
    bytes32 internal constant REGISTRY_STORAGE = 0xb58da0dce03316992faea3e12c60705b8ac05a309e27e3bc8421e5b271c9d200;
    /// @dev ValidatorStatus.Active.
    uint8 internal constant STATUS_ACTIVE = 2;
    /// @dev Storage word of a 32-byte `bytes` (long form): length * 2 + 1.
    uint256 internal constant PUBKEY32_LENGTH_WORD = 65;
    uint256 internal constant MAX_VALIDATORS = 256;
    uint256 internal constant ANCHOR_LENGTH = 72;
    uint256 internal constant SERVICE_ADDRESS_SLOT = 25;
    uint256 internal constant HEADER_PARENT_HASH = 0;
    uint256 internal constant HEADER_STATE_ROOT = 3;
    uint256 internal constant HEADER_NUMBER = 8;
    uint256 internal constant HEADER_MIN_FIELDS = 15;
    /// @dev SSZ Vote fixed part: type(1) + height(8) + round offset(4) + value offset(4) + address(20).
    uint32 internal constant SSZ_FIXED_LEN = 37;
    /// @dev Round variable part: Option<u32> = selector(1) + u32(4).
    uint32 internal constant SSZ_ROUND_LEN = 5;

    // ── Profile (immutable) ───────────────────────────────────────────────────

    bytes32 public immutable CHAIN_ID_HASH;
    IEd25519Verifier public immutable ED25519;
    address public immutable REGISTRY;
    bytes32 public immutable BOOTSTRAP_SET_HASH;
    bytes32 public immutable BOOTSTRAP_REGISTRY_ROOT;
    uint64 public immutable BOOTSTRAP_HEIGHT;

    // ── Errors ────────────────────────────────────────────────────────────────

    error InvalidProfile();
    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error InvalidHeader();
    error HeightTooOld();
    error InvalidValidator();
    error TooManyValidators();
    error ValidatorSetHashMismatch();
    error InvalidRound();
    error SignerIndexNotIncreasing();
    error SignerIndexOutOfRange();
    error InvalidSignature();
    error QuorumNotMet();
    error ParentHeaderMismatch();
    error RegistryRootMismatch();
    error EmptyValidatorSet();
    error ChainIdMismatch();
    error ServiceAddressSlotMismatch();

    constructor(Profile memory p) {
        if (
            p.ed25519Verifier == address(0) || p.registry == address(0) || p.bootstrapSetHash == bytes32(0)
                || bytes(p.chainId).length == 0
        ) revert InvalidProfile();
        CHAIN_ID_HASH = keccak256(bytes(p.chainId));
        ED25519 = IEd25519Verifier(p.ed25519Verifier);
        REGISTRY = p.registry;
        BOOTSTRAP_SET_HASH = p.bootstrapSetHash;
        BOOTSTRAP_REGISTRY_ROOT = p.bootstrapRegistryRoot;
        BOOTSTRAP_HEIGHT = p.bootstrapHeight;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   IClprVerifier
    // ─────────────────────────────────────────────────────────────────────────

    /// @inheritdoc IClprVerifier
    /// @dev proofBytes = RLP([step, hops[], serviceAccountProof, storageProof, bundleContent
    ///      (, manifestStorageProof, manifestPreimage)]); step = see {_step}.
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
        Anchor memory start = _decodeAnchor(trustAnchor);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        Memory.Slice[] memory p = RLP.decodeList(proofBytes);
        if (p.length != 5 && p.length != 7) revert InvalidPayloadShape();

        Anchor memory a = _applyHops(start, p[1]);
        bytes32 stateRoot;
        (a, stateRoot) = _step(a, p[0]);

        bytes32 storageRoot = _verifyServiceStorageRoot(p[2], stateRoot, _toAddress(ctx.remoteServiceAddress), 0);
        metadata = _verifyChannelStorage(p[3], storageRoot, ctx.channelId);
        messagePayloads = _decodeBundleContent(RLP.readBytes(p[4]));
        if (p.length == 7) {
            newEndpointManifest =
                _verifyEndpointManifest(p[5], storageRoot, RLP.readBytes(p[6]), ctx.remoteServiceAddress);
        } else {
            newEndpointManifest = _absentEndpointManifest();
        }

        if (a.setHash != start.setHash || a.registryRoot != start.registryRoot || a.height != start.height) {
            newTrustAnchor = _encodeAnchor(a);
            newTrustAnchorId = newTrustAnchor;
        }
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes = RLP([step, hops[], serviceAccountProof, serviceAddressSlotProof,
    ///      ledgerConfiguration]); trust starts at the deploy-time checkpoint. endpointManifestProofBytes
    ///      is empty (bring-up) or RLP([manifestStorageProof, manifestPreimage]) against the same
    ///      service account.
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
        Memory.Slice[] memory p = RLP.decodeList(configProofBytes);
        if (p.length != 5) revert InvalidPayloadShape();

        Anchor memory a = _applyHops(
            Anchor({setHash: BOOTSTRAP_SET_HASH, registryRoot: BOOTSTRAP_REGISTRY_ROOT, height: BOOTSTRAP_HEIGHT}), p[1]
        );
        bytes32 stateRoot;
        (a, stateRoot) = _step(a, p[0]);

        bytes20 service;
        (chainId, service, peerConfigNanos, throttles,) = Codec.parseLedgerConfiguration(RLP.readBytes(p[4]));
        if (keccak256(bytes(chainId)) != CHAIN_ID_HASH) revert ChainIdMismatch();

        bytes32 storageRoot = _verifyServiceStorageRoot(p[2], stateRoot, address(service), 0);
        bytes32[] memory slot = new bytes32[](1);
        slot[0] = bytes32(SERVICE_ADDRESS_SLOT);
        bytes32[] memory proven = ClprEvmStateProof.verifyProvenSlots(RLP.readList(p[3]), storageRoot, slot);
        // Short `bytes` (20 B) layout: data left-aligned, length*2 = 0x28 in the low byte.
        if (proven[0] != bytes32(uint256(bytes32(service)) | 0x28)) revert ServiceAddressSlotMismatch();

        serviceAddress = abi.encodePacked(service);
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        initialTrustAnchor = _encodeAnchor(a);
        initialTrustAnchorId = initialTrustAnchor;

        if (endpointManifestProofBytes.length == 0) {
            endpointManifest = _uninitializedEndpointManifest(serviceAddress);
        } else {
            Memory.Slice[] memory m = RLP.decodeList(endpointManifestProofBytes);
            if (m.length != 2) revert InvalidPayloadShape();
            endpointManifest = _verifyEndpointManifest(m[0], storageRoot, RLP.readBytes(m[1]), serviceAddress);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Light client
    // ─────────────────────────────────────────────────────────────────────────

    function _applyHops(Anchor memory a, Memory.Slice hopsItem) internal view returns (Anchor memory) {
        Memory.Slice[] memory hops = RLP.readList(hopsItem);
        for (uint256 i; i < hops.length; ++i) {
            (a,) = _step(a, hops[i]);
        }
        return a;
    }

    /// @dev step = RLP([header, parentHeader, round, signatures[[index, sig64]], validators[[pubkey32, power]],
    ///      parentRegistryAccountProof, rotation]); rotation = [] or [registryAccountProof, registrySetProof].
    ///
    ///      Binding the signing set: Arc's set for height H is `getActiveValidatorSet()` at state H-1, a
    ///      pure function of the registry's storage there (the ERC-1967 implementation slot included,
    ///      so an upgrade changes the root too). The step proves the registry storage root at
    ///      stateRoot(H-1) (parentHeader, hash-linked by header.parentHash) equals the anchor's
    ///      `registryRoot`, so the supplied set IS the set that signed H. A relay therefore cannot skip
    ///      a registry change: once it happens, no later header verifies until a rotation step moves
    ///      the anchor across it.
    ///
    ///      Rotation: with `rotation` present, the registry root at stateRoot(H) and an {MptMultiProof}
    ///      of its storage give the set for H+1, and the anchor becomes (thatSet, thatRoot, H+1).
    function _step(Anchor memory a, Memory.Slice stepItem)
        internal
        view
        returns (Anchor memory next, bytes32 stateRoot)
    {
        Memory.Slice[] memory f = RLP.readList(stepItem);
        if (f.length != 7) revert InvalidPayloadShape();

        bytes memory header = RLP.readBytes(f[0]);
        bytes32 blockHash = keccak256(header);
        uint64 height;
        bytes32 parentHash;
        (stateRoot, height, parentHash) = _headerFields(header);
        if (height < a.height || height == 0) revert HeightTooOld();
        {
            bytes memory parent = RLP.readBytes(f[1]);
            if (keccak256(parent) != parentHash) revert ParentHeaderMismatch();
            (bytes32 parentStateRoot, uint64 parentHeight,) = _headerFields(parent);
            if (parentHeight + 1 != height) revert ParentHeaderMismatch();
            if (_verifyRegistryRoot(f[5], parentStateRoot) != a.registryRoot) revert RegistryRootMismatch();
        }

        (bytes32[] memory keys, uint64[] memory powers, uint256 total) = _parseValidators(f[4], a.setHash);
        uint256 round = RLP.readUint256(f[2]);
        if (round > type(uint32).max) revert InvalidRound();
        // forge-lint: disable-next-line(unsafe-typecast)
        _verifyCertificate(height, uint32(round), blockHash, keys, powers, total, f[3]);

        Memory.Slice[] memory rot = RLP.readList(f[6]);
        if (rot.length == 0) return (a, stateRoot);
        if (rot.length != 2) revert InvalidPayloadShape();
        bytes32 newRoot = _verifyRegistryRoot(rot[0], stateRoot);
        next = Anchor({setHash: _deriveSetHash(rot[1], newRoot), registryRoot: newRoot, height: height + 1});
    }

    /// @dev (stateRoot, number, parentHash) of an RLP execution header.
    function _headerFields(bytes memory header)
        internal
        pure
        returns (bytes32 stateRoot, uint64 height, bytes32 parentHash)
    {
        Memory.Slice[] memory h = RLP.decodeList(header);
        if (h.length < HEADER_MIN_FIELDS) revert InvalidHeader();
        parentHash = RLP.readBytes32(h[HEADER_PARENT_HASH]);
        stateRoot = RLP.readBytes32(h[HEADER_STATE_ROOT]);
        uint256 n = RLP.readUint256(h[HEADER_NUMBER]);
        if (n >= type(uint64).max) revert InvalidHeader();
        // forge-lint: disable-next-line(unsafe-typecast)
        height = uint64(n);
    }

    /// @dev Validators as RLP [[pubkey(32), power], …] in registry order; must hash to `setHash`.
    function _parseValidators(Memory.Slice item, bytes32 setHash)
        internal
        pure
        returns (bytes32[] memory keys, uint64[] memory powers, uint256 total)
    {
        Memory.Slice[] memory vs = RLP.readList(item);
        if (vs.length == 0) revert EmptyValidatorSet();
        if (vs.length > MAX_VALIDATORS) revert TooManyValidators();
        keys = new bytes32[](vs.length);
        powers = new uint64[](vs.length);
        bytes memory packed = new bytes(vs.length * 40);
        for (uint256 i; i < vs.length; ++i) {
            Memory.Slice[] memory v = RLP.readList(vs[i]);
            if (v.length != 2) revert InvalidValidator();
            bytes memory pk = RLP.readBytes(v[0]);
            uint256 power = RLP.readUint256(v[1]);
            if (pk.length != 32 || power == 0 || power > type(uint64).max) revert InvalidValidator();
            // forge-lint: disable-next-line(unsafe-typecast)
            bytes32 k = bytes32(pk);
            keys[i] = k;
            // forge-lint: disable-next-line(unsafe-typecast)
            powers[i] = uint64(power);
            total += power;
            assembly ("memory-safe") {
                let dst := add(add(packed, 32), mul(i, 40))
                mstore(dst, k)
                mstore(add(dst, 32), shl(192, power))
            }
        }
        if (keccak256(packed) != setHash) revert ValidatorSetHashMismatch();
    }

    /// @dev signatures = RLP [[index, sig(64)], …] with strictly increasing indices into the set.
    function _verifyCertificate(
        uint64 height,
        uint32 round,
        bytes32 blockHash,
        bytes32[] memory keys,
        uint64[] memory powers,
        uint256 total,
        Memory.Slice sigsItem
    ) internal view {
        Memory.Slice[] memory sigs = RLP.readList(sigsItem);
        uint256 signed;
        uint256 prev;
        for (uint256 i; i < sigs.length; ++i) {
            Memory.Slice[] memory s = RLP.readList(sigs[i]);
            if (s.length != 2) revert InvalidSignature();
            uint256 idx = RLP.readUint256(s[0]);
            if (idx >= keys.length) revert SignerIndexOutOfRange();
            if (i > 0 && idx <= prev) revert SignerIndexNotIncreasing();
            prev = idx;
            bytes memory sig = RLP.readBytes(s[1]);
            if (sig.length != 64) revert InvalidSignature();
            bytes memory msg_ =
                precommitSignBytes(height, round, blockHash, bytes20(keccak256(abi.encodePacked(keys[idx]))));
            if (!_verifyEd25519(keys[idx], msg_, sig)) revert InvalidSignature();
            signed += powers[idx];
        }
        if (signed * 3 <= total * 2) revert QuorumNotMet();
    }

    /// @dev Virtual so test harnesses can stub the (expensive) Ed25519 external call.
    function _verifyEd25519(bytes32 key, bytes memory message, bytes memory sig) internal view virtual returns (bool) {
        return ED25519.verify(key, message, sig);
    }

    /// @notice SSZ sign bytes of a Malachite precommit for `blockHash` (arc-node crates/types vote.rs):
    ///         type(1)=1 ‖ height(u64 LE) ‖ off(round)=37 (u32 LE) ‖ off(value)=42 (u32 LE) ‖
    ///         address(20) ‖ round = Some: 0x01 ‖ u32 LE ‖ value = Some: 0x01 ‖ hash(32). 75 bytes.
    function precommitSignBytes(uint64 height, uint32 round, bytes32 blockHash, bytes20 addr)
        public
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            uint8(1),
            _le64(height),
            _le32(SSZ_FIXED_LEN),
            _le32(SSZ_FIXED_LEN + SSZ_ROUND_LEN),
            addr,
            uint8(1),
            _le32(round),
            uint8(1),
            blockHash
        );
    }

    /// @dev Registry account proof at `stateRoot` → its storage root.
    function _verifyRegistryRoot(Memory.Slice item, bytes32 stateRoot) internal view returns (bytes32 storageRoot) {
        (storageRoot,) = ClprEvmStateProof.decodeAccount(ClprEvmStateProof.verifyAccount(item, stateRoot, REGISTRY));
    }

    /// @notice Hash of the validator set the registry storage under `registryRoot` yields, exactly as
    ///         Arc's `abi_decode_validator_set` builds it: `getActiveValidatorSet()` in `_values`
    ///         order, keeping entries with status Active, voting power > 0 and a 32-byte key.
    ///         setHash = keccak256(‖ pubkey(32) ‖ power(8, big-endian)).
    /// @dev Lookup order (= `paths` order): length; then per entry i: `_values[i]`, status word,
    ///      power word, key-length word, and the key word only when the entry is kept.
    function _deriveSetHash(Memory.Slice proofItem, bytes32 registryRoot) internal pure returns (bytes32) {
        MptMultiProof.Pool memory pool = MptMultiProof.load(proofItem);
        bytes32 lenSlot = bytes32(uint256(REGISTRY_STORAGE) + 1);
        uint256 n = uint256(MptMultiProof.getWord(pool, registryRoot, lenSlot));
        if (n > MAX_VALIDATORS) revert TooManyValidators();
        uint256 valuesBase = uint256(keccak256(abi.encode(lenSlot)));
        bytes memory packed = new bytes(n * 40);
        uint256 kept;
        for (uint256 i; i < n; ++i) {
            uint256 id = uint256(MptMultiProof.getWord(pool, registryRoot, bytes32(valuesBase + i)));
            uint256 sb = uint256(keccak256(abi.encode(id, REGISTRY_STORAGE)));
            // forge-lint: disable-next-line(unsafe-typecast)
            uint256 status = uint8(uint256(MptMultiProof.getWord(pool, registryRoot, bytes32(sb))));
            // forge-lint: disable-next-line(unsafe-typecast)
            uint64 power = uint64(uint256(MptMultiProof.getWord(pool, registryRoot, bytes32(sb + 2))));
            uint256 lenWord = uint256(MptMultiProof.getWord(pool, registryRoot, bytes32(sb + 1)));
            if (status != STATUS_ACTIVE || power == 0 || lenWord != PUBKEY32_LENGTH_WORD) continue;
            bytes32 pk = MptMultiProof.getWord(pool, registryRoot, keccak256(abi.encode(sb + 1)));
            assembly ("memory-safe") {
                let dst := add(add(packed, 32), mul(kept, 40))
                mstore(dst, pk)
                mstore(add(dst, 32), shl(192, power))
            }
            ++kept;
        }
        MptMultiProof.finish(pool);
        if (kept == 0) revert EmptyValidatorSet();
        assembly ("memory-safe") {
            mstore(packed, mul(kept, 40))
        }
        return keccak256(packed);
    }

    // ── Anchor ────────────────────────────────────────────────────────────────

    function _decodeAnchor(bytes calldata b) internal pure returns (Anchor memory a) {
        if (b.length != ANCHOR_LENGTH) revert InvalidTrustAnchor();
        a.setHash = bytes32(b[0:32]);
        a.registryRoot = bytes32(b[32:64]);
        // forge-lint: disable-next-line(unsafe-typecast)
        a.height = uint64(bytes8(b[64:72]));
        if (a.setHash == bytes32(0)) revert InvalidTrustAnchor();
    }

    function _encodeAnchor(Anchor memory a) internal pure returns (bytes memory) {
        return abi.encodePacked(a.setHash, a.registryRoot, a.height);
    }

    // ── Little-endian helpers ─────────────────────────────────────────────────

    function _le64(uint64 v) private pure returns (bytes8 r) {
        uint64 x = v;
        x = ((x & 0x00ff00ff00ff00ff) << 8) | ((x >> 8) & 0x00ff00ff00ff00ff);
        x = ((x & 0x0000ffff0000ffff) << 16) | ((x >> 16) & 0x0000ffff0000ffff);
        x = (x << 32) | (x >> 32);
        r = bytes8(x);
    }

    function _le32(uint32 v) private pure returns (bytes4 r) {
        uint32 x = v;
        x = ((x & 0x00ff00ff) << 8) | ((x >> 8) & 0x00ff00ff);
        x = (x << 16) | (x >> 16);
        r = bytes4(x);
    }
}
