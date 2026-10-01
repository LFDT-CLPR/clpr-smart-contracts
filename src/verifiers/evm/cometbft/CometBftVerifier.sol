// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {CometBftLib} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftLib.sol";
import {CometBftProofCodec as Codec} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftProofCodec.sol";
import {Ics23Lib} from "@hiero-ledger/clpr/libraries/proof/cometbft/Ics23Lib.sol";

/// @title CometBftVerifier
/// @notice One verifier for every CometBFT (Tendermint) chain whose CLPR Service is an EVM contract
///         kept in a Cosmos SDK IAVL store: Cronos and Mezo (Ethermint `evm` store, key prefix
///         0x02), Sei (`evm` store, prefix 0x03). The chain is a deploy-time {Profile}; the code is
///         the same for all of them. See README.md in this directory.
///
/// ## Verification chain (verifyBundle)
///   0. Trust anchor = validatorSetHash(32) ‖ height(8, big-endian): the set trusted to sign every
///      header at or above `height`.
///   1. Optional hops: each hop is a header signed (>2/3) by the current set; it moves the working
///      anchor to (header.next_validators_hash, header.height + 1). This is how a relay catches up
///      across validator-set changes.
///   2. The supplied validator set (raw CometBFT SimpleValidator leaves) must hash to the working
///      anchor hash, and equal the header's validators_hash.
///   3. Header hash (14-field simple Merkle) is rebuilt on-chain; commit signatures from >2/3 of the
///      set's voting power must sign the canonical precommit for that hash.
///   4. ICS-23 multistore proof: store key → store root, rooted at header.app_hash.
///   5. ICS-23 IAVL proof per storage slot: key = prefix ‖ serviceAddress(20) ‖ slot(32).
///   6. If header.next_validators_hash differs from the anchor, the new anchor is
///      (next_validators_hash, header.height + 1).
///
/// ## Signature schemes ({KeyScheme})
///   ED25519        Standard CometBFT keys (Cronos, Mezo, Sei, dYdX, Provenance, THORChain). No
///                  EVM precompile exists on Hedera, so verification is delegated to an
///                  {IEd25519Verifier} (pure-Solidity, ~0.6M gas per signature).
///   SECP256K1_ETH  Polygon's CometBFT fork (Heimdall v2): 65-byte uncompressed keys in PublicKey
///                  oneof field 3, signature = r‖s‖v over keccak256(signBytes), validator address =
///                  Ethereum address. Verified with `ecrecover` (~3k gas per signature).
///
/// ## Trust model
///   Bootstrap: `verifyConfig` starts from the deploy-time weak-subjectivity checkpoint
///   (BOOTSTRAP_VALIDATORS_HASH, BOOTSTRAP_HEIGHT) and must hop to the config header. It never
///   accepts a validator set the proof itself supplies.
///   After that, the usual light-client assumption: no set the verifier trusts ever had >2/3 of its
///   power sign two conflicting headers. Like every sequential light client without a trusting
///   period, a set that has fully unbonded could forge a hop; relays must keep channels within the
///   chain's unbonding period (README §5).
contract CometBftVerifier is ClprEvmBundleVerifier {
    // ── Types ─────────────────────────────────────────────────────────────────

    enum KeyScheme {
        ED25519,
        SECP256K1_ETH
    }

    /// @param chainId                 CometBFT chain id (header.chain_id), e.g. "cronosmainnet_25-1".
    /// @param storeKey                IAVL store holding EVM contract storage, e.g. "evm".
    /// @param evmStateKeyPrefix       Storage key prefix inside that store (Ethermint 0x02, Sei 0x03).
    /// @param keyScheme               Consensus key type of the validator set.
    /// @param ed25519Verifier         {IEd25519Verifier}; required iff keyScheme == ED25519.
    /// @param bootstrapValidatorsHash Validator-set hash trusted at `bootstrapHeight` (checkpoint).
    /// @param bootstrapHeight         First height the bootstrap set signs.
    struct Profile {
        string chainId;
        bytes storeKey;
        uint8 evmStateKeyPrefix;
        KeyScheme keyScheme;
        address ed25519Verifier;
        bytes32 bootstrapValidatorsHash;
        uint64 bootstrapHeight;
    }

    /// @dev One validator: ED25519 → the 32-byte public key; SECP256K1_ETH → the Ethereum address
    ///      (right-aligned), derived from the 65-byte key in the hashed leaf.
    struct Validator {
        bytes32 key;
        int64 power;
    }

    /// @dev Decoded CometBftBundlePayload (README §4).
    struct BundlePayload {
        bytes stateProof;
        bytes bundleContent;
        bytes validatorSet;
        bytes manifestStorageProof;
        bytes manifestPreimage;
        bytes[] hops;
    }

    // ── Constants ─────────────────────────────────────────────────────────────

    uint256 internal constant ANCHOR_LENGTH = 40;
    /// @dev ClprService `_config.serviceAddress` (LedgerConfiguration member 2 at slot 23; see
    ///      storage-layout.json). verifyConfig proves this exact slot.
    uint256 internal constant SERVICE_ADDRESS_SLOT = 25;
    uint8 internal constant STORAGE_PROOF_MIN_ENTRIES = 5;
    uint8 internal constant STORAGE_PROOF_MAX_ENTRIES = 6;
    uint8 internal constant PRECOMMIT_TYPE = 2;
    uint256 internal constant SECP256K1_HALF_N = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    /// @dev CometBFT MaxTotalVotingPower = MaxInt64 / 8.
    int64 internal constant MAX_TOTAL_VOTING_POWER = type(int64).max / 8;
    uint64 internal constant MAX_VALIDATOR_POWER = uint64(type(int64).max / 8);

    // ── Profile (immutable) ───────────────────────────────────────────────────

    bytes32 public immutable CHAIN_ID_HASH;
    bytes32 public immutable STORE_KEY_HASH;
    uint8 public immutable EVM_STATE_KEY_PREFIX;
    KeyScheme public immutable KEY_SCHEME;
    IEd25519Verifier public immutable ED25519;
    bytes32 public immutable BOOTSTRAP_VALIDATORS_HASH;
    uint64 public immutable BOOTSTRAP_HEIGHT;

    // ── Errors ────────────────────────────────────────────────────────────────

    error InvalidProfile();
    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error MissingStateProof();
    error MissingBundleContent();
    error MissingValidatorSet();
    error MissingLedgerConfig();
    error EmptyValidatorSet();
    error InvalidValidatorLeaf();
    error ValidatorSetHashMismatch();
    error ChainIdMismatch();
    error HeightTooOld();
    error InvalidSignersBitsLength();
    error SignersBitOutOfRange();
    error TooFewSignatures();
    error ExtraSignatures();
    error InvalidSignature();
    error QuorumNotMet();
    error InvalidStoreKey();
    error InvalidStoreRoot();
    error StorageKeyMismatch();
    error StorageProofFailed();
    error InvalidStorageValueLength();
    error NonExistenceSlotNotEmpty();
    error InvalidStorageProofCount();
    error ServiceAddressSlotMismatch();
    error ManifestProofPairMismatch();
    error OnlyExistenceProofsSupported();

    constructor(Profile memory p) {
        if (bytes(p.chainId).length == 0 || p.storeKey.length == 0 || p.bootstrapValidatorsHash == bytes32(0)) {
            revert InvalidProfile();
        }
        if (p.keyScheme == KeyScheme.ED25519 && p.ed25519Verifier == address(0)) revert InvalidProfile();
        CHAIN_ID_HASH = keccak256(bytes(p.chainId));
        STORE_KEY_HASH = keccak256(p.storeKey);
        EVM_STATE_KEY_PREFIX = p.evmStateKeyPrefix;
        KEY_SCHEME = p.keyScheme;
        ED25519 = IEd25519Verifier(p.ed25519Verifier);
        BOOTSTRAP_VALIDATORS_HASH = p.bootstrapValidatorsHash;
        BOOTSTRAP_HEIGHT = p.bootstrapHeight;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   IClprVerifier
    // ─────────────────────────────────────────────────────────────────────────

    /// @inheritdoc IClprVerifier
    /// @dev proofBytes = CometBftBundlePayload; trustAnchor = validatorSetHash(32) ‖ height(8).
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
        (bytes32 anchorHash, uint64 anchorHeight) = _decodeAnchor(trustAnchor);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        bytes20 serviceAddr = _toBytes20(ctx.remoteServiceAddress);
        BundlePayload memory p = _parseBundlePayload(proofBytes);

        (bytes32 setHash, uint64 minHeight) = _applyHops(p.hops, anchorHash, anchorHeight);
        Validator[] memory vals = _parseValidatorSet(p.validatorSet, setHash);

        (
            CometBftLib.SeiHeader memory header,
            bytes32[] memory slotValues,
            bytes32[] memory slotNumbers,
            bytes32 storeRoot
        ) = _verifyStateProof(p.stateProof, vals, setHash, minHeight, serviceAddr);

        if (slotValues.length < STORAGE_PROOF_MIN_ENTRIES || slotValues.length > STORAGE_PROOF_MAX_ENTRIES) {
            revert StorageProofFailed();
        }
        metadata = _bindChannelSlots(slotNumbers, slotValues, ctx.channelId);
        newEndpointManifest = _verifyManifest(
            p.manifestStorageProof, p.manifestPreimage, storeRoot, serviceAddr, ctx.remoteServiceAddress
        );

        if (header.nextValidatorsHash != anchorHash) {
            // forge-lint: disable-next-line(unsafe-typecast)
            newTrustAnchor = _encodeAnchor(header.nextValidatorsHash, uint64(header.height) + 1);
            newTrustAnchorId = newTrustAnchor;
        }
        messagePayloads = _decodeBundleContent(p.bundleContent);
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes = CometBftConfigPayload. Trust starts at the deploy-time bootstrap
    ///      checkpoint and follows hops to the config header; the proven slot must be ClprService's
    ///      `_config.serviceAddress` holding the declared address.
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
        (bytes memory valSetBytes, bytes memory ledgerConfig, bytes memory stateProof, bytes[] memory hops) =
            _parseConfigPayload(configProofBytes);

        bytes20 lServiceAddr;
        (, lServiceAddr, peerConfigNanos, throttles,) = Codec.parseLedgerConfiguration(ledgerConfig);

        (bytes32 setHash, uint64 minHeight) = _applyHops(hops, BOOTSTRAP_VALIDATORS_HASH, BOOTSTRAP_HEIGHT);
        Validator[] memory vals = _parseValidatorSet(valSetBytes, setHash);
        (
            CometBftLib.SeiHeader memory header,
            bytes32[] memory slotValues,
            bytes32[] memory slotNumbers,
            bytes32 storeRoot
        ) = _verifyStateProof(stateProof, vals, setHash, minHeight, lServiceAddr);

        if (slotValues.length != 1) revert InvalidStorageProofCount();
        // Short `bytes` (20 B) layout: data left-aligned, length*2 = 0x28 in the low byte.
        if (
            slotNumbers[0] != bytes32(SERVICE_ADDRESS_SLOT)
                || slotValues[0] != bytes32(uint256(bytes32(lServiceAddr)) | 0x28)
        ) {
            revert ServiceAddressSlotMismatch();
        }

        serviceAddress = abi.encodePacked(lServiceAddr);
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        chainId = header.chainId;
        // forge-lint: disable-next-line(unsafe-typecast)
        initialTrustAnchor = _encodeAnchor(header.nextValidatorsHash, uint64(header.height) + 1);
        initialTrustAnchorId = initialTrustAnchor;
        endpointManifest = _verifyConfigManifest(endpointManifestProofBytes, storeRoot, lServiceAddr, serviceAddress);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Light client
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Walks `hops` (each = ValidatorSetHop{1: ValidatorSet, 2: SignedHeader}) from
    ///      (setHash, minHeight). Each hop header must be signed by the current set at or above the
    ///      current height; the working anchor then moves to its next_validators_hash.
    function _applyHops(bytes[] memory hops, bytes32 setHash, uint64 minHeight)
        internal
        view
        returns (bytes32, uint64)
    {
        for (uint256 i; i < hops.length; ++i) {
            bytes memory valSetBytes;
            bytes memory signedHeader;
            bytes memory h = hops[i];
            uint256 off;
            while (off < h.length) {
                (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(h, off);
                off = off2;
                if (fn_ == 1 && wt == 2) (valSetBytes, off) = PB.decodeLengthDelimited(h, off);
                else if (fn_ == 2 && wt == 2) (signedHeader, off) = PB.decodeLengthDelimited(h, off);
                else off = PB.skipField(h, off, wt);
            }
            Validator[] memory vals = _parseValidatorSet(valSetBytes, setHash);
            (CometBftLib.SeiHeader memory header, CometBftLib.SeiCommit memory commit) =
                Codec.parseSignedHeader(signedHeader);
            _verifySignedHeader(header, commit, vals, setHash, minHeight);
            setHash = header.nextValidatorsHash;
            // forge-lint: disable-next-line(unsafe-typecast)
            minHeight = uint64(header.height) + 1;
        }
        return (setHash, minHeight);
    }

    /// @dev Chain id, validator-set binding, height floor, header hash and >2/3 commit.
    function _verifySignedHeader(
        CometBftLib.SeiHeader memory header,
        CometBftLib.SeiCommit memory commit,
        Validator[] memory vals,
        bytes32 setHash,
        uint64 minHeight
    ) internal view {
        if (keccak256(bytes(header.chainId)) != CHAIN_ID_HASH) {
            revert ChainIdMismatch();
        }
        if (header.validatorsHash != setHash) revert ValidatorSetHashMismatch();
        // forge-lint: disable-next-line(unsafe-typecast)
        if (header.height <= 0 || uint64(header.height) < minHeight) revert HeightTooOld();
        _verifyCommit(commit, CometBftLib.headerHash(header), header, vals);
    }

    /// @dev >2/3 of the set's total power must have signed the canonical precommit for `headerHash`.
    ///      `signersBits` selects validators (MSB-first); signatures follow in validator order.
    ///      Verification stops once the quorum is met: signatures past that point are never
    ///      checked and never counted. Sets are sorted by power (desc), so a relay that supplies
    ///      the first committed signers in index order supplies the fewest signatures.
    function _verifyCommit(
        CometBftLib.SeiCommit memory commit,
        bytes32 headerHash,
        CometBftLib.SeiHeader memory header,
        Validator[] memory vals
    ) internal view {
        uint256 n = vals.length;
        if (commit.signersBits.length != (n + 7) / 8) revert InvalidSignersBitsLength();
        for (uint256 bit = n; bit < commit.signersBits.length * 8; ++bit) {
            if (_bitSet(commit.signersBits, bit)) revert SignersBitOutOfRange();
        }

        bytes memory prefix;
        bytes memory suffix;
        {
            bytes memory canonicalBlockId =
                CometBftLib.encodeBlockId(headerHash, commit.partSetTotal, commit.partSetHash);
            prefix = abi.encodePacked(
                CometBftLib.pbVarintField(1, PRECOMMIT_TYPE),
                abi.encodePacked(CometBftLib.pbTag(2, 1), CometBftLib.sfixed64LE(header.height)),
                commit.round != 0
                    ? abi.encodePacked(CometBftLib.pbTag(3, 1), CometBftLib.sfixed64LE(commit.round))
                    : bytes(""),
                CometBftLib.pbMessageField(4, canonicalBlockId)
            );
            suffix = CometBftLib.pbBytesField(6, bytes(header.chainId));
        }

        int256 totalPower;
        uint256 setBits;
        for (uint256 i; i < n; ++i) {
            totalPower += vals[i].power;
            if (_bitSet(commit.signersBits, i)) ++setBits;
        }
        if (commit.signatures.length < setBits) revert TooFewSignatures();
        if (commit.signatures.length > setBits) revert ExtraSignatures();

        int256 signedPower;
        uint256 sigIdx;
        for (uint256 i; i < n; ++i) {
            if (signedPower * 3 > totalPower * 2) break;
            if (!_bitSet(commit.signersBits, i)) continue;
            CometBftLib.CommitSig memory sig = commit.signatures[sigIdx++];
            bytes memory signBytes =
                CometBftLib.precommitSignBytesHoisted(prefix, suffix, sig.timestampSeconds, sig.timestampNanos);
            if (!_verifyVote(vals[i].key, signBytes, sig.signature)) revert InvalidSignature();
            signedPower += vals[i].power;
        }
        if (signedPower * 3 <= totalPower * 2) revert QuorumNotMet();
    }

    /// @dev Scheme dispatch. Virtual so test harnesses can stub the Ed25519 external call.
    function _verifyVote(bytes32 key, bytes memory signBytes, bytes memory sig) internal view virtual returns (bool) {
        if (KEY_SCHEME == KeyScheme.ED25519) {
            if (sig.length != 64) return false;
            return ED25519.verify(key, signBytes, sig);
        }
        if (sig.length != 65) return false;
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        if (uint256(s) > SECP256K1_HALF_N) return false;
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return false;
        address signer = ecrecover(keccak256(signBytes), v, r, s);
        return signer != address(0) && bytes32(uint256(uint160(signer))) == key;
    }

    /// @dev ValidatorSet{repeated bytes leaf = 1}: each leaf is the exact CometBFT SimpleValidator
    ///      bytes hashed into validators_hash, so the set is authenticated by hashing what was
    ///      supplied (no re-encoding) and then strictly decoded.
    function _parseValidatorSet(bytes memory data, bytes32 expectedHash)
        internal
        view
        returns (Validator[] memory vals)
    {
        uint256 n;
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            if (fn_ != 1 || wt != 2) revert InvalidValidatorLeaf();
            off = PB.skipField(data, off2, wt);
            ++n;
        }
        if (n == 0) revert EmptyValidatorSet();
        bytes[] memory leaves = new bytes[](n);
        vals = new Validator[](n);
        off = 0;
        int256 total;
        for (uint256 i; i < n; ++i) {
            (,, uint256 off2) = PB.decodeFieldKey(data, off);
            (leaves[i], off) = PB.decodeLengthDelimited(data, off2);
            vals[i] = _decodeLeaf(leaves[i]);
            total += vals[i].power;
        }
        if (total > MAX_TOTAL_VOTING_POWER) revert InvalidValidatorLeaf();
        if (CometBftLib.simpleMerkleRoot(leaves) != expectedHash) revert ValidatorSetHashMismatch();
    }

    /// @dev SimpleValidator{1: PublicKey{oneof: ed25519 = 1 | secp256k1_uncompressed = 3}, 2: power}.
    ///      Exactly this canonical shape is accepted; power must be positive.
    function _decodeLeaf(bytes memory leaf) internal view returns (Validator memory v) {
        bool ed = KEY_SCHEME == KeyScheme.ED25519;
        uint256 keyLen = ed ? 32 : 65;
        // 0x0a <len> <tag> <keyLen> key… [0x10 <power varint>]
        if (leaf.length < 4 + keyLen || uint8(leaf[0]) != 0x0a || uint8(leaf[1]) != keyLen + 2) {
            revert InvalidValidatorLeaf();
        }
        if (uint8(leaf[2]) != (ed ? 0x0a : 0x1a) || uint8(leaf[3]) != keyLen) revert InvalidValidatorLeaf();
        uint256 off = 4 + keyLen;
        if (off == leaf.length || uint8(leaf[off]) != 0x10) revert InvalidValidatorLeaf();
        (uint64 power, uint256 end) = PB.decodeVarint(leaf, off + 1);
        if (end != leaf.length || power == 0 || power > MAX_VALIDATOR_POWER) revert InvalidValidatorLeaf();
        // forge-lint: disable-next-line(unsafe-typecast)
        v.power = int64(power);
        if (ed) {
            v.key = Codec.load32(leaf, 4);
        } else {
            if (uint8(leaf[4]) != 0x04) revert InvalidValidatorLeaf();
            bytes32 h;
            assembly {
                h := keccak256(add(leaf, 37), 64)
            }
            v.key = bytes32(uint256(uint160(uint256(h))));
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   State proof
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Signed header → app_hash → store root (ICS-23 Tendermint spec) → one IAVL proof per
    ///      storage entry of `serviceAddr`. Returns each proven slot number and value (absent = 0).
    function _verifyStateProof(
        bytes memory stateProofBytes,
        Validator[] memory vals,
        bytes32 setHash,
        uint64 minHeight,
        bytes20 serviceAddr
    )
        internal
        view
        returns (
            CometBftLib.SeiHeader memory header,
            bytes32[] memory slotValues,
            bytes32[] memory slotNumbers,
            bytes32 storeRoot
        )
    {
        (bytes memory signedHeader, bytes memory storeKey, bytes memory multistoreProof, bytes[] memory entries) =
            Codec.parseStateProof(stateProofBytes);
        CometBftLib.SeiCommit memory commit;
        (header, commit) = Codec.parseSignedHeader(signedHeader);
        _verifySignedHeader(header, commit, vals, setHash, minHeight);

        if (keccak256(storeKey) != STORE_KEY_HASH) revert InvalidStoreKey();
        Ics23Lib.ExistenceProof memory ms = Codec.parseExistenceProof(multistoreProof);
        Ics23Lib.verifyMembershipTendermint(ms, header.appHash, storeKey, ms.value);
        if (ms.value.length != 32) revert InvalidStoreRoot();
        storeRoot = Codec.load32(ms.value, 0);

        uint256 n = entries.length;
        slotValues = new bytes32[](n);
        slotNumbers = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            (bytes memory key, bytes memory value, bytes memory proof) = Codec.parseStorageProofEntry(entries[i]);
            _checkStorageKey(key, serviceAddr);
            slotNumbers[i] = Codec.load32(key, 21);
            (bool isExistence, Ics23Lib.ExistenceProof memory ep, Ics23Lib.NonExistenceProof memory nep) =
                Codec.parseCommitmentProof(proof);
            if (isExistence) {
                if (value.length != 32) revert InvalidStorageValueLength();
                Ics23Lib.verifyMembershipIavl(ep, storeRoot, key, value);
                slotValues[i] = Codec.load32(value, 0);
            } else {
                // Never-written (or deleted) slot: absent from the tree, reads as zero.
                if (value.length != 0) revert NonExistenceSlotNotEmpty();
                Ics23Lib.verifyNonMembershipIavl(nep, storeRoot, key);
            }
        }
    }

    /// @dev key = EVM_STATE_KEY_PREFIX ‖ serviceAddr(20) ‖ slot(32).
    function _checkStorageKey(bytes memory key, bytes20 serviceAddr) internal view {
        if (key.length != 53 || uint8(key[0]) != EVM_STATE_KEY_PREFIX) revert StorageKeyMismatch();
        bytes20 a;
        assembly {
            a := mload(add(key, 33))
        }
        if (a != serviceAddr) revert StorageKeyMismatch();
    }

    /// @dev Binds proven slots to the channel's layout: indices 0..4 are
    ///      {_channelMetadataSlots}; an optional 6th is the last sent message's running hash.
    function _bindChannelSlots(bytes32[] memory slotNumbers, bytes32[] memory slotValues, bytes32 channelId)
        internal
        pure
        returns (ClprTypes.QueueMetadata memory metadata)
    {
        bytes32[] memory channelSlots = _channelMetadataSlots(channelId);
        for (uint256 i; i < channelSlots.length; ++i) {
            if (slotNumbers[i] != channelSlots[i]) revert StorageKeyMismatch();
        }
        metadata = _buildQueueMetadata(slotValues);
        if (slotNumbers.length == STORAGE_PROOF_MAX_ENTRIES) {
            if (metadata.nextMessageId == 0) revert InvalidNextMessageId();
            if (slotNumbers[5] != _lastMessageRunningHashSlot(channelId, uint64(metadata.nextMessageId - 1))) {
                revert StorageKeyMismatch();
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Endpoint manifest
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Config-time manifest proof: protobuf {1: StorageProofEntry, 2: preimage}; empty →
    ///      UNINITIALIZED (version 0) manifest.
    function _verifyConfigManifest(
        bytes calldata proofBytes,
        bytes32 storeRoot,
        bytes20 serviceAddr,
        bytes memory expectedServiceAddress
    ) internal view returns (ClprTypes.ClprEndpointManifest memory) {
        if (proofBytes.length == 0) {
            return _uninitializedEndpointManifest(expectedServiceAddress);
        }
        bytes memory entry;
        bytes memory preimage;
        bytes memory data = proofBytes;
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (fn_ == 1 && wt == 2) (entry, off) = PB.decodeLengthDelimited(data, off);
            else if (fn_ == 2 && wt == 2) (preimage, off) = PB.decodeLengthDelimited(data, off);
            else off = PB.skipField(data, off, wt);
        }
        return _verifyManifest(entry, preimage, storeRoot, serviceAddr, expectedServiceAddress);
    }

    /// @dev IAVL existence proof of the manifest-commitment slot, preimage bound by keccak256.
    ///      Both inputs empty → absent manifest (version 0, "no update").
    function _verifyManifest(
        bytes memory entryBytes,
        bytes memory preimage,
        bytes32 storeRoot,
        bytes20 serviceAddr,
        bytes memory expectedServiceAddress
    ) internal view returns (ClprTypes.ClprEndpointManifest memory manifest) {
        if (entryBytes.length == 0 && preimage.length == 0) {
            return _absentEndpointManifest();
        }
        if (entryBytes.length == 0 || preimage.length == 0) revert ManifestProofPairMismatch();

        (bytes memory key, bytes memory value, bytes memory proof) = Codec.parseStorageProofEntry(entryBytes);
        _checkStorageKey(key, serviceAddr);
        if (Codec.load32(key, 21) != bytes32(ENDPOINT_MANIFEST_COMMITMENT_SLOT)) revert StorageKeyMismatch();
        if (value.length != 32) revert InvalidStorageValueLength();
        (bool isExistence, Ics23Lib.ExistenceProof memory ep,) = Codec.parseCommitmentProof(proof);
        if (!isExistence) revert OnlyExistenceProofsSupported();
        Ics23Lib.verifyMembershipIavl(ep, storeRoot, key, value);
        if (keccak256(preimage) != Codec.load32(value, 0)) revert ManifestCommitmentMismatch();

        manifest = ClprProtobuf.decodeEndpointManifest(preimage);
        if (manifest.version == 0) revert ManifestVersionZero();
        if (keccak256(manifest.serviceAddress) != keccak256(expectedServiceAddress)) {
            revert ManifestServiceAddressMismatch();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Payload decoding
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev CometBftBundlePayload: 1 state_proof, 2 bundle_content, 3 validator_set,
    ///      4 manifest storage proof, 5 manifest preimage, 6 repeated hop.
    function _parseBundlePayload(bytes memory data) internal pure returns (BundlePayload memory p) {
        p.hops = new bytes[](_countField(data, 6));
        uint256 h;
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (wt != 2) {
                off = PB.skipField(data, off, wt);
            } else if (fn_ == 1) {
                (p.stateProof, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 2) {
                (p.bundleContent, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 3) {
                (p.validatorSet, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 4) {
                (p.manifestStorageProof, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 5) {
                (p.manifestPreimage, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 6) {
                (p.hops[h++], off) = PB.decodeLengthDelimited(data, off);
            } else {
                off = PB.skipField(data, off, wt);
            }
        }
        if (p.stateProof.length == 0) revert MissingStateProof();
        if (p.bundleContent.length == 0) revert MissingBundleContent();
        if (p.validatorSet.length == 0) revert MissingValidatorSet();
    }

    /// @dev CometBftConfigPayload: 1 validator_set, 2 ledger_configuration, 3 state_proof,
    ///      4 repeated hop (from the bootstrap checkpoint).
    function _parseConfigPayload(bytes memory data)
        internal
        pure
        returns (bytes memory valSet, bytes memory ledgerConfig, bytes memory stateProof, bytes[] memory hops)
    {
        hops = new bytes[](_countField(data, 4));
        uint256 h;
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            off = off2;
            if (wt != 2) {
                off = PB.skipField(data, off, wt);
            } else if (fn_ == 1) {
                (valSet, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 2) {
                (ledgerConfig, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 3) {
                (stateProof, off) = PB.decodeLengthDelimited(data, off);
            } else if (fn_ == 4) {
                (hops[h++], off) = PB.decodeLengthDelimited(data, off);
            } else {
                off = PB.skipField(data, off, wt);
            }
        }
        if (valSet.length == 0) revert MissingValidatorSet();
        if (ledgerConfig.length == 0) revert MissingLedgerConfig();
        if (stateProof.length == 0) revert MissingStateProof();
    }

    function _countField(bytes memory data, uint64 field) private pure returns (uint256 n) {
        uint256 off;
        while (off < data.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(data, off);
            if (fn_ == field && wt == 2) ++n;
            off = PB.skipField(data, off2, wt);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Helpers
    // ─────────────────────────────────────────────────────────────────────────

    function _decodeAnchor(bytes calldata anchor) internal pure returns (bytes32 setHash, uint64 height) {
        if (anchor.length != ANCHOR_LENGTH) revert InvalidTrustAnchor();
        setHash = bytes32(anchor[0:32]);
        height = uint64(bytes8(anchor[32:40]));
        if (setHash == bytes32(0)) revert InvalidTrustAnchor();
    }

    function _encodeAnchor(bytes32 setHash, uint64 height) internal pure returns (bytes memory) {
        return abi.encodePacked(setHash, height);
    }

    function _toBytes20(bytes memory b) internal pure returns (bytes20 addr) {
        if (b.length != 20) revert InvalidServiceAddressLength();
        assembly {
            addr := mload(add(b, 32))
        }
    }

    function _bitSet(bytes memory bits, uint256 idx) internal pure returns (bool) {
        return uint8(bits[idx / 8]) & (uint8(0x80) >> (idx % 8)) != 0;
    }
}
