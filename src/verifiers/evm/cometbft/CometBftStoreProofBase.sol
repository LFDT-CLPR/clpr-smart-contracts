// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {CometBftProofCodec as Codec} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftProofCodec.sol";
import {Ics23Lib} from "@hiero-ledger/clpr/libraries/proof/cometbft/Ics23Lib.sol";
import {CometBftCommitAccumulator} from "@hiero-ledger/clpr/verifiers/evm/cometbft/CometBftCommitAccumulator.sol";

/// @title CometBftStoreProofBase
/// @notice The CometBFT half shared by verifiers that read one Cosmos SDK IAVL store through a
///         {CometBftCommitAccumulator}: trust anchor → hops → header (inline or accumulated) →
///         app_hash → store root (ICS-23 Tendermint spec) → one IAVL entry (existence or absence).
///         Used by {CosmWasmVerifier} (store `wasm`: Provenance, THORChain) and
///         {PolygonPosVerifier} (Heimdall v2 store `milestone`). Moved out of CosmWasmVerifier
///         unchanged. See src/verifiers/evm/provenance/README.md §2.
///
///         Trust anchor = validatorSetHash(32) ‖ height(8, big-endian): the set trusted to sign
///         every header at or above `height`.
///
///         A `HeaderRef` is either inline `{1 validator_set, 2 signed_header}` (checked by
///         {CometBftCommitAccumulator.checkHeader} in the same call) or `{3 header_hash}` of a header
///         whose commit was accumulated in earlier transactions. Either way the header must be
///         signed by the working set at or above the working height.
abstract contract CometBftStoreProofBase {
    uint256 internal constant ANCHOR_LENGTH = 40;

    CometBftCommitAccumulator public immutable ACCUMULATOR;
    bytes32 public immutable STORE_KEY_HASH;
    bytes32 public immutable BOOTSTRAP_VALIDATORS_HASH;
    uint64 public immutable BOOTSTRAP_HEIGHT;

    error InvalidProfile();
    error InvalidTrustAnchor();
    error MissingHeader();
    error MissingStateProof();
    error MissingStorageEntry();
    error InvalidHeaderRef();
    error ValidatorSetHashMismatch();
    error HeightTooOld();
    error InvalidStoreKey();
    error InvalidStoreRoot();
    error StorageKeyMismatch();
    error NonExistenceValueNotEmpty();

    constructor(
        CometBftCommitAccumulator accumulator,
        bytes memory storeKey,
        bytes32 bootstrapValidatorsHash,
        uint64 bootstrapHeight
    ) {
        if (address(accumulator) == address(0) || storeKey.length == 0 || bootstrapValidatorsHash == bytes32(0)) {
            revert InvalidProfile();
        }
        ACCUMULATOR = accumulator;
        STORE_KEY_HASH = keccak256(storeKey);
        BOOTSTRAP_VALIDATORS_HASH = bootstrapValidatorsHash;
        BOOTSTRAP_HEIGHT = bootstrapHeight;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Headers
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Hops, then the state header, then app_hash → store root of the profile's store.
    function _verifiedStoreRoot(
        bytes memory header,
        bytes[] memory hops,
        bytes memory multistoreProof,
        bytes32 setHash,
        uint64 minHeight
    ) internal view returns (CometBftCommitAccumulator.Header memory h, bytes32 storeRoot) {
        if (header.length == 0) revert MissingHeader();
        if (multistoreProof.length == 0) revert MissingStateProof();
        for (uint256 i; i < hops.length; ++i) {
            h = _resolveHeader(hops[i], setHash, minHeight);
            setHash = h.nextValidatorsHash;
            minHeight = h.height + 1;
        }
        h = _resolveHeader(header, setHash, minHeight);

        Ics23Lib.ExistenceProof memory ms = Codec.parseExistenceProof(multistoreProof);
        if (keccak256(ms.key) != STORE_KEY_HASH) revert InvalidStoreKey();
        Ics23Lib.verifyMembershipTendermint(ms, h.appHash, ms.key, ms.value);
        if (ms.value.length != 32) revert InvalidStoreRoot();
        storeRoot = Codec.load32(ms.value, 0);
    }

    /// @dev HeaderRef{1 validator_set, 2 signed_header} (inline) or {3 header_hash} (accumulated).
    function _resolveHeader(bytes memory ref, bytes32 setHash, uint64 minHeight)
        internal
        view
        returns (CometBftCommitAccumulator.Header memory h)
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
            (, h) = ACCUMULATOR.checkHeader(valSet, signedHeader, setHash, minHeight);
        } else {
            if (headerHash.length != 32 || valSet.length != 0 || signedHeader.length != 0) revert InvalidHeaderRef();
            // forge-lint: disable-next-line(unsafe-typecast)
            h = ACCUMULATOR.finalizedHeader(bytes32(headerHash));
            if (h.validatorsHash != setHash) revert ValidatorSetHashMismatch();
            if (h.height < minHeight) revert HeightTooOld();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   IAVL entry
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev StorageProofEntry{1 key, 2 value, 3 IAVL CommitmentProof}. The key must equal
    ///      `expectedKey`; existence proofs return the value, non-existence proofs return (false, "").
    function _proveEntry(bytes memory entry, bytes32 storeRoot, bytes memory expectedKey)
        internal
        pure
        returns (bool exists, bytes memory value)
    {
        if (entry.length == 0) revert MissingStorageEntry();
        bytes memory key;
        bytes memory proof;
        (key, value, proof) = Codec.parseStorageProofEntry(entry);
        if (keccak256(key) != keccak256(expectedKey)) revert StorageKeyMismatch();
        (bool isExistence, Ics23Lib.ExistenceProof memory ep, Ics23Lib.NonExistenceProof memory nep) =
            Codec.parseCommitmentProof(proof);
        if (isExistence) {
            Ics23Lib.verifyMembershipIavl(ep, storeRoot, key, value);
            exists = true;
        } else {
            if (value.length != 0) revert NonExistenceValueNotEmpty();
            Ics23Lib.verifyNonMembershipIavl(nep, storeRoot, key);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Anchor
    // ─────────────────────────────────────────────────────────────────────────

    function _decodeAnchor(bytes calldata anchor) internal pure returns (bytes32 setHash, uint64 height) {
        if (anchor.length != ANCHOR_LENGTH) revert InvalidTrustAnchor();
        setHash = bytes32(anchor[0:32]);
        height = uint64(bytes8(anchor[32:40]));
        if (setHash == bytes32(0)) revert InvalidTrustAnchor();
    }

    /// @dev The anchor a verified header hands on: its next set, trusted from the next height.
    function _nextAnchor(CometBftCommitAccumulator.Header memory h) internal pure returns (bytes memory) {
        return abi.encodePacked(h.nextValidatorsHash, h.height + 1);
    }
}
