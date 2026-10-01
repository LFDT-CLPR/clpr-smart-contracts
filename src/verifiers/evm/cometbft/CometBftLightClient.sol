// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {CometBftLib} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftLib.sol";
import {CometBftProofCodec as Codec} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftProofCodec.sol";

/// @title CometBftLightClient
/// @notice The CometBFT light-client step shared by the CometBFT verifier family: authenticate a
///         validator set by its hash, rebuild a header hash, and check that more than 2/3 of the
///         set's voting power signed the canonical precommit for it. Also walks "hops" (headers
///         that move trust to the next validator set). Moved out of {CometBftVerifier} unchanged so
///         {CometBftCommitAccumulator} and the CosmWasm verifier run the same code.
///         See src/verifiers/evm/cometbft/README.md §2–§3.
abstract contract CometBftLightClient {
    // ── Types ─────────────────────────────────────────────────────────────────

    enum KeyScheme {
        ED25519,
        SECP256K1_ETH
    }

    /// @dev One validator: ED25519 → the 32-byte public key; SECP256K1_ETH → the Ethereum address
    ///      (right-aligned), derived from the 65-byte key in the hashed leaf.
    struct Validator {
        bytes32 key;
        int64 power;
    }

    // ── Constants ─────────────────────────────────────────────────────────────

    uint8 internal constant PRECOMMIT_TYPE = 2;
    uint256 internal constant SECP256K1_HALF_N = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    /// @dev CometBFT MaxTotalVotingPower = MaxInt64 / 8.
    int64 internal constant MAX_TOTAL_VOTING_POWER = type(int64).max / 8;
    uint64 internal constant MAX_VALIDATOR_POWER = uint64(type(int64).max / 8);

    // ── Profile (immutable) ───────────────────────────────────────────────────

    bytes32 public immutable CHAIN_ID_HASH;
    KeyScheme public immutable KEY_SCHEME;
    IEd25519Verifier public immutable ED25519;

    // ── Errors ────────────────────────────────────────────────────────────────

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

    constructor(bytes32 chainIdHash, KeyScheme keyScheme, address ed25519Verifier) {
        CHAIN_ID_HASH = chainIdHash;
        KEY_SCHEME = keyScheme;
        ED25519 = IEd25519Verifier(ed25519Verifier);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Hops
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
            (bytes memory valSetBytes, bytes memory signedHeader) = _parseHop(hops[i]);
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

    /// @dev ValidatorSetHop{1: ValidatorSet, 2: SignedHeader}.
    function _parseHop(bytes memory h) internal pure returns (bytes memory valSetBytes, bytes memory signedHeader) {
        uint256 off;
        while (off < h.length) {
            (uint64 fn_, uint8 wt, uint256 off2) = PB.decodeFieldKey(h, off);
            off = off2;
            if (fn_ == 1 && wt == 2) (valSetBytes, off) = PB.decodeLengthDelimited(h, off);
            else if (fn_ == 2 && wt == 2) (signedHeader, off) = PB.decodeLengthDelimited(h, off);
            else off = PB.skipField(h, off, wt);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //   Header + commit
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Chain id, validator-set binding, height floor, header hash and >2/3 commit.
    function _verifySignedHeader(
        CometBftLib.SeiHeader memory header,
        CometBftLib.SeiCommit memory commit,
        Validator[] memory vals,
        bytes32 setHash,
        uint64 minHeight
    ) internal view {
        _checkHeaderBinding(header, setHash, minHeight);
        _verifyCommit(commit, CometBftLib.headerHash(header), header, vals);
    }

    /// @dev Chain id, validator-set hash and height floor (no signatures).
    function _checkHeaderBinding(CometBftLib.SeiHeader memory header, bytes32 setHash, uint64 minHeight) internal view {
        if (keccak256(bytes(header.chainId)) != CHAIN_ID_HASH) {
            revert ChainIdMismatch();
        }
        if (header.validatorsHash != setHash) revert ValidatorSetHashMismatch();
        // forge-lint: disable-next-line(unsafe-typecast)
        if (header.height <= 0 || uint64(header.height) < minHeight) revert HeightTooOld();
    }

    /// @dev Canonical precommit sign bytes around the per-signature timestamp:
    ///      `CanonicalVote{PRECOMMIT, height, round, BlockID{hash, parts}, <timestamp>, chain_id}`.
    function _voteTemplate(CometBftLib.SeiCommit memory commit, bytes32 headerHash, CometBftLib.SeiHeader memory header)
        internal
        pure
        returns (bytes memory prefix, bytes memory suffix)
    {
        bytes memory canonicalBlockId = CometBftLib.encodeBlockId(headerHash, commit.partSetTotal, commit.partSetHash);
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

    /// @dev `signersBits` must be exactly ceil(n/8) bytes with no bit at or past n.
    function _checkSignersBits(bytes memory signersBits, uint256 n) internal pure {
        if (signersBits.length != (n + 7) / 8) revert InvalidSignersBitsLength();
        for (uint256 bit = n; bit < signersBits.length * 8; ++bit) {
            if (_bitSet(signersBits, bit)) revert SignersBitOutOfRange();
        }
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
        _checkSignersBits(commit.signersBits, n);
        (bytes memory prefix, bytes memory suffix) = _voteTemplate(commit, headerHash, header);

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

    // ─────────────────────────────────────────────────────────────────────────
    //   Validator set
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Decodes the set and requires its hash to equal `expectedHash`.
    function _parseValidatorSet(bytes memory data, bytes32 expectedHash)
        internal
        view
        returns (Validator[] memory vals)
    {
        bytes32 setHash;
        (vals, setHash) = _decodeValidatorSet(data);
        if (setHash != expectedHash) revert ValidatorSetHashMismatch();
    }

    /// @dev ValidatorSet{repeated bytes leaf = 1}: each leaf is the exact CometBFT SimpleValidator
    ///      bytes hashed into validators_hash, so the set is authenticated by hashing what was
    ///      supplied (no re-encoding) and then strictly decoded.
    function _decodeValidatorSet(bytes memory data) internal view returns (Validator[] memory vals, bytes32 setHash) {
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
        setHash = CometBftLib.simpleMerkleRoot(leaves);
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

    function _bitSet(bytes memory bits, uint256 idx) internal pure returns (bool) {
        return uint8(bits[idx / 8]) & (uint8(0x80) >> (idx % 8)) != 0;
    }
}
