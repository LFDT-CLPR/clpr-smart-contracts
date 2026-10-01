// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IEd25519Verifier} from "@hiero-ledger/clpr/verifiers/evm/sei/lib/IEd25519Verifier.sol";
import {TezosBlake2b} from "@hiero-ledger/clpr/libraries/proof/tezos/TezosBlake2b.sol";
import {TezosBls} from "@hiero-ledger/clpr/libraries/proof/tezos/TezosBls.sol";
import {TezosContextVerifier} from "@hiero-ledger/clpr/verifiers/evm/tezos/TezosContextVerifier.sol";
import {TezosKeys} from "@hiero-ledger/clpr/libraries/proof/tezos/TezosKeys.sol";
import {TezosSampler} from "@hiero-ledger/clpr/libraries/proof/tezos/TezosSampler.sol";
import {TezosSignatureCache} from "@hiero-ledger/clpr/verifiers/evm/tezos/TezosSignatureCache.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/// @title TezosLightClient
/// @notice Tezos (Tenderbake) finality and context roots, verified on Hedera.
///
/// Trust anchor: a context tree root `R_a` of a Tezos block whose state is already trusted (the
/// deploy-time checkpoint, then the root each verified bundle returns). A finality proof for level L:
///
///  1. Rights. The delegate sampler and the random seed of L's cycle are read from `R_a`
///     (`cycle/<c>/delegate_sampler_state`, `cycle/<c>/random_seed`, {TezosContextProof}). Tezos
///     fixes both `consensus_rights_delay` (2) cycles ahead, so `R_a` covers its own cycle and the
///     next two.
///  2. Payload. `P = BLAKE2b(hash(header_{L−1}) ‖ payload_round ‖ operations_hash)` — the
///     Tenderbake block payload hash, which commits to the predecessor block.
///  3. Quorum. Attestations for (L, round, P): tz1/tz2/tz3 operations signed one by one (or found
///     in {TezosSignatureCache}) and at most one tz4 `attestations_aggregate` (one BLS pairing). The
///     signers' slots are re-drawn from the sampler ({TezosSampler.countSignedSlots}) until they own
///     at least `consensus_threshold_size` (4667) of the `consensus_committee_size` (7000) slots.
///     A quorum on P makes block L−1 final (Tenderbake: a block is final once its successor's
///     payload has a quorum).
///  4. Context. `header_{L−1}.context` is the Irmin commit of the state after block L−2; the commit
///     preimage (`u64be(32) ‖ root ‖ parents ‖ info`) is hashed to it, which yields the new tree
///     root. That root becomes the next trust anchor (state level L−2).
abstract contract TezosLightClient {
    uint8 internal constant PK_ED25519 = 0;
    uint8 internal constant PK_SECP256K1 = 1;
    uint8 internal constant PK_P256 = 2;
    uint8 internal constant PK_BLS = 3;

    uint8 internal constant TAG_ATTESTATION = 21;
    uint8 internal constant TAG_ATTESTATION_WITH_DAL = 23;
    uint8 internal constant TAG_BLS_MODE_ATTESTATION = 41;
    uint8 internal constant WATERMARK_ATTESTATION = 0x13;
    /// @dev `absentStep` value for {TezosContextProof.verify} when no absence is checked.
    uint256 internal constant NO_ABSENCE = type(uint256).max;

    /// @notice Per-deployment chain parameters (read from the chain's constants at deployment).
    struct Profile {
        bytes4 chainId; // Tezos chain id (mainnet NetXdQprcVkpaWU = 0x7a06a770)
        uint8 protocolLevel; // shell-header `proto` the predecessor header must carry (25 = PsUshuai)
        uint32 eraFirstLevel; // first level of the current cycle era
        uint32 eraFirstCycle; // cycle number at eraFirstLevel
        uint32 blocksPerCycle; // blocks_per_cycle of the era
        uint16 committeeSize; // consensus_committee_size
        uint16 threshold; // consensus_threshold_size
    }

    /// @notice A tz1 / tz2 / tz3 attestation operation.
    struct Attestation {
        uint16 signer; // index of the attester's consensus key in the sampler support
        uint16 slot; // `slot` field of the signed operation
        bytes32 branch; // operation branch
        bool withDal; // tag 23 (attestation_with_dal) instead of 21
        bytes dal; // Zarith (`Data_encoding.z`) DAL bitset bytes when withDal
        bytes signature; // 64 bytes; empty = look the signature up in the cache
        bytes32 y; // tz2 / tz3: affine y of the consensus key
    }

    /// @notice A tz4 `attestations_aggregate` operation.
    struct Aggregate {
        bytes32 branch;
        uint16[] signers; // support indices of the committee members
        bytes[] keys; // 128-byte EIP-2537 consensus keys (x must match the context key)
        bytes[] dal; // per member: empty = no DAL content, else 0x01 ‖ Z.to_bits(bitset)
        bytes[] companionKeys; // 128-byte EIP-2537 companion keys for members with DAL content
        bytes signature; // 256-byte EIP-2537 G2 signature
    }

    struct FinalityProof {
        uint32 level; // attested level L
        uint32 round; // attestation round
        uint32 payloadRound;
        bytes32 operationsHash; // Operation_list_hash of the payload
        bytes predecessorHeader; // raw header of block L−1
        bytes32 contextRoot; // tree root committed by header_{L−1}.context
        bytes commitTail; // commit preimage after the root: parents ‖ info
        bytes samplerProof; // cycle/<c>/delegate_sampler_state under the anchor root
        bytes seedProof; // cycle/<c>/random_seed under the anchor root
        Attestation[] attestations;
        Aggregate[] aggregates; // at most one
    }

    error HeaderLevelMismatch();
    error ProtocolMismatch();
    error ContextCommitMismatch();
    error NotAfterAnchor();
    error BeforeEra();
    error BadSeed();
    error UnsupportedSigner(uint256 index);
    error SignerOutOfRange(uint256 index);
    error BadAttestationSignature(uint256 index);
    error SignatureNotCached(uint256 index);
    error TooManyAggregates();
    error AggregateShape();
    error BlsKeyMismatch(uint256 member);
    error QuorumNotReached(uint256 counted);
    error ZeroDependency();

    Profile internal _profile;
    IEd25519Verifier public immutable ED25519;
    TezosSignatureCache public immutable CACHE;
    TezosContextVerifier public immutable CONTEXT;

    constructor(
        Profile memory profile_,
        IEd25519Verifier ed25519,
        TezosSignatureCache cache,
        TezosContextVerifier context
    ) {
        if (address(ed25519) == address(0) || address(cache) == address(0) || address(context) == address(0)) {
            revert ZeroDependency();
        }
        _profile = profile_;
        ED25519 = ed25519;
        CACHE = cache;
        CONTEXT = context;
    }

    /// @dev Context value at `steps` under `root` (no absence check).
    function _contextValue(bytes32 root, bytes[] memory steps, bytes memory proof)
        internal
        view
        returns (bytes memory)
    {
        return CONTEXT.verify(root, steps, proof, NO_ABSENCE, bytes32(0));
    }

    function profile() external view returns (Profile memory) {
        return _profile;
    }

    // ── trust anchor ───────────────────────────────────────────────────────

    /// @notice Anchor encoding: abi.encode(uint32 stateLevel, bytes32 contextRoot).
    function encodeAnchor(uint32 stateLevel, bytes32 root) public pure returns (bytes memory) {
        return abi.encode(stateLevel, root);
    }

    function decodeAnchor(bytes memory anchor) public pure returns (uint32 stateLevel, bytes32 root) {
        return abi.decode(anchor, (uint32, bytes32));
    }

    // ── finality ───────────────────────────────────────────────────────────

    /// @notice Verify `p` from the anchor (`anchorLevel`, `anchorRoot`); returns the state level
    ///         (L−2) and tree root that are final with it.
    function _verifyFinality(FinalityProof memory p, uint32 anchorLevel, bytes32 anchorRoot)
        internal
        view
        virtual
        returns (uint32 stateLevel, bytes32 root)
    {
        Profile memory pr = _profile;
        if (p.level < 3 || p.level - 2 <= anchorLevel) revert NotAfterAnchor();
        if (p.level < pr.eraFirstLevel) revert BeforeEra();

        // 1. Rights for L's cycle, from the anchor state.
        uint256 sinceEra = p.level - pr.eraFirstLevel;
        string memory cycle = Strings.toString(pr.eraFirstCycle + sinceEra / pr.blocksPerCycle);
        // The anchor state must not schedule "all bakers attest" (`data/all_bakers_attest_first_level`
        // absent): that mode replaces sampled slots with per-delegate stake and starts at least
        // consensus_rights_delay + 1 cycles after it is recorded, i.e. after every cycle this anchor covers.
        TezosSampler.Sampler memory sampler = TezosSampler.parse(
            CONTEXT.verify(
                anchorRoot,
                _cyclePath(cycle, "delegate_sampler_state"),
                p.samplerProof,
                1,
                keccak256("all_bakers_attest_first_level")
            )
        );
        bytes memory seed = _contextValue(anchorRoot, _cyclePath(cycle, "random_seed"), p.seedProof);
        if (seed.length != 32) revert BadSeed();
        // casting is safe: seed.length == 32 is checked above.
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes32 seedWord = bytes32(seed);

        // 2. Payload hash from the predecessor header.
        bytes memory h = p.predecessorHeader;
        (uint32 hLevel, uint8 hProto, bytes32 hContext) = _parseHeader(h);
        if (hLevel != p.level - 1) revert HeaderLevelMismatch();
        if (hProto != pr.protocolLevel) revert ProtocolMismatch();
        bytes32 payload =
            TezosBlake2b.hash256(abi.encodePacked(TezosBlake2b.hash256(h), p.payloadRound, p.operationsHash));

        // 3. Quorum.
        bytes memory signer = new bytes(sampler.n);
        _checkAttestations(p, sampler, payload, signer, pr.chainId);
        _checkAggregate(p, sampler, payload, signer, pr.chainId);
        uint256 counted = TezosSampler.countSignedSlots(
            sampler, seedWord, sinceEra % pr.blocksPerCycle, pr.committeeSize, pr.threshold, signer
        );
        if (counted < pr.threshold) revert QuorumNotReached(counted);

        // 4. Context root committed by the (now final) predecessor header.
        if (TezosBlake2b.hash256(abi.encodePacked(uint64(32), p.contextRoot, p.commitTail)) != hContext) {
            revert ContextCommitMismatch();
        }
        return (p.level - 2, p.contextRoot);
    }

    /// @dev Cycle of `level` in the profile's era (levels before the era map to 0).
    function _cycleOf(uint256 level) internal view returns (uint256) {
        Profile memory pr = _profile;
        if (level < pr.eraFirstLevel) return 0;
        return pr.eraFirstCycle + (level - pr.eraFirstLevel) / pr.blocksPerCycle;
    }

    function _cyclePath(string memory cycle, string memory leaf) private pure returns (bytes[] memory steps) {
        steps = new bytes[](4);
        steps[0] = "data";
        steps[1] = "cycle";
        steps[2] = bytes(cycle);
        steps[3] = bytes(leaf);
    }

    /// @dev Shell header: level(4) proto(1) predecessor(32) timestamp(8) validation_pass(1)
    ///      operations_hash(32) fitness(u32 size ‖ …) context(32) ‖ protocol data.
    function _parseHeader(bytes memory h) private pure returns (uint32 level, uint8 proto, bytes32 context) {
        if (h.length < 82) revert HeaderLevelMismatch();
        uint256 fitnessLen;
        assembly ("memory-safe") {
            let w := mload(add(h, 0x20))
            level := shr(224, w)
            proto := byte(4, w)
            fitnessLen := shr(224, mload(add(h, add(0x20, 78))))
        }
        uint256 off = 82 + fitnessLen;
        if (h.length < off + 32) revert HeaderLevelMismatch();
        assembly ("memory-safe") {
            context := mload(add(add(h, 0x20), off))
        }
    }

    function _checkAttestations(
        FinalityProof memory p,
        TezosSampler.Sampler memory sampler,
        bytes32 payload,
        bytes memory signer,
        bytes4 chainId
    ) private view {
        for (uint256 i = 0; i < p.attestations.length; i++) {
            Attestation memory a = p.attestations[i];
            if (a.signer >= sampler.n) revert SignerOutOfRange(i);
            bytes memory contents = abi.encodePacked(
                a.withDal ? TAG_ATTESTATION_WITH_DAL : TAG_ATTESTATION, a.slot, p.level, p.round, payload
            );
            if (a.withDal) contents = bytes.concat(contents, a.dal);
            bytes32 digest = TezosBlake2b.hash256(abi.encodePacked(WATERMARK_ATTESTATION, chainId, a.branch, contents));
            (uint256 scheme, uint256 keyAt) = TezosSampler.key(sampler, a.signer);
            bool ok;
            if (a.signature.length == 0) {
                if (scheme != PK_ED25519 && scheme != PK_P256) revert SignatureNotCached(i);
                // casting is safe: scheme is a key tag byte (0..3).
                // forge-lint: disable-next-line(unsafe-typecast)
                ok = CACHE.isVerified(uint8(scheme), _copy(keyAt, scheme == PK_ED25519 ? 32 : 33), digest);
                if (!ok) revert SignatureNotCached(i);
            } else if (scheme == PK_ED25519) {
                bytes32 pk;
                assembly ("memory-safe") {
                    pk := mload(keyAt)
                }
                ok = ED25519.verify(pk, abi.encodePacked(digest), a.signature);
            } else if (scheme == PK_SECP256K1) {
                ok = TezosKeys.verifySecp256k1(keyAt, a.y, digest, a.signature);
            } else if (scheme == PK_P256) {
                ok = CACHE.checkP256(_copy(keyAt, 33), a.y, digest, a.signature);
            } else {
                // tz4 attestations must be aggregated (`aggregate_attestation` = true).
                revert UnsupportedSigner(i);
            }
            if (!ok) revert BadAttestationSignature(i);
            signer[a.signer] = 0x01;
        }
    }

    function _checkAggregate(
        FinalityProof memory p,
        TezosSampler.Sampler memory sampler,
        bytes32 payload,
        bytes memory signer,
        bytes4 chainId
    ) private view {
        if (p.aggregates.length == 0) return;
        if (p.aggregates.length > 1) revert TooManyAggregates();
        Aggregate memory g = p.aggregates[0];
        uint256 k = g.signers.length;
        if (k == 0 || g.keys.length != k || g.dal.length != k || g.companionKeys.length != k) revert AggregateShape();

        bytes memory op = abi.encodePacked(g.branch, TAG_BLS_MODE_ATTESTATION, p.level, p.round, payload);
        uint256 terms = k;
        for (uint256 j = 0; j < k; j++) {
            if (g.dal[j].length != 0) terms++;
        }
        bytes memory msm = new bytes(terms * 160);
        uint256 t = 0;
        for (uint256 j = 0; j < k; j++) {
            uint256 idx = g.signers[j];
            if (idx >= sampler.n) revert SignerOutOfRange(j);
            (uint256 scheme, uint256 keyAt) = TezosSampler.key(sampler, idx);
            if (scheme != PK_BLS) revert UnsupportedSigner(j);
            _bindBlsKey(g.keys[j], keyAt, j);
            _msmTerm(msm, t++, g.keys[j], 1);
            if (g.dal[j].length != 0) {
                uint256 compAt = TezosSampler.companion(sampler, idx);
                if (compAt == 0) revert AggregateShape();
                _bindBlsKey(g.companionKeys[j], compAt, j);
                _msmTerm(msm, t++, g.companionKeys[j], _dalWeight(keyAt, compAt, op, g.dal[j]));
            }
            signer[idx] = 0x01;
        }
        TezosBls.verifyAggregate(msm, g.signature, abi.encodePacked(WATERMARK_ATTESTATION, chainId, op));
    }

    /// @dev `Dal_dependent_signing.weight`: BLAKE2b-256(pkh(consensus) ‖ pkh(companion) ‖ op ‖ bits)
    ///      read as a little-endian integer.
    function _dalWeight(uint256 keyAt, uint256 compAt, bytes memory op, bytes memory dal)
        private
        view
        returns (uint256 z)
    {
        bytes20 a = bytes20(TezosBlake2b.hashAt(keyAt, 48, TezosBlake2b.H0_20));
        bytes20 b = bytes20(TezosBlake2b.hashAt(compAt, 48, TezosBlake2b.H0_20));
        bytes memory bits = new bytes(dal.length - 1);
        assembly ("memory-safe") {
            mcopy(add(bits, 0x20), add(dal, 0x21), mload(bits))
        }
        bytes32 hLe = TezosBlake2b.hash256(abi.encodePacked(a, b, op, bits));
        for (uint256 i = 0; i < 32; i++) {
            z |= uint256(uint8(hLe[i])) << (8 * i);
        }
    }

    /// @dev The relayer's uncompressed key must have the x coordinate of the 48-byte context key
    ///      (whose three top bits are encoding flags).
    function _bindBlsKey(bytes memory point, uint256 keyAt, uint256 member) private pure {
        if (point.length != 128) revert BlsKeyMismatch(member);
        bool ok;
        assembly ("memory-safe") {
            let px := add(point, 0x20)
            // point: 16 zero bytes ‖ x(48) ‖ 16 zero bytes ‖ y(48)
            let k0 := and(mload(keyAt), 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
            let k1 := shr(128, mload(add(keyAt, 32)))
            let x0 := mload(add(px, 16))
            let x1 := shr(128, mload(add(px, 48)))
            ok := and(and(eq(k0, x0), eq(k1, x1)), iszero(shr(128, mload(px))))
        }
        if (!ok) revert BlsKeyMismatch(member);
    }

    function _msmTerm(bytes memory msm, uint256 t, bytes memory point, uint256 scalar) private pure {
        assembly ("memory-safe") {
            let dst := add(add(msm, 0x20), mul(t, 160))
            mcopy(dst, add(point, 0x20), 128)
            mstore(add(dst, 128), scalar)
        }
    }

    function _copy(uint256 at, uint256 len) private pure returns (bytes memory out) {
        out = new bytes(len);
        assembly ("memory-safe") {
            mcopy(add(out, 0x20), at, len)
        }
    }
}
