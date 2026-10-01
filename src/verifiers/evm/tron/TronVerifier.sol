// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {TronLib} from "@hiero-ledger/clpr/verifiers/evm/tron/TronLib.sol";
import {IClprTronAttestor} from "@hiero-ledger/clpr/verifiers/evm/tron/ClprTronAttestor.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title TronVerifier
/// @notice TRON → Hiero `IClprVerifier`: a DPoS light client over TRON's 27 Super Representatives
///         (SRs) plus transaction-inclusion proofs of CLPR queue attestations.
///
/// @dev Finality. A block is accepted once at least `THRESHOLD` distinct members of the trusted SR
///      set have produced blocks on the chain from it onwards (it included), each signature
///      replayed with ecrecover. This is java-tron's solidification rule (DposService
///      .updateSolidBlock: 70 % of the active witnesses, i.e. 19 of 27).
///
///      SR set. The trust anchor commits to the set as `keccak256(witness_i || signingKey_i)` sorted
///      by witness; the set itself rides in every proof. The signing key is the witness-permission
///      address (AllowMultiSign = 1 on mainnet and Nile; 6 of 27 mainnet SRs sign with a key other
///      than their witness address). The set rotates to maintenance period p with headers from p:
///      a header h0 at or after p's maintenance block, then window headers h1..hw that name exactly
///      SR_COUNT distinct witnesses, then headers in which `THRESHOLD` distinct members of the old
///      set sign at or after hw. Periods follow java-tron's grid
///      (`MAINTENANCE_OFFSET_MS + k * MAINTENANCE_INTERVAL_MS`, DynamicPropertiesStore
///      .updateNextMaintenanceTime). A window key is accepted only if it equals the witness address,
///      the old set's key for that witness, or a key proven by an `AccountPermissionUpdateContract`
///      in a block confirmed by the current set. FN-DSA-512 (TIP-899, live on Nile) signed headers
///      are accepted as hash-chain links but never counted.
///
///      State. TRON headers commit to no account or storage state (accountStateRoot is disabled and
///      never covers storage; there is no receipts root and no eth_getProof). The queue state is
///      proven instead as a successful `IClprTronAttestor.attestQueue` call in a confirmed block:
///      `ret[0].contractRet == SUCCESS` is re-executed and enforced by every validating node.
///
///      Trust anchor: abi.encode(uint64 period, bytes32 setHash, address attestor, uint64 keyWatermark).
///
///      Bundle proof: RLP([
///        0 srSet           [[witness20, key20], ...] (SR_COUNT entries, sorted by witness),
///        1 keyUpdates      [TxProof, ...] AccountPermissionUpdateContract txs (block numbers increasing),
///        2 rotation        [] or [headers, windowEnd],
///        3 attestation     TxProof of attestQueue,
///        4 bundleContent   ClprBundleContent protobuf,
///        5 manifest        ClprEndpointManifest protobuf preimage, or empty
///      ])
///      TxProof = [headers, txBytes, index, count, siblings]; headers = [[rawHeader, sig65 | ""], ...]
///      starting at the block that contains the transaction.
contract TronVerifier is ClprEvmBundleVerifier {
    /// @notice Number of active SRs (java-tron MAX_ACTIVE_WITNESS_NUM = 27).
    uint256 public immutable SR_COUNT;
    /// @notice Distinct SR signatures needed to accept a block (19 of 27).
    uint256 public immutable THRESHOLD;
    /// @notice Maintenance period length (mainnet 21,600,000 ms; Nile 1,800,000 ms).
    uint64 public immutable MAINTENANCE_INTERVAL_MS;
    /// @notice Maintenance grid offset: maintenance times are OFFSET + k * INTERVAL (ms).
    uint64 public immutable MAINTENANCE_OFFSET_MS;
    /// @notice keccak256 of the CAIP-2 id this verifier serves, e.g. "tron:0x2b6653dc" (mainnet) or
    ///         "tron:0xcd8690dc" (Nile): the last 4 bytes of the genesis block id. TRON headers carry
    ///         no chain id, so verifyConfig pins the peer configuration's chain id instead.
    bytes32 public immutable CHAIN_ID_HASH;

    uint256 internal constant TRUST_ANCHOR_LENGTH = 128;
    uint256 internal constant BUNDLE_FIELDS = 6;
    uint256 internal constant TX_PROOF_FIELDS = 5;
    uint256 internal constant CONFIG_FIELDS = 4;
    /// @dev attestQueue calldata: selector + 9 static words.
    uint256 internal constant ATTEST_QUEUE_CALLDATA_LENGTH = 4 + 9 * 32;
    /// @dev attestManifest calldata: selector + 2 static words.
    uint256 internal constant ATTEST_MANIFEST_CALLDATA_LENGTH = 4 + 2 * 32;

    struct Anchor {
        uint64 period;
        bytes32 setHash;
        address attestor;
        uint64 keyWatermark;
    }

    /// @dev Sorted by witness. A zero key marks a witness whose signatures cannot be checked here
    ///      (e.g. it signs with FN-DSA-512); such a witness never counts toward the threshold.
    struct SrSet {
        address[] witnesses;
        address[] keys;
    }

    /// @dev Keys proven by AccountPermissionUpdateContract for witnesses outside the current set.
    struct PendingKeys {
        address[] witnesses;
        address[] keys;
        uint256 length;
    }

    error InvalidConstructorParams();
    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error SrSetHashMismatch();
    error SrSetMalformed();
    error HeaderChainBroken(uint256 index);
    error EmptyHeaderChain();
    error InsufficientConfirmations(uint256 have, uint256 need);
    error TxRootMismatch();
    error UnexpectedContractType(uint64 contractType);
    error AttestationFailed(uint64 contractRet);
    error WrongAttestor(address got);
    error WrongAttestationCall();
    error AttestedServiceMismatch();
    error AttestedChannelMismatch();
    error InvalidChannelStatus(uint8 status);
    error StaleKeyUpdate(uint64 blockNumber, uint64 watermark);
    error ZeroSigningKey();
    error RotationWindowInvalid();
    error RotationPeriodMismatch();
    error RotationStale(uint64 period, uint64 anchorPeriod);
    error RotationWitnessCount(uint256 count);
    error UnauthenticatedSignerKey(address witness, address key);
    error ConflictingSignerKeys(address witness);
    error WrongChain(string chainId);

    constructor(
        uint256 srCount,
        uint256 threshold,
        uint64 maintenanceIntervalMs,
        uint64 maintenanceOffsetMs,
        string memory chainId
    ) {
        if (
            srCount == 0 || srCount > 256 || threshold > srCount || threshold * 3 <= srCount * 2
                || maintenanceIntervalMs == 0 || maintenanceOffsetMs >= maintenanceIntervalMs
                || bytes(chainId).length == 0
        ) revert InvalidConstructorParams();
        CHAIN_ID_HASH = keccak256(bytes(chainId));
        SR_COUNT = srCount;
        THRESHOLD = threshold;
        MAINTENANCE_INTERVAL_MS = maintenanceIntervalMs;
        MAINTENANCE_OFFSET_MS = maintenanceOffsetMs;
    }

    // ── IClprVerifier ─────────────────────────────────────────────────────────

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
        Anchor memory anchor = _decodeTrustAnchor(trustAnchor);
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);

        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory p = RLP.decodeList(proofMem);
        if (p.length != BUNDLE_FIELDS) revert InvalidPayloadShape();

        (SrSet memory set, bytes32 setHash) = _decodeSrSet(p[0]);
        if (setHash != anchor.setHash) revert SrSetHashMismatch();

        // 1. Signing-key updates proven against the current set.
        bool changed;
        PendingKeys memory pending;
        (pending, changed) = _applyKeyUpdates(p[1], set, anchor);

        // 2. Optional SR-set rotation to a later maintenance period.
        Memory.Slice[] memory rotation = RLP.readList(p[2]);
        if (rotation.length != 0) {
            (set, anchor.period) = _rotate(rotation, set, pending, anchor.period);
            changed = true;
        }

        // 3. Queue attestation confirmed by the (possibly rotated) set.
        bytes32 manifestCommitment;
        (metadata, manifestCommitment) = _verifyQueueAttestation(p[3], set, anchor.attestor, ctx);

        // 4. Message payloads. BundleLib binds them to metadata.sentRunningHash.
        messagePayloads = _decodeBundleContent(RLP.readBytes(p[4]));

        // 5. Optional endpoint-manifest update, bound to the attested commitment.
        bytes memory manifestPreimage = RLP.readBytes(p[5]);
        newEndpointManifest = manifestPreimage.length == 0
            ? _absentEndpointManifest()
            : _bindManifest(manifestPreimage, manifestCommitment, ctx.remoteServiceAddress);

        if (changed) {
            newTrustAnchor = abi.encode(anchor.period, _hashSrSet(set), anchor.attestor, anchor.keyWatermark);
            newTrustAnchorId = abi.encodePacked(anchor.period);
        }
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProof = RLP([srSet, attestor20, headers, ledgerConfigControlMessage]).
    ///      The SR set and attestor are the channel's weak-subjectivity inputs (as for every light
    ///      client); `headers` must carry THRESHOLD distinct signatures from that set as a sanity
    ///      check, and fix the starting period and key-update watermark.
    ///      endpointManifestProof = RLP([attestManifest TxProof, manifestPreimage]) or empty.
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
        if (cfg.length != CONFIG_FIELDS) revert InvalidPayloadShape();

        (SrSet memory set, bytes32 setHash) = _decodeSrSet(cfg[0]);
        address attestor = RLP.readAddress(cfg[1]);

        (TronLib.Header[] memory hs, address[] memory signers) = _parseHeaders(cfg[2]);
        _requireConfirmed(hs, signers, 0, set);

        ClprTypes.LedgerConfiguration memory lc = ClprProtobuf.decodeControlMessage(RLP.readBytes(cfg[3])).config;
        if (keccak256(bytes(lc.chainId)) != CHAIN_ID_HASH) revert WrongChain(lc.chainId);
        serviceAddress = lc.serviceAddress;
        _toAddress(serviceAddress); // a TRON service is addressed by its 20-byte EVM-form address

        uint64 period = _period(hs[0].timestamp);
        initialTrustAnchor = abi.encode(period, setHash, attestor, hs[hs.length - 1].number);
        initialTrustAnchorId = abi.encodePacked(period);
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        endpointManifest = endpointManifestProofBytes.length == 0
            ? _uninitializedEndpointManifest(serviceAddress)
            : _verifyConfigManifest(endpointManifestProofBytes, set, attestor, serviceAddress);
        return (
            channelContext,
            lc.chainId,
            serviceAddress,
            lc.nanosSinceEpoch,
            lc.throttles,
            initialTrustAnchor,
            initialTrustAnchorId,
            endpointManifest
        );
    }

    // ── Headers and confirmations ─────────────────────────────────────────────

    /// @dev Parse [[raw, sig], ...], enforce parent-hash links, consecutive numbers and increasing
    ///      timestamps, and recover each ECDSA signer (address(0) when absent or invalid).
    function _parseHeaders(Memory.Slice item)
        internal
        pure
        returns (TronLib.Header[] memory hs, address[] memory signers)
    {
        Memory.Slice[] memory list = RLP.readList(item);
        if (list.length == 0) revert EmptyHeaderChain();
        hs = new TronLib.Header[](list.length);
        signers = new address[](list.length);
        for (uint256 i = 0; i < list.length; ++i) {
            Memory.Slice[] memory pair = RLP.readList(list[i]);
            if (pair.length != 2) revert InvalidPayloadShape();
            hs[i] = TronLib.parseHeader(RLP.readBytes(pair[0]));
            signers[i] = TronLib.recoverSigner(hs[i].rawHash, RLP.readBytes(pair[1]));
            if (i > 0) {
                TronLib.Header memory prev = hs[i - 1];
                if (
                    hs[i].parentHash != TronLib.blockId(prev) || uint256(hs[i].number) != uint256(prev.number) + 1
                        || hs[i].timestamp <= prev.timestamp
                ) revert HeaderChainBroken(i);
            }
        }
    }

    /// @dev Distinct set members whose header at index >= `from` carries a valid signature by the
    ///      set's signing key for that header's witness.
    function _countEndorsers(TronLib.Header[] memory hs, address[] memory signers, uint256 from, SrSet memory set)
        internal
        pure
        returns (uint256 count)
    {
        uint256 seen;
        for (uint256 i = from; i < hs.length; ++i) {
            address signer = signers[i];
            if (signer == address(0)) continue;
            (bool found, uint256 idx) = _indexOf(set.witnesses, hs[i].witness);
            if (!found || set.keys[idx] != signer) continue;
            // forge-lint: disable-next-line(incorrect-shift)
            uint256 bit = 1 << idx; // bit `idx` of the bitmap; idx < SR_COUNT <= 256
            if (seen & bit == 0) {
                seen |= bit;
                ++count;
            }
        }
    }

    function _requireConfirmed(TronLib.Header[] memory hs, address[] memory signers, uint256 from, SrSet memory set)
        internal
        view
    {
        uint256 have = _countEndorsers(hs, signers, from, set);
        if (have < THRESHOLD) revert InsufficientConfirmations(have, THRESHOLD);
    }

    /// @dev Verify a TxProof: the header chain is confirmed by the set and the transaction is in the
    ///      first header's txTrieRoot. Returns that header and the transaction bytes.
    function _confirmTx(Memory.Slice item, SrSet memory set)
        internal
        view
        returns (TronLib.Header memory target, bytes memory txBytes)
    {
        Memory.Slice[] memory tp = RLP.readList(item);
        if (tp.length != TX_PROOF_FIELDS) revert InvalidPayloadShape();
        (TronLib.Header[] memory hs, address[] memory signers) = _parseHeaders(tp[0]);
        _requireConfirmed(hs, signers, 0, set);
        target = hs[0];

        txBytes = RLP.readBytes(tp[1]);
        Memory.Slice[] memory sibItems = RLP.readList(tp[4]);
        bytes32[] memory siblings = new bytes32[](sibItems.length);
        for (uint256 i = 0; i < sibItems.length; ++i) {
            siblings[i] = RLP.readBytes32(sibItems[i]);
        }
        bytes32 root =
            TronLib.txMerkleRoot(TronLib.txLeaf(txBytes), RLP.readUint256(tp[2]), RLP.readUint256(tp[3]), siblings);
        if (root != target.txTrieRoot) revert TxRootMismatch();
    }

    // ── SR-set maintenance ────────────────────────────────────────────────────

    /// @dev Apply proven witness-permission changes in increasing block order above the anchor's
    ///      watermark (so an older permission update cannot be replayed over a newer one).
    function _applyKeyUpdates(Memory.Slice item, SrSet memory set, Anchor memory anchor)
        internal
        view
        returns (PendingKeys memory pending, bool changed)
    {
        Memory.Slice[] memory updates = RLP.readList(item);
        pending.witnesses = new address[](updates.length);
        pending.keys = new address[](updates.length);
        for (uint256 i = 0; i < updates.length; ++i) {
            (TronLib.Header memory h, bytes memory txBytes) = _confirmTx(updates[i], set);
            if (h.number <= anchor.keyWatermark) revert StaleKeyUpdate(h.number, anchor.keyWatermark);
            anchor.keyWatermark = h.number;

            (uint64 ctype, bytes memory param,) = TronLib.parseTransaction(txBytes);
            if (ctype != TronLib.ACCOUNT_PERMISSION_UPDATE_CONTRACT) revert UnexpectedContractType(ctype);
            // System contracts that fail validation make the whole block invalid, so inclusion
            // in a confirmed block implies the update was applied.
            (address witness, address key) = TronLib.parsePermissionUpdate(param);
            if (key == address(0)) revert ZeroSigningKey();

            (bool found, uint256 idx) = _indexOf(set.witnesses, witness);
            if (found) {
                set.keys[idx] = key;
            } else {
                _setPending(pending, witness, key);
            }
            changed = true;
        }
    }

    /// @dev Rotate to the set of maintenance period p. See the contract notes for the rules.
    function _rotate(
        Memory.Slice[] memory rotation,
        SrSet memory oldSet,
        PendingKeys memory pending,
        uint64 anchorPeriod
    ) internal view returns (SrSet memory next, uint64 period) {
        if (rotation.length != 2) revert InvalidPayloadShape();
        (TronLib.Header[] memory hs, address[] memory signers) = _parseHeaders(rotation[0]);
        uint256 w = RLP.readUint256(rotation[1]);
        if (w == 0 || w >= hs.length) revert RotationWindowInvalid();

        // h0 sits at or after p's maintenance block and hw before p+1's, so h1..hw were all scheduled
        // from p's active-witness list (timestamps increase along the chain).
        period = _period(hs[w].timestamp);
        if (_period(hs[0].timestamp) != period) revert RotationPeriodMismatch();
        if (period < anchorPeriod) revert RotationStale(period, anchorPeriod);

        // The old set must confirm the window's last block.
        _requireConfirmed(hs, signers, w, oldSet);

        next.witnesses = new address[](SR_COUNT);
        next.keys = new address[](SR_COUNT);
        uint256 n;
        for (uint256 i = 1; i <= w; ++i) {
            address witness = hs[i].witness;
            uint256 j;
            while (j < n && next.witnesses[j] != witness) ++j;
            if (j == n) {
                if (n == SR_COUNT) revert RotationWitnessCount(n + 1);
                next.witnesses[n++] = witness;
            }
            address key = signers[i];
            if (key == address(0)) continue;
            if (!_keyAuthenticated(witness, key, oldSet, pending)) revert UnauthenticatedSignerKey(witness, key);
            if (next.keys[j] != address(0) && next.keys[j] != key) revert ConflictingSignerKeys(witness);
            next.keys[j] = key;
        }
        if (n != SR_COUNT) revert RotationWitnessCount(n);

        // Witnesses with no checked signature in the window keep their known key, if any.
        for (uint256 j = 0; j < n; ++j) {
            if (next.keys[j] != address(0)) continue;
            (bool found, uint256 idx) = _indexOf(oldSet.witnesses, next.witnesses[j]);
            if (found) next.keys[j] = oldSet.keys[idx];
            else next.keys[j] = _pendingKey(pending, next.witnesses[j]);
        }
        _sortSet(next);
    }

    function _keyAuthenticated(address witness, address key, SrSet memory oldSet, PendingKeys memory pending)
        internal
        pure
        returns (bool)
    {
        if (key == witness) return true;
        (bool found, uint256 idx) = _indexOf(oldSet.witnesses, witness);
        if (found && oldSet.keys[idx] == key) return true;
        return _pendingKey(pending, witness) == key;
    }

    // ── Attestations ─────────────────────────────────────────────────────────

    function _verifyQueueAttestation(
        Memory.Slice item,
        SrSet memory set,
        address attestor,
        ClprTypes.ChannelContext memory ctx
    ) internal view returns (ClprTypes.QueueMetadata memory metadata, bytes32 manifestCommitment) {
        bytes memory args = _attestationArgs(item, set, attestor, IClprTronAttestor.attestQueue.selector);
        if (args.length != ATTEST_QUEUE_CALLDATA_LENGTH - 4) revert WrongAttestationCall();
        (
            address service,
            bytes32 channelId,
            uint8 status,
            uint64 nextMessageId,
            bytes32 sentRunningHash,
            uint64 receivedMessageId,
            bytes32 receivedRunningHash,
            uint64 endpointManifestVersion,
            bytes32 commitment
        ) = abi.decode(args, (address, bytes32, uint8, uint64, bytes32, uint64, bytes32, uint64, bytes32));
        if (service != _toAddress(ctx.remoteServiceAddress)) revert AttestedServiceMismatch();
        if (channelId != ctx.channelId) revert AttestedChannelMismatch();
        if (status > uint8(type(ClprTypes.ChannelStatus).max)) revert InvalidChannelStatus(status);
        metadata = ClprTypes.QueueMetadata({
            nextMessageId: nextMessageId,
            sentRunningHash: sentRunningHash,
            receivedMessageId: receivedMessageId,
            receivedRunningHash: receivedRunningHash,
            state: ClprTypes.ChannelStatus(status),
            endpointManifestVersion: endpointManifestVersion
        });
        manifestCommitment = commitment;
    }

    function _verifyConfigManifest(
        bytes calldata proofBytes,
        SrSet memory set,
        address attestor,
        bytes memory serviceAddress
    ) internal view returns (ClprTypes.ClprEndpointManifest memory) {
        bytes memory mem = proofBytes;
        Memory.Slice[] memory p = RLP.decodeList(mem);
        if (p.length != 2) revert InvalidPayloadShape();
        bytes memory args = _attestationArgs(p[0], set, attestor, IClprTronAttestor.attestManifest.selector);
        if (args.length != ATTEST_MANIFEST_CALLDATA_LENGTH - 4) revert WrongAttestationCall();
        (address service, bytes32 commitment) = abi.decode(args, (address, bytes32));
        if (service != _toAddress(serviceAddress)) revert AttestedServiceMismatch();
        return _bindManifest(RLP.readBytes(p[1]), commitment, serviceAddress);
    }

    /// @dev Confirm a TriggerSmartContract tx to `attestor` that succeeded, check its selector and
    ///      return the ABI-encoded arguments.
    function _attestationArgs(Memory.Slice item, SrSet memory set, address attestor, bytes4 selector)
        internal
        view
        returns (bytes memory args)
    {
        (, bytes memory txBytes) = _confirmTx(item, set);
        (uint64 ctype, bytes memory param, uint64 contractRet) = TronLib.parseTransaction(txBytes);
        if (ctype != TronLib.TRIGGER_SMART_CONTRACT) revert UnexpectedContractType(ctype);
        if (contractRet != TronLib.CONTRACT_RESULT_SUCCESS) revert AttestationFailed(contractRet);
        (address target, bytes memory data) = TronLib.parseTrigger(param);
        if (target != attestor) revert WrongAttestor(target);
        // casting to 'bytes4' is safe because data.length >= 4 is checked first (short-circuit)
        // forge-lint: disable-next-line(unsafe-typecast)
        if (data.length < 4 || bytes4(data) != selector) revert WrongAttestationCall();
        args = new bytes(data.length - 4);
        for (uint256 i = 0; i < args.length; ++i) {
            args[i] = data[i + 4];
        }
    }

    function _bindManifest(bytes memory preimage, bytes32 commitment, bytes memory expectedServiceAddress)
        internal
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

    // ── SR set encoding ───────────────────────────────────────────────────────

    function _decodeSrSet(Memory.Slice item) internal view returns (SrSet memory set, bytes32 setHash) {
        Memory.Slice[] memory entries = RLP.readList(item);
        if (entries.length != SR_COUNT) revert SrSetMalformed();
        set.witnesses = new address[](SR_COUNT);
        set.keys = new address[](SR_COUNT);
        for (uint256 i = 0; i < SR_COUNT; ++i) {
            Memory.Slice[] memory e = RLP.readList(entries[i]);
            if (e.length != 2) revert SrSetMalformed();
            set.witnesses[i] = RLP.readAddress(e[0]);
            set.keys[i] = RLP.readAddress(e[1]);
            if (set.witnesses[i] == address(0)) revert SrSetMalformed();
            if (i > 0 && set.witnesses[i] <= set.witnesses[i - 1]) revert SrSetMalformed();
        }
        setHash = _hashSrSet(set);
    }

    /// @notice keccak256(witness_0 || key_0 || witness_1 || key_1 || ...), 40 bytes per SR.
    function _hashSrSet(SrSet memory set) internal pure returns (bytes32) {
        bytes memory packed = new bytes(set.witnesses.length * 40);
        for (uint256 i = 0; i < set.witnesses.length; ++i) {
            address w = set.witnesses[i];
            address k = set.keys[i];
            assembly ("memory-safe") {
                let ptr := add(add(packed, 0x20), mul(i, 40))
                mstore(ptr, shl(96, w))
                mstore(add(ptr, 20), shl(96, k))
            }
        }
        return keccak256(packed);
    }

    function _indexOf(address[] memory sorted, address w) internal pure returns (bool, uint256) {
        uint256 lo = 0;
        uint256 hi = sorted.length;
        while (lo < hi) {
            uint256 mid = (lo + hi) >> 1;
            address v = sorted[mid];
            if (v == w) return (true, mid);
            if (v < w) lo = mid + 1;
            else hi = mid;
        }
        return (false, 0);
    }

    function _sortSet(SrSet memory set) internal pure {
        for (uint256 i = 1; i < set.witnesses.length; ++i) {
            address w = set.witnesses[i];
            address k = set.keys[i];
            uint256 j = i;
            while (j > 0 && set.witnesses[j - 1] > w) {
                set.witnesses[j] = set.witnesses[j - 1];
                set.keys[j] = set.keys[j - 1];
                --j;
            }
            set.witnesses[j] = w;
            set.keys[j] = k;
        }
    }

    function _setPending(PendingKeys memory pending, address witness, address key) internal pure {
        for (uint256 i = 0; i < pending.length; ++i) {
            if (pending.witnesses[i] == witness) {
                pending.keys[i] = key;
                return;
            }
        }
        pending.witnesses[pending.length] = witness;
        pending.keys[pending.length] = key;
        ++pending.length;
    }

    function _pendingKey(PendingKeys memory pending, address witness) internal pure returns (address) {
        for (uint256 i = 0; i < pending.length; ++i) {
            if (pending.witnesses[i] == witness) return pending.keys[i];
        }
        return address(0);
    }

    // ── Misc ──────────────────────────────────────────────────────────────────

    /// @notice Maintenance period index of a block timestamp (ms).
    function _period(uint64 timestampMs) internal view returns (uint64) {
        if (timestampMs < MAINTENANCE_OFFSET_MS) return 0;
        return (timestampMs - MAINTENANCE_OFFSET_MS) / MAINTENANCE_INTERVAL_MS;
    }

    function _decodeTrustAnchor(bytes calldata trustAnchor) internal pure returns (Anchor memory a) {
        if (trustAnchor.length != TRUST_ANCHOR_LENGTH) revert InvalidTrustAnchor();
        (a.period, a.setHash, a.attestor, a.keyWatermark) = abi.decode(trustAnchor, (uint64, bytes32, address, uint64));
    }
}
