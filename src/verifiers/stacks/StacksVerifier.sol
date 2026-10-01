// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClarityCodec} from "@hiero-ledger/clpr/libraries/proof/stacks/ClarityCodec.sol";
import {NakamotoHeader} from "@hiero-ledger/clpr/libraries/proof/stacks/NakamotoHeader.sol";
import {StacksMarf} from "@hiero-ledger/clpr/libraries/proof/stacks/StacksMarf.sol";

/// @title StacksVerifier
/// @notice Stacks → Hiero CLPR verifier. Stacks (Nakamoto) blocks are final once at least 70% of the
///         reward cycle's signer weight has signed them; the signer set comes from Stacking (PoX), and
///         the PoX anchoring to Bitcoin is NOT checked here. Trust therefore rests on the signer set,
///         not on Bitcoin proof-of-work.
///
///         A bundle proves the CLPR queue record of a Clarity CLPR service contract through the
///         block's MARF state root. Signer sets rotate every reward cycle (2,100 Bitcoin blocks);
///         {registerRotation} proves the next cycle's set from `.signers` `cycle-signer-set` in a
///         block signed by the current set and records the hop. See README.md in this directory.
///
/// Trust anchor: ABI-encoded {Anchor}. Signer sets are passed in full with each proof and checked
/// against the anchor's hash (or a recorded successor of it).
contract StacksVerifier is ClprEvmBundleVerifier {
    // ── Types ────────────────────────────────────────────────────────────────

    /// @notice A reward cycle's signers in reward-set order: ecrecover address of each signing key
    ///         and its weight (stacks-core `NakamotoSignerEntry`).
    struct SignerSet {
        uint64 cycle;
        address[] signers;
        uint64[] weights;
    }

    struct Anchor {
        uint64 cycle;
        bytes32 signerSetHash; // keccak256(abi.encode(SignerSet))
        uint64 lastChainLength; // chain length of the last proven block; the next must be higher
    }

    /// @notice A block header without its signer signatures (the block-hash preimage) and the
    ///         signatures as `index(2) ‖ recid ‖ r ‖ s`, ascending signer index.
    struct SignedHeader {
        bytes header;
        bytes signatures;
    }

    /// @notice The queue record a Clarity CLPR service keeps per channel (map `clpr-queue`, key
    ///         `(buff 32)` channel id). Its fields are proven, not trusted.
    struct QueueRecord {
        uint64 nextMessageId;
        bytes32 sentRunningHash;
        uint64 receivedMessageId;
        bytes32 receivedRunningHash;
        uint8 status;
        uint64 endpointManifestVersion;
    }

    /// @notice `proofBytes` of {verifyBundle}.
    struct BundleProof {
        SignerSet signerSet; // the anchor's set or a recorded successor of it
        SignedHeader block; // a block signed by that set, whose state holds the record
        bytes marfProof; // TrieMerkleProof of the record, as served by the node
        bytes[] bindings; // header preimages of older tries the proof passes through (often none)
        QueueRecord record;
        bytes bundleContent; // ClprBundleContent protobuf
    }

    /// @notice `configProofBytes` of {verifyConfig}.
    struct ConfigProof {
        SignerSet signerSet; // the deployment set or a recorded successor of it
        SignedHeader block;
        bytes servicePrincipal; // Clarity contract principal, e.g. "SP….clpr-service"
        uint96 peerConfigNanos;
        ClprTypes.Throttles throttles;
    }

    /// @notice `endpointManifestProofBytes` of {verifyConfig}: the manifest and the MARF proof of the
    ///         service's `clpr-manifest-commitment` data-var (keccak256 of the preimage), at the
    ///         config block.
    struct ConfigManifestProof {
        bytes manifestPreimage; // ClprEndpointManifest protobuf
        bytes marfProof;
        bytes[] bindings;
    }

    /// @notice An uncompressed secp256k1 public key.
    struct PublicKey {
        bytes32 x;
        bytes32 y;
    }

    /// @notice Input of {registerRotation}.
    struct RotationProof {
        SignerSet current; // cycle N
        SignedHeader block; // a block signed by cycle N's set
        bytes marfProof; // `.signers` cycle-signer-set[N+1] in that block's state
        bytes[] bindings;
        bytes signerList; // the entry's stored value: serialize(some(list {signer, weight}))
        PublicKey[] nextKeys; // the keys behind each listed hash160, same order
    }

    // ── Events and errors ────────────────────────────────────────────────────

    event RotationRegistered(
        bytes32 indexed fromSet, bytes32 indexed toSet, uint64 toCycle, bytes32 blockId, uint64 chainLength
    );

    error StacksBadParams();
    error SignerSetUnknown();
    error ConflictingRotation(bytes32 recorded, bytes32 proven);
    error NextKeyCountMismatch();
    error NextKeyNotOnCurve(uint256 index);
    error NextKeyHashMismatch(uint256 index);
    error StaleBlock(uint64 chainLength, uint64 lastChainLength);
    error BadServicePrincipal();

    // ── Configuration ────────────────────────────────────────────────────────

    /// @dev secp256k1 field prime.
    uint256 private constant P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    /// @notice How many recorded rotations a proof may skip ahead of its anchor (one per ~2 weeks).
    uint256 public constant MAX_HOPS = 64;
    /// @notice Map that holds the CLPR queue record in the service contract.
    bytes public constant QUEUE_MAP = "clpr-queue";
    /// @notice Data-var that holds keccak256 of the service's endpoint manifest, a `(buff 32)`.
    bytes public constant MANIFEST_VAR = "clpr-manifest-commitment";

    address public immutable HASHER;
    uint8 public immutable PRINCIPAL_VERSION; // p2pkh version byte of signer principals (22 mainnet, 26 testnet)
    bytes32 public immutable GENESIS_SET_HASH;
    uint64 public immutable GENESIS_CYCLE;
    string internal chainIdString; // CAIP-2, "stacks:1" (mainnet) or "stacks:2147483648" (testnet)
    bytes internal signersContract; // "SP000000000000000000002Q6VF78.signers" on mainnet

    /// @notice Signer-set hash → hash of the next cycle's set, proven by {registerRotation}.
    mapping(bytes32 => bytes32) public successorOf;

    /// @param hasher a deployed {ClprSha512t256Hasher}
    /// @param chainId CAIP-2 chain id
    /// @param signersContract_ principal of the `.signers` boot contract
    /// @param principalVersion p2pkh version byte of signer principals
    /// @param genesis the deployment signer set, read by the deployer from `/v3/stacker_set/{cycle}`
    constructor(
        address hasher,
        string memory chainId,
        string memory signersContract_,
        uint8 principalVersion,
        SignerSet memory genesis
    ) {
        if (hasher.code.length == 0 || genesis.signers.length == 0 || genesis.signers.length != genesis.weights.length)
        {
            revert StacksBadParams();
        }
        HASHER = hasher;
        chainIdString = chainId;
        signersContract = bytes(signersContract_);
        PRINCIPAL_VERSION = principalVersion;
        GENESIS_SET_HASH = setHash(genesis);
        GENESIS_CYCLE = genesis.cycle;
    }

    // ── IClprVerifier ────────────────────────────────────────────────────────

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
        Anchor memory anchor = abi.decode(trustAnchor, (Anchor));
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        BundleProof memory p = abi.decode(proofBytes, (BundleProof));

        bytes32 sh = _resolveSet(anchor.signerSetHash, p.signerSet);
        NakamotoHeader.Header memory h = _verifySigned(p.signerSet, p.block);
        if (h.chainLength <= anchor.lastChainLength) revert StaleBlock(h.chainLength, anchor.lastChainLength);

        bytes32 path =
            ClarityCodec.mapEntryPath(HASHER, ctx.remoteServiceAddress, QUEUE_MAP, ClarityCodec.buff32(ctx.channelId));
        bytes32 value = ClarityCodec.valueHash(HASHER, queueRecordValue(p.record));
        StacksMarf.verify(HASHER, p.marfProof, path, value, h.stateIndexRoot, p.bindings);

        metadata = ClprTypes.QueueMetadata({
            nextMessageId: p.record.nextMessageId,
            sentRunningHash: p.record.sentRunningHash,
            receivedMessageId: p.record.receivedMessageId,
            receivedRunningHash: p.record.receivedRunningHash,
            state: ClprTypes.ChannelStatus(p.record.status),
            endpointManifestVersion: p.record.endpointManifestVersion
        });
        messagePayloads = _decodeBundleContent(p.bundleContent);
        newEndpointManifest = _absentEndpointManifest();
        newTrustAnchor =
            abi.encode(Anchor({cycle: p.signerSet.cycle, signerSetHash: sh, lastChainLength: h.chainLength}));
        newTrustAnchorId = abi.encodePacked(h.blockId);
    }

    /// @inheritdoc IClprVerifier
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
        ConfigProof memory c = abi.decode(configProofBytes, (ConfigProof));
        bytes32 sh = _resolveSet(GENESIS_SET_HASH, c.signerSet);
        NakamotoHeader.Header memory h = _verifySigned(c.signerSet, c.block);
        _checkPrincipal(c.servicePrincipal);

        serviceAddress = c.servicePrincipal;
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        chainId = chainIdString;
        peerConfigNanos = c.peerConfigNanos;
        throttles = c.throttles;
        // lastChainLength 0: the record may have been written before this block.
        initialTrustAnchor = abi.encode(Anchor({cycle: c.signerSet.cycle, signerSetHash: sh, lastChainLength: 0}));
        initialTrustAnchorId = abi.encodePacked(h.blockId);
        if (endpointManifestProofBytes.length == 0) {
            endpointManifest = _uninitializedEndpointManifest(serviceAddress);
        } else {
            ConfigManifestProof memory m = abi.decode(endpointManifestProofBytes, (ConfigManifestProof));
            endpointManifest = _verifyStacksManifest(h.stateIndexRoot, serviceAddress, m);
        }
    }

    /// @dev Prove the service's manifest commitment (a `(buff 32)` data-var, Clarity key
    ///      `vm::<service>::1::clpr-manifest-commitment`) and bind the preimage to it.
    function _verifyStacksManifest(bytes32 stateRoot, bytes memory service, ConfigManifestProof memory m)
        internal
        view
        returns (ClprTypes.ClprEndpointManifest memory manifest)
    {
        bytes32 path = _sha512t256(bytes.concat("vm::", service, "::1::", MANIFEST_VAR));
        bytes32 value = ClarityCodec.valueHash(HASHER, ClarityCodec.buff32(keccak256(m.manifestPreimage)));
        StacksMarf.verify(HASHER, m.marfProof, path, value, stateRoot, m.bindings);
        manifest = ClprProtobuf.decodeEndpointManifest(m.manifestPreimage);
        if (manifest.version == 0) revert ManifestVersionZero();
        if (keccak256(manifest.serviceAddress) != keccak256(service)) revert ManifestServiceAddressMismatch();
    }

    // ── Signer-set rotation ──────────────────────────────────────────────────

    /// @notice Record that `r.current` (cycle N) signed a block whose state names the signer set of
    ///         cycle N+1. Permissionless: a record only links two set hashes, and a proof is accepted
    ///         only when its set is the anchor's or reachable from it through such links.
    /// @return nextHash hash of the proven cycle N+1 set
    function registerRotation(RotationProof calldata r) external returns (bytes32 nextHash) {
        SignerSet memory current = r.current;
        bytes32 currentHash = setHash(current);
        NakamotoHeader.Header memory h = _verifySigned(current, r.block);

        bytes memory key = ClarityCodec.uintValue(uint128(current.cycle) + 1);
        bytes32 path = ClarityCodec.mapEntryPath(HASHER, signersContract, "cycle-signer-set", key);
        StacksMarf.verify(
            HASHER, r.marfProof, path, ClarityCodec.valueHash(HASHER, r.signerList), h.stateIndexRoot, r.bindings
        );

        (bytes20[] memory keyHashes, uint64[] memory weights) =
            ClarityCodec.parseSignerList(r.signerList, PRINCIPAL_VERSION);
        if (r.nextKeys.length != keyHashes.length) revert NextKeyCountMismatch();
        address[] memory signers = new address[](keyHashes.length);
        for (uint256 i = 0; i < keyHashes.length; ++i) {
            signers[i] = _signerAddress(r.nextKeys[i], keyHashes[i], i);
        }
        SignerSet memory next = SignerSet({cycle: current.cycle + 1, signers: signers, weights: weights});
        nextHash = setHash(next);

        bytes32 recorded = successorOf[currentHash];
        if (recorded == bytes32(0)) {
            successorOf[currentHash] = nextHash;
            emit RotationRegistered(currentHash, nextHash, next.cycle, h.blockId, h.chainLength);
        } else if (recorded != nextHash) {
            revert ConflictingRotation(recorded, nextHash);
        }
    }

    // ── Generic entry point (live tests, tooling) ────────────────────────────

    /// @notice Prove any MARF entry (`key` string, stored `value` serialization) at a block signed by
    ///         `set`, where `set` is the anchor's or reachable from it. Same checks as {verifyBundle}
    ///         without the CLPR record and chain-length rules.
    function verifyEntry(
        bytes calldata trustAnchor,
        SignerSet calldata set,
        SignedHeader calldata block_,
        bytes calldata marfProof,
        bytes[] calldata bindings,
        bytes calldata key,
        bytes calldata value
    ) external view returns (bytes32 blockId, uint64 chainLength, uint256 segments) {
        Anchor memory anchor = abi.decode(trustAnchor, (Anchor));
        SignerSet memory s = set;
        _resolveSet(anchor.signerSetHash, s);
        NakamotoHeader.Header memory h = _verifySigned(s, block_);
        segments = StacksMarf.verify(
            HASHER, marfProof, _sha512t256(key), ClarityCodec.valueHash(HASHER, value), h.stateIndexRoot, bindings
        );
        return (h.blockId, h.chainLength, segments);
    }

    // ── Helpers (public for relayers and tests) ──────────────────────────────

    function setHash(SignerSet memory s) public pure returns (bytes32) {
        return keccak256(abi.encode(s));
    }

    /// @notice Serialized `some({endpoint-manifest-version: uint, next-message-id: uint,
    ///         received-message-id: uint, received-running-hash: (buff 32), sent-running-hash: (buff 32),
    ///         status: uint})` — tuple fields in name order, as Clarity stores them.
    function queueRecordValue(QueueRecord memory q) public pure returns (bytes memory) {
        return bytes.concat(
            abi.encodePacked(uint8(0x0a), uint8(0x0c), uint32(6)),
            abi.encodePacked(uint8(25), "endpoint-manifest-version", ClarityCodec.uintValue(q.endpointManifestVersion)),
            abi.encodePacked(uint8(15), "next-message-id", ClarityCodec.uintValue(q.nextMessageId)),
            abi.encodePacked(uint8(19), "received-message-id", ClarityCodec.uintValue(q.receivedMessageId)),
            abi.encodePacked(uint8(21), "received-running-hash", ClarityCodec.buff32(q.receivedRunningHash)),
            abi.encodePacked(uint8(17), "sent-running-hash", ClarityCodec.buff32(q.sentRunningHash)),
            abi.encodePacked(uint8(6), "status", ClarityCodec.uintValue(q.status))
        );
    }

    // ── Internals ────────────────────────────────────────────────────────────

    /// @dev The hash of `s`, which must be `anchorSet` or reachable from it via {successorOf}.
    function _resolveSet(bytes32 anchorSet, SignerSet memory s) internal view returns (bytes32 sh) {
        sh = setHash(s);
        bytes32 cur = anchorSet;
        for (uint256 i = 0; i <= MAX_HOPS; ++i) {
            if (cur == sh) return sh;
            cur = successorOf[cur];
            if (cur == bytes32(0)) break;
        }
        revert SignerSetUnknown();
    }

    function _verifySigned(SignerSet memory s, SignedHeader memory b)
        internal
        view
        returns (NakamotoHeader.Header memory h)
    {
        h = NakamotoHeader.parse(HASHER, b.header);
        NakamotoHeader.verifySigners(h.blockHash, s.signers, s.weights, b.signatures);
    }

    /// @dev ecrecover address of an uncompressed key whose compressed form hashes (hash160) to `h160`.
    function _signerAddress(PublicKey calldata k, bytes20 h160, uint256 i) private pure returns (address) {
        uint256 x = uint256(k.x);
        uint256 y = uint256(k.y);
        if (x >= P || y >= P || mulmod(y, y, P) != addmod(mulmod(mulmod(x, x, P), x, P), 7, P)) {
            revert NextKeyNotOnCurve(i);
        }
        bytes memory compressed = abi.encodePacked(uint8(2 + (y & 1)), k.x);
        if (ripemd160(abi.encodePacked(sha256(compressed))) != h160) revert NextKeyHashMismatch(i);
        return address(uint160(uint256(keccak256(abi.encodePacked(k.x, k.y)))));
    }

    /// @dev "<address>.<name>": c32 address characters, one dot, Clarity name characters.
    function _checkPrincipal(bytes memory s) private pure {
        uint256 n = s.length;
        if (n < 3 || n > 171) revert BadServicePrincipal();
        uint256 dots;
        for (uint256 i = 0; i < n; ++i) {
            bytes1 c = s[i];
            if (c == ".") {
                ++dots;
                continue;
            }
            bool ok = (c >= "0" && c <= "9") || (c >= "A" && c <= "Z") || (c >= "a" && c <= "z") || c == "-" || c == "_";
            if (!ok) revert BadServicePrincipal();
        }
        if (dots != 1 || s[0] == "." || s[n - 1] == ".") revert BadServicePrincipal();
    }

    function _sha512t256(bytes memory b) private view returns (bytes32 out) {
        address hasher = HASHER;
        bool ok;
        assembly ("memory-safe") {
            ok := staticcall(gas(), hasher, add(b, 0x20), mload(b), 0x00, 0x20)
            out := mload(0x00)
        }
        if (!ok) revert StacksMarf.MarfHasherFailed();
    }
}
