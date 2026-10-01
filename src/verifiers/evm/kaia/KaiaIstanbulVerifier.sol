// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmBundleVerifier} from "@hiero-ledger/clpr/verifiers/evm/common/ClprEvmBundleVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprKaiaIstanbul} from "@hiero-ledger/clpr/libraries/proof/kaia/ClprKaiaIstanbul.sol";
import {ClprEvmStateProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprEvmStateProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/// @title KaiaIstanbulVerifier
/// @notice CLPR verifier for Kaia: Istanbul BFT committed seals (like {QBFTVerifier}, but with
///         Kaia's header and extraData layout), qualified-validator-set tracking from the set every
///         header carries, and Kaia's type-prefixed account encoding in the state trie.
///
/// ## Trust anchor (flat packed, 74 bytes)
/// ```
///   [0..32)   codeHash   pinned ClprService runtime code hash
///   [32..64)  setHash    keccak256(packed qualified validators, header order)
///   [64..72)  setBlock   block whose header introduced the set
///   [72..74)  setSize    number of qualified validators
/// ```
///
/// ## Bundle proof (RLP list, 5 items; 7 with an endpoint-manifest update)
/// ```
/// [ 0: validators    anchor set, n × address20 in header order; keccak256 must equal setHash
///   1: headers       [H_1, …, H_k], strictly increasing numbers; H_k carries the proven state root
///   2: accountProof  MPT account proof (Kaia SmartContractAccount leaf) at H_k.stateRoot
///   3: storageProof  5 or 6 × [slot, proofNodes] for the channelId-derived slots
///   4: bundleContent protobuf ClprBundleContent
///   5: manifestStorageProof, 6: manifestPreimage (optional) ]
/// ```
///
/// ## Acceptance rule, per header H with qualified set S' (from its extraData), current set S
/// - distinct committers in S' ≥ 2f(S') + 1 (Kaia's own commit quorum), and
/// - if S' ≠ S: distinct committers in S ≥ f(S) + 1 (more than a third of the trusted set vouches
///   for the header that introduces the new set). The anchor then moves to S'.
contract KaiaIstanbulVerifier is ClprEvmBundleVerifier {
    uint256 internal constant PAYLOAD_FIELDS = 5;
    uint256 internal constant PAYLOAD_FIELDS_WITH_MANIFEST = 7;
    uint256 internal constant IDX_VALIDATORS = 0;
    uint256 internal constant IDX_HEADERS = 1;
    uint256 internal constant IDX_ACCOUNT_PROOF = 2;
    uint256 internal constant IDX_STORAGE_PROOF = 3;
    uint256 internal constant IDX_BUNDLE_CONTENT = 4;
    uint256 internal constant IDX_MANIFEST_STORAGE_PROOF = 5;
    uint256 internal constant IDX_MANIFEST_PREIMAGE = 6;
    uint256 internal constant MAX_HEADERS = 32;
    uint256 internal constant TRUST_ANCHOR_LENGTH = 74;
    /// @dev Kaia account type tag of a SmartContractAccount (`account.SmartContractAccountType`).
    uint8 internal constant SMART_CONTRACT_ACCOUNT = 2;

    // Config payload: [ledgerConfiguration, header, codeHash].
    uint256 internal constant CONFIG_FIELDS = 3;
    // Config-time manifest proof: [validators, headers, accountProof, manifestStorageProof, manifestPreimage].
    uint256 internal constant CONFIG_MANIFEST_PROOF_FIELDS = 5;

    /// @notice EIP-155 chain id; the peer's CAIP-2 id must be eip155:<CHAIN_ID>.
    uint64 public immutable CHAIN_ID;

    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error InvalidConfigPayload();
    error ChainIdMismatch();
    error ValidatorSetMismatch();
    error InvalidKaiaAccount();
    error HeaderOutOfOrder(uint64 number, uint64 previous);
    error InsufficientCommittedSeals(uint256 got, uint256 required);
    error InsufficientRotationSeals(uint256 got, uint256 required);

    struct Anchor {
        bytes32 codeHash;
        bytes32 setHash;
        uint64 setBlock;
        uint16 setSize;
    }

    constructor(uint64 chainId) {
        if (chainId == 0) revert ChainIdMismatch();
        CHAIN_ID = chainId;
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

        (bytes32 stateRoot, bool rotated) = _verifyHeaders(anchor, payload[IDX_VALIDATORS], payload[IDX_HEADERS]);

        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        bytes32 storageRoot = _verifyKaiaServiceStorageRoot(
            payload[IDX_ACCOUNT_PROOF], stateRoot, _toAddress(ctx.remoteServiceAddress), anchor.codeHash
        );
        metadata = _verifyChannelStorage(payload[IDX_STORAGE_PROOF], storageRoot, ctx.channelId);
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
            newTrustAnchor = _encodeAnchor(anchor);
            newTrustAnchorId = abi.encodePacked(anchor.setBlock);
        }
    }

    /// @inheritdoc IClprVerifier
    /// @dev configProofBytes = RLP([ledgerConfiguration (ClprMessagePayload control protobuf), header,
    ///      codeHash]). A trusted (weak-subjectivity) bootstrap: the header's qualified set becomes the
    ///      anchor set. The header must carry its own commit quorum.
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

        ClprKaiaIstanbul.Header memory h = ClprKaiaIstanbul.decodeHeader(cfg[1]);
        _requireQuorum(h);
        Anchor memory anchor = Anchor({
            codeHash: RLP.readBytes32(cfg[2]),
            setHash: h.validatorsHash,
            setBlock: h.number,
            // forge-lint: disable-next-line(unsafe-typecast)
            setSize: uint16(h.validators.length)
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

    /// @dev Verify every header under the running set (rotating as sets change) and return the last
    ///      header's state root.
    function _verifyHeaders(Anchor memory anchor, Memory.Slice validatorsItem, Memory.Slice headersItem)
        internal
        pure
        returns (bytes32 stateRoot, bool rotated)
    {
        address[] memory set = _decodeAnchorSet(anchor, RLP.readBytes(validatorsItem));
        Memory.Slice[] memory items = RLP.readList(headersItem);
        uint256 k = items.length;
        if (k == 0 || k > MAX_HEADERS) revert InvalidPayloadShape();

        uint64 previous = anchor.setBlock;
        for (uint256 i = 0; i < k; i++) {
            ClprKaiaIstanbul.Header memory h = ClprKaiaIstanbul.decodeHeader(items[i]);
            // Never older than the anchor; strictly increasing within the run.
            if (i == 0 ? h.number < previous : h.number <= previous) revert HeaderOutOfOrder(h.number, previous);
            previous = h.number;

            _requireQuorum(h);
            if (h.validatorsHash != anchor.setHash) {
                uint256 vouch = ClprKaiaIstanbul.countMembers(h.committers, set);
                uint256 need = ClprKaiaIstanbul.faultBound(set.length) + 1;
                if (vouch < need) revert InsufficientRotationSeals(vouch, need);
                set = h.validators;
                anchor.setHash = h.validatorsHash;
                // forge-lint: disable-next-line(unsafe-typecast)
                anchor.setSize = uint16(h.validators.length);
                anchor.setBlock = h.number;
                rotated = true;
            }
            stateRoot = h.stateRoot;
        }
    }

    /// @dev Kaia's own commit rule on the header's qualified set.
    function _requireQuorum(ClprKaiaIstanbul.Header memory h) internal pure {
        uint256 got = ClprKaiaIstanbul.countMembers(h.committers, h.validators);
        uint256 need = ClprKaiaIstanbul.quorum(h.validators.length);
        if (got < need) revert InsufficientCommittedSeals(got, need);
    }

    function _decodeAnchorSet(Anchor memory anchor, bytes memory packed) internal pure returns (address[] memory set) {
        if (packed.length != uint256(anchor.setSize) * 20 || keccak256(packed) != anchor.setHash) {
            revert ValidatorSetMismatch();
        }
        set = new address[](anchor.setSize);
        for (uint256 i = 0; i < set.length; i++) {
            address a;
            assembly ("memory-safe") {
                a := shr(96, mload(add(add(packed, 0x20), mul(i, 20))))
            }
            set[i] = a;
        }
    }

    /// @dev Kaia's state trie is a keccak Merkle-Patricia trie, but its account leaf is
    ///      `type ‖ RLP([common, storageRoot, codeHash, codeInfo])`. Only a SmartContractAccount
    ///      (type 2) has storage.
    function _verifyKaiaServiceStorageRoot(
        Memory.Slice accountProofItem,
        bytes32 stateRoot,
        address service,
        bytes32 expectedCodeHash
    ) internal pure returns (bytes32 storageRoot) {
        bytes memory leaf = ClprEvmStateProof.verifyAccount(accountProofItem, stateRoot, service);
        if (leaf.length < 2 || uint8(leaf[0]) != SMART_CONTRACT_ACCOUNT) revert InvalidKaiaAccount();
        bytes memory body = new bytes(leaf.length - 1);
        assembly ("memory-safe") {
            mcopy(add(body, 0x20), add(leaf, 0x21), mload(body))
        }
        Memory.Slice[] memory fields = RLP.decodeList(body);
        if (fields.length != 4) revert InvalidKaiaAccount();
        storageRoot = RLP.readBytes32(fields[1]);
        bytes32 codeHash = RLP.readBytes32(fields[2]);
        if (expectedCodeHash != bytes32(0) && codeHash != expectedCodeHash) revert CodeHashMismatch();
    }

    function _verifyConfigEndpointManifest(bytes calldata proofBytes, Anchor memory anchor, bytes memory serviceAddress)
        internal
        pure
        returns (ClprTypes.ClprEndpointManifest memory)
    {
        if (proofBytes.length == 0) return _uninitializedEndpointManifest(serviceAddress);
        bytes memory proofMem = proofBytes;
        Memory.Slice[] memory p = RLP.decodeList(proofMem);
        if (p.length != CONFIG_MANIFEST_PROOF_FIELDS) revert InvalidConfigPayload();
        (bytes32 stateRoot,) = _verifyHeaders(anchor, p[0], p[1]);
        bytes32 storageRoot =
            _verifyKaiaServiceStorageRoot(p[2], stateRoot, _toAddress(serviceAddress), anchor.codeHash);
        return _verifyEndpointManifest(p[3], storageRoot, RLP.readBytes(p[4]), serviceAddress);
    }

    function _decodeAnchor(bytes calldata ta) internal pure returns (Anchor memory a) {
        if (ta.length != TRUST_ANCHOR_LENGTH) revert InvalidTrustAnchor();
        a.codeHash = bytes32(ta[0:32]);
        a.setHash = bytes32(ta[32:64]);
        a.setBlock = uint64(bytes8(ta[64:72]));
        a.setSize = uint16(bytes2(ta[72:74]));
        if (a.setSize == 0 || a.setSize > ClprKaiaIstanbul.MAX_VALIDATORS) revert InvalidTrustAnchor();
    }

    function _encodeAnchor(Anchor memory a) internal pure returns (bytes memory) {
        return abi.encodePacked(a.codeHash, a.setHash, a.setBlock, a.setSize);
    }
}
