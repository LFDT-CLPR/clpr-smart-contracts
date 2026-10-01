// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprRecordVerifierBase} from "@hiero-ledger/clpr/verifiers/evm/common/ClprRecordVerifierBase.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprQueueRecord} from "@hiero-ledger/clpr/libraries/codec/ClprQueueRecord.sol";
import {ClprAttestorQuorum} from "@hiero-ledger/clpr/libraries/proof/attestor/ClprAttestorQuorum.sol";
import {ClprReceiptProof} from "@hiero-ledger/clpr/libraries/proof/evm/ClprReceiptProof.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/// @title HyperEvmVerifier
/// @notice Hyperliquid HyperEVM → Hiero `IClprVerifier` (attestor tier; see README.md).
///
///         TRUST: ATTESTOR-TRUSTED. HyperEVM finality is not proven. Nothing that Hyperliquid's
///         validators sign covers HyperEVM blocks (Bridge2 validators sign bridge actions only), so a
///         K-of-N set of CLPR attestors signs (chainId, number, blockHash). If K attestors collude
///         they can make the verifier accept any block. Everything below the block hash is proven.
///
///         HyperEVM headers carry `stateRoot = 0x0` and the RPC has no `eth_getProof`, so channel
///         storage cannot be proven. Receipts are committed. The HyperEVM side runs
///         {ClprHyperEvmBeacon}, which reads the ClprService and emits its queue state as a
///         {ClprQueueRecord} event. The verifier proves that event: block header → receiptsRoot →
///         receipt (status 1) → log from the pinned beacon, naming the service and the channel.
///
/// @dev Bundle proof, RLP:
///        [0] attestor set [threshold, [attestor, ...]]      must hash to the anchor
///        [1] rotations [[newSet, [sig, ...]], ...]           each signed by the then-current set
///        [2] block header (RLP, as hashed into blockHash)
///        [3] block attestation [sig, ...]                    ascending signers, >= threshold
///        [4] receipt [transactionIndex, [node, ...]]
///        [5] log index within that receipt
///        [6] ClprBundleContent protobuf (messages; bound by the record's sentRunningHash)
///        [7] optional endpoint manifest preimage (bound by the record's manifestCommitment)
///      Trust anchor: abi.encode(bytes32 setHash, uint256 epoch, uint256 minBlock, address beacon).
contract HyperEvmVerifier is ClprRecordVerifierBase {
    bytes32 public constant BLOCK_DOMAIN = keccak256("CLPR_HYPEREVM_BLOCK_ATTESTATION_V1");
    bytes32 public constant ROTATE_DOMAIN = keccak256("CLPR_HYPEREVM_ATTESTOR_ROTATION_V1");
    bytes32 public constant RECORD_TOPIC = keccak256("ClprQueueRecord(address,bytes32,bytes)");

    /// @notice HyperEVM EIP-155 chain id (999 mainnet, 998 testnet), bound into every signature.
    uint256 public immutable HYPEREVM_CHAIN_ID;

    error InvalidTrustAnchor();
    error InvalidPayloadShape();
    error InvalidHeader();
    error StaleBlock(uint256 number, uint256 minBlock);
    error WrongEmitter(address emitter);
    error WrongEvent();
    error WrongService();

    struct Anchor {
        bytes32 setHash;
        uint256 epoch;
        uint256 minBlock;
        address beacon;
    }

    constructor(string memory caip2, uint256 hyperEvmChainId) ClprRecordVerifierBase(caip2) {
        HYPEREVM_CHAIN_ID = hyperEvmChainId;
    }

    /// @notice Digest attestors sign for a block.
    function blockDigest(uint256 number, bytes32 blockHash) public view returns (bytes32) {
        return keccak256(abi.encode(BLOCK_DOMAIN, HYPEREVM_CHAIN_ID, number, blockHash));
    }

    /// @notice Digest the current set signs to hand over to `newSetHash` as epoch `epoch`.
    function rotationDigest(uint256 epoch, bytes32 newSetHash) public view returns (bytes32) {
        return keccak256(abi.encode(ROTATE_DOMAIN, HYPEREVM_CHAIN_ID, epoch, newSetHash));
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
        ClprTypes.ChannelContext memory ctx = ClprTypes.decodeChannelContext(channelContext);
        Memory.Slice[] memory p = RLP.decodeList(proofBytes);
        if (p.length != 7 && p.length != 8) revert InvalidPayloadShape();

        ClprAttestorQuorum.Set memory set = ClprAttestorQuorum.decode(p[0], a.setHash);
        Memory.Slice[] memory rotations = RLP.readList(p[1]);
        for (uint256 i = 0; i < rotations.length; ++i) {
            set = _rotate(set, rotations[i], ++a.epoch);
        }

        (uint256 number, ClprQueueRecord.Record memory r) =
            _provenRecord(set, p, a, ctx.remoteServiceAddress, ctx.channelId);
        if (number < a.minBlock) revert StaleBlock(number, a.minBlock);
        _requireChannel(r, ctx.channelId);
        metadata = ClprQueueRecord.toMetadata(r);
        messagePayloads = _decodeBundleContent(RLP.readBytes(p[6]));
        newEndpointManifest = p.length == 8
            ? _recordManifest(r, RLP.readBytes(p[7]), ctx.remoteServiceAddress)
            : _absentEndpointManifest();

        if (rotations.length > 0) {
            bytes32 h = ClprAttestorQuorum.hash(set);
            newTrustAnchor = abi.encode(h, a.epoch, number, a.beacon);
            newTrustAnchorId = abi.encodePacked(a.epoch);
        }
    }

    /// @dev Attested block → receipt → the beacon's record for (service, channelId).
    function _provenRecord(
        ClprAttestorQuorum.Set memory set,
        Memory.Slice[] memory p,
        Anchor memory a,
        bytes memory service,
        bytes32 channelId
    ) internal view returns (uint256 number, ClprQueueRecord.Record memory r) {
        ClprReceiptProof.Log memory log;
        (number, log) = _provenLog(set, p);
        r = _recordFromLog(log, a.beacon, service, channelId);
    }

    /// @dev The attested block (fields [2], [3]) and log [5] of receipt [4] in it.
    function _provenLog(ClprAttestorQuorum.Set memory set, Memory.Slice[] memory p)
        internal
        view
        returns (uint256 number, ClprReceiptProof.Log memory log)
    {
        bytes memory header = RLP.readBytes(p[2]);
        Memory.Slice[] memory h = RLP.decodeList(header);
        if (h.length < 15 || h.length > 21) revert InvalidHeader();
        number = RLP.readUint256(h[8]);
        ClprAttestorQuorum.requireQuorum(set, blockDigest(number, keccak256(header)), p[3]);

        Memory.Slice[] memory rc = RLP.readList(p[4]);
        if (rc.length != 2) revert InvalidPayloadShape();
        Memory.Slice[] memory nodes = RLP.readList(rc[1]);
        bytes[] memory proof = new bytes[](nodes.length);
        for (uint256 i = 0; i < nodes.length; ++i) {
            proof[i] = RLP.readBytes(nodes[i]);
        }
        bytes memory receipt = ClprReceiptProof.verifyReceipt(RLP.readBytes32(h[5]), RLP.readUint256(rc[0]), proof);
        log = ClprReceiptProof.successfulLog(receipt, RLP.readUint256(p[5]));
    }

    function _recordFromLog(ClprReceiptProof.Log memory log, address beacon, bytes memory service, bytes32 channelId)
        internal
        pure
        returns (ClprQueueRecord.Record memory)
    {
        if (log.emitter != beacon) revert WrongEmitter(log.emitter);
        if (log.topics.length != 3 || log.topics[0] != RECORD_TOPIC) revert WrongEvent();
        if (service.length != 20 || log.topics[1] != bytes32(uint256(uint160(bytes20(service))))) {
            revert WrongService();
        }
        // a bundle names its channel; config accepts the service-level record (channel 0) too
        if (log.topics[2] != channelId && log.topics[2] != bytes32(0)) {
            revert RecordChannelMismatch(channelId, log.topics[2]);
        }
        bytes memory record = abi.decode(log.data, (bytes));
        ClprQueueRecord.Record memory r = ClprQueueRecord.decode(record, 0);
        if (r.channelId != log.topics[2]) revert WrongEvent();
        return r;
    }

    function _rotate(ClprAttestorQuorum.Set memory set, Memory.Slice item, uint256 epoch)
        internal
        view
        returns (ClprAttestorQuorum.Set memory next)
    {
        Memory.Slice[] memory e = RLP.readList(item);
        if (e.length != 2) revert InvalidPayloadShape();
        next = ClprAttestorQuorum.decodeUnchecked(e[0]);
        ClprAttestorQuorum.requireQuorum(set, rotationDigest(epoch, ClprAttestorQuorum.hash(next)), e[1]);
    }

    /// @inheritdoc IClprVerifier
    /// @dev Config proof, RLP: [attestorSet, header, attestation, receipt, logIndex, controlMessage,
    ///      beacon]. The beacon's record (channel 0 or this channel) must commit to the control
    ///      message, and the LedgerConfiguration's service must be the one the event names.
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
        Memory.Slice[] memory c = RLP.decodeList(configProofBytes);
        if (c.length != 7) revert InvalidPayloadShape();
        ClprAttestorQuorum.Set memory set = ClprAttestorQuorum.decodeUnchecked(c[0]);
        bytes memory control = RLP.readBytes(c[5]);
        ClprTypes.LedgerConfiguration memory lc = _peekConfig(control);
        Anchor memory a;
        a.beacon = RLP.readAddress(c[6]);
        // reuse the bundle layout: [set, -, header, sigs, receipt, logIndex]
        Memory.Slice[] memory p = new Memory.Slice[](6);
        (p[2], p[3], p[4], p[5]) = (c[1], c[2], c[3], c[4]);
        (uint256 number, ClprQueueRecord.Record memory r) = _provenRecord(set, p, a, lc.serviceAddress, channelId);
        lc = _verifiedConfig(r, channelId, control);

        serviceAddress = lc.serviceAddress;
        bytes32 setHash = ClprAttestorQuorum.hash(set);
        initialTrustAnchor = abi.encode(setHash, uint256(0), number, a.beacon);
        initialTrustAnchorId = abi.encodePacked(uint256(0));
        channelContext = ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: serviceAddress})
        );
        endpointManifest = _configManifest(r, endpointManifestProofBytes, serviceAddress);
        chainId = lc.chainId;
        peerConfigNanos = lc.nanosSinceEpoch;
        throttles = lc.throttles;
    }

    /// @dev Read the service address before the record is proven (it selects the event to accept);
    ///      {_verifiedConfig} binds the same bytes to the record afterwards.
    function _peekConfig(bytes memory control) internal pure returns (ClprTypes.LedgerConfiguration memory lc) {
        lc = ClprProtobuf.decodeControlMessage(control).config;
        if (lc.serviceAddress.length != 20) revert InvalidServiceAddressLength();
    }

    function _decodeAnchor(bytes calldata trustAnchor) internal pure returns (Anchor memory a) {
        if (trustAnchor.length != 128) revert InvalidTrustAnchor();
        (a.setHash, a.epoch, a.minBlock, a.beacon) = abi.decode(trustAnchor, (bytes32, uint256, uint256, address));
        if (a.setHash == bytes32(0) || a.beacon == address(0)) revert InvalidTrustAnchor();
    }
}

