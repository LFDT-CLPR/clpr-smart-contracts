// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprVerifierComplianceTest} from "@test/verifiers/compliance/ClprVerifierComplianceTest.sol";
import {EthCommitteeFixtures} from "@test/verifiers/evm/ethereum/EthCommitteeFixtures.sol";
import {StarknetSyntheticProofs} from "@test/helpers/StarknetSyntheticProofs.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {StarknetVerifier} from "@hiero-ledger/clpr/verifiers/evm/starknet/StarknetVerifier.sol";
import {EthL1StateVerifier} from "@hiero-ledger/clpr/verifiers/evm/ethereum/EthL1StateVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprBeaconSsz} from "@hiero-ledger/clpr/libraries/proof/beacon/ClprBeaconSsz.sol";
import {RLP} from "@openzeppelin/contracts/utils/RLP.sol";

/// @title StarknetComplianceTest
/// @notice The verifier-agnostic compliance suite against {StarknetVerifier}, every vector built in
///         Solidity end to end (generator sync committee → synthetic core contract → Starknet tries).
contract StarknetComplianceTest is ClprVerifierComplianceTest, StarknetSyntheticProofs {
    uint256 internal constant SERVICE = 0x05e7c1ce1acce5e7c1ce1acce5e7c1ce1acce5e7c1ce1acce5e7c1ce1acce5e;
    uint256 internal constant CLASS_HASH = 0x01a55c1a55c1a55c1a55c1a55c1a55c1a55c1a55c1a55c1a55c1a55c1a55c1a;
    bytes32 internal constant SYNTHETIC_CHANNEL_ID = bytes32(uint256(0xC0FFEE));

    function setUp() public override(ClprVerifierComplianceTest, EthCommitteeFixtures) {
        EthCommitteeFixtures.setUp();
        ClprVerifierComplianceTest.setUp();
    }

    function _layout() internal pure returns (StarknetVerifier.Layout memory) {
        return StarknetVerifier.Layout({
            channelsBase: uint256(keccak256("clpr_channels")) & ((1 << 250) - 1),
            statusOffset: 0,
            nextMessageIdOffset: 1,
            receivedMessageIdOffset: 2,
            sentRunningHashOffset: 3,
            receivedRunningHashOffset: 5,
            endpointManifestVersionOffset: 7,
            messagesBase: uint256(keccak256("clpr_messages")) & ((1 << 250) - 1),
            messageRunningHashOffset: 0,
            manifestCommitmentAddress: uint256(keccak256("clpr_endpoint_manifest_commitment")) & ((1 << 250) - 1)
        });
    }

    function _deployVerifier() internal override returns (IClprVerifier) {
        EthL1StateVerifier l1 = new EthL1StateVerifier(
            ClprBeaconSsz.GINDEX_EXECUTION_STATE_ROOT_IN_BODY,
            9,
            ClprBeaconSsz.GINDEX_NEXT_SYNC_COMMITTEE_IN_STATE,
            6,
            8192
        );
        StarknetVerifier.Profile memory p;
        p.core = SYNTH_CORE;
        return IClprVerifier(address(new StarknetVerifier(l1, _deployStarkProver(), p, _layout())));
    }

    function _config(bytes memory aggregate) internal view returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory lc;
        lc.chainId = "starknet:SN_SEPOLIA";
        lc.serviceAddress = abi.encodePacked(SERVICE);
        bytes[] memory cfg = new bytes[](6);
        cfg[0] = RLP.encode(uint256(SYNTH_L1_SLOT));
        cfg[1] = _encodeCommittee(_uncompressedKeys(SYNC_COMMITTEE_SIZE), aggregate);
        cfg[2] = RLP.encode(abi.encodePacked(SYNTH_GVR));
        cfg[3] = RLP.encode(abi.encodePacked(SYNTH_FORK_VERSION));
        cfg[4] = RLP.encode(ClprProtobuf.encodeControlMessage(lc));
        cfg[5] = RLP.encode(abi.encodePacked(bytes32(CLASS_HASH)));
        return RLP.encode(cfg);
    }

    function _validConfig() internal view override returns (ConfigVector memory) {
        return ConfigVector({
            configProof: _config(genUncompressed),
            channelId: SYNTHETIC_CHANNEL_ID,
            expectedChainId: "starknet:SN_SEPOLIA",
            expectedServiceAddress: abi.encodePacked(SERVICE)
        });
    }

    /// @dev The 8 channel keys, in the verifier's order.
    function _channelKeys(bytes32 channelId) internal view returns (uint256[] memory keys) {
        uint256[] memory felts = new uint256[](2);
        felts[0] = uint256(channelId) & type(uint128).max;
        felts[1] = uint256(channelId) >> 128;
        uint256 b = starkProver.mapAddress(_layout().channelsBase, felts);
        keys = new uint256[](8);
        uint256[8] memory off = [uint256(0), 1, 2, 3, 4, 5, 6, 7];
        for (uint256 i = 0; i < 8; i++) {
            keys[i] = b + off[i];
        }
    }

    /// @dev Bundle for `channelId` whose queue is ACTIVE with `nextMessageId` and `sentHash`.
    function _bundle(bytes32 channelId, uint64 nextMessageId, bytes32 sentHash, bytes memory bundleContent)
        internal
        returns (bytes memory)
    {
        uint256[] memory vals = new uint256[](8);
        vals[0] = 1;
        vals[1] = nextMessageId;
        vals[3] = uint256(sentHash) & type(uint128).max;
        vals[4] = uint256(sentHash) >> 128;
        (uint256 globalRoot, bytes memory starknetProof) =
            _starknetState(SERVICE, CLASS_HASH, _channelKeys(channelId), vals);
        (bytes32 l1StateRoot, bytes memory coreProof) = _coreProof(globalRoot);
        bytes[] memory items = new bytes[](5);
        items[0] = RLP.encode(_syntheticLightClientProof(l1StateRoot));
        items[1] = coreProof;
        items[2] = RLP.encode(starknetProof);
        items[3] = RLP.encode(bytes(""));
        items[4] = RLP.encode(bundleContent);
        return RLP.encode(items);
    }

    function _context(bytes32 channelId) internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: channelId, remoteServiceAddress: abi.encodePacked(SERVICE)})
        );
    }

    function _validBundle() internal override returns (BundleVector memory) {
        return BundleVector({
            proofBytes: _bundle(SYNTHETIC_CHANNEL_ID, 3, bytes32(uint256(0xabc)), ""),
            trustAnchor: _syntheticAnchor(SYNTHETIC_CHANNEL_ID, CLASS_HASH),
            channelContext: _context(SYNTHETIC_CHANNEL_ID),
            expectedNextMessageId: 3,
            expectedPayloadCount: 0
        });
    }

    function _runningHashVector() internal override returns (RunningHashVector memory) {
        bytes memory payload = ClprProtobuf.encodeDataMessage(hex"01", hex"02", hex"03", hex"04");
        bytes32 sent = sha256(abi.encodePacked(bytes32(0), sha256(payload)));
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = payload;
        ClprTypes.QueueMetadata memory dummy;
        return RunningHashVector({
            proofBytes: _bundle(SYNTHETIC_CHANNEL_ID, 2, sent, ClprProtobuf.encodeBundleContent(dummy, payloads)),
            trustAnchor: _syntheticAnchor(SYNTHETIC_CHANNEL_ID, CLASS_HASH),
            channelContext: _context(SYNTHETIC_CHANNEL_ID),
            previousRunningHash: bytes32(0)
        });
    }

    /// @dev Config-time manifest proof `[lightClientProof, coreProof, starknetProof, manifestPreimage]`,
    ///      signed by the config committee (512·G aggregate), whose Starknet state commits
    ///      keccak256(committedPreimage) as the u256 manifest commitment.
    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        uint256 at = _layout().manifestCommitmentAddress;
        uint256[] memory keys = new uint256[](2);
        keys[0] = at;
        keys[1] = at + 1;
        uint256[] memory vals = new uint256[](2);
        vals[0] = uint256(keccak256(committedPreimage)) & type(uint128).max;
        vals[1] = uint256(keccak256(committedPreimage)) >> 128;
        (uint256 globalRoot, bytes memory starknetProof) = _starknetState(SERVICE, CLASS_HASH, keys, vals);
        (bytes32 l1StateRoot, bytes memory coreProof) = _coreProof(globalRoot);
        bytes[] memory items = new bytes[](4);
        items[0] = RLP.encode(_syntheticLightClientProof(l1StateRoot));
        items[1] = coreProof;
        items[2] = RLP.encode(starknetProof);
        items[3] = RLP.encode(carriedPreimage);
        return (_config(_committeeAggregate()), SYNTHETIC_CHANNEL_ID, RLP.encode(items));
    }

    /// @dev A config whose committee carries 48-byte (compressed, beacon-native) keys: the 128-byte
    ///      EIP-2537 form is required, so the light client rejects it (as for EthMainnetVerifier).
    function _wrongChainConfigVector() internal pure override returns (bytes memory configProof, bytes32 channelId) {
        ClprTypes.LedgerConfiguration memory lc;
        bytes[] memory cfg = new bytes[](6);
        cfg[0] = RLP.encode(uint256(100));
        cfg[1] = _encodeCommittee(_compressedKeys(SYNC_COMMITTEE_SIZE), G1_GEN_COMPRESSED);
        cfg[2] = RLP.encode(abi.encodePacked(SYNTH_GVR));
        cfg[3] = RLP.encode(abi.encodePacked(SYNTH_FORK_VERSION));
        cfg[4] = RLP.encode(ClprProtobuf.encodeControlMessage(lc));
        cfg[5] = RLP.encode(abi.encodePacked(bytes32(0)));
        return (RLP.encode(cfg), SYNTHETIC_CHANNEL_ID);
    }
}
