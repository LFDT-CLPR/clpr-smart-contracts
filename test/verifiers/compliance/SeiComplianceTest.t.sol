// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprEvmStorageComplianceTest} from "@test/verifiers/compliance/ClprEvmStorageComplianceTest.sol";
import {SeiSyntheticProofs} from "@test/helpers/SeiSyntheticProofs.sol";
import {SeiCometBftVerifierHarness} from "@test/helpers/SeiCometBftVerifierHarness.sol";
import {SeiCometBftVerifier} from "@hiero-ledger/clpr/verifiers/evm/sei/SeiCometBftVerifier.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobufHelpers as PB} from "@hiero-ledger/clpr/libraries/codec/ClprProtobufHelpers.sol";
import {CometBftLib} from "@hiero-ledger/clpr/libraries/proof/cometbft/CometBftLib.sol";

/// @dev Compliance harness: exercises the entire verifier pipeline (header hash, merkle,
///      validator-set hash, commit assembly, quorum, IAVL/multistore, slot derivation). Only the
///      Ed25519 curve op is replaced by a message-binding check, so tampering with any signed byte
///      changes the recomputed sign-bytes and fails here. The real curve is covered by
///      SeiRealBundle.t.sol / Ed25519Port.t.sol.
contract SeiComplianceHarness is SeiCometBftVerifierHarness {
    constructor(bool alwaysOk) SeiCometBftVerifierHarness(alwaysOk) {}

    function _verifyEd25519(bytes32 pubKey, bytes memory message, bytes memory sig)
        internal
        pure
        override
        returns (bool)
    {
        // casting to 'bytes32' is safe: we only read the first 32-byte word of the 64-byte sig and
        // compare it, matching how `_bindSig` lays the digest out.
        // forge-lint: disable-next-line(unsafe-typecast)
        return sig.length == 64 && bytes32(sig) == sha256(abi.encodePacked(pubKey, message));
    }
}

/// @title SeiComplianceTest
/// @notice Compliance adapter binding `SeiCometBftVerifier` to the shared EVM verifier compliance
///         suite (`ClprVerifierComplianceTest` + `ClprEvmStorageComplianceTest`). Deploys a harness
///         whose only change to the verifier is a message-binding Ed25519 stub (see
///         `SeiComplianceHarness`), and supplies synthetic CometBFT/ICS-23 proof vectors.
contract SeiComplianceTest is ClprEvmStorageComplianceTest, SeiSyntheticProofs {
    string internal constant CHAIN_ID = "sei-chain-1";
    address internal constant SERVICE_ADDR = 0x5e7c1Ce1acCE5E7C1Ce1ACCe5e7c1CE1ACce5e7C;
    bytes20 internal constant SERVICE_ADDR20 = bytes20(SERVICE_ADDR);
    bytes32 internal constant CHANNEL_ID = bytes32(uint256(0xC0FFEE));
    bytes32 internal constant OTHER_CHANNEL_ID = bytes32(uint256(0xDEADBEEF));

    SeiCometBftVerifierHarness internal h;

    // ── Deployment ────────────────────────────────────────────────────────────

    function _deployVerifier() internal override returns (IClprVerifier) {
        // have _verifyEd25519 verify signatures by passing false
        h = SeiCometBftVerifierHarness(deployCode("SeiComplianceTest.t.sol:SeiComplianceHarness", abi.encode(false)));
        return IClprVerifier(address(h));
    }

    // ── Shared fixtures ─────────────────────────────────────────────────────────

    function _syntheticValidators() internal pure returns (CometBftLib.SeiValidator[] memory v) {
        v = new CometBftLib.SeiValidator[](2);
        v[0] = CometBftLib.SeiValidator({ed25519PubKey: keccak256("sei-validator-0"), votingPower: 100});
        v[1] = CometBftLib.SeiValidator({ed25519PubKey: keccak256("sei-validator-1"), votingPower: 200});
    }

    function _ctxFor(bytes32 connId, bytes20 svc) internal pure returns (bytes memory) {
        return ClprTypes.encodeChannelContext(
            ClprTypes.ChannelContext({channelId: connId, remoteServiceAddress: abi.encodePacked(svc)})
        );
    }

    function _trustAnchor() internal pure returns (bytes memory) {
        return abi.encode(CHAIN_ID, _syntheticValidators());
    }

    function _successValues() internal pure returns (bytes32[5] memory values) {
        values[0] = bytes32((uint256(1) << 160) | (uint256(100) << 168)); // status=ACTIVE, nextMessageId=100
        values[1] = bytes32(uint256(50) << 64); // receivedMessageId=50
        values[2] = bytes32(uint256(0xAAAA1111)); // sentRunningHash
        values[3] = bytes32(uint256(0xBBBB2222)); // receivedRunningHash
        values[4] = bytes32(uint256(3)); // endpointManifestVersion
    }

    /// @dev Builds the SeiStateProof inner bytes (fields 1-4): signed header, "evm" store key,
    ///      multistore proof, and the caller's already-encoded field-4 storage entries.
    ///      `validatorsHashOverride` is stuffed verbatim into header.validatorsHash /
    ///      nextValidatorsHash — pass `h.validatorSetHash(_syntheticValidators())` for a valid proof,
    ///      or garbage to force a `ValidatorSetHashMismatch`.
    function _stateProof(bytes32 iavlRoot, bytes32 validatorsHashOverride, bytes memory storageEntriesField4)
        internal
        view
        returns (bytes memory)
    {
        (bytes memory multistoreProofBytes, bytes32 appHash) = _buildMultistoreProof(iavlRoot);

        CometBftLib.SeiHeader memory header = _syntheticHeader();
        header.validatorsHash = validatorsHashOverride;
        header.nextValidatorsHash = validatorsHashOverride;
        header.appHash = appHash;

        CometBftLib.SeiCommit memory commit;
        commit.height = header.height;
        commit.round = 0;
        commit.blockIdHash = h.headerHash(header);
        commit.partSetTotal = 1;
        commit.partSetHash = bytes32(uint256(0xBBBB));
        commit.signersBits = hex"C0";
        bytes memory message = h.precommitSignBytes(
            CHAIN_ID,
            header.height,
            commit.round,
            commit.blockIdHash,
            commit.partSetTotal,
            commit.partSetHash,
            header.timeSeconds,
            int32(0)
        );
        CometBftLib.SeiValidator[] memory vals = _syntheticValidators();
        commit.signatures = new CometBftLib.CommitSig[](2);
        commit.signatures[0] = CometBftLib.CommitSig({
            timestampSeconds: header.timeSeconds, timestampNanos: 0, signature: _bindSig(vals[0].ed25519PubKey, message)
        });
        commit.signatures[1] = CometBftLib.CommitSig({
            timestampSeconds: header.timeSeconds, timestampNanos: 0, signature: _bindSig(vals[1].ed25519PubKey, message)
        });

        bytes memory signedHeaderInner = abi.encodePacked(
            PB.encodeBytesField(1, _buildHeaderBytes(header)),
            PB.encodeBytesField(2, _buildCommitBytes(commit, header.timeSeconds))
        );

        return abi.encodePacked(
            PB.encodeBytesField(1, signedHeaderInner),
            PB.encodeBytesField(2, bytes("evm")),
            PB.encodeBytesField(3, multistoreProofBytes),
            storageEntriesField4
        );
    }

    /// @dev Deterministic stand-in for an Ed25519 signature: 64 bytes whose first word is
    ///      sha256(pubKey ‖ message). Must match SeiComplianceHarness._verifyEd25519 exactly.
    function _bindSig(bytes32 pubKey, bytes memory message) internal pure returns (bytes memory) {
        return abi.encodePacked(sha256(abi.encodePacked(pubKey, message)), bytes32(0));
    }

    /// @dev Concatenates a 5-slot Channel storage proof into field-4 entries and wraps a full
    ///      ClprSeiBundlePayload (state proof + bundle content).
    function _bundle(bytes32 connId, bytes20 svc, bytes32[5] memory values, bytes memory bundleContent)
        internal
        view
        returns (bytes memory)
    {
        (bytes[5] memory entries, bytes32 iavlRoot) = _buildFiveLeafChannelProof(connId, svc, values);
        bytes memory field4;
        for (uint256 i = 0; i < 5; i++) {
            field4 = abi.encodePacked(field4, PB.encodeBytesField(4, entries[i]));
        }
        bytes memory sp = _stateProof(iavlRoot, h.validatorSetHash(_syntheticValidators()), field4);
        return abi.encodePacked(PB.encodeBytesField(1, sp), PB.encodeBytesField(2, bundleContent));
    }

    /// @dev Builds a ClprSeiLedgerConfigurationPayload proving the config-declared service
    ///      address's service-address slot. `validatorsHashOverride` and `includeStorageSlot` let
    ///      callers force the two config negative cases.
    function _configProof(bytes32 validatorsHashOverride, bool includeStorageSlot)
        internal
        view
        returns (bytes memory)
    {
        CometBftLib.SeiValidator[] memory vals = _syntheticValidators();
        bytes memory validatorSetBytes = abi.encodePacked(
            PB.encodeBytesField(1, _encodeValidatorSingleWrapped(vals[0])),
            PB.encodeBytesField(1, _encodeValidatorSingleWrapped(vals[1]))
        );

        ClprTypes.Throttles memory throttles = ClprTypes.Throttles({
            maxMessagesPerBundle: 10,
            maxMessagePayloadBytes: 1024,
            maxGasPerMessage: 100000,
            maxQueueDepth: 50,
            maxSyncBytes: 2048,
            maxLocalEndpoints: 0,
            maxPeerEndpoints: 0
        });
        bytes memory ledgerConfigBytes = abi.encodePacked(
            PB.encodeBytesField(1, bytes(CHAIN_ID)),
            PB.encodeBytesField(2, abi.encodePacked(SERVICE_ADDR)),
            PB.encodeVarintField(3, uint64(123456789)),
            PB.encodeBytesField(4, _buildThrottlesBytes(throttles))
        );

        bytes memory spKey = abi.encodePacked(uint8(0x03), SERVICE_ADDR20, bytes32(0));
        (bytes memory storageEntry, bytes32 iavlRoot) =
            _buildStorageProofEntry(spKey, abi.encodePacked(_serviceAddressSlotValue()));

        bytes memory field4 = includeStorageSlot ? PB.encodeBytesField(4, storageEntry) : bytes("");
        bytes memory sp = _stateProof(iavlRoot, validatorsHashOverride, field4);

        return abi.encodePacked(
            PB.encodeBytesField(1, validatorSetBytes),
            PB.encodeBytesField(2, ledgerConfigBytes),
            PB.encodeBytesField(3, sp)
        );
    }

    /// @dev The proven value the verifier demands in the `_config.serviceAddress` slot:
    ///      Solidity's short-bytes(20) layout [addr 20B][zeros 11B][len*2 = 0x28].
    function _serviceAddressSlotValue() private pure returns (bytes32 slotValue) {
        bytes20 svc20 = SERVICE_ADDR20;
        assembly {
            slotValue := or(svc20, 0x28)
        }
    }

    /// @dev Assemble a config proof around an already-built IAVL storage entry and its root, so a
    ///      caller can share one tree between the config's service-address leaf and other leaves.
    function _configProofOverTree(bytes32 validatorsHashOverride, bytes memory storageEntry, bytes32 iavlRoot)
        private
        view
        returns (bytes memory)
    {
        CometBftLib.SeiValidator[] memory vals = _syntheticValidators();
        bytes memory validatorSetBytes = abi.encodePacked(
            PB.encodeBytesField(1, _encodeValidatorSingleWrapped(vals[0])),
            PB.encodeBytesField(1, _encodeValidatorSingleWrapped(vals[1]))
        );

        ClprTypes.Throttles memory throttles = ClprTypes.Throttles({
            maxMessagesPerBundle: 10,
            maxMessagePayloadBytes: 1024,
            maxGasPerMessage: 100000,
            maxQueueDepth: 50,
            maxSyncBytes: 2048,
            maxLocalEndpoints: 0,
            maxPeerEndpoints: 0
        });
        bytes memory ledgerConfigBytes = abi.encodePacked(
            PB.encodeBytesField(1, bytes(CHAIN_ID)),
            PB.encodeBytesField(2, abi.encodePacked(SERVICE_ADDR)),
            PB.encodeVarintField(3, uint64(123456789)),
            PB.encodeBytesField(4, _buildThrottlesBytes(throttles))
        );

        bytes memory sp = _stateProof(iavlRoot, validatorsHashOverride, PB.encodeBytesField(4, storageEntry));
        return abi.encodePacked(
            PB.encodeBytesField(1, validatorSetBytes),
            PB.encodeBytesField(2, ledgerConfigBytes),
            PB.encodeBytesField(3, sp)
        );
    }

    /// @dev Sei couples the config and manifest proofs: the manifest's IAVL existence proof is
    ///      verified against the very store root the config's state proof authenticates. Both leaves
    ///      therefore live in one tree — the config's `_config.serviceAddress` leaf and the
    ///      manifest-commitment leaf keyed `0x03 || serviceAddr || slot(18)` (full-key match).
    ///      The manifest proof itself is protobuf `[field1 = StorageProofEntry, field2 = preimage]`.
    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        view
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        bytes[] memory keys = new bytes[](2);
        bytes32[] memory values = new bytes32[](2);
        keys[0] = abi.encodePacked(uint8(0x03), SERVICE_ADDR20, bytes32(0));
        values[0] = _serviceAddressSlotValue();
        keys[1] = abi.encodePacked(uint8(0x03), SERVICE_ADDR20, bytes32(MANIFEST_COMMITMENT_SLOT));
        values[1] = keccak256(committedPreimage);

        (bytes[] memory entries, bytes32 iavlRoot) = _buildLinearChainStorageProof(keys, values);

        configProof = _configProofOverTree(h.validatorSetHash(_syntheticValidators()), entries[0], iavlRoot);
        channelId = CHANNEL_ID;
        manifestProof = abi.encodePacked(PB.encodeBytesField(1, entries[1]), PB.encodeBytesField(2, carriedPreimage));
    }

    // ── Base hooks ────────────────────────────────────────────────────────────

    function _validConfig() internal view override returns (ConfigVector memory) {
        return ConfigVector({
            configProof: _configProof(h.validatorSetHash(_syntheticValidators()), true),
            channelId: CHANNEL_ID,
            expectedChainId: CHAIN_ID,
            expectedServiceAddress: abi.encodePacked(SERVICE_ADDR)
        });
    }

    function _validBundle() internal view override returns (BundleVector memory) {
        return BundleVector({
            proofBytes: _bundle(CHANNEL_ID, SERVICE_ADDR20, _successValues(), PB.encodeBytesField(2, hex"aabbcc")),
            trustAnchor: _trustAnchor(),
            channelContext: _ctxFor(CHANNEL_ID, SERVICE_ADDR20),
            expectedNextMessageId: 100,
            expectedPayloadCount: 1
        });
    }

    function _runningHashVector() internal view override returns (RunningHashVector memory) {
        bytes memory payload = hex"aabbcc";
        bytes32[5] memory values = _successValues();
        values[2] = sha256(abi.encodePacked(bytes32(0), sha256(payload))); // sentRunningHash = chain over 1 payload
        return RunningHashVector({
            proofBytes: _bundle(CHANNEL_ID, SERVICE_ADDR20, values, PB.encodeBytesField(2, payload)),
            trustAnchor: _trustAnchor(),
            channelContext: _ctxFor(CHANNEL_ID, SERVICE_ADDR20),
            previousRunningHash: bytes32(0)
        });
    }

    /// @dev Sei's verifyConfig is a bootstrapping root with no pinned-chain string check; the
    ///      closest "not from this chain" signal is a signed header committing to a validator set
    ///      other than the one carried in the proof → ValidatorSetHashMismatch.
    function _wrongChainConfigVector() internal view override returns (bytes memory, bytes32) {
        return (_configProof(bytes32(uint256(0xDEAD)), true), CHANNEL_ID);
    }

    // ── Storage hooks ───────────────────────────────────────────────────────────

    function _crossChannelVector()
        internal
        view
        override
        returns (bytes memory, bytes memory, bytes memory, bytes memory)
    {
        return (
            _bundle(CHANNEL_ID, SERVICE_ADDR20, _successValues(), PB.encodeBytesField(2, hex"aabbcc")),
            _trustAnchor(),
            _ctxFor(OTHER_CHANNEL_ID, SERVICE_ADDR20),
            abi.encodeWithSelector(SeiCometBftVerifier.StorageKeyMismatch.selector)
        );
    }

    /// @dev Config proof with 0 storage entries → verifyConfig's `slotValues.length != 1`
    ///      (InvalidStorageProofCount): a required state-proofed field omitted.
    function _partialSlotCoverageVector() internal view override returns (bytes memory, bytes32) {
        return (_configProof(h.validatorSetHash(_syntheticValidators()), false), CHANNEL_ID);
    }

    function _wrongServiceAddressVector() internal view override returns (bytes memory, bytes memory, bytes memory) {
        address differentService = address(uint160(uint256(keccak256("different-service"))));
        return (
            _bundle(CHANNEL_ID, SERVICE_ADDR20, _successValues(), PB.encodeBytesField(2, hex"aabbcc")),
            _trustAnchor(),
            _ctxFor(CHANNEL_ID, bytes20(differentService))
        );
    }

    /// @dev Bundle with exactly 3 storage entries (Channel slots +1/+2/+4, the rest absent) →
    ///      StorageProofFailed (entry count neither 5 nor 6).
    function _threeSlotStorageVector() internal view override returns (bytes memory, bytes memory, bytes memory) {
        bytes32 cBase = keccak256(abi.encode(CHANNEL_ID, uint256(15)));
        uint8[3] memory offsets = [1, 2, 4];
        bytes[] memory keys = new bytes[](3);
        bytes32[] memory values = new bytes32[](3);
        for (uint256 i = 0; i < 3; i++) {
            keys[i] = abi.encodePacked(uint8(0x03), SERVICE_ADDR20, bytes32(uint256(cBase) + offsets[i]));
            values[i] = bytes32(uint256(i + 1));
        }
        (bytes[] memory entries, bytes32 iavlRoot) = _buildLinearChainStorageProof(keys, values);
        bytes memory field4;
        for (uint256 i = 0; i < 3; i++) {
            field4 = abi.encodePacked(field4, PB.encodeBytesField(4, entries[i]));
        }
        bytes memory sp = _stateProof(iavlRoot, h.validatorSetHash(_syntheticValidators()), field4);
        bytes memory proof =
            abi.encodePacked(PB.encodeBytesField(1, sp), PB.encodeBytesField(2, PB.encodeBytesField(2, hex"aabbcc")));
        return (proof, _trustAnchor(), _ctxFor(CHANNEL_ID, SERVICE_ADDR20));
    }

    /// @dev Bundle with 5 entries but offsets [+1,+2,+3,+5,+16] — cBase+3 in place of cBase+4. The
    ///      verifier derives cBase+4 from the layout and finds slot #2 mismatched → StorageKeyMismatch.
    function _wrongSlotIndexVector() internal view override returns (bytes memory, bytes memory, bytes memory) {
        bytes32 cBase = keccak256(abi.encode(CHANNEL_ID, uint256(15)));
        uint8[5] memory offsets = [1, 2, 3, 5, 16];
        bytes[5] memory keys;
        for (uint256 i = 0; i < 5; i++) {
            keys[i] = abi.encodePacked(uint8(0x03), SERVICE_ADDR20, bytes32(uint256(cBase) + offsets[i]));
        }
        bytes32[5] memory values = _successValues();
        (bytes[5] memory entries, bytes32 iavlRoot) = _buildFiveLeafStorageProof(keys, values);
        bytes memory field4;
        for (uint256 i = 0; i < 5; i++) {
            field4 = abi.encodePacked(field4, PB.encodeBytesField(4, entries[i]));
        }
        bytes memory sp = _stateProof(iavlRoot, h.validatorSetHash(_syntheticValidators()), field4);
        bytes memory proof =
            abi.encodePacked(PB.encodeBytesField(1, sp), PB.encodeBytesField(2, PB.encodeBytesField(2, hex"aabbcc")));
        return (proof, _trustAnchor(), _ctxFor(CHANNEL_ID, SERVICE_ADDR20));
    }
}
