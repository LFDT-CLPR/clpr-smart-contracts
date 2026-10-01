// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {ClprVerifierComplianceTest} from "@test/verifiers/compliance/ClprVerifierComplianceTest.sol";
import {BindingEd25519Stub} from "@test/verifiers/compliance/GrandpaComplianceTest.t.sol";
import {SubstrateSyntheticProofs} from "@test/helpers/SubstrateSyntheticProofs.sol";
import {IClprVerifier} from "@hiero-ledger/clpr/interfaces/IClprVerifier.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {Blake2b} from "@hiero-ledger/clpr/libraries/proof/substrate/Blake2b.sol";
import {ScaleCodec} from "@hiero-ledger/clpr/libraries/proof/substrate/ScaleCodec.sol";
import {GrandpaLightClient} from "@hiero-ledger/clpr/verifiers/evm/grandpa/GrandpaLightClient.sol";
import {GrandpaPalletVerifier} from "@hiero-ledger/clpr/verifiers/evm/grandpa/GrandpaPalletVerifier.sol";

/// @title GrandpaPalletComplianceTest
/// @notice ClprVerifierComplianceTest adapter for GrandpaPalletVerifier. The CLPR state is a
///         synthetic native-pallet trie (`Clpr::Queues`, `Clpr::Service`) built per vector, so any
///         manifest commitment or running hash can be proven; every bundle carries a GRANDPA commit
///         of a one-authority set through the full GrandpaLib path, with the curve operation
///         replaced by {BindingEd25519Stub}. The real curve and the accumulator path are covered by
///         GrandpaPalletVerifier.t.sol and the live Chainflip spec.
contract GrandpaPalletComplianceTest is ClprVerifierComplianceTest, SubstrateSyntheticProofs {
    string internal constant CHAIN_ID = "polkadot:8b8c140b0af9db70686583e3f6bf2a59";
    bytes16 internal constant PALLET = 0x4d9bf76bff04c57065ce79a2c97923fb; // twox128("Clpr")
    bytes16 internal constant QUEUES = 0xb5cd230cad01da4acb0378dad6ed82e9; // twox128("Queues")
    bytes16 internal constant SERVICE_ITEM = 0x221b4c4483eae1aedca119452a71c709; // twox128("Service")
    bytes32 internal constant SERVICE = keccak256("grandpa-pallet-compliance-service");
    bytes32 internal constant CHANNEL_ID = bytes32(uint256(0xC0FFEE));
    uint96 internal constant NANOS = 1_750_000_000_000_000_001;
    uint64 internal constant NEXT_MESSAGE_ID = 4;
    uint32 internal constant BLOCK = 10;
    uint64 internal constant ROUND = 1;
    bytes32 internal constant AUTHORITY_KEY = keccak256("grandpa-pallet-compliance-authority");

    bytes internal authorities;

    function _deployVerifier() internal override returns (IClprVerifier) {
        authorities = abi.encodePacked(AUTHORITY_KEY, hex"0100000000000000");
        BindingEd25519Stub ed = new BindingEd25519Stub();
        return IClprVerifier(
            address(new GrandpaPalletVerifier(address(ed), address(0), PALLET, CHAIN_ID, 0, keccak256(authorities), 1))
        );
    }

    // ── Finality ─────────────────────────────────────────────────────────────

    function _anchor() internal view returns (bytes memory) {
        return abi.encodePacked(uint64(0), keccak256(authorities), uint32(1));
    }

    function _steps(bytes32 stateRoot) internal view returns (GrandpaLightClient.Step[] memory steps) {
        bytes memory header = _header(keccak256("parent"), BLOCK, stateRoot);
        bytes32 h = Blake2b.hash256(header);
        bytes memory message =
            abi.encodePacked(uint8(1), h, ScaleCodec.le32(BLOCK), ScaleCodec.le64(ROUND), ScaleCodec.le64(0));
        bytes memory sig = abi.encodePacked(
            sha256(abi.encodePacked(AUTHORITY_KEY, message)), sha256(abi.encodePacked(message, AUTHORITY_KEY))
        );
        steps = new GrandpaLightClient.Step[](1);
        steps[0].headers = new bytes[](1);
        steps[0].headers[0] = header;
        steps[0].round = ROUND;
        steps[0].votes = abi.encodePacked(uint16(0), h, uint32(BLOCK), sig);
        steps[0].ancestry = new bytes[](0);
        steps[0].authorities = authorities;
    }

    // ── Pallet state ─────────────────────────────────────────────────────────

    function _queueEntry(bytes32 sentHash) internal view returns (Entry memory) {
        bytes memory record = abi.encodePacked(
            uint8(ClprTypes.ChannelStatus.ACTIVE),
            ScaleCodec.le64(NEXT_MESSAGE_ID),
            ScaleCodec.le64(2),
            ScaleCodec.le64(1),
            sentHash,
            keccak256("received")
        );
        return Entry(
            abi.encodePacked(PALLET, QUEUES, Blake2b.hash128(abi.encodePacked(CHANNEL_ID)), CHANNEL_ID), record, true
        );
    }

    function _serviceEntry(bytes memory committedManifest) internal pure returns (Entry memory) {
        bytes32 commitment = committedManifest.length > 0 ? keccak256(committedManifest) : bytes32(0);
        bytes memory record =
            abi.encodePacked(SERVICE, commitment, ScaleCodec.le64(uint64(NANOS)), ScaleCodec.le64(uint64(NANOS >> 64)));
        return Entry(abi.encodePacked(PALLET, SERVICE_ITEM), record, true);
    }

    function _bundle(bytes32 sentHash, bytes memory content) internal returns (bytes memory) {
        Entry[] memory e = new Entry[](2);
        e[0] = _queueEntry(sentHash);
        e[1] = _serviceEntry("");
        (bytes32 root, bytes[] memory nodes) = _buildTrie(e);
        return abi.encode(GrandpaPalletVerifier.BundleProof(_steps(root), nodes, content, ""));
    }

    function _ledgerConfig(string memory chainId) internal pure returns (bytes memory) {
        ClprTypes.LedgerConfiguration memory lc;
        lc.protocolVersion = 1;
        lc.chainId = chainId;
        lc.serviceAddress = abi.encodePacked(SERVICE);
        lc.nanosSinceEpoch = NANOS;
        lc.throttles = ClprTypes.Throttles(10, 1024, 1_000_000, 100, 4096, 4, 4);
        return ClprProtobuf.encodeControlMessage(lc);
    }

    function _config(bytes memory committedManifest, string memory chainId) internal returns (bytes memory) {
        Entry[] memory e = new Entry[](2);
        e[0] = _queueEntry(keccak256("sent"));
        e[1] = _serviceEntry(committedManifest);
        (bytes32 root, bytes[] memory nodes) = _buildTrie(e);
        return abi.encode(GrandpaPalletVerifier.ConfigProof(_steps(root), nodes, _ledgerConfig(chainId)));
    }

    // ── ClprVerifierComplianceTest hooks ─────────────────────────────────────

    function _validConfig() internal override returns (ConfigVector memory) {
        return ConfigVector({
            configProof: _config("", CHAIN_ID),
            channelId: CHANNEL_ID,
            expectedChainId: CHAIN_ID,
            expectedServiceAddress: abi.encodePacked(SERVICE)
        });
    }

    function _validBundle() internal override returns (BundleVector memory) {
        return BundleVector({
            proofBytes: _bundle(keccak256("sent"), ""),
            trustAnchor: _anchor(),
            channelContext: abi.encodePacked(CHANNEL_ID, SERVICE),
            expectedNextMessageId: NEXT_MESSAGE_ID,
            expectedPayloadCount: 0
        });
    }

    function _manifestConfigVector(bytes memory committedPreimage, bytes memory carriedPreimage)
        internal
        override
        returns (bytes memory configProof, bytes32 channelId, bytes memory manifestProof)
    {
        configProof = _config(committedPreimage, CHAIN_ID);
        channelId = CHANNEL_ID;
        manifestProof = carriedPreimage;
    }

    function _runningHashVector() internal override returns (RunningHashVector memory) {
        bytes[2] memory payloads = [bytes("payload-one"), bytes("payload-two")];
        bytes32 h;
        bytes memory content;
        for (uint256 i; i < payloads.length; ++i) {
            h = sha256(abi.encodePacked(h, sha256(payloads[i])));
            content = abi.encodePacked(content, hex"12", uint8(payloads[i].length), payloads[i]);
        }
        return RunningHashVector({
            proofBytes: _bundle(h, content),
            trustAnchor: _anchor(),
            channelContext: abi.encodePacked(CHANNEL_ID, SERVICE),
            previousRunningHash: bytes32(0)
        });
    }

    function _wrongChainConfigVector() internal override returns (bytes memory, bytes32) {
        return (_config("", "eip155:1"), CHANNEL_ID);
    }
}
