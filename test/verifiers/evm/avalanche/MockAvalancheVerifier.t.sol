// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {MockAvalancheVerifier} from "@hiero-ledger/clpr/verifiers/evm/avalanche/MockAvalancheVerifier.sol";
import {ClprProtobuf} from "@hiero-ledger/clpr/libraries/codec/ClprProtobuf.sol";
import {ClprTypes} from "@hiero-ledger/clpr/libraries/ClprTypes.sol";

/// @dev Unit tests for the MockAvalancheVerifier test harness verifier:
///      configurable verifyConfig + protobuf bundle decode in verifyBundle.
contract MockAvalancheVerifierTest is Test {
    MockAvalancheVerifier internal verifier;

    function setUp() public {
        verifier = new MockAvalancheVerifier();
    }

    function _throttles() internal pure returns (ClprTypes.Throttles memory) {
        return ClprTypes.Throttles({
            maxMessagesPerBundle: 100,
            maxMessagePayloadBytes: 100_000,
            maxGasPerMessage: 1_000_000,
            maxQueueDepth: 1000,
            maxSyncBytes: 100_000,
            maxLocalEndpoints: 0,
            maxPeerEndpoints: 0
        });
    }

    /// @dev configure() (incl. the seed-endpoint copy loop) then verifyConfig() returns it back.
    function test_configure_then_verifyConfig_roundtrip() public {
        ClprTypes.Endpoint[] memory seeds = new ClprTypes.Endpoint[](2);
        seeds[0] = ClprTypes.Endpoint({ipAddress: "10.0.0.1", port: 9650, tlsCertificate: hex"aa", accountId: hex"cc"});
        seeds[1] = ClprTypes.Endpoint({ipAddress: "10.0.0.2", port: 9651, tlsCertificate: hex"dd", accountId: hex"ff"});

        verifier.configure(
            "avalanche:43113", hex"c0ffee", uint96(1_700_000_000), _throttles(), hex"a11ce5", hex"a11d", seeds
        );

        (
            ,
            string memory chainId,
            bytes memory peerServiceAddress,
            uint96 peerConfigNanos,
            ClprTypes.Throttles memory throttles,
            bytes memory initialTrustAnchor,
            bytes memory initialTrustAnchorId,
            ClprTypes.ClprEndpointManifest memory outSeeds
        ) = verifier.verifyConfig(hex"", bytes32(0), "");

        assertEq(chainId, "avalanche:43113");
        assertEq(keccak256(peerServiceAddress), keccak256(hex"c0ffee"));
        assertEq(peerConfigNanos, 1_700_000_000);
        assertEq(throttles.maxMessagesPerBundle, 100);
        assertEq(keccak256(initialTrustAnchor), keccak256(hex"a11ce5"));
        assertEq(keccak256(initialTrustAnchorId), keccak256(hex"a11d"));
        assertEq(outSeeds.endpoints.length, 2);
        assertEq(outSeeds.endpoints[0].ipAddress, "10.0.0.1");
        assertEq(outSeeds.endpoints[1].port, 9651);
    }

    /// @dev configure() replaces (not appends) seed endpoints on a second call.
    function test_configure_replacesSeedEndpoints() public {
        ClprTypes.Endpoint[] memory one = new ClprTypes.Endpoint[](1);
        one[0] = ClprTypes.Endpoint({ipAddress: "1.1.1.1", port: 1, tlsCertificate: "", accountId: ""});
        verifier.configure("c", hex"", 0, _throttles(), hex"", hex"", one);

        verifier.configure("c", hex"", 0, _throttles(), hex"", hex"", new ClprTypes.Endpoint[](0));
        (,,,,,,, ClprTypes.ClprEndpointManifest memory outSeeds) = verifier.verifyConfig(hex"", bytes32(0), "");
        assertEq(outSeeds.endpoints.length, 0, "second configure must clear prior seed endpoints");
    }

    /// @dev verifyBundle decodes BundleContent and returns empty trust anchors / peer address.
    function test_verifyBundle_decodesBundleContent() public view {
        bytes[] memory payloads = new bytes[](2);
        payloads[0] = hex"deadbeef";
        payloads[1] = hex"cafe";

        ClprTypes.QueueMetadata memory meta = ClprTypes.QueueMetadata({
            nextMessageId: 7,
            sentRunningHash: keccak256("sent"),
            receivedMessageId: 6,
            receivedRunningHash: keccak256("recv"),
            state: ClprTypes.ChannelStatus.ACTIVE,
            endpointManifestVersion: 0,
            lastMessageId: 6,
            lastMessageRunningHash: keccak256("sent")
        });
        bytes memory encoded = ClprProtobuf.encodeBundleContent(meta, payloads);

        (
            ClprTypes.QueueMetadata memory outMeta,
            bytes[] memory outPayloads,
            bytes memory newTrustAnchor,
            bytes memory newTrustAnchorId,
        ) = verifier.verifyBundle(encoded, hex"", hex"");

        assertEq(outMeta.nextMessageId, 7);
        assertEq(outMeta.receivedMessageId, 6);
        assertEq(uint8(outMeta.state), uint8(ClprTypes.ChannelStatus.ACTIVE));
        assertEq(outPayloads.length, 2);
        assertEq(keccak256(outPayloads[0]), keccak256(hex"deadbeef"));
        assertEq(newTrustAnchor.length, 0);
        assertEq(newTrustAnchorId.length, 0);
    }
}
